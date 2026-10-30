package store

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// The fourth review of A3c: a resumed deletion checks the backup against
// a manifest of every path in it, the entries' and the objects' contents
// too, even where the source digest, which leaves them out, still
// matches; a symbolic link is refused; and a journal of an earlier build,
// with no manifest, goes on only with the whole backup.

// discardingFork crashes a fork of a forkFixture vault, with --discard-old,
// once its deletion of the backup is recorded and before anything of it
// is deleted. It returns the config, the backup and the journal.
func discardingFork(t *testing.T) (Config, string, *forkJournal) {
	t.Helper()
	x := forkFixture(t)
	cfg := x.f.cfg
	crashForkAt(t, cfg, "fork:discarding", true)
	j, err := readForkJournal(cfg.DataDir)
	if err != nil || j == nil || !j.Discarding || j.DiscardManifest == nil {
		t.Fatalf("the journal: %+v %v", j, err)
	}
	return cfg, onlyBackup(t, cfg), j
}

// firstFile is the first regular file in dir.
func firstFile(t *testing.T, dir string) string {
	t.Helper()
	des, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, de := range des {
		if de.Type().IsRegular() {
			return filepath.Join(dir, de.Name())
		}
	}
	t.Fatalf("no file in %s", dir)
	return ""
}

func rewrite(t *testing.T, p string, b []byte) {
	t.Helper()
	if err := os.WriteFile(p, b, 0o600); err != nil {
		t.Fatal(err)
	}
}

// sourceMatches requires the backup to match the source digest still: a
// change the digest does not see.
func sourceMatches(t *testing.T, backup string, j *forkJournal) {
	t.Helper()
	if d, err := forkSourceDigest(backup); err != nil || d != j.Source {
		t.Fatalf("the source digest no longer matches (%v): the test changes what it commits to", err)
	}
}

// resumeRefused requires the resume to fail with want and keep the backup
// and the file kept in it.
func resumeRefused(t *testing.T, cfg Config, backup, kept string, want error) {
	t.Helper()
	if _, _, err := ResumeFork(context.Background(), cfg, ForkOptions{}); !errors.Is(err, want) {
		t.Fatalf("resume: %v, want %v", err, want)
	}
	forkUnfinished(t, cfg, backup)
	if _, err := os.Lstat(kept); err != nil {
		t.Errorf("%s: %v", kept, err)
	}
}

// An entry's contents changed under its name are seen, with device.json
// gone (a cut-short deletion) and with it there, where the source digest,
// which commits to the entries' names only, still matches (P1).
func TestForkResumedDeletionChecksEntryContents(t *testing.T) {
	for _, removeDevice := range []bool{true, false} {
		name := "device.json kept"
		if removeDevice {
			name = "device.json removed"
		}
		t.Run(name, func(t *testing.T) {
			cfg, backup, j := discardingFork(t)
			entry := firstFile(t, layout{data: backup}.entries())
			rewrite(t, entry, []byte(`{"changed":true}`))
			if removeDevice {
				if err := os.Remove(layout{data: backup}.deviceConfig()); err != nil {
					t.Fatal(err)
				}
			} else {
				sourceMatches(t, backup, j)
			}
			resumeRefused(t, cfg, backup, entry, ErrForkStale)
		})
	}
}

// The objects, which the source digest leaves out, are in the manifest: one
// added or changed, or the directory replaced by a file, is refused, with
// the source digest still matching; one removed is what a deletion leaves,
// and the deletion goes on (P1).
func TestForkResumedDeletionChecksObjects(t *testing.T) {
	for _, c := range []struct {
		name   string
		change func(t *testing.T, objects string) string
	}{
		{"added", func(t *testing.T, objects string) string {
			p := filepath.Join(objects, "added")
			rewrite(t, p, []byte("x"))
			return p
		}},
		{"changed", func(t *testing.T, objects string) string {
			p := firstFile(t, objects)
			rewrite(t, p, []byte(`{"changed":true}`))
			return p
		}},
		{"replaced by a file", func(t *testing.T, objects string) string {
			if err := os.RemoveAll(objects); err != nil {
				t.Fatal(err)
			}
			rewrite(t, objects, []byte("x"))
			return objects
		}},
	} {
		t.Run(c.name, func(t *testing.T) {
			cfg, backup, j := discardingFork(t)
			kept := c.change(t, layout{data: backup}.objects())
			sourceMatches(t, backup, j)
			resumeRefused(t, cfg, backup, kept, ErrForkStale)
		})
	}
	t.Run("removed", func(t *testing.T) {
		cfg, backup, _ := discardingFork(t)
		if err := os.Remove(firstFile(t, layout{data: backup}.objects())); err != nil {
			t.Fatal(err)
		}
		res, _, err := ResumeFork(context.Background(), cfg, ForkOptions{})
		if err != nil || res == nil || !res.Discarded {
			t.Fatalf("resume: %+v %v", res, err)
		}
		if _, err := os.Lstat(backup); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("the backup: %v", err)
		}
	})
}

// A data directory holds no symbolic link: a vault with one is not forked,
// and one found in the backup once its deletion began, in the objects or
// in place of an entry, stops the deletion (P1).
func TestForkRefusesSymlinks(t *testing.T) {
	t.Run("prepare", func(t *testing.T) {
		x := forkFixture(t)
		cfg := x.f.cfg
		release(cfg)
		link := filepath.Join(layout{data: cfg.DataDir}.objects(), "link")
		if err := os.Symlink(t.TempDir(), link); err != nil {
			t.Fatal(err)
		}
		fp, err := PrepareFork(context.Background(), cfg, ForkOptions{})
		if err == nil {
			fp.Close()
		}
		if !errors.Is(err, ErrForkRefused) {
			t.Fatalf("prepare: %v, want ErrForkRefused", err)
		}
		noForkFiles(t, cfg)
	})
	t.Run("in the objects", func(t *testing.T) {
		cfg, backup, _ := discardingFork(t)
		link := filepath.Join(layout{data: backup}.objects(), "link")
		if err := os.Symlink(t.TempDir(), link); err != nil {
			t.Fatal(err)
		}
		resumeRefused(t, cfg, backup, link, ErrForkRefused)
	})
	t.Run("in place of an entry", func(t *testing.T) {
		cfg, backup, _ := discardingFork(t)
		entry := firstFile(t, layout{data: backup}.entries())
		elsewhere := filepath.Join(filepath.Dir(backup), "entry")
		if err := os.Rename(entry, elsewhere); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(elsewhere, entry); err != nil {
			t.Fatal(err)
		}
		resumeRefused(t, cfg, backup, entry, ErrForkRefused)
		if _, err := os.Stat(elsewhere); err != nil {
			t.Errorf("the link's target: %v", err)
		}
	})
}

// A journal of an earlier build records the deletion as begun with no
// manifest: the deletion goes on with the whole backup as the fork read
// it, and with nothing less (P1).
func TestForkResumedDeletionWithoutAManifest(t *testing.T) {
	legacy := func(t *testing.T, cfg Config) {
		t.Helper()
		p := forkJournalFile(cfg.DataDir)
		b, err := os.ReadFile(p)
		if err != nil {
			t.Fatal(err)
		}
		var m map[string]json.RawMessage
		if err := json.Unmarshal(b, &m); err != nil {
			t.Fatal(err)
		}
		m["discard_files"] = m["discard_manifest"]
		delete(m, "discard_manifest")
		if b, err = json.Marshal(m); err != nil {
			t.Fatal(err)
		}
		rewrite(t, p, b)
	}
	t.Run("whole", func(t *testing.T) {
		cfg, backup, _ := discardingFork(t)
		legacy(t, cfg)
		res, _, err := ResumeFork(context.Background(), cfg, ForkOptions{})
		if err != nil || res == nil || !res.Discarded {
			t.Fatalf("resume: %+v %v", res, err)
		}
		if _, err := os.Lstat(backup); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("the backup: %v", err)
		}
	})
	t.Run("part", func(t *testing.T) {
		cfg, backup, _ := discardingFork(t)
		legacy(t, cfg)
		if err := os.Remove(layout{data: backup}.deviceConfig()); err != nil {
			t.Fatal(err)
		}
		resumeRefused(t, cfg, backup, layout{data: backup}.stateFile(), ErrForkStale)
	})
}
