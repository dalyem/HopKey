package store

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A backup that is missing is never reported deleted (review 3 of A3c,
// P2): before its deletion was recorded as begun, the resume refuses
// (ErrForkDamaged) and --keep-old finishes without it; after, the fork
// finishes and reports it missing, not deleted, in the result and in its
// JSON.

// movedAway moves the fork's backup out of its place, as a user would.
func movedAway(t *testing.T, cfg Config) (backup, moved string) {
	t.Helper()
	backup = onlyBackup(t, cfg)
	moved = filepath.Join(filepath.Dir(cfg.DataDir), "moved")
	if err := os.Rename(backup, moved); err != nil {
		t.Fatal(err)
	}
	return backup, moved
}

// missingNotDeleted requires res to report the backup missing, not
// deleted, and its JSON to say so.
func missingNotDeleted(t *testing.T, res *ForkResult) {
	t.Helper()
	if res == nil || res.Discarded || !res.BackupMissing {
		t.Fatalf("result: %+v", res)
	}
	b, err := json.Marshal(res)
	if err != nil {
		t.Fatal(err)
	}
	if s := string(b); !strings.Contains(s, `"backup_missing":true`) || strings.Contains(s, `"discarded"`) {
		t.Errorf("JSON: %s", s)
	}
}

func TestForkBackupMovedBeforeTheDeletion(t *testing.T) {
	ctx := context.Background()
	x := forkFixture(t)
	cfg := x.f.cfg
	old := idsOf(t, cfg)
	crashForkAt(t, cfg, "fork:moved-new", true)
	_, moved := movedAway(t, cfg)
	if _, _, err := ResumeFork(ctx, cfg, ForkOptions{}); !errors.Is(err, ErrForkDamaged) || !strings.Contains(err.Error(), "missing") {
		t.Fatalf("resume with the backup moved away: %v, want ErrForkDamaged", err)
	}
	if pending, err := ForkInProgress(cfg.DataDir); err != nil || !pending {
		t.Errorf("in progress after the refusal: %v %v", pending, err)
	}
	j, err := readForkJournal(cfg.DataDir)
	if err != nil || j == nil || j.Discarding {
		t.Fatalf("the journal: %+v %v", j, err)
	}
	res, _, err := ResumeFork(ctx, cfg, ForkOptions{KeepOld: true})
	if err != nil {
		t.Fatal(err)
	}
	missingNotDeleted(t, res)
	oldVaultIn(t, moved, old)
	if _, err := cfg.Keyring.Get(keychainService, slotOf(old.acct, old.dev)); err != nil {
		t.Errorf("the old device key: %v", err)
	}
	if rec, err := ForkRecord(cfg.DataDir); err != nil || rec == nil || !rec.BackupMissing || rec.Discarded {
		t.Errorf("the fork's record: %+v %v", rec, err)
	}
}

// Once the deletion began, a missing backup can't be told from one the
// fork deleted before it stopped, so it is reported missing: after a crash
// that deleted it all (fork:discarded), and after a refused deletion whose
// backup the user moved away to keep it.
func TestForkBackupMissingAfterTheDeletionBegan(t *testing.T) {
	ctx := context.Background()
	t.Run("deleted before the crash", func(t *testing.T) {
		x := forkFixture(t)
		cfg := x.f.cfg
		crashForkAt(t, cfg, "fork:discarded", true)
		res, _, err := ResumeFork(ctx, cfg, ForkOptions{})
		if err != nil {
			t.Fatal(err)
		}
		missingNotDeleted(t, res)
	})
	t.Run("moved away to keep it", func(t *testing.T) {
		f := fileServerVault(t)
		cfg := f.cfg
		old := idsOf(t, cfg)
		crashForkAt(t, cfg, "fork:discarding", true)
		changeBackup(t, cfg, onlyBackup(t, cfg), "added during the deletion")
		if _, _, err := ResumeFork(ctx, cfg, ForkOptions{}); !errors.Is(err, ErrForkStale) {
			t.Fatalf("resume: %v, want ErrForkStale", err)
		}
		_, moved := movedAway(t, cfg)
		res, _, err := ResumeFork(ctx, cfg, ForkOptions{})
		if err != nil {
			t.Fatal(err)
		}
		missingNotDeleted(t, res)
		oldVaultIn(t, moved, old)
		if !hasCredential(t, cfg, moved, "added during the deletion") {
			t.Error("the change made in the backup is gone")
		}
	})
}
