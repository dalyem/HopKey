package store

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/dalyem/hopkey/internal/filelock"
	"github.com/dalyem/hopkey/internal/model"
)

// The third review of A3c: a deletion that had begun is resumed only on
// what it may have left of the backup, finishFork owns the backup's owner
// lock to its end, --keep-old never meets a deletion already under way,
// and a vault with access items is refused before anything is written.

// fileServerVault is serverVault with the device key in device.key
// (unsealed), whose deletion is the directory's: nothing of the backup
// goes before its files do.
func fileServerVault(t *testing.T) *fixture {
	t.Helper()
	cfg := testConfig(t)
	p, err := PrepareInit(cfg, InitOptions{Password: []byte(testPassword), DeviceStore: DeviceStoreFile})
	if err != nil {
		t.Fatal(err)
	}
	s, err := p.Commit()
	if err != nil {
		t.Fatal(err)
	}
	track(t, cfg, s)
	r := newFakeRemote(t, cfg.DataDir)
	if err := s.EnableServerMode(); err != nil {
		t.Fatal(err)
	}
	addHost(t, s, "web")
	newCredential(t, s, "db-login")
	pushAll(t, s, r)
	return &fixture{cfg: cfg, kit: p.Kit(), s: s}
}

// forkUnfinished requires the fork of cfg's vault to be in progress with
// its deletion of the backup recorded as begun, and the backup there.
func forkUnfinished(t *testing.T, cfg Config, backup string) {
	t.Helper()
	j, err := readForkJournal(cfg.DataDir)
	if err != nil || j == nil || j.State == forkDone || !j.Discarding || j.Discarded {
		t.Fatalf("the journal: %+v %v", j, err)
	}
	if _, err := os.Lstat(backup); err != nil {
		t.Errorf("the backup: %v", err)
	}
}

// A file-backed device key goes with the backup's directory, so a crash at
// fork:discarding leaves the backup whole, and a hop that does not know the
// fence can open and change it. The resume does not delete it: the change
// is refused with ErrForkStale, and the backup is kept, change and all
// (P1).
func TestForkResumedDeletionRechecksTheBackup(t *testing.T) {
	ctx := context.Background()
	f := fileServerVault(t)
	cfg := f.cfg
	old := idsOf(t, cfg)
	crashForkAt(t, cfg, "fork:discarding", true)
	backup := onlyBackup(t, cfg)
	changeBackup(t, cfg, backup, "added during the deletion")
	if _, _, err := ResumeFork(ctx, cfg, ForkOptions{}); !errors.Is(err, ErrForkStale) {
		t.Fatalf("resume after a change to the backup: %v, want ErrForkStale", err)
	}
	forkUnfinished(t, cfg, backup)
	oldVaultIn(t, backup, old)
	if _, err := os.Lstat(filepath.Join(backup, "device.key")); err != nil {
		t.Errorf("the backup's device key: %v", err)
	}
	// Opened outside the fence, by a copy under another name.
	kept := filepath.Join(filepath.Dir(cfg.DataDir), "kept")
	copyTree(t, backup, kept)
	if !hasCredential(t, cfg, kept, "added during the deletion") {
		t.Error("the change made in the backup is gone")
	}
}

// What a cut-short deletion leaves is files the deletion recorded,
// unchanged. One of them changed, or one added, is not: ErrForkStale, and
// the rest of the backup stays (P1).
func TestForkResumedDeletionRefusesAChangedRemnant(t *testing.T) {
	ctx := context.Background()
	for _, c := range []struct {
		name   string
		change func(t *testing.T, backup string)
	}{
		{"changed", func(t *testing.T, backup string) {
			p := filepath.Join(layout{data: backup}.vault(), "state.json")
			b, err := os.ReadFile(p)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(p, append(b, ' '), 0o600); err != nil {
				t.Fatal(err)
			}
		}},
		{"added", func(t *testing.T, backup string) {
			if err := os.WriteFile(filepath.Join(layout{data: backup}.vault(), "added"), []byte("x"), 0o600); err != nil {
				t.Fatal(err)
			}
		}},
	} {
		t.Run(c.name, func(t *testing.T) {
			x := forkFixture(t)
			cfg := x.f.cfg
			crashForkAt(t, cfg, "fork:discarding", true)
			backup := onlyBackup(t, cfg)
			// Cut short: device.json went first.
			if err := os.Remove(layout{data: backup}.deviceConfig()); err != nil {
				t.Fatal(err)
			}
			c.change(t, backup)
			if _, _, err := ResumeFork(ctx, cfg, ForkOptions{}); !errors.Is(err, ErrForkStale) {
				t.Fatalf("resume: %v, want ErrForkStale", err)
			}
			forkUnfinished(t, cfg, backup)
			if _, err := os.Lstat(filepath.Join(layout{data: backup}.vault(), "state.json")); err != nil {
				t.Errorf("the backup's state: %v", err)
			}
		})
	}
}

// A crash after the old vault moved into the backup, with --discard-old:
// the resume checks the backup, swaps, and deletes it, under the one owner
// lock it took (a second would be busy with the first) (P2).
func TestForkResumeAfterTheMoveDiscards(t *testing.T) {
	ctx := context.Background()
	x := forkFixture(t)
	cfg := x.f.cfg
	old := idsOf(t, cfg)
	crashForkAt(t, cfg, "fork:moved-old", true)
	backup := onlyBackup(t, cfg)
	res, _, err := ResumeFork(ctx, cfg, ForkOptions{})
	if err != nil || res == nil || !res.Discarded {
		t.Fatalf("resume: %+v %v", res, err)
	}
	if _, err := os.Lstat(backup); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("the backup: %v", err)
	}
	if _, err := cfg.Keyring.Get(keychainService, slotOf(old.acct, old.dev)); err == nil {
		t.Error("the old device key is still in the keychain")
	}
}

// A kept backup is not left owned by the fork that checked it: once the
// resume returns, its owner lock is free, whether the resume finished or
// was refused (P2).
func TestForkReleasesTheBackupsOwner(t *testing.T) {
	ctx := context.Background()
	free := func(t *testing.T, backup string) {
		t.Helper()
		f, err := filelock.TryLock(layout{data: backup}.ownerLock())
		if err != nil {
			t.Fatalf("the backup's owner lock: %v", err)
		}
		f.Close()
	}
	t.Run("finished", func(t *testing.T) {
		x := forkFixture(t)
		cfg := x.f.cfg
		crashForkAt(t, cfg, "fork:moved-old", false)
		backup := onlyBackup(t, cfg)
		if res, _, err := ResumeFork(ctx, cfg, ForkOptions{}); err != nil || res == nil || res.Discarded {
			t.Fatalf("resume: %+v %v", res, err)
		}
		free(t, backup)
	})
	t.Run("refused", func(t *testing.T) {
		x := forkFixture(t)
		cfg := x.f.cfg
		crashForkAt(t, cfg, "fork:moved-new", true)
		backup := onlyBackup(t, cfg)
		changeBackup(t, cfg, backup, "added after the swap")
		if _, _, err := ResumeFork(ctx, cfg, ForkOptions{}); !errors.Is(err, ErrForkStale) {
			t.Fatalf("resume: %v, want ErrForkStale", err)
		}
		free(t, backup)
	})
}

// --keep-old once the deletion had begun is refused, and nothing is
// deleted; the resume without it finishes the deletion (P2).
func TestForkKeepOldAfterTheDeletionBegan(t *testing.T) {
	ctx := context.Background()
	f := fileServerVault(t)
	cfg := f.cfg
	old := idsOf(t, cfg)
	crashForkAt(t, cfg, "fork:discarding", true)
	backup := onlyBackup(t, cfg)
	_, _, err := ResumeFork(ctx, cfg, ForkOptions{KeepOld: true})
	if !errors.Is(err, ErrForkRefused) || !strings.Contains(err.Error(), "without --keep-old") {
		t.Fatalf("resume with KeepOld: %v, want ErrForkRefused", err)
	}
	forkUnfinished(t, cfg, backup)
	oldVaultIn(t, backup, old)
	if _, err := os.Lstat(filepath.Join(backup, "device.key")); err != nil {
		t.Errorf("the backup's device key: %v", err)
	}
	res, _, err := ResumeFork(ctx, cfg, ForkOptions{})
	if err != nil || res == nil || !res.Discarded {
		t.Fatalf("resume: %+v %v", res, err)
	}
	if _, err := os.Lstat(backup); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("the backup: %v", err)
	}
}

// A vault with an access item, verified, queued or held, is refused before
// anything is written: no staging directory, no backup, and the old vault
// opens as it was (P3).
func TestForkRefusesAccessItems(t *testing.T) {
	for _, c := range []struct {
		name  string
		setup func(t *testing.T, p *pair)
	}{
		{"verified", func(t *testing.T, p *pair) {
			newAccess(t, p.a.s, p.host.ItemID, model.AccessPending)
			pushAll(t, p.a.s, p.r)
			if n := len(records(t, p.a.s)); n != 0 {
				t.Fatalf("%d records queued", n)
			}
		}},
		{"pending", func(t *testing.T, p *pair) {
			newAccess(t, p.a.s, p.host.ItemID, model.AccessPending)
			recs := records(t, p.a.s)
			if len(recs) == 0 || recs[0].Held {
				t.Fatalf("records: %+v", recs)
			}
		}},
		{"held", func(t *testing.T, p *pair) {
			heldAccess(t, p, model.AccessPending,
				func(x *model.AccessTarget) { x.State, x.Gen = model.AccessRemoving, 2 },
				func(x *model.AccessTarget) { x.State, x.Error = model.AccessFailed, "no" })
		}},
	} {
		t.Run(c.name, func(t *testing.T) {
			p := newPair(t)
			cfg := p.a.cfg
			c.setup(t, p)
			old := idsOf(t, cfg)
			release(cfg)
			fp, err := PrepareFork(context.Background(), cfg, ForkOptions{})
			if err == nil {
				fp.Close()
			}
			if !errors.Is(err, ErrForkRefused) || !strings.Contains(err.Error(), `"access"`) {
				t.Fatalf("prepare: %v, want ErrForkRefused for the access item", err)
			}
			noForkFiles(t, cfg)
			if s := open(t, cfg); s.Info().Locked || s.Info().AccountID != old.acct.String() {
				t.Errorf("the old vault: %+v", s.Info())
			}
		})
	}
}
