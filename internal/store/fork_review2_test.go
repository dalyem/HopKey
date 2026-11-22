package store

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/dalyem/hopkey/internal/filelock"
	"github.com/dalyem/hopkey/internal/model"
)

// The second review of A3c: the backup is fenced and checked like the old
// vault until the fork is done, a commit whose outcome is uncertain keeps
// its kit, and predecessor writes stay out of a fork's way.

// onlyBackup is the one fork backup beside cfg's data directory.
func onlyBackup(t *testing.T, cfg Config) string {
	t.Helper()
	b := forkBackups(t, cfg.DataDir)
	if len(b) != 1 {
		t.Fatalf("backups: %v", b)
	}
	return b[0]
}

// changeBackup adds a credential to the vault in backup as a hop that
// does not know the fence would: opened without the gate.
func changeBackup(t *testing.T, cfg Config, backup, name string) {
	t.Helper()
	bcfg := cfg
	bcfg.DataDir = backup
	s, err := openStore(context.Background(), bcfg, false)
	if err != nil {
		t.Fatal(err)
	}
	newCredential(t, s, name)
	s.Close()
}

// hasCredential reports whether the vault in dir holds a credential named
// name.
func hasCredential(t *testing.T, cfg Config, dir, name string) bool {
	t.Helper()
	c := cfg
	c.DataDir = dir
	s := open(t, c)
	defer release(c)
	return slices.ContainsFunc(snapshot(t, s).Credentials, func(x model.Credential) bool { return x.Name == name })
}

// After a crash that moved the old vault into the backup, the backup is
// fenced as the data directory is: an open is refused (and is busy while
// a fork holds the gate). A change made there anyway (by a hop that does
// not know the fence) makes the resume refuse with ErrForkStale, even with
// --discard-old, and keeps the backup; the abandon puts it back, change
// and all (P1).
func TestForkFencesAndChecksTheBackup(t *testing.T) {
	ctx := context.Background()
	x := forkFixture(t)
	cfg := x.f.cfg
	old := idsOf(t, cfg)
	crashForkAt(t, cfg, "fork:moved-old", true)
	backup := onlyBackup(t, cfg)
	bcfg := cfg
	bcfg.DataDir = backup
	if s, err := Open(ctx, bcfg); !errors.Is(err, ErrForkPending) {
		if err == nil {
			s.Close()
		}
		t.Fatalf("open of the backup during the fork: %v, want ErrForkPending", err)
	}
	data, _, err := forkPaths(cfg.DataDir)
	if err != nil {
		t.Fatal(err)
	}
	gate, err := takeForkGate(data)
	if err != nil {
		t.Fatal(err)
	}
	if s, err := Open(ctx, bcfg); !errors.Is(err, ErrVaultBusy) {
		if err == nil {
			s.Close()
		}
		t.Errorf("open of the backup while a fork holds the gate: %v, want ErrVaultBusy", err)
	}
	gate.Close()

	changeBackup(t, cfg, backup, "added in the backup")
	if _, _, err := ResumeFork(ctx, cfg, ForkOptions{}); !errors.Is(err, ErrForkStale) {
		t.Fatalf("resume after a change to the backup: %v, want ErrForkStale", err)
	}
	oldVaultIn(t, backup, old)
	if _, err := os.Lstat(cfg.DataDir + forkNewSuffix); err != nil {
		t.Errorf("the staging directory: %v", err)
	}
	if _, err := os.Lstat(cfg.DataDir); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("the data directory: %v", err)
	}
	if ok, err := AbandonFork(ctx, cfg); err != nil || !ok {
		t.Fatalf("abandon: %v %v", ok, err)
	}
	oldVaultIn(t, cfg.DataDir, old)
	if !hasCredential(t, cfg, cfg.DataDir, "added in the backup") {
		t.Error("the change made in the backup is gone")
	}
}

// A backup changed after the swap is not deleted by --discard-old: the
// resume refuses with ErrForkStale, and --keep-old finishes the fork and
// keeps it, change and all. Once the fork is done, the backup opens (P1).
func TestForkKeepsABackupChangedAfterTheSwap(t *testing.T) {
	ctx := context.Background()
	x := forkFixture(t)
	cfg := x.f.cfg
	old := idsOf(t, cfg)
	crashForkAt(t, cfg, "fork:moved-new", true)
	backup := onlyBackup(t, cfg)
	changeBackup(t, cfg, backup, "added after the swap")
	if _, _, err := ResumeFork(ctx, cfg, ForkOptions{}); !errors.Is(err, ErrForkStale) {
		t.Fatalf("resume after a change to the backup: %v, want ErrForkStale", err)
	}
	oldVaultIn(t, backup, old)
	if pending, err := ForkInProgress(cfg.DataDir); err != nil || !pending {
		t.Errorf("in progress after the refusal: %v %v", pending, err)
	}
	res, _, err := ResumeFork(ctx, cfg, ForkOptions{KeepOld: true})
	if err != nil || res == nil || res.Discarded {
		t.Fatalf("resume with KeepOld: %+v %v", res, err)
	}
	if !hasCredential(t, cfg, backup, "added after the swap") {
		t.Error("the change made in the backup is gone")
	}
	if s := open(t, cfg); s.Info().AccountID != res.New.AccountID.String() {
		t.Errorf("the new vault: %+v", s.Info())
	}
}

// --discard-old does not delete a backup a process has open: the resume is
// busy, and finishes once it is closed (P1).
func TestForkDiscardWaitsForTheBackupsOwner(t *testing.T) {
	ctx := context.Background()
	x := forkFixture(t)
	cfg := x.f.cfg
	old := idsOf(t, cfg)
	crashForkAt(t, cfg, "fork:moved-new", true)
	backup := onlyBackup(t, cfg)
	owner, err := filelock.TryLock(layout{data: backup}.ownerLock())
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := ResumeFork(ctx, cfg, ForkOptions{}); !errors.Is(err, ErrVaultBusy) {
		t.Fatalf("resume with the backup owned: %v, want ErrVaultBusy", err)
	}
	oldVaultIn(t, backup, old)
	if _, err := cfg.Keyring.Get(keychainService, slotOf(old.acct, old.dev)); err != nil {
		t.Errorf("the old device key: %v", err)
	}
	owner.Close()
	if res, _, err := ResumeFork(ctx, cfg, ForkOptions{}); err != nil || res == nil || !res.Discarded {
		t.Fatalf("resume: %+v %v", res, err)
	}
	if _, err := os.Lstat(backup); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("the backup: %v", err)
	}
}

// A backup with no device.json is not identified as the old vault, and is
// not deleted (P2). Once the deletion was recorded as begun, a resume
// tolerates the identity files a cut-short deletion removed, and finishes.
func TestForkDiscardIdentifiesTheBackup(t *testing.T) {
	ctx := context.Background()
	t.Run("unidentified", func(t *testing.T) {
		x := forkFixture(t)
		cfg := x.f.cfg
		crashForkAt(t, cfg, "fork:moved-new", true)
		backup := onlyBackup(t, cfg)
		if err := os.Remove(layout{data: backup}.deviceConfig()); err != nil {
			t.Fatal(err)
		}
		if _, _, err := ResumeFork(ctx, cfg, ForkOptions{}); !errors.Is(err, ErrForkDamaged) {
			t.Fatalf("resume with an unidentified backup: %v, want ErrForkDamaged", err)
		}
		if _, err := os.Lstat(layout{data: backup}.vault()); err != nil {
			t.Errorf("the backup's vault: %v", err)
		}
	})
	t.Run("partly deleted", func(t *testing.T) {
		x := forkFixture(t)
		cfg := x.f.cfg
		old := idsOf(t, cfg)
		crashForkAt(t, cfg, "fork:discarding", true)
		j, err := readForkJournal(cfg.DataDir)
		if err != nil || j == nil || !j.Discarding || j.Discarded {
			t.Fatalf("the journal at the crash: %+v %v", j, err)
		}
		backup := onlyBackup(t, cfg)
		for _, f := range []string{layout{data: backup}.deviceConfig(), filepath.Join(layout{data: backup}.vault(), "state.json")} {
			if err := os.Remove(f); err != nil {
				t.Fatal(err)
			}
		}
		res, _, err := ResumeFork(ctx, cfg, ForkOptions{})
		if err != nil || res == nil || !res.Discarded {
			t.Fatalf("resume of the deletion: %+v %v", res, err)
		}
		if _, err := os.Lstat(backup); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("the backup: %v", err)
		}
		if _, err := cfg.Keyring.Get(keychainService, slotOf(old.acct, old.dev)); err == nil {
			t.Error("the old device key is still in the keychain")
		}
	})
}

// A commit whose last journal write was renamed into place but whose
// directory sync failed reports an error with the fork in fact done: it is
// not Abandoned, so hop vault fork keeps the Emergency Kit file (P1). A
// commit whose staging failed and was deleted is Abandoned.
func TestForkCommitOutcome(t *testing.T) {
	ctx := context.Background()
	t.Run("final sync fails", func(t *testing.T) {
		x := forkFixture(t)
		cfg := x.f.cfg
		data, _, err := forkPaths(cfg.DataDir)
		if err != nil {
			t.Fatal(err)
		}
		release(cfg)
		p, err := PrepareFork(ctx, cfg, ForkOptions{})
		if err != nil {
			t.Fatal(err)
		}
		defer p.Close()
		if _, err := p.Generate([]byte(forkPassword), ""); err != nil {
			t.Fatal(err)
		}
		failed := false
		syncDir = func(dir string) error {
			if j, err := readForkJournal(dir); dir == data && err == nil && j != nil && j.State == forkDone {
				failed = true
				return errors.New("injected: the directory sync failed")
			}
			return fsyncDir(dir)
		}
		t.Cleanup(func() { syncDir = fsyncDir })
		_, err = p.Commit(ctx, false)
		syncDir = fsyncDir
		p.Close()
		if err == nil || !failed {
			t.Fatalf("commit: %v (sync failed %v)", err, failed)
		}
		if p.Abandoned() {
			t.Error("a fork that is done reports Abandoned")
		}
		if pending, err := ForkInProgress(cfg.DataDir); err != nil || pending {
			t.Errorf("in progress: %v %v", pending, err)
		}
		rec, err := ForkRecord(cfg.DataDir)
		if err != nil || rec == nil {
			t.Fatalf("the record: %+v %v", rec, err)
		}
		if s := open(t, cfg); s.Info().AccountID != rec.New.AccountID.String() {
			t.Errorf("the vault in the data directory: %+v; the fork made %s", s.Info(), rec.New.AccountID)
		}
	})
	t.Run("staging fails", func(t *testing.T) {
		x := forkFixture(t)
		cfg := x.f.cfg
		old := idsOf(t, cfg)
		release(cfg)
		p, err := PrepareFork(ctx, cfg, ForkOptions{})
		if err != nil {
			t.Fatal(err)
		}
		defer p.Close()
		if _, err := p.Generate([]byte(forkPassword), ""); err != nil {
			t.Fatal(err)
		}
		forkHook = func(s string) error {
			if s == "fork:imported" {
				return errors.New("injected: the import failed")
			}
			return nil
		}
		t.Cleanup(func() { forkHook = nil })
		if _, err := p.Commit(ctx, false); err == nil {
			t.Fatal("commit succeeded")
		}
		forkHook = nil
		if !p.Abandoned() {
			t.Error("a fork whose staging was deleted is not Abandoned")
		}
		if _, err := os.Lstat(cfg.DataDir + forkNewSuffix); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("the staging directory: %v", err)
		}
		oldVaultIn(t, cfg.DataDir, old)
	})
}

// A predecessor write no store owns the vault for is refused while a fork
// is unfinished, before and after the swap, so it can't write the old
// vault's entries into the new data directory (P2).
func TestForkFencesPredecessorWrites(t *testing.T) {
	ctx := context.Background()
	for _, stage := range []string{"fork:verified", "fork:moved-new"} {
		t.Run(stage, func(t *testing.T) {
			x := forkFixture(t)
			cfg := x.f.cfg
			p := Predecessor{AccountID: model.ID{1}, DeviceID: model.ID{2, 1}, Outcome: OutcomeUnknown, At: 1000}
			if err := recordPredecessor(cfg.DataDir, p); err != nil {
				t.Fatal(err)
			}
			crashForkAt(t, cfg, stage, false)
			if err := ForgetPredecessor(cfg.DataDir, p.DeviceID); !errors.Is(err, ErrForkPending) {
				t.Errorf("forget during the fork: %v, want ErrForkPending", err)
			}
			if err := MarkPredecessorReported(cfg.DataDir, p.DeviceID, AdviceRevoke); !errors.Is(err, ErrForkPending) {
				t.Errorf("mark during the fork: %v, want ErrForkPending", err)
			}
			res, _, err := ResumeFork(ctx, cfg, ForkOptions{})
			if err != nil || res == nil {
				t.Fatalf("resume: %+v %v", res, err)
			}
			if got, err := ReadPredecessors(cfg.DataDir); err != nil || len(got) != 0 {
				t.Errorf("the new vault's predecessors: %+v %v", got, err)
			}
			if got, err := ReadPredecessors(res.Backup); err != nil || len(got) != 1 {
				t.Errorf("the backup's predecessors: %+v %v", got, err)
			}
		})
	}
}

// A predecessor write paused between its read and its write holds off a
// fork: the fork can't swap the data directory under it (P2).
func TestPredecessorWriteHoldsOffAFork(t *testing.T) {
	ctx := context.Background()
	x := forkFixture(t)
	cfg := x.f.cfg
	a := Predecessor{AccountID: model.ID{1}, DeviceID: model.ID{2, 1}, Outcome: OutcomeUnknown, At: 1000}
	b := Predecessor{AccountID: model.ID{1}, DeviceID: model.ID{2, 2}, Outcome: OutcomeUnknown, At: 1001}
	for _, e := range []Predecessor{a, b} {
		if err := recordPredecessor(cfg.DataDir, e); err != nil {
			t.Fatal(err)
		}
	}
	var forkErr error
	predecessorRMWHook = func() {
		predecessorRMWHook = nil
		release(cfg)
		var p *PendingFork
		if p, forkErr = PrepareFork(ctx, cfg, ForkOptions{}); forkErr != nil {
			return
		}
		defer p.Close()
		if _, forkErr = p.Generate([]byte(forkPassword), ""); forkErr == nil {
			_, forkErr = p.Commit(ctx, false)
		}
	}
	t.Cleanup(func() { predecessorRMWHook = nil })
	if err := ForgetPredecessor(cfg.DataDir, a.DeviceID); err != nil {
		t.Fatal(err)
	}
	if !errors.Is(forkErr, ErrVaultBusy) {
		t.Errorf("a fork during the write: %v, want ErrVaultBusy", forkErr)
	}
	if got, err := ReadPredecessors(cfg.DataDir); err != nil || len(got) != 1 || got[0].DeviceID != b.DeviceID {
		t.Fatalf("after the forget: %+v %v", got, err)
	}
	if rec, _ := ForkRecord(cfg.DataDir); rec == nil {
		res := fork(t, cfg, false)
		if got, err := ReadPredecessors(res.Backup); err != nil || len(got) != 1 {
			t.Errorf("the backup's predecessors: %+v %v", got, err)
		}
	}
	if got, err := ReadPredecessors(cfg.DataDir); err != nil || len(got) != 0 {
		t.Errorf("the new vault's predecessors: %+v %v", got, err)
	}
}
