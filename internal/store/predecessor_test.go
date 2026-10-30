package store

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/dalyem/hopkey/internal/model"
	"github.com/dalyem/hopkey/internal/vaultlog"
)

// A2b option E: the note a logout leaves for the next sign-in.

// blockedRetirer is the fake server for a device its operator blocked: no
// session is granted (the refusal comes first, as for a real block), and
// retire-status and retire-post stay open.
type blockedRetirer struct{ retirer }

func (b blockedRetirer) Since(context.Context, DeviceAuth, uint64) ([]Committed, vaultlog.Head, error) {
	return nil, vaultlog.Head{}, &AdminRefusal{Code: AdminDeviceBlocked}
}

func (b blockedRetirer) Post(context.Context, DeviceAuth, *vaultlog.Wire) (vaultlog.Head, error) {
	return vaultlog.Head{}, &AdminRefusal{Code: AdminDeviceBlocked}
}

func (b blockedRetirer) Reauthenticate(context.Context, DeviceAuth) error {
	return &AdminRefusal{Code: AdminDeviceBlocked}
}

func onlyPredecessor(t *testing.T, cfg Config) Predecessor {
	t.Helper()
	got, err := ReadPredecessors(cfg.DataDir)
	if err != nil || len(got) != 1 {
		t.Fatalf("predecessors %+v, %v; want exactly one", got, err)
	}
	return got[0]
}

// A --local-only logout never tells the server, so the old ID may still
// be in the account: the data directory keeps its ID, the account and
// the server, the number of changes the logout discarded, and that the
// server was not told.
func TestLocalOnlyLogoutLeavesAPredecessor(t *testing.T) {
	ctx := context.Background()
	f, _ := retireFixture(t)
	who := idsOf(t, f.cfg)
	si, err := f.s.ServerInfo()
	if err != nil {
		t.Fatal(err)
	}
	newCredential(t, f.s, "queued 1")
	newCredential(t, f.s, "queued 2")
	pc, err := f.s.PendingChanges()
	if err != nil || pc.Queued != 2 || !pc.HeldKnown || pc.Held != 0 {
		t.Fatalf("pending before the logout: %+v, %v", pc, err)
	}
	res, err := f.s.Logout(ctx, nil, LogoutOptions{LocalOnly: true, DiscardPending: true})
	if err != nil || !res.Done || res.Discarded != 2 {
		t.Fatalf("logout: %+v, %v", res, err)
	}
	loggedOut(t, f.cfg, who)
	p := onlyPredecessor(t, f.cfg)
	if p.DeviceID != who.dev || p.AccountID != who.acct || p.Outcome != OutcomeUnknown || p.Queued != 2 || p.Why != "" ||
		p.Server != si.Server || p.Email != si.Email || p.At == 0 {
		t.Errorf("predecessor %+v; want device %v of account %v, unknown, 2 queued, server %q", p, who.dev, who.acct, si.Server)
	}
}

// A device the operator locked out leaves a note even when the server
// takes the retirement: the new device still has to decide whether to
// rekey, and the changes it held are gone either way.
func TestLogoutOfAnAdminLockedDeviceLeavesAPredecessorEvenWhenRetired(t *testing.T) {
	ctx := context.Background()
	f, srv := retireFixture(t)
	who := idsOf(t, f.cfg)
	newCredential(t, f.s, "queued")
	res, err := f.s.Logout(ctx, blockedRetirer{retirer{srv}}, LogoutOptions{DiscardPending: true, Why: AdminDeviceBlocked})
	if err != nil || !res.Done || res.Outcome != OutcomeCommitted || res.RevokeElsewhere || res.Discarded != 1 {
		t.Fatalf("logout: %+v, %v", res, err)
	}
	if how := retiredOnServer(t, srv, who.dev); how != "retired" {
		t.Errorf("the server says %q; a blocked device's own retirement is open to it", how)
	}
	loggedOut(t, f.cfg, who)
	p := onlyPredecessor(t, f.cfg)
	if p.DeviceID != who.dev || p.Outcome != OutcomeCommitted || p.Why != AdminDeviceBlocked || p.Queued != 1 {
		t.Errorf("predecessor %+v", p)
	}
}

// An ordinary logout leaves nothing, and an unknown reason is not
// recorded as one.
func TestPlainLogoutLeavesNoPredecessor(t *testing.T) {
	ctx := context.Background()
	f, srv := retireFixture(t)
	who := idsOf(t, f.cfg)
	if res, err := f.s.Logout(ctx, retirer{srv}, LogoutOptions{Why: "no such code"}); err != nil || !res.Done {
		t.Fatalf("logout: %+v, %v", res, err)
	}
	loggedOut(t, f.cfg, who)
	if got, err := ReadPredecessors(f.cfg.DataDir); err != nil || len(got) != 0 {
		t.Errorf("predecessors %+v, %v", got, err)
	}
	if _, err := os.Stat(filepath.Join(f.cfg.DataDir, predecessorName)); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("%s: %v", predecessorName, err)
	}
}

// A refused logout (queued changes, no --discard-pending) changes
// nothing: no journal, no note, the vault still unlocked.
func TestRefusedLogoutLeavesNoNote(t *testing.T) {
	ctx := context.Background()
	f, srv := retireFixture(t)
	newCredential(t, f.s, "queued")
	if _, err := f.s.Logout(ctx, retirer{srv}, LogoutOptions{Why: AdminDeviceBlocked}); !errors.Is(err, ErrOutboxNotEmpty) {
		t.Fatalf("logout: %v", err)
	}
	if _, err := os.Stat(filepath.Join(f.cfg.DataDir, "vault", retireNoteRel)); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("a refused logout wrote a note: %v", err)
	}
	if f.s.Info().Locked {
		t.Error("a refused logout locked the vault")
	}
	if pc, err := f.s.PendingChanges(); err != nil || pc.Queued != 1 {
		t.Errorf("pending after a refusal: %+v, %v", pc, err)
	}
}

// A logout that is pending (the server unreachable, then --local-only)
// keeps the counts and the reason from when it began: the retry runs
// with no daemon to ask and an outbox the journal no longer shows.
func TestPendingLogoutKeepsItsNoteThroughLocalOnly(t *testing.T) {
	ctx := context.Background()
	f, srv := retireFixture(t)
	who := idsOf(t, f.cfg)
	newCredential(t, f.s, "queued")
	srv.down = errDown
	if _, err := f.s.Logout(ctx, retirer{srv}, LogoutOptions{DiscardPending: true, Why: AdminDeviceBlocked}); !errors.Is(err, ErrLogoutPending) {
		t.Fatalf("logout with the server down: %v", err)
	}
	s, err := tryOpen(t, f.cfg)
	if err != nil {
		t.Fatal(err)
	}
	res, err := s.Logout(ctx, nil, LogoutOptions{LocalOnly: true})
	if err != nil || !res.Done || res.Outcome != OutcomeUnknown || res.Discarded != 1 {
		t.Fatalf("--local-only from RETIRING: %+v, %v", res, err)
	}
	loggedOut(t, f.cfg, who)
	if p := onlyPredecessor(t, f.cfg); p.Why != AdminDeviceBlocked || p.Queued != 1 || p.Outcome != OutcomeUnknown {
		t.Errorf("predecessor %+v", p)
	}
}

// A crash anywhere in the cleanup of a RETIRED logout still leaves
// exactly one note: it is written before the first thing is deleted, and
// the resumed cleanup rewrites it without duplicating it.
func TestPredecessorSurvivesACrashInTheCleanup(t *testing.T) {
	for _, stage := range []string{"retire:outbox", "retire:cache", "retire:device", "retire:journal"} {
		t.Run(stage, func(t *testing.T) {
			ctx := context.Background()
			f, _ := retireFixture(t)
			who := idsOf(t, f.cfg)
			newCredential(t, f.s, "queued")
			f.s.testHook = crashAt(stage)
			if _, err := f.s.Logout(ctx, nil, LogoutOptions{LocalOnly: true, DiscardPending: true, Why: AdminAccountDisabled}); !errors.Is(err, errCrash) {
				t.Fatalf("logout: %v", err)
			}
			if _, err := tryOpen(t, f.cfg); !errors.Is(err, ErrLoggedOut) {
				t.Fatalf("open after the crash: %v", err)
			}
			loggedOut(t, f.cfg, who)
			p := onlyPredecessor(t, f.cfg)
			if p.DeviceID != who.dev || p.Queued != 1 || p.Why != AdminAccountDisabled || p.Outcome != OutcomeUnknown {
				t.Errorf("predecessor %+v", p)
			}
		})
	}
}

// A record that does not parse must not keep a logout from finishing: it
// is replaced, and the note of this logout is what remains.
func TestCorruptPredecessorRecordDoesNotBlockALogout(t *testing.T) {
	ctx := context.Background()
	f, _ := retireFixture(t)
	who := idsOf(t, f.cfg)
	if err := os.WriteFile(filepath.Join(f.cfg.DataDir, predecessorName), []byte("not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadPredecessors(f.cfg.DataDir); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("read of a corrupt record: %v", err)
	}
	if res, err := f.s.Logout(ctx, nil, LogoutOptions{LocalOnly: true}); err != nil || !res.Done {
		t.Fatalf("logout: %+v, %v", res, err)
	}
	loggedOut(t, f.cfg, who)
	if p := onlyPredecessor(t, f.cfg); p.DeviceID != who.dev {
		t.Errorf("predecessor %+v", p)
	}
}

// The record keeps one entry per device, the newest eight in all, and
// ForgetPredecessor removes one entry, or the file with the last.
func TestPredecessorRecordBookkeeping(t *testing.T) {
	dir := t.TempDir()
	acct := model.ID{1}
	mk := func(n byte) Predecessor {
		return Predecessor{AccountID: acct, DeviceID: model.ID{2, n}, Server: "https://hop.example", Email: "a@example.com",
			Outcome: OutcomeUnknown, Queued: int(n), At: model.Timestamp(1000 + int64(n))}
	}
	for n := byte(1); n <= 10; n++ {
		if err := recordPredecessor(dir, mk(n)); err != nil {
			t.Fatal(err)
		}
	}
	got, err := ReadPredecessors(dir)
	if err != nil || len(got) != maxPredecessors || got[0] != mk(3) || got[len(got)-1] != mk(10) {
		t.Fatalf("after ten: %d entries, %v", len(got), err)
	}
	// The same device again replaces its entry and moves it to the end.
	again := mk(5)
	again.Queued = 99
	if err := recordPredecessor(dir, again); err != nil {
		t.Fatal(err)
	}
	got, _ = ReadPredecessors(dir)
	if len(got) != maxPredecessors || got[len(got)-1] != again {
		t.Errorf("after a repeat: %+v", got)
	}
	if err := ForgetPredecessor(dir, model.ID{2, 5}); err != nil {
		t.Fatal(err)
	}
	if got, _ = ReadPredecessors(dir); len(got) != maxPredecessors-1 {
		t.Errorf("after forgetting one: %d entries", len(got))
	}
	if err := ForgetPredecessor(dir, model.ID{9}); err != nil {
		t.Errorf("forgetting an unknown device: %v", err)
	}
	for _, e := range got {
		if err := ForgetPredecessor(dir, e.DeviceID); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := os.Stat(filepath.Join(dir, predecessorName)); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("the record is still there after the last entry: %v", err)
	}
	if got, err = ReadPredecessors(dir); err != nil || len(got) != 0 {
		t.Errorf("an empty record: %+v, %v", got, err)
	}
}

// PendingChanges counts the queue from file names while the vault is
// locked, and says it can't tell the held ones then.
func TestPendingChangesWhileLocked(t *testing.T) {
	f, _ := retireFixture(t)
	if pc, err := f.s.PendingChanges(); err != nil || pc.Queued != 0 || !pc.HeldKnown {
		t.Errorf("an empty queue: %+v, %v", pc, err)
	}
	newCredential(t, f.s, "a")
	newCredential(t, f.s, "b")
	f.s.Lock()
	pc, err := f.s.PendingChanges()
	if err != nil || pc.Queued != 2 || pc.HeldKnown {
		t.Errorf("locked: %+v, %v", pc, err)
	}
}

// A held change is counted among the queued ones, in the note too: the
// user is told how many changes the logout throws away and how many of
// them were waiting for a decision.
func TestHeldChangesAreCountedAndRecorded(t *testing.T) {
	ctx := context.Background()
	p := newPair(t)
	p.unitConflict(t)
	newCredential(t, p.a.s, "behind the held one")
	pc, err := p.a.s.PendingChanges()
	if err != nil || pc.Queued != 2 || pc.Held != 1 || !pc.HeldKnown {
		t.Fatalf("pending: %+v, %v", pc, err)
	}
	who := idsOf(t, p.a.cfg)
	res, err := p.a.s.Logout(ctx, nil, LogoutOptions{LocalOnly: true, DiscardPending: true})
	if err != nil || !res.Done || res.Discarded != 2 {
		t.Fatalf("logout: %+v, %v", res, err)
	}
	loggedOut(t, p.a.cfg, who)
	if got := onlyPredecessor(t, p.a.cfg); got.Queued != 2 || got.Held != 1 {
		t.Errorf("predecessor %+v", got)
	}
}
