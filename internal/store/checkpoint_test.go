package store

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/dalyem/hopkey/internal/crypto"
	"github.com/dalyem/hopkey/internal/model"
	"github.com/dalyem/hopkey/internal/vaultlog"
)

// Slice E2: checkpoints through the server (§10.1, §5.4).

// crashAtN fails the nth time stage is reached (1-based), once.
func crashAtN(stage string, n int) func(string) error {
	seen := 0
	return func(s string) error {
		if s == stage {
			seen++
			if seen == n {
				return errCrash
			}
		}
		return nil
	}
}

// deviceID is s's device.
func deviceID(t *testing.T, s *Store) model.ID {
	t.Helper()
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.dev == nil {
		t.Fatal("the store is locked")
	}
	return s.dev.ID
}

// serverActive reports whether device id is active at r's head.
func serverActive(t *testing.T, r *fakeRemote, id model.ID) bool {
	t.Helper()
	r.mu.Lock()
	defer r.mu.Unlock()
	pub, err := r.publicLocked()
	if err != nil {
		t.Fatal(err)
	}
	return pub.DeviceActive(id)
}

// serverCheckpoints counts the checkpoints in r's log.
func serverCheckpoints(t *testing.T, r *fakeRemote) int {
	t.Helper()
	cs, _, err := r.Since(context.Background(), 0)
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	for _, c := range cs {
		if c.Wire.Entry.Kind == vaultlog.KindCheckpoint {
			n++
		}
	}
	return n
}

// secondDeviceNamed is secondDevice with the new device named name.
func secondDeviceNamed(t *testing.T, f *fixture, r *fakeRemote, name string) *fixture {
	t.Helper()
	ctx := context.Background()
	pull(t, f.s, r)
	cfg := testConfig(t)
	cfg.DeviceName = name
	copyDir(t, f.cfg.DataDir, cfg.DataDir)
	if err := os.Remove(filepath.Join(cfg.DataDir, "device.key")); err != nil && !errors.Is(err, os.ErrNotExist) {
		t.Fatal(err)
	}
	b, err := Open(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	track(t, cfg, b)
	if err := b.UnlockWithPasswordRemote(ctx, r, []byte(testPassword), f.kit.SecretKey); err != nil {
		t.Fatal(err)
	}
	pull(t, f.s, r)
	return &fixture{cfg: cfg, kit: f.kit, s: b}
}

// newCkptPair is a server-backed vault with a host and a second device.
func newCkptPair(t *testing.T) (*fixture, *fixture, *fakeRemote) {
	t.Helper()
	a, r := serverVault(t)
	addHost(t, a.s, "web")
	if res := pushAll(t, a.s, r); res.Outcome != PushEmpty {
		t.Fatalf("push: %+v", res)
	}
	b := secondDevice(t, a, r)
	pull(t, b.s, r)
	return a, b, r
}

// opensAccount reports whether password and sk open the account at s's
// verified head.
func opensAccount(t *testing.T, s *Store, password, sk string) bool {
	t.Helper()
	parsed, err := crypto.ParseSecretKey(sk)
	if err != nil {
		t.Fatal(err)
	}
	s.mu.Lock()
	a, err := accountOf(s.state, objectDir(s.l.objects()))
	s.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	acct, err := openWithPassword(a, []byte(password), &parsed)
	if err != nil {
		return false
	}
	acct.Zero()
	return true
}

func journalExists(t *testing.T, cfg Config) bool {
	t.Helper()
	ok, err := layout{data: cfg.DataDir}.checkpointExists()
	if err != nil {
		t.Fatal(err)
	}
	return ok
}

// storedSecretKey is the Secret Key in s's device record in the keychain.
func storedSecretKey(t *testing.T, cfg Config, s *Store) string {
	t.Helper()
	s.mu.Lock()
	ds := s.deviceStore(s.devCfg)
	id := s.dev.ID
	s.mu.Unlock()
	rec, err := ds.loadID(id)
	if err != nil {
		t.Fatal(err)
	}
	defer rec.zero()
	return rec.SecretKey
}

// A password change keeps every active device (§10.1): both stay active,
// the other device crosses the checkpoint with its new unlock blob, and the
// new password with the new Secret Key opens the account. The kit is
// pending from the verified commit until AckKit.
func TestCheckpointPasswordChangeKeepsEveryDevice(t *testing.T) {
	ctx := context.Background()
	a, b, r := newCkptPair(t)
	aID, bID := deviceID(t, a.s), deviceID(t, b.s)
	kit, err := a.s.ChangePasswordRemote(ctx, r, []byte(testPassword), []byte(newPassword), CheckpointOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if serverCheckpoints(t, r) != 1 {
		t.Fatalf("%d checkpoints on the server", serverCheckpoints(t, r))
	}
	if !serverActive(t, r, aID) || !serverActive(t, r, bID) {
		t.Error("a password change revoked a device")
	}
	if kit.SecretKey == a.kit.SecretKey || kit.AccountID != a.kit.AccountID {
		t.Errorf("kit %+v", kit)
	}
	if p := a.s.PendingKit(); p == nil || p.SecretKey != kit.SecretKey {
		t.Fatalf("pending kit %+v", p)
	}
	if !opensAccount(t, a.s, newPassword, kit.SecretKey) || opensAccount(t, a.s, testPassword, a.kit.SecretKey) {
		t.Error("the new credentials are not the account's")
	}
	if headOf(t, a.s) != (Head{Seq: r.head().Seq, H: r.head().H.String()}) {
		t.Error("this device did not install the verified checkpoint")
	}
	// The other device crosses it with its new unlock blob.
	pull(t, b.s, r)
	if headOf(t, b.s) != headOf(t, a.s) {
		t.Fatal("the other device is not at the checkpoint")
	}
	b.s.mu.Lock()
	akv := b.s.sec.Account.AKV
	b.s.mu.Unlock()
	if akv != 2 {
		t.Errorf("the other device holds account keys %d", akv)
	}
	hostNamed(t, snapshot(t, b.s), "web")
	if open(t, b.cfg).Info().Locked {
		t.Error("the other device does not unlock after a restart")
	}
	// The kit stays pending until AckKit, across a restart.
	a.s = open(t, a.cfg)
	if p := a.s.PendingKit(); p == nil || p.SecretKey != kit.SecretKey {
		t.Fatalf("pending kit after a restart %+v", p)
	}
	if !journalExists(t, a.cfg) {
		t.Fatal("the journal went before the kit was acknowledged")
	}
	if err := a.s.AckKit(); err != nil {
		t.Fatal(err)
	}
	if journalExists(t, a.cfg) || a.s.PendingKit() != nil {
		t.Error("AckKit left the journal or the kit")
	}
	if got := storedSecretKey(t, a.cfg, a.s); got != kit.SecretKey {
		t.Error("the device record does not hold the new Secret Key")
	}
	// Local-only ChangePassword is unchanged: refused here.
	if _, err := a.s.ChangePassword(ctx, []byte(newPassword), []byte(testPassword)); !errors.Is(err, ErrServerBacked) {
		t.Errorf("local ChangePassword on a server-backed vault: %v", err)
	}
	// A wrong current password writes nothing.
	n := r.postCount()
	if _, err := a.s.ChangePasswordRemote(ctx, r, []byte("wrong password here"), []byte(testPassword), CheckpointOptions{}); !errors.Is(err, ErrWrongPassword) {
		t.Errorf("wrong password: %v", err)
	}
	if r.postCount() != n || journalExists(t, a.cfg) {
		t.Error("a wrong password posted or journaled")
	}
}

// Rotate keeps this device and the devices kept by ID or unique name; every
// other device is revoked, and a revoked device's vault is terminal (§5.5).
func TestCheckpointRotateKeepByID(t *testing.T) {
	ctx := context.Background()
	a, b, r := newCkptPair(t)
	c := secondDeviceNamed(t, a, r, "laptop")
	pull(t, b.s, r)
	aID, bID, cID := deviceID(t, a.s), deviceID(t, b.s), deviceID(t, c.s)
	kit, err := a.s.Rotate(ctx, r, []byte(testPassword), CheckpointOptions{Keep: []string{bID.String()}})
	if err != nil {
		t.Fatal(err)
	}
	if !serverActive(t, r, aID) || !serverActive(t, r, bID) || serverActive(t, r, cID) {
		t.Fatalf("active: a %v b %v c %v", serverActive(t, r, aID), serverActive(t, r, bID), serverActive(t, r, cID))
	}
	// The password stays; the Secret Key is new.
	if !opensAccount(t, a.s, testPassword, kit.SecretKey) {
		t.Error("the rotated credentials do not open with the same password")
	}
	pull(t, b.s, r)
	hostNamed(t, snapshot(t, b.s), "web")
	// The revoked device meets the checkpoint and is terminal (D1).
	if err := c.s.Pull(ctx, r); !errors.Is(err, ErrDeviceRevoked) {
		t.Fatalf("revoked device's pull: %v", err)
	}
	if !c.s.IsRevoked() {
		t.Error("the revoked device is not marked revoked")
	}
	if info := open(t, c.cfg).Info(); !info.Locked || !info.Revoked {
		t.Errorf("revoked device after a restart: %+v", info)
	}
	if err := a.s.AckKit(); err != nil {
		t.Fatal(err)
	}
	// By default only this device survives.
	kit2, err := a.s.Rotate(ctx, r, []byte(testPassword), CheckpointOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if serverActive(t, r, bID) || !serverActive(t, r, aID) {
		t.Error("a rotation with no --keep did not revoke the other device")
	}
	if kit2.SecretKey == kit.SecretKey {
		t.Error("the second rotation reused the Secret Key")
	}
}

// --keep resolves a name only when exactly one active device has it
// (§10.1); an ambiguous or unknown name is refused before anything is
// journaled or posted.
func TestCheckpointKeepByName(t *testing.T) {
	ctx := context.Background()
	a, b, r := newCkptPair(t)
	c := secondDeviceNamed(t, a, r, "laptop")
	bID, cID := deviceID(t, b.s), deviceID(t, c.s)
	n := r.postCount()
	// Both a and b are "test device".
	if _, err := a.s.Rotate(ctx, r, []byte(testPassword), CheckpointOptions{Keep: []string{"test device"}}); !errors.Is(err, ErrAmbiguousDevice) {
		t.Errorf("ambiguous name: %v", err)
	}
	if _, err := a.s.Rotate(ctx, r, []byte(testPassword), CheckpointOptions{Keep: []string{"phone"}}); !errors.Is(err, ErrUnknownDevice) {
		t.Errorf("unknown name: %v", err)
	}
	other, _ := vaultlog.NewID()
	if _, err := a.s.Rotate(ctx, r, []byte(testPassword), CheckpointOptions{Keep: []string{other.String()}}); !errors.Is(err, ErrUnknownDevice) {
		t.Errorf("unknown ID: %v", err)
	}
	if r.postCount() != n || journalExists(t, a.cfg) {
		t.Fatal("a refused --keep posted or journaled")
	}
	if ids, err := a.s.ResolveDevices([]string{"laptop", cID.String()}); err != nil || !slices.Equal(ids, []model.ID{cID}) {
		t.Errorf("resolve: %v %v", ids, err)
	}
	if _, err := a.s.Rotate(ctx, r, []byte(testPassword), CheckpointOptions{Keep: []string{"laptop"}}); err != nil {
		t.Fatal(err)
	}
	if !serverActive(t, r, cID) || serverActive(t, r, bID) {
		t.Error("--keep by name kept the wrong device")
	}
}

// A 409 rebuilds the checkpoint with fresh secrets and the journaled
// survivors: a device that first appeared meanwhile is revoked (§10.1).
func TestCheckpointRebuildExcludesNewDevice(t *testing.T) {
	ctx := context.Background()
	a, b, r := newCkptPair(t)
	aID, bID := deviceID(t, a.s), deviceID(t, b.s)
	var newID model.ID
	var first crypto.Hash
	a.s.testHook = func(stage string) error {
		if stage != "checkpoint:post" || !newID.IsZero() {
			return nil
		}
		// Another device adds a device first (a bootstrap), named like the
		// others.
		pull(t, b.s, r)
		_, info, err := newDeviceRecord(accountOfKit(t, a), a.kit.SecretKey)
		if err != nil {
			return err
		}
		info.Name = "test device"
		b.s.mu.Lock()
		w, _, _, err := vaultlog.BuildBootstrap(b.s.state, b.s.sec, info, b.s.now())
		b.s.mu.Unlock()
		if err != nil {
			return err
		}
		if _, err := r.commit(w); err != nil {
			return err
		}
		newID = info.ID
		st, _ := a.s.pendingForTest(t)
		first = st
		return nil
	}
	kit, err := a.s.Rotate(ctx, r, []byte(testPassword), CheckpointOptions{Keep: []string{bID.String()}})
	if err != nil {
		t.Fatal(err)
	}
	if newID.IsZero() {
		t.Fatal("no device appeared")
	}
	if !serverActive(t, r, aID) || !serverActive(t, r, bID) || serverActive(t, r, newID) {
		t.Errorf("active: a %v b %v new %v", serverActive(t, r, aID), serverActive(t, r, bID), serverActive(t, r, newID))
	}
	if r.committed(first) {
		t.Error("the first candidate committed")
	}
	if serverCheckpoints(t, r) != 1 {
		t.Errorf("%d checkpoints", serverCheckpoints(t, r))
	}
	if !opensAccount(t, a.s, testPassword, kit.SecretKey) {
		t.Error("the kit is not the rebuilt checkpoint's")
	}
	// Only the committed candidate is left in the journal.
	if j := journalOf(t, a.s); len(j.Candidates) != 1 || j.Candidates[0].Status != statusCommitted {
		t.Fatalf("journal %+v", j)
	}
}

// journalOf opens s's checkpoint journal.
func journalOf(t *testing.T, s *Store) *ckptJournal {
	t.Helper()
	s.mu.Lock()
	defer s.mu.Unlock()
	unlock, err := s.lockFile()
	if err != nil {
		t.Fatal(err)
	}
	defer unlock()
	j, err := s.readCheckpointJournal(s.rec, s.state.VaultID)
	if err != nil || j == nil {
		t.Fatalf("journal %v %v", j, err)
	}
	return j
}

// pendingForTest returns the live candidate's H and seq.
func (s *Store) pendingForTest(t *testing.T) (crypto.Hash, uint64) {
	t.Helper()
	st, err := s.PendingCheckpoint()
	if err != nil || st == nil || st.Live == nil {
		t.Fatalf("pending checkpoint %+v %v", st, err)
	}
	var h crypto.Hash
	if err := h.UnmarshalText([]byte(st.Live.H)); err != nil {
		t.Fatal(err)
	}
	return h, st.Live.Seq
}

// An uncertain post (§5.4) leaves the candidate live: the next attempt
// posts the identical wire while the head is its prev. One that committed
// with its response lost is found by the pull, and posted no more.
func TestCheckpointUncertainPostRepostsIdenticalWire(t *testing.T) {
	ctx := context.Background()
	t.Run("lost before commit", func(t *testing.T) {
		a, _, r := newCkptPair(t)
		r.onPost = func(*vaultlog.Wire) (bool, error) { return false, errLostResponse }
		if _, err := a.s.Rotate(ctx, r, []byte(testPassword), CheckpointOptions{}); !errors.Is(err, errLostResponse) {
			t.Fatalf("lost post: %v", err)
		}
		h, _ := a.s.pendingForTest(t)
		if a.s.PendingKit() != nil {
			t.Fatal("a kit before the commit is verified")
		}
		r.onPost = nil
		n := r.postCount()
		kit, err := a.s.ResumeCheckpoint(ctx, r)
		if err != nil {
			t.Fatal(err)
		}
		r.mu.Lock()
		posted := slices.Clone(r.posts[n:])
		r.mu.Unlock()
		if len(posted) != 1 || !posted[0].Equal(h) || !r.committed(h) {
			t.Errorf("reposted %v; want the identical %v", posted, h)
		}
		if !opensAccount(t, a.s, testPassword, kit.SecretKey) {
			t.Error("the kit is not the committed candidate's")
		}
	})
	t.Run("committed, response lost", func(t *testing.T) {
		a, _, r := newCkptPair(t)
		r.onPost = func(*vaultlog.Wire) (bool, error) { return true, errLostResponse }
		if _, err := a.s.Rotate(ctx, r, []byte(testPassword), CheckpointOptions{}); !errors.Is(err, errLostResponse) {
			t.Fatalf("lost response: %v", err)
		}
		r.onPost = nil
		n := r.postCount()
		if a.s.PendingKit() != nil {
			t.Fatal("a kit before the commit is verified")
		}
		if _, err := a.s.ResumeCheckpoint(ctx, r); err != nil {
			t.Fatal(err)
		}
		if r.postCount() != n {
			t.Error("a committed candidate was posted again")
		}
	})
	t.Run("head moved", func(t *testing.T) {
		a, b, r := newCkptPair(t)
		bID := deviceID(t, b.s)
		r.onPost = func(w *vaultlog.Wire) (bool, error) {
			if w.Entry.Kind == vaultlog.KindCheckpoint {
				return false, errLostResponse
			}
			return true, nil
		}
		keep := CheckpointOptions{Keep: []string{bID.String()}}
		if _, err := a.s.Rotate(ctx, r, []byte(testPassword), keep); !errors.Is(err, errLostResponse) {
			t.Fatalf("lost post: %v", err)
		}
		first, _ := a.s.pendingForTest(t)
		// Another device writes first: the candidate can't commit now.
		addHost(t, b.s, "db")
		pushAll(t, b.s, r)
		r.onPost = nil
		if _, err := a.s.ResumeCheckpoint(ctx, r); !errors.Is(err, ErrCheckpointRebuild) {
			t.Fatalf("resume after the head moved: %v", err)
		}
		// The dead candidate stays until one commits (§5.4).
		if j := journalOf(t, a.s); len(j.Candidates) != 1 || j.Candidates[0].Status != statusDead || !j.Candidates[0].H.Equal(first) {
			t.Fatalf("journal after the head moved: %+v", j)
		}
		// Other survivors are refused: the journaled choice is reused.
		if _, err := a.s.Rotate(ctx, r, []byte(testPassword), CheckpointOptions{}); !errors.Is(err, ErrCheckpointPending) {
			t.Errorf("rotate with other survivors: %v", err)
		}
		if _, err := a.s.ChangePasswordRemote(ctx, r, []byte(testPassword), []byte(newPassword), CheckpointOptions{}); !errors.Is(err, ErrCheckpointPending) {
			t.Errorf("another kind: %v", err)
		}
		kit, err := a.s.Rotate(ctx, r, []byte(testPassword), keep)
		if err != nil {
			t.Fatal(err)
		}
		if r.committed(first) || !serverActive(t, r, bID) {
			t.Error("the rebuild did not keep the journaled survivors, or the dead candidate committed")
		}
		if !opensAccount(t, a.s, testPassword, kit.SecretKey) {
			t.Error("the kit is not the rebuilt candidate's")
		}
	})
}

// A crash at each step of the journal (§5.4, §10.1) leaves either nothing
// (the next call starts over) or a journal the next call, or a pull,
// settles: exactly one checkpoint commits, and its kit shows only once a
// pull has verified it.
func TestCheckpointCrashAtEachJournalStep(t *testing.T) {
	ctx := context.Background()
	cases := []struct {
		name      string
		hook      func(string) error
		journaled bool // a candidate is journaled after the crash
		committed bool // the server committed it before the crash
		installed bool // the restart finds it installed (the pull's commit replays)
	}{
		{"before the journal", crashAt("checkpoint:journal"), false, false, false},
		{"journal not installed", crashAtN("wal:install", 1), false, false, false},
		{"journal installed, not applied", crashAtN("wal:op:0", 1), true, false, false},
		{"journal applied, wal not removed", crashAtN("wal:removed", 1), true, false, false},
		{"before the post", crashAt("checkpoint:post"), true, false, false},
		{"after the post", crashAt("checkpoint:posted"), true, true, false},
		{"pull's commit installed", crashAtN("wal:op:0", 2), true, true, true},
		{"pull's commit applied", crashAtN("wal:removed", 2), true, true, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			a, _, r := newCkptPair(t)
			a.s.testHook = tc.hook
			if _, err := a.s.Rotate(ctx, r, []byte(testPassword), CheckpointOptions{}); err == nil {
				t.Fatal("no crash")
			}
			if got := serverCheckpoints(t, r); got != map[bool]int{false: 0, true: 1}[tc.committed] {
				t.Fatalf("%d checkpoints on the server", got)
			}
			s := open(t, a.cfg)
			if s.Info().Locked {
				t.Fatalf("locked after the restart: %s", s.Info().LockReason)
			}
			if journalExists(t, a.cfg) != tc.journaled {
				t.Fatalf("journal exists %v; want %v", !tc.journaled, tc.journaled)
			}
			if (s.PendingKit() != nil) != tc.installed {
				t.Fatalf("pending kit %v before any pull", s.PendingKit() != nil)
			}
			if tc.committed && !tc.installed {
				// Only verified history settles it: a pull shows the kit.
				pull(t, s, r)
				if s.PendingKit() == nil {
					t.Fatal("the pull did not settle the committed candidate")
				}
			}
			var kit Kit
			var err error
			if tc.journaled {
				kit, err = s.ResumeCheckpoint(ctx, r)
			} else {
				if _, rerr := s.ResumeCheckpoint(ctx, r); !errors.Is(rerr, ErrNoCheckpoint) {
					t.Errorf("resume with nothing journaled: %v", rerr)
				}
				kit, err = s.Rotate(ctx, r, []byte(testPassword), CheckpointOptions{})
			}
			if err != nil {
				t.Fatal(err)
			}
			if serverCheckpoints(t, r) != 1 {
				t.Errorf("%d checkpoints on the server", serverCheckpoints(t, r))
			}
			if !opensAccount(t, s, testPassword, kit.SecretKey) {
				t.Error("the kit is not the committed checkpoint's")
			}
			// The ack, crashing once, then for real.
			s.testHook = crashAt("kit:ack")
			if err := s.AckKit(); !errors.Is(err, errCrash) {
				t.Fatalf("ack: %v", err)
			}
			s = open(t, a.cfg)
			if p := s.PendingKit(); p == nil || p.SecretKey != kit.SecretKey {
				t.Fatalf("kit after a crash in the ack: %+v", p)
			}
			if err := s.AckKit(); err != nil {
				t.Fatal(err)
			}
			if journalExists(t, a.cfg) {
				t.Error("the journal outlived the ack")
			}
		})
	}
}

// §4.5: while a recovery's checkpoint is due, only RecoveryCheckpoint runs;
// it keeps only this device by default, and the commit that installs it,
// verified from the server, ends CheckpointDue, also when that commit is
// a pull after a crash.
func TestRecoveryCheckpointClearsDue(t *testing.T) {
	ctx := context.Background()
	d := newSignInFix(t)
	cfg := testConfig(t)
	p := d.params(t)
	p.Method = SignInRecovery
	s, res, err := SignIn(ctx, cfg, d.srv.login(t), p)
	if err != nil {
		t.Fatal(err)
	}
	track(t, cfg, s)
	if !res.CheckpointDue {
		t.Fatal("no checkpoint due")
	}
	if _, err := s.ChangePasswordRemote(ctx, d.r, []byte(testPassword), []byte(newPassword), CheckpointOptions{}); !errors.Is(err, ErrRecoveryDue) {
		t.Errorf("password change during a recovery: %v", err)
	}
	if _, err := s.Rotate(ctx, d.r, []byte(testPassword), CheckpointOptions{}); !errors.Is(err, ErrRecoveryDue) {
		t.Errorf("rotate during a recovery: %v", err)
	}
	if _, err := d.dst.s.RecoveryCheckpoint(ctx, d.r, []byte(newPassword), CheckpointOptions{}); !errors.Is(err, ErrNoRecoveryDue) {
		t.Errorf("recovery checkpoint with none due: %v", err)
	}
	other := deviceID(t, d.dst.s)
	self := deviceID(t, s)
	// A crash once the server committed it: still due until a pull
	// verifies it.
	s.testHook = crashAt("checkpoint:posted")
	if _, err := s.RecoveryCheckpoint(ctx, d.r, []byte(newPassword), CheckpointOptions{}); !errors.Is(err, errCrash) {
		t.Fatalf("crash: %v", err)
	}
	s = open(t, cfg)
	if si, err := s.ServerInfo(); err != nil || !si.CheckpointDue {
		t.Fatalf("due after a crash before the verified commit: %+v %v", si, err)
	}
	pull(t, s, d.r)
	if si, err := s.ServerInfo(); err != nil || si.CheckpointDue {
		t.Fatalf("still due after the commit verified: %+v %v", si, err)
	}
	kit, err := s.RecoveryCheckpoint(ctx, d.r, []byte(newPassword), CheckpointOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if !opensAccount(t, s, newPassword, kit.SecretKey) {
		t.Error("the recovery's kit does not open the account with the new password")
	}
	if !serverActive(t, d.r, self) || serverActive(t, d.r, other) {
		t.Error("the recovery did not keep only this device")
	}
	if err := d.dst.s.Pull(ctx, d.r); !errors.Is(err, ErrDeviceRevoked) {
		t.Errorf("the other device's pull: %v", err)
	}
	if err := s.AckKit(); err != nil {
		t.Fatal(err)
	}
	s = open(t, cfg)
	if si, err := s.ServerInfo(); err != nil || si.CheckpointDue {
		t.Errorf("due after a restart: %+v %v", si, err)
	}
	// Ordinary checkpoints work again.
	if _, err := s.Rotate(ctx, d.r, []byte(newPassword), CheckpointOptions{}); err != nil {
		t.Errorf("rotate after the recovery: %v", err)
	}
}

// RevokeDevices revokes the named devices and, as a response to compromise,
// keeps only this device and --keep.
func TestCheckpointRevokeDevices(t *testing.T) {
	ctx := context.Background()
	a, b, r := newCkptPair(t)
	c := secondDeviceNamed(t, a, r, "laptop")
	aID, bID, cID := deviceID(t, a.s), deviceID(t, b.s), deviceID(t, c.s)
	if _, err := a.s.RevokeDevices(ctx, r, []byte(testPassword), []string{aID.String()}, CheckpointOptions{}); err == nil {
		t.Error("revoking this device was accepted")
	}
	if _, err := a.s.RevokeDevices(ctx, r, []byte(testPassword), []string{"laptop"}, CheckpointOptions{Keep: []string{"laptop"}}); err == nil {
		t.Error("a device both kept and revoked was accepted")
	}
	if _, err := a.s.RevokeDevices(ctx, r, []byte(testPassword), []string{"laptop"}, CheckpointOptions{Keep: []string{bID.String()}}); err != nil {
		t.Fatal(err)
	}
	if !serverActive(t, r, aID) || !serverActive(t, r, bID) || serverActive(t, r, cID) {
		t.Error("revoke did not revoke exactly the named device")
	}
}

// The device listing (§10.1) gives each active device's ID, name, when and
// how it was added, and when it last wrote.
func TestDevicesListing(t *testing.T) {
	a, b, r := newCkptPair(t)
	pull(t, a.s, r)
	ls, err := a.s.Devices()
	if err != nil {
		t.Fatal(err)
	}
	if len(ls) != 2 {
		t.Fatalf("%d devices", len(ls))
	}
	byID := map[model.ID]DeviceListing{}
	for _, l := range ls {
		byID[l.ID] = l
	}
	la, lb := byID[deviceID(t, a.s)], byID[deviceID(t, b.s)]
	if la.How != AddedBySignup || !la.This || la.LastSeen == nil || la.Name != "test device" || la.AddedAt.IsZero() {
		t.Errorf("this device %+v", la)
	}
	if lb.How != AddedByBootstrap || lb.This || lb.LastSeen != nil || lb.AddedAt.IsZero() || lb.AddedAt.Before(la.AddedAt) {
		t.Errorf("the other device %+v", lb)
	}
}

// Pull drops the secrets of every state it supersedes (D2 follow-up), and
// leaves the installed ones alone when a commit fails.
func TestPullZeroesSupersededSecrets(t *testing.T) {
	a, b, r := newCkptPair(t)
	addHost(t, b.s, "db")
	addHost(t, b.s, "cache")
	pushAll(t, b.s, r)
	a.s.mu.Lock()
	old := a.s.sec
	a.s.mu.Unlock()
	// A commit that fails before its journal is installed changes nothing.
	a.s.testHook = crashAt("wal:before")
	if err := a.s.Pull(context.Background(), r); !errors.Is(err, errCrash) {
		t.Fatalf("pull: %v", err)
	}
	a.s.mu.Lock()
	kept := a.s.sec == old && !allZero(old.VK[:]) && len(old.Items) > 0 && old.Account != nil
	a.s.mu.Unlock()
	if !kept {
		t.Fatal("a failed commit dropped the installed secrets")
	}
	a.s.testHook = nil
	pull(t, a.s, r)
	a.s.mu.Lock()
	defer a.s.mu.Unlock()
	if !allZero(old.VK[:]) || len(old.Items) != 0 || old.Account != nil {
		t.Error("the superseded secrets were not dropped")
	}
	if allZero(a.s.sec.VK[:]) || a.s.sec.Account == nil || allZero(a.s.sec.Account.Sig) {
		t.Error("the installed secrets were dropped")
	}
}
