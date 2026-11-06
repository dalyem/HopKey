package store

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/dalyem/hopkey/internal/crypto"
	"github.com/dalyem/hopkey/internal/model"
	"github.com/dalyem/hopkey/internal/vaultlog"
)

// Slice E2, review round 2: the fixes GPT-6-Astra's second review asked
// for.

// loseCheckpoints makes r keep every checkpoint posted to it from
// committing, and lose the response.
func loseCheckpoints(r *fakeRemote) {
	r.onPost = func(w *vaultlog.Wire) (bool, error) {
		if w.Entry.Kind == vaultlog.KindCheckpoint {
			return false, errLostResponse
		}
		return true, nil
	}
}

// [P2] Run again over a journaled rotation, a name or device ID that no
// active device has, and that no device the rotation chose ever had, is
// ErrUnknownDevice: a typo does not let the rotation revoke the device the
// user meant to keep. A chosen device that has retired since is still
// passed over, by its ID or by the name it had.
func TestCheckpointResumeRefusesUnknownDevice(t *testing.T) {
	ctx := context.Background()
	pw := []byte(testPassword)
	t.Run("typo", func(t *testing.T) {
		a, b, r := newCkptPair(t)
		c := secondDeviceNamed(t, a, r, "laptop")
		pull(t, b.s, r)
		bID, cID := deviceID(t, b.s), deviceID(t, c.s)
		// The rotation keeps b; laptop is to be revoked.
		loseCheckpoints(r)
		if _, err := a.s.Rotate(ctx, r, pw, CheckpointOptions{Keep: []string{bID.String()}}); !errors.Is(err, errLostResponse) {
			t.Fatalf("lost post: %v", err)
		}
		r.onPost = nil
		other, _ := vaultlog.NewID()
		for _, restart := range []bool{false, true} {
			if restart {
				a.s = open(t, a.cfg)
			}
			// The user means to keep laptop too, and mistypes it.
			for _, ref := range []string{"lpatop", other.String()} {
				if _, err := a.s.Rotate(ctx, r, pw, CheckpointOptions{Keep: []string{bID.String(), ref}}); !errors.Is(err, ErrUnknownDevice) {
					t.Errorf("rotate keeping %q (restart %v): %v", ref, restart, err)
				}
			}
		}
		if serverCheckpoints(t, r) != 0 || !serverActive(t, r, cID) {
			t.Fatal("a mistyped survivor let the rotation commit and revoke laptop")
		}
		// Named right, it is another rotation than the journaled one.
		var pending *CheckpointPendingError
		if _, err := a.s.Rotate(ctx, r, pw, CheckpointOptions{Keep: []string{bID.String(), "laptop"}}); !errors.As(err, &pending) {
			t.Errorf("rotate keeping laptop: %v", err)
		}
		if _, err := a.s.Rotate(ctx, r, pw, CheckpointOptions{Keep: []string{bID.String()}}); err != nil {
			t.Fatalf("the journaled rotation: %v", err)
		}
		if serverActive(t, r, cID) || !serverActive(t, r, bID) {
			t.Error("the journaled rotation did not keep b and revoke laptop")
		}
	})
	t.Run("departed survivor", func(t *testing.T) {
		for _, byName := range []bool{true, false} {
			t.Run(map[bool]string{true: "by name", false: "by ID"}[byName], func(t *testing.T) {
				a, b, r := newCkptPair(t)
				c := secondDeviceNamed(t, a, r, "laptop")
				pull(t, b.s, r)
				bID, cID := deviceID(t, b.s), deviceID(t, c.s)
				ref := "laptop"
				if !byName {
					ref = cID.String()
				}
				keep := CheckpointOptions{Keep: []string{bID.String(), ref}}
				loseCheckpoints(r)
				if _, err := a.s.Rotate(ctx, r, pw, keep); !errors.Is(err, errLostResponse) {
					t.Fatalf("lost post: %v", err)
				}
				r.onPost = nil
				retire(t, c, r)
				a.s = open(t, a.cfg)
				// Laptop is gone, and a typo is still a typo.
				if _, err := a.s.Rotate(ctx, r, pw, CheckpointOptions{Keep: []string{bID.String(), "lpatop"}}); !errors.Is(err, ErrUnknownDevice) {
					t.Errorf("rotate keeping a typo after laptop retired: %v", err)
				}
				if _, err := a.s.Rotate(ctx, r, pw, keep); err != nil {
					t.Fatalf("the same command after laptop retired: %v", err)
				}
				if serverCheckpoints(t, r) != 1 || !serverActive(t, r, bID) {
					t.Error("the rotation did not commit keeping b")
				}
			})
		}
	})
	t.Run("password change", func(t *testing.T) {
		a, _, r := newCkptPair(t)
		loseCheckpoints(r)
		if _, err := a.s.ChangePasswordRemote(ctx, r, pw, []byte(newPassword), CheckpointOptions{}); !errors.Is(err, errLostResponse) {
			t.Fatalf("lost post: %v", err)
		}
		r.onPost = nil
		if _, err := a.s.ChangePasswordRemote(ctx, r, pw, []byte(newPassword), CheckpointOptions{Exclude: []string{"lpatop"}}); !errors.Is(err, ErrUnknownDevice) {
			t.Errorf("password change excluding a typo: %v", err)
		}
		if serverCheckpoints(t, r) != 0 {
			t.Error("the password change committed")
		}
	})
}

// [P2] Abort whose budget write is interrupted at the WAL's install
// boundary locks the store: it does not panic, it returns the
// interruption, and the journal keeps the attempt's candidate. The next
// unlock replays the budget write, and the failed attempt's device is
// still reported for revocation.
func TestApprovalAbortInterruptedBudgetWrite(t *testing.T) {
	ctx := context.Background()
	x := newEnrollFix(t)
	x.confirmedOnBoth(t)
	x.r.onPost = func(*vaultlog.Wire) (bool, error) { return true, errLostResponse }
	if _, err := x.a.s.ApproveFinish(ctx, x.r); !errors.Is(err, errLostResponse) {
		t.Fatalf("lost response: %v", err)
	}
	x.r.onPost = nil
	dev := x.prepared(t).Cert.DeviceID
	before, err := os.ReadFile(filepath.Join(x.a.cfg.DataDir, "vault", approvalRel))
	if err != nil {
		t.Fatal(err)
	}
	x.a.s.testHook = crashAfter("approve:budget", "wal:install:sync")
	func() {
		defer func() {
			if p := recover(); p != nil {
				t.Fatalf("abort panicked: %v", p)
			}
		}()
		if err := x.a.s.ApproveAbort(); !errors.Is(err, errCrash) {
			t.Fatalf("abort: %v", err)
		}
	}()
	if !x.a.s.Info().Locked {
		t.Error("the interrupted commit left the store unlocked")
	}
	if _, err := os.Lstat(filepath.Join(x.a.cfg.DataDir, "vault", approvalOrphansRel)); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("the candidates moved while the store was locked: %v", err)
	}
	after, err := os.ReadFile(filepath.Join(x.a.cfg.DataDir, "vault", approvalRel))
	if err != nil || len(after) == 0 {
		t.Fatalf("the journal is gone: %v", err)
	}
	if slices.Equal(before, after) {
		t.Error("the failed state was not journaled before the budget write")
	}
	x.a.s = open(t, x.a.cfg)
	if x.a.s.Info().Locked {
		t.Fatalf("the next unlock did not recover: %s", x.a.s.Info().LockReason)
	}
	info, err := x.a.s.Approval()
	if err != nil || info == nil || info.State != crypto.ApprovalFailed {
		t.Fatalf("approval after recovery: %+v %v", info, err)
	}
	pull(t, x.a.s, x.r)
	if !hasWarning(x.a.s.Info(), dev.String()) {
		t.Errorf("the failed attempt's device is not reported: %q", x.a.s.Info().Warnings)
	}
	// The budget write the unlock replayed released the challenge.
	id, _ := vaultlog.NewID()
	if err := x.a.s.ApproveStart(id); err != nil {
		t.Errorf("a new approval: %v", err)
	}
	if !hasWarning(x.a.s.Info(), dev.String()) {
		t.Errorf("after the new approval: %q", x.a.s.Info().Warnings)
	}
}

// newServerDevice commits a bootstrap of a new device to r, built on b's
// verified state, as another machine's password unlock would.
func newServerDevice(t *testing.T, a, b *fixture, r *fakeRemote) model.ID {
	t.Helper()
	pull(t, b.s, r)
	_, info, err := newDeviceRecord(accountOfKit(t, a), a.kit.SecretKey)
	if err != nil {
		t.Fatal(err)
	}
	b.s.mu.Lock()
	w, _, _, err := vaultlog.BuildBootstrap(b.s.state, b.s.sec, info, b.s.now())
	b.s.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := r.commit(w); err != nil {
		t.Fatal(err)
	}
	return info.ID
}

// [P2] A password change whose answer is journaled meets another new
// device: the same command, in the same call or run again (after a restart
// too), keeps its journaled answer and asks only about the device that is
// still undecided.
func TestPasswordChangeAnswerSurvivesAnotherConflict(t *testing.T) {
	ctx := context.Background()
	pw, next := []byte(testPassword), []byte(newPassword)
	for _, restart := range []bool{false, true} {
		t.Run(map[bool]string{false: "same process", true: "restart"}[restart], func(t *testing.T) {
			a, b, r := newCkptPair(t)
			aID, bID := deviceID(t, a.s), deviceID(t, b.s)
			var added []model.ID
			posts := 0
			hook := func(stage string) error {
				if stage != "checkpoint:post" {
					return nil
				}
				// A device appears before each of the first two posts:
				// each candidate is rebuilt.
				if posts++; posts <= 2 {
					added = append(added, newServerDevice(t, a, b, r))
				}
				return nil
			}
			a.s.testHook = hook
			var nd *NewDevicesError
			if _, err := a.s.ChangePasswordRemote(ctx, r, pw, next, CheckpointOptions{}); !errors.As(err, &nd) || !slices.Equal(nd.Devices, added[:1]) {
				t.Fatalf("first conflict: %v", err)
			}
			first := CheckpointOptions{Keep: []string{added[0].String()}}
			// The answer is journaled with the second candidate, which
			// another new device makes dead: the call asks about that one.
			if _, err := a.s.ChangePasswordRemote(ctx, r, pw, next, first); !errors.As(err, &nd) || !slices.Equal(nd.Devices, added[1:2]) {
				t.Fatalf("second conflict, in the same call: %v", err)
			}
			if j := journalOf(t, a.s); !slices.Contains(j.Survivors, added[0]) {
				t.Fatal("the answer is not journaled")
			}
			if restart {
				a.s = open(t, a.cfg)
				a.s.testHook = hook
			}
			// The same command again: the same question.
			if _, err := a.s.ChangePasswordRemote(ctx, r, pw, next, first); !errors.As(err, &nd) || !slices.Equal(nd.Devices, added[1:2]) {
				t.Fatalf("the same command again: %v", err)
			}
			// Contradicting the journaled answer is refused.
			if _, err := a.s.ChangePasswordRemote(ctx, r, pw, next, CheckpointOptions{Exclude: []string{added[0].String(), added[1].String()}}); err == nil || errors.As(err, &nd) {
				t.Errorf("excluding the kept device: %v", err)
			}
			// The repeated answer with the new one finishes it.
			kit, err := a.s.ChangePasswordRemote(ctx, r, pw, next, CheckpointOptions{Keep: []string{added[0].String()}, Exclude: []string{added[1].String()}})
			if err != nil {
				t.Fatal(err)
			}
			if posts != 3 || serverCheckpoints(t, r) != 1 {
				t.Errorf("%d posts, %d checkpoints", posts, serverCheckpoints(t, r))
			}
			for id, want := range map[model.ID]bool{aID: true, bID: true, added[0]: true, added[1]: false} {
				if serverActive(t, r, id) != want {
					t.Errorf("device %v active %v; want %v", id, !want, want)
				}
			}
			if !opensAccount(t, a.s, newPassword, kit.SecretKey) {
				t.Error("the kit is not the committed checkpoint's")
			}
		})
	}
}

// [P2] The §7 deadline is enforced when the delivery is accepted: a valid
// delivery staged before the deadline, whose log fetch ends after it,
// fails the attempt, in the live process as after a restart.
func TestEnrollmentDeadlinePassesWhileChecking(t *testing.T) {
	ctx := context.Background()
	for _, how := range []string{"live", "restart before the deadline", "restart after the deadline"} {
		t.Run(how, func(t *testing.T) {
			x := newEnrollFix(t)
			var shift time.Duration
			x.cfg.Now = func() time.Time { return time.Now().Add(shift) }
			e, _, _, _ := x.confirmedOnBoth(t)
			env, err := x.a.s.ApproveFinish(ctx, x.r)
			if err != nil {
				t.Fatal(err)
			}
			late := func(s string) error {
				if s == "enroll:fetch" {
					shift = crypto.EnrollDeadline + time.Minute
				}
				return nil
			}
			delivery := &env
			if how != "live" {
				// A crash during the fetch, before the deadline: the
				// delivery stays staged.
				e.s.testHook = func(s string) error {
					if s == "enroll:fetch" {
						panic(errCrash)
					}
					return nil
				}
				func() {
					defer func() {
						if p := recover(); p != errCrash {
							t.Fatalf("install: %v", p)
						}
					}()
					e.Install(ctx, x.remote(), &env)
				}()
				if how == "restart after the deadline" {
					shift = crypto.EnrollDeadline + time.Minute
				}
				e = x.resume(t, e)
				delivery = nil
			}
			e.s.testHook = late
			if _, err := e.Install(ctx, x.remote(), delivery); !errors.Is(err, crypto.ErrEnrollExpired) {
				t.Fatalf("install past the deadline: %v", err)
			}
			if e.State() != crypto.DeviceFailed {
				t.Errorf("state %s", e.State())
			}
			if _, err := os.Lstat(filepath.Join(x.cfg.DataDir, "device.json")); !errors.Is(err, os.ErrNotExist) {
				t.Error("device.json after the deadline")
			}
			e = x.resume(t, e)
			if e.State() != crypto.DeviceFailed {
				t.Errorf("resumed %s", e.State())
			}
			if _, err := e.Install(ctx, x.remote(), &env); !errors.Is(err, crypto.ErrEnrollExpired) {
				t.Errorf("install after a restart: %v", err)
			}
			e.Close()
			if err := DiscardEnrollment(x.cfg); err != nil {
				t.Errorf("discard: %v", err)
			}
		})
	}
}

// secretKeyGenOf is the creds generation device.json records for id's
// Secret Key, or false.
func secretKeyGenOf(t *testing.T, cfg Config, id model.ID) (uint32, bool) {
	t.Helper()
	c, err := (&Store{cfg: cfg, l: layout{data: cfg.DataDir}}).readDeviceConfig()
	if err != nil {
		t.Fatal(err)
	}
	return c.SecretKeyGen.Gen, c.SecretKeyGen.DeviceID == id
}

// The Secret Key a device stores goes stale when another device's
// checkpoint replaces the credentials. A password check with it then asks
// for the current one (ErrSecretKeyStale, which is ErrNeedSecretKey)
// instead of calling the password wrong; once a check passes with the
// current one, the device stores it, durably, with its generation.
func TestStaleSecretKeyAfterAnotherDevicesCheckpoint(t *testing.T) {
	ctx := context.Background()
	pw := []byte(testPassword)
	// b rotates; a crosses it with the Secret Key it stored before.
	setup := func(t *testing.T) (*fixture, *fixture, *fakeRemote, Kit) {
		t.Helper()
		a, b, r := newCkptPair(t)
		kit, err := b.s.Rotate(ctx, r, pw, CheckpointOptions{Keep: []string{deviceID(t, a.s).String()}})
		if err != nil {
			t.Fatal(err)
		}
		if err := b.s.AckKit(); err != nil {
			t.Fatal(err)
		}
		pull(t, a.s, r)
		if got := storedSecretKey(t, a.cfg, a.s); got != a.kit.SecretKey || got == kit.SecretKey {
			t.Fatal("a does not hold the old Secret Key")
		}
		if gen, ok := secretKeyGenOf(t, a.cfg, deviceID(t, a.s)); !ok || gen != 1 {
			t.Fatalf("a's Secret Key generation: %d %v", gen, ok)
		}
		return a, b, r, kit
	}
	stale := func(t *testing.T, what string, err error) {
		t.Helper()
		if !errors.Is(err, ErrSecretKeyStale) || !errors.Is(err, ErrNeedSecretKey) || errors.Is(err, ErrWrongPassword) {
			t.Fatalf("%s with the stale Secret Key: %v", what, err)
		}
	}
	t.Run("checkpoint", func(t *testing.T) {
		a, b, r, kit := setup(t)
		aID, bID := deviceID(t, a.s), deviceID(t, b.s)
		n := r.postCount()
		_, err := a.s.Rotate(ctx, r, pw, CheckpointOptions{Keep: []string{bID.String()}})
		stale(t, "rotate", err)
		_, err = a.s.ChangePasswordRemote(ctx, r, pw, []byte(newPassword), CheckpointOptions{})
		stale(t, "password change", err)
		// A wrong password with the current Secret Key is still wrong.
		if _, err := a.s.Rotate(ctx, r, []byte("wrong password"), CheckpointOptions{SecretKey: kit.SecretKey}); !errors.Is(err, ErrWrongPassword) {
			t.Errorf("a wrong password: %v", err)
		}
		if r.postCount() != n || journalExists(t, a.cfg) {
			t.Fatal("a checkpoint that did not verify the password posted or journaled")
		}
		// The current Secret Key passes, and is stored before anything is
		// journaled.
		a.s.testHook = crashAt("checkpoint:journal")
		if _, err := a.s.Rotate(ctx, r, pw, CheckpointOptions{Keep: []string{bID.String()}, SecretKey: kit.SecretKey}); !errors.Is(err, errCrash) {
			t.Fatalf("rotate with the current Secret Key: %v", err)
		}
		a.s = open(t, a.cfg)
		if got := storedSecretKey(t, a.cfg, a.s); got != kit.SecretKey {
			t.Error("the current Secret Key was not stored")
		}
		if gen, ok := secretKeyGenOf(t, a.cfg, aID); !ok || gen != 2 {
			t.Errorf("the stored Secret Key's generation: %d %v", gen, ok)
		}
		// From now on the stored one serves.
		kit2, err := a.s.Rotate(ctx, r, pw, CheckpointOptions{Keep: []string{bID.String()}})
		if err != nil {
			t.Fatal(err)
		}
		if err := a.s.AckKit(); err != nil {
			t.Fatal(err)
		}
		if got := storedSecretKey(t, a.cfg, a.s); got != kit2.SecretKey {
			t.Error("a's own checkpoint did not store its Secret Key")
		}
		if gen, ok := secretKeyGenOf(t, a.cfg, aID); !ok || gen != 3 {
			t.Errorf("the generation after a's own checkpoint: %d %v", gen, ok)
		}
	})
	t.Run("password unlock", func(t *testing.T) {
		a, _, r, kit := setup(t)
		a.s.Lock()
		stale(t, "password unlock", a.s.UnlockWithPasswordRemote(ctx, r, pw, ""))
		if !a.s.Info().Locked {
			t.Fatal("unlocked")
		}
		if err := a.s.UnlockWithPasswordRemote(ctx, r, pw, kit.SecretKey); err != nil {
			t.Fatal(err)
		}
		hostNamed(t, snapshot(t, a.s), "web")
		id := deviceID(t, a.s)
		if got := storedSecretKey(t, a.cfg, a.s); got != kit.SecretKey {
			t.Error("the new device record does not hold the current Secret Key")
		}
		if gen, ok := secretKeyGenOf(t, a.cfg, id); !ok || gen != 2 {
			t.Errorf("the generation of the new record's Secret Key: %d %v", gen, ok)
		}
		// The next password check uses it.
		if _, err := a.s.ChangePasswordRemote(ctx, r, pw, []byte(newPassword), CheckpointOptions{}); err != nil {
			t.Errorf("password change after the refresh: %v", err)
		}
	})
	t.Run("enrolled device", func(t *testing.T) {
		x := newEnrollFix(t)
		e, _, _, _ := x.confirmedOnBoth(t)
		env, err := x.a.s.ApproveFinish(ctx, x.r)
		if err != nil {
			t.Fatal(err)
		}
		s, err := e.Install(ctx, x.remote(), &env)
		if err != nil {
			t.Fatal(err)
		}
		track(t, x.cfg, s)
		// The approver rotates: the enrolled device stores no Secret Key,
		// so it still needs one given, and is not told it is stale.
		kit, err := x.a.s.Rotate(ctx, x.r, pw, CheckpointOptions{Keep: []string{deviceID(t, s).String()}})
		if err != nil {
			t.Fatal(err)
		}
		pull(t, s, x.r)
		if _, err := s.Rotate(ctx, x.r, pw, CheckpointOptions{}); !errors.Is(err, ErrNeedSecretKey) || errors.Is(err, ErrSecretKeyStale) {
			t.Errorf("rotate on the enrolled device: %v", err)
		}
		s.testHook = crashAt("checkpoint:journal")
		if _, err := s.Rotate(ctx, x.r, pw, CheckpointOptions{SecretKey: kit.SecretKey}); !errors.Is(err, errCrash) {
			t.Fatalf("rotate with the current Secret Key: %v", err)
		}
		s.testHook = nil
		if got := storedSecretKey(t, x.cfg, s); got != "" {
			t.Error("the enrolled device stored a Secret Key it was only given")
		}
		kit2, err := s.Rotate(ctx, x.r, pw, CheckpointOptions{SecretKey: kit.SecretKey})
		if err != nil {
			t.Fatal(err)
		}
		if err := s.AckKit(); err != nil {
			t.Fatal(err)
		}
		if got := storedSecretKey(t, x.cfg, s); got != kit2.SecretKey {
			t.Error("the enrolled device's own checkpoint did not store its Secret Key")
		}
		if s = open(t, x.cfg); s.Info().Locked {
			t.Errorf("does not reopen: %s", s.Info().LockReason)
		}
	})
}
