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
)

// Slice E2, review round 3: the fixes GPT-6-Astra's third review asked
// for.

// [P2] A password change whose answer is journaled with a live candidate
// (posted, its outcome unknown) refuses a call whose Keep or Exclude
// contradicts that answer, or names a device in both, before the candidate
// is posted again: in the same process and after a restart. The journaled
// answer then finishes it.
func TestPasswordChangeLiveCandidateRefusesContradictions(t *testing.T) {
	ctx := context.Background()
	pw, next := []byte(testPassword), []byte(newPassword)
	for _, restart := range []bool{false, true} {
		t.Run(map[bool]string{false: "same process", true: "restart"}[restart], func(t *testing.T) {
			a, b, r := newCkptPair(t)
			aID, bID := deviceID(t, a.s), deviceID(t, b.s)
			var added []model.ID
			a.s.testHook = func(stage string) error {
				// Two devices appear before the first post.
				if stage == "checkpoint:post" && added == nil {
					added = append(added, newServerDevice(t, a, b, r), newServerDevice(t, a, b, r))
				}
				return nil
			}
			var nd *NewDevicesError
			if _, err := a.s.ChangePasswordRemote(ctx, r, pw, next, CheckpointOptions{}); !errors.As(err, &nd) || len(nd.Devices) != 2 {
				t.Fatalf("first conflict: %v", err)
			}
			x, y := added[0], added[1]
			// x is excluded and y kept; the post's outcome is lost, and
			// the candidate stays live.
			answer := CheckpointOptions{Keep: []string{y.String()}, Exclude: []string{x.String()}}
			loseCheckpoints(r)
			if _, err := a.s.ChangePasswordRemote(ctx, r, pw, next, answer); !errors.Is(err, errLostResponse) {
				t.Fatalf("lost post: %v", err)
			}
			r.onPost = nil
			if j := journalOf(t, a.s); j.live() == nil || !slices.Contains(j.Targets, x) || !slices.Contains(j.Survivors, y) {
				t.Fatal("the answer is not journaled with a live candidate")
			}
			if restart {
				a.s = open(t, a.cfg)
			}
			n := r.postCount()
			for name, opts := range map[string]CheckpointOptions{
				"keeping the excluded device":    {Keep: []string{y.String(), x.String()}},
				"excluding the kept device":      {Exclude: []string{x.String(), y.String()}},
				"excluding an original survivor": {Keep: []string{y.String()}, Exclude: []string{x.String(), bID.String()}},
				"keeping and excluding a device": {Keep: []string{y.String(), x.String()}, Exclude: []string{x.String()}},
			} {
				_, err := a.s.ChangePasswordRemote(ctx, r, pw, next, opts)
				if !errors.Is(err, ErrContradictsJournal) || errors.As(err, &nd) {
					t.Errorf("%s: %v", name, err)
				}
			}
			if r.postCount() != n {
				t.Fatalf("a contradicting answer posted the candidate again (%d posts)", r.postCount()-n)
			}
			if !serverActive(t, r, x) || serverCheckpoints(t, r) != 0 {
				t.Fatal("a contradicting answer committed the checkpoint")
			}
			// The journaled answer finishes it, with the same candidate.
			kit, err := a.s.ChangePasswordRemote(ctx, r, pw, next, answer)
			if err != nil {
				t.Fatal(err)
			}
			if r.postCount() != n+1 || serverCheckpoints(t, r) != 1 {
				t.Errorf("%d posts, %d checkpoints", r.postCount()-n, serverCheckpoints(t, r))
			}
			for id, want := range map[model.ID]bool{aID: true, bID: true, y: true, x: false} {
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

// [P2] The §7 deadline passes while a delivery is checked, and failing the
// attempt (FAILED) can't be persisted: the enrollment never installs from
// the DONE state it held, and the next Install, without a restart, fails
// it. While persisting keeps failing, Install keeps refusing.
func TestEnrollmentExpiryPersistFailureFailsClosed(t *testing.T) {
	ctx := context.Background()
	for _, failures := range []int{1, 3} {
		t.Run(map[int]string{1: "once", 3: "repeatedly"}[failures], func(t *testing.T) {
			x := newEnrollFix(t)
			var shift time.Duration
			x.cfg.Now = func() time.Time { return time.Now().Add(shift) }
			e, _, _, _ := x.confirmedOnBoth(t)
			env, err := x.a.s.ApproveFinish(ctx, x.r)
			if err != nil {
				t.Fatal(err)
			}
			failing := 0
			e.s.testHook = func(s string) error {
				switch {
				case s == "enroll:fetch":
					shift = crypto.EnrollDeadline + time.Minute
					failing = failures
				case s == "enroll:persist" && failing > 0:
					failing--
					return errCrash
				}
				return nil
			}
			noDevice := func(when string) {
				t.Helper()
				if _, err := os.Lstat(filepath.Join(x.cfg.DataDir, "device.json")); !errors.Is(err, os.ErrNotExist) {
					t.Fatalf("device.json %s", when)
				}
			}
			if s, err := e.Install(ctx, x.remote(), &env); err == nil || s != nil {
				t.Fatalf("install past the deadline: %v", err)
			}
			if e.State() == crypto.DeviceDone {
				t.Error("the enrollment reports DONE")
			}
			noDevice("after the failed expiry")
			for i := 1; i < failures; i++ {
				if s, err := e.Install(ctx, x.remote(), nil); err == nil || s != nil {
					t.Fatalf("install while the expiry can't be persisted: %v", err)
				}
				noDevice("while the expiry can't be persisted")
			}
			for _, delivery := range []*crypto.HPKEEnvelope{nil, &env} {
				if s, err := e.Install(ctx, x.remote(), delivery); !errors.Is(err, crypto.ErrEnrollExpired) || s != nil {
					t.Fatalf("install again: %v", err)
				}
			}
			if e.State() != crypto.DeviceFailed {
				t.Errorf("state %s", e.State())
			}
			noDevice("after the deadline")
			if e = x.resume(t, e); e.State() != crypto.DeviceFailed {
				t.Errorf("resumed %s", e.State())
			}
			e.Close()
		})
	}
}

// [P3] A sign-in whose install committed and then stopped before device.json
// named the device keeps the generation of its Secret Key: once another
// device's checkpoint replaces it, a password check with the stored one
// asks for the current Secret Key instead of calling the password wrong.
func TestSignInInstallCrashKeepsSecretKeyGen(t *testing.T) {
	ctx := context.Background()
	for _, stage := range []string{"wal:applied", "wal:removed"} {
		t.Run(stage, func(t *testing.T) {
			d := newSignInFix(t)
			cfg := testConfig(t)
			if _, _, err := signIn(ctx, cfg, d.srv.login(t), d.params(t), crashAfter("signin:install", stage)); !errors.Is(err, errCrash) {
				t.Fatalf("sign-in: %v", err)
			}
			s := open(t, cfg)
			if info := s.Info(); info.Locked {
				t.Fatalf("the install does not reopen: %s", info.LockReason)
			}
			id := deviceID(t, s)
			if gen, ok := secretKeyGenOf(t, cfg, id); !ok || gen != 1 {
				t.Errorf("the Secret Key's generation: %d %v", gen, ok)
			}
			checkpointKit(t, d.dst.s, d.r, nil)
			pull(t, s, d.r)
			_, err := s.Rotate(ctx, d.r, []byte(testPassword), CheckpointOptions{})
			if !errors.Is(err, ErrSecretKeyStale) || errors.Is(err, ErrWrongPassword) {
				t.Errorf("rotate with the stale Secret Key: %v", err)
			}
		})
	}
}

// A login merge's destination device keeps the generation of its Secret
// Key through the promotion, live or finished by the next open: another
// device's checkpoint then makes it stale (ErrSecretKeyStale).
func TestMergedDeviceKeepsSecretKeyGen(t *testing.T) {
	ctx := context.Background()
	for _, crash := range []bool{false, true} {
		t.Run(map[bool]string{false: "live", true: "promoted at open"}[crash], func(t *testing.T) {
			m := newMergeFix(t, testConfig(t))
			s := m.src.s
			if _, err := s.MergeStart(); err != nil {
				t.Fatal(err)
			}
			if crash {
				s.testHook = crashAt("signin:promote")
				if _, err := m.signIn(t, s); !errors.Is(err, errCrash) {
					t.Fatalf("sign-in: %v", err)
				}
				if diskDeviceConfig(t, m.src.cfg).Next == nil {
					t.Fatal("the promotion happened")
				}
				s.Close()
				s = open(t, m.src.cfg)
			} else if _, err := m.signIn(t, s); err != nil {
				t.Fatal(err)
			}
			if info := s.Info(); info.Locked || info.AccountID != m.dst.kit.AccountID {
				t.Fatalf("after the merge: %+v", info)
			}
			id := deviceID(t, s)
			if gen, ok := secretKeyGenOf(t, m.src.cfg, id); !ok || gen != 1 {
				t.Errorf("the destination Secret Key's generation: %d %v", gen, ok)
			}
			if res := pushAll(t, s, m.r); res.Outcome != PushEmpty {
				t.Fatalf("push: %+v", res)
			}
			checkpointKit(t, m.dst.s, m.r, nil)
			pull(t, s, m.r)
			_, err := s.Rotate(ctx, m.r, []byte(testPassword), CheckpointOptions{})
			if !errors.Is(err, ErrSecretKeyStale) || errors.Is(err, ErrWrongPassword) {
				t.Errorf("rotate with the stale Secret Key: %v", err)
			}
		})
	}
}
