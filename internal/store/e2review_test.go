package store

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/dalyem/hopkey/internal/crypto"
	"github.com/dalyem/hopkey/internal/model"
	"github.com/dalyem/hopkey/internal/vaultlog"
)

// Slice E2, review round 1: the fixes GPT-6-Astra's review asked for.

// crashFrom fails at stage and at every hook after it: the process is
// gone, so nothing it would have done next happens.
func crashFrom(stage string) func(string) error {
	dead := false
	return func(s string) error {
		if s == stage {
			dead = true
		}
		if dead {
			return errCrash
		}
		return nil
	}
}

// confirmedOnBoth runs an enrollment until the user confirmed the SAS on D
// and on A.
func (x *enrollFix) confirmedOnBoth(t *testing.T) (*Enrollment, crypto.EnrollCommit, crypto.EnrollChal, crypto.EnrollOpen) {
	t.Helper()
	e, commit := x.begin(t)
	chal, open := x.reveal(t, e, commit)
	if err := e.ConfirmSAS(); err != nil {
		t.Fatal(err)
	}
	if err := x.a.s.ApproveConfirm(true); err != nil {
		t.Fatal(err)
	}
	return e, commit, chal, open
}

// prepared returns A's prepared device_add.
func (x *enrollFix) prepared(t *testing.T) *crypto.PreparedDevice {
	t.Helper()
	s := x.a.s
	s.mu.Lock()
	defer s.mu.Unlock()
	unlock, err := s.lockFile()
	if err != nil {
		t.Fatal(err)
	}
	defer unlock()
	_, a, _, err := s.loadApproval()
	if err != nil {
		t.Fatal(err)
	}
	pd, err := a.Prepared()
	if err != nil {
		t.Fatal(err)
	}
	return pd
}

// withClock gives A a clock that runs shift ahead, across restarts.
func (x *enrollFix) withClock(shift *time.Duration) {
	now := func() time.Time { return time.Now().Add(*shift) }
	x.a.cfg.Now = now
	x.a.s.mu.Lock()
	x.a.s.cfg.Now = now
	x.a.s.mu.Unlock()
}

// [P1] A relay that substitutes anchor_h (§7 step 6) gets the delivery
// refused before it is accepted: the state stays CONFIRMED, device.json is
// not written, DiscardEnrollment is still allowed, and the genuine
// delivery, handed in next, with or without a restart, installs.
func TestEnrollmentBadAnchorThenGenuine(t *testing.T) {
	ctx := context.Background()
	for _, restart := range []bool{false, true} {
		t.Run(map[bool]string{false: "same process", true: "restart"}[restart], func(t *testing.T) {
			x := newEnrollFix(t)
			e, commit, chal, open := x.confirmedOnBoth(t)
			// The device_add commits; A has not delivered yet.
			x.a.s.testHook = crashAt("approve:deliver")
			if _, err := x.a.s.ApproveFinish(ctx, x.r); !errors.Is(err, errCrash) {
				t.Fatalf("finish: %v", err)
			}
			x.a.s.testHook = nil
			// The relay's delivery: A's real device_add material, another
			// anchor_h.
			pd := x.prepared(t)
			var wrong crypto.Hash
			wrong[0] = 7
			th := crypto.TranscriptHash(crypto.Transcript(commit.C, &chal, &open))
			bad, err := crypto.SealDelivery(open.KEMPK, th, &crypto.EnrollDelivery{
				V: crypto.Version, Cert: pd.Cert, CertSig: pd.CertSig, Unlock: pd.Unlock, AnchorSeq: 0, AnchorH: wrong,
			})
			if err != nil {
				t.Fatal(err)
			}
			if _, err := e.Install(ctx, x.remote(), &bad); err == nil || !strings.Contains(err.Error(), "not the delivered anchor_h") {
				t.Fatalf("the substituted anchor: %v", err)
			}
			if e.State() != crypto.DeviceConfirmed {
				t.Fatalf("state after the bad anchor: %s", e.State())
			}
			if _, err := os.Lstat(filepath.Join(x.cfg.DataDir, "device.json")); !errors.Is(err, os.ErrNotExist) {
				t.Error("a refused delivery wrote device.json")
			}
			if restart {
				e = x.resume(t, e)
				if e.State() != crypto.DeviceConfirmed {
					t.Fatalf("resumed %s", e.State())
				}
			}
			// Nothing was staged: the persisted delivery is none.
			if _, err := e.Install(ctx, x.remote(), nil); !errors.Is(err, crypto.ErrEnrollState) {
				t.Errorf("install with no delivery: %v", err)
			}
			good, err := x.a.s.ApproveFinish(ctx, x.r)
			if err != nil {
				t.Fatal(err)
			}
			s, err := e.Install(ctx, x.remote(), &good)
			if err != nil {
				t.Fatalf("the genuine delivery after a bad anchor: %v", err)
			}
			track(t, x.cfg, s)
			x.installed(t, s)
		})
	}
	t.Run("discard", func(t *testing.T) {
		x := newEnrollFix(t)
		e, _, _, _ := x.confirmedOnBoth(t)
		x.a.s.testHook = crashAt("approve:deliver")
		if _, err := x.a.s.ApproveFinish(ctx, x.r); !errors.Is(err, errCrash) {
			t.Fatalf("finish: %v", err)
		}
		x.a.s.testHook = nil
		var wrong crypto.Hash
		wrong[0] = 7
		if _, err := e.Install(ctx, x.remote(), func() *crypto.HPKEEnvelope { d := x.rawDelivery(t, 0, wrong); return &d }()); err == nil {
			t.Fatal("a bad anchor installed")
		}
		e.Close()
		if err := DiscardEnrollment(x.cfg); err != nil {
			t.Fatalf("discard after a refused delivery: %v", err)
		}
		noUntrackedRecords(t, x.cfg, "after the discard")
	})
}

// A crash while the staged delivery is being checked leaves CONFIRMED with
// the delivery staged: Install with no delivery checks it again and
// installs. (A check that fails, a network error included, unstages it;
// only a crash leaves it, so the crash during the fetch is a panic that
// skips everything after it.)
func TestEnrollmentStagedDeliverySurvivesACrash(t *testing.T) {
	ctx := context.Background()
	for _, stage := range []string{"enroll:staged", "enroll:fetch", "enroll:accept"} {
		t.Run(stage, func(t *testing.T) {
			x := newEnrollFix(t)
			e, _, _, _ := x.confirmedOnBoth(t)
			env, err := x.a.s.ApproveFinish(ctx, x.r)
			if err != nil {
				t.Fatal(err)
			}
			e.s.testHook = func(s string) error {
				if s == stage {
					panic(errCrash)
				}
				return nil
			}
			func() {
				defer func() {
					if p := recover(); p != errCrash {
						t.Fatalf("install crashing at %s: %v", stage, p)
					}
				}()
				e.Install(ctx, x.remote(), &env)
			}()
			e = x.resume(t, e)
			if e.State() != crypto.DeviceConfirmed {
				t.Fatalf("after a crash at %s: %s", stage, e.State())
			}
			if _, err := os.Lstat(filepath.Join(x.cfg.DataDir, "device.json")); !errors.Is(err, os.ErrNotExist) {
				t.Error("device.json before the delivery was accepted")
			}
			s, err := e.Install(ctx, x.remote(), nil)
			if err != nil {
				t.Fatal(err)
			}
			track(t, x.cfg, s)
			x.installed(t, s)
		})
	}
}

// [P1] A pending kit that a later checkpoint supersedes goes, with its
// journal, as soon as a pull verifies the later one: it is not shown,
// resumed or acknowledged.
func TestPullDropsSupersededKit(t *testing.T) {
	ctx := context.Background()
	a, b, r := newCkptPair(t)
	aID, bID := deviceID(t, a.s), deviceID(t, b.s)
	kit1, err := a.s.Rotate(ctx, r, []byte(testPassword), CheckpointOptions{Keep: []string{bID.String()}})
	if err != nil {
		t.Fatal(err)
	}
	if a.s.PendingKit() == nil {
		t.Fatal("no pending kit")
	}
	// The other device checkpoints next, while a's kit is pending.
	pull(t, b.s, r)
	kit2, err := b.s.Rotate(ctx, r, []byte(testPassword), CheckpointOptions{Keep: []string{aID.String()}, SecretKey: kit1.SecretKey})
	if err != nil {
		t.Fatal(err)
	}
	pull(t, a.s, r)
	if p := a.s.PendingKit(); p != nil {
		t.Fatalf("the superseded kit is still pending: %v", p.SecretKey == kit1.SecretKey)
	}
	if journalExists(t, a.cfg) || a.s.Info().KitPending {
		t.Error("the superseded journal or kit survived the pull")
	}
	if _, err := a.s.ResumeCheckpoint(ctx, r); !errors.Is(err, ErrNoCheckpoint) {
		t.Errorf("resume: %v", err)
	}
	if err := a.s.AckKit(); err != nil {
		t.Errorf("ack with nothing pending: %v", err)
	}
	if opensAccount(t, a.s, testPassword, kit1.SecretKey) || !opensAccount(t, a.s, testPassword, kit2.SecretKey) {
		t.Error("the account's credentials are not the later checkpoint's")
	}
	if a.s = open(t, a.cfg); a.s.PendingKit() != nil {
		t.Error("a pending kit after a restart")
	}
	// This device checkpoints again with the current Secret Key.
	if _, err := a.s.Rotate(ctx, r, []byte(testPassword), CheckpointOptions{SecretKey: kit2.SecretKey}); err != nil {
		t.Errorf("a new checkpoint after the superseded kit: %v", err)
	}
}

// retire logs f's device out through the fake server.
func retire(t *testing.T, f *fixture, r *fakeRemote) {
	t.Helper()
	srv := newFakeServer(t, r)
	if _, err := f.s.Logout(context.Background(), retirer{srv}, LogoutOptions{}); err != nil {
		t.Fatal(err)
	}
}

// [P1] A journaled survivor or revoke target that retires before the
// rebuild does not wedge the checkpoint: after a restart, the same command
// finishes it, and nothing is left to block a logout.
func TestCheckpointSurvivesRetiredChoices(t *testing.T) {
	ctx := context.Background()
	lostCheckpoint := func(r *fakeRemote) {
		r.onPost = func(w *vaultlog.Wire) (bool, error) {
			if w.Entry.Kind == vaultlog.KindCheckpoint {
				return false, errLostResponse
			}
			return true, nil
		}
	}
	finish := func(t *testing.T, a *fixture, r *fakeRemote, run func(*Store) (Kit, error)) {
		t.Helper()
		a.s = open(t, a.cfg)
		if _, err := a.s.ResumeCheckpoint(ctx, r); !errors.Is(err, ErrCheckpointRebuild) {
			t.Fatalf("resume: %v", err)
		}
		if _, err := run(a.s); err != nil {
			t.Fatalf("the same command after a retirement: %v", err)
		}
		if err := a.s.AckKit(); err != nil {
			t.Fatal(err)
		}
		if j, err := a.s.HasCheckpointJournal(); err != nil || j {
			t.Errorf("a checkpoint journal is left: %v %v", j, err)
		}
	}
	t.Run("survivors", func(t *testing.T) {
		a, b, r := newCkptPair(t)
		c := secondDeviceNamed(t, a, r, "laptop")
		pull(t, b.s, r)
		bID := deviceID(t, b.s)
		keep := CheckpointOptions{Keep: []string{bID.String(), "laptop"}}
		lostCheckpoint(r)
		if _, err := a.s.Rotate(ctx, r, []byte(testPassword), keep); !errors.Is(err, errLostResponse) {
			t.Fatalf("lost post: %v", err)
		}
		r.onPost = nil
		retire(t, b, r)
		retire(t, c, r)
		finish(t, a, r, func(s *Store) (Kit, error) { return s.Rotate(ctx, r, []byte(testPassword), keep) })
		if serverCheckpoints(t, r) != 1 || !serverActive(t, r, deviceID(t, a.s)) {
			t.Error("the rebuilt checkpoint did not commit")
		}
	})
	t.Run("revoke targets", func(t *testing.T) {
		a, b, r := newCkptPair(t)
		c := secondDeviceNamed(t, a, r, "laptop")
		pull(t, b.s, r)
		bID, cID := deviceID(t, b.s), deviceID(t, c.s)
		lostCheckpoint(r)
		if _, err := a.s.RevokeDevices(ctx, r, []byte(testPassword), []string{cID.String()}, CheckpointOptions{Keep: []string{bID.String()}}); !errors.Is(err, errLostResponse) {
			t.Fatalf("lost post: %v", err)
		}
		r.onPost = nil
		retire(t, c, r)
		pull(t, b.s, r)
		finish(t, a, r, func(s *Store) (Kit, error) {
			return s.RevokeDevices(ctx, r, []byte(testPassword), []string{cID.String()}, CheckpointOptions{Keep: []string{bID.String()}})
		})
		if !serverActive(t, r, bID) {
			t.Error("the kept device was revoked")
		}
	})
}

// [P2] Every checkpoint but a recovery's checks the current password: a
// nil or empty one is wrong, and nothing is journaled or posted.
func TestCheckpointNeedsTheCurrentPassword(t *testing.T) {
	ctx := context.Background()
	a, b, r := newCkptPair(t)
	bID := deviceID(t, b.s)
	n := r.postCount()
	for name, pw := range map[string][]byte{"nil": nil, "empty": {}} {
		if _, err := a.s.ChangePasswordRemote(ctx, r, pw, []byte(newPassword), CheckpointOptions{}); !errors.Is(err, ErrWrongPassword) {
			t.Errorf("password change, %s current password: %v", name, err)
		}
		if _, err := a.s.Rotate(ctx, r, pw, CheckpointOptions{}); !errors.Is(err, ErrWrongPassword) {
			t.Errorf("rotate, %s password: %v", name, err)
		}
		if _, err := a.s.RevokeDevices(ctx, r, pw, []string{bID.String()}, CheckpointOptions{}); !errors.Is(err, ErrWrongPassword) {
			t.Errorf("revoke, %s password: %v", name, err)
		}
	}
	if r.postCount() != n || journalExists(t, a.cfg) {
		t.Error("a checkpoint without the current password posted or journaled")
	}
}

// [P2] An enrolled device stores no Secret Key: a checkpoint with a nil
// current password still needs it (ErrNeedSecretKey), and posts nothing.
func TestEnrolledDeviceCheckpointNeedsSecretKey(t *testing.T) {
	ctx := context.Background()
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
	n := x.r.postCount()
	if _, err := s.Rotate(ctx, x.r, nil, CheckpointOptions{}); !errors.Is(err, ErrNeedSecretKey) {
		t.Errorf("rotate with no password and no Secret Key: %v", err)
	}
	if _, err := s.ChangePasswordRemote(ctx, x.r, nil, []byte(newPassword), CheckpointOptions{}); !errors.Is(err, ErrNeedSecretKey) {
		t.Errorf("password change with no password and no Secret Key: %v", err)
	}
	if _, err := s.Rotate(ctx, x.r, nil, CheckpointOptions{SecretKey: x.a.kit.SecretKey}); !errors.Is(err, ErrWrongPassword) {
		t.Errorf("rotate with the Secret Key and no password: %v", err)
	}
	if x.r.postCount() != n {
		t.Error("a checkpoint that could not verify the password posted")
	}
}

// [P2] An approval whose device_add committed with its response lost, and
// that then ends (aborted, or past its deadline), keeps its candidate when
// a new approval replaces its journal: the device is reported for
// revocation, and it is never delivered.
func TestApprovalOrphanIsReported(t *testing.T) {
	ctx := context.Background()
	for _, how := range []string{"abort", "expire"} {
		t.Run(how, func(t *testing.T) {
			x := newEnrollFix(t)
			var shift time.Duration
			x.withClock(&shift)
			x.confirmedOnBoth(t)
			x.r.onPost = func(*vaultlog.Wire) (bool, error) { return true, errLostResponse }
			if _, err := x.a.s.ApproveFinish(ctx, x.r); !errors.Is(err, errLostResponse) {
				t.Fatalf("lost response: %v", err)
			}
			x.r.onPost = nil
			dev := x.prepared(t).Cert.DeviceID
			switch how {
			case "abort":
				if err := x.a.s.ApproveAbort(); err != nil {
					t.Fatal(err)
				}
			case "expire":
				shift = crypto.EnrollDeadline + time.Minute
				x.a.s = open(t, x.a.cfg)
				// Late delivery stays forbidden.
				if _, err := x.a.s.ApproveFinish(ctx, x.r); err == nil {
					t.Fatal("a delivery after the deadline")
				}
			}
			id, _ := vaultlog.NewID()
			if err := x.a.s.ApproveStart(id); err != nil {
				t.Fatal(err)
			}
			pull(t, x.a.s, x.r)
			ls, err := x.a.s.Devices()
			if err != nil {
				t.Fatal(err)
			}
			found := false
			for _, l := range ls {
				if l.ID == dev {
					found = l.Undelivered && l.How == AddedByApproval
				} else if l.Undelivered {
					t.Errorf("device %v reported undelivered", l.ID)
				}
			}
			if !found {
				t.Fatalf("the orphaned device is not reported: %+v", ls)
			}
			if !hasWarning(x.a.s.Info(), dev.String()) {
				t.Errorf("no warning names the orphaned device: %q", x.a.s.Info().Warnings)
			}
			// It survives a restart, and a revocation ends it.
			x.a.s = open(t, x.a.cfg)
			if !hasWarning(x.a.s.Info(), dev.String()) {
				t.Error("the report did not survive a restart")
			}
			if err := x.a.s.ApproveAbort(); err != nil {
				t.Fatal(err)
			}
			if _, err := x.a.s.Rotate(ctx, x.r, []byte(testPassword), CheckpointOptions{}); err != nil {
				t.Fatal(err)
			}
			if serverActive(t, x.r, dev) || hasWarning(x.a.s.Info(), dev.String()) {
				t.Error("the orphaned device is still active or reported after the checkpoint")
			}
		})
	}
	t.Run("aborted before the commit is known", func(t *testing.T) {
		x := newEnrollFix(t)
		x.confirmedOnBoth(t)
		x.r.onPost = func(*vaultlog.Wire) (bool, error) { return true, errLostResponse }
		if _, err := x.a.s.ApproveFinish(ctx, x.r); !errors.Is(err, errLostResponse) {
			t.Fatalf("lost response: %v", err)
		}
		x.r.onPost = nil
		dev := x.prepared(t).Cert.DeviceID
		if err := x.a.s.ApproveAbort(); err != nil {
			t.Fatal(err)
		}
		// Not yet verified: the warning says it may still be added.
		if !hasWarning(x.a.s.Info(), "may still be added") {
			t.Errorf("warnings %q", x.a.s.Info().Warnings)
		}
		id, _ := vaultlog.NewID()
		if err := x.a.s.ApproveStart(id); err != nil {
			t.Fatal(err)
		}
		pull(t, x.a.s, x.r)
		if !hasWarning(x.a.s.Info(), dev.String()) || hasWarning(x.a.s.Info(), "may still be added") {
			t.Errorf("after the pull: %q", x.a.s.Info().Warnings)
		}
	})
}

// [P2] On A, a checkpoint that changes the verified account keys after the
// user confirmed ends the attempt by itself: a new approval can start.
func TestApprovalEndsWhenTheAccountChanges(t *testing.T) {
	ctx := context.Background()
	x := newEnrollFix(t)
	x.confirmedOnBoth(t)
	if _, err := x.a.s.Rotate(ctx, x.r, []byte(testPassword), CheckpointOptions{}); err != nil {
		t.Fatal(err)
	}
	if err := x.a.s.AckKit(); err != nil {
		t.Fatal(err)
	}
	n := x.r.postCount()
	if _, err := x.a.s.ApproveFinish(ctx, x.r); !errors.Is(err, crypto.ErrAccountMismatch) {
		t.Fatalf("finish after the account changed: %v", err)
	}
	if x.r.postCount() != n {
		t.Error("a device_add under the old account keys was posted")
	}
	if info, err := x.a.s.Approval(); err != nil || info.State != crypto.ApprovalFailed {
		t.Fatalf("approval %+v %v", info, err)
	}
	id, _ := vaultlog.NewID()
	if err := x.a.s.ApproveStart(id); err != nil {
		t.Errorf("a new approval: %v", err)
	}
}

// [P2] A password unlock that drops a checkpoint journal and an approval
// journal no device record can open records the loss durably and reports
// it, also with an empty outbox, until it is acknowledged.
func TestLostJournalsAreReported(t *testing.T) {
	ctx := context.Background()
	f, r := serverVault(t)
	addHost(t, f.s, "web")
	pushAll(t, f.s, r)
	if empty, _ := f.s.OutboxEmpty(); !empty {
		t.Fatal("the outbox is not empty")
	}
	r.onPost = func(*vaultlog.Wire) (bool, error) { return false, errLostResponse }
	if _, err := f.s.Rotate(ctx, r, []byte(testPassword), CheckpointOptions{}); !errors.Is(err, errLostResponse) {
		t.Fatalf("lost post: %v", err)
	}
	r.onPost = nil
	id, _ := vaultlog.NewID()
	if err := f.s.ApproveStart(id); err != nil {
		t.Fatal(err)
	}
	f.cfg.Keyring.(*memRing).clear()
	s := open(t, f.cfg)
	if err := s.UnlockWithPasswordRemote(ctx, r, []byte(testPassword), f.kit.SecretKey); err != nil {
		t.Fatal(err)
	}
	check := func(s *Store, want LostJournals) {
		t.Helper()
		got, err := s.LostJournals()
		if err != nil || got != want {
			t.Errorf("lost journals %+v %v; want %+v", got, err, want)
		}
		if hasWarning(s.Info(), "checkpoint (hop passwd") != want.Checkpoint || hasWarning(s.Info(), "an approval of a new device") != want.Approval {
			t.Errorf("warnings %q", s.Info().Warnings)
		}
	}
	check(s, LostJournals{Checkpoint: true, Approval: true})
	if lost, _ := s.LostIntents(); lost != 0 {
		t.Errorf("lost intents %d", lost)
	}
	if journalExists(t, f.cfg) {
		t.Error("the unreadable checkpoint journal is still there")
	}
	s = open(t, f.cfg)
	check(s, LostJournals{Checkpoint: true, Approval: true})
	if err := s.AckLostJournals(); err != nil {
		t.Fatal(err)
	}
	check(s, LostJournals{})
	s = open(t, f.cfg)
	check(s, LostJournals{})
}

// [P2] A rebuilt device_add (§5.4) carries a freshly sealed unlock blob,
// journaled with it, for the same device and certificate; the delivery
// carries the committed one, and it installs.
func TestApprovalRebuildReseals(t *testing.T) {
	ctx := context.Background()
	x := newEnrollFix(t)
	e, commit, chal, open := x.confirmedOnBoth(t)
	var adds []*vaultlog.DeviceAddOp
	x.r.onPost = func(w *vaultlog.Wire) (bool, error) {
		if w.Entry.Kind != vaultlog.KindNormal {
			return true, nil
		}
		found := false
		for _, o := range w.Entry.Ops {
			if d, ok := o.(*vaultlog.DeviceAddOp); ok {
				adds, found = append(adds, d), true
			}
		}
		if found && len(adds) == 1 {
			return false, errLostResponse
		}
		return true, nil
	}
	if _, err := x.a.s.ApproveFinish(ctx, x.r); !errors.Is(err, errLostResponse) {
		t.Fatalf("lost post: %v", err)
	}
	// Another device writes first: the candidate is dead, and rebuilt.
	b := secondDevice(t, x.a, x.r)
	addHost(t, b.s, "db")
	pushAll(t, b.s, x.r)
	env, err := x.a.s.ApproveFinish(ctx, x.r)
	if err != nil {
		t.Fatal(err)
	}
	if len(adds) != 2 {
		t.Fatalf("%d device_adds posted", len(adds))
	}
	first, second := adds[0], adds[1]
	if first.UnlockSHA256.Equal(second.UnlockSHA256) {
		t.Error("the rebuild reused the unlock blob")
	}
	if first.Cert != second.Cert || string(first.CertSig) != string(second.CertSig) || string(first.KEMPK) != string(second.KEMPK) {
		t.Error("the rebuild changed the device or its certificate")
	}
	th := crypto.TranscriptHash(crypto.Transcript(commit.C, &chal, &open))
	if got, ok := second.Cert.EnrollTranscript.Get(); !ok || !got.Equal(th) {
		t.Error("the rebuilt certificate is not bound to the transcript")
	}
	kem, _ := e.d.DeviceKeys()
	d, err := crypto.OpenDelivery(kem, th, env)
	if err != nil {
		t.Fatal(err)
	}
	if h, err := d.Unlock.Digest(); err != nil || !h.Equal(second.UnlockSHA256) {
		t.Error("the delivery does not carry the committed unlock blob")
	}
	s, err := e.Install(ctx, x.remote(), &env)
	if err != nil {
		t.Fatal(err)
	}
	track(t, x.cfg, s)
	x.installed(t, s)
}

// The lead's rule for a password change (§10.1): a rebuild that would
// revoke a device which appeared after it started stops and names it; the
// same call, keeping or excluding it, finishes. A rotation still excludes
// such a device without asking (TestCheckpointRebuildExcludesNewDevice).
func TestPasswordChangeAsksAboutNewDevices(t *testing.T) {
	ctx := context.Background()
	for _, keepIt := range []bool{false, true} {
		t.Run(map[bool]string{false: "exclude", true: "keep"}[keepIt], func(t *testing.T) {
			a, b, r := newCkptPair(t)
			aID, bID := deviceID(t, a.s), deviceID(t, b.s)
			var newID model.ID
			a.s.testHook = func(stage string) error {
				if stage != "checkpoint:post" || !newID.IsZero() {
					return nil
				}
				pull(t, b.s, r)
				_, info, err := newDeviceRecord(accountOfKit(t, a), a.kit.SecretKey)
				if err != nil {
					return err
				}
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
				return nil
			}
			_, err := a.s.ChangePasswordRemote(ctx, r, []byte(testPassword), []byte(newPassword), CheckpointOptions{})
			var nd *NewDevicesError
			if !errors.As(err, &nd) || !errors.Is(err, ErrCheckpointRebuild) || !slices.Equal(nd.Devices, []model.ID{newID}) {
				t.Fatalf("rebuild with a new device: %v", err)
			}
			if serverCheckpoints(t, r) != 0 {
				t.Fatal("a checkpoint committed")
			}
			// Asked again without an answer, or with a device that did not
			// appear, it still refuses.
			if _, err := a.s.ChangePasswordRemote(ctx, r, []byte(testPassword), []byte(newPassword), CheckpointOptions{}); !errors.As(err, &nd) {
				t.Errorf("again without an answer: %v", err)
			}
			if _, err := a.s.ChangePasswordRemote(ctx, r, []byte(testPassword), []byte(newPassword), CheckpointOptions{Exclude: []string{bID.String()}}); err == nil || errors.As(err, &nd) {
				t.Errorf("excluding a device that did not appear: %v", err)
			}
			opts := CheckpointOptions{Exclude: []string{newID.String()}}
			if keepIt {
				opts = CheckpointOptions{Keep: []string{newID.String()}}
			}
			kit, err := a.s.ChangePasswordRemote(ctx, r, []byte(testPassword), []byte(newPassword), opts)
			if err != nil {
				t.Fatal(err)
			}
			if !serverActive(t, r, aID) || !serverActive(t, r, bID) || serverActive(t, r, newID) != keepIt {
				t.Errorf("active: a %v b %v new %v", serverActive(t, r, aID), serverActive(t, r, bID), serverActive(t, r, newID))
			}
			if !opensAccount(t, a.s, newPassword, kit.SecretKey) {
				t.Error("the kit is not the rebuilt checkpoint's")
			}
		})
	}
	t.Run("nothing to answer", func(t *testing.T) {
		a, b, r := newCkptPair(t)
		if _, err := a.s.ChangePasswordRemote(ctx, r, []byte(testPassword), []byte(newPassword), CheckpointOptions{Keep: []string{deviceID(t, b.s).String()}}); err == nil {
			t.Error("a password change took Keep with no new device")
		}
		if _, err := a.s.Rotate(ctx, r, []byte(testPassword), CheckpointOptions{Exclude: []string{deviceID(t, b.s).String()}}); err == nil {
			t.Error("a rotation took Exclude")
		}
	})
}

// Fault injection at A's budget reservation and journal writes (§7): a
// crash at any boundary never grants more than the budget, never leaves
// two challenges outstanding, never posts a device_add twice, and leaves a
// state the next call finishes.
func TestApprovalCrashBoundaries(t *testing.T) {
	ctx := context.Background()
	t.Run("reservation not persisted", func(t *testing.T) {
		x := newEnrollFix(t)
		x.a.s.testHook = crashFrom("approve:budget")
		id, _ := vaultlog.NewID()
		if err := x.a.s.ApproveStart(id); !errors.Is(err, errCrash) {
			t.Fatalf("start: %v", err)
		}
		x.a.s = open(t, x.a.cfg)
		if n, err := x.a.s.ApprovalsRemaining(); err != nil || n != 3 {
			t.Errorf("remaining %d %v", n, err)
		}
		if info, err := x.a.s.Approval(); err != nil || info != nil {
			t.Errorf("approval %+v %v", info, err)
		}
		if err := x.a.s.ApproveStart(id); err != nil {
			t.Error(err)
		}
	})
	t.Run("reserved, journal not written", func(t *testing.T) {
		x := newEnrollFix(t)
		var shift time.Duration
		x.withClock(&shift)
		x.a.s.testHook = crashFrom("approve:journal")
		id, _ := vaultlog.NewID()
		if err := x.a.s.ApproveStart(id); !errors.Is(err, errCrash) {
			t.Fatalf("start: %v", err)
		}
		x.a.s = open(t, x.a.cfg)
		if info, err := x.a.s.Approval(); err != nil || info != nil {
			t.Errorf("approval %+v %v", info, err)
		}
		// The slot is spent and the reservation stays outstanding until its
		// deadline, never shorter.
		if err := x.a.s.ApproveStart(id); !errors.Is(err, crypto.ErrChallengeOutstanding) {
			t.Errorf("start during the reservation: %v", err)
		}
		shift = crypto.EnrollDeadline + time.Second
		if n, err := x.a.s.ApprovalsRemaining(); err != nil || n != 2 {
			t.Errorf("remaining %d %v", n, err)
		}
		if err := x.a.s.ApproveStart(id); err != nil {
			t.Error(err)
		}
	})
	t.Run("challenge not journaled", func(t *testing.T) {
		x := newEnrollFix(t)
		e, commit := x.begin(t)
		id, _ := vaultlog.NewID()
		if err := e.SetEnrollID(id); err != nil {
			t.Fatal(err)
		}
		if err := x.a.s.ApproveStart(id); err != nil {
			t.Fatal(err)
		}
		x.a.s.testHook = crashFrom("approve:journal")
		if _, err := x.a.s.ApproveCommit(&commit); !errors.Is(err, errCrash) {
			t.Fatalf("commit: %v", err)
		}
		x.a.s = open(t, x.a.cfg)
		if info, err := x.a.s.Approval(); err != nil || info.State != crypto.ApprovalReserved {
			t.Fatalf("approval %+v %v", info, err)
		}
		chal, err := x.a.s.ApproveCommit(&commit)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := e.HandleChal(&chal); err != nil {
			t.Fatal(err)
		}
	})
	// The device_add: the journal write of its preparation, of its
	// candidate, the post, the delivery's seal and its persisting.
	for _, tc := range []struct {
		name   string
		hook   func(string) error
		posted bool // the device_add reached the server before the crash
	}{
		{"prepared, not journaled", crashAtN("approve:journal", 1), false},
		{"candidate not journaled", crashAtN("approve:journal", 2), false},
		{"journaled, not posted", crashAt("approve:post"), false},
		{"committed, settlement not journaled", crashAtN("approve:journal", 3), true},
		{"committed, not delivered", crashAt("approve:deliver"), true},
		{"delivery not journaled", crashAtN("approve:journal", 4), true},
		{"delivered, budget not released", crashAt("approve:budget"), true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			x := newEnrollFix(t)
			e, _, _, _ := x.confirmedOnBoth(t)
			before := x.r.head().Seq
			x.a.s.testHook = tc.hook
			if _, err := x.a.s.ApproveFinish(ctx, x.r); !errors.Is(err, errCrash) {
				t.Fatalf("finish: %v", err)
			}
			if posted := x.r.head().Seq > before; posted != tc.posted {
				t.Fatalf("posted %v; want %v", posted, tc.posted)
			}
			x.a.s = open(t, x.a.cfg)
			env, err := x.a.s.ApproveFinish(ctx, x.r)
			if err != nil {
				t.Fatal(err)
			}
			if x.r.head().Seq != before+1 {
				t.Errorf("%d entries; want one device_add", x.r.head().Seq-before)
			}
			s, err := e.Install(ctx, x.remote(), &env)
			if err != nil {
				t.Fatal(err)
			}
			track(t, x.cfg, s)
			x.installed(t, s)
		})
	}
	t.Run("orphan move not committed", func(t *testing.T) {
		x := newEnrollFix(t)
		x.confirmedOnBoth(t)
		x.r.onPost = func(*vaultlog.Wire) (bool, error) { return true, errLostResponse }
		if _, err := x.a.s.ApproveFinish(ctx, x.r); !errors.Is(err, errLostResponse) {
			t.Fatalf("lost response: %v", err)
		}
		x.r.onPost = nil
		dev := x.prepared(t).Cert.DeviceID
		x.a.s.testHook = crashAt("approve:orphans")
		if err := x.a.s.ApproveAbort(); !errors.Is(err, errCrash) {
			t.Fatalf("abort: %v", err)
		}
		x.a.s = open(t, x.a.cfg)
		pull(t, x.a.s, x.r)
		// The failed attempt, not yet moved, is still reported; the next
		// load moves it, and the new approval does not forget it.
		if !hasWarning(x.a.s.Info(), dev.String()) {
			t.Errorf("before the move: %q", x.a.s.Info().Warnings)
		}
		id, _ := vaultlog.NewID()
		if err := x.a.s.ApproveStart(id); err != nil {
			t.Fatal(err)
		}
		if !hasWarning(x.a.s.Info(), dev.String()) {
			t.Errorf("after the move: %q", x.a.s.Info().Warnings)
		}
	})
}
