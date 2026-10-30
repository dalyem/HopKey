package store

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/dalyem/hopkey/internal/crypto"
	"github.com/dalyem/hopkey/internal/model"
	"github.com/dalyem/hopkey/internal/vaultlog"
)

// Slice E2: enrollment by approval (§7), with the messages passed in memory
// where slice E3's relay will carry them.

type enrollFix struct {
	a   *fixture
	r   *fakeRemote
	srv *fakeServer
	cfg Config // the new device's data directory
}

func newEnrollFix(t *testing.T) *enrollFix {
	t.Helper()
	a, r := serverVault(t)
	addHost(t, a.s, "web")
	if res := pushAll(t, a.s, r); res.Outcome != PushEmpty {
		t.Fatalf("push: %+v", res)
	}
	return &enrollFix{a: a, r: r, srv: newFakeServer(t, r), cfg: testConfig(t)}
}

func (x *enrollFix) params() EnrollParams {
	return EnrollParams{ServerURL: x.srv.origin, Email: testEmail, DeviceName: "phone"}
}

func (x *enrollFix) begin(t *testing.T) (*Enrollment, crypto.EnrollCommit) {
	t.Helper()
	e, commit, err := BeginEnrollment(x.cfg, x.params())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { e.Close() })
	return e, commit
}

// resume restarts the new device: the enrollment is closed and resumed.
func (x *enrollFix) resume(t *testing.T, e *Enrollment) *Enrollment {
	t.Helper()
	e.Close()
	e, err := ResumeEnrollment(x.cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { e.Close() })
	return e
}

// reveal relays commit, chal and open, and checks that both sides show the
// same SAS and name.
func (x *enrollFix) reveal(t *testing.T, e *Enrollment, commit crypto.EnrollCommit) (crypto.EnrollChal, crypto.EnrollOpen) {
	t.Helper()
	id, err := vaultlog.NewID()
	if err != nil {
		t.Fatal(err)
	}
	if err := e.SetEnrollID(id); err != nil {
		t.Fatal(err)
	}
	if err := x.a.s.ApproveStart(id); err != nil {
		t.Fatal(err)
	}
	chal, err := x.a.s.ApproveCommit(&commit)
	if err != nil {
		t.Fatal(err)
	}
	open, err := e.HandleChal(&chal)
	if err != nil {
		t.Fatal(err)
	}
	sasA, name, err := x.a.s.ApproveOpen(&open)
	if err != nil {
		t.Fatal(err)
	}
	sasD, err := e.SAS()
	if err != nil {
		t.Fatal(err)
	}
	if sasA != sasD || name != "phone" {
		t.Fatalf("SAS %q vs %q, name %q", sasA, sasD, name)
	}
	return chal, open
}

// approve confirms on A and has A commit the device and seal the delivery.
func (x *enrollFix) approve(t *testing.T) crypto.HPKEEnvelope {
	t.Helper()
	if err := x.a.s.ApproveConfirm(true); err != nil {
		t.Fatal(err)
	}
	env, err := x.a.s.ApproveFinish(context.Background(), x.r)
	if err != nil {
		t.Fatal(err)
	}
	return env
}

func (x *enrollFix) remote() EnrollRemote { return publisher{x.srv} }

// installed checks the new device's vault after Install.
func (x *enrollFix) installed(t *testing.T, s *Store) {
	t.Helper()
	if info := s.Info(); info.Locked || info.AccountID != x.a.kit.AccountID {
		t.Fatalf("after the install: %+v", info)
	}
	if !s.ServerBacked() {
		t.Fatal("not server-backed")
	}
	hostNamed(t, snapshot(t, s), "web")
	if got := storedSecretKey(t, x.cfg, s); got != "" {
		t.Error("an enrolled device stores a Secret Key")
	}
	dc := diskDeviceConfig(t, x.cfg)
	if dc.DeviceID != deviceID(t, s) || dc.Pending != nil {
		t.Errorf("device.json %+v", dc)
	}
	if si, err := s.ServerInfo(); err != nil || si.Server != x.srv.origin || si.Email != testEmail || si.CheckpointDue {
		t.Errorf("server info %+v %v", si, err)
	}
	if pending, _ := s.l.enrollPending(); pending {
		t.Error("enroll.json outlived the install")
	}
	noUntrackedRecords(t, x.cfg, "after the install")
}

// The full enrollment: D commits, A challenges, both show one SAS, the user
// confirms on both, A commits the device_add and delivers, and D installs a
// vault verified from the delivered anchor. Both then sync, and D reopens
// with no Secret Key stored.
func TestEnrollmentFull(t *testing.T) {
	ctx := context.Background()
	x := newEnrollFix(t)
	e, commit := x.begin(t)
	if e.State() != crypto.DeviceCommitted {
		t.Fatalf("state %s", e.State())
	}
	x.reveal(t, e, commit)
	if err := e.ConfirmSAS(); err != nil {
		t.Fatal(err)
	}
	env := x.approve(t)
	// Called again, A returns the same delivery.
	again, err := x.a.s.ApproveFinish(ctx, x.r)
	if err != nil {
		t.Fatal(err)
	}
	if d1, _ := env.Digest(); !func() bool { d2, _ := again.Digest(); return d1.Equal(d2) }() {
		t.Error("a second ApproveFinish sealed another delivery")
	}
	if info, err := x.a.s.Approval(); err != nil || info.State != crypto.ApprovalDelivered {
		t.Errorf("approval %+v %v", info, err)
	}
	s, err := e.Install(ctx, x.remote(), &env)
	if err != nil {
		t.Fatal(err)
	}
	track(t, x.cfg, s)
	x.installed(t, s)
	dID := deviceID(t, s)
	if !serverActive(t, x.r, dID) {
		t.Error("the new device is not active on the server")
	}
	// A lists it as added by approval.
	pull(t, x.a.s, x.r)
	ls, err := x.a.s.Devices()
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, l := range ls {
		if l.ID == dID {
			found = l.How == AddedByApproval && l.Name == "phone"
		}
	}
	if !found {
		t.Errorf("listing %+v", ls)
	}
	// Both sync.
	addHost(t, s, "from-phone")
	if res := pushAll(t, s, x.r); res.Outcome != PushEmpty {
		t.Fatalf("push: %+v", res)
	}
	pull(t, x.a.s, x.r)
	hostNamed(t, snapshot(t, x.a.s), "from-phone")
	// It reopens with its device key, no Secret Key stored.
	s = open(t, x.cfg)
	if info := s.Info(); info.Locked {
		t.Fatalf("the enrolled device does not reopen: %s", info.LockReason)
	}
	// It crosses a checkpoint that keeps it.
	if _, err := x.a.s.Rotate(ctx, x.r, []byte(testPassword), CheckpointOptions{Keep: []string{dID.String()}}); err != nil {
		t.Fatal(err)
	}
	pull(t, s, x.r)
	hostNamed(t, snapshot(t, s), "from-phone")
}

// A crash at every step of D (§7: every transition is persisted before
// anything is sent) resumes in the state it reached, and a resumed device
// accepts no second chal. A crash before the first state was durable
// forgets the attempt, which produced nothing.
func TestEnrollmentDeviceCrashAtEachState(t *testing.T) {
	ctx := context.Background()
	x := newEnrollFix(t)
	for _, stage := range []string{"enroll:intent", "enroll:persist"} {
		if _, _, err := beginEnrollment(x.cfg, x.params(), crashAt(stage)); !errors.Is(err, errCrash) {
			t.Fatalf("%s: %v", stage, err)
		}
		if _, err := ResumeEnrollment(x.cfg); !errors.Is(err, ErrNoEnrollment) {
			t.Fatalf("resume after a crash at %s: %v", stage, err)
		}
	}
	e, commit := x.begin(t)
	// COMMITTED.
	e = x.resume(t, e)
	if e.State() != crypto.DeviceCommitted || e.Commit() != commit {
		t.Fatalf("resumed %s, commit %v", e.State(), e.Commit())
	}
	id, _ := vaultlog.NewID()
	if err := e.SetEnrollID(id); err != nil {
		t.Fatal(err)
	}
	e = x.resume(t, e)
	if err := e.SetEnrollID(id); err != nil {
		t.Errorf("the same enroll_id again: %v", err)
	}
	if err := x.a.s.ApproveStart(id); err != nil {
		t.Fatal(err)
	}
	chal, err := x.a.s.ApproveCommit(&commit)
	if err != nil {
		t.Fatal(err)
	}
	open, err := e.HandleChal(&chal)
	if err != nil {
		t.Fatal(err)
	}
	// REVEALED: exactly one chal, the same open again.
	e = x.resume(t, e)
	if e.State() != crypto.DeviceRevealed {
		t.Fatalf("resumed %s", e.State())
	}
	if _, err := e.HandleChal(&chal); !errors.Is(err, crypto.ErrChalAfterReveal) {
		t.Errorf("a second chal: %v", err)
	}
	if again, err := e.Open(); err != nil || string(again.KEMPK) != string(open.KEMPK) || string(again.ND) != string(open.ND) {
		t.Errorf("open after a restart: %v", err)
	}
	if _, _, err := x.a.s.ApproveOpen(&open); err != nil {
		t.Fatal(err)
	}
	// CONFIRMED.
	if err := e.ConfirmSAS(); err != nil {
		t.Fatal(err)
	}
	e = x.resume(t, e)
	if e.State() != crypto.DeviceConfirmed {
		t.Fatalf("resumed %s", e.State())
	}
	env := x.approve(t)
	// DONE, then a crash at each step of the install; the delivery is
	// handed in once, and every later attempt uses the persisted one.
	delivery := &env
	for _, stage := range []string{"enroll:delivered", "enroll:intent-device", "enroll:record", "enroll:fetch", "signin:install"} {
		e.s.testHook = crashAt(stage)
		if _, err := e.Install(ctx, x.remote(), delivery); !errors.Is(err, errCrash) {
			t.Fatalf("install crashing at %s: %v", stage, err)
		}
		delivery = nil
		e = x.resume(t, e)
		if e.State() != crypto.DeviceDone {
			t.Fatalf("after a crash at %s: %s", stage, e.State())
		}
		noUntrackedRecords(t, x.cfg, "after a crash at "+stage)
	}
	// The install commits, and the cleanup after it crashes.
	e.s.testHook = crashAt("enroll:cleanup")
	s, err := e.Install(ctx, x.remote(), nil)
	if err != nil {
		t.Fatal(err)
	}
	s.Close()
	if pending, _ := (layout{data: x.cfg.DataDir}).enrollPending(); !pending {
		t.Fatal("the cleanup did not crash")
	}
	s, err = InstallEnrolled(ctx, x.cfg, x.remote(), nil)
	if err != nil {
		t.Fatal(err)
	}
	track(t, x.cfg, s)
	x.installed(t, s)
	if n := activeCount(t, x.srv); n != 2 {
		t.Errorf("%d active devices; want 2", n)
	}
}

// §7 step 6: a delivery that arrives before the user confirmed the SAS on D
// is discarded with no change of state; after confirmation it is accepted.
func TestEnrollmentDeliveryBeforeConfirmedIsDiscarded(t *testing.T) {
	ctx := context.Background()
	x := newEnrollFix(t)
	e, commit := x.begin(t)
	x.reveal(t, e, commit)
	env := x.approve(t)
	if _, err := e.Install(ctx, x.remote(), &env); !errors.Is(err, crypto.ErrSASNotConfirmed) {
		t.Fatalf("delivery before confirmation: %v", err)
	}
	e = x.resume(t, e)
	if e.State() != crypto.DeviceRevealed {
		t.Fatalf("state %s", e.State())
	}
	if _, err := os.Lstat(x.cfg.DataDir + "/device.json"); !errors.Is(err, os.ErrNotExist) {
		t.Error("a discarded delivery wrote device.json")
	}
	if err := e.ConfirmSAS(); err != nil {
		t.Fatal(err)
	}
	s, err := e.Install(ctx, x.remote(), &env)
	if err != nil {
		t.Fatal(err)
	}
	track(t, x.cfg, s)
	x.installed(t, s)
}

// REJECTED is terminal (§7): the keys are wiped, no delivery is accepted,
// a restart keeps it, and only discarding it lets a new enrollment start.
func TestEnrollmentRejectedIsTerminal(t *testing.T) {
	ctx := context.Background()
	x := newEnrollFix(t)
	e, commit := x.begin(t)
	chal, _ := x.reveal(t, e, commit)
	if err := e.RejectSAS(); err != nil {
		t.Fatal(err)
	}
	if k, s := e.d.DeviceKeys(); k != nil || s != nil {
		t.Error("a rejected enrollment keeps its keys")
	}
	env := x.approve(t)
	if _, err := e.Install(ctx, x.remote(), &env); !errors.Is(err, crypto.ErrSASRejected) {
		t.Fatalf("delivery after rejection: %v", err)
	}
	e = x.resume(t, e)
	if e.State() != crypto.DeviceRejected {
		t.Fatalf("resumed %s", e.State())
	}
	if _, err := e.Install(ctx, x.remote(), &env); !errors.Is(err, crypto.ErrSASRejected) {
		t.Errorf("delivery after a restart: %v", err)
	}
	if _, err := e.Install(ctx, x.remote(), nil); !errors.Is(err, crypto.ErrSASRejected) {
		t.Errorf("install from the persisted delivery: %v", err)
	}
	if _, err := e.HandleChal(&chal); err == nil {
		t.Error("a rejected enrollment accepted a chal")
	}
	e.Close()
	if _, _, err := BeginEnrollment(x.cfg, x.params()); !errors.Is(err, ErrEnrollmentPending) {
		t.Errorf("begin over a rejected enrollment: %v", err)
	}
	if err := DiscardEnrollment(x.cfg); err != nil {
		t.Fatal(err)
	}
	noUntrackedRecords(t, x.cfg, "after the discard")
	e2, _, err := BeginEnrollment(x.cfg, x.params())
	if err != nil {
		t.Fatalf("begin after the discard: %v", err)
	}
	e2.Close()
}

// A delivery substituted by the relay, sealed to D's key and binding its
// transcript but carrying another account's keys, fails §7 step 6: it is
// discarded with no change of state, and the real one still installs.
func TestEnrollmentSubstitutedDeliveryRefused(t *testing.T) {
	ctx := context.Background()
	x := newEnrollFix(t)
	e, commit := x.begin(t)
	chal, open := x.reveal(t, e, commit)
	if err := e.ConfirmSAS(); err != nil {
		t.Fatal(err)
	}
	env := x.approve(t)
	// The attacker's own account, and everything public in the transcript.
	m := newVault(t, testConfig(t))
	acct := cloneAccount(t, m.s)
	th := crypto.TranscriptHash(crypto.Transcript(commit.C, &chal, &open))
	devID, _ := vaultlog.NewID()
	cert := crypto.Cert{
		V: crypto.Version, AccountID: acct.AccountID, AKV: acct.AKV, DeviceID: devID, Name: "phone",
		KEMFp: crypto.FpKEM(open.KEMPK), SigFp: crypto.FpSig(open.SigPK), EnrollTranscript: crypto.SomeHash(th),
		IssuedAt: model.TimestampOf(time.Now()),
	}
	sig, err := crypto.SignCert(acct, &cert)
	if err != nil {
		t.Fatal(err)
	}
	unlock, err := crypto.SealUnlock(open.KEMPK, &cert, acct)
	if err != nil {
		t.Fatal(err)
	}
	fake, err := crypto.SealDelivery(open.KEMPK, th, &crypto.EnrollDelivery{V: crypto.Version, Cert: cert, CertSig: sig, Unlock: unlock, AnchorSeq: 0})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.Install(ctx, x.remote(), &fake); !errors.Is(err, crypto.ErrAccountMismatch) || !errors.Is(err, ErrDeliveryInvalid) {
		t.Fatalf("a substituted delivery: %v", err)
	}
	if e.State() != crypto.DeviceConfirmed {
		t.Fatalf("state after a substituted delivery: %s", e.State())
	}
	if _, err := os.Lstat(x.cfg.DataDir + "/device.json"); !errors.Is(err, os.ErrNotExist) {
		t.Error("a substituted delivery wrote device.json")
	}
	s, err := e.Install(ctx, x.remote(), &env)
	if err != nil {
		t.Fatal(err)
	}
	track(t, x.cfg, s)
	x.installed(t, s)
}

// substitutedDelivery is what an approver in the middle sends: sealed to
// D's key and binding the transcript D saw, but carrying the attacker's
// own account.
func substitutedDelivery(t *testing.T, commit crypto.EnrollCommit, chal crypto.EnrollChal, open crypto.EnrollOpen) crypto.HPKEEnvelope {
	t.Helper()
	m := newVault(t, testConfig(t))
	acct := cloneAccount(t, m.s)
	th := crypto.TranscriptHash(crypto.Transcript(commit.C, &chal, &open))
	devID, _ := vaultlog.NewID()
	cert := crypto.Cert{
		V: crypto.Version, AccountID: acct.AccountID, AKV: acct.AKV, DeviceID: devID, Name: open.Name,
		KEMFp: crypto.FpKEM(open.KEMPK), SigFp: crypto.FpSig(open.SigPK), EnrollTranscript: crypto.SomeHash(th),
		IssuedAt: model.TimestampOf(time.Now()),
	}
	sig, err := crypto.SignCert(acct, &cert)
	if err != nil {
		t.Fatal(err)
	}
	unlock, err := crypto.SealUnlock(open.KEMPK, &cert, acct)
	if err != nil {
		t.Fatal(err)
	}
	env, err := crypto.SealDelivery(open.KEMPK, th, &crypto.EnrollDelivery{V: crypto.Version, Cert: cert, CertSig: sig, Unlock: unlock, AnchorSeq: 0})
	if err != nil {
		t.Fatal(err)
	}
	return env
}

// §7: a substituted approver's delivery is never installed without the
// user's SAS confirmation on D. Before the confirmation (the state hop
// auth login is in when it has no terminal to confirm on) it is refused
// with nothing written, whatever account it carries; after a rejection it
// is refused for good.
func TestEnrollmentSubstitutedApproverNeedsTheSAS(t *testing.T) {
	ctx := context.Background()
	x := newEnrollFix(t)
	e, commit := x.begin(t)
	chal, open := x.reveal(t, e, commit)
	fake := substitutedDelivery(t, commit, chal, open)
	for range 2 {
		if _, err := e.Install(ctx, x.remote(), &fake); !errors.Is(err, crypto.ErrSASNotConfirmed) {
			t.Fatalf("a substituted delivery before the confirmation: %v", err)
		}
		if e.State() != crypto.DeviceRevealed {
			t.Fatalf("state after a substituted delivery: %s", e.State())
		}
		e = x.resume(t, e)
	}
	if _, err := os.Lstat(x.cfg.DataDir + "/device.json"); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("a delivery before the confirmation wrote device.json")
	}
	if err := e.RejectSAS(); err != nil {
		t.Fatal(err)
	}
	if _, err := e.Install(ctx, x.remote(), &fake); !errors.Is(err, crypto.ErrSASRejected) {
		t.Fatalf("a substituted delivery after the rejection: %v", err)
	}
	if ok, err := Exists(x.cfg.DataDir); err != nil || ok {
		t.Errorf("a vault exists after the rejection: %v %v", ok, err)
	}
}

// A's approval budget (§7: 3 per rolling hour, one outstanding challenge)
// is persisted, so a restart resets neither.
func TestApprovalBudgetPersists(t *testing.T) {
	cfg := testConfig(t)
	var shift time.Duration
	cfg.Now = func() time.Time { return time.Now().Add(shift) }
	a := newVault(t, cfg)
	if err := a.s.EnableServerMode(); err != nil {
		t.Fatal(err)
	}
	newID := func() model.ID {
		id, err := vaultlog.NewID()
		if err != nil {
			t.Fatal(err)
		}
		return id
	}
	// One outstanding challenge, across a restart.
	if err := a.s.ApproveStart(newID()); err != nil {
		t.Fatal(err)
	}
	a.s = open(t, cfg)
	if err := a.s.ApproveStart(newID()); !errors.Is(err, ErrApprovalPending) {
		t.Errorf("a second approval after a restart: %v", err)
	}
	if info, err := a.s.Approval(); err != nil || info == nil || info.State != crypto.ApprovalReserved {
		t.Errorf("approval %+v %v", info, err)
	}
	if err := a.s.ApproveAbort(); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if err := a.s.ApproveStart(newID()); err != nil {
			t.Fatal(err)
		}
		if err := a.s.ApproveAbort(); err != nil {
			t.Fatal(err)
		}
	}
	if err := a.s.ApproveStart(newID()); !errors.Is(err, crypto.ErrBudgetExhausted) {
		t.Fatalf("a fourth approval: %v", err)
	}
	a.s = open(t, cfg)
	if err := a.s.ApproveStart(newID()); !errors.Is(err, crypto.ErrBudgetExhausted) {
		t.Errorf("a fourth approval after a restart: %v", err)
	}
	if n, err := a.s.ApprovalsRemaining(); err != nil || n != 0 {
		t.Errorf("remaining %d %v", n, err)
	}
	// The window rolls.
	shift = 61 * time.Minute
	a.s = open(t, cfg)
	if n, err := a.s.ApprovalsRemaining(); err != nil || n != 3 {
		t.Errorf("remaining an hour later %d %v", n, err)
	}
	if err := a.s.ApproveStart(newID()); err != nil {
		t.Errorf("an approval an hour later: %v", err)
	}
}

// An enrolled device stores no Secret Key (§11 addendum): a password unlock
// after it loses its device key, and its own password change, take the
// Secret Key from the caller and refuse without it. Its own checkpoint
// stores the new one.
func TestEnrolledDeviceNeedsSecretKey(t *testing.T) {
	ctx := context.Background()
	x := newEnrollFix(t)
	e, commit := x.begin(t)
	x.reveal(t, e, commit)
	if err := e.ConfirmSAS(); err != nil {
		t.Fatal(err)
	}
	env := x.approve(t)
	s, err := e.Install(ctx, x.remote(), &env)
	if err != nil {
		t.Fatal(err)
	}
	track(t, x.cfg, s)
	acct, dev := accountOfKit(t, x.a), deviceID(t, s)
	// Its own password change needs the Secret Key passed in.
	if _, err := s.ChangePasswordRemote(ctx, x.r, []byte(testPassword), []byte(newPassword), CheckpointOptions{}); !errors.Is(err, ErrNeedSecretKey) {
		t.Errorf("password change without the Secret Key: %v", err)
	}
	// The device key is lost: a password unlock needs the Secret Key.
	release(x.cfg)
	if err := x.cfg.Keyring.Delete(keychainService, slotOf(acct, dev)); err != nil {
		t.Fatal(err)
	}
	s = open(t, x.cfg)
	if !s.Info().Locked {
		t.Fatal("unlocked without its device key")
	}
	if err := s.UnlockWithPasswordRemote(ctx, x.r, []byte(testPassword), ""); !errors.Is(err, ErrNeedSecretKey) {
		t.Fatalf("password unlock without the Secret Key: %v", err)
	}
	if err := s.UnlockWithPasswordRemote(ctx, x.r, []byte(testPassword), x.a.kit.SecretKey); err != nil {
		t.Fatal(err)
	}
	hostNamed(t, snapshot(t, s), "web")
	// The new record keeps the Secret Key it was given, and the password
	// change works from it.
	kit, err := s.ChangePasswordRemote(ctx, x.r, []byte(testPassword), []byte(newPassword), CheckpointOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if err := s.AckKit(); err != nil {
		t.Fatal(err)
	}
	if got := storedSecretKey(t, x.cfg, s); got != kit.SecretKey {
		t.Error("the checkpoint did not store the new Secret Key")
	}
}

// The password change of an enrolled device that still has its key, with
// the Secret Key passed in, stores the new one.
func TestEnrolledDevicePasswordChangeStoresSecretKey(t *testing.T) {
	ctx := context.Background()
	x := newEnrollFix(t)
	e, commit := x.begin(t)
	x.reveal(t, e, commit)
	if err := e.ConfirmSAS(); err != nil {
		t.Fatal(err)
	}
	env := x.approve(t)
	s, err := e.Install(ctx, x.remote(), &env)
	if err != nil {
		t.Fatal(err)
	}
	track(t, x.cfg, s)
	if _, err := s.ChangePasswordRemote(ctx, x.r, []byte(testPassword), []byte(newPassword), CheckpointOptions{SecretKey: "not a key"}); err == nil {
		t.Error("a malformed Secret Key was accepted")
	}
	kit, err := s.ChangePasswordRemote(ctx, x.r, []byte(testPassword), []byte(newPassword), CheckpointOptions{SecretKey: x.a.kit.SecretKey})
	if err != nil {
		t.Fatal(err)
	}
	if err := s.AckKit(); err != nil {
		t.Fatal(err)
	}
	if got := storedSecretKey(t, x.cfg, s); got != kit.SecretKey {
		t.Error("the checkpoint did not store the new Secret Key")
	}
	// The approver crosses it and keeps working.
	pull(t, x.a.s, x.r)
	hostNamed(t, snapshot(t, x.a.s), "web")
	if s = open(t, x.cfg); s.Info().Locked {
		t.Errorf("does not reopen: %s", s.Info().LockReason)
	}
}

// rawDelivery has A seal a delivery with the given anchor, preparing its
// device_add first if it is not yet: what an approver that skips the
// commit, or names another anchor, would send.
func (x *enrollFix) rawDelivery(t *testing.T, anchorSeq uint64, anchorH crypto.Hash) crypto.HPKEEnvelope {
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
	if a.State() == crypto.ApprovalConfirmed {
		id, _ := vaultlog.NewID()
		if _, err := a.Prepare(s.sec.Account, id, s.now()); err != nil {
			t.Fatal(err)
		}
	}
	env, err := a.Deliver(anchorSeq, anchorH)
	if err != nil {
		t.Fatal(err)
	}
	return env
}

// §7 step 6: D anchors only at the delivered (anchor_seq, anchor_h), and
// the verified log must hold its device_add with the delivered
// certificate. A delivery that names another anchor, or a device_add that
// never committed, installs nothing.
func TestEnrollmentDeliveryMustMatchTheLog(t *testing.T) {
	ctx := context.Background()
	confirmed := func(t *testing.T) (*enrollFix, *Enrollment) {
		x := newEnrollFix(t)
		e, commit := x.begin(t)
		x.reveal(t, e, commit)
		if err := e.ConfirmSAS(); err != nil {
			t.Fatal(err)
		}
		if err := x.a.s.ApproveConfirm(true); err != nil {
			t.Fatal(err)
		}
		return x, e
	}
	genesis := func(t *testing.T, x *enrollFix) crypto.Hash {
		h, err := x.a.s.entryHash(0)
		if err != nil {
			t.Fatal(err)
		}
		return h
	}
	refused := func(t *testing.T, x *enrollFix, e *Enrollment, env crypto.HPKEEnvelope, want string) {
		t.Helper()
		// A server that serves the log without checking the session, so
		// that only the client's own checks stand.
		_, err := e.Install(ctx, laxReader{x.srv}, &env)
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Fatalf("install: %v; want %q", err, want)
		}
		if !errors.Is(err, ErrDeliveryInvalid) {
			t.Errorf("install: %v; want ErrDeliveryInvalid", err)
		}
		if exists, _ := (layout{data: x.cfg.DataDir}).exists(); exists {
			t.Error("a refused delivery installed a vault")
		}
	}
	t.Run("device_add never committed", func(t *testing.T) {
		x, e := confirmed(t)
		refused(t, x, e, x.rawDelivery(t, 0, genesis(t, x)), "no device_add with the delivered certificate")
	})
	t.Run("another anchor_h", func(t *testing.T) {
		x, e := confirmed(t)
		// The device_add commits; the delivery is then sealed by hand.
		x.a.s.testHook = crashAt("approve:deliver")
		if _, err := x.a.s.ApproveFinish(ctx, x.r); !errors.Is(err, errCrash) {
			t.Fatalf("finish: %v", err)
		}
		x.a.s.testHook = nil
		var wrong crypto.Hash
		wrong[0] = 1
		refused(t, x, e, x.rawDelivery(t, 0, wrong), "not the delivered anchor_h")
	})
	t.Run("anchor_seq not an anchor", func(t *testing.T) {
		x, e := confirmed(t)
		x.a.s.testHook = crashAt("approve:deliver")
		if _, err := x.a.s.ApproveFinish(ctx, x.r); !errors.Is(err, errCrash) {
			t.Fatalf("finish: %v", err)
		}
		x.a.s.testHook = nil
		h1, err := x.a.s.entryHash(1)
		if err != nil {
			t.Fatal(err)
		}
		refused(t, x, e, x.rawDelivery(t, 1, h1), "does not verify")
	})
}

// laxReader is the fake server as an EnrollRemote that ignores the
// session.
type laxReader struct{ f *fakeServer }

func (l laxReader) EntryAt(ctx context.Context, _ DeviceAuth, seq uint64) (Committed, error) {
	return l.f.entryAt(seq)
}

func (l laxReader) Since(ctx context.Context, _ DeviceAuth, after uint64) ([]Committed, vaultlog.Head, error) {
	return l.f.fakeRemote.Since(ctx, after)
}

// A's device_add follows the outbox's candidate rules (§5.4): an uncertain
// post is posted again identically, and a 409 rebuilds it against the new
// head with the same prepared device_add, so the delivery still installs.
func TestApproveFinishCandidates(t *testing.T) {
	ctx := context.Background()
	for _, tc := range []string{"uncertain", "conflict"} {
		t.Run(tc, func(t *testing.T) {
			x := newEnrollFix(t)
			e, commit := x.begin(t)
			x.reveal(t, e, commit)
			if err := e.ConfirmSAS(); err != nil {
				t.Fatal(err)
			}
			if err := x.a.s.ApproveConfirm(true); err != nil {
				t.Fatal(err)
			}
			var first crypto.Hash
			posted := 0
			x.r.onPost = func(w *vaultlog.Wire) (bool, error) {
				posted++
				if posted > 1 {
					return true, nil
				}
				first, _ = w.Entry.Hash()
				return false, errLostResponse
			}
			if _, err := x.a.s.ApproveFinish(ctx, x.r); !errors.Is(err, errLostResponse) {
				t.Fatalf("lost post: %v", err)
			}
			if tc == "conflict" {
				// Another device writes first: the candidate is dead.
				b := secondDevice(t, x.a, x.r)
				addHost(t, b.s, "db")
				pushAll(t, b.s, x.r)
			}
			n := x.r.postCount()
			env, err := x.a.s.ApproveFinish(ctx, x.r)
			if err != nil {
				t.Fatal(err)
			}
			x.r.mu.Lock()
			again := x.r.posts[n]
			x.r.mu.Unlock()
			if again.Equal(first) != (tc == "uncertain") {
				t.Errorf("reposted the identical wire: %v", again.Equal(first))
			}
			if x.r.committed(first) == (tc == "conflict") {
				t.Errorf("first candidate committed: %v", x.r.committed(first))
			}
			s, err := e.Install(ctx, x.remote(), &env)
			if err != nil {
				t.Fatal(err)
			}
			track(t, x.cfg, s)
			x.installed(t, s)
		})
	}
}
