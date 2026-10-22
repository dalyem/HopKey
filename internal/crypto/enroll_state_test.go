package crypto

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"testing"
	"time"

	"github.com/dalyem/hopkey/internal/canonjson"
	"github.com/dalyem/hopkey/internal/model"
)

// runToDelivery takes the rig through an SAS confirmed on both devices,
// Prepare and Deliver and returns the delivery envelope.
func (r *enrollRig) runToDelivery(t *testing.T) (HPKEEnvelope, Hash) {
	t.Helper()
	r.runToOpen(t, fixedID(0x80))
	if err := r.d.ConfirmSAS(); err != nil {
		t.Fatal(err)
	}
	return r.deliverFromA(t)
}

// deliverFromA confirms the SAS on A, prepares and delivers. D is left as
// it is.
func (r *enrollRig) deliverFromA(t *testing.T) (HPKEEnvelope, Hash) {
	t.Helper()
	if err := r.a.Confirm(true); err != nil {
		t.Fatal(err)
	}
	if _, err := r.a.Prepare(r.acct, fixedID(0x41), ts(t, "2026-10-22T12:00:00Z")); err != nil {
		t.Fatal(err)
	}
	anchorH := Hash(sha256.Sum256([]byte("anchor")))
	env, err := r.a.Deliver(7, anchorH)
	if err != nil {
		t.Fatal(err)
	}
	return env, anchorH
}

// crashAfterPersist durably stores the state, then reports an error, as a
// process that dies right after the fsync would.
type crashAfterPersist struct {
	*memPersister
	crash bool
}

func (c *crashAfterPersist) Persist(b []byte) error {
	if err := c.memPersister.Persist(b); err != nil {
		return err
	}
	if c.crash {
		return errors.New("crashed after the save")
	}
	return nil
}

// Finding 3: D persists DONE together with the delivery, so a crash right
// after the save loses nothing. Restoring gives the same account keys,
// certificate and anchor, and retrieving the result is idempotent.
func TestDeviceCrashAfterDone(t *testing.T) {
	r := newEnrollRig(t)
	cp := &crashAfterPersist{memPersister: r.dp}
	r.dp = cp.memPersister
	env, anchorH := r.runToDelivery(t)
	// Swap D's persister for one that crashes after the DONE save.
	d, err := RestoreDeviceEnrollmentWithClock(cp, r.clock.now, r.dp.state)
	if err != nil {
		t.Fatal(err)
	}
	cp.crash = true
	if _, err := d.HandleDelivery(env); err == nil {
		t.Fatal("the simulated crash did not surface")
	}
	cp.crash = false

	// A new process starts from what reached the disk.
	d2, err := RestoreDeviceEnrollmentWithClock(cp, r.clock.now, cp.state)
	if err != nil {
		t.Fatal(err)
	}
	if d2.State() != DeviceDone {
		t.Fatalf("state after restore = %q", d2.State())
	}
	v, err := d2.Delivered()
	if err != nil {
		t.Fatalf("result lost in the crash: %v", err)
	}
	if !v.Account.Pin().Equal(r.acct.Pin()) || v.AnchorSeq != 7 || v.AnchorH != anchorH || v.Cert.DeviceID != fixedID(0x41) {
		t.Fatal("restored result differs from the delivery")
	}
	// The same account private keys, not just the same pin.
	want, _ := r.acct.MarshalAcctPriv()
	got, _ := v.Account.MarshalAcctPriv()
	if !bytes.Equal(got, want) {
		t.Fatal("restored account keys differ")
	}

	// Idempotent: Delivered again, and HandleDelivery with the same
	// envelope, give the same result. A different envelope is refused.
	v2, err := d2.Delivered()
	if err != nil || v2.Cert != v.Cert || !bytes.Equal(v2.CertSig, v.CertSig) || v2.AnchorH != v.AnchorH {
		t.Fatalf("second Delivered: %v", err)
	}
	v3, err := d2.HandleDelivery(env)
	if err != nil || v3.Cert != v.Cert || !v3.Account.Pin().Equal(r.acct.Pin()) {
		t.Fatalf("same delivery again: %v", err)
	}
	other := env
	other.CT = bytes.Clone(env.CT)
	other.CT[0] ^= 1
	if _, err := d2.HandleDelivery(other); !errors.Is(err, ErrEnrollState) {
		t.Fatalf("different delivery after DONE: %v", err)
	}
	// And across a further restart.
	d3, err := RestoreDeviceEnrollmentWithClock(cp, r.clock.now, cp.state)
	if err != nil {
		t.Fatal(err)
	}
	if v4, err := d3.Delivered(); err != nil || v4.Cert != v.Cert {
		t.Fatalf("third restore: %v", err)
	}
}

// A DONE record without its delivery is inconsistent and does not load.
func TestDeviceDoneNeedsDelivery(t *testing.T) {
	r := newEnrollRig(t)
	env, _ := r.runToDelivery(t)
	if _, err := r.d.HandleDelivery(env); err != nil {
		t.Fatal(err)
	}
	rec := r.d.rec
	rec.Delivery = nil
	if err := r.d.save(rec); err != nil {
		t.Fatal(err)
	}
	if _, err := RestoreDeviceEnrollmentWithClock(r.dp, r.clock.now, r.dp.state); err == nil {
		t.Fatal("DONE without a delivery restored")
	}
}

// Finding 1: both state machines copy what they are given and what they
// return. Changing the caller's buffers after the SAS is shown does not
// change what Prepare certifies, and changing returned values does not
// change the persisted material.
func TestEnrollmentCopiesBuffers(t *testing.T) {
	r := newEnrollRig(t)
	d, commit, err := NewDeviceEnrollmentWithClock(r.dp, r.clock.now, "new-laptop")
	if err != nil {
		t.Fatal(err)
	}
	_ = d.SetEnrollID(fixedID(0x80))
	a, err := StartApproval(r.budget, r.ap, fixedID(0x80), r.acct.Pin(), r.approver)
	if err != nil {
		t.Fatal(err)
	}
	ch, err := a.HandleCommit(&commit)
	if err != nil {
		t.Fatal(err)
	}
	origChal := *ch.clone()
	// The chal A returns, and returns again for re-sending, are copies.
	c2, err := a.Chal()
	if err != nil {
		t.Fatal(err)
	}
	c2.NA[0] ^= 1
	ch.NA[1] ^= 1
	if c3, _ := a.Chal(); !bytes.Equal(c3.NA, origChal.NA) {
		t.Fatal("HandleCommit or Chal returned A's internal nA")
	}
	ch.NA[1] ^= 1
	open, err := d.HandleChal(&ch)
	if err != nil {
		t.Fatal(err)
	}
	orig := *open.clone()
	aSAS, _, err := a.HandleOpen(&open)
	if err != nil {
		t.Fatal(err)
	}
	dSAS, _ := d.SAS()

	// The SAS is on screen. Now the caller's buffers change.
	scribble := func(b []byte) {
		for i := range b {
			b[i] ^= 0xa5
		}
	}
	scribble(open.KEMPK)
	scribble(open.SigPK)
	scribble(open.ND)
	scribble(ch.NA)
	if s, _, _ := a.SAS(); s != aSAS {
		t.Fatal("A's SAS changed with the caller's open buffers")
	}
	if s, _ := d.SAS(); s != dSAS {
		t.Fatal("D's SAS changed with the caller's chal buffers")
	}
	if o, _ := d.Open(); !bytes.Equal(o.KEMPK, orig.KEMPK) || !bytes.Equal(o.ND, orig.ND) {
		t.Fatal("D's open changed with the returned buffers")
	}
	// Values returned by accessors are copies too.
	o2, _ := d.Open()
	scribble(o2.ND)
	if o3, _ := d.Open(); !bytes.Equal(o3.ND, orig.ND) {
		t.Fatal("Open returned D's internal nD")
	}

	if err := a.Confirm(true); err != nil {
		t.Fatal(err)
	}
	if err := d.ConfirmSAS(); err != nil {
		t.Fatal(err)
	}
	prep, err := a.Prepare(r.acct, fixedID(0x41), 0)
	if err != nil {
		t.Fatal(err)
	}
	if !prep.Cert.KEMFp.Equal(FpKEM(orig.KEMPK)) || !prep.Cert.SigFp.Equal(FpSig(orig.SigPK)) {
		t.Fatal("Prepare certified keys from the caller's changed buffers")
	}
	if !prep.Cert.EnrollTranscript.Equal(TranscriptHash(Transcript(Commitment(&orig), &origChal, &orig))) {
		t.Fatal("Prepare bound a transcript built from changed buffers")
	}
	// Prepared material and the delivery are copies.
	keep := *prep
	keep.CertSig = bytes.Clone(prep.CertSig)
	keep.KEMPK = bytes.Clone(prep.KEMPK)
	keep.Unlock = prep.Unlock.clone()
	scribble(prep.CertSig)
	scribble(prep.KEMPK)
	scribble(prep.SigPK)
	scribble(prep.Unlock.CT)
	scribble(prep.Unlock.Enc)
	again, _ := a.Prepared()
	if !bytes.Equal(again.CertSig, keep.CertSig) || !bytes.Equal(again.KEMPK, keep.KEMPK) ||
		!bytes.Equal(again.Unlock.CT, keep.Unlock.CT) || !bytes.Equal(again.Unlock.Enc, keep.Unlock.Enc) {
		t.Fatal("Prepared returned internal slices")
	}
	env, err := a.Deliver(0, Hash{})
	if err != nil {
		t.Fatal(err)
	}
	envKeep := env.clone()
	scribble(env.CT)
	if env2, _ := a.Deliver(0, Hash{}); !bytes.Equal(env2.CT, envKeep.CT) {
		t.Fatal("Deliver returned the internal delivery")
	}
	// D copies the delivery it is given.
	in := envKeep.clone()
	v, err := d.HandleDelivery(in)
	if err != nil {
		t.Fatal(err)
	}
	scribble(in.CT)
	scribble(v.CertSig)
	if v2, err := d.Delivered(); err != nil || !bytes.Equal(v2.CertSig, keep.CertSig) {
		t.Fatalf("D kept the caller's delivery or certificate buffers: %v", err)
	}
	_, sig := d.DeviceKeys()
	scribble(sig)
	if _, sig2 := d.DeviceKeys(); bytes.Equal(sig, sig2) {
		t.Fatal("DeviceKeys returned the internal signing key")
	}
}

// §7: D's deadline is 10 minutes from COMMITTED. When it passes, the
// attempt fails and stays failed across restarts.
func TestDeviceDeadline(t *testing.T) {
	clock := &fakeClock{t: time.Date(2026, 10, 22, 12, 0, 0, 0, time.UTC)}
	dp := &memPersister{}
	d, _, err := NewDeviceEnrollmentWithClock(dp, clock.now, "n")
	if err != nil {
		t.Fatal(err)
	}
	if !d.Deadline().Equal(clock.t.Add(10 * time.Minute)) {
		t.Fatalf("deadline %v", d.Deadline())
	}
	_ = d.SetEnrollID(fixedID(0x80))
	ch := testChal(t)
	clock.advance(10*time.Minute - time.Second)
	if _, err := d.Open(); !errors.Is(err, ErrEnrollState) {
		t.Fatalf("before the deadline: %v", err)
	}
	clock.advance(time.Second)
	if _, err := d.HandleChal(ch); !errors.Is(err, ErrEnrollExpired) {
		t.Fatalf("chal at the deadline: %v", err)
	}
	if d.State() != DeviceFailed {
		t.Fatalf("state %q", d.State())
	}
	d2, err := RestoreDeviceEnrollmentWithClock(dp, clock.now, dp.state)
	if err != nil {
		t.Fatal(err)
	}
	if d2.State() != DeviceFailed {
		t.Fatal("failure not persisted")
	}
	clock.advance(-time.Hour) // a clock moving back does not revive it
	if _, err := d2.HandleChal(ch); !errors.Is(err, ErrEnrollExpired) {
		t.Fatalf("chal after failure: %v", err)
	}

	// A valid delivery that arrives after the deadline is refused too.
	r := newEnrollRig(t)
	env, _ := r.runToDelivery(t)
	if r.d.State() != DeviceConfirmed {
		t.Fatalf("state %q before the deadline", r.d.State())
	}
	r.clock.advance(10 * time.Minute)
	if _, err := r.d.HandleDelivery(env); !errors.Is(err, ErrEnrollExpired) || r.d.State() != DeviceFailed {
		t.Fatalf("delivery after the deadline: %v, %q", err, r.d.State())
	}

	// Restoring after the deadline fails the attempt.
	dp3 := &memPersister{}
	c3 := &fakeClock{t: clock.t}
	if _, _, err := NewDeviceEnrollmentWithClock(dp3, c3.now, "n"); err != nil {
		t.Fatal(err)
	}
	c3.advance(11 * time.Minute)
	d3, err := RestoreDeviceEnrollmentWithClock(dp3, c3.now, dp3.state)
	if err != nil || d3.State() != DeviceFailed {
		t.Fatalf("restore after the deadline: %v, %q", err, d3.State())
	}
}

// §7: A's deadline is 10 minutes from CHALLENGED. When it passes, the
// attempt fails, its slot stays spent, and the outstanding-challenge slot
// is released.
func TestApprovalDeadline(t *testing.T) {
	r := newEnrollRig(t)
	t0 := r.clock.t
	d, commit, _ := NewDeviceEnrollmentWithClock(r.dp, r.clock.now, "n")
	_ = d.SetEnrollID(fixedID(0x80))
	a, err := StartApproval(r.budget, r.ap, fixedID(0x80), r.acct.Pin(), r.approver)
	if err != nil {
		t.Fatal(err)
	}
	r.clock.advance(time.Minute)
	ch, err := a.HandleCommit(&commit)
	if err != nil {
		t.Fatal(err)
	}
	if !a.Deadline().Equal(t0.Add(11 * time.Minute)) {
		t.Fatalf("deadline %v, want CHALLENGED + 10m", a.Deadline())
	}
	open, _ := d.HandleChal(&ch)
	// Ten and a half minutes after the reservation, but only 9.5 after
	// CHALLENGED: still running, and still holding the outstanding slot.
	r.clock.advance(9*time.Minute + 30*time.Second)
	if _, err := a.Chal(); err != nil {
		t.Fatalf("before the deadline: %v", err)
	}
	if _, err := StartApproval(r.budget, &memPersister{}, fixedID(0x81), r.acct.Pin(), r.approver); !errors.Is(err, ErrChallengeOutstanding) {
		t.Fatalf("second approval while one is outstanding: %v", err)
	}
	r.clock.advance(30 * time.Second)
	if _, _, err := a.HandleOpen(&open); !errors.Is(err, ErrEnrollExpired) {
		t.Fatalf("open at the deadline: %v", err)
	}
	if a.State() != ApprovalFailed {
		t.Fatalf("state %q", a.State())
	}
	if _, err := a.Prepare(r.acct, fixedID(0x41), 0); err == nil {
		t.Fatal("expired attempt prepared a device")
	}
	// Slot spent, outstanding mark released.
	if got := r.budget.Remaining(); got != 2 {
		t.Fatalf("remaining = %d, want 2", got)
	}
	if _, err := StartApproval(r.budget, &memPersister{}, fixedID(0x82), r.acct.Pin(), r.approver); err != nil {
		t.Fatalf("approval after the deadline released the slot: %v", err)
	}
}

// The budget releases an expired outstanding challenge by itself, even if
// the approving process died and its attempt is never restored.
func TestBudgetReleasesExpiredChallenge(t *testing.T) {
	bp := &memPersister{}
	clock := &fakeClock{t: time.Date(2026, 10, 22, 12, 0, 0, 0, time.UTC)}
	b, _ := LoadApprovalBudget(bp, clock.now, nil)
	acct := fixedAccount(t, 1)
	a, err := StartApproval(b, &memPersister{}, fixedID(0x80), acct.Pin(), fixedID(0x40))
	if err != nil {
		t.Fatal(err)
	}
	d, commit, _ := NewDeviceEnrollmentWithClock(&memPersister{}, clock.now, "n")
	_ = d.SetEnrollID(fixedID(0x80))
	clock.advance(2 * time.Minute)
	if _, err := a.HandleCommit(&commit); err != nil {
		t.Fatal(err)
	}
	// The process dies here. A new one loads only the budget.
	clock.advance(9 * time.Minute) // 11 minutes after the reservation, 9 after CHALLENGED
	b2, err := LoadApprovalBudget(bp, clock.now, bp.state)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := StartApproval(b2, &memPersister{}, fixedID(0x81), acct.Pin(), fixedID(0x40)); !errors.Is(err, ErrChallengeOutstanding) {
		t.Fatalf("outstanding released before CHALLENGED + 10m: %v", err)
	}
	clock.advance(time.Minute)
	if b2.Remaining() != 2 {
		t.Fatalf("remaining = %d, want 2", b2.Remaining())
	}
	if _, err := StartApproval(b2, &memPersister{}, fixedID(0x81), acct.Pin(), fixedID(0x40)); err != nil {
		t.Fatalf("expired outstanding challenge still blocks: %v", err)
	}
}

// A reservation that never gets a commit is bounded the same way.
func TestApprovalReservedDeadline(t *testing.T) {
	r := newEnrollRig(t)
	a, err := StartApproval(r.budget, r.ap, fixedID(0x80), r.acct.Pin(), r.approver)
	if err != nil {
		t.Fatal(err)
	}
	r.clock.advance(10 * time.Minute)
	commit := EnrollCommit{V: 1}
	if _, err := a.HandleCommit(&commit); !errors.Is(err, ErrEnrollExpired) || a.State() != ApprovalFailed {
		t.Fatalf("commit after the deadline: %v", err)
	}
	// Restoring an expired attempt fails it as well.
	r2 := newEnrollRig(t)
	if _, err := StartApproval(r2.budget, r2.ap, fixedID(0x80), r2.acct.Pin(), r2.approver); err != nil {
		t.Fatal(err)
	}
	r2.clock.advance(time.Hour)
	a2, err := RestoreApproval(r2.budget, r2.ap, r2.ap.state)
	if err != nil || a2.State() != ApprovalFailed {
		t.Fatalf("restore after the deadline: %v", err)
	}
}

// §7: invalid input is discarded with no change of state, and the real
// message can still arrive before the deadline.
func TestInvalidMessagesChangeNothing(t *testing.T) {
	r := newEnrollRig(t)
	d, commit, _ := NewDeviceEnrollmentWithClock(r.dp, r.clock.now, "new-laptop")
	_ = d.SetEnrollID(fixedID(0x80))
	a, _ := StartApproval(r.budget, r.ap, fixedID(0x80), r.acct.Pin(), r.approver)

	unchanged := func(name string, p *memPersister, before []byte, saves int) {
		t.Helper()
		if !bytes.Equal(p.state, before) || p.saves != saves {
			t.Errorf("%s changed the persisted state", name)
		}
	}
	snap := func(p *memPersister) ([]byte, int) { return bytes.Clone(p.state), p.saves }

	// A: bad commits.
	st, n := snap(r.ap)
	badCommit := commit
	badCommit.V = 2
	if _, err := a.HandleCommit(&badCommit); err == nil {
		t.Fatal("commit with v=2 accepted")
	}
	unchanged("bad commit", r.ap, st, n)
	if a.State() != ApprovalReserved {
		t.Fatal("bad commit moved A")
	}
	ch, err := a.HandleCommit(&commit)
	if err != nil {
		t.Fatalf("real commit after a bad one: %v", err)
	}

	// D: bad chals.
	st, n = snap(r.dp)
	for name, mutate := range map[string]func(*EnrollChal){
		"wrong enroll_id": func(c *EnrollChal) { c.EnrollID = fixedID(0x81) },
		"short nA":        func(c *EnrollChal) { c.NA = c.NA[:31] },
		"v=2":             func(c *EnrollChal) { c.V = 2 },
		"zero account":    func(c *EnrollChal) { c.AccountID = model.ID{} },
	} {
		bad := *ch.clone()
		mutate(&bad)
		if _, err := d.HandleChal(&bad); err == nil {
			t.Errorf("chal %s accepted", name)
		}
		unchanged("chal "+name, r.dp, st, n)
	}
	open, err := d.HandleChal(&ch)
	if err != nil {
		t.Fatalf("real chal after bad ones: %v", err)
	}

	// A: bad opens.
	st, n = snap(r.ap)
	for name, mutate := range map[string]func(*EnrollOpen){
		"does not match c": func(o *EnrollOpen) { o.Name = "evil" },
		"short nD":         func(o *EnrollOpen) { o.ND = o.ND[:31] },
		"bad kem_pk":       func(o *EnrollOpen) { o.KEMPK = o.KEMPK[:100] },
		"name with LF":     func(o *EnrollOpen) { o.Name = "a\nb" },
	} {
		bad := *open.clone()
		mutate(&bad)
		if _, _, err := a.HandleOpen(&bad); err == nil {
			t.Errorf("open %s accepted", name)
		}
		unchanged("open "+name, r.ap, st, n)
	}
	if _, _, err := a.HandleOpen(&open); err != nil {
		t.Fatalf("real open after bad ones: %v", err)
	}
	_ = a.Confirm(true)
	if err := d.ConfirmSAS(); err != nil {
		t.Fatal(err)
	}
	if _, err := a.Prepare(r.acct, fixedID(0x41), 0); err != nil {
		t.Fatal(err)
	}
	env, err := a.Deliver(0, Hash{})
	if err != nil {
		t.Fatal(err)
	}

	// D: bad deliveries.
	st, n = snap(r.dp)
	garbled := env.clone()
	garbled.CT[len(garbled.CT)-1] ^= 1
	if _, err := d.HandleDelivery(garbled); err == nil {
		t.Fatal("garbled delivery accepted")
	}
	unchanged("garbled delivery", r.dp, st, n)
	if _, err := d.HandleDelivery(HPKEEnvelope{V: 2, Suite: 1}); err == nil {
		t.Fatal("delivery v=2 accepted")
	}
	unchanged("delivery v=2", r.dp, st, n)
	if d.State() != DeviceConfirmed {
		t.Fatal("bad deliveries moved D")
	}
	if _, err := d.HandleDelivery(env); err != nil {
		t.Fatalf("real delivery after bad ones: %v", err)
	}
}

// §7 step 6: D requires Cert.name = open.name. A certificate that is
// otherwise perfect, signed by the real account, but names the device
// differently is refused.
func TestDeliveryCertNameMustMatchOpen(t *testing.T) {
	r := newEnrollRig(t)
	r.runToOpen(t, fixedID(0x80))
	if err := r.d.ConfirmSAS(); err != nil {
		t.Fatal(err)
	}
	open, _ := r.d.Open()
	tr := r.d.transcript()
	th := TranscriptHash(tr)
	build := func(name string) HPKEEnvelope {
		cert := Cert{V: 1, AccountID: r.acct.AccountID, AKV: 1, DeviceID: fixedID(0x41), Name: name,
			KEMFp: FpKEM(open.KEMPK), SigFp: FpSig(open.SigPK), EnrollTranscript: SomeHash(th)}
		sig, err := SignCert(r.acct, &cert)
		if err != nil {
			t.Fatal(err)
		}
		unlock, err := SealUnlock(open.KEMPK, &cert, r.acct)
		if err != nil {
			t.Fatal(err)
		}
		env, err := SealDelivery(open.KEMPK, th, &EnrollDelivery{V: 1, Cert: cert, CertSig: sig, Unlock: unlock})
		if err != nil {
			t.Fatal(err)
		}
		return env
	}
	st := bytes.Clone(r.dp.state)
	if _, err := r.d.HandleDelivery(build("new-laptoq")); !errors.Is(err, ErrCertName) {
		t.Fatalf("certificate with another name: %v", err)
	}
	if !bytes.Equal(r.dp.state, st) || r.d.State() != DeviceConfirmed {
		t.Fatal("a rejected delivery changed D's state")
	}
	// The exported VerifyDelivery reads open.name back from T.
	kem, _ := r.d.DeviceKeys()
	if _, err := VerifyDelivery(kem, open.SigPK, r.d.rec.Chal, tr, build("other")); !errors.Is(err, ErrCertName) {
		t.Fatalf("VerifyDelivery with another name: %v", err)
	}
	if _, err := VerifyDelivery(kem, open.SigPK, r.d.rec.Chal, tr, build(open.Name)); err != nil {
		t.Fatalf("VerifyDelivery with the right name: %v", err)
	}
	if _, err := r.d.HandleDelivery(build(open.Name)); err != nil {
		t.Fatalf("certificate with the right name: %v", err)
	}
}

func TestTranscriptName(t *testing.T) {
	o := testOpen(t)
	ch := testChal(t)
	tr := Transcript(Commitment(o), ch, o)
	if name, err := transcriptName(tr); err != nil || name != o.Name {
		t.Fatalf("name = %q, %v", name, err)
	}
	empty := *o
	empty.Name = ""
	if name, err := transcriptName(Transcript(Commitment(&empty), ch, &empty)); err != nil || name != "" {
		t.Fatalf("empty name = %q, %v", name, err)
	}
	for name, bad := range map[string][]byte{
		"truncated":     tr[:len(tr)-1],
		"trailing byte": append(bytes.Clone(tr), 0),
		"empty":         nil,
		"other label":   append(LP([]byte("hopkey/v1/enroll-commit")), tr[4+len(LabelEnrollTranscript):]...),
	} {
		if _, err := transcriptName(bad); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

// §7 step 6 (rev 9): D accepts a delivery only in CONFIRMED. A genuine
// delivery that arrives before the user confirmed on D is discarded with
// the persisted state byte-for-byte unchanged, and it is not kept: after
// ConfirmSAS, D is CONFIRMED without a delivery until it is handed in again.
func TestDeviceDiscardsDeliveryBeforeConfirm(t *testing.T) {
	r := newEnrollRig(t)
	r.runToOpen(t, fixedID(0x80))
	env, anchorH := r.deliverFromA(t)
	before, saves := bytes.Clone(r.dp.state), r.dp.saves
	for _, d := range []*DeviceEnrollment{r.d, r.d, mustRestore(t, r.dp, r.clock.now)} {
		if _, err := d.HandleDelivery(env); !errors.Is(err, ErrSASNotConfirmed) {
			t.Fatalf("delivery before confirmation: %v", err)
		}
		if !bytes.Equal(r.dp.state, before) || r.dp.saves != saves || d.State() != DeviceRevealed {
			t.Fatal("the early delivery changed D's state")
		}
	}

	if err := r.d.ConfirmSAS(); err != nil {
		t.Fatal(err)
	}
	if r.d.State() != DeviceConfirmed || r.d.rec.Delivery != nil {
		t.Fatal("D kept the early delivery")
	}
	if _, err := r.d.Delivered(); !errors.Is(err, ErrEnrollState) {
		t.Fatalf("Delivered in CONFIRMED: %v", err)
	}

	// CONFIRMED was persisted: a restart keeps the decision, the same SAS
	// and the open, and the delivery handed in again is accepted.
	d2 := mustRestore(t, r.dp, r.clock.now)
	if d2.State() != DeviceConfirmed {
		t.Fatalf("restored state %q", d2.State())
	}
	s1, _ := r.d.SAS()
	if s2, err := d2.SAS(); err != nil || s1 != s2 {
		t.Fatalf("SAS after restoring CONFIRMED: %v", err)
	}
	if _, err := d2.Open(); err != nil {
		t.Fatalf("Open in CONFIRMED: %v", err)
	}
	if _, err := d2.HandleChal(r.a.rec.Chal); !errors.Is(err, ErrChalAfterReveal) {
		t.Fatalf("chal in CONFIRMED: %v", err)
	}
	v, err := d2.HandleDelivery(env)
	if err != nil {
		t.Fatalf("delivery after confirmation: %v", err)
	}
	if !v.Account.Pin().Equal(r.acct.Pin()) || v.AnchorH != anchorH || d2.State() != DeviceDone {
		t.Fatal("delivery after confirmation gave the wrong result")
	}

	// A delivery before any chal is discarded the same way.
	dp := &memPersister{}
	d3, _, err := NewDeviceEnrollmentWithClock(dp, r.clock.now, "new-laptop")
	if err != nil {
		t.Fatal(err)
	}
	before, saves = bytes.Clone(dp.state), dp.saves
	if _, err := d3.HandleDelivery(env); !errors.Is(err, ErrSASNotConfirmed) {
		t.Fatalf("delivery in COMMITTED: %v", err)
	}
	if !bytes.Equal(dp.state, before) || dp.saves != saves {
		t.Fatal("a delivery in COMMITTED changed D's state")
	}
}

// ConfirmSAS and RejectSAS are valid only in REVEALED with an SAS on
// screen and before the deadline, and each persists before it returns.
func TestDeviceSASDecisionStates(t *testing.T) {
	// COMMITTED: no SAS yet.
	dp := &memPersister{}
	clock := &fakeClock{t: time.Date(2026, 10, 22, 12, 0, 0, 0, time.UTC)}
	d, _, err := NewDeviceEnrollmentWithClock(dp, clock.now, "n")
	if err != nil {
		t.Fatal(err)
	}
	saves := dp.saves
	if err := d.ConfirmSAS(); !errors.Is(err, ErrEnrollState) {
		t.Fatalf("ConfirmSAS in COMMITTED: %v", err)
	}
	if err := d.RejectSAS(); !errors.Is(err, ErrEnrollState) {
		t.Fatalf("RejectSAS in COMMITTED: %v", err)
	}
	if dp.saves != saves || d.State() != DeviceCommitted {
		t.Fatal("a refused decision changed D's state")
	}

	// A persist failure changes nothing, and D still accepts no delivery.
	r := newEnrollRig(t)
	r.runToOpen(t, fixedID(0x80))
	env, _ := r.deliverFromA(t)
	r.dp.fail = true
	if err := r.d.ConfirmSAS(); !errors.Is(err, errPersist) || r.d.State() != DeviceRevealed {
		t.Fatalf("ConfirmSAS with a failing persister: %v, %q", err, r.d.State())
	}
	if err := r.d.RejectSAS(); !errors.Is(err, errPersist) || r.d.State() != DeviceRevealed {
		t.Fatalf("RejectSAS with a failing persister: %v, %q", err, r.d.State())
	}
	if kem, sig := r.d.DeviceKeys(); kem == nil || len(sig) == 0 {
		t.Fatal("keys wiped although REJECTED was not persisted")
	}
	if _, err := r.d.HandleDelivery(env); !errors.Is(err, ErrSASNotConfirmed) {
		t.Fatalf("delivery after a failed decision: %v", err)
	}
	r.dp.fail = false

	// CONFIRMED and DONE: the decision is made.
	if err := r.d.ConfirmSAS(); err != nil {
		t.Fatal(err)
	}
	for _, step := range []string{"confirmed", "done"} {
		if err := r.d.ConfirmSAS(); !errors.Is(err, ErrEnrollState) {
			t.Fatalf("ConfirmSAS when %s: %v", step, err)
		}
		if err := r.d.RejectSAS(); !errors.Is(err, ErrEnrollState) {
			t.Fatalf("RejectSAS when %s: %v", step, err)
		}
		if _, err := r.d.HandleDelivery(env); err != nil {
			t.Fatal(err)
		}
	}

	// The deadline: a decision at the deadline fails the attempt.
	r2 := newEnrollRig(t)
	r2.runToOpen(t, fixedID(0x80))
	r2.clock.advance(EnrollDeadline)
	if err := r2.d.ConfirmSAS(); !errors.Is(err, ErrEnrollExpired) || r2.d.State() != DeviceFailed {
		t.Fatalf("ConfirmSAS at the deadline: %v, %q", err, r2.d.State())
	}
	if err := r2.d.RejectSAS(); !errors.Is(err, ErrEnrollExpired) {
		t.Fatalf("RejectSAS after the deadline: %v", err)
	}
}

// §7 step 4 (rev 9): REJECTED is terminal. The persisted record keeps only
// the state, the enrollment keys are wiped from memory, and every later
// call is refused, also past the deadline and after a restart.
func TestDeviceRejectedIsTerminal(t *testing.T) {
	r := newEnrollRig(t)
	r.runToOpen(t, fixedID(0x80))
	env, _ := r.deliverFromA(t) // a genuine delivery, to show it is refused
	kemSK, seed, sigKey := r.d.rec.KEMSK, r.d.rec.SigSeed, r.d.sig
	secrets := [][]byte{bytes.Clone(kemSK), bytes.Clone(seed), bytes.Clone(sigKey)}
	if err := r.d.RejectSAS(); err != nil {
		t.Fatal(err)
	}

	// The persisted record: nothing but the state.
	want, err := canonjson.Marshal(deviceRecord{V: Version, State: DeviceRejected})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(r.dp.state, want) {
		t.Fatalf("rejected record = %s", r.dp.state)
	}
	for _, sec := range secrets {
		for _, enc := range []string{base64.RawURLEncoding.EncodeToString(sec), base64.StdEncoding.EncodeToString(sec)} {
			if bytes.Contains(r.dp.state, []byte(enc)) || bytes.Contains(r.dp.state, sec) {
				t.Fatal("the rejected record contains private key material")
			}
		}
	}
	// Memory: the key bytes D held are zeroed and the keys dropped.
	for _, b := range [][]byte{kemSK, seed, sigKey} {
		if !bytes.Equal(b, make([]byte, len(b))) {
			t.Fatal("private key bytes left in memory")
		}
	}
	if r.d.kem != nil || r.d.sig != nil || r.d.open.KEMPK != nil {
		t.Fatal("D still references its enrollment keys")
	}

	refused := func(name string, d *DeviceEnrollment) {
		t.Helper()
		saves := r.dp.saves
		errs := map[string]error{}
		errs["SetEnrollID"] = d.SetEnrollID(fixedID(0x80))
		_, errs["HandleChal"] = d.HandleChal(r.a.rec.Chal)
		_, errs["Open"] = d.Open()
		_, errs["SAS"] = d.SAS()
		errs["ConfirmSAS"] = d.ConfirmSAS()
		errs["RejectSAS"] = d.RejectSAS()
		_, errs["HandleDelivery"] = d.HandleDelivery(env)
		_, errs["Delivered"] = d.Delivered()
		for call, err := range errs {
			if !errors.Is(err, ErrSASRejected) {
				t.Errorf("%s: %s after REJECTED: %v", name, call, err)
			}
		}
		if c := d.Commit(); c != (EnrollCommit{}) {
			t.Errorf("%s: Commit after REJECTED returned a commitment", name)
		}
		if kem, sig := d.DeviceKeys(); kem != nil || sig != nil {
			t.Errorf("%s: DeviceKeys after REJECTED returned keys", name)
		}
		if d.State() != DeviceRejected || r.dp.saves != saves || !bytes.Equal(r.dp.state, want) {
			t.Errorf("%s: a refused call changed D's state", name)
		}
	}
	refused("in memory", r.d)
	r.clock.advance(time.Hour) // past the deadline: still REJECTED, not FAILED
	refused("past the deadline", r.d)
	refused("restored", mustRestore(t, r.dp, r.clock.now))
}

// Restoring checks the new states for consistency: REJECTED holds nothing
// but the state, and CONFIRMED holds its chal and no delivery.
func TestRestoreDeviceDecisionStates(t *testing.T) {
	r := newEnrollRig(t)
	r.runToOpen(t, fixedID(0x80))
	revealed := r.d.rec
	for name, rec := range map[string]deviceRecord{
		"rejected with keys":       {V: Version, State: DeviceRejected, KEMSK: revealed.KEMSK},
		"rejected with a seed":     {V: Version, State: DeviceRejected, SigSeed: revealed.SigSeed},
		"rejected with a chal":     {V: Version, State: DeviceRejected, Chal: revealed.Chal},
		"rejected with an ID":      {V: Version, State: DeviceRejected, EnrollID: revealed.EnrollID},
		"rejected with a deadline": {V: Version, State: DeviceRejected, Deadline: revealed.Deadline},
		"confirmed without chal": func() deviceRecord {
			c := revealed
			c.State, c.Chal = DeviceConfirmed, nil
			return c
		}(),
		"confirmed with a cert": func() deviceRecord {
			c := revealed
			c.State, c.Cert = DeviceConfirmed, &Cert{}
			return c
		}(),
	} {
		j, err := canonjson.Marshal(rec)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := RestoreDeviceEnrollmentWithClock(&memPersister{}, r.clock.now, j); err == nil {
			t.Errorf("%s: restored", name)
		}
	}
}
