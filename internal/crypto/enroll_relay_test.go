package crypto

import (
	"bytes"
	"errors"
	"math/rand/v2"
	"testing"
	"time"

	"github.com/dalyem/hopkey/internal/canonjson"
	"github.com/dalyem/hopkey/internal/model"
)

// The §13 relay-schedule fuzz test for §7. The server relays every message
// between D and A, so here a hostile relay decides the schedule: it
// delivers, reorders, duplicates and drops messages, injects its own
// commits, chals, opens and deliveries (from a device it controls and from
// account keys of its own), lets time pass and restarts either party.
//
// The property: no schedule produces a confirmed SAS match with
// substituted keys. Whenever both screens show the same code, A's open is
// D's own open and D's chal is A's own chal; A confirms only then, as a
// user comparing the two screens would. Whenever D finishes after a
// confirmed match, it holds the real account keys and a certificate for
// its own keys.
//
// D can also finish under the relay's own account after the screens
// showed different codes, because §7 gives D no confirmation step; see the
// SPEC GAP on DeviceEnrollment.HandleDelivery and
// TestDeviceAcceptsRelayDeliveryAfterMismatch.

// relayWorld is one schedule's state.
type relayWorld struct {
	t     testing.TB
	pick  func(n int) int
	clock *fakeClock
	acct  *AccountKeys
	evil  *AccountKeys // the relay's own account keys, same account_id and akv
	eid   model.ID

	dp, ap, bp *memPersister
	budget     *ApprovalBudget
	d          *DeviceEnrollment // the real new device
	m          *DeviceEnrollment // a device the relay controls
	a          *Approval

	// Wire messages the relay has seen or made, as JSON.
	commits, chals, opens, deliveries [][]byte

	confirmed   bool // A confirmed a match
	done        bool // D reached DONE with the real account
	substituted bool // D reached DONE under the relay's account (SPEC GAP)
}

func newRelayWorld(t testing.TB, pick func(int) int) *relayWorld {
	w := &relayWorld{t: t, pick: pick, clock: &fakeClock{t: time.Date(2026, 10, 22, 12, 0, 0, 0, time.UTC)},
		eid: fixedID(0x80), dp: &memPersister{}, ap: &memPersister{}, bp: &memPersister{}}
	w.acct = fixedAccount(t, 1)
	var err error
	w.evil, err = NewAccountKeys(w.acct.AccountID, 1, fixedKEM(t, "relay-kem"), fixedBytes("relay-sig", 32))
	if err != nil {
		t.Fatal(err)
	}
	if w.budget, err = LoadApprovalBudget(w.bp, w.clock.now, nil); err != nil {
		t.Fatal(err)
	}
	var c EnrollCommit
	if w.d, c, err = NewDeviceEnrollmentWithClock(w.dp, w.clock.now, "laptop"); err != nil {
		t.Fatal(err)
	}
	w.send(&w.commits, &c)
	var mc EnrollCommit
	if w.m, mc, err = NewDeviceEnrollmentWithClock(&memPersister{}, w.clock.now, "laptop"); err != nil {
		t.Fatal(err)
	}
	w.send(&w.commits, &mc)
	for _, dev := range []*DeviceEnrollment{w.d, w.m} {
		if err := dev.SetEnrollID(w.eid); err != nil {
			t.Fatal(err)
		}
	}
	if w.a, err = StartApproval(w.budget, w.ap, w.eid, w.acct.Pin(), fixedID(0x40)); err != nil {
		t.Fatal(err)
	}
	return w
}

func (w *relayWorld) send(pool *[][]byte, v any) {
	j, err := canonjson.Marshal(v)
	if err != nil {
		w.t.Fatal(err)
	}
	*pool = append(*pool, j)
}

func (w *relayWorld) from(pool [][]byte) ([]byte, bool) {
	if len(pool) == 0 {
		return nil, false
	}
	return pool[w.pick(len(pool))], true
}

// step performs one relay action.
func (w *relayWorld) step() {
	switch w.pick(12) {
	case 0: // a commit to A
		if b, ok := w.from(w.commits); ok {
			var c EnrollCommit
			if ParseEnrollMessage(b, &c) == nil {
				if ch, err := w.a.HandleCommit(&c); err == nil {
					w.send(&w.chals, &ch)
				}
			}
		}
	case 1, 2: // a chal to D or to the relay's device
		dev := w.d
		if w.pick(2) == 1 {
			dev = w.m
		}
		if b, ok := w.from(w.chals); ok {
			var ch EnrollChal
			if ParseEnrollMessage(b, &ch) == nil {
				if o, err := dev.HandleChal(&ch); err == nil {
					w.send(&w.opens, &o)
				}
			}
		}
	case 3: // an open to A
		if b, ok := w.from(w.opens); ok {
			var o EnrollOpen
			if ParseEnrollMessage(b, &o) == nil {
				_, _, _ = w.a.HandleOpen(&o)
			}
		}
	case 4: // the user compares the screens on A and D
		w.compare()
	case 5: // A writes the device_add and delivers
		if w.a.State() == ApprovalConfirmed {
			_, _ = w.a.Prepare(w.acct, fixedID(0x41), model.TimestampOf(w.clock.t))
		}
		if w.a.State() == ApprovalPrepared {
			if env, err := w.a.Deliver(0, Hash{9}); err == nil {
				w.send(&w.deliveries, &env)
			}
		}
	case 6: // a delivery to D
		if b, ok := w.from(w.deliveries); ok {
			var env HPKEEnvelope
			if canonjson.Unmarshal(b, &env) == nil {
				if v, err := w.d.HandleDelivery(env); err == nil {
					w.checkDone(v)
				}
			}
		}
	case 7:
		w.forgeChal()
	case 8:
		w.forgeOpen()
	case 9:
		w.forgeDelivery()
	case 10: // time passes, up to 4 minutes
		w.clock.advance(time.Duration(w.pick(241)) * time.Second)
	case 11: // a party restarts from its persisted state
		var err error
		if w.pick(2) == 0 {
			w.d, err = RestoreDeviceEnrollmentWithClock(w.dp, w.clock.now, w.dp.state)
		} else {
			if w.budget, err = LoadApprovalBudget(w.bp, w.clock.now, w.bp.state); err == nil {
				w.a, err = RestoreApproval(w.budget, w.ap, w.ap.state)
			}
		}
		if err != nil {
			w.t.Fatalf("restart: %v", err)
		}
	}
	w.checkInvariants()
}

// compare is the user looking at both screens. A user confirms only when
// D shows the same 8 digits as A.
func (w *relayWorld) compare() {
	if w.a.State() != ApprovalOpened {
		return
	}
	aSAS, _, err := w.a.SAS()
	if err != nil {
		return
	}
	dSAS, err := w.d.SAS()
	match := err == nil && dSAS == aSAS
	if err := w.a.Confirm(match); err == nil && match {
		w.confirmed = true
	}
}

// The relay's own chal: a seen chal with one field changed, or a fresh one
// naming the relay's account.
func (w *relayWorld) forgeChal() {
	var ch EnrollChal
	if b, ok := w.from(w.chals); ok && w.pick(4) != 0 {
		_ = canonjson.Unmarshal(b, &ch)
	} else {
		ch = EnrollChal{V: 1, EnrollID: w.eid, NA: fixedBytes("relay nA", 32), AccountID: w.acct.AccountID,
			ApproverDeviceID: fixedID(0x40), AcctSigFp: w.evil.Pin().FpSig, AKV: 1}
	}
	switch w.pick(6) {
	case 0:
		ch.NA = fixedBytes("relay nA "+string(rune('a'+w.pick(26))), 32)
	case 1:
		ch.AcctSigFp = w.evil.Pin().FpSig
	case 2:
		ch.AKV++
	case 3:
		ch.ApproverDeviceID = fixedID(0x41)
	case 4:
		ch.EnrollID = fixedID(0x81)
	case 5:
		ch.AccountID = fixedID(0x11)
	}
	w.send(&w.chals, &ch)
}

// The relay's own open: one of the seen opens with fields mixed in from
// the relay's device or changed.
func (w *relayWorld) forgeOpen() {
	b, ok := w.from(w.opens)
	if !ok {
		return
	}
	var o EnrollOpen
	_ = canonjson.Unmarshal(b, &o)
	mo := w.m.open
	switch w.pick(5) {
	case 0:
		o.KEMPK = bytes.Clone(mo.KEMPK)
	case 1:
		o.SigPK = bytes.Clone(mo.SigPK)
	case 2:
		o.ND = bytes.Clone(mo.ND)
	case 3:
		o.Name = "laptop2"
	case 4:
		o = *mo.clone()
	}
	w.send(&w.opens, &o)
}

// The relay's own delivery to D, consistent in every way except that it
// can only sign with the relay's account keys.
func (w *relayWorld) forgeDelivery() {
	if w.d.rec.Chal == nil {
		return
	}
	o := w.d.open
	th := TranscriptHash(w.d.transcript())
	signer := w.evil
	name := o.Name
	switch w.pick(3) {
	case 1:
		// Real account fingerprint claimed, but no real signing key.
		name = "laptop"
	case 2:
		// A certificate for the relay's device keys.
		o = w.m.open
	}
	cert := Cert{V: 1, AccountID: w.acct.AccountID, AKV: 1, DeviceID: fixedID(0x42), Name: name,
		KEMFp: FpKEM(o.KEMPK), SigFp: FpSig(o.SigPK), EnrollTranscript: SomeHash(th)}
	sig, err := SignCert(signer, &cert)
	if err != nil {
		w.t.Fatal(err)
	}
	// Sealed by hand to D's KEM key, whatever keys the certificate names.
	aad, err := unlockAAD(&cert)
	if err != nil {
		w.t.Fatal(err)
	}
	pt, err := signer.MarshalAcctPriv()
	if err != nil {
		w.t.Fatal(err)
	}
	unlock, err := SealHPKE(w.d.open.KEMPK, unlockInfo(&cert), aad, pt)
	if err != nil {
		w.t.Fatal(err)
	}
	env, err := SealDelivery(w.d.open.KEMPK, th, &EnrollDelivery{V: 1, Cert: cert, CertSig: sig, Unlock: unlock})
	if err != nil {
		w.t.Fatal(err)
	}
	w.send(&w.deliveries, &env)
}

func (w *relayWorld) checkDone(v *VerifiedDelivery) {
	if !v.Account.Pin().Equal(w.acct.Pin()) {
		// The SPEC GAP on HandleDelivery: D has no confirmation step, so it
		// can finish under the relay's account after the user saw a
		// mismatch. It must never happen after a confirmed match.
		if w.confirmed {
			w.t.Fatal("D finished with substituted account keys after a confirmed SAS match")
		}
		if ar := w.a.rec; ar.Open != nil {
			aSAS, err1 := SAS(Transcript(ar.Commit.C, ar.Chal, ar.Open))
			dSAS, err2 := SAS(w.d.transcript())
			if err1 == nil && err2 == nil && aSAS == dSAS {
				w.t.Fatal("D finished with substituted account keys while the screens matched")
			}
		}
		w.substituted = true
		return
	}
	if err := CheckCertKeys(&v.Cert, w.d.open.KEMPK, w.d.open.SigPK); err != nil {
		w.t.Fatal("D finished with a certificate for other keys")
	}
	if !w.confirmed {
		w.t.Fatal("D finished although nobody confirmed the SAS")
	}
	w.done = true
}

func (w *relayWorld) checkInvariants() {
	ar := w.a.rec
	dr := w.d.rec
	// Equal screens imply the same open and chal on both sides.
	if ar.Open != nil && dr.Chal != nil {
		aSAS, err1 := SAS(Transcript(ar.Commit.C, ar.Chal, ar.Open))
		dSAS, err2 := SAS(w.d.transcript())
		if err1 == nil && err2 == nil && aSAS == dSAS {
			w.sameKeys("matching SAS")
		}
	}
	if w.confirmed {
		w.sameKeys("confirmed SAS")
	}
	if ar.State == ApprovalPrepared || ar.State == ApprovalDelivered {
		if !ar.Cert.KEMFp.Equal(FpKEM(w.d.open.KEMPK)) || !ar.Cert.SigFp.Equal(FpSig(w.d.open.SigPK)) {
			w.t.Fatal("A certified keys other than D's")
		}
	}
}

func (w *relayWorld) sameKeys(why string) {
	ar, dr := w.a.rec, w.d.rec
	o := w.d.open
	if ar.Open == nil || dr.Chal == nil {
		w.t.Fatalf("%s without an open on A and a chal on D", why)
	}
	if !bytes.Equal(ar.Open.KEMPK, o.KEMPK) || !bytes.Equal(ar.Open.SigPK, o.SigPK) ||
		!bytes.Equal(ar.Open.ND, o.ND) || ar.Open.Name != o.Name {
		w.t.Fatalf("%s with substituted keys", why)
	}
	ac, dc := ar.Chal, dr.Chal
	if !bytes.Equal(ac.NA, dc.NA) || ac.EnrollID != dc.EnrollID || ac.AccountID != dc.AccountID ||
		ac.ApproverDeviceID != dc.ApproverDeviceID || !ac.AcctSigFp.Equal(dc.AcctSigFp) || ac.AKV != dc.AKV {
		w.t.Fatalf("%s with a substituted chal", why)
	}
}

func runRelaySchedule(t testing.TB, pick func(int) int, steps int) *relayWorld {
	w := newRelayWorld(t, pick)
	for range steps {
		w.step()
	}
	return w
}

// Seeded randomized schedules. The count of runs that got all the way to
// DONE shows the schedules reach the end of the protocol.
func TestEnrollRelaySchedules(t *testing.T) {
	runs, steps := 400, 80
	if testing.Short() {
		runs = 50
	}
	var confirmed, done, substituted int
	for seed := range uint64(runs) {
		rng := rand.New(rand.NewPCG(seed, 0x6e726f6c6c))
		w := runRelaySchedule(t, rng.IntN, steps)
		if w.confirmed {
			confirmed++
		}
		if w.done {
			done++
		}
		if w.substituted {
			substituted++
		}
		if t.Failed() {
			t.Fatalf("seed %d failed", seed)
		}
	}
	t.Logf("%d schedules: %d confirmed a match, %d finished enrollment, %d left D under the relay's account after a mismatch",
		runs, confirmed, done, substituted)
	if done == 0 {
		t.Fatal("no schedule finished enrollment; the driver does not reach the end")
	}
}

// FuzzEnrollRelay drives the same relay from fuzzer input: each byte picks
// the next choice. Under go test it runs the seed corpus; run it with
// go test -fuzz FuzzEnrollRelay ./internal/crypto for more.
func FuzzEnrollRelay(f *testing.F) {
	// The honest schedule: commit to A, chal to D, open to A, compare,
	// deliver, delivery to D (choice bytes, with the pool index next).
	f.Add([]byte{0, 0, 1, 0, 0, 3, 0, 4, 5, 6, 0})
	f.Add([]byte{0, 1, 2, 1, 0, 3, 0, 4, 5, 6, 0, 6, 0})
	f.Add([]byte{8, 0, 3, 1, 1, 0, 0, 3, 0, 4, 7, 0, 9, 6, 1, 6, 0})
	f.Add([]byte{0, 0, 10, 240, 10, 240, 10, 240, 1, 0, 0})
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 512 {
			return
		}
		i := 0
		pick := func(n int) int {
			if i >= len(data) {
				return 0
			}
			v := int(data[i]) % n
			i++
			return v
		}
		w := newRelayWorld(t, pick)
		for i < len(data) {
			w.step()
		}
	})
}

// The relay's tools work: each forged message is refused where it lands.
func TestEnrollRelayForgeriesRefused(t *testing.T) {
	w := runRelaySchedule(t, func(int) int { return 0 }, 0)
	// Honest commit, chal and open.
	var c EnrollCommit
	_ = ParseEnrollMessage(w.commits[0], &c)
	ch, err := w.a.HandleCommit(&c)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.d.HandleChal(&ch); err != nil {
		t.Fatal(err)
	}
	for i := range 3 {
		w.pick = func(int) int { return i } // forgeDelivery's variant
		w.forgeDelivery()
		var env HPKEEnvelope
		_ = canonjson.Unmarshal(w.deliveries[len(w.deliveries)-1], &env)
		if _, err := w.d.HandleDelivery(env); err == nil {
			t.Fatalf("forged delivery %d accepted", i)
		} else if i == 0 && !errors.Is(err, ErrAccountMismatch) {
			t.Fatalf("forged delivery %d: %v", i, err)
		}
	}
}

// SPEC GAP evidence (see DeviceEnrollment.HandleDelivery): the relay gives
// D a chal naming its own account fingerprint. The screens differ and the
// user rejects on A, but D accepts the relay's own delivery anyway,
// because §7 never tells D the user's verdict. This test records the
// spec-literal behavior and must change with the spec.
func TestDeviceAcceptsRelayDeliveryAfterMismatch(t *testing.T) {
	w := runRelaySchedule(t, func(int) int { return 0 }, 0)
	var c EnrollCommit
	_ = ParseEnrollMessage(w.commits[0], &c) // D's real commit
	ch, err := w.a.HandleCommit(&c)
	if err != nil {
		t.Fatal(err)
	}
	forged := *ch.clone()
	forged.AcctSigFp = w.evil.Pin().FpSig
	open, err := w.d.HandleChal(&forged)
	if err != nil {
		t.Fatal(err)
	}
	aSAS, _, err := w.a.HandleOpen(&open)
	if err != nil {
		t.Fatal(err)
	}
	dSAS, _ := w.d.SAS()
	if aSAS == dSAS {
		t.Fatal("the substituted chal gave matching codes")
	}
	if err := w.a.Confirm(false); err != nil || w.a.State() != ApprovalFailed {
		t.Fatalf("mismatch on A: %v", err)
	}
	w.pick = func(int) int { return 0 }
	w.forgeDelivery()
	var env HPKEEnvelope
	_ = canonjson.Unmarshal(w.deliveries[len(w.deliveries)-1], &env)
	v, err := w.d.HandleDelivery(env)
	if err != nil {
		t.Fatalf("the gap is closed (update the SPEC GAP note): %v", err)
	}
	if v.Account.Pin().Equal(w.acct.Pin()) || !v.Account.Pin().FpSig.Equal(w.evil.Pin().FpSig) {
		t.Fatal("expected D to hold the relay's account keys")
	}
}
