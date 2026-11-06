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
// The simulated user compares the two screens and, on each device waiting
// for a decision, confirms only when D's code equals the code A showed and
// rejects otherwise (§7 step 4, rev 9). The properties, checked after
// every step and at the end of every schedule:
//
//	(a) no schedule produces a confirmed SAS match, on A or on D, with
//	    substituted keys: A's open is D's own open and D's chal is A's own
//	    chal;
//	(b) no schedule ends with D holding account keys other than the
//	    honest account's. Whenever D finishes, it holds the real account
//	    keys and a certificate for its own keys, and its user confirmed.

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

	// D's open and accepted chal, kept by the test because D wipes its own
	// copies when its user rejects.
	dOpen EnrollOpen
	dChal *EnrollChal

	// Wire messages the relay has seen or made, as JSON.
	commits, chals, opens, deliveries [][]byte
	forged                            map[string]bool // deliveries the relay sealed itself

	confirmed  bool // A confirmed a match
	dConfirmed bool // D's user confirmed a match
	dRejected  bool // D's user rejected a mismatch
	done       bool // D reached DONE
	early      int  // deliveries D discarded before its user confirmed
	attacks    int  // relay deliveries handed to D while its chal named the relay's account
}

func newRelayWorld(t testing.TB, pick func(int) int) *relayWorld {
	w := &relayWorld{t: t, pick: pick, clock: &fakeClock{t: time.Date(2026, 10, 22, 12, 0, 0, 0, time.UTC)},
		eid: fixedID(0x80), dp: &memPersister{}, ap: &memPersister{}, bp: &memPersister{}, forged: map[string]bool{}}
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
	w.dOpen = *w.d.open.clone()
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

// handleChal hands a chal to dev and, if dev is D and accepts it, records
// D's chal.
func (w *relayWorld) handleChal(dev *DeviceEnrollment, ch *EnrollChal) (EnrollOpen, error) {
	o, err := dev.HandleChal(ch)
	if err == nil && dev == w.d {
		w.dChal = ch.clone()
	}
	return o, err
}

// dTranscript is T as D built it.
func (w *relayWorld) dTranscript() []byte {
	return Transcript(Commitment(&w.dOpen), w.dChal, &w.dOpen)
}

// aShown returns the code A showed, once it accepted an open.
func (w *relayWorld) aShown() (string, bool) {
	ar := w.a.rec
	if ar.Open == nil {
		return "", false
	}
	sas, err := SAS(Transcript(ar.Commit.C, ar.Chal, ar.Open))
	return sas, err == nil
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
				if o, err := w.handleChal(dev, &ch); err == nil {
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
			if w.forged[string(b)] && w.dChal != nil && w.dChal.AcctSigFp.Equal(w.evil.Pin().FpSig) {
				w.attacks++
			}
			var env HPKEEnvelope
			if canonjson.Unmarshal(b, &env) == nil {
				v, err := w.d.HandleDelivery(env)
				switch {
				case err == nil:
					w.checkDone(v)
				case errors.Is(err, ErrSASNotConfirmed):
					w.early++
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

// compare is the user looking at both screens and deciding on each device
// that waits for a decision. The user confirms only when D shows the same
// 8 digits as A and rejects otherwise. A with no code on D's screen is
// rejected; D with no code on A's screen waits.
func (w *relayWorld) compare() {
	aSAS, aOK := w.aShown()
	dSAS, err := w.d.SAS()
	dOK := err == nil
	match := aOK && dOK && aSAS == dSAS
	if w.a.State() == ApprovalOpened {
		if err := w.a.Confirm(match); err == nil && match {
			w.confirmed = true
		}
	}
	if w.d.State() == DeviceRevealed && aOK && dOK {
		if match {
			if w.d.ConfirmSAS() == nil {
				w.dConfirmed = true
			}
		} else if w.d.RejectSAS() == nil {
			w.dRejected = true
		}
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
	if w.dChal == nil {
		return
	}
	o := w.dOpen
	th := TranscriptHash(w.dTranscript())
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
	unlock, err := SealHPKE(w.dOpen.KEMPK, unlockInfo(&cert), aad, pt)
	if err != nil {
		w.t.Fatal(err)
	}
	env, err := SealDelivery(w.dOpen.KEMPK, th, &EnrollDelivery{V: 1, Cert: cert, CertSig: sig, Unlock: unlock})
	if err != nil {
		w.t.Fatal(err)
	}
	w.send(&w.deliveries, &env)
	w.forged[string(w.deliveries[len(w.deliveries)-1])] = true
}

// checkDone checks a delivery D accepted: property (b).
func (w *relayWorld) checkDone(v *VerifiedDelivery) {
	if !v.Account.Pin().Equal(w.acct.Pin()) {
		w.t.Fatalf("property (b): D finished with the relay's account keys (D confirmed: %v, D rejected: %v)",
			w.dConfirmed, w.dRejected)
	}
	if err := CheckCertKeys(&v.Cert, w.dOpen.KEMPK, w.dOpen.SigPK); err != nil {
		w.t.Fatal("D finished with a certificate for other keys")
	}
	if !w.confirmed || !w.dConfirmed {
		w.t.Fatalf("D finished without a confirmed SAS (A: %v, D: %v)", w.confirmed, w.dConfirmed)
	}
	w.done = true
}

// finish checks the end of a schedule: property (b) on whatever D holds,
// in memory and after a restart from its persisted state.
func (w *relayWorld) finish() {
	d, err := RestoreDeviceEnrollmentWithClock(w.dp, w.clock.now, w.dp.state)
	if err != nil {
		w.t.Fatalf("restore at the end: %v", err)
	}
	for _, dev := range []*DeviceEnrollment{w.d, d} {
		v, err := dev.Delivered()
		if dev.State() != DeviceDone {
			if err == nil {
				w.t.Fatalf("property (b): D in state %q returned account keys", dev.State())
			}
			continue
		}
		if err != nil {
			w.t.Fatalf("DONE without a delivery: %v", err)
		}
		if !v.Account.Pin().Equal(w.acct.Pin()) {
			w.t.Fatal("property (b): the schedule ended with D holding the relay's account keys")
		}
	}
}

func (w *relayWorld) checkInvariants() {
	ar := w.a.rec
	// Equal screens imply the same open and chal on both sides.
	if ar.Open != nil && w.dChal != nil {
		aSAS, err1 := SAS(Transcript(ar.Commit.C, ar.Chal, ar.Open))
		dSAS, err2 := SAS(w.dTranscript())
		if err1 == nil && err2 == nil && aSAS == dSAS {
			w.sameKeys("matching SAS")
		}
	}
	// Property (a).
	if w.confirmed {
		w.sameKeys("SAS confirmed on A")
	}
	if w.dConfirmed {
		w.sameKeys("SAS confirmed on D")
	}
	switch w.d.State() {
	case DeviceConfirmed, DeviceDone:
		if !w.dConfirmed {
			w.t.Fatalf("D reached %q without its user confirming", w.d.State())
		}
	case DeviceRejected, DeviceFailed:
		var rec deviceRecord
		if err := canonjson.Unmarshal(w.dp.state, &rec); err != nil || rec.State != w.d.State() || !rec.onlyState() {
			w.t.Fatalf("D's %s record keeps more than the state", w.d.State())
		}
		if kem, sig := w.d.DeviceKeys(); kem != nil || sig != nil {
			w.t.Fatalf("D returns enrollment keys in %s", w.d.State())
		}
	}
	if ar.State == ApprovalPrepared || ar.State == ApprovalDelivered {
		if !ar.Cert.KEMFp.Equal(FpKEM(w.dOpen.KEMPK)) || !ar.Cert.SigFp.Equal(FpSig(w.dOpen.SigPK)) {
			w.t.Fatal("A certified keys other than D's")
		}
	}
}

func (w *relayWorld) sameKeys(why string) {
	ar := w.a.rec
	o := w.dOpen
	if ar.Open == nil || w.dChal == nil {
		w.t.Fatalf("%s without an open on A and a chal on D", why)
	}
	if !bytes.Equal(ar.Open.KEMPK, o.KEMPK) || !bytes.Equal(ar.Open.SigPK, o.SigPK) ||
		!bytes.Equal(ar.Open.ND, o.ND) || ar.Open.Name != o.Name {
		w.t.Fatalf("%s with substituted keys", why)
	}
	ac, dc := ar.Chal, w.dChal
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
	w.finish()
	return w
}

// Seeded randomized schedules. The counts show the schedules reach the end
// of the protocol, reach both of D's decisions, and try the attack that
// rev 9 closed (a relay delivery to a D whose chal names the relay's
// account).
func TestEnrollRelaySchedules(t *testing.T) {
	runs, steps := 400, 80
	if testing.Short() {
		runs = 50
	}
	var confirmed, dConfirmed, dRejected, done, early, attacked int
	for seed := range uint64(runs) {
		rng := rand.New(rand.NewPCG(seed, 0x6e726f6c6c))
		w := runRelaySchedule(t, rng.IntN, steps)
		for _, c := range []struct {
			n  *int
			ok bool
		}{{&confirmed, w.confirmed}, {&dConfirmed, w.dConfirmed}, {&dRejected, w.dRejected}, {&done, w.done},
			{&early, w.early > 0}, {&attacked, w.attacks > 0}} {
			if c.ok {
				*c.n++
			}
		}
		if t.Failed() {
			t.Fatalf("seed %d failed", seed)
		}
	}
	t.Logf("%d schedules: %d confirmed a match on A, %d on D, %d rejected on D, %d finished enrollment, "+
		"%d had a delivery discarded before D's confirmation, %d handed D a relay delivery under a chal naming the relay's account",
		runs, confirmed, dConfirmed, dRejected, done, early, attacked)
	if done == 0 || dRejected == 0 || attacked == 0 {
		t.Fatal("the driver does not reach the end, a rejection on D, or the relay-account attack")
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
	// The rev 9 attack: a fresh chal naming the relay's account to D, then
	// the relay's own delivery before D's user decides.
	f.Add([]byte{7, 0, 1, 0, 0, 9, 0, 6, 0})
	// The same after A's real chal: the relay changes acct_sig_fp, A gets
	// D's open, the relay delivers before and after the user compares
	// (rejecting on both devices).
	f.Add([]byte{0, 0, 7, 0, 1, 1, 1, 0, 1, 3, 0, 9, 0, 6, 1, 4, 9, 0, 6, 2})
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
		w.finish()
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
	open, err := w.handleChal(w.d, &ch)
	if err != nil {
		t.Fatal(err)
	}
	// The codes match and the user confirms, so the forgeries reach the
	// step 6 checks.
	if _, _, err := w.a.HandleOpen(&open); err != nil {
		t.Fatal(err)
	}
	if err := w.d.ConfirmSAS(); err != nil {
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

// The rev 9 attack: the relay gives D a chal naming its own account
// fingerprint, so the screens differ and the user rejects on A. The relay
// then hands D a delivery sealed under its own account keys, which passes
// every step 6 check. D discards it while its user has not confirmed,
// leaving its persisted state unchanged, and refuses it after its user
// rejects.
func TestDeviceRefusesDeliveryAfterRejectedSAS(t *testing.T) {
	w := runRelaySchedule(t, func(int) int { return 0 }, 0)
	var c EnrollCommit
	_ = ParseEnrollMessage(w.commits[0], &c) // D's real commit
	ch, err := w.a.HandleCommit(&c)
	if err != nil {
		t.Fatal(err)
	}
	forged := *ch.clone()
	forged.AcctSigFp = w.evil.Pin().FpSig
	open, err := w.handleChal(w.d, &forged)
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

	// D's user has not decided yet.
	before, saves := bytes.Clone(w.dp.state), w.dp.saves
	if _, err := w.d.HandleDelivery(env); !errors.Is(err, ErrSASNotConfirmed) {
		t.Fatalf("delivery before D's decision: %v (state %q)", err, w.d.State())
	}
	if !bytes.Equal(w.dp.state, before) || w.dp.saves != saves || w.d.State() != DeviceRevealed {
		t.Fatal("the discarded delivery changed D's state")
	}

	// D's user sees the mismatch too and rejects.
	if err := w.d.RejectSAS(); err != nil {
		t.Fatal(err)
	}
	for _, d := range []*DeviceEnrollment{w.d, mustRestore(t, w.dp, w.clock.now)} {
		if _, err := d.HandleDelivery(env); !errors.Is(err, ErrSASRejected) {
			t.Fatalf("delivery after the rejection: %v", err)
		}
		if _, err := d.Delivered(); err == nil {
			t.Fatal("D holds account keys after the rejection")
		}
	}
	w.finish()
}

func mustRestore(t *testing.T, p *memPersister, now Clock) *DeviceEnrollment {
	t.Helper()
	d, err := RestoreDeviceEnrollmentWithClock(p, now, p.state)
	if err != nil {
		t.Fatal(err)
	}
	return d
}
