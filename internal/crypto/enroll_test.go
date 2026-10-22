package crypto

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/dalyem/hopkey/internal/canonjson"
	"github.com/dalyem/hopkey/internal/model"
)

func TestRender8HandComputed(t *testing.T) {
	words := func(ws ...uint32) []byte {
		b := make([]byte, 64)
		for i := range 16 {
			binary.BigEndian.PutUint32(b[4*i:], 0xffffffff)
		}
		for i, w := range ws {
			binary.BigEndian.PutUint32(b[4*i:], w)
		}
		return b
	}
	for _, tc := range []struct {
		name string
		in   []byte
		want string
	}{
		{"zero", words(0), "00000000"},
		{"leading zeros", words(1_000_000), "01000000"},
		{"one", words(1), "00000001"},
		{"largest accepted", words(4_199_999_999), "99999999"},            // 0xFA56E9FF
		{"mod 10^8", words(123_456_789), "23456789"},                      // 0x075BCD15
		{"4.2e9 skipped", words(4_200_000_000, 7), "00000007"},            // 0xFA56EA00 is rejected
		{"max skipped", words(0xffffffff, 4_200_000_000, 42), "00000042"}, // two skipped words
		{"last word", append(bytes.Repeat([]byte{0xff}, 60), 0, 0, 0x30, 0x39), "00012345"},
	} {
		got, err := render8(tc.in)
		if err != nil || got != tc.want {
			t.Errorf("%s: %q, %v; want %q", tc.name, got, err, tc.want)
		}
	}
	// 0xFA56EA00 really is 4,200,000,000.
	if 0xFA56EA00 != 4_200_000_000 {
		t.Fatal("constant check")
	}
	if _, err := render8(bytes.Repeat([]byte{0xfa, 0x56, 0xea, 0x00}, 16)); !errors.Is(err, ErrSASAbort) {
		t.Errorf("all 16 words at the bound: %v", err)
	}
	if _, err := render8(words()); !errors.Is(err, ErrSASAbort) {
		t.Errorf("all 16 words 0xffffffff: %v", err)
	}
}

func testOpen(t *testing.T) *EnrollOpen {
	return &EnrollOpen{V: 1, KEMPK: fixedKEM(t, "D-kem").PublicKey().Bytes(), SigPK: fixedSig("D-sig").Public().(ed25519.PublicKey),
		ND: fixedBytes("nD", 32), Name: "new-laptop"}
}

func testChal(t *testing.T) *EnrollChal {
	acct := fixedAccount(t, 1)
	return &EnrollChal{V: 1, EnrollID: fixedID(0x80), NA: fixedBytes("nA", 32), AccountID: acct.AccountID,
		ApproverDeviceID: fixedID(0x40), AcctSigFp: acct.Pin().FpSig, AKV: 1}
}

// c and T built byte by byte from the §7 definitions.
func TestCommitmentAndTranscriptBytes(t *testing.T) {
	o := testOpen(t)
	ch := testChal(t)
	if len(o.KEMPK) != 1216 {
		t.Fatalf("X-Wing public key is %d bytes", len(o.KEMPK))
	}
	var c bytes.Buffer
	c.Write([]byte{0, 0, 0, 23})
	c.WriteString("hopkey/v1/enroll-commit")
	c.Write([]byte{0, 0, 0, 1})
	c.Write([]byte{0, 0, 0x04, 0xc0})
	c.Write(o.KEMPK)
	c.Write([]byte{0, 0, 0, 32})
	c.Write(o.SigPK)
	c.Write([]byte{0, 0, 0, 32})
	c.Write(o.ND)
	c.Write([]byte{0, 0, 0, 10})
	c.WriteString("new-laptop")
	wantC := sha256.Sum256(c.Bytes())
	gotC := Commitment(o)
	if gotC != Hash(wantC) {
		t.Fatal("c does not follow §7")
	}

	var tr bytes.Buffer
	tr.Write([]byte{0, 0, 0, 27})
	tr.WriteString("hopkey/v1/enroll-transcript")
	tr.Write([]byte{0, 0, 0, 1})
	tr.Write([]byte{0, 0, 0, 16})
	tr.Write(ch.EnrollID[:])
	tr.Write([]byte{0, 0, 0, 32})
	tr.Write(wantC[:])
	tr.Write([]byte{0, 0, 0, 32})
	tr.Write(ch.NA)
	tr.Write([]byte{0, 0, 0, 16})
	tr.Write(ch.AccountID[:])
	tr.Write([]byte{0, 0, 0, 16})
	tr.Write(ch.ApproverDeviceID[:])
	tr.Write([]byte{0, 0, 0, 32})
	tr.Write(ch.AcctSigFp[:])
	tr.Write([]byte{0, 0, 0, 1}) // akv
	tr.Write([]byte{0, 0, 0x04, 0xc0})
	tr.Write(o.KEMPK)
	tr.Write([]byte{0, 0, 0, 32})
	tr.Write(o.SigPK)
	tr.Write([]byte{0, 0, 0, 32})
	tr.Write(o.ND)
	tr.Write([]byte{0, 0, 0, 10})
	tr.WriteString("new-laptop")
	if got := Transcript(gotC, ch, o); !bytes.Equal(got, tr.Bytes()) {
		t.Fatal("T does not follow §7")
	}

	// SAS = render8(HKDF(SHA-256(T), salt=empty, info=lp("hopkey/v1/enroll-sas"), 64)).
	th := sha256.Sum256(tr.Bytes())
	okm, _ := hkdfKey(th[:], nil, LP([]byte("hopkey/v1/enroll-sas")), 64)
	want, _ := render8(okm)
	got, err := SAS(tr.Bytes())
	if err != nil || got != want || len(got) != 8 {
		t.Fatalf("SAS = %q, %v", got, err)
	}

	// Every field of open is covered by c.
	for name, mutate := range map[string]func(*EnrollOpen){
		"kem_pk": func(o *EnrollOpen) { o.KEMPK = fixedKEM(t, "x").PublicKey().Bytes() },
		"sig_pk": func(o *EnrollOpen) { o.SigPK = fixedSig("x").Public().(ed25519.PublicKey) },
		"nD":     func(o *EnrollOpen) { o.ND = fixedBytes("x", 32) },
		"name":   func(o *EnrollOpen) { o.Name = "new-laptoq" },
	} {
		m := *o
		mutate(&m)
		if Commitment(&m) == gotC {
			t.Errorf("c does not cover %s", name)
		}
	}
}

func TestEnrollMessageSchemas(t *testing.T) {
	for name, tc := range map[string]struct {
		in string
		v  interface{ Validate() error }
	}{
		"commit unknown member": {`{"c":"` + strings.Repeat("a", 64) + `","v":1,"x":1}`, &EnrollCommit{}},
		"commit duplicate":      {`{"c":"` + strings.Repeat("a", 64) + `","c":"` + strings.Repeat("b", 64) + `","v":1}`, &EnrollCommit{}},
		"commit v=2":            {`{"c":"` + strings.Repeat("a", 64) + `","v":2}`, &EnrollCommit{}},
		"commit missing c":      {`{"v":1}`, &EnrollCommit{}},
		"chal missing akv":      {`{"account_id":"` + strings.Repeat("1", 32) + `","acct_sig_fp":"` + strings.Repeat("a", 64) + `","approver_device_id":"` + strings.Repeat("2", 32) + `","enroll_id":"` + strings.Repeat("3", 32) + `","nA":"` + strings.Repeat("A", 43) + `","v":1}`, &EnrollChal{}},
	} {
		if err := ParseEnrollMessage([]byte(tc.in), tc.v); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	// open with valid keys and only nD the wrong length: the rejection must
	// come from nD, not from an earlier field.
	o := testOpen(t)
	if j, err := canonjson.Marshal(o); err != nil {
		t.Fatal(err)
	} else if err := ParseEnrollMessage(j, &EnrollOpen{}); err != nil {
		t.Fatalf("valid open rejected: %v", err)
	}
	for _, n := range []int{0, 31, 33} {
		short := *o
		short.ND = fixedBytes("nD", n)
		j, err := canonjson.Marshal(&short)
		if err != nil {
			t.Fatal(err)
		}
		var se *SchemaError
		if err := ParseEnrollMessage(j, &EnrollOpen{}); !errors.As(err, &se) || se.Field != "nD" {
			t.Errorf("open with %d-byte nD: %v", n, err)
		}
	}
	good := `{"c":"` + strings.Repeat("a", 64) + `","v":1}`
	var c EnrollCommit
	if err := ParseEnrollMessage([]byte(good), &c); err != nil {
		t.Errorf("valid commit rejected: %v", err)
	}
	chal := `{"account_id":"` + strings.Repeat("1", 32) + `","acct_sig_fp":"` + strings.Repeat("a", 64) + `","akv":1,"approver_device_id":"` + strings.Repeat("2", 32) + `","enroll_id":"` + strings.Repeat("3", 32) + `","nA":"` + strings.Repeat("A", 43) + `","v":1}`
	var ch EnrollChal
	if err := ParseEnrollMessage([]byte(chal), &ch); err != nil {
		t.Errorf("valid chal rejected: %v", err)
	}
}

// enrollRig holds both parties with their persisters and a shared budget.
type enrollRig struct {
	acct     *AccountKeys
	approver model.ID
	dp, ap   *memPersister
	bp       *memPersister
	clock    *fakeClock
	budget   *ApprovalBudget
	d        *DeviceEnrollment
	a        *Approval
}

func newEnrollRig(t *testing.T) *enrollRig {
	t.Helper()
	r := &enrollRig{acct: fixedAccount(t, 1), approver: fixedID(0x40), dp: &memPersister{}, ap: &memPersister{},
		bp: &memPersister{}, clock: &fakeClock{t: time.Date(2026, 10, 22, 12, 0, 0, 0, time.UTC)}}
	var err error
	r.budget, err = LoadApprovalBudget(r.bp, r.clock.now, nil)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

// runToOpen takes the protocol through commit, chal and open. It returns
// both SAS values.
func (r *enrollRig) runToOpen(t *testing.T, enrollID model.ID) (dSAS, aSAS string) {
	t.Helper()
	d, commit, err := NewDeviceEnrollmentWithClock(r.dp, r.clock.now, "new-laptop")
	if err != nil {
		t.Fatal(err)
	}
	r.d = d
	if err := d.SetEnrollID(enrollID); err != nil {
		t.Fatal(err)
	}
	a, err := StartApproval(r.budget, r.ap, enrollID, r.acct.Pin(), r.approver)
	if err != nil {
		t.Fatal(err)
	}
	r.a = a
	ch, err := a.HandleCommit(&commit)
	if err != nil {
		t.Fatal(err)
	}
	open, err := d.HandleChal(&ch)
	if err != nil {
		t.Fatal(err)
	}
	aSAS, name, err := a.HandleOpen(&open)
	if err != nil {
		t.Fatal(err)
	}
	if name != "new-laptop" {
		t.Fatalf("name = %q", name)
	}
	dSAS, err = d.SAS()
	if err != nil {
		t.Fatal(err)
	}
	return dSAS, aSAS
}

func TestEnrollmentHappyPath(t *testing.T) {
	r := newEnrollRig(t)
	dSAS, aSAS := r.runToOpen(t, fixedID(0x80))
	if dSAS != aSAS {
		t.Fatalf("SAS differ: %s vs %s", dSAS, aSAS)
	}
	if err := r.a.Confirm(true); err != nil {
		t.Fatal(err)
	}
	if err := r.d.ConfirmSAS(); err != nil {
		t.Fatal(err)
	}
	prep, err := r.a.Prepare(r.acct, fixedID(0x41), ts(t, "2026-10-22T12:00:00Z"))
	if err != nil {
		t.Fatal(err)
	}
	// The device_add material is consistent.
	if err := CheckCertKeys(&prep.Cert, prep.KEMPK, prep.SigPK); err != nil {
		t.Fatal(err)
	}
	if err := VerifyCert(r.acct.Public().SigPK, &prep.Cert, prep.CertSig); err != nil {
		t.Fatal(err)
	}
	anchorH := Hash(sha256.Sum256([]byte("anchor")))
	env, err := r.a.Deliver(0, anchorH)
	if err != nil {
		t.Fatal(err)
	}
	if r.a.State() != ApprovalDelivered || r.budget.rec.Outstanding != (model.ID{}) {
		t.Fatal("attempt not closed")
	}
	v, err := r.d.HandleDelivery(env)
	if err != nil {
		t.Fatal(err)
	}
	if !v.Account.Pin().Equal(r.acct.Pin()) || v.AnchorH != anchorH || v.AnchorSeq != 0 || v.Cert.DeviceID != fixedID(0x41) {
		t.Fatal("delivery contents wrong")
	}
	if r.d.State() != DeviceDone {
		t.Fatal("D not done")
	}
	// The delivered certificate binds SHA-256(T).
	if !v.Cert.EnrollTranscript.Equal(TranscriptHash(r.d.transcript())) {
		t.Fatal("enroll_transcript is not SHA-256(T)")
	}
}

func TestSecondChalAfterReveal(t *testing.T) {
	r := newEnrollRig(t)
	r.runToOpen(t, fixedID(0x80))
	again := *r.a.rec.Chal
	if _, err := r.d.HandleChal(&again); !errors.Is(err, ErrChalAfterReveal) {
		t.Fatalf("identical second chal: %v", err)
	}
	other := again
	other.NA = fixedBytes("other nA", 32)
	if _, err := r.d.HandleChal(&other); !errors.Is(err, ErrChalAfterReveal) {
		t.Fatalf("different second chal: %v", err)
	}
	// Also after a restart.
	d, err := RestoreDeviceEnrollmentWithClock(r.dp, r.clock.now, r.dp.state)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := d.HandleChal(&other); !errors.Is(err, ErrChalAfterReveal) {
		t.Fatalf("second chal after restart: %v", err)
	}
	// The open message is re-sendable and unchanged.
	o1, _ := r.d.Open()
	o2, err := d.Open()
	if err != nil || Commitment(&o1) != Commitment(&o2) {
		t.Fatal("open changed across restart")
	}
}

func TestChalRules(t *testing.T) {
	dp := &memPersister{}
	d, _, err := NewDeviceEnrollment(dp, "n")
	if err != nil {
		t.Fatal(err)
	}
	ch := testChal(t)
	// Before the server assigns enroll_id, no chal is accepted.
	if _, err := d.HandleChal(ch); !errors.Is(err, ErrEnrollState) {
		t.Fatalf("chal before enroll_id: %v", err)
	}
	if err := d.SetEnrollID(fixedID(0x81)); err != nil {
		t.Fatal(err)
	}
	if _, err := d.HandleChal(ch); !errors.Is(err, ErrWrongEnrollID) {
		t.Fatalf("chal for another enroll_id: %v", err)
	}
	bad := *ch
	bad.EnrollID = fixedID(0x81)
	bad.NA = bad.NA[:31]
	if _, err := d.HandleChal(&bad); err == nil {
		t.Fatal("chal with short nA accepted")
	}
	// The rejected chals left D able to accept the right one.
	good := *ch
	good.EnrollID = fixedID(0x81)
	if _, err := d.HandleChal(&good); err != nil {
		t.Fatalf("valid chal after rejected ones: %v", err)
	}
	if err := d.SetEnrollID(fixedID(0x82)); err == nil {
		t.Fatal("enroll_id changed after reveal")
	}
}

func TestStateIsPersistedBeforeMessages(t *testing.T) {
	r := newEnrollRig(t)
	r.dp.fail = true
	if _, _, err := NewDeviceEnrollment(r.dp, "n"); !errors.Is(err, errPersist) {
		t.Fatalf("commit returned without persisting: %v", err)
	}
	r.dp.fail = false
	d, commit, err := NewDeviceEnrollment(r.dp, "n")
	if err != nil {
		t.Fatal(err)
	}
	if err := d.SetEnrollID(fixedID(0x80)); err != nil {
		t.Fatal(err)
	}
	a, err := StartApproval(r.budget, r.ap, fixedID(0x80), r.acct.Pin(), r.approver)
	if err != nil {
		t.Fatal(err)
	}
	r.ap.fail = true
	if _, err := a.HandleCommit(&commit); !errors.Is(err, errPersist) || a.State() != ApprovalReserved {
		t.Fatalf("chal returned without persisting: %v", err)
	}
	r.ap.fail = false
	ch, err := a.HandleCommit(&commit)
	if err != nil {
		t.Fatal(err)
	}
	r.dp.fail = true
	if _, err := d.HandleChal(&ch); !errors.Is(err, errPersist) || d.State() != DeviceCommitted {
		t.Fatalf("open returned without persisting REVEALED: %v", err)
	}
	r.dp.fail = false
	if _, err := d.HandleChal(&ch); err != nil {
		t.Fatalf("chal after a failed persist: %v", err)
	}
	// A accepts exactly one commit.
	if _, err := a.HandleCommit(&commit); !errors.Is(err, ErrEnrollState) {
		t.Fatalf("second commit: %v", err)
	}
}

func TestOpenMustMatchCommitment(t *testing.T) {
	r := newEnrollRig(t)
	d, commit, _ := NewDeviceEnrollment(r.dp, "n")
	_ = d.SetEnrollID(fixedID(0x80))
	a, _ := StartApproval(r.budget, r.ap, fixedID(0x80), r.acct.Pin(), r.approver)
	ch, _ := a.HandleCommit(&commit)
	open, _ := d.HandleChal(&ch)
	forged := open
	forged.Name = "evil"
	if _, _, err := a.HandleOpen(&forged); !errors.Is(err, ErrCommitMismatch) {
		t.Fatalf("forged open: %v", err)
	}
	if _, _, err := a.HandleOpen(&open); err != nil {
		t.Fatalf("real open after a forged one: %v", err)
	}
}

// A relay that substitutes its own keys toward A gets a different SAS on
// the two screens.
func TestRelaySubstitutionChangesSAS(t *testing.T) {
	r := newEnrollRig(t)
	d, _, _ := NewDeviceEnrollment(r.dp, "laptop")
	_ = d.SetEnrollID(fixedID(0x80))
	mitm, mcommit, _ := NewDeviceEnrollment(&memPersister{}, "laptop")
	_ = mitm.SetEnrollID(fixedID(0x80))
	a, _ := StartApproval(r.budget, r.ap, fixedID(0x80), r.acct.Pin(), r.approver)
	ch, _ := a.HandleCommit(&mcommit) // the relay's commit reaches A
	mopen, _ := mitm.HandleChal(&ch)
	aSAS, _, err := a.HandleOpen(&mopen)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := d.HandleChal(&ch); err != nil { // the same chal is relayed to D
		t.Fatal(err)
	}
	dSAS, _ := d.SAS()
	if aSAS == dSAS {
		t.Fatal("substituted keys produced matching SAS")
	}
	// The user sees the mismatch: failure, slot spent.
	if err := a.Confirm(false); err != nil || a.State() != ApprovalFailed {
		t.Fatalf("mismatch: %v", err)
	}
	if r.budget.Remaining() != 2 {
		t.Fatalf("slot released after failure: %d left", r.budget.Remaining())
	}
	if _, err := a.Prepare(r.acct, fixedID(0x41), 0); !errors.Is(err, ErrEnrollState) {
		t.Fatal("failed attempt can still prepare a device")
	}
}

// A substituted delivery: unlock keys that do not match the SAS-authenticated
// fingerprint are refused by D.
func TestSubstitutedDelivery(t *testing.T) {
	r := newEnrollRig(t)
	r.runToOpen(t, fixedID(0x80))
	if err := r.d.ConfirmSAS(); err != nil {
		t.Fatal(err)
	}
	open, _ := r.d.Open()
	th := TranscriptHash(r.d.transcript())

	// The attacker holds its own account keys (same account_id and akv) and
	// builds a perfectly consistent delivery under them.
	evil, err := NewAccountKeys(r.acct.AccountID, 1, fixedKEM(t, "evil-kem"), fixedBytes("evil-sig", 32))
	if err != nil {
		t.Fatal(err)
	}
	cert := Cert{V: 1, AccountID: evil.AccountID, AKV: 1, DeviceID: fixedID(0x41), Name: open.Name,
		KEMFp: FpKEM(open.KEMPK), SigFp: FpSig(open.SigPK), EnrollTranscript: SomeHash(th), IssuedAt: 0}
	sig, _ := SignCert(evil, &cert)
	unlock, _ := SealUnlock(open.KEMPK, &cert, evil)
	env, _ := SealDelivery(open.KEMPK, th, &EnrollDelivery{V: 1, Cert: cert, CertSig: sig, Unlock: unlock})
	if _, err := r.d.HandleDelivery(env); !errors.Is(err, ErrAccountMismatch) {
		t.Fatalf("substituted delivery: %v", err)
	}
	if r.d.State() != DeviceConfirmed {
		t.Fatal("a rejected delivery changed D's state")
	}

	// Real account keys, but a certificate for someone else's keys.
	cert2 := cert
	cert2.AccountID = r.acct.AccountID
	cert2.KEMFp = FpKEM(fixedKEM(t, "other").PublicKey().Bytes())
	sig2, _ := SignCert(r.acct, &cert2)
	unlock2, err := SealUnlock(open.KEMPK, &Cert{}, r.acct)
	if err == nil {
		t.Fatal("unlock sealed for an invalid certificate")
	}
	_ = unlock2
	// Build it by hand, sealing to D's key for the forged cert.
	aad, _ := unlockAAD(&cert2)
	pt, _ := r.acct.MarshalAcctPriv()
	unlock3, _ := SealHPKE(open.KEMPK, unlockInfo(&cert2), aad, pt)
	env2, _ := SealDelivery(open.KEMPK, th, &EnrollDelivery{V: 1, Cert: cert2, CertSig: sig2, Unlock: unlock3})
	if _, err := r.d.HandleDelivery(env2); err == nil {
		t.Fatal("certificate binding other keys accepted")
	}

	// Right keys, wrong transcript.
	cert3 := cert
	cert3.AccountID = r.acct.AccountID
	cert3.EnrollTranscript = SomeHash(sha256.Sum256([]byte("other T")))
	sig3, _ := SignCert(r.acct, &cert3)
	unlock4, _ := SealUnlock(open.KEMPK, &cert3, r.acct)
	env3, _ := SealDelivery(open.KEMPK, th, &EnrollDelivery{V: 1, Cert: cert3, CertSig: sig3, Unlock: unlock4})
	if _, err := r.d.HandleDelivery(env3); err == nil {
		t.Fatal("certificate for another transcript accepted")
	}

	// Right everything, but cert_sig by another key.
	cert4 := cert
	cert4.AccountID = r.acct.AccountID
	unlock5, _ := SealUnlock(open.KEMPK, &cert4, r.acct)
	badSig, _ := Sign(evil.Sig, LabelDeviceCert, &cert4)
	env4, _ := SealDelivery(open.KEMPK, th, &EnrollDelivery{V: 1, Cert: cert4, CertSig: badSig, Unlock: unlock5})
	if _, err := r.d.HandleDelivery(env4); !errors.Is(err, ErrBadSignature) {
		t.Fatalf("bad cert_sig: %v", err)
	}

	// Sealed under another transcript hash: does not open.
	sig4, _ := SignCert(r.acct, &cert4)
	env5, _ := SealDelivery(open.KEMPK, Hash(sha256.Sum256([]byte("x"))), &EnrollDelivery{V: 1, Cert: cert4, CertSig: sig4, Unlock: unlock5})
	if _, err := r.d.HandleDelivery(env5); !errors.Is(err, ErrDecrypt) {
		t.Fatalf("delivery under another T: %v", err)
	}

	// And the genuine one still works.
	env6, _ := SealDelivery(open.KEMPK, th, &EnrollDelivery{V: 1, Cert: cert4, CertSig: sig4, Unlock: unlock5})
	if _, err := r.d.HandleDelivery(env6); err != nil {
		t.Fatalf("genuine delivery: %v", err)
	}
}

func TestApprovalBudgetAcrossRestart(t *testing.T) {
	bp := &memPersister{}
	clock := &fakeClock{t: time.Date(2026, 10, 22, 12, 0, 0, 0, time.UTC)}
	b, _ := LoadApprovalBudget(bp, clock.now, nil)
	acct := fixedAccount(t, 1)
	for i := range 3 {
		a, err := StartApproval(b, &memPersister{}, fixedID(byte(0x80+i)), acct.Pin(), fixedID(0x40))
		if err != nil {
			t.Fatalf("attempt %d: %v", i, err)
		}
		// One outstanding challenge at a time.
		if _, err := StartApproval(b, &memPersister{}, fixedID(0x90), acct.Pin(), fixedID(0x40)); !errors.Is(err, ErrChallengeOutstanding) {
			t.Fatalf("second outstanding challenge: %v", err)
		}
		if err := a.Abort(); err != nil {
			t.Fatal(err)
		}
		clock.advance(10 * time.Minute)
	}
	// Simulated restart: a fresh process loads the persisted budget.
	b2, err := LoadApprovalBudget(bp, clock.now, bp.state)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := StartApproval(b2, &memPersister{}, fixedID(0x84), acct.Pin(), fixedID(0x40)); !errors.Is(err, ErrBudgetExhausted) {
		t.Fatalf("fourth attempt within the hour after restart: %v", err)
	}
	// The first reservation leaves the window an hour after it was made.
	clock.advance(30 * time.Minute) // 60 minutes after the first
	if _, err := StartApproval(b2, &memPersister{}, fixedID(0x85), acct.Pin(), fixedID(0x40)); err != nil {
		t.Fatalf("attempt after the window rolled: %v", err)
	}
}

func TestOutstandingChallengeSurvivesRestart(t *testing.T) {
	bp := &memPersister{}
	ap := &memPersister{}
	clock := &fakeClock{t: time.Date(2026, 10, 22, 12, 0, 0, 0, time.UTC)}
	b, _ := LoadApprovalBudget(bp, clock.now, nil)
	acct := fixedAccount(t, 1)
	if _, err := StartApproval(b, ap, fixedID(0x80), acct.Pin(), fixedID(0x40)); err != nil {
		t.Fatal(err)
	}
	b2, _ := LoadApprovalBudget(bp, clock.now, bp.state)
	if _, err := StartApproval(b2, &memPersister{}, fixedID(0x81), acct.Pin(), fixedID(0x40)); !errors.Is(err, ErrChallengeOutstanding) {
		t.Fatalf("restart reset the outstanding challenge: %v", err)
	}
	// Restoring the attempt and ending it releases the outstanding mark
	// but not the slot.
	a, err := RestoreApproval(b2, ap, ap.state)
	if err != nil {
		t.Fatal(err)
	}
	if err := a.Abort(); err != nil {
		t.Fatal(err)
	}
	if b2.Remaining() != 2 {
		t.Fatalf("remaining = %d", b2.Remaining())
	}
}

func TestBudgetClockMovingBack(t *testing.T) {
	bp := &memPersister{}
	clock := &fakeClock{t: time.Date(2026, 10, 22, 12, 0, 0, 0, time.UTC)}
	b, _ := LoadApprovalBudget(bp, clock.now, nil)
	acct := fixedAccount(t, 1)
	for i := range 3 {
		a, _ := StartApproval(b, &memPersister{}, fixedID(byte(0x80+i)), acct.Pin(), fixedID(0x40))
		_ = a.Abort()
	}
	clock.advance(-24 * time.Hour)
	if _, err := StartApproval(b, &memPersister{}, fixedID(0x84), acct.Pin(), fixedID(0x40)); !errors.Is(err, ErrBudgetExhausted) {
		t.Fatalf("clock moved back released the budget: %v", err)
	}
}

func TestBudgetPersistFailureReservesNothing(t *testing.T) {
	bp := &memPersister{fail: true}
	clock := &fakeClock{t: time.Date(2026, 10, 22, 12, 0, 0, 0, time.UTC)}
	b, _ := LoadApprovalBudget(bp, clock.now, nil)
	acct := fixedAccount(t, 1)
	if _, err := StartApproval(b, &memPersister{}, fixedID(0x80), acct.Pin(), fixedID(0x40)); !errors.Is(err, errPersist) {
		t.Fatalf("reserve without persisting: %v", err)
	}
	bp.fail = false
	if b.Remaining() != 3 {
		t.Fatalf("a failed reservation counted: %d", b.Remaining())
	}
}

func TestApprovalRestartMidway(t *testing.T) {
	r := newEnrollRig(t)
	r.runToOpen(t, fixedID(0x80))
	if err := r.d.ConfirmSAS(); err != nil {
		t.Fatal(err)
	}
	sas1, _, _ := r.a.SAS()
	a2, err := RestoreApproval(r.budget, r.ap, r.ap.state)
	if err != nil {
		t.Fatal(err)
	}
	sas2, _, err := a2.SAS()
	if err != nil || sas1 != sas2 {
		t.Fatalf("SAS changed across restart: %v", err)
	}
	if err := a2.Confirm(true); err != nil {
		t.Fatal(err)
	}
	if _, err := a2.Prepare(r.acct, fixedID(0x41), 0); err != nil {
		t.Fatal(err)
	}
	a3, _ := RestoreApproval(r.budget, r.ap, r.ap.state)
	env, err := a3.Deliver(0, Hash{})
	if err != nil {
		t.Fatal(err)
	}
	// Delivering again after a restart returns the same envelope.
	a4, _ := RestoreApproval(r.budget, r.ap, r.ap.state)
	env2, err := a4.Deliver(0, Hash{})
	if err != nil || !bytes.Equal(env.CT, env2.CT) {
		t.Fatal("delivery not stable across restart")
	}
	d2, err := RestoreDeviceEnrollmentWithClock(r.dp, r.clock.now, r.dp.state)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := d2.HandleDelivery(env); err != nil {
		t.Fatal(err)
	}
}

func TestPrepareRequiresPinnedAccount(t *testing.T) {
	r := newEnrollRig(t)
	r.runToOpen(t, fixedID(0x80))
	_ = r.a.Confirm(true)
	if _, err := r.a.Prepare(fixedAccount(t, 2), fixedID(0x41), 0); !errors.Is(err, ErrAccountMismatch) {
		t.Fatalf("prepare with another akv's keys: %v", err)
	}
}
