package crypto

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"maps"
	"math/big"
	"slices"
	"strings"
	"testing"

	"github.com/dalyem/hopkey/internal/canonjson"
)

// Byte strings computed by hand from the §3 definitions.
func TestLPU32U64HandComputed(t *testing.T) {
	if got, want := LP(nil), []byte{0, 0, 0, 0}; !bytes.Equal(got, want) {
		t.Errorf("lp(empty) = %x, want %x", got, want)
	}
	if got, want := LP([]byte("ab")), []byte{0, 0, 0, 2, 'a', 'b'}; !bytes.Equal(got, want) {
		t.Errorf("lp(ab) = %x, want %x", got, want)
	}
	long := bytes.Repeat([]byte{0xee}, 0x0102)
	if got := LP(long); !bytes.Equal(got[:4], []byte{0, 0, 1, 2}) || !bytes.Equal(got[4:], long) {
		t.Errorf("lp(258 bytes) prefix = %x", got[:4])
	}
	if got, want := U32(1), []byte{0, 0, 0, 1}; !bytes.Equal(got, want) {
		t.Errorf("u32(1) = %x", got)
	}
	if got, want := U32(4294967295), []byte{0xff, 0xff, 0xff, 0xff}; !bytes.Equal(got, want) {
		t.Errorf("u32(max) = %x", got)
	}
	if got, want := U32(0x01020304), []byte{1, 2, 3, 4}; !bytes.Equal(got, want) {
		t.Errorf("u32(0x01020304) = %x", got)
	}
	if got, want := U64(1), []byte{0, 0, 0, 0, 0, 0, 0, 1}; !bytes.Equal(got, want) {
		t.Errorf("u64(1) = %x", got)
	}
	if got, want := U64(0x0102030405060708), []byte{1, 2, 3, 4, 5, 6, 7, 8}; !bytes.Equal(got, want) {
		t.Errorf("u64 = %x", got)
	}
	if got, want := U64(18446744073709551615), bytes.Repeat([]byte{0xff}, 8); !bytes.Equal(got, want) {
		t.Errorf("u64(max) = %x", got)
	}
}

func TestDAndFingerprintsHandComputed(t *testing.T) {
	obj := map[string]any{"b": 1, "a": "x"}
	// lp("hopkey/v1/test") || lp(`{"a":"x","b":1}`)
	label := "hopkey/v1/test"
	jcs := `{"a":"x","b":1}`
	msg := append([]byte{0, 0, 0, byte(len(label))}, label...)
	msg = append(msg, 0, 0, 0, byte(len(jcs)))
	msg = append(msg, jcs...)
	want := sha256.Sum256(msg)
	got, err := D(label, obj)
	if err != nil {
		t.Fatal(err)
	}
	if got != Hash(want) {
		t.Fatalf("D = %v, want %x", got, want)
	}

	pk := []byte{1, 2, 3}
	kemMsg := append([]byte{0, 0, 0, 16}, "hopkey/v1/kem-pk"...)
	kemMsg = append(kemMsg, 0, 0, 0, 3, 1, 2, 3)
	if FpKEM(pk) != Hash(sha256.Sum256(kemMsg)) {
		t.Error("fp_kem mismatch")
	}
	sigMsg := append([]byte{0, 0, 0, 16}, "hopkey/v1/sig-pk"...)
	sigMsg = append(sigMsg, 0, 0, 0, 3, 1, 2, 3)
	if FpSig(pk) != Hash(sha256.Sum256(sigMsg)) {
		t.Error("fp_sig mismatch")
	}
	if FpSig(pk) == FpKEM(pk) {
		t.Error("fingerprints are not domain separated")
	}
}

func TestLabelsMustBeV1(t *testing.T) {
	if _, err := D("hopkey/v2/x", 1); err == nil {
		t.Error("non-v1 label accepted")
	}
	if _, err := D("hopkey/v1/", 1); err == nil {
		t.Error("empty label suffix accepted")
	}
}

func TestSignVerify(t *testing.T) {
	key := fixedSig("signer")
	pub := key.Public().(ed25519.PublicKey)
	obj := map[string]any{"v": 1}
	sig, err := Sign(key, LabelDeviceCert, obj)
	if err != nil {
		t.Fatal(err)
	}
	if err := Verify(pub, LabelDeviceCert, obj, sig); err != nil {
		t.Fatalf("valid signature rejected: %v", err)
	}
	// The signed message is lp(label) || lp(JCS(obj)).
	other := fixedSig("other").Public().(ed25519.PublicKey)
	for name, err := range map[string]error{
		"wrong label":  Verify(pub, LabelGrantBundle, obj, sig),
		"wrong object": Verify(pub, LabelDeviceCert, map[string]any{"v": 2}, sig),
		"wrong key":    Verify(other, LabelDeviceCert, obj, sig),
		"short sig":    Verify(pub, LabelDeviceCert, obj, sig[:63]),
	} {
		if !errors.Is(err, ErrBadSignature) {
			t.Errorf("%s: got %v", name, err)
		}
	}
}

// Malformed and non-canonical Ed25519 signatures are rejected. S + L is
// the classic malleated signature: it satisfies the verification equation,
// so only the canonical-S check (RFC 8032 §5.1.7) refuses it.
func TestVerifyRejectsMalformedSignatures(t *testing.T) {
	key := fixedSig("signer")
	pub := key.Public().(ed25519.PublicKey)
	obj := map[string]any{"v": 1}
	sig, err := Sign(key, LabelDeviceCert, obj)
	if err != nil {
		t.Fatal(err)
	}
	// L = 2^252 + 27742317777372353535851937790883648493, little-endian.
	l := new(big.Int).Add(new(big.Int).Lsh(big.NewInt(1), 252), mustBig("27742317777372353535851937790883648493"))
	le := func(b []byte) *big.Int {
		r := bytes.Clone(b)
		slices.Reverse(r)
		return new(big.Int).SetBytes(r)
	}
	toLE := func(n *big.Int) []byte {
		b := n.FillBytes(make([]byte, 32))
		slices.Reverse(b)
		return b
	}
	sPlusL := bytes.Clone(sig)
	copy(sPlusL[32:], toLE(new(big.Int).Add(le(sig[32:]), l)))
	highS := bytes.Clone(sig)
	highS[63] |= 0xe0
	// R replaced by a non-canonical encoding: y = p + 1 is the identity
	// written with y >= p.
	p := new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 255), big.NewInt(19))
	nonCanonR := bytes.Clone(sig)
	copy(nonCanonR[:32], toLE(new(big.Int).Add(p, big.NewInt(1))))
	identityR := bytes.Clone(sig)
	copy(identityR[:32], toLE(big.NewInt(1)))
	for name, bad := range map[string][]byte{
		"S + L":           sPlusL,
		"S top bits set":  highS,
		"non-canonical R": nonCanonR,
		"identity R":      identityR,
		"all zero":        make([]byte, 64),
		"all 0xff":        bytes.Repeat([]byte{0xff}, 64),
		"long":            append(bytes.Clone(sig), 0),
		"short":           sig[:63],
		"empty":           nil,
		"flipped bit":     func() []byte { b := bytes.Clone(sig); b[10] ^= 1; return b }(),
	} {
		if err := Verify(pub, LabelDeviceCert, obj, bad); !errors.Is(err, ErrBadSignature) {
			t.Errorf("%s: %v", name, err)
		}
	}
	if err := Verify(pub, LabelDeviceCert, obj, sig); err != nil {
		t.Fatalf("the original no longer verifies: %v", err)
	}
	// A malformed public key fails as well.
	for name, k := range map[string][]byte{"short key": pub[:31], "long key": append(bytes.Clone(pub), 0)} {
		if err := Verify(k, LabelDeviceCert, obj, sig); !errors.Is(err, ErrBadSignature) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func mustBig(s string) *big.Int {
	n, ok := new(big.Int).SetString(s, 10)
	if !ok {
		panic(s)
	}
	return n
}

// §3: input need not be canonical (whitespace, escapes and member order
// may vary), but every digest and signature is over the JCS re-encoding of
// the decoded value. A certificate received in non-canonical form has the
// same digest and verifies under the same signature.
func TestNonCanonicalInputSameDigestAndSignature(t *testing.T) {
	acct := fixedAccount(t, 1)
	c := Cert{V: 1, AccountID: acct.AccountID, AKV: 1, DeviceID: fixedID(0x40), Name: "laptop é",
		KEMFp: Hash{1, 2, 3}, SigFp: Hash{4, 5, 6}, EnrollTranscript: SomeHash(Hash{}), IssuedAt: 1792670400}
	sig, err := SignCert(acct, &c)
	if err != nil {
		t.Fatal(err)
	}
	canon, err := canonjson.Marshal(&c)
	if err != nil {
		t.Fatal(err)
	}
	want, _ := c.Digest()

	// The same value: members reversed, whitespace everywhere, and
	// characters written as escapes (\u0061 for "a", \u00e9 for "é",
	// \/ for "/").
	var members []string
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(canon, &obj); err != nil {
		t.Fatal(err)
	}
	keys := slices.Sorted(maps.Keys(obj))
	slices.Reverse(keys)
	esc := func(s string) string {
		return strings.ReplaceAll(strings.ReplaceAll(s, "a", `\u0061`), "é", `\u00e9`)
	}
	for _, k := range keys {
		members = append(members, "\n\t\""+esc(k)+"\" :\r\n "+esc(string(obj[k])))
	}
	noncanon := []byte("{ " + strings.Join(members, " ,") + "\n}\n")
	if bytes.Equal(noncanon, canon) {
		t.Fatal("test input is canonical")
	}
	var got Cert
	if err := canonjson.Unmarshal(noncanon, &got); err != nil {
		t.Fatalf("non-canonical certificate rejected: %v\n%s", err, noncanon)
	}
	if got != c {
		t.Fatal("non-canonical input decoded to a different value")
	}
	if d, _ := got.Digest(); !d.Equal(want) {
		t.Fatal("digest depends on the received bytes")
	}
	if err := VerifyCert(acct.Public().SigPK, &got, sig); err != nil {
		t.Fatalf("signature does not verify over the decoded value: %v", err)
	}
	if again, _ := SignCert(acct, &got); !bytes.Equal(again, sig) {
		t.Fatal("re-signing the decoded value gives another signature")
	}
	if re, _ := canonjson.Canonicalize(noncanon); !bytes.Equal(re, canon) {
		t.Fatalf("Canonicalize = %s", re)
	}
	// The digest is never over the received bytes.
	raw := sha256.Sum256(cat(lps(LabelDeviceCert), LP(noncanon)))
	if Hash(raw).Equal(want) {
		t.Fatal("digest computed over received bytes")
	}
}

func TestHashText(t *testing.T) {
	var h Hash
	good := strings.Repeat("ab", 32)
	if err := h.UnmarshalText([]byte(good)); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{"", strings.Repeat("AB", 32), strings.Repeat("ab", 31), strings.Repeat("zz", 32)} {
		if err := h.UnmarshalText([]byte(bad)); err == nil {
			t.Errorf("Hash accepted %q", bad)
		}
	}
	var o OptHash
	if err := o.UnmarshalText(nil); err != nil || !o.IsZero() {
		t.Errorf("OptHash rejected empty: %v", err)
	}
	if b, _ := o.MarshalText(); len(b) != 0 {
		t.Errorf("zero OptHash marshals as %q", b)
	}
	// Presence is separate from the digest: an all-zero digest is a present
	// h value (§3 allows it) and round-trips as 64 zeros, not as "".
	zeros := strings.Repeat("00", 32)
	if err := o.UnmarshalText([]byte(zeros)); err != nil || o.IsZero() {
		t.Fatalf("OptHash rejected the all-zero digest: %v", err)
	}
	if got, ok := o.Get(); !ok || got != (Hash{}) || !o.Equal(Hash{}) {
		t.Error("all-zero OptHash is not present with a zero digest")
	}
	if b, _ := o.MarshalText(); string(b) != zeros {
		t.Errorf("all-zero OptHash marshals as %q", b)
	}
	if (OptHash{}).Equal(Hash{}) {
		t.Error("absent OptHash equals the zero digest")
	}
	if b, _ := SomeHash(Hash{1}).MarshalText(); string(b) != "01"+strings.Repeat("00", 31) {
		t.Errorf("SomeHash marshals as %q", b)
	}
	for _, bad := range []string{strings.Repeat("AB", 32), strings.Repeat("ab", 31), " "} {
		if err := o.UnmarshalText([]byte(bad)); err == nil {
			t.Errorf("OptHash accepted %q", bad)
		}
	}
	// Through canonjson, inside a certificate.
	c := Cert{V: 1, AccountID: fixedID(1), DeviceID: fixedID(2), Name: "n", EnrollTranscript: SomeHash(Hash{})}
	j, err := canonjson.Marshal(&c)
	if err != nil || !strings.Contains(string(j), `"enroll_transcript":"`+zeros+`"`) {
		t.Fatalf("cert with all-zero enroll_transcript: %s, %v", j, err)
	}
	var back Cert
	if err := canonjson.Unmarshal(j, &back); err != nil || back != c {
		t.Fatalf("round trip: %v", err)
	}
	c.EnrollTranscript = OptHash{}
	j, _ = canonjson.Marshal(&c)
	if !strings.Contains(string(j), `"enroll_transcript":""`) {
		t.Fatalf("absent enroll_transcript: %s", j)
	}
	if b, _ := (Hash{}).MarshalText(); len(b) != 64 {
		t.Error("zero Hash does not marshal as 64 hex characters")
	}
}

func TestEnvelopeSchemas(t *testing.T) {
	good := `{"ct":"AAAAAAAAAAAAAAAAAAAAAA","nonce":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","suite":1,"v":1}`
	if _, err := ParseAEADEnvelope([]byte(good)); err != nil {
		t.Fatalf("valid envelope rejected: %v", err)
	}
	for name, in := range map[string]string{
		"unknown v":        strings.Replace(good, `"v":1`, `"v":2`, 1),
		"unknown suite":    strings.Replace(good, `"suite":1`, `"suite":2`, 1),
		"unknown member":   strings.Replace(good, `"v":1`, `"v":1,"x":1`, 1),
		"duplicate member": strings.Replace(good, `"v":1`, `"v":1,"v":1`, 1),
		"missing member":   strings.Replace(good, `"suite":1,`, ``, 1),
		"short nonce":      strings.Replace(good, `"nonce":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"`, `"nonce":"AAAA"`, 1),
		"trailing data":    good + "{}",
	} {
		if _, err := ParseAEADEnvelope([]byte(in)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	hgood := `{"ct":"AA","enc":"AA","suite":1,"v":1}`
	if _, err := ParseHPKEEnvelope([]byte(hgood)); err != nil {
		t.Fatalf("valid HPKE envelope rejected: %v", err)
	}
	for name, in := range map[string]string{
		"unknown v":        strings.Replace(hgood, `"v":1`, `"v":0`, 1),
		"unknown suite":    strings.Replace(hgood, `"suite":1`, `"suite":7`, 1),
		"unknown member":   strings.Replace(hgood, `"v":1`, `"v":1,"aad":"AA"`, 1),
		"duplicate member": strings.Replace(hgood, `"ct":"AA"`, `"ct":"AA","ct":"AA"`, 1),
	} {
		if _, err := ParseHPKEEnvelope([]byte(in)); err == nil {
			t.Errorf("HPKE %s: accepted", name)
		}
	}
}

func TestEnvelopeDigestIsSHA256OfJCS(t *testing.T) {
	e := AEADEnvelope{V: 1, Suite: 1, Nonce: make([]byte, 24), CT: []byte{1}}
	j, err := canonjson.Marshal(e)
	if err != nil {
		t.Fatal(err)
	}
	if string(j) != `{"ct":"AQ","nonce":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","suite":1,"v":1}` {
		t.Fatalf("JCS = %s", j)
	}
	d, err := e.Digest()
	if err != nil || d != Hash(sha256.Sum256(j)) {
		t.Fatalf("digest mismatch: %v", err)
	}
}

func TestCheckSecretHash(t *testing.T) {
	secret := []byte("secret")
	stored := SHA256(secret)
	if !CheckSecretHash(stored, secret) {
		t.Error("matching secret rejected")
	}
	if CheckSecretHash(stored, []byte("secreu")) {
		t.Error("wrong secret accepted")
	}
	// The hash itself is never a credential.
	if CheckSecretHash(stored, stored[:]) {
		t.Error("stored hash accepted as the secret")
	}
}
