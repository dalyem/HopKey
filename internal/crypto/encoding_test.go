package crypto

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"errors"
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
	if err := o.UnmarshalText([]byte(strings.Repeat("00", 32))); err == nil {
		t.Error("OptHash accepted the reserved all-zero digest")
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
