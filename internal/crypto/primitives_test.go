package crypto

import (
	"bytes"
	"encoding/hex"
	"errors"
	"testing"

	"golang.org/x/crypto/argon2"
)

// RFC 5869 Appendix A.1 and A.3 (HKDF-SHA256).
func TestHKDFRFC5869(t *testing.T) {
	ikm := bytes.Repeat([]byte{0x0b}, 22)
	for _, tc := range []struct {
		name, salt, info, okm string
	}{
		{
			"A.1", "000102030405060708090a0b0c", "f0f1f2f3f4f5f6f7f8f9",
			"3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865",
		},
		{
			"A.3", "", "",
			"8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8",
		},
	} {
		got, err := hkdfKey(ikm, mustHex(t, tc.salt), mustHex(t, tc.info), 42)
		if err != nil {
			t.Fatal(err)
		}
		if hex.EncodeToString(got) != tc.okm {
			t.Errorf("%s: OKM = %x", tc.name, got)
		}
	}
	// A.1's PRK through the Expand-only path, as used for authKey/encKey.
	prk := mustHex(t, "077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5")
	got, err := hkdfExpand(prk, mustHex(t, "f0f1f2f3f4f5f6f7f8f9"), 42)
	if err != nil {
		t.Fatal(err)
	}
	if hex.EncodeToString(got) != "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865" {
		t.Errorf("Expand(A.1 PRK) = %x", got)
	}
}

// Argon2id v0x13 known answers.
//
// The x/crypto rows are copied from golang.org/x/crypto@v0.58.0
// argon2/argon2_test.go, var testVectors (lines 140-242): every
// mode: argon2id row, run there through deriveKey(argon2id, "password",
// "somesalt", nil, nil, ...), which is what IDKey calls. The first row is
// the entry at lines 155-156.
//
// The t=2, m=2^16, p=1 row is the Argon2id v0x13 case in phc-winner-argon2
// src/test.c. It is not in x/crypto's tests and its source could not be
// checked offline; it is kept because it is the only row at the 64 MiB
// memory size kdf_version 1 uses. RFC 9106 §5.3's vector needs a secret and
// associated data, which IDKey does not take (x/crypto checks it as
// testArgon2id, through the unexported deriveKey).
func TestArgon2idReferenceVector(t *testing.T) {
	for _, tc := range []struct {
		time, memory uint32
		threads      uint8
		hash         string
	}{
		{1, 64, 1, "655ad15eac652dc59f7170a7332bf49b8469be1fdb9c28bb"},
		{2, 64, 1, "068d62b26455936aa6ebe60060b0a65870dbfa3ddf8d41f7"},
		{2, 64, 2, "350ac37222f436ccb5c0972f1ebd3bf6b958bf2071841362"},
		{3, 256, 2, "4668d30ac4187e6878eedeacf0fd83c5a0a30db2cc16ef0b"},
		{4, 4096, 4, "145db9733a9f4ee43edf33c509be96b934d505a4efb33c5a"},
		{4, 1024, 8, "8dafa8e004f8ea96bf7c0f93eecf67a6047476143d15577f"},
		{2, 64, 3, "4a15b31aec7c2590b87d1f520be7d96f56658172deaa3079"},
		{3, 1024, 6, "1640b932f4b60e272f5d2207b9a9c626ffa1bd88d2349016"},
		{2, 1 << 16, 1, "09316115d5cf24ed5a15a31a3ba326e5cf32edc24702987c02b6566f61913cf7"}, // phc-winner-argon2
	} {
		got := argon2.IDKey([]byte("password"), []byte("somesalt"), tc.time, tc.memory, tc.threads, uint32(len(tc.hash)/2))
		if hex.EncodeToString(got) != tc.hash {
			t.Errorf("Argon2id t=%d m=%d p=%d = %x", tc.time, tc.memory, tc.threads, got)
		}
	}
}

// Buffer ownership in Go 1.27.3's crypto/hpke, as documented above
// DeriveKEMKey. NewPrivateKey and DeriveKeyPair do not retain their input,
// and Bytes() returns the stored seed itself. If this test starts failing,
// a Go release changed the behavior; the copies in DeriveKEMKey,
// ParseKEMPrivateKey and kemPrivateBytes keep our zeroing safe either way.
func TestHPKEBufferOwnership(t *testing.T) {
	kem := hpkeKEM()
	seed := fixedBytes("ownership", 32)
	in := bytes.Clone(seed)
	k, err := kem.NewPrivateKey(in)
	if err != nil {
		t.Fatal(err)
	}
	pub := k.PublicKey().Bytes()
	clear(in)
	if b, _ := k.Bytes(); !bytes.Equal(b, seed) || !bytes.Equal(k.PublicKey().Bytes(), pub) {
		t.Fatal("crypto/hpke NewPrivateKey retains its input slice")
	}
	ikm := bytes.Clone(seed)
	dk, err := kem.DeriveKeyPair(ikm)
	if err != nil {
		t.Fatal(err)
	}
	dpub := dk.PublicKey().Bytes()
	clear(ikm)
	if !bytes.Equal(dk.PublicKey().Bytes(), dpub) {
		t.Fatal("crypto/hpke DeriveKeyPair retains its input slice")
	}
	b1, _ := k.Bytes()
	b2, _ := k.Bytes()
	if &b1[0] != &b2[0] {
		t.Log("crypto/hpke Bytes() now returns a copy; kemPrivateBytes still copies")
	}

	// Our wrappers: clearing what we passed in or got back never touches
	// the key.
	in = bytes.Clone(seed)
	pk, err := ParseKEMPrivateKey(in)
	if err != nil {
		t.Fatal(err)
	}
	clear(in)
	out, err := kemPrivateBytes(pk)
	if err != nil {
		t.Fatal(err)
	}
	clear(out)
	if b, _ := pk.Bytes(); !bytes.Equal(b, seed) {
		t.Fatal("clearing our buffers destroyed the key")
	}
	ikm = bytes.Clone(seed)
	dk2, err := DeriveKEMKey(ikm)
	if err != nil {
		t.Fatal(err)
	}
	clear(ikm)
	if !bytes.Equal(dk2.PublicKey().Bytes(), dpub) {
		t.Fatal("clearing ikm changed the derived key")
	}
	// MarshalAcctPriv clears its copy of the KEM seed; the account key is
	// unaffected.
	acct := fixedAccount(t, 1)
	before, _ := acct.KEM.Bytes()
	before = bytes.Clone(before)
	ap, err := acct.MarshalAcctPriv()
	if err != nil {
		t.Fatal(err)
	}
	clear(ap)
	if after, _ := acct.KEM.Bytes(); !bytes.Equal(after, before) {
		t.Fatal("MarshalAcctPriv cleared the account KEM seed")
	}
}

func TestHPKESuite(t *testing.T) {
	kem, kdf, aead := HPKESuiteIDs()
	// draft-ietf-hpke-pq MLKEM768-X25519 = 0x647a; RFC 9180 HKDF-SHA256 =
	// 0x0001, AES-256-GCM = 0x0002.
	if kem != 0x647a || kdf != 0x0001 || aead != 0x0002 {
		t.Fatalf("suite = %#04x/%#04x/%#04x", kem, kdf, aead)
	}
}

func TestDeriveKeyPairDeterministic(t *testing.T) {
	ikm := fixedBytes("ikm", 32)
	a, err := DeriveKEMKey(ikm)
	if err != nil {
		t.Fatal(err)
	}
	b, err := DeriveKEMKey(bytes.Clone(ikm))
	if err != nil {
		t.Fatal(err)
	}
	ab, _ := a.Bytes()
	bb, _ := b.Bytes()
	if !bytes.Equal(ab, bb) || !bytes.Equal(a.PublicKey().Bytes(), b.PublicKey().Bytes()) {
		t.Fatal("DeriveKeyPair is not deterministic")
	}
	c, err := DeriveKEMKey(fixedBytes("other ikm", 32))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(a.PublicKey().Bytes(), c.PublicKey().Bytes()) {
		t.Fatal("different ikm gave the same key")
	}
	// Private keys round-trip through Bytes().
	back, err := ParseKEMPrivateKey(ab)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(back.PublicKey().Bytes(), a.PublicKey().Bytes()) {
		t.Fatal("PrivateKey.Bytes() does not round-trip")
	}
}

func TestHPKERoundTrip(t *testing.T) {
	sk := fixedKEM(t, "recipient")
	pk := sk.PublicKey().Bytes()
	info, aad, pt := []byte("info"), []byte("aad"), []byte("plaintext")
	e, err := SealHPKE(pk, info, aad, pt)
	if err != nil {
		t.Fatal(err)
	}
	if e.V != 1 || e.Suite != 1 {
		t.Fatalf("envelope header %d/%d", e.V, e.Suite)
	}
	got, err := OpenHPKE(sk, e, info, aad)
	if err != nil || !bytes.Equal(got, pt) {
		t.Fatalf("open: %q, %v", got, err)
	}
	other := fixedKEM(t, "someone else")
	for name, open := range map[string]func() ([]byte, error){
		"wrong info": func() ([]byte, error) { return OpenHPKE(sk, e, []byte("infx"), aad) },
		"wrong aad":  func() ([]byte, error) { return OpenHPKE(sk, e, info, []byte("aax")) },
		"wrong key":  func() ([]byte, error) { return OpenHPKE(other, e, info, aad) },
		"bad ct": func() ([]byte, error) {
			b := e
			b.CT = bytes.Clone(e.CT)
			b.CT[0] ^= 1
			return OpenHPKE(sk, b, info, aad)
		},
		"bad enc": func() ([]byte, error) {
			b := e
			b.Enc = bytes.Clone(e.Enc)
			b.Enc[0] ^= 1
			return OpenHPKE(sk, b, info, aad)
		},
		"v=2":     func() ([]byte, error) { b := e; b.V = 2; return OpenHPKE(sk, b, info, aad) },
		"suite=2": func() ([]byte, error) { b := e; b.Suite = 2; return OpenHPKE(sk, b, info, aad) },
	} {
		if _, err := open(); err == nil {
			t.Errorf("%s: opened", name)
		}
	}
	if _, err := OpenHPKE(sk, HPKEEnvelope{V: 2, Suite: 1}, info, aad); !errors.Is(err, ErrUnsupported) {
		t.Errorf("unknown v: %v", err)
	}
}

func TestAEADRoundTrip(t *testing.T) {
	key := SymKey(fixedBytes("key", 32))
	e, err := SealAEAD(&key, []byte("pt"), []byte("aad"))
	if err != nil {
		t.Fatal(err)
	}
	if len(e.Nonce) != 24 {
		t.Fatalf("nonce is %d bytes", len(e.Nonce))
	}
	got, err := OpenAEAD(&key, e, []byte("aad"))
	if err != nil || string(got) != "pt" {
		t.Fatalf("open: %q, %v", got, err)
	}
	if _, err := OpenAEAD(&key, e, []byte("aax")); !errors.Is(err, ErrDecrypt) {
		t.Errorf("wrong aad: %v", err)
	}
	other := SymKey(fixedBytes("other", 32))
	if _, err := OpenAEAD(&other, e, []byte("aad")); !errors.Is(err, ErrDecrypt) {
		t.Errorf("wrong key: %v", err)
	}
	b := e
	b.Suite = 2
	if _, err := OpenAEAD(&key, b, []byte("aad")); !errors.Is(err, ErrUnsupported) {
		t.Errorf("unknown suite: %v", err)
	}
	e2, _ := SealAEAD(&key, []byte("pt"), []byte("aad"))
	if bytes.Equal(e.Nonce, e2.Nonce) {
		t.Error("nonce reused")
	}
}
