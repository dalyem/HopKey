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

// Argon2id v0x13 from the reference implementation's test suite
// (phc-winner-argon2 src/test.c: t=2, m=2^16 KiB, p=1, "password",
// "somesalt"). RFC 9106 §5.3's Argon2id vector needs a secret and
// associated data, which x/crypto's IDKey does not take, so it cannot be
// replayed here. The pinned kdf_version 1 tuple is covered by the KAT.
func TestArgon2idReferenceVector(t *testing.T) {
	got := argon2.IDKey([]byte("password"), []byte("somesalt"), 2, 1<<16, 1, 32)
	if hex.EncodeToString(got) != "09316115d5cf24ed5a15a31a3ba326e5cf32edc24702987c02b6566f61913cf7" {
		t.Fatalf("Argon2id = %x", got)
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
