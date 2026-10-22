package crypto

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	"golang.org/x/crypto/argon2"
)

// The NFKC tables are pinned so a change of Unicode version is noticed.
// See the SPEC GAP on UnicodeVersion: the spec asks for 15.0.0, which x/text
// does not provide on Go 1.27.
func TestUnicodeVersionPinned(t *testing.T) {
	if UnicodeVersion != "17.0.0" {
		t.Fatalf("NFKC tables are Unicode %s; the pinned value is 17.0.0", UnicodeVersion)
	}
}

func TestNormalizePassword(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{"\ufb01ancy-pass", "fiancy-pass"}, // ligature fi decomposes under NFKC
		{"ＰＡＳＳword", "PASSword"},           // fullwidth letters
		{"café au lait", "café au lait"},  // composition
		{"  spaces  ", "  spaces  "},       // no trimming
	} {
		got, err := NormalizePassword([]byte(tc.in))
		if err != nil || string(got) != tc.want {
			t.Errorf("NFKC(%q) = %q, %v; want %q", tc.in, got, err, tc.want)
		}
	}
}

func TestPasswordBounds(t *testing.T) {
	ok := func(s string) bool { _, err := NormalizePassword([]byte(s)); return err == nil }
	if ok(strings.Repeat("a", 7)) || !ok(strings.Repeat("a", 8)) {
		t.Error("lower bound is not 8 bytes")
	}
	if !ok(strings.Repeat("a", 1024)) || ok(strings.Repeat("a", 1025)) {
		t.Error("upper bound is not 1024 bytes")
	}
	// The bound applies after normalization: 4 ligatures (12 bytes in) become
	// 8 bytes out and pass; U+FDFA is 3 bytes in and 33 bytes out, so 32 of
	// them (96 bytes in) exceed 1024.
	if !ok(strings.Repeat("ﬁ", 4)) {
		t.Error("bound checked before normalization (short side)")
	}
	if ok(strings.Repeat("ﷺ", 32)) {
		t.Error("bound checked before normalization (long side)")
	}
	if ok("\xff\xfe-not-utf8-at-all") {
		t.Error("invalid UTF-8 accepted")
	}
}

func TestKDFParamsOffProfile(t *testing.T) {
	if err := CheckKDFParams(KDFv1); err != nil {
		t.Fatal(err)
	}
	sk := SecretKey{Hint: "ABCDEF"}
	salt := make([]byte, SaltSize)
	acct := fixedID(1)
	for name, mutate := range map[string]func(*KDFParams){
		"version 2":     func(p *KDFParams) { p.Version = 2 },
		"version 0":     func(p *KDFParams) { p.Version = 0 },
		"t=2":           func(p *KDFParams) { p.Time = 2 },
		"t=4":           func(p *KDFParams) { p.Time = 4 },
		"m=32768":       func(p *KDFParams) { p.MemoryKiB = 32768 },
		"m=huge":        func(p *KDFParams) { p.MemoryKiB = 1 << 31 },
		"p=1":           func(p *KDFParams) { p.Threads = 1 },
		"len=64":        func(p *KDFParams) { p.KeyLen = 64 },
		"len=16":        func(p *KDFParams) { p.KeyLen = 16 },
		"everything 0s": func(p *KDFParams) { *p = KDFParams{} },
	} {
		p := KDFv1
		mutate(&p)
		// An off-profile tuple fails before Argon2 runs, so a huge m costs
		// nothing here.
		if _, err := DeriveLoginKeys([]byte("password1"), salt, &sk, acct, p); !errors.Is(err, ErrKDFParams) {
			t.Errorf("%s: got %v", name, err)
		}
	}
	if _, err := DeriveLoginKeys([]byte("password1"), make([]byte, 15), &sk, acct, KDFv1); err == nil {
		t.Error("15-byte salt accepted")
	}
	bad := sk
	bad.SK17[0] = 0x04 // a bit above the 130-bit value
	if _, err := DeriveLoginKeys([]byte("password1"), salt, &bad, acct, KDFv1); err == nil {
		t.Error("SK17 with nonzero top bits accepted")
	}
}

// DeriveLoginKeys composes Argon2id and the HKDF steps exactly as §4.1
// writes them; this recomputes the chain from the primitives.
func TestDeriveLoginKeysComposition(t *testing.T) {
	pw := []byte("correct horse battery")
	salt := fixedBytes("salt", 16)
	sk := SecretKey{Hint: "ABCDEF"}
	copy(sk.SK17[:], fixedBytes("sk", 17))
	sk.SK17[0] &= 0x03
	acct := fixedID(0x20)
	got, err := DeriveLoginKeys(pw, salt, &sk, acct, KDFv1)
	if err != nil {
		t.Fatal(err)
	}
	if string(pw) != "correct horse battery" {
		t.Fatal("DeriveLoginKeys modified the caller's password buffer")
	}

	pwKey := argon2.IDKey(pw, salt, 3, 65536, 4, 32)
	skKey, _ := hkdfKey(sk.SK17[:], acct[:], LP([]byte("hopkey/v1/secret-key")), 32)
	info := append(LP([]byte("hopkey/v1/muk")), 0, 0, 0, 1)
	muk, _ := hkdfKey(append(bytes.Clone(pwKey), skKey...), acct[:], info, 32)
	auth, _ := hkdfExpand(muk, LP([]byte("hopkey/v1/auth")), 32)
	enc, _ := hkdfExpand(muk, LP([]byte("hopkey/v1/enc")), 32)
	if !bytes.Equal(got.AuthKey[:], auth) || !bytes.Equal(got.EncKey[:], enc) {
		t.Fatal("derivation does not follow §4.1")
	}
	if bytes.Equal(auth, enc) {
		t.Fatal("authKey equals encKey")
	}

	// Each input matters.
	other, err := DeriveLoginKeys(pw, salt, &sk, fixedID(0x21), KDFv1)
	if err != nil || other.AuthKey == got.AuthKey {
		t.Error("account ID does not affect the keys")
	}
	sk2 := sk
	sk2.SK17[16] ^= 1
	other, err = DeriveLoginKeys(pw, salt, &sk2, acct, KDFv1)
	if err != nil || other.AuthKey == got.AuthKey {
		t.Error("Secret Key does not affect the keys")
	}
	// The hint is never key material.
	sk3 := sk
	sk3.Hint = "ZZZZZZ"
	other, err = DeriveLoginKeys(pw, salt, &sk3, acct, KDFv1)
	if err != nil || other.AuthKey != got.AuthKey {
		t.Error("hint affected the keys")
	}
}
