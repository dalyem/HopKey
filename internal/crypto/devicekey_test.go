package crypto

import (
	"encoding/hex"
	"testing"

	"golang.org/x/crypto/argon2"
)

// Known answer for the rev 14 device key file (§11). The password and salt
// are the §4.1 vector's (testdata/kdf.json), so the Argon2id output is its
// pw_key; the HKDF step and the AAD were computed separately with Python's
// hmac and hashlib.
func TestDevicePassphraseKeyVector(t *testing.T) {
	pw := []byte("correct horse battery staple")
	salt := fixedBytes("vector salt", 16)
	dev := fixedID(0x20)
	const (
		wantPwKey = "69179d01c6bb55ad92b2a02b8173c63bc5fa97afa62afae27205c8bab763fc85"
		wantKey   = "a0e3409340ed03f569748c1c3435d48d70799d277dff8bee178873fb16e95594"
		wantAAD   = "00000019686f706b65792f76312f6465766963652d6b65792d66696c6500000010202122232425262728292a2b2c2d2e2f"
	)
	if got := hex.EncodeToString(argon2.IDKey(pw, salt, 3, 65536, 4, 32)); got != wantPwKey {
		t.Fatalf("argon2 = %s, the §4.1 vector moved", got)
	}
	k, err := DevicePassphraseKey(pw, salt, dev)
	if err != nil {
		t.Fatal(err)
	}
	if got := hex.EncodeToString(k[:]); got != wantKey {
		t.Errorf("pk = %s, want %s", got, wantKey)
	}
	if got := hex.EncodeToString(DeviceKeyFileAAD(dev)); got != wantAAD {
		t.Errorf("aad = %s, want %s", got, wantAAD)
	}
	// NFKC applies first: "staﬀ" and "staff" give the same key.
	a, err := DevicePassphraseKey([]byte("correct horse battery staﬀ"), salt, dev)
	if err != nil {
		t.Fatal(err)
	}
	b, err := DevicePassphraseKey([]byte("correct horse battery staff"), salt, dev)
	if err != nil || *a != *b {
		t.Errorf("NFKC is not applied before Argon2: %v", err)
	}
	// The device ID is the HKDF salt: another device gets another key.
	other, err := DevicePassphraseKey(pw, salt, fixedID(0x30))
	if err != nil || *other == *k {
		t.Errorf("the key does not depend on the device ID: %v", err)
	}
}

func TestDevicePassphraseKeyRejects(t *testing.T) {
	salt := fixedBytes("vector salt", 16)
	for name, tc := range map[string]struct {
		pw   string
		salt []byte
	}{
		"short passphrase": {"seven77", salt},
		"not utf-8":        {"passphrase\xff\xfe", salt},
		"unassigned":       {"passphrase \U000E0080", salt},
		"short salt":       {"a fine passphrase", salt[:15]},
	} {
		if _, err := DevicePassphraseKey([]byte(tc.pw), tc.salt, fixedID(0x20)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if _, err := DevicePassphraseKey([]byte("a fine passphrase"), salt, [16]byte{}); err == nil {
		t.Error("zero device ID: accepted")
	}
}
