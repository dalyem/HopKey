package crypto

import (
	"crypto/ed25519"
	"crypto/sha256"
	"errors"
	"testing"

	"github.com/dalyem/hopkey/internal/model"
)

func seqBytes(start byte, n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = start + byte(i)
	}
	return b
}

func seqID(start byte) model.ID {
	var id model.ID
	copy(id[:], seqBytes(start, len(id)))
	return id
}

func fixedAuthObjects(t *testing.T) (ed25519.PrivateKey, *AccountKeys, *DeviceAuth, *SignupPoP) {
	t.Helper()
	dev := ed25519.NewKeyFromSeed(seqBytes(0x01, 32))
	kem, err := DeriveKEMKey(seqBytes(0x61, 32))
	if err != nil {
		t.Fatal(err)
	}
	acct, err := NewAccountKeys(seqID(0x10), 2, kem, seqBytes(0x41, 32))
	if err != nil {
		t.Fatal(err)
	}
	da := &DeviceAuth{
		V: 1, Origin: "https://hop.example.com", AccountID: seqID(0x10), DeviceID: seqID(0xa0),
		Operation: OperationSession, Challenge: seqBytes(0xc0, 32),
	}
	pop := &SignupPoP{
		V: 1, Origin: "https://hop.example.com", Email: "alice@example.com",
		AccountID: seqID(0x10), VaultID: seqID(0x20), UploadSeq: 7,
		UploadH: sha256.Sum256([]byte("upload")), Challenge: seqBytes(0xc0, 32),
	}
	return dev, acct, da, pop
}

// The signed objects of §9 and §4.3 (rev 16 addendum). The checked-in
// values were computed independently of this package (Python's
// cryptography Ed25519 over lp(label) || lp(JCS(obj))).
func TestVectorsAuth(t *testing.T) {
	dev, acct, da, pop := fixedAuthObjects(t)
	v := vectors{}
	v.hex("device_sig_pk", dev.Public().(ed25519.PublicKey))
	v.hex("account_sig_pk", acct.Sig.Public().(ed25519.PublicKey))
	v.json(t, "device_auth", da)
	sig, err := SignDeviceAuth(dev, da)
	if err != nil {
		t.Fatal(err)
	}
	v.hex("device_auth_sig", sig)
	v.json(t, "signup_pop", pop)
	psig, err := SignSignupPoP(acct, pop)
	if err != nil {
		t.Fatal(err)
	}
	v.hex("signup_pop_sig", psig)
	want := compareVectors(t, "auth", v)

	if err := VerifyDeviceAuth(dev.Public().(ed25519.PublicKey), da, unhex(t, want, "device_auth_sig")); err != nil {
		t.Errorf("stored device-auth signature: %v", err)
	}
	if err := VerifySignupPoP(acct.Sig.Public().(ed25519.PublicKey), pop, unhex(t, want, "signup_pop_sig")); err != nil {
		t.Errorf("stored signup-pop signature: %v", err)
	}
}

func TestAuthObjectsBindEveryField(t *testing.T) {
	dev, acct, da, pop := fixedAuthObjects(t)
	devPK := dev.Public().(ed25519.PublicKey)
	acctPK := acct.Sig.Public().(ed25519.PublicKey)
	sig, err := SignDeviceAuth(dev, da)
	if err != nil {
		t.Fatal(err)
	}
	psig, err := SignSignupPoP(acct, pop)
	if err != nil {
		t.Fatal(err)
	}

	daMut := map[string]func(a *DeviceAuth){
		"origin":    func(a *DeviceAuth) { a.Origin = "https://evil.example.com" },
		"account":   func(a *DeviceAuth) { a.AccountID = seqID(0x11) },
		"device":    func(a *DeviceAuth) { a.DeviceID = seqID(0xa1) },
		"operation": func(a *DeviceAuth) { a.Operation = OperationRetireStatus },
		"challenge": func(a *DeviceAuth) { a.Challenge = seqBytes(0xc1, 32) },
	}
	for name, mut := range daMut {
		c := *da
		mut(&c)
		if err := VerifyDeviceAuth(devPK, &c, sig); !errors.Is(err, ErrBadSignature) {
			t.Errorf("device-auth with another %s: %v, want ErrBadSignature", name, err)
		}
	}
	popMut := map[string]func(p *SignupPoP){
		"origin":    func(p *SignupPoP) { p.Origin = "https://evil.example.com" },
		"email":     func(p *SignupPoP) { p.Email = "bob@example.com" },
		"account":   func(p *SignupPoP) { p.AccountID = seqID(0x11) },
		"vault":     func(p *SignupPoP) { p.VaultID = seqID(0x21) },
		"seq":       func(p *SignupPoP) { p.UploadSeq = 8 },
		"h":         func(p *SignupPoP) { p.UploadH = sha256.Sum256([]byte("other")) },
		"challenge": func(p *SignupPoP) { p.Challenge = seqBytes(0xc1, 32) },
	}
	for name, mut := range popMut {
		c := *pop
		mut(&c)
		if err := VerifySignupPoP(acctPK, &c, psig); !errors.Is(err, ErrBadSignature) {
			t.Errorf("signup-pop with another %s: %v, want ErrBadSignature", name, err)
		}
	}

	// The labels separate the two objects and the log entry.
	if err := Verify(devPK, LabelLogEntry, da, sig); !errors.Is(err, ErrBadSignature) {
		t.Errorf("device-auth signature verifies under the log-entry label: %v", err)
	}
	if err := VerifyDeviceAuth(acctPK, da, psig); !errors.Is(err, ErrBadSignature) {
		t.Errorf("signup-pop signature verifies as device-auth: %v", err)
	}
}

func TestAuthObjectsSchema(t *testing.T) {
	dev, acct, da, pop := fixedAuthObjects(t)
	bad := map[string]func(a *DeviceAuth){
		"v":               func(a *DeviceAuth) { a.V = 2 },
		"empty origin":    func(a *DeviceAuth) { a.Origin = "" },
		"control origin":  func(a *DeviceAuth) { a.Origin = "https://a\x00b" },
		"long origin":     func(a *DeviceAuth) { a.Origin = string(make([]byte, 257)) },
		"zero account":    func(a *DeviceAuth) { a.AccountID = model.ID{} },
		"zero device":     func(a *DeviceAuth) { a.DeviceID = model.ID{} },
		"empty operation": func(a *DeviceAuth) { a.Operation = "" },
		"long operation":  func(a *DeviceAuth) { a.Operation = "abcdefghijklmnopqrstuvwxyz0123456" },
		"short challenge": func(a *DeviceAuth) { a.Challenge = seqBytes(0, 31) },
		"long challenge":  func(a *DeviceAuth) { a.Challenge = seqBytes(0, 33) },
	}
	for name, mut := range bad {
		c := *da
		mut(&c)
		if _, err := SignDeviceAuth(dev, &c); err == nil {
			t.Errorf("device-auth with %s: signed", name)
		}
	}
	badPoP := map[string]func(p *SignupPoP){
		"v":               func(p *SignupPoP) { p.V = 0 },
		"empty email":     func(p *SignupPoP) { p.Email = "" },
		"long email":      func(p *SignupPoP) { p.Email = string(seqBytes('a', 255)) },
		"zero vault":      func(p *SignupPoP) { p.VaultID = model.ID{} },
		"short challenge": func(p *SignupPoP) { p.Challenge = nil },
	}
	for name, mut := range badPoP {
		c := *pop
		mut(&c)
		if _, err := SignSignupPoP(acct, &c); err == nil {
			t.Errorf("signup-pop with %s: signed", name)
		}
	}
	other := *pop
	other.AccountID = seqID(0x11)
	if _, err := SignSignupPoP(acct, &other); err == nil {
		t.Error("signup-pop signed for another account")
	}
}

func TestCanonicalOrigin(t *testing.T) {
	for in, want := range map[string]string{
		"https://hop.example.com":      "https://hop.example.com",
		"https://HOP.Example.com/":     "https://hop.example.com",
		"HTTPS://hop.example.com:443":  "https://hop.example.com",
		"https://hop.example.com:8443": "https://hop.example.com:8443",
		"http://127.0.0.1:80":          "http://127.0.0.1",
		"http://[::1]:8080":            "http://[::1]:8080",
	} {
		if got, err := CanonicalOrigin(in); err != nil || got != want {
			t.Errorf("CanonicalOrigin(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	for _, in := range []string{"", "hop.example.com", "ftp://x", "https://x/path", "https://x?q", "https://x#f", "https://u@x", "https://"} {
		if got, err := CanonicalOrigin(in); err == nil {
			t.Errorf("CanonicalOrigin(%q) = %q, want an error", in, got)
		}
	}
}
