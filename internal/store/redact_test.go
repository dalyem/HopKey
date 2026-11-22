package store

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/dalyem/hopkey/internal/redact"
)

// covered reports whether one of secrets, as the daemon looks for them
// (redact.Literals), covers the whole of v where it stands in a text.
func covered(secrets []redact.Secret, v string) bool {
	text := "before " + v + " after"
	lo, hi := len("before "), len("before ")+len(v)
	for _, h := range redact.Literals(text, secrets) {
		if h.Lo <= lo && hi <= h.Hi && strings.HasPrefix(h.Kind, "vault-") {
			return true
		}
	}
	return false
}

// A queued replacement does not take the old password out of what is
// redacted: until the server takes the change, the old one is still the
// vault's, and still logs in. The new one is redacted too.
func TestAccountSecretsCoverVerifiedAndQueuedItems(t *testing.T) {
	ctx := context.Background()
	f := newVault(t, testConfig(t))
	c := newCredential(t, f.s, "db")
	old := c.Password
	newFakeRemote(t, f.cfg.DataDir)
	if err := f.s.EnableServerMode(); err != nil {
		t.Fatal(err)
	}
	c.Password = "a replacement password"
	if _, err := f.s.PutCredential(ctx, c); err != nil {
		t.Fatal(err)
	}
	snap := snapshot(t, f.s)
	if len(snap.Credentials) != 1 || snap.Credentials[0].Password != c.Password || snap.Marks[c.ItemID] == "" {
		t.Fatalf("the replacement is not queued: %+v", snap)
	}
	secrets, err := f.s.AccountSecrets()
	if err != nil {
		t.Fatal(err)
	}
	if !covered(secrets, old) {
		t.Errorf("the verified password %q, which a queued change replaces, is not redacted", old)
	}
	if !covered(secrets, c.Password) {
		t.Errorf("the queued password %q is not redacted", c.Password)
	}
}

// The account's private keys are as secret as the device's, and are
// redacted in the same encodings.
func TestAccountSecretsCoverTheAccountKeys(t *testing.T) {
	f := newVault(t, testConfig(t))
	acct := f.s.sec.Account
	kem, err := acct.KEM.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	secrets, err := f.s.AccountSecrets()
	if err != nil {
		t.Fatal(err)
	}
	for name, b := range map[string][]byte{"KEM private key": kem, "signing seed": acct.Sig.Seed(), "signing key": acct.Sig} {
		for enc, v := range map[string]string{
			"base64url": base64.RawURLEncoding.EncodeToString(b),
			"base64":    base64.StdEncoding.EncodeToString(b),
			"hex":       hex.EncodeToString(b),
		} {
			if !covered(secrets, v) {
				t.Errorf("the account %s in %s is not redacted", name, enc)
			}
		}
	}
}
