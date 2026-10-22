package crypto

import (
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"

	"github.com/dalyem/hopkey/internal/canonjson"
	"github.com/dalyem/hopkey/internal/model"
)

// testSSHLine is a well-formed ssh-ed25519 authorized_keys line.
const testSSHLine = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDsPCdYbkGZUj2R+9nkWgRhNyvIyarH5H7OGojd9hz2A"

// badSSHLines are values that are not OpenSSH authorized_keys lines
// "<type> <base64> [comment]" (§6.5, rev 10 item 11), though each passes
// str≤8192.
func badSSHLines() map[string]string {
	f := strings.Fields(testSSHLine)
	return map[string]string{
		"empty":                   "",
		"no blob":                 f[0],
		"blob is not base64":      f[0] + " !!!!",
		"blob is not a key":       f[0] + " " + base64.StdEncoding.EncodeToString([]byte("not a key")),
		"truncated blob":          "ssh-ed25519 AAAA",
		"type differs from blob":  "ssh-rsa " + f[1],
		"authorized_keys options": `from="10.0.0.1" ` + testSSHLine,
		"blob in URL-safe base64": f[0] + " " + strings.NewReplacer("+", "-", "/", "_").Replace(f[1]),
	}
}

// ValidateKey (public_key) and ValidateHost (each host_keys entry) enforce
// the OpenSSH line rule, so every caller of the §6.5 validators (builders,
// transitions, anchors, bundles, token clients) applies the same rule.
func TestSSHKeyLineRule(t *testing.T) {
	for name, line := range badSSHLines() {
		k := testKey(2, model.ID{})
		k.PublicKey = line
		if err := ValidateKey(k); !errors.Is(err, ErrSSHKeyLine) {
			t.Errorf("key public_key %s: %v", name, err)
		}
		h := testHost(fixedID(1), 1)
		h.HostKeys = []string{testSSHLine, line}
		err := ValidateHost(h)
		var se *SchemaError
		if !errors.Is(err, ErrSSHKeyLine) || !errors.As(err, &se) || se.Field != "host_keys[1]" {
			t.Errorf("host_keys %s: %v", name, err)
		}
		if _, err := SSHFingerprint(line); !errors.Is(err, ErrSSHKeyLine) {
			t.Errorf("SSHFingerprint %s: %v", name, err)
		}
	}
	// A line with or without a comment is fine, and an empty host_keys list
	// is allowed.
	for _, line := range []string{testSSHLine, testSSHLine + " user@laptop", testSSHLine + " two words"} {
		k := testKey(2, model.ID{})
		k.PublicKey = line
		if err := ValidateKey(k); err != nil {
			t.Errorf("key %q: %v", line, err)
		}
		h := testHost(fixedID(1), 1)
		h.HostKeys = []string{line}
		if err := ValidateHost(h); err != nil {
			t.Errorf("host %q: %v", line, err)
		}
	}
	h := testHost(fixedID(1), 1)
	h.HostKeys = []string{}
	if err := ValidateHost(h); err != nil {
		t.Errorf("empty host_keys: %v", err)
	}
}

// SSHFingerprint matches OpenSSH's SHA256 fingerprint (§10.3).
func TestSSHFingerprint(t *testing.T) {
	pub := ed25519.NewKeyFromSeed(fixedBytes("fp", 32)).Public()
	pk, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	line := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(pk))) + " comment"
	got, err := SSHFingerprint(line)
	if err != nil {
		t.Fatal(err)
	}
	if want := ssh.FingerprintSHA256(pk); got != want {
		t.Fatalf("fingerprint %s, want %s", got, want)
	}
}

// A token client rejects a validly signed bundle whose host carries a
// malformed host key: OpenBundle runs the same §6.5 validator.
func TestOpenBundleRejectsMalformedHostKey(t *testing.T) {
	f := newGrantFixture(t)
	b, err := BuildBundle(f.rec, f.items, f.acct.AccountID, 1, 1)
	if err != nil {
		t.Fatal(err)
	}
	// BuildBundle and SealBundle refuse the host too.
	bad := *f.items[fixedID(0x01)].(*model.Host)
	bad.HostKeys = []string{"ssh-ed25519 AAAA"}
	items := map[model.ID]Item{}
	for id, it := range f.items {
		items[id] = it
	}
	items[fixedID(0x01)] = &bad
	if _, err := BuildBundle(f.rec, items, f.acct.AccountID, 1, 1); !errors.Is(err, ErrSSHKeyLine) {
		t.Errorf("BuildBundle: %v", err)
	}
	// Replace the host's plaintext in a built bundle, bypassing the
	// builder, then sign and seal it as a careless author would.
	pt, err := canonjson.Marshal(&bad)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for i := range b.Items {
		if b.Items[i].ItemID == fixedID(0x01) {
			b.Items[i].Plaintext = canonjson.Raw(pt)
			found = true
		}
	}
	if !found {
		t.Fatal("host not in the bundle")
	}
	if _, err := SealBundle(f.acct, f.rec, b); !errors.Is(err, ErrSSHKeyLine) {
		t.Errorf("SealBundle: %v", err)
	}
	e := resealPayload(t, f, b, f.acct, f.acct.Public().SigPK, 1)
	if _, err := OpenBundle(f.tok, e, 1, f.now); !errors.Is(err, ErrSSHKeyLine) {
		t.Fatalf("OpenBundle: %v", err)
	}
	// The same bundle with a well-formed host key opens.
	good := f.seal(t, 1)
	if _, err := OpenBundle(f.tok, good, 1, f.now); err != nil {
		t.Fatal(err)
	}
}
