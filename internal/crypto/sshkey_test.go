package crypto

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/pem"
	"errors"
	"slices"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"

	"github.com/dalyem/hopkey/internal/canonjson"
	"github.com/dalyem/hopkey/internal/model"
)

// testSSHLine is a well-formed ssh-ed25519 authorized_keys line.
const testSSHLine = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDsPCdYbkGZUj2R+9nkWgRhNyvIyarH5H7OGojd9hz2A"

// testKeyPEM and testKeyLine are a fixed Ed25519 key pair for key items:
// an unencrypted OpenSSH private key and its public-key line.
var testKeyPEM, testKeyLine = fixedSSHKey("ssh-key")

// opensshEd25519 returns an unencrypted OpenSSH private key (PEM) for an
// Ed25519 seed.
func opensshEd25519(seed []byte, comment string) string {
	return opensshEd25519Raw(ed25519.NewKeyFromSeed(seed), comment)
}

// opensshEd25519Raw encodes a raw 64-byte Ed25519 private key (seed and
// public half, which need not match) in the unencrypted openssh-key-v1
// format. ssh.MarshalPrivateKey draws random check bytes; fixed ones keep
// fixtures and vectors deterministic.
func opensshEd25519Raw(priv []byte, comment string) string {
	pub := priv[ed25519.SeedSize:]
	str := func(b []byte) []byte { return append(binary.BigEndian.AppendUint32(nil, uint32(len(b))), b...) }
	algo := []byte(ssh.KeyAlgoED25519)
	pubBlob := slices.Concat(str(algo), str(pub))
	sec := slices.Concat([]byte{1, 2, 3, 4, 1, 2, 3, 4}, str(algo), str(pub), str(priv), str([]byte(comment)))
	for i := byte(1); len(sec)%8 != 0; i++ {
		sec = append(sec, i)
	}
	body := slices.Concat([]byte("openssh-key-v1\x00"), str([]byte("none")), str([]byte("none")), str(nil),
		[]byte{0, 0, 0, 1}, str(pubBlob), str(sec))
	return string(pem.EncodeToMemory(&pem.Block{Type: "OPENSSH PRIVATE KEY", Bytes: body}))
}

// fixedSSHKey returns a deterministic Ed25519 OpenSSH private key and its
// public-key line.
func fixedSSHKey(label string) (pemText, line string) {
	seed := fixedBytes(label, 32)
	pk, err := ssh.NewPublicKey(ed25519.NewKeyFromSeed(seed).Public())
	if err != nil {
		panic(err)
	}
	return opensshEd25519(seed, ""), strings.TrimSpace(string(ssh.MarshalAuthorizedKey(pk)))
}

// genKey returns a fresh private key: "ed25519", "ecdsa-p256",
// "ecdsa-p384" or "rsa-3072".
func genKey(t *testing.T, kind string) any {
	t.Helper()
	var key any
	var err error
	switch kind {
	case "ed25519":
		_, key, err = ed25519.GenerateKey(rand.Reader)
	case "ecdsa-p256":
		key, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	case "ecdsa-p384":
		key, err = ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	case "rsa-3072":
		key, err = rsa.GenerateKey(rand.Reader, 3072)
	default:
		t.Fatalf("unknown key kind %q", kind)
	}
	if err != nil {
		t.Fatal(err)
	}
	return key
}

// sshLineOf returns the public-key line of a private key.
func sshLineOf(t *testing.T, key any) string {
	t.Helper()
	s, err := ssh.NewSignerFromKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return strings.TrimSpace(string(ssh.MarshalAuthorizedKey(s.PublicKey())))
}

// genSSHKey returns a fresh unencrypted OpenSSH private key and its
// public-key line.
func genSSHKey(t *testing.T, kind string) (pemText, line string) {
	t.Helper()
	key := genKey(t, kind)
	blk, err := ssh.MarshalPrivateKey(key, "")
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(blk)), sshLineOf(t, key)
}

// badSSHLines are values that are not OpenSSH authorized_keys lines
// "type SP base64 [SP comment]" (§6.5, rev 12), though each passes
// str≤8192.
func badSSHLines() map[string]string {
	f := strings.Fields(testSSHLine)
	return map[string]string{
		"empty":                        "",
		"no blob":                      f[0],
		"blob is not base64":           f[0] + " !!!!",
		"blob is not a key":            f[0] + " " + base64.StdEncoding.EncodeToString([]byte("not a key")),
		"truncated blob":               "ssh-ed25519 AAAA",
		"type differs from blob":       "ssh-rsa " + f[1],
		"authorized_keys options":      `from="10.0.0.1" ` + testSSHLine,
		"options without value":        "restrict " + testSSHLine,
		"blob in URL-safe base64":      f[0] + " " + strings.NewReplacer("+", "-", "/", "_").Replace(f[1]),
		"leading space":                " " + testSSHLine,
		"trailing space":               testSSHLine + " ",
		"trailing space after comment": testSSHLine + " c ",
		// Unicode spaces are not SP: strings.Fields would split on them.
		"NBSP separator":        f[0] + "\u00a0" + f[1],
		"NBSP before comment":   testSSHLine + "\u00a0comment",
		"em space separator":    f[0] + "\u2003" + f[1],
		"ideographic separator": f[0] + "\u3000" + f[1],
		"ogham space separator": f[0] + "\u1680" + f[1],
		"line separator":        f[0] + "\u2028" + f[1],
		"non-ASCII comment":     testSSHLine + " caf\u00e9",
	}
}

// controlSSHLines are not key lines either, but str≤8192 already rejects
// them, so only ParseSSHKeyLine reports ErrSSHKeyLine for them.
func controlSSHLines() map[string]string {
	f := strings.Fields(testSSHLine)
	return map[string]string{
		"second record on a new line": testSSHLine + "\n" + testSSHLine,
		"trailing LF":                 testSSHLine + "\n",
		"trailing tab":                testSSHLine + "\t",
		"leading tab":                 "\t" + testSSHLine,
		"CR separator":                f[0] + "\r" + f[1],
		"NUL in comment":              testSSHLine + " a\x00b",
		"NEL separator":               f[0] + "\u0085" + f[1],
		"longer than 8192 bytes":      testSSHLine + " " + strings.Repeat("c", 8192),
	}
}

// ValidateKey (public_key) and ValidateHost (each host_keys entry) enforce
// the OpenSSH line rule, so every caller of the §6.5 validators (builders,
// transitions, anchors, bundles, token clients) applies the same rule.
func TestSSHKeyLineRule(t *testing.T) {
	keyFields := strings.Fields(testKeyLine)
	for name, line := range badSSHLines() {
		if _, err := ParseSSHKeyLine(line); !errors.Is(err, ErrSSHKeyLine) {
			t.Errorf("ParseSSHKeyLine %s: %v", name, err)
		}
		k := testKey(2, model.ID{})
		// The same mutation on the key item's own line.
		k.PublicKey = strings.ReplaceAll(line, strings.Fields(testSSHLine)[1], keyFields[1])
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
	for name, line := range controlSSHLines() {
		if _, err := ParseSSHKeyLine(line); !errors.Is(err, ErrSSHKeyLine) {
			t.Errorf("ParseSSHKeyLine %s: %v", name, err)
		}
		k := testKey(2, model.ID{})
		k.PublicKey = strings.ReplaceAll(line, strings.Fields(testSSHLine)[1], keyFields[1])
		if ValidateKey(k) == nil {
			t.Errorf("key public_key %s: accepted", name)
		}
		h := testHost(fixedID(1), 1)
		h.HostKeys = []string{line}
		if ValidateHost(h) == nil {
			t.Errorf("host_keys %s: accepted", name)
		}
	}
	// A line with or without a comment is fine, SP may be several spaces,
	// and an empty host_keys list is allowed.
	for _, sep := range []string{" ", "  ", "   "} {
		for _, comment := range []string{"", sep + "user@laptop", sep + "two words"} {
			kl := keyFields[0] + sep + keyFields[1] + comment
			k := testKey(2, model.ID{})
			k.PublicKey = kl
			if err := ValidateKey(k); err != nil {
				t.Errorf("key %q: %v", kl, err)
			}
			hl := strings.Replace(testSSHLine, " ", sep, 1) + comment
			h := testHost(fixedID(1), 1)
			h.HostKeys = []string{hl}
			if err := ValidateHost(h); err != nil {
				t.Errorf("host %q: %v", hl, err)
			}
		}
	}
	h := testHost(fixedID(1), 1)
	h.HostKeys = []string{}
	if err := ValidateHost(h); err != nil {
		t.Errorf("empty host_keys: %v", err)
	}
}

// SP is one or more ASCII spaces (§6.5, rev 13). A tab is a control
// character, not a separator, so the line grammar itself rejects it and the
// item validators report ErrSSHKeyLine.
func TestSSHKeyLineRejectsTabs(t *testing.T) {
	f := strings.Fields(testSSHLine)
	for _, line := range []string{f[0] + "\t" + f[1], f[0] + " \t " + f[1] + " comment", f[0] + " " + f[1] + " c\td"} {
		if _, err := ParseSSHKeyLine(line); !errors.Is(err, ErrSSHKeyLine) {
			t.Errorf("ParseSSHKeyLine %q: %v, want ErrSSHKeyLine", line, err)
		}
	}
	if _, err := ParseSSHKeyLine(f[0] + "   " + f[1] + "  two  spaces"); err != nil {
		t.Errorf("runs of spaces should separate fields: %v", err)
	}
}

// key.private_key MUST be an unencrypted OpenSSH private key whose public
// key equals public_key's blob and whose algorithm matches key_type (§6.5,
// rev 12).
func TestPrivateKeyRule(t *testing.T) {
	keys := map[string]string{"ed25519": "ed25519", "ecdsa-p256": "ecdsa-p256", "rsa-3072": "rsa"}
	gen := map[string][2]string{}
	for kind, kt := range keys {
		pemText, line := genSSHKey(t, kind)
		gen[kind] = [2]string{pemText, line}
		k := testKey(2, model.ID{})
		k.KeyType, k.PrivateKey, k.PublicKey = kt, pemText, line+" comment"
		if err := ValidateKey(k); err != nil {
			t.Errorf("real %s key rejected: %v", kind, err)
		}
	}
	if err := ValidateKey(testKey(2, model.ID{})); err != nil {
		t.Errorf("fixed Ed25519 fixture rejected: %v", err)
	}

	encrypted := func(kind string) string {
		key := genKey(t, kind)
		blk, err := ssh.MarshalPrivateKeyWithPassphrase(key, "", []byte("passphrase"))
		if err != nil {
			t.Fatal(err)
		}
		return string(pem.EncodeToMemory(blk))
	}
	edKey := genKey(t, "ed25519")
	edLine := sshLineOf(t, edKey)
	p384PEM, p384Line := genSSHKey(t, "ecdsa-p384")
	pkcs8, err := x509.MarshalPKCS8PrivateKey(edKey)
	if err != nil {
		t.Fatal(err)
	}
	rsaKey := genKey(t, "rsa-3072").(*rsa.PrivateKey)
	pkcs1 := string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(rsaKey)}))
	// A legacy encrypted PEM (deprecated, which is the point).
	legacy, err := x509.EncryptPEMBlock(rand.Reader, "RSA PRIVATE KEY", x509.MarshalPKCS1PrivateKey(rsaKey), []byte("pw"), x509.PEMCipherAES256)
	if err != nil {
		t.Fatal(err)
	}
	// An Ed25519 key whose stored public half is another key's.
	other := ed25519.NewKeyFromSeed(fixedBytes("other", 32))
	forged := slices.Concat(fixedBytes("ssh-key", 32), other[32:])

	cases := map[string]struct {
		keyType, priv, pub string
	}{
		"empty":                       {"ed25519", "", testKeyLine},
		"garbage":                     {"ed25519", "not a key", testKeyLine},
		"garbage PEM":                 {"ed25519", "-----BEGIN OPENSSH PRIVATE KEY-----\nAAAA\n-----END OPENSSH PRIVATE KEY-----\n", testKeyLine},
		"encrypted ed25519":           {"ed25519", encrypted("ed25519"), testKeyLine},
		"encrypted rsa":               {"rsa", encrypted("rsa-3072"), testKeyLine},
		"legacy encrypted PEM":        {"rsa", string(pem.EncodeToMemory(legacy)), sshLineOf(t, rsaKey)},
		"PKCS#8 ed25519":              {"ed25519", string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8})), edLine},
		"PKCS#1 rsa":                  {"rsa", pkcs1, sshLineOf(t, rsaKey)},
		"public key of another key":   {"ed25519", testKeyPEM, edLine},
		"public key of another type":  {"ed25519", testKeyPEM, gen["rsa-3072"][1]},
		"key_type rsa for ed25519":    {"rsa", testKeyPEM, testKeyLine},
		"key_type ecdsa-p256 for rsa": {"ecdsa-p256", gen["rsa-3072"][0], gen["rsa-3072"][1]},
		"key_type ed25519 for ecdsa":  {"ed25519", gen["ecdsa-p256"][0], gen["ecdsa-p256"][1]},
		"ecdsa-p384 as ecdsa-p256":    {"ecdsa-p256", p384PEM, p384Line},
		"text before the PEM":         {"ed25519", "comment\n" + testKeyPEM, testKeyLine},
		"second PEM block":            {"ed25519", testKeyPEM + gen["ed25519"][0], testKeyLine},
		"malformed block before":      {"ed25519", "-----BEGIN OPENSSH PRIVATE KEY-----\n!!notbase64!!\n-----END OPENSSH PRIVATE KEY-----\n" + testKeyPEM, testKeyLine},
		"text after the PEM":          {"ed25519", testKeyPEM + "trailing\n", testKeyLine},
		"forged Ed25519 public half":  {"ed25519", opensshEd25519Raw(forged, ""), sshLineOfPub(t, other.Public())},
		"PEM header":                  {"ed25519", strings.Replace(testKeyPEM, "-----\n", "-----\nX-Note: 1\n\n", 1), testKeyLine},
	}
	for name, c := range cases {
		k := testKey(2, model.ID{})
		k.KeyType, k.PrivateKey, k.PublicKey = c.keyType, c.priv, c.pub
		err := ValidateKey(k)
		var se *SchemaError
		if !errors.Is(err, ErrSSHPrivateKey) || !errors.As(err, &se) || se.Field != "private_key" {
			t.Errorf("%s: %v", name, err)
		}
	}
	// Parsing a key line that is fine leaves private_key to this rule:
	// a bad public_key is reported as ErrSSHKeyLine first.
	k := testKey(2, model.ID{})
	k.PublicKey = "ssh-ed25519 AAAA"
	if err := ValidateKey(k); !errors.Is(err, ErrSSHKeyLine) {
		t.Errorf("bad public_key: %v", err)
	}
}

func sshLineOfPub(t *testing.T, pub any) string {
	t.Helper()
	pk, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	return strings.TrimSpace(string(ssh.MarshalAuthorizedKey(pk)))
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
