package cli_test

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"

	"github.com/dalyem/hopkey/internal/cli"
)

// writeKeyOfType writes an unencrypted OpenSSH private key of the type
// (ed25519, ecdsa or rsa) and returns its public half and the secret numbers
// of its private half.
func writeKeyOfType(t *testing.T, path, typ string) (ssh.PublicKey, [][]byte) {
	t.Helper()
	var priv crypto.PrivateKey
	var err error
	switch typ {
	case "ed25519":
		_, priv, err = ed25519.GenerateKey(rand.Reader)
	case "ecdsa":
		priv, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	case "rsa":
		priv, err = rsa.GenerateKey(rand.Reader, 2048)
	default:
		t.Fatalf("no key type %s", typ)
	}
	if err != nil {
		t.Fatal(err)
	}
	block, err := ssh.MarshalPrivateKey(priv, "")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, pem.EncodeToMemory(block), 0o600); err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	var secrets [][]byte
	switch k := priv.(type) {
	case ed25519.PrivateKey:
		secrets = [][]byte{k.Seed(), k}
	case *ecdsa.PrivateKey:
		secrets = [][]byte{k.D.Bytes()}
	case *rsa.PrivateKey:
		secrets = [][]byte{k.D.Bytes(), k.Primes[0].Bytes(), k.Primes[1].Bytes()}
	}
	return signer.PublicKey(), secrets
}

func TestKeyPubPrintsThePublicHalfOfEachKeyType(t *testing.T) {
	e := newE2E(t)
	sshKeygen, keygenErr := exec.LookPath("ssh-keygen")
	if keygenErr != nil && os.Getenv("HOPKEY_REQUIRE_SSH") != "" {
		t.Fatalf("ssh-keygen not found and HOPKEY_REQUIRE_SSH is set: %v", keygenErr)
	}

	for _, typ := range []string{"ed25519", "ecdsa", "rsa"} {
		t.Run(typ, func(t *testing.T) {
			path := filepath.Join(e.home, ".ssh", "id_"+typ)
			pub, secrets := writeKeyOfType(t, path, typ)
			name := "pub-" + typ
			if code, _, stderr := e.hop(t, "key", "add", path, "--name", name); code != 0 {
				t.Fatalf("key add: %d %s", code, stderr)
			}

			code, stdout, stderr := e.hop(t, "key", "pub", name)
			if code != 0 || stderr != "" {
				t.Fatalf("key pub: %d, stderr %q", code, stderr)
			}
			// An authorized_keys line: type, base64, comment.
			want := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(pub)))
			if stdout != want+" "+name+"\n" {
				t.Errorf("key pub = %q, want %q", stdout, want+" "+name+"\n")
			}
			if keygenErr == nil {
				// ssh-keygen -y prints type and base64 for the same private key.
				out, err := exec.Command(sshKeygen, "-y", "-f", path).Output()
				if err != nil {
					t.Fatalf("ssh-keygen -y: %v", err)
				}
				if got := strings.Join(strings.Fields(stdout)[:2], " "); got != strings.TrimSpace(string(out)) {
					t.Errorf("key pub = %q, ssh-keygen -y = %q", got, strings.TrimSpace(string(out)))
				}
			}

			code, fpOut, stderr := e.hop(t, "key", "pub", name, "--fingerprint")
			if code != 0 || stderr != "" {
				t.Fatalf("key pub --fingerprint: %d, stderr %q", code, stderr)
			}
			if fpOut != ssh.FingerprintSHA256(pub)+"\n" {
				t.Errorf("key pub --fingerprint = %q, want %q", fpOut, ssh.FingerprintSHA256(pub))
			}
			if keygenErr == nil {
				// What ssh-keygen -l prints: bits, fingerprint, comment, type.
				out, err := exec.Command(sshKeygen, "-l", "-f", path).Output()
				if err != nil {
					t.Fatalf("ssh-keygen -l: %v", err)
				}
				if f := strings.Fields(string(out)); len(f) < 2 || f[1]+"\n" != fpOut {
					t.Errorf("key pub --fingerprint = %q, ssh-keygen -l = %q", fpOut, out)
				}
			}

			code, jsonOut, stderr := e.hop(t, "key", "pub", name, "--json")
			if code != 0 {
				t.Fatalf("key pub --json: %d %s", code, stderr)
			}
			var v cli.KeyPubView
			if err := json.Unmarshal([]byte(jsonOut), &v); err != nil {
				t.Fatalf("%v\n%s", err, jsonOut)
			}
			if v.Name != name || v.PublicKey != strings.TrimSpace(stdout) || v.Fingerprint != ssh.FingerprintSHA256(pub) || v.ID == "" || v.KeyType == "" {
				t.Errorf("key pub --json = %+v", v)
			}
			var fields map[string]any
			json.Unmarshal([]byte(jsonOut), &fields)
			if len(fields) != 5 {
				t.Errorf("key pub --json has fields %v, want id, name, key_type, public_key and fingerprint", fields)
			}

			// The key can be named by its ID too.
			if code, byID, _ := e.hop(t, "key", "pub", v.ID); code != 0 || byID != stdout {
				t.Errorf("key pub by ID: %d %q", code, byID)
			}

			// No private byte in any of it.
			all := stdout + fpOut + jsonOut
			for _, secret := range secrets {
				for _, form := range []string{
					string(secret), hex.EncodeToString(secret), base64.StdEncoding.EncodeToString(secret),
					base64.RawStdEncoding.EncodeToString(secret), base64.RawURLEncoding.EncodeToString(secret),
				} {
					if strings.Contains(all, form) {
						t.Errorf("the output holds private key material: %q", form)
					}
				}
			}
			if strings.Contains(all, "PRIVATE") {
				t.Error("the output mentions a private key")
			}
		})
	}
}

func TestKeyPubRefusals(t *testing.T) {
	e := newE2E(t)
	if code, _, stderr := e.hop(t, "key", "pub"); code != 255 || !strings.Contains(stderr, "exactly one key name") {
		t.Errorf("no name: %d %q", code, stderr)
	}
	if code, stdout, stderr := e.hop(t, "key", "pub", "nothing"); code != 255 || stdout != "" || !strings.Contains(stderr, `no key named "nothing"`) || !strings.Contains(stderr, "deploy-key") {
		t.Errorf("unknown key: %d %q %q", code, stdout, stderr)
	}
}

// A name with spaces or control characters cannot add a field, an option or
// a line to the authorized_keys line it comments.
func TestKeyPubCommentIsOneWord(t *testing.T) {
	e := newE2E(t)
	path := filepath.Join(e.home, ".ssh", "id_odd")
	pub, _ := writeKeyOfType(t, path, "ed25519")
	if code, _, stderr := e.hop(t, "key", "add", path, "--name", "my laptop\x1b[2J\nx"); code != 0 {
		t.Fatalf("key add: %d %s", code, stderr)
	}
	code, stdout, _ := e.hop(t, "key", "pub", "my laptop\x1b[2J\nx")
	if code != 0 {
		t.Fatalf("key pub: %d", code)
	}
	want := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(pub))) + " my_laptop_[2J_x\n"
	if stdout != want {
		t.Errorf("key pub = %q, want %q", stdout, want)
	}
}
