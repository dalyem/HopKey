package sshkeys

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/pem"
	"errors"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
)

func pemOf(t *testing.T, key any, passphrase string) []byte {
	t.Helper()
	var block *pem.Block
	var err error
	if passphrase == "" {
		block, err = ssh.MarshalPrivateKey(key, "")
	} else {
		block, err = ssh.MarshalPrivateKeyWithPassphrase(key, "", []byte(passphrase))
	}
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(block)
}

func TestParseKeyTypes(t *testing.T) {
	_, ed, _ := ed25519.GenerateKey(rand.Reader)
	p256, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	p384, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)

	tests := []struct {
		name    string
		key     any
		want    string
		wantErr string
	}{
		{name: "ed25519", key: ed, want: "ed25519"},
		{name: "ecdsa p256", key: p256, want: "ecdsa-p256"},
		{name: "rsa", key: rsaKey, want: "rsa"},
		{name: "ecdsa p384 is not stored", key: p384, wantErr: "unsupported key type"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			k, err := Parse(pemOf(t, tt.key, ""))
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("err = %v, want %q", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if k.Type != tt.want {
				t.Errorf("type = %s, want %s", k.Type, tt.want)
			}
			// Raw is something the agent keyring accepts: never *ed25519.PrivateKey.
			if _, ok := k.Raw.(*ed25519.PrivateKey); ok {
				t.Error("Raw is a pointer to an ed25519 key")
			}
			// The public key signs and verifies with Raw.
			signer, err := ssh.NewSignerFromKey(k.Raw)
			if err != nil || string(signer.PublicKey().Marshal()) != string(k.Public.Marshal()) {
				t.Errorf("Raw and Public disagree: %v", err)
			}
		})
	}
}

func TestMarshalPrivateRoundTrips(t *testing.T) {
	_, ed, _ := ed25519.GenerateKey(rand.Reader)
	rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	for _, key := range []any{ed, rsaKey} {
		first, err := Parse(pemOf(t, key, ""))
		if err != nil {
			t.Fatal(err)
		}
		out, err := first.MarshalPrivate("comment")
		if err != nil {
			t.Fatal(err)
		}
		if !strings.HasPrefix(out, "-----BEGIN OPENSSH PRIVATE KEY-----") {
			t.Errorf("not OpenSSH format: %.40q", out)
		}
		second, err := Parse([]byte(out))
		if err != nil || Fingerprint(second.Public) != Fingerprint(first.Public) {
			t.Errorf("round trip changed the key: %v", err)
		}
	}
}

func TestPassphrases(t *testing.T) {
	_, ed, _ := ed25519.GenerateKey(rand.Reader)
	enc := pemOf(t, ed, "pw")
	if _, err := Parse(enc); !errors.Is(err, ErrPassphrase) {
		t.Fatalf("Parse of an encrypted key: %v, want ErrPassphrase", err)
	}
	if _, err := ParseWithPassphrase(enc, []byte("nope")); err == nil || errors.Is(err, ErrPassphrase) {
		t.Errorf("wrong passphrase: %v", err)
	}
	k, err := ParseWithPassphrase(enc, []byte("pw"))
	if err != nil || k.Type != "ed25519" {
		t.Fatalf("right passphrase: %v", err)
	}
	// What MarshalPrivate writes needs no passphrase.
	out, _ := k.MarshalPrivate("")
	if _, err := Parse([]byte(out)); err != nil {
		t.Errorf("re-marshalled key still encrypted: %v", err)
	}
}

func TestParseGarbage(t *testing.T) {
	for _, in := range []string{"", "hello", "-----BEGIN OPENSSH PRIVATE KEY-----\nAAAA\n-----END OPENSSH PRIVATE KEY-----\n"} {
		if _, err := Parse([]byte(in)); err == nil {
			t.Errorf("Parse(%q) succeeded", in)
		}
	}
}

func TestParsePublic(t *testing.T) {
	_, ed, _ := ed25519.GenerateKey(rand.Reader)
	signer, _ := ssh.NewSignerFromKey(ed)
	line := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(signer.PublicKey())))

	for _, in := range []string{line, line + " user@host", "  " + line + "\n"} {
		pub, err := ParsePublic(in)
		if err != nil || Fingerprint(pub) != Fingerprint(signer.PublicKey()) {
			t.Errorf("ParsePublic(%q) = %v", in, err)
		}
	}
	if got := Line(signer.PublicKey()); got != line {
		t.Errorf("Line = %q, want %q", got, line)
	}
	for _, in := range []string{"", "not a key", `command="rm -rf /" ` + line, "ssh-ed25519 AAAA"} {
		if _, err := ParsePublic(in); err == nil {
			t.Errorf("ParsePublic(%q) succeeded", in)
		}
	}
}
