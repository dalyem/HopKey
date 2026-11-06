// Package sshkeys parses and describes SSH keys for the CLI and the daemon.
package sshkeys

import (
	"crypto/ed25519"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/ssh"
)

// ErrPassphrase means the private key is encrypted and needs a passphrase.
var ErrPassphrase = errors.New("sshkeys: private key is passphrase-protected")

// Private is a parsed private key.
type Private struct {
	// Raw is the key in the form sshagent.Keyring.Add takes:
	// *rsa.PrivateKey, *ecdsa.PrivateKey or ed25519.PrivateKey.
	Raw    any
	Public ssh.PublicKey
	Type   string // ed25519, ecdsa-p256 or rsa, as in model.Key.KeyType
}

// Parse reads an unencrypted private key in OpenSSH or PEM form. An encrypted
// key returns ErrPassphrase.
func Parse(data []byte) (*Private, error) {
	return parse(data, nil)
}

// ParseWithPassphrase is Parse for an encrypted key.
func ParseWithPassphrase(data, passphrase []byte) (*Private, error) {
	return parse(data, passphrase)
}

func parse(data, passphrase []byte) (*Private, error) {
	var raw any
	var err error
	if passphrase == nil {
		raw, err = ssh.ParseRawPrivateKey(data)
	} else {
		raw, err = ssh.ParseRawPrivateKeyWithPassphrase(data, passphrase)
	}
	var missing *ssh.PassphraseMissingError
	if errors.As(err, &missing) {
		return nil, ErrPassphrase
	}
	if err != nil {
		return nil, fmt.Errorf("sshkeys: %w", err)
	}
	if p, ok := raw.(*ed25519.PrivateKey); ok {
		raw = *p
	}
	signer, err := ssh.NewSignerFromKey(raw)
	if err != nil {
		return nil, fmt.Errorf("sshkeys: %w", err)
	}
	typ, err := KeyType(signer.PublicKey())
	if err != nil {
		return nil, err
	}
	return &Private{Raw: raw, Public: signer.PublicKey(), Type: typ}, nil
}

// MarshalPrivate writes the key as an unencrypted OpenSSH private key.
func (p *Private) MarshalPrivate(comment string) (string, error) {
	block, err := ssh.MarshalPrivateKey(p.Raw, comment)
	if err != nil {
		return "", fmt.Errorf("sshkeys: %w", err)
	}
	return string(pem.EncodeToMemory(block)), nil
}

// KeyType maps an SSH public key to a model.Key.KeyType. Only the three types
// the vault stores are accepted.
func KeyType(pub ssh.PublicKey) (string, error) {
	switch pub.Type() {
	case ssh.KeyAlgoED25519:
		return "ed25519", nil
	case ssh.KeyAlgoECDSA256:
		return "ecdsa-p256", nil
	case ssh.KeyAlgoRSA:
		return "rsa", nil
	}
	return "", fmt.Errorf("sshkeys: unsupported key type %s (the vault stores ed25519, ecdsa-p256 and rsa keys)", pub.Type())
}

// ParsePublic reads one OpenSSH public-key line (authorized_keys form). A
// trailing comment is ignored; options before the key type are refused.
func ParsePublic(line string) (ssh.PublicKey, error) {
	line = strings.TrimSpace(line)
	pub, _, options, _, err := ssh.ParseAuthorizedKey([]byte(line))
	if err != nil {
		return nil, fmt.Errorf("sshkeys: %w", err)
	}
	if len(options) > 0 {
		return nil, errors.New("sshkeys: public key line has options")
	}
	return pub, nil
}

// Line renders a public key as an OpenSSH line without a trailing newline.
func Line(pub ssh.PublicKey) string {
	return strings.TrimSpace(string(ssh.MarshalAuthorizedKey(pub)))
}

// Fingerprint is the SHA256:... fingerprint of pub.
func Fingerprint(pub ssh.PublicKey) string { return ssh.FingerprintSHA256(pub) }
