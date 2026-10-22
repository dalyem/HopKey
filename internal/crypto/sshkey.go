package crypto

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"strings"

	"golang.org/x/crypto/ssh"
)

// ErrSSHKeyLine marks a key.public_key or host.host_keys entry that is not
// an OpenSSH authorized_keys line (§6.5, rev 10 item 11). Schema errors for
// those fields wrap it, so callers can tell this rule apart with errors.Is.
var ErrSSHKeyLine = errors.New("not an OpenSSH public-key line")

// ErrSSHPrivateKey marks a key.private_key that is not an unencrypted
// OpenSSH private key matching public_key and key_type (§6.5, rev 12).
// Schema errors for that field wrap it.
var ErrSSHPrivateKey = errors.New("not an unencrypted OpenSSH private key for this public key")

// maxSSHKeyLine bounds a key line; it is the str≤8192 bound of public_key
// and host_keys (§6.5).
const maxSSHKeyLine = 8192

// isSSHSpace reports whether c is SP in the key line grammar: an ASCII
// space. Tabs are not separators (spec rev 13): the fields holding key
// lines are str≤n, which forbids TAB.
func isSSHSpace(c byte) bool { return c == ' ' }

// splitSSHField returns the field at the start of s and what follows its
// separator. The separator is one or more SP; rest is "" when s has no
// separator.
func splitSSHField(s string) (field, rest string, sep bool) {
	i := strings.IndexByte(s, ' ')
	if i < 0 {
		return s, "", false
	}
	field, rest = s[:i], s[i:]
	for rest != "" && isSSHSpace(rest[0]) {
		rest = rest[1:]
	}
	return field, rest, true
}

// ParseSSHKeyLine parses an OpenSSH authorized_keys line and returns the
// key's wire blob. The grammar is ASCII only: type SP base64 [SP comment],
// where SP is one or more ASCII spaces (§6.5, rev 13). The line has
// no leading or trailing whitespace, no options prefix and no second
// record, and type equals the type encoded in the blob. Every error wraps
// ErrSSHKeyLine.
func ParseSSHKeyLine(line string) ([]byte, error) {
	if len(line) > maxSSHKeyLine {
		return nil, fmt.Errorf("%w: longer than %d bytes", ErrSSHKeyLine, maxSSHKeyLine)
	}
	for i := 0; i < len(line); i++ {
		c := line[i]
		if c >= 0x80 {
			return nil, fmt.Errorf("%w: not ASCII", ErrSSHKeyLine)
		}
		// Control characters, including TAB and the LF of a second record.
		if c < 0x20 || c == 0x7f {
			return nil, fmt.Errorf("%w: contains a control character", ErrSSHKeyLine)
		}
	}
	if line == "" || isSSHSpace(line[0]) || isSSHSpace(line[len(line)-1]) {
		return nil, fmt.Errorf("%w: empty, or leading or trailing whitespace", ErrSSHKeyLine)
	}
	typ, rest, _ := splitSSHField(line)
	b64, _, _ := splitSSHField(rest)
	if b64 == "" {
		return nil, fmt.Errorf("%w: no key blob", ErrSSHKeyLine)
	}
	blob, err := base64.StdEncoding.Strict().DecodeString(b64)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrSSHKeyLine, err)
	}
	pk, err := ssh.ParsePublicKey(blob)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrSSHKeyLine, err)
	}
	// An options prefix puts the options where the type belongs, so it
	// fails here too.
	if pk.Type() != typ {
		return nil, fmt.Errorf("%w: type does not match its blob", ErrSSHKeyLine)
	}
	return blob, nil
}

// SSHFingerprint returns ssh_pk_fp for an OpenSSH public-key line: "SHA256:"
// and the unpadded standard base64 of the SHA-256 of the public-key wire
// blob, which is OpenSSH's format (§10.3).
func SSHFingerprint(line string) (string, error) {
	blob, err := ParseSSHKeyLine(line)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(blob)
	return "SHA256:" + base64.RawStdEncoding.EncodeToString(sum[:]), nil
}

// checkSSHKeyLine is the §6.5 rule for one key line field. It returns the
// key's wire blob.
func checkSSHKeyLine(field, line string) ([]byte, error) {
	blob, err := ParseSSHKeyLine(line)
	if err != nil {
		return nil, &SchemaError{Field: field, Reason: err.Error(), Err: ErrSSHKeyLine}
	}
	return blob, nil
}

// sshKeyAlgo maps key_type to the OpenSSH key algorithm (§6.5, rev 12).
var sshKeyAlgo = map[string]string{
	"ed25519":    ssh.KeyAlgoED25519,
	"ecdsa-p256": ssh.KeyAlgoECDSA256,
	"rsa":        ssh.KeyAlgoRSA,
}

const opensshPEMType = "OPENSSH PRIVATE KEY"

// checkPrivateKey is the §6.5 rule for key.private_key (rev 12): an
// unencrypted OpenSSH private key whose public key is pubBlob (the
// public_key's wire blob) and whose algorithm matches keyType. Every error
// wraps ErrSSHPrivateKey. The parsed key material is zeroed where Go allows
// it.
func checkPrivateKey(keyType, privateKey string, pubBlob []byte) error {
	bad := func(reason string) error {
		return &SchemaError{Field: "private_key", Reason: reason, Err: ErrSSHPrivateKey}
	}
	if privateKey == "" {
		return bad("is empty")
	}
	// One OpenSSH PEM block and nothing else: pem.Decode would skip text
	// before it, and ssh.ParseRawPrivateKey also takes PKCS#1, PKCS#8 and
	// SEC 1 keys.
	if !strings.HasPrefix(privateKey, "-----BEGIN "+opensshPEMType+"-----") {
		return bad("is not an OpenSSH PEM block")
	}
	raw := []byte(privateKey)
	defer clear(raw)
	block, rest := pem.Decode(raw)
	if block == nil || block.Type != opensshPEMType || len(block.Headers) != 0 || len(bytes.TrimSpace(rest)) != 0 {
		if block != nil {
			clear(block.Bytes)
		}
		return bad("is not a single OpenSSH PEM block")
	}
	clear(block.Bytes)
	key, err := ssh.ParseRawPrivateKey(raw)
	var missing *ssh.PassphraseMissingError
	switch {
	case errors.As(err, &missing):
		return bad("is encrypted")
	case err != nil:
		return bad(err.Error())
	}
	defer zeroPrivateKey(key)
	var pub any
	switch k := key.(type) {
	case *ed25519.PrivateKey:
		// Derive the public key from the seed rather than trusting the
		// stored public half. The RSA and ECDSA parsers check their keys.
		seed := k.Seed()
		d := ed25519.NewKeyFromSeed(seed)
		clear(seed)
		defer clear(d)
		if !bytes.Equal(d[ed25519.SeedSize:], (*k)[ed25519.SeedSize:]) {
			return bad("Ed25519 seed does not match its public half")
		}
		pub = d.Public()
	case *ecdsa.PrivateKey:
		pub = &k.PublicKey
	case *rsa.PrivateKey:
		pub = &k.PublicKey
	default:
		return bad(fmt.Sprintf("unsupported key %T", key))
	}
	pk, err := ssh.NewPublicKey(pub)
	if err != nil {
		return bad(err.Error())
	}
	if want := sshKeyAlgo[keyType]; pk.Type() != want {
		return bad(fmt.Sprintf("is a %s key, key_type %q needs %s", pk.Type(), keyType, want))
	}
	if !bytes.Equal(pk.Marshal(), pubBlob) {
		return bad("does not match public_key")
	}
	return nil
}

// zeroPrivateKey overwrites the secret parts of a parsed private key.
// big.Int has no wipe, so this clears the words its Bits share.
func zeroPrivateKey(key any) {
	zeroInt := func(n *big.Int) {
		if n != nil {
			clear(n.Bits())
		}
	}
	switch k := key.(type) {
	case *ed25519.PrivateKey:
		clear(*k)
	case *ecdsa.PrivateKey:
		zeroInt(k.D)
	case *rsa.PrivateKey:
		zeroInt(k.D)
		for _, p := range k.Primes {
			zeroInt(p)
		}
		zeroInt(k.Precomputed.Dp)
		zeroInt(k.Precomputed.Dq)
		zeroInt(k.Precomputed.Qinv)
	}
}
