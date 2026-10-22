package crypto

import (
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/ssh"
)

// ErrSSHKeyLine marks a key.public_key or host.host_keys entry that is not
// an OpenSSH authorized_keys line (§6.5, rev 10 item 11). Schema errors for
// those fields wrap it, so callers can tell this rule apart with errors.Is.
var ErrSSHKeyLine = errors.New("not an OpenSSH public-key line")

// ParseSSHKeyLine parses an OpenSSH authorized_keys line without options,
// "<type> <base64> [comment]" (§6.5, rev 10 item 11), and returns the key's
// wire blob. The blob must parse as a key of the named type. Every error
// wraps ErrSSHKeyLine.
func ParseSSHKeyLine(line string) ([]byte, error) {
	f := strings.Fields(line)
	if len(f) < 2 {
		return nil, ErrSSHKeyLine
	}
	blob, err := base64.StdEncoding.DecodeString(f[1])
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrSSHKeyLine, err)
	}
	pk, err := ssh.ParsePublicKey(blob)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrSSHKeyLine, err)
	}
	if pk.Type() != f[0] {
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

// checkSSHKeyLine is the §6.5 rule for one key line field.
func checkSSHKeyLine(field, line string) error {
	if _, err := ParseSSHKeyLine(line); err != nil {
		return &SchemaError{Field: field, Reason: err.Error(), Err: ErrSSHKeyLine}
	}
	return nil
}
