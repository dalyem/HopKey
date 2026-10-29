package store

import (
	"encoding/base64"
	"encoding/hex"
	"strings"

	"github.com/dalyem/hopkey/internal/crypto"
	"github.com/dalyem/hopkey/internal/redact"
)

// AccountSecrets is what this device holds of the account beyond the
// vault's items, while it is unlocked, for the daemon to redact from what
// hop mcp hands an agent (daemon.AccountSecrets): the Secret Key the
// device record keeps, the Secret Key and Recovery Key of a kit not yet
// confirmed, and the device's own key material. Each comes in every form
// it may be printed in. The values stay in the daemon: nothing returns
// them over the control socket. It fails while the store is locked.
func (s *Store) AccountSecrets() ([]redact.Secret, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.sec == nil || s.rec == nil {
		return nil, s.lockedErr()
	}
	var out []redact.Secret
	out = append(out, kitKeyForms(redact.KindVaultSecretKey, s.rec.SecretKey)...)
	if k := s.kit; k != nil {
		out = append(out, kitKeyForms(redact.KindVaultSecretKey, k.SecretKey)...)
		out = append(out, kitKeyForms(redact.KindVaultRecoveryKey, k.RecoveryKey)...)
	}
	// The device record stores these as base64url (canonjson's b64); a
	// tool that prints them may use another encoding.
	for _, b := range [][]byte{s.rec.KEMSK, s.rec.SigSeed, s.rec.LocalKey} {
		if len(b) == 0 {
			continue
		}
		for _, v := range []string{base64.RawURLEncoding.EncodeToString(b), base64.StdEncoding.EncodeToString(b), hex.EncodeToString(b)} {
			out = append(out, redact.Secret{Kind: redact.KindVaultDeviceKey, Value: v})
		}
	}
	return out, nil
}

// kitKeyForms is a Secret Key or Recovery Key as text a remote may print
// it in: as the kit prints it, in lowercase, without its hyphens, and its
// secret symbols alone (without the "H1-" or "R1-" prefix and, for the
// Secret Key, the public hint), each with and without hyphens and in
// either case. It is nothing for text that is not a key: §12 reads the
// keys ignoring case and hyphens, so the canonical form is taken from the
// parsed key.
func kitKeyForms(kind, text string) []redact.Secret {
	var canonical, secret string
	switch kind {
	case redact.KindVaultSecretKey:
		sk, err := crypto.ParseSecretKey(text)
		if err != nil {
			return nil
		}
		canonical = sk.String()
		sk.Zero()
		// H1-HHHHHH-: the prefix and the public hint.
		secret = canonical[len("H1-")+len(sk.Hint)+1:]
	case redact.KindVaultRecoveryKey:
		rk, err := crypto.ParseRecoveryKey(text)
		if err != nil {
			return nil
		}
		canonical = rk.String()
		rk.Zero()
		secret = canonical[len("R1-"):]
	default:
		return nil
	}
	var out []redact.Secret
	for _, v := range []string{canonical, secret} {
		bare := strings.ReplaceAll(v, "-", "")
		for _, f := range []string{v, bare, strings.ToLower(v), strings.ToLower(bare)} {
			out = append(out, redact.Secret{Kind: kind, Value: f})
		}
	}
	return out
}
