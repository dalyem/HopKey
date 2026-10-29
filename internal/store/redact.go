package store

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"strings"

	"github.com/dalyem/hopkey/internal/crypto"
	"github.com/dalyem/hopkey/internal/model"
	"github.com/dalyem/hopkey/internal/redact"
)

// AccountSecrets is what this device holds of the account beyond what the
// daemon's snapshot shows, while it is unlocked, for the daemon to redact
// from what hop mcp hands an agent (daemon.AccountSecrets): the secrets of
// the vault's items, verified and queued both, the Secret Key the device
// record keeps, the Secret Key and Recovery Key of a kit not yet
// confirmed, and the account's and the device's own key material. Each
// comes in every form it may be printed in. The values stay in the daemon:
// nothing returns them over the control socket. It fails while the store
// is locked.
//
// A queued change shows in the snapshot as what the user asked for, but
// until the server takes it the verified item is the vault's too: a
// replaced password still logs in, and a held change may never commit.
// So both go, read under one hold of the store's lock.
func (s *Store) AccountSecrets() ([]redact.Secret, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.sec == nil || s.rec == nil {
		return nil, s.lockedErr()
	}
	var out []redact.Secret
	for _, p := range s.sec.Items {
		out = append(out, itemSecrets(p.Item)...)
	}
	if s.server {
		unlock, err := s.lockFile()
		if err != nil {
			return nil, err
		}
		ov, err := s.overlayLocked()
		unlock()
		if err != nil {
			return nil, err
		}
		for _, it := range ov.items {
			p, err := plainOf(it)
			if err != nil {
				return nil, err
			}
			out = append(out, itemSecrets(p)...)
		}
	}
	out = append(out, kitKeyForms(redact.KindVaultSecretKey, s.rec.SecretKey)...)
	if k := s.kit; k != nil {
		out = append(out, kitKeyForms(redact.KindVaultSecretKey, k.SecretKey)...)
		out = append(out, kitKeyForms(redact.KindVaultRecoveryKey, k.RecoveryKey)...)
	}
	// The device record stores these as base64url (canonjson's b64); a
	// tool that prints them may use another encoding.
	for _, b := range [][]byte{s.rec.KEMSK, s.rec.SigSeed, s.rec.LocalKey} {
		out = append(out, byteForms(redact.KindVaultDeviceKey, b)...)
	}
	if a := s.sec.Account; a != nil {
		if a.KEM != nil {
			// The KEM's own seed, not a copy: it is not cleared.
			kem, err := a.KEM.Bytes()
			if err != nil {
				return nil, err
			}
			out = append(out, byteForms(redact.KindVaultAccountKey, kem)...)
		}
		if len(a.Sig) == ed25519.PrivateKeySize {
			seed := a.Sig.Seed()
			out = append(out, byteForms(redact.KindVaultAccountKey, seed)...)
			clear(seed)
			out = append(out, byteForms(redact.KindVaultAccountKey, a.Sig)...)
		}
	}
	if s.sec.VK != (crypto.SymKey{}) {
		out = append(out, byteForms(redact.KindVaultAccountKey, s.sec.VK[:])...)
	}
	return out, nil
}

// itemSecrets is the secret fields of a vault item: a credential's
// password, a key's private half.
func itemSecrets(it crypto.Item) []redact.Secret {
	switch v := it.(type) {
	case *model.Credential:
		if v.Password != "" {
			return []redact.Secret{{Kind: redact.KindVaultPassword, Value: v.Password}}
		}
	case *model.Key:
		return redact.PrivateKeyForms(v.PrivateKey)
	}
	return nil
}

// byteForms is key material as a tool may print it: base64url, as
// canonjson stores it, standard base64, and hex. It is nothing for no
// bytes.
func byteForms(kind string, b []byte) []redact.Secret {
	if len(b) == 0 {
		return nil
	}
	var out []redact.Secret
	for _, v := range []string{base64.RawURLEncoding.EncodeToString(b), base64.StdEncoding.EncodeToString(b), hex.EncodeToString(b)} {
		out = append(out, redact.Secret{Kind: kind, Value: v})
	}
	return out
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
