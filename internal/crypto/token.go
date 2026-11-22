package crypto

import (
	"crypto/ed25519"
	"crypto/hpke"
	"crypto/rand"
	"crypto/subtle"
	"errors"

	"github.com/dalyem/hopkey/internal/model"
)

// Token layout (§8.1): raw = grant_id16 || seed32 || fp_sig(acct_sig_pk)[0:16].
const (
	TokenPrefix   = "hop1_"
	tokenRawSize  = 16 + 32 + 16
	tokenSymbols  = 103 // ceil(512/5); 515 bits with 3 zero padding bits
	TokenLength   = len(TokenPrefix) + tokenSymbols
	tokenSeedSize = 32
	tokenFpSize   = 16
)

// Token is a decoded grant token. It holds the seed, so treat it as secret.
type Token struct {
	GrantID model.ID
	Seed    [tokenSeedSize]byte
	AcctFp  [tokenFpSize]byte // fp_sig(acct_sig_pk)[0:16]
}

// Zero clears the seed.
func (t *Token) Zero() { clear(t.Seed[:]) }

// NewToken creates a token with a random seed for grantID, bound to the
// account signing key.
func NewToken(grantID model.ID, acctSigPK ed25519.PublicKey) (*Token, error) {
	if grantID.IsZero() {
		return nil, errors.New("crypto: zero grant ID")
	}
	if len(acctSigPK) != ed25519.PublicKeySize {
		return nil, errors.New("crypto: bad account signing key")
	}
	t := &Token{GrantID: grantID}
	if _, err := rand.Read(t.Seed[:]); err != nil {
		return nil, err
	}
	fp := FpSig(acctSigPK)
	copy(t.AcctFp[:], fp[:tokenFpSize])
	return t, nil
}

func (t *Token) raw() []byte {
	return cat(t.GrantID[:], t.Seed[:], t.AcctFp[:])
}

// String returns "hop1_" || crockford32(raw): 108 characters, uppercase.
func (t *Token) String() string {
	r := t.raw()
	defer clear(r)
	return TokenPrefix + crockfordEncode(r, 0, tokenSymbols)
}

// ErrBadToken means a token string failed to parse.
var ErrBadToken = errors.New("crypto: malformed token")

// ParseToken decodes a token string (§8.1). It requires the exact prefix
// "hop1_", accepts lowercase, reads I and L as 1 and O as 0, and rejects
// hyphens, any other character, a symbol count other than 103 and nonzero
// padding bits.
func ParseToken(s string) (*Token, error) {
	if len(s) < len(TokenPrefix) || s[:len(TokenPrefix)] != TokenPrefix {
		return nil, ErrBadToken
	}
	body := s[len(TokenPrefix):]
	if len(body) != tokenSymbols {
		return nil, ErrBadToken
	}
	vals := make([]int, tokenSymbols)
	defer clear(vals)
	for i := range tokenSymbols {
		v := crockfordValue(body[i])
		if v < 0 {
			return nil, ErrBadToken
		}
		vals[i] = v
	}
	raw, overflow := crockfordDecode(vals, 0, tokenRawSize)
	defer clear(raw)
	if overflow != 0 {
		return nil, ErrBadToken
	}
	t := &Token{}
	copy(t.GrantID[:], raw[0:16])
	copy(t.Seed[:], raw[16:48])
	copy(t.AcctFp[:], raw[48:64])
	return t, nil
}

// Auth returns tAuth = HKDF(seed, salt=grant_id16, info=lp("hopkey/v1/token-auth")).
// The server stores SHA-256(tAuth).
func (t *Token) Auth() ([]byte, error) {
	return hkdf32(t.Seed[:], t.GrantID[:], lps(LabelTokenAuth))
}

// KEMKey returns tKem = MLKEM768X25519().DeriveKeyPair(HKDF(seed,
// salt=grant_id16, info=lp("hopkey/v1/token-kem"))).
func (t *Token) KEMKey() (hpke.PrivateKey, error) {
	ikm, err := hkdf32(t.Seed[:], t.GrantID[:], lps(LabelTokenKEM))
	if err != nil {
		return nil, err
	}
	defer clear(ikm)
	return DeriveKEMKey(ikm)
}

// MatchesAccount reports whether fp_sig(sigPK)[0:16] equals the token's
// account fingerprint.
func (t *Token) MatchesAccount(sigPK []byte) bool {
	fp := FpSig(sigPK)
	return subtle.ConstantTimeCompare(fp[:tokenFpSize], t.AcctFp[:]) == 1
}
