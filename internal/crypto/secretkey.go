package crypto

import (
	"crypto/rand"
	"errors"
	"strings"
)

// Secret Key text form (§12).
const (
	secretKeyPrefix   = "H1"
	secretKeyHintLen  = 6
	secretKeySymbols  = 26 // 130 bits
	secretKeyBytes    = 17
	secretKeyTopZeros = 8*secretKeyBytes - 5*secretKeySymbols // 6
)

// SecretKey is the account Secret Key: a public hint and the 130-bit secret
// SK17. The hint is never key material.
type SecretKey struct {
	Hint string               // 6 symbols, uppercase canonical form
	SK17 [secretKeyBytes]byte // big-endian, top 6 bits zero
}

// Zero clears the secret part.
func (k *SecretKey) Zero() { clear(k.SK17[:]) }

// ErrBadSecretKey means a Secret Key string failed to parse.
var ErrBadSecretKey = errors.New("crypto: malformed Secret Key")

// GenerateSecretKey returns a Secret Key with 130 random secret bits and
// the given hint.
//
// SPEC GAP: §12 does not say what the six public-hint characters are, how
// they are chosen, or which alphabet they use. This code requires the
// caller to supply them and accepts Crockford base32 symbols only.
func GenerateSecretKey(hint string) (SecretKey, error) {
	h, ok := normalizeHint(hint)
	if !ok {
		return SecretKey{}, errors.New("crypto: Secret Key hint must be 6 Crockford base32 symbols")
	}
	k := SecretKey{Hint: h}
	if _, err := rand.Read(k.SK17[:]); err != nil {
		return SecretKey{}, err
	}
	k.SK17[0] &= 0xff >> secretKeyTopZeros
	return k, nil
}

func normalizeHint(hint string) (string, bool) {
	if len(hint) != secretKeyHintLen {
		return "", false
	}
	out := make([]byte, secretKeyHintLen)
	for i := 0; i < len(hint); i++ {
		v := crockfordValue(hint[i])
		if v < 0 {
			return "", false
		}
		out[i] = crockfordAlphabet[v]
	}
	return string(out), true
}

// secretSymbols returns the 26 secret symbols of SK17.
func (k SecretKey) secretSymbols() string {
	return crockfordEncode(k.SK17[:], secretKeyTopZeros, secretKeySymbols)
}

// checkSymbol is Crockford's mod-37 check symbol over the value of the
// secret symbols (§12).
func checkSymbol(vals []int) byte {
	m := 0
	for _, v := range vals {
		m = (m*32 + v) % 37
	}
	return crockfordCheckSymbols[m]
}

// String returns the text form.
//
// SPEC GAP: §12 says the text is "grouped with hyphens" but not where the
// hyphens go, and §4.3 has the user type back "the final group". This code
// writes H1-HHHHHH-SSSSSS-SSSSS-SSSSS-SSSSS-SSSSSC (hint, then the secret
// in groups of 6,5,5,5,5 with the check symbol ending the last group) until
// the spec fixes a layout. Parsing ignores hyphens, so the choice does not
// affect what is accepted.
func (k SecretKey) String() string {
	s := k.secretSymbols()
	vals := make([]int, len(s))
	for i := range len(s) {
		vals[i] = crockfordValue(s[i])
	}
	check := checkSymbol(vals)
	return secretKeyPrefix + "-" + k.Hint + "-" + s[0:6] + "-" + s[6:11] + "-" + s[11:16] + "-" +
		s[16:21] + "-" + s[21:26] + string(check)
}

// ParseSecretKey reads the text form: case-insensitive, hyphens ignored,
// I and L read as 1, O as 0, and the check symbol verified.
func ParseSecretKey(text string) (SecretKey, error) {
	var b []byte
	for i := 0; i < len(text); i++ {
		if text[i] != '-' {
			b = append(b, text[i])
		}
	}
	defer clear(b)
	if len(b) != len(secretKeyPrefix)+secretKeyHintLen+secretKeySymbols+1 {
		return SecretKey{}, ErrBadSecretKey
	}
	if !strings.EqualFold(string(b[0:1]), "H") || crockfordValue(b[1]) != 1 {
		return SecretKey{}, ErrBadSecretKey
	}
	b = b[len(secretKeyPrefix):]
	hint, ok := normalizeHint(string(b[:secretKeyHintLen]))
	if !ok {
		return SecretKey{}, ErrBadSecretKey
	}
	b = b[secretKeyHintLen:]
	vals := make([]int, secretKeySymbols)
	defer clear(vals)
	for i := range secretKeySymbols {
		vals[i] = crockfordValue(b[i])
		if vals[i] < 0 {
			return SecretKey{}, ErrBadSecretKey
		}
	}
	c := b[secretKeySymbols]
	if 'a' <= c && c <= 'z' {
		c -= 'a' - 'A'
	}
	if v := crockfordValue(c); v >= 0 {
		c = crockfordAlphabet[v]
	}
	if c != checkSymbol(vals) {
		return SecretKey{}, errors.New("crypto: Secret Key check symbol does not match")
	}
	k := SecretKey{Hint: hint}
	sk, overflow := crockfordDecode(vals, secretKeyTopZeros, secretKeyBytes)
	if overflow != 0 {
		return SecretKey{}, ErrBadSecretKey
	}
	copy(k.SK17[:], sk)
	clear(sk)
	return k, nil
}
