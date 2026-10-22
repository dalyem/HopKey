package crypto

import (
	"crypto/rand"
	"errors"
	"fmt"
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

// NewSecretKey returns a Secret Key with 130 random secret bits and a
// random 6-symbol public hint (§12). This is what signup uses.
func NewSecretKey() (SecretKey, error) {
	var hint [secretKeyHintLen]byte
	if _, err := rand.Read(hint[:]); err != nil {
		return SecretKey{}, err
	}
	for i, b := range hint {
		hint[i] = crockfordAlphabet[b&31]
	}
	return GenerateSecretKey(string(hint[:]))
}

// GenerateSecretKey returns a Secret Key with 130 random secret bits and
// the given hint, which must be 6 Crockford base32 symbols. §12 draws the
// hint at random at signup; NewSecretKey does that.
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
// symbols vals, read as a base-32 number (§12).
func checkSymbol(vals []int) byte {
	m := 0
	for _, v := range vals {
		m = (m*32 + v) % 37
	}
	return crockfordCheckSymbols[m]
}

// checkSymbolText returns the symbols of s followed by their check symbol.
func checkSymbolText(s string) string {
	vals := make([]int, len(s))
	for i := range len(s) {
		vals[i] = crockfordValue(s[i])
	}
	return s + string(checkSymbol(vals))
}

// String returns the text form H1-HHHHHH-SSSSSS-SSSSS-SSSSS-SSSSS-SSSSSC
// (§12): the hint, then the secret in groups of 6, 5, 5, 5 and 5, with the
// check symbol ending the last group.
func (k SecretKey) String() string {
	s := checkSymbolText(k.secretSymbols())
	return secretKeyPrefix + "-" + k.Hint + "-" + s[0:6] + "-" + s[6:11] + "-" + s[11:16] + "-" +
		s[16:21] + "-" + s[21:]
}

// parseKitText applies the §12 parsing rules shared by the Secret Key and
// the Recovery Key: hyphens are ignored, case does not matter, I and L
// read as 1 and O as 0. The text must be prefix (a letter, then "1"),
// then nPlain plain symbols, then nChecked symbols followed by their check
// symbol. It returns the plain symbols in canonical form and the values of
// the checked symbols. The caller clears vals.
func parseKitText(text string, prefix byte, nPlain, nChecked int, bad error) (plain string, vals []int, err error) {
	var b []byte
	for i := 0; i < len(text); i++ {
		if text[i] != '-' {
			b = append(b, text[i])
		}
	}
	defer clear(b)
	if len(b) != 2+nPlain+nChecked+1 {
		return "", nil, bad
	}
	if c := b[0] &^ 0x20; c != prefix || crockfordValue(b[1]) != 1 {
		return "", nil, bad
	}
	b = b[2:]
	p := make([]byte, nPlain)
	for i := range nPlain {
		v := crockfordValue(b[i])
		if v < 0 {
			return "", nil, bad
		}
		p[i] = crockfordAlphabet[v]
	}
	b = b[nPlain:]
	vals = make([]int, nChecked)
	for i := range nChecked {
		vals[i] = crockfordValue(b[i])
		if vals[i] < 0 {
			clear(vals)
			return "", nil, bad
		}
	}
	c := b[nChecked]
	if 'a' <= c && c <= 'z' {
		c -= 'a' - 'A'
	}
	if v := crockfordValue(c); v >= 0 {
		c = crockfordAlphabet[v]
	}
	if c != checkSymbol(vals) {
		clear(vals)
		return "", nil, fmt.Errorf("%w: check symbol does not match", bad)
	}
	return string(p), vals, nil
}

// ParseSecretKey reads the text form: case-insensitive, hyphens ignored,
// I and L read as 1, O as 0, nonzero padding bits rejected and the check
// symbol verified (§12).
func ParseSecretKey(text string) (SecretKey, error) {
	hint, vals, err := parseKitText(text, 'H', secretKeyHintLen, secretKeySymbols, ErrBadSecretKey)
	if err != nil {
		return SecretKey{}, err
	}
	defer clear(vals)
	k := SecretKey{Hint: hint}
	sk, overflow := crockfordDecode(vals, secretKeyTopZeros, secretKeyBytes)
	defer clear(sk)
	if overflow != 0 {
		return SecretKey{}, ErrBadSecretKey
	}
	copy(k.SK17[:], sk)
	return k, nil
}
