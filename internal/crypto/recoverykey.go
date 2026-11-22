package crypto

import (
	"crypto/rand"
	"errors"
	"strings"
)

// Recovery Key text form (§12): "R1-" and 52 Crockford symbols (256 bits
// padded on the right with 4 zero bits) in 13 groups of 4, with the mod-37
// check symbol over the 52 symbols appended to the last group.
const (
	RecoveryKeySize     = 32
	recoveryKeyPrefix   = "R1"
	recoveryKeySymbols  = 52
	recoveryKeyGroupLen = 4
)

// RecoveryKey is RK, 32 bytes from the OS CSPRNG (§12). Treat it as secret.
type RecoveryKey [RecoveryKeySize]byte

// Zero clears the key.
func (k *RecoveryKey) Zero() { clear(k[:]) }

// ErrBadRecoveryKey means a Recovery Key string failed to parse.
var ErrBadRecoveryKey = errors.New("crypto: malformed Recovery Key")

// NewRecoveryKey returns 32 random bytes from the OS CSPRNG.
func NewRecoveryKey() (RecoveryKey, error) {
	var k RecoveryKey
	if _, err := rand.Read(k[:]); err != nil {
		return RecoveryKey{}, err
	}
	return k, nil
}

// String returns the text form R1-XXXX-…-XXXXC: 13 groups of 4 symbols,
// the last followed by the check symbol.
func (k RecoveryKey) String() string {
	s := checkSymbolText(crockfordEncode(k[:], 0, recoveryKeySymbols))
	var b strings.Builder
	b.WriteString(recoveryKeyPrefix)
	for i := 0; i < recoveryKeySymbols; i += recoveryKeyGroupLen {
		b.WriteByte('-')
		end := i + recoveryKeyGroupLen
		if end == recoveryKeySymbols {
			end++ // the check symbol ends the last group
		}
		b.WriteString(s[i:end])
	}
	return b.String()
}

// ParseRecoveryKey reads the text form under the same rules as the Secret
// Key (§12): case-insensitive, hyphens ignored, I and L read as 1, O as 0,
// nonzero padding bits and a bad check symbol rejected.
func ParseRecoveryKey(text string) (RecoveryKey, error) {
	_, vals, err := parseKitText(text, 'R', 0, recoveryKeySymbols, ErrBadRecoveryKey)
	if err != nil {
		return RecoveryKey{}, err
	}
	defer clear(vals)
	raw, overflow := crockfordDecode(vals, 0, RecoveryKeySize)
	defer clear(raw)
	if overflow != 0 {
		return RecoveryKey{}, ErrBadRecoveryKey
	}
	var k RecoveryKey
	copy(k[:], raw)
	return k, nil
}
