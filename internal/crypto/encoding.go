// Package crypto implements HopKey's cryptographic layer, suite 1, as
// defined by the crypto and protocol spec rev 8
// (https://plan.23d.dev/p/xuu5z9q2). The spec is normative; section
// numbers in comments refer to it. Nothing here goes beyond the spec, and
// places where the spec is silent or contradictory are marked SPEC GAP.
//
// JSON goes through internal/canonjson (RFC 8785, closed schemas). Binary
// members are []byte, which canonjson writes as base64url without padding.
package crypto

import (
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"

	"github.com/dalyem/hopkey/internal/canonjson"
)

// Format version and suite numbers (§2, §3).
const (
	Version = 1
	Suite   = 1
)

// Labels. Every label is "hopkey/v1/…" (§3).
const (
	LabelLogEntry         = "hopkey/v1/log-entry"
	LabelDeviceCert       = "hopkey/v1/device-cert"
	LabelDeviceUnlock     = "hopkey/v1/device-unlock"
	LabelVaultKey         = "hopkey/v1/vault-key"
	LabelItemKey          = "hopkey/v1/item-key"
	LabelItem             = "hopkey/v1/item"
	LabelKEMPK            = "hopkey/v1/kem-pk"
	LabelSigPK            = "hopkey/v1/sig-pk"
	LabelSecretKey        = "hopkey/v1/secret-key"
	LabelMUK              = "hopkey/v1/muk"
	LabelAuth             = "hopkey/v1/auth"
	LabelEnc              = "hopkey/v1/enc"
	LabelPwBlob           = "hopkey/v1/pw-blob"
	LabelRkBlob           = "hopkey/v1/rk-blob"
	LabelRecoveryWrap     = "hopkey/v1/recovery-wrap"
	LabelRecoveryAuth     = "hopkey/v1/recovery-auth"
	LabelEnrollCommit     = "hopkey/v1/enroll-commit"
	LabelEnrollTranscript = "hopkey/v1/enroll-transcript"
	LabelEnrollSAS        = "hopkey/v1/enroll-sas"
	LabelEnrollDeliver    = "hopkey/v1/enroll-deliver"
	LabelTokenAuth        = "hopkey/v1/token-auth"
	LabelTokenKEM         = "hopkey/v1/token-kem"
	LabelGrantBundle      = "hopkey/v1/grant-bundle"
	LabelVKCommit         = "hopkey/v1/vk-commit"
)

const labelPrefix = "hopkey/v1/"

// LP returns lp(x) = u32be(len(x)) || x (§3).
func LP(x []byte) []byte {
	out := make([]byte, 4, 4+len(x))
	binary.BigEndian.PutUint32(out, uint32(len(x)))
	return append(out, x...)
}

// U32 returns the 4-byte big-endian encoding of n, with no length prefix.
func U32(n uint32) []byte { return binary.BigEndian.AppendUint32(nil, n) }

// U64 returns the 8-byte big-endian encoding of n, with no length prefix.
func U64(n uint64) []byte { return binary.BigEndian.AppendUint64(nil, n) }

// cat concatenates byte strings.
func cat(parts ...[]byte) []byte {
	n := 0
	for _, p := range parts {
		n += len(p)
	}
	out := make([]byte, 0, n)
	for _, p := range parts {
		out = append(out, p...)
	}
	return out
}

// lps is lp of a string's UTF-8 bytes.
func lps(s string) []byte { return LP([]byte(s)) }

// Hash is an h value (§3): a SHA-256 digest written as 64 lowercase hex
// characters. It never encodes as "".
type Hash [32]byte

func (h Hash) String() string { return hex.EncodeToString(h[:]) }

func (h Hash) MarshalText() ([]byte, error) { return []byte(h.String()), nil }

func (h *Hash) UnmarshalText(b []byte) error {
	return parseHex(b, h[:])
}

// Equal compares in constant time.
func (h Hash) Equal(o Hash) bool { return subtle.ConstantTimeCompare(h[:], o[:]) == 1 }

// OptHash is an "h | \"\"" value. Presence is kept separately from the
// digest, so "" means absent and any 64-hex value, including all zeros,
// means present. The zero value is absent.
type OptHash struct {
	h   Hash
	set bool
}

// SomeHash returns a present OptHash holding h.
func SomeHash(h Hash) OptHash { return OptHash{h: h, set: true} }

// Get returns the digest and whether it is present.
func (o OptHash) Get() (Hash, bool) { return o.h, o.set }

// IsZero reports whether the value is absent ("").
func (o OptHash) IsZero() bool { return !o.set }

// Equal reports, in constant time, whether o is present and equals h.
func (o OptHash) Equal(h Hash) bool { return o.set && o.h.Equal(h) }

func (o OptHash) MarshalText() ([]byte, error) {
	if !o.set {
		return []byte{}, nil
	}
	return []byte(o.h.String()), nil
}

func (o *OptHash) UnmarshalText(b []byte) error {
	if len(b) == 0 {
		*o = OptHash{}
		return nil
	}
	var x Hash
	if err := parseHex(b, x[:]); err != nil {
		return err
	}
	*o = SomeHash(x)
	return nil
}

func parseHex(b []byte, dst []byte) error {
	if len(b) != 2*len(dst) {
		return fmt.Errorf("crypto: want %d lowercase hex characters, got %d", 2*len(dst), len(b))
	}
	for _, c := range b {
		if !('0' <= c && c <= '9' || 'a' <= c && c <= 'f') {
			return errors.New("crypto: not lowercase hex")
		}
	}
	_, err := hex.Decode(dst, b)
	return err
}

func checkLabel(label string) error {
	if !strings.HasPrefix(label, labelPrefix) || len(label) == len(labelPrefix) {
		return fmt.Errorf("crypto: label %q is not hopkey/v1/…", label)
	}
	return nil
}

// signedMessage is lp(label) || lp(JCS(obj)), the input to D and Sig.
func signedMessage(label string, obj any) ([]byte, error) {
	if err := checkLabel(label); err != nil {
		return nil, err
	}
	j, err := canonjson.Marshal(obj)
	if err != nil {
		return nil, err
	}
	return cat(lps(label), LP(j)), nil
}

// D returns SHA-256(lp(label) || lp(JCS(obj))) (§3).
func D(label string, obj any) (Hash, error) {
	m, err := signedMessage(label, obj)
	if err != nil {
		return Hash{}, err
	}
	return sha256.Sum256(m), nil
}

// Sign returns Sig(key, label, obj) = Ed25519(key, lp(label) || lp(JCS(obj))).
func Sign(key ed25519.PrivateKey, label string, obj any) ([]byte, error) {
	if len(key) != ed25519.PrivateKeySize {
		return nil, errors.New("crypto: bad Ed25519 private key")
	}
	m, err := signedMessage(label, obj)
	if err != nil {
		return nil, err
	}
	return ed25519.Sign(key, m), nil
}

// ErrBadSignature means a signature did not verify.
var ErrBadSignature = errors.New("crypto: signature verification failed")

// Verify checks sig as Sig(pub, label, obj).
func Verify(pub ed25519.PublicKey, label string, obj any, sig []byte) error {
	if len(pub) != ed25519.PublicKeySize || len(sig) != ed25519.SignatureSize {
		return ErrBadSignature
	}
	m, err := signedMessage(label, obj)
	if err != nil {
		return err
	}
	if !ed25519.Verify(pub, m, sig) {
		return ErrBadSignature
	}
	return nil
}

// FpKEM returns fp_kem(pk) = SHA-256(lp("hopkey/v1/kem-pk") || lp(pk)).
func FpKEM(pk []byte) Hash { return sha256.Sum256(cat(lps(LabelKEMPK), LP(pk))) }

// FpSig returns fp_sig(pk) = SHA-256(lp("hopkey/v1/sig-pk") || lp(pk)).
func FpSig(pk []byte) Hash { return sha256.Sum256(cat(lps(LabelSigPK), LP(pk))) }

// VKCommit returns vk_commit(VK) = SHA-256(lp("hopkey/v1/vk-commit") || VK)
// (rev 12). VK is not length-prefixed. Genesis and checkpoint history ops
// publish it; it reveals nothing usable, because VK is 256 random bits.
func VKCommit(vk *SymKey) Hash { return sha256.Sum256(cat(lps(LabelVKCommit), vk[:])) }

// SHA256 is a convenience for stored-hash fields (auth_sha256 and the like).
func SHA256(b []byte) Hash { return sha256.Sum256(b) }

// CheckSecretHash reports, in constant time, whether SHA-256(secret)
// equals stored. Servers use it for authKey, rAuth and tAuth (§4.2, §8.1).
func CheckSecretHash(stored Hash, secret []byte) bool {
	got := sha256.Sum256(secret)
	return subtle.ConstantTimeCompare(got[:], stored[:]) == 1
}

// Zero overwrites b. Go gives no guarantee that copies made by the runtime
// or by the standard library are cleared; this covers the buffers we own.
func Zero(b []byte) { clear(b) }
