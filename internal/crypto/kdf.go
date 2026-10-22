package crypto

import (
	"bytes"
	"errors"
	"fmt"
	"unicode/utf8"

	"golang.org/x/crypto/argon2"
	"golang.org/x/text/unicode/norm"

	"github.com/dalyem/hopkey/internal/model"
)

// KDFParams is an Argon2id parameter tuple tagged with its kdf_version.
type KDFParams struct {
	Version   uint32
	Time      uint32 // t
	MemoryKiB uint32 // m
	Threads   uint8  // p
	KeyLen    uint32
}

// KDFv1 is the only tuple kdf_version 1 allows (§4.1).
var KDFv1 = KDFParams{Version: 1, Time: 3, MemoryKiB: 65536, Threads: 4, KeyLen: 32}

// SaltSize is the Argon2id salt length (salt16, §4.1; b64(16) in creds).
const SaltSize = 16

// Password bounds after normalization, in bytes (§4.1).
const (
	MinPasswordBytes = 8
	MaxPasswordBytes = 1024
)

// ErrKDFParams means a KDF tuple other than KDFv1 was offered.
var ErrKDFParams = errors.New("crypto: KDF parameters are not the kdf_version 1 profile")

// CheckKDFParams accepts exactly KDFv1. Callers must run it before any
// Argon2 memory is allocated; DeriveLoginKeys does.
func CheckKDFParams(p KDFParams) error {
	if p != KDFv1 {
		return ErrKDFParams
	}
	return nil
}

// UnicodeVersion is the Unicode version of the NFKC tables compiled in.
//
// SPEC GAP (§4.1): the spec pins NFKC to Unicode 15.0.0 via
// golang.org/x/text/unicode/norm. That combination does not exist for this
// module: x/crypto v0.58.0 (and every version from v0.52.0, the spec's
// minimum) requires x/text v0.37.0 or later, and those versions select their
// Unicode 17.0.0 tables under Go 1.27 (build tag go1.27). The spec's own Go
// minimum is 1.27. This code uses whatever norm provides and a test pins
// the value to "17.0.0" so a silent change is caught. Normalization of
// characters assigned in 15.0.0 is stable across versions; only passwords
// containing code points first assigned in 16.0 or 17.0 can differ.
const UnicodeVersion = norm.Version

// NormalizePassword returns pw' = NFKC(password) after checking that the
// input is valid UTF-8 and that the result is 8 to 1024 bytes. Nothing is
// trimmed.
func NormalizePassword(password []byte) ([]byte, error) {
	if !utf8.Valid(password) {
		return nil, errors.New("crypto: password is not valid UTF-8")
	}
	// norm returns its input unchanged when it is already normalized, so
	// work on a copy: the caller's buffer is never aliased or cleared.
	in := bytes.Clone(password)
	out := norm.NFKC.Bytes(in)
	pw := bytes.Clone(out)
	clear(in)
	clear(out)
	if len(pw) < MinPasswordBytes || len(pw) > MaxPasswordBytes {
		clear(pw)
		return nil, fmt.Errorf("crypto: password must be %d to %d bytes after normalization", MinPasswordBytes, MaxPasswordBytes)
	}
	return pw, nil
}

// LoginKeys are the two outputs of the kdf_version 1 derivation.
type LoginKeys struct {
	AuthKey [32]byte // sent to the server over TLS; it stores SHA-256(authKey)
	EncKey  SymKey   // opens pw_blob
}

// Zero clears both keys.
func (k *LoginKeys) Zero() {
	clear(k.AuthKey[:])
	k.EncKey.Zero()
}

// AuthHash is SHA-256(authKey), the creds.auth_sha256 value.
func (k *LoginKeys) AuthHash() Hash { return SHA256(k.AuthKey[:]) }

// DeriveLoginKeys runs §4.1:
//
//	pwKey   = Argon2id(pw', salt16, t=3, m=65536 KiB, p=4, len=32)
//	skKey   = HKDF(ikm=SK17, salt=account_id_bytes, info=lp("hopkey/v1/secret-key"))
//	MUK     = HKDF(ikm=pwKey || skKey, salt=account_id_bytes, info=lp("hopkey/v1/muk") || u32(1))
//	authKey = HKDF-Expand(MUK, lp("hopkey/v1/auth"), 32)
//	encKey  = HKDF-Expand(MUK, lp("hopkey/v1/enc"), 32)
//
// The parameter tuple and all inputs are checked before Argon2 runs.
func DeriveLoginKeys(password []byte, salt []byte, sk *SecretKey, accountID model.ID, params KDFParams) (*LoginKeys, error) {
	if err := CheckKDFParams(params); err != nil {
		return nil, err
	}
	if len(salt) != SaltSize {
		return nil, fmt.Errorf("crypto: salt must be %d bytes", SaltSize)
	}
	if sk == nil || sk.SK17[0]>>(8-secretKeyTopZeros) != 0 {
		return nil, errors.New("crypto: bad Secret Key")
	}
	if accountID.IsZero() {
		return nil, errors.New("crypto: zero account ID")
	}
	pw, err := NormalizePassword(password)
	if err != nil {
		return nil, err
	}
	pwKey := argon2.IDKey(pw, salt, params.Time, params.MemoryKiB, params.Threads, params.KeyLen)
	clear(pw)
	defer clear(pwKey)
	skKey, err := deriveSKKey(sk, accountID)
	if err != nil {
		return nil, err
	}
	defer clear(skKey)
	return deriveFromParts(pwKey, skKey, accountID)
}

func deriveSKKey(sk *SecretKey, accountID model.ID) ([]byte, error) {
	return hkdf32(sk.SK17[:], accountID[:], lps(LabelSecretKey))
}

func deriveFromParts(pwKey, skKey []byte, accountID model.ID) (*LoginKeys, error) {
	ikm := cat(pwKey, skKey)
	defer clear(ikm)
	muk, err := hkdf32(ikm, accountID[:], cat(lps(LabelMUK), U32(1)))
	if err != nil {
		return nil, err
	}
	defer clear(muk)
	auth, err := hkdfExpand(muk, lps(LabelAuth), 32)
	if err != nil {
		return nil, err
	}
	enc, err := hkdfExpand(muk, lps(LabelEnc), 32)
	if err != nil {
		clear(auth)
		return nil, err
	}
	var k LoginKeys
	copy(k.AuthKey[:], auth)
	copy(k.EncKey[:], enc)
	clear(auth)
	clear(enc)
	return &k, nil
}
