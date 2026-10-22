package crypto

import (
	"crypto/hkdf"
	"crypto/hpke"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"

	"golang.org/x/crypto/chacha20poly1305"

	"github.com/dalyem/hopkey/internal/canonjson"
)

// KeySize is the length of every symmetric key: VK, IK, encKey, rkKey (§2).
const KeySize = 32

// SymKey is a 32-byte XChaCha20-Poly1305 key.
type SymKey [KeySize]byte

// Zero clears the key.
func (k *SymKey) Zero() { clear(k[:]) }

// NewSymKey returns a random key.
func NewSymKey() (SymKey, error) {
	var k SymKey
	_, err := rand.Read(k[:])
	return k, err
}

// hkdfKey is HKDF-SHA256 (extract and expand) with length n.
func hkdfKey(ikm, salt, info []byte, n int) ([]byte, error) {
	return hkdf.Key(sha256.New, ikm, salt, string(info), n)
}

// hkdfExpand is HKDF-Expand with SHA-256.
func hkdfExpand(prk, info []byte, n int) ([]byte, error) {
	return hkdf.Expand(sha256.New, prk, string(info), n)
}

// hkdf32 is HKDF-SHA256 with the default 32-byte output (§2).
func hkdf32(ikm, salt, info []byte) ([]byte, error) { return hkdfKey(ikm, salt, info, 32) }

// AEADEnvelope is {"v":1,"suite":1,"nonce":b64,"ct":b64} (§3).
type AEADEnvelope struct {
	V     int    `json:"v"`
	Suite int    `json:"suite"`
	Nonce []byte `json:"nonce"`
	CT    []byte `json:"ct"`
}

// HPKEEnvelope is {"v":1,"suite":1,"enc":b64,"ct":b64} (§3).
type HPKEEnvelope struct {
	V     int    `json:"v"`
	Suite int    `json:"suite"`
	Enc   []byte `json:"enc"`
	CT    []byte `json:"ct"`
}

// ErrUnsupported means an object names a format version or suite other
// than 1.
var ErrUnsupported = errors.New("crypto: unsupported version or suite")

// ErrDecrypt means authenticated decryption failed. It deliberately says
// nothing about which input was wrong.
var ErrDecrypt = errors.New("crypto: decryption failed")

// Check verifies the envelope's version, suite and nonce length.
func (e AEADEnvelope) Check() error {
	if e.V != Version || e.Suite != Suite {
		return ErrUnsupported
	}
	if len(e.Nonce) != chacha20poly1305.NonceSizeX {
		return fmt.Errorf("crypto: AEAD nonce is %d bytes, want %d", len(e.Nonce), chacha20poly1305.NonceSizeX)
	}
	if len(e.CT) < chacha20poly1305.Overhead {
		return errors.New("crypto: AEAD ciphertext too short")
	}
	return nil
}

// Check verifies the envelope's version and suite.
func (e HPKEEnvelope) Check() error {
	if e.V != Version || e.Suite != Suite {
		return ErrUnsupported
	}
	return nil
}

// Digest returns SHA-256(JCS(envelope)) (§3).
func (e AEADEnvelope) Digest() (Hash, error) { return envelopeDigest(e) }

// Digest returns SHA-256(JCS(envelope)) (§3).
func (e HPKEEnvelope) Digest() (Hash, error) { return envelopeDigest(e) }

// JCS returns the canonical encoding of the envelope.
func (e AEADEnvelope) JCS() ([]byte, error) { return canonjson.Marshal(e) }

// JCS returns the canonical encoding of the envelope.
func (e HPKEEnvelope) JCS() ([]byte, error) { return canonjson.Marshal(e) }

func envelopeDigest(e any) (Hash, error) {
	j, err := canonjson.Marshal(e)
	if err != nil {
		return Hash{}, err
	}
	return sha256.Sum256(j), nil
}

// ParseAEADEnvelope decodes and checks an AEAD envelope.
func ParseAEADEnvelope(b []byte) (AEADEnvelope, error) {
	var e AEADEnvelope
	if err := canonjson.Unmarshal(b, &e); err != nil {
		return AEADEnvelope{}, err
	}
	return e, e.Check()
}

// ParseHPKEEnvelope decodes and checks an HPKE envelope.
func ParseHPKEEnvelope(b []byte) (HPKEEnvelope, error) {
	var e HPKEEnvelope
	if err := canonjson.Unmarshal(b, &e); err != nil {
		return HPKEEnvelope{}, err
	}
	return e, e.Check()
}

// SealAEAD encrypts pt under key with XChaCha20-Poly1305 and a random
// 24-byte nonce.
func SealAEAD(key *SymKey, pt, aad []byte) (AEADEnvelope, error) {
	a, err := chacha20poly1305.NewX(key[:])
	if err != nil {
		return AEADEnvelope{}, err
	}
	nonce := make([]byte, chacha20poly1305.NonceSizeX)
	if _, err := rand.Read(nonce); err != nil {
		return AEADEnvelope{}, err
	}
	return AEADEnvelope{V: Version, Suite: Suite, Nonce: nonce, CT: a.Seal(nil, nonce, pt, aad)}, nil
}

// OpenAEAD checks and decrypts an AEAD envelope.
func OpenAEAD(key *SymKey, e AEADEnvelope, aad []byte) ([]byte, error) {
	if err := e.Check(); err != nil {
		return nil, err
	}
	a, err := chacha20poly1305.NewX(key[:])
	if err != nil {
		return nil, err
	}
	pt, err := a.Open(nil, e.Nonce, e.CT, aad)
	if err != nil {
		return nil, ErrDecrypt
	}
	return pt, nil
}

// The HPKE suite (§2): base mode, MLKEM768-X25519 (X-Wing), HKDF-SHA256,
// AES-256-GCM.
func hpkeKEM() hpke.KEM   { return hpke.MLKEM768X25519() }
func hpkeKDF() hpke.KDF   { return hpke.HKDFSHA256() }
func hpkeAEAD() hpke.AEAD { return hpke.AES256GCM() }

// HPKESuiteIDs returns the RFC 9180 identifiers of the suite: KEM, KDF and
// AEAD.
func HPKESuiteIDs() (kem, kdf, aead uint16) {
	return hpkeKEM().ID(), hpkeKDF().ID(), hpkeAEAD().ID()
}

// GenerateKEMKey returns a new X-Wing key pair.
func GenerateKEMKey() (hpke.PrivateKey, error) { return hpkeKEM().GenerateKey() }

// DeriveKEMKey is KEM.DeriveKeyPair(ikm) (RFC 9180 §7.1.3).
func DeriveKEMKey(ikm []byte) (hpke.PrivateKey, error) { return hpkeKEM().DeriveKeyPair(ikm) }

// ParseKEMPrivateKey reads PrivateKey.Bytes() output.
func ParseKEMPrivateKey(b []byte) (hpke.PrivateKey, error) { return hpkeKEM().NewPrivateKey(b) }

// ParseKEMPublicKey reads PublicKey.Bytes() output.
func ParseKEMPublicKey(b []byte) (hpke.PublicKey, error) { return hpkeKEM().NewPublicKey(b) }

// SealHPKE creates one HPKE context for pk and info and calls Seal on it
// exactly once (§2).
func SealHPKE(pk []byte, info, aad, pt []byte) (HPKEEnvelope, error) {
	pub, err := ParseKEMPublicKey(pk)
	if err != nil {
		return HPKEEnvelope{}, fmt.Errorf("crypto: bad KEM public key: %w", err)
	}
	enc, s, err := hpke.NewSender(pub, hpkeKDF(), hpkeAEAD(), info)
	if err != nil {
		return HPKEEnvelope{}, err
	}
	ct, err := s.Seal(aad, pt)
	if err != nil {
		return HPKEEnvelope{}, err
	}
	return HPKEEnvelope{V: Version, Suite: Suite, Enc: enc, CT: ct}, nil
}

// OpenHPKE checks and opens an envelope made by SealHPKE.
func OpenHPKE(sk hpke.PrivateKey, e HPKEEnvelope, info, aad []byte) ([]byte, error) {
	if err := e.Check(); err != nil {
		return nil, err
	}
	if sk == nil || sk.KEM().ID() != hpkeKEM().ID() {
		return nil, errors.New("crypto: KEM private key is not X-Wing")
	}
	r, err := hpke.NewRecipient(e.Enc, sk, hpkeKDF(), hpkeAEAD(), info)
	if err != nil {
		return nil, ErrDecrypt
	}
	pt, err := r.Open(aad, e.CT)
	if err != nil {
		return nil, ErrDecrypt
	}
	return pt, nil
}
