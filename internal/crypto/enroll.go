package crypto

import (
	"bytes"
	"crypto/ed25519"
	"crypto/hpke"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/dalyem/hopkey/internal/canonjson"
	"github.com/dalyem/hopkey/internal/model"
)

// Nonce length for nA and nD (§7).
const EnrollNonceSize = 32

// EnrollCommit is commit (D→A): {"v":1,"c":h}.
type EnrollCommit struct {
	V int  `json:"v"`
	C Hash `json:"c"`
}

// EnrollChal is chal (A→D).
type EnrollChal struct {
	V                int      `json:"v"`
	EnrollID         model.ID `json:"enroll_id"`
	NA               []byte   `json:"nA"`
	AccountID        model.ID `json:"account_id"`
	ApproverDeviceID model.ID `json:"approver_device_id"`
	AcctSigFp        Hash     `json:"acct_sig_fp"`
	AKV              uint32   `json:"akv"`
}

// EnrollOpen is open (D→A).
type EnrollOpen struct {
	V     int    `json:"v"`
	KEMPK []byte `json:"kem_pk"`
	SigPK []byte `json:"sig_pk"`
	ND    []byte `json:"nD"`
	Name  string `json:"name"`
}

// EnrollDelivery is the plaintext A seals to D after committing the
// device_add: {"v":1,"cert","cert_sig","unlock","anchor_seq","anchor_h"}.
// anchor_seq and anchor_h identify the genesis or checkpoint entry for the
// current akv, not the enrollment entry.
type EnrollDelivery struct {
	V         int          `json:"v"`
	Cert      Cert         `json:"cert"`
	CertSig   []byte       `json:"cert_sig"`
	Unlock    HPKEEnvelope `json:"unlock"`
	AnchorSeq uint64       `json:"anchor_seq,string"`
	AnchorH   Hash         `json:"anchor_h"`
}

// Validate checks the closed schema.
func (m *EnrollCommit) Validate() error {
	if m.V != Version {
		return ErrUnsupported
	}
	return nil
}

// Validate checks the closed schema.
func (m *EnrollChal) Validate() error {
	if m.V != Version {
		return ErrUnsupported
	}
	if err := CheckID("enroll_id", m.EnrollID); err != nil {
		return err
	}
	if len(m.NA) != EnrollNonceSize {
		return schemaErr("nA", "must be %d bytes", EnrollNonceSize)
	}
	if err := CheckID("account_id", m.AccountID); err != nil {
		return err
	}
	return CheckID("approver_device_id", m.ApproverDeviceID)
}

// Validate checks the closed schema and that both keys decode.
func (m *EnrollOpen) Validate() error {
	if m.V != Version {
		return ErrUnsupported
	}
	if _, err := ParseKEMPublicKey(m.KEMPK); err != nil {
		return schemaErr("kem_pk", "not an X-Wing public key")
	}
	if len(m.SigPK) != ed25519.PublicKeySize {
		return schemaErr("sig_pk", "not an Ed25519 public key")
	}
	if len(m.ND) != EnrollNonceSize {
		return schemaErr("nD", "must be %d bytes", EnrollNonceSize)
	}
	return CheckStr("name", m.Name, 64)
}

// Validate checks the closed schema.
func (m *EnrollDelivery) Validate() error {
	if m.V != Version {
		return ErrUnsupported
	}
	if err := m.Cert.Validate(); err != nil {
		return err
	}
	if len(m.CertSig) != ed25519.SignatureSize {
		return schemaErr("cert_sig", "not an Ed25519 signature")
	}
	return m.Unlock.Check()
}

// ParseEnrollMessage decodes one of the §7 messages strictly and validates
// it. v must point to an EnrollCommit, EnrollChal, EnrollOpen or
// EnrollDelivery.
func ParseEnrollMessage(b []byte, v interface{ Validate() error }) error {
	if err := canonjson.Unmarshal(b, v); err != nil {
		return err
	}
	return v.Validate()
}

// Commitment returns c = SHA-256(lp("hopkey/v1/enroll-commit") || u32(1)
// || lp(kem_pk) || lp(sig_pk) || lp(nD) || lp(name)).
func Commitment(o *EnrollOpen) Hash {
	return sha256.Sum256(cat(lps(LabelEnrollCommit), U32(1), LP(o.KEMPK), LP(o.SigPK), LP(o.ND), lps(o.Name)))
}

// Transcript returns T, built from the decoded typed fields (never from
// received JSON bytes):
//
//	T = lp("hopkey/v1/enroll-transcript") || u32(1) || lp(enroll_id) || lp(c)
//	    || lp(nA) || lp(account_id) || lp(approver_device_id) || lp(acct_sig_fp)
//	    || u32(akv) || lp(kem_pk) || lp(sig_pk) || lp(nD) || lp(name)
//
// Each id is its 16 decoded bytes, each h its 32 decoded bytes, each b64
// its decoded bytes and name its UTF-8 bytes.
func Transcript(c Hash, ch *EnrollChal, o *EnrollOpen) []byte {
	return cat(lps(LabelEnrollTranscript), U32(1), LP(ch.EnrollID[:]), LP(c[:]), LP(ch.NA),
		LP(ch.AccountID[:]), LP(ch.ApproverDeviceID[:]), LP(ch.AcctSigFp[:]), U32(ch.AKV),
		LP(o.KEMPK), LP(o.SigPK), LP(o.ND), lps(o.Name))
}

// TranscriptHash is SHA-256(T), the value of Cert.enroll_transcript.
func TranscriptHash(t []byte) Hash { return sha256.Sum256(t) }

// ErrSASAbort means none of the 16 words was below 4,200,000,000 and the
// attempt must abort (§7).
var ErrSASAbort = errors.New("crypto: SAS derivation found no usable word; the attempt aborts")

// SAS returns render8(HKDF(ikm=SHA-256(T), salt=empty,
// info=lp("hopkey/v1/enroll-sas"), 64)).
func SAS(t []byte) (string, error) {
	th := TranscriptHash(t)
	okm, err := hkdfKey(th[:], nil, lps(LabelEnrollSAS), 64)
	if err != nil {
		return "", err
	}
	return render8(okm)
}

// render8 reads 4-byte big-endian words in order and takes the first
// w < 4,200,000,000, returning w mod 10^8 as 8 digits with leading zeros.
func render8(b []byte) (string, error) {
	for i := 0; i+4 <= len(b); i += 4 {
		w := binary.BigEndian.Uint32(b[i:])
		if w < 4_200_000_000 {
			return fmt.Sprintf("%08d", w%100_000_000), nil
		}
	}
	return "", ErrSASAbort
}

func deliverInfo(th Hash) []byte { return cat(lps(LabelEnrollDeliver), LP(th[:])) }

// SealDelivery returns HPKE.Seal(kem_pk, info = lp("hopkey/v1/enroll-deliver")
// || lp(SHA-256(T)), aad = empty, pt = JCS(delivery)).
func SealDelivery(devKEMPK []byte, th Hash, d *EnrollDelivery) (HPKEEnvelope, error) {
	if err := d.Validate(); err != nil {
		return HPKEEnvelope{}, err
	}
	pt, err := canonjson.Marshal(d)
	if err != nil {
		return HPKEEnvelope{}, err
	}
	defer clear(pt)
	return SealHPKE(devKEMPK, deliverInfo(th), nil, pt)
}

// OpenDelivery opens a delivery envelope and decodes it under its closed
// schema. It does not check its contents against the enrollment; see
// VerifyDelivery.
func OpenDelivery(devKEM hpke.PrivateKey, th Hash, e HPKEEnvelope) (*EnrollDelivery, error) {
	pt, err := OpenHPKE(devKEM, e, deliverInfo(th), nil)
	if err != nil {
		return nil, err
	}
	defer clear(pt)
	var d EnrollDelivery
	if err := ParseEnrollMessage(pt, &d); err != nil {
		return nil, err
	}
	return &d, nil
}

// VerifiedDelivery is what D learns from a delivery that passed §7 step 6.
type VerifiedDelivery struct {
	Cert      Cert
	CertSig   []byte
	Unlock    HPKEEnvelope
	Account   *AccountKeys
	AnchorSeq uint64
	AnchorH   Hash
}

// ErrCertName means the delivered certificate names the device differently
// from the open message (§7 step 6 requires Cert.name = open.name).
var ErrCertName = errors.New("crypto: certificate name differs from the enrolled device name")

// VerifyDelivery runs D's delivery checks (§7 step 6): it opens the
// delivery and the unlock blob, derives the account public keys from
// acct_priv and requires fp_sig = chal.acct_sig_fp, akv = chal.akv and
// account_id = chal.account_id, the certificate to bind D's own keys,
// SHA-256(T) and open.name, and cert_sig to verify under the derived
// signing key. open.name is read back from T, which ends in lp(name). The
// anchor checks that follow belong to the vault log.
func VerifyDelivery(devKEM hpke.PrivateKey, devSigPK []byte, ch *EnrollChal, t []byte, e HPKEEnvelope) (*VerifiedDelivery, error) {
	name, err := transcriptName(t)
	if err != nil {
		return nil, err
	}
	return verifyDelivery(devKEM, devSigPK, ch, name, TranscriptHash(t), e)
}

// transcriptName returns the name field of T: every field before it has a
// fixed layout (§7), and lp(name) is the last.
func transcriptName(t []byte) (string, error) {
	errT := errors.New("crypto: malformed enrollment transcript")
	r := t
	lp := func() ([]byte, bool) {
		if len(r) < 4 {
			return nil, false
		}
		n := binary.BigEndian.Uint32(r)
		if uint64(len(r)-4) < uint64(n) {
			return nil, false
		}
		f := r[4 : 4+n]
		r = r[4+n:]
		return f, true
	}
	u32 := func() bool {
		if len(r) < 4 {
			return false
		}
		r = r[4:]
		return true
	}
	// label, u32(1), enroll_id, c, nA, account_id, approver_device_id,
	// acct_sig_fp, u32(akv), kem_pk, sig_pk, nD, name.
	label, ok := lp()
	if !ok || string(label) != LabelEnrollTranscript || !u32() {
		return "", errT
	}
	for range 6 {
		if _, ok := lp(); !ok {
			return "", errT
		}
	}
	if !u32() {
		return "", errT
	}
	for range 3 {
		if _, ok := lp(); !ok {
			return "", errT
		}
	}
	name, ok := lp()
	if !ok || len(r) != 0 {
		return "", errT
	}
	return string(name), nil
}

func verifyDelivery(devKEM hpke.PrivateKey, devSigPK []byte, ch *EnrollChal, name string, th Hash, e HPKEEnvelope) (*VerifiedDelivery, error) {
	d, err := OpenDelivery(devKEM, th, e)
	if err != nil {
		return nil, err
	}
	acct, err := OpenUnlock(devKEM, &d.Cert, d.Unlock)
	if err != nil {
		return nil, err
	}
	pin := acct.Pin()
	if !pin.FpSig.Equal(ch.AcctSigFp) || pin.AKV != ch.AKV || pin.AccountID != ch.AccountID {
		acct.Zero()
		return nil, ErrAccountMismatch
	}
	if err := CheckCertKeys(&d.Cert, devKEM.PublicKey().Bytes(), devSigPK); err != nil {
		acct.Zero()
		return nil, err
	}
	if !d.Cert.EnrollTranscript.Equal(th) {
		acct.Zero()
		return nil, errors.New("crypto: certificate does not bind this enrollment transcript")
	}
	if d.Cert.Name != name {
		acct.Zero()
		return nil, ErrCertName
	}
	if err := VerifyCert(acct.Public().SigPK, &d.Cert, d.CertSig); err != nil {
		acct.Zero()
		return nil, err
	}
	return &VerifiedDelivery{
		Cert: d.Cert, CertSig: d.CertSig, Unlock: d.Unlock, Account: acct,
		AnchorSeq: d.AnchorSeq, AnchorH: d.AnchorH,
	}, nil
}

// clone returns a deep copy.
func (m *EnrollChal) clone() *EnrollChal {
	c := *m
	c.NA = bytes.Clone(m.NA)
	return &c
}

// clone returns a deep copy.
func (m *EnrollOpen) clone() *EnrollOpen {
	c := *m
	c.KEMPK = bytes.Clone(m.KEMPK)
	c.SigPK = bytes.Clone(m.SigPK)
	c.ND = bytes.Clone(m.ND)
	return &c
}
