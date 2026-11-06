package crypto

import (
	"crypto/ed25519"
	"crypto/hpke"
	"errors"

	"github.com/dalyem/hopkey/internal/model"
)

// Cert is the device certificate (§6.1).
type Cert struct {
	V                int             `json:"v"`
	AccountID        model.ID        `json:"account_id"`
	AKV              uint32          `json:"akv"`
	DeviceID         model.ID        `json:"device_id"`
	Name             string          `json:"name"`
	KEMFp            Hash            `json:"kem_fp"`
	SigFp            Hash            `json:"sig_fp"`
	EnrollTranscript OptHash         `json:"enroll_transcript"`
	IssuedAt         model.Timestamp `json:"issued_at"`
}

// Validate checks the closed schema.
func (c *Cert) Validate() error {
	if c.V != Version {
		return ErrUnsupported
	}
	if err := CheckID("account_id", c.AccountID); err != nil {
		return err
	}
	if err := CheckID("device_id", c.DeviceID); err != nil {
		return err
	}
	if err := CheckStr("name", c.Name, 64); err != nil {
		return err
	}
	if _, err := c.IssuedAt.MarshalText(); err != nil {
		return schemaErr("issued_at", "%v", err)
	}
	return nil
}

// Digest is D("hopkey/v1/device-cert", Cert), the unlock blob's AAD input.
func (c *Cert) Digest() (Hash, error) { return D(LabelDeviceCert, c) }

// SignCert returns cert_sig = Sig(acct_sig[akv], "hopkey/v1/device-cert", Cert).
// The signing keys must belong to the certificate's account and akv.
func SignCert(acct *AccountKeys, c *Cert) ([]byte, error) {
	if err := c.Validate(); err != nil {
		return nil, err
	}
	if acct.AccountID != c.AccountID || acct.AKV != c.AKV {
		return nil, errors.New("crypto: certificate names a different account or akv than the signing key")
	}
	return Sign(acct.Sig, LabelDeviceCert, c)
}

// VerifyCert checks the schema and cert_sig under the account signing key.
func VerifyCert(acctSigPK ed25519.PublicKey, c *Cert, sig []byte) error {
	if err := c.Validate(); err != nil {
		return err
	}
	return Verify(acctSigPK, LabelDeviceCert, c, sig)
}

// CheckCertKeys requires the device_add public keys to match the
// certificate's fingerprints (§6.1).
func CheckCertKeys(c *Cert, kemPK, sigPK []byte) error {
	if !FpKEM(kemPK).Equal(c.KEMFp) || !FpSig(sigPK).Equal(c.SigFp) {
		return errors.New("crypto: device keys do not match the certificate fingerprints")
	}
	return nil
}

// --- §6.2 device unlock blob ---

func unlockInfo(c *Cert) []byte {
	return cat(lps(LabelDeviceUnlock), LP(c.AccountID[:]), LP(c.DeviceID[:]), U32(c.AKV))
}

func unlockAAD(c *Cert) ([]byte, error) {
	d, err := c.Digest()
	if err != nil {
		return nil, err
	}
	return LP(d[:]), nil
}

// SealUnlock returns HPKE.Seal(dev_kem_pk, info = lp("hopkey/v1/device-unlock")
// || lp(account_id_bytes) || lp(device_id_bytes) || u32(akv),
// aad = lp(D("hopkey/v1/device-cert", Cert)), pt = acct_priv) (§6.2).
// devKEMPK must match the certificate's kem_fp.
func SealUnlock(devKEMPK []byte, c *Cert, acct *AccountKeys) (HPKEEnvelope, error) {
	if err := c.Validate(); err != nil {
		return HPKEEnvelope{}, err
	}
	if acct.AccountID != c.AccountID || acct.AKV != c.AKV {
		return HPKEEnvelope{}, errors.New("crypto: certificate names a different account or akv")
	}
	if !FpKEM(devKEMPK).Equal(c.KEMFp) {
		return HPKEEnvelope{}, errors.New("crypto: device KEM key does not match the certificate")
	}
	aad, err := unlockAAD(c)
	if err != nil {
		return HPKEEnvelope{}, err
	}
	pt, err := acct.MarshalAcctPriv()
	if err != nil {
		return HPKEEnvelope{}, err
	}
	defer clear(pt)
	return SealHPKE(devKEMPK, unlockInfo(c), aad, pt)
}

// OpenUnlock opens a device unlock blob and checks that acct_priv names
// the certificate's account and akv. The caller then compares the derived
// public keys with what it expects (§6.2): its pin for a normal unlock, the
// authenticated account_keys of a checkpoint, or the SAS-authenticated
// fingerprint during enrollment. CheckUnlockPin and CheckUnlockKeys do that.
func OpenUnlock(devKEM hpke.PrivateKey, c *Cert, e HPKEEnvelope) (*AccountKeys, error) {
	if err := c.Validate(); err != nil {
		return nil, err
	}
	aad, err := unlockAAD(c)
	if err != nil {
		return nil, err
	}
	pt, err := OpenHPKE(devKEM, e, unlockInfo(c), aad)
	if err != nil {
		return nil, err
	}
	defer clear(pt)
	return ParseAcctPriv(pt, c.AccountID, c.AKV)
}

// ErrAccountMismatch means opened account keys are not the expected ones.
var ErrAccountMismatch = errors.New("crypto: account keys do not match the expected account")

// CheckUnlockPin requires opened account keys to match a pin.
func CheckUnlockPin(k *AccountKeys, pin AccountPin) error {
	if !k.Pin().Equal(pin) {
		return ErrAccountMismatch
	}
	return nil
}

// CheckUnlockKeys requires opened account keys to equal the public keys of
// an authenticated account_keys op.
func CheckUnlockKeys(k *AccountKeys, want AccountPublic) error {
	return CheckUnlockPin(k, want.Pin())
}

// --- §6.3 vault key envelope ---

// VKContext names the vault key being wrapped.
type VKContext struct {
	VaultID   model.ID
	AccountID model.ID
	KV        uint32
	AKV       uint32
}

func (v VKContext) info() []byte {
	return cat(lps(LabelVaultKey), LP(v.VaultID[:]), LP(v.AccountID[:]), U32(v.KV), U32(v.AKV))
}

// SealVK returns HPKE.Seal(acct_kem_pk[akv], info = lp("hopkey/v1/vault-key")
// || lp(vault_id_bytes) || lp(account_id_bytes) || u32(kv) || u32(akv),
// aad = empty, pt = VK[kv]) (§6.3).
func SealVK(acctKEMPK []byte, v VKContext, vk *SymKey) (HPKEEnvelope, error) {
	return SealHPKE(acctKEMPK, v.info(), nil, vk[:])
}

// OpenVK opens a vault key envelope with the account KEM key for v.AKV.
func OpenVK(acct *AccountKeys, v VKContext, e HPKEEnvelope) (SymKey, error) {
	if acct.AccountID != v.AccountID || acct.AKV != v.AKV {
		return SymKey{}, errors.New("crypto: account keys do not match the vault key context")
	}
	pt, err := OpenHPKE(acct.KEM, e, v.info(), nil)
	if err != nil {
		return SymKey{}, err
	}
	defer clear(pt)
	if len(pt) != KeySize {
		return SymKey{}, ErrDecrypt
	}
	var vk SymKey
	copy(vk[:], pt)
	return vk, nil
}

// --- §6.4 items ---

// ItemContext is everything an item's wrap and body AADs bind.
type ItemContext struct {
	AccountID   model.ID
	VaultID     model.ID
	ItemID      model.ID
	Type        model.Type
	ItemVersion uint64
	IV          uint32
	KV          uint32
}

func (c ItemContext) wrapAAD() []byte {
	return cat(lps(LabelItemKey), LP(c.VaultID[:]), LP(c.ItemID[:]), U32(c.KV), U32(c.IV))
}

func (c ItemContext) bodyAAD() []byte {
	return cat(lps(LabelItem), LP(c.AccountID[:]), LP(c.VaultID[:]), LP(c.ItemID[:]),
		lps(string(c.Type)), U32(c.IV), U64(c.ItemVersion))
}

// WrapItemKey returns wrap = AEAD(VK[kv], IK, aad = lp("hopkey/v1/item-key")
// || lp(vault_id_bytes) || lp(item_id_bytes) || u32(kv) || u32(iv)) (§6.4).
func WrapItemKey(vk *SymKey, c ItemContext, ik *SymKey) (AEADEnvelope, error) {
	return SealAEAD(vk, ik[:], c.wrapAAD())
}

// UnwrapItemKey opens an item key wrap.
func UnwrapItemKey(vk *SymKey, c ItemContext, e AEADEnvelope) (SymKey, error) {
	pt, err := OpenAEAD(vk, e, c.wrapAAD())
	if err != nil {
		return SymKey{}, err
	}
	defer clear(pt)
	if len(pt) != KeySize {
		return SymKey{}, ErrDecrypt
	}
	var ik SymKey
	copy(ik[:], pt)
	return ik, nil
}

// SealItem returns body = AEAD(IK, JCS(plaintext), aad = lp("hopkey/v1/item")
// || lp(account_id_bytes) || lp(vault_id_bytes) || lp(item_id_bytes)
// || lp(type) || u32(iv) || u64(item_version)) (§6.4). The plaintext must
// pass §6.5 and its item_id, type and item_version must match c.
func SealItem(ik *SymKey, c ItemContext, it Item) (AEADEnvelope, error) {
	if err := checkItemMatches(it, c); err != nil {
		return AEADEnvelope{}, err
	}
	pt, err := MarshalItem(it)
	if err != nil {
		return AEADEnvelope{}, err
	}
	defer clear(pt)
	return SealAEAD(ik, pt, c.bodyAAD())
}

// OpenItem opens an item body, decodes it under the closed schema for
// c.Type and requires its header to match c.
func OpenItem(ik *SymKey, c ItemContext, e AEADEnvelope) (Item, error) {
	pt, err := OpenAEAD(ik, e, c.bodyAAD())
	if err != nil {
		return nil, err
	}
	defer clear(pt)
	it, err := ParseItem(c.Type, pt)
	if err != nil {
		return nil, err
	}
	if err := checkItemMatches(it, c); err != nil {
		return nil, err
	}
	return it, nil
}

func checkItemMatches(it Item, c ItemContext) error {
	h, err := ItemHeader(it)
	if err != nil {
		return err
	}
	if h.ItemID != c.ItemID || h.Type != c.Type || h.ItemVersion != c.ItemVersion {
		return errors.New("crypto: plaintext item_id, type or item_version does not match the envelope")
	}
	return nil
}
