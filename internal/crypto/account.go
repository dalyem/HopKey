package crypto

import (
	"crypto/ed25519"
	"crypto/hpke"
	"errors"
	"fmt"

	"github.com/dalyem/hopkey/internal/canonjson"
	"github.com/dalyem/hopkey/internal/model"
)

// acctPriv is the §4.2 plaintext:
// {"v":1,"account_id":id,"akv":u32,"kem_sk":b64,"sig_seed":b64}.
type acctPriv struct {
	V         int      `json:"v"`
	AccountID model.ID `json:"account_id"`
	AKV       uint32   `json:"akv"`
	KEMSK     []byte   `json:"kem_sk"`
	SigSeed   []byte   `json:"sig_seed"`
}

// AccountKeys are the private account keys for one akv.
type AccountKeys struct {
	AccountID model.ID
	AKV       uint32
	KEM       hpke.PrivateKey
	Sig       ed25519.PrivateKey
}

// AccountPublic is the public half of AccountKeys, as carried by an
// account_keys op.
type AccountPublic struct {
	AccountID model.ID
	AKV       uint32
	KEMPK     []byte
	SigPK     ed25519.PublicKey
}

// AccountPin is what a client pins after opening acct_priv (§4.2):
// (account_id, akv, fp_kem, fp_sig).
type AccountPin struct {
	AccountID model.ID
	AKV       uint32
	FpKEM     Hash
	FpSig     Hash
}

// GenerateAccountKeys creates new account keys for akv.
func GenerateAccountKeys(accountID model.ID, akv uint32) (*AccountKeys, error) {
	if accountID.IsZero() {
		return nil, errors.New("crypto: zero account ID")
	}
	kem, err := GenerateKEMKey()
	if err != nil {
		return nil, err
	}
	_, sig, err := ed25519.GenerateKey(nil)
	if err != nil {
		return nil, err
	}
	return &AccountKeys{AccountID: accountID, AKV: akv, KEM: kem, Sig: sig}, nil
}

// NewAccountKeys assembles keys from a KEM private key and an Ed25519 seed.
func NewAccountKeys(accountID model.ID, akv uint32, kem hpke.PrivateKey, sigSeed []byte) (*AccountKeys, error) {
	if accountID.IsZero() {
		return nil, errors.New("crypto: zero account ID")
	}
	if kem == nil || kem.KEM().ID() != hpkeKEM().ID() {
		return nil, errors.New("crypto: account KEM key is not X-Wing")
	}
	if len(sigSeed) != ed25519.SeedSize {
		return nil, errors.New("crypto: Ed25519 seed must be 32 bytes")
	}
	return &AccountKeys{AccountID: accountID, AKV: akv, KEM: kem, Sig: ed25519.NewKeyFromSeed(sigSeed)}, nil
}

// Zero clears the signing key. The KEM private key lives inside crypto/hpke
// and cannot be cleared from here; dropping the reference is all we can do.
func (k *AccountKeys) Zero() {
	clear(k.Sig)
	k.KEM = nil
}

// Public derives the public keys from the private ones.
func (k *AccountKeys) Public() AccountPublic {
	return AccountPublic{
		AccountID: k.AccountID,
		AKV:       k.AKV,
		KEMPK:     k.KEM.PublicKey().Bytes(),
		SigPK:     k.Sig.Public().(ed25519.PublicKey),
	}
}

// Pin returns the values a client pins for this account.
func (k *AccountKeys) Pin() AccountPin { return k.Public().Pin() }

// Pin returns (account_id, akv, fp_kem, fp_sig).
func (p AccountPublic) Pin() AccountPin {
	return AccountPin{AccountID: p.AccountID, AKV: p.AKV, FpKEM: FpKEM(p.KEMPK), FpSig: FpSig(p.SigPK)}
}

// Equal compares two pins.
func (p AccountPin) Equal(o AccountPin) bool {
	return p.AccountID == o.AccountID && p.AKV == o.AKV && p.FpKEM.Equal(o.FpKEM) && p.FpSig.Equal(o.FpSig)
}

// MarshalAcctPriv returns acct_priv = JCS({"v":1,"account_id","akv","kem_sk","sig_seed"}).
// The caller should Zero the result when done.
func (k *AccountKeys) MarshalAcctPriv() ([]byte, error) {
	// crypto/hpke returns its internal seed here, not a copy: clearing it
	// would destroy the key, so it is left alone.
	kemSK, err := k.KEM.Bytes()
	if err != nil {
		return nil, err
	}
	seed := k.Sig.Seed()
	defer clear(seed)
	return canonjson.Marshal(acctPriv{V: Version, AccountID: k.AccountID, AKV: k.AKV, KEMSK: kemSK, SigSeed: seed})
}

// ParseAcctPriv decodes acct_priv and requires it to name accountID and
// akv, the values bound by the blob's AAD or info (§4.2).
func ParseAcctPriv(b []byte, accountID model.ID, akv uint32) (*AccountKeys, error) {
	var p acctPriv
	if err := canonjson.Unmarshal(b, &p); err != nil {
		return nil, err
	}
	defer clear(p.KEMSK)
	defer clear(p.SigSeed)
	if p.V != Version {
		return nil, ErrUnsupported
	}
	if p.AccountID != accountID || p.AKV != akv {
		return nil, errors.New("crypto: acct_priv names a different account or akv")
	}
	kem, err := ParseKEMPrivateKey(p.KEMSK)
	if err != nil {
		return nil, fmt.Errorf("crypto: bad kem_sk: %w", err)
	}
	return NewAccountKeys(p.AccountID, p.AKV, kem, p.SigSeed)
}

func blobAAD(label string, accountID model.ID, akv uint32) []byte {
	return cat(lps(label), LP(accountID[:]), U32(akv))
}

// SealPwBlob returns pw_blob = AEAD(encKey, acct_priv,
// aad = lp("hopkey/v1/pw-blob") || lp(account_id_bytes) || u32(akv)).
func SealPwBlob(encKey *SymKey, k *AccountKeys) (AEADEnvelope, error) {
	return sealAcctBlob(encKey, LabelPwBlob, k)
}

// OpenPwBlob opens pw_blob and checks that acct_priv matches the AAD.
func OpenPwBlob(encKey *SymKey, e AEADEnvelope, accountID model.ID, akv uint32) (*AccountKeys, error) {
	return openAcctBlob(encKey, LabelPwBlob, e, accountID, akv)
}

// SealRkBlob returns rk_blob = AEAD(rkKey, acct_priv,
// aad = lp("hopkey/v1/rk-blob") || lp(account_id_bytes) || u32(akv)).
func SealRkBlob(rkKey *SymKey, k *AccountKeys) (AEADEnvelope, error) {
	return sealAcctBlob(rkKey, LabelRkBlob, k)
}

// OpenRkBlob opens rk_blob and checks that acct_priv matches the AAD.
func OpenRkBlob(rkKey *SymKey, e AEADEnvelope, accountID model.ID, akv uint32) (*AccountKeys, error) {
	return openAcctBlob(rkKey, LabelRkBlob, e, accountID, akv)
}

func sealAcctBlob(key *SymKey, label string, k *AccountKeys) (AEADEnvelope, error) {
	pt, err := k.MarshalAcctPriv()
	if err != nil {
		return AEADEnvelope{}, err
	}
	defer clear(pt)
	return SealAEAD(key, pt, blobAAD(label, k.AccountID, k.AKV))
}

func openAcctBlob(key *SymKey, label string, e AEADEnvelope, accountID model.ID, akv uint32) (*AccountKeys, error) {
	pt, err := OpenAEAD(key, e, blobAAD(label, accountID, akv))
	if err != nil {
		return nil, err
	}
	defer clear(pt)
	return ParseAcctPriv(pt, accountID, akv)
}

// RecoveryKeys derives the two recovery values from RK (§4.2):
//
//	rkKey = HKDF(RK, salt=account_id_bytes, info=lp("hopkey/v1/recovery-wrap"))
//	rAuth = HKDF(RK, salt=account_id_bytes, info=lp("hopkey/v1/recovery-auth"))
//
// The server stores SHA-256(rAuth); the client sends rAuth itself.
//
// SPEC GAP (§4.2, §4.3, §12): RK's length, how it is generated and its
// Emergency Kit text form are not specified. This function takes RK as
// opaque bytes and only refuses an empty value; there is no RK generator.
func RecoveryKeys(rk []byte, accountID model.ID) (rkKey SymKey, rAuth []byte, err error) {
	if len(rk) == 0 {
		return SymKey{}, nil, errors.New("crypto: empty recovery key")
	}
	if accountID.IsZero() {
		return SymKey{}, nil, errors.New("crypto: zero account ID")
	}
	w, err := hkdf32(rk, accountID[:], lps(LabelRecoveryWrap))
	if err != nil {
		return SymKey{}, nil, err
	}
	copy(rkKey[:], w)
	clear(w)
	rAuth, err = hkdf32(rk, accountID[:], lps(LabelRecoveryAuth))
	if err != nil {
		rkKey.Zero()
		return SymKey{}, nil, err
	}
	return rkKey, rAuth, nil
}
