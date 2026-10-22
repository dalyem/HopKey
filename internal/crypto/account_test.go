package crypto

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"strings"
	"testing"

	"github.com/dalyem/hopkey/internal/canonjson"
	"github.com/dalyem/hopkey/internal/model"
)

func TestAcctPrivRoundTrip(t *testing.T) {
	k := fixedAccount(t, 3)
	b, err := k.MarshalAcctPriv()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(string(b), `{"account_id":"101112131415161718191a1b1c1d1e1f","akv":3,"kem_sk":"`) {
		t.Fatalf("acct_priv = %s", b)
	}
	back, err := ParseAcctPriv(b, k.AccountID, 3)
	if err != nil {
		t.Fatal(err)
	}
	if !back.Pin().Equal(k.Pin()) {
		t.Fatal("acct_priv round trip changed the keys")
	}
	if _, err := ParseAcctPriv(b, fixedID(0x99), 3); err == nil {
		t.Error("acct_priv accepted for another account")
	}
	if _, err := ParseAcctPriv(b, k.AccountID, 4); err == nil {
		t.Error("acct_priv accepted for another akv")
	}
	for name, in := range map[string]string{
		"unknown member":   strings.Replace(string(b), `"akv":3`, `"akv":3,"extra":1`, 1),
		"duplicate member": strings.Replace(string(b), `"akv":3`, `"akv":3,"akv":3`, 1),
		"unknown v":        strings.Replace(string(b), `"v":1`, `"v":2`, 1),
		"missing member":   strings.Replace(string(b), `"akv":3,`, ``, 1),
	} {
		if _, err := ParseAcctPriv([]byte(in), k.AccountID, 3); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

// Every AAD field of pw_blob and rk_blob: label, account_id, akv (§4.2).
func TestAccountBlobsAAD(t *testing.T) {
	k := fixedAccount(t, 2)
	key := SymKey(fixedBytes("encKey", 32))
	for _, blob := range []struct {
		label string
		seal  func(*SymKey, *AccountKeys) (AEADEnvelope, error)
		open  func(*SymKey, AEADEnvelope, model.ID, uint32) (*AccountKeys, error)
	}{
		{LabelPwBlob, SealPwBlob, OpenPwBlob},
		{LabelRkBlob, SealRkBlob, OpenRkBlob},
	} {
		e, err := blob.seal(&key, k)
		if err != nil {
			t.Fatal(err)
		}
		got, err := blob.open(&key, e, k.AccountID, 2)
		if err != nil || !got.Pin().Equal(k.Pin()) {
			t.Fatalf("%s: open: %v", blob.label, err)
		}
		if _, err := blob.open(&key, e, fixedID(0x77), 2); !errors.Is(err, ErrDecrypt) {
			t.Errorf("%s: account_id changed: %v", blob.label, err)
		}
		if _, err := blob.open(&key, e, k.AccountID, 3); !errors.Is(err, ErrDecrypt) {
			t.Errorf("%s: akv changed: %v", blob.label, err)
		}
		other := SymKey(fixedBytes("other", 32))
		if _, err := blob.open(&other, e, k.AccountID, 2); !errors.Is(err, ErrDecrypt) {
			t.Errorf("%s: wrong key: %v", blob.label, err)
		}
	}
	// The label is part of the AAD: a pw_blob does not open as an rk_blob.
	e, _ := SealPwBlob(&key, k)
	if _, err := OpenRkBlob(&key, e, k.AccountID, 2); !errors.Is(err, ErrDecrypt) {
		t.Errorf("label changed: %v", err)
	}
}

// A blob whose AAD is right but whose acct_priv names another account must
// be refused: the client checks that account_id and akv match the AAD.
func TestAccountBlobInnerMismatch(t *testing.T) {
	k := fixedAccount(t, 2)
	key := SymKey(fixedBytes("encKey", 32))
	inner := *k
	inner.AKV = 5
	pt, err := inner.MarshalAcctPriv()
	if err != nil {
		t.Fatal(err)
	}
	e, err := SealAEAD(&key, pt, blobAAD(LabelPwBlob, k.AccountID, 2))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := OpenPwBlob(&key, e, k.AccountID, 2); err == nil || errors.Is(err, ErrDecrypt) {
		t.Fatalf("inner akv mismatch: %v", err)
	}
}

func TestRecoveryKeys(t *testing.T) {
	rk := fixedBytes("RK", 32)
	acct := fixedID(1)
	rkKey, rAuth, err := RecoveryKeys(rk, acct)
	if err != nil {
		t.Fatal(err)
	}
	wantWrap, _ := hkdfKey(rk, acct[:], LP([]byte("hopkey/v1/recovery-wrap")), 32)
	wantAuth, _ := hkdfKey(rk, acct[:], LP([]byte("hopkey/v1/recovery-auth")), 32)
	if !bytes.Equal(rkKey[:], wantWrap) || !bytes.Equal(rAuth, wantAuth) {
		t.Fatal("recovery derivation does not follow §4.2")
	}
	if bytes.Equal(rkKey[:], rAuth) {
		t.Fatal("rkKey equals rAuth")
	}
	k2, _, _ := RecoveryKeys(rk, fixedID(2))
	if k2 == rkKey {
		t.Fatal("account ID does not salt the recovery keys")
	}
	if _, _, err := RecoveryKeys(nil, acct); err == nil {
		t.Fatal("empty RK accepted")
	}
}

func TestPublicKeysDerivedFromPrivate(t *testing.T) {
	k := fixedAccount(t, 1)
	pub := k.Public()
	if !bytes.Equal(pub.KEMPK, fixedKEM(t, "account-kem").PublicKey().Bytes()) {
		t.Error("KEM public key not derived from the private key")
	}
	if !bytes.Equal(pub.SigPK, fixedSig("account-sig").Public().(ed25519.PublicKey)) {
		t.Error("signing public key not derived from the seed")
	}
	pin := k.Pin()
	if pin.FpKEM != FpKEM(pub.KEMPK) || pin.FpSig != FpSig(pub.SigPK) || pin.AKV != 1 {
		t.Error("pin does not hold the fingerprints")
	}
	if _, err := canonjson.Marshal(pin); err != nil {
		t.Error(err)
	}
}
