package crypto

import (
	"crypto/ed25519"
	"errors"
	"strings"
	"testing"

	"github.com/dalyem/hopkey/internal/canonjson"
	"github.com/dalyem/hopkey/internal/model"
)

func testCert(t *testing.T, acct *AccountKeys, devKEMPK, devSigPK []byte) Cert {
	return Cert{
		V: 1, AccountID: acct.AccountID, AKV: acct.AKV, DeviceID: fixedID(0x40), Name: "laptop",
		KEMFp: FpKEM(devKEMPK), SigFp: FpSig(devSigPK), IssuedAt: ts(t, "2026-10-22T12:00:00Z"),
	}
}

func TestCertSignVerify(t *testing.T) {
	acct := fixedAccount(t, 1)
	dev := fixedKEM(t, "device-kem")
	devSig := fixedSig("device-sig")
	c := testCert(t, acct, dev.PublicKey().Bytes(), devSig.Public().(ed25519.PublicKey))
	sig, err := SignCert(acct, &c)
	if err != nil {
		t.Fatal(err)
	}
	pub := acct.Public().SigPK
	if err := VerifyCert(pub, &c, sig); err != nil {
		t.Fatal(err)
	}
	if err := CheckCertKeys(&c, dev.PublicKey().Bytes(), devSig.Public().(ed25519.PublicKey)); err != nil {
		t.Fatal(err)
	}
	// Every field is signed.
	for name, mutate := range map[string]func(*Cert){
		"account_id":        func(c *Cert) { c.AccountID = fixedID(0x99) },
		"akv":               func(c *Cert) { c.AKV = 2 },
		"device_id":         func(c *Cert) { c.DeviceID = fixedID(0x41) },
		"name":              func(c *Cert) { c.Name = "laptop2" },
		"kem_fp":            func(c *Cert) { c.KEMFp[0] ^= 1 },
		"sig_fp":            func(c *Cert) { c.SigFp[0] ^= 1 },
		"enroll_transcript": func(c *Cert) { c.EnrollTranscript[0] = 1 },
		"issued_at":         func(c *Cert) { c.IssuedAt++ },
	} {
		m := c
		mutate(&m)
		if err := VerifyCert(pub, &m, sig); err == nil {
			t.Errorf("%s changed: still verifies", name)
		}
	}
	other := fixedSig("not the account")
	if err := VerifyCert(other.Public().(ed25519.PublicKey), &c, sig); !errors.Is(err, ErrBadSignature) {
		t.Errorf("wrong key: %v", err)
	}
	if err := CheckCertKeys(&c, fixedKEM(t, "x").PublicKey().Bytes(), devSig.Public().(ed25519.PublicKey)); err == nil {
		t.Error("device_add KEM key not matching kem_fp accepted")
	}
	if err := CheckCertKeys(&c, dev.PublicKey().Bytes(), other.Public().(ed25519.PublicKey)); err == nil {
		t.Error("device_add sig key not matching sig_fp accepted")
	}
	// Signing under another akv's keys is refused.
	acct2 := fixedAccount(t, 2)
	if _, err := SignCert(acct2, &c); err == nil {
		t.Error("certificate signed by a key for another akv")
	}
	bad := c
	bad.V = 2
	if err := VerifyCert(pub, &bad, sig); !errors.Is(err, ErrUnsupported) {
		t.Errorf("unknown v: %v", err)
	}
	bad = c
	bad.Name = "line\nbreak"
	if _, err := SignCert(acct, &bad); err == nil {
		t.Error("control character in name accepted")
	}
}

func TestCertSchema(t *testing.T) {
	acct := fixedAccount(t, 1)
	c := testCert(t, acct, []byte("k"), []byte("s"))
	j, err := canonjson.Marshal(&c)
	if err != nil {
		t.Fatal(err)
	}
	want := `{"account_id":"101112131415161718191a1b1c1d1e1f","akv":1,"device_id":"404142434445464748494a4b4c4d4e4f","enroll_transcript":"","issued_at":"2026-10-22T12:00:00Z","kem_fp":"` +
		FpKEM([]byte("k")).String() + `","name":"laptop","sig_fp":"` + FpSig([]byte("s")).String() + `","v":1}`
	if string(j) != want {
		t.Fatalf("got  %s\nwant %s", j, want)
	}
	for name, in := range map[string]string{
		"unknown member":   strings.Replace(want, `"v":1`, `"v":1,"x":true`, 1),
		"duplicate member": strings.Replace(want, `"akv":1`, `"akv":1,"akv":1`, 1),
		"bad ts":           strings.Replace(want, `2026-10-22T12:00:00Z`, `2026-10-22T12:00:00+00:00`, 1),
		"bad ts 2":         strings.Replace(want, `2026-10-22T12:00:00Z`, `2026-10-22 12:00:00Z`, 1),
		"bad ts range":     strings.Replace(want, `2026-10-22T12:00:00Z`, `2026-13-22T12:00:00Z`, 1),
		"uppercase id":     strings.Replace(want, `404142434445464748494a4b4c4d4e4f`, `404142434445464748494A4B4C4D4E4F`, 1),
	} {
		var back Cert
		if err := canonjson.Unmarshal([]byte(in), &back); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

// §6.2: every info field (account_id, device_id, akv) and the AAD (the
// certificate digest) are bound.
func TestUnlockBlobBinding(t *testing.T) {
	acct := fixedAccount(t, 1)
	dev := fixedKEM(t, "device-kem")
	devPK := dev.PublicKey().Bytes()
	c := testCert(t, acct, devPK, []byte("s"))
	e, err := SealUnlock(devPK, &c, acct)
	if err != nil {
		t.Fatal(err)
	}
	got, err := OpenUnlock(dev, &c, e)
	if err != nil {
		t.Fatal(err)
	}
	if err := CheckUnlockPin(got, acct.Pin()); err != nil {
		t.Fatal(err)
	}
	if err := CheckUnlockKeys(got, acct.Public()); err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*Cert){
		"info account_id": func(c *Cert) { c.AccountID = fixedID(0x99) },
		"info device_id":  func(c *Cert) { c.DeviceID = fixedID(0x41) },
		"info akv":        func(c *Cert) { c.AKV = 2 },
		"aad name":        func(c *Cert) { c.Name = "other" },
		"aad issued_at":   func(c *Cert) { c.IssuedAt++ },
		"aad kem_fp":      func(c *Cert) { c.KEMFp[1] ^= 1 },
	} {
		m := c
		mutate(&m)
		if _, err := OpenUnlock(dev, &m, e); !errors.Is(err, ErrDecrypt) {
			t.Errorf("%s changed: %v", name, err)
		}
	}
	if _, err := OpenUnlock(fixedKEM(t, "other device"), &c, e); !errors.Is(err, ErrDecrypt) {
		t.Errorf("wrong device key: %v", err)
	}
	// The receiver compares derived keys with the expected account.
	if err := CheckUnlockPin(got, fixedAccount(t, 2).Pin()); !errors.Is(err, ErrAccountMismatch) {
		t.Errorf("pin for another akv: %v", err)
	}
	if _, err := SealUnlock(fixedKEM(t, "x").PublicKey().Bytes(), &c, acct); err == nil {
		t.Error("sealed to a key that does not match kem_fp")
	}
}

// §6.3: vault_id, account_id, kv and akv are bound through info.
func TestVKEnvelopeBinding(t *testing.T) {
	acct := fixedAccount(t, 1)
	v := VKContext{VaultID: fixedID(0x50), AccountID: acct.AccountID, KV: 1, AKV: 1}
	vk := SymKey(fixedBytes("VK", 32))
	e, err := SealVK(acct.Public().KEMPK, v, &vk)
	if err != nil {
		t.Fatal(err)
	}
	got, err := OpenVK(acct, v, e)
	if err != nil || got != vk {
		t.Fatalf("open: %v", err)
	}
	m := v
	m.VaultID = fixedID(0x51)
	if _, err := OpenVK(acct, m, e); !errors.Is(err, ErrDecrypt) {
		t.Errorf("vault_id changed: %v", err)
	}
	m = v
	m.KV = 2
	if _, err := OpenVK(acct, m, e); !errors.Is(err, ErrDecrypt) {
		t.Errorf("kv changed: %v", err)
	}
	// account_id and akv are checked against the keys and bound in info.
	other := *acct
	other.AccountID = fixedID(0x99)
	m = v
	m.AccountID = other.AccountID
	if _, err := OpenVK(&other, m, e); !errors.Is(err, ErrDecrypt) {
		t.Errorf("account_id changed: %v", err)
	}
	other = *acct
	other.AKV = 2
	m = v
	m.AKV = 2
	if _, err := OpenVK(&other, m, e); !errors.Is(err, ErrDecrypt) {
		t.Errorf("akv changed: %v", err)
	}
	if _, err := OpenVK(acct, VKContext{VaultID: v.VaultID, AccountID: acct.AccountID, KV: 1, AKV: 2}, e); err == nil {
		t.Error("context akv differs from the key's akv but opened")
	}
}

func testHost(id model.ID, version uint64) *model.Host {
	return &model.Host{
		Header: model.Header{V: 1, ItemID: id, Type: model.TypeHost, ItemVersion: version},
		Name:   "web-1", Aliases: []string{"w1"}, Addresses: []string{"10.0.0.1"}, Port: 22, User: "root",
		Tags: []string{"prod"}, Route: "auto", HostKeys: []string{"ssh-ed25519 AAAA"}, AgentAccess: "allow",
	}
}

// §6.4: every field of the wrap AAD and the body AAD is bound.
func TestItemEnvelopesAAD(t *testing.T) {
	vk := SymKey(fixedBytes("VK", 32))
	ik := SymKey(fixedBytes("IK", 32))
	c := ItemContext{AccountID: fixedID(0x10), VaultID: fixedID(0x50), ItemID: fixedID(0x60),
		Type: model.TypeHost, ItemVersion: 3, IV: 1, KV: 1}
	wrap, err := WrapItemKey(&vk, c, &ik)
	if err != nil {
		t.Fatal(err)
	}
	got, err := UnwrapItemKey(&vk, c, wrap)
	if err != nil || got != ik {
		t.Fatalf("unwrap: %v", err)
	}
	// Wrap AAD: vault_id, item_id, kv, iv. (account_id, type and
	// item_version are not in it.)
	for name, mutate := range map[string]func(*ItemContext){
		"vault_id": func(c *ItemContext) { c.VaultID = fixedID(0x51) },
		"item_id":  func(c *ItemContext) { c.ItemID = fixedID(0x61) },
		"kv":       func(c *ItemContext) { c.KV = 2 },
		"iv":       func(c *ItemContext) { c.IV = 2 },
	} {
		m := c
		mutate(&m)
		if _, err := UnwrapItemKey(&vk, m, wrap); !errors.Is(err, ErrDecrypt) {
			t.Errorf("wrap %s changed: %v", name, err)
		}
	}

	host := testHost(c.ItemID, 3)
	body, err := SealItem(&ik, c, host)
	if err != nil {
		t.Fatal(err)
	}
	it, err := OpenItem(&ik, c, body)
	if err != nil {
		t.Fatal(err)
	}
	if h := it.(*model.Host); h.Name != "web-1" || h.ItemVersion != 3 {
		t.Fatalf("opened %+v", h)
	}
	// Body AAD: account_id, vault_id, item_id, type, iv, item_version.
	for name, mutate := range map[string]func(*ItemContext){
		"account_id":   func(c *ItemContext) { c.AccountID = fixedID(0x11) },
		"vault_id":     func(c *ItemContext) { c.VaultID = fixedID(0x51) },
		"item_id":      func(c *ItemContext) { c.ItemID = fixedID(0x61) },
		"type":         func(c *ItemContext) { c.Type = model.TypeKey },
		"iv":           func(c *ItemContext) { c.IV = 2 },
		"item_version": func(c *ItemContext) { c.ItemVersion = 4 },
	} {
		m := c
		mutate(&m)
		if _, err := OpenItem(&ik, m, body); !errors.Is(err, ErrDecrypt) {
			t.Errorf("body %s changed: %v", name, err)
		}
	}
	// kv is not in the body AAD (the IK binds it through the wrap).
	m := c
	m.KV = 2
	if _, err := OpenItem(&ik, m, body); err != nil {
		t.Errorf("kv is not part of the body AAD but changed the result: %v", err)
	}
}

func TestItemPlaintextMustMatchEnvelope(t *testing.T) {
	ik := SymKey(fixedBytes("IK", 32))
	c := ItemContext{AccountID: fixedID(0x10), VaultID: fixedID(0x50), ItemID: fixedID(0x60),
		Type: model.TypeHost, ItemVersion: 3, IV: 1, KV: 1}
	for name, h := range map[string]*model.Host{
		"item_id":      testHost(fixedID(0x61), 3),
		"item_version": testHost(c.ItemID, 2),
	} {
		if _, err := SealItem(&ik, c, h); err == nil {
			t.Errorf("sealed a plaintext with a different %s", name)
		}
		// Bypass the sealing check to make sure the opener checks too.
		pt, _ := canonjson.Marshal(h)
		e, _ := SealAEAD(&ik, pt, c.bodyAAD())
		if _, err := OpenItem(&ik, c, e); err == nil {
			t.Errorf("opened a plaintext with a different %s", name)
		}
	}
	h := testHost(c.ItemID, 3)
	h.Type = model.TypeKey
	if _, err := SealItem(&ik, c, h); err == nil {
		t.Error("sealed a plaintext with a different type")
	}
}
