package crypto

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"testing/cryptotest"
	"time"

	"golang.org/x/crypto/argon2"

	"github.com/dalyem/hopkey/internal/canonjson"
	"github.com/dalyem/hopkey/internal/model"
)

// Known-answer vectors (§13). Each generator builds its vectors from fixed
// inputs. Randomness (AEAD nonces, HPKE encapsulation) comes from
// testing/cryptotest.SetGlobalRandom with a fixed seed, so the envelopes
// are reproducible on Go 1.27's crypto/hpke. The tests recompute every
// value and compare it with testdata/*.json; separate checks open the
// stored envelopes with the fixed keys, which does not depend on how the
// standard library consumes randomness.
//
// Regenerate with: go test ./internal/crypto -run TestVectors -update

var update = flag.Bool("update", false, "rewrite testdata/*.json")

type vectors map[string]string

func (v vectors) hex(name string, b []byte) { v[name] = hex.EncodeToString(b) }

func (v vectors) json(t *testing.T, name string, obj any) {
	t.Helper()
	j, err := canonjson.Marshal(obj)
	if err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	v[name] = string(j)
}

func compareVectors(t *testing.T, file string, got vectors) vectors {
	t.Helper()
	path := filepath.Join("testdata", file+".json")
	if *update {
		j, err := json.MarshalIndent(got, "", "  ")
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, append(j, '\n'), 0o644); err != nil {
			t.Fatal(err)
		}
		return got
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("%v (run with -update to create it)", err)
	}
	var want vectors
	if err := json.Unmarshal(raw, &want); err != nil {
		t.Fatal(err)
	}
	keys := slices.Sorted(func(yield func(string) bool) {
		for k := range want {
			if !yield(k) {
				return
			}
		}
		for k := range got {
			if _, ok := want[k]; !ok && !yield(k) {
				return
			}
		}
	})
	for _, k := range keys {
		if got[k] != want[k] {
			g, w := got[k], want[k]
			if len(g) > 160 {
				g = g[:160] + "…"
			}
			if len(w) > 160 {
				w = w[:160] + "…"
			}
			t.Errorf("%s: %s\n got  %s\n want %s", file, k, g, w)
		}
	}
	return want
}

func seeded(t *testing.T, seed uint64) { cryptotest.SetGlobalRandom(t, seed) }

func unhex(t *testing.T, v vectors, k string) []byte {
	t.Helper()
	b, err := hex.DecodeString(v[k])
	if err != nil {
		t.Fatalf("%s: %v", k, err)
	}
	return b
}

func aeadEnv(t *testing.T, v vectors, k string) AEADEnvelope {
	t.Helper()
	e, err := ParseAEADEnvelope([]byte(v[k]))
	if err != nil {
		t.Fatalf("%s: %v", k, err)
	}
	return e
}

func hpkeEnv(t *testing.T, v vectors, k string) HPKEEnvelope {
	t.Helper()
	e, err := ParseHPKEEnvelope([]byte(v[k]))
	if err != nil {
		t.Fatalf("%s: %v", k, err)
	}
	return e
}

// --- §3 encoding ---

func TestVectorsEncoding(t *testing.T) {
	v := vectors{}
	v.hex("lp_hopkey", LP([]byte("hopkey")))
	v.hex("u32_deadbeef", U32(0xdeadbeef))
	v.hex("u64_0102030405060708", U64(0x0102030405060708))
	obj := map[string]any{"v": 1, "b": []string{"x"}, "a": map[string]any{"é": true, "e": nil}}
	v.json(t, "d_obj_jcs", obj)
	d, err := D(LabelLogEntry, obj)
	if err != nil {
		t.Fatal(err)
	}
	v["d_log_entry"] = d.String()
	acct := fixedAccount(t, 1)
	pub := acct.Public()
	v.hex("acct_kem_pk", pub.KEMPK)
	v.hex("acct_sig_pk", pub.SigPK)
	v["fp_kem"] = FpKEM(pub.KEMPK).String()
	v["fp_sig"] = FpSig(pub.SigPK).String()
	sig, err := Sign(acct.Sig, LabelLogEntry, obj)
	if err != nil {
		t.Fatal(err)
	}
	v.hex("sig_log_entry", sig)
	want := compareVectors(t, "encoding", v)
	if err := Verify(pub.SigPK, LabelLogEntry, obj, unhex(t, want, "sig_log_entry")); err != nil {
		t.Errorf("stored signature: %v", err)
	}
}

// --- §2 HPKE suite ---

func TestVectorsHPKE(t *testing.T) {
	v := vectors{}
	kem, kdf, aead := HPKESuiteIDs()
	v["suite_ids"] = fmt.Sprintf("%04x%04x%04x", kem, kdf, aead)
	ikm := fixedBytes("hpke ikm", 32)
	sk, err := DeriveKEMKey(ikm)
	if err != nil {
		t.Fatal(err)
	}
	skb, _ := sk.Bytes()
	v.hex("derive_ikm", ikm)
	v.hex("derive_sk", skb)
	v.hex("derive_pk", sk.PublicKey().Bytes())
	seeded(t, 1)
	e, err := SealHPKE(sk.PublicKey().Bytes(), []byte("info"), []byte("aad"), []byte("plaintext"))
	if err != nil {
		t.Fatal(err)
	}
	v.json(t, "seal_envelope", e)
	want := compareVectors(t, "hpke", v)
	pt, err := OpenHPKE(sk, hpkeEnv(t, want, "seal_envelope"), []byte("info"), []byte("aad"))
	if err != nil || string(pt) != "plaintext" {
		t.Errorf("stored envelope: %q, %v", pt, err)
	}
	// PrivateKey.Bytes() is pinned: the stored sk rebuilds the stored pk.
	back, err := ParseKEMPrivateKey(unhex(t, want, "derive_sk"))
	if err != nil || !bytes.Equal(back.PublicKey().Bytes(), unhex(t, want, "derive_pk")) {
		t.Errorf("stored private key: %v", err)
	}
}

// --- §4.1 and §12 ---

func vectorSecretKey() SecretKey {
	sk := SecretKey{Hint: "HQPK01"}
	copy(sk.SK17[:], fixedBytes("vector sk", 17))
	sk.SK17[0] &= 0x03
	return sk
}

func TestVectorsKDF(t *testing.T) {
	v := vectors{}
	pw := []byte("correct horse battery staple")
	salt := fixedBytes("vector salt", 16)
	sk := vectorSecretKey()
	acct := fixedID(0x10)
	v["password"] = string(pw)
	v.hex("salt", salt)
	v["secret_key"] = sk.String()
	v["account_id"] = acct.String()
	v.hex("pw_key", argon2.IDKey(pw, salt, 3, 65536, 4, 32))
	skKey, err := deriveSKKey(&sk, acct)
	if err != nil {
		t.Fatal(err)
	}
	v.hex("sk_key", skKey)
	keys, err := DeriveLoginKeys(pw, salt, &sk, acct, KDFv1)
	if err != nil {
		t.Fatal(err)
	}
	v.hex("auth_key", keys.AuthKey[:])
	v.hex("enc_key", keys.EncKey[:])
	v["auth_sha256"] = keys.AuthHash().String()
	// NFKC applies before Argon2: "staﬀ" normalizes to "staff".
	v["nfkc_password"] = "correct horse battery staﬀ"
	nk, err := DeriveLoginKeys([]byte(v["nfkc_password"]), salt, &sk, acct, KDFv1)
	if err != nil {
		t.Fatal(err)
	}
	plain, err := DeriveLoginKeys([]byte("correct horse battery staff"), salt, &sk, acct, KDFv1)
	if err != nil || plain.AuthKey != nk.AuthKey {
		t.Fatal("NFKC is not applied before Argon2")
	}
	v.hex("nfkc_auth_key", nk.AuthKey[:])
	compareVectors(t, "kdf", v)
}

func TestVectorsSecretKey(t *testing.T) {
	v := vectors{}
	sk := vectorSecretKey()
	v.hex("sk17", sk.SK17[:])
	v["hint"] = sk.Hint
	v["text"] = sk.String()
	want := compareVectors(t, "secretkey", v)
	back, err := ParseSecretKey(want["text"])
	if err != nil || !bytes.Equal(back.SK17[:], unhex(t, want, "sk17")) {
		t.Errorf("stored text: %v", err)
	}
}

// --- §4.2 ---

func TestVectorsAccount(t *testing.T) {
	v := vectors{}
	acct := fixedAccount(t, 1)
	ap, err := acct.MarshalAcctPriv()
	if err != nil {
		t.Fatal(err)
	}
	v["acct_priv"] = string(ap)
	encKey := SymKey(fixedBytes("vector encKey", 32))
	v.hex("enc_key", encKey[:])
	seeded(t, 2)
	pw, err := SealPwBlob(&encKey, acct)
	if err != nil {
		t.Fatal(err)
	}
	v.json(t, "pw_blob", pw)
	rk := fixedBytes("vector RK", 32)
	v.hex("rk", rk)
	rkKey, rAuth, err := RecoveryKeys(rk, acct.AccountID)
	if err != nil {
		t.Fatal(err)
	}
	v.hex("rk_key", rkKey[:])
	v.hex("r_auth", rAuth)
	v["r_auth_sha256"] = SHA256(rAuth).String()
	seeded(t, 3)
	rb, err := SealRkBlob(&rkKey, acct)
	if err != nil {
		t.Fatal(err)
	}
	v.json(t, "rk_blob", rb)
	d, _ := rb.Digest()
	v["rk_blob_sha256"] = d.String()
	want := compareVectors(t, "account", v)

	got, err := OpenPwBlob(&encKey, aeadEnv(t, want, "pw_blob"), acct.AccountID, 1)
	if err != nil || !got.Pin().Equal(acct.Pin()) {
		t.Errorf("stored pw_blob: %v", err)
	}
	got, err = OpenRkBlob(&rkKey, aeadEnv(t, want, "rk_blob"), acct.AccountID, 1)
	if err != nil || !got.Pin().Equal(acct.Pin()) {
		t.Errorf("stored rk_blob: %v", err)
	}
}

// --- §6 ---

func TestVectorsObjects(t *testing.T) {
	v := vectors{}
	acct := fixedAccount(t, 1)
	dev := fixedKEM(t, "device-kem")
	devSig := fixedSig("device-sig")
	cert := testCert(t, acct, dev.PublicKey().Bytes(), devSig.Public().(ed25519.PublicKey))
	v.json(t, "cert", &cert)
	cd, _ := cert.Digest()
	v["cert_digest"] = cd.String()
	sig, err := SignCert(acct, &cert)
	if err != nil {
		t.Fatal(err)
	}
	v.hex("cert_sig", sig)
	seeded(t, 4)
	unlock, err := SealUnlock(dev.PublicKey().Bytes(), &cert, acct)
	if err != nil {
		t.Fatal(err)
	}
	v.json(t, "unlock", unlock)
	ud, _ := unlock.Digest()
	v["unlock_sha256"] = ud.String()

	vkc := VKContext{VaultID: fixedID(0x50), AccountID: acct.AccountID, KV: 1, AKV: 1}
	vk := SymKey(fixedBytes("vector VK", 32))
	v.hex("vk", vk[:])
	seeded(t, 5)
	vke, err := SealVK(acct.Public().KEMPK, vkc, &vk)
	if err != nil {
		t.Fatal(err)
	}
	v.json(t, "vk_envelope", vke)

	ic := ItemContext{AccountID: acct.AccountID, VaultID: vkc.VaultID, ItemID: fixedID(0x60), Type: model.TypeHost,
		ItemVersion: 2, IV: 1, KV: 1}
	ik := SymKey(fixedBytes("vector IK", 32))
	v.hex("ik", ik[:])
	v.hex("wrap_aad", ic.wrapAAD())
	v.hex("body_aad", ic.bodyAAD())
	seeded(t, 6)
	wrap, err := WrapItemKey(&vk, ic, &ik)
	if err != nil {
		t.Fatal(err)
	}
	v.json(t, "item_wrap", wrap)
	host := testHost(ic.ItemID, 2)
	host.Tailscale = &model.Tailscale{StableNodeID: "nXXXX", DNSName: "web-1.tail.ts.net", SSH: "yes"}
	v.json(t, "item_plaintext", host)
	seeded(t, 7)
	body, err := SealItem(&ik, ic, host)
	if err != nil {
		t.Fatal(err)
	}
	v.json(t, "item_body", body)
	want := compareVectors(t, "objects", v)

	if err := VerifyCert(acct.Public().SigPK, &cert, unhex(t, want, "cert_sig")); err != nil {
		t.Errorf("stored cert_sig: %v", err)
	}
	if k, err := OpenUnlock(dev, &cert, hpkeEnv(t, want, "unlock")); err != nil || !k.Pin().Equal(acct.Pin()) {
		t.Errorf("stored unlock: %v", err)
	}
	if got, err := OpenVK(acct, vkc, hpkeEnv(t, want, "vk_envelope")); err != nil || got != vk {
		t.Errorf("stored VK envelope: %v", err)
	}
	if got, err := UnwrapItemKey(&vk, ic, aeadEnv(t, want, "item_wrap")); err != nil || got != ik {
		t.Errorf("stored wrap: %v", err)
	}
	it, err := OpenItem(&ik, ic, aeadEnv(t, want, "item_body"))
	if err != nil {
		t.Fatalf("stored body: %v", err)
	}
	if j, _ := canonjson.Marshal(it); string(j) != want["item_plaintext"] {
		t.Errorf("stored body opened to %s", j)
	}
}

// --- §7 ---

// enrollVector finds, deterministically, the first device name suffix
// whose SAS satisfies pred, so the vectors include a SAS with a leading
// zero and one where the first word was skipped.
func enrollVector(t *testing.T, pred func(okm []byte, sas string) bool) (*EnrollOpen, *EnrollChal, string) {
	t.Helper()
	ch := testChal(t)
	for i := range 100000 {
		o := testOpen(t)
		o.Name = fmt.Sprintf("laptop-%d", i)
		tr := Transcript(Commitment(o), ch, o)
		th := TranscriptHash(tr)
		okm, _ := hkdfKey(th[:], nil, lps(LabelEnrollSAS), 64)
		sas, err := SAS(tr)
		if err == nil && pred(okm, sas) {
			return o, ch, sas
		}
	}
	t.Fatal("no candidate found")
	return nil, nil, ""
}

func TestVectorsEnroll(t *testing.T) {
	v := vectors{}
	cases := map[string]func(okm []byte, sas string) bool{
		"plain":        func(okm []byte, sas string) bool { return sas[0] != '0' && okm[0] < 0xfa },
		"leading_zero": func(okm []byte, sas string) bool { return strings.HasPrefix(sas, "0") },
		"skipped_word": func(okm []byte, sas string) bool { return okm[0] == 0xff },
	}
	for _, name := range slices.Sorted(func(yield func(string) bool) {
		for k := range cases {
			if !yield(k) {
				return
			}
		}
	}) {
		o, ch, sas := enrollVector(t, cases[name])
		v.json(t, name+"_open", o)
		v.json(t, name+"_chal", ch)
		c := Commitment(o)
		v["c_"+name] = c.String()
		tr := Transcript(c, ch, o)
		v.hex("t_"+name, tr)
		v["t_sha256_"+name] = TranscriptHash(tr).String()
		v["sas_"+name] = sas
	}

	// A delivery for the plain case.
	acct := fixedAccount(t, 1)
	o, ch, _ := enrollVector(t, cases["plain"])
	th := TranscriptHash(Transcript(Commitment(o), ch, o))
	cert := Cert{V: 1, AccountID: acct.AccountID, AKV: 1, DeviceID: fixedID(0x41), Name: o.Name,
		KEMFp: FpKEM(o.KEMPK), SigFp: FpSig(o.SigPK), EnrollTranscript: OptHash(th), IssuedAt: ts(t, "2026-10-22T12:00:00Z")}
	sig, _ := SignCert(acct, &cert)
	seeded(t, 8)
	unlock, err := SealUnlock(o.KEMPK, &cert, acct)
	if err != nil {
		t.Fatal(err)
	}
	d := EnrollDelivery{V: 1, Cert: cert, CertSig: sig, Unlock: unlock, AnchorSeq: 0, AnchorH: Hash(fixedBytes("anchor", 32))}
	seeded(t, 9)
	env, err := SealDelivery(o.KEMPK, th, &d)
	if err != nil {
		t.Fatal(err)
	}
	v.json(t, "delivery", env)
	want := compareVectors(t, "enroll", v)

	for _, name := range []string{"plain", "leading_zero", "skipped_word"} {
		tr := unhex(t, want, "t_"+name)
		if sas, err := SAS(tr); err != nil || sas != want["sas_"+name] {
			t.Errorf("stored T for %s gives SAS %q, %v", name, sas, err)
		}
	}
	if !strings.HasPrefix(want["sas_leading_zero"], "0") {
		t.Error("leading-zero vector has no leading zero")
	}
	got, err := VerifyDelivery(fixedKEM(t, "D-kem"), o.SigPK, ch, Transcript(Commitment(o), ch, o), hpkeEnv(t, want, "delivery"))
	if err != nil || !got.Account.Pin().Equal(acct.Pin()) {
		t.Errorf("stored delivery: %v", err)
	}
}

// --- §8 ---

func TestVectorsToken(t *testing.T) {
	v := vectors{}
	f := newGrantFixture(t)
	v.hex("grant_id", f.tok.GrantID[:])
	v.hex("seed", f.tok.Seed[:])
	v.hex("acct_sig_pk", f.acct.Public().SigPK)
	v["token"] = f.tok.String()
	auth, _ := f.tok.Auth()
	v.hex("t_auth", auth)
	v["t_auth_sha256"] = SHA256(auth).String()
	tk, err := f.tok.KEMKey()
	if err != nil {
		t.Fatal(err)
	}
	tkb, _ := tk.Bytes()
	v.hex("t_kem_sk", tkb)
	v.hex("t_kem_pk", tk.PublicKey().Bytes())
	b, err := BuildBundle(f.rec, f.items, f.acct.AccountID, 1, 7)
	if err != nil {
		t.Fatal(err)
	}
	v.json(t, "bundle", b)
	bd, _ := b.Digest()
	v["bundle_sha256"] = bd.String()
	s, _ := Sign(f.acct.Sig, LabelGrantBundle, b)
	v.hex("bundle_sig", s)
	seeded(t, 10)
	e, err := SealBundle(f.acct, f.rec, b)
	if err != nil {
		t.Fatal(err)
	}
	v.json(t, "bundle_envelope", e)
	want := compareVectors(t, "token", v)

	tok, err := ParseToken(want["token"])
	if err != nil || *tok != *f.tok {
		t.Fatalf("stored token: %v", err)
	}
	got, err := OpenBundle(tok, hpkeEnv(t, want, "bundle_envelope"), 7, time.Date(2026, 10, 22, 0, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatalf("stored bundle envelope: %v", err)
	}
	if j, _ := canonjson.Marshal(got.Bundle); string(j) != want["bundle"] {
		t.Errorf("stored envelope opened to a different B")
	}
}
