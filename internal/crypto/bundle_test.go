package crypto

import (
	"errors"
	"testing"
	"time"

	"github.com/dalyem/hopkey/internal/canonjson"
	"github.com/dalyem/hopkey/internal/model"
)

type grantFixture struct {
	acct  *AccountKeys
	tok   *Token
	rec   *model.Grant
	items map[model.ID]Item
	now   time.Time
}

// newGrantFixture: a dedicated grant over one host, its dedicated key, a
// credential and a snippet, plus an unlisted item in the vault.
func newGrantFixture(t *testing.T) *grantFixture {
	t.Helper()
	acct := fixedAccount(t, 1)
	grantID := fixedID(0x70)
	tok := &Token{GrantID: grantID}
	copy(tok.Seed[:], fixedBytes("seed", 32))
	fp := FpSig(acct.Public().SigPK)
	copy(tok.AcctFp[:], fp[:16])
	tkem, err := tok.KEMKey()
	if err != nil {
		t.Fatal(err)
	}

	host := testHost(fixedID(0x01), 4)
	host.KeyID = fixedID(0x09) // overridden by host_key_map
	host.CredentialID = fixedID(0x03)
	key := testKey(0x02, grantID)
	cred := &model.Credential{Header: hdr(model.TypeCredential, 0x03), Name: "c", Username: "u", Password: "p"}
	snip := &model.Snippet{Header: hdr(model.TypeSnippet, 0x04), Name: "s", Command: "uptime"}
	other := testKey(0x09, model.ID{})
	rec := &model.Grant{
		Header: hdr(model.TypeGrant, 0x05), GrantID: grantID, Name: "cloud-ci",
		ExpiresAt: ts(t, "2026-10-29T00:00:00Z"), TokenKEMPK: tkem.PublicKey().Bytes(),
		Items:      []model.ID{fixedID(0x01), fixedID(0x02), fixedID(0x03), fixedID(0x04)},
		HostKeyMap: map[model.ID]model.ID{fixedID(0x01): fixedID(0x02)},
		KeyPolicy:  "dedicated", DedicatedKeyID: fixedID(0x02),
	}
	items := map[model.ID]Item{
		fixedID(0x01): host, fixedID(0x02): key, fixedID(0x03): cred, fixedID(0x04): snip,
		fixedID(0x05): rec, fixedID(0x09): other,
	}
	return &grantFixture{acct: acct, tok: tok, rec: rec, items: items, now: ts(t, "2026-10-22T00:00:00Z").Time()}
}

func (f *grantFixture) seal(t *testing.T, version uint64) HPKEEnvelope {
	t.Helper()
	b, err := BuildBundle(f.rec, f.items, f.acct.AccountID, f.acct.AKV, version)
	if err != nil {
		t.Fatal(err)
	}
	e, err := SealBundle(f.acct, f.rec, b)
	if err != nil {
		t.Fatal(err)
	}
	return e
}

func TestBundleRoundTrip(t *testing.T) {
	f := newGrantFixture(t)
	e := f.seal(t, 3)
	got, err := OpenBundle(f.tok, e, 3, f.now)
	if err != nil {
		t.Fatal(err)
	}
	b := got.Bundle
	if b.BundleVersion != 3 || b.Name != "cloud-ci" || len(b.Items) != 4 || len(got.Items) != 4 {
		t.Fatalf("bundle = %+v", b)
	}
	if _, ok := got.Items[fixedID(0x09)]; ok {
		t.Fatal("unlisted item leaked into the bundle")
	}
	if b.HostKeyMap[fixedID(0x01)] != fixedID(0x02) {
		t.Fatal("host_key_map not copied")
	}
	// The token survives its string form.
	parsed, err := ParseToken(f.tok.String())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := OpenBundle(parsed, e, 3, f.now); err != nil {
		t.Fatal(err)
	}
}

// resealPayload signs and seals an arbitrary payload, bypassing SealBundle's
// checks, to exercise the token client's own checks.
func resealPayload(t *testing.T, f *grantFixture, b *Bundle, signer *AccountKeys, sigPK []byte, infoVersion uint64) HPKEEnvelope {
	t.Helper()
	sig, err := Sign(signer.Sig, LabelGrantBundle, b)
	if err != nil {
		t.Fatal(err)
	}
	pt, err := canonjson.Marshal(bundlePayload{V: 1, Bundle: *b, Sig: sig, SigPK: sigPK})
	if err != nil {
		t.Fatal(err)
	}
	e, err := SealHPKE(f.rec.TokenKEMPK, bundleInfo(b.GrantID, infoVersion), nil, pt)
	if err != nil {
		t.Fatal(err)
	}
	return e
}

func TestBundleSignedByWrongKey(t *testing.T) {
	f := newGrantFixture(t)
	b, err := BuildBundle(f.rec, f.items, f.acct.AccountID, 1, 1)
	if err != nil {
		t.Fatal(err)
	}
	attacker, err := NewAccountKeys(f.acct.AccountID, 1, fixedKEM(t, "attacker"), fixedBytes("attacker-sig", 32))
	if err != nil {
		t.Fatal(err)
	}
	// Signed by another key and carrying that key: fails the fingerprint.
	e := resealPayload(t, f, b, attacker, attacker.Public().SigPK, 1)
	if _, err := OpenBundle(f.tok, e, 1, f.now); err == nil {
		t.Error("bundle signed and carried by a foreign key accepted")
	}
	// Signed by another key but carrying the real sig_pk: fails S.
	e = resealPayload(t, f, b, attacker, f.acct.Public().SigPK, 1)
	if _, err := OpenBundle(f.tok, e, 1, f.now); !errors.Is(err, ErrBadSignature) {
		t.Errorf("bundle with a forged S: %v", err)
	}
	// SealBundle refuses keys for another account or akv.
	if _, err := SealBundle(fixedAccount(t, 2), f.rec, b); err == nil {
		t.Error("SealBundle used a key for another akv")
	}
}

func TestBundleOuterInnerVersionsDiffer(t *testing.T) {
	f := newGrantFixture(t)
	b, err := BuildBundle(f.rec, f.items, f.acct.AccountID, 1, 4)
	if err != nil {
		t.Fatal(err)
	}
	// Sealed under info version 5 but B says 4.
	e := resealPayload(t, f, b, f.acct, f.acct.Public().SigPK, 5)
	if _, err := OpenBundle(f.tok, e, 5, f.now); err == nil {
		t.Fatal("outer version 5 with inner version 4 accepted")
	}
	// Fetched as a different version than it was sealed under: HPKE fails.
	good := f.seal(t, 4)
	if _, err := OpenBundle(f.tok, good, 5, f.now); !errors.Is(err, ErrDecrypt) {
		t.Fatalf("wrong outer version: %v", err)
	}
}

func TestBundleTokenChecks(t *testing.T) {
	f := newGrantFixture(t)
	e := f.seal(t, 1)
	if _, err := OpenBundle(f.tok, e, 1, f.rec.ExpiresAt.Time()); err == nil {
		t.Error("bundle accepted at expires_at")
	}
	if _, err := OpenBundle(f.tok, e, 1, f.rec.ExpiresAt.Time().Add(time.Second)); err == nil {
		t.Error("expired bundle accepted")
	}
	// Another token (different seed) cannot open it.
	other := *f.tok
	other.Seed[0] ^= 1
	if _, err := OpenBundle(&other, e, 1, f.now); !errors.Is(err, ErrDecrypt) {
		t.Errorf("other token: %v", err)
	}
	// A token for another account fingerprint rejects a valid bundle.
	wrongFp := *f.tok
	wrongFp.AcctFp[0] ^= 1
	if _, err := OpenBundle(&wrongFp, e, 1, f.now); err == nil {
		t.Error("account fingerprint not checked")
	}

	// B.grant_id must match the token.
	b, _ := BuildBundle(f.rec, f.items, f.acct.AccountID, 1, 1)
	b.GrantID = fixedID(0x7f)
	pt, _ := canonjson.Marshal(bundlePayload{V: 1, Bundle: *b, Sig: mustSign(t, f.acct, b), SigPK: f.acct.Public().SigPK})
	e2, _ := SealHPKE(f.rec.TokenKEMPK, bundleInfo(f.tok.GrantID, 1), nil, pt)
	if _, err := OpenBundle(f.tok, e2, 1, f.now); err == nil {
		t.Error("bundle for another grant accepted")
	}
}

func mustSign(t *testing.T, k *AccountKeys, b *Bundle) []byte {
	t.Helper()
	s, err := Sign(k.Sig, LabelGrantBundle, b)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// Structural §8.3/§8.7 rules, checked by the token client on signed
// bundles that a careless or malicious author produced.
func TestBundleStructureRejected(t *testing.T) {
	f := newGrantFixture(t)
	base := func() *Bundle {
		b, err := BuildBundle(f.rec, f.items, f.acct.AccountID, 1, 1)
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	grantPT, _ := MarshalItem(f.rec)
	for name, mutate := range map[string]func(*Bundle){
		"duplicate item": func(b *Bundle) { b.Items = append(b.Items, b.Items[0]) },
		"grant item":     func(b *Bundle) { b.Items = append(b.Items, BundleItem{fixedID(0x05), model.TypeGrant, 1, grantPT}) },
		"outer item_id":  func(b *Bundle) { b.Items[3].ItemID = fixedID(0x0a) },
		"outer version":  func(b *Bundle) { b.Items[0].ItemVersion = 5 },
		"outer type":     func(b *Bundle) { b.Items[3].Type = model.TypeCredential },
		"bad plaintext":  func(b *Bundle) { b.Items[3].Plaintext = canonjson.Raw(`{"v":1}`) },
		"map key not a host": func(b *Bundle) {
			b.HostKeyMap = map[model.ID]model.ID{fixedID(0x03): fixedID(0x02)}
		},
		"map value not a key": func(b *Bundle) {
			b.HostKeyMap = map[model.ID]model.ID{fixedID(0x01): fixedID(0x03)}
		},
		"unmapped host key missing": func(b *Bundle) { b.HostKeyMap = map[model.ID]model.ID{} }, // host.key_id 0x09 is not listed
		"credential missing":        func(b *Bundle) { b.Items = append(b.Items[:2], b.Items[3]) },
		"unknown v":                 func(b *Bundle) { b.V = 2 },
	} {
		b := base()
		mutate(b)
		e := resealPayload(t, f, b, f.acct, f.acct.Public().SigPK, 1)
		if _, err := OpenBundle(f.tok, e, 1, f.now); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	// The payload schema is closed too.
	b := base()
	pt, _ := canonjson.Marshal(map[string]any{"v": 1, "bundle": b, "sig": mustSign(t, f.acct, b), "sig_pk": []byte(f.acct.Public().SigPK), "extra": 1})
	e, _ := SealHPKE(f.rec.TokenKEMPK, bundleInfo(b.GrantID, 1), nil, pt)
	if _, err := OpenBundle(f.tok, e, 1, f.now); err == nil {
		t.Error("payload with an unknown member accepted")
	}
}

// Bundle creation enforces §8.7 on the record.
func TestBuildBundleRecordRules(t *testing.T) {
	for name, mutate := range map[string]func(*grantFixture){
		"jump host not listed": func(f *grantFixture) {
			f.items[fixedID(0x01)].(*model.Host).JumpHostID = fixedID(0x0b)
		},
		"listed item missing": func(f *grantFixture) { delete(f.items, fixedID(0x04)) },
		"grant lists a grant": func(f *grantFixture) {
			f.rec.Items = append(f.rec.Items, fixedID(0x05))
		},
		"dedicated key of another grant": func(f *grantFixture) {
			f.items[fixedID(0x02)].(*model.Key).DedicatedGrant = fixedID(0x7e)
		},
		"dedicated key empty": func(f *grantFixture) { f.rec.DedicatedKeyID = model.ID{} },
		"dedicated key not a key": func(f *grantFixture) {
			f.rec.DedicatedKeyID = fixedID(0x03)
		},
		"dedicated grant maps another key": func(f *grantFixture) {
			f.rec.Items = []model.ID{fixedID(0x01), fixedID(0x02), fixedID(0x03), fixedID(0x04), fixedID(0x09)}
			f.rec.HostKeyMap = map[model.ID]model.ID{fixedID(0x01): fixedID(0x09)}
		},
		"shared grant with dedicated key": func(f *grantFixture) { f.rec.KeyPolicy = "shared" },
		"plaintext item_id differs": func(f *grantFixture) {
			f.items[fixedID(0x04)] = &model.Snippet{Header: hdr(model.TypeSnippet, 0x0c), Name: "s"}
		},
	} {
		f := newGrantFixture(t)
		mutate(f)
		if _, err := BuildBundle(f.rec, f.items, f.acct.AccountID, 1, 1); err == nil {
			t.Errorf("%s: built", name)
		}
	}
	// A shared grant with an empty dedicated_key_id is fine.
	f := newGrantFixture(t)
	f.rec.KeyPolicy = "shared"
	f.rec.DedicatedKeyID = model.ID{}
	if _, err := BuildBundle(f.rec, f.items, f.acct.AccountID, 1, 1); err != nil {
		t.Errorf("shared grant: %v", err)
	}
	// The record's name and expiry bind B (§8.7).
	f = newGrantFixture(t)
	b, _ := BuildBundle(f.rec, f.items, f.acct.AccountID, 1, 1)
	b.Name = "renamed"
	if _, err := SealBundle(f.acct, f.rec, b); err == nil {
		t.Error("B.name differing from the record sealed")
	}
	b, _ = BuildBundle(f.rec, f.items, f.acct.AccountID, 1, 1)
	b.ExpiresAt++
	if _, err := SealBundle(f.acct, f.rec, b); err == nil {
		t.Error("B.expires_at differing from the record sealed")
	}
	// An expired grant still gets bundles (see the SPEC GAP on BuildBundle).
	f = newGrantFixture(t)
	f.rec.ExpiresAt = ts(t, "2000-01-01T00:00:00Z")
	if _, err := BuildBundle(f.rec, f.items, f.acct.AccountID, 1, 1); err != nil {
		t.Errorf("expired grant: %v", err)
	}
}

func TestBundlePin(t *testing.T) {
	f := newGrantFixture(t)
	b3, _ := BuildBundle(f.rec, f.items, f.acct.AccountID, 1, 3)
	pin, err := BundlePin{}.Check(b3)
	if err != nil || pin.Version != 3 {
		t.Fatal(err)
	}
	if _, err := pin.Check(b3); err != nil {
		t.Fatalf("same bundle again: %v", err)
	}
	b2, _ := BuildBundle(f.rec, f.items, f.acct.AccountID, 1, 2)
	if _, err := pin.Check(b2); !errors.Is(err, ErrBundleRollback) {
		t.Fatalf("rollback: %v", err)
	}
	f.items[fixedID(0x04)].(*model.Snippet).Command = "reboot"
	b3x, _ := BuildBundle(f.rec, f.items, f.acct.AccountID, 1, 3)
	if _, err := pin.Check(b3x); !errors.Is(err, ErrBundleEquivocation) {
		t.Fatalf("equivocation: %v", err)
	}
	b4, _ := BuildBundle(f.rec, f.items, f.acct.AccountID, 1, 4)
	if next, err := pin.Check(b4); err != nil || next.Version != 4 {
		t.Fatalf("newer bundle: %v", err)
	}
}
