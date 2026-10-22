package crypto

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"time"

	"github.com/dalyem/hopkey/internal/canonjson"
	"github.com/dalyem/hopkey/internal/model"
)

// BundleItem is one entry of B.items (§8.2).
type BundleItem struct {
	ItemID      model.ID      `json:"item_id"`
	Type        model.Type    `json:"type"`
	ItemVersion uint64        `json:"item_version,string"`
	Plaintext   canonjson.Raw `json:"plaintext"`
}

// Bundle is B (§8.2).
type Bundle struct {
	V             int                   `json:"v"`
	GrantID       model.ID              `json:"grant_id"`
	AccountID     model.ID              `json:"account_id"`
	AKV           uint32                `json:"akv"`
	Name          string                `json:"name"`
	BundleVersion uint64                `json:"bundle_version,string"`
	ExpiresAt     model.Timestamp       `json:"expires_at"`
	Items         []BundleItem          `json:"items"`
	HostKeyMap    map[model.ID]model.ID `json:"host_key_map"`
}

// bundlePayload is the sealed plaintext {"v":1,"bundle":B,"sig":b64(S),"sig_pk":b64}.
type bundlePayload struct {
	V      int    `json:"v"`
	Bundle Bundle `json:"bundle"`
	Sig    []byte `json:"sig"`
	SigPK  []byte `json:"sig_pk"`
}

// Digest returns SHA-256(JCS(B)), the value §8.4 pins.
func (b *Bundle) Digest() (Hash, error) {
	j, err := canonjson.Marshal(b)
	if err != nil {
		return Hash{}, err
	}
	return sha256.Sum256(j), nil
}

func bundleInfo(grantID model.ID, version uint64) []byte {
	return cat(lps(LabelGrantBundle), LP(grantID[:]), U64(version))
}

// isType reports whether the item with id in items has type t.
func isType(items map[model.ID]Item, id model.ID, t model.Type) bool {
	it, ok := items[id]
	if !ok {
		return false
	}
	h, err := ItemHeader(it)
	return err == nil && h.Type == t
}

// checkReferences applies the token-mode reference rule (§8.7): within
// items, host_key_map overrides host.key_id for a mapped host, and every
// other non-empty reference a host uses resolves to an item of the
// matching type. It also checks that every host_key_map key is a host and
// every value a key (§8.3).
func checkReferences(items map[model.ID]Item, hostKeyMap map[model.ID]model.ID) error {
	for h, k := range hostKeyMap {
		if !isType(items, h, model.TypeHost) {
			return fmt.Errorf("crypto: host_key_map key %v is not a host in the grant", h)
		}
		if !isType(items, k, model.TypeKey) {
			return fmt.Errorf("crypto: host_key_map value %v is not a key in the grant", k)
		}
	}
	for id, it := range items {
		host, ok := it.(*model.Host)
		if !ok {
			continue
		}
		key := host.KeyID
		if mapped, ok := hostKeyMap[id]; ok {
			key = mapped
		}
		if !key.IsZero() && !isType(items, key, model.TypeKey) {
			return fmt.Errorf("crypto: host %v uses key %v, which is not in the grant", id, key)
		}
		if !host.CredentialID.IsZero() && !isType(items, host.CredentialID, model.TypeCredential) {
			return fmt.Errorf("crypto: host %v uses credential %v, which is not in the grant", id, host.CredentialID)
		}
		if !host.JumpHostID.IsZero() && !isType(items, host.JumpHostID, model.TypeHost) {
			return fmt.Errorf("crypto: host %v uses jump host %v, which is not in the grant", id, host.JumpHostID)
		}
	}
	return nil
}

// CheckGrantRecord checks a grant record against the items it lists
// (§6.5, §8.7). items must hold the verified current plaintexts and may
// hold more than the record lists. It checks:
//   - the §6.5 schema;
//   - every listed item exists and has type host, key, credential or
//     snippet;
//   - host_key_map and every host reference resolve within the listed items;
//   - key_policy "dedicated": dedicated_key_id names a listed key whose
//     dedicated_grant is this grant, and every host_key_map value is that key;
//   - key_policy "shared": dedicated_key_id is "". (The reach-warning
//     confirmation is the caller's job.)
func CheckGrantRecord(rec *model.Grant, items map[model.ID]Item) error {
	if err := ValidateGrant(rec); err != nil {
		return err
	}
	listed := make(map[model.ID]Item, len(rec.Items))
	for _, id := range rec.Items {
		it, ok := items[id]
		if !ok {
			return fmt.Errorf("crypto: grant lists item %v, which is not available", id)
		}
		h, err := ItemHeader(it)
		if err != nil {
			return err
		}
		if h.ItemID != id {
			return fmt.Errorf("crypto: item %v has plaintext item_id %v", id, h.ItemID)
		}
		if !isBundleType(h.Type) {
			return fmt.Errorf("crypto: grant lists item %v of type %q: %w", id, h.Type, errNotBundleType)
		}
		listed[id] = it
	}
	if err := checkReferences(listed, rec.HostKeyMap); err != nil {
		return err
	}
	switch rec.KeyPolicy {
	case "dedicated":
		k, ok := listed[rec.DedicatedKeyID].(*model.Key)
		if rec.DedicatedKeyID.IsZero() || !ok {
			return errors.New("crypto: dedicated_key_id must name a key listed in the grant")
		}
		if k.DedicatedGrant != rec.GrantID {
			return errors.New("crypto: the dedicated key's dedicated_grant is not this grant")
		}
		for _, v := range rec.HostKeyMap {
			if v != rec.DedicatedKeyID {
				return errors.New("crypto: a dedicated grant maps a host to a key other than its dedicated key")
			}
		}
	case "shared":
		if !rec.DedicatedKeyID.IsZero() {
			return errors.New("crypto: a shared grant must have an empty dedicated_key_id")
		}
	}
	return nil
}

// BuildBundle builds B from a verified grant record and the verified
// current item plaintexts (§8.6): B.items are the record's items at their
// current versions, host_key_map is copied from the record, and B.name and
// B.expires_at come from the record (§8.7). The result is validated against
// §8.3 before it is returned.
//
// SPEC GAP (§5.3 vs §8.3): the author must validate B "against §8.3", which
// includes "expires_at is in the future", yet log rules treat an expired
// grant as active and require a bundle_put for it whenever a listed item
// changes. Applying the expiry check here would make such edits impossible,
// so BuildBundle applies every §8.3 rule except expiry, which only the token
// client (OpenBundle) checks against its clock.
func BuildBundle(rec *model.Grant, items map[model.ID]Item, accountID model.ID, akv uint32, bundleVersion uint64) (*Bundle, error) {
	if err := CheckGrantRecord(rec, items); err != nil {
		return nil, err
	}
	b := &Bundle{
		V:             Version,
		GrantID:       rec.GrantID,
		AccountID:     accountID,
		AKV:           akv,
		Name:          rec.Name,
		BundleVersion: bundleVersion,
		ExpiresAt:     rec.ExpiresAt,
		Items:         make([]BundleItem, 0, len(rec.Items)),
		HostKeyMap:    make(map[model.ID]model.ID, len(rec.HostKeyMap)),
	}
	for _, id := range rec.Items {
		it := items[id]
		h, _ := ItemHeader(it)
		pt, err := MarshalItem(it)
		if err != nil {
			return nil, err
		}
		b.Items = append(b.Items, BundleItem{ItemID: h.ItemID, Type: h.Type, ItemVersion: h.ItemVersion, Plaintext: pt})
	}
	for k, v := range rec.HostKeyMap {
		b.HostKeyMap[k] = v
	}
	if _, err := validateBundle(b); err != nil {
		return nil, err
	}
	return b, nil
}

// validateBundle applies the §8.3 structural rules (all but the token
// fingerprint, signature, grant_id, expiry and info-version checks) and the
// §8.7 binding of outer item fields to plaintexts. It returns the decoded
// items.
func validateBundle(b *Bundle) (map[model.ID]Item, error) {
	if b.V != Version {
		return nil, ErrUnsupported
	}
	if err := CheckID("grant_id", b.GrantID); err != nil {
		return nil, err
	}
	if err := CheckID("account_id", b.AccountID); err != nil {
		return nil, err
	}
	if err := CheckStr("name", b.Name, 64); err != nil {
		return nil, err
	}
	if _, err := b.ExpiresAt.MarshalText(); err != nil {
		return nil, schemaErr("expires_at", "%v", err)
	}
	items := make(map[model.ID]Item, len(b.Items))
	for i, bi := range b.Items {
		if !isBundleType(bi.Type) {
			return nil, fmt.Errorf("crypto: bundle item %d has type %q: %w", i, bi.Type, errNotBundleType)
		}
		if _, dup := items[bi.ItemID]; dup {
			return nil, fmt.Errorf("crypto: bundle lists item %v twice", bi.ItemID)
		}
		it, err := ParseItem(bi.Type, bi.Plaintext)
		if err != nil {
			return nil, fmt.Errorf("crypto: bundle item %d: %w", i, err)
		}
		h, _ := ItemHeader(it)
		if h.ItemID != bi.ItemID || h.Type != bi.Type || h.ItemVersion != bi.ItemVersion {
			return nil, fmt.Errorf("crypto: bundle item %d: outer fields do not match the plaintext", i)
		}
		items[bi.ItemID] = it
	}
	if err := checkReferences(items, b.HostKeyMap); err != nil {
		return nil, err
	}
	return items, nil
}

// SealBundle signs B with the account key for its akv and seals it to the
// grant's token KEM key (§8.2):
//
//	S        = Sig(acct_sig[akv], "hopkey/v1/grant-bundle", B)
//	envelope = HPKE.Seal(token_kem_pk, info = lp("hopkey/v1/grant-bundle")
//	           || lp(grant_id16) || u64(bundle_version), aad = empty,
//	           pt = JCS({"v":1,"bundle":B,"sig":b64(S),"sig_pk":b64}))
//
// rec is the grant record the bundle belongs to; its grant_id, name and
// expires_at must equal B's (§8.7), and token_kem_pk comes from it.
func SealBundle(acct *AccountKeys, rec *model.Grant, b *Bundle) (HPKEEnvelope, error) {
	if acct.AccountID != b.AccountID || acct.AKV != b.AKV {
		return HPKEEnvelope{}, errors.New("crypto: bundle names a different account or akv than the signing key")
	}
	if rec.GrantID != b.GrantID || rec.Name != b.Name || rec.ExpiresAt != b.ExpiresAt {
		return HPKEEnvelope{}, errors.New("crypto: bundle grant_id, name or expires_at differ from the grant record")
	}
	if _, err := validateBundle(b); err != nil {
		return HPKEEnvelope{}, err
	}
	sig, err := Sign(acct.Sig, LabelGrantBundle, b)
	if err != nil {
		return HPKEEnvelope{}, err
	}
	pub := acct.Public()
	pt, err := canonjson.Marshal(bundlePayload{V: Version, Bundle: *b, Sig: sig, SigPK: pub.SigPK})
	if err != nil {
		return HPKEEnvelope{}, err
	}
	defer clear(pt)
	return SealHPKE(rec.TokenKEMPK, bundleInfo(b.GrantID, b.BundleVersion), nil, pt)
}

// OpenedBundle is a bundle that passed every §8.3 check.
type OpenedBundle struct {
	Bundle *Bundle
	Items  map[model.ID]Item // decoded plaintexts, by item_id
	SigPK  []byte            // the account signing key that signed it
}

// OpenBundle is the token client's verification (§8.3). bundleVersion is
// the version the bundle was fetched as; it goes into the HPKE info and
// must equal B.bundle_version. now is the client's clock.
func OpenBundle(tok *Token, e HPKEEnvelope, bundleVersion uint64, now time.Time) (*OpenedBundle, error) {
	sk, err := tok.KEMKey()
	if err != nil {
		return nil, err
	}
	pt, err := OpenHPKE(sk, e, bundleInfo(tok.GrantID, bundleVersion), nil)
	if err != nil {
		return nil, err
	}
	defer clear(pt)
	var p bundlePayload
	if err := canonjson.Unmarshal(pt, &p); err != nil {
		return nil, err
	}
	if p.V != Version {
		return nil, ErrUnsupported
	}
	if !tok.MatchesAccount(p.SigPK) {
		return nil, errors.New("crypto: bundle signing key does not match the token's account fingerprint")
	}
	if err := Verify(p.SigPK, LabelGrantBundle, &p.Bundle, p.Sig); err != nil {
		return nil, err
	}
	b := &p.Bundle
	if b.GrantID != tok.GrantID {
		return nil, errors.New("crypto: bundle is for a different grant")
	}
	if !b.ExpiresAt.Time().After(now) {
		return nil, errors.New("crypto: grant has expired")
	}
	if b.BundleVersion != bundleVersion {
		return nil, errors.New("crypto: bundle_version differs from the version it was sealed under")
	}
	items, err := validateBundle(b)
	if err != nil {
		return nil, err
	}
	return &OpenedBundle{Bundle: b, Items: items, SigPK: p.SigPK}, nil
}

// BundlePin is the §8.4 rollback pin kept per grant_id when HOP_STATE_DIR
// is set.
type BundlePin struct {
	Version uint64
	Digest  Hash
}

// ErrBundleRollback and ErrBundleEquivocation are the two §8.4 failures.
var (
	ErrBundleRollback     = errors.New("crypto: bundle version is lower than the pinned version")
	ErrBundleEquivocation = errors.New("crypto: bundle differs from the pinned bundle of the same version")
)

// Check compares a verified bundle with the pin. It returns the pin to
// store if the bundle is acceptable.
func (p BundlePin) Check(b *Bundle) (BundlePin, error) {
	d, err := b.Digest()
	if err != nil {
		return p, err
	}
	switch {
	case b.BundleVersion < p.Version:
		return p, ErrBundleRollback
	case b.BundleVersion == p.Version && !d.Equal(p.Digest):
		return p, ErrBundleEquivocation
	}
	return BundlePin{Version: b.BundleVersion, Digest: d}, nil
}
