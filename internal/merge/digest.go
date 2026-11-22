package merge

import (
	"bytes"
	"errors"
	"fmt"
	"slices"

	"github.com/dalyem/hopkey/internal/canonjson"
	"github.com/dalyem/hopkey/internal/crypto"
	"github.com/dalyem/hopkey/internal/model"
)

// Digest labels (§5.4, §4.4). crypto defines the D function but not these
// labels.
const (
	LabelResolve      = "hopkey/v1/resolve"
	LabelMergeDiscard = "hopkey/v1/merge-discard"
	LabelMergeItem    = "hopkey/v1/merge-item"
)

// resolveObject is the object c is computed over:
// {"n":u64s, "action", "seen":item|null, "want":item|null}.
type resolveObject struct {
	N      uint64         `json:"n,string"`
	Action Action         `json:"action"`
	Seen   *canonjson.Raw `json:"seen"`
	Want   *canonjson.Raw `json:"want"`
}

func newResolveObject(n uint64, replacement Intent) (resolveObject, error) {
	if err := replacement.Validate(); err != nil {
		return resolveObject{}, err
	}
	o := resolveObject{N: n, Action: replacement.Action}
	if replacement.Seen != nil {
		p := replacement.Seen.plain
		o.Seen = &p
	}
	if replacement.Want != nil {
		p := replacement.Want.plain
		o.Want = &p
	}
	return o, nil
}

// ResolveDigest returns c = D("hopkey/v1/resolve", {"n", "action", "seen",
// "want"}) for the replacement a Keep mine or Edit proposes at outbox
// position n. The client shows it with the proposal. Automation confirms
// only by passing c back, and the client recomputes it against current S
// first, so a proposal that S has changed since needs fresh approval.
func ResolveDigest(n uint64, replacement Intent) (crypto.Hash, error) {
	o, err := newResolveObject(n, replacement)
	if err != nil {
		return crypto.Hash{}, err
	}
	return crypto.D(LabelResolve, o)
}

// ManifestRow is one row of a merge manifest (§4.4): an item that was
// moved into the import bundle, with its MergeItemDigest.
type ManifestRow struct {
	ItemID model.ID    `json:"item_id"`
	Type   model.Type  `json:"type"`
	Digest crypto.Hash `json:"digest"`
}

// discardObject is {"vault_id", "txn_id", "items":[{item_id, type, digest}]}.
type discardObject struct {
	VaultID model.ID      `json:"vault_id"`
	TxnID   model.ID      `json:"txn_id"`
	Items   []ManifestRow `json:"items"`
}

// MergeDiscardDigest returns c = D("hopkey/v1/merge-discard", {"vault_id",
// "txn_id", "items"}) (§5.4). items must be exactly the manifest rows that
// have no receipt. They may come in any order: the digest sorts a copy by
// item_id. A repeated item_id is refused.
func MergeDiscardDigest(vaultID, txnID model.ID, items []ManifestRow) (crypto.Hash, error) {
	o, err := newDiscardObject(vaultID, txnID, items)
	if err != nil {
		return crypto.Hash{}, err
	}
	return crypto.D(LabelMergeDiscard, o)
}

func newDiscardObject(vaultID, txnID model.ID, items []ManifestRow) (discardObject, error) {
	if vaultID.IsZero() || txnID.IsZero() {
		return discardObject{}, errors.New("merge: vault_id and txn_id must not be the zero ID")
	}
	rows := slices.Clone(items)
	slices.SortFunc(rows, func(a, b ManifestRow) int { return bytes.Compare(a.ItemID[:], b.ItemID[:]) })
	for i, r := range rows {
		if r.ItemID.IsZero() {
			return discardObject{}, errors.New("merge: manifest row has the zero item_id")
		}
		if err := validType(r.Type); err != nil {
			return discardObject{}, err
		}
		if i > 0 && rows[i-1].ItemID == r.ItemID {
			return discardObject{}, fmt.Errorf("merge: manifest lists item %s twice", r.ItemID)
		}
	}
	return discardObject{VaultID: vaultID, TxnID: txnID, Items: rows}, nil
}

// MergeItemDigest returns D("hopkey/v1/merge-item", plaintext) with
// item_version set to "1" (§4.4), so a manifest digest does not depend on
// the version the source vault had reached.
func MergeItemDigest(item *Item) (crypto.Hash, error) {
	p, err := mergeItemObject(item)
	if err != nil {
		return crypto.Hash{}, err
	}
	return crypto.D(LabelMergeItem, p)
}

func mergeItemObject(item *Item) (canonjson.Raw, error) {
	if item == nil {
		return nil, errors.New("merge: no item to digest")
	}
	v1, err := item.with(map[string]canonjson.Raw{"item_version": rawString("1")})
	if err != nil {
		return nil, err
	}
	return v1.plain, nil
}
