package vaultlog

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"maps"
	"slices"

	"github.com/dalyem/hopkey/internal/canonjson"
	"github.com/dalyem/hopkey/internal/crypto"
	"github.com/dalyem/hopkey/internal/model"
)

// Head is the verified head (seq, H).
type Head struct {
	Seq uint64      `json:"seq,string"`
	H   crypto.Hash `json:"h"`
}

// Short is what hop status prints: seq and the first 8 bytes of H (§5.6).
func (h Head) Short() string { return hex.EncodeToString(h.H[:8]) }

// Account is the pinned account and its public keys (§5.5).
type Account struct {
	AccountID model.ID    `json:"account_id"`
	AKV       uint32      `json:"akv"`
	FpKEM     crypto.Hash `json:"fp_kem"`
	FpSig     crypto.Hash `json:"fp_sig"`
	KEMPK     []byte      `json:"kem_pk"`
	SigPK     []byte      `json:"sig_pk"`
}

// Pin returns (account_id, akv, fp_kem, fp_sig).
func (a *Account) Pin() crypto.AccountPin {
	return crypto.AccountPin{AccountID: a.AccountID, AKV: a.AKV, FpKEM: a.FpKEM, FpSig: a.FpSig}
}

// Public returns the account public keys.
func (a *Account) Public() crypto.AccountPublic {
	return crypto.AccountPublic{AccountID: a.AccountID, AKV: a.AKV, KEMPK: a.KEMPK, SigPK: ed25519.PublicKey(a.SigPK)}
}

func accountFromOp(accountID model.ID, o *AccountKeysOp) Account {
	return Account{
		AccountID: accountID, AKV: o.AKV,
		FpKEM: crypto.FpKEM(o.KEMPK), FpSig: crypto.FpSig(o.SigPK),
		KEMPK: slices.Clone(o.KEMPK), SigPK: slices.Clone(o.SigPK),
	}
}

// ItemState is item_id → {type, item_version, iv, kv, body_sha256,
// wrap_sha256} (§5.5).
type ItemState struct {
	Type        model.Type  `json:"type"`
	ItemVersion uint64      `json:"item_version,string"`
	IV          uint32      `json:"iv"`
	KV          uint32      `json:"kv"`
	BodySHA256  crypto.Hash `json:"body_sha256"`
	WrapSHA256  crypto.Hash `json:"wrap_sha256"`
}

// GrantState is grant_id → {record_item_id, token_kem_pk, expires_at,
// bundle_version, envelope_sha256} (§5.5). Only active grants are kept: a
// grant is active from its grant_add until its grant_revoke (§5.3), and a
// revoked grant's ID moves to Retired.GrantIDs.
type GrantState struct {
	RecordItemID   model.ID        `json:"record_item_id"`
	TokenKEMPK     []byte          `json:"token_kem_pk"`
	ExpiresAt      model.Timestamp `json:"expires_at"`
	BundleVersion  uint64          `json:"bundle_version,string"`
	EnvelopeSHA256 crypto.Hash     `json:"envelope_sha256"`
}

// Retired holds the cumulative retired sets: every item deleted, device
// revoked and grant revoked since genesis (§5.3). A checkpoint's retired op
// must equal it. Each list is sorted ascending.
type Retired struct {
	ItemIDs   []model.ID `json:"item_ids"`
	DeviceIDs []model.ID `json:"device_ids"`
	GrantIDs  []model.ID `json:"grant_ids"`
}

// State is the verified durable state of §5.5. It holds only public data
// (digests and metadata); plaintexts and keys are in Secrets. The caller
// persists it, together with Secrets, in one durable commit before using
// either.
//
// SPEC GAP (§5.5): the state list does not name vault_id. It is kept
// because every transition must stay in the same vault, §6.3 and §6.4 bind
// it, and the anchor identity names it.
type State struct {
	VaultID   model.ID                 `json:"vault_id"`
	Head      Head                     `json:"head"`
	Account   Account                  `json:"account"`
	KV        uint32                   `json:"kv"`
	Creds     CredsOp                  `json:"creds"`
	VKWrap    VKWrapOp                 `json:"vk_wrap"`
	Devices   map[model.ID]DeviceAddOp `json:"devices"` // active devices, each with its complete device_add
	Items     map[model.ID]ItemState   `json:"items"`
	Grants    map[model.ID]GrantState  `json:"grants"`
	DeployOps map[model.ID]DeployOp    `json:"deploy_ops"` // incomplete and closed
	Retired   Retired                  `json:"retired"`
}

// Marshal returns the deterministic (JCS) serialization of the state.
func (s *State) Marshal() ([]byte, error) { return canonjson.Marshal(s) }

// ParseState decodes a serialized state with the strict decoder and checks
// that it is internally consistent. It does not re-run the log rules.
func ParseState(b []byte) (*State, error) {
	s := new(State)
	if err := canonjson.Unmarshal(b, s); err != nil {
		return nil, err
	}
	if err := s.selfCheck(); err != nil {
		return nil, err
	}
	return s, nil
}

func (s *State) selfCheck() error {
	if s.VaultID.IsZero() || s.Account.AccountID.IsZero() {
		return errors.New("vaultlog: state has an empty vault or account ID")
	}
	if !crypto.FpKEM(s.Account.KEMPK).Equal(s.Account.FpKEM) || !crypto.FpSig(s.Account.SigPK).Equal(s.Account.FpSig) {
		return errors.New("vaultlog: state account fingerprints do not match its keys")
	}
	for id, d := range s.Devices {
		if d.Cert.DeviceID != id {
			return errors.New("vaultlog: state device map key differs from its certificate")
		}
	}
	for id, o := range s.DeployOps {
		if o.OpID != id {
			return errors.New("vaultlog: state deploy_op map key differs from its op_id")
		}
	}
	for _, l := range [][]model.ID{s.Retired.ItemIDs, s.Retired.DeviceIDs, s.Retired.GrantIDs} {
		if err := checkSortedIDs("state", "retired", l); err != nil {
			return err
		}
	}
	return nil
}

// Pin returns the pinned account.
func (s *State) Pin() crypto.AccountPin { return s.Account.Pin() }

// ObjectDigests returns every object digest the state names: the VK
// envelope, both credential blobs, every active device's unlock blob, every
// live item's wrap and body, and every active grant's bundle.
func (s *State) ObjectDigests() []crypto.Hash {
	out := []crypto.Hash{s.VKWrap.EnvelopeSHA256, s.Creds.PwBlobSHA256, s.Creds.RkBlobSHA256}
	for _, d := range s.Devices {
		out = append(out, d.UnlockSHA256)
	}
	for _, it := range s.Items {
		out = append(out, it.WrapSHA256, it.BodySHA256)
	}
	for _, g := range s.Grants {
		out = append(out, g.EnvelopeSHA256)
	}
	return out
}

// Usable reports whether an object digest is named by this state. Only such
// objects may be used: a digest found only in history is not enough (§5.5).
func (s *State) Usable(h crypto.Hash) bool {
	return slices.Contains(s.ObjectDigests(), h)
}

// IncompleteDeployOps returns the op IDs of every deploy_op that is not
// closed, sorted.
func (s *State) IncompleteDeployOps() []model.ID {
	var out []model.ID
	for id, o := range s.DeployOps {
		if !o.Closed() {
			out = append(out, id)
		}
	}
	sortIDs(out)
	return out
}

func (s *State) clone() *State {
	c := *s
	c.Account.KEMPK = slices.Clone(s.Account.KEMPK)
	c.Account.SigPK = slices.Clone(s.Account.SigPK)
	c.Creds.Salt = slices.Clone(s.Creds.Salt)
	c.Devices = maps.Clone(s.Devices)
	c.Items = maps.Clone(s.Items)
	c.Grants = maps.Clone(s.Grants)
	c.DeployOps = maps.Clone(s.DeployOps)
	c.Retired = Retired{
		ItemIDs:   slices.Clone(s.Retired.ItemIDs),
		DeviceIDs: slices.Clone(s.Retired.DeviceIDs),
		GrantIDs:  slices.Clone(s.Retired.GrantIDs),
	}
	return &c
}

func emptyState() *State {
	return &State{
		Devices:   map[model.ID]DeviceAddOp{},
		Items:     map[model.ID]ItemState{},
		Grants:    map[model.ID]GrantState{},
		DeployOps: map[model.ID]DeployOp{},
		Retired:   Retired{ItemIDs: []model.ID{}, DeviceIDs: []model.ID{}, GrantIDs: []model.ID{}},
	}
}

func sortIDs(ids []model.ID) {
	slices.SortFunc(ids, func(a, b model.ID) int { return bytes.Compare(a[:], b[:]) })
}

// idSet is a set of IDs.
type idSet map[model.ID]bool

func setOf(ids []model.ID) idSet {
	s := make(idSet, len(ids))
	for _, id := range ids {
		s[id] = true
	}
	return s
}

func (s idSet) sorted() []model.ID {
	out := make([]model.ID, 0, len(s))
	for id := range s {
		out = append(out, id)
	}
	sortIDs(out)
	return out
}

func (s idSet) equal(o idSet) bool {
	if len(s) != len(o) {
		return false
	}
	for id := range s {
		if !o[id] {
			return false
		}
	}
	return true
}

// allIDs returns every ID in the live sets (items, devices, grants, deploy
// ops) and in retired, with a count of how often each occurs.
//
// SPEC GAP (§5.3, §5.5): "the live sets" are not enumerated. This code
// counts items, active devices, active grants and every deploy_op op_id
// (op_ids are never removed and "can never be recreated").
func (s *State) allIDs() map[model.ID]int {
	n := map[model.ID]int{}
	for id := range s.Items {
		n[id]++
	}
	for id := range s.Devices {
		n[id]++
	}
	for id := range s.Grants {
		n[id]++
	}
	for id := range s.DeployOps {
		n[id]++
	}
	for _, l := range [][]model.ID{s.Retired.ItemIDs, s.Retired.DeviceIDs, s.Retired.GrantIDs} {
		for _, id := range l {
			n[id]++
		}
	}
	return n
}
