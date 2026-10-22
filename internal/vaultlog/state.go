package vaultlog

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"fmt"
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
// either. It also holds vault_id (rev 10 item 3) and the signed account-key
// and VK-commitment history (rev 12).
type State struct {
	VaultID model.ID `json:"vault_id"`
	Head    Head     `json:"head"`
	Account Account  `json:"account"`
	// History runs from version 1 through Account.AKV and KV. An anchor
	// imports it whole, so every client at the same head holds the same
	// state (rev 12).
	History   History                  `json:"history"`
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
	h := &s.History
	if err := checkHistoryRows(h.Accounts, h.VKCommits); err != nil {
		return fmt.Errorf("vaultlog: state history: %w", err)
	}
	if last := h.Accounts[len(h.Accounts)-1]; !last.matches(&s.Account) || len(h.VKCommits) != int(s.KV) {
		return errors.New("vaultlog: state history does not end at the current account keys and kv")
	}
	return nil
}

// matches reports whether the row names a's akv and fingerprints.
func (r AccountRow) matches(a *Account) bool {
	return r.AKV == a.AKV && r.FpKEM.Equal(a.FpKEM) && r.FpSig.Equal(a.FpSig)
}

// lastAccount and lastVK return the rows for the current akv and kv.
func (h *History) lastAccount() AccountRow { return h.Accounts[len(h.Accounts)-1] }
func (h *History) lastVK() VKRow           { return h.VKCommits[len(h.VKCommits)-1] }

// checkFreshAccount requires an account key pair with fingerprints fk and
// fs to differ from every key in earlier, the earlier history rows (rev 11;
// global since rev 12).
func checkFreshAccount(earlier []AccountRow, fk, fs crypto.Hash) error {
	var kem, sig bool
	for _, r := range earlier {
		kem = kem || fk.Equal(r.FpKEM)
		sig = sig || fs.Equal(r.FpSig)
	}
	switch {
	case kem && sig:
		return fail(RuleCheckpointFreshKeys, "account_keys reuse an earlier KEM key and an earlier signing key")
	case kem:
		return fail(RuleCheckpointFreshKeys, "account_keys.kem_pk reuses an earlier account key")
	case sig:
		return fail(RuleCheckpointFreshKeys, "account_keys.sig_pk reuses an earlier account key")
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
	c.History = s.History.clone()
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
		History:   History{Accounts: []AccountRow{}, VKCommits: []VKRow{}},
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

// allIDs returns every ID in the live sets and in retired, with a count of
// how often each occurs. The live sets are the live item IDs, the active
// device IDs, the active grant IDs and every deploy_op ID (rev 10 item 4).
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
