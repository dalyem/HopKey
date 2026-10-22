package vaultlog

import (
	"errors"
	"slices"

	"github.com/dalyem/hopkey/internal/canonjson"
	"github.com/dalyem/hopkey/internal/crypto"
	"github.com/dalyem/hopkey/internal/model"
)

// PublicState is the state a server derives from the public ops of the log
// (rev 16): the head, the account keys and akv, kv, creds, the active
// devices, the item map metadata, grants, deploy ops, the retired sets and
// vk_wrap. It is for servers only.
//
// It is not verified state. ApplyPublic runs only the public stage of §5.5:
// no unlock blob, VK commitment, item plaintext or other plaintext rule is
// checked. A client must never use it in place of the State that Transition
// or Anchor returns. It is a separate type with no conversion to State, and
// its serialization is not one ParseState accepts (nor the reverse).
//
// The zero value, like a nil *PublicState, is the empty state before
// genesis.
type PublicState struct {
	s *State // nil before genesis

	// The devices the head entry revoked and retired, each sorted.
	revoked []model.ID
	retired []model.ID
}

// ApplyPublic runs the public stage (CheckPublic) of w against pre and
// returns the post-state the public ops alone determine. With an empty or
// nil pre it accepts only a genesis entry. It returns the same errors as
// CheckPublic, including ErrAlreadyApplied, ErrStale and
// *EquivocationError. pre is not modified. objs supplies objects the wire
// does not carry; it may be nil.
//
// The result shares data with w; the caller must not modify w afterwards.
func ApplyPublic(pre *PublicState, w *Wire, objs ObjectFetcher) (*PublicState, error) {
	var s *State
	if pre != nil {
		s = pre.s
	}
	c, err := CheckPublic(s, w, objs)
	if err != nil {
		return nil, err
	}
	return &PublicState{s: c.Post, revoked: c.revokedDevices.sorted(), retired: c.retiredDevices.sorted()}, nil
}

// Empty reports whether the state is before genesis.
func (p *PublicState) Empty() bool { return p == nil || p.s == nil }

// Head returns the head (seq, H), or the zero Head when the state is
// empty.
func (p *PublicState) Head() Head {
	if p.Empty() {
		return Head{}
	}
	return p.s.Head
}

// VaultID returns the vault ID, or the zero ID when the state is empty.
func (p *PublicState) VaultID() model.ID {
	if p.Empty() {
		return model.ID{}
	}
	return p.s.VaultID
}

// AccountID returns the account ID, or the zero ID when the state is empty.
func (p *PublicState) AccountID() model.ID {
	if p.Empty() {
		return model.ID{}
	}
	return p.s.Account.AccountID
}

// Account returns the current account public keys and akv.
func (p *PublicState) Account() (crypto.AccountPublic, bool) {
	if p.Empty() {
		return crypto.AccountPublic{}, false
	}
	a := p.s.Account.Public()
	a.KEMPK = slices.Clone(a.KEMPK)
	a.SigPK = slices.Clone(a.SigPK)
	return a, true
}

// DeviceActive reports whether device id is active.
func (p *PublicState) DeviceActive(id model.ID) bool {
	_, ok := p.Device(id)
	return ok
}

// Device returns the complete device_add of an active device, which holds
// its public keys and certificate.
func (p *PublicState) Device(id model.ID) (DeviceAddOp, bool) {
	if p.Empty() {
		return DeviceAddOp{}, false
	}
	d, ok := p.s.Devices[id]
	if !ok {
		return DeviceAddOp{}, false
	}
	d.CertSig = slices.Clone(d.CertSig)
	d.KEMPK = slices.Clone(d.KEMPK)
	d.SigPK = slices.Clone(d.SigPK)
	return d, true
}

// Creds returns the latest creds op: salt, kdf_version, auth_sha256,
// rauth_sha256 and the pw_blob and rk_blob digests.
func (p *PublicState) Creds() (CredsOp, bool) {
	if p.Empty() {
		return CredsOp{}, false
	}
	c := p.s.Creds
	c.Salt = slices.Clone(c.Salt)
	return c, true
}

// ObjectDigests returns every object digest the state names (see
// State.ObjectDigests).
func (p *PublicState) ObjectDigests() []crypto.Hash {
	if p.Empty() {
		return nil
	}
	return p.s.ObjectDigests()
}

// DepartureKind is how a device left the account (§9 retirement status).
type DepartureKind string

const (
	DepartRetired DepartureKind = "retired" // device_retire
	DepartRevoked DepartureKind = "revoked" // a checkpoint's device_revoke
)

// Departure is a device that the head entry removed: what a server ends
// sessions for and writes a permanent receipt {device_id, how, seq, H}
// about (§9).
type Departure struct {
	DeviceID model.ID
	How      DepartureKind
	Head     Head // the removing entry
}

// Departures returns the devices the head entry retired or revoked, sorted
// by device ID within each kind, retirements first. It is empty for
// every other entry.
func (p *PublicState) Departures() []Departure {
	if p.Empty() {
		return nil
	}
	var out []Departure
	for _, id := range p.retired {
		out = append(out, Departure{DeviceID: id, How: DepartRetired, Head: p.s.Head})
	}
	for _, id := range p.revoked {
		out = append(out, Departure{DeviceID: id, How: DepartRevoked, Head: p.s.Head})
	}
	return out
}

// publicStateJSON is the serialized PublicState. Its members differ from
// State's, so neither parser accepts the other's output.
type publicStateJSON struct {
	State       *State     `json:"public_state"`
	HeadRevoked []model.ID `json:"head_revoked"`
	HeadRetired []model.ID `json:"head_retired"`
}

// Marshal returns the deterministic (JCS) serialization. An empty state
// has none.
func (p *PublicState) Marshal() ([]byte, error) {
	if p.Empty() {
		return nil, errors.New("vaultlog: an empty public state has no serialization")
	}
	return canonjson.Marshal(&publicStateJSON{
		State:       p.s,
		HeadRevoked: slices.Clone(p.revoked),
		HeadRetired: slices.Clone(p.retired),
	})
}

// ParsePublicState decodes a serialized PublicState with the strict decoder
// and checks that it is internally consistent. It does not re-run the log
// rules.
func ParsePublicState(b []byte) (*PublicState, error) {
	var j publicStateJSON
	if err := canonjson.Unmarshal(b, &j); err != nil {
		return nil, err
	}
	if j.State == nil {
		return nil, errors.New("vaultlog: public state has no state")
	}
	if err := j.State.selfCheck(); err != nil {
		return nil, err
	}
	retired := setOf(j.State.Retired.DeviceIDs)
	for _, l := range [][]model.ID{j.HeadRevoked, j.HeadRetired} {
		if err := checkSortedIDs("public state", "head departures", l); err != nil {
			return nil, err
		}
		for _, id := range l {
			if _, active := j.State.Devices[id]; active || !retired[id] {
				return nil, errors.New("vaultlog: public state names a departed device that is active or not retired")
			}
		}
	}
	if len(setOf(slices.Concat(j.HeadRevoked, j.HeadRetired))) != len(j.HeadRevoked)+len(j.HeadRetired) {
		return nil, errors.New("vaultlog: public state names a device as both revoked and retired")
	}
	return &PublicState{
		s:       j.State,
		revoked: nonNil(j.HeadRevoked),
		retired: nonNil(j.HeadRetired),
	}, nil
}

func nonNil(ids []model.ID) []model.ID {
	if ids == nil {
		return []model.ID{}
	}
	return ids
}
