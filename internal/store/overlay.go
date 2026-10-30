package store

import (
	"errors"
	"fmt"
	"slices"

	"github.com/dalyem/hopkey/internal/crypto"
	"github.com/dalyem/hopkey/internal/merge"
	"github.com/dalyem/hopkey/internal/model"
	"github.com/dalyem/hopkey/internal/vaultlog"
)

// newPlain returns an empty plaintext of type t.
func newPlain(t model.Type) (crypto.Item, error) {
	switch t {
	case model.TypeHost:
		return new(model.Host), nil
	case model.TypeKey:
		return new(model.Key), nil
	case model.TypeCredential:
		return new(model.Credential), nil
	case model.TypeSnippet:
		return new(model.Snippet), nil
	case model.TypePolicy:
		return new(model.Policy), nil
	case model.TypeAccess:
		return new(model.Access), nil
	}
	return nil, fmt.Errorf("store: %q items do not queue", t)
}

// plainOf decodes a merge item into its model type.
func plainOf(it *merge.Item) (crypto.Item, error) {
	p, err := newPlain(it.Type())
	if err != nil {
		return nil, err
	}
	if err := it.Decode(p); err != nil {
		return nil, err
	}
	return p, nil
}

// withVersion returns it with item_version v.
func withVersion(it *merge.Item, v uint64) (*merge.Item, error) {
	p, err := plainOf(it)
	if err != nil {
		return nil, err
	}
	header(p).ItemVersion = v
	return merge.ItemOf(p)
}

func version(it *merge.Item) uint64 {
	p, err := plainOf(it)
	if err != nil {
		return 0
	}
	return header(p).ItemVersion
}

// verifiedItem returns verified state's plaintext of id as a merge item,
// or nil if id is not live (or is a grant record, which never merges).
func (s *Store) verifiedItem(id model.ID) (*merge.Item, error) {
	p, ok := s.sec.Items[id]
	if !ok {
		return nil, nil
	}
	if _, grant := p.Item.(*model.Grant); grant {
		return nil, nil
	}
	return merge.ItemOf(p.Item)
}

// evaluation is the merge rule's verdict on an intent against verified
// state, with the candidate entry for a write.
type evaluation struct {
	res  merge.Result
	wire *vaultlog.Wire
}

// evaluate rebuilds in against the verified state S with the merge rule
// (§5.4) and, for a write, builds the candidate entry with
// vaultlog.BuildNormal from verified state: the item_put or item_delete
// and every companion op (§5.3, §8.6). A build that fails, a host whose
// jump chain would loop, or a candidate over the server's admission limits
// (admitWire), holds the change. Nothing is built from the
// overlay. The caller holds s.mu.
func (s *Store) evaluate(in merge.Intent) (evaluation, error) {
	cur, err := s.verifiedItem(in.ItemID)
	if err != nil {
		return evaluation{}, err
	}
	_, live := s.state.Items[in.ItemID]
	retired := slices.Contains(s.state.Retired.ItemIDs, in.ItemID)
	if live && cur == nil {
		// The ID is a grant record. A create of it is taken; nothing else
		// can name it.
		return evaluation{res: merge.Result{Kind: merge.KindHold, Cause: merge.CauseIDTaken}}, nil
	}
	var ev evaluation
	ev.res = merge.CheckCandidate(s.accessRebase(in, merge.Rebuild(in, cur, live, retired)), func(action merge.Action, pt *merge.Item) error {
		var ch vaultlog.Changes
		if action == merge.ActionDelete {
			ch.Delete = []model.ID{in.ItemID}
		} else {
			p, err := plainOf(pt)
			if err != nil {
				return err
			}
			if err := s.checkJumpLoop(p, s.sec.Plaintexts()); err != nil {
				return err
			}
			ch.Put = []crypto.Item{p}
		}
		w, _, _, err := vaultlog.BuildNormal(s.state, s.sec, s.dev, ch, s.now(), objectDir(s.l.objects()))
		if err != nil {
			return err
		}
		// The admission preflight: a candidate the server would refuse as
		// too large holds here, before it is journaled.
		if err := admitWire(w); err != nil {
			return err
		}
		ev.wire = w
		return nil
	})
	if ev.res.Kind != merge.KindWrite {
		ev.wire = nil
	}
	return ev, nil
}

// checkJumpLoop refuses a host whose jump chain, through items, comes back
// to it.
func (s *Store) checkJumpLoop(it crypto.Item, items map[model.ID]crypto.Item) error {
	host, ok := it.(*model.Host)
	if !ok {
		return nil
	}
	seen := map[model.ID]bool{host.ItemID: true}
	for next := host.JumpHostID; !next.IsZero(); {
		if seen[next] {
			return fmt.Errorf("store: host %q has a jump host loop", host.Name)
		}
		seen[next] = true
		j, ok := items[next].(*model.Host)
		if !ok {
			break // the log rules report a missing jump host
		}
		next = j.JumpHostID
	}
	return nil
}

// overlay is what users and agents see in a server-backed vault (§11.1):
// verified state with the queued records applied in order. It is never
// verified state, and nothing is ever built from it.
type overlay struct {
	items map[model.ID]*merge.Item
	marks map[model.ID]model.Mark
}

// overlayLocked computes the overlay. Each record is merged, in n order,
// against the overlay so far, as it would be against S when its turn
// comes. A change the merge would hold shows what the user asked for; a
// held delete leaves the item in place. Affected items are marked pending,
// or held for a held record. The caller holds s.mu and the file lock.
func (s *Store) overlayLocked() (*overlay, error) {
	ov := &overlay{items: map[model.ID]*merge.Item{}, marks: map[model.ID]model.Mark{}}
	for id := range s.sec.Items {
		it, err := s.verifiedItem(id)
		if err != nil {
			return nil, err
		}
		if it != nil {
			ov.items[id] = it
		}
	}
	recs, err := s.readOutbox()
	if err != nil {
		return nil, err
	}
	gone := map[model.ID]bool{}
	for _, id := range s.state.Retired.ItemIDs {
		gone[id] = true
	}
	for _, r := range recs {
		in := r.Intent
		id := in.ItemID
		mark := model.MarkPending
		if r.Held {
			mark = model.MarkHeld
		}
		if ov.marks[id] != model.MarkHeld {
			ov.marks[id] = mark
		}
		cur := ov.items[id]
		if cur != nil && cur.Type() != in.Type {
			continue // a grant record's ID; the push holds it
		}
		res := merge.Rebuild(in, cur, cur != nil, gone[id])
		switch {
		case res.Kind == merge.KindDrop:
		case in.Action == merge.ActionDelete && (res.Kind == merge.KindWrite || !r.Held):
			delete(ov.items, id)
			gone[id] = true
		case in.Action == merge.ActionDelete:
			// A held delete: the item stays, marked held.
		default:
			next := in.Want
			if res.Kind == merge.KindWrite {
				next = res.Plaintext
			}
			v := uint64(1)
			if cur != nil {
				v = version(cur) + 1
			}
			if next, err = withVersion(next, v); err != nil {
				return nil, err
			}
			ov.items[id] = next
		}
	}
	return ov, nil
}

// snapshot decodes the overlay into a model.Snapshot with its marks.
func (ov *overlay) snapshot() (model.Snapshot, error) {
	sec := &vaultlog.Secrets{Items: map[model.ID]vaultlog.PlainItem{}}
	for id, it := range ov.items {
		p, err := plainOf(it)
		if err != nil {
			return model.Snapshot{}, err
		}
		sec.Items[id] = vaultlog.PlainItem{Item: p}
	}
	snap := snapshotOf(sec)
	if len(ov.marks) > 0 {
		snap.Marks = map[model.ID]model.Mark{}
		for id, m := range ov.marks {
			snap.Marks[id] = m
		}
	}
	return snap, nil
}

// queuePut queues a create or a put of it (§11.1). The model.Store rules
// are checked against the overlay, which is what the user sees: a
// replacement names a live overlay item of the same type at its overlay
// version, and every reference names a live overlay item of the right
// type. seen is the overlay item. A non-nil cond is checked against the
// overlay too (checkExpect), and it is made from the overlay host
// (hostKeyWrite.apply): an item a pull deleted is changed. The record is
// durable when it returns. The caller holds s.mu.
func (s *Store) queuePut(it crypto.Item, isNew bool, cond *hostKeyWrite) error {
	unlock, err := s.lockFile()
	if err != nil {
		return err
	}
	defer unlock()
	if err := s.refuseImportingWrite(); err != nil {
		return err
	}
	ov, err := s.overlayLocked()
	if err != nil {
		return err
	}
	if cond != nil {
		err := cond.apply(it, func(id model.ID) (crypto.Item, bool) {
			cur, ok := ov.items[id]
			if !ok || cur == nil {
				return nil, false
			}
			p, err := plainOf(cur)
			return p, err == nil
		})
		if err != nil {
			return err
		}
	}
	h := header(it)
	in := merge.Intent{Action: merge.ActionCreate, ItemID: h.ItemID, Type: h.Type}
	if isNew {
		h.ItemVersion = 1
	} else {
		cur, ok := ov.items[h.ItemID]
		switch {
		case !ok:
			return model.ErrNotFound
		case cur.Type() != h.Type:
			return fmt.Errorf("store: item %s is a %s, not a %s", h.ItemID, cur.Type(), h.Type)
		case version(cur) != h.ItemVersion:
			return fmt.Errorf("store: item %s is at version %d, not %d", h.ItemID, version(cur), h.ItemVersion)
		}
		in.Action, in.Seen = merge.ActionPut, cur
		h.ItemVersion = version(cur) + 1
	}
	if err := crypto.ValidateItem(it); err != nil {
		return err
	}
	if a, ok := it.(*model.Access); ok {
		var cur *model.Access
		if in.Seen != nil {
			p, err := plainOf(in.Seen)
			if err != nil {
				return err
			}
			cur = p.(*model.Access)
		}
		if err := checkAccessWrite(cur, a); err != nil {
			return err
		}
		if taken := overlayLabelTaken(ov.items, h.ItemID, a.Label); taken != "" {
			return labelErr(taken)
		}
	}
	if err := checkRefs(it, ov.items); err != nil {
		return err
	}
	items := map[model.ID]crypto.Item{}
	for id, o := range ov.items {
		if p, err := plainOf(o); err == nil {
			items[id] = p
		}
	}
	items[h.ItemID] = it
	if err := s.checkJumpLoop(it, items); err != nil {
		return err
	}
	if in.Want, err = merge.ItemOf(it); err != nil {
		return err
	}
	_, err = s.appendRecord(in)
	return err
}

// queueDelete queues a delete of a live overlay item. Like a direct delete,
// it is refused while another overlay item refers to it. Grant records are
// not references here: the push drops the item from them (§8.6).
func (s *Store) queueDelete(id model.ID) error {
	unlock, err := s.lockFile()
	if err != nil {
		return err
	}
	defer unlock()
	if err := s.refuseImportingWrite(); err != nil {
		return err
	}
	ov, err := s.overlayLocked()
	if err != nil {
		return err
	}
	cur, ok := ov.items[id]
	if !ok {
		return model.ErrNotFound
	}
	for oid, o := range ov.items {
		p, err := plainOf(o)
		if err != nil {
			return err
		}
		if h, ok := p.(*model.Host); ok && oid != id && (h.KeyID == id || h.CredentialID == id || h.JumpHostID == id) {
			return fmt.Errorf("store: host %q still refers to item %s", h.Name, id)
		}
	}
	_, err = s.appendRecord(merge.Intent{Action: merge.ActionDelete, ItemID: id, Type: cur.Type(), Seen: cur})
	return err
}

// errDangling is a reference to an item that is not in the overlay.
var errDangling = errors.New("store: a reference names no live item of the right type")

// checkRefs requires every reference a host makes to name a live overlay
// item of the matching type (§5.3, against what the user sees).
func checkRefs(it crypto.Item, items map[model.ID]*merge.Item) error {
	h, ok := it.(*model.Host)
	if !ok {
		return nil
	}
	for _, ref := range []struct {
		id  model.ID
		typ model.Type
		f   string
	}{{h.KeyID, model.TypeKey, "key_id"}, {h.CredentialID, model.TypeCredential, "credential_id"}, {h.JumpHostID, model.TypeHost, "jump_host_id"}} {
		if ref.id.IsZero() {
			continue
		}
		if o, ok := items[ref.id]; !ok || o.Type() != ref.typ {
			return fmt.Errorf("%w: host %q %s %s", errDangling, h.Name, ref.f, ref.id)
		}
	}
	return nil
}
