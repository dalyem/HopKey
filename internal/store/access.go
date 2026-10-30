package store

import (
	"context"
	"errors"
	"fmt"

	"github.com/dalyem/hopkey/internal/access"
	"github.com/dalyem/hopkey/internal/merge"
	"github.com/dalyem/hopkey/internal/model"
	"github.com/dalyem/hopkey/internal/vaultlog"
)

// Access items (crypto spec rev 17, Part 2). Every write of one is stamped
// with this device's ID in by and passes V_access against verified state
// (§5.0, §5.1): when it is journaled, on every rebase, and in every
// resolution that writes.

// ErrNothingToRecord is a resolution of an access item whose result
// changes nothing but by (§5.1 rule 6).
var ErrNothingToRecord = errors.New("store: nothing to record: use --take-theirs")

// PutAccess creates or replaces an access item. by is set to this device.
func (s *Store) PutAccess(_ context.Context, a model.Access) (model.Access, error) {
	a = *access.Clone(&a)
	out, err := put(s, &a, model.TypeAccess, nil)
	if err != nil {
		return model.Access{}, err
	}
	return *access.Clone(out), nil
}

// DeleteAccess deletes an access item: every target must be terminal, and
// removed unless forget (§5.1 rule 5).
func (s *Store) DeleteAccess(ctx context.Context, id model.ID, forget bool) error {
	s.mu.Lock()
	if s.sec == nil {
		s.mu.Unlock()
		return s.lockedErr()
	}
	cur := s.verifiedAccess(id)
	ov, err := s.accessOverlayItem(id)
	if ov != nil {
		cur = ov
	}
	s.mu.Unlock()
	if err != nil {
		return err
	}
	if cur == nil {
		return model.ErrNotFound
	}
	if err := access.CheckDelete(cur, forget); err != nil {
		return err
	}
	return s.Delete(ctx, id)
}

// accessOverlayItem is id in the overlay, in a server-backed vault, as an
// access item; nil when it is not one. The caller holds s.mu.
func (s *Store) accessOverlayItem(id model.ID) (*model.Access, error) {
	if !s.server {
		return nil, nil
	}
	unlock, err := s.lockFile()
	if err != nil {
		return nil, err
	}
	defer unlock()
	ov, err := s.overlayLocked()
	if err != nil {
		return nil, err
	}
	it, ok := ov.items[id]
	if !ok || it.Type() != model.TypeAccess {
		return nil, nil
	}
	p, err := plainOf(it)
	if err != nil {
		return nil, err
	}
	return p.(*model.Access), nil
}

// stampAccess sets by to this device on an access plaintext (§5.0).
func (s *Store) stampAccess(a *model.Access) { a.By = s.dev.ID }

// stampItem returns it with by stamped, if it is an access item.
func (s *Store) stampItem(it *merge.Item) (*merge.Item, error) {
	if it == nil || it.Type() != model.TypeAccess {
		return it, nil
	}
	p, err := plainOf(it)
	if err != nil {
		return nil, err
	}
	s.stampAccess(p.(*model.Access))
	return merge.ItemOf(p)
}

// verifiedAccess is verified state's access item id, or nil.
func (s *Store) verifiedAccess(id model.ID) *model.Access {
	a, _ := s.sec.Items[id].Item.(*model.Access)
	return a
}

// checkAccessWrite is V_access for a direct write of it (a local-only
// vault, or a put about to be journaled): against cur, the item as the
// writer sees it (nil for a create).
func checkAccessWrite(cur, next *model.Access) error {
	if err := access.Check(cur, next, access.PathWrite); err != nil {
		return err
	}
	return nil
}

// accessRebase applies §5.0 and §5.1 to the merge rule's result for an
// access intent: a write is stamped and checked with V_access against S;
// a put that changes nothing but by is dropped (rule 6); a failure holds
// the change as a rule failure.
func (s *Store) accessRebase(in merge.Intent, res merge.Result) merge.Result {
	if in.Type != model.TypeAccess || res.Kind != merge.KindWrite {
		return res
	}
	cur := s.verifiedAccess(in.ItemID)
	if res.Action == merge.ActionDelete {
		if cur != nil {
			if err := access.CheckDelete(cur, true); err != nil {
				return merge.Result{Kind: merge.KindHold, Cause: merge.CauseRuleFailure, Err: err}
			}
		}
		return res
	}
	stamped, err := s.stampItem(res.Plaintext)
	if err != nil {
		return merge.Result{Kind: merge.KindHold, Cause: merge.CauseRuleFailure, Err: err}
	}
	p, err := plainOf(stamped)
	if err != nil {
		return merge.Result{Kind: merge.KindHold, Cause: merge.CauseRuleFailure, Err: err}
	}
	next := p.(*model.Access)
	if cur != nil && !access.Substantive(cur, next) {
		return merge.Result{Kind: merge.KindDrop}
	}
	if err := access.Check(cur, next, access.PathWrite); err != nil {
		return merge.Result{Kind: merge.KindHold, Cause: merge.CauseRuleFailure, Err: err}
	}
	res.Plaintext = stamped
	return res
}

// checkAccessResolution refuses a resolution of an access item whose
// result V_access refuses, that changes nothing but by, or that creates,
// changes or clears an attestation (§2.11 as amended by Part 2, §5.0).
// want is the replacement's want, already stamped; for a retry, the
// rebased plaintext.
func (s *Store) checkAccessResolution(id model.ID, want *merge.Item) error {
	if want == nil || want.Type() != model.TypeAccess {
		return nil
	}
	p, err := plainOf(want)
	if err != nil {
		return err
	}
	next := p.(*model.Access)
	cur := s.verifiedAccess(id)
	if cur == nil {
		return access.Check(nil, next, access.PathResolve)
	}
	if !access.Substantive(cur, next) {
		return ErrNothingToRecord
	}
	if err := access.CheckAttestationUnchanged(cur, next); err != nil {
		return err
	}
	if err := access.Check(cur, next, access.PathResolve); err != nil {
		return fmt.Errorf("%w: %w", ErrReplacementRefused, err)
	}
	return nil
}

// liveAccess reports whether verified state holds a live access item.
func liveAccess(st *vaultlog.State) bool {
	for _, it := range st.Items {
		if it.Type == model.TypeAccess {
			return true
		}
	}
	return false
}

// RetiredDevices lists the devices verified state has revoked or retired,
// for attributing access records to them (§7.5).
func (s *Store) RetiredDevices() []model.ID {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.state == nil {
		return nil
	}
	return append([]model.ID(nil), s.state.Retired.DeviceIDs...)
}
