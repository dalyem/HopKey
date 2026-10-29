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

// Resolving a held head in place (§5.4, §11.1).

var (
	// ErrNotHeld means the outbox head is not held (or there is none).
	ErrNotHeld = errors.New("store: the outbox head is not held")
	// ErrImportRecord means the head is an import record of a login merge.
	// Those are resolved only through the merge's pause, resume and
	// discard (§4.4); take theirs in particular is refused.
	ErrImportRecord = errors.New("store: the outbox head is an import record; resolve it through hop auth merge")
	// ErrLiveCandidate means the head still has a candidate that may
	// commit. It can be resolved only once all its candidates are dead.
	ErrLiveCandidate = errors.New("store: the outbox head has a candidate that may still commit")
	// ErrNoLongerHeld means the held change would apply now: retry it.
	ErrNoLongerHeld = errors.New("store: the held change would apply now; retry it")
	// ErrStillHeld means a retry found the change still held.
	ErrStillHeld = errors.New("store: the change is still held")
	// ErrStaleConfirm means the confirmation digest is not the one for the
	// replacement against current state: S changed, so the user must
	// approve again (§5.4).
	ErrStaleConfirm = errors.New("store: the confirmation does not match the current proposal")
	// ErrReplacementRefused means a keep mine or edit replacement would not
	// apply to verified state: a reference names no verified item (one that
	// only a later queued record creates included), or a §5.3 rule such as
	// a deploy-op blocker fails (§11.1).
	ErrReplacementRefused = errors.New("store: the replacement does not apply to verified state")
)

// Resolution is the user's choice for the held outbox head.
type Resolution struct {
	Choice merge.Choice
	// Edited is the user's edited item for merge.ChoiceEdit, edited from
	// HeldRecord.EditStart. It may be nil only to turn a put whose item
	// isn't live into a fresh create of the held want unchanged.
	Edited crypto.Item
	// NewID is the fresh item ID of a put turned into a create. Propose
	// picks one; pass it back to Resolve.
	NewID model.ID
	// Confirm is the digest c of the proposal, needed for keep mine, edit
	// and the two --merge choices. Resolve recomputes it against current
	// state and refuses a different one.
	Confirm crypto.Hash
}

// HeldRecord is the held outbox head, for hop sync resolve.
type HeldRecord struct {
	N      uint64
	Import bool
	Action merge.Action
	ItemID model.ID
	Type   model.Type
	// Seen and Want are the held intent's plaintexts (canonical JSON), and
	// Current is the item in verified state; each is nil when absent.
	Seen, Want, Current []byte
	// Hold says why it is held now. It is nil if a retry would apply it.
	Hold *HoldInfo
}

// Proposal is the replacement a keep mine, an edit or a --merge choice
// would write, with the digest c the user confirms (§5.4). Take theirs and
// retry need none.
type Proposal struct {
	N      uint64
	Choice merge.Choice
	Action merge.Action
	ItemID model.ID
	Type   model.Type
	// Seen and Want are the replacement's plaintexts (canonical JSON), nil
	// when absent. Want, or Seen for a delete, is what the user confirms.
	Seen, Want []byte
	NewID      model.ID
	Digest     crypto.Hash
}

// HeldHead returns the held outbox head, or nil if the head is not held.
func (s *Store) HeldHead() (*HeldRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.needServer(); err != nil {
		return nil, err
	}
	unlock, err := s.lockFile()
	if err != nil {
		return nil, err
	}
	defer unlock()
	recs, err := s.readOutbox()
	if err != nil || len(recs) == 0 || !recs[0].Held {
		return nil, err
	}
	rec := recs[0]
	ev, err := s.evaluate(rec.Intent)
	if err != nil {
		return nil, err
	}
	in := rec.Intent
	out := &HeldRecord{N: rec.N, Import: !rec.Import.IsZero(), Action: in.Action, ItemID: in.ItemID, Type: in.Type}
	if in.Seen != nil {
		out.Seen = in.Seen.Plaintext()
	}
	if in.Want != nil {
		out.Want = in.Want.Plaintext()
	}
	if cur, err := s.verifiedItem(in.ItemID); err != nil {
		return nil, err
	} else if cur != nil {
		out.Current = cur.Plaintext()
	}
	if ev.res.Kind == merge.KindHold {
		out.Hold = holdInfo(ev.res)
	}
	return out, nil
}

// Propose computes the replacement a resolution would write and its digest
// c, without writing anything.
func (s *Store) Propose(r Resolution) (Proposal, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	unlock, err := s.lockFile()
	if err != nil {
		return Proposal{}, err
	}
	defer unlock()
	rec, ev, err := s.heldHeadLocked()
	if err != nil {
		return Proposal{}, err
	}
	p := Proposal{N: rec.N, Choice: r.Choice}
	if !confirmed(r.Choice) {
		return p, nil
	}
	repl, newID, err := s.replacement(rec, ev, &r)
	if err != nil {
		return Proposal{}, err
	}
	d, err := merge.ResolveDigest(rec.N, repl)
	if err != nil {
		return Proposal{}, err
	}
	p.Action, p.ItemID, p.Type, p.NewID, p.Digest = repl.Action, repl.ItemID, repl.Type, newID, d
	if repl.Seen != nil {
		p.Seen = repl.Seen.Plaintext()
	}
	if repl.Want != nil {
		p.Want = repl.Want.Plaintext()
	}
	return p, nil
}

// Resolve resolves the held outbox head in place (§11.1), in one durable
// commit:
//
//   - keep mine and edit replace the record's intent at the same n, using
//     the §5.4 table, keep its (dead) candidates and clear held. They need
//     r.Confirm to equal the digest of the replacement against current
//     state. Keep mine --merge and take theirs --merge are computed edits
//     (rev 17) and do the same with their proposals.
//   - take theirs deletes the record.
//   - retry re-evaluates the unchanged intent against current verified
//     state and clears held only if every rule passes; otherwise it
//     returns ErrStillHeld and the record stays held.
//
// Later records keep their original seen. Import records, and a head with
// a live candidate, are refused.
func (s *Store) Resolve(r Resolution) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	unlock, err := s.lockFile()
	if err != nil {
		return err
	}
	defer unlock()
	rec, ev, err := s.heldHeadLocked()
	if err != nil {
		return err
	}
	t := &txn{}
	switch r.Choice {
	case merge.ChoiceTakeTheirs:
		if ev.res.Kind == merge.KindHold {
			if err := merge.TakeTheirs(rec.Intent, ev.res.Cause); err != nil {
				return err
			}
		}
		t.remove(outboxRel(rec.N))
		return s.commitTxn(t)
	case merge.ChoiceRetry:
		if ev.res.Kind == merge.KindHold {
			return fmt.Errorf("%w: %s", ErrStillHeld, ev.res.Cause)
		}
	case merge.ChoiceKeepMine, merge.ChoiceEdit, merge.ChoiceKeepMineMerge, merge.ChoiceTakeTheirsMerge:
		repl, _, err := s.replacement(rec, ev, &r)
		if err != nil {
			return err
		}
		d, err := merge.ResolveDigest(rec.N, repl)
		if err != nil {
			return err
		}
		if !d.Equal(r.Confirm) {
			return ErrStaleConfirm
		}
		rec.Intent = repl
	default:
		return fmt.Errorf("store: unknown resolution %q", r.Choice)
	}
	rec.Held = false
	if err := s.putRecord(t, rec); err != nil {
		return err
	}
	return s.commitTxn(t)
}

// heldHeadLocked returns the held head and the merge rule's verdict on it
// now. The caller holds s.mu and the file lock.
func (s *Store) heldHeadLocked() (*record, evaluation, error) {
	if err := s.needServer(); err != nil {
		return nil, evaluation{}, err
	}
	recs, err := s.readOutbox()
	if err != nil {
		return nil, evaluation{}, err
	}
	if len(recs) == 0 || !recs[0].Held {
		return nil, evaluation{}, ErrNotHeld
	}
	rec := recs[0]
	if !rec.Import.IsZero() {
		return nil, evaluation{}, ErrImportRecord
	}
	if rec.live() != nil {
		return nil, evaluation{}, ErrLiveCandidate
	}
	ev, err := s.evaluate(rec.Intent)
	return rec, ev, err
}

// confirmed reports whether choice writes a replacement the user confirms
// with its digest.
func confirmed(c merge.Choice) bool {
	switch c {
	case merge.ChoiceKeepMine, merge.ChoiceEdit, merge.ChoiceKeepMineMerge, merge.ChoiceTakeTheirsMerge:
		return true
	}
	return false
}

// replacement computes the keep mine, edit or --merge replacement with the
// §5.4 table, from the held intent and why it holds now. It returns the fresh ID
// a put turned into a create uses.
func (s *Store) replacement(rec *record, ev evaluation, r *Resolution) (merge.Intent, model.ID, error) {
	if ev.res.Kind != merge.KindHold {
		return merge.Intent{}, model.ID{}, ErrNoLongerHeld
	}
	held, cause := rec.Intent, ev.res.Cause
	cur, err := s.verifiedItem(held.ItemID)
	if err != nil {
		return merge.Intent{}, model.ID{}, err
	}
	var repl merge.Intent
	var newID model.ID
	switch r.Choice {
	case merge.ChoiceKeepMine:
		repl, err = merge.KeepMine(held, cause, cur)
	case merge.ChoiceKeepMineMerge:
		repl, err = merge.KeepMineMerge(held, cause, cur)
	case merge.ChoiceTakeTheirsMerge:
		repl, err = merge.TakeTheirsMerge(held, cause, cur)
	default:
		var edited *merge.Item
		if r.Edited != nil {
			if edited, err = merge.ItemOf(r.Edited); err != nil {
				return merge.Intent{}, model.ID{}, err
			}
		}
		repl, err = merge.Edit(held, cause, cur, edited, func() (model.ID, error) {
			newID = r.NewID
			if newID.IsZero() {
				id, err := vaultlog.NewID()
				newID = id
				return id, err
			}
			return newID, nil
		})
	}
	if err != nil {
		return merge.Intent{}, model.ID{}, err
	}
	if repl.Action == merge.ActionCreate && repl.ItemID != held.ItemID {
		if err := s.checkFreshID(repl.ItemID); err != nil {
			return merge.Intent{}, model.ID{}, err
		}
	}
	if err := s.checkReplacement(repl); err != nil {
		return merge.Intent{}, model.ID{}, err
	}
	return repl, newID, nil
}

// checkReplacement requires a replacement to apply to verified state as it
// is now (§11.1): nothing comes before the head, so every reference must
// name a verified item of the right type, never one that only a later
// queued record creates, and the candidate the push would build from it
// must pass the §5.3 rules, deploy-op blockers included. Propose and
// Resolve both run it, so a held flag is never cleared on a replacement
// that would only hold again on a rule. The caller holds s.mu and the file
// lock.
func (s *Store) checkReplacement(repl merge.Intent) error {
	if repl.Want != nil {
		p, err := plainOf(repl.Want)
		if err != nil {
			return err
		}
		if err := crypto.ValidateItem(p); err != nil {
			return err
		}
		verified := map[model.ID]*merge.Item{}
		for id := range s.sec.Items {
			it, err := s.verifiedItem(id)
			if err != nil {
				return err
			}
			if it != nil {
				verified[id] = it
			}
		}
		if err := checkRefs(p, verified); err != nil {
			return fmt.Errorf("%w: %w", ErrReplacementRefused, err)
		}
	}
	ev, err := s.evaluate(repl)
	if err != nil {
		return err
	}
	if ev.res.Kind == merge.KindHold && ev.res.Cause == merge.CauseRuleFailure {
		return fmt.Errorf("%w: %v", ErrReplacementRefused, ev.res.Err)
	}
	return nil
}

// checkFreshID requires id to be unused: not live or retired in verified
// state, and named by no queued record.
func (s *Store) checkFreshID(id model.ID) error {
	_, live := s.state.Items[id]
	_, dev := s.state.Devices[id]
	_, grant := s.state.Grants[id]
	_, op := s.state.DeployOps[id]
	r := s.state.Retired
	if live || dev || grant || op || slices.Contains(r.ItemIDs, id) || slices.Contains(r.DeviceIDs, id) || slices.Contains(r.GrantIDs, id) {
		return fmt.Errorf("store: item ID %s is already used", id)
	}
	recs, err := s.readOutbox()
	if err != nil {
		return err
	}
	for _, rec := range recs {
		if rec.Intent.ItemID == id {
			return fmt.Errorf("store: item ID %s is already used by a queued change", id)
		}
	}
	return nil
}
