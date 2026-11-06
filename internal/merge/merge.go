package merge

import (
	"errors"
	"fmt"

	"github.com/dalyem/hopkey/internal/canonjson"
	"github.com/dalyem/hopkey/internal/model"
)

// Action is the kind of change an Intent asks for.
type Action string

const (
	ActionCreate Action = "create"
	ActionPut    Action = "put"
	ActionDelete Action = "delete"
)

// Intent is an intended change (§5.4): (action, item_id, type, seen, want).
//
// Seen is the item exactly as the user saw it when they made the edit,
// which may be the local overlay including earlier queued edits. It is nil
// for a create. Want is the complete plaintext the user asked for. It is
// nil for a delete. Seen and Want must carry the intent's ItemID and Type.
type Intent struct {
	Action Action
	ItemID model.ID
	Type   model.Type
	Seen   *Item
	Want   *Item
}

// Validate checks that the intent is well formed: a known action, a
// non-zero ID, one of the four mergeable types (a grant is refused), Seen
// and Want present exactly where the action needs them, and both naming the
// intent's item.
func (in Intent) Validate() error {
	if in.ItemID.IsZero() {
		return errors.New("merge: intent has no item_id")
	}
	if err := validType(in.Type); err != nil {
		return err
	}
	var needSeen, needWant bool
	switch in.Action {
	case ActionCreate:
		needWant = true
	case ActionPut:
		needSeen, needWant = true, true
	case ActionDelete:
		needSeen = true
	default:
		return fmt.Errorf("merge: unknown action %q", string(in.Action))
	}
	for _, c := range []struct {
		name string
		it   *Item
		need bool
	}{{"seen", in.Seen, needSeen}, {"want", in.Want, needWant}} {
		switch {
		case c.it == nil && c.need:
			return fmt.Errorf("merge: a %s intent needs %s", in.Action, c.name)
		case c.it != nil && !c.need:
			return fmt.Errorf("merge: a %s intent has no %s", in.Action, c.name)
		case c.it != nil && (c.it.id != in.ItemID || c.it.typ != in.Type):
			return fmt.Errorf("merge: %s is not the intent's item", c.name)
		}
	}
	return nil
}

// Kind says what Rebuild decided.
type Kind string

const (
	// KindWrite: write Result.Plaintext as Result.Action.
	KindWrite Kind = "write"
	// KindDrop: a delete that is already complete. Nothing is written.
	KindDrop Kind = "drop"
	// KindHold: nothing is written. The change is kept until the user
	// resolves it, and Result.Cause says why.
	KindHold Kind = "hold"
)

// Cause is why a change is held. It selects the row of the §5.4 resolution
// table.
type Cause string

const (
	// CauseGuardedConflict: a put where both sides changed one unit
	// differently, raced on a selector class, or made changes a coupling
	// forbids combining (rev 17); or, for an item the rev 17 tables don't
	// cover, both sides changed its guarded group (rev 16).
	CauseGuardedConflict Cause = "guarded_conflict"
	// CauseNotLive: a put on an item that is not live in S.
	CauseNotLive Cause = "not_live"
	// CauseRuleFailure: the candidate post-state failed a §5.3 rule
	// (supplied by the caller through CheckCandidate), or the intent is
	// malformed.
	CauseRuleFailure Cause = "rule_failure"
	// CauseIDTaken: a create whose ID is live or retired in S.
	CauseIDTaken Cause = "id_taken"
	// CauseDeleteChanged: a delete of an item whose content changed in S.
	CauseDeleteChanged Cause = "delete_content_changed"
)

// Result is the outcome of Rebuild.
type Result struct {
	Kind Kind

	// Write: the action and, for a create or put, the complete plaintext.
	// The header comes from the candidate state: a put carries S's header
	// (the caller sets item_version = S's + 1 when it builds the entry),
	// and a create carries the header of its want. A delete has no
	// plaintext.
	Action    Action
	Plaintext *Item
	// Replaced lists, sorted, the free members both sides changed to
	// different values: want's value replaced the one S had (§5.4), with
	// nothing held. A put write only.
	Replaced []string
	// Combined, for a put write, is set when rev 16 would have held this
	// change: rev 17 combined it with changes the user never saw (§5.4,
	// "combined" note).
	Combined *Combined

	// Hold: the reason. For CauseGuardedConflict, Local lists the non-free
	// members the user changed and Remote the non-free members S changed,
	// both sorted, and Conflicts says which units, classes and couplings
	// hold it (none when rev 16 decided the item). For CauseRuleFailure,
	// Err is the failed rule.
	Cause     Cause
	Local     []string
	Remote    []string
	Conflicts []Conflict
	Err       error
}

func hold(c Cause) Result { return Result{Kind: KindHold, Cause: c} }

func ruleFailure(err error) Result {
	return Result{Kind: KindHold, Cause: CauseRuleFailure, Err: err}
}

// CheckCandidate applies the caller's §5.3 validation of the candidate
// post-state (reference integrity, bundle validation, deploy-op
// restrictions, companion ops) to a Write result. A failure becomes a Hold
// with CauseRuleFailure, so the outbox and the online path treat every hold
// the same way. A Drop or a Hold passes through without calling check.
// plaintext is nil for a delete.
func CheckCandidate(r Result, check func(action Action, plaintext *Item) error) Result {
	if r.Kind != KindWrite {
		return r
	}
	if err := check(r.Action, r.Plaintext); err != nil {
		return ruleFailure(err)
	}
	return r
}

// Rebuild merges the intended change against the current verified state S
// (§5.4, merge rule rev 17).
//
// current is S's item for in.ItemID and live says it is live in S. current
// may be nil when the item is not live (and, for a create, whenever the
// caller has no use for it). retired says the ID was deleted in S. A live
// item is never retired.
//
// Rebuild does not run the §5.3 rules. The caller runs them on the
// candidate post-state and maps a failure with CheckCandidate.
func Rebuild(in Intent, current *Item, live, retired bool) Result {
	if err := in.Validate(); err != nil {
		return ruleFailure(err)
	}
	switch in.Action {
	case ActionCreate:
		if live || retired {
			return hold(CauseIDTaken)
		}
		return Result{Kind: KindWrite, Action: ActionCreate, Plaintext: in.Want}
	case ActionPut, ActionDelete:
		if live {
			if current == nil {
				return ruleFailure(errors.New("merge: item is live but has no plaintext"))
			}
			if current.id != in.ItemID || current.typ != in.Type {
				return ruleFailure(errors.New("merge: current item is not the intent's item"))
			}
		}
	}
	if in.Action == ActionDelete {
		return rebuildDelete(in, current, live)
	}
	if !live {
		return hold(CauseNotLive)
	}
	return rebuildPutRev17(in, current)
}

// rebuildDelete: already deleted is complete, S unchanged since seen
// deletes, anything else holds. An item that is not live and was never
// retired (the create that would have made it was discarded) has nothing to
// delete either, and no resolution could do more than discard the record,
// so it drops too.
func rebuildDelete(in Intent, current *Item, live bool) Result {
	switch {
	case !live:
		return Result{Kind: KindDrop}
	case in.Seen.Equal(current):
		return Result{Kind: KindWrite, Action: ActionDelete}
	}
	return hold(CauseDeleteChanged)
}

// rebuildPutRev16 is the rev 16 put rule, rev16(seen, want, S): hold if L
// and R both contain a non-free member and want and S differ on a non-free
// member; otherwise write want's value for every member in L and S's for
// every other. Rev 17 uses it for an item with an unclassified member.
func rebuildPutRev16(in Intent, s *Item) Result {
	var local, remote []string // guarded members in L and in R
	var replaced []string      // free members in L and R that differ
	inL := map[string]bool{}
	for _, m := range names(in.Want, in.Seen, s) {
		l := !memberEqual(in.Want, in.Seen, m)
		r := !memberEqual(s, in.Seen, m)
		inL[m] = l
		if IsFree(in.Type, m) && l && r && !memberEqual(in.Want, s, m) {
			replaced = append(replaced, m)
		}
		if IsGuarded(in.Type, m) {
			if l {
				local = append(local, m)
			}
			if r {
				remote = append(remote, m)
			}
		}
	}
	if len(local) > 0 && len(remote) > 0 && !sameOnGuarded(in.Type, in.Want, s) {
		res := hold(CauseGuardedConflict)
		res.Local, res.Remote = local, remote
		return res
	}
	// want's value for each member in L, S's value for every other member.
	// A free member in both L and R is in L, so it takes want's value.
	set := map[string]canonjson.Raw{}
	for m, l := range inL {
		src := s
		if l {
			src = in.Want
		}
		set[m] = src.members[m] // nil removes an absent member
	}
	merged, err := s.with(set)
	if err != nil {
		return ruleFailure(err)
	}
	return Result{Kind: KindWrite, Action: ActionPut, Plaintext: merged, Replaced: replaced}
}

// sameOnGuarded reports whether a and b agree on every guarded member.
func sameOnGuarded(t model.Type, a, b *Item) bool {
	for _, m := range diff(a, b) {
		if IsGuarded(t, m) {
			return false
		}
	}
	return true
}
