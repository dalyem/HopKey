package merge

import (
	"errors"
	"fmt"

	"github.com/dalyem/hopkey/internal/canonjson"
	"github.com/dalyem/hopkey/internal/model"
)

// Choice is how the user resolves a held change (§5.4, §11.1).
type Choice string

const (
	ChoiceKeepMine   Choice = "keep mine"
	ChoiceEdit       Choice = "edit"
	ChoiceTakeTheirs Choice = "take theirs"
	ChoiceRetry      Choice = "retry"
)

// Row names a row of the §5.4 resolution table. Its text is what a
// RefusalError quotes.
type Row string

const (
	// RowPutConflict: put, the item is live in S, held on a guarded conflict.
	RowPutConflict Row = "put, item live, guarded conflict"
	// RowPutNotLive: put, the item isn't live in S.
	RowPutNotLive Row = "put, item not live"
	// RowDeleteChanged: delete, the item changed in S.
	RowDeleteChanged Row = "delete, item changed"
	// RowDeleteBlocked: delete of an unchanged item, held because a §5.3
	// rule failed.
	RowDeleteBlocked Row = "delete, item unchanged, rule failure"
	// RowWriteBlocked: create or put (item live) held because a §5.3 rule
	// failed, or a create whose ID is taken.
	RowWriteBlocked Row = "create or put, rule failure or ID taken"
)

// ErrRefused matches every RefusalError.
var ErrRefused = errors.New("merge: resolution refused")

// ErrInvalidHold means the intent and cause can't come from Rebuild
// together, such as a delete held as id_taken.
var ErrInvalidHold = errors.New("merge: cause does not fit the held intent")

// RefusalError says the table refuses Choice for Row, and why.
type RefusalError struct {
	Choice Choice
	Row    Row
	Reason string
}

func (e *RefusalError) Error() string {
	return fmt.Sprintf("merge: %s is refused for a %s hold: %s", e.Choice, e.Row, e.Reason)
}

// Is makes errors.Is(err, ErrRefused) true.
func (e *RefusalError) Is(target error) bool { return target == ErrRefused }

func refuse(c Choice, r Row, reason string) error {
	return &RefusalError{Choice: c, Row: r, Reason: reason}
}

// IDFunc returns a fresh item ID. Tests pass a deterministic one;
// vaultlog.NewID fits.
type IDFunc func() (model.ID, error)

// RowOf returns the resolution-table row for a held intent and its cause.
func RowOf(held Intent, cause Cause) (Row, error) {
	if err := held.Validate(); err != nil {
		return "", err
	}
	a := held.Action
	switch {
	case cause == CauseGuardedConflict && a == ActionPut:
		return RowPutConflict, nil
	case cause == CauseNotLive && a == ActionPut:
		return RowPutNotLive, nil
	case cause == CauseDeleteChanged && a == ActionDelete:
		return RowDeleteChanged, nil
	case cause == CauseRuleFailure && a == ActionDelete:
		return RowDeleteBlocked, nil
	case cause == CauseRuleFailure && (a == ActionCreate || a == ActionPut):
		return RowWriteBlocked, nil
	case cause == CauseIDTaken && a == ActionCreate:
		return RowWriteBlocked, nil
	}
	return "", fmt.Errorf("%w: %s on a %s", ErrInvalidHold, cause, a)
}

const (
	reasonNotLiveNow = "the item is no longer live in S; retry first"
	reasonNothingNew = "keeping the same content can't succeed"
)

// checkS verifies that s, when present, is the held item's current state.
func checkS(held Intent, s *Item) error {
	if s != nil && (s.id != held.ItemID || s.typ != held.Type) {
		return errors.New("merge: S is not the held intent's item")
	}
	return nil
}

// KeepMine returns the replacement intent for "keep mine" (§5.4).
//
// For a guarded conflict it recomputes L₀ from the intent held now, the
// members where held.Want differs from held.Seen. The replacement is S with
// only the L₀ members replaced by the wanted values, and seen′ = S. Across
// successive Keep mine replacements L₀ can only lose members that already
// match S. After an Edit it can gain the members the Edit changed.
//
// For a held delete whose item changed it keeps the delete (want stays
// nil) and sets seen′ = S. s is nil when the item is not live in S; both
// of those rows then refuse and the user retries first.
//
// Every other row is refused with a *RefusalError.
func KeepMine(held Intent, cause Cause, s *Item) (Intent, error) {
	row, err := RowOf(held, cause)
	if err != nil {
		return Intent{}, err
	}
	if err := checkS(held, s); err != nil {
		return Intent{}, err
	}
	switch row {
	case RowPutConflict:
		if s == nil {
			return Intent{}, refuse(ChoiceKeepMine, row, reasonNotLiveNow)
		}
		set := map[string]canonjson.Raw{}
		for _, m := range diff(held.Want, held.Seen) {
			set[m] = held.Want.members[m] // nil removes an absent member
		}
		want, err := s.with(set)
		if err != nil {
			return Intent{}, err
		}
		return Intent{Action: ActionPut, ItemID: held.ItemID, Type: held.Type, Seen: s, Want: want}, nil
	case RowDeleteChanged:
		if s == nil {
			return Intent{}, refuse(ChoiceKeepMine, row, reasonNotLiveNow)
		}
		return Intent{Action: ActionDelete, ItemID: held.ItemID, Type: held.Type, Seen: s}, nil
	case RowPutNotLive:
		return Intent{}, refuse(ChoiceKeepMine, row,
			"a deleted ID is never reused, and a discarded create never produced the item")
	case RowDeleteBlocked:
		return Intent{}, refuse(ChoiceKeepMine, row,
			"resolve the blocker first, then take theirs and queue a new delete, or retry")
	default: // RowWriteBlocked
		return Intent{}, refuse(ChoiceKeepMine, row, reasonNothingNew)
	}
}

// EditStart returns the item the user starts editing from for Edit: S for a
// put, the held want for a create, and for a put whose item isn't live the
// held want, which becomes a new create. The two delete rows are refused.
func EditStart(held Intent, cause Cause, s *Item) (*Item, error) {
	row, err := RowOf(held, cause)
	if err != nil {
		return nil, err
	}
	if err := checkS(held, s); err != nil {
		return nil, err
	}
	switch row {
	case RowPutConflict:
		if s == nil {
			return nil, refuse(ChoiceEdit, row, reasonNotLiveNow)
		}
		return s, nil
	case RowPutNotLive:
		return held.Want, nil
	case RowWriteBlocked:
		if held.Action == ActionCreate {
			return held.Want, nil
		}
		if s == nil {
			return nil, refuse(ChoiceEdit, row, reasonNotLiveNow)
		}
		return s, nil
	case RowDeleteChanged:
		return nil, refuse(ChoiceEdit, row, "take theirs, then edit the item")
	default: // RowDeleteBlocked
		return nil, refuse(ChoiceEdit, row,
			"resolve the blocker first (edit the referring item, or mark the deploy targets abandoned), then take theirs or retry")
	}
}

// Edit returns the replacement intent for "edit". edited is the user's
// result, edited from EditStart's item.
//
//   - Put, item live: a put of edited with seen′ = S. This covers the
//     guarded conflict and a put held on a rule failure.
//   - Put, item not live: only a new create (seen nil) with a fresh ID from
//     newID, set both on the intent and in the plaintext's item_id, and
//     item_version 1 as a new ID needs (§5.3). edited may be nil to start
//     the create from the held want unchanged. Later records that name the
//     old ID are never retargeted.
//   - Create held on a rule failure or a taken ID: a create of edited with
//     the same ID, and every rule runs again. A taken ID therefore holds
//     again until it is no longer taken, which the spec leaves to the user.
//   - Both delete rows are refused.
//
// The result's header comes from S (a put) or the held want (a create);
// whatever header edited carried is ignored.
func Edit(held Intent, cause Cause, s, edited *Item, newID IDFunc) (Intent, error) {
	row, err := RowOf(held, cause)
	if err != nil {
		return Intent{}, err
	}
	start, err := EditStart(held, cause, s) // also checks s and the refusals
	if err != nil {
		return Intent{}, err
	}
	if edited == nil {
		if row != RowPutNotLive {
			return Intent{}, errors.New("merge: edit needs the edited item")
		}
		edited = start
	}
	if edited.typ != held.Type {
		return Intent{}, errors.New("merge: edited item has the wrong type")
	}
	if row == RowPutNotLive {
		return editToCreate(held, edited, newID)
	}
	if edited.id != held.ItemID {
		return Intent{}, errors.New("merge: edited item has the wrong item_id")
	}
	want, err := edited.withHeaderOf(start)
	if err != nil {
		return Intent{}, err
	}
	out := Intent{Action: held.Action, ItemID: held.ItemID, Type: held.Type, Want: want}
	if held.Action == ActionPut {
		out.Seen = s
	}
	return out, nil
}

func editToCreate(held Intent, edited *Item, newID IDFunc) (Intent, error) {
	if newID == nil {
		return Intent{}, errors.New("merge: a put on an item that isn't live needs an ID generator")
	}
	id, err := newID()
	if err != nil {
		return Intent{}, fmt.Errorf("merge: new item ID: %w", err)
	}
	if id.IsZero() || id == held.ItemID {
		return Intent{}, errors.New("merge: the new item ID is not fresh")
	}
	want, err := edited.with(map[string]canonjson.Raw{
		"item_id":      rawString(id.String()),
		"item_version": rawString("1"),
	})
	if err != nil {
		return Intent{}, err
	}
	return Intent{Action: ActionCreate, ItemID: id, Type: held.Type, Want: want}, nil
}

// TakeTheirs says whether the held record may be discarded. The table
// allows it for every row, so the error is non-nil only if held and cause
// can't be a hold at all. It writes nothing and needs no digest.
func TakeTheirs(held Intent, cause Cause) error {
	_, err := RowOf(held, cause)
	return err
}

// Retry returns the intent for "retry": the held intent, unchanged. The
// caller re-evaluates it with Rebuild and CheckCandidate against current S
// and clears the hold only if both pass. If the item's content has changed
// since, the record holds again and goes through the confirmed Keep mine
// path. Retry needs no confirmation or digest, because it writes nothing the
// user hasn't already approved.
func Retry(held Intent, cause Cause) (Intent, error) {
	if _, err := RowOf(held, cause); err != nil {
		return Intent{}, err
	}
	return held, nil
}
