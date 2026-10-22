package merge

import (
	"errors"
	"strings"
	"testing"

	"github.com/dalyem/hopkey/internal/canonjson"
	"github.com/dalyem/hopkey/internal/model"
)

func fixedID(t testing.TB, id string) IDFunc {
	i := mustID(t, id)
	return func() (model.ID, error) { return i, nil }
}

// wantRefusal fails unless err is a *RefusalError for the given choice and
// row, naming the row in its text.
func wantRefusal(t testing.TB, err error, choice Choice, row Row) {
	t.Helper()
	var ref *RefusalError
	if !errors.As(err, &ref) {
		t.Fatalf("got %v, want a refusal of %s for %q", err, choice, row)
	}
	if !errors.Is(err, ErrRefused) {
		t.Errorf("%v does not match ErrRefused", err)
	}
	if ref.Choice != choice || ref.Row != row {
		t.Errorf("refused %s for %q, want %s for %q", ref.Choice, ref.Row, choice, row)
	}
	if !strings.Contains(err.Error(), string(row)) || !strings.Contains(err.Error(), string(choice)) {
		t.Errorf("error %q does not name the row and the choice", err)
	}
}

// TestResolutionTable walks every row of the §5.4 table, with every choice.
func TestResolutionTable(t *testing.T) {
	base := host(t, 1)
	tests := []struct {
		name   string
		held   Intent
		cause  Cause
		s      *Item
		edited *Item
		row    Row
		// keepMine and edit say whether the table allows the choice; a
		// refused choice is checked against the row.
		keepMine, edit bool
	}{
		{
			name:   "put, item live, guarded conflict",
			held:   put(base, host(t, 2, credRef(t, idCred2))),
			cause:  CauseGuardedConflict,
			s:      host(t, 7, addrs("10.0.0.2")),
			edited: host(t, 7, addrs("10.0.0.2"), name("mine")),
			row:    RowPutConflict, keepMine: true, edit: true,
		},
		{
			name:   "put, item not live",
			held:   put(base, host(t, 2, name("x"))),
			cause:  CauseNotLive,
			edited: host(t, 2, name("y")),
			row:    RowPutNotLive, keepMine: false, edit: true,
		},
		{
			name:  "delete, item changed",
			held:  del(base),
			cause: CauseDeleteChanged,
			s:     host(t, 7, name("x")),
			row:   RowDeleteChanged, keepMine: true, edit: false,
		},
		{
			name:  "delete, unchanged, rule failure",
			held:  del(base),
			cause: CauseRuleFailure,
			s:     host(t, 7),
			row:   RowDeleteBlocked, keepMine: false, edit: false,
		},
		{
			name:   "create, rule failure",
			held:   create(host(t, 1, name("x"))),
			cause:  CauseRuleFailure,
			edited: host(t, 1, name("y")),
			row:    RowWriteBlocked, keepMine: false, edit: true,
		},
		{
			name:   "put, item live, rule failure",
			held:   put(base, host(t, 2, name("x"))),
			cause:  CauseRuleFailure,
			s:      host(t, 7),
			edited: host(t, 7, name("y")),
			row:    RowWriteBlocked, keepMine: false, edit: true,
		},
		{
			name:   "create, ID taken",
			held:   create(host(t, 1, name("x"))),
			cause:  CauseIDTaken,
			s:      host(t, 3),
			edited: host(t, 1, name("y")),
			row:    RowWriteBlocked, keepMine: false, edit: true,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got, err := RowOf(tc.held, tc.cause); err != nil || got != tc.row {
				t.Fatalf("RowOf = %q, %v, want %q", got, err, tc.row)
			}

			got, err := KeepMine(tc.held, tc.cause, tc.s)
			if tc.keepMine {
				if err != nil {
					t.Errorf("keep mine: %v", err)
				}
				if got.Action != tc.held.Action || got.ItemID != tc.held.ItemID {
					t.Errorf("keep mine changed the action or ID: %s %s", got.Action, got.ItemID)
				}
				if err := got.Validate(); err != nil {
					t.Errorf("keep mine produced an invalid intent: %v", err)
				}
			} else {
				wantRefusal(t, err, ChoiceKeepMine, tc.row)
			}

			got, err = Edit(tc.held, tc.cause, tc.s, tc.edited, fixedID(t, idFresh))
			if tc.edit {
				if err != nil {
					t.Errorf("edit: %v", err)
				} else if err := got.Validate(); err != nil {
					t.Errorf("edit produced an invalid intent: %v", err)
				}
			} else {
				wantRefusal(t, err, ChoiceEdit, tc.row)
				_, err := EditStart(tc.held, tc.cause, tc.s)
				wantRefusal(t, err, ChoiceEdit, tc.row)
			}

			// Take theirs discards in every row.
			if err := TakeTheirs(tc.held, tc.cause); err != nil {
				t.Errorf("take theirs: %v", err)
			}

			// Retry keeps the intent unchanged in every row.
			r, err := Retry(tc.held, tc.cause)
			if err != nil {
				t.Fatalf("retry: %v", err)
			}
			sameIntent(t, r, tc.held)
		})
	}
}

func TestResolutionRejectsImpossibleHolds(t *testing.T) {
	base, changed := host(t, 1), host(t, 2, name("x"))
	for _, tc := range []struct {
		name  string
		held  Intent
		cause Cause
	}{
		{"delete held as id_taken", del(base), CauseIDTaken},
		{"delete held as guarded_conflict", del(base), CauseGuardedConflict},
		{"delete held as not_live", del(base), CauseNotLive},
		{"create held as not_live", create(changed), CauseNotLive},
		{"create held as guarded_conflict", create(changed), CauseGuardedConflict},
		{"create held as delete_content_changed", create(changed), CauseDeleteChanged},
		{"put held as id_taken", put(base, changed), CauseIDTaken},
		{"put held as delete_content_changed", put(base, changed), CauseDeleteChanged},
		{"unknown cause", put(base, changed), "weather"},
		{"malformed intent", Intent{Action: ActionPut, ItemID: base.ID(), Type: model.TypeHost}, CauseGuardedConflict},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := RowOf(tc.held, tc.cause); err == nil {
				t.Error("RowOf accepted it")
			}
			if _, err := KeepMine(tc.held, tc.cause, base); err == nil {
				t.Error("KeepMine accepted it")
			}
			if _, err := Edit(tc.held, tc.cause, base, changed, fixedID(t, idFresh)); err == nil {
				t.Error("Edit accepted it")
			}
			if err := TakeTheirs(tc.held, tc.cause); err == nil {
				t.Error("TakeTheirs accepted it")
			}
			if _, err := Retry(tc.held, tc.cause); err == nil {
				t.Error("Retry accepted it")
			}
			if tc.name != "malformed intent" {
				if _, err := RowOf(tc.held, tc.cause); !errors.Is(err, ErrInvalidHold) {
					t.Errorf("RowOf: %v, want ErrInvalidHold", err)
				}
			}
		})
	}
}

func TestKeepMineRebuildsOnlyL0(t *testing.T) {
	// The user changed the credential. Another device changed the address.
	seen := host(t, 1)
	want := host(t, 2, credRef(t, idCred2))
	s := host(t, 7, addrs("10.0.0.2"))
	held := put(seen, want)
	if res := Rebuild(held, s, true, false); res.Kind != KindHold || res.Cause != CauseGuardedConflict {
		t.Fatalf("setup: got %s/%s", res.Kind, res.Cause)
	}

	got, err := KeepMine(held, CauseGuardedConflict, s)
	if err != nil {
		t.Fatal(err)
	}
	// want′ is S with only the credential replaced: the new address stays.
	sameIntent(t, got, Intent{
		Action: ActionPut, ItemID: held.ItemID, Type: model.TypeHost,
		Seen: s,
		Want: host(t, 7, addrs("10.0.0.2"), credRef(t, idCred2)),
	})
	// Against the same S the replacement merges cleanly and writes want′.
	res := Rebuild(got, s, true, false)
	if res.Kind != KindWrite {
		t.Fatalf("replacement: got %s/%s", res.Kind, res.Cause)
	}
	samePlain(t, res.Plaintext, got.Want)
}

func TestKeepMineOverwritesMembersTheUserChanged(t *testing.T) {
	// L₀ members take the user's value even where S changed them too.
	seen := host(t, 1)
	held := put(seen, host(t, 2, name("mine"), credRef(t, idCred2)))
	s := host(t, 7, name("theirs"), addrs("10.0.0.2"))
	got, err := KeepMine(held, CauseGuardedConflict, s)
	if err != nil {
		t.Fatal(err)
	}
	samePlain(t, got.Want, host(t, 7, name("mine"), addrs("10.0.0.2"), credRef(t, idCred2)))
	if res := Rebuild(got, s, true, false); res.Kind != KindWrite {
		t.Errorf("replacement: got %s/%s", res.Kind, res.Cause)
	}
}

func TestKeepMineRecomputesL0AfterASecondHold(t *testing.T) {
	s0 := host(t, 1)
	held := put(s0, host(t, 2, name("x"), credRef(t, idCred2), user("bob")))

	// The remote also renamed the host to "x" and changed the address.
	s1 := host(t, 5, name("x"), addrs("10.0.0.2"))
	first, err := KeepMine(held, CauseGuardedConflict, s1)
	if err != nil {
		t.Fatal(err)
	}
	samePlain(t, first.Want, host(t, 5, name("x"), addrs("10.0.0.2"), credRef(t, idCred2), user("bob")))
	if first.Seen != s1 {
		t.Error("seen′ is not S")
	}

	// A second hold: the remote changes the credential and renames again.
	s2 := host(t, 9, name("z"), addrs("10.0.0.2"), credRef(t, "c9c9c9c9c9c9c9c9c9c9c9c9c9c9c9c9"))
	res := Rebuild(first, s2, true, false)
	if res.Kind != KindHold || res.Cause != CauseGuardedConflict {
		t.Fatalf("second hold: got %s/%s", res.Kind, res.Cause)
	}
	second, err := KeepMine(first, CauseGuardedConflict, s2)
	if err != nil {
		t.Fatal(err)
	}
	// name matched S when the first replacement was made, so it is no
	// longer in L₀ and the remote rename survives.
	samePlain(t, second.Want, host(t, 9, name("z"), addrs("10.0.0.2"), credRef(t, idCred2), user("bob")))
	if second.Seen != s2 {
		t.Error("seen′ is not S")
	}
}

func TestEditWidensL0(t *testing.T) {
	s0 := host(t, 1)
	held := put(s0, host(t, 2, credRef(t, idCred2)))
	s1 := host(t, 5, addrs("10.0.0.2"))

	kept, err := KeepMine(held, CauseGuardedConflict, s1)
	if err != nil {
		t.Fatal(err)
	}
	// Another remote change holds the replacement again.
	s2 := host(t, 6, addrs("10.0.0.3"))
	if res := Rebuild(kept, s2, true, false); res.Kind != KindHold {
		t.Fatalf("setup: got %s", res.Kind)
	}

	// The user edits from S2 and also changes the user.
	start, err := EditStart(kept, CauseGuardedConflict, s2)
	if err != nil {
		t.Fatal(err)
	}
	samePlain(t, start, s2)
	edited := host(t, 0, addrs("10.0.0.3"), credRef(t, idCred2), user("alice"))
	editedIntent, err := Edit(kept, CauseGuardedConflict, s2, edited, nil)
	if err != nil {
		t.Fatal(err)
	}
	// The result is the edit with seen′ = S and S's header.
	sameIntent(t, editedIntent, Intent{
		Action: ActionPut, ItemID: held.ItemID, Type: model.TypeHost,
		Seen: s2,
		Want: host(t, 6, addrs("10.0.0.3"), credRef(t, idCred2), user("alice")),
	})

	// The next conflict's Keep mine carries both the credential and the
	// user, because the Edit made the user part of the delta.
	s3 := host(t, 8, addrs("10.0.0.4"))
	if res := Rebuild(editedIntent, s3, true, false); res.Kind != KindHold {
		t.Fatalf("setup: got %s", res.Kind)
	}
	again, err := KeepMine(editedIntent, CauseGuardedConflict, s3)
	if err != nil {
		t.Fatal(err)
	}
	samePlain(t, again.Want, host(t, 8, addrs("10.0.0.4"), credRef(t, idCred2), user("alice")))
}

func TestKeepMineOnAHeldDelete(t *testing.T) {
	seen := host(t, 1)
	held := del(seen)
	s := host(t, 7, name("x"))
	if res := Rebuild(held, s, true, false); res.Kind != KindHold || res.Cause != CauseDeleteChanged {
		t.Fatalf("setup: got %s/%s", res.Kind, res.Cause)
	}
	got, err := KeepMine(held, CauseDeleteChanged, s)
	if err != nil {
		t.Fatal(err)
	}
	if got.Action != ActionDelete || got.Want != nil {
		t.Errorf("got %s with want %v, want a delete with no want", got.Action, got.Want)
	}
	if got.Seen != s {
		t.Error("seen′ is not S")
	}
	// The deletion rules run again: against the same S it now writes.
	if res := Rebuild(got, s, true, false); res.Kind != KindWrite || res.Action != ActionDelete {
		t.Errorf("rerun: got %s/%s/%s", res.Kind, res.Action, res.Cause)
	}
	// If S changes again the delete holds again.
	if res := Rebuild(got, host(t, 8, name("y")), true, false); res.Kind != KindHold || res.Cause != CauseDeleteChanged {
		t.Errorf("after another change: got %s/%s", res.Kind, res.Cause)
	}
	// If the item is gone by now, there's nothing to keep: retry drops it.
	_, err = KeepMine(held, CauseDeleteChanged, nil)
	wantRefusal(t, err, ChoiceKeepMine, RowDeleteChanged)
	if res := Rebuild(held, nil, false, true); res.Kind != KindDrop {
		t.Errorf("retry after the item was deleted elsewhere: got %s", res.Kind)
	}
}

func TestEditOfAPutOnAnItemThatIsNotLiveMakesAFreshCreate(t *testing.T) {
	// The create before this put was discarded with take theirs, so the
	// item never existed.
	seen := host(t, 1, name("mine"))
	want := host(t, 4, name("mine"), hostDesc("l2"))
	held := put(seen, want)
	if res := Rebuild(held, nil, false, false); res.Kind != KindHold || res.Cause != CauseNotLive {
		t.Fatalf("setup: got %s/%s", res.Kind, res.Cause)
	}

	start, err := EditStart(held, CauseNotLive, nil)
	if err != nil {
		t.Fatal(err)
	}
	samePlain(t, start, want)

	got, err := Edit(held, CauseNotLive, nil, nil, fixedID(t, idFresh))
	if err != nil {
		t.Fatal(err)
	}
	fresh := mustID(t, idFresh)
	if got.Action != ActionCreate || got.Seen != nil {
		t.Errorf("got %s with seen %v, want a create with no seen", got.Action, got.Seen)
	}
	// The fresh ID is on the intent and in the plaintext, and the new item
	// starts at item_version 1.
	if got.ItemID != fresh || got.Want.ID() != fresh {
		t.Errorf("intent ID %s, plaintext ID %s, want %s in both", got.ItemID, got.Want.ID(), fresh)
	}
	if v, _ := got.Want.Member("item_id"); string(v) != `"`+idFresh+`"` {
		t.Errorf("item_id member = %s", v)
	}
	if v, _ := got.Want.Member("item_version"); string(v) != `"1"` {
		t.Errorf("item_version member = %s", v)
	}
	// Everything else is the held want.
	moved, err := host(t, 1, name("mine"), hostDesc("l2")).with(map[string]canonjson.Raw{"item_id": rawString(idFresh)})
	if err != nil {
		t.Fatal(err)
	}
	samePlain(t, got.Want, moved)
	if err := got.Validate(); err != nil {
		t.Fatal(err)
	}
	// The new create writes against a state that has never seen the ID.
	if res := Rebuild(got, nil, false, false); res.Kind != KindWrite || res.Action != ActionCreate {
		t.Errorf("create: got %s/%s/%s", res.Kind, res.Action, res.Cause)
	}
	// Later records that name the old ID are not retargeted: they hold.
	later := put(want, host(t, 5, name("mine"), hostDesc("l3")))
	if res := Rebuild(later, nil, false, false); res.Kind != KindHold || res.Cause != CauseNotLive {
		t.Errorf("later record: got %s/%s", res.Kind, res.Cause)
	}

	// The user may change the item while converting it.
	edited := host(t, 4, name("renamed"))
	got, err = Edit(held, CauseNotLive, nil, edited, fixedID(t, idFresh))
	if err != nil {
		t.Fatal(err)
	}
	if v, _ := got.Want.Member("name"); string(v) != `"renamed"` || got.Want.ID() != fresh {
		t.Errorf("edited create: name %s id %s", v, got.Want.ID())
	}
}

func TestEditToCreateNeedsAFreshID(t *testing.T) {
	held := put(host(t, 1), host(t, 2, name("x")))
	boom := errors.New("no entropy")
	zero := func() (model.ID, error) { return model.ID{}, nil }
	same := func() (model.ID, error) { return held.ItemID, nil }
	failing := func() (model.ID, error) { return model.ID{}, boom }
	for _, tc := range []struct {
		name string
		gen  IDFunc
	}{{"no generator", nil}, {"zero ID", zero}, {"the old ID", same}, {"generator error", failing}} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := Edit(held, CauseNotLive, nil, nil, tc.gen); err == nil {
				t.Error("accepted")
			}
		})
	}
	if _, err := Edit(held, CauseNotLive, nil, nil, failing); !errors.Is(err, boom) {
		t.Errorf("generator error not wrapped: %v", err)
	}
}

func TestEditStart(t *testing.T) {
	base := host(t, 1)
	want := host(t, 2, name("x"))
	s := host(t, 7, user("admin"))
	for _, tc := range []struct {
		name  string
		held  Intent
		cause Cause
		s     *Item
		start *Item
	}{
		{"conflict starts from S", put(base, want), CauseGuardedConflict, s, s},
		{"not live starts from want", put(base, want), CauseNotLive, nil, want},
		{"put rule failure starts from S", put(base, want), CauseRuleFailure, s, s},
		{"create rule failure starts from want", create(want), CauseRuleFailure, nil, want},
		{"create, ID taken starts from want", create(want), CauseIDTaken, s, want},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := EditStart(tc.held, tc.cause, tc.s)
			if err != nil {
				t.Fatal(err)
			}
			samePlain(t, got, tc.start)
		})
	}
}

func TestResolutionsNeedLiveSWhereTheRowUsesIt(t *testing.T) {
	// The item was deleted elsewhere after the hold. The user retries
	// first, which holds again as not_live.
	base := host(t, 1)
	held := put(base, host(t, 2, name("x")))
	_, err := KeepMine(held, CauseGuardedConflict, nil)
	wantRefusal(t, err, ChoiceKeepMine, RowPutConflict)
	_, err = Edit(held, CauseGuardedConflict, nil, host(t, 2, name("y")), nil)
	wantRefusal(t, err, ChoiceEdit, RowPutConflict)
	_, err = Edit(held, CauseRuleFailure, nil, host(t, 2, name("y")), nil)
	wantRefusal(t, err, ChoiceEdit, RowWriteBlocked)
	if res := Rebuild(held, nil, false, true); res.Cause != CauseNotLive {
		t.Errorf("retry: got %s", res.Cause)
	}
}

func TestEditChecksTheEditedItem(t *testing.T) {
	base := host(t, 1)
	held := put(base, host(t, 2, name("x")))
	s := host(t, 7, addrs("10.0.0.2"))
	gen := fixedID(t, idFresh)

	if _, err := Edit(held, CauseGuardedConflict, s, nil, gen); err == nil {
		t.Error("accepted a nil edit")
	}
	if _, err := Edit(held, CauseGuardedConflict, s, credential(t, 1, nil), gen); err == nil {
		t.Error("accepted an edit of another type")
	}
	other, err := host(t, 1).with(map[string]canonjson.Raw{"item_id": rawString(idHost2)})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Edit(held, CauseGuardedConflict, s, other, gen); err == nil {
		t.Error("accepted an edit of another item")
	}
	if _, err := Edit(held, CauseGuardedConflict, other, host(t, 1), gen); err == nil {
		t.Error("accepted an S of another item")
	}
	// The header the user's editor carried is replaced by S's.
	got, err := Edit(held, CauseGuardedConflict, s, host(t, 99, name("y")), gen)
	if err != nil {
		t.Fatal(err)
	}
	samePlain(t, got.Want, host(t, 7, name("y")))
}

// TestRetryAfterTheBlockerClears: a delete held on a rule failure is
// retried unchanged, with every rule run again.
func TestRetryAfterTheBlockerClears(t *testing.T) {
	seen := host(t, 1)
	held := del(seen)
	s := host(t, 4)
	blocked := true
	check := func(Action, *Item) error {
		if blocked {
			return errors.New("an incomplete deploy op names the host")
		}
		return nil
	}

	first := CheckCandidate(Rebuild(held, s, true, false), check)
	if first.Kind != KindHold || first.Cause != CauseRuleFailure {
		t.Fatalf("first: got %s/%s", first.Kind, first.Cause)
	}
	// The user marks the targets abandoned; the same record is retried.
	blocked = false
	retried, err := Retry(held, first.Cause)
	if err != nil {
		t.Fatal(err)
	}
	sameIntent(t, retried, held)
	res := CheckCandidate(Rebuild(retried, s, true, false), check)
	if res.Kind != KindWrite || res.Action != ActionDelete {
		t.Errorf("retry: got %s/%s/%s", res.Kind, res.Action, res.Cause)
	}

	// If the item changed in the meantime the retry holds again, and the
	// confirmed Keep mine path takes over.
	changed := host(t, 6, name("x"))
	res = CheckCandidate(Rebuild(retried, changed, true, false), check)
	if res.Kind != KindHold || res.Cause != CauseDeleteChanged {
		t.Fatalf("changed: got %s/%s", res.Kind, res.Cause)
	}
	if _, err := KeepMine(retried, res.Cause, changed); err != nil {
		t.Errorf("keep mine after the retry: %v", err)
	}
}
