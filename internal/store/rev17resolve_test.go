package store

import (
	"errors"
	"slices"
	"testing"

	"github.com/dalyem/hopkey/internal/canonjson"
	"github.com/dalyem/hopkey/internal/merge"
	"github.com/dalyem/hopkey/internal/model"
)

// The two computed edits of rev 17 (keep mine --merge, take theirs
// --merge) through the store, and a record held under rev 16 that rev 17
// would write.

// unitConflict commits on B an address change and queues on A a user and a
// description change: both changed how the host connects, so it holds on
// the connection unit, and A's description is outside the conflict.
func (p *pair) unitConflict(t *testing.T) {
	t.Helper()
	editHost(t, p.b.s, p.host.ItemID, func(h *model.Host) { h.Addresses = []string{"10.0.0.2"} })
	pushAll(t, p.b.s, p.r)
	editHost(t, p.a.s, p.host.ItemID, func(h *model.Host) { h.User = "admin"; h.Description = "from A" })
	res := pushAll(t, p.a.s, p.r)
	if res.Outcome != PushHeld || res.Hold.Cause != merge.CauseGuardedConflict || len(res.Hold.Conflicts) != 1 ||
		res.Hold.Conflicts[0].Kind != merge.ConflictUnit || res.Hold.Conflicts[0].Name != merge.UnitConnection {
		t.Fatalf("push: %+v %+v", res, res.Hold)
	}
}

func resolveWith(t *testing.T, s *Store, c merge.Choice) Proposal {
	t.Helper()
	prop, err := s.Propose(Resolution{Choice: c})
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Resolve(Resolution{Choice: c, Confirm: prop.Digest}); err != nil {
		t.Fatal(err)
	}
	return prop
}

func TestKeepMineMergeAndTakeTheirsMerge(t *testing.T) {
	orig := func(p *pair) []string { return p.host.Addresses }
	for _, tc := range []struct {
		choice merge.Choice
		addrs  func(p *pair) []string
		user   string
	}{
		// The connection as A's: B's address is replaced, A's description
		// kept.
		{merge.ChoiceKeepMineMerge, orig, "admin"},
		// The connection as B's: A's user is dropped, A's description kept.
		{merge.ChoiceTakeTheirsMerge, func(*pair) []string { return []string{"10.0.0.2"} }, "deploy"},
	} {
		t.Run(string(tc.choice), func(t *testing.T) {
			p := newPair(t)
			a := p.a.s
			p.unitConflict(t)
			prop := resolveWith(t, a, tc.choice)
			var want model.Host
			if err := canonjson.Unmarshal(prop.Want, &want); err != nil {
				t.Fatal(err)
			}
			if prop.Action != merge.ActionPut || !slices.Equal(want.Addresses, tc.addrs(p)) || want.User != tc.user || want.Description != "from A" {
				t.Errorf("proposal %+v", want)
			}
			// The digest is the Edit digest of the computed edit.
			cur, _ := verifiedHost(t, a, p.host.ItemID)
			seen, wantItem := mergeItem(t, &cur), mergeItem(t, &want)
			if d, err := merge.ResolveDigest(prop.N, merge.Intent{Action: merge.ActionPut, ItemID: p.host.ItemID, Type: model.TypeHost, Seen: seen, Want: wantItem}); err != nil || !d.Equal(prop.Digest) {
				t.Errorf("digest %v %v, want the Edit digest", d, err)
			}
			if res := pushAll(t, a, p.r); res.Outcome != PushEmpty {
				t.Fatalf("push: %+v", res)
			}
			got, _ := verifiedHost(t, a, p.host.ItemID)
			if !slices.Equal(got.Addresses, tc.addrs(p)) || got.User != tc.user || got.Description != "from A" {
				t.Errorf("host %+v", got)
			}
		})
	}
}

// A --merge confirmation is recomputed against current S: a change on the
// server since makes the token stale, as for keep mine and edit.
func TestMergeProposalGoesStale(t *testing.T) {
	p := newPair(t)
	a, b := p.a.s, p.b.s
	p.unitConflict(t)
	prop, err := a.Propose(Resolution{Choice: merge.ChoiceTakeTheirsMerge})
	if err != nil {
		t.Fatal(err)
	}
	editHost(t, b, p.host.ItemID, func(h *model.Host) { h.Port = 2222 })
	pushAll(t, b, p.r)
	pull(t, a, p.r)
	if err := a.Resolve(Resolution{Choice: merge.ChoiceTakeTheirsMerge, Confirm: prop.Digest}); !errors.Is(err, ErrStaleConfirm) {
		t.Errorf("resolve with the old token: %v", err)
	}
	if !records(t, a)[0].Held {
		t.Error("the record is no longer held")
	}
}

// A credential change against an address change holds on the connection
// unit. P_theirs is then S itself, so take theirs --merge is refused
// ("nothing to merge"); P_mine keeps A's whole connection, which plain keep
// mine doesn't (it writes A's credential on B's address), so it is offered.
func TestMergeProposalRefusals(t *testing.T) {
	p := newPair(t)
	a := p.a.s
	p.conflict(t)
	pushAll(t, a, p.r)
	if _, err := a.Propose(Resolution{Choice: merge.ChoiceTakeTheirsMerge}); !errors.Is(err, merge.ErrRefused) {
		t.Errorf("take theirs --merge: %v", err)
	}
	if _, err := a.Propose(Resolution{Choice: merge.ChoiceKeepMineMerge}); err != nil {
		t.Errorf("keep mine --merge: %v", err)
	}
}

// A record held under rev 16 keeps its held flag after the upgrade; it is
// reported as applying now, and Retry writes the merge.
func TestRecordHeldUnderRev16RetriesIntoAMerge(t *testing.T) {
	p := newPair(t)
	a := p.a.s
	p.combine(t)
	// Rev 16 held it: set the flag as an older build would have.
	a.mu.Lock()
	unlock, err := a.lockFile()
	if err != nil {
		t.Fatal(err)
	}
	recs, err := a.readOutbox()
	if err == nil {
		recs[0].Held = true
		tx := &txn{}
		if err = a.putRecord(tx, recs[0]); err == nil {
			err = a.commitTxn(tx)
		}
	}
	unlock()
	a.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	pull(t, a, p.r)
	if res := pushAll(t, a, p.r); res.Outcome != PushHeld || res.Hold == nil || res.Hold.Reason != "it would apply now: retry it" {
		t.Fatalf("push: %+v %+v", res, res.Hold)
	}
	h, err := a.HeldHead()
	if err != nil || h == nil || h.Hold != nil {
		t.Fatalf("held head %+v %v", h, err)
	}
	if err := a.Resolve(Resolution{Choice: merge.ChoiceRetry}); err != nil {
		t.Fatal(err)
	}
	if res := pushAll(t, a, p.r); res.Outcome != PushEmpty {
		t.Fatalf("push after retry: %+v", res)
	}
	got, _ := verifiedHost(t, a, p.host.ItemID)
	if !slices.Equal(got.Addresses, []string{"10.0.0.2"}) || len(got.Aliases) != 0 {
		t.Errorf("host %+v", got)
	}
	checkCombined(t, takeSyncNotes(t, a), p)
}
