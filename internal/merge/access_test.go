package merge

import (
	"slices"
	"testing"

	"github.com/dalyem/hopkey/internal/model"
)

func accessAt(t testing.TB, version uint64, by byte, states ...string) *Item {
	t.Helper()
	a := model.Access{
		Header: model.Header{V: 1, ItemID: model.ID{7}, Type: model.TypeAccess, ItemVersion: version},
		Label:  "alice", RecordID: model.ID{8}, PublicKey: "ssh-ed25519 AAAA", Fingerprint: "SHA256:x",
		Options: model.AccessOptions{From: []string{}}, By: model.ID{by},
	}
	for i, s := range states {
		a.Targets = append(a.Targets, model.AccessTarget{HostItemID: model.ID{byte(i + 1)}, User: "root", ServerKeyFP: "SHA256:h", Gen: 1, State: s})
	}
	it, err := ItemOf(a)
	if err != nil {
		t.Fatal(err)
	}
	return it
}

// by is a system member: never in L or R, S's value in every merge, and
// no conflict on its own (§5.0).
func TestAccessByIsNotMerged(t *testing.T) {
	seen := accessAt(t, 1, 1, model.AccessPending, model.AccessPending)
	want := accessAt(t, 1, 2, model.AccessPending, model.AccessPending)
	s := accessAt(t, 2, 3, model.AccessInstalled, model.AccessPending)
	got := Rebuild(put(seen, want), s, true, false)
	if got.Kind != KindWrite {
		t.Fatalf("a by-only change against S: %+v", got)
	}
	samePlain(t, got.Plaintext, s)

	// Both change targets: one unit conflict, by in neither list.
	want = accessAt(t, 1, 2, model.AccessFailed, model.AccessPending)
	got = Rebuild(put(seen, want), s, true, false)
	if got.Kind != KindHold || len(got.Conflicts) != 1 || got.Conflicts[0].Name != UnitAccess ||
		!slices.Equal(got.Local, []string{"targets"}) || !slices.Equal(got.Remote, []string{"targets"}) {
		t.Fatalf("hold %+v", got)
	}
	// With one unit, P_mine is keep mine's result and P_theirs is S, so
	// both --merge choices are refused (Part 1, §2.11); keep mine copies
	// L₀, which holds by only when by differs between seen and want. The
	// store stamps by on whatever is written.
	in := put(seen, want)
	// Here by differs between seen and want, so keep mine copies it and
	// P_mine, which keeps S's by, differs from it.
	if p, err := KeepMineMerge(in, got.Cause, s); err != nil {
		t.Errorf("keep mine --merge: %v", err)
	} else if b, _ := p.Want.Member("by"); string(b) != string(mustMember(t, s, "by")) {
		t.Errorf("P_mine by %s", b)
	}
	if _, err := TakeTheirsMerge(in, got.Cause, s); !isRefusal(err) {
		t.Errorf("take theirs --merge: %v", err)
	}
	for range 2 {
		mine, err := KeepMine(in, got.Cause, s)
		if err != nil {
			t.Fatal(err)
		}
		if tg, _ := mine.Want.Member("targets"); string(tg) != string(mustMember(t, want, "targets")) {
			t.Errorf("keep mine targets %s", tg)
		}
	}
}

func mustMember(t testing.TB, it *Item, m string) []byte {
	t.Helper()
	b, ok := it.Member(m)
	if !ok {
		t.Fatalf("no %s", m)
	}
	return b
}

// An injected unclassified member makes an access item fall back to the
// rev 16 rule, with no unit conflicts.
func TestAccessUnclassifiedFallsBack(t *testing.T) {
	seen := withMember(t, accessAt(t, 1, 1, model.AccessPending), "future", "base")
	want := withMember(t, accessAt(t, 1, 1, model.AccessPending), "future", "x")
	s := withMember(t, accessAt(t, 2, 1, model.AccessInstalled), "future", "base")
	got := Rebuild(put(seen, want), s, true, false)
	if got.Kind != KindHold || got.Cause != CauseGuardedConflict || len(got.Conflicts) != 0 {
		t.Fatalf("got %+v", got)
	}
}
