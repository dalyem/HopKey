package daemon

import (
	"fmt"
	"slices"
	"testing"
	"time"
)

// bigTags is about 600 KiB of tags, as JSON.
func bigTags() []string {
	out := make([]string, 0, 18000)
	for i := range cap(out) {
		out = append(out, fmt.Sprintf("t%05d-%s", i, "abcdefghijklmnopqrstuvwxyz")[:32])
	}
	return out
}

// A held host of about 600 KiB still lists, and each --merge proposal
// still arrives, within the client's 4 MiB response limit: the listing
// carries the three versions and the keep-mine proposal, never the --merge
// proposals, and sync.proposal returns one proposal at a time. Here this
// device changed the port and removed one tag while the server changed the
// user and removed another, so both --merge proposals are offered.
func TestLargeHeldHostListsAndProposes(t *testing.T) {
	x := newSyncSetup(t)
	x.w.start(x.n1, x.n1.st, SyncOptions{})
	x.w.start(x.n2, x.n2.st, SyncOptions{})
	tags := bigTags()
	h := webHost("big", x.keyID, "203.0.113.60")
	h.Tags = tags
	x.n1.putHost(h)
	eventually(t, 20*time.Second, "big reaches the laptop", func() bool { return x.n2.host("big") != nil })

	x.n2.pause(true)
	time.Sleep(100 * time.Millisecond)
	desk := *x.n1.host("big")
	desk.User = "root"
	desk.Tags = slices.Delete(slices.Clone(tags), 1, 2)
	x.n1.putHost(desk)
	eventually(t, 20*time.Second, "the desk's edit is pushed", func() bool { return x.n1.status().Pending == 0 })
	laptop := *x.n2.host("big")
	laptop.Port = 2222
	laptop.Tags = slices.Delete(slices.Clone(tags), 0, 1)
	x.n2.putHost(laptop)
	x.n2.pause(false)
	eventually(t, 20*time.Second, "the laptop's change is held", func() bool { return x.n2.status().Held == 1 })

	var held SyncHeldResult
	x.n2.must(OpSyncHeld, nil, &held)
	if len(held.Held) != 1 {
		t.Fatalf("held %d", len(held.Held))
	}
	hc := held.Held[0]
	// The case is only a regression if nine copies of the item, the
	// listing's old shape, would not fit.
	if n := len(hc.Current); 9*n <= maxRequest {
		t.Fatalf("the host is %d bytes: too small to test the limit", n)
	}
	if hc.KeepMine == nil || !slices.Contains(hc.Choices, ChoiceKeepMineMerge) || !slices.Contains(hc.Choices, ChoiceTakeTheirsMerge) {
		t.Fatalf("choices %v, keep mine %v", hc.Choices, hc.KeepMine != nil)
	}

	props := map[string]*Proposal{}
	for _, ch := range []string{ChoiceKeepMineMerge, ChoiceTakeTheirsMerge} {
		var res SyncProposalResult
		x.n2.must(OpSyncProposal, SyncProposalParams{N: hc.N, Choice: ch}, &res)
		p := res.Proposal
		if p == nil || p.N != hc.N || p.Choice != ch || p.Confirm == "" {
			t.Fatalf("%s: %+v", ch, p)
		}
		props[ch] = p
	}
	// take theirs --merge: the desk's user, the laptop's port is dropped
	// with the rest of the connection, and both removals are kept.
	var res SyncResolveResult
	x.n2.must(OpSyncResolve, SyncResolveParams{N: hc.N, Choice: ChoiceTakeTheirsMerge, Confirm: props[ChoiceTakeTheirsMerge].Confirm}, &res)
	eventually(t, 20*time.Second, "the merge reaches the desk", func() bool {
		got := x.n1.host("big")
		return got != nil && len(got.Tags) == len(tags)-2
	})
	got := x.n1.host("big")
	if got.User != "root" || got.Port != 22 || slices.Contains(got.Tags, tags[0]) || slices.Contains(got.Tags, tags[1]) {
		t.Errorf("host user %q port %d, %d tags", got.User, got.Port, len(got.Tags))
	}
}

// sync.proposal returns only the computed proposals, for the held record
// it names.
func TestSyncProposalSchema(t *testing.T) {
	f := newFixture(t, nil)
	if err := f.client().Call(t.Context(), OpSyncProposal, SyncProposalParams{N: 1, Choice: ChoiceKeepMineMerge}, nil); !IsCode(err, CodeLocalOnly) {
		t.Errorf("on a store that does not sync: %v", err)
	}
	x := newSyncSetup(t)
	x.w.start(x.n1, x.n1.st, SyncOptions{})
	for _, ch := range []string{ChoiceEdit, ChoiceTakeTheirs, ChoiceRetry, "keep mine"} {
		if err := x.n1.call(OpSyncProposal, SyncProposalParams{N: 1, Choice: ch}, nil); !IsCode(err, CodeInvalid) {
			t.Errorf("%s: %v", ch, err)
		}
	}
	if err := x.n1.call(OpSyncProposal, map[string]any{"n": 1, "choice": ChoiceKeepMineMerge, "propose": true}, nil); !IsCode(err, CodeInvalid) {
		t.Errorf("an unknown param: %v", err)
	}
	if err := x.n1.call(OpSyncProposal, SyncProposalParams{N: 1, Choice: ChoiceKeepMineMerge}, nil); !IsCode(err, CodeNotHeld) {
		t.Errorf("nothing held: %v", err)
	}
}
