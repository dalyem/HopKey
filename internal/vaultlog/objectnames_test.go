package vaultlog

import (
	"slices"
	"testing"

	"github.com/dalyem/hopkey/internal/crypto"
)

// The builders put exactly the objects an entry names on its wire, so
// Entry.ObjectDigests must list the same set for every kind.
func TestEntryObjectDigestsMatchBuiltWires(t *testing.T) {
	w := full(t)
	wire, st, sec, err := BuildCheckpoint(w.st, w.sec, w.devA(), w.checkpointParams(idDevB))
	if err != nil {
		t.Fatal(err)
	}
	w.record(wire)
	w.st, w.sec = st, sec
	kinds := map[Kind]bool{}
	for _, wire := range w.log {
		kinds[wire.Entry.Kind] = true
		objs, err := WireObjects(wire)
		if err != nil {
			t.Fatal(err)
		}
		var want []crypto.Hash
		for h := range objs {
			want = append(want, h)
		}
		got := wire.Entry.ObjectDigests()
		cmp := func(a, b crypto.Hash) int { return slices.Compare(a[:], b[:]) }
		slices.SortFunc(want, cmp)
		sorted := slices.SortedFunc(slices.Values(got), cmp)
		if !slices.Equal(sorted, want) || len(got) != len(sorted) {
			t.Errorf("seq %d (%s): ObjectDigests %v, wire carries %v", wire.Entry.Seq, wire.Entry.Kind, got, want)
		}
	}
	for _, k := range []Kind{KindGenesis, KindBootstrap, KindNormal, KindCheckpoint} {
		if !kinds[k] {
			t.Errorf("no %s entry was checked", k)
		}
	}
}
