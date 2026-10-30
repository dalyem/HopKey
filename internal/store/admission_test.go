package store

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/dalyem/hopkey/internal/canonjson"
	"github.com/dalyem/hopkey/internal/crypto"
	"github.com/dalyem/hopkey/internal/merge"
	"github.com/dalyem/hopkey/internal/model"
	"github.com/dalyem/hopkey/internal/vaultlog"
)

// The admission preflight (crypto spec rev 17 amendment, §3.1, vectors
// S1-S3). internal/server's TestSingletonLenIsTheSpecFormula pins the
// server's accounting to the same formula and limits.

// capturedWire is a real candidate wire, as A posts it.
func capturedWire(t *testing.T) *vaultlog.Wire {
	t.Helper()
	p := newPair(t)
	var got *vaultlog.Wire
	p.r.onPost = func(w *vaultlog.Wire) (bool, error) { got = w; return true, nil }
	editHost(t, p.a.s, p.host.ItemID, func(h *model.Host) { h.Description = "x" })
	pushAll(t, p.a.s, p.r)
	if got == nil {
		t.Fatal("nothing was posted")
	}
	return got
}

// jsonString is a canonical JSON string n bytes long.
func jsonString(n int) canonjson.Raw { return canonjson.Raw(`"` + strings.Repeat("a", n-2) + `"`) }

func TestAdmissionBoundaries(t *testing.T) {
	base := capturedWire(t)
	named := base.Entry.ObjectDigests()
	if len(named) == 0 {
		t.Fatal("the entry names no object")
	}
	wire := func(bodies ...int) *vaultlog.Wire {
		w := &vaultlog.Wire{Entry: base.Entry, Sigs: base.Sigs}
		for _, n := range bodies {
			w.Objects = append(w.Objects, vaultlog.Object{SHA256: named[0], Body: jsonString(n)})
		}
		return w
	}

	// S1, S2: one object at 1 MiB is admitted, one byte more is not.
	if err := admitWire(wire(maxObjectBody)); err != nil {
		t.Errorf("an object of exactly 1 MiB: %v", err)
	}
	if err := admitWire(wire(maxObjectBody + 1)); !errors.Is(err, ErrTooLarge) || !strings.Contains(err.Error(), "per item") {
		t.Errorf("an object 1 byte over 1 MiB: %v", err)
	}

	// S3: the singleton length is 212 + digits(seq) + len(JCS(wire)), and
	// a wire at exactly 4 MiB by that measure is admitted, 1 byte more not.
	measure := func(w *vaultlog.Wire) int {
		b, err := w.Marshal()
		if err != nil {
			t.Fatal(err)
		}
		n, err := singletonLen(w, b)
		if err != nil {
			t.Fatal(err)
		}
		if want := 212 + len(strconv.FormatUint(w.Entry.Seq, 10)) + len(b); n != want {
			t.Fatalf("singletonLen %d, want 212 + digits(seq) + len(wire) = %d", n, want)
		}
		return n
	}
	big := maxObjectBody - 64
	n0 := measure(wire(big, big, big, 2))
	k := 2 + maxSingletonWire - n0
	if k < 2 || k > maxObjectBody {
		t.Fatalf("can't reach the boundary: k = %d", k)
	}
	if n := measure(wire(big, big, big, k)); n != maxSingletonWire {
		t.Fatalf("built %d, want %d", n, maxSingletonWire)
	}
	if err := admitWire(wire(big, big, big, k)); err != nil {
		t.Errorf("a wire of exactly 4 MiB: %v", err)
	}
	if err := admitWire(wire(big, big, big, k+1)); !errors.Is(err, ErrTooLarge) {
		t.Errorf("a wire 1 byte over 4 MiB: %v", err)
	}

	// The server keeps only the objects the entry names, so an extra one,
	// however large, is not counted.
	w := wire(maxObjectBody)
	w.Objects = append(w.Objects, vaultlog.Object{SHA256: crypto.Hash{0xee}, Body: jsonString(2 * maxObjectBody)})
	if err := admitWire(w); err != nil {
		t.Errorf("an object the entry doesn't name was counted: %v", err)
	}

	// The op and object counts.
	w = wire(10)
	for len(w.Objects) <= maxObjectsPerWire {
		w.Objects = append(w.Objects, w.Objects[0])
	}
	if err := admitWire(w); !errors.Is(err, ErrTooLarge) {
		t.Errorf("%d objects: %v", len(w.Objects), err)
	}
}

// manyTags is n distinct tags of 32 bytes, the schema's longest.
func manyTags(prefix string, n int) []string {
	out := make([]string, n)
	for i := range out {
		out[i] = fmt.Sprintf("%s%031d", prefix, i)
	}
	return out
}

// A class merge can push a valid item over 1 MiB: the merge holds with
// rule_failure before anything is journaled, the queue behind it waits on
// the hold rather than on retries, and keep mine is refused while edit and
// take theirs work.
func TestOversizeMergeHolds(t *testing.T) {
	p := newPair(t)
	a, b := p.a.s, p.b.s
	const n = 14000 // each side well under 1 MiB, the union over it
	editHost(t, b, p.host.ItemID, func(h *model.Host) { h.Tags = append(slices.Clone(h.Tags), manyTags("b", n)...) })
	if res := pushAll(t, b, p.r); res.Outcome != PushEmpty {
		t.Fatalf("B's push: %+v", res)
	}
	editHost(t, a, p.host.ItemID, func(h *model.Host) { h.Tags = append(slices.Clone(h.Tags), manyTags("a", n)...) })
	_, other := addHost(t, a, "behind")
	posts := p.r.postCount()
	for range 3 {
		res, err := a.PushHead(context.Background(), p.r)
		if err != nil {
			t.Fatal(err)
		}
		if res.Outcome != PushHeld || res.Hold == nil || res.Hold.Cause != merge.CauseRuleFailure || !strings.Contains(res.Hold.Reason, "MiB") {
			t.Fatalf("push: %+v %+v", res, res.Hold)
		}
	}
	if p.r.postCount() != posts {
		t.Errorf("%d posts while the head was held", p.r.postCount()-posts)
	}
	recs := records(t, a)
	if len(recs) < 2 || !recs[0].Held || len(recs[0].Cands) != 0 {
		t.Fatalf("records: %+v", recs)
	}
	for _, r := range recs[1:] {
		if r.Held || len(r.Cands) != 0 {
			t.Errorf("record %d behind the hold: held %v, %d candidates", r.N, r.Held, len(r.Cands))
		}
	}
	if _, err := a.Propose(Resolution{Choice: merge.ChoiceKeepMine}); !errors.Is(err, merge.ErrRefused) {
		t.Errorf("keep mine: %v, want a refusal", err)
	}
	if err := a.Resolve(Resolution{Choice: merge.ChoiceTakeTheirs}); err != nil {
		t.Fatal(err)
	}
	if res := pushAll(t, a, p.r); res.Outcome != PushEmpty {
		t.Fatalf("after take theirs: %+v", res)
	}
	if _, ok := verifiedHost(t, a, other.ItemID); !ok {
		t.Error("the record behind the hold never went up")
	}
}
