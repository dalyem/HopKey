package store

import (
	"bytes"
	"context"
	"errors"
	"slices"
	"testing"

	"github.com/dalyem/hopkey/internal/access"
	"github.com/dalyem/hopkey/internal/canonjson"
	"github.com/dalyem/hopkey/internal/merge"
	"github.com/dalyem/hopkey/internal/model"
)

// createAccess queues (or writes) a new record labelled label on host
// through s, pending with gen 1.
func createAccess(t *testing.T, s *Store, label string, host model.ID) (model.Access, error) {
	t.Helper()
	line, fp := accessKey(t, 1)
	_, hfp := accessKey(t, 2)
	return s.PutAccess(context.Background(), model.Access{
		Label: label, RecordID: randomID(t), PublicKey: line, Fingerprint: fp,
		Options: model.AccessOptions{From: []string{}},
		Targets: []model.AccessTarget{{HostItemID: host, User: "root", ServerKeyFP: hfp, Gen: 1, State: model.AccessPending, Time: 1}},
	})
}

// Labels are unique among live access records under K_alias (§5.1 writer
// rule): in a local-only vault, among this device's queued changes, and
// against current state when a queued create is rebased onto a record
// another device made meanwhile (review P2-4).
func TestAccessLabelsAreUnique(t *testing.T) {
	t.Run("local", func(t *testing.T) {
		f := newVault(t, testConfig(t))
		_, host := addHost(t, f.s, "web")
		if _, err := createAccess(t, f.s, "alice", host.ItemID); err != nil {
			t.Fatal(err)
		}
		for _, l := range []string{"alice", "ALICE", "alice.", " Alice. "} {
			if _, err := createAccess(t, f.s, l, host.ItemID); !errors.Is(err, ErrAccessLabelTaken) {
				t.Errorf("%q: %v", l, err)
			}
		}
		if _, err := createAccess(t, f.s, "alice2", host.ItemID); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("queued", func(t *testing.T) {
		p := newPair(t)
		if _, err := createAccess(t, p.a.s, "alice", p.host.ItemID); err != nil {
			t.Fatal(err)
		}
		if _, err := createAccess(t, p.a.s, "Alice.", p.host.ItemID); !errors.Is(err, ErrAccessLabelTaken) {
			t.Fatalf("second queued create: %v", err)
		}
	})
	t.Run("rebase", func(t *testing.T) {
		p := newPair(t)
		if _, err := createAccess(t, p.a.s, "alice", p.host.ItemID); err != nil {
			t.Fatal(err)
		}
		if _, err := createAccess(t, p.b.s, "ALICE", p.host.ItemID); err != nil {
			t.Fatal(err)
		}
		pushAll(t, p.b.s, p.r)
		pull(t, p.a.s, p.r)
		res := pushAll(t, p.a.s, p.r)
		if res.Outcome != PushHeld || res.Hold == nil || res.Hold.Cause != merge.CauseRuleFailure {
			t.Fatalf("A's push: %+v %+v", res, res.Hold)
		}
		n := 0
		for _, it := range p.a.s.state.Items {
			if it.Type == model.TypeAccess {
				n++
			}
		}
		if n != 1 {
			t.Fatalf("%d live access records", n)
		}
	})
}

// After a checkpoint that revokes a device, every device that verifies it
// gets one access-review note, in the commit that verifies it, naming the
// live records the revoked device last changed, and keeps it until it is
// acknowledged, across a restart. A record the revoked device made and an
// active device changed later is not named (§7.5, §3.2).
func TestAccessReviewNoteAfterRevocation(t *testing.T) {
	ctx := context.Background()
	a, b, r := newCkptPair(t)
	c := secondDeviceNamed(t, a, r, "laptop")
	host := randomID(t)
	alice, err := createAccess(t, c.s, "alice", host)
	if err != nil {
		t.Fatal(err)
	}
	carol, err := createAccess(t, c.s, "carol", host)
	if err != nil {
		t.Fatal(err)
	}
	pushAll(t, c.s, r)
	pull(t, b.s, r)
	// B changes carol later: by is B now.
	cur := overlayAccess(t, b.s, carol.ItemID)
	cur.Targets[0].State = model.AccessInstalled
	if _, err := b.s.PutAccess(ctx, cur); err != nil {
		t.Fatal(err)
	}
	pushAll(t, b.s, r)
	pull(t, a.s, r)
	if ns := takeSyncNotes(t, a.s); len(ns.AccessReviews) != 0 {
		t.Fatalf("a note before any revocation: %+v", ns)
	}
	cID := deviceID(t, c.s)
	if _, err := a.s.RevokeDevices(ctx, r, []byte(testPassword), []string{"laptop"}, CheckpointOptions{Keep: []string{deviceID(t, b.s).String()}}); err != nil {
		t.Fatal(err)
	}
	pull(t, a.s, r)
	pull(t, b.s, r)
	want := func(t *testing.T, s *Store) AccessReviewNote {
		t.Helper()
		ns, err := s.SyncNotes()
		if err != nil {
			t.Fatal(err)
		}
		if len(ns.AccessReviews) != 1 {
			t.Fatalf("notes %+v", ns)
		}
		n := ns.AccessReviews[0]
		s.mu.Lock()
		head := s.state.Head.Seq
		s.mu.Unlock()
		if !slices.Equal(n.Devices, []model.ID{cID}) || len(n.Items) != 1 || n.Items[0].ItemID != alice.ItemID || n.Items[0].Label != "alice" ||
			n.CheckpointSeq == 0 || n.CheckpointSeq > head {
			t.Fatalf("note %+v (head %d)", n, head)
		}
		return n
	}
	// The author of the checkpoint, and another device.
	want(t, a.s)
	n := want(t, b.s)
	// It stays until acknowledged, across a restart, and is added once.
	if err := b.s.Close(); err != nil {
		t.Fatal(err)
	}
	b.s = open(t, b.cfg)
	pull(t, b.s, r)
	if again := want(t, b.s); again.ID != n.ID {
		t.Fatalf("the note changed across a restart: %+v -> %+v", n, again)
	}
	if err := b.s.AckSyncNotes(SyncNotes{AccessReviews: []AccessReviewNote{{ID: n.ID}}}); err != nil {
		t.Fatal(err)
	}
	if ns, _ := b.s.SyncNotes(); len(ns.AccessReviews) != 0 {
		t.Fatalf("after the acknowledgement: %+v", ns)
	}
	// The note is the checkpoint's, not part of the log: verified state
	// still attributes alice to the revoked device.
	if got := verifiedAccessOf(t, b.s, alice.ItemID); got.By != cID {
		t.Fatalf("by %v", got.By)
	}
}

// A record made before a device was enrolled, then changed by that
// device, is attributed to it (by), and when the device is revoked the
// note names the record, the device is in the retired list hop access ls
// marks records with, and verified state keeps by through the checkpoint.
// A device enrolled after the checkpoint opens the vault with the record
// still attributed to the revoked device (§7.5).
func TestAccessReviewNamesARecordOfALaterDevice(t *testing.T) {
	ctx := context.Background()
	a, b, r := newCkptPair(t)
	alice, err := createAccess(t, b.s, "alice", randomID(t))
	if err != nil {
		t.Fatal(err)
	}
	pushAll(t, b.s, r)
	// The laptop is enrolled after alice exists, and changes her.
	c := secondDeviceNamed(t, a, r, "laptop")
	pull(t, c.s, r)
	cur := overlayAccess(t, c.s, alice.ItemID)
	cur.Targets[0].State = model.AccessInstalled
	if _, err := c.s.PutAccess(ctx, cur); err != nil {
		t.Fatal(err)
	}
	pushAll(t, c.s, r)
	pull(t, a.s, r)
	pull(t, b.s, r)
	cID := deviceID(t, c.s)
	if got := verifiedAccessOf(t, b.s, alice.ItemID); got == nil || got.By != cID {
		t.Fatalf("before the revocation: %+v", got)
	}
	kit, err := a.s.RevokeDevices(ctx, r, []byte(testPassword), []string{"laptop"}, CheckpointOptions{Keep: []string{deviceID(t, b.s).String()}})
	if err != nil {
		t.Fatal(err)
	}
	pull(t, a.s, r)
	pull(t, b.s, r)
	for _, s := range []*Store{a.s, b.s} {
		ns, err := s.SyncNotes()
		if err != nil || len(ns.AccessReviews) != 1 {
			t.Fatalf("notes %+v %v", ns, err)
		}
		n := ns.AccessReviews[0]
		if !slices.Equal(n.Devices, []model.ID{cID}) || len(n.Items) != 1 || n.Items[0].ItemID != alice.ItemID || n.Items[0].Label != "alice" {
			t.Fatalf("note %+v", n)
		}
		if !slices.Contains(s.RetiredDevices(), cID) {
			t.Fatalf("retired %v", s.RetiredDevices())
		}
		if got := verifiedAccessOf(t, s, alice.ItemID); got == nil || got.By != cID {
			t.Fatalf("after the checkpoint: %+v", got)
		}
	}
	// The checkpoint made a new Secret Key.
	d := secondDeviceNamed(t, &fixture{cfg: a.cfg, kit: kit, s: a.s}, r, "tablet")
	pull(t, d.s, r)
	if got := verifiedAccessOf(t, d.s, alice.ItemID); got == nil || got.By != cID {
		t.Fatalf("the new device: %+v", got)
	}
	if !slices.Contains(d.s.RetiredDevices(), cID) {
		t.Fatalf("the new device's retired list %v", d.s.RetiredDevices())
	}
}

// A checkpoint that revokes a device that last changed no live record
// adds no note.
func TestAccessReviewNoteOnlyWhenRecordsAreAttributed(t *testing.T) {
	ctx := context.Background()
	a, b, r := newCkptPair(t)
	secondDeviceNamed(t, a, r, "laptop")
	if _, err := createAccess(t, b.s, "alice", randomID(t)); err != nil {
		t.Fatal(err)
	}
	pushAll(t, b.s, r)
	pull(t, a.s, r)
	if _, err := a.s.RevokeDevices(ctx, r, []byte(testPassword), []string{"laptop"}, CheckpointOptions{Keep: []string{deviceID(t, b.s).String()}}); err != nil {
		t.Fatal(err)
	}
	pull(t, b.s, r)
	for _, s := range []*Store{a.s, b.s} {
		if ns, err := s.SyncNotes(); err != nil || len(ns.AccessReviews) != 0 {
			t.Fatalf("notes %+v %v", ns, err)
		}
	}
}

// Access proposals are functions of (seen, want, S, d): proposing again
// gives the same plaintext and digest, by is this device in it, and the
// digest confirms the choice (§5.0, P9).
func TestAccessProposalIsDeterministic(t *testing.T) {
	p := newPair(t)
	heldAccess(t, p, model.AccessPending,
		func(x *model.AccessTarget) { x.State, x.Gen = model.AccessRemoving, 2 },
		func(x *model.AccessTarget) { x.State, x.Error = model.AccessFailed, "no" })
	first, err := p.a.s.Propose(Resolution{Choice: merge.ChoiceKeepMine})
	if err != nil {
		t.Fatal(err)
	}
	for range 3 {
		again, err := p.a.s.Propose(Resolution{Choice: merge.ChoiceKeepMine})
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(again.Want, first.Want) || !bytes.Equal(again.Seen, first.Seen) || again.Digest != first.Digest {
			t.Fatalf("proposals differ:\n%s\n%s", first.Want, again.Want)
		}
	}
	if !bytes.Contains(first.Want, []byte(`"by":"`+p.a.s.dev.ID.String()+`"`)) {
		t.Fatalf("by is not this device: %s", first.Want)
	}
	// Edit stamps by before it digests: an edit that carries another
	// device's by proposes the same plaintext and digest as one that
	// carries this device's.
	var mine model.Access
	if err := canonjson.Unmarshal(first.Want, &mine); err != nil {
		t.Fatal(err)
	}
	theirsBy := *access.Clone(&mine)
	theirsBy.By = p.b.s.dev.ID
	e1, err := p.a.s.Propose(Resolution{Choice: merge.ChoiceEdit, Edited: &mine})
	if err != nil {
		t.Fatal(err)
	}
	e2, err := p.a.s.Propose(Resolution{Choice: merge.ChoiceEdit, Edited: &theirsBy})
	if err != nil {
		t.Fatal(err)
	}
	if e1.Digest != e2.Digest || !bytes.Equal(e1.Want, e2.Want) {
		t.Fatalf("edit proposals differ by by:\n%s\n%s", e1.Want, e2.Want)
	}
	if err := p.a.s.Resolve(Resolution{Choice: merge.ChoiceKeepMine, Confirm: first.Digest}); err != nil {
		t.Fatal(err)
	}
}
