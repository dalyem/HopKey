package store

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"testing"

	"golang.org/x/crypto/ssh"

	"github.com/dalyem/hopkey/internal/access"
	"github.com/dalyem/hopkey/internal/canonjson"
	"github.com/dalyem/hopkey/internal/merge"
	"github.com/dalyem/hopkey/internal/model"
)

func accessKey(t *testing.T, seed byte) (line, fp string) {
	t.Helper()
	s := make([]byte, 32)
	s[0] = seed
	pk, err := ssh.NewPublicKey(ed25519.NewKeyFromSeed(s).Public())
	if err != nil {
		t.Fatal(err)
	}
	return pk.Type() + " " + base64.StdEncoding.EncodeToString(pk.Marshal()), ssh.FingerprintSHA256(pk)
}

// newAccess creates alice on host (pending, gen 1) through s, and records
// state for that gen if it is installed or failed.
func newAccess(t *testing.T, s *Store, host model.ID, state string) model.Access {
	t.Helper()
	line, fp := accessKey(t, 1)
	_, hfp := accessKey(t, 2)
	rid := randomID(t)
	a, err := s.PutAccess(context.Background(), model.Access{
		Label: "alice", RecordID: rid, PublicKey: line, Fingerprint: fp,
		Options: model.AccessOptions{From: []string{}},
		Targets: []model.AccessTarget{{HostItemID: host, User: "root", ServerKeyFP: hfp, Gen: 1, State: model.AccessPending, Time: 1}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if state != model.AccessPending {
		a.Targets[0].State = state
		if a, err = s.PutAccess(context.Background(), a); err != nil {
			t.Fatal(err)
		}
	}
	return a
}

func overlayAccess(t *testing.T, s *Store, id model.ID) model.Access {
	t.Helper()
	snap, err := s.Snapshot(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	for _, a := range snap.Access {
		if a.ItemID == id {
			return a
		}
	}
	t.Fatalf("no access item %v", id)
	return model.Access{}
}

func verifiedAccessOf(t *testing.T, s *Store, id model.ID) *model.Access {
	t.Helper()
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.verifiedAccess(id)
}

func putTarget(t *testing.T, s *Store, id model.ID, f func(t *model.AccessTarget)) error {
	t.Helper()
	a := overlayAccess(t, s, id)
	f(&a.Targets[0])
	_, err := s.PutAccess(context.Background(), a)
	return err
}

// Every write is stamped with the writing device's ID (§5.0), and a write
// V_access refuses is not journaled.
func TestAccessWritesAreStamped(t *testing.T) {
	p := newPair(t)
	a := newAccess(t, p.a.s, p.host.ItemID, model.AccessPending)
	if a.By != p.a.s.dev.ID {
		t.Fatalf("by %v, want A %v", a.By, p.a.s.dev.ID)
	}
	pushAll(t, p.a.s, p.r)
	pull(t, p.b.s, p.r)
	if err := putTarget(t, p.b.s, a.ItemID, func(x *model.AccessTarget) { x.State = model.AccessInstalled }); err != nil {
		t.Fatal(err)
	}
	pushAll(t, p.b.s, p.r)
	pull(t, p.a.s, p.r)
	if got := verifiedAccessOf(t, p.a.s, a.ItemID); got.By != p.b.s.dev.ID || got.Targets[0].State != model.AccessInstalled {
		t.Fatalf("after B's write: %+v", got)
	}
	// installed -> failed is no row of the table.
	err := putTarget(t, p.a.s, a.ItemID, func(x *model.AccessTarget) { x.State, x.Error = model.AccessFailed, "x" })
	if !errors.Is(err, access.ErrRefused) {
		t.Fatalf("refused write: %v", err)
	}
	if n := len(records(t, p.a.s)); n != 0 {
		t.Fatalf("%d records queued", n)
	}
	// A put that changes nothing but by is not journaled either.
	if err := putTarget(t, p.a.s, a.ItemID, func(*model.AccessTarget) {}); !errors.Is(err, access.ErrRefused) {
		t.Fatalf("put with no change: %v", err)
	}
}

// A queued put that rebases to S on every member but by is dropped: it
// leaves the outbox and posts nothing (§5.1 rule 6).
func TestAccessRebaseToSameStateDrops(t *testing.T) {
	p := newPair(t)
	a := newAccess(t, p.a.s, p.host.ItemID, model.AccessPending)
	pushAll(t, p.a.s, p.r)
	pull(t, p.b.s, p.r)
	both := func(x *model.AccessTarget) { x.State = model.AccessInstalled }
	if err := putTarget(t, p.a.s, a.ItemID, both); err != nil {
		t.Fatal(err)
	}
	if err := putTarget(t, p.b.s, a.ItemID, both); err != nil {
		t.Fatal(err)
	}
	pushAll(t, p.b.s, p.r)
	pull(t, p.a.s, p.r)
	before := p.a.s.state.Items[a.ItemID].ItemVersion
	res, err := p.a.s.PushHead(context.Background(), p.r)
	if err != nil || res.Outcome != PushDropped {
		t.Fatalf("push: %+v %v", res, err)
	}
	pull(t, p.a.s, p.r)
	if n := len(records(t, p.a.s)); n != 0 || p.a.s.state.Items[a.ItemID].ItemVersion != before {
		t.Fatalf("records %d, version %d -> %d", n, before, p.a.s.state.Items[a.ItemID].ItemVersion)
	}
	if got := verifiedAccessOf(t, p.a.s, a.ItemID); got.By != p.b.s.dev.ID {
		t.Fatalf("by moved to %v", got.By)
	}
}

// heldAccess queues on A mine(target) and commits on B theirs(target),
// then pushes A, which holds.
func heldAccess(t *testing.T, p *pair, start string, mine, theirs func(x *model.AccessTarget)) model.Access {
	t.Helper()
	a := newAccess(t, p.a.s, p.host.ItemID, start)
	pushAll(t, p.a.s, p.r)
	pull(t, p.b.s, p.r)
	if err := putTarget(t, p.a.s, a.ItemID, mine); err != nil {
		t.Fatal(err)
	}
	if err := putTarget(t, p.b.s, a.ItemID, theirs); err != nil {
		t.Fatal(err)
	}
	pushAll(t, p.b.s, p.r)
	pull(t, p.a.s, p.r)
	if res := pushAll(t, p.a.s, p.r); res.Outcome != PushHeld {
		t.Fatalf("A's push: %+v", res)
	}
	return a
}

// Keep mine of a held access put journals this device's by, shown and
// digested before journaling; one that would regress a target is refused.
func TestAccessKeepMine(t *testing.T) {
	t.Run("stamped", func(t *testing.T) {
		p := newPair(t)
		// A removes a pending target while B records that its add failed:
		// failed -> removing is a row, so keep mine applies.
		a := heldAccess(t, p, model.AccessPending,
			func(x *model.AccessTarget) { x.State, x.Gen = model.AccessRemoving, 2 },
			func(x *model.AccessTarget) { x.State, x.Error = model.AccessFailed, "no" })
		prop := keepMine(t, p.a.s)
		var want model.Access
		if err := canonjson.Unmarshal(prop.Want, &want); err != nil {
			t.Fatal(err)
		}
		if want.By != p.a.s.dev.ID || want.Targets[0].State != model.AccessRemoving {
			t.Fatalf("keep mine proposes %+v", want)
		}
		pushAll(t, p.a.s, p.r)
		if got := verifiedAccessOf(t, p.a.s, a.ItemID); got.By != p.a.s.dev.ID || got.Targets[0].State != model.AccessRemoving {
			t.Fatalf("committed %+v", got)
		}
	})
	t.Run("regression refused", func(t *testing.T) {
		p := newPair(t)
		// A records installed for gen 1; B has started removing (gen 2).
		heldAccess(t, p, model.AccessPending,
			func(x *model.AccessTarget) { x.State = model.AccessInstalled },
			func(x *model.AccessTarget) { x.State, x.Gen = model.AccessRemoving, 2 })
		if _, err := p.a.s.Propose(Resolution{Choice: merge.ChoiceKeepMine}); !errors.Is(err, access.ErrRefused) {
			t.Errorf("keep mine: %v", err)
		}
		if err := p.a.s.Resolve(Resolution{Choice: merge.ChoiceTakeTheirs}); err != nil {
			t.Fatal(err)
		}
		if n := len(records(t, p.a.s)); n != 0 {
			t.Fatalf("%d records after take theirs", n)
		}
	})
}

// A held rm --same-machine put: every choice that writes is refused with
// the re-run message, and take theirs succeeds (R4-P2-4).
func TestAccessAttestationIsNeverResolved(t *testing.T) {
	p := newPair(t)
	_, hfp := accessKey(t, 2)
	other := model.ID{0xff}
	heldAccess(t, p, model.AccessInstalled,
		func(x *model.AccessTarget) {
			x.State, x.Gen = model.AccessRemoving, 2
			x.SameMachine = &model.SameMachine{Gen: 2, ServerKeyFP: hfp, HostItemIDs: []model.ID{other}}
		},
		func(x *model.AccessTarget) { x.State, x.Gen = model.AccessRemoving, 2 })
	// Keep mine carries the statement into S: refused. (With one unit,
	// both --merge choices are refused by the Part 1 rule already.)
	_, err := p.a.s.Propose(Resolution{Choice: merge.ChoiceKeepMine})
	var r *access.Refusal
	if !errors.As(err, &r) || r.Rule != access.RuleAttestation {
		t.Errorf("keep mine: %v", err)
	}
	for _, c := range []merge.Choice{merge.ChoiceKeepMineMerge, merge.ChoiceTakeTheirsMerge} {
		if _, err := p.a.s.Propose(Resolution{Choice: c}); err == nil {
			t.Errorf("%s accepted", c)
		}
	}
	if err := p.a.s.Resolve(Resolution{Choice: merge.ChoiceTakeTheirs}); err != nil {
		t.Fatal(err)
	}
}

// A queued rm --same-machine put with no concurrent change rebases and
// carries the attestation.
func TestAccessAttestationRebases(t *testing.T) {
	p := newPair(t)
	a := newAccess(t, p.a.s, p.host.ItemID, model.AccessInstalled)
	pushAll(t, p.a.s, p.r)
	_, hfp := accessKey(t, 2)
	sm := &model.SameMachine{Gen: 2, ServerKeyFP: hfp, HostItemIDs: []model.ID{{0xff}}}
	if err := putTarget(t, p.a.s, a.ItemID, func(x *model.AccessTarget) { x.State, x.Gen, x.SameMachine = model.AccessRemoving, 2, sm }); err != nil {
		t.Fatal(err)
	}
	pushAll(t, p.a.s, p.r)
	if got := verifiedAccessOf(t, p.a.s, a.ItemID); got.Targets[0].SameMachine == nil || got.Targets[0].SameMachine.Gen != 2 {
		t.Fatalf("committed %+v", got.Targets[0])
	}
}

// Local-only: V_access and the delete rules apply to direct writes.
func TestAccessLocalOnly(t *testing.T) {
	f := newVault(t, testConfig(t))
	_, host := addHost(t, f.s, "web")
	ctx := context.Background()
	a := newAccess(t, f.s, host.ItemID, model.AccessPending)
	if a.By != f.s.dev.ID || a.ItemVersion != 1 {
		t.Fatalf("created %+v", a)
	}
	if err := putTarget(t, f.s, a.ItemID, func(x *model.AccessTarget) { x.State = model.AccessRemoved }); !errors.Is(err, access.ErrRefused) {
		t.Fatalf("pending -> removed: %v", err)
	}
	if err := f.s.DeleteAccess(ctx, a.ItemID, true); !errors.Is(err, access.ErrRefused) {
		t.Fatalf("delete with a pending target: %v", err)
	}
	if err := putTarget(t, f.s, a.ItemID, func(x *model.AccessTarget) { x.State, x.Gen = model.AccessAbandoned, 2 }); err != nil {
		t.Fatal(err)
	}
	if err := f.s.DeleteAccess(ctx, a.ItemID, false); !errors.Is(err, access.ErrRefused) {
		t.Fatalf("rm's delete with an abandoned target: %v", err)
	}
	if err := f.s.DeleteAccess(ctx, a.ItemID, true); err != nil {
		t.Fatalf("forget: %v", err)
	}
}

// capsPublisher is the fake server as a Publisher that answers GET
// /v1/capabilities with types.
type capsPublisher struct {
	publisher
	types []model.Type
	calls *int
}

func (p capsPublisher) ItemTypes(context.Context) ([]model.Type, error) {
	*p.calls++
	return p.types, nil
}

// Publishing a local-only vault whose log ever held an access item needs a
// server that lists access; the check covers a deleted record's history,
// and a refusal journals nothing (crypto spec rev 17, §5.3).
func TestPublishWithAccessHistory(t *testing.T) {
	ctx := context.Background()
	f, srv := publishFixture(t)
	_, host := addHost(t, f.s, "db")
	a := newAccess(t, f.s, host.ItemID, model.AccessPending)
	a.Targets[0].State, a.Targets[0].Gen = model.AccessAbandoned, 2
	if _, err := f.s.PutAccess(ctx, a); err != nil {
		t.Fatal(err)
	}
	if err := f.s.DeleteAccess(ctx, a.ItemID, true); err != nil {
		t.Fatal(err)
	}
	calls := 0
	for _, p := range []Publisher{publisher{srv}, capsPublisher{publisher{srv}, []model.Type{model.TypeHost, model.TypeKey}, &calls}} {
		if _, err := f.s.Publish(ctx, p, pubOpts); !errors.Is(err, ErrAccessUnsupported) {
			t.Fatalf("publish: %v", err)
		}
		if pending, err := f.s.l.publicationPending(); err != nil || pending {
			t.Fatalf("publication journaled: %v %v", pending, err)
		}
		newCredential(t, f.s, "still-writable-"+string(rune('a'+calls)))
	}
	if calls != 1 || srv.signups != 0 {
		t.Fatalf("capabilities calls %d, signups %d", calls, srv.signups)
	}
	if _, err := f.s.Publish(ctx, capsPublisher{publisher{srv}, []model.Type{model.TypeAccess, model.TypeHost}, &calls}, pubOpts); err != nil {
		t.Fatalf("publish to a server that lists access: %v", err)
	}
	published(t, f, f.s, srv)
}
