package store

import (
	"context"
	"errors"
	"slices"
	"testing"

	"github.com/dalyem/hopkey/internal/merge"
	"github.com/dalyem/hopkey/internal/model"
)

// expectOf is what SetHostKeyIfChain requires of h as the caller saw it: the
// host being written (dest) with its key.
func expectOf(h model.Host, dest bool) HostExpect {
	return HostExpect{Version: h.ItemVersion, Conn: model.ConnDigest(h, dest)}
}

// SetHostKeyIfChain writes only while every item it names is live at the
// version and connection it names, and otherwise writes nothing and says
// which item moved.
func TestSetHostKeyIfChainChecksEveryVersionItNames(t *testing.T) {
	f := newVault(t, testConfig(t))
	ctx := context.Background()
	k, bastion := addHost(t, f.s, "bastion")
	_, web := addHost(t, f.s, "web")
	web.JumpHostID = bastion.ItemID
	web, err := f.s.PutHost(ctx, web)
	if err != nil {
		t.Fatal(err)
	}
	expect := map[model.ID]HostExpect{web.ItemID: expectOf(web, true), bastion.ItemID: expectOf(bastion, false)}

	// The jump host moved since the caller looked.
	b2 := bastion
	b2.Port = 2222
	b2, err = f.s.PutHost(ctx, b2)
	if err != nil {
		t.Fatal(err)
	}
	_, err = f.s.SetHostKeyIfChain(ctx, web.ItemID, k.ItemID, expect)
	var ce *ChangedError
	if !errors.As(err, &ce) || ce.ID != bastion.ItemID || !errors.Is(err, ErrChanged) {
		t.Fatalf("stale jump host: %v, want a ChangedError naming the bastion", err)
	}
	for _, h := range snapshot(t, f.s).Hosts {
		if h.ItemID == web.ItemID && (h.ItemVersion != web.ItemVersion || h.KeyID == k.ItemID) {
			t.Fatalf("a refused write changed web: %+v", h)
		}
	}

	// An item that is gone is changed too.
	gone := map[model.ID]HostExpect{web.ItemID: expectOf(web, true), {9}: {Version: 1, Conn: "x"}}
	if _, err := f.s.SetHostKeyIfChain(ctx, web.ItemID, k.ItemID, gone); !errors.Is(err, ErrChanged) {
		t.Errorf("missing item: %v", err)
	}

	// The right version with another connection, or another key on the
	// host itself: changed.
	expect[bastion.ItemID] = HostExpect{Version: b2.ItemVersion, Conn: expectOf(bastion, false).Conn}
	if _, err := f.s.SetHostKeyIfChain(ctx, web.ItemID, k.ItemID, expect); !errors.As(err, &ce) || ce.ID != bastion.ItemID {
		t.Errorf("jump host at its version, another port: %v", err)
	}
	expect[bastion.ItemID] = expectOf(b2, false)
	otherKey := web
	otherKey.KeyID = model.ID{7}
	expect[web.ItemID] = expectOf(otherKey, true)
	if _, err := f.s.SetHostKeyIfChain(ctx, web.ItemID, k.ItemID, expect); !errors.As(err, &ce) || ce.ID != web.ItemID {
		t.Errorf("host at its version, another key: %v", err)
	}

	// Current versions and connections: written.
	expect[web.ItemID] = expectOf(web, true)
	saved, err := f.s.SetHostKeyIfChain(ctx, web.ItemID, k.ItemID, expect)
	if err != nil {
		t.Fatal(err)
	}
	if saved.KeyID != k.ItemID || saved.ItemVersion != web.ItemVersion+1 || saved.JumpHostID != bastion.ItemID {
		t.Errorf("saved %+v", saved)
	}
}

// Resolving a held edit replaces the queued intent in place: the host's
// overlay version stays where it was while its address changes. A write
// that names the host as it was before the resolve is refused.
func TestSetHostKeyIfChainSeesAHeldEditResolvedInPlace(t *testing.T) {
	ctx := context.Background()
	p := newPair(t)
	a := p.a.s
	p.conflict(t)
	if res := pushAll(t, a, p.r); res.Outcome != PushHeld {
		t.Fatalf("push: %+v", res)
	}
	// What hop key rotate tested: the host as the overlay shows it now.
	tested, ok := hostByID(t, a, p.host.ItemID)
	if !ok {
		t.Fatal("no host")
	}

	// The user resolves the held edit, pointing the host at another server.
	cur, _ := verifiedHost(t, a, p.host.ItemID)
	edited := cloneHost(cur)
	edited.CredentialID = p.c2.ItemID
	edited.Addresses = []string{"198.51.100.77"}
	prop, err := a.Propose(Resolution{Choice: merge.ChoiceEdit, Edited: &edited})
	if err != nil {
		t.Fatal(err)
	}
	if err := a.Resolve(Resolution{Choice: merge.ChoiceEdit, Edited: &edited, Confirm: prop.Digest}); err != nil {
		t.Fatal(err)
	}
	now, _ := hostByID(t, a, p.host.ItemID)
	if now.ItemVersion != tested.ItemVersion || now.Addresses[0] != "198.51.100.77" {
		t.Fatalf("after the resolve the overlay host is %+v (version %d, was %d): the test proves nothing", now.Addresses, now.ItemVersion, tested.ItemVersion)
	}

	_, err = a.SetHostKeyIfChain(ctx, tested.ItemID, p.key.ItemID, map[model.ID]HostExpect{tested.ItemID: expectOf(tested, true)})
	var ce *ChangedError
	if !errors.As(err, &ce) || ce.ID != tested.ItemID {
		t.Fatalf("a write over a held edit resolved to another address: %v, want a ChangedError naming the host", err)
	}
	if h, _ := hostByID(t, a, p.host.ItemID); h.Addresses[0] != "198.51.100.77" || h.ItemVersion != now.ItemVersion {
		t.Fatalf("a refused write changed the host: %+v", h)
	}
}

// A pull that deletes the host between the caller's snapshot and the
// write: refused as changed, in a server-backed vault as in a local one.
func TestSetHostKeyIfChainSeesAPulledDeletion(t *testing.T) {
	ctx := context.Background()
	p := newPair(t)
	a, b := p.a.s, p.b.s
	pull(t, a, p.r)
	seen, ok := hostByID(t, a, p.host.ItemID)
	if !ok {
		t.Fatal("no host")
	}
	if err := b.Delete(ctx, p.host.ItemID); err != nil {
		t.Fatal(err)
	}
	if res := pushAll(t, b, p.r); res.Outcome != PushEmpty {
		t.Fatalf("B's push: %+v", res)
	}
	pull(t, a, p.r)
	if _, ok := hostByID(t, a, p.host.ItemID); ok {
		t.Fatal("the pull did not delete the host: the test proves nothing")
	}
	_, err := a.SetHostKeyIfChain(ctx, seen.ItemID, p.key.ItemID, map[model.ID]HostExpect{seen.ItemID: expectOf(seen, true)})
	var ce *ChangedError
	if !errors.As(err, &ce) || ce.ID != seen.ItemID {
		t.Fatalf("a write over a pulled deletion: %v, want a ChangedError naming the host", err)
	}
}

// The conditional write changes the host's key and nothing else. A held
// edit resolved in place between the caller's snapshot and the write keeps
// the host's version and connection but changes its description and tags:
// the write goes through, since the connection is as tested, and keeps
// what the resolve wrote.
func TestSetHostKeyIfChainKeepsWhatAResolveChangedOutsideTheDigest(t *testing.T) {
	ctx := context.Background()
	p := newPair(t)
	a := p.a.s
	p.conflict(t)
	if res := pushAll(t, a, p.r); res.Outcome != PushHeld {
		t.Fatalf("push: %+v", res)
	}
	privPEM, pub := sshKey(t)
	newKey, err := a.PutKey(ctx, model.Key{Name: "web-key-rotated", KeyType: "ed25519", PrivateKey: privPEM, PublicKey: pub})
	if err != nil {
		t.Fatal(err)
	}
	// What hop key rotate tested: the host as the overlay shows it now.
	tested, ok := hostByID(t, a, p.host.ItemID)
	if !ok {
		t.Fatal("no host")
	}

	// The user resolves the held edit with the same connection, and a new
	// description and tags.
	cur, _ := verifiedHost(t, a, p.host.ItemID)
	edited := cloneHost(tested)
	edited.ItemVersion = cur.ItemVersion
	edited.Description = "resolved"
	edited.Tags = []string{"prod", "resolved"}
	prop, err := a.Propose(Resolution{Choice: merge.ChoiceEdit, Edited: &edited})
	if err != nil {
		t.Fatal(err)
	}
	if err := a.Resolve(Resolution{Choice: merge.ChoiceEdit, Edited: &edited, Confirm: prop.Digest}); err != nil {
		t.Fatal(err)
	}
	now, _ := hostByID(t, a, p.host.ItemID)
	if now.ItemVersion != tested.ItemVersion || model.ConnDigest(now, true) != model.ConnDigest(tested, true) || now.Description != "resolved" {
		t.Fatalf("after the resolve the overlay host is %+v (version %d, was %d): the test proves nothing", now, now.ItemVersion, tested.ItemVersion)
	}

	saved, err := a.SetHostKeyIfChain(ctx, tested.ItemID, newKey.ItemID, map[model.ID]HostExpect{tested.ItemID: expectOf(tested, true)})
	if err != nil {
		t.Fatalf("the repoint over a resolve that kept the connection: %v", err)
	}
	h, _ := hostByID(t, a, p.host.ItemID)
	for what, got := range map[string]model.Host{"returned": saved, "overlay": h} {
		if got.KeyID != newKey.ItemID || got.Description != "resolved" || !slices.Equal(got.Tags, edited.Tags) {
			t.Errorf("%s host: key %v description %q tags %q, want key %v, the resolved description and tags", what, got.KeyID, got.Description, got.Tags, newKey.ItemID)
		}
	}
}
