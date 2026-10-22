package modeltest

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/dalyem/hopkey/internal/model"
)

func newHost(name string) model.Host {
	return model.Host{Name: name, Route: "auto", AgentAccess: "allow", Port: 22}
}

func newKey(name string) model.Key {
	return model.Key{Name: name, KeyType: "ed25519", PrivateKey: "private", PublicKey: "public"}
}

func TestPutAssignsIDsAndBumpsVersions(t *testing.T) {
	ctx := context.Background()
	s := New()
	h, err := s.PutHost(ctx, newHost("a"))
	if err != nil {
		t.Fatal(err)
	}
	if h.ItemID.IsZero() || h.ItemVersion != 1 || h.Type != model.TypeHost || h.V != 1 {
		t.Fatalf("created host header = %+v", h.Header)
	}
	if h.Aliases == nil || h.Addresses == nil || h.Tags == nil || h.HostKeys == nil {
		t.Error("nil slices were not normalised to empty ones")
	}
	h.Description = "changed"
	h2, err := s.PutHost(ctx, h)
	if err != nil || h2.ItemVersion != 2 {
		t.Fatalf("replace: %+v, %v", h2.Header, err)
	}
	// A stale version is refused.
	if _, err := s.PutHost(ctx, h); err == nil || !strings.Contains(err.Error(), "version") {
		t.Errorf("replace with a stale version: %v", err)
	}
	// An unknown ID is not found.
	ghost := newHost("ghost")
	ghost.ItemID = model.ID{1}
	if _, err := s.PutHost(ctx, ghost); !errors.Is(err, model.ErrNotFound) {
		t.Errorf("unknown id: %v", err)
	}
	// An ID of another type is refused.
	k, err := s.PutKey(ctx, newKey("k"))
	if err != nil {
		t.Fatal(err)
	}
	wrong := newHost("wrong")
	wrong.ItemID, wrong.ItemVersion = k.ItemID, 1
	if _, err := s.PutHost(ctx, wrong); err == nil || !strings.Contains(err.Error(), "not a host") {
		t.Errorf("replacing a key with a host: %v", err)
	}
	snap, _ := s.Snapshot(ctx)
	if len(snap.Hosts) != 1 || snap.Hosts[0].Description != "changed" || len(snap.Keys) != 1 {
		t.Errorf("snapshot = %+v", snap)
	}
}

func TestReferenceIntegrity(t *testing.T) {
	ctx := context.Background()
	s := New()
	k, _ := s.PutKey(ctx, newKey("k"))
	jump, _ := s.PutHost(ctx, newHost("jump"))

	h := newHost("web")
	h.KeyID, h.JumpHostID = k.ItemID, jump.ItemID
	web, err := s.PutHost(ctx, h)
	if err != nil {
		t.Fatal(err)
	}

	bad := newHost("bad")
	bad.KeyID = model.ID{9}
	if _, err := s.PutHost(ctx, bad); err == nil || !strings.Contains(err.Error(), "missing key") {
		t.Errorf("dangling key: %v", err)
	}
	if err := s.Delete(ctx, k.ItemID); err == nil {
		t.Error("deleted a key that a host uses")
	}
	if err := s.Delete(ctx, jump.ItemID); err == nil {
		t.Error("deleted a host that another jumps through")
	}
	// Loops are refused.
	jump.JumpHostID = web.ItemID
	if _, err := s.PutHost(ctx, jump); err == nil || !strings.Contains(err.Error(), "loop") {
		t.Errorf("jump loop: %v", err)
	}
	// After the user is gone the key can go.
	if err := s.Delete(ctx, web.ItemID); err != nil {
		t.Fatal(err)
	}
	if err := s.Delete(ctx, k.ItemID); err != nil {
		t.Errorf("deleting an unused key: %v", err)
	}
	if err := s.Delete(ctx, k.ItemID); !errors.Is(err, model.ErrNotFound) {
		t.Errorf("deleting twice: %v", err)
	}
}

func TestPersistFailureRollsBack(t *testing.T) {
	ctx := context.Background()
	s := New()
	if _, err := s.PutHost(ctx, newHost("kept")); err != nil {
		t.Fatal(err)
	}
	s.Persist = func(model.Snapshot) error { return errors.New("disk full") }
	if _, err := s.PutHost(ctx, newHost("lost")); err == nil {
		t.Fatal("PutHost ignored the persist error")
	}
	snap, _ := s.Snapshot(ctx)
	if len(snap.Hosts) != 1 || snap.Hosts[0].Name != "kept" {
		t.Errorf("snapshot after a failed persist = %+v", snap.Hosts)
	}
	if s.Writes() != 1 {
		t.Errorf("writes = %d, want 1", s.Writes())
	}
}

func TestSnapshotIsACopy(t *testing.T) {
	ctx := context.Background()
	s := New()
	h := newHost("a")
	h.Tags = []string{"x"}
	h.Tailscale = &model.Tailscale{StableNodeID: "n", SSH: "yes"}
	if _, err := s.PutHost(ctx, h); err != nil {
		t.Fatal(err)
	}
	snap, _ := s.Snapshot(ctx)
	snap.Hosts[0].Tags[0] = "mutated"
	snap.Hosts[0].Tailscale.SSH = "no"
	again, _ := s.Snapshot(ctx)
	if again.Hosts[0].Tags[0] != "x" || again.Hosts[0].Tailscale.SSH != "yes" {
		t.Error("changing a snapshot changed the store")
	}
}

func TestValidation(t *testing.T) {
	ctx := context.Background()
	s := New()
	for name, mod := range map[string]func(*model.Host){
		"no name":    func(h *model.Host) { h.Name = "" },
		"bad port":   func(h *model.Host) { h.Port = 70000 },
		"bad route":  func(h *model.Host) { h.Route = "x" },
		"bad access": func(h *model.Host) { h.AgentAccess = "x" },
		"bad ts ssh": func(h *model.Host) { h.Tailscale = &model.Tailscale{SSH: "maybe"} },
	} {
		h := newHost("a")
		mod(&h)
		if _, err := s.PutHost(ctx, h); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if _, err := s.PutKey(ctx, model.Key{Name: "k", KeyType: "dsa", PrivateKey: "p", PublicKey: "q"}); err == nil {
		t.Error("accepted a dsa key")
	}
}
