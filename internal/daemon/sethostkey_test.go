package daemon

import (
	"context"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/dalyem/hopkey/internal/model"
	"github.com/dalyem/hopkey/internal/store"
	"github.com/dalyem/hopkey/internal/syncclient"
)

// set_host_key writes only while the host and every jump host on its way
// are at the versions the caller names, and changes nothing else.
func TestSetHostKeyIsConditionalOnTheWholeWay(t *testing.T) {
	f := newFixture(t, nil)
	ctx := context.Background()
	c := f.client()
	other := genKey(t)
	k2, err := f.store.PutKey(ctx, model.Key{Name: "k2", KeyType: "ed25519", PrivateKey: other.pem, PublicKey: other.line()})
	if err != nil {
		t.Fatal(err)
	}
	bastion := f.put(f.host("bastion", nil))
	web := f.put(f.host("web", func(h *model.Host) { h.JumpHostID = bastion.ItemID; h.Description = "kept" }))
	chain := func(hs ...model.Host) []ItemVersion {
		var out []ItemVersion
		for i, h := range hs {
			out = append(out, ItemVersion{ID: h.ItemID.String(), Version: h.ItemVersion, Conn: model.ConnDigest(h, i == 0)})
		}
		return out
	}
	set := func(ch []ItemVersion) error {
		return c.Call(ctx, OpSetHostKey, SetHostKeyParams{HostID: web.ItemID.String(), KeyID: k2.ItemID.String(), Chain: ch}, nil)
	}
	webNow := func() model.Host {
		for _, h := range f.list().Hosts {
			if h.ItemID == web.ItemID {
				return h
			}
		}
		t.Fatal("web is gone")
		return model.Host{}
	}

	// The jump host changed since the caller looked: refused.
	bastion2 := bastion
	bastion2.Port = 2222
	bastion2 = f.put(bastion2)
	if err := set(chain(web, bastion)); !IsCode(err, CodeChanged) {
		t.Fatalf("stale jump host: %v, want %s", err, CodeChanged)
	}
	// A way shorter or longer than the record's: refused.
	if err := set(chain(web)); !IsCode(err, CodeChanged) {
		t.Errorf("chain without the jump host: %v", err)
	}
	if err := set(chain(web, bastion2, web)); !IsCode(err, CodeChanged) {
		t.Errorf("chain past the last jump host: %v", err)
	}
	// The host itself changed: refused.
	web2 := web
	web2.Description = "edited"
	web2 = f.put(web2)
	if err := set(chain(web, bastion2)); !IsCode(err, CodeChanged) {
		t.Errorf("stale host: %v", err)
	}
	// The right versions, but not the connections the caller checked: the
	// jump host at another address, the host on another key. Refused.
	stale := chain(web2, bastion2)
	b3 := bastion2
	b3.Addresses = []string{"198.51.100.9"}
	stale[1].Conn = model.ConnDigest(b3, false)
	if err := set(stale); !IsCode(err, CodeChanged) {
		t.Errorf("jump host with another connection: %v", err)
	}
	stale = chain(web2, bastion2)
	w3 := web2
	w3.KeyID = k2.ItemID
	stale[0].Conn = model.ConnDigest(w3, true)
	if err := set(stale); !IsCode(err, CodeChanged) {
		t.Errorf("host on another key: %v", err)
	}
	stale = chain(web2, bastion2)
	stale[1].Conn = ""
	if err := set(stale); !IsCode(err, CodeInvalid) {
		t.Errorf("chain without a connection digest: %v", err)
	}
	if got := webNow(); got.KeyID != f.key.ItemID {
		t.Fatalf("a refused write moved the host to %v", got.KeyID)
	}

	// Current versions: written, and only the key changes.
	var saved model.Host
	if err := c.Call(ctx, OpSetHostKey, SetHostKeyParams{HostID: web.ItemID.String(), KeyID: k2.ItemID.String(), Chain: chain(web2, bastion2)}, &saved); err != nil {
		t.Fatal(err)
	}
	got := webNow()
	if got.KeyID != k2.ItemID || saved.KeyID != k2.ItemID || got.Description != "edited" || got.JumpHostID != bastion.ItemID || got.ItemVersion != web2.ItemVersion+1 {
		t.Errorf("after the write: %+v", got)
	}
	// The same versions again are stale now.
	if err := set(chain(web2, bastion2)); !IsCode(err, CodeChanged) {
		t.Errorf("replayed write: %v", err)
	}
	// A key that is not in the vault.
	err = c.Call(ctx, OpSetHostKey, SetHostKeyParams{HostID: web.ItemID.String(), KeyID: model.ID{7}.String(), Chain: chain(got, bastion2)}, nil)
	if !IsCode(err, CodeNotFound) {
		t.Errorf("missing key: %v", err)
	}
}

// A pull that commits between the daemon's snapshot and its write (the
// sync loop pulls without d.mu) and changes a jump host on the way makes
// set_host_key refuse: the store checks the versions in the write's own
// transaction.
func TestSetHostKeyRefusesAJumpHostAPullChanged(t *testing.T) {
	x := newSyncSetup(t)
	ctx := context.Background()
	remote := func(n *node) store.Remote {
		dev, err := syncclient.StoreDevice(n.st.DeviceAuth)
		if err != nil {
			t.Fatal(err)
		}
		return x.w.client(t).Remote(x.pub.VaultID, dev)
	}
	r1, r2 := remote(x.n1), remote(x.n2)
	pushAll := func(s *store.Store, r store.Remote) {
		t.Helper()
		for range 10 {
			res, err := s.PushHead(ctx, r)
			if err != nil {
				t.Fatalf("push: %v", err)
			}
			if res.Outcome == store.PushEmpty {
				return
			}
		}
		t.Fatal("the outbox never drained")
	}
	other := genKey(t)
	k2, err := x.n1.st.PutKey(ctx, model.Key{Name: "k2", KeyType: "ed25519", PrivateKey: other.pem, PublicKey: other.line()})
	if err != nil {
		t.Fatal(err)
	}
	bastion, err := x.n1.st.PutHost(ctx, webHost("bastion", x.keyID, "203.0.113.1"))
	if err != nil {
		t.Fatal(err)
	}
	wh := webHost("web", x.keyID, "203.0.113.10")
	wh.JumpHostID = bastion.ItemID
	web, err := x.n1.st.PutHost(ctx, wh)
	if err != nil {
		t.Fatal(err)
	}
	pushAll(x.n1.st, r1)
	if err := x.n1.st.Pull(ctx, r1); err != nil {
		t.Fatal(err)
	}
	if err := x.n2.st.Pull(ctx, r2); err != nil {
		t.Fatal(err)
	}
	bastionVersion := func(s *store.Store) uint64 {
		t.Helper()
		snap, err := s.Snapshot(ctx)
		if err != nil {
			t.Fatal(err)
		}
		for _, h := range snap.Hosts {
			if h.ItemID == bastion.ItemID {
				return h.ItemVersion
			}
		}
		t.Fatal("no bastion")
		return 0
	}
	seen := bastionVersion(x.n1.st)

	// The hook runs after the daemon's snapshot and checks, under d.mu: it
	// pulls the laptop's new bastion address the way the sync loop does.
	var fired atomic.Bool
	x.w.startWith(x.n1, x.n1.st, Options{Sync: SyncOptions{noPoll: true}, beforeHostKeyWrite: func() {
		fired.Store(true)
		if v := bastionVersion(x.n1.st); v != seen {
			t.Errorf("the desk had the new bastion before the write (version %d, not %d): the test proves nothing", v, seen)
		}
		if err := x.n1.st.Pull(ctx, r1); err != nil {
			t.Errorf("pull: %v", err)
		}
		if v := bastionVersion(x.n1.st); v == seen {
			t.Errorf("the pull did not bring the new bastion")
		}
	}})
	x.n1.pause(true)
	b2 := bastion
	b2.ItemVersion = seen
	b2.Addresses = []string{"198.51.100.66"}
	if _, err := x.n2.st.PutHost(ctx, b2); err != nil {
		t.Fatal(err)
	}
	pushAll(x.n2.st, r2)

	err = x.n1.call(OpSetHostKey, SetHostKeyParams{HostID: web.ItemID.String(), KeyID: k2.ItemID.String(), Chain: []ItemVersion{
		{ID: web.ItemID.String(), Version: web.ItemVersion, Conn: model.ConnDigest(web, true)},
		{ID: bastion.ItemID.String(), Version: seen, Conn: model.ConnDigest(bastion, false)},
	}}, nil)
	if !fired.Load() {
		t.Fatal("the hook never ran")
	}
	if !IsCode(err, CodeChanged) || !strings.Contains(err.Error(), "jump host bastion") {
		t.Fatalf("set_host_key over a jump host a pull changed: %v, want %s naming bastion", err, CodeChanged)
	}
	if h := x.n1.host("web"); h == nil || h.KeyID != x.keyID {
		t.Fatalf("a refused write moved the host: %+v", h)
	}
}
