package daemon

import (
	"context"
	"testing"

	"github.com/dalyem/hopkey/internal/model"
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
		for _, h := range hs {
			out = append(out, ItemVersion{ID: h.ItemID.String(), Version: h.ItemVersion})
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
