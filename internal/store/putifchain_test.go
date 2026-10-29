package store

import (
	"context"
	"errors"
	"testing"

	"github.com/dalyem/hopkey/internal/model"
)

// PutHostIfChain writes only while every item it names is live at the
// version it names, and otherwise writes nothing and says which item moved.
func TestPutHostIfChainChecksEveryVersionItNames(t *testing.T) {
	f := newVault(t, testConfig(t))
	ctx := context.Background()
	k, bastion := addHost(t, f.s, "bastion")
	_, web := addHost(t, f.s, "web")
	web.JumpHostID = bastion.ItemID
	web, err := f.s.PutHost(ctx, web)
	if err != nil {
		t.Fatal(err)
	}
	expect := map[model.ID]uint64{web.ItemID: web.ItemVersion, bastion.ItemID: bastion.ItemVersion}

	// The jump host moved since the caller looked.
	b2 := bastion
	b2.Port = 2222
	if _, err := f.s.PutHost(ctx, b2); err != nil {
		t.Fatal(err)
	}
	moved := web
	moved.KeyID = k.ItemID
	_, err = f.s.PutHostIfChain(ctx, moved, expect)
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
	gone := map[model.ID]uint64{web.ItemID: web.ItemVersion, {9}: 1}
	if _, err := f.s.PutHostIfChain(ctx, moved, gone); !errors.Is(err, ErrChanged) {
		t.Errorf("missing item: %v", err)
	}

	// Current versions: written.
	expect[bastion.ItemID] = bastion.ItemVersion + 1
	saved, err := f.s.PutHostIfChain(ctx, moved, expect)
	if err != nil {
		t.Fatal(err)
	}
	if saved.KeyID != k.ItemID || saved.ItemVersion != web.ItemVersion+1 || saved.JumpHostID != bastion.ItemID {
		t.Errorf("saved %+v", saved)
	}
}
