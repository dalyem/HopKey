//go:build hopdev

package devstore

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/dalyem/hopkey/internal/model"
)

func TestPersistsAcrossOpens(t *testing.T) {
	dir, err := os.MkdirTemp("", "hk")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	path := filepath.Join(dir, "state", "dev.json")
	ctx := context.Background()

	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	k, err := s.PutKey(ctx, model.Key{Name: "k", KeyType: "ed25519", PrivateKey: "secret", PublicKey: "pub"})
	if err != nil {
		t.Fatal(err)
	}
	h, err := s.PutHost(ctx, model.Host{Name: "web", Route: "auto", AgentAccess: "allow", KeyID: k.ItemID, Addresses: []string{"1.2.3.4"}})
	if err != nil {
		t.Fatal(err)
	}
	if fi, err := os.Stat(path); err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("file: %v %v", fi, err)
	}

	again, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	snap, _ := again.Snapshot(ctx)
	if len(snap.Hosts) != 1 || snap.Hosts[0].ItemID != h.ItemID || snap.Hosts[0].ItemVersion != 1 || snap.Hosts[0].KeyID != k.ItemID || len(snap.Keys) != 1 {
		t.Errorf("reopened snapshot = %+v", snap)
	}
	// Versions continue where they were.
	h2, err := again.PutHost(ctx, snap.Hosts[0])
	if err != nil || h2.ItemVersion != 2 {
		t.Errorf("replace after reopen: %+v %v", h2.Header, err)
	}
	// A corrupt file is an error that says which store it came from.
	os.WriteFile(path, []byte("{not json"), 0o600)
	if _, err := Open(path); err == nil || !strings.Contains(err.Error(), Marker) {
		t.Errorf("corrupt file: %v", err)
	}
}
