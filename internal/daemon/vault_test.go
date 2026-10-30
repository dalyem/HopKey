package daemon

import (
	"context"
	"errors"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/zalando/go-keyring"

	"github.com/dalyem/hopkey/internal/model"
	"github.com/dalyem/hopkey/internal/store"
)

// countingStore counts snapshot reads of the encrypted store.
type countingStore struct {
	*store.Store
	snapshots atomic.Int32
}

func (c *countingStore) Snapshot(ctx context.Context) (model.Snapshot, error) {
	c.snapshots.Add(1)
	return c.Store.Snapshot(ctx)
}

// memKeyring is an in-memory store.Keyring.
type memKeyring struct {
	mu sync.Mutex
	m  map[string]string
}

func (r *memKeyring) Get(s, u string) (string, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	v, ok := r.m[s+"/"+u]
	if !ok {
		return "", keyring.ErrNotFound
	}
	return v, nil
}

func (r *memKeyring) Set(s, u, v string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.m[s+"/"+u] = v
	return nil
}

func (r *memKeyring) Delete(s, u string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.m, s+"/"+u)
	return nil
}

func TestEncryptedVaultOps(t *testing.T) {
	base := shortDir(t)
	ring := &memKeyring{m: map[string]string{}}
	cfg := store.Config{DataDir: filepath.Join(base, "data"), Keyring: ring, Getenv: func(string) string { return "" }}
	const password = "a master password"
	p, err := store.PrepareInit(cfg, store.InitOptions{Password: []byte(password)})
	if err != nil {
		t.Fatal(err)
	}
	s0, err := p.Commit()
	if err != nil {
		t.Fatal(err)
	}
	s0.Close() // the daemon below owns the vault

	ring.m = map[string]string{} // the keychain entry is lost

	ctx := context.Background()
	s, err := store.Open(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	cs := &countingStore{Store: s}
	paths := Paths{RunDir: filepath.Join(base, "run"), ConfigDir: filepath.Join(base, "cfg")}
	d, err := Start(Options{Paths: paths, Store: cs, Tailscale: fakeTS{}})
	if err != nil {
		t.Fatalf("a locked vault should still get a daemon: %v", err)
	}
	defer d.Close()
	c, err := Dial(ctx, d.ControlSocket())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	var st StatusResult
	if err := c.Call(ctx, OpStatus, nil, &st); err != nil {
		t.Fatal(err)
	}
	if st.Vault == nil || !st.Vault.Locked || st.Vault.LockReason == "" || st.Vault.DeviceStore != "keychain" {
		t.Fatalf("status of a locked vault: %+v", st.Vault)
	}
	if err := c.Call(ctx, OpList, nil, nil); !IsCode(err, CodeLocked) {
		t.Errorf("list while locked: %v", err)
	}
	if err := c.Call(ctx, OpUnlock, nil, nil); err == nil {
		t.Error("device-key unlock worked without a device key")
	}
	if err := c.Call(ctx, OpUnlock, UnlockParams{Password: password}, nil); !IsCode(err, CodeNeedSecretKey) {
		t.Errorf("password unlock without a Secret Key: %v", err)
	}
	if err := c.Call(ctx, OpUnlock, UnlockParams{Password: "wrong password", SecretKey: p.Kit().SecretKey}, nil); !IsCode(err, CodeWrongPassword) {
		t.Errorf("wrong password: %v", err)
	}
	if err := c.Call(ctx, OpUnlock, UnlockParams{Password: password, SecretKey: p.Kit().SecretKey}, nil); err != nil {
		t.Fatal(err)
	}

	// While the head does not move, requests do not re-read the store.
	if err := c.Call(ctx, OpList, nil, nil); err != nil {
		t.Fatal(err)
	}
	n := cs.snapshots.Load()
	for range 3 {
		if err := c.Call(ctx, OpList, nil, nil); err != nil {
			t.Fatal(err)
		}
	}
	if got := cs.snapshots.Load(); got != n {
		t.Errorf("%d snapshot reads for three lists at one head", got-n)
	}
	// A write moves the head, and the next request sees it.
	k := genKey(t)
	if _, err := cs.PutKey(ctx, model.Key{Name: "k1", KeyType: "ed25519", PrivateKey: k.pem, PublicKey: k.line()}); err != nil {
		t.Fatal(err)
	}
	var l ListResult
	if err := c.Call(ctx, OpList, nil, &l); err != nil || len(l.Keys) != 1 {
		t.Errorf("list after a write: %v %+v", err, l.Keys)
	}
	if keys, _ := d.live.List(); len(keys) != 1 {
		t.Errorf("%d keys in the agent, want 1", len(keys))
	}

	// The lost device key's device is stale until hop passwd revokes it.
	var unlocked StatusResult
	if err := c.Call(ctx, OpStatus, nil, &unlocked); err != nil || unlocked.Vault.StaleDevices != 1 || len(unlocked.Vault.Warnings) != 1 {
		t.Errorf("status after a password unlock: %v %+v", err, unlocked.Vault)
	}
	if err := c.Call(ctx, OpPasswd, PasswdParams{Current: "wrong password", New: "another password"}, nil); !IsCode(err, CodeWrongPassword) {
		t.Errorf("passwd with a wrong current password: %v", err)
	}
	var kr KitResult
	if err := c.Call(ctx, OpPasswd, PasswdParams{Current: password, New: "another password"}, &kr); err != nil || kr.Kit == nil {
		t.Fatalf("passwd: %v %+v", err, kr)
	}
	if err := c.Call(ctx, OpPasswd, PasswdParams{Current: "another password", New: password}, nil); !IsCode(err, CodeKitPending) {
		t.Errorf("passwd with a kit pending: %v", err)
	}
	if err := c.Call(ctx, OpKitDone, nil, nil); err != nil {
		t.Fatal(err)
	}
	if err := c.Call(ctx, OpKit, nil, &kr); err != nil || kr.Kit != nil {
		t.Errorf("kit after ack: %v %+v", err, kr.Kit)
	}
	if err := c.Call(ctx, OpLock, nil, nil); err != nil {
		t.Fatal(err)
	}
	if keys, _ := d.live.List(); len(keys) != 0 {
		t.Errorf("%d keys in the agent after lock", len(keys))
	}
	if err := c.Call(ctx, OpUnlock, nil, nil); err != nil {
		t.Fatalf("unlock with the new device key: %v", err)
	}
	if keys, _ := d.live.List(); len(keys) != 1 {
		t.Errorf("%d keys in the agent after unlock, want 1", len(keys))
	}
	var after StatusResult
	if err := c.Call(ctx, OpStatus, nil, &after); err != nil || after.Vault.StaleDevices != 0 || len(after.Vault.Warnings) != 0 {
		t.Errorf("status after passwd: %v %+v", err, after.Vault)
	}

	// The daemon owns the vault until it stops, and then lets it go.
	if _, err := store.Open(ctx, cfg); !errors.Is(err, store.ErrVaultBusy) {
		t.Errorf("open while the daemon runs: %v, want ErrVaultBusy", err)
	}
	c.Close()
	if err := d.Close(); err != nil {
		t.Fatal(err)
	}
	s2, err := store.Open(ctx, cfg)
	if err != nil {
		t.Fatalf("open after the daemon stopped: %v", err)
	}
	s2.Close()
}
