package daemon

import (
	"context"
	"errors"
	"fmt"
	"net"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/crypto/ssh/agent"

	"github.com/dalyem/hopkey/internal/model"
	"github.com/dalyem/hopkey/internal/model/modeltest"
	"github.com/dalyem/hopkey/internal/store"
)

// fencedStore is a Vault with store.Store's lock-free fence: a generation
// that moves, and a revoked flag that is set, before any slow persistence.
// Its own mutex stands for store.Store's: while a revocation persists, it
// holds it, so Head and Snapshot wait.
type fencedStore struct {
	*modeltest.Store
	gen       atomic.Uint64
	isRevoked atomic.Bool
	ch        chan struct{}

	mu      sync.Mutex
	locked  bool
	revoked bool
	// failPut makes the next PutHost fail as an interrupted commit does: the
	// store locks itself and returns an error that is not model.ErrLocked.
	failPut bool
}

func newFencedStore() *fencedStore {
	return &fencedStore{Store: modeltest.New(), ch: make(chan struct{})}
}

func (f *fencedStore) Generation() uint64       { return f.gen.Load() }
func (f *fencedStore) IsRevoked() bool          { return f.isRevoked.Load() }
func (f *fencedStore) Revoked() <-chan struct{} { return f.ch }

// revoke moves the fence and signals, then persists under the mutex until
// persist is closed.
func (f *fencedStore) revoke(persist <-chan struct{}) {
	f.isRevoked.Store(true)
	f.gen.Add(1)
	close(f.ch)
	f.mu.Lock()
	defer f.mu.Unlock()
	<-persist
	f.revoked, f.locked = true, true
}

func (f *fencedStore) errLocked() error {
	switch {
	case f.revoked:
		return fmt.Errorf("%w (in a test)", store.ErrDeviceRevoked)
	case f.locked:
		return fmt.Errorf("%w (in a test)", model.ErrLocked)
	}
	return nil
}

func (f *fencedStore) Snapshot(ctx context.Context) (model.Snapshot, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.errLocked(); err != nil {
		return model.Snapshot{}, err
	}
	return f.Store.Snapshot(ctx)
}

func (f *fencedStore) PutHost(ctx context.Context, h model.Host) (model.Host, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.errLocked(); err != nil {
		return model.Host{}, err
	}
	if f.failPut {
		f.failPut = false
		f.gen.Add(1)
		f.locked = true
		return model.Host{}, errors.New("store: injected journal failure after install")
	}
	return f.Store.PutHost(ctx, h)
}

func (f *fencedStore) Head() (store.Head, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.errLocked(); err != nil {
		return store.Head{}, err
	}
	return store.Head{Seq: uint64(f.Writes()), H: "test"}, nil
}

func (f *fencedStore) Info() store.Info {
	f.mu.Lock()
	defer f.mu.Unlock()
	return store.Info{Locked: f.locked, Revoked: f.revoked}
}

func (f *fencedStore) Lock() {
	f.gen.Add(1)
	f.mu.Lock()
	defer f.mu.Unlock()
	f.locked = true
}

func (f *fencedStore) Unlock(context.Context) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.revoked {
		return f.errLocked()
	}
	if f.locked {
		f.locked = false
		f.gen.Add(1)
	}
	return nil
}

func (f *fencedStore) UnlockWithPassword(ctx context.Context, _ []byte, _ string) error {
	return f.Unlock(ctx)
}
func (f *fencedStore) UnlockWithPassphrase(ctx context.Context, _ []byte) error {
	return f.Unlock(ctx)
}
func (f *fencedStore) ChangePassword(context.Context, []byte, []byte) (store.Kit, error) {
	return store.Kit{}, errors.New("not in this test")
}
func (f *fencedStore) PendingKit() *store.Kit { return nil }
func (f *fencedStore) AckKit() error          { return nil }

// startFenced starts a daemon on a fencedStore holding one key and a host
// that uses it, and returns an agent client on an open connection.
func startFenced(t *testing.T) (*Daemon, *fencedStore, testKey, agent.ExtendedAgent) {
	t.Helper()
	ctx := context.Background()
	base := shortDir(t)
	k := genKey(t)
	fs := newFencedStore()
	key, err := fs.Store.PutKey(ctx, model.Key{Name: "k1", KeyType: "ed25519", PrivateKey: k.pem, PublicKey: k.line()})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fs.Store.PutHost(ctx, model.Host{Name: "web", Addresses: []string{"203.0.113.10"}, Port: 22, User: "deploy",
		KeyID: key.ItemID, Route: "auto", AgentAccess: "allow"}); err != nil {
		t.Fatal(err)
	}
	paths := Paths{RunDir: filepath.Join(base, "run"), ConfigDir: filepath.Join(base, "cfg")}
	d, err := Start(Options{Paths: paths, Store: fs, Version: "test", Tailscale: fakeTS{}, Logf: t.Logf})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { d.Close() })
	conn, err := net.Dial("unix", d.AgentSocket())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	ag := agent.NewClient(conn)
	if _, err := ag.Sign(k.pub, []byte("before")); err != nil {
		t.Fatalf("setup: sign: %v", err)
	}
	if l, err := ag.List(); err != nil || len(l) != 1 {
		t.Fatalf("setup: list %d keys, %v", len(l), err)
	}
	return d, fs, k, ag
}

// keyringSize is how many keys the daemon's keyring holds, past the fence.
func keyringSize(t *testing.T, d *Daemon) int {
	t.Helper()
	l, err := d.live.cur.Load().kr.Agent().List()
	if err != nil {
		t.Fatal(err)
	}
	return len(l)
}

// Round 3 (D1), finding 1: a revocation fences signing at once. The store
// moves its generation and sets its revoked flag first, then persists
// while holding its mutex, which the daemon's teardown waits on. An agent
// connection that was already open lists no keys and signs nothing while
// that persistence is still blocked; the teardown follows once it ends.
func TestRevocationFencesSigningBeforeTeardown(t *testing.T) {
	d, fs, k, ag := startFenced(t)
	persist := make(chan struct{})
	revoked := make(chan struct{})
	go func() {
		defer close(revoked)
		fs.revoke(persist)
	}()
	<-fs.ch

	done := make(chan struct{})
	var signErr, listErr error
	var listed []*agent.Key
	go func() {
		defer close(done)
		_, signErr = ag.Sign(k.pub, []byte("during the revocation"))
		listed, listErr = ag.List()
	}()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		close(persist)
		t.Fatal("the agent blocked behind the revocation")
	}
	if signErr == nil {
		t.Error("the agent signed while the revocation was persisting")
	}
	if listErr != nil || len(listed) != 0 {
		t.Errorf("the agent listed %d keys (%v) while the revocation was persisting", len(listed), listErr)
	}
	select {
	case <-revoked:
		t.Fatal("setup: the revocation's persistence was not blocked")
	default:
	}
	if keyringSize(t, d) != 1 {
		t.Fatal("setup: the teardown ran before the persistence finished")
	}

	close(persist)
	<-revoked
	for deadline := time.Now().Add(5 * time.Second); keyringSize(t, d) != 0 && time.Now().Before(deadline); {
		time.Sleep(10 * time.Millisecond)
	}
	if n := keyringSize(t, d); n != 0 {
		t.Errorf("the keyring holds %d keys after the teardown", n)
	}
	if _, err := ag.Sign(k.pub, []byte("after")); err == nil {
		t.Error("the agent signed after the revocation")
	}
}

// Round 3 (D1), finding 5: a daemon mutation whose store commit fails after
// its journal is installed locks the store, with an error that is not
// model.ErrLocked. The agent signs nothing from then on, and the daemon
// empties its keyring.
func TestASelfLockingStoreFailureEmptiesTheKeyring(t *testing.T) {
	ctx := context.Background()
	d, fs, k, ag := startFenced(t)
	fs.mu.Lock()
	fs.failPut = true
	fs.mu.Unlock()
	c, err := Dial(ctx, d.ControlSocket())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	h := model.Host{Name: "db", Addresses: []string{"203.0.113.11"}, Port: 22}
	if err := c.Call(ctx, OpPutHost, PutHostParams{Host: h}, nil); err == nil {
		t.Fatal("the put went through")
	}
	if _, err := ag.Sign(k.pub, []byte("after")); err == nil {
		t.Error("the agent signed after the store locked itself")
	}
	if l, err := ag.List(); err != nil || len(l) != 0 {
		t.Errorf("the agent lists %d keys (%v)", len(l), err)
	}
	if n := keyringSize(t, d); n != 0 {
		t.Errorf("the keyring holds %d keys after the store locked itself", n)
	}
	if st := d.state.Load(); st == nil || !st.locked {
		t.Error("the daemon is not in the locked state")
	}

	// Unlocking again serves the keys again.
	if err := c.Call(ctx, OpUnlock, nil, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := ag.Sign(k.pub, []byte("unlocked again")); err != nil {
		t.Errorf("sign after the unlock: %v", err)
	}
}
