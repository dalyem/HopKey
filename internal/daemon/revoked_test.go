package daemon

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ssh/agent"

	"github.com/dalyem/hopkey/internal/model"
	"github.com/dalyem/hopkey/internal/model/modeltest"
	"github.com/dalyem/hopkey/internal/store"
)

// revocableStore is a Vault whose device can be revoked, as store.Store is
// when a pull meets a checkpoint that revokes it: from then on every use
// fails with store.ErrDeviceRevoked, and, when signal is set, the Revoked
// channel closes.
type revocableStore struct {
	*modeltest.Store
	signal bool
	ch     chan struct{}

	mu      sync.Mutex
	revoked bool
}

func (r *revocableStore) revoke() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.revoked = true
	if r.signal {
		close(r.ch)
	}
}

func (r *revocableStore) err() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.revoked {
		return fmt.Errorf("%w (in a test)", store.ErrDeviceRevoked)
	}
	return nil
}

func (r *revocableStore) Snapshot(ctx context.Context) (model.Snapshot, error) {
	if err := r.err(); err != nil {
		return model.Snapshot{}, err
	}
	return r.Store.Snapshot(ctx)
}

func (r *revocableStore) Revoked() <-chan struct{} { return r.ch }

func (r *revocableStore) Head() (store.Head, error) {
	if err := r.err(); err != nil {
		return store.Head{}, err
	}
	return store.Head{Seq: 1, H: "unchanged"}, nil
}

func (r *revocableStore) Info() store.Info {
	revoked := r.err() != nil
	return store.Info{Locked: revoked, Revoked: revoked}
}

func (r *revocableStore) Lock()                        {}
func (r *revocableStore) Unlock(context.Context) error { return r.err() }
func (r *revocableStore) UnlockWithPassword(context.Context, []byte, string) error {
	return r.err()
}
func (r *revocableStore) ChangePassword(context.Context, []byte, []byte) (store.Kit, error) {
	return store.Kit{}, errors.New("not in this test")
}
func (r *revocableStore) PendingKit() *store.Kit { return nil }
func (r *revocableStore) AckKit() error          { return nil }

// §5.5: a revoked device's daemon drops what the vault decrypted, as hop
// lock does, and its ssh config is emptied: the agent lists no keys and
// signs nothing. The daemon sees the revocation at once from the store's
// Revoked signal, with no request at all, and otherwise from the first
// store error that says so.
func TestRevocationEmptiesTheAgent(t *testing.T) {
	for _, signal := range []bool{true, false} {
		name := "revoked signal"
		if !signal {
			name = "store error"
		}
		t.Run(name, func(t *testing.T) {
			ctx := context.Background()
			base := shortDir(t)
			k := genKey(t)
			rs := &revocableStore{Store: modeltest.New(), signal: signal, ch: make(chan struct{})}
			key, err := rs.PutKey(ctx, model.Key{Name: "k1", KeyType: "ed25519", PrivateKey: k.pem, PublicKey: k.line()})
			if err != nil {
				t.Fatal(err)
			}
			if _, err := rs.PutHost(ctx, model.Host{Name: "web", Addresses: []string{"203.0.113.10"}, Port: 22, User: "deploy",
				KeyID: key.ItemID, Route: "auto", AgentAccess: "allow"}); err != nil {
				t.Fatal(err)
			}
			paths := Paths{RunDir: filepath.Join(base, "run"), ConfigDir: filepath.Join(base, "cfg")}
			d, err := Start(Options{Paths: paths, Store: rs, Version: "test", Tailscale: fakeTS{}, Logf: t.Logf})
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
			keys := func() int {
				t.Helper()
				l, err := ag.List()
				if err != nil {
					t.Fatal(err)
				}
				return len(l)
			}
			config := func() string {
				t.Helper()
				b, err := os.ReadFile(filepath.Join(paths.ConfigDir, "config"))
				if err != nil {
					t.Fatal(err)
				}
				return string(b)
			}
			if _, err := ag.Sign(k.pub, []byte("before")); err != nil || keys() != 1 || !strings.Contains(config(), "Host web\n") {
				t.Fatalf("setup: sign %v, %d keys\n%s", err, keys(), config())
			}

			rs.revoke()
			if signal {
				for deadline := time.Now().Add(5 * time.Second); keys() != 0 && time.Now().Before(deadline); {
					time.Sleep(10 * time.Millisecond)
				}
			} else {
				c, err := Dial(ctx, d.ControlSocket())
				if err != nil {
					t.Fatal(err)
				}
				defer c.Close()
				if err := c.Call(ctx, OpList, nil, nil); err == nil {
					t.Error("list of a revoked vault worked")
				}
			}
			if n := keys(); n != 0 {
				t.Errorf("the agent lists %d keys after the revocation", n)
			}
			if _, err := ag.Sign(k.pub, []byte("after")); err == nil {
				t.Error("the agent signed after the revocation")
			}
			if cfg := config(); strings.Contains(cfg, "web") || strings.Contains(cfg, "203.0.113.10") {
				t.Errorf("the ssh config still names the vault's host:\n%s", cfg)
			}
			c, err := Dial(ctx, d.ControlSocket())
			if err != nil {
				t.Fatal(err)
			}
			defer c.Close()
			var st StatusResult
			if err := c.Call(ctx, OpStatus, nil, &st); err != nil || st.Vault == nil || !st.Vault.Revoked || st.KeysInAgent != 0 {
				t.Errorf("status: %v %+v", err, st.Vault)
			}
		})
	}
}

// A daemon starts on the vault of a revoked device, so hop status can say
// so, with nothing in the agent.
func TestDaemonStartsOnARevokedVault(t *testing.T) {
	ctx := context.Background()
	base := shortDir(t)
	ring := &memKeyring{m: map[string]string{}}
	cfg := store.Config{DataDir: filepath.Join(base, "data"), Keyring: ring, Getenv: func(string) string { return "" }}
	p, err := store.PrepareInit(cfg, store.InitOptions{Password: []byte("a master password")})
	if err != nil {
		t.Fatal(err)
	}
	s0, err := p.Commit()
	if err != nil {
		t.Fatal(err)
	}
	s0.Close()
	if err := os.WriteFile(filepath.Join(cfg.DataDir, "vault", "revoked.json"), []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	s, err := store.Open(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	paths := Paths{RunDir: filepath.Join(base, "run"), ConfigDir: filepath.Join(base, "cfg")}
	d, err := Start(Options{Paths: paths, Store: s, Tailscale: fakeTS{}, Logf: t.Logf})
	if err != nil {
		s.Close()
		t.Fatalf("start on a revoked vault: %v", err)
	}
	defer d.Close()
	c, err := Dial(ctx, d.ControlSocket())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	var st StatusResult
	if err := c.Call(ctx, OpStatus, nil, &st); err != nil || st.Vault == nil || !st.Vault.Revoked || !st.Vault.Locked {
		t.Errorf("status: %v %+v", err, st.Vault)
	}
	if keys, _ := d.live.List(); len(keys) != 0 {
		t.Errorf("%d keys in the agent", len(keys))
	}
	if err := c.Call(ctx, OpUnlock, nil, nil); err == nil {
		t.Error("the revoked vault unlocked")
	}
}
