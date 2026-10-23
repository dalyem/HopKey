package cli_test

import (
	"bytes"
	"context"
	"crypto/x509"
	"errors"
	"io"
	"log/slog"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/zalando/go-keyring"

	"github.com/dalyem/hopkey/internal/cli"
	"github.com/dalyem/hopkey/internal/crypto"
	"github.com/dalyem/hopkey/internal/daemon"
	"github.com/dalyem/hopkey/internal/model"
	"github.com/dalyem/hopkey/internal/server"
	"github.com/dalyem/hopkey/internal/store"
	"github.com/dalyem/hopkey/internal/syncclient"
	"github.com/dalyem/hopkey/internal/vaultlog"
)

// hop sync resolve against real parts: two daemons over server-backed
// stores, a real hop-server on SQLite behind httptest TLS, and a guarded
// conflict made the way two devices make one. The setup follows
// internal/daemon's syncWorld, which this package cannot import.

const (
	resolvePassword = "correct horse battery staple"
	resolveEmail    = "me@example.com"
)

type memRing struct {
	mu sync.Mutex
	m  map[string]string
}

func (r *memRing) Get(s, u string) (string, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	v, ok := r.m[s+"/"+u]
	if !ok {
		return "", keyring.ErrNotFound
	}
	return v, nil
}

func (r *memRing) Set(s, u, v string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.m[s+"/"+u] = v
	return nil
}

func (r *memRing) Delete(s, u string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.m, s+"/"+u)
	return nil
}

func shortTemp(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "hkr")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	return dir
}

// resolveWorld is the server and the TLS pool the daemons trust.
type resolveWorld struct {
	st     *server.SQLite
	origin string
	pool   *x509.CertPool
}

func newResolveWorld(t *testing.T) *resolveWorld {
	t.Helper()
	ts := httptest.NewUnstartedServer(nil)
	origin := "https://" + ts.Listener.Addr().String()
	st, err := server.OpenSQLite(filepath.Join(shortTemp(t), "hop.db"))
	if err != nil {
		t.Fatal(err)
	}
	r := server.Rate{N: 100_000, Per: time.Minute}
	rates := server.Rates{PreloginIP: r, PreloginEmail: r, LoginIP: r, LoginAccount: r, IP: r, Account: r, Device: r, EnrollIP: r, Claim: r}
	srv, err := server.New(context.Background(), server.Config{
		Origin: origin, Store: st, Rates: &rates,
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	if err != nil {
		t.Fatal(err)
	}
	ts.Config.Handler = srv.Handler()
	ts.StartTLS()
	// Registered first, so it runs after the daemons have closed.
	t.Cleanup(func() {
		ts.Close()
		srv.Close()
		st.Close()
	})
	pool := x509.NewCertPool()
	pool.AddCert(ts.Certificate())
	return &resolveWorld{st: st, origin: origin, pool: pool}
}

func (w *resolveWorld) client(t *testing.T) *syncclient.Client {
	t.Helper()
	c, err := syncclient.New(w.origin, syncclient.Options{RootCAs: w.pool})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(c.CloseIdleConnections)
	return c
}

func resolveStoreConfig(t *testing.T, name string) store.Config {
	return store.Config{
		DataDir: filepath.Join(shortTemp(t), "data"), Keyring: &memRing{m: map[string]string{}},
		Getenv: func(string) string { return "" }, DeviceName: name,
	}
}

// signInDevice is the password sign-in of a second device over the API.
func signInDevice(t *testing.T, c *syncclient.Client, cfg store.Config, kit store.Kit, pub store.Publication) *store.Store {
	t.Helper()
	ctx := context.Background()
	pre, err := c.Prelogin(ctx, resolveEmail)
	if err != nil {
		t.Fatal(err)
	}
	sk, err := crypto.ParseSecretKey(kit.SecretKey)
	if err != nil {
		t.Fatal(err)
	}
	keys, err := crypto.DeriveLoginKeys([]byte(resolvePassword), pre.Salt, &sk, pre.AccountID, crypto.KDFv1)
	if err != nil {
		t.Fatal(err)
	}
	tr, err := c.Login(ctx, pre.AccountID, keys.AuthKey[:])
	if err != nil {
		t.Fatal(err)
	}
	acct := openAccountKeys(t, tr, keys)
	keys.Zero()
	s, _, err := store.SignIn(ctx, cfg, tr, store.SignInParams{
		ServerURL: pub.Server, Email: resolveEmail, Account: acct, SecretKey: kit.SecretKey, DeviceName: cfg.DeviceName,
	})
	if err != nil {
		t.Fatalf("sign-in: %v", err)
	}
	return s
}

// openAccountKeys opens pw_blob of the latest creds in the log.
func openAccountKeys(t *testing.T, r *syncclient.TokenRemote, keys *crypto.LoginKeys) *crypto.AccountKeys {
	t.Helper()
	ctx := context.Background()
	c0, err := r.EntryAt(ctx, 0)
	if err != nil {
		t.Fatal(err)
	}
	wires := []*vaultlog.Wire{c0.Wire}
	for after := uint64(0); ; {
		entries, head, err := r.Since(ctx, after)
		if err != nil {
			t.Fatal(err)
		}
		for _, e := range entries {
			wires = append(wires, e.Wire)
			after = e.Seq
		}
		if after >= head.Seq || len(entries) == 0 {
			break
		}
	}
	objs := vaultlog.ObjectMap{}
	var pub *vaultlog.PublicState
	for _, w := range wires {
		for _, o := range w.Objects {
			objs[o.SHA256] = o.Body
		}
		if pub, err = vaultlog.ApplyPublic(pub, w, objs); err != nil {
			t.Fatal(err)
		}
	}
	creds, _ := pub.Creds()
	acctState, _ := pub.Account()
	blob, err := r.Object(ctx, creds.PwBlobSHA256)
	if err != nil {
		t.Fatal(err)
	}
	env, err := crypto.ParseAEADEnvelope(blob)
	if err != nil {
		t.Fatal(err)
	}
	ak, err := crypto.OpenPwBlob(&keys.EncKey, env, r.AccountID, acctState.AKV)
	if err != nil {
		t.Fatal(err)
	}
	return ak
}

// device is a daemon over one store, and how to run hop against it.
type device struct {
	name  string
	home  string
	paths daemon.Paths
	c     *daemon.Client
}

func (w *resolveWorld) startDaemon(t *testing.T, name string, st *store.Store) *device {
	t.Helper()
	base := shortTemp(t)
	dv := &device{name: name, home: filepath.Join(base, "home"), paths: daemon.Paths{
		RunDir: filepath.Join(base, "run"), ConfigDir: filepath.Join(base, "home", ".ssh", "hop"), StateDir: filepath.Join(base, "state"),
	}}
	if err := os.MkdirAll(dv.home, 0o700); err != nil {
		t.Fatal(err)
	}
	d, err := daemon.Start(daemon.Options{
		Paths: dv.paths, Store: st, Version: "test", Tailscale: noTailscale{},
		Logf: func(format string, args ...any) { t.Logf(name+": "+format, args...) },
		Sync: daemon.SyncOptions{Client: syncclient.Options{RootCAs: w.pool}},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { d.Close() })
	c, err := daemon.Dial(context.Background(), d.ControlSocket())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	dv.c = c
	return dv
}

func (dv *device) must(t *testing.T, op string, params, result any) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
	defer cancel()
	if err := dv.c.Call(ctx, op, params, result); err != nil {
		t.Fatalf("%s: %s: %v", dv.name, op, err)
	}
}

func (dv *device) host(t *testing.T, name string) *model.Host {
	t.Helper()
	var l daemon.ListResult
	dv.must(t, daemon.OpList, nil, &l)
	for _, h := range l.Hosts {
		if h.Name == name {
			return &h
		}
	}
	return nil
}

func (dv *device) syncStatus(t *testing.T) daemon.SyncStatusResult {
	t.Helper()
	var s daemon.SyncStatusResult
	dv.must(t, daemon.OpSyncStatus, nil, &s)
	return s
}

func (dv *device) hop(t *testing.T, args ...string) (code int, stdout, stderr string) {
	t.Helper()
	var so, se bytes.Buffer
	env := &cli.Env{
		Stdin: strings.NewReader(""), Stdout: &so, Stderr: &se,
		Getenv: func(string) string { return "" },
		Home:   dv.home, Paths: dv.paths,
		StartDaemon: func() error {
			t.Error("the CLI tried to start a daemon, but one is running")
			return errors.New("unexpected daemon start")
		},
		DialTimeout: 5 * time.Second,
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	code = cli.Run(ctx, args, env)
	return code, so.String(), se.String()
}

func waitFor(t *testing.T, within time.Duration, what string, ok func() bool) {
	t.Helper()
	deadline := time.Now().Add(within)
	for !ok() {
		if time.Now().After(deadline) {
			t.Fatalf("not within %v: %s", within, what)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// The desk and the laptop both change a host's address. The laptop made
// its change while its daemon was down, so when it starts, it finds the
// desk's change on the server and holds its own. hop sync resolve lists
// it with a keep-mine token; keep-mine without the token writes nothing;
// with it, the laptop's address reaches the desk.
func TestSyncResolveKeepMineEndToEnd(t *testing.T) {
	ctx := context.Background()
	w := newResolveWorld(t)
	cfg1 := resolveStoreConfig(t, "desk")
	p, err := store.PrepareInit(cfg1, store.InitOptions{Password: []byte(resolvePassword)})
	if err != nil {
		t.Fatal(err)
	}
	s1, err := p.Commit()
	if err != nil {
		t.Fatal(err)
	}
	shared, err := s1.PutHost(ctx, model.Host{Name: "shared", Addresses: []string{"203.0.113.20"}, Port: 22, User: "deploy", Route: "auto", AgentAccess: "allow"})
	if err != nil {
		t.Fatal(err)
	}
	c := w.client(t)
	invite, err := server.CreateInvite(ctx, w.st, resolveEmail, 24*time.Hour, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	pub, err := s1.Publish(ctx, c.Publisher(model.ID{}), store.PublishOptions{Server: w.origin, Email: resolveEmail, RegistrationCode: invite})
	if err != nil {
		t.Fatalf("publish: %v", err)
	}
	s2 := signInDevice(t, c, resolveStoreConfig(t, "laptop"), p.Kit(), pub)

	desk := w.startDaemon(t, "desk", s1)
	theirs := *desk.host(t, "shared")
	theirs.Addresses = []string{"203.0.113.21"}
	desk.must(t, daemon.OpPutHost, daemon.PutHostParams{Host: theirs}, nil)
	waitFor(t, 10*time.Second, "the desk pushes", func() bool { return desk.syncStatus(t).Pending == 0 })

	// The laptop's change, made from the version it had.
	snap, err := s2.Snapshot(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var mine model.Host
	for _, h := range snap.Hosts {
		if h.ItemID == shared.ItemID {
			mine = h
		}
	}
	if mine.ItemID.IsZero() || mine.Addresses[0] != "203.0.113.20" {
		t.Fatalf("the laptop's copy of shared: %+v", mine)
	}
	mine.Addresses = []string{"203.0.113.31"}
	if _, err := s2.PutHost(ctx, mine); err != nil {
		t.Fatal(err)
	}
	laptop := w.startDaemon(t, "laptop", s2)
	waitFor(t, 10*time.Second, "the laptop's change is held", func() bool { return laptop.syncStatus(t).Held == 1 })

	// The listing: the change, both addresses, and the token.
	code, out, errOut := laptop.hop(t, "sync", "resolve", "--json")
	if code != 0 {
		t.Fatalf("list: exit %d: %s", code, errOut)
	}
	var held daemon.SyncHeldResult
	decodeJSON(t, out, &held)
	if len(held.Held) != 1 || held.Held[0].KeepMine == nil || held.Held[0].KeepMine.Confirm == "" {
		t.Fatalf("held: %s", out)
	}
	h := held.Held[0]
	n := strconv.FormatUint(h.N, 10)
	code, out, _ = laptop.hop(t, "sync", "resolve")
	if code != 0 || !strings.Contains(out, "203.0.113.21") || !strings.Contains(out, "203.0.113.31") ||
		!strings.Contains(out, "hop sync resolve "+n+" --keep-mine --confirm "+h.KeepMine.Confirm) {
		t.Errorf("listing: exit %d:\n%s", code, out)
	}

	// Without the token: the proposal, and nothing written.
	code, out, errOut = laptop.hop(t, "sync", "resolve", n, "--keep-mine")
	if code != 255 || !strings.Contains(errOut, "needs --confirm") || !strings.Contains(out, "keep mine writes") {
		t.Errorf("without the token: exit %d, %q %q", code, out, errOut)
	}
	if st := laptop.syncStatus(t); st.Held != 1 {
		t.Fatalf("keep-mine without a token changed something: %+v", st)
	}
	if got := desk.host(t, "shared"); got.Addresses[0] != "203.0.113.21" {
		t.Fatalf("the desk's host changed: %v", got.Addresses)
	}

	// With it.
	code, out, errOut = laptop.hop(t, "sync", "resolve", n, "--keep-mine", "--confirm", h.KeepMine.Confirm)
	if code != 0 || !strings.Contains(out, "change "+n+" resolved: keep-mine") {
		t.Fatalf("keep-mine: exit %d: %s %s", code, out, errOut)
	}
	waitFor(t, 10*time.Second, "keep mine reaches the desk", func() bool {
		got := desk.host(t, "shared")
		return got != nil && got.Addresses[0] == "203.0.113.31"
	})
	waitFor(t, 10*time.Second, "the laptop's outbox drains", func() bool {
		st := laptop.syncStatus(t)
		return st.Pending == 0 && st.Held == 0
	})
	code, out, _ = laptop.hop(t, "sync", "resolve")
	if code != 0 || !strings.Contains(out, "nothing is held") {
		t.Errorf("after: exit %d, %q", code, out)
	}
}
