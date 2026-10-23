package daemon

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/crypto/ssh/agent"

	"github.com/dalyem/hopkey/internal/crypto"
	"github.com/dalyem/hopkey/internal/merge"
	"github.com/dalyem/hopkey/internal/model"
	"github.com/dalyem/hopkey/internal/resolve"
	"github.com/dalyem/hopkey/internal/server"
	"github.com/dalyem/hopkey/internal/store"
	"github.com/dalyem/hopkey/internal/syncclient"
	"github.com/dalyem/hopkey/internal/vaultlog"
)

const (
	syncPassword = "correct horse battery staple"
	syncEmail    = "Me@Example.COM"
)

// syncWorld is a real hop-server on SQLite behind an httptest TLS server
// whose certificate the daemons trust. While down is set it answers every
// request 503, as a server that is down or overloaded behind a proxy.
// intercept, when set, sees each request first and answers it instead of
// the server if it returns true.
type syncWorld struct {
	st        *server.SQLite
	origin    string
	pool      *x509.CertPool
	down      atomic.Bool
	intercept atomic.Pointer[interceptor]
}

type interceptor func(rw http.ResponseWriter, req *http.Request, next http.Handler) bool

func newSyncWorld(t *testing.T) *syncWorld {
	t.Helper()
	w := &syncWorld{}
	ts := httptest.NewUnstartedServer(nil)
	origin := "https://" + ts.Listener.Addr().String()
	st, err := server.OpenSQLite(filepath.Join(shortDir(t), "hop.db"))
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
	h := srv.Handler()
	ts.Config.Handler = http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		if w.down.Load() {
			http.Error(rw, "down for maintenance", http.StatusServiceUnavailable)
			return
		}
		if f := w.intercept.Load(); f != nil && (*f)(rw, req, h) {
			return
		}
		h.ServeHTTP(rw, req)
	})
	ts.StartTLS()
	// Registered first, so it runs after every daemon has closed and
	// dropped its long-poll.
	t.Cleanup(func() {
		ts.Close()
		srv.Close()
		st.Close()
	})
	pool := x509.NewCertPool()
	pool.AddCert(ts.Certificate())
	w.st, w.origin, w.pool = st, origin, pool
	return w
}

func (w *syncWorld) client(t *testing.T) *syncclient.Client {
	t.Helper()
	c, err := syncclient.New(w.origin, syncclient.Options{RootCAs: w.pool})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(c.CloseIdleConnections)
	return c
}

func syncStoreConfig(t *testing.T, name string) store.Config {
	t.Helper()
	return store.Config{
		DataDir: filepath.Join(shortDir(t), "data"), Keyring: &memKeyring{m: map[string]string{}},
		Getenv: func(string) string { return "" }, DeviceName: name,
	}
}

// node is one device: its store and the daemon that owns it.
type node struct {
	t     *testing.T
	name  string
	cfg   store.Config
	st    *store.Store
	paths Paths
	d     *Daemon
	c     *Client
}

// start runs a daemon for n over ms (n.st, or a wrapper of it).
func (w *syncWorld) start(n *node, ms model.Store, opts SyncOptions) {
	t := n.t
	t.Helper()
	base := shortDir(t)
	n.paths = Paths{RunDir: filepath.Join(base, "run"), ConfigDir: filepath.Join(base, "cfg"), StateDir: filepath.Join(base, "state")}
	opts.Client.RootCAs = w.pool
	name := n.name
	d, err := Start(Options{
		Paths: n.paths, Store: ms, Version: "test", Tailscale: fakeTS{}, Sync: opts,
		Logf: func(format string, args ...any) { t.Logf(name+": "+format, args...) },
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { d.Close() })
	c, err := Dial(context.Background(), d.ControlSocket())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	n.d, n.c = d, c
}

func (n *node) call(op string, params, result any) error {
	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
	defer cancel()
	return n.c.Call(ctx, op, params, result)
}

func (n *node) must(op string, params, result any) {
	n.t.Helper()
	if err := n.call(op, params, result); err != nil {
		n.t.Fatalf("%s: %s: %v", n.name, op, err)
	}
}

func (n *node) list() *ListResult {
	n.t.Helper()
	var l ListResult
	n.must(OpList, nil, &l)
	return &l
}

func (n *node) status() *SyncStatusResult {
	n.t.Helper()
	var s SyncStatusResult
	n.must(OpSyncStatus, nil, &s)
	return &s
}

func (n *node) host(name string) *model.Host {
	n.t.Helper()
	for _, h := range n.list().Hosts {
		if h.Name == name {
			return &h
		}
	}
	return nil
}

func (n *node) putHost(h model.Host) model.Host {
	n.t.Helper()
	var saved model.Host
	n.must(OpPutHost, PutHostParams{Host: h}, &saved)
	return saved
}

func (n *node) config() string {
	n.t.Helper()
	b, err := os.ReadFile(filepath.Join(n.paths.ConfigDir, "config"))
	if errors.Is(err, os.ErrNotExist) {
		return ""
	}
	if err != nil {
		n.t.Fatal(err)
	}
	return string(b)
}

func (n *node) agentKeys() int {
	n.t.Helper()
	conn, err := net.Dial("unix", n.d.AgentSocket())
	if err != nil {
		n.t.Fatal(err)
	}
	defer conn.Close()
	keys, err := agent.NewClient(conn).List()
	if err != nil {
		n.t.Fatal(err)
	}
	return len(keys)
}

// entries counts the log entries on disk: a pull that applies anything
// writes one.
func (n *node) entries() int {
	n.t.Helper()
	des, err := os.ReadDir(filepath.Join(n.cfg.DataDir, "vault", "entries"))
	if err != nil {
		n.t.Fatal(err)
	}
	return len(des)
}

// pause stops n's sync loop from pulling or pushing, ending a long-poll.
func (n *node) pause(on bool) {
	n.d.sync.pause.Store(on)
	n.d.sync.wake()
}

func eventually(t *testing.T, within time.Duration, what string, ok func() bool) {
	t.Helper()
	deadline := time.Now().Add(within)
	for !ok() {
		if time.Now().After(deadline) {
			t.Fatalf("not within %v: %s", within, what)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

func webHost(name string, keyID model.ID, addr string) model.Host {
	return model.Host{Name: name, Addresses: []string{addr}, Port: 22, User: "deploy", KeyID: keyID, Route: "auto", AgentAccess: "allow"}
}

// syncSetup is device 1 ("desk", a published vault with a key) and device
// 2 ("laptop", signed in with the password), neither with a daemon yet.
type syncSetup struct {
	w      *syncWorld
	n1, n2 *node
	keyID  model.ID
	kit    store.Kit
	pub    store.Publication
}

func newSyncSetup(t *testing.T) *syncSetup {
	t.Helper()
	ctx := context.Background()
	w := newSyncWorld(t)
	cfg1 := syncStoreConfig(t, "desk")
	p, err := store.PrepareInit(cfg1, store.InitOptions{Password: []byte(syncPassword)})
	if err != nil {
		t.Fatal(err)
	}
	s1, err := p.Commit()
	if err != nil {
		t.Fatal(err)
	}
	k := genKey(t)
	key, err := s1.PutKey(ctx, model.Key{Name: "k1", KeyType: "ed25519", PrivateKey: k.pem, PublicKey: k.line()})
	if err != nil {
		t.Fatal(err)
	}
	c := w.client(t)
	code, err := server.CreateInvite(ctx, w.st, syncEmail, 24*time.Hour, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	pub, err := s1.Publish(ctx, c.Publisher(model.ID{}), store.PublishOptions{Server: w.origin, Email: syncEmail, RegistrationCode: code})
	if err != nil {
		t.Fatalf("publish: %v", err)
	}
	cfg2 := syncStoreConfig(t, "laptop")
	s2 := signIn(t, c, cfg2, p.Kit(), pub)
	return &syncSetup{
		w: w, keyID: key.ItemID, kit: p.Kit(), pub: pub,
		n1: &node{t: t, name: "desk", cfg: cfg1, st: s1},
		n2: &node{t: t, name: "laptop", cfg: cfg2, st: s2},
	}
}

// signIn is the password method of §4.4 over the API: prelogin, the §4.1
// keys, login, pw_blob from the latest creds, store.SignIn.
func signIn(t *testing.T, c *syncclient.Client, cfg store.Config, kit store.Kit, pub store.Publication) *store.Store {
	t.Helper()
	ctx := context.Background()
	pre, err := c.Prelogin(ctx, syncEmail)
	if err != nil {
		t.Fatal(err)
	}
	sk, err := crypto.ParseSecretKey(kit.SecretKey)
	if err != nil {
		t.Fatal(err)
	}
	keys, err := crypto.DeriveLoginKeys([]byte(syncPassword), pre.Salt, &sk, pre.AccountID, crypto.KDFv1)
	if err != nil {
		t.Fatal(err)
	}
	tr, err := c.Login(ctx, pre.AccountID, keys.AuthKey[:])
	if err != nil {
		t.Fatal(err)
	}
	acct := openAccount(t, tr, keys)
	keys.Zero()
	s, _, err := store.SignIn(ctx, cfg, tr, store.SignInParams{
		ServerURL: pub.Server, Email: syncEmail, Account: acct, SecretKey: kit.SecretKey, DeviceName: cfg.DeviceName,
	})
	if err != nil {
		t.Fatalf("sign-in: %v", err)
	}
	return s
}

// openAccount opens pw_blob of the latest creds, read from the log with
// the login token.
func openAccount(t *testing.T, r *syncclient.TokenRemote, keys *crypto.LoginKeys) *crypto.AccountKeys {
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

// pullCounter counts the pulls and pushes the daemon asks the store for.
type pullCounter struct {
	*store.Store
	calls atomic.Int32
}

func (p *pullCounter) Pull(ctx context.Context, r store.Remote) error {
	p.calls.Add(1)
	return p.Store.Pull(ctx, r)
}

func (p *pullCounter) PushHead(ctx context.Context, r store.Remote) (store.PushResult, error) {
	p.calls.Add(1)
	return p.Store.PushHead(ctx, r)
}

// An edit on one daemon reaches the other with no sync command, and the
// other's ssh config and status follow.
func TestSyncEditReachesTheOtherDaemon(t *testing.T) {
	x := newSyncSetup(t)
	x.w.start(x.n1, x.n1.st, SyncOptions{})
	x.w.start(x.n2, x.n2.st, SyncOptions{})

	x.n1.putHost(webHost("web1", x.keyID, "203.0.113.10"))
	eventually(t, 5*time.Second, "web1 reaches the laptop", func() bool { return x.n2.host("web1") != nil })
	eventually(t, 2*time.Second, "the laptop's ssh config has web1", func() bool { return strings.Contains(x.n2.config(), "Host web1\n") })
	if got := x.n2.agentKeys(); got != 1 {
		t.Errorf("the laptop's agent holds %d keys; want 1", got)
	}

	eventually(t, 5*time.Second, "the desk's outbox drains", func() bool { return x.n1.status().Pending == 0 })
	st := x.n2.status()
	if st.State != SyncOnline || st.SyncedAt == nil || st.Server != x.w.origin || st.Email != "Me@example.com" ||
		st.VaultID != x.pub.VaultID.String() || st.AccountID != x.pub.AccountID.String() || st.Head == nil || st.LastError != "" {
		t.Errorf("laptop sync status %+v", st)
	}
	var full StatusResult
	x.n2.must(OpStatus, nil, &full)
	if full.Sync == nil || full.Sync.State != SyncOnline {
		t.Errorf("status has sync %+v", full.Sync)
	}
	if l := x.n2.list(); l.SyncedAt == nil || len(l.Marks) != 0 {
		t.Errorf("list: synced_at %v, marks %v", l.SyncedAt, l.Marks)
	}

	// And the other way, a delete included.
	h := x.n2.host("web1")
	x.n2.must(OpDelete, DeleteParams{ID: h.ItemID.String()}, nil)
	eventually(t, 5*time.Second, "the delete reaches the desk", func() bool { return x.n1.host("web1") == nil })
	eventually(t, 2*time.Second, "the desk's ssh config drops web1", func() bool { return !strings.Contains(x.n1.config(), "Host web1\n") })

	var devs DevicesResult
	x.n1.must(OpDevicesList, nil, &devs)
	if len(devs.Devices) != 2 {
		t.Errorf("devices %+v", devs.Devices)
	}
}

// Edits made while the server is down queue, show as pending, are in the
// ssh config at once, and go up once it is back.
func TestOfflineEditsQueueAndPushWhenTheServerReturns(t *testing.T) {
	x := newSyncSetup(t)
	fast := SyncOptions{minBackoff: 20 * time.Millisecond, maxBackoff: 200 * time.Millisecond}
	x.w.start(x.n1, x.n1.st, fast)
	x.w.start(x.n2, x.n2.st, fast)

	x.w.down.Store(true)
	saved := x.n1.putHost(webHost("offline1", x.keyID, "203.0.113.11"))
	x.n1.putHost(webHost("offline2", x.keyID, "203.0.113.12"))
	l := x.n1.list()
	if l.Marks[saved.ItemID.String()] != model.MarkPending {
		t.Errorf("marks while offline: %v", l.Marks)
	}
	var res ResolveResult
	x.n1.must(OpResolve, ResolveParams{Target: "offline1"}, &res)
	if res.Host == nil || res.Mark != model.MarkPending {
		t.Errorf("resolve while offline: host %v, mark %q", res.Host, res.Mark)
	}
	eventually(t, 5*time.Second, "the desk backs off", func() bool {
		st := x.n1.status()
		return st.State == SyncBackingOff && st.Backoff != nil && st.LastError != "" && st.Pending == 2
	})
	if err := x.n1.call(OpSyncNow, nil, nil); !IsCode(err, CodeUnreachable) {
		t.Errorf("sync.now while the server is down: %v", err)
	}

	x.w.down.Store(false)
	eventually(t, 5*time.Second, "the queued edits reach the laptop", func() bool {
		return x.n2.host("offline1") != nil && x.n2.host("offline2") != nil
	})
	eventually(t, 5*time.Second, "the desk's marks clear", func() bool {
		st := x.n1.status()
		return len(x.n1.list().Marks) == 0 && st.Pending == 0 && st.State == SyncOnline && st.LastError == ""
	})
}

// A queued write regenerates the ssh config and the keyring at once, from
// the overlay, without waiting for the server.
func TestQueuedWriteRegeneratesTheSSHConfig(t *testing.T) {
	x := newSyncSetup(t)
	x.w.start(x.n1, x.n1.st, SyncOptions{})
	x.w.down.Store(true)
	before := x.n1.config()
	if strings.Contains(before, "Host queued1\n") {
		t.Fatal("the host is in the config before it is added")
	}
	x.n1.putHost(webHost("queued1", x.keyID, "203.0.113.13"))
	if !strings.Contains(x.n1.config(), "Host queued1\n") {
		t.Errorf("the queued host is not in the ssh config:\n%s", x.n1.config())
	}
	if st := x.n1.status(); st.Pending != 1 {
		t.Errorf("pending %d; want 1", st.Pending)
	}
}

func TestBackoffDelays(t *testing.T) {
	for _, r := range []float64{0, 0.5, 0.999999} {
		b := backoff{min: time.Second, max: time.Minute, rand: func() float64 { return r }}
		prev := time.Duration(0)
		for n := 1; n <= 40; n++ {
			d := b.delay(n)
			if d > time.Minute || d < 500*time.Millisecond {
				t.Fatalf("rand %v, attempt %d: %v", r, n, d)
			}
			if r == 0 && d < prev {
				t.Fatalf("attempt %d: %v after %v", n, d, prev)
			}
			prev = d
		}
		if d := b.delay(40); d < 30*time.Second {
			t.Errorf("rand %v: the 40th delay is %v; the cap's jitter is 30-60 s", r, d)
		}
	}
}

// While the server stays down, the loop's retries back off and the wait
// stops growing at a minute.
func TestSyncBackoffCapsAtAMinute(t *testing.T) {
	x := newSyncSetup(t)
	var mu sync.Mutex
	var delays []time.Duration
	fired := make(chan time.Time)
	close(fired)
	opts := SyncOptions{after: func(d time.Duration) <-chan time.Time {
		mu.Lock()
		defer mu.Unlock()
		delays = append(delays, d)
		if len(delays) >= 20 {
			return nil // wait for a wake from here on
		}
		return fired
	}}
	x.w.down.Store(true)
	x.w.start(x.n1, x.n1.st, opts)
	eventually(t, 20*time.Second, "20 retries", func() bool {
		mu.Lock()
		defer mu.Unlock()
		return len(delays) >= 20
	})
	mu.Lock()
	got := slices.Clone(delays)
	mu.Unlock()
	for i, d := range got {
		if d > time.Minute {
			t.Errorf("retry %d waits %v, more than a minute", i+1, d)
		}
	}
	if got[0] > time.Second {
		t.Errorf("the first retry waits %v", got[0])
	}
	for i, d := range got[8:] {
		if d < 30*time.Second {
			t.Errorf("retry %d waits %v; it should be at the cap by now", i+9, d)
		}
	}
	st := x.n1.status()
	if st.State != SyncBackingOff || st.Backoff == nil || st.Backoff.Attempt < 20 || st.Backoff.RetryAt.Sub(time.Now()) > time.Minute {
		t.Errorf("status %+v backoff %+v", st, st.Backoff)
	}
}

// Locking pauses sync: nothing is pulled or applied while locked. Unlocking
// resumes from the last verified head.
func TestLockPausesSyncAndUnlockResumes(t *testing.T) {
	x := newSyncSetup(t)
	x.w.start(x.n1, x.n1.st, SyncOptions{})
	counted := &pullCounter{Store: x.n2.st}
	x.w.start(x.n2, counted, SyncOptions{minBackoff: 10 * time.Millisecond, maxBackoff: 20 * time.Millisecond})

	x.n1.putHost(webHost("before", x.keyID, "203.0.113.14"))
	eventually(t, 5*time.Second, "before reaches the laptop", func() bool { return x.n2.host("before") != nil })

	x.n2.must(OpLock, nil, nil)
	eventually(t, 2*time.Second, "the laptop says locked", func() bool { return x.n2.status().State == SyncLocked })
	calls, entries := counted.calls.Load(), x.n2.entries()

	x.n1.putHost(webHost("while-locked", x.keyID, "203.0.113.15"))
	eventually(t, 5*time.Second, "the desk pushes", func() bool { return x.n1.status().Pending == 0 })
	time.Sleep(time.Second)
	if got := counted.calls.Load(); got > calls+1 {
		t.Errorf("%d pulls or pushes while locked", got-calls)
	}
	if got := x.n2.entries(); got != entries {
		t.Errorf("%d entries applied while locked", got-entries)
	}
	if x.n2.agentKeys() != 0 {
		t.Error("the agent serves keys while locked")
	}
	if st := x.n2.status(); st.State != SyncLocked || st.Head != nil || st.LastError != "" || st.Backoff != nil {
		t.Errorf("status while locked %+v", st)
	}

	x.n2.must(OpUnlock, UnlockParams{}, nil)
	eventually(t, 5*time.Second, "while-locked reaches the laptop after the unlock", func() bool { return x.n2.host("while-locked") != nil })
	if x.n2.agentKeys() != 1 {
		t.Error("the agent is empty after the unlock")
	}
	eventually(t, 2*time.Second, "the laptop is online again", func() bool { return x.n2.status().State == SyncOnline })
}

// A revocation stops sync on the revoked device and empties its agent and
// ssh config.
func TestRevocationStopsSyncAndEmptiesTheAgent(t *testing.T) {
	x := newSyncSetup(t)
	x.w.start(x.n1, x.n1.st, SyncOptions{})
	x.w.start(x.n2, x.n2.st, SyncOptions{})
	x.n1.putHost(webHost("web1", x.keyID, "203.0.113.16"))
	eventually(t, 5*time.Second, "web1 reaches the laptop", func() bool { return strings.Contains(x.n2.config(), "Host web1\n") })
	if x.n2.agentKeys() != 1 {
		t.Fatal("the laptop's agent is empty")
	}

	// The desk revokes the laptop, outside its daemon's loop.
	x.n1.pause(true)
	ctx := context.Background()
	dev1, err := syncclient.StoreDevice(x.n1.st.DeviceAuth)
	if err != nil {
		t.Fatal(err)
	}
	r1 := x.w.client(t).Remote(x.pub.VaultID, dev1)
	laptop := x.n2.st.Info().DeviceID
	if _, err := x.n1.st.RevokeDevices(ctx, r1, []byte(syncPassword), []string{laptop}, store.CheckpointOptions{}); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	x.n1.pause(false)

	eventually(t, 10*time.Second, "the laptop stops", func() bool { return x.n2.status().State == SyncRevoked })
	if x.n2.agentKeys() != 0 {
		t.Error("the revoked laptop's agent still serves keys")
	}
	if strings.Contains(x.n2.config(), "Host ") {
		t.Errorf("the revoked laptop's ssh config still has hosts:\n%s", x.n2.config())
	}
	if err := x.n2.call(OpSyncNow, nil, nil); !IsCode(err, CodeRevoked) {
		t.Errorf("sync.now on a revoked device: %v", err)
	}

	// The desk carries on.
	x.n1.putHost(webHost("web2", x.keyID, "203.0.113.17"))
	eventually(t, 5*time.Second, "the desk pushes", func() bool { return x.n1.status().Pending == 0 })
}

// A target that matches nothing gets one bounded catch-up pull before the
// answer, which finds a host another device added a moment ago.
func TestCatchUpPullFindsAJustAddedHost(t *testing.T) {
	x := newSyncSetup(t)
	x.w.start(x.n1, x.n1.st, SyncOptions{})
	// The laptop pulls only when asked, so only the catch-up can find it.
	x.w.start(x.n2, x.n2.st, SyncOptions{noPoll: true, catchUpAge: time.Nanosecond})

	x.n1.putHost(webHost("fresh", x.keyID, "203.0.113.18"))
	eventually(t, 5*time.Second, "the desk pushes", func() bool { return x.n1.status().Pending == 0 })
	if x.n2.host("fresh") != nil {
		t.Fatal("the laptop pulled without being asked")
	}
	var res ResolveResult
	x.n2.must(OpResolve, ResolveParams{Target: "fresh"}, &res)
	if res.Result.Status != resolve.StatusMatched || res.Host == nil || res.Host.Name != "fresh" || !res.CaughtUp {
		t.Fatalf("resolve after the catch-up: %+v (caught up %v)", res.Result, res.CaughtUp)
	}
	if res.SSHAlias != "fresh" {
		t.Errorf("ssh alias %q", res.SSHAlias)
	}
	if !strings.Contains(x.n2.config(), "Host fresh\n") {
		t.Error("the catch-up did not regenerate the ssh config")
	}

	// A miss that a pull can't fix still answers no match.
	x.n2.must(OpResolve, ResolveParams{Target: "nowhere"}, &res)
	if res.Result.Status != resolve.StatusNoMatch {
		t.Errorf("resolve nowhere: %+v", res.Result)
	}
}

// conflict makes the laptop's edit of h's address conflict with the desk's:
// the laptop is paused while the desk commits first, then queues its own
// edit and pushes it, and the push holds it.
func (x *syncSetup) conflict(t *testing.T, h model.Host, deskAddr, laptopAddr string) {
	t.Helper()
	x.n2.pause(true)
	time.Sleep(100 * time.Millisecond)
	mine := *x.n2.host(h.Name)
	theirs := *x.n1.host(h.Name)
	theirs.Addresses = []string{deskAddr}
	x.n1.putHost(theirs)
	eventually(t, 5*time.Second, "the desk pushes", func() bool { return x.n1.status().Pending == 0 })
	if got := x.n2.host(h.Name); got.Addresses[0] == deskAddr {
		t.Fatal("the paused laptop pulled")
	}
	mine.Addresses = []string{laptopAddr}
	x.n2.putHost(mine)
	x.n2.pause(false)
	eventually(t, 5*time.Second, "the laptop's change is held", func() bool { return x.n2.status().Held == 1 })
}

// A guarded conflict is held, shows in sync.held with its proposal, and
// resolves through sync.resolve: take-theirs regenerates the ssh config
// from verified state, keep-mine needs the proposal's digest and then goes
// up.
func TestHeldConflictResolvesThroughSyncResolve(t *testing.T) {
	x := newSyncSetup(t)
	x.w.start(x.n1, x.n1.st, SyncOptions{})
	x.w.start(x.n2, x.n2.st, SyncOptions{})
	h := x.n1.putHost(webHost("shared", x.keyID, "203.0.113.20"))
	eventually(t, 5*time.Second, "shared reaches the laptop", func() bool { return x.n2.host("shared") != nil })

	// Round 1: take theirs.
	x.conflict(t, h, "203.0.113.21", "203.0.113.31")
	if l := x.n2.list(); l.Marks[h.ItemID.String()] != model.MarkHeld {
		t.Errorf("marks %v", l.Marks)
	}
	if !strings.Contains(x.n2.config(), "HostName 203.0.113.31\n") {
		t.Errorf("the held change is not what the laptop's config shows:\n%s", x.n2.config())
	}
	st := x.n2.status()
	if st.State != SyncOnline || !slices.ContainsFunc(st.Warnings, func(w string) bool { return strings.Contains(w, "held") }) {
		t.Errorf("status with a held change: %+v", st)
	}
	var held SyncHeldResult
	x.n2.must(OpSyncHeld, nil, &held)
	if len(held.Held) != 1 {
		t.Fatalf("held %+v", held)
	}
	hc := held.Held[0]
	if hc.ItemID != h.ItemID.String() || hc.Type != model.TypeHost || hc.Hold == nil || hc.Hold.Cause != merge.CauseGuardedConflict ||
		hc.KeepMine == nil || hc.KeepMine.Confirm == "" || !slices.Contains(hc.Choices, ChoiceKeepMine) || !slices.Contains(hc.Choices, ChoiceEdit) ||
		!strings.Contains(string(hc.Current), "203.0.113.21") || !strings.Contains(string(hc.Want), "203.0.113.31") {
		t.Fatalf("held change %+v keep mine %+v", hc, hc.KeepMine)
	}
	var res SyncResolveResult
	if err := x.n2.call(OpSyncResolve, SyncResolveParams{N: hc.N + 1, Choice: ChoiceTakeTheirs}, &res); !IsCode(err, CodeNotHeld) {
		t.Errorf("resolving another record: %v", err)
	}
	x.n2.must(OpSyncResolve, SyncResolveParams{N: hc.N, Choice: ChoiceTakeTheirs}, &res)
	if res.Status == nil || res.Status.Held != 0 || res.Status.Pending != 0 {
		t.Errorf("after take theirs: %+v", res.Status)
	}
	// Nothing new came from the server, yet the config follows the overlay.
	if cfg := x.n2.config(); !strings.Contains(cfg, "HostName 203.0.113.21\n") || strings.Contains(cfg, "203.0.113.31") {
		t.Errorf("the laptop's config after take theirs:\n%s", cfg)
	}
	if l := x.n2.list(); len(l.Marks) != 0 {
		t.Errorf("marks after take theirs: %v", l.Marks)
	}

	// Round 2: keep mine, which needs the digest.
	x.conflict(t, h, "203.0.113.22", "203.0.113.32")
	x.n2.must(OpSyncHeld, nil, &held)
	hc = held.Held[0]
	if err := x.n2.call(OpSyncResolve, SyncResolveParams{N: hc.N, Choice: ChoiceKeepMine}, nil); !IsCode(err, CodeConfirm) {
		t.Errorf("keep mine without a digest: %v", err)
	}
	if err := x.n2.call(OpSyncResolve, SyncResolveParams{N: hc.N, Choice: ChoiceKeepMine, Confirm: strings.Repeat("00", 32)}, nil); !IsCode(err, CodeStaleConfirm) {
		t.Errorf("keep mine with a wrong digest: %v", err)
	}
	if err := x.n2.call(OpSyncResolve, map[string]any{"n": hc.N, "choice": ChoiceKeepMine, "surprise": true}, nil); !IsCode(err, CodeInvalid) {
		t.Errorf("an unknown member: %v", err)
	}
	var prop SyncResolveResult
	x.n2.must(OpSyncResolve, SyncResolveParams{N: hc.N, Choice: ChoiceKeepMine, Propose: true}, &prop)
	if prop.Proposal == nil || prop.Proposal.Confirm != hc.KeepMine.Confirm {
		t.Fatalf("proposal %+v; sync.held had %+v", prop.Proposal, hc.KeepMine)
	}
	x.n2.must(OpSyncResolve, SyncResolveParams{N: hc.N, Choice: ChoiceKeepMine, Confirm: hc.KeepMine.Confirm, NewID: hc.KeepMine.NewID}, &res)
	eventually(t, 5*time.Second, "keep mine reaches the desk", func() bool {
		got := x.n1.host("shared")
		return got != nil && got.Addresses[0] == "203.0.113.32"
	})
	eventually(t, 5*time.Second, "the laptop's outbox drains", func() bool {
		st := x.n2.status()
		return st.Pending == 0 && st.Held == 0
	})
	x.n2.must(OpSyncHeld, nil, &held)
	if len(held.Held) != 0 {
		t.Errorf("still held: %+v", held.Held)
	}

	// Round 3: edit, proposed and then confirmed.
	x.conflict(t, h, "203.0.113.23", "203.0.113.33")
	x.n2.must(OpSyncHeld, nil, &held)
	hc = held.Held[0]
	var edited model.Host
	if err := json.Unmarshal(hc.Want, &edited); err != nil {
		t.Fatal(err)
	}
	edited.Addresses = []string{"203.0.113.43"}
	raw, err := json.Marshal(edited)
	if err != nil {
		t.Fatal(err)
	}
	if err := x.n2.call(OpSyncResolve, SyncResolveParams{N: hc.N, Choice: ChoiceEdit, Edited: raw}, nil); !IsCode(err, CodeConfirm) {
		t.Errorf("edit without a digest: %v", err)
	}
	x.n2.must(OpSyncResolve, SyncResolveParams{N: hc.N, Choice: ChoiceEdit, Edited: raw, Propose: true}, &prop)
	if prop.Proposal == nil || !strings.Contains(string(prop.Proposal.Want), "203.0.113.43") {
		t.Fatalf("edit proposal %+v", prop.Proposal)
	}
	x.n2.must(OpSyncResolve, SyncResolveParams{N: hc.N, Choice: ChoiceEdit, Edited: raw, Confirm: prop.Proposal.Confirm, NewID: prop.Proposal.NewID}, &res)
	eventually(t, 5*time.Second, "the edit reaches the desk", func() bool {
		got := x.n1.host("shared")
		return got != nil && got.Addresses[0] == "203.0.113.43"
	})
}

// A daemon started on a vault whose logout is pending finishes it.
func TestStartupResumesAPendingLogout(t *testing.T) {
	x := newSyncSetup(t)
	ctx := context.Background()
	x.w.start(x.n1, x.n1.st, SyncOptions{})

	// The laptop starts a logout while the server is down: it stays
	// RETIRING, and the vault is locked for good.
	x.w.down.Store(true)
	_, err := x.n2.st.Logout(ctx, x.w.client(t).Retirer(x.pub.VaultID), store.LogoutOptions{})
	if !errors.Is(err, store.ErrLogoutPending) {
		t.Fatalf("logout while the server is down: %v", err)
	}
	if state, err := x.n2.st.Retirement(); err != nil || state != store.StateRetiring {
		t.Fatalf("retirement %q %v", state, err)
	}
	x.n2.st.Close()
	x.w.down.Store(false)

	s2, err := store.Open(ctx, x.n2.cfg)
	if err != nil {
		t.Fatal(err)
	}
	x.n2.st = s2
	x.w.start(x.n2, s2, SyncOptions{minBackoff: 20 * time.Millisecond, maxBackoff: 200 * time.Millisecond})
	eventually(t, 10*time.Second, "the logout finishes", func() bool { return x.n2.status().State == SyncLoggedOut })
	if exists, err := store.Exists(x.n2.cfg.DataDir); err != nil || exists {
		t.Errorf("the vault is still on the laptop: %v %v", exists, err)
	}
	if x.n2.agentKeys() != 0 || strings.Contains(x.n2.config(), "Host ") {
		t.Error("the logged-out laptop still serves keys or hosts")
	}
	eventually(t, 5*time.Second, "the desk sees one device", func() bool {
		var devs DevicesResult
		x.n1.must(OpDevicesList, nil, &devs)
		return len(devs.Devices) == 1 && devs.Devices[0].This
	})
}

// The sync ops refuse params they do not take, and a store that can't
// sync refuses them all.
func TestSyncOpsSchemas(t *testing.T) {
	f := newFixture(t, nil)
	c := f.client()
	ctx := context.Background()
	for _, op := range []string{OpSyncStatus, OpSyncNow, OpSyncHeld, OpSyncResolve, OpDevicesList} {
		if err := c.Call(ctx, op, nil, nil); !IsCode(err, CodeLocalOnly) {
			t.Errorf("%s on a store that does not sync: %v", op, err)
		}
	}

	x := newSyncSetup(t)
	x.w.start(x.n1, x.n1.st, SyncOptions{})
	if err := x.n1.call(OpSyncStatus, map[string]any{"x": 1}, nil); !IsCode(err, CodeInvalid) {
		t.Errorf("sync.status with params: %v", err)
	}
	if err := x.n1.call(OpSyncResolve, SyncResolveParams{Choice: "keep mine"}, nil); !IsCode(err, CodeInvalid) {
		t.Errorf("an unknown choice: %v", err)
	}
	if err := x.n1.call(OpSyncResolve, SyncResolveParams{Choice: ChoiceRetry}, nil); !IsCode(err, CodeNotHeld) {
		t.Errorf("resolve with nothing held: %v", err)
	}
	var held SyncHeldResult
	x.n1.must(OpSyncHeld, nil, &held)
	if held.Held == nil || len(held.Held) != 0 {
		t.Errorf("held %+v", held)
	}
	var now SyncStatusResult
	x.n1.must(OpSyncNow, nil, &now)
	if now.State != SyncOnline || now.SyncedAt == nil {
		t.Errorf("sync.now %+v", now)
	}
}

// A push that holds a change moves no head: the outbox alone changed, and
// the daemon still rebuilds, so the item shows held, not pending.
func TestHoldWithoutANewHeadUpdatesTheMarks(t *testing.T) {
	x := newSyncSetup(t)
	x.w.start(x.n1, x.n1.st, SyncOptions{})
	x.w.start(x.n2, x.n2.st, SyncOptions{noPoll: true, catchUpAge: time.Nanosecond})
	h := x.n1.putHost(webHost("shared", x.keyID, "203.0.113.40"))
	eventually(t, 5*time.Second, "the desk pushes", func() bool { return x.n1.status().Pending == 0 })
	var res ResolveResult
	x.n2.must(OpResolve, ResolveParams{Target: "shared"}, &res) // caught up
	if res.Host == nil {
		t.Fatal("the laptop did not catch up")
	}

	x.n2.pause(true)
	theirs := *x.n1.host("shared")
	theirs.Addresses = []string{"203.0.113.41"}
	x.n1.putHost(theirs)
	eventually(t, 5*time.Second, "the desk pushes", func() bool { return x.n1.status().Pending == 0 })
	mine := *x.n2.host("shared")
	mine.Addresses = []string{"203.0.113.51"}
	x.n2.putHost(mine)
	// The desk's edit arrives by a catch-up while the laptop's waits.
	x.n2.must(OpResolve, ResolveParams{Target: "nowhere"}, &res)
	if !res.CaughtUp {
		t.Fatal("no catch-up")
	}
	before := x.n2.status().Head
	if l := x.n2.list(); l.Marks[h.ItemID.String()] != model.MarkPending {
		t.Fatalf("marks before the push: %v", l.Marks)
	}

	x.n2.pause(false)
	eventually(t, 5*time.Second, "the laptop's change is held", func() bool { return x.n2.status().Held == 1 })
	if after := x.n2.status().Head; *after != *before {
		t.Fatalf("the head moved from %v to %v", before, after)
	}
	if l := x.n2.list(); l.Marks[h.ItemID.String()] != model.MarkHeld {
		t.Errorf("marks after the hold: %v", l.Marks)
	}
}
