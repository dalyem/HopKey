package syncclient_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"errors"
	"io"
	"log/slog"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/zalando/go-keyring"

	"github.com/dalyem/hopkey/internal/canonjson"
	"github.com/dalyem/hopkey/internal/crypto"
	"github.com/dalyem/hopkey/internal/model"
	"github.com/dalyem/hopkey/internal/server"
	"github.com/dalyem/hopkey/internal/store"
	"github.com/dalyem/hopkey/internal/syncclient"
	"github.com/dalyem/hopkey/internal/vaultlog"
)

const (
	e2ePassword = "correct horse battery staple"
	e2eEmail    = "Me@Example.COM"
)

// memRing is an in-memory store.Keyring.
type memRing struct {
	mu sync.Mutex
	m  map[string]string
}

func (r *memRing) Get(service, user string) (string, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	v, ok := r.m[service+"/"+user]
	if !ok {
		return "", keyring.ErrNotFound
	}
	return v, nil
}

func (r *memRing) Set(service, user, secret string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.m[service+"/"+user] = secret
	return nil
}

func (r *memRing) Delete(service, user string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.m, service+"/"+user)
	return nil
}

// world is a real hop-server on SQLite behind an httptest TLS server,
// whose certificate the clients trust. The server's clock runs skew
// ahead of the real one.
type world struct {
	st     *server.SQLite
	origin string
	pool   *x509.CertPool
	skew   atomic.Int64 // a time.Duration
}

func newWorld(t *testing.T) *world {
	t.Helper()
	w := &world{}
	ts := httptest.NewUnstartedServer(nil)
	origin := "https://" + ts.Listener.Addr().String()
	st, err := server.OpenSQLite(filepath.Join(t.TempDir(), "hop.db"))
	if err != nil {
		t.Fatal(err)
	}
	// The test makes more requests from one IP than R14 allows a minute.
	r := server.Rate{N: 100_000, Per: time.Minute}
	rates := server.Rates{PreloginIP: r, PreloginEmail: r, LoginIP: r, LoginAccount: r, IP: r, Account: r, Device: r, EnrollIP: r, Claim: r}
	srv, err := server.New(context.Background(), server.Config{
		Origin: origin, Store: st, Rates: &rates,
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
		Now:    func() time.Time { return time.Now().Add(time.Duration(w.skew.Load())) },
	})
	if err != nil {
		t.Fatal(err)
	}
	ts.Config.Handler = srv.Handler()
	ts.StartTLS()
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

func (w *world) client(t *testing.T) *syncclient.Client {
	t.Helper()
	c, err := syncclient.New(w.origin, syncclient.Options{RootCAs: w.pool})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(c.CloseIdleConnections)
	return c
}

func storeConfig(t *testing.T, name string) store.Config {
	t.Helper()
	dir, err := os.MkdirTemp("", "hksync")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	return store.Config{
		DataDir: filepath.Join(dir, "data"), Keyring: &memRing{m: map[string]string{}},
		Getenv: func(string) string { return "" }, DeviceName: name,
	}
}

func snippet(t *testing.T, s *store.Store, name string) {
	t.Helper()
	if _, err := s.PutSnippet(context.Background(), model.Snippet{Name: name, Command: "echo " + name}); err != nil {
		t.Fatal(err)
	}
}

func snippets(t *testing.T, s *store.Store) []string {
	t.Helper()
	snap, err := s.Snapshot(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, sn := range snap.Snippets {
		out = append(out, sn.Name)
	}
	slices.Sort(out)
	return out
}

func wantSnippets(t *testing.T, s *store.Store, who string, want ...string) {
	t.Helper()
	slices.Sort(want)
	if got := snippets(t, s); !slices.Equal(got, want) {
		t.Errorf("%s has snippets %v; want %v", who, got, want)
	}
}

// pushAll pushes the outbox until it is empty.
func pushAll(t *testing.T, s *store.Store, r store.Remote) {
	t.Helper()
	for range 10 {
		res, err := s.PushHead(context.Background(), r)
		if err != nil {
			t.Fatal(err)
		}
		switch res.Outcome {
		case store.PushEmpty:
			return
		case store.PushHeld:
			t.Fatalf("held: %+v", res.Hold)
		}
	}
	t.Fatal("the outbox did not drain")
}

// readLog reads the whole log with a login token.
func readLog(t *testing.T, r *syncclient.TokenRemote) []*vaultlog.Wire {
	t.Helper()
	ctx := context.Background()
	c0, err := r.EntryAt(ctx, 0)
	if err != nil {
		t.Fatal(err)
	}
	wires := []*vaultlog.Wire{c0.Wire}
	after := uint64(0)
	for {
		entries, head, err := r.Since(ctx, after)
		if err != nil {
			t.Fatal(err)
		}
		for _, e := range entries {
			wires = append(wires, e.Wire)
			after = e.Seq
		}
		if after >= head.Seq {
			return wires
		}
		if len(entries) == 0 {
			t.Fatalf("no entries past %d before head %d", after, head.Seq)
		}
	}
}

// openAccount is the password method of §4.4 over the API: the public
// state of the log read with the login token names the latest creds, whose
// pw_blob (fetched from the object endpoint) opens with the encKey.
func openAccount(t *testing.T, r *syncclient.TokenRemote, keys *crypto.LoginKeys) *crypto.AccountKeys {
	t.Helper()
	creds, akv := latestCreds(t, r)
	ak, err := crypto.OpenPwBlob(&keys.EncKey, object(t, r, creds.PwBlobSHA256), r.AccountID, akv)
	if err != nil {
		t.Fatal(err)
	}
	return ak
}

// openRecovery is the recovery method of §4.5 over the API: rk_blob of
// the latest creds opens with the Recovery Key's rkKey.
func openRecovery(t *testing.T, r *syncclient.TokenRemote, rkKey *crypto.SymKey) *crypto.AccountKeys {
	t.Helper()
	creds, akv := latestCreds(t, r)
	ak, err := crypto.OpenRkBlob(rkKey, object(t, r, creds.RkBlobSHA256), r.AccountID, akv)
	if err != nil {
		t.Fatal(err)
	}
	return ak
}

// object fetches an AEAD envelope from the object endpoint.
func object(t *testing.T, r *syncclient.TokenRemote, h crypto.Hash) crypto.AEADEnvelope {
	t.Helper()
	blob, err := r.Object(context.Background(), h)
	if err != nil {
		t.Fatal(err)
	}
	env, err := crypto.ParseAEADEnvelope(blob)
	if err != nil {
		t.Fatal(err)
	}
	return env
}

// latestCreds is the creds op in effect at the head, and the account's
// akv, from the public state of the log read with the token.
func latestCreds(t *testing.T, r *syncclient.TokenRemote) (vaultlog.CredsOp, uint32) {
	t.Helper()
	objs := vaultlog.ObjectMap{}
	var pub *vaultlog.PublicState
	for _, w := range readLog(t, r) {
		for _, o := range w.Objects {
			objs[o.SHA256] = o.Body
		}
		var err error
		if pub, err = vaultlog.ApplyPublic(pub, w, objs); err != nil {
			t.Fatal(err)
		}
	}
	creds, _ := pub.Creds()
	acct, _ := pub.Account()
	return creds, acct.AKV
}

// racing is a Remote whose first Post lets another device commit first,
// so that post meets a real head conflict.
type racing struct {
	*syncclient.Remote
	first     func()
	once      sync.Once
	conflicts atomic.Int32
}

func (r *racing) Post(ctx context.Context, w *vaultlog.Wire) (vaultlog.Head, error) {
	r.once.Do(r.first)
	h, err := r.Remote.Post(ctx, w)
	var hc *store.HeadConflictError
	if errors.As(err, &hc) {
		r.conflicts.Add(1)
	}
	return h, err
}

// localVault is device 1 before the publication: a local vault with a
// snippet.
func localVault(t *testing.T) (*store.Store, store.Kit) {
	t.Helper()
	p, err := store.PrepareInit(storeConfig(t, "desk"), store.InitOptions{Password: []byte(e2ePassword)})
	if err != nil {
		t.Fatal(err)
	}
	s, err := p.Commit()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	snippet(t, s, "deploy")
	return s, p.Kit()
}

// publish publishes s through c with a fresh invite (§4.3).
func publish(t *testing.T, w *world, c *syncclient.Client, s *store.Store) store.Publication {
	t.Helper()
	ctx := context.Background()
	code, err := server.CreateInvite(ctx, w.st, e2eEmail, 24*time.Hour, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	before, err := s.Head()
	if err != nil {
		t.Fatal(err)
	}
	pub, err := s.Publish(ctx, c.Publisher(model.ID{}), store.PublishOptions{Server: w.origin, Email: e2eEmail, RegistrationCode: code})
	if err != nil {
		t.Fatalf("publish: %v", err)
	}
	if !s.ServerBacked() || pub.Upload != before || pub.Email != "Me@example.com" {
		t.Fatalf("after the publication: %+v, server-backed %v", pub, s.ServerBacked())
	}
	return pub
}

// signIn is the password method of §4.4 over the API: prelogin, the §4.1
// keys, login, pw_blob from the latest creds, SignIn.
func signIn(t *testing.T, w *world, c *syncclient.Client, kit store.Kit, pub store.Publication) (*store.Store, *syncclient.TokenRemote) {
	t.Helper()
	ctx := context.Background()
	tr, acct := login(t, c, kit, pub)
	s, res, err := store.SignIn(ctx, storeConfig(t, "laptop"), tr, store.SignInParams{
		ServerURL: w.origin, Email: e2eEmail, Account: acct, SecretKey: kit.SecretKey, DeviceName: "laptop",
	})
	if err != nil {
		t.Fatalf("sign-in: %v", err)
	}
	t.Cleanup(func() { s.Close() })
	if res.CheckpointDue || !s.ServerBacked() {
		t.Errorf("after the sign-in: %+v, server-backed %v", res, s.ServerBacked())
	}
	return s, tr
}

// login is the API part of the password method: prelogin, the §4.1 keys,
// login, and the account keys from pw_blob.
func login(t *testing.T, c *syncclient.Client, kit store.Kit, pub store.Publication) (*syncclient.TokenRemote, *crypto.AccountKeys) {
	t.Helper()
	ctx := context.Background()
	pre, err := c.Prelogin(ctx, " "+e2eEmail)
	if err != nil {
		t.Fatal(err)
	}
	if pre.AccountID != pub.AccountID || pre.KDFVersion != crypto.KDFv1.Version {
		t.Fatalf("prelogin %+v; want account %v", pre, pub.AccountID)
	}
	sk, err := crypto.ParseSecretKey(kit.SecretKey)
	if err != nil {
		t.Fatal(err)
	}
	keys, err := crypto.DeriveLoginKeys([]byte(e2ePassword), pre.Salt, &sk, pre.AccountID, crypto.KDFv1)
	if err != nil {
		t.Fatal(err)
	}
	tr, err := c.Login(ctx, pre.AccountID, keys.AuthKey[:])
	if err != nil {
		t.Fatal(err)
	}
	if tr.VaultID != pub.VaultID {
		t.Fatalf("login vault %v; want %v", tr.VaultID, pub.VaultID)
	}
	acct := openAccount(t, tr, keys)
	keys.Zero()
	return tr, acct
}

// Two devices through the real server: publication, password sign-in,
// sync both ways with a long-poll, a head conflict and its rebase, logout,
// and an enrollment relay exchange.
func TestEndToEnd(t *testing.T) {
	ctx := context.Background()
	w := newWorld(t)

	// Device 1: a local vault with a snippet.
	s1, kit := localVault(t)
	c1 := w.client(t)

	// Before the publication the server has no vault for the device.
	auth1, err := s1.DeviceAuth()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c1.Publisher(model.ID{1}).EntryAt(ctx, auth1, 0); !errors.Is(err, store.ErrPublicationAbsent) {
		t.Fatalf("EntryAt before the publication: %v", err)
	}

	// (a) Signup publishes the local vault.
	pub := publish(t, w, c1, s1)
	// The publication reads: no entry past the head, the upload itself,
	// and nothing of another vault.
	if auth1, err = s1.DeviceAuth(); err != nil {
		t.Fatal(err)
	}
	if _, err := c1.Publisher(pub.VaultID).EntryAt(ctx, auth1, pub.Upload.Seq+100); !errors.Is(err, store.ErrPublicationAbsent) {
		t.Errorf("EntryAt past the head: %v", err)
	}
	if c, err := c1.Publisher(pub.VaultID).EntryAt(ctx, auth1, pub.Upload.Seq); err != nil || c.Seq != pub.Upload.Seq || c.H.String() != pub.Upload.H {
		t.Errorf("EntryAt the upload: %v %v", c.Seq, err)
	}
	if _, err := c1.Publisher(model.ID{7}).EntryAt(ctx, auth1, 0); !errors.Is(err, store.ErrPublicationAbsent) {
		t.Errorf("EntryAt in another vault: %v", err)
	}
	dev1, err := syncclient.StoreDevice(s1.DeviceAuth)
	if err != nil {
		t.Fatal(err)
	}
	r1 := c1.Remote(pub.VaultID, dev1)

	// (b) Device 2 signs in with the password.
	c2 := w.client(t)
	if _, err := c2.Login(ctx, pub.AccountID, make([]byte, 32)); !errors.Is(err, syncclient.ErrUnauthorized) {
		t.Errorf("login with a wrong key: %v", err)
	}
	s2, tr := signIn(t, w, c2, kit, pub)
	wantSnippets(t, s2, "device 2", "deploy")
	dev2, err := syncclient.StoreDevice(s2.DeviceAuth)
	if err != nil {
		t.Fatal(err)
	}
	r2 := c2.Remote(tr.VaultID, dev2)

	// (c) An edit on device 1 reaches device 2, whose pull is waiting in a
	// long-poll when it is pushed.
	if err := s2.Pull(ctx, r2); err != nil {
		t.Fatal(err)
	}
	pulled := make(chan error, 1)
	start := time.Now()
	go func() { pulled <- s2.Pull(ctx, r2.WithWait(30*time.Second)) }()
	time.Sleep(300 * time.Millisecond)
	snippet(t, s1, "from-desk")
	pushAll(t, s1, r1)
	if err := <-pulled; err != nil {
		t.Fatal(err)
	}
	if d := time.Since(start); d > 20*time.Second {
		t.Errorf("the long-poll took %v to see the commit", d)
	}
	wantSnippets(t, s2, "device 2", "deploy", "from-desk")

	// (d) Concurrent edits: device 2's post meets device 1's commit, gets
	// the 409 with the server's head, and rebases.
	snippet(t, s1, "desk-2")
	snippet(t, s2, "laptop-2")
	race := &racing{Remote: r2, first: func() { pushAll(t, s1, r1) }}
	pushAll(t, s2, race)
	if n := race.conflicts.Load(); n != 1 {
		t.Errorf("%d head conflicts; want 1", n)
	}
	if err := s1.Pull(ctx, r1); err != nil {
		t.Fatal(err)
	}
	all := []string{"deploy", "from-desk", "desk-2", "laptop-2"}
	wantSnippets(t, s1, "device 1", all...)
	wantSnippets(t, s2, "device 2", all...)
	h1, _ := s1.Head()
	h2, _ := s2.Head()
	if h1 != h2 {
		t.Errorf("heads differ: %v and %v", h1, h2)
	}

	// (e) Device 2 logs out through the Retirer; its sessions end.
	lres, err := s2.Logout(ctx, c2.Retirer(tr.VaultID), store.LogoutOptions{})
	if err != nil {
		t.Fatalf("logout: %v", err)
	}
	if lres.State != store.StateRetired || lres.Outcome != store.OutcomeCommitted || !lres.Done {
		t.Errorf("logout %+v", lres)
	}
	if _, _, err := r2.Since(ctx, 0); !errors.Is(err, syncclient.ErrSessionEnded) {
		t.Errorf("device 2 after its logout: %v", err)
	}
	if err := s1.Pull(ctx, r1); err != nil {
		t.Fatal(err)
	}
	if _, _, err := r1.Since(ctx, 0); err != nil {
		t.Errorf("device 1 after device 2's logout: %v", err)
	}

	// (f) The enrollment relay: a new device D and device 1 as A.
	relay(t, w, c1, dev1, pub.AccountID)
}

// lossy is a Retirer whose first Post loses its outcome: with lose, the
// entry commits and the response is lost; otherwise the post never
// happens and the session looks ended, so the store uses RetirePost.
type lossy struct {
	*syncclient.Retirer
	lose     bool
	once     sync.Once
	statuses atomic.Int32
	posts    atomic.Int32

	mu   sync.Mutex
	last store.RetireStatus
}

var errLost = errors.New("e2e: the response was lost")

func (r *lossy) Post(ctx context.Context, auth store.DeviceAuth, w *vaultlog.Wire) (h vaultlog.Head, err error) {
	first := false
	r.once.Do(func() { first = true })
	switch {
	case !first:
		return r.Retirer.Post(ctx, auth, w)
	case r.lose:
		if _, err := r.Retirer.Post(ctx, auth, w); err != nil {
			return vaultlog.Head{}, err
		}
		return vaultlog.Head{}, errLost
	}
	return vaultlog.Head{}, syncclient.ErrSessionEnded
}

func (r *lossy) RetireStatus(ctx context.Context, auth store.DeviceAuth, h crypto.Hash) (store.RetireStatus, error) {
	r.statuses.Add(1)
	st, err := r.Retirer.RetireStatus(ctx, auth, h)
	r.mu.Lock()
	r.last = st
	r.mu.Unlock()
	return st, err
}

func (r *lossy) RetirePost(ctx context.Context, auth store.DeviceAuth, w *vaultlog.Wire) (vaultlog.Head, error) {
	r.posts.Add(1)
	return r.Retirer.RetirePost(ctx, auth, w)
}

// A logout whose outcome the session can't tell resolves through the
// retire-status endpoints (§9): a committed retirement whose response was
// lost is found by its receipt, and a retirement posted without a session
// commits through retire-status/post.
func TestLogoutThroughRetireStatus(t *testing.T) {
	for _, lose := range []bool{true, false} {
		name := "post without a session"
		if lose {
			name = "lost response"
		}
		t.Run(name, func(t *testing.T) {
			ctx := context.Background()
			w := newWorld(t)
			s1, kit := localVault(t)
			c1 := w.client(t)
			pub := publish(t, w, c1, s1)
			c2 := w.client(t)
			s2, tr := signIn(t, w, c2, kit, pub)

			dev2 := s2.Info().DeviceID
			r := &lossy{Retirer: c2.Retirer(tr.VaultID), lose: lose}
			res, err := s2.Logout(ctx, r, store.LogoutOptions{})
			if lose {
				// The first attempt can't know; the next one asks.
				if !errors.Is(err, store.ErrLogoutPending) || !errors.Is(err, errLost) {
					t.Fatalf("logout with a lost response: %+v %v", res, err)
				}
				res, err = s2.Logout(ctx, r, store.LogoutOptions{})
			}
			if err != nil {
				t.Fatalf("logout: %v", err)
			}
			if res.State != store.StateRetired || res.Outcome != store.OutcomeCommitted || !res.Done {
				t.Errorf("logout %+v", res)
			}
			if r.statuses.Load() == 0 {
				t.Fatal("retire-status was never asked")
			}
			// The last answer: this device's permanent receipt for its own
			// retirement, which is committed at the receipt's seq.
			r.mu.Lock()
			st := r.last
			r.mu.Unlock()
			if rc := st.Receipt; rc == nil || rc.DeviceID.String() != dev2 || rc.How != "retired" ||
				!st.Committed || st.Seq != rc.Seq || st.Head.Seq < rc.Seq {
				t.Errorf("retire-status %+v, receipt %+v; want device %s retired and committed", st, st.Receipt, dev2)
			}
			if wantPosts := map[bool]int32{true: 0, false: 1}[lose]; r.posts.Load() != wantPosts {
				t.Errorf("%d retire-status posts; want %d", r.posts.Load(), wantPosts)
			}
			// Device 1 sees exactly one retirement, and syncs on.
			dev1, err := syncclient.StoreDevice(s1.DeviceAuth)
			if err != nil {
				t.Fatal(err)
			}
			r1 := c1.Remote(pub.VaultID, dev1)
			if err := s1.Pull(ctx, r1); err != nil {
				t.Fatal(err)
			}
			snippet(t, s1, "after")
			pushAll(t, s1, r1)
		})
	}
}

func random(t *testing.T, n int) []byte {
	t.Helper()
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return b
}

func relay(t *testing.T, w *world, cA *syncclient.Client, devA syncclient.Device, accountID model.ID) {
	t.Helper()
	ctx := context.Background()
	kem, err := crypto.GenerateKEMKey()
	if err != nil {
		t.Fatal(err)
	}
	sigPK, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	open := crypto.EnrollOpen{V: 1, KEMPK: kem.PublicKey().Bytes(), SigPK: sigPK, ND: random(t, crypto.EnrollNonceSize), Name: "phone"}
	commit := crypto.EnrollCommit{V: 1, C: crypto.Commitment(&open)}

	cD := w.client(t)
	mb, err := cD.CreateMailbox(ctx, commit)
	if err != nil {
		t.Fatal(err)
	}
	d := cD.DeviceRelay(mb)

	// A claims it, twice: the same result.
	cl, err := cA.Claim(ctx, devA, mb.RoutingCode)
	if err != nil {
		t.Fatal(err)
	}
	if cl.EnrollID != mb.EnrollID || cl.Commit != commit {
		t.Fatalf("claim %+v; want %v and the commit", cl, mb.EnrollID)
	}
	if again, err := cA.Claim(ctx, devA, mb.RoutingCode); err != nil || again != cl {
		t.Errorf("repeated claim: %+v %v", again, err)
	}
	a := cA.ApproverRelay(cl.EnrollID, devA)

	// D waits for chal in a long-poll while A sends it.
	got := make(chan []syncclient.Message, 1)
	go func() {
		m, err := d.Messages(ctx, 0, 30*time.Second)
		if err != nil {
			t.Error(err)
		}
		got <- m
	}()
	time.Sleep(300 * time.Millisecond)
	chal := crypto.EnrollChal{
		V: 1, EnrollID: cl.EnrollID, NA: random(t, crypto.EnrollNonceSize), AccountID: accountID,
		ApproverDeviceID: devA.DeviceID, AcctSigFp: crypto.SHA256([]byte("fp")), AKV: 1,
	}
	if n, err := a.Post(ctx, syncclient.MsgChal, &chal); err != nil || n != 1 {
		t.Fatalf("chal: %d %v", n, err)
	}
	msgs := <-got
	if len(msgs) != 1 || msgs[0].N != 1 || msgs[0].Type != syncclient.MsgChal {
		t.Fatalf("D got %+v", msgs)
	}
	var gotChal crypto.EnrollChal
	if err := crypto.ParseEnrollMessage(msgs[0].Body, &gotChal); err != nil || gotChal.EnrollID != chal.EnrollID {
		t.Errorf("chal body: %v", err)
	}

	// Roles and order: D can't send chal, A can't replace it.
	if _, err := d.Post(ctx, syncclient.MsgChal, &chal); !errors.Is(err, syncclient.ErrUnauthorized) {
		t.Errorf("chal from D: %v", err)
	}
	other := chal
	other.NA = random(t, crypto.EnrollNonceSize)
	if _, err := a.Post(ctx, syncclient.MsgChal, &other); !errors.Is(err, syncclient.ErrConflict) {
		t.Errorf("a second chal: %v", err)
	}

	// D answers with open, retransmits it, and A reads it.
	for range 2 {
		if n, err := d.Post(ctx, syncclient.MsgOpen, &open); err != nil || n != 2 {
			t.Fatalf("open: %d %v", n, err)
		}
	}
	msgs, err = a.Messages(ctx, 1, 10*time.Second)
	if err != nil || len(msgs) != 1 || msgs[0].N != 2 || msgs[0].Type != syncclient.MsgOpen {
		t.Fatalf("A got %+v %v", msgs, err)
	}

	// A delivers; D reads everything after open.
	env, err := crypto.SealHPKE(open.KEMPK, []byte("e2e"), nil, []byte("delivery"))
	if err != nil {
		t.Fatal(err)
	}
	if n, err := a.Post(ctx, syncclient.MsgDeliver, env); err != nil || n != 3 {
		t.Fatalf("deliver: %d %v", n, err)
	}
	msgs, err = d.Messages(ctx, 2, 0)
	if err != nil || len(msgs) != 1 || msgs[0].Type != syncclient.MsgDeliver {
		t.Fatalf("D got %+v %v", msgs, err)
	}
	var gotEnv crypto.HPKEEnvelope
	if err := canonjson.Unmarshal(msgs[0].Body, &gotEnv); err != nil {
		t.Fatal(err)
	}
	if pt, err := crypto.OpenHPKE(kem, gotEnv, []byte("e2e"), nil); err != nil || string(pt) != "delivery" {
		t.Errorf("delivery: %q %v", pt, err)
	}
	all, err := d.Messages(ctx, 0, 0)
	if err != nil || len(all) != 3 {
		t.Errorf("all messages: %d %v", len(all), err)
	}
	// Another device's session can't claim it.
	if _, err := cD.Claim(ctx, syncclient.Device{AccountID: accountID, DeviceID: model.ID{9}, Signer: devA.Signer}, mb.RoutingCode); err == nil {
		t.Error("a claim by an unknown device succeeded")
	}
}

// lostAck is a Publisher whose first Signup commits and loses its
// response. It keeps the upload and the acknowledgment it lost.
type lostAck struct {
	*syncclient.Publisher
	once sync.Once
	req  *store.SignupRequest // without its proof
	ack  vaultlog.Head
}

func (p *lostAck) Signup(ctx context.Context, req *store.SignupRequest) (vaultlog.Head, error) {
	first := false
	p.once.Do(func() { first = true })
	h, err := p.Publisher.Signup(ctx, req)
	if !first || err != nil {
		return h, err
	}
	p.req = &store.SignupRequest{
		Server: req.Server, Email: req.Email, RegistrationCode: req.RegistrationCode, AccountID: req.AccountID,
		VaultID: req.VaultID, UploadSeq: req.UploadSeq, UploadH: req.UploadH, Wires: req.Wires,
	}
	p.ack = h
	return vaultlog.Head{}, errLost
}

// R3: the identical publication, posted again after its commit, gets the
// original acknowledgment back, after later appends and after the
// capability expired, with no challenge (the server issues none for a
// consumed capability) and no proof. Any other publication is refused.
func TestSignupRetryGetsTheAcknowledgment(t *testing.T) {
	ctx := context.Background()
	w := newWorld(t)
	s1, _ := localVault(t)
	c1 := w.client(t)
	code, err := server.CreateInvite(ctx, w.st, e2eEmail, time.Hour, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	lost := &lostAck{Publisher: c1.Publisher(model.ID{})}
	pub, err := s1.Publish(ctx, lost, store.PublishOptions{Server: w.origin, Email: e2eEmail, RegistrationCode: code})
	if err != nil {
		t.Fatalf("publish with a lost acknowledgment: %v", err)
	}
	if lost.req == nil || lost.ack.Seq != pub.Upload.Seq || lost.ack.H.String() != pub.Upload.H {
		t.Fatalf("the lost acknowledgment %+v; want the upload %+v", lost.ack, pub.Upload)
	}
	if len(lost.req.Wires) < 2 {
		t.Fatalf("the upload has %d entries; the test needs 2", len(lost.req.Wires))
	}
	if _, err := lost.req.Prove(w.origin, make([]byte, crypto.ChallengeSize)); err == nil {
		t.Fatal("the kept request can still prove")
	}

	// The retry goes through a new client, as after a restart.
	retry := func(when string) {
		t.Helper()
		h, err := w.client(t).Publisher(model.ID{}).Signup(ctx, lost.req)
		if err != nil || h != lost.ack {
			t.Errorf("the identical publication %s: %+v %v; want %+v", when, h, err, lost.ack)
		}
	}
	retry("after its commit")

	// Another publication under the consumed capability: a prefix of it.
	other := *lost.req
	other.Wires = other.Wires[:len(other.Wires)-1]
	other.UploadSeq--
	if _, err := w.client(t).Publisher(model.ID{}).Signup(ctx, &other); !errors.Is(err, syncclient.ErrRegistrationConflict) {
		t.Errorf("another publication: %v; want ErrRegistrationConflict", err)
	}
	// And another code is still refused.
	bad := *lost.req
	bad.RegistrationCode = "not-a-registration-code"
	if _, err := w.client(t).Publisher(model.ID{}).Signup(ctx, &bad); !errors.Is(err, syncclient.ErrUnauthorized) {
		t.Errorf("a wrong registration code: %v; want ErrUnauthorized", err)
	}

	dev1, err := syncclient.StoreDevice(s1.DeviceAuth)
	if err != nil {
		t.Fatal(err)
	}
	snippet(t, s1, "later")
	pushAll(t, s1, c1.Remote(pub.VaultID, dev1))
	retry("after a later append")

	w.skew.Store(int64(2 * time.Hour))
	retry("after the capability expired")
}

// R6, §4.5: a recovery token from the Recovery Key opens rk_blob and
// bootstraps a new device, whose recovery leaves the checkpoint due.
func TestRecoverySignIn(t *testing.T) {
	ctx := context.Background()
	w := newWorld(t)
	s1, kit := localVault(t)
	pub := publish(t, w, w.client(t), s1)

	c := w.client(t)
	rk, err := crypto.ParseRecoveryKey(kit.RecoveryKey)
	if err != nil {
		t.Fatal(err)
	}
	rkKey, rAuth, err := crypto.RecoveryKeys(rk[:], pub.AccountID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Recover(ctx, pub.AccountID, random(t, len(rAuth))); !errors.Is(err, syncclient.ErrUnauthorized) {
		t.Errorf("recovery with a wrong r_auth: %v", err)
	}
	tr, err := c.Recover(ctx, pub.AccountID, rAuth)
	if err != nil {
		t.Fatal(err)
	}
	if tr.VaultID != pub.VaultID || tr.AccountID != pub.AccountID {
		t.Fatalf("recovery token for %v/%v; want %v/%v", tr.AccountID, tr.VaultID, pub.AccountID, pub.VaultID)
	}
	acct := openRecovery(t, tr, &rkKey)
	s, res, err := store.SignIn(ctx, storeConfig(t, "spare"), tr, store.SignInParams{
		ServerURL: w.origin, Email: e2eEmail, Account: acct, SecretKey: kit.SecretKey,
		DeviceName: "spare", Method: store.SignInRecovery,
	})
	if err != nil {
		t.Fatalf("recovery sign-in: %v", err)
	}
	t.Cleanup(func() { s.Close() })
	if !res.CheckpointDue || !s.ServerBacked() {
		t.Errorf("after the recovery: %+v, server-backed %v; want the checkpoint due", res, s.ServerBacked())
	}
	if si, err := s.ServerInfo(); err != nil || !si.CheckpointDue || si.Server != w.origin {
		t.Errorf("server info %+v %v; want the checkpoint due", si, err)
	}
	wantSnippets(t, s, "the recovered device", "deploy")
}

// deviceAuthObject is the device-auth object of §4.6 that a device signs
// for a session.
type deviceAuthObject struct {
	V         int      `json:"v"`
	Origin    string   `json:"origin"`
	AccountID model.ID `json:"account_id"`
	DeviceID  model.ID `json:"device_id"`
	Operation string   `json:"operation"`
	Challenge []byte   `json:"challenge"`
}

// localSigner signs device auth with a device key the test holds.
type localSigner struct {
	account model.ID
	dev     *vaultlog.LocalDevice
}

func (s localSigner) Sign(origin, operation string, challenge []byte) ([]byte, error) {
	return crypto.Sign(s.dev.Sig, crypto.LabelDeviceAuth, &deviceAuthObject{
		V: 1, Origin: origin, AccountID: s.account, DeviceID: s.dev.ID, Operation: operation, Challenge: challenge,
	})
}

// replay verifies the log read with a login token from its genesis with
// the account keys, as a reader that is no device.
func replay(t *testing.T, r *syncclient.TokenRemote, acct *crypto.AccountKeys) (*vaultlog.State, *vaultlog.Secrets) {
	t.Helper()
	objs := vaultlog.ObjectMap{}
	var st *vaultlog.State
	var sec *vaultlog.Secrets
	for i, w := range readLog(t, r) {
		for _, o := range w.Objects {
			objs[o.SHA256] = o.Body
		}
		var err error
		if i == 0 {
			st, sec, _, err = vaultlog.Anchor(acct.Pin(), acct, w, objs, nil)
		} else {
			st, sec, err = vaultlog.Transition(st, sec, nil, w, objs)
		}
		if err != nil {
			t.Fatalf("entry %d: %v", i, err)
		}
	}
	return st, sec
}

// newCreds derives a creds op's content for new account keys (§4.2).
func newCreds(t *testing.T, acct *crypto.AccountKeys) vaultlog.CredsInput {
	t.Helper()
	sk, err := crypto.NewSecretKey()
	if err != nil {
		t.Fatal(err)
	}
	rk, err := crypto.NewRecoveryKey()
	if err != nil {
		t.Fatal(err)
	}
	salt := random(t, crypto.SaltSize)
	lk, err := crypto.DeriveLoginKeys([]byte(e2ePassword), salt, &sk, acct.AccountID, crypto.KDFv1)
	if err != nil {
		t.Fatal(err)
	}
	defer lk.Zero()
	pw, err := crypto.SealPwBlob(&lk.EncKey, acct)
	if err != nil {
		t.Fatal(err)
	}
	rkKey, rAuth, err := crypto.RecoveryKeys(rk[:], acct.AccountID)
	if err != nil {
		t.Fatal(err)
	}
	rkBlob, err := crypto.SealRkBlob(&rkKey, acct)
	if err != nil {
		t.Fatal(err)
	}
	return vaultlog.CredsInput{
		KDFVersion: crypto.KDFv1.Version, Salt: salt, AuthSHA256: lk.AuthHash(),
		RAuthSHA256: crypto.SHA256(rAuth), PwBlob: pw, RkBlob: rkBlob,
	}
}

// A checkpoint ends every session (§10.1). A surviving device's cached
// session is refused once, authenticated again without its caller seeing
// it, and its Pull crosses the checkpoint.
//
// The store can't author a checkpoint for a server-backed vault on this
// branch, so a device the test holds does: it joins with a bootstrap
// under a login token, and posts a checkpoint built with vaultlog under
// its own session.
func TestCheckpointReauthenticates(t *testing.T) {
	ctx := context.Background()
	w := newWorld(t)
	s1, kit := localVault(t)
	c1 := w.client(t)
	pub := publish(t, w, c1, s1)
	c2 := w.client(t)
	s2, _ := signIn(t, w, c2, kit, pub)

	auth2, err := syncclient.StoreDevice(s2.DeviceAuth)
	if err != nil {
		t.Fatal(err)
	}
	var signs atomic.Int32
	dev2 := auth2
	dev2.Signer = func() (syncclient.Signer, error) {
		signs.Add(1)
		return auth2.Signer()
	}
	r2 := c2.Remote(pub.VaultID, dev2)
	if err := s2.Pull(ctx, r2); err != nil {
		t.Fatal(err)
	}
	if n := signs.Load(); n != 1 {
		t.Fatalf("%d authentications before the checkpoint; want 1", n)
	}

	// The checkpoint's author.
	cG := w.client(t)
	tr, acct := login(t, cG, kit, pub)
	st, sec := replay(t, tr, acct)
	kem, err := crypto.GenerateKEMKey()
	if err != nil {
		t.Fatal(err)
	}
	sigPK, sigSK, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ghost := &vaultlog.LocalDevice{ID: model.ID(random(t, len(model.ID{}))), KEM: kem, Sig: sigSK}
	now := model.TimestampOf(time.Now())
	bw, st, sec, err := vaultlog.BuildBootstrap(st, sec, vaultlog.DeviceInfo{
		ID: ghost.ID, Name: "ghost", KEMPK: kem.PublicKey().Bytes(), SigPK: sigPK,
	}, now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tr.Post(ctx, bw); err != nil {
		t.Fatalf("the author's bootstrap: %v", err)
	}
	next, err := crypto.GenerateAccountKeys(pub.AccountID, st.Account.AKV+1)
	if err != nil {
		t.Fatal(err)
	}
	vk, err := crypto.NewSymKey()
	if err != nil {
		t.Fatal(err)
	}
	cw, _, _, err := vaultlog.BuildCheckpoint(st, sec, ghost, vaultlog.CheckpointParams{
		NewAccount: next, NewVK: vk, Creds: newCreds(t, next), Time: now,
	})
	if err != nil {
		t.Fatal(err)
	}
	gdev := syncclient.Device{AccountID: pub.AccountID, DeviceID: ghost.ID, Signer: func() (syncclient.Signer, error) {
		return localSigner{pub.AccountID, ghost}, nil
	}}
	head, err := cG.Remote(pub.VaultID, gdev).Post(ctx, cw)
	if err != nil {
		t.Fatalf("the checkpoint: %v", err)
	}
	if head.Seq != cw.Entry.Seq {
		t.Fatalf("the checkpoint committed at %d; want %d", head.Seq, cw.Entry.Seq)
	}

	// Device 2's session ended; its pull authenticates once more and
	// crosses the checkpoint.
	if err := s2.Pull(ctx, r2); err != nil {
		t.Fatalf("pull across the checkpoint: %v", err)
	}
	if n := signs.Load(); n != 2 {
		t.Errorf("%d authentications after the checkpoint; want 2", n)
	}
	if h, err := s2.Head(); err != nil || h.Seq != head.Seq || h.H != head.H.String() {
		t.Errorf("device 2 at %+v %v; want %+v", h, err, head)
	}
	wantSnippets(t, s2, "device 2", "deploy")

	// Both survivors write under the new keys.
	snippet(t, s2, "after")
	pushAll(t, s2, r2)
	dev1, err := syncclient.StoreDevice(s1.DeviceAuth)
	if err != nil {
		t.Fatal(err)
	}
	r1 := c1.Remote(pub.VaultID, dev1)
	if err := s1.Pull(ctx, r1); err != nil {
		t.Fatalf("device 1 across the checkpoint: %v", err)
	}
	wantSnippets(t, s1, "device 1", "deploy", "after")
}
