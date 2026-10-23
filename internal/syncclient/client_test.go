package syncclient

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/dalyem/hopkey/internal/canonjson"
	"github.com/dalyem/hopkey/internal/crypto"
	"github.com/dalyem/hopkey/internal/model"
	"github.com/dalyem/hopkey/internal/store"
	"github.com/dalyem/hopkey/internal/vaultlog"
)

// tlsServer is an httptest TLS server and a client that trusts its
// certificate (issued for 127.0.0.1, ::1 and example.com).
func tlsServer(t *testing.T, h http.Handler, opts Options) (*Client, *httptest.Server) {
	t.Helper()
	ts := httptest.NewTLSServer(h)
	t.Cleanup(ts.Close)
	return trusting(t, ts, ts.URL, opts), ts
}

func trusting(t *testing.T, ts *httptest.Server, serverURL string, opts Options) *Client {
	t.Helper()
	pool := x509.NewCertPool()
	pool.AddCert(ts.Certificate())
	opts.RootCAs = pool
	c, err := New(serverURL, opts)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func writeCanon(w http.ResponseWriter, status int, v any) {
	b, err := canonjson.Marshal(v)
	if err != nil {
		panic(err)
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	w.Write(b)
}

func healthy(w http.ResponseWriter, _ *http.Request) {
	writeCanon(w, http.StatusOK, healthResponse{OK: true, Version: "test"})
}

var bg = context.Background()

// R10: https only, with certificate and hostname verification.
func TestTLSRequired(t *testing.T) {
	for _, u := range []string{"http://hop.example.com", "http://127.0.0.1:8443", "http://localhost", "ftp://hop.example.com", "hop.example.com"} {
		if _, err := New(u, Options{}); err == nil {
			t.Errorf("New(%q) accepted a server without TLS", u)
		} else if strings.HasPrefix(u, "http://") && !errors.Is(err, ErrInsecureURL) {
			t.Errorf("New(%q): %v; want ErrInsecureURL", u, err)
		}
	}
	for _, u := range []string{"https://hop.example.com/v1", "https://user@hop.example.com", "https://hop.example.com?x=1"} {
		if _, err := New(u, Options{}); err == nil {
			t.Errorf("New(%q) accepted a URL that is not an origin", u)
		}
	}
	c, err := New("HTTPS://Hop.Example.COM:443/", Options{})
	if err != nil || c.Origin() != "https://hop.example.com" {
		t.Fatalf("origin %q, %v", c.Origin(), err)
	}

	ts := httptest.NewTLSServer(http.HandlerFunc(healthy))
	defer ts.Close()
	// An untrusted certificate fails, and dev mode changes nothing for
	// https.
	for _, opts := range []Options{{}, {DevInsecure: true}} {
		c, err := New(ts.URL, opts)
		if err != nil {
			t.Fatal(err)
		}
		_, err = c.Health(bg)
		if !errors.Is(err, ErrTLS) || Retryable(err) {
			t.Errorf("untrusted certificate (%+v): %v", opts, err)
		}
	}
	// A trusted certificate for another name fails: the test certificate
	// has no "localhost".
	_, port, _ := net.SplitHostPort(ts.Listener.Addr().String())
	_, err = trusting(t, ts, "https://localhost:"+port, Options{}).Health(bg)
	if !errors.Is(err, ErrTLS) {
		t.Errorf("hostname mismatch: %v", err)
	}
	if v, err := trusting(t, ts, ts.URL, Options{}).Health(bg); err != nil || v != "test" {
		t.Errorf("trusted: %q, %v", v, err)
	}
}

// R10: HOP_DEV_INSECURE=1 allows http:// for loopback servers only.
func TestDevInsecureLoopbackOnly(t *testing.T) {
	if !DevInsecureFromEnv(func(k string) string { return map[string]string{DevInsecureEnv: "1"}[k] }) {
		t.Error("HOP_DEV_INSECURE=1 not seen")
	}
	for _, v := range []string{"", "0", "true", "yes", " 1"} {
		if DevInsecureFromEnv(func(string) string { return v }) {
			t.Errorf("HOP_DEV_INSECURE=%q taken as the opt-in", v)
		}
	}
	for _, u := range []string{"http://hop.example.com", "http://10.0.0.1:8080", "http://192.168.1.2", "http://[fe80::1]", "http://0.0.0.0:80", "http://127.0.0.1.example.com"} {
		if _, err := New(u, Options{DevInsecure: true}); !errors.Is(err, ErrInsecureURL) {
			t.Errorf("dev mode accepted %q: %v", u, err)
		}
	}
	ts := httptest.NewServer(http.HandlerFunc(healthy))
	defer ts.Close()
	_, port, _ := net.SplitHostPort(ts.Listener.Addr().String())
	for _, u := range []string{ts.URL, "http://localhost:" + port} {
		c, err := New(u, Options{DevInsecure: true})
		if err != nil {
			t.Fatalf("%s: %v", u, err)
		}
		if _, err := c.Health(bg); err != nil {
			t.Errorf("%s: %v", u, err)
		}
	}
	// Whatever a name resolves to, a plaintext connection goes to a
	// loopback address or nowhere.
	for addr, ok := range map[string]bool{
		"127.0.0.1:80": true, "127.8.9.10:1": true, "[::1]:443": true,
		"192.0.2.1:80": false, "[2001:db8::1]:80": false, "10.0.0.1:80": false, "0.0.0.0:80": false,
	} {
		if err := loopbackOnly("tcp", addr, nil); (err == nil) != ok {
			t.Errorf("loopbackOnly(%s) = %v", addr, err)
		}
	}
}

// R10: a redirect never carries credentials, and never leaves the origin
// (which also keeps the scheme).
func TestRedirects(t *testing.T) {
	var other atomic.Int32
	foreign := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		other.Add(1)
		healthy(w, r)
	}))
	defer foreign.Close()

	var mu sync.Mutex
	seen := map[string]string{} // path → Authorization
	mux := http.NewServeMux()
	record := func(r *http.Request) {
		mu.Lock()
		seen[r.URL.Path] = r.Header.Get("Authorization")
		mu.Unlock()
	}
	mux.HandleFunc("/v1/same", func(w http.ResponseWriter, r *http.Request) {
		record(r)
		http.Redirect(w, r, "/v1/target", http.StatusTemporaryRedirect)
	})
	mux.HandleFunc("/v1/target", func(w http.ResponseWriter, r *http.Request) {
		record(r)
		healthy(w, r)
	})
	mux.HandleFunc("/v1/away", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, foreign.URL+"/v1/healthz", http.StatusFound)
	})
	mux.HandleFunc("/v1/downgrade", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "http://"+r.Host+"/v1/target", http.StatusFound)
	})
	mux.HandleFunc("/v1/loop", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/v1/loop", http.StatusFound)
	})
	// /v1/chain/n redirects n times before it answers.
	mux.HandleFunc("/v1/chain/{n}", func(w http.ResponseWriter, r *http.Request) {
		n, _ := strconv.Atoi(r.PathValue("n"))
		if n == 0 {
			healthy(w, r)
			return
		}
		http.Redirect(w, r, "/v1/chain/"+strconv.Itoa(n-1), http.StatusFound)
	})
	c, _ := tlsServer(t, mux, Options{})

	// At most maxRedirects are followed.
	for n := 0; n <= maxRedirects+1; n++ {
		var h healthResponse
		err := c.do(bg, &call{method: "GET", path: "/v1/chain/" + strconv.Itoa(n)}, &h)
		if n <= maxRedirects && (err != nil || !h.OK) {
			t.Errorf("%d redirects: %v", n, err)
		}
		if n > maxRedirects && !errors.Is(err, ErrRedirect) {
			t.Errorf("%d redirects: %v; want ErrRedirect", n, err)
		}
	}

	var h healthResponse
	if err := c.do(bg, &call{method: "POST", path: "/v1/same", token: "secret-token", body: struct{}{}}, &h); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	defer mu.Unlock()
	if seen["/v1/same"] != "Bearer secret-token" {
		t.Errorf("the request itself had Authorization %q", seen["/v1/same"])
	}
	if a, ok := seen["/v1/target"]; !ok || a != "" {
		t.Errorf("the redirected request had Authorization %q (reached: %v)", a, ok)
	}
	for _, p := range []string{"/v1/away", "/v1/downgrade", "/v1/loop"} {
		err := c.do(bg, &call{method: "GET", path: p, token: "secret-token"}, &h)
		if !errors.Is(err, ErrRedirect) || Retryable(err) {
			t.Errorf("%s: %v; want ErrRedirect", p, err)
		}
	}
	if n := other.Load(); n != 0 {
		t.Errorf("the other origin got %d requests", n)
	}
}

// fakeSigner records what it is asked to sign.
type fakeSigner struct {
	mu    sync.Mutex
	calls []string // origin|operation|len(challenge)
	err   error
}

func (s *fakeSigner) Sign(origin, operation string, challenge []byte) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.err != nil {
		return nil, s.err
	}
	s.calls = append(s.calls, fmt.Sprintf("%s|%s|%d", origin, operation, len(challenge)))
	return []byte("signature"), nil
}

func (s *fakeSigner) n() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.calls)
}

// fakeAuth is the session part of the server, and a log that needs a
// session.
type fakeAuth struct {
	mu         sync.Mutex
	challenges int
	sessions   int
	logs       int
	tokens     map[string]bool
	inactive   bool // session challenges get 401
	refuse     int  // this many session requests get 401
	logRefuse  bool // every log request gets 401
	ttl        time.Duration
	vault      model.ID // the vault the sessions are bound to
	noVault    bool     // session responses have no vault_id, as an older server's
}

func newFakeAuth() *fakeAuth {
	return &fakeAuth{tokens: map[string]bool{}, ttl: 15 * time.Minute, vault: model.ID{3}}
}

func (f *fakeAuth) unauthorized(w http.ResponseWriter) {
	writeCanon(w, http.StatusUnauthorized, errorResponse{errorBody{"unauthorized", "authentication failed"}})
}

func (f *fakeAuth) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	switch {
	case r.URL.Path == "/v1/auth/challenge":
		f.challenges++
		if f.inactive {
			f.unauthorized(w)
			return
		}
		ch := make([]byte, crypto.ChallengeSize)
		ch[0] = byte(f.challenges)
		writeCanon(w, http.StatusOK, challengeResponse{ch})
	case r.URL.Path == "/v1/auth/session":
		f.sessions++
		if f.refuse > 0 {
			f.refuse--
			f.unauthorized(w)
			return
		}
		tok := "tok-" + strconv.Itoa(f.sessions)
		f.tokens[tok] = true
		exp := model.TimestampOf(time.Now().Add(f.ttl))
		if f.noVault {
			writeCanon(w, http.StatusOK, struct {
				AccessToken string          `json:"access_token"`
				ExpiresAt   model.Timestamp `json:"expires_at"`
			}{tok, exp})
			return
		}
		writeCanon(w, http.StatusOK, sessionResponse{tok, exp, f.vault})
	case strings.HasSuffix(r.URL.Path, "/log"):
		f.logs++
		tok, _ := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
		if f.logRefuse || !f.tokens[tok] {
			f.unauthorized(w)
			return
		}
		writeCanon(w, http.StatusOK, logPage{Entries: []wireEntry{}, Head: vaultlog.Head{Seq: 7}})
	default:
		http.NotFound(w, r)
	}
}

func (f *fakeAuth) set(fn func(f *fakeAuth)) {
	f.mu.Lock()
	defer f.mu.Unlock()
	fn(f)
}

func (f *fakeAuth) counts() (challenges, sessions, logs int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.challenges, f.sessions, f.logs
}

func (f *fakeAuth) revokeAll() {
	f.mu.Lock()
	defer f.mu.Unlock()
	clear(f.tokens)
}

type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *clock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

func sessionFixture(t *testing.T) (*fakeAuth, *Remote, *fakeSigner, *clock, *Client) {
	t.Helper()
	f := newFakeAuth()
	clk := &clock{t: time.Now()}
	c, _ := tlsServer(t, f, Options{Now: clk.now})
	s := &fakeSigner{}
	dev := Device{AccountID: model.ID{1}, DeviceID: model.ID{2}, Signer: func() (Signer, error) { return s, nil }}
	return f, c.Remote(model.ID{3}, dev), s, clk, c
}

func since(t *testing.T, r *Remote) {
	t.Helper()
	if _, head, err := r.Since(bg, 0); err != nil || head.Seq != 7 {
		t.Fatalf("Since: %v %v", head, err)
	}
}

func wantCounts(t *testing.T, f *fakeAuth, challenges, sessions, logs int) {
	t.Helper()
	if c, s, l := f.counts(); c != challenges || s != sessions || l != logs {
		t.Errorf("%d challenges, %d sessions, %d log requests; want %d, %d, %d", c, s, l, challenges, sessions, logs)
	}
}

// A session is authenticated once, signed by the device over this
// server's origin, cached, and replaced a minute before it expires.
func TestSessionCachedAndRefreshed(t *testing.T) {
	f, r, s, clk, c := sessionFixture(t)
	since(t, r)
	since(t, r)
	wantCounts(t, f, 1, 1, 2)
	if s.n() != 1 || s.calls[0] != c.Origin()+"|session|32" {
		t.Errorf("signer calls %v", s.calls)
	}
	clk.advance(13*time.Minute + 50*time.Second)
	since(t, r)
	wantCounts(t, f, 1, 1, 3)
	clk.advance(20 * time.Second) // within RefreshMargin of the expiry
	since(t, r)
	wantCounts(t, f, 2, 2, 4)
	// expires_at is never trusted past the session lifetime.
	f.set(func(f *fakeAuth) { f.ttl = 24 * time.Hour })
	clk.advance(time.Hour)
	since(t, r)
	clk.advance(sessionTTL - RefreshMargin + time.Second)
	since(t, r)
	wantCounts(t, f, 4, 4, 6)
}

// A 401 gets one new session and one retry; a session ended while the
// device stays active is replaced transparently.
func TestSessionReauthenticatesOnce(t *testing.T) {
	f, r, _, _, _ := sessionFixture(t)
	since(t, r)
	f.revokeAll()
	since(t, r)
	wantCounts(t, f, 2, 2, 3)

	// A 401 for the session just issued: the server ended it.
	f.set(func(f *fakeAuth) { f.logRefuse = true })
	_, _, err := r.Since(bg, 0)
	if !errors.Is(err, ErrSessionEnded) || !errors.Is(err, store.ErrSessionEnded) || !errors.Is(err, ErrUnauthorized) {
		t.Errorf("401 after a fresh session: %v", err)
	}
	wantCounts(t, f, 3, 3, 5)
}

// A refused session challenge means the device is not active.
func TestSessionEnded(t *testing.T) {
	f, r, s, _, _ := sessionFixture(t)
	since(t, r)
	f.set(func(f *fakeAuth) { f.inactive = true })
	f.revokeAll()
	if _, _, err := r.Since(bg, 0); !errors.Is(err, store.ErrSessionEnded) {
		t.Errorf("inactive device: %v", err)
	}
	if s.n() != 1 {
		t.Errorf("signed %d times; a refused challenge needs no signature", s.n())
	}
}

// A refused session is tried once more with a fresh challenge; a second
// refusal is an authentication failure, not a session the server ended.
func TestSessionRefusedRetriedOnce(t *testing.T) {
	f, r, _, _, _ := sessionFixture(t)
	f.set(func(f *fakeAuth) { f.refuse = 1 })
	since(t, r)
	wantCounts(t, f, 2, 2, 1)

	f, r, _, _, _ = sessionFixture(t)
	f.set(func(f *fakeAuth) { f.refuse = 2 })
	_, _, err := r.Since(bg, 0)
	if !errors.Is(err, ErrUnauthorized) || errors.Is(err, ErrSessionEnded) {
		t.Errorf("refused twice: %v", err)
	}
	wantCounts(t, f, 2, 2, 0)
}

// A session response without a vault_id (an older server), or with a zero
// one, is malformed, and nothing is cached from it.
func TestSessionWithoutVaultIDRefused(t *testing.T) {
	for name, set := range map[string]func(f *fakeAuth){
		"missing": func(f *fakeAuth) { f.noVault = true },
		"zero":    func(f *fakeAuth) { f.vault = model.ID{} },
	} {
		t.Run(name, func(t *testing.T) {
			f, r, _, _, c := sessionFixture(t)
			f.set(set)
			if _, _, err := r.Since(bg, 0); !errors.Is(err, ErrMalformedResponse) {
				t.Errorf("Since: %v; want ErrMalformedResponse", err)
			}
			if _, err := c.SessionVault(bg, r.dev); !errors.Is(err, ErrMalformedResponse) {
				t.Errorf("SessionVault: %v; want ErrMalformedResponse", err)
			}
			wantCounts(t, f, 2, 2, 0)
		})
	}
}

// SessionVault returns the vault the session is bound to, from the same
// cached session the log requests use, and a replaced session brings its
// own.
func TestSessionVaultCached(t *testing.T) {
	f, r, _, clk, c := sessionFixture(t)
	v, err := c.SessionVault(bg, r.dev)
	if err != nil || v != (model.ID{3}) {
		t.Fatalf("SessionVault: %v, %v", v, err)
	}
	wantCounts(t, f, 1, 1, 0)
	since(t, r) // reuses the session SessionVault authenticated
	if v, err = c.SessionVault(bg, r.dev); err != nil || v != (model.ID{3}) {
		t.Fatalf("second SessionVault: %v, %v", v, err)
	}
	wantCounts(t, f, 1, 1, 1)

	// The next session is bound to another vault: the cache follows it.
	f.set(func(f *fakeAuth) { f.vault = model.ID{4} })
	clk.advance(sessionTTL)
	if v, err = c.SessionVault(bg, r.dev); err != nil || v != (model.ID{4}) {
		t.Fatalf("SessionVault after the refresh: %v, %v", v, err)
	}
	wantCounts(t, f, 2, 2, 1)

	// A session replaced after a 401 brings its own vault.
	f.revokeAll()
	f.set(func(f *fakeAuth) { f.vault = model.ID{5} })
	since(t, r)
	if v, err = c.SessionVault(bg, r.dev); err != nil || v != (model.ID{5}) {
		t.Fatalf("SessionVault after re-authentication: %v, %v", v, err)
	}
}

// Concurrent calls share one authentication.
func TestSessionSingleFlight(t *testing.T) {
	f, r, _, _, _ := sessionFixture(t)
	var wg sync.WaitGroup
	for range 8 {
		wg.Go(func() {
			if _, _, err := r.Since(bg, 0); err != nil {
				t.Error(err)
			}
		})
	}
	wg.Wait()
	wantCounts(t, f, 1, 1, 8)
}

// The signer's errors stop the authentication before the session request,
// and a forced reauthentication replaces a cached session.
func TestSessionSignerAndReauthenticate(t *testing.T) {
	f, r, s, _, c := sessionFixture(t)
	s.err = store.ErrAuthClosed
	if _, _, err := r.Since(bg, 0); !errors.Is(err, store.ErrAuthClosed) {
		t.Errorf("closed signer: %v", err)
	}
	wantCounts(t, f, 1, 0, 0)
	s.err = nil
	since(t, r)
	if _, err := c.sessionToken(bg, r.dev, "", true); err != nil {
		t.Fatal(err)
	}
	since(t, r)
	wantCounts(t, f, 3, 2, 2)

	// No signer at all.
	nr := c.Remote(model.ID{3}, Device{AccountID: model.ID{9}, DeviceID: model.ID{9}})
	if _, _, err := nr.Since(bg, 0); !errors.Is(err, store.ErrAuthClosed) {
		t.Errorf("no signer: %v", err)
	}
}

// A session challenge refused before any session existed.
func TestSessionEndedWithNothingCached(t *testing.T) {
	f, r, _, _, _ := sessionFixture(t)
	f.set(func(f *fakeAuth) { f.inactive = true })
	if _, _, err := r.Since(bg, 0); !errors.Is(err, ErrSessionEnded) {
		t.Errorf("%v", err)
	}
	wantCounts(t, f, 1, 0, 0)
}

func TestLifetime(t *testing.T) {
	sent := time.Date(2026, 10, 22, 12, 0, 0, 0, time.UTC)
	hdr := func(d time.Time) http.Header { return http.Header{"Date": {d.Format(http.TimeFormat)}} }
	server := sent.Add(-3 * time.Hour) // the client's clock is 3 hours ahead
	for _, c := range []struct {
		expires time.Time
		h       http.Header
		want    time.Duration
	}{
		{server.Add(15 * time.Minute), hdr(server), 15 * time.Minute},
		{server.Add(10 * time.Minute), hdr(server), 10 * time.Minute},
		{server.Add(2 * time.Hour), hdr(server), sessionTTL},
		{server.Add(-time.Minute), hdr(server), 0},
		{sent.Add(5 * time.Minute), http.Header{}, 5 * time.Minute},
		{sent.Add(5 * time.Minute), http.Header{"Date": {"garbage"}}, 5 * time.Minute},
	} {
		if got := lifetime(c.expires, c.h, sent); got != c.want {
			t.Errorf("lifetime(%v, %v) = %v; want %v", c.expires, c.h, got, c.want)
		}
	}
}

// fixed answers every request with one status and body.
func fixed(status int, body string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		w.Write([]byte(body))
	})
}

const testHash = "0101010101010101010101010101010101010101010101010101010101010101"

// R11 errors and the status codes map to typed errors.
func TestErrorMapping(t *testing.T) {
	type check func(error) bool
	is := func(target error) check { return func(err error) bool { return errors.Is(err, target) } }
	not := func(target error) check { return func(err error) bool { return !errors.Is(err, target) } }
	retry := func(want bool) check { return func(err error) bool { return Retryable(err) == want } }
	code := func(want string) check {
		return func(err error) bool {
			var ae *APIError
			return errors.As(err, &ae) && ae.Code == want
		}
	}
	env := func(code string) string { return `{"error":{"code":"` + code + `","message":"m"}}` }
	for _, c := range []struct {
		status int
		body   string
		checks []check
	}{
		{409, `{"error":{"code":"head_conflict","message":"prev is not the head"},"head":{"h":"` + testHash + `","seq":"41"}}`,
			[]check{is(store.ErrHeadConflict), retry(false), func(err error) bool {
				var hc *store.HeadConflictError
				return errors.As(err, &hc) && hc.Head.Seq == 41 && hc.Head.H.String() == testHash
			}}},
		// A head conflict whose head does not decode is no conflict.
		{409, `{"error":{"code":"head_conflict","message":"m"},"head":{"h":"zz","seq":"41"}}`, []check{not(store.ErrHeadConflict), is(ErrConflict)}},
		{409, `{"error":{"code":"head_conflict","message":"m"},"head":{"h":"` + testHash + `","seq":41}}`, []check{not(store.ErrHeadConflict)}},
		{409, env("head_conflict"), []check{not(store.ErrHeadConflict), is(ErrMalformedResponse)}},
		{409, env("registration_conflict"), []check{is(ErrRegistrationConflict), is(ErrConflict), not(store.ErrHeadConflict), code("registration_conflict")}},
		{409, env("already_claimed"), []check{is(ErrAlreadyClaimed), not(ErrRegistrationConflict)}},
		{409, env("conflict"), []check{is(ErrConflict), not(ErrAlreadyClaimed), not(store.ErrHeadConflict)}},
		{400, env("bad_request"), []check{is(ErrBadRequest), retry(false)}},
		{401, env("unauthorized"), []check{is(ErrUnauthorized), not(ErrSessionEnded), retry(false), code("unauthorized")}},
		{404, env("not_found"), []check{is(ErrNotFound), retry(false)}},
		{413, env("too_large"), []check{is(ErrTooLarge), retry(false)}},
		{429, env("rate_limited"), []check{is(ErrRateLimited), retry(true)}},
		{429, env("busy"), []check{is(ErrRateLimited), retry(true), code("busy")}},
		{507, env("quota_exhausted"), []check{is(ErrQuota), not(ErrServer), retry(false)}},
		{500, env("internal"), []check{is(ErrServer), retry(true)}},
		{502, `<html>bad gateway</html>`, []check{is(ErrServer), retry(true), code("")}},
		{503, ``, []check{is(ErrServer), retry(true)}},
		// The envelope is decoded strictly too.
		{400, `{"error":{"code":"bad_request","message":"m","extra":1}}`, []check{is(ErrBadRequest), code("")}},
		{401, `{"error":{"code":"unauthorized"}}`, []check{is(ErrUnauthorized), code("")}},
		{401, strings.Repeat(" ", maxSmallResponse+1), []check{is(ErrUnauthorized), not(ErrResponseTooLarge)}},
	} {
		t.Run(fmt.Sprintf("%d %.40s", c.status, c.body), func(t *testing.T) {
			cl, _ := tlsServer(t, fixed(c.status, c.body), Options{})
			err := cl.do(bg, &call{method: "POST", path: "/v1/vaults/x/log", body: struct{}{}}, nil)
			if err == nil {
				t.Fatal("no error")
			}
			for i, ch := range c.checks {
				if !ch(err) {
					t.Errorf("check %d failed for %v", i, err)
				}
			}
		})
	}

	// A login token's 401 is an authentication failure, never retried and
	// never a session ending.
	var hits atomic.Int32
	cl, _ := tlsServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		fixed(401, env("unauthorized")).ServeHTTP(w, r)
	}), Options{})
	tr := &TokenRemote{c: cl, token: "secret-token-xyz", VaultID: model.ID{5}}
	if _, _, err := tr.Since(bg, 0); !errors.Is(err, ErrUnauthorized) || errors.Is(err, ErrSessionEnded) || hits.Load() != 1 {
		t.Errorf("token 401: %v after %d requests", err, hits.Load())
	}
	if s := fmt.Sprintf("%v %+v %s", tr, tr, tr); strings.Contains(s, "secret-token-xyz") {
		t.Errorf("the remote prints its token: %s", s)
	}

	// Unreachable servers are retryable; cancellations are not.
	ts := httptest.NewTLSServer(http.HandlerFunc(healthy))
	dead := trusting(t, ts, ts.URL, Options{})
	ts.Close()
	if _, err := dead.Health(bg); !errors.Is(err, ErrUnreachable) || !Retryable(err) {
		t.Errorf("closed server: %v", err)
	}
	ctx, cancel := context.WithCancel(bg)
	cancel()
	if _, err := cl.Health(ctx); !errors.Is(err, context.Canceled) || Retryable(err) {
		t.Errorf("cancelled: %v", err)
	}
}

// No standard formatting of a value that holds a bearer credential prints
// it: every verb, on the value and on the pointer, and slog's text and
// JSON handlers.
func TestCredentialsNeverPrinted(t *testing.T) {
	const secret = "secret-token-xyz"
	c, err := New("https://hop.example", Options{})
	if err != nil {
		t.Fatal(err)
	}
	dev := Device{AccountID: model.ID{1}, DeviceID: model.ID{2}}
	c.session(dev).token = secret // a cached session
	tr := &TokenRemote{c: c, token: secret, AccountID: model.ID{1}, VaultID: model.ID{5}}
	mb := NewMailbox(model.ID{6}, "ABCDEFGHJK", secret)
	d, a := c.DeviceRelay(mb), c.ApproverRelay(model.ID{6}, dev)
	cases := []struct {
		name string
		v    any
		want string // what the description names
	}{
		{"*TokenRemote", tr, model.ID{5}.String()},
		{"TokenRemote", *tr, model.ID{5}.String()},
		{"*Mailbox", mb, model.ID{6}.String()},
		{"Mailbox", *mb, model.ID{6}.String()},
		{"D's *Relay", d, model.ID{6}.String()},
		{"D's Relay", *d, model.ID{6}.String()},
		{"A's *Relay", a, model.ID{6}.String()},
		{"A's Relay", *a, model.ID{6}.String()},
		{"*Client", c, "hop.example"},
	}
	// Values that hold the client hold its sessions too.
	rm, pb, rt := c.Remote(model.ID{5}, dev), c.Publisher(model.ID{5}), c.Retirer(model.ID{5})
	cases = append(cases, []struct {
		name string
		v    any
		want string
	}{
		{"*Remote", rm, ""}, {"Remote", *rm, ""},
		{"*Publisher", pb, ""},
		{"*Retirer", rt, ""}, {"Retirer", *rt, ""},
	}...)
	leaks := func(s string) bool {
		return strings.Contains(s, secret) || strings.Contains(strings.ToLower(s), fmt.Sprintf("%x", secret))
	}
	for _, k := range cases {
		for _, verb := range []string{"%v", "%+v", "%#v", "%s", "%q", "%x", "%X", "%d"} {
			s := fmt.Sprintf(verb, k.v)
			if leaks(s) {
				t.Errorf("%s with %s prints the token: %s", k.name, verb, s)
			}
			if verb != "%x" && verb != "%X" && !strings.Contains(s, k.want) {
				t.Errorf("%s with %s is %s; want it to name %s", k.name, verb, s, k.want)
			}
		}
		var buf strings.Builder
		slog.New(slog.NewTextHandler(&buf, nil)).Info("m", "v", k.v)
		slog.New(slog.NewJSONHandler(&buf, nil)).Info("m", "v", k.v)
		slog.New(slog.NewJSONHandler(&buf, nil)).Info("m", slog.Group("g", "v", k.v))
		if leaks(buf.String()) || !strings.Contains(buf.String(), k.want) {
			t.Errorf("%s in slog: %s", k.name, buf.String())
		}
		// encoding/json, directly and nested where slog's JSON handler
		// does not call LogValue: in a map, a slice and a struct.
		var nested strings.Builder
		slog.New(slog.NewJSONHandler(&nested, nil)).Info("m", "state", map[string]any{"v": k.v})
		for _, v := range []any{k.v, map[string]any{"v": k.v}, []any{k.v}, struct{ V any }{k.v}} {
			b, err := json.Marshal(v)
			if err == nil && leaks(string(b)) {
				t.Errorf("%s through encoding/json: %s", k.name, b)
			}
		}
		if leaks(nested.String()) {
			t.Errorf("%s nested in a slog JSON map: %s", k.name, nested.String())
		}
	}
}

// R8/R9: responses are capped per endpoint, with or without a
// Content-Length; requests over the body limit are not sent.
func TestBodyCaps(t *testing.T) {
	pad := func(n int) string { return strings.Repeat("a", n) }
	healthOf := func(size int) string {
		frame := `{"ok":true,"version":""}`
		return `{"ok":true,"version":"` + pad(size-len(frame)) + `"}`
	}
	for _, c := range []struct {
		name    string
		body    string
		chunked bool
		call    func(*Client) error
		tooBig  bool
	}{
		{"small at limit", healthOf(maxSmallResponse), false, health, false},
		{"small over limit", healthOf(maxSmallResponse + 1), false, health, true},
		{"small over limit, chunked", healthOf(maxSmallResponse + 1), true, health, true},
		{"log over limit", `{"entries":[],"head":{"h":"` + testHash + `","seq":"0"},"x":"` + pad(maxLogResponse) + `"}`, false, logCall, true},
		{"log over limit, chunked", `{"entries":[],"head":{"h":"` + testHash + `","seq":"0"},"x":"` + pad(maxLogResponse) + `"}`, true, logCall, true},
		// Within the log limit, so it is read, and refused by the strict
		// decoder instead.
		{"log under limit", `{"entries":[],"head":{"h":"` + testHash + `","seq":"0"},"x":"` + pad(maxSmallResponse*2) + `"}`, false, logCall, false},
		{"object over limit", pad(maxObjectResponse + 1), true, objectCall, true},
		{"mailbox over limit", `{"messages":[],"x":"` + pad(maxMailboxResponse) + `"}`, true, mailboxCall, true},
	} {
		t.Run(c.name, func(t *testing.T) {
			cl, _ := tlsServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if !c.chunked {
					w.Header().Set("Content-Length", strconv.Itoa(len(c.body)))
				}
				w.WriteHeader(http.StatusOK)
				if c.chunked {
					w.(http.Flusher).Flush()
				}
				w.Write([]byte(c.body))
			}), Options{})
			err := c.call(cl)
			if got := errors.Is(err, ErrResponseTooLarge); got != c.tooBig {
				t.Errorf("err %v; want too large: %v", err, c.tooBig)
			}
		})
	}

	// The reads are bounded, not just checked afterwards: an endless body
	// and an oversized Content-Length fail at once, long before the
	// request's deadline.
	for name, h := range map[string]http.HandlerFunc{
		"endless": func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			chunk := []byte(strings.Repeat(" ", 4096))
			for r.Context().Err() == nil {
				if _, err := w.Write(chunk); err != nil {
					return
				}
			}
		},
		"declared": func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Length", strconv.Itoa(maxSmallResponse+1))
			w.WriteHeader(http.StatusOK)
			w.(http.Flusher).Flush()
			<-r.Context().Done()
		},
	} {
		cl, _ := tlsServer(t, h, Options{Timeout: 3 * time.Second})
		start := time.Now()
		if _, err := cl.Health(bg); !errors.Is(err, ErrResponseTooLarge) || time.Since(start) > 2*time.Second {
			t.Errorf("%s: %v after %v", name, err, time.Since(start))
		}
	}

	var hits atomic.Int32
	cl, _ := tlsServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		healthy(w, r)
	}), Options{})
	type big struct {
		X string `json:"x"`
	}
	frame := len(`{"x":""}`)
	if err := cl.do(bg, &call{method: "POST", path: "/v1/x", body: big{pad(maxRequestBody - frame + 1)}}, nil); !errors.Is(err, ErrRequestTooLarge) {
		t.Errorf("request over 4 MiB: %v", err)
	}
	if hits.Load() != 0 {
		t.Error("a request over the limit was sent")
	}
	if err := cl.do(bg, &call{method: "POST", path: "/v1/x", body: big{pad(maxRequestBody - frame)}}, nil); err != nil {
		t.Errorf("request at 4 MiB: %v", err)
	}
	if err := cl.do(bg, &call{method: "POST", path: "/v1/signup", maxBody: maxSignupBody, body: big{pad(maxRequestBody)}}, nil); err != nil {
		t.Errorf("signup over 4 MiB: %v", err)
	}
}

func health(c *Client) error { _, err := c.Health(bg); return err }

func logCall(c *Client) error {
	_, _, err := (&TokenRemote{c: c, token: "t", VaultID: model.ID{1}}).Since(bg, 0)
	return err
}

func objectCall(c *Client) error {
	_, err := (&TokenRemote{c: c, token: "t", VaultID: model.ID{1}}).Object(bg, crypto.Hash{})
	return err
}

func mailboxCall(c *Client) error {
	_, err := c.DeviceRelay(NewMailbox(model.ID{1}, "", "t")).Messages(bg, 0, 0)
	return err
}

// Responses are decoded with the strict decoder: unknown, duplicate and
// missing members, wrong types and trailing data are refused.
func TestStrictDecoding(t *testing.T) {
	for _, body := range []string{
		`{"ok":true,"version":"v","extra":1}`,
		`{"ok":true,"version":"v","version":"w"}`,
		`{"ok":true}`,
		`{"ok":"true","version":"v"}`,
		`{"ok":true,"version":"v"} {}`,
		`{"ok":true,"version":"v"`,
		`[]`,
		``,
	} {
		cl, _ := tlsServer(t, fixed(200, body), Options{})
		if _, err := cl.Health(bg); !errors.Is(err, ErrMalformedResponse) {
			t.Errorf("%q: %v", body, err)
		}
	}
	// Non-canonical JSON the strict decoder accepts is fine.
	cl, _ := tlsServer(t, fixed(200, ` { "version" : "v",
		"ok" : true } `), Options{})
	if v, err := cl.Health(bg); err != nil || v != "v" {
		t.Errorf("non-canonical: %q %v", v, err)
	}

	// A log page whose entries go backwards, a page entry that is no wire,
	// an object that does not match its digest, a compressed response.
	for name, c := range map[string]struct {
		h    http.Handler
		call func(*Client) error
	}{
		"page order": {fixed(200, `{"entries":[{"h":"`+testHash+`","seq":"0","wire":{}}],"head":{"h":"`+testHash+`","seq":"0"}}`), logCall},
		"page wire":  {fixed(200, `{"entries":[{"h":"`+testHash+`","seq":"1","wire":{}}],"head":{"h":"`+testHash+`","seq":"1"}}`), logCall},
		"object":     {fixed(200, `{"v":1}`), objectCall},
		"encoding": {http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Encoding", "gzip")
			healthy(w, r)
		}), health},
		"mailbox order": {fixed(200, `{"messages":[{"body":{},"n":"2","type":"open"},{"body":{},"n":"1","type":"chal"}]}`), mailboxCall},
	} {
		cl, _ := tlsServer(t, c.h, Options{})
		err := c.call(cl)
		if !errors.Is(err, ErrMalformedResponse) {
			t.Errorf("%s: %v", name, err)
		}
		// The order is checked before any wire is parsed.
		if strings.HasSuffix(name, "order") && !strings.Contains(fmt.Sprint(err), "out of order") {
			t.Errorf("%s: %v; want an order error", name, err)
		}
	}
}

// A long-poll's deadline covers its wait; a request's deadline ends a
// server that never answers.
func TestDeadlines(t *testing.T) {
	release := make(chan struct{})
	defer close(release)
	cl, _ := tlsServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("wait") == "1" {
			time.Sleep(1200 * time.Millisecond)
			writeCanon(w, 200, logPage{Entries: []wireEntry{}, Head: vaultlog.Head{}})
			return
		}
		select {
		case <-release:
		case <-r.Context().Done():
		}
	}), Options{Timeout: 500 * time.Millisecond})
	start := time.Now()
	_, err := cl.Health(bg)
	if !errors.Is(err, context.DeadlineExceeded) || !Retryable(err) || time.Since(start) > 5*time.Second {
		t.Errorf("hung server: %v after %v", err, time.Since(start))
	}
	tr := &TokenRemote{c: cl, token: "t", VaultID: model.ID{1}}
	if _, _, err := tr.c.since(bg, "t", model.ID{1}, 0, time.Second); err != nil {
		t.Errorf("a long-poll past the request timeout: %v", err)
	}
}
