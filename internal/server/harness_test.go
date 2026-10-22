package server

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/dalyem/hopkey/internal/canonjson"
	"github.com/dalyem/hopkey/internal/crypto"
	"github.com/dalyem/hopkey/internal/model"
	"github.com/dalyem/hopkey/internal/vaultlog"
)

const testOrigin = "https://hop.example.com"

// clock is a settable clock for the server under test.
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

// env is a server on a real SQLite store behind an httptest server.
type env struct {
	t     *testing.T
	st    *SQLite
	srv   *Server
	ts    *httptest.Server
	clock *clock
	logs  *syncBuffer
	path  string
}

type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.b.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.b.String()
}

// unlimited rates keep tests that make many requests clear of R14; the
// rate-limit tests use DefaultRates.
func unlimitedRates() *Rates {
	r := Rate{N: 1 << 30, Per: time.Second}
	return &Rates{r, r, r, r, r, r, r}
}

type envOpt func(*Config)

func withLimits(f func(*Limits)) envOpt {
	return func(c *Config) {
		l := DefaultLimits()
		if c.Limits != nil {
			l = *c.Limits
		}
		f(&l)
		c.Limits = &l
	}
}

func withRates(r Rates) envOpt { return func(c *Config) { c.Rates = &r } }

func withProxies(p ...string) envOpt {
	return func(c *Config) {
		for _, s := range p {
			c.TrustedProxies = append(c.TrustedProxies, netip.MustParsePrefix(s))
		}
	}
}

func newEnv(t *testing.T, opts ...envOpt) *env {
	t.Helper()
	return newEnvAt(t, filepath.Join(t.TempDir(), "hop.db"), opts...)
}

func newEnvAt(t *testing.T, path string, opts ...envOpt) *env {
	t.Helper()
	st, err := OpenSQLite(path)
	if err != nil {
		t.Fatal(err)
	}
	e := &env{t: t, st: st, clock: &clock{t: time.Date(2026, 10, 22, 12, 0, 0, 0, time.UTC)}, logs: &syncBuffer{}, path: path}
	cfg := Config{
		Origin: testOrigin, Store: st, Now: e.clock.now, Rates: unlimitedRates(),
		Logger: slog.New(slog.NewTextHandler(e.logs, &slog.HandlerOptions{Level: slog.LevelDebug})),
	}
	for _, o := range opts {
		o(&cfg)
	}
	if e.srv, err = New(context.Background(), cfg); err != nil {
		t.Fatal(err)
	}
	e.ts = httptest.NewServer(e.srv.Handler())
	t.Cleanup(func() {
		e.ts.Close()
		e.srv.Close()
		st.Close()
	})
	return e
}

// resp is a response: status and body.
type resp struct {
	status int
	body   []byte
}

func (r resp) String() string { return fmt.Sprintf("%d %s", r.status, r.body) }

// do sends a request. body is nil, []byte, or a value encoded with
// canonjson. hdr holds extra headers.
func (e *env) do(method, path, token string, body any, hdr ...string) resp {
	e.t.Helper()
	return e.doCtx(context.Background(), method, path, token, body, hdr...)
}

func (e *env) doCtx(ctx context.Context, method, path, token string, body any, hdr ...string) resp {
	e.t.Helper()
	var rd io.Reader
	switch b := body.(type) {
	case nil:
	case []byte:
		rd = bytes.NewReader(b)
	default:
		j, err := canonjson.Marshal(b)
		if err != nil {
			e.t.Fatal(err)
		}
		rd = bytes.NewReader(j)
	}
	req, err := http.NewRequestWithContext(ctx, method, e.ts.URL+path, rd)
	if err != nil {
		e.t.Fatal(err)
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	for i := 0; i+1 < len(hdr); i += 2 {
		req.Header.Set(hdr[i], hdr[i+1])
	}
	res, err := e.ts.Client().Do(req)
	if err != nil {
		e.t.Fatal(err)
	}
	defer res.Body.Close()
	b, err := io.ReadAll(res.Body)
	if err != nil {
		e.t.Fatal(err)
	}
	return resp{res.StatusCode, b}
}

// must checks the status and decodes the body into v (when not nil).
func (e *env) must(r resp, status int, v any) {
	e.t.Helper()
	if r.status != status {
		e.t.Fatalf("status %d, want %d: %s", r.status, status, r.body)
	}
	if v != nil {
		if err := canonjson.Unmarshal(r.body, v); err != nil {
			e.t.Fatalf("decoding %s: %v", r.body, err)
		}
	}
}

func wantStatus(t *testing.T, r resp, status int, what string) {
	t.Helper()
	if r.status != status {
		t.Errorf("%s: status %d, want %d: %s", what, r.status, status, r.body)
	}
}

func wantCode(t *testing.T, r resp, status int, code, what string) {
	t.Helper()
	wantStatus(t, r, status, what)
	if !strings.Contains(string(r.body), `"code":"`+code+`"`) {
		t.Errorf("%s: body %s, want code %s", what, r.body, code)
	}
}

// --- a client-side vault, built with the phase 1 builders ---

type tvault struct {
	t       *testing.T
	email   string
	acct    *crypto.AccountKeys // at the head akv
	accts   map[uint32]*crypto.AccountKeys
	devs    map[model.ID]*vaultlog.LocalDevice
	infos   map[model.ID]vaultlog.DeviceInfo
	order   []model.ID
	st      *vaultlog.State
	sec     *vaultlog.Secrets
	log     []*vaultlog.Wire
	archive vaultlog.ObjectMap
	tick    int64
	authKey []byte // current derived secrets; their hashes are in creds
	rAuth   []byte
}

func randBytes(t *testing.T, n int) []byte {
	t.Helper()
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return b
}

func randID(t *testing.T) model.ID {
	t.Helper()
	id, err := vaultlog.NewID()
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func (v *tvault) now() model.Timestamp {
	v.tick++
	return model.TimestampOf(time.Date(2026, 10, 22, 0, 0, 0, 0, time.UTC)) + model.Timestamp(v.tick*60)
}

func (v *tvault) newDevice(name string) model.ID {
	v.t.Helper()
	id := randID(v.t)
	kem, err := crypto.GenerateKEMKey()
	if err != nil {
		v.t.Fatal(err)
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		v.t.Fatal(err)
	}
	v.devs[id] = &vaultlog.LocalDevice{ID: id, KEM: kem, Sig: priv}
	v.infos[id] = vaultlog.DeviceInfo{ID: id, Name: name, KEMPK: kem.PublicKey().Bytes(), SigPK: pub}
	v.order = append(v.order, id)
	return id
}

// dev returns the i-th device created.
func (v *tvault) dev(i int) model.ID { return v.order[i] }

func (v *tvault) creds(acct *crypto.AccountKeys) vaultlog.CredsInput {
	v.t.Helper()
	v.authKey, v.rAuth = randBytes(v.t, 32), randBytes(v.t, 32)
	enc, err := crypto.NewSymKey()
	if err != nil {
		v.t.Fatal(err)
	}
	pw, err := crypto.SealPwBlob(&enc, acct)
	if err != nil {
		v.t.Fatal(err)
	}
	rk, err := crypto.SealRkBlob(&enc, acct)
	if err != nil {
		v.t.Fatal(err)
	}
	return vaultlog.CredsInput{
		KDFVersion: 1, Salt: randBytes(v.t, 16),
		AuthSHA256: crypto.SHA256(v.authKey), RAuthSHA256: crypto.SHA256(v.rAuth),
		PwBlob: pw, RkBlob: rk,
	}
}

func (v *tvault) record(w *vaultlog.Wire, st *vaultlog.State, sec *vaultlog.Secrets, err error) *vaultlog.Wire {
	v.t.Helper()
	if err != nil {
		v.t.Fatal(err)
	}
	objs, err := vaultlog.WireObjects(w)
	if err != nil {
		v.t.Fatal(err)
	}
	for h, b := range objs {
		v.archive[h] = b
	}
	v.log = append(v.log, w)
	v.st, v.sec = st, sec
	return w
}

// newVault runs genesis with one device.
func newVault(t *testing.T, email string) *tvault {
	t.Helper()
	v := &tvault{
		t: t, email: email, accts: map[uint32]*crypto.AccountKeys{},
		devs: map[model.ID]*vaultlog.LocalDevice{}, infos: map[model.ID]vaultlog.DeviceInfo{},
		archive: vaultlog.ObjectMap{},
	}
	acct, err := crypto.GenerateAccountKeys(randID(t), 1)
	if err != nil {
		t.Fatal(err)
	}
	v.acct, v.accts[1] = acct, acct
	vk, err := crypto.NewSymKey()
	if err != nil {
		t.Fatal(err)
	}
	a := v.newDevice("dev-a")
	w, st, sec, err := vaultlog.BuildGenesis(vaultlog.GenesisParams{
		VaultID: randID(t), Account: acct, VK: vk, Creds: v.creds(acct), Device: v.infos[a], Time: v.now(),
	})
	v.record(w, st, sec, err)
	return v
}

func (v *tvault) accountID() model.ID { return v.st.Account.AccountID }
func (v *tvault) vaultID() model.ID   { return v.st.VaultID }
func (v *tvault) head() vaultlog.Head { return v.st.Head }

func (v *tvault) bootstrap(name string) (model.ID, *vaultlog.Wire) {
	v.t.Helper()
	id := v.newDevice(name)
	w, st, sec, err := vaultlog.BuildBootstrap(v.st, v.sec, v.infos[id], v.now())
	return id, v.record(w, st, sec, err)
}

func snippet(t *testing.T, cmd string) crypto.Item {
	return &model.Snippet{Header: model.Header{ItemID: randID(t), Type: model.TypeSnippet}, Name: "s", Command: cmd, Params: []string{}}
}

// normal adds n snippets with commands of size bytes, authored by dev.
func (v *tvault) normal(dev model.ID, n, size int) *vaultlog.Wire {
	v.t.Helper()
	var puts []crypto.Item
	for range n {
		puts = append(puts, snippet(v.t, strings.Repeat("x", size)))
	}
	w, st, sec, err := vaultlog.BuildNormal(v.st, v.sec, v.devs[dev], vaultlog.Changes{Put: puts}, v.now(), v.archive)
	return v.record(w, st, sec, err)
}

// unrecorded builds a normal entry on the current head without applying
// it.
func (v *tvault) unrecorded(dev model.ID) *vaultlog.Wire {
	v.t.Helper()
	w, _, _, err := vaultlog.BuildNormal(v.st, v.sec, v.devs[dev], vaultlog.Changes{Put: []crypto.Item{snippet(v.t, "ls")}}, v.now(), v.archive)
	if err != nil {
		v.t.Fatal(err)
	}
	return w
}

func (v *tvault) checkpoint(dev model.ID, revoke ...model.ID) *vaultlog.Wire {
	v.t.Helper()
	na, err := crypto.GenerateAccountKeys(v.accountID(), v.st.Account.AKV+1)
	if err != nil {
		v.t.Fatal(err)
	}
	vk, err := crypto.NewSymKey()
	if err != nil {
		v.t.Fatal(err)
	}
	w, st, sec, err := vaultlog.BuildCheckpoint(v.st, v.sec, v.devs[dev], vaultlog.CheckpointParams{
		NewAccount: na, NewVK: vk, Creds: v.creds(na), Revoke: revoke, Time: v.now(),
	})
	v.acct, v.accts[na.AKV] = na, na
	return v.record(w, st, sec, err)
}

func (v *tvault) retire(dev model.ID) *vaultlog.Wire {
	v.t.Helper()
	w, st, sec, err := vaultlog.BuildRetire(v.st, v.sec, v.devs[dev], v.now())
	return v.record(w, st, sec, err)
}

func wireJSON(t *testing.T, w *vaultlog.Wire) canonjson.Raw {
	t.Helper()
	b, err := w.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func postBody(t *testing.T, w *vaultlog.Wire) postLogRequest {
	return postLogRequest{Wire: wireJSON(t, w)}
}

// --- API helpers ---

func (e *env) invite(email string) string {
	e.t.Helper()
	code, err := CreateInvite(context.Background(), e.st, email, 7*24*time.Hour, e.clock.now())
	if err != nil {
		e.t.Fatal(err)
	}
	return code
}

func (e *env) signupChallenge(email, code string) []byte {
	e.t.Helper()
	var cr challengeResponse
	e.must(e.do("POST", "/v1/signup/challenge", "", signupChallengeRequest{email, code}), 200, &cr)
	return cr.Challenge
}

// signupReq builds a signup of v's first n wires (all when n is 0), with
// pop_sig by signer (the head account key when nil) over origin.
func (e *env) signupReq(v *tvault, code string, chal []byte, n int, signer *crypto.AccountKeys, origin string) signupRequest {
	e.t.Helper()
	if n == 0 {
		n = len(v.log)
	}
	last := v.log[n-1]
	h, err := last.Entry.Hash()
	if err != nil {
		e.t.Fatal(err)
	}
	if signer == nil {
		signer = v.accts[last.Entry.AKV]
	}
	pop := &crypto.SignupPoP{
		V: 1, Origin: origin, Email: v.email, AccountID: v.accountID(), VaultID: v.vaultID(),
		UploadSeq: last.Entry.Seq, UploadH: h, Challenge: chal,
	}
	sig, err := crypto.SignSignupPoP(signer, pop)
	if err != nil {
		e.t.Fatal(err)
	}
	req := signupRequest{Email: v.email, RegistrationCode: code, Challenge: chal, PopSig: sig}
	for _, w := range v.log[:n] {
		req.Wires = append(req.Wires, wireJSON(e.t, w))
	}
	return req
}

// publish signs v up with a fresh invite and returns the invite code.
func (e *env) publish(v *tvault) string {
	e.t.Helper()
	code := e.invite(v.email)
	chal := e.signupChallenge(v.email, code)
	var h vaultlog.Head
	e.must(e.do("POST", "/v1/signup", "", e.signupReq(v, code, chal, 0, nil, testOrigin)), 200, &h)
	if h != v.head() {
		e.t.Fatalf("signup acknowledged %+v, want %+v", h, v.head())
	}
	return code
}

func (e *env) challenge(v *tvault, dev model.ID, op string) resp {
	return e.do("POST", "/v1/auth/challenge", "", challengeRequest{v.accountID(), dev, op})
}

func (e *env) signAuth(v *tvault, dev model.ID, op, origin string, chal []byte) []byte {
	e.t.Helper()
	sig, err := crypto.SignDeviceAuth(v.devs[dev].Sig, &crypto.DeviceAuth{
		V: 1, Origin: origin, AccountID: v.accountID(), DeviceID: dev, Operation: op, Challenge: chal,
	})
	if err != nil {
		e.t.Fatal(err)
	}
	return sig
}

// session runs the device-auth flow and returns an access token.
func (e *env) session(v *tvault, dev model.ID) string {
	e.t.Helper()
	var cr challengeResponse
	e.must(e.challenge(v, dev, "session"), 200, &cr)
	var sr sessionResponse
	e.must(e.do("POST", "/v1/auth/session", "", sessionRequest{v.accountID(), dev, cr.Challenge,
		e.signAuth(v, dev, "session", testOrigin, cr.Challenge)}), 200, &sr)
	return sr.AccessToken
}

func (e *env) login(v *tvault) string {
	e.t.Helper()
	var lr loginResponse
	e.must(e.do("POST", "/v1/login", "", loginRequest{v.accountID(), v.authKey}), 200, &lr)
	if lr.VaultID != v.vaultID() {
		e.t.Fatalf("login vault %v, want %v", lr.VaultID, v.vaultID())
	}
	return lr.LoginToken
}

func (e *env) recoverToken(v *tvault) string {
	e.t.Helper()
	var lr loginResponse
	e.must(e.do("POST", "/v1/recover", "", recoverRequest{v.accountID(), v.rAuth}), 200, &lr)
	return lr.LoginToken
}

func logPath(v *tvault) string { return "/v1/vaults/" + v.vaultID().String() + "/log" }

// post posts a wire to v's vault.
func (e *env) post(v *tvault, tok string, w *vaultlog.Wire) resp {
	e.t.Helper()
	return e.do("POST", logPath(v), tok, postBody(e.t, w))
}

func (e *env) mustPost(v *tvault, tok string, w *vaultlog.Wire) {
	e.t.Helper()
	var h vaultlog.Head
	e.must(e.post(v, tok, w), 200, &h)
	want, err := w.Entry.Hash()
	if err != nil {
		e.t.Fatal(err)
	}
	if h.Seq != w.Entry.Seq || h.H != want {
		e.t.Fatalf("commit %+v, want seq %d h %v", h, w.Entry.Seq, want)
	}
}

type logPage struct {
	Entries []struct {
		Seq  uint64        `json:"seq,string"`
		H    crypto.Hash   `json:"h"`
		Wire canonjson.Raw `json:"wire"`
	} `json:"entries"`
	Head vaultlog.Head `json:"head"`
}

func (e *env) readLog(v *tvault, tok, query string) (resp, logPage) {
	e.t.Helper()
	r := e.do("GET", logPath(v)+query, tok, nil)
	var p logPage
	if r.status == 200 {
		e.must(r, 200, &p)
	}
	return r, p
}

// view runs fn in a read transaction of the store under test.
func (e *env) view(fn func(Tx) error) {
	e.t.Helper()
	if err := e.st.View(context.Background(), fn); err != nil {
		e.t.Fatal(err)
	}
}
