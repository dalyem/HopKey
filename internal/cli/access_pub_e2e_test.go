package cli_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/dalyem/hopkey/internal/cli"
	"github.com/dalyem/hopkey/internal/crypto"
	"github.com/dalyem/hopkey/internal/daemon"
	"github.com/dalyem/hopkey/internal/model"
	"github.com/dalyem/hopkey/internal/server"
	"github.com/dalyem/hopkey/internal/store"
)

// hop access in a published vault: two devices (desk and laptop), each
// with its daemon, over a real hop-server; the hosts are akServers. The
// server can be made to refuse posts, and to serve some devices an old
// prefix of the log (a server that withholds entries, outside C2).

type pubAccess struct {
	t         *testing.T
	w         *resolveWorld
	srv       []*akServer
	orig      []string
	desk      *device
	laptop    *device
	colleague ssh.Signer
	pub, fp   string
	intercept atomic.Pointer[func(rw http.ResponseWriter, req *http.Request, next http.Handler) bool]
}

func newPubAccess(t *testing.T, hosts int) *pubAccess {
	t.Helper()
	requireSSH(t)
	cli.SetAKLockWait(t, 1)
	ctx := context.Background()
	x := &pubAccess{t: t, colleague: newSigner(t)}
	x.pub = authorizedKeysLine(x.colleague.PublicKey())
	x.fp = ssh.FingerprintSHA256(x.colleague.PublicKey())

	ts := httptest.NewUnstartedServer(nil)
	origin := "https://" + ts.Listener.Addr().String()
	st, err := server.OpenSQLite(filepath.Join(shortTemp(t), "hop.db"))
	if err != nil {
		t.Fatal(err)
	}
	r := server.Rate{N: 100_000, Per: time.Minute}
	rates := server.Rates{PreloginIP: r, PreloginEmail: r, LoginIP: r, LoginAccount: r, IP: r, Account: r, Device: r, EnrollIP: r, Claim: r}
	srv, err := server.New(ctx, server.Config{Origin: origin, Store: st, Rates: &rates, Logger: slog.New(slog.NewTextHandler(io.Discard, nil))})
	if err != nil {
		t.Fatal(err)
	}
	h := srv.Handler()
	ts.Config.Handler = http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		if f := x.intercept.Load(); f != nil && (*f)(rw, req, h) {
			return
		}
		h.ServeHTTP(rw, req)
	})
	ts.StartTLS()
	t.Cleanup(func() {
		ts.Close()
		srv.Close()
		st.Close()
	})
	pool := x509.NewCertPool()
	pool.AddCert(ts.Certificate())
	x.w = &resolveWorld{st: st, origin: origin, pool: pool}

	cfg1 := resolveStoreConfig(t, "desk")
	p, err := store.PrepareInit(cfg1, store.InitOptions{Password: []byte(resolvePassword)})
	if err != nil {
		t.Fatal(err)
	}
	s1, err := p.Commit()
	if err != nil {
		t.Fatal(err)
	}
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	login, _ := ssh.NewSignerFromKey(priv)
	block, _ := ssh.MarshalPrivateKey(priv, "")
	key, err := s1.PutKey(ctx, model.Key{Name: "deploy-key", KeyType: "ed25519", PrivateKey: string(pem.EncodeToMemory(block)), PublicKey: authorizedKeysLine(login.PublicKey())})
	if err != nil {
		t.Fatal(err)
	}
	user := localUser(t)
	base := shortTemp(t)
	for i := range hosts {
		home := filepath.Join(base, fmt.Sprintf("remote%d", i+1))
		os.MkdirAll(filepath.Join(home, ".ssh"), 0o700)
		content := "# hop test\n" + authorizedKeysLine(login.PublicKey()) + " deploy\n"
		os.WriteFile(filepath.Join(home, ".ssh", "authorized_keys"), []byte(content), 0o600)
		s := startAKServer(t, home)
		x.srv, x.orig = append(x.srv, s), append(x.orig, content)
		if _, err := s1.PutHost(ctx, model.Host{
			Name: fmt.Sprintf("web-%d", i+1), Addresses: []string{"127.0.0.1"}, Port: uint32(s.port), User: user,
			KeyID: key.ItemID, Route: "auto", AgentAccess: "allow", HostKeys: []string{authorizedKeysLine(s.hostKey)},
		}); err != nil {
			t.Fatal(err)
		}
	}
	c := x.w.client(t)
	invite, err := server.CreateInvite(ctx, st, resolveEmail, 24*time.Hour, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	pub, err := s1.Publish(ctx, c.Publisher(model.ID{}), store.PublishOptions{Server: origin, Email: resolveEmail, RegistrationCode: invite})
	if err != nil {
		t.Fatalf("publish: %v", err)
	}
	s2 := signInDevice(t, c, resolveStoreConfig(t, "laptop"), p.Kit(), pub)
	x.desk = x.w.startDaemon(t, "desk", s1)
	x.laptop = x.w.startDaemon(t, "laptop", s2)
	return x
}

func (x *pubAccess) setIntercept(f func(rw http.ResponseWriter, req *http.Request, next http.Handler) bool) {
	if f == nil {
		x.intercept.Store(nil)
		return
	}
	x.intercept.Store(&f)
}

func (x *pubAccess) ak(i int) string {
	b, err := os.ReadFile(filepath.Join(x.srv[i].home, ".ssh", "authorized_keys"))
	if err != nil {
		x.t.Fatal(err)
	}
	return string(b)
}

// hop runs hop on dv with what hop access needs of its environment.
func (x *pubAccess) hop(dv *device, args ...string) (int, string) {
	t := x.t
	t.Helper()
	var so, se bytes.Buffer
	env := &cli.Env{
		Stdin: strings.NewReader(""), Stdout: &so, Stderr: &se,
		Getenv: func(string) string { return "" },
		Home:   dv.home, Paths: dv.paths, SSHProbeEnv: passwdShimEnv(),
		PasswdHome: func() (string, error) { return dv.home, nil },
		StartDaemon: func() error {
			t.Error("the CLI tried to start a daemon, but one is running")
			return errors.New("unexpected daemon start")
		},
		DialTimeout: 5 * time.Second,
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	code := cli.Run(ctx, args, env)
	t.Logf("%s: hop %s: exit %d\n%s%s", dv.name, strings.Join(args, " "), code, so.String(), se.String())
	return code, so.String() + se.String()
}

func (x *pubAccess) add(dv *device, label string, hosts ...string) (int, cli.AccessRunResult) {
	code, out := x.hop(dv, append(append([]string{"access", "add", label}, hosts...), "--pubkey", x.pub, "--fingerprint", x.fp, "--yes", "--json")...)
	return code, decodeRun(out)
}

func decodeRun(out string) cli.AccessRunResult {
	var res cli.AccessRunResult
	if i := strings.Index(out, "{"); i >= 0 {
		json.NewDecoder(strings.NewReader(out[i:])).Decode(&res)
	}
	return res
}

func (x *pubAccess) list(dv *device) daemon.AccessListResult {
	var l daemon.AccessListResult
	dv.must(x.t, daemon.OpAccessList, nil, &l)
	return l
}

func (x *pubAccess) record(dv *device, label string) *model.Access {
	l := x.list(dv)
	for i := range l.Access {
		if l.Access[i].Label == label {
			return &l.Access[i]
		}
	}
	return nil
}

func (x *pubAccess) check(dv *device, args ...string) (int, []cli.AccessFinding) {
	code, out := x.hop(dv, append([]string{"access", "check", "--json"}, args...)...)
	var fs []cli.AccessFinding
	if i := strings.Index(out, "["); i >= 0 {
		json.NewDecoder(strings.NewReader(out[i:])).Decode(&fs)
	}
	return code, fs
}

func isLogPost(req *http.Request) bool {
	return req.Method == http.MethodPost && strings.HasSuffix(req.URL.Path, "/log")
}

// Commit before touching (§7.1): when the before-acting put can't commit,
// the command says "recorded, not applied" and no host is touched; a run
// that resumes a target whose record is only queued commits it first.
func TestAccessPublishedCommitsBeforeTouching(t *testing.T) {
	x := newPubAccess(t, 1)
	var posts atomic.Int32
	x.setIntercept(func(rw http.ResponseWriter, req *http.Request, next http.Handler) bool {
		if isLogPost(req) {
			posts.Add(1)
			http.Error(rw, "down for maintenance", http.StatusServiceUnavailable)
			return true
		}
		return false
	})
	code, out := x.hop(x.laptop, "access", "add", "alice", "web-1", "--pubkey", x.pub, "--fingerprint", x.fp, "--yes", "--json")
	if code == 0 || !strings.Contains(out, "recorded, not applied") || posts.Load() == 0 {
		t.Fatalf("add with the server refusing posts: %d %s (posts %d)", code, out, posts.Load())
	}
	if x.ak(0) != x.orig[0] {
		t.Fatal("a host was touched before the record committed")
	}
	if l := x.list(x.laptop); len(l.Access) != 1 || len(l.Marks) != 1 {
		t.Fatalf("the queued record: %+v", l)
	}
	// Still refused: the resume doesn't act on the queued record.
	code, out = x.hop(x.laptop, "access", "add", "alice", "--json")
	if code == 0 || !strings.Contains(out, "recorded, not applied") || x.ak(0) != x.orig[0] {
		t.Fatalf("resume while queued: %d %s", code, out)
	}
	x.setIntercept(nil)
	code, out = x.hop(x.laptop, "access", "add", "alice", "--json")
	if res := decodeRun(out); code != 0 || targetStates(res)["web-1"] != model.AccessInstalled {
		t.Fatalf("resume once the server takes posts: %d %s", code, out)
	}
	if !strings.Contains(x.ak(0), "hop-access:") {
		t.Fatal("no line")
	}
}

// A result put that holds because another device changed the record
// meanwhile: the run says so and suggests hop sync resolve and hop access
// check; Take theirs discards it, check finds the host ahead of the
// record, and the next rm records removed without writing.
func TestAccessPublishedHeldResultIsDiscarded(t *testing.T) {
	x := newPubAccess(t, 2)
	h := installHooks(t)
	wh := &withholder{st: x.w.st, device: x.deviceID(x.laptop)}
	x.setIntercept(wh.serve)
	if code, _ := x.add(x.desk, "alice", "web-1", "web-2"); code != 0 {
		t.Fatal("add")
	}
	waitFor(t, 15*time.Second, "the laptop has alice", func() bool { return x.record(x.laptop, "alice") != nil })
	a := x.record(x.laptop, "alice")
	// The laptop's rm of web-1 is held before it records: the server
	// serves the laptop the head it has from then on, and the desk
	// removes web-2 meanwhile. The laptop's result is built on the state
	// before the desk's change.
	h.on("before-record", a.RecordID, func() {
		wh.freeze(t)
		if code, _ := x.hop(x.desk, "access", "rm", "alice", "web-2", "--yes", "--json"); code != 0 {
			t.Error("the desk's rm")
		}
	})
	code, out := x.hop(x.laptop, "access", "rm", "alice", "web-1", "--yes", "--json")
	res := decodeRun(out)
	if len(res.Targets) != 1 || !res.Targets[0].Recorded || res.Targets[0].State != model.AccessRemoved {
		t.Fatalf("the laptop's rm: %d %s", code, out)
	}
	wh.unfreeze()
	x.hop(x.laptop, "sync")
	waitFor(t, 20*time.Second, "the laptop's result put holds", func() bool { return x.laptop.syncStatus(t).Held == 1 })
	code, out = x.hop(x.laptop, "sync", "resolve", "--json")
	var held daemon.SyncHeldResult
	if i := strings.Index(out, "{"); code != 0 || i < 0 || json.Unmarshal([]byte(out[i:]), &held) != nil || len(held.Held) != 1 || held.Held[0].Type != model.TypeAccess {
		t.Fatalf("hop sync resolve: %d %s", code, out)
	}
	n := fmt.Sprint(held.Held[0].N)
	if code, out := x.hop(x.laptop, "sync", "resolve", n, "--take-theirs", "--yes"); code != 0 || !strings.Contains(out, "run hop access check") {
		t.Fatalf("take theirs: %d %s", code, out)
	}
	if st := x.laptop.syncStatus(t); st.Held != 0 || st.Pending != 0 {
		t.Fatalf("after take theirs: %+v", st)
	}
	// The vault says web-1 is removing; the host has the tombstone.
	code, fs := x.check(x.laptop)
	if code != 1 || kinds(fs)["tombstone-not-removed"] != 1 || kinds(fs)["unfinished-target"] != 1 {
		t.Fatalf("check: %d %+v", code, fs)
	}
	before := x.ak(0)
	code, out = x.hop(x.laptop, "access", "rm", "alice", "--yes", "--json")
	if res := decodeRun(out); code != 0 || !res.Deleted || x.ak(0) != before {
		t.Fatalf("rm after take theirs: %d %s", code, out)
	}
}

// withholder serves one device an old prefix of the log: once frozen is
// set, every GET of the log made with a session of that device gets the
// entries up to frozen and frozen as the head. Sessions are mapped to
// devices through the server's session table.
type withholder struct {
	st     *server.SQLite
	device model.ID
	mu     sync.Mutex
	frozen json.RawMessage // the head to serve; nil: serve everything
	last   json.RawMessage // the last head the device was served
}

type logPageJSON struct {
	Entries []struct {
		Seq string `json:"seq"`
	} `json:"entries"`
	Head json.RawMessage `json:"head"`
}

// deviceOf is the device whose session the request carries.
func (wh *withholder) deviceOf(req *http.Request) model.ID {
	tok, ok := strings.CutPrefix(req.Header.Get("Authorization"), "Bearer ")
	if !ok {
		return model.ID{}
	}
	var raw []byte
	for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
		if b, err := enc.DecodeString(tok); err == nil {
			raw = b
			break
		}
	}
	var dev model.ID
	wh.st.View(req.Context(), func(tx server.Tx) error {
		if sess, err := tx.Session(crypto.SHA256(raw)); err == nil {
			dev = sess.DeviceID
		}
		return nil
	})
	return dev
}

func (wh *withholder) serve(rw http.ResponseWriter, req *http.Request, next http.Handler) bool {
	if req.Method != http.MethodGet || !strings.HasSuffix(req.URL.Path, "/log") || wh.deviceOf(req) != wh.device {
		return false
	}
	rec := httptest.NewRecorder()
	next.ServeHTTP(rec, req)
	body := rec.Body.Bytes()
	// Read when the answer is ready: a long-poll that started before the
	// freeze is held back too.
	wh.mu.Lock()
	frozen := wh.frozen
	wh.mu.Unlock()
	if rec.Code == http.StatusOK {
		var full map[string]json.RawMessage
		var page logPageJSON
		if json.Unmarshal(body, &full) == nil && json.Unmarshal(body, &page) == nil {
			if frozen == nil {
				wh.mu.Lock()
				wh.last = page.Head
				wh.mu.Unlock()
			} else {
				var fh struct {
					Seq string `json:"seq"`
				}
				json.Unmarshal(frozen, &fh)
				var entries []json.RawMessage
				json.Unmarshal(full["entries"], &entries)
				kept := []json.RawMessage{}
				for i, e := range entries {
					if i < len(page.Entries) && lessSeq(page.Entries[i].Seq, fh.Seq) {
						kept = append(kept, e)
					}
				}
				full["entries"], _ = json.Marshal(kept)
				full["head"] = frozen
				body, _ = json.Marshal(full)
				if len(kept) == 0 {
					time.Sleep(300 * time.Millisecond) // no hot loop of long-polls
				}
			}
		}
	}
	for k, v := range rec.Header() {
		if k != "Content-Length" {
			rw.Header()[k] = v
		}
	}
	rw.WriteHeader(rec.Code)
	rw.Write(body)
	return true
}

// unfreeze serves the device the whole log again.
func (wh *withholder) unfreeze() {
	wh.mu.Lock()
	defer wh.mu.Unlock()
	wh.frozen = nil
}

// deviceID is dv's device ID, as its daemon reports it.
func (x *pubAccess) deviceID(dv *device) model.ID {
	t := x.t
	t.Helper()
	var st daemon.StatusResult
	dv.must(t, daemon.OpStatus, nil, &st)
	if st.Vault == nil {
		t.Fatalf("no vault in %s's status", dv.name)
	}
	id, err := model.ParseID(st.Vault.DeviceID)
	if err != nil {
		t.Fatalf("%s's device ID %q: %v", dv.name, st.Vault.DeviceID, err)
	}
	return id
}

// freeze serves the device, from now on, the head it was last served.
func (wh *withholder) freeze(t *testing.T) {
	t.Helper()
	wh.mu.Lock()
	defer wh.mu.Unlock()
	if wh.last == nil {
		t.Fatal("the device has not pulled yet")
	}
	wh.frozen = wh.last
}

// lessSeq is a ≤ b for decimal seqs.
func lessSeq(a, b string) bool {
	if len(a) != len(b) {
		return len(a) < len(b)
	}
	return a <= b
}

// The stale-prefix walk-through of §7.7 (outside C2, still safe). The
// laptop commits alice pending on web-1 and is cut off before its session.
// The desk removes it: removing/gen 2, a tombstone, removed, and the
// record deleted. The server then serves the laptop the prefix it had, so
// its fence passes; the add reads the tombstone and writes nothing, and
// check on the laptop reports the host's tombstone against its state.
func TestAccessPublishedStalePrefixTombstoneBlocksTheAdd(t *testing.T) {
	x := newPubAccess(t, 1)
	h := installHooks(t)
	wh := &withholder{st: x.w.st, device: x.deviceID(x.laptop)}
	x.setIntercept(wh.serve)
	// The laptop's add commits pending, then can't reach the host.
	h.on("before-session", model.ID{}, func() { x.srv[0].down.Store(true) })
	if code, _ := x.add(x.laptop, "alice", "web-1"); code == 0 {
		t.Fatal("the laptop's add reached the host")
	}
	x.srv[0].down.Store(false)
	a := x.record(x.laptop, "alice")
	if a == nil || a.Targets[0].State != model.AccessPending {
		t.Fatalf("the laptop's record %+v", a)
	}
	x.laptop.must(t, daemon.OpSyncNow, nil, nil)
	// From here the server serves the laptop the head it has.
	wh.freeze(t)
	waitFor(t, 15*time.Second, "the desk has alice", func() bool { return x.record(x.desk, "alice") != nil })
	code, out := x.hop(x.desk, "access", "rm", "alice", "--yes", "--json")
	if res := decodeRun(out); code != 0 || !res.Deleted {
		t.Fatalf("the desk's rm: %d %s", code, out)
	}
	tomb := fmt.Sprintf("# hop-access-removed %s 2\n", a.RecordID)
	if x.ak(0) != x.orig[0]+tomb {
		t.Fatalf("after the desk's rm: %q", x.ak(0))
	}
	// The laptop still sees alice pending at gen 1.
	if r := x.record(x.laptop, "alice"); r == nil || r.Targets[0].State != model.AccessPending {
		t.Fatalf("the laptop is not stale: %+v", r)
	}
	code, out = x.hop(x.laptop, "access", "add", "alice", "--json")
	res := decodeRun(out)
	if code == 0 || len(res.Targets) != 1 || !strings.Contains(res.Targets[0].Message, "was removed here (gen 2)") {
		t.Fatalf("the stale add: %d %s", code, out)
	}
	if x.ak(0) != x.orig[0]+tomb {
		t.Fatalf("the stale add wrote: %q", x.ak(0))
	}
	code, fs := x.check(x.laptop)
	if code != 1 || kinds(fs)["tombstone-not-removed"] != 1 {
		t.Fatalf("check on the stale laptop: %d %+v", code, fs)
	}
	for _, f := range fs {
		if strings.Contains(f.Fix, "hop access add") {
			t.Errorf("check offers add over a tombstone: %+v", f)
		}
	}
}
