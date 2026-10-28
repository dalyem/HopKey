package cli_test

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/dalyem/hopkey/internal/cli"
	"github.com/dalyem/hopkey/internal/daemon"
	"github.com/dalyem/hopkey/internal/server"
	"github.com/dalyem/hopkey/internal/store"
	"github.com/dalyem/hopkey/internal/syncclient"
)

// The two-machine test of the plan's "Done means", through the CLI entry
// point only: a real hop-server on SQLite behind httptest TLS, data
// directories of their own, and a real daemon for each, which the CLI
// stops and starts itself (Env.StartDaemon runs it in this process).

const authEmail = "me@example.com"

// authWorld is the server. down makes it look stopped: every request's
// connection is closed unanswered. hook, when set, sees each request
// first, and takes it by returning true.
type authWorld struct {
	st     *server.SQLite
	origin string
	pool   *x509.CertPool
	ts     *httptest.Server
	down   atomic.Bool
	hook   atomic.Pointer[func(http.ResponseWriter, *http.Request) bool]
}

func newAuthWorld(t *testing.T) *authWorld {
	t.Helper()
	w := &authWorld{}
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
	h := srv.Handler()
	ts.Config.Handler = http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		if w.down.Load() {
			if c, _, err := rw.(http.Hijacker).Hijack(); err == nil {
				c.Close()
			}
			return
		}
		if hook := w.hook.Load(); hook != nil && (*hook)(rw, r) {
			return
		}
		h.ServeHTTP(rw, r)
	})
	ts.StartTLS()
	// Registered first, so it runs after the daemons have closed.
	t.Cleanup(func() {
		ts.Close()
		srv.Close()
		st.Close()
	})
	pool := x509.NewCertPool()
	pool.AddCert(ts.Certificate())
	w.st, w.origin, w.pool, w.ts = st, origin, pool, ts
	return w
}

// stop and start the server, as far as the clients can tell.
func (w *authWorld) stop() {
	w.down.Store(true)
	w.ts.CloseClientConnections()
}

func (w *authWorld) start() { w.down.Store(false) }

func (w *authWorld) invite(t *testing.T) string {
	t.Helper()
	code, err := server.CreateInvite(context.Background(), w.st, authEmail, 24*time.Hour, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	return code
}

// syncBuffer is a buffer one goroutine writes while another reads it.
type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

// machine is one device: a data directory, a keychain, and the daemon
// the CLI starts on it.
type machine struct {
	name  string
	w     *authWorld
	home  string
	data  string
	paths daemon.Paths
	ring  *memRing
	// noDaemon makes the CLI's daemon starts fail, so nothing syncs.
	noDaemon atomic.Bool

	mu sync.Mutex
	d  *daemon.Daemon
}

func newMachine(t *testing.T, w *authWorld, name string) *machine {
	t.Helper()
	base := shortTemp(t)
	m := &machine{
		name: name, w: w, home: filepath.Join(base, "home"), data: filepath.Join(base, "data"),
		paths: daemon.Paths{
			RunDir: filepath.Join(base, "run"), ConfigDir: filepath.Join(base, "home", ".ssh", "hop"), StateDir: filepath.Join(base, "state"),
		},
		ring: &memRing{m: map[string]string{}},
	}
	if err := os.MkdirAll(m.home, 0o700); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		m.mu.Lock()
		defer m.mu.Unlock()
		if m.d != nil {
			m.d.Close()
		}
	})
	return m
}

// startDaemon is Env.StartDaemon: the daemon, in this process, over the
// machine's vault, trusting the test server.
func (m *machine) startDaemon(t *testing.T) func() error {
	return func() error {
		if m.noDaemon.Load() {
			return errors.New("this machine's daemon is off for the test")
		}
		s, err := store.Open(context.Background(), store.Config{DataDir: m.data, Keyring: m.ring, Getenv: func(string) string { return "" }})
		if err != nil {
			return err
		}
		d, err := daemon.Start(daemon.Options{
			Paths: m.paths, Store: s, Version: "test", Tailscale: noTailscale{},
			Logf: func(format string, args ...any) { t.Logf(m.name+" daemon: "+format, args...) },
			Sync: daemon.SyncOptions{Client: syncclient.Options{RootCAs: m.w.pool}},
		})
		if err != nil {
			s.Close()
			return err
		}
		m.mu.Lock()
		defer m.mu.Unlock()
		if m.d != nil {
			m.d.Close() // a daemon the CLI stopped; Close is idempotent
		}
		m.d = d
		return nil
	}
}

// session is how one hop command runs: on a scripted terminal, or not.
type session struct {
	tty bool
	env map[string]string
	// secrets answer ReadPassword prompts by prefix; a type-back prompt is
	// answered from the last kit printed on stdout.
	secrets map[string]string
	// answer answers a line prompt on stderr (stdin on the terminal).
	answer func(prompt string) string
	// wrongTypeBack types back something else than the kit.
	wrongTypeBack bool
	// ctx, when set, is the context the command runs under.
	ctx context.Context

	stdout, stderr syncBuffer
}

var linePrompts = []string{"Type yes or no: ", "[y/N] ", "Enter keeps only this device): ", "Enter revokes all of them): ", ": "}

// stdin feeds answers to the prompts the command writes on stderr.
type promptStdin struct {
	s       *session
	seen    int
	pending []byte
}

func (p *promptStdin) Read(b []byte) (int, error) {
	if len(p.pending) == 0 {
		deadline := time.Now().Add(60 * time.Second)
		for {
			out := p.s.stderr.String()
			if len(out) > p.seen && hasPromptSuffix(out) {
				prompt := out[strings.LastIndex(out[:len(out)-1], "\n")+1:]
				p.seen = len(out)
				if p.s.answer == nil {
					return 0, io.EOF
				}
				p.pending = []byte(p.s.answer(prompt) + "\n")
				break
			}
			if time.Now().After(deadline) {
				return 0, io.EOF
			}
			time.Sleep(10 * time.Millisecond)
		}
	}
	n := copy(b, p.pending)
	p.pending = p.pending[n:]
	return n, nil
}

func hasPromptSuffix(out string) bool {
	for _, s := range linePrompts {
		if strings.HasSuffix(out, s) {
			return true
		}
	}
	return false
}

func (m *machine) hop(t *testing.T, s *session, args ...string) int {
	t.Helper()
	if s == nil {
		s = &session{}
	}
	var stdin io.Reader = strings.NewReader("")
	if s.tty {
		stdin = &promptStdin{s: s}
	}
	env := &cli.Env{
		Stdin: stdin, Stdout: &s.stdout, Stderr: &s.stderr,
		Getenv: func(k string) string { return s.env[k] },
		Home:   m.home, Paths: m.paths, DataDir: m.data, Keyring: m.ring,
		StdinTTY: s.tty, StdoutTTY: s.tty,
		StartDaemon: m.startDaemon(t), SyncClient: syncclient.Options{RootCAs: m.w.pool},
		DialTimeout: 5 * time.Second,
		ReadPassword: func(prompt string) ([]byte, error) {
			if strings.HasPrefix(prompt, "Type the last group of your ") {
				if s.wrongTypeBack {
					return []byte("WRONG"), nil
				}
				which := strings.TrimSuffix(strings.TrimPrefix(prompt, "Type the last group of your "), ": ")
				key := ""
				for _, g := range lastGroupLine.FindAllStringSubmatch(s.stdout.String(), -1) {
					if g[1] == which {
						key = g[2]
					}
				}
				if key == "" {
					return nil, errors.New("no kit printed")
				}
				return []byte(store.LastGroup(key)), nil
			}
			for p, a := range s.secrets {
				if strings.HasPrefix(prompt, p) {
					return []byte(a), nil
				}
			}
			t.Errorf("%s: unexpected secret prompt %q", m.name, prompt)
			return nil, errors.New("no answer")
		},
	}
	parent := s.ctx
	if parent == nil {
		parent = context.Background()
	}
	ctx, cancel := context.WithTimeout(parent, 90*time.Second)
	defer cancel()
	code := cli.Run(ctx, args, env)
	t.Logf("%s: hop %s: exit %d\nstdout: %s\nstderr: %s", m.name, strings.Join(args, " "), code, redactKit(s.stdout.String()), redactKit(s.stderr.String()))
	return code
}

// must runs a command off the terminal and fails the test unless it
// exits 0.
func (m *machine) must(t *testing.T, env map[string]string, args ...string) string {
	t.Helper()
	s := &session{env: env}
	if code := m.hop(t, s, args...); code != 0 {
		t.Fatalf("%s: hop %v: exit %d: %s", m.name, args, code, s.stderr.String())
	}
	return s.stdout.String()
}

func (m *machine) hosts(t *testing.T) map[string]cli.HostView {
	t.Helper()
	var hs []cli.HostView
	decodeJSON(t, m.must(t, nil, "ls", "--json"), &hs)
	out := map[string]cli.HostView{}
	for _, h := range hs {
		out[h.Name] = h
	}
	return out
}

func (m *machine) syncState(t *testing.T) *daemon.SyncStatusResult {
	t.Helper()
	var st struct {
		Sync *daemon.SyncStatusResult `json:"sync"`
	}
	decodeJSON(t, m.must(t, nil, "status", "--json"), &st)
	if st.Sync == nil {
		t.Fatalf("%s: hop status has no sync block", m.name)
	}
	return st.Sync
}

func (m *machine) authStatus(t *testing.T) cli.AuthStatus {
	t.Helper()
	var a cli.AuthStatus
	decodeJSON(t, m.must(t, nil, "auth", "status", "--json"), &a)
	return a
}

var (
	routingLine = regexp.MustCompile(`(?m)^ +hop auth approve (\S+)$`)
	sasLine     = regexp.MustCompile(`(?m)^ +Check code: +(\d{4} \d{4})$`)
)

func sasOf(s *session) string {
	if m := sasLine.FindStringSubmatch(s.stderr.String()); m != nil {
		return m[1]
	}
	return ""
}

func kitKeys(t *testing.T, out string) (sk, rk string) {
	t.Helper()
	for _, g := range lastGroupLine.FindAllStringSubmatch(out, -1) {
		if g[1] == "Secret Key" {
			sk = g[2]
		} else {
			rk = g[2]
		}
	}
	if sk == "" || rk == "" {
		t.Fatalf("no kit in the output")
	}
	return sk, rk
}

func TestTwoMachinesEndToEnd(t *testing.T) {
	w := newAuthWorld(t)
	m1, m2 := newMachine(t, w, "m1"), newMachine(t, w, "m2")

	// Machine 1: a phase 1 vault with a host, then signup publishes it.
	initS := &session{secrets: map[string]string{"Master password: ": resolvePassword, "Repeat it: ": resolvePassword}}
	if code := m1.hop(t, initS, "init"); code != 0 {
		t.Fatalf("init: exit %d: %s", code, initS.stderr.String())
	}
	sk, rk := kitKeys(t, initS.stdout.String())
	m1.must(t, nil, "add", "web", "--address", "203.0.113.10", "--user", "deploy")

	// Without a terminal, a missing answer names its flag.
	s := &session{}
	if code := m1.hop(t, s, "auth", "signup", "--server", w.origin, "--email", authEmail); code != 255 || !strings.Contains(s.stderr.String(), "--code") {
		t.Errorf("signup without --code: exit %d, %q", code, s.stderr.String())
	}
	var su struct {
		Server  string `json:"server"`
		Created bool   `json:"created"`
		VaultID string `json:"vault_id"`
	}
	decodeJSON(t, m1.must(t, nil, "auth", "signup", "--server", w.origin, "--email", authEmail, "--code", w.invite(t), "--json"), &su)
	if su.Created || su.Server != w.origin || su.VaultID == "" {
		t.Fatalf("signup: %+v", su)
	}
	if a := m1.authStatus(t); !a.SignedIn || a.Server != w.origin || a.DeviceID == "" || a.Locked {
		t.Fatalf("m1 auth status: %+v", a)
	}

	// Machine 2 signs in by approval: it shows a routing code, machine 1
	// approves it, and each confirms the check code only once it has seen
	// that both show the same digits.
	approver, newcomer := &session{tty: true}, &session{tty: true}
	matching := func(mine, theirs *session) func(string) string {
		return func(prompt string) string {
			if !strings.HasSuffix(prompt, "Type yes or no: ") {
				t.Errorf("unexpected prompt %q", prompt)
				return ""
			}
			deadline := time.Now().Add(30 * time.Second)
			for sasOf(theirs) == "" && time.Now().Before(deadline) {
				time.Sleep(10 * time.Millisecond)
			}
			if a, b := sasOf(mine), sasOf(theirs); a == "" || a != b {
				t.Errorf("the check codes differ: %q and %q", a, b)
				return "no"
			}
			return "yes"
		}
	}
	approver.answer, newcomer.answer = matching(approver, newcomer), matching(newcomer, approver)
	var wg sync.WaitGroup
	var loginCode, approveCode int
	wg.Add(1)
	go func() {
		defer wg.Done()
		loginCode = m2.hop(t, newcomer, "login", "--server", w.origin, "--name", "m2")
	}()
	waitFor(t, 30*time.Second, "the routing code", func() bool { return routingLine.MatchString(newcomer.stderr.String()) })
	code := routingLine.FindStringSubmatch(newcomer.stderr.String())[1]
	wg.Add(1)
	go func() {
		defer wg.Done()
		approveCode = m1.hop(t, approver, "auth", "approve", code)
	}()
	wg.Wait()
	if loginCode != 0 || approveCode != 0 {
		t.Fatalf("approval: login exit %d, approve exit %d", loginCode, approveCode)
	}
	if !strings.Contains(approver.stdout.String(), "Approved m2. It receives") {
		t.Errorf("approve output: %q (want the name alone, with no empty device ID in parentheses)", approver.stdout.String())
	}

	// Machine 2 gets the host with no sync command.
	waitFor(t, 20*time.Second, "web on m2", func() bool { _, ok := m2.hosts(t)["web"]; return ok })
	m2.must(t, nil, "add", "db", "--address", "203.0.113.11")
	waitFor(t, 20*time.Second, "db on m1", func() bool { _, ok := m1.hosts(t)["db"]; return ok })

	// An edit while the server is down is queued, and goes up once it is
	// back.
	w.stop()
	m1.must(t, nil, "edit", "web", "--address", "203.0.113.12")
	if h := m1.hosts(t)["web"]; h.Mark != "pending" {
		t.Errorf("the offline edit is not marked pending: %q", h.Mark)
	}
	time.Sleep(500 * time.Millisecond)
	if h := m2.hosts(t)["web"]; len(h.Addresses) != 1 || h.Addresses[0] != "203.0.113.10" {
		t.Fatalf("m2 saw the edit while the server was down: %v", h.Addresses)
	}
	w.start()
	waitFor(t, 20*time.Second, "the offline edit on m2", func() bool {
		h := m2.hosts(t)["web"]
		return len(h.Addresses) == 1 && h.Addresses[0] == "203.0.113.12"
	})
	waitFor(t, 20*time.Second, "m1's queue drains", func() bool { return m1.syncState(t).Pending == 0 })

	// Both change the same guarded field from the same version: the
	// second to reach the server is held, and keep-mine resolves it.
	w.stop()
	m1.must(t, nil, "edit", "web", "--user", "alice")
	m2.must(t, nil, "edit", "web", "--user", "bob")
	w.start()
	var held, other *machine
	waitFor(t, 30*time.Second, "a held change", func() bool {
		switch {
		case m1.syncState(t).Held == 1:
			held, other = m1, m2
		case m2.syncState(t).Held == 1:
			held, other = m2, m1
		}
		return held != nil
	})
	mine := map[*machine]string{m1: "alice", m2: "bob"}[held]
	var hr daemon.SyncHeldResult
	decodeJSON(t, held.must(t, nil, "sync", "resolve", "--json"), &hr)
	if len(hr.Held) != 1 || hr.Held[0].KeepMine == nil || hr.Held[0].KeepMine.Confirm == "" {
		t.Fatalf("held: %+v", hr)
	}
	held.must(t, nil, "sync", "resolve", strconv.FormatUint(hr.Held[0].N, 10), "--keep-mine", "--confirm", hr.Held[0].KeepMine.Confirm)
	waitFor(t, 20*time.Second, "keep-mine reaches the other machine", func() bool { return other.hosts(t)["web"].User == mine })
	for _, m := range []*machine{m1, m2} {
		waitFor(t, 20*time.Second, m.name+"'s queue drains", func() bool { st := m.syncState(t); return st.Pending == 0 && st.Held == 0 })
	}

	// Logout needs --yes without a terminal, then leaves nothing: not
	// even what the vault decrypted into the ssh config directory.
	checkWiped := plantHopSSH(t, m2.paths.ConfigDir, m2.home)
	s = &session{}
	if code := m2.hop(t, s, "logout"); code != 255 || !strings.Contains(s.stderr.String(), "--yes") {
		t.Errorf("logout without --yes: exit %d, %q", code, s.stderr.String())
	}
	var lo struct {
		Done bool `json:"done"`
	}
	decodeJSON(t, m2.must(t, nil, "logout", "--yes", "--json"), &lo)
	if !lo.Done {
		t.Errorf("logout not done")
	}
	if a := m2.authStatus(t); a.Vault || a.SignedIn {
		t.Errorf("m2 after logout: %+v", a)
	}
	checkWiped()
	var dl daemon.DevicesResult
	waitFor(t, 20*time.Second, "m1 stops listing m2", func() bool {
		decodeJSON(t, m1.must(t, nil, "auth", "devices", "--json"), &dl)
		for _, d := range dl.Devices {
			if d.Name == "m2" {
				return false
			}
		}
		return true
	})

	// A password login on a third machine, without a terminal: the
	// secrets come from the environment.
	m3 := newMachine(t, w, "m3")
	s = &session{}
	if code := m3.hop(t, s, "login", "--method", "password", "--server", w.origin, "--email", authEmail, "--name", "m3"); code != 255 || !strings.Contains(s.stderr.String(), "HOP_PASSWORD") {
		t.Errorf("password login without secrets: exit %d, %q", code, s.stderr.String())
	}
	var li struct {
		DeviceName string `json:"device_name"`
		Method     string `json:"method"`
	}
	decodeJSON(t, m3.must(t, map[string]string{"HOP_PASSWORD": resolvePassword, "HOP_SECRET_KEY": sk},
		"login", "--method", "password", "--server", w.origin, "--email", authEmail, "--name", "m3", "--json"), &li)
	if li.DeviceName != "m3" || li.Method != "password" {
		t.Errorf("password login: %+v", li)
	}
	waitFor(t, 20*time.Second, "the hosts on m3", func() bool {
		hs := m3.hosts(t)
		return hs["web"].User == mine && len(hs["db"].Addresses) == 1
	})

	// A recovery login on a fourth: the Recovery Key alone, then the
	// mandatory checkpoint, keeping m1 and m3. Without a terminal its kit
	// can't be typed back in the same run: hop auth resume finishes it.
	m4 := newMachine(t, w, "m4")
	keep := m1.authStatus(t).DeviceID + "," + m3.authStatus(t).DeviceID
	recEnv := map[string]string{"HOP_RECOVERY_KEY": rk, "HOP_NEW_PASSWORD": "a brand new password"}
	s = &session{env: recEnv}
	if code := m4.hop(t, s, "login", "--method", "recovery", "--server", w.origin, "--email", authEmail, "--name", "m4", "--keep", keep); code != 255 || !strings.Contains(s.stderr.String(), "--yes") {
		t.Fatalf("recovery without --yes: exit %d, %q", code, s.stderr.String())
	}
	// The recovery is not finished, and hop auth passwd would finish it:
	// with --json its notice saying so is a JSON line, like all of stderr.
	s = &session{}
	if code := m4.hop(t, s, "auth", "passwd", "--json"); code != 255 {
		t.Fatalf("passwd with nothing to answer its prompts: exit %d", code)
	}
	noticed := false
	for _, line := range strings.Split(strings.TrimSpace(s.stderr.String()), "\n") {
		var v map[string]any
		if err := json.Unmarshal([]byte(line), &v); err != nil {
			t.Errorf("hop auth passwd --json wrote a line that is not JSON on stderr: %q", line)
		}
		if n, _ := v["notice"].(string); strings.Contains(n, "the new password finishes the recovery") {
			noticed = true
		}
	}
	if !noticed {
		t.Errorf("no recovery notice from hop auth passwd --json: %q", s.stderr.String())
	}
	s = &session{env: recEnv}
	if code := m4.hop(t, s, "login", "--method", "recovery", "--server", w.origin, "--email", authEmail, "--name", "m4", "--keep", keep, "--yes"); code != 255 ||
		!strings.Contains(s.stderr.String(), "HOP_KIT_CONFIRM") || !strings.Contains(s.stderr.String(), "hop auth resume") {
		t.Fatalf("recovery: exit %d, %q", code, s.stderr.String())
	}
	sk2, rk2 := kitKeys(t, s.stdout.String())
	if a := m4.authStatus(t); !a.SignedIn || !a.KitPending {
		t.Errorf("m4 before resume: %+v", a)
	}
	s = &session{env: map[string]string{"HOP_KIT_CONFIRM": "wrong groups"}}
	if code := m4.hop(t, s, "auth", "resume"); code != 255 {
		t.Errorf("resume with the wrong groups: exit %d", code)
	}
	var cr struct {
		Kind    string `json:"kind"`
		Devices []struct {
			Name string `json:"name"`
		} `json:"devices"`
	}
	decodeJSON(t, m4.must(t, map[string]string{"HOP_KIT_CONFIRM": store.LastGroup(sk2) + " " + store.LastGroup(rk2)}, "auth", "resume", "--json"), &cr)
	// The pending kit keeps the kind of the checkpoint that made it.
	if cr.Kind != store.CheckpointRecovery || len(cr.Devices) != 3 {
		t.Errorf("resume: %+v", cr)
	}
	if a := m4.authStatus(t); a.RecoveryDue || a.KitPending {
		t.Errorf("m4 after resume: %+v", a)
	}
	m4.must(t, nil, "add", "cache", "--address", "203.0.113.13")
	waitFor(t, 20*time.Second, "cache on m1, which was kept", func() bool { _, ok := m1.hosts(t)["cache"]; return ok })

	// The new device can't confirm the check code without a terminal,
	// --yes or not: it refuses before it stops the daemon or reaches the
	// server.
	m5 := newMachine(t, w, "m5")
	for _, args := range [][]string{
		{"login", "--server", w.origin, "--name", "m5", "--yes"},
		{"login", "--server", w.origin, "--name", "m5", "--yes", "--json"},
	} {
		s = &session{env: map[string]string{"HOP_KIT_CONFIRM": "yes yes"}}
		if c := m5.hop(t, s, args...); c != 255 || !strings.Contains(s.stderr.String(), "--method password") || strings.Contains(s.stderr.String(), "routing") {
			t.Errorf("%v without a terminal: exit %d, %q", args, c, s.stderr.String())
		}
	}
	if ok, _ := store.Exists(m5.data); ok {
		t.Fatal("a refused approval login left a vault")
	}

	// An approval with no terminal on the approving device. The server
	// goes away while the new device waits, and the enrollment resumes in
	// the same process. The approving device then needs --sas: the digits
	// the new device shows, which it never shows itself.
	newcomer = &session{tty: true, answer: func(prompt string) string {
		if !strings.HasSuffix(prompt, "Type yes or no: ") {
			t.Errorf("unexpected prompt %q", prompt)
			return ""
		}
		// The test carries these digits to the approving device, which
		// compares them.
		return "yes"
	}}
	var m5Code int
	wg.Add(1)
	go func() {
		defer wg.Done()
		m5Code = m5.hop(t, newcomer, "login", "--server", w.origin, "--name", "m5")
	}()
	waitFor(t, 30*time.Second, "m5's routing code", func() bool { return routingLine.MatchString(newcomer.stderr.String()) })
	code = routingLine.FindStringSubmatch(newcomer.stderr.String())[1]
	w.stop()
	waitFor(t, 30*time.Second, "the enrollment resumes", func() bool { return strings.Contains(newcomer.stderr.String(), "resuming") })
	w.start()
	approver = &session{}
	if c := m1.hop(t, approver, "auth", "approve", code); c != 255 || !strings.Contains(approver.stderr.String(), "--sas") {
		t.Fatalf("approve without a terminal or --sas: exit %d, %q", c, approver.stderr.String())
	}
	waitFor(t, 30*time.Second, "m5's check code", func() bool { return sasOf(newcomer) != "" })
	sas := strings.ReplaceAll(sasOf(newcomer), " ", "")
	if strings.Contains(approver.stdout.String()+approver.stderr.String(), sas) {
		t.Errorf("the approving device printed its check code without a terminal")
	}
	var ap struct {
		Approved struct {
			DeviceName string `json:"device_name"`
		} `json:"approved"`
	}
	decodeJSON(t, m1.must(t, nil, "auth", "approve", code, "--sas", sas[:4]+" "+sas[4:], "--json"), &ap)
	if ap.Approved.DeviceName != "m5" {
		t.Errorf("approved: %+v", ap)
	}
	wg.Wait()
	if m5Code != 0 {
		t.Fatalf("m5 login: exit %d: %s", m5Code, newcomer.stderr.String())
	}
	if !strings.Contains(newcomer.stdout.String(), "Signed in to "+w.origin+" as m5") {
		t.Errorf("m5 login: %q", newcomer.stdout.String())
	}
	waitFor(t, 20*time.Second, "cache on m5", func() bool { _, ok := m5.hosts(t)["cache"]; return ok })
}

// Signup on a machine with no vault creates one on the terminal: a new
// password, the kit typed back, and another registration code when the
// server refuses the first. A kit that is not typed back creates nothing,
// and its --kit-file goes too.
func TestSignupCreatesAVault(t *testing.T) {
	w := newAuthWorld(t)
	m := newMachine(t, w, "solo")
	kitFile := filepath.Join(shortTemp(t), "kit.txt")
	pw := map[string]string{"New master password: ": resolvePassword, "Repeat it: ": resolvePassword}

	s := &session{tty: true, secrets: pw, wrongTypeBack: true}
	if code := m.hop(t, s, "auth", "signup", "--server", w.origin, "--email", authEmail, "--code", w.invite(t), "--kit-file", kitFile); code != 255 {
		t.Fatalf("a wrong type-back: exit %d", code)
	}
	if ok, _ := store.Exists(m.data); ok {
		t.Errorf("a vault was created without its kit typed back")
	}
	if _, err := os.Lstat(kitFile); !os.IsNotExist(err) {
		t.Errorf("the kit file of a vault that does not exist is still there: %v", err)
	}

	good := w.invite(t)
	asked := 0
	s = &session{tty: true, secrets: pw, answer: func(prompt string) string {
		if !strings.Contains(prompt, "registration code") {
			t.Errorf("unexpected prompt %q", prompt)
			return ""
		}
		asked++
		return good
	}}
	if code := m.hop(t, s, "auth", "signup", "--server", w.origin, "--email", authEmail, "--code", "not-a-code", "--kit-file", kitFile); code != 0 {
		t.Fatalf("signup: exit %d: %s", code, s.stderr.String())
	}
	if asked != 1 || !strings.Contains(s.stderr.String(), "refused") {
		t.Errorf("asked %d times for another code: %q", asked, s.stderr.String())
	}
	sk, _ := kitKeys(t, s.stdout.String())
	if b, err := os.ReadFile(kitFile); err != nil || !strings.Contains(string(b), sk) {
		t.Errorf("the kit file: %v", err)
	}
	if !strings.Contains(s.stdout.String(), "Signed up") {
		t.Errorf("output: %q", s.stdout.String())
	}
	if a := m.authStatus(t); !a.SignedIn || a.Server != w.origin {
		t.Errorf("auth status: %+v", a)
	}
	// Signup again is refused: this device is signed in.
	s = &session{}
	if code := m.hop(t, s, "auth", "signup", "--server", w.origin, "--email", authEmail, "--code", "x"); code != 255 || !strings.Contains(s.stderr.String(), "already signed in") {
		t.Errorf("a second signup: exit %d, %q", code, s.stderr.String())
	}
}

// hex64 matches what a 32-byte hash prints as: the discard token, or the
// digest it is made from, which must never be shown.
var hex64 = regexp.MustCompile(`\b[0-9a-f]{64}\b`)

// hop auth merge --discard shows, takes and reports a token, and nothing
// else a hash could be: the digest of the merge's items, a verifier of
// their plaintext, is never printed, in text or JSON, in a refusal or a
// success.
func TestMergeDiscardShowsOnlyTheToken(t *testing.T) {
	w := newAuthWorld(t)
	m1, m6 := newMachine(t, w, "m1"), newMachine(t, w, "m6")
	pw := map[string]string{"Master password: ": resolvePassword, "Repeat it: ": resolvePassword}
	initS := &session{secrets: pw}
	if code := m1.hop(t, initS, "init"); code != 0 {
		t.Fatalf("init: exit %d: %s", code, initS.stderr.String())
	}
	sk, _ := kitKeys(t, initS.stdout.String())
	m1.must(t, nil, "auth", "signup", "--server", w.origin, "--email", authEmail, "--code", w.invite(t), "--json")

	// m6 has a local vault, merged into the account with no daemon to
	// upload it, then paused: its items are never imported.
	initS = &session{secrets: pw}
	if code := m6.hop(t, initS, "init"); code != 0 {
		t.Fatalf("init on m6: exit %d: %s", code, initS.stderr.String())
	}
	m6.must(t, nil, "add", "local-web", "--address", "198.51.100.7")
	m6.must(t, nil, "add", "local-db", "--address", "198.51.100.8")
	m6.noDaemon.Store(true)
	login := &session{tty: true, secrets: map[string]string{"Master password: ": resolvePassword, "Current master password: ": resolvePassword, "Secret Key": sk}}
	if code := m6.hop(t, login, "login", "--method", "password", "--merge", "--server", w.origin, "--email", authEmail, "--name", "m6"); code != 0 {
		t.Fatalf("login --merge: exit %d: %s", code, login.stderr.String())
	}
	m6.must(t, nil, "auth", "merge", "--pause", "--json")

	onlyToken := func(what, out, token string) {
		t.Helper()
		for _, h := range hex64.FindAllString(out, -1) {
			if h != token {
				t.Errorf("%s shows %s, which is not the token", what, h)
			}
		}
	}
	s := &session{}
	if code := m6.hop(t, s, "auth", "merge", "--discard", "--json"); code != 255 {
		t.Fatalf("discard without --confirm: exit %d", code)
	}
	var prop struct {
		Discard map[string]json.RawMessage `json:"discard"`
	}
	decodeJSON(t, s.stdout.String(), &prop)
	var token string
	if err := json.Unmarshal(prop.Discard["token"], &token); err != nil || !hex64.MatchString(token) {
		t.Fatalf("the proposal has no token: %s (%v)", s.stdout.String(), err)
	}
	if _, ok := prop.Discard["digest"]; ok {
		t.Errorf("the proposal has a digest: %s", s.stdout.String())
	}
	var items []json.RawMessage
	if err := json.Unmarshal(prop.Discard["items"], &items); err != nil || len(items) < 2 {
		t.Errorf("the proposal lists %d items: %s", len(items), s.stdout.String())
	}
	if !strings.Contains(s.stderr.String(), "--confirm "+token) {
		t.Errorf("the refusal does not name the token: %q", s.stderr.String())
	}
	onlyToken("--discard --json", s.stdout.String()+s.stderr.String(), token)

	s = &session{}
	if code := m6.hop(t, s, "auth", "merge", "--discard"); code != 255 || !strings.Contains(s.stdout.String(), "--confirm "+token) {
		t.Fatalf("discard in text: exit %d, %q", code, s.stdout.String())
	}
	onlyToken("--discard", s.stdout.String()+s.stderr.String(), token)

	// Another token confirms nothing.
	s = &session{}
	if code := m6.hop(t, s, "auth", "merge", "--discard", "--confirm", strings.Repeat("0", 64)); code != 255 || !strings.Contains(s.stderr.String(), "is not a token") {
		t.Errorf("discard with a zero token: exit %d, %q", code, s.stderr.String())
	}
	s = &session{}
	if code := m6.hop(t, s, "auth", "merge", "--discard", "--confirm", strings.Repeat("1", 64)); code != 255 || !strings.Contains(s.stderr.String(), "changed since that token was shown") {
		t.Errorf("discard with another token: exit %d, %q", code, s.stderr.String())
	}

	s = &session{}
	if code := m6.hop(t, s, "auth", "merge", "--discard", "--confirm", token, "--json"); code != 0 {
		t.Fatalf("discard with the token: exit %d, %q %q", code, s.stdout.String(), s.stderr.String())
	}
	var done struct {
		Done string `json:"done"`
	}
	if decodeJSON(t, s.stdout.String(), &done); done.Done != "discarded" {
		t.Errorf("discard with the token: %s", s.stdout.String())
	}
	onlyToken("the discard's report", s.stdout.String()+s.stderr.String(), token)
	var left map[string]any
	if decodeJSON(t, m6.must(t, nil, "auth", "merge", "--json"), &left); left["merge"] != nil {
		t.Errorf("a merge is left after the discard: %v", left)
	}
}

// SIGINT while a hop auth flow waits on the server: the request is cut
// short, the flow fails and returns, its release starts the daemon again,
// and hop exits 130 rather than with the flow's failure.
func TestInterruptedRequestExits130(t *testing.T) {
	w := newAuthWorld(t)
	m := newMachine(t, w, "solo")
	initS := &session{secrets: map[string]string{"Master password: ": resolvePassword, "Repeat it: ": resolvePassword}}
	if code := m.hop(t, initS, "init"); code != 0 {
		t.Fatalf("init: exit %d: %s", code, initS.stderr.String())
	}
	m.must(t, nil, "auth", "signup", "--server", w.origin, "--email", authEmail, "--code", w.invite(t), "--json")

	ctx, interrupt := context.WithCancelCause(context.Background())
	var claims atomic.Int32
	hook := func(rw http.ResponseWriter, r *http.Request) bool {
		if r.URL.Path != "/v1/enroll/claim" {
			return false
		}
		claims.Add(1)
		// Read to the end, so the server notices when the client hangs up.
		io.Copy(io.Discard, r.Body)
		interrupt(cli.ErrInterrupted) // the signal, while the request waits
		select {
		case <-r.Context().Done(): // the client gave up on it
		case <-time.After(10 * time.Second):
		}
		return true
	}
	w.hook.Store(&hook)
	s := &session{ctx: ctx}
	code := m.hop(t, s, "auth", "approve", "ABCD-EFGH", "--sas", "12345678")
	w.hook.Store(nil)
	if code != cli.ExitInterrupted {
		t.Errorf("exit %d, want %d: %s", code, cli.ExitInterrupted, s.stderr.String())
	}
	if claims.Load() == 0 {
		t.Fatalf("%d claims reached the server; the test did not interrupt a request", claims.Load())
	}
	c, err := daemon.Dial(context.Background(), m.paths.ControlSocket())
	if err != nil {
		t.Fatalf("the daemon did not start again: %v", err)
	}
	c.Close()
}
