package daemon

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/dalyem/hopkey/internal/model/modeltest"
	"github.com/dalyem/hopkey/internal/procs"
)

// Environment of this test binary run as hop session attach (TestMain):
// the file it writes the daemon's answer to, and whether it then stays,
// to hold up the ssh that runs it as its ProxyCommand.
const (
	attachOutVar  = "HOPKEY_TEST_ATTACH_OUT"
	attachHoldVar = "HOPKEY_TEST_ATTACH_HOLD"
)

// TestMain runs this binary as hop session attach --control SOCKET ALIAS
// when it is called that way (cli.SessionAttach).
func TestMain(m *testing.M) {
	if len(os.Args) >= 3 && os.Args[1] == "session" && os.Args[2] == "attach" {
		var sock, alias string
		for i := 3; i < len(os.Args); i++ {
			if os.Args[i] == "--control" && i+1 < len(os.Args) {
				i++
				sock = os.Args[i]
			} else {
				alias = os.Args[i]
			}
		}
		res := "ok"
		if err := Attach(sock, alias); err != nil {
			res = err.Error()
		}
		if out := os.Getenv(attachOutVar); out != "" {
			os.WriteFile(out, []byte(res), 0o600)
		}
		if os.Getenv(attachHoldVar) != "" {
			time.Sleep(time.Minute)
		}
		os.Exit(0)
	}
	os.Exit(m.Run())
}

// proc is a process a test started: an ssh, or something else.
type proc struct {
	cmd  *exec.Cmd
	done chan struct{}
	err  error
	log  string
}

// startProc starts name with args; env is added to this process's
// environment, which loses its own SSH_AUTH_SOCK.
func startProc(t *testing.T, env []string, name string, args ...string) *proc {
	t.Helper()
	path, err := exec.LookPath(name)
	if err != nil {
		if os.Getenv("HOPKEY_REQUIRE_SSH") != "" {
			t.Fatalf("%s not found and HOPKEY_REQUIRE_SSH is set: %v", name, err)
		}
		t.Skipf("no %s on PATH", name)
	}
	errFile := filepath.Join(t.TempDir(), "stderr")
	f, err := os.Create(errFile)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	cmd := exec.Command(path, args...)
	for _, kv := range os.Environ() {
		if !strings.HasPrefix(kv, "SSH_AUTH_SOCK=") {
			cmd.Env = append(cmd.Env, kv)
		}
	}
	cmd.Env = append(cmd.Env, env...)
	// A file, not a pipe: a child may hold stderr open after it ends.
	cmd.Stderr = f
	// Its own group, so its children go with it at the end.
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	p := &proc{cmd: cmd, done: make(chan struct{}), log: errFile}
	go func() {
		p.err = cmd.Wait()
		close(p.done)
	}()
	t.Cleanup(func() {
		syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
		<-p.done
	})
	return p
}

func (p *proc) running() bool {
	select {
	case <-p.done:
		return false
	default:
		return true
	}
}

func (p *proc) stderr() string {
	b, _ := os.ReadFile(p.log)
	return string(b)
}

// waitEnd waits for p to end and says how: "signal: hangup" for one the
// daemon ended with SIGHUP.
func (p *proc) waitEnd(t *testing.T, within time.Duration, what string) string {
	t.Helper()
	select {
	case <-p.done:
		return p.err.Error()
	case <-time.After(within):
		t.Fatalf("%s still runs after %v", what, within)
		return ""
	}
}

// hungUp says a process ended on SIGHUP: killed by it, or ssh's own exit
// 255 once it caught it.
func hungUp(how string) bool { return how == "signal: hangup" || how == "exit status 255" }

// self is this test binary, which runs as hop session attach (TestMain).
func self(t *testing.T) string {
	t.Helper()
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	return exe
}

// waitAttach waits for the hop session attach that writes out to finish,
// and returns the daemon's answer: "ok", or why it refused.
func waitAttach(t *testing.T, out string) string {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for {
		if b, err := os.ReadFile(out); err == nil && len(b) > 0 {
			return string(b)
		}
		if time.Now().After(deadline) {
			t.Fatal("hop session attach never answered")
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// attachedSSH is a real ssh whose child is hop session attach for alias,
// as LocalCommand makes it once ssh has logged in. There is no server to
// log in to, so the child is its ProxyCommand, which ssh runs the same
// way (exec, through the shell), and which stays to hold the ssh up. It
// returns once the daemon has answered, and that answer.
func attachedSSH(t *testing.T, sock, alias string) (*proc, string) {
	t.Helper()
	out := filepath.Join(t.TempDir(), "attach")
	proxy := fmt.Sprintf("ProxyCommand=%s session attach --control %s %s", self(t), sock, alias)
	p := startProc(t, []string{attachOutVar + "=" + out, attachHoldVar + "=1"},
		"ssh", "-F", "/dev/null", "-o", "BatchMode=yes", "-o", proxy, alias)
	return p, waitAttach(t, out)
}

// registered is the PIDs the daemon holds as sessions.
func registered(d *Daemon) []int {
	s := d.sessions
	s.mu.Lock()
	defer s.mu.Unlock()
	var pids []int
	for pid := range s.reg {
		pids = append(pids, pid)
	}
	return pids
}

// startLocal starts a daemon over an empty local store with opts' hooks.
func startLocal(t *testing.T, opts Options) (*Daemon, *Client) {
	t.Helper()
	base := shortDir(t)
	cfgDir := opts.Paths.ConfigDir
	if cfgDir == "" {
		cfgDir = filepath.Join(base, "cfg")
	}
	opts.Paths = Paths{RunDir: filepath.Join(base, "run"), ConfigDir: cfgDir, StateDir: filepath.Join(base, "state")}
	opts.Store, opts.Version, opts.Tailscale = modeltest.New(), "test", fakeTS{}
	if opts.Logf == nil {
		opts.Logf = t.Logf
	}
	d, err := Start(opts)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { d.Close() })
	c, err := Dial(context.Background(), d.ControlSocket())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	return d, c
}

// A real ssh whose child is hop session attach is registered, and ended
// with SIGHUP; status names it by its alias, and session.ended says why,
// once.
func TestAttachedSSHIsEnded(t *testing.T) {
	d, c := startLocal(t, Options{})
	p, res := attachedSSH(t, d.ControlSocket(), "web1")
	if res != "ok" {
		t.Fatalf("the daemon refused a real ssh: %s", res)
	}
	pid := p.cmd.Process.Pid
	if got := registered(d); len(got) != 1 || got[0] != pid {
		t.Fatalf("registered %v, want the ssh, %d", got, pid)
	}
	got := <-d.endSessions(whyLock)
	if len(got) != 1 || got[0] != (EndedSession{PID: pid, Alias: "web1"}) {
		t.Errorf("ended %+v", got)
	}
	if how := p.waitEnd(t, 5*time.Second, "the attached ssh"); !hungUp(how) {
		t.Errorf("ended with %q, want SIGHUP", how)
	}
	ctx := context.Background()
	var r SessionEndedResult
	if err := c.Call(ctx, OpSessionEnded, SessionEndedParams{PID: pid}, &r); err != nil || r.Ended != whyLock {
		t.Errorf("session.ended: %+v, %v", r, err)
	}
	r = SessionEndedResult{}
	if err := c.Call(ctx, OpSessionEnded, SessionEndedParams{PID: pid}, &r); err != nil || r.Ended != "" {
		t.Errorf("session.ended a second time: %+v, %v", r, err)
	}
	if st := d.endedSessions(); st == nil || st.Count != 1 || st.Why != whyLock || st.NotEnded != 0 {
		t.Errorf("status: %+v", st)
	}
	if len(registered(d)) != 0 {
		t.Errorf("the ended session is still registered: %v", registered(d))
	}
}

// session.attach registers the caller's parent only when the kernel shows
// it is an ssh of this user: not when the caller's parent is the daemon,
// a shell, or another program named ssh. None of them is registered, so
// none is ended.
func TestAttachRefusesAParentThatIsNotSSH(t *testing.T) {
	d, _ := startLocal(t, Options{})
	sock := d.ControlSocket()
	shell, err := exec.LookPath("sh")
	if err != nil {
		t.Fatal(err)
	}
	// Another program named ssh: a copy of sh.
	fake := filepath.Join(t.TempDir(), "ssh")
	if b, err := os.ReadFile(shell); err != nil {
		t.Fatal(err)
	} else if err := os.WriteFile(fake, b, 0o755); err != nil {
		t.Fatal(err)
	}
	// The child is hop session attach, and the parent stays.
	script := `"$0" session attach --control "$1" web1; exec sleep 60`
	cases := []struct {
		name, why string
		start     func(out string) *proc
	}{
		{"a shell", "not ssh", func(out string) *proc {
			return startProc(t, []string{attachOutVar + "=" + out}, "sh", "-c", script, self(t), sock)
		}},
		{"a copy of sh named ssh", "not ssh", func(out string) *proc {
			return startProc(t, []string{attachOutVar + "=" + out}, fake, "-c", script, self(t), sock, "-F", "cfg", "web1")
		}},
	}
	var parents []*proc
	for _, c := range cases {
		out := filepath.Join(t.TempDir(), "attach")
		p := c.start(out)
		parents = append(parents, p)
		if res := waitAttach(t, out); !strings.Contains(res, c.why) {
			t.Errorf("%s: the daemon answered %q, want a refusal (%s)", c.name, res, c.why)
		}
	}
	// The caller's parent is the daemon itself.
	out := filepath.Join(t.TempDir(), "attach")
	cmd := exec.Command(self(t), "session", "attach", "--control", sock, "web1")
	cmd.Env = append(os.Environ(), attachOutVar+"="+out)
	if err := cmd.Run(); err != nil {
		t.Fatal(err)
	}
	if res := waitAttach(t, out); !strings.Contains(res, "parent is the daemon") {
		t.Errorf("a child of the daemon: the daemon answered %q", res)
	}

	if got := registered(d); len(got) != 0 {
		t.Fatalf("registered %v", got)
	}
	if got := <-d.endSessions(whyRevoked); len(got) != 0 {
		t.Errorf("ended %+v", got)
	}
	time.Sleep(200 * time.Millisecond)
	for i, p := range parents {
		if !p.running() {
			t.Errorf("%s was ended: %v", cases[i].name, p.err)
		}
	}
}

// The registration that took any process the caller named, session.start,
// is gone: a process of this user that names itself is not ended.
func TestNamedPIDIsNotRegistered(t *testing.T) {
	d, c := startLocal(t, Options{})
	p := startProc(t, nil, "sleep", "60")
	pr, err := procs.Lookup(p.cmd.Process.Pid)
	if err != nil {
		t.Fatal(err)
	}
	params := map[string]any{"pid": pr.PID, "start": pr.Start, "alias": "web1", "via": "hop exec"}
	if err := c.Call(context.Background(), "session.start", params, nil); err == nil {
		t.Error("session.start registered a PID the caller named")
	}
	if got := <-d.endSessions(whyRevoked); len(got) != 0 {
		t.Errorf("ended %+v", got)
	}
	time.Sleep(200 * time.Millisecond)
	if !p.running() {
		t.Fatalf("the named process was ended: %v", p.err)
	}
}

// register adds a running process the test started as a session, held
// by a real pin, as session.attach would.
func register(t *testing.T, d *Daemon, p *proc) {
	t.Helper()
	pr, pn, err := d.procs.Open(p.cmd.Process.Pid)
	if err != nil {
		t.Fatal(err)
	}
	if err := d.sessions.add(d, &session{proc: pr, pin: pn}); err != nil {
		t.Fatal(err)
	}
}

// A session that outlasts SIGHUP gets SIGTERM, and one that outlasts that
// too gets SIGKILL, and status says it was killed.
func TestStubbornSessionsAreKilled(t *testing.T) {
	d, _ := startLocal(t, Options{sessionTerm: 300 * time.Millisecond, sessionKill: 800 * time.Millisecond})
	noHUP := startProc(t, nil, "sh", "-c", `trap "" HUP; sleep 60; :`)
	neither := startProc(t, nil, "sh", "-c", `trap "" HUP TERM; sleep 60; :`)
	time.Sleep(500 * time.Millisecond) // the traps are set
	register(t, d, noHUP)
	register(t, d, neither)
	start := time.Now()
	got := <-d.endSessions(whyLock)
	if how := noHUP.waitEnd(t, 5*time.Second, "the shell that ignores SIGHUP"); how != "signal: terminated" {
		t.Errorf("the shell that ignores SIGHUP ended with %q", how)
	}
	if how := neither.waitEnd(t, 5*time.Second, "the shell that ignores SIGHUP and SIGTERM"); how != "signal: killed" {
		t.Errorf("the shell that ignores both ended with %q", how)
	}
	if d := time.Since(start); d < 800*time.Millisecond {
		t.Errorf("SIGKILL came after %v, before the wait for it", d)
	}
	killed := map[int]bool{}
	for _, e := range got {
		killed[e.PID] = e.Killed
	}
	if len(got) != 2 || killed[noHUP.cmd.Process.Pid] || !killed[neither.cmd.Process.Pid] {
		t.Errorf("ended %+v", got)
	}
	if st := d.endedSessions(); st == nil || st.Count != 2 {
		t.Errorf("status: %+v", st)
	} else {
		for _, e := range st.Sessions {
			if e.Killed != (e.PID == neither.cmd.Process.Pid) {
				t.Errorf("status: %+v", e)
			}
		}
	}
}

// A registered PID that has another start time now (the process ended
// and the PID was reused) is never signalled.
func TestReusedPIDIsNotSignalled(t *testing.T) {
	d, _ := startLocal(t, Options{})
	p := startProc(t, nil, "sleep", "60")
	pr, err := procs.Lookup(p.cmd.Process.Pid)
	if err != nil {
		t.Fatal(err)
	}
	pr.Start = "an earlier process"
	d.sessions.mu.Lock()
	d.sessions.reg[pr.PID] = &session{proc: pr}
	d.sessions.mu.Unlock()
	if got := <-d.endSessions(whyLock); len(got) != 0 {
		t.Errorf("ended %+v", got)
	}
	time.Sleep(200 * time.Millisecond)
	if !p.running() {
		t.Fatalf("the process that has the PID now was signalled: %v", p.err)
	}
}

// noPins is this machine's processes, but none can be pinned, as on a
// Linux with no pidfd.
type noPins struct{ sysProcs }

func (noPins) Open(int) (procs.Proc, pin, error) {
	return procs.Proc{}, nil, fmt.Errorf("%w: pidfd_open: %v", procs.ErrNoPin, syscall.ENOSYS)
}

// A session that can't be pinned is registered but never signalled: there
// is no kill(2) by PID to fall back to. Status counts it as not ended.
func TestUnpinnedSessionIsNotSignalled(t *testing.T) {
	d, _ := startLocal(t, Options{procs: noPins{}})
	p, res := attachedSSH(t, d.ControlSocket(), "web1")
	if res != "ok" {
		t.Fatalf("the daemon refused a real ssh: %s", res)
	}
	if got := registered(d); len(got) != 1 {
		t.Fatalf("registered %v", got)
	}
	if got := <-d.endSessions(whyRevoked); len(got) != 0 {
		t.Errorf("ended %+v", got)
	}
	time.Sleep(300 * time.Millisecond)
	if !p.running() {
		t.Fatalf("an unpinned session was signalled: %v\n%s", p.err, p.stderr())
	}
	if st := d.endedSessions(); st == nil || st.Count != 0 || st.NotEnded != 1 || st.Why != whyRevoked {
		t.Errorf("status: %+v", st)
	}
}

// A device that learns, online, that it was revoked ends the registered
// sessions. An ssh to the same alias through hop's config that never ran
// hop session attach (it never logged in) is not registered, and keeps
// running: nothing is found by looking at processes.
func TestRevocationEndsRegisteredSessions(t *testing.T) {
	x := newSyncSetup(t)
	x.w.start(x.n1, x.n1.st, SyncOptions{})
	x.w.start(x.n2, x.n2.st, SyncOptions{})
	x.n1.putHost(webHost("web1", x.keyID, "203.0.113.16"))
	eventually(t, 10*time.Second, "web1 reaches the laptop", func() bool { return strings.Contains(x.n2.config(), "Host web1\n") })
	cfg := filepath.Join(x.n2.paths.ConfigDir, "config")

	ended, res := attachedSSH(t, x.n2.d.ControlSocket(), "web1")
	if res != "ok" {
		t.Fatalf("the daemon refused a real ssh: %s", res)
	}
	kept := startProc(t, []string{"SSH_AUTH_SOCK=" + x.n2.d.AgentSocket()}, "ssh", "-F", cfg, "-o", "BatchMode=yes", "-o", "ProxyCommand=sleep 60", "web1")
	time.Sleep(time.Second)
	if !kept.running() {
		t.Fatalf("the unregistered ssh ended before the test: %v\n%s", kept.err, kept.stderr())
	}

	x.revokeLaptop(t)
	revoked := time.Now()
	how := ended.waitEnd(t, 20*time.Second, "the registered ssh")
	t.Logf("the registered ssh ended %v after the revoke: %s", time.Since(revoked).Round(time.Millisecond), how)
	if !hungUp(how) {
		t.Errorf("the registered ssh ended with %q, want SIGHUP", how)
	}
	time.Sleep(time.Second)
	if !kept.running() {
		t.Errorf("the unregistered ssh was ended: %v", kept.err)
	}
	var st StatusResult
	x.n2.must(OpStatus, nil, &st)
	if e := st.EndedSessions; e == nil || e.Count != 1 || e.Why != whyRevoked || e.Sessions[0] != (EndedSession{PID: ended.cmd.Process.Pid, Alias: "web1"}) {
		t.Fatalf("status: ended sessions %+v", e)
	}
}

// The max-offline policy's lock ends the sessions too: the laptop's clock
// jumps two hours past its last contact, with a one-hour policy.
func TestMaxOfflineLockEndsSessions(t *testing.T) {
	x := newSyncSetup(t)
	var skew atomic.Int64
	clock := func() time.Time { return time.Now().Add(time.Duration(skew.Load())) }
	x.w.start(x.n1, x.n1.st, SyncOptions{})
	x.w.startWith(x.n2, x.n2.st, Options{offlineEvery: 50 * time.Millisecond, now: clock})
	x.n1.putHost(webHost("web1", x.keyID, "203.0.113.16"))
	x.n1.must(OpPolicy, PolicyParams{MaxOffline: 3600}, nil)
	eventually(t, 10*time.Second, "the policy and web1 reach the laptop", func() bool {
		x.n1.call(OpSyncNow, nil, nil)
		x.n2.call(OpSyncNow, nil, nil)
		return x.n2.policy() == 3600 && strings.Contains(x.n2.config(), "Host web1\n")
	})
	p, res := attachedSSH(t, x.n2.d.ControlSocket(), "web1")
	if res != "ok" {
		t.Fatalf("the daemon refused a real ssh: %s", res)
	}

	skew.Store(int64(2 * time.Hour))
	if how := p.waitEnd(t, 15*time.Second, "ssh web1 after the max-offline lock"); !hungUp(how) {
		t.Errorf("ssh ended with %q, want SIGHUP", how)
	}
	if s := x.n2.status(); s.OfflineLocked == "" {
		t.Errorf("the vault did not lock for the policy: %+v", s)
	}
	var st StatusResult
	x.n2.must(OpStatus, nil, &st)
	if e := st.EndedSessions; e == nil || e.Count != 1 || e.Why != whyOffline {
		t.Errorf("status: ended sessions %+v", e)
	}
}

// With Hop set, each host's block in the config the daemon writes runs hop
// session attach on this daemon's control socket; without it, nothing.
func TestConfigRegistersSessionsWithHop(t *testing.T) {
	x := newSyncSetup(t)
	x.w.start(x.n1, x.n1.st, SyncOptions{})
	x.w.startWith(x.n2, x.n2.st, Options{Hop: "/opt/hop bin/hop"})
	x.n1.putHost(webHost("web1", x.keyID, "203.0.113.16"))
	eventually(t, 10*time.Second, "web1 reaches both", func() bool {
		return strings.Contains(x.n2.config(), "Host web1\n") && strings.Contains(x.n1.config(), "Host web1\n")
	})
	want := fmt.Sprintf("  PermitLocalCommand yes\n  LocalCommand exec '/opt/hop bin/hop' session attach --control '%s' web1\n", x.n2.d.ControlSocket())
	if !strings.Contains(x.n2.config(), want) {
		t.Errorf("the config with Hop has no %q:\n%s", want, x.n2.config())
	}
	if strings.Contains(x.n1.config(), "LocalCommand") {
		t.Errorf("the config without Hop has a LocalCommand:\n%s", x.n1.config())
	}
}
