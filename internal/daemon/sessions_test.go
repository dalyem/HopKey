package daemon

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/dalyem/hopkey/internal/model/modeltest"
	"github.com/dalyem/hopkey/internal/procs"
)

// sshProc is a real ssh that hangs before it logs in: its ProxyCommand is
// a sleep that never answers, so it stays connected to nothing for a
// minute. env is added to this process's environment, which loses its own
// SSH_AUTH_SOCK.
type sshProc struct {
	cmd  *exec.Cmd
	done chan struct{}
	err  error
	log  string
}

func startProc(t *testing.T, env []string, name string, args ...string) *sshProc {
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
	// A file, not a pipe: the ProxyCommand holds stderr open after ssh ends.
	cmd.Stderr = f
	// Its own group, so the ProxyCommand sleep goes with it at the end.
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	p := &sshProc{cmd: cmd, done: make(chan struct{}), log: errFile}
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

// ssh runs it with exec itself.
const hangProxy = "ProxyCommand=sleep 60"

func hangingSSH(t *testing.T, env []string, args ...string) *sshProc {
	t.Helper()
	return startProc(t, env, "ssh", append([]string{"-o", "BatchMode=yes", "-o", hangProxy}, args...)...)
}

func (p *sshProc) running() bool {
	select {
	case <-p.done:
		return false
	default:
		return true
	}
}

func (p *sshProc) stderr() string {
	b, _ := os.ReadFile(p.log)
	return string(b)
}

// waitEnd waits for p to end and says how: "signal: hangup" for one the
// daemon ended with SIGHUP.
func (p *sshProc) waitEnd(t *testing.T, within time.Duration, what string) string {
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

func allRunning(t *testing.T, ps map[string]*sshProc) {
	t.Helper()
	time.Sleep(time.Second)
	for name, p := range ps {
		if !p.running() {
			t.Fatalf("%s ended before the test: %v\n%s", name, p.err, p.stderr())
		}
	}
}

// A device that learns, online, that it was revoked ends the plain ssh
// sessions that use hop: the one to a hop alias through hop's config, and
// one whose SSH_AUTH_SOCK is hop's agent. An ssh to another destination,
// one that reads another config, and a process that is not ssh but names
// the alias keep running.
func TestRevocationEndsPlainSSHThroughHop(t *testing.T) {
	x := newSyncSetup(t)
	x.w.start(x.n1, x.n1.st, SyncOptions{})
	x.w.start(x.n2, x.n2.st, SyncOptions{})
	x.n1.putHost(webHost("web1", x.keyID, "203.0.113.16"))
	eventually(t, 10*time.Second, "web1 reaches the laptop", func() bool { return strings.Contains(x.n2.config(), "Host web1\n") })
	cfg := filepath.Join(x.n2.paths.ConfigDir, "config")

	end := map[string]*sshProc{
		"ssh web1 with hop's config": hangingSSH(t, nil, "-F", cfg, "web1"),
		"ssh with hop's agent":       hangingSSH(t, []string{"SSH_AUTH_SOCK=" + x.n2.d.AgentSocket()}, "-F", "/dev/null", "other.example"),
	}
	keep := map[string]*sshProc{
		"ssh to another destination":   hangingSSH(t, nil, "-F", cfg, "other.example"),
		"ssh web1 with another config": hangingSSH(t, nil, "-F", "/dev/null", "web1"),
		"sh naming web1":               startProc(t, nil, "sh", "-c", "sleep 60", "ssh", "web1"),
	}
	allRunning(t, end)
	allRunning(t, keep)

	x.revokeLaptop(t)
	revoked := time.Now()
	for name, p := range end {
		how := p.waitEnd(t, 20*time.Second, name)
		t.Logf("%s ended %v after the revoke: %s", name, time.Since(revoked).Round(time.Millisecond), how)
		if !hungUp(how) {
			t.Errorf("%s ended with %q, want SIGHUP", name, how)
		}
	}
	time.Sleep(time.Second)
	for name, p := range keep {
		if !p.running() {
			t.Errorf("%s was ended: %v", name, p.err)
		}
	}
	var st StatusResult
	x.n2.must(OpStatus, nil, &st)
	if e := st.EndedSessions; e == nil || e.Count != 2 || e.Why != whyRevoked {
		t.Fatalf("status: ended sessions %+v", e)
	}
	for _, s := range st.EndedSessions.Sessions {
		if s.Via != "ssh" || (s.Alias != "web1" && s.Alias != "other.example") {
			t.Errorf("ended session %+v", s)
		}
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
	p := hangingSSH(t, nil, "-F", filepath.Join(x.n2.paths.ConfigDir, "config"), "web1")
	allRunning(t, map[string]*sshProc{"ssh web1": p})

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

// startLocal starts a daemon over an empty local store with opts' hooks.
func startLocal(t *testing.T, opts Options) (*Daemon, *Client) {
	t.Helper()
	base := shortDir(t)
	cfgDir := opts.Paths.ConfigDir
	if cfgDir == "" {
		cfgDir = filepath.Join(base, "cfg")
	}
	opts.Paths = Paths{RunDir: filepath.Join(base, "run"), ConfigDir: cfgDir, StateDir: filepath.Join(base, "state")}
	opts.Store, opts.Version, opts.Tailscale, opts.Logf = modeltest.New(), "test", fakeTS{}, t.Logf
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

// A registered session is checked against its process: one whose start
// time is not the process's is refused, and one that matches is ended
// with SIGHUP and reported.
func TestRegisteredSessionIsEnded(t *testing.T) {
	d, c := startLocal(t, Options{})
	p := startProc(t, nil, "sleep", "60")
	pr, err := procs.Lookup(p.cmd.Process.Pid)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	bad := SessionParams{PID: pr.PID, Start: pr.Start + "1", Alias: "web1", Via: "hop exec"}
	if err := c.Call(ctx, OpSessionStart, bad, nil); !IsCode(err, CodeInvalid) {
		t.Fatalf("a wrong start time was registered: %v", err)
	}
	if err := c.Call(ctx, OpSessionStart, SessionParams{PID: pr.PID, Start: pr.Start, Alias: "web1", Via: "hop exec"}, nil); err != nil {
		t.Fatal(err)
	}
	got := <-d.endSessions(whyLock)
	if len(got) != 1 || got[0] != (EndedSession{PID: pr.PID, Alias: "web1", Via: "hop exec"}) {
		t.Errorf("ended %+v", got)
	}
	if how := p.waitEnd(t, 5*time.Second, "the registered sleep"); how != "signal: hangup" {
		t.Errorf("ended with %q", how)
	}
}

// A session that outlasts SIGHUP gets SIGTERM, and one that outlasts that
// too gets SIGKILL, and status says it was killed.
func TestStubbornSessionsAreKilled(t *testing.T) {
	d, c := startLocal(t, Options{sessionTerm: 300 * time.Millisecond, sessionKill: 800 * time.Millisecond})
	ctx := context.Background()
	register := func(p *sshProc) {
		t.Helper()
		pr, err := procs.Lookup(p.cmd.Process.Pid)
		if err != nil {
			t.Fatal(err)
		}
		if err := c.Call(ctx, OpSessionStart, SessionParams{PID: pr.PID, Start: pr.Start, Via: "hop exec"}, nil); err != nil {
			t.Fatal(err)
		}
	}
	noHUP := startProc(t, nil, "sh", "-c", `trap "" HUP; sleep 60; :`)
	neither := startProc(t, nil, "sh", "-c", `trap "" HUP TERM; sleep 60; :`)
	allRunning(t, map[string]*sshProc{"noHUP": noHUP, "neither": neither})
	register(noHUP)
	register(neither)
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
	d.sessions.mu.Lock()
	d.sessions.reg[pr.PID] = SessionParams{PID: pr.PID, Start: "an earlier process", Via: "hop exec"}
	d.sessions.mu.Unlock()
	if got := <-d.endSessions(whyLock); len(got) != 0 {
		t.Errorf("ended %+v", got)
	}
	time.Sleep(200 * time.Millisecond)
	if !p.running() {
		t.Fatalf("the process that has the PID now was signalled: %v", p.err)
	}
	// The last check is the signal's own: a PID reused between the scan
	// and the signal is not signalled either.
	stale := pr
	stale.Start += "1"
	if err := procs.Signal(stale, syscall.SIGHUP); !errors.Is(err, procs.ErrGone) {
		t.Errorf("Signal with another start time: %v", err)
	}
	time.Sleep(200 * time.Millisecond)
	if !p.running() {
		t.Fatalf("procs.Signal signalled a reused PID: %v", p.err)
	}
}

// fakeProcs is a process table with processes of other users in it; the
// ones signalled end at once.
type fakeProcs struct {
	mu       sync.Mutex
	list     []procs.Proc
	signaled []int
}

func (f *fakeProcs) Lookup(pid int) (procs.Proc, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if slices.Contains(f.signaled, pid) {
		return procs.Proc{}, procs.ErrGone
	}
	for _, p := range f.list {
		if p.PID == pid {
			return p, nil
		}
	}
	return procs.Proc{}, procs.ErrGone
}

func (f *fakeProcs) List(int) ([]procs.Proc, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.list), nil
}

func (f *fakeProcs) Signal(p procs.Proc, sig syscall.Signal) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if slices.Contains(f.signaled, p.PID) {
		return procs.ErrGone
	}
	f.signaled = append(f.signaled, p.PID)
	return nil
}

// Only ssh processes of this user that use hop are ended, whatever else
// the process table shows. hop's config is ~/.ssh/hop/config here, so an
// ssh with no -F reads it.
func TestOnlyThisUsersSSHThroughHopIsEnded(t *testing.T) {
	home := shortDir(t)
	t.Setenv("HOME", home)
	f := &fakeProcs{}
	d, _ := startLocal(t, Options{procs: f, Paths: Paths{ConfigDir: filepath.Join(home, ".ssh", "hop")}})
	if err := os.MkdirAll(d.opts.Paths.ConfigDir, 0o700); err != nil {
		t.Fatal(err)
	}
	cfg := filepath.Join(d.opts.Paths.ConfigDir, "config")
	if err := os.WriteFile(cfg, []byte("# Generated by hop\n\nHost web1\n  HostName 203.0.113.16\n\nHost Db-2\n  HostName 203.0.113.17\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	me, other := os.Getuid(), os.Getuid()+1
	proc := func(pid, uid int, exe, sock string, args ...string) procs.Proc {
		return procs.Proc{PID: pid, UID: uid, EUID: uid, Start: "s", Exe: exe, Args: args, AgentSocket: sock}
	}
	f.list = []procs.Proc{
		proc(1001, me, "ssh", "", "ssh", "web1"),
		proc(1002, me, "ssh", "", "ssh", "-l", "deploy", "-p22", "-tt", "db-2", "uptime"),
		proc(1003, me, "ssh", "", "ssh", "-F", cfg, "-o", "BatchMode=yes", "--", "deploy@web1"),
		proc(1004, me, "ssh", d.AgentSocket(), "ssh", "elsewhere.example"),
		proc(1005, me, "ssh", "", "ssh", "ssh://ops@web1:2222"),
		// Never: another user, as real or effective user; not ssh; not
		// hop's destination; another config; exited.
		proc(2001, other, "ssh", d.AgentSocket(), "ssh", "web1"),
		{PID: 2002, UID: me, EUID: other, Start: "s", Exe: "ssh", Args: []string{"ssh", "web1"}},
		proc(2003, me, "bash", d.AgentSocket(), "ssh", "web1"),
		proc(2004, me, "ssh", "", "ssh", "elsewhere.example"),
		proc(2005, me, "ssh", "", "ssh", "-F", "/home/me/.ssh/other", "web1"),
		proc(2006, me, "ssh", "", "ssh", "-o", "web1", "elsewhere.example"),
		{PID: 2007, UID: me, EUID: me, Start: "s", Exe: "ssh", Args: []string{"ssh", "web1"}, Exited: true},
		proc(os.Getpid(), me, "ssh", d.AgentSocket(), "ssh", "web1"),
	}
	got := <-d.endSessions(whyRevoked)
	ended := func(got []EndedSession) []int {
		var pids []int
		for _, e := range got {
			pids = append(pids, e.PID)
		}
		return pids
	}
	pids := ended(got)
	if want := []int{1001, 1002, 1003, 1004, 1005}; !slices.Equal(pids, want) {
		t.Errorf("ended %v, want %v", pids, want)
	}
	slices.Sort(f.signaled)
	if want := []int{1001, 1002, 1003, 1004, 1005}; !slices.Equal(f.signaled, want) {
		t.Errorf("signalled %v, want %v", f.signaled, want)
	}
	if st := d.endedSessions(); st == nil || st.Count != 5 || st.Why != whyRevoked || st.Sessions[1].Alias != "db-2" {
		t.Errorf("status: %+v", st)
	}

	// Under another home, hop's config is not the one ssh reads by
	// default: an ssh with no -F is not hop's.
	t.Setenv("HOME", shortDir(t))
	f.mu.Lock()
	f.signaled = nil
	f.mu.Unlock()
	if got, want := ended(<-d.endSessions(whyRevoked)), []int{1003, 1004}; !slices.Equal(got, want) {
		t.Errorf("with another home, ended %v, want %v", got, want)
	}
}

func TestSSHDestination(t *testing.T) {
	for _, c := range []struct {
		args       []string
		dest, conf string
	}{
		{[]string{"ssh", "web1"}, "web1", ""},
		{[]string{"ssh", "-v", "-p", "22", "user@web1", "ls"}, "user@web1", ""},
		{[]string{"ssh", "-vp22", "-Fcfg", "web1"}, "web1", "cfg"},
		{[]string{"ssh", "-o", "User=x", "-tt", "--", "-weird"}, "-weird", ""},
		{[]string{"ssh", "-i"}, "", ""},
		{[]string{"ssh", "-NL", "8080:localhost:80", "web1"}, "web1", ""},
		{[]string{"ssh"}, "", ""},
	} {
		dest, conf := sshDestination(c.args)
		if dest != c.dest || conf != c.conf {
			t.Errorf("%q: dest %q config %q, want %q %q", c.args, dest, conf, c.dest, c.conf)
		}
	}
	for in, want := range map[string]string{"web1": "web1", "u@web1": "web1", "ssh://u@web1:22": "web1", "a@b@web1": "web1", "": ""} {
		if got := destHost(in); got != want {
			t.Errorf("destHost(%q) = %q, want %q", in, got, want)
		}
	}
}
