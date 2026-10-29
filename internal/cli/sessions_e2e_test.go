package cli_test

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/dalyem/hopkey/internal/cli"
)

// sessionKey writes a new ed25519 key to a file hop key add reads, and
// returns the file and its signer.
func sessionKey(t *testing.T) (string, ssh.Signer) {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	block, err := ssh.MarshalPrivateKey(priv, "")
	if err != nil {
		t.Fatal(err)
	}
	f := filepath.Join(shortTemp(t), "deploy")
	if err := os.WriteFile(f, pem.EncodeToMemory(block), 0o600); err != nil {
		t.Fatal(err)
	}
	return f, signer
}

// longExec runs hop exec web-1 -- sleep on m in the background: the
// server holds that command for 30 seconds. It returns once the server
// has the command, and the channel gets hop's exit code and result.
type execEnd struct {
	code int
	res  cli.ExecResult
	at   time.Time
}

func longExec(t *testing.T, m *machine, srv *sshServer) <-chan execEnd {
	t.Helper()
	srv.reset()
	out := make(chan execEnd, 1)
	go func() {
		s := &session{}
		code := m.hop(t, s, "exec", "web-1", "--json", "--", "sleep")
		var r cli.ExecResult
		decodeJSON(t, s.stdout.String(), &r)
		out <- execEnd{code: code, res: r, at: time.Now()}
	}()
	waitSleeps(t, srv, 1)
	return out
}

// waitSleeps waits for the server to hold n sleep commands.
func waitSleeps(t *testing.T, srv *sshServer, n int) {
	t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	for {
		got := 0
		for _, c := range srv.commands() {
			if strings.HasSuffix(c, "sleep") {
				got++
			}
		}
		if got >= n {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("the server holds %d sleeps, want %d", got, n)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// stopped says the daemon ended the session (ssh exits 255 on its SIGHUP),
// long before the server would end the command, and hop exec says why.
func stopped(e execEnd, why string) bool {
	return e.code == 255 && e.res.ExitCode == 255 && e.res.DurationMS < 25_000 &&
		e.res.Error == "the hop daemon ended this ssh session when "+why
}

// plainSSH is an ssh the test runs itself, not through hop.
type plainSSH struct {
	name   string
	cmd    *exec.Cmd
	done   chan struct{}
	err    error
	stderr bytes.Buffer
	at     time.Time
}

// startPlainSSH runs ssh with args, with env added to this process's
// environment (which loses its own SSH_AUTH_SOCK).
func startPlainSSH(t *testing.T, name string, env []string, args ...string) *plainSSH {
	t.Helper()
	p := &plainSSH{name: name, done: make(chan struct{})}
	p.cmd = exec.Command("ssh", append([]string{"-o", "BatchMode=yes"}, args...)...)
	for _, kv := range os.Environ() {
		if !strings.HasPrefix(kv, "SSH_AUTH_SOCK=") {
			p.cmd.Env = append(p.cmd.Env, kv)
		}
	}
	p.cmd.Env = append(p.cmd.Env, env...)
	p.cmd.Stderr = &p.stderr
	p.cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if err := p.cmd.Start(); err != nil {
		t.Fatal(err)
	}
	go func() {
		p.err = p.cmd.Wait()
		p.at = time.Now()
		close(p.done)
	}()
	t.Cleanup(func() {
		syscall.Kill(-p.cmd.Process.Pid, syscall.SIGKILL)
		<-p.done
	})
	return p
}

func (p *plainSSH) wait(t *testing.T, within time.Duration) error {
	t.Helper()
	select {
	case <-p.done:
		return p.err
	case <-time.After(within):
		t.Fatalf("%s still runs after %v", p.name, within)
		return nil
	}
}

func writeFile(t *testing.T, path, body string) string {
	t.Helper()
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// sshG is ssh -G with args: the configuration ssh would use, lower-cased
// keywords one per line.
func sshG(t *testing.T, args ...string) string {
	t.Helper()
	out, err := exec.Command("ssh", append([]string{"-G"}, args...)...).CombinedOutput()
	if err != nil {
		t.Fatalf("ssh -G %v: %v\n%s", args, err, out)
	}
	return string(out)
}

// timeSSH is how long ssh with args takes to run true on the server, the
// best of three.
func timeSSH(t *testing.T, args ...string) time.Duration {
	t.Helper()
	best := time.Duration(1 << 62)
	for range 3 {
		start := time.Now()
		cmd := exec.Command("ssh", append(append([]string{"-o", "BatchMode=yes"}, args...), "true")...)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("ssh %v: %v\n%s", args, err, out)
		}
		best = min(best, time.Since(start))
	}
	return best
}

// A device revoked while it is online ends the ssh sessions that took
// hop's config, and only those. Ended: hop exec, an MCP exec, ssh -F with
// hop's config, and ssh with a config that includes it first. Not ended,
// though each reaches the same host under the same alias: ssh with the
// user's own config, before or after the destination, an ssh with no -F
// whose ~/.ssh/config has no Include, one where a block above the
// Include turns LocalCommand off or sets its own, one with IdentityAgent
// none and hop's agent in SSH_AUTH_SOCK, and one whose own config points
// IdentityAgent at hop's agent.
func TestRevokeEndsTheSessionsThroughHopsConfig(t *testing.T) {
	requireSSH(t)
	w := newAuthWorld(t)
	m1, m2 := newMachine(t, w, "m1"), newMachine(t, w, "m2")
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	m2.hopBin = exe
	// hop's config is ~/.ssh/hop/config of this home.
	t.Setenv("HOME", m2.home)
	initS := &session{secrets: map[string]string{"Master password: ": resolvePassword, "Repeat it: ": resolvePassword}}
	if code := m1.hop(t, initS, "init"); code != 0 {
		t.Fatalf("init: exit %d: %s", code, initS.stderr.String())
	}
	sk, _ := kitKeys(t, initS.stdout.String())
	m1.must(t, nil, "auth", "signup", "--server", w.origin, "--email", authEmail, "--code", w.invite(t), "--json")
	m2.must(t, map[string]string{"HOP_PASSWORD": resolvePassword, "HOP_SECRET_KEY": sk},
		"login", "--method", "password", "--server", w.origin, "--email", authEmail, "--name", "m2", "--json")

	keyFile, signer := sessionKey(t)
	srv := startSSHServer(t, signer.PublicKey())
	m1.must(t, nil, "key", "add", keyFile, "--name", "deploy-key")
	m1.must(t, nil, "add", "web-1", "--address", "127.0.0.1", "--port", strconv.Itoa(srv.port),
		"--user", "deploy", "--key", "deploy-key", "--host-key", authorizedKeysLine(srv.hostKey))
	m1.must(t, nil, "sync")
	deadline := time.Now().Add(30 * time.Second)
	for {
		m2.must(t, nil, "sync")
		if _, ok := m2.hosts(t)["web-1"]; ok {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("web-1 never reached m2")
		}
		time.Sleep(200 * time.Millisecond)
	}

	hopCfg := filepath.Join(m2.paths.ConfigDir, "config")
	agent := m2.paths.AgentSocket()
	dir := shortTemp(t)
	// The user's own definition of web-1: the same server, their own key
	// file, no hop.
	own := fmt.Sprintf("Host web-1\n  HostName 127.0.0.1\n  Port %d\n  User deploy\n  IdentityFile %s\n  IdentitiesOnly yes\n"+
		"  StrictHostKeyChecking no\n  UserKnownHostsFile /dev/null\n  GlobalKnownHostsFile /dev/null\n", srv.port, keyFile)
	ownCfg := writeFile(t, filepath.Join(dir, "own.conf"), own)
	// The user's config that includes hop's first, as hop setup writes it.
	inclCfg := writeFile(t, filepath.Join(dir, "incl.conf"), "Include "+hopCfg+"\n\nHost *\n  ServerAliveInterval 30\n")
	// Blocks above the Include: one turns LocalCommand off, one runs its
	// own. ssh takes the first value of each keyword.
	offCfg := writeFile(t, filepath.Join(dir, "off.conf"), "Host web-1\n  PermitLocalCommand no\n\nInclude "+hopCfg+"\n")
	ownLCCfg := writeFile(t, filepath.Join(dir, "ownlc.conf"), "Host web-1\n  LocalCommand true\n\nInclude "+hopCfg+"\n")
	// The user's own config with hop's agent as its IdentityAgent.
	viaAgentCfg := writeFile(t, filepath.Join(dir, "agent.conf"), strings.Replace(own, "  IdentityFile "+keyFile+"\n  IdentitiesOnly yes\n", "  IdentityAgent "+agent+"\n", 1))

	// What ssh takes from each config, as ssh -G says.
	wantLC := fmt.Sprintf("localcommand exec '%s' session attach --control '%s' web-1\n", exe, m2.paths.ControlSocket())
	for name, c := range map[string]struct {
		args             []string
		permit, hasLocal bool
	}{
		"hop's config":          {[]string{"-F", hopCfg, "web-1"}, true, true},
		"the Include":           {[]string{"-F", inclCfg, "web-1"}, true, true},
		"own config":            {[]string{"-F", ownCfg, "web-1"}, false, false},
		"own config after":      {[]string{"web-1", "-F", ownCfg}, false, false},
		"PermitLocalCommand no": {[]string{"-F", offCfg, "web-1"}, false, true},
		"own LocalCommand":      {[]string{"-F", ownLCCfg, "web-1"}, true, false},
	} {
		g := sshG(t, c.args...)
		if strings.Contains(g, "permitlocalcommand yes\n") != c.permit || strings.Contains(g, wantLC) != c.hasLocal {
			t.Errorf("ssh -G %s: want permitlocalcommand %v and hop's LocalCommand %v; got:\n%s", name, c.permit, c.hasLocal, g)
		}
	}

	// LocalCommand runs before the session starts, and ssh waits for it:
	// how much it adds. Starting this test binary (large, and slow under
	// the race detector) is not hop's cost, so the attach is measured
	// against the same binary run as a LocalCommand that does nothing.
	var noLC, noop []string
	for _, l := range strings.SplitAfter(m2.config(t), "\n") {
		if !strings.Contains(l, "LocalCommand") {
			noLC = append(noLC, l)
		}
		noop = append(noop, strings.Replace(l, " session attach --control ", " session noop ", 1))
	}
	noLCCfg := writeFile(t, filepath.Join(dir, "nolc.conf"), strings.Join(noLC, ""))
	noopCfg := writeFile(t, filepath.Join(dir, "noop.conf"), strings.Join(noop, ""))
	with, bare, none := timeSSH(t, "-F", hopCfg, "web-1"), timeSSH(t, "-F", noopCfg, "web-1"), timeSSH(t, "-F", noLCCfg, "web-1")
	t.Logf("ssh web-1 true: %v with hop session attach, %v with a LocalCommand that only starts the binary, %v with none",
		with.Round(time.Millisecond), bare.Round(time.Millisecond), none.Round(time.Millisecond))
	if with-bare > time.Second {
		t.Errorf("hop session attach makes a session %v slower", with-bare)
	}

	srv.reset()
	hopExec := longExec(t, m2, srv)
	mcpS := startMCP(t, m2.env(t, &session{}))
	mcpDone := make(chan cli.MCPExec, 1)
	go func() {
		mcpDone <- mcpCall[cli.MCPExec](mcpS, "exec", map[string]any{"hosts": []string{"web-1"}, "command": "sleep", "timeout_s": 60})
	}()
	end := []*plainSSH{
		startPlainSSH(t, "ssh -F hop's config", nil, "-F", hopCfg, "web-1", "sleep"),
		startPlainSSH(t, "ssh through the Include", nil, "-F", inclCfg, "web-1", "sleep"),
	}
	hopAgent := []string{"SSH_AUTH_SOCK=" + agent}
	keep := []*plainSSH{
		startPlainSSH(t, "ssh -F own config", nil, "-F", ownCfg, "web-1", "sleep"),
		startPlainSSH(t, "ssh web-1 -F own config", nil, "web-1", "-F", ownCfg, "sleep"),
		startPlainSSH(t, "ssh with no -F and no Include", nil, "-o", "HostName=127.0.0.1", "-p", strconv.Itoa(srv.port), "-l", "deploy",
			"-i", keyFile, "-o", "IdentitiesOnly=yes", "-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null", "web-1", "sleep"),
		startPlainSSH(t, "ssh with PermitLocalCommand no above the Include", nil, "-F", offCfg, "web-1", "sleep"),
		startPlainSSH(t, "ssh with its own LocalCommand above the Include", nil, "-F", ownLCCfg, "web-1", "sleep"),
		startPlainSSH(t, "ssh -o IdentityAgent=none with hop's agent in SSH_AUTH_SOCK", hopAgent, "-F", ownCfg, "-o", "IdentityAgent=none", "web-1", "sleep"),
		startPlainSSH(t, "ssh with hop's agent as its own IdentityAgent", nil, "-F", viaAgentCfg, "web-1", "sleep"),
	}
	waitSleeps(t, srv, 2+len(end)+len(keep))

	s := &session{
		tty:     true,
		secrets: map[string]string{"Current master password: ": resolvePassword},
		answer: func(prompt string) string {
			switch {
			case strings.Contains(prompt, "Rotate them now?"):
				return "n"
			case strings.HasSuffix(prompt, "[y/N] "):
				return "y"
			}
			return "" // keep only this device
		},
	}
	if code := m1.hop(t, s, "auth", "devices", "revoke", "m2"); code != 0 {
		t.Fatalf("revoke: exit %d: %s", code, s.stderr.String())
	}
	revoked := time.Now()
	var e execEnd
	select {
	case e = <-hopExec:
	case <-time.After(45 * time.Second):
		t.Fatal("hop exec on the revoked device still runs 45s after the revoke")
	}
	if !stopped(e, "this device was revoked") {
		t.Errorf("hop exec ended %v after the revoke with exit %d, %+v: not stopped by the revocation", e.at.Sub(revoked), e.code, e.res)
	}
	select {
	case out := <-mcpDone:
		if r := execResults(t, out)["web-1"]; r.ExitCode != 255 || r.Error != "the hop daemon ended this ssh session when this device was revoked" {
			t.Errorf("MCP exec: %+v", r)
		}
	case <-time.After(45 * time.Second):
		t.Fatal("the MCP exec on the revoked device still runs 45s after the revoke")
	}
	for _, p := range end {
		err := p.wait(t, 45*time.Second)
		t.Logf("%s ended %v after the revoke: %v", p.name, p.at.Sub(revoked).Round(time.Millisecond), err)
		if err == nil || p.at.Sub(revoked) > 25*time.Second {
			t.Errorf("%s was not ended by the revocation: %v\n%s", p.name, err, p.stderr.String())
		}
	}
	// The others run to the end of their command: the server ends it
	// after 30 seconds, and ssh exits 0.
	for _, p := range keep {
		if err := p.wait(t, 60*time.Second); err != nil {
			t.Errorf("%s was ended: %v\n%s", p.name, err, p.stderr.String())
		}
	}

	var st struct {
		EndedSessions *struct {
			Count    int `json:"count"`
			Sessions []struct {
				PID   int    `json:"pid"`
				Alias string `json:"alias"`
			} `json:"sessions"`
		} `json:"ended_sessions"`
	}
	decodeJSON(t, m2.must(t, nil, "status", "--json"), &st)
	if st.EndedSessions == nil || st.EndedSessions.Count != 4 {
		t.Fatalf("hop status --json: ended sessions %+v, want 4", st.EndedSessions)
	}
	var pids []int
	for _, s := range st.EndedSessions.Sessions {
		if s.Alias != "web-1" {
			t.Errorf("ended session %+v", s)
		}
		pids = append(pids, s.PID)
	}
	for _, p := range end {
		if !slices.Contains(pids, p.cmd.Process.Pid) {
			t.Errorf("status does not name %s, pid %d: %v", p.name, p.cmd.Process.Pid, pids)
		}
	}
	for _, p := range keep {
		if slices.Contains(pids, p.cmd.Process.Pid) {
			t.Errorf("status names %s, pid %d", p.name, p.cmd.Process.Pid)
		}
	}
	out := m2.must(t, nil, "status")
	if !strings.Contains(out, "sessions:     ended 4 ssh sessions when this device was revoked") || !strings.Contains(out, " web-1") {
		t.Errorf("hop status does not say the sessions ended:\n%s", out)
	}
	if out := m2.must(t, nil, "auth", "status"); !strings.Contains(out, "ended 4 ssh sessions when this device was revoked") {
		t.Errorf("hop auth status does not say the sessions ended:\n%s", out)
	}
}

// config is the ssh config m's daemon wrote.
func (m *machine) config(t *testing.T) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(m.paths.ConfigDir, "config"))
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// A plain hop lock leaves open sessions running; hop lock --end-sessions
// ends them.
func TestLockEndsSessionsOnlyWhenAsked(t *testing.T) {
	requireSSH(t)
	w := newAuthWorld(t)
	m := newMachine(t, w, "m")
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	m.hopBin = exe
	initS := &session{secrets: map[string]string{"Master password: ": resolvePassword, "Repeat it: ": resolvePassword}}
	if code := m.hop(t, initS, "init"); code != 0 {
		t.Fatalf("init: exit %d: %s", code, initS.stderr.String())
	}
	keyFile, signer := sessionKey(t)
	srv := startSSHServer(t, signer.PublicKey())
	m.must(t, nil, "key", "add", keyFile, "--name", "deploy-key")
	m.must(t, nil, "add", "web-1", "--address", "127.0.0.1", "--port", strconv.Itoa(srv.port),
		"--user", "deploy", "--key", "deploy-key", "--host-key", authorizedKeysLine(srv.hostKey))

	ended := longExec(t, m, srv)
	m.must(t, nil, "lock")
	select {
	case e := <-ended:
		t.Fatalf("a plain hop lock ended the session: exit %d, %+v", e.code, e.res)
	case <-time.After(3 * time.Second):
	}

	locked := time.Now()
	out := m.must(t, nil, "lock", "--end-sessions")
	var e execEnd
	select {
	case e = <-ended:
	case <-time.After(15 * time.Second):
		t.Fatal("hop lock --end-sessions left the session running")
	}
	if !stopped(e, "hop lock --end-sessions ran") {
		t.Fatalf("the session ended with exit %d, %+v: not stopped by hop lock --end-sessions", e.code, e.res)
	}
	if d := e.at.Sub(locked); d > 8*time.Second {
		t.Errorf("the session ended %v after hop lock --end-sessions", d)
	}
	if !strings.Contains(out, "ended 1 ssh session") {
		t.Errorf("hop lock --end-sessions says:\n%s", out)
	}
	if out := m.must(t, nil, "status"); !strings.Contains(out, "ended 1 ssh session when hop lock --end-sessions ran") {
		t.Errorf("hop status:\n%s", out)
	}
}

// hop session attach, which ssh runs and waits for, prints nothing and
// exits 0 at once, whatever is at the socket: no daemon, a socket where
// nothing answers, or a daemon that refuses (its parent is not ssh). It
// never starts a daemon.
func TestSessionAttachIsQuietAndBounded(t *testing.T) {
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	dir := shortTemp(t)
	silent := filepath.Join(dir, "silent.sock")
	ln, err := net.Listen("unix", silent)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			defer c.Close() // accepted, never answered
		}
	}()
	var times []string
	for name, sock := range map[string]string{"no daemon": filepath.Join(dir, "none.sock"), "no answer": silent} {
		// What ssh runs: no output, exit 0. Its time includes starting
		// this test binary, which is large, so it is only logged.
		cmd := exec.Command(exe, "session", "attach", "--control", sock, "web-1")
		start := time.Now()
		out, err := cmd.CombinedOutput()
		took := time.Since(start)
		if err != nil || len(out) != 0 {
			t.Errorf("%s: %v, output %q", name, err, out)
		}
		// The attach itself.
		start = time.Now()
		cli.SessionAttach([]string{"--control", sock, "web-1"})
		attach := time.Since(start)
		times = append(times, fmt.Sprintf("%s %v (%v as a process)", name, attach.Round(time.Millisecond), took.Round(time.Millisecond)))
		if attach > time.Second {
			t.Errorf("%s: took %v", name, attach)
		}
	}
	sort.Strings(times)
	t.Logf("hop session attach: %s", strings.Join(times, ", "))
	if _, err := os.Stat(filepath.Join(dir, "none.sock")); err == nil {
		t.Error("hop session attach started a daemon")
	}
}
