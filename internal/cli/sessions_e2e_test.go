//go:build linux

package cli_test

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/sys/unix"

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

// localWeb is a machine with a local vault and a host web-1 on an
// in-process ssh server.
func localWeb(t *testing.T) (*machine, *sshServer) {
	t.Helper()
	w := newAuthWorld(t)
	m := newMachine(t, w, "m")
	initS := &session{secrets: map[string]string{"Master password: ": resolvePassword, "Repeat it: ": resolvePassword}}
	if code := m.hop(t, initS, "init"); code != 0 {
		t.Fatalf("init: exit %d: %s", code, initS.stderr.String())
	}
	keyFile, signer := sessionKey(t)
	srv := startSSHServer(t, signer.PublicKey())
	m.must(t, nil, "key", "add", keyFile, "--name", "deploy-key")
	m.must(t, nil, "add", "web-1", "--address", "127.0.0.1", "--port", strconv.Itoa(srv.port),
		"--user", "deploy", "--key", "deploy-key", "--host-key", authorizedKeysLine(srv.hostKey))
	return m, srv
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

// stopped says hop ended the session (ssh exits 255 on its SIGHUP), long
// before the server would end the command, and hop exec says why.
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

func startPlainSSH(t *testing.T, name string, args ...string) *plainSSH {
	t.Helper()
	p := &plainSSH{name: name, done: make(chan struct{})}
	p.cmd = exec.Command("ssh", append([]string{"-o", "BatchMode=yes"}, args...)...)
	for _, kv := range os.Environ() {
		if !strings.HasPrefix(kv, "SSH_AUTH_SOCK=") {
			p.cmd.Env = append(p.cmd.Env, kv)
		}
	}
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

// termHop is hop on a pseudo-terminal of its own, as a job of a minimal
// job-control shell (cli.JobShellVar): this test binary twice.
type termHop struct {
	master *os.File
	shell  *exec.Cmd
	log    string
	mu     sync.Mutex
	out    bytes.Buffer
	pos    int
	done   chan struct{}
	code   int
}

func (h *termHop) Write(b []byte) (int, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.out.Write(b)
}

func (h *termHop) output() string {
	h.mu.Lock()
	defer h.mu.Unlock()
	return strings.ReplaceAll(h.out.String(), "\r", "")
}

// startTerminalHop runs hop args for m on a new 80x24 terminal.
func startTerminalHop(t *testing.T, m *machine, args ...string) *termHop {
	t.Helper()
	master, slave := openPTY(t)
	setSize(t, master, 80, 24)
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	paths, _ := json.Marshal(cli.HopMainPaths{Home: m.home, Data: m.data, Run: m.paths.RunDir, Config: m.paths.ConfigDir, State: m.paths.StateDir})
	h := &termHop{master: master, log: filepath.Join(shortTemp(t), "job.log"), done: make(chan struct{})}
	h.shell = exec.Command(exe, args...)
	for _, kv := range os.Environ() {
		if !strings.HasPrefix(kv, "SSH_AUTH_SOCK=") && !strings.HasPrefix(kv, "HOME=") && !strings.HasPrefix(kv, "TERM=") {
			h.shell.Env = append(h.shell.Env, kv)
		}
	}
	h.shell.Env = append(h.shell.Env, "HOME="+m.home, "TERM=xterm", cli.HopMainVar+"="+string(paths), cli.JobShellVar+"="+h.log)
	h.shell.Stdin, h.shell.Stdout, h.shell.Stderr = slave, slave, slave
	h.shell.SysProcAttr = &syscall.SysProcAttr{Setsid: true, Setctty: true, Ctty: 0}
	if err := h.shell.Start(); err != nil {
		t.Fatal(err)
	}
	slave.Close()
	go io.Copy(h, master) // ends (EIO) once every process on the terminal has exited
	go func() {
		err := h.shell.Wait()
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			h.code = ee.ExitCode()
		} else if err != nil {
			h.code = -1
		}
		close(h.done)
	}()
	t.Cleanup(func() {
		if pid, ok := h.jobPID(); ok {
			syscall.Kill(-pid, syscall.SIGKILL)
		}
		h.shell.Process.Kill()
		<-h.done
		master.Close()
		t.Logf("hop %s on a terminal:\n%s\njob: %q", strings.Join(args, " "), h.output(), h.events())
	})
	return h
}

func (h *termHop) send(s string) { h.master.Write([]byte(s)) }

// expect waits for s in what the terminal shows after the last expect.
func (h *termHop) expect(t *testing.T, s string) {
	t.Helper()
	deadline := time.Now().Add(20 * time.Second)
	for {
		out := h.output()
		if i := strings.Index(out[h.pos:], s); i >= 0 {
			h.pos += i + len(s)
			return
		}
		select {
		case <-h.done:
			t.Fatalf("hop exited (%d) before the terminal showed %q:\n%s", h.code, s, out)
		default:
		}
		if time.Now().After(deadline) {
			t.Fatalf("the terminal never showed %q:\n%s", s, out)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// events is what the job shell logged about hop.
func (h *termHop) events() []string {
	b, _ := os.ReadFile(h.log)
	return strings.Fields(strings.ReplaceAll(string(b), " ", "_"))
}

func (h *termHop) jobPID() (int, bool) {
	for _, ev := range h.events() {
		if n, ok := strings.CutPrefix(ev, "pid_"); ok {
			pid, err := strconv.Atoi(n)
			return pid, err == nil
		}
	}
	return 0, false
}

// event waits for the job shell to log ev ("stopped 20", "exit 3").
func (h *termHop) event(t *testing.T, ev string) {
	t.Helper()
	want := strings.ReplaceAll(ev, " ", "_")
	deadline := time.Now().Add(20 * time.Second)
	for {
		for _, got := range h.events() {
			if got == want {
				return
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("the job shell never logged %q: %q\n%s", ev, h.events(), h.output())
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// wait waits for hop, and the shell, to exit, and returns the status.
func (h *termHop) wait(t *testing.T, within time.Duration) int {
	t.Helper()
	select {
	case <-h.done:
		return h.code
	case <-time.After(within):
		t.Fatalf("hop on the terminal still runs after %v:\n%s", within, h.output())
		return -1
	}
}

// openPTY opens a pseudo-terminal pair.
func openPTY(t *testing.T) (master, slave *os.File) {
	t.Helper()
	m, err := os.OpenFile("/dev/ptmx", os.O_RDWR|syscall.O_NOCTTY|syscall.O_CLOEXEC, 0)
	if err != nil {
		t.Fatalf("opening a pseudo-terminal: %v", err)
	}
	fd := int(m.Fd())
	if err := unix.IoctlSetPointerInt(fd, unix.TIOCSPTLCK, 0); err != nil {
		m.Close()
		t.Fatalf("unlocking the pseudo-terminal: %v", err)
	}
	n, err := unix.IoctlGetInt(fd, unix.TIOCGPTN)
	if err != nil {
		m.Close()
		t.Fatalf("naming the pseudo-terminal: %v", err)
	}
	s, err := os.OpenFile(fmt.Sprintf("/dev/pts/%d", n), os.O_RDWR|syscall.O_NOCTTY|syscall.O_CLOEXEC, 0)
	if err != nil {
		m.Close()
		t.Fatalf("opening the pseudo-terminal's slave: %v", err)
	}
	return m, s
}

func setSize(t *testing.T, master *os.File, cols, rows uint16) {
	t.Helper()
	if err := unix.IoctlSetWinsize(int(master.Fd()), unix.TIOCSWINSZ, &unix.Winsize{Col: cols, Row: rows}); err != nil {
		t.Fatal(err)
	}
}

// hop <target> runs ssh as its child on the terminal and behaves as a
// plain ssh does: the session is interactive, Ctrl-C goes to the remote
// side and hop keeps running, a new window size reaches the server, ~^Z
// suspends the job (hop stops with ssh, and both go on with SIGCONT), and
// hop exits with ssh's status. SIGTERM sent to hop alone reaches ssh, and
// hop exits as ssh does, not as an interrupted hop.
func TestTerminalSessionBehavesAsPlainSSH(t *testing.T) {
	requireSSH(t)
	m, _ := localWeb(t)

	h := startTerminalHop(t, m, "web-1")
	h.expect(t, "remote$ ")
	h.send("\x03")
	h.expect(t, "remote got ^C")
	h.send("still here\r")
	h.expect(t, "remote saw: still here")

	setSize(t, h.master, 100, 30)
	h.expect(t, "remote size 100x30")

	h.send("\r~\x1a")
	h.event(t, fmt.Sprintf("stopped %d", int(syscall.SIGTSTP)))
	pid, ok := h.jobPID()
	if !ok {
		t.Fatal("the job shell logged no pid")
	}
	if err := syscall.Kill(-pid, syscall.SIGCONT); err != nil {
		t.Fatal(err)
	}
	h.send("back\r")
	h.expect(t, "remote saw: back")

	h.send("exit 3\r")
	if code := h.wait(t, 15*time.Second); code != 3 {
		t.Errorf("hop exited %d after the remote shell exited 3", code)
	}
	h.event(t, "exit 3")
	if out := h.output(); strings.Contains(out, "hop daemon ended") {
		t.Errorf("hop says the daemon ended a session it did not end:\n%s", out)
	}

	h = startTerminalHop(t, m, "web-1")
	h.expect(t, "remote$ ")
	pid, ok = h.jobPID()
	if !ok {
		t.Fatal("the job shell logged no pid")
	}
	if err := syscall.Kill(pid, syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}
	if code := h.wait(t, 15*time.Second); code != 255 {
		t.Errorf("hop exited %d after SIGTERM, want ssh's 255", code)
	}
	h.event(t, "exit 255")
}

// A device revoked while it is online ends the ssh sessions hop started,
// each ended by the hop process that runs it: hop exec, an MCP exec, and
// hop <target> on a terminal, which says why. A plain ssh through hop's
// config is not hop's to end, and runs to its end (README, What
// revocation does: a documented limit). hop's ssh config has no hook for
// sessions. A hop exec on the revoked device does not reach the server.
func TestRevokeEndsTheSessionsHopStarted(t *testing.T) {
	requireSSH(t)
	w := newAuthWorld(t)
	m1, m2 := newMachine(t, w, "m1"), newMachine(t, w, "m2")
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
	if cfg := m2.config(t); strings.Contains(cfg, "LocalCommand") {
		t.Errorf("hop's ssh config runs something when a session starts:\n%s", cfg)
	}

	srv.reset()
	hopExec := longExec(t, m2, srv)
	mcpS := startMCP(t, m2.env(t, &session{}))
	mcpDone := make(chan cli.MCPExec, 1)
	go func() {
		mcpDone <- mcpCall[cli.MCPExec](mcpS, "exec", map[string]any{"hosts": []string{"web-1"}, "command": "sleep", "timeout_s": 60})
	}()
	term := startTerminalHop(t, m2, "web-1")
	term.expect(t, "remote$ ")
	plain := startPlainSSH(t, "ssh -F hop's config", "-F", hopCfg, "web-1", "sleep")
	waitSleeps(t, srv, 3)

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
	const why = "this device was revoked"
	var e execEnd
	select {
	case e = <-hopExec:
	case <-time.After(45 * time.Second):
		t.Fatal("hop exec on the revoked device still runs 45s after the revoke")
	}
	t.Logf("hop exec ended %v after the revoke", e.at.Sub(revoked).Round(time.Millisecond))
	if !stopped(e, why) {
		t.Errorf("hop exec ended %v after the revoke with exit %d, %+v: not stopped by the revocation", e.at.Sub(revoked), e.code, e.res)
	}
	select {
	case out := <-mcpDone:
		if r := execResults(t, out)["web-1"]; r.ExitCode != 255 || r.Error != "the hop daemon ended this ssh session when "+why {
			t.Errorf("MCP exec: %+v", r)
		}
	case <-time.After(45 * time.Second):
		t.Fatal("the MCP exec on the revoked device still runs 45s after the revoke")
	}
	if code := term.wait(t, 45*time.Second); code != 255 {
		t.Errorf("hop web-1 on the terminal exited %d, want ssh's 255", code)
	}
	if out := term.output(); !strings.Contains(out, "hop: the hop daemon ended this ssh session when "+why+"\n") {
		t.Errorf("hop web-1 does not say why its session ended:\n%s", out)
	}
	// The plain ssh runs to the end of its command: the server ends it
	// after 30 seconds, and ssh exits 0.
	if err := plain.wait(t, 60*time.Second); err != nil {
		t.Errorf("%s was ended: %v\n%s", plain.name, err, plain.stderr.String())
	}

	var st struct {
		EndedSessions *struct {
			Count    int    `json:"count"`
			Why      string `json:"why"`
			Sessions []struct {
				PID   int    `json:"pid"`
				Alias string `json:"alias"`
			} `json:"sessions"`
		} `json:"ended_sessions"`
	}
	decodeJSON(t, m2.must(t, nil, "status", "--json"), &st)
	if st.EndedSessions == nil || st.EndedSessions.Count != 3 || st.EndedSessions.Why != why {
		t.Fatalf("hop status --json: ended sessions %+v, want 3", st.EndedSessions)
	}
	for _, s := range st.EndedSessions.Sessions {
		if s.Alias != "web-1" || s.PID <= 0 {
			t.Errorf("ended session %+v", s)
		}
	}
	out := m2.must(t, nil, "status")
	if !strings.Contains(out, "sessions:     ended 3 ssh sessions hop started, when "+why) || !strings.Contains(out, "web-1 (hop pid ") {
		t.Errorf("hop status does not say the sessions ended:\n%s", out)
	}
	if out := m2.must(t, nil, "auth", "status"); !strings.Contains(out, "ended 3 ssh sessions hop started, when "+why) {
		t.Errorf("hop auth status does not say the sessions ended:\n%s", out)
	}

	// A new hop exec: refused before ssh runs, or ended at once.
	srv.reset()
	s = &session{}
	code := m2.hop(t, s, "exec", "web-1", "--json", "--", "sleep")
	if code == 0 {
		t.Errorf("hop exec on the revoked device succeeded: %s", s.stdout.String())
	}
	time.Sleep(time.Second)
	if c := srv.commands(); len(c) != 0 {
		t.Errorf("hop exec on the revoked device reached the server: %q", c)
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
	m, srv := localWeb(t)

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
	if !strings.Contains(out, "ended 1 ssh session hop started") {
		t.Errorf("hop lock --end-sessions says:\n%s", out)
	}
	if out := m.must(t, nil, "status"); !strings.Contains(out, "ended 1 ssh session hop started, when hop lock --end-sessions ran") {
		t.Errorf("hop status:\n%s", out)
	}
}
