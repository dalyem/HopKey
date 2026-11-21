//go:build linux

package cli_test

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/dalyem/hopkey/internal/cli"
	"github.com/dalyem/hopkey/internal/daemon"
	"github.com/dalyem/hopkey/internal/model"
	"github.com/dalyem/hopkey/internal/resolve"
)

// fakeSSHScript is an ssh that says which terminal it has and its PID,
// then echoes each line it reads.
const fakeSSHScript = `#!/bin/sh
echo "fake pid $$ on $(readlink /proc/self/fd/0)"
while IFS= read -r l; do echo "fake saw: $l"; done
`

// fakeSSHPath is a PATH whose ssh is fakeSSHScript.
func fakeSSHPath(t *testing.T) string {
	t.Helper()
	dir := shortTemp(t)
	if err := os.WriteFile(filepath.Join(dir, "ssh"), []byte(fakeSSHScript), 0o755); err != nil {
		t.Fatal(err)
	}
	return "PATH=" + dir + string(os.PathListSeparator) + os.Getenv("PATH")
}

var fakeSSHStart = regexp.MustCompile(`fake pid (\d+) on (\S+)\n`)

// fakeSSH waits for the fake ssh to start, and returns its PID and its
// stdin's terminal.
func (h *termHop) fakeSSH(t *testing.T) (pid int, tty string) {
	t.Helper()
	for deadline := time.Now().Add(20 * time.Second); ; time.Sleep(20 * time.Millisecond) {
		if m := fakeSSHStart.FindStringSubmatch(h.output()); m != nil {
			pid, _ = strconv.Atoi(m[1])
			return pid, m[2]
		}
		select {
		case <-h.done:
			t.Fatalf("hop exited (%d) before the fake ssh started:\n%s", h.code, h.output())
		default:
		}
		if time.Now().After(deadline) {
			t.Fatalf("the fake ssh never started:\n%s", h.output())
		}
	}
}

// procState is pid's state letter in /proc: T when it is stopped.
func procState(t *testing.T, pid int) string {
	t.Helper()
	b, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		t.Fatal(err)
	}
	s := string(b)
	return strings.Fields(s[strings.LastIndexByte(s, ')')+1:])[0]
}

func waitState(t *testing.T, pid int, want string) {
	t.Helper()
	for deadline := time.Now().Add(10 * time.Second); ; time.Sleep(20 * time.Millisecond) {
		got := procState(t, pid)
		if (want == "T") == (got == "T") {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("ssh (pid %d) is in state %s, want %s", pid, got, want)
		}
	}
}

// stops is how many times the job shell saw hop stop, by any signal.
func (h *termHop) stops() int {
	n := 0
	for _, got := range h.events() {
		if strings.HasPrefix(got, "stopped_") {
			n++
		}
	}
	return n
}

// panelNotice is the start of what hop says when it connects without the
// shortcuts panel because something failed.
const panelNotice = "connecting without the shortcuts panel"

// hop <target> to a host with shortcuts runs ssh behind the panel: Ctrl-]
// then a shortcut's keys types its command into the session, the host's
// own and the global ones, with Enter unless it was added with
// --no-enter. SIGTERM sent to hop still reaches ssh, and hop exits as ssh
// does.
func TestTerminalPanelTypesShortcuts(t *testing.T) {
	requireSSH(t)
	m, _ := localWeb(t)
	m.must(t, nil, "shortcut", "add", "u", "--host", "web-1", "--", "echo host one")
	m.must(t, nil, "shortcut", "add", "gl", "--", "echo global one")
	m.must(t, nil, "shortcut", "add", "n", "--no-enter", "--", "typed only")

	h := startTerminalHop(t, m, "web-1")
	h.expect(t, "remote$ ")
	h.send("\x1d")
	time.Sleep(100 * time.Millisecond)
	h.send("u")
	h.expect(t, "remote saw: echo host one")
	h.send("\x1d")
	time.Sleep(100 * time.Millisecond)
	h.send("gl")
	h.expect(t, "remote saw: echo global one")
	h.send("\x1d")
	time.Sleep(100 * time.Millisecond)
	h.send("n")
	time.Sleep(300 * time.Millisecond)
	h.send(" then Enter\r")
	h.expect(t, "remote saw: typed only then Enter")
	if out := h.output(); strings.Contains(out, panelNotice) {
		t.Errorf("hop connected without the panel:\n%s", out)
	}

	pid, ok := h.jobPID()
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

// ssh runs behind the panel only when the session has shortcuts: with
// none, or with HOP_SHORTCUT_KEY=off, its stdin is the terminal itself,
// as before there were shortcuts, and hop says nothing about the panel.
func TestTerminalPanelOnlyWithShortcuts(t *testing.T) {
	m, _ := localWeb(t)
	path := fakeSSHPath(t)

	var hs []*termHop
	h := startTerminalHopEnv(t, m, []string{path}, "web-1")
	hs = append(hs, h)
	if _, tty := h.fakeSSH(t); tty != h.tty {
		t.Errorf("with no shortcuts, ssh runs on %s, not on the terminal %s", tty, h.tty)
	}
	h.send("hello\r")
	h.expect(t, "fake saw: hello")

	m.must(t, nil, "shortcut", "add", "u", "--host", "web-1", "--", "echo hi")
	h = startTerminalHopEnv(t, m, []string{path, "HOP_SHORTCUT_KEY=off"}, "web-1")
	hs = append(hs, h)
	if _, tty := h.fakeSSH(t); tty != h.tty {
		t.Errorf("with HOP_SHORTCUT_KEY=off, ssh runs on %s, not on the terminal %s", tty, h.tty)
	}
	h.send("\x1du\r")
	h.expect(t, "fake saw: \x1du")

	// web-1 has a shortcut: ssh is on the panel's pty.
	h = startTerminalHopEnv(t, m, []string{path, "HOP_SHORTCUT_KEY=ctrl-b"}, "web-1")
	hs = append(hs, h)
	if _, tty := h.fakeSSH(t); tty == h.tty || !strings.HasPrefix(tty, "/dev/pts/") {
		t.Errorf("with a shortcut, ssh runs on %s; want a pty of the panel's, not the terminal %s", tty, h.tty)
	}
	h.send("\x02")
	time.Sleep(100 * time.Millisecond)
	h.send("u")
	h.expect(t, "fake saw: echo hi")

	for _, h := range hs {
		if out := h.output(); strings.Contains(out, panelNotice) {
			t.Errorf("hop said something about the panel:\n%s", out)
		}
	}
}

// A shortcut lookup that fails (here, a daemon that does not know the
// request) does not stop the session: hop says so on one line, and ssh
// runs on the terminal itself.
func TestTerminalPanelLookupFails(t *testing.T) {
	f := newFakeDaemon(t)
	id := model.ID{1}
	data := filepath.Join(f.base, "data")
	if err := os.MkdirAll(data, 0o700); err != nil {
		t.Fatal(err)
	}
	f.reply(daemon.OpResolve, &daemon.ResolveResult{
		Result:   &resolve.Result{Target: "web-1", Status: resolve.StatusMatched, HostID: id.String(), HostName: "web-1"},
		Host:     &model.Host{ItemID: id, Name: "web-1", Addresses: []string{"127.0.0.1"}},
		Route:    &resolve.Route{Setting: resolve.RouteDirect, Chosen: resolve.RouteDirect, Address: "127.0.0.1", Port: 22},
		SSHAlias: "web-1",
	})
	f.fail(daemon.OpShortcuts, daemon.CodeInvalid, "unknown op shortcuts")
	h := startTerminalHopAt(t, cli.HopMainPaths{Home: f.home, Data: data, Run: f.paths.RunDir, Config: f.paths.ConfigDir, State: f.paths.StateDir},
		[]string{fakeSSHPath(t)}, "web-1")
	if _, tty := h.fakeSSH(t); tty != h.tty {
		t.Errorf("after a failed lookup, ssh runs on %s, not on the terminal %s", tty, h.tty)
	}
	h.send("hello\r")
	h.expect(t, "fake saw: hello")
	out := h.output()
	if n := strings.Count(out, panelNotice); n != 1 {
		t.Errorf("hop said %d times that it connects without the panel, want once:\n%s", n, out)
	}
	if !strings.Contains(out, "hop: "+panelNotice+": unknown op shortcuts\n") {
		t.Errorf("the notice is not one line that says why:\n%s", out)
	}
	if got := f.called(daemon.OpShortcuts); len(got) != 1 {
		t.Errorf("hop asked for the shortcuts %d times", len(got))
	} else {
		var p daemon.ShortcutsParams
		if err := json.Unmarshal(got[0], &p); err != nil || p.HostID != id.String() {
			t.Errorf("hop asked for the shortcuts of %s (%v), want web-1's", got[0], err)
		}
	}
}

// Behind the panel ssh is not in the terminal's job, so hop stops it when
// it stops itself: Ctrl-Z in the panel, or a SIGTSTP sent to hop, stops
// both, and fg continues both. hop stops with SIGSTOP (termpanel's
// stopSelf says why), so the shell sees a stop either way. A SIGTERM sent to hop reaches ssh, and hop
// exits with 128 plus the signal that killed ssh.
func TestTerminalPanelSuspendStopsSSH(t *testing.T) {
	m, _ := localWeb(t)
	m.must(t, nil, "shortcut", "add", "u", "--", "echo hi")
	h := startTerminalHopEnv(t, m, []string{fakeSSHPath(t)}, "web-1")
	sshPID, tty := h.fakeSSH(t)
	if tty == h.tty {
		t.Fatalf("ssh runs on the terminal %s, not behind the panel", tty)
	}
	pid, ok := h.jobPID()
	if !ok {
		t.Fatal("the job shell logged no pid")
	}
	for i, suspend := range []func(){
		func() {
			h.send("\x1d")
			time.Sleep(100 * time.Millisecond)
			h.send("\x1a")
		},
		func() { syscall.Kill(pid, syscall.SIGTSTP) },
	} {
		suspend()
		for deadline := time.Now().Add(10 * time.Second); h.stops() < i+1; time.Sleep(20 * time.Millisecond) {
			if time.Now().After(deadline) {
				t.Fatalf("hop did not stop (%d): %q\n%s", i, h.events(), h.output())
			}
		}
		waitState(t, sshPID, "T")
		if err := syscall.Kill(-pid, syscall.SIGCONT); err != nil {
			t.Fatal(err)
		}
		waitState(t, sshPID, "S")
		h.send(fmt.Sprintf("back %d\r", i))
		h.expect(t, fmt.Sprintf("fake saw: back %d", i))
	}

	if err := syscall.Kill(pid, syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}
	if code := h.wait(t, 15*time.Second); code != 128+int(syscall.SIGTERM) {
		t.Errorf("hop exited %d after SIGTERM killed ssh, want %d", code, 128+int(syscall.SIGTERM))
	}
}
