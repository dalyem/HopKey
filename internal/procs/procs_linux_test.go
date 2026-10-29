package procs

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

// stat is a /proc/<pid>/stat line with command name comm, state and
// start time.
func stat(pid int, comm string, state byte, start string) string {
	f := make([]string, 50)
	for i := range f {
		f[i] = "0"
	}
	f[0] = string(state)
	f[19] = start
	return strconv.Itoa(pid) + " (" + comm + ") " + strings.Join(f, " ") + "\n"
}

// fakeProc writes /proc/<pid> under dir.
func fakeProc(t *testing.T, dir string, pid, uid, euid int, exe string, args, env []string) {
	t.Helper()
	d := filepath.Join(dir, strconv.Itoa(pid))
	if err := os.MkdirAll(d, 0o755); err != nil {
		t.Fatal(err)
	}
	files := map[string]string{
		"stat":    stat(pid, filepath.Base(exe)+") (odd", 'S', "4242"+strconv.Itoa(pid)),
		"status":  "Name:\tx\nUmask:\t0022\nUid:\t" + strconv.Itoa(uid) + "\t" + strconv.Itoa(euid) + "\t0\t0\nGid:\t0\t0\t0\t0\n",
		"comm":    filepath.Base(exe) + "\n",
		"cmdline": strings.Join(args, "\x00") + "\x00",
		"environ": strings.Join(env, "\x00") + "\x00",
	}
	for name, body := range files {
		if err := os.WriteFile(filepath.Join(d, name), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if exe != "" {
		if err := os.Symlink(exe, filepath.Join(d, "exe")); err != nil {
			t.Fatal(err)
		}
	}
}

func useRoot(t *testing.T, dir string) {
	old := root
	root = dir
	t.Cleanup(func() { root = old })
}

func TestParseStat(t *testing.T) {
	start, state, err := parseStat([]byte(stat(7, "a) (b c", 'Z', "123456")))
	if err != nil || start != "123456" || state != 'Z' {
		t.Errorf("parseStat: %q %c %v", start, state, err)
	}
	if _, _, err := parseStat([]byte("7 (x) S 1 2")); err == nil {
		t.Error("a short stat parsed")
	}
}

// List reads only uid's processes, with their program, command line and
// agent socket; a program replaced on disk still reads as itself.
func TestListReadsAFakeProc(t *testing.T) {
	dir := t.TempDir()
	fakeProc(t, dir, 10, 1000, 1000, "/usr/bin/ssh", []string{"ssh", "-p", "22", "web1"}, []string{"HOME=/h", "SSH_AUTH_SOCK=/run/hop/agent.sock"})
	fakeProc(t, dir, 11, 1000, 1000, "/usr/bin/ssh (deleted)", []string{"ssh", "web1"}, nil)
	fakeProc(t, dir, 12, 1001, 1001, "/usr/bin/ssh", []string{"ssh", "web1"}, nil)
	fakeProc(t, dir, 13, 1000, 0, "/usr/bin/ssh", []string{"ssh", "web1"}, nil)
	// No exe link (it can't be read): the kernel's comm stands in.
	fakeProc(t, dir, 14, 1000, 1000, "", []string{"ssh", "db"}, nil)
	os.WriteFile(filepath.Join(dir, "14", "comm"), []byte("ssh\n"), 0o644)
	os.MkdirAll(filepath.Join(dir, "self"), 0o755)
	useRoot(t, dir)

	list, err := List(1000)
	if err != nil {
		t.Fatal(err)
	}
	var pids []int
	for _, p := range list {
		pids = append(pids, p.PID)
	}
	slices.Sort(pids)
	if !slices.Equal(pids, []int{10, 11, 14}) {
		t.Fatalf("listed %v, want [10 11 14] (13 runs as root)", pids)
	}
	p, err := Lookup(10)
	if err != nil {
		t.Fatal(err)
	}
	if p.Exe != "ssh" || p.Start != "424210" || !slices.Equal(p.Args, []string{"ssh", "-p", "22", "web1"}) || p.AgentSocket != "" {
		t.Errorf("Lookup(10) = %+v (Lookup reads no environment)", p)
	}
	for _, p := range list {
		switch p.PID {
		case 10:
			if p.AgentSocket != "/run/hop/agent.sock" {
				t.Errorf("10: agent socket %q", p.AgentSocket)
			}
		case 11, 14:
			if p.Exe != "ssh" {
				t.Errorf("%d: exe %q", p.PID, p.Exe)
			}
		}
	}
	if _, err := Lookup(99); !errors.Is(err, ErrGone) {
		t.Errorf("Lookup of no process: %v", err)
	}
}

// Signal signals a process only while its PID has the start time it was
// found with.
func TestSignalChecksTheStartTime(t *testing.T) {
	cmd := exec.Command("sleep", "60")
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	t.Cleanup(func() { cmd.Process.Kill() })

	p, err := Lookup(cmd.Process.Pid)
	if err != nil {
		t.Fatal(err)
	}
	if p.Exe != "sleep" || !p.OwnedBy(os.Getuid()) || p.Exited || !Alive(p) {
		t.Fatalf("Lookup = %+v", p)
	}
	stale := p
	stale.Start = "1"
	if err := Signal(stale, syscall.SIGTERM); !errors.Is(err, ErrGone) {
		t.Errorf("Signal with another start time: %v", err)
	}
	select {
	case err := <-done:
		t.Fatalf("the process was signalled: %v", err)
	case <-time.After(200 * time.Millisecond):
	}
	if err := Signal(p, syscall.SIGHUP); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if err == nil || err.Error() != "signal: hangup" {
			t.Errorf("ended with %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("SIGHUP did not end it")
	}
	if Alive(p) {
		t.Error("an ended, reaped process is alive")
	}
	if err := Signal(p, syscall.SIGHUP); !errors.Is(err, ErrGone) {
		t.Errorf("Signal of an ended process: %v", err)
	}
}

// A process that exited but is not reaped yet is not alive.
func TestZombieIsNotAlive(t *testing.T) {
	cmd := exec.Command("true")
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer cmd.Wait()
	deadline := time.Now().Add(5 * time.Second)
	for {
		p, err := Lookup(cmd.Process.Pid)
		if err != nil {
			t.Fatal(err)
		}
		if p.Exited {
			if Alive(p) || !errors.Is(Signal(p, syscall.SIGHUP), ErrGone) {
				t.Error("a zombie counts as alive")
			}
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("true never exited")
		}
		time.Sleep(10 * time.Millisecond)
	}
}
