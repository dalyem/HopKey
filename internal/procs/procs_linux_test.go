package procs

import (
	"errors"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// stat is a /proc/<pid>/stat line with command name comm, state, parent
// and start time.
func stat(pid int, comm string, state byte, ppid int, start string) string {
	f := make([]string, 50)
	for i := range f {
		f[i] = "0"
	}
	f[0] = string(state)
	f[1] = strconv.Itoa(ppid)
	f[19] = start
	return strconv.Itoa(pid) + " (" + comm + ") " + strings.Join(f, " ") + "\n"
}

// fakeProc writes /proc/<pid> under dir; exe "" leaves out the exe link,
// as for a process whose program can't be read.
func fakeProc(t *testing.T, dir string, pid, ppid, uid, euid int, exe, comm string) {
	t.Helper()
	d := filepath.Join(dir, strconv.Itoa(pid))
	if err := os.MkdirAll(d, 0o755); err != nil {
		t.Fatal(err)
	}
	files := map[string]string{
		"stat":    stat(pid, comm+") (odd", 'S', ppid, "4242"+strconv.Itoa(pid)),
		"status":  "Name:\tx\nUmask:\t0022\nUid:\t" + strconv.Itoa(uid) + "\t" + strconv.Itoa(euid) + "\t0\t0\nGid:\t0\t0\t0\t0\n",
		"comm":    comm + "\n",
		"cmdline": "ssh\x00web1\x00",
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
	st, err := parseStat([]byte(stat(7, "a) (b c", 'Z', 4, "123456")))
	if err != nil || st.start != "123456" || st.state != 'Z' || st.ppid != 4 {
		t.Errorf("parseStat: %+v %v", st, err)
	}
	if _, err := parseStat([]byte("7 (x) S 1 2")); err == nil {
		t.Error("a short stat parsed")
	}
}

// Lookup reads the program from the exe link alone: a binary replaced on
// disk still reads as its path, and a process whose exe can't be read has
// no program, whatever its comm and command line say.
func TestLookupReadsTheProgramFromExeOnly(t *testing.T) {
	dir := t.TempDir()
	fakeProc(t, dir, 10, 1, 1000, 1000, "/usr/bin/ssh", "ssh")
	fakeProc(t, dir, 11, 10, 1000, 1000, "/usr/bin/ssh (deleted)", "ssh")
	fakeProc(t, dir, 14, 10, 1000, 1000, "", "ssh")
	useRoot(t, dir)

	for pid, want := range map[int]Proc{
		10: {PID: 10, PPID: 1, UID: 1000, EUID: 1000, Start: "424210", Exe: "/usr/bin/ssh"},
		11: {PID: 11, PPID: 10, UID: 1000, EUID: 1000, Start: "424211", Exe: "/usr/bin/ssh"},
		14: {PID: 14, PPID: 10, UID: 1000, EUID: 1000, Start: "424214"},
	} {
		if p, err := Lookup(pid); err != nil || p != want {
			t.Errorf("Lookup(%d) = %+v, %v; want %+v", pid, p, err, want)
		}
	}
	if _, err := Lookup(99); !errors.Is(err, ErrGone) {
		t.Errorf("Lookup of no process: %v", err)
	}
}

func startSleep(t *testing.T) (*exec.Cmd, chan error) {
	t.Helper()
	cmd := exec.Command("sleep", "60")
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	t.Cleanup(func() { cmd.Process.Kill() })
	return cmd, done
}

// A Pin signals the process it holds, and once that has exited, nothing.
func TestPinSignalsItsProcess(t *testing.T) {
	cmd, done := startSleep(t)
	p, err := Open(cmd.Process.Pid)
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	sleep, _ := exec.LookPath("sleep")
	sleep, _ = filepath.EvalSymlinks(sleep)
	if p.PPID != os.Getpid() || !p.OwnedBy(os.Getuid()) || p.Proc.Exited || p.Exe != sleep || !p.Pinned() || p.Exited() {
		t.Fatalf("Open = %+v (pinned %v), want sleep %s", p.Proc, p.Pinned(), sleep)
	}
	if err := p.Signal(syscall.SIGHUP); err != nil {
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
	if !p.Exited() {
		t.Error("an ended, reaped process has not exited")
	}
	if err := p.Signal(syscall.SIGHUP); !errors.Is(err, ErrGone) {
		t.Errorf("Signal of an ended process: %v", err)
	}
	p.Close()
	if err := p.Signal(syscall.SIGHUP); !errors.Is(err, ErrGone) {
		t.Errorf("Signal through a closed Pin: %v", err)
	}
}

// Without a pidfd a process is not pinned, so it is never signalled: there
// is no kill(2) by PID to fall back to.
func TestNoPidfdMeansNoSignal(t *testing.T) {
	old := pidfdOpen
	pidfdOpen = func(int, int) (int, error) { return -1, unix.ENOSYS }
	t.Cleanup(func() { pidfdOpen = old })

	cmd, done := startSleep(t)
	p, err := Open(cmd.Process.Pid)
	if !errors.Is(err, ErrNoPin) || p != nil {
		t.Fatalf("Open without a pidfd: %v, %+v", err, p)
	}
	select {
	case err := <-done:
		t.Fatalf("the process was signalled: %v", err)
	case <-time.After(200 * time.Millisecond):
	}
}

// A process that exited but is not reaped yet is not pinned.
func TestZombieIsNotPinned(t *testing.T) {
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
			if pin, err := Open(cmd.Process.Pid); !errors.Is(err, ErrGone) {
				t.Errorf("Open of a zombie: %+v, %v", pin, err)
			}
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("true never exited")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// PeerPID is the process at the other end of a connection: here, this one.
func TestPeerPID(t *testing.T) {
	sock := filepath.Join(t.TempDir(), "s")
	ln, err := net.ListenUnix("unix", &net.UnixAddr{Name: sock, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		c, err := net.Dial("unix", sock)
		if err == nil {
			defer c.Close()
			time.Sleep(time.Second)
		}
	}()
	c, err := ln.AcceptUnix()
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if pid, err := PeerPID(c); err != nil || pid != os.Getpid() {
		t.Errorf("PeerPID = %d, %v; want %d", pid, err, os.Getpid())
	}
}
