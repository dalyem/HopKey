//go:build unix

package cli

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

// The lock of the authorized_keys write script. The path is spelled out:
// it is what a user finds in ~/.ssh and may have to remove.
const testLockDir = ".hop-authorized_keys.lock.d"

func akHome(t *testing.T, content []byte) (home, file string) {
	t.Helper()
	home = t.TempDir()
	if err := os.Mkdir(filepath.Join(home, ".ssh"), 0o700); err != nil {
		t.Fatal(err)
	}
	file = filepath.Join(home, ".ssh", "authorized_keys")
	if err := os.WriteFile(file, content, 0o600); err != nil {
		t.Fatal(err)
	}
	return home, file
}

// noFlockPath is a PATH with every command of this one but flock: a server
// without util-linux.
func noFlockPath(t *testing.T) string {
	t.Helper()
	bin := t.TempDir()
	for _, dir := range filepath.SplitList(os.Getenv("PATH")) {
		entries, _ := os.ReadDir(dir)
		for _, e := range entries {
			if e.Name() == "flock" {
				continue
			}
			os.Symlink(filepath.Join(dir, e.Name()), filepath.Join(bin, e.Name())) // the first one on PATH wins
		}
	}
	return bin
}

func requireFlock(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("flock"); err != nil {
		if os.Getenv("HOPKEY_REQUIRE_SSH") != "" {
			t.Fatal("flock(1) is not installed")
		}
		t.Skip("flock(1) is not installed")
	}
}

// akWriter is the write script running in the background, as sshd runs
// it, in a process group of its own. It stops at reading its stdin, which
// the test feeds when it wants the script to go on.
type akWriter struct {
	cmd   *exec.Cmd
	stdin io.WriteCloser
	done  chan int
	err   bytes.Buffer
}

func startAKWriter(t *testing.T, home, path, script string) *akWriter {
	t.Helper()
	return startAKShell(t, home, path, sh(script))
}

// startAKShell is startAKWriter with the script as the shell's own command,
// not under a login shell, so that the process the test signals and waits
// for is the script's shell.
func startAKShell(t *testing.T, home, path, script string) *akWriter {
	t.Helper()
	return startAKIn(t, "sh", home, path, script)
}

// startAKIn is startAKShell with the shell given.
func startAKIn(t *testing.T, shell, home, path, script string) *akWriter {
	t.Helper()
	return startAKArgv(t, home, path, []string{shell, "-c", script})
}

// startAKArgv runs argv as startAKShell runs the script.
func startAKArgv(t *testing.T, home, path string, argv []string) *akWriter {
	t.Helper()
	w := &akWriter{done: make(chan int, 1)}
	w.cmd = exec.Command(argv[0], argv[1:]...)
	w.cmd.Env = []string{"HOME=" + home, "PATH=" + path}
	w.cmd.Stderr = &w.err
	w.cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	var err error
	if w.stdin, err = w.cmd.StdinPipe(); err != nil {
		t.Fatal(err)
	}
	if err := w.cmd.Start(); err != nil {
		t.Fatal(err)
	}
	// A script that never ends would hang the package until go test's
	// own timeout, with nothing said about which run it was. After
	// akRunLimit its process group is killed, so done reports -1 (killed)
	// and the test fails on that code with the script's stderr.
	watchdog := time.AfterFunc(akRunLimit, func() { syscall.Kill(-w.cmd.Process.Pid, syscall.SIGKILL) })
	go func() {
		err := w.cmd.Wait()
		watchdog.Stop()
		code := 0
		if ee, ok := err.(*exec.ExitError); ok {
			code = ee.ExitCode()
		}
		w.done <- code
	}()
	t.Cleanup(func() {
		watchdog.Stop()
		syscall.Kill(-w.cmd.Process.Pid, syscall.SIGKILL)
	})
	return w
}

// akRunLimit bounds one run of a remote script in these tests.
const akRunLimit = 60 * time.Second

// waitFor polls until ok, or fails the test after a few seconds.
func waitFor(t *testing.T, what string, ok func() bool) {
	t.Helper()
	for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); time.Sleep(20 * time.Millisecond) {
		if ok() {
			return
		}
	}
	t.Fatalf("timed out waiting for %s", what)
}

// holdsTemp reports whether a write script is past the lock: it has made
// its temp file in its session directory.
func holdsTemp(home string) bool {
	m, _ := filepath.Glob(filepath.Join(home, ".ssh", ".hop-s.*", "new"))
	return len(m) > 0
}

func runAKScriptPath(t *testing.T, home, path, script string, stdin []byte) (int, string) {
	t.Helper()
	cmd := exec.Command("sh", "-c", sh(script))
	cmd.Env = []string{"HOME=" + home, "PATH=" + path}
	cmd.Stdin = bytes.NewReader(stdin)
	var errOut bytes.Buffer
	cmd.Stderr = &errOut
	err := cmd.Run()
	code := 0
	if ee, ok := err.(*exec.ExitError); ok {
		code = ee.ExitCode()
	} else if err != nil {
		t.Fatal(err)
	}
	return code, errOut.String()
}

// lockOwner is the owner file of the lock, or "" when there is none.
func lockOwner(home string) string {
	b, _ := os.ReadFile(filepath.Join(home, ".ssh", testLockDir, "owner"))
	return string(b)
}

// Two writers never edit at once: the second waits for the first's lock,
// and then finds the file changed under it. A host where one run has
// flock(1) on its PATH and another has not is no different: there is one
// lock.
func TestAKWriteScriptSerializesWriters(t *testing.T) {
	requireFlock(t)
	defer func(w int) { akLockWait = w }(akLockWait)
	akLockWait = 5
	for _, c := range []struct {
		name         string
		pathA, pathB string
	}{
		{"same PATH", os.Getenv("PATH"), os.Getenv("PATH")},
		{"flock on one PATH only", os.Getenv("PATH"), noFlockPath(t)},
		{"flock on the other PATH only", noFlockPath(t), os.Getenv("PATH")},
	} {
		t.Run(c.name, func(t *testing.T) {
			orig := []byte("a\n")
			home, f := akHome(t, orig)
			first, second := []byte("a\nfirst\n"), []byte("a\nsecond\n")

			a := startAKWriter(t, home, c.pathA, akWriteScript(cksum(orig), cksum(first)))
			waitFor(t, "the first writer to take the lock", func() bool { return holdsTemp(home) })
			b := startAKWriter(t, home, c.pathB, akWriteScript(cksum(orig), cksum(second)))
			b.stdin.Write(second)
			b.stdin.Close()
			select {
			case code := <-b.done:
				t.Fatalf("the second writer ran while the first held the lock: exit %d %s", code, b.err.String())
			case <-time.After(1500 * time.Millisecond):
			}
			a.stdin.Write(first)
			a.stdin.Close()
			if code := <-a.done; code != 0 {
				t.Fatalf("first writer: exit %d %s", code, a.err.String())
			}
			if code := <-b.done; code != akExitChanged {
				t.Errorf("second writer: exit %d %s, want %d (changed)", code, b.err.String(), akExitChanged)
			}
			if got, _ := os.ReadFile(f); !bytes.Equal(got, first) {
				t.Errorf("authorized_keys: %q", got)
			}
			if entries, _ := os.ReadDir(filepath.Join(home, ".ssh")); len(entries) != 1 {
				t.Errorf("~/.ssh holds %d entries, want only authorized_keys", len(entries))
			}
		})
	}
}

// The lock is a directory with this run's token, PID and time in it while
// the run holds it, and gone when the run ends.
func TestAKWriteScriptLockNamesItsOwner(t *testing.T) {
	orig, next := []byte("a\n"), []byte("a\nb\n")
	home, f := akHome(t, orig)
	a := startAKWriter(t, home, os.Getenv("PATH"), akWriteScript(cksum(orig), cksum(next)))
	waitFor(t, "the writer to take the lock", func() bool { return holdsTemp(home) })
	fields := strings.Fields(lockOwner(home))
	if len(fields) != 3 || len(fields[0]) != 32 {
		t.Fatalf("owner %q, want the token, PID and time", lockOwner(home))
	}
	if pid, err := strconv.Atoi(fields[1]); err != nil || syscall.Kill(pid, 0) != nil {
		t.Errorf("owner PID %q is not a running process: %v", fields[1], err)
	}
	if _, err := time.Parse(time.RFC3339, fields[2]); err != nil {
		t.Errorf("owner time: %v", err)
	}
	a.stdin.Write(next)
	a.stdin.Close()
	if code := <-a.done; code != 0 {
		t.Fatalf("exit %d %s", code, a.err.String())
	}
	if got, _ := os.ReadFile(f); !bytes.Equal(got, next) {
		t.Errorf("authorized_keys: %q", got)
	}
	if entries, _ := os.ReadDir(filepath.Join(home, ".ssh")); len(entries) != 1 {
		t.Errorf("~/.ssh holds %d entries, want only authorized_keys", len(entries))
	}
}

// A lock left over is never taken over, whatever its age and whether its
// PID still runs: its run may still be going. The edit stops with nothing
// changed, and the message says who holds the lock and how to remove it.
func TestAKWriteScriptLeftOverLockFailsClosed(t *testing.T) {
	defer func(w int) { akLockWait = w }(akLockWait)
	akLockWait = 1
	gone := exec.Command("sh", "-c", "exit 0")
	if err := gone.Run(); err != nil {
		t.Fatal(err)
	}
	const at = "2026-10-28T09:15:00Z"
	for _, c := range []struct {
		name, owner string
		want        []string
	}{
		{"its process is gone", fmt.Sprintf("other-token %d %s\n", gone.Process.Pid, at),
			[]string{fmt.Sprintf("process %d took it at %s, on the machine that took it", gone.Process.Pid, at)}},
		{"its process still runs", fmt.Sprintf("other-token %d %s\n", os.Getpid(), at),
			[]string{fmt.Sprintf("process %d took it at %s, on the machine that took it", os.Getpid(), at)}},
		{"no owner", "", []string{"with no owner in it"}},
	} {
		t.Run(c.name, func(t *testing.T) {
			orig, next := []byte("a\n"), []byte("a\nb\n")
			home, f := akHome(t, orig)
			lock := filepath.Join(home, ".ssh", testLockDir)
			if err := os.Mkdir(lock, 0o700); err != nil {
				t.Fatal(err)
			}
			if c.owner != "" {
				if err := os.WriteFile(filepath.Join(lock, "owner"), []byte(c.owner), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			old := time.Now().Add(-24 * time.Hour)
			os.Chtimes(lock, old, old)

			code, stderr := runAKScriptPath(t, home, os.Getenv("PATH"), akWriteScript(cksum(orig), cksum(next)), next)
			want := append(c.want, "~/.ssh/"+testLockDir+" ", "rm -r ~/.ssh/"+testLockDir+")",
				"hop key rotate and hop access both use this lock",
				"on every device you use, and on every machine that shares this home directory")
			if code != akExitLocked {
				t.Errorf("exit %d %q, want %d", code, stderr, akExitLocked)
			}
			for _, w := range want {
				if !strings.Contains(stderr, w) {
					t.Errorf("the message %q does not say %q", stderr, w)
				}
			}
			// The PID is shown, never probed: it may be another machine's.
			if strings.Contains(stderr, "running") || strings.Contains(stderr, "this host") {
				t.Errorf("the message judges the owner's PID: %q", stderr)
			}
			// The waiter made nothing and removed nothing.
			if entries, _ := os.ReadDir(filepath.Join(home, ".ssh")); len(entries) != 2 {
				t.Errorf("~/.ssh holds %d entries, want authorized_keys and the lock", len(entries))
			}
			if got, _ := os.ReadFile(f); !bytes.Equal(got, orig) {
				t.Errorf("written under another's lock: %q", got)
			}
			if fi, err := os.Stat(lock); err != nil || !fi.IsDir() || lockOwner(home) != c.owner {
				t.Errorf("the other run's lock was touched: %q %v", lockOwner(home), err)
			}
		})
	}
}

// A run's traps remove its own lock and never another's: not when the lock
// was replaced while the run held it (a user removed it, and another run
// took it), and not when a run waiting for another's lock is stopped. A run
// that finds its lock replaced says so and exits 89: another run may have
// edited the file at the same time.
func TestAKWriteScriptTrapsKeepAnotherOwnersLock(t *testing.T) {
	const theirs = "other-token 1 2026-10-28T09:15:00Z\n"
	orig, next := []byte("a\n"), []byte("a\nb\n")
	takeOver := func(t *testing.T, home string) {
		t.Helper()
		lock := filepath.Join(home, ".ssh", testLockDir)
		if err := os.RemoveAll(lock); err != nil {
			t.Fatal(err)
		}
		if err := os.Mkdir(lock, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(lock, "owner"), []byte(theirs), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	held := func(home string) bool { return holdsTemp(home) && lockOwner(home) != "" }

	t.Run("replaced, the run exits", func(t *testing.T) {
		home, _ := akHome(t, orig)
		a := startAKShell(t, home, os.Getenv("PATH"), akWriteScript(cksum(orig), cksum(next)))
		waitFor(t, "the writer to take the lock", func() bool { return held(home) })
		takeOver(t, home)
		a.stdin.Write(next)
		a.stdin.Close()
		if code := <-a.done; code != akExitCleanup || !strings.Contains(a.err.String(), "was removed, replaced or unreadable when this hop run went to release it") {
			t.Fatalf("exit %d %s, want %d and the lost-lock message", code, a.err.String(), akExitCleanup)
		}
		if lockOwner(home) != theirs {
			t.Errorf("the writer removed another owner's lock: owner %q", lockOwner(home))
		}
		if holdsTemp(home) {
			t.Error("the session directory is still there")
		}
	})
	t.Run("replaced, the run is stopped", func(t *testing.T) {
		home, _ := akHome(t, orig)
		a := startAKShell(t, home, os.Getenv("PATH"), akWriteScript(cksum(orig), cksum(next)))
		waitFor(t, "the writer to take the lock", func() bool { return held(home) })
		takeOver(t, home)
		syscall.Kill(-a.cmd.Process.Pid, syscall.SIGTERM)
		if code := <-a.done; code != akExitCleanup {
			t.Errorf("exit %d %s, want %d", code, a.err.String(), akExitCleanup)
		}
		if lockOwner(home) != theirs {
			t.Errorf("the stopped writer removed another owner's lock: owner %q", lockOwner(home))
		}
	})
	t.Run("waiting, the run is stopped", func(t *testing.T) {
		home, _ := akHome(t, orig)
		takeOver(t, home)
		a := startAKShell(t, home, os.Getenv("PATH"), akWriteScript(cksum(orig), cksum(next)))
		time.Sleep(1500 * time.Millisecond) // in its wait loop
		syscall.Kill(-a.cmd.Process.Pid, syscall.SIGTERM)
		if code := <-a.done; code != 86 {
			t.Errorf("exit %d %s, want 86", code, a.err.String())
		}
		if lockOwner(home) != theirs {
			t.Errorf("a stopped waiter removed another owner's lock: owner %q", lockOwner(home))
		}
	})
	t.Run("its own, the run is stopped", func(t *testing.T) {
		home, f := akHome(t, orig)
		a := startAKShell(t, home, os.Getenv("PATH"), akWriteScript(cksum(orig), cksum(next)))
		waitFor(t, "the writer to take the lock", func() bool { return held(home) })
		syscall.Kill(-a.cmd.Process.Pid, syscall.SIGTERM)
		if code := <-a.done; code != 86 {
			t.Errorf("exit %d %s, want 86", code, a.err.String())
		}
		if entries, _ := os.ReadDir(filepath.Join(home, ".ssh")); len(entries) != 1 {
			t.Errorf("~/.ssh holds %d entries after a stopped run, want only authorized_keys", len(entries))
		}
		if got, _ := os.ReadFile(f); !bytes.Equal(got, orig) {
			t.Errorf("authorized_keys: %q", got)
		}
	})
}
