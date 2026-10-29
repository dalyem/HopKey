//go:build unix

package cli

import (
	"bytes"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

// The lock of the authorized_keys write script. The paths are spelled out:
// they are what a user finds in ~/.ssh and may have to remove.
const (
	testLockFile = ".hop-authorized_keys.lock"
	testLockDir  = ".hop-authorized_keys.lock.d"
)

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
	w := &akWriter{done: make(chan int, 1)}
	w.cmd = exec.Command("sh", "-c", sh(script))
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
	go func() {
		err := w.cmd.Wait()
		code := 0
		if ee, ok := err.(*exec.ExitError); ok {
			code = ee.ExitCode()
		}
		w.done <- code
	}()
	t.Cleanup(func() {
		syscall.Kill(-w.cmd.Process.Pid, syscall.SIGKILL)
	})
	return w
}

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
// its temp file in ~/.ssh.
func holdsTemp(home string) bool {
	m, _ := filepath.Glob(filepath.Join(home, ".ssh", ".authorized_keys.hop-*"))
	return len(m) > 0
}

// With flock, a second writer waits for the first and then finds the file
// changed under it: the two never edit at once.
func TestAKWriteScriptFlockSerializesWriters(t *testing.T) {
	requireFlock(t)
	defer func(w int) { akLockWait = w }(akLockWait)
	akLockWait = 5
	orig := []byte("a\n")
	home, f := akHome(t, orig)
	first, second := []byte("a\nfirst\n"), []byte("a\nsecond\n")

	a := startAKWriter(t, home, os.Getenv("PATH"), akWriteScript(cksum(orig), cksum(first)))
	waitFor(t, "the first writer to take the lock", func() bool { return holdsTemp(home) })
	b := startAKWriter(t, home, os.Getenv("PATH"), akWriteScript(cksum(orig), cksum(second)))
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
	if fi, err := os.Stat(filepath.Join(home, ".ssh", testLockFile)); err != nil || !fi.Mode().IsRegular() {
		t.Errorf("the flock lock is not a file: %v", err)
	}
}

// A writer that is killed holding the flock does not keep the next one
// out, though the lock file is still there: the kernel let go of the lock
// with the process.
func TestAKWriteScriptFlockIsReleasedWhenTheWriterDies(t *testing.T) {
	requireFlock(t)
	defer func(w int) { akLockWait = w }(akLockWait)
	akLockWait = 2
	orig := []byte("a\n")
	home, f := akHome(t, orig)
	a := startAKWriter(t, home, os.Getenv("PATH"), akWriteScript(cksum(orig), cksum([]byte("x\n"))))
	waitFor(t, "the writer to take the lock", func() bool { return holdsTemp(home) })
	syscall.Kill(-a.cmd.Process.Pid, syscall.SIGKILL)
	<-a.done

	next := []byte("a\nb\n")
	if code, _, stderr := runAKScript(t, home, akWriteScript(cksum(orig), cksum(next)), next); code != 0 {
		t.Fatalf("after a killed writer: exit %d %q", code, stderr)
	}
	if got, _ := os.ReadFile(f); !bytes.Equal(got, next) {
		t.Errorf("authorized_keys: %q", got)
	}
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

// Without flock, the lock is a directory with this run's token in it,
// removed when the run ends.
func TestAKWriteScriptMkdirLock(t *testing.T) {
	path := noFlockPath(t)
	orig, next := []byte("a\n"), []byte("a\nb\n")
	home, f := akHome(t, orig)
	if code, stderr := runAKScriptPath(t, home, path, akWriteScript(cksum(orig), cksum(next)), next); code != 0 {
		t.Fatalf("exit %d %q", code, stderr)
	}
	if got, _ := os.ReadFile(f); !bytes.Equal(got, next) {
		t.Errorf("authorized_keys: %q", got)
	}
	if entries, _ := os.ReadDir(filepath.Join(home, ".ssh")); len(entries) != 1 {
		t.Errorf("~/.ssh holds %d entries, want only authorized_keys", len(entries))
	}
}

// An old mkdir lock is never taken over: its run may still be going on the
// server after its ssh died. The edit stops with nothing changed, and the
// message names the directory to remove.
func TestAKWriteScriptStaleMkdirLockFailsClosed(t *testing.T) {
	defer func(w int) { akLockWait = w }(akLockWait)
	akLockWait = 1
	path := noFlockPath(t)
	orig, next := []byte("a\n"), []byte("a\nb\n")
	home, f := akHome(t, orig)
	lock := filepath.Join(home, ".ssh", testLockDir)
	if err := os.Mkdir(lock, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(lock, "owner"), []byte("someone-else\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	old := time.Now().Add(-time.Hour)
	os.Chtimes(lock, old, old)

	code, stderr := runAKScriptPath(t, home, path, akWriteScript(cksum(orig), cksum(next)), next)
	if code != akExitLocked || !strings.Contains(stderr, "~/.ssh/"+testLockDir) || !strings.Contains(stderr, "remove it") {
		t.Errorf("stale lock: exit %d %q", code, stderr)
	}
	if got, _ := os.ReadFile(f); !bytes.Equal(got, orig) {
		t.Errorf("written under another's lock: %q", got)
	}
	if b, err := os.ReadFile(filepath.Join(lock, "owner")); err != nil || string(b) != "someone-else\n" {
		t.Errorf("the other run's lock was touched: %q %v", b, err)
	}
}

// The lock is replaced while a run holds it (a user removed it, and
// another run took it): the first run's exit does not remove the new
// owner's lock.
func TestAKWriteScriptKeepsAnotherOwnersLock(t *testing.T) {
	path := noFlockPath(t)
	orig, next := []byte("a\n"), []byte("a\nb\n")
	home, _ := akHome(t, orig)
	lock := filepath.Join(home, ".ssh", testLockDir)
	a := startAKWriter(t, home, path, akWriteScript(cksum(orig), cksum(next)))
	waitFor(t, "the writer to take the lock", func() bool {
		b, err := os.ReadFile(filepath.Join(lock, "owner"))
		return err == nil && len(b) > 0 && holdsTemp(home)
	})
	if err := os.RemoveAll(lock); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(lock, 0o700); err != nil { // another run's, as an empty directory
		t.Fatal(err)
	}
	a.stdin.Write(next)
	a.stdin.Close()
	if code := <-a.done; code != 0 {
		t.Fatalf("exit %d %s", code, a.err.String())
	}
	if fi, err := os.Stat(lock); err != nil || !fi.IsDir() {
		t.Errorf("the writer removed another owner's lock: %v", err)
	}
}
