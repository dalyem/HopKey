//go:build unix

package cli

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"syscall"
	"testing"
	"time"
)

// The write script's session: its own directory, named by the run's token,
// a hard-link probe before anything is written, and a cleanup that trusts
// only the exit statuses of rm and rmdir (spec rev 17, §7.5 and §7.7).

// akShell is a shell the write script runs under, as sh.
type akShell struct{ name, path string }

// akInterpreters are the shells on this machine that hosts run as sh. Each
// is started through a link named sh, so bash and busybox act as sh does.
// dash and bash are in the check image and must be there under
// HOPKEY_REQUIRE_SSH; they are the shells hop's support claim rests on.
// The others run only where they are installed, and the log names the ones
// that were not.
func akInterpreters(t *testing.T) []akShell {
	t.Helper()
	var out []akShell
	var missing []string
	defer func() {
		if len(missing) > 0 {
			t.Logf("NOT TESTED as sh (not installed): %s", strings.Join(missing, ", "))
		}
	}()
	for _, c := range []struct {
		name, bin string
		required  bool
	}{
		{"dash", "dash", true},
		{"bash as sh", "bash", true},
		{"busybox ash", "busybox", false},
		{"mksh", "mksh", false},
		{"ksh", "ksh", false},
		{"zsh as sh", "zsh", false},
	} {
		p, err := exec.LookPath(c.bin)
		if err != nil {
			if c.required && os.Getenv("HOPKEY_REQUIRE_SSH") != "" {
				t.Fatalf("%s is not installed", c.bin)
			}
			missing = append(missing, c.name)
			continue
		}
		link := filepath.Join(t.TempDir(), "sh")
		if err := os.Symlink(p, link); err != nil {
			t.Fatal(err)
		}
		out = append(out, akShell{c.name, link})
	}
	return out
}

// fakeBin is a directory of commands that stand in for the real ones,
// to put first on PATH. Each body is a sh script.
func fakeBin(t *testing.T, bodies map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	for name, body := range bodies {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("#!/bin/sh\n"+body+"\n"), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	return dir + string(os.PathListSeparator) + os.Getenv("PATH")
}

func runAKIn(t *testing.T, shell, home, path, script string, stdin []byte) (int, string) {
	t.Helper()
	cmd := exec.Command(shell, "-c", script)
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

// sshEntries lists ~/.ssh, recursively, with the content of each file.
func sshEntries(t *testing.T, home string) []string {
	t.Helper()
	var out []string
	root := filepath.Join(home, ".ssh")
	filepath.Walk(root, func(p string, fi os.FileInfo, err error) error {
		if err != nil || p == root {
			return err
		}
		rel, _ := filepath.Rel(root, p)
		if fi.IsDir() {
			out = append(out, rel+"/")
		} else {
			b, _ := os.ReadFile(p)
			out = append(out, rel+"="+string(b))
		}
		return nil
	})
	return out
}

// onlyAK fails the test unless ~/.ssh holds authorized_keys and nothing
// else: no session directory, no probe link, no lock.
func onlyAK(t *testing.T, home string) {
	t.Helper()
	if entries, _ := os.ReadDir(filepath.Join(home, ".ssh")); len(entries) != 1 || entries[0].Name() != "authorized_keys" {
		t.Errorf("~/.ssh holds %v, want only authorized_keys", sshEntries(t, home))
	}
}

var tokenRE = regexp.MustCompile(`\.hop-s\.([0-9a-f]{32})"`)

// scriptToken is the token a write script was built with.
func scriptToken(t *testing.T, script string) string {
	t.Helper()
	m := tokenRE.FindStringSubmatch(script)
	if m == nil {
		t.Fatalf("no session directory in the script: %s", script)
	}
	return m[1]
}

// Every exit status of the write script, under each shell a host may run
// it with: what it leaves in authorized_keys, in ~/.ssh, and in the lock.
func TestAKWriteScriptUnderEachShell(t *testing.T) {
	defer func(w int) { akLockWait = w }(akLockWait)
	akLockWait = 1
	shells := akInterpreters(t)
	if len(shells) == 0 {
		t.Skip("no shell to test with")
	}
	for _, sh := range shells {
		t.Run(sh.name, func(t *testing.T) { akScriptCases(t, sh.path) })
	}
}

func akScriptCases(t *testing.T, shell string) {
	orig, next := []byte("a\n"), []byte("a\nb\n")
	path := os.Getenv("PATH")
	script := func() string { return akWriteScript(cksum(orig), cksum(next)) }
	home := func(t *testing.T) (string, string) {
		h, f := akHome(t, orig)
		os.Chmod(f, 0o640)
		return h, f
	}
	unchanged := func(t *testing.T, f string) {
		t.Helper()
		if got, _ := os.ReadFile(f); !bytes.Equal(got, orig) {
			t.Errorf("authorized_keys changed: %q", got)
		}
	}

	t.Run("written", func(t *testing.T) {
		h, f := home(t)
		if code, stderr := runAKIn(t, shell, h, path, script(), next); code != 0 {
			t.Fatalf("exit %d %q", code, stderr)
		}
		got, _ := os.ReadFile(f)
		fi, _ := os.Stat(f)
		if !bytes.Equal(got, next) || fi.Mode().Perm() != 0o640 {
			t.Errorf("after the write: %q mode %v", got, fi.Mode().Perm())
		}
		onlyAK(t, h)
	})
	t.Run("83 changed", func(t *testing.T) {
		h, f := home(t)
		code, stderr := runAKIn(t, shell, h, path, akWriteScript(cksum(next), cksum(orig)), orig)
		if code != akExitChanged || !strings.Contains(stderr, "changed while hop was editing it") {
			t.Errorf("exit %d %q, want %d", code, stderr, akExitChanged)
		}
		unchanged(t, f)
		onlyAK(t, h)
	})
	t.Run("84 cut short", func(t *testing.T) {
		h, f := home(t)
		if code, stderr := runAKIn(t, shell, h, path, script(), next[:2]); code != akExitWrite {
			t.Errorf("exit %d %q, want %d", code, stderr, akExitWrite)
		}
		unchanged(t, f)
		onlyAK(t, h)
	})
	t.Run("84 hard-link probe refused", func(t *testing.T) {
		h, f := home(t)
		ran := filepath.Join(t.TempDir(), "mv-ran")
		p := fakeBin(t, map[string]string{
			"ln": "exit 1",
			"mv": `: > "` + ran + `"; exit 1`,
		})
		code, stderr := runAKIn(t, shell, h, p, script(), next)
		if code != akExitWrite || !strings.Contains(stderr, akProbeMsg) {
			t.Errorf("exit %d %q, want %d and the probe message", code, stderr, akExitWrite)
		}
		if _, err := os.Stat(ran); err == nil {
			t.Error("mv ran after the probe failed")
		}
		unchanged(t, f)
		onlyAK(t, h)
	})
	t.Run("84 session directory exists", func(t *testing.T) {
		h, f := home(t)
		const token = "0123456789abcdef0123456789abcdef"
		planted := filepath.Join(h, ".ssh", ".hop-s."+token)
		if err := os.Mkdir(planted, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(planted, "new"), []byte("theirs\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		before := sshEntries(t, h)
		code, stderr := runAKIn(t, shell, h, path, akTokenScript(token, cksum(orig), cksum(next)), next)
		if code != akExitWrite || !strings.Contains(stderr, "cannot create ~/.ssh/.hop-s."+token) {
			t.Errorf("exit %d %q, want %d", code, stderr, akExitWrite)
		}
		unchanged(t, f)
		// The planted directory is untouched, and the lock released.
		if after := sshEntries(t, h); !slices.Equal(before, after) {
			t.Errorf("~/.ssh: %v, want %v", after, before)
		}
	})
	t.Run("85 held", func(t *testing.T) {
		h, f := home(t)
		lock := filepath.Join(h, ".ssh", testLockDir)
		os.Mkdir(lock, 0o700)
		const owner = "other-token 4242 2026-10-28T09:15:00Z\n"
		os.WriteFile(filepath.Join(lock, "owner"), []byte(owner), 0o600)
		// The holder's own files, which a waiter must never touch.
		theirs := filepath.Join(h, ".ssh", ".hop-s.other-token")
		os.Mkdir(theirs, 0o700)
		os.WriteFile(filepath.Join(theirs, "new"), []byte("theirs\n"), 0o600)
		before := sshEntries(t, h)
		code, stderr := runAKIn(t, shell, h, path, script(), next)
		want := strings.NewReplacer("LOCK", "~/.ssh/"+testLockDir, "$op", "4242", "$ow", "2026-10-28T09:15:00Z").Replace(akHeldMsg) + "\n"
		if code != akExitLocked || stderr != want {
			t.Errorf("exit %d %q\nwant %d %q", code, stderr, akExitLocked, want)
		}
		unchanged(t, f)
		if after := sshEntries(t, h); !slices.Equal(before, after) {
			t.Errorf("a waiter changed ~/.ssh: %v, want %v", after, before)
		}
	})
	t.Run("85 held, no owner", func(t *testing.T) {
		h, f := home(t)
		os.Mkdir(filepath.Join(h, ".ssh", testLockDir), 0o700)
		code, stderr := runAKIn(t, shell, h, path, script(), next)
		want := strings.ReplaceAll(akNoOwnerMsg, "LOCK", "~/.ssh/"+testLockDir) + "\n"
		if code != akExitLocked || stderr != want {
			t.Errorf("exit %d %q\nwant %d %q", code, stderr, akExitLocked, want)
		}
		unchanged(t, f)
	})
	t.Run("86 mv failed", func(t *testing.T) {
		h, f := home(t)
		code, stderr := runAKIn(t, shell, h, fakeBin(t, map[string]string{"mv": "exit 1"}), script(), next)
		if code != akExitUncertain || akRefused(code) {
			t.Errorf("exit %d %q, want %d", code, stderr, akExitUncertain)
		}
		unchanged(t, f)
		onlyAK(t, h) // its directory removed, its lock released
	})

	// The rest stop the script at its stdin, past the lock, and change
	// something under it.
	start := func(t *testing.T, h, s string) *akWriter {
		t.Helper()
		w := startAKIn(t, shell, h, path, s)
		waitFor(t, "the writer to take the lock", func() bool { return holdsTemp(h) })
		return w
	}
	finish := func(w *akWriter) (int, string) {
		w.stdin.Write(next)
		w.stdin.Close()
		return <-w.done, w.err.String()
	}
	t.Run("89 session directory not removed", func(t *testing.T) {
		h, f := home(t)
		s := script()
		token := scriptToken(t, s)
		w := start(t, h, s)
		os.WriteFile(filepath.Join(h, ".ssh", ".hop-s."+token, "planted"), nil, 0o600)
		code, stderr := finish(w)
		if code != akExitCleanup || !strings.Contains(stderr, "could not confirm that it removed its session directory ~/.ssh/.hop-s."+token+", so it left the lock") {
			t.Errorf("exit %d %q, want %d", code, stderr, akExitCleanup)
		}
		if got, _ := os.ReadFile(f); !bytes.Equal(got, next) {
			t.Errorf("authorized_keys: %q", got)
		}
		// The lock is still this run's.
		if fields := strings.Fields(lockOwner(h)); len(fields) != 3 || fields[0] != token {
			t.Errorf("lock owner %q, want this run's token %s", lockOwner(h), token)
		}
	})
	t.Run("89 lock replaced", func(t *testing.T) {
		h, _ := home(t)
		w := start(t, h, script())
		const theirs = "other-token 1 2026-10-28T09:15:00Z\n"
		os.WriteFile(filepath.Join(h, ".ssh", testLockDir, "owner"), []byte(theirs), 0o600)
		code, stderr := finish(w)
		if code != akExitCleanup || !strings.Contains(stderr, "was removed, replaced or unreadable when this hop run went to release it") {
			t.Errorf("exit %d %q, want %d", code, stderr, akExitCleanup)
		}
		if lockOwner(h) != theirs {
			t.Errorf("the other owner's lock was touched: %q", lockOwner(h))
		}
		if holdsTemp(h) {
			t.Error("the session directory is still there")
		}
	})
	t.Run("89 lock not removed", func(t *testing.T) {
		h, _ := home(t)
		w := start(t, h, script())
		os.WriteFile(filepath.Join(h, ".ssh", testLockDir, "planted"), nil, 0o600)
		code, stderr := finish(w)
		if code != akExitCleanup || !strings.Contains(stderr, "hop could not remove its lock ~/.ssh/"+testLockDir+". This hop run has finished") {
			t.Errorf("exit %d %q, want %d", code, stderr, akExitCleanup)
		}
		if fi, err := os.Stat(filepath.Join(h, ".ssh", testLockDir)); err != nil || !fi.IsDir() {
			t.Errorf("the lock is gone: %v", err)
		}
	})
	// A signal that comes between a successful mkdir and the flag that
	// says the run made it is held until the flag is set: the lock and
	// the session directory are cleaned up all the same. The fake mkdir
	// makes the directory, then signals the script's shell before it
	// returns.
	realMkdir, err := exec.LookPath("mkdir")
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct{ name, pattern string }{
		{"the lock", "*/" + testLockDir},
		{"the session directory", "*/.hop-s.*"},
	} {
		t.Run("86 TERM right after the mkdir of "+c.name, func(t *testing.T) {
			h, f := home(t)
			p := fakeBin(t, map[string]string{
				"mkdir": `'` + realMkdir + `' "$@" || exit; case "$1" in ` + c.pattern + `) kill -TERM $PPID ;; esac; exit 0`,
			})
			code, stderr := runAKIn(t, shell, h, p, script(), next)
			if code != akExitUncertain {
				t.Errorf("exit %d %q, want %d", code, stderr, akExitUncertain)
			}
			unchanged(t, f)
			onlyAK(t, h) // the lock released, the session directory removed
		})
	}
	// A TERM sent to the script's shell alone, while mv runs in the
	// foreground, waits for mv: nothing is cleaned up and the lock stays
	// until mv returns, and then the script ends as for any signal.
	t.Run("86 TERM to the shell alone waits for mv", func(t *testing.T) {
		h, f := home(t)
		realMv, err := exec.LookPath("mv")
		if err != nil {
			t.Fatal(err)
		}
		dir := t.TempDir()
		started, release := filepath.Join(dir, "mv-started"), filepath.Join(dir, "release")
		p := fakeBin(t, map[string]string{
			"mv": `: > '` + started + `'; until [ -e '` + release + `' ]; do sleep 0.02; done; exec '` + realMv + `' "$@"`,
		})
		w := startAKIn(t, shell, h, p, script())
		w.stdin.Write(next)
		w.stdin.Close()
		waitFor(t, "mv to start", func() bool { _, err := os.Stat(started); return err == nil })
		if err := syscall.Kill(w.cmd.Process.Pid, syscall.SIGTERM); err != nil {
			t.Fatal(err)
		}
		select {
		case code := <-w.done:
			t.Fatalf("the shell exited %d while mv was running: %q", code, w.err.String())
		case <-time.After(300 * time.Millisecond):
		}
		if !holdsTemp(h) {
			t.Error("the session directory was cleaned up while mv was running")
		}
		if fields := strings.Fields(lockOwner(h)); len(fields) != 3 {
			t.Errorf("the lock was released while mv was running: owner %q", lockOwner(h))
		}
		unchanged(t, f)
		if err := os.WriteFile(release, nil, 0o600); err != nil {
			t.Fatal(err)
		}
		if code := <-w.done; code != akExitUncertain {
			t.Errorf("exit %d %q, want %d", code, w.err.String(), akExitUncertain)
		}
		if got, _ := os.ReadFile(f); !bytes.Equal(got, next) {
			t.Errorf("authorized_keys %q: mv did not finish before the cleanup", got)
		}
		onlyAK(t, h)
	})
	t.Run("86 TERM past the lock", func(t *testing.T) {
		h, f := home(t)
		w := start(t, h, script())
		syscall.Kill(-w.cmd.Process.Pid, syscall.SIGTERM)
		if code := <-w.done; code != akExitUncertain {
			t.Errorf("exit %d %q, want %d", code, w.err.String(), akExitUncertain)
		}
		unchanged(t, f)
		onlyAK(t, h)
	})
}

// Through each login shell a host may have, the command hop sends (sh -c
// and the quoted script) reaches sh unchanged: the write goes through, and
// the held-lock message arrives byte for byte. sh, dash and bash must be
// there under HOPKEY_REQUIRE_SSH; the others run only where installed, and
// the log names the ones that were not.
func TestAKWriteScriptThroughLoginShells(t *testing.T) {
	defer func(w int) { akLockWait = w }(akLockWait)
	akLockWait = 1
	tested := 0
	var missing []string
	defer func() {
		if len(missing) > 0 {
			t.Logf("NOT TESTED as login shells (not installed): %s", strings.Join(missing, ", "))
		}
	}()
	for _, name := range []string{"sh", "dash", "bash", "zsh", "ksh", "mksh", "fish", "tcsh", "csh"} {
		shell, err := exec.LookPath(name)
		if err != nil {
			if (name == "sh" || name == "dash" || name == "bash") && os.Getenv("HOPKEY_REQUIRE_SSH") != "" {
				t.Fatalf("%s is not installed", name)
			}
			missing = append(missing, name)
			continue
		}
		tested++
		t.Run(name, func(t *testing.T) {
			orig, next := []byte("a\n"), []byte("a\nb\n")
			h, f := akHome(t, orig)
			if code, stderr := runAKIn(t, shell, h, os.Getenv("PATH"), sh(akWriteScript(cksum(orig), cksum(next))), next); code != 0 {
				t.Fatalf("exit %d %q", code, stderr)
			}
			if got, _ := os.ReadFile(f); !bytes.Equal(got, next) {
				t.Errorf("authorized_keys: %q", got)
			}
			onlyAK(t, h)

			lock := filepath.Join(h, ".ssh", testLockDir)
			os.Mkdir(lock, 0o700)
			os.WriteFile(filepath.Join(lock, "owner"), []byte("other-token 4242 2026-10-28T09:15:00Z\n"), 0o600)
			code, stderr := runAKIn(t, shell, h, os.Getenv("PATH"), sh(akWriteScript(cksum(next), cksum(orig))), orig)
			want := strings.NewReplacer("LOCK", "~/.ssh/"+testLockDir, "$op", "4242", "$ow", "2026-10-28T09:15:00Z").Replace(akHeldMsg) + "\n"
			if code != akExitLocked || stderr != want {
				t.Errorf("exit %d %q\nwant %d %q", code, stderr, akExitLocked, want)
			}
		})
	}
	if tested == 0 {
		t.Skip("no shell to test with")
	}
}

// Two runs whose shells have the same PID (machines that share a home
// directory) used to share a temp file name, and a run that gave up on the
// lock removed the holder's temp file. Each PID namespace's first process
// is PID 1, so two of them stand in for two machines.
func TestAKWriteScriptEqualPIDsShareAHome(t *testing.T) {
	defer func(w int) { akLockWait = w }(akLockWait)
	akLockWait = 1
	unshare, err := exec.LookPath("unshare")
	if err != nil {
		t.Skip("unshare(1) is not installed")
	}
	// -r maps this user to root, which lets -p make a PID namespace; -f
	// forks, so the command is the namespace's first process.
	ns := func(script string) []string { return []string{unshare, "-r", "-p", "-f", "sh", "-c", script} }
	// The same nesting as the write script's, so the same PID.
	probe := ns(sh("echo $$"))
	out, err := exec.Command(probe[0], probe[1:]...).Output()
	if err != nil {
		t.Skipf("no unprivileged PID namespaces here: %v", err)
	}
	pid := strings.TrimSpace(string(out))

	orig, next := []byte("a\n"), []byte("a\nb\n")
	h, f := akHome(t, orig)
	holder := startAKArgv(t, h, os.Getenv("PATH"), ns(sh(akWriteScript(cksum(orig), cksum(next)))))
	waitFor(t, "the holder to take the lock", func() bool { return holdsTemp(h) })
	if fields := strings.Fields(lockOwner(h)); len(fields) != 3 || fields[1] != pid {
		t.Fatalf("holder's owner line %q, want PID %s", lockOwner(h), pid)
	}

	argv := ns(sh(akWriteScript(cksum(orig), cksum(orig))))
	cmd := exec.Command(argv[0], argv[1:]...)
	cmd.Env = []string{"HOME=" + h, "PATH=" + os.Getenv("PATH")}
	cmd.Stdin = bytes.NewReader(orig)
	err = cmd.Run()
	if ee, ok := err.(*exec.ExitError); !ok || ee.ExitCode() != akExitLocked {
		t.Fatalf("waiter: %v, want exit %d", err, akExitLocked)
	}
	if !holdsTemp(h) {
		t.Fatal("the waiter removed the holder's temp file")
	}
	holder.stdin.Write(next)
	holder.stdin.Close()
	if code := <-holder.done; code != 0 {
		t.Fatalf("holder: exit %d %s", code, holder.err.String())
	}
	if got, _ := os.ReadFile(f); !bytes.Equal(got, next) {
		t.Errorf("authorized_keys: %q", got)
	}
	onlyAK(t, h)
}
