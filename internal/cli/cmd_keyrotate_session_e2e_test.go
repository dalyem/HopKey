package cli_test

import (
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/dalyem/hopkey/internal/cli"
)

// hop key rotate against akServer, for the write script's session (spec
// rev 17, §7.5 and §7.7): keepalives on every editing connection, a
// failed mv or an unconfirmed cleanup counted as "may have happened", and
// hop access lines left alone.

// fakeServerBin is a PATH for akServer with the given commands first. Each
// body is a sh script.
func fakeServerBin(t *testing.T, bodies map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	for name, body := range bodies {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("#!/bin/sh\n"+body+"\n"), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	return dir + string(os.PathListSeparator) + os.Getenv("PATH")
}

// Every ssh that runs the write script carries the keepalive options, with
// hop's generated config (the first write, over the old key) and with a
// check config (the second, over the new key alone).
func TestKeyRotateWritesCarryKeepalives(t *testing.T) {
	w := newRotWorld(t, rotWorldOpts{})
	sshPath, err := exec.LookPath("ssh")
	if err != nil {
		t.Fatal(err)
	}
	argvLog := filepath.Join(w.base, "ssh-argv")
	wrapper := filepath.Join(w.base, "ssh-wrapper")
	script := "#!/bin/sh\n{ printf '%s\\037' \"$@\"; echo; } >> '" + argvLog + "'\nexec '" + sshPath + "' \"$@\"\n"
	if err := os.WriteFile(wrapper, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	w.sshBin = wrapper

	code, stdout, stderr := w.hop(t, "key", "rotate", "deploy-key", "--hosts", "web-1", "--yes", "--json")
	t.Logf("hop key rotate (exit %d)\n%s\nstderr: %s", code, stdout, stderr)
	if h := decodeRotateHosts(t, stdout)["web-1"]; code != 0 || h.Status != "rotated" {
		t.Fatalf("exit %d, web-1 %+v", code, h)
	}
	b, err := os.ReadFile(argvLog)
	if err != nil {
		t.Fatal(err)
	}
	var generated, check int
	for _, line := range strings.Split(strings.TrimSuffix(string(b), "\n"), "\n") {
		argv := strings.Split(strings.TrimSuffix(line, "\x1f"), "\x1f")
		if !strings.Contains(argv[len(argv)-1], ".hop-s.") {
			continue
		}
		for _, o := range []string{"ServerAliveInterval=15", "ServerAliveCountMax=3"} {
			if i := slices.Index(argv, o); i < 1 || argv[i-1] != "-o" {
				t.Errorf("a write runs without -o %s: %q", o, argv[:len(argv)-1])
			}
		}
		if slices.Contains(argv, "hop-rotate-check") {
			check++
		} else {
			generated++
		}
	}
	if generated == 0 || check == 0 {
		t.Errorf("writes seen: %d with the generated config, %d with a check config; want both", generated, check)
	}
}

// mv fails on the server: hop can't tell whether the file was replaced
// (86), reads it again, finds it as it was, and says so.
func TestKeyRotateFailedMvIsUncertain(t *testing.T) {
	w := newRotWorld(t, rotWorldOpts{})
	w.srv[0].setPath(fakeServerBin(t, map[string]string{"mv": "exit 1"}))
	code, stdout, stderr := w.hop(t, "key", "rotate", "deploy-key", "--hosts", "web-1", "--yes", "--json")
	t.Logf("hop key rotate (exit %d)\n%s\nstderr: %s", code, stdout, stderr)
	h := decodeRotateHosts(t, stdout)["web-1"]
	if code == 0 || h.Status != "failed" || !strings.Contains(h.Reason, "hop could not tell whether it replaced ~/.ssh/authorized_keys (exit status 86)") ||
		!strings.Contains(h.Reason, "put back as it was") {
		t.Errorf("exit %d, web-1 %+v", code, h)
	}
	if got, _ := w.authorizedKeys(t, 0); got != w.orig[0] {
		t.Errorf("authorized_keys:\n%s\nwant:\n%s", got, w.orig[0])
	}
	entries, _ := os.ReadDir(filepath.Join(w.srv[0].home, ".ssh"))
	for _, e := range entries {
		if e.Name() != "authorized_keys" {
			t.Errorf("left in ~/.ssh: %s", e.Name())
		}
	}
	if w.keyNamed(t, "deploy-key") == nil || w.hostKeyID(t, "web-1") != w.keyID {
		t.Error("the old key is gone, or web-1 moved off it")
	}
}

// The script renames the file but can't confirm that it removed its
// session directory (89): it keeps the lock, and hop treats the host as
// "may have changed": it needs attention, and both keys stay.
func TestKeyRotateUnconfirmedCleanupKeepsTheLock(t *testing.T) {
	cli.SetAKLockWait(t, 1)
	w := newRotWorld(t, rotWorldOpts{})
	rmdir, err := exec.LookPath("rmdir")
	if err != nil {
		t.Fatal(err)
	}
	w.srv[0].setPath(fakeServerBin(t, map[string]string{
		"rmdir": `case "$1" in *.hop-s.*) exit 1 ;; esac; exec '` + rmdir + `' "$@"`,
	}))
	code, stdout, stderr := w.hop(t, "key", "rotate", "deploy-key", "--hosts", "web-1", "--yes", "--json")
	t.Logf("hop key rotate (exit %d)\n%s\nstderr: %s", code, stdout, stderr)
	res := decodeRotate(t, stdout)
	h := decodeRotateHosts(t, stdout)["web-1"]
	if code == 0 || h.Status != "needs-attention" || !strings.Contains(h.Reason, "hop could not tell whether it replaced") ||
		!strings.Contains(h.Reason, "could not confirm that it removed its session directory ~/.ssh/.hop-s.") {
		t.Errorf("exit %d, web-1 %+v", code, h)
	}
	if w.keyNamed(t, "deploy-key") == nil || w.keyNamed(t, res.Keys[0].NewKey) == nil {
		t.Errorf("both keys should stay: %+v", res.Keys[0])
	}
	lock := filepath.Join(w.srv[0].home, ".ssh", ".hop-authorized_keys.lock.d")
	if b, err := os.ReadFile(filepath.Join(lock, "owner")); err != nil || len(strings.Fields(string(b))) != 3 {
		t.Errorf("the lock was released: %q %v", b, err)
	}
}

// A hop access line that holds the old key is not rotate's: it keeps it
// byte for byte, never copies its options, and never calls the host done
// while the line is there. Tombstones are kept byte for byte too.
func TestKeyRotateLeavesHopAccessLines(t *testing.T) {
	const record = "0123456789abcdef0123456789abcdef"
	w := newRotWorld(t, rotWorldOpts{})
	access := []string{
		`restrict,from="127.0.0.1" ` + authorizedKeysLine(w.oldKey.PublicKey()) + " hop-access:" + record,
		"# hop-access-removed " + record + " 2",
		" \t# HOP-ACCESS-REMOVED x 0\r",
		authorizedKeysLine(newSigner(t).PublicKey()) + " hop-access:ffffffffffffffffffffffffffffffff",
	}
	f := filepath.Join(w.srv[0].home, ".ssh", "authorized_keys")
	orig := w.orig[0] + strings.Join(access, "\n") + "\n"
	if err := os.WriteFile(f, []byte(orig), 0o640); err != nil {
		t.Fatal(err)
	}
	keeps := func(what string) string {
		t.Helper()
		got, _ := w.authorizedKeys(t, 0)
		for _, l := range access {
			if n := strings.Count("\n"+got, "\n"+l+"\n"); n != 1 {
				t.Errorf("%s: %q is there %d times, want once, byte for byte", what, l, n)
			}
		}
		return got
	}

	code, stdout, stderr := w.hop(t, "key", "rotate", "deploy-key", "--hosts", "web-1", "--yes", "--json")
	t.Logf("hop key rotate (exit %d)\n%s\nstderr: %s", code, stdout, stderr)
	res := decodeRotate(t, stdout)
	h := decodeRotateHosts(t, stdout)["web-1"]
	want := "the host now uses the new key, but a hop access line (record " + record + ") still authorizes the old key; rotate left it"
	if code == 0 || h.Status != "needs-attention" || !strings.HasPrefix(h.Reason, want) {
		t.Errorf("exit %d, web-1 %+v\nwant a reason starting %q", code, h, want)
	}
	// The old-key check never ran, and the report doesn't say the server
	// takes only the new key.
	if strings.Contains(h.Reason, "still logs in") || strings.Contains(h.Reason, "takes only the new key") {
		t.Errorf("reason %q", h.Reason)
	}
	if w.keyNamed(t, "deploy-key") == nil || res.Keys[0].OldKey != "kept" {
		t.Errorf("the old key was deleted: %+v", res.Keys[0])
	}
	newKey := w.keyNamed(t, res.Keys[0].NewKey)
	if newKey == nil || w.hostKeyID(t, "web-1") != newKey.ItemID {
		t.Fatal("web-1 is not on the new key")
	}
	got := keeps("after the rotation")
	// One new line, with the options of rotate's own old line only.
	var newLines []string
	for _, l := range strings.Split(got, "\n") {
		if strings.Contains(l, "hop-rotated") {
			newLines = append(newLines, l)
		}
	}
	if len(newLines) != 1 || !strings.HasPrefix(newLines[0], rotOptions+" ") {
		t.Errorf("new key lines %q, want one with %s", newLines, rotOptions)
	}

	// The fix the report names finds the line still there: never
	// already-rotated.
	if h.Fix == "" {
		t.Fatal("no fix named")
	}
	args := append(strings.Fields(h.Fix)[1:], "--yes", "--json")
	code, stdout, stderr = w.hop(t, args...)
	t.Logf("hop %s (exit %d)\n%s\nstderr: %s", strings.Join(args, " "), code, stdout, stderr)
	if h := decodeRotateHosts(t, stdout)["web-1"]; code == 0 || h.Status != "needs-attention" || !strings.Contains(h.Reason, "a hop access line (record "+record+") still authorizes the old key") {
		t.Errorf("the fix: exit %d, web-1 %+v", code, h)
	}
	if w.keyNamed(t, "deploy-key") == nil {
		t.Error("the fix deleted the old key")
	}
	if again := keeps("after the fix"); again != got {
		t.Errorf("the fix changed authorized_keys:\n%s\nwas:\n%s", again, got)
	}
}

// When the old key is only on hop access lines, rotate has nothing to do
// on that host, and changes nothing.
func TestKeyRotateOldKeyOnlyOnHopAccessLines(t *testing.T) {
	const record = "0123456789abcdef0123456789abcdef"
	w := newRotWorld(t, rotWorldOpts{})
	f := filepath.Join(w.srv[0].home, ".ssh", "authorized_keys")
	content := strings.Replace(w.orig[0], " deploy@old\n", " hop-access:"+record+"\n", 1)
	if err := os.WriteFile(f, []byte(content), 0o640); err != nil {
		t.Fatal(err)
	}
	code, stdout, stderr := w.hop(t, "key", "rotate", "deploy-key", "--hosts", "web-1", "--yes", "--json")
	t.Logf("hop key rotate (exit %d)\n%s\nstderr: %s", code, stdout, stderr)
	if h := decodeRotateHosts(t, stdout)["web-1"]; code == 0 || h.Status != "failed" ||
		!strings.Contains(h.Reason, "only on hop access lines (record "+record+"), which rotate doesn't touch") {
		t.Errorf("exit %d, web-1 %+v", code, h)
	}
	if got, _ := w.authorizedKeys(t, 0); got != content {
		t.Errorf("authorized_keys changed:\n%s", got)
	}
}
