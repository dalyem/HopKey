package cli

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

func rotTestKey(t *testing.T) ssh.PublicKey {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	k, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func akText(k ssh.PublicKey) string { return strings.TrimSpace(string(ssh.MarshalAuthorizedKey(k))) }

func TestCksumMatchesPOSIX(t *testing.T) {
	cases := map[string]string{
		"":        "4294967295 0",
		"hello\n": "3015617425 6",
	}
	for in, want := range cases {
		if got := cksum([]byte(in)); got != want {
			t.Errorf("cksum(%q) = %q, want %q", in, got, want)
		}
	}
	// And against the system's cksum, where there is one.
	path, err := exec.LookPath("cksum")
	if err != nil {
		t.Skip("no cksum binary")
	}
	data := bytes.Repeat([]byte("ssh-ed25519 AAAA something\n"), 300)
	cmd := exec.Command(path)
	cmd.Stdin = bytes.NewReader(data)
	out, err := cmd.Output()
	if err != nil {
		t.Fatal(err)
	}
	if got, want := cksum(data), strings.TrimSpace(string(out)); got != want {
		t.Errorf("cksum = %q, system cksum = %q", got, want)
	}
}

func TestParseAKLineKeepsOptionsAsWritten(t *testing.T) {
	k := rotTestKey(t)
	cases := []struct{ line, opts string }{
		{akText(k) + " me@laptop", ""},
		{akText(k), ""},
		{`from="10.0.0.1,192.168.*",no-agent-forwarding ` + akText(k) + " c", `from="10.0.0.1,192.168.*",no-agent-forwarding`},
		{`command="echo a  b",restrict ` + akText(k), `command="echo a  b",restrict`},
		{"  restrict\t" + akText(k) + " x\r", "restrict"},
	}
	for _, c := range cases {
		got, ok := parseAKLine(c.line)
		if !ok {
			t.Errorf("%q: not parsed", c.line)
			continue
		}
		if got.options != c.opts || !bytes.Equal(got.pub.Marshal(), k.Marshal()) {
			t.Errorf("%q: options %q, want %q", c.line, got.options, c.opts)
		}
	}
	for _, l := range []string{"", "   ", "# " + akText(k), "garbage here", "ssh-ed25519 notbase64"} {
		if _, ok := parseAKLine(l); ok {
			t.Errorf("%q parsed as a key", l)
		}
	}
	if got, _ := parseAKLine("cert-authority " + akText(k)); !got.certCA {
		t.Error("cert-authority not noticed")
	}
}

func TestPlanAKEdit(t *testing.T) {
	oldK, newK, other := rotTestKey(t), rotTestKey(t), rotTestKey(t)
	orig := "# managed by hand\n" +
		akText(other) + " alice@laptop\n" +
		`from="127.0.0.1",no-pty ` + akText(oldK) + " deploy@old\n" +
		"\n" +
		`command="/bin/backup",restrict ` + akText(other) + " backup\n" +
		akText(oldK) + "\n"
	ed, err := planAKEdit([]byte(orig), oldK, newK, "hop-rotated 2026-10-28")
	if err != nil {
		t.Fatal(err)
	}
	wantAdded := []string{
		`from="127.0.0.1",no-pty ` + akText(newK) + " hop-rotated 2026-10-28",
		akText(newK) + " hop-rotated 2026-10-28",
	}
	if strings.Join(ed.added, "\n") != strings.Join(wantAdded, "\n") {
		t.Errorf("added:\n%s\nwant:\n%s", strings.Join(ed.added, "\n"), strings.Join(wantAdded, "\n"))
	}
	if want := orig + strings.Join(wantAdded, "\n") + "\n"; string(ed.appended) != want {
		t.Errorf("appended:\n%s\nwant:\n%s", ed.appended, want)
	}
	wantFinal := "# managed by hand\n" +
		akText(other) + " alice@laptop\n" +
		"\n" +
		`command="/bin/backup",restrict ` + akText(other) + " backup\n" +
		strings.Join(wantAdded, "\n") + "\n"
	if string(ed.final) != wantFinal {
		t.Errorf("final:\n%s\nwant:\n%s", ed.final, wantFinal)
	}
	if len(ed.removed) != 2 {
		t.Errorf("removed %q", ed.removed)
	}

	// Run again on the appended file (an earlier run stopped there): no
	// duplicate is added.
	again, err := planAKEdit(ed.appended, oldK, newK, "hop-rotated 2026-10-29")
	if err != nil {
		t.Fatal(err)
	}
	if len(again.added) != 0 || !bytes.Equal(again.appended, ed.appended) || string(again.final) != wantFinal {
		t.Errorf("second plan added %q; final:\n%s", again.added, again.final)
	}

	// No newline at the end: the new line still starts on its own line.
	ed, err = planAKEdit([]byte(akText(oldK)), oldK, newK, "c")
	if err != nil {
		t.Fatal(err)
	}
	if want := akText(oldK) + "\n" + akText(newK) + " c\n"; string(ed.appended) != want {
		t.Errorf("appended %q, want %q", ed.appended, want)
	}

	// The old key is not there, or only as a CA.
	if _, err := planAKEdit([]byte(akText(other)+"\n"), oldK, newK, "c"); err != errOldKeyMissing {
		t.Errorf("missing old key: %v", err)
	}
	if _, err := planAKEdit([]byte("cert-authority "+akText(oldK)+"\n"), oldK, newK, "c"); err != errOldKeyCertCA {
		t.Errorf("cert-authority only: %v", err)
	}
}

func TestRollbackAK(t *testing.T) {
	oldK, newK, other := rotTestKey(t), rotTestKey(t), rotTestKey(t)
	orig := akText(other) + " a\n" + "restrict " + akText(oldK) + " b\n"
	ed, err := planAKEdit([]byte(orig), oldK, newK, "c")
	if err != nil {
		t.Fatal(err)
	}
	// From the appended state: the new line goes.
	if got, changed := rollbackAK(ed.appended, ed); !changed || string(got) != orig {
		t.Errorf("rollback of appended = %q, want %q", got, orig)
	}
	// From the final state: the new line goes and the old one comes back.
	if got, changed := rollbackAK(ed.final, ed); !changed || string(got) != akText(other)+" a\n"+"restrict "+akText(oldK)+" b\n" {
		t.Errorf("rollback of final = %q", got)
	}
	// A line someone else added meanwhile stays.
	cur := string(ed.appended) + "ssh-rsa AAAAB3 added-meanwhile\n"
	got, _ := rollbackAK([]byte(cur), ed)
	if string(got) != orig+"ssh-rsa AAAAB3 added-meanwhile\n" {
		t.Errorf("rollback dropped someone else's line: %q", got)
	}
	// Nothing to undo.
	if _, changed := rollbackAK([]byte(orig), ed); changed {
		t.Error("rollback of the original changed it")
	}
}

func TestRotatedName(t *testing.T) {
	now := time.Date(2026, 10, 28, 23, 0, 0, 0, time.UTC)
	taken := map[string]bool{"deploy": true}
	if got := rotatedName("deploy", now, taken); got != "deploy-rotated-2026-10-28" {
		t.Errorf("got %q", got)
	}
	taken["deploy-rotated-2026-10-28"] = true
	if got := rotatedName("deploy", now, taken); got != "deploy-rotated-2026-10-28-2" {
		t.Errorf("got %q", got)
	}
	if got := rotatedName("deploy-rotated-2025-01-02-3", now, map[string]bool{}); got != "deploy-rotated-2026-10-28" {
		t.Errorf("a second rotation: got %q", got)
	}
}

// The scripts go through the remote login shell to sh: one line, no '!'.
func TestAKScriptsAreOneLineWithoutBang(t *testing.T) {
	for _, s := range []string{akReadScript, akWriteScript("1 2", "3 4")} {
		if strings.ContainsAny(s, "\n!") {
			t.Errorf("script has a newline or '!': %s", s)
		}
	}
}

// runAKScript runs a remote script with the local sh, as sshd would, in a
// home of its own.
func runAKScript(t *testing.T, home, script string, stdin []byte) (int, string, string) {
	t.Helper()
	cmd := exec.Command("sh", "-c", sh(script))
	cmd.Env = []string{"HOME=" + home, "PATH=" + os.Getenv("PATH")}
	cmd.Stdin = bytes.NewReader(stdin)
	var out, errOut bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errOut
	err := cmd.Run()
	code := 0
	if ee, ok := err.(*exec.ExitError); ok {
		code = ee.ExitCode()
	} else if err != nil {
		t.Fatal(err)
	}
	return code, out.String(), errOut.String()
}

func TestAKScriptsWithSh(t *testing.T) {
	home := t.TempDir()
	dir := filepath.Join(home, ".ssh")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	f := filepath.Join(dir, "authorized_keys")

	if code, _, stderr := runAKScript(t, home, akReadScript, nil); code != akExitMissing || !strings.Contains(stderr, "does not exist") {
		t.Errorf("read of a missing file: %d %q", code, stderr)
	}

	orig := []byte("line one\nline two\n")
	if err := os.WriteFile(f, orig, 0o640); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(f, 0o640); err != nil {
		t.Fatal(err)
	}
	code, stdout, _ := runAKScript(t, home, akReadScript, nil)
	if code != 0 || stdout != string(orig) {
		t.Fatalf("read: %d %q", code, stdout)
	}

	next := []byte("line one\nline two\nline three\n")
	if code, _, stderr := runAKScript(t, home, akWriteScript(cksum(orig), cksum(next)), next); code != 0 {
		t.Fatalf("write: %d %q", code, stderr)
	}
	got, _ := os.ReadFile(f)
	fi, _ := os.Stat(f)
	if !bytes.Equal(got, next) || fi.Mode().Perm() != 0o640 {
		t.Errorf("after write: %q mode %v", got, fi.Mode().Perm())
	}

	// The file changed since it was read: refused, untouched.
	if code, _, stderr := runAKScript(t, home, akWriteScript(cksum(orig), cksum(orig)), orig); code != akExitChanged || !strings.Contains(stderr, "changed") {
		t.Errorf("stale write: %d %q", code, stderr)
	}
	// Short stdin: refused, untouched.
	if code, _, _ := runAKScript(t, home, akWriteScript(cksum(next), cksum(orig)), orig[:4]); code != akExitWrite {
		t.Errorf("short write: %d", code)
	}
	if got, _ := os.ReadFile(f); !bytes.Equal(got, next) {
		t.Errorf("a refused write changed the file: %q", got)
	}
	// No temp file is left behind.
	entries, _ := os.ReadDir(dir)
	if len(entries) != 1 {
		t.Errorf("~/.ssh holds %d entries, want only authorized_keys", len(entries))
	}

	// A symlink is not edited.
	os.Rename(f, f+".real")
	os.Symlink(f+".real", f)
	if code, _, _ := runAKScript(t, home, akReadScript, nil); code != akExitSymlink {
		t.Errorf("read through a symlink: %d", code)
	}
	if code, _, _ := runAKScript(t, home, akWriteScript(cksum(next), cksum(orig)), orig); code != akExitSymlink {
		t.Errorf("write through a symlink: %d", code)
	}
}
