package cli

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// runSession runs the access session script under shell with stdin and
// returns the exit status, stdout and stderr.
func runSession(t *testing.T, shell, home, path, script string, stdin []byte) (int, string, string) {
	t.Helper()
	cmd := exec.Command(shell, "-c", script)
	cmd.Env = append([]string{"HOME=" + home, "PATH=" + path}, nssEnv()...)
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

// nssEnv is the nss_wrapper environment scripts/with-passwd.sh sets up,
// so that id -un works in a test machine's sandbox.
func nssEnv() []string {
	var out []string
	for _, kv := range os.Environ() {
		if strings.HasPrefix(kv, "LD_PRELOAD=") || strings.HasPrefix(kv, "NSS_WRAPPER_") {
			out = append(out, kv)
		}
	}
	return out
}

const sessionToken = "0123456789abcdef0123456789abcdef"

// The locked session of hop access (spec rev 17, §7.7) under each shell a
// host may run it as sh: the header and the file, then the decision.
func TestAccessSessionScript(t *testing.T) {
	old := []byte("ssh-ed25519 AAAA one\n# a comment\n")
	next := append(bytes.Clone(old), "ssh-ed25519 BBBB two\n"...)
	write := []byte("write " + cksum(old) + " " + cksum(next) + "\n")
	script := akSessionScript(sessionToken)
	if strings.ContainsAny(script, "\n!#") || strings.Contains(script, `\\`) || strings.Contains(script, `\'`) {
		t.Fatal("the script breaks the transport rules")
	}
	for _, sh := range akInterpreters(t) {
		t.Run(sh.name, func(t *testing.T) {
			path := os.Getenv("PATH")
			check := func(t *testing.T, stdin []byte, wantCode int, want []byte) (string, string) {
				t.Helper()
				home, file := akHome(t, old)
				code, out, errOut := runSession(t, sh.path, home, path, script, stdin)
				got, _ := os.ReadFile(file)
				if code != wantCode || !bytes.Equal(got, want) {
					t.Fatalf("exit %d (want %d), file %q (want %q), stderr %q", code, wantCode, got, want, errOut)
				}
				onlyAK(t, home)
				return out, errOut
			}
			t.Run("write", func(t *testing.T) {
				out, _ := check(t, append(bytes.Clone(write), next...), 0, next)
				head, rest, _ := strings.Cut(out, "\n")
				f := strings.Fields(head)
				if len(f) != 5 || f[0] != "hop-session" || f[1] != "1" || f[3]+" "+f[4] != cksum(old) || rest != string(old) {
					t.Fatalf("header %q, then %q", head, rest)
				}
			})
			t.Run("abort", func(t *testing.T) { check(t, []byte("abort\n"), akExitDecision, old) })
			t.Run("no decision", func(t *testing.T) { check(t, nil, akExitDecision, old) })
			t.Run("half a line", func(t *testing.T) { check(t, []byte("write 1 2"), akExitDecision, old) })
			t.Run("not numbers", func(t *testing.T) { check(t, []byte("write 1 2 x 4\n"), akExitDecision, old) })
			t.Run("five numbers", func(t *testing.T) { check(t, []byte("write 1 2 3 4 5\n"), akExitDecision, old) })
			t.Run("payload cut short", func(t *testing.T) {
				check(t, append(bytes.Clone(write), next[:len(next)-3]...), akExitWrite, old)
			})
			t.Run("file changed since the header", func(t *testing.T) {
				bad := []byte("write " + cksum([]byte("x")) + " " + cksum(next) + "\n")
				check(t, append(bad, next...), akExitChanged, old)
			})
			t.Run("ln fails", func(t *testing.T) {
				home, file := akHome(t, old)
				code, _, errOut := runSession(t, sh.path, home, fakeBin(t, map[string]string{"ln": "exit 1"}), script, append(bytes.Clone(write), next...))
				got, _ := os.ReadFile(file)
				if code != akExitWrite || !bytes.Equal(got, old) || !strings.Contains(errOut, "can't be hard-linked") {
					t.Fatalf("exit %d, file %q, stderr %q", code, got, errOut)
				}
				onlyAK(t, home)
			})
			t.Run("mv fails", func(t *testing.T) {
				home, _ := akHome(t, old)
				code, _, _ := runSession(t, sh.path, home, fakeBin(t, map[string]string{"mv": "exit 1"}), script, append(bytes.Clone(write), next...))
				if code != akExitUncertain || akSessionRefused(code) {
					t.Fatalf("exit %d", code)
				}
				onlyAK(t, home)
			})
			t.Run("a session directory already there", func(t *testing.T) {
				home, _ := akHome(t, old)
				planted := filepath.Join(home, ".ssh", ".hop-s."+sessionToken)
				if err := os.Mkdir(planted, 0o700); err != nil {
					t.Fatal(err)
				}
				os.WriteFile(filepath.Join(planted, "keep"), []byte("x"), 0o600)
				code, _, _ := runSession(t, sh.path, home, path, script, []byte("abort\n"))
				if code != akExitWrite {
					t.Fatalf("exit %d", code)
				}
				if b, err := os.ReadFile(filepath.Join(planted, "keep")); err != nil || string(b) != "x" {
					t.Fatal("the planted directory was touched")
				}
			})
			t.Run("a held lock", func(t *testing.T) {
				defer func(w int) { akLockWait = w }(akLockWait)
				akLockWait = 1
				home, _ := akHome(t, old)
				lock := filepath.Join(home, ".ssh", testLockDir)
				os.Mkdir(lock, 0o700)
				os.WriteFile(filepath.Join(lock, "owner"), []byte("ffff 42 2026-10-29T00:00:00Z\n"), 0o600)
				code, out, errOut := runSession(t, sh.path, home, path, akSessionScript(sessionToken), []byte("abort\n"))
				if code != akExitLocked || out != "" || !strings.Contains(errOut, "hop key rotate and hop access both use this lock") {
					t.Fatalf("exit %d, stdout %q, stderr %q", code, out, errOut)
				}
				if entries, _ := os.ReadDir(filepath.Join(home, ".ssh")); len(entries) != 2 {
					t.Fatalf("~/.ssh: %v", sshEntries(t, home))
				}
			})
		})
	}
}

// Rotate keeps every tombstone-like line byte for byte (§6.1a).
func TestRotateKeepsTombstones(t *testing.T) {
	oldPub, newPub := rotTestKey(t), rotTestKey(t)
	tomb := "  # hop-access-removed " + strings.Repeat("ab", 16) + " 3 \r"
	orig := []byte(tomb + "\n" + akText(oldPub) + " old\n# HOP-ACCESS-REMOVED junk\n")
	ed, err := planAKEdit(orig, oldPub, newPub, "new")
	if err != nil {
		t.Fatal(err)
	}
	for _, b := range [][]byte{ed.appended, ed.final} {
		if !bytes.Contains(b, []byte(tomb+"\n")) || !bytes.Contains(b, []byte("# HOP-ACCESS-REMOVED junk\n")) {
			t.Fatalf("tombstones lost: %q", b)
		}
	}
	if out, _ := withoutKey(orig, oldPub); !bytes.Contains(out, []byte(tomb+"\n")) {
		t.Fatalf("withoutKey lost the tombstone: %q", out)
	}
	if out, _ := rollbackAK(ed.final, ed); !bytes.Contains(out, []byte(tomb+"\n")) {
		t.Fatalf("rollback lost the tombstone: %q", out)
	}
}
