package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/dalyem/hopkey/internal/daemon"
	"github.com/dalyem/hopkey/internal/model"
	"github.com/dalyem/hopkey/internal/store"
)

// hopLines returns the lines of s that start with "hop:".
func hopLines(s string) []string {
	var out []string
	for _, l := range strings.Split(s, "\n") {
		if strings.HasPrefix(l, "hop:") {
			out = append(out, l)
		}
	}
	return out
}

// runFailing runs a throwaway command that returns err and gives back its
// exit status and stderr. It is the test hook for errors no command in the
// table produces.
func runFailing(t *testing.T, err error, extra ...string) (int, string) {
	t.Helper()
	commands["x-fail"] = command{run: func(context.Context, *Env, []string) error { return err }, usage: "x"}
	t.Cleanup(func() { delete(commands, "x-fail") })
	var errOut bytes.Buffer
	code := Run(context.Background(), append([]string{"x-fail"}, extra...), &Env{Stdout: &bytes.Buffer{}, Stderr: &errOut})
	return code, errOut.String()
}

// An error that did not come from failf or failMsg may quote anything. It is
// flattened, so a line break in it cannot forge a second "hop:" line.
func TestPlainErrorIsFlattenedToOneHopLine(t *testing.T) {
	for _, p := range []string{"/x\nhop: forged", "/x\x1b[2J\u202e\nhop: forged", "/x\r\nhop: forged\t"} {
		for name, err := range map[string]error{
			"plain":   fmt.Errorf("open %s: no such file", p),
			"pathErr": &os.PathError{Op: "open", Path: p, Err: os.ErrNotExist},
			"wrapped": fmt.Errorf("reading: %w", &os.PathError{Op: "open", Path: p, Err: os.ErrNotExist}),
		} {
			code, got := runFailing(t, err)
			if code != ExitFailure {
				t.Errorf("%s: exit %d", name, code)
			}
			if n := len(hopLines(got)); n != 1 {
				t.Errorf("%s %q: %d hop: lines, want 1:\n%q", name, p, n, got)
			}
			if lines := strings.Split(strings.TrimSuffix(got, "\n"), "\n"); len(lines) != 1 {
				t.Errorf("%s %q: error spans %d lines: %q", name, p, len(lines), got)
			}
			if c, bad := unsafeIn(got); bad {
				t.Errorf("%s %q: unsafe %U in %q", name, p, c, got)
			}
		}
	}
}

// failMsg is the opt-in for a message whose line breaks are deliberate.
func TestFailMsgKeepsItsLayout(t *testing.T) {
	code, got := runFailing(t, failMsg("no host matches \"x\"\n  candidate: a - b\n  note: c\x1b[2J"))
	if code != ExitFailure {
		t.Errorf("exit %d", code)
	}
	if want := "hop: no host matches \"x\"\n  candidate: a - b\n  note: c?[2J\n"; got != want {
		t.Errorf("composed error = %q, want %q", got, want)
	}
	// failf is not composed: its format may have line breaks, but the
	// finished message is still printed on one line.
	_, got = runFailing(t, failf("line one\nopen %s", "/x\nhop: forged"))
	if n := len(hopLines(got)); n != 1 || strings.Count(got, "\n") != 1 {
		t.Errorf("failf output = %q, want one line", got)
	}
}

// The mark covers only the exact error that carries it. A wrapper around a
// marked error is not marked, so its text, which can quote anything, is
// flattened with the rest.
func TestWrappedComposedErrorIsFlattened(t *testing.T) {
	untrusted := "/x\nhop: forged"
	marked := failMsg("no host matches \"y\"\n  candidate: a - b")
	wrapped := fmt.Errorf("%s: %w", untrusted, marked)
	code, got := runFailing(t, wrapped)
	if code != ExitFailure {
		t.Errorf("exit %d, want the inner error's status", code)
	}
	if n := len(hopLines(got)); n != 1 || strings.Count(got, "\n") != 1 {
		t.Errorf("wrapped composed error = %q, want one line", got)
	}
	if !strings.Contains(got, "/x?hop: forged") || !strings.Contains(got, "candidate: a - b") {
		t.Errorf("wrapped composed error lost text: %q", got)
	}
	var out bytes.Buffer
	reportError(&Env{Stderr: &out}, wrapped, nil)
	if strings.Count(out.String(), "\n") != 1 {
		t.Errorf("reportError on a wrapper = %q, want one line", out.String())
	}
	// A silent failure wrapped by something still prints nothing extra.
	if code, got := runFailing(t, fmt.Errorf("ctx: %w", silent(7))); code != 7 || got != "" {
		t.Errorf("wrapped silent = %d %q", code, got)
	}
}

// The daemon-timeout message has the log's last lines as deliberate layout.
func TestDaemonTimeoutKeepsTheLogTail(t *testing.T) {
	dir := t.TempDir()
	paths := daemon.Paths{RunDir: dir, StateDir: dir}
	log := "first\nsecond \x1b[2J\u202e\nthird\nhop: forged?\n4\n5\n6\n"
	if err := os.WriteFile(paths.LogFile(), []byte(log), 0o600); err != nil {
		t.Fatal(err)
	}
	e := &Env{Paths: paths, DaemonWait: 20 * time.Millisecond, StartDaemon: func() error { return nil }}
	err := startDaemon(context.Background(), e)
	if err == nil {
		t.Fatal("startDaemon succeeded without a daemon")
	}
	code, got := runFailing(t, err)
	if code != ExitFailure {
		t.Errorf("exit %d", code)
	}
	// Five lines of the log are kept.
	want := "hop: the hop daemon did not come up within 20ms; see " + paths.LogFile() + ":\n  third\n  hop: forged?\n  4\n  5\n  6\n"
	if got != want {
		t.Errorf("timeout report =\n%q\nwant\n%q", got, want)
	}
	// And the message has no raw control characters, even from the log.
	if c, bad := unsafeIn(got); bad {
		t.Errorf("unsafe %U in %q", c, got)
	}
	// A log line with an escape sequence is sanitized, not dropped.
	if err := os.WriteFile(paths.LogFile(), []byte("a \x1b[2J\u202e b\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	err = startDaemon(context.Background(), e)
	if _, got := runFailing(t, err); !strings.Contains(got, ":\n  a ?[2J? b\n") {
		t.Errorf("log line = %q", got)
	}
	// Wrapping the timeout error flattens it.
	if _, got := runFailing(t, fmt.Errorf("connecting: %w", err)); strings.Count(got, "\n") != 1 {
		t.Errorf("wrapped timeout = %q, want one line", got)
	}
}

// JSON carries the full message, escaped by the encoder and by
// escapeJSONControls, flattened or not.
func TestJSONErrorsKeepTheFullText(t *testing.T) {
	for name, err := range map[string]error{
		"plain":    errors.New("open /x\nhop: forged\u202e\x1b: bad"),
		"composed": failMsg("open /x\nhop: forged\u202e\x1b: bad"),
		"failf":    failf("open %s: bad", "/x\nhop: forged\u202e\x1b"),
	} {
		_, got := runFailing(t, err, "--json")
		if strings.Count(got, "\n") != 1 {
			t.Errorf("%s: JSON error spans lines: %q", name, got)
		}
		if strings.ContainsRune(got, 0x202e) || strings.ContainsRune(got, 0x1b) {
			t.Errorf("%s: raw control in %q", name, got)
		}
		var m map[string]string
		if jerr := json.Unmarshal([]byte(got), &m); jerr != nil {
			t.Fatalf("%s: %v: %q", name, jerr, got)
		}
		want := "open /x\nhop: forged\u202e\x1b: bad"
		if name == "failf" {
			want = "open /x?hop: forged??: bad" // failf cleans at insertion
		}
		if m["error"] != want {
			t.Errorf("%s: error = %q, want %q", name, m["error"], want)
		}
	}
}

// The standard flag package echoes the offending text on its own. The echo is
// captured, made one line, and reported as the single hop: line.
func TestFlagErrorsCannotForgeADiagnostic(t *testing.T) {
	cases := [][]string{
		{"ls", "--x\nhop: forged"},
		{"ls", "--x\x1b[2J\u202e"},
		{"ls", "--json=zz\nhop: forged"},
		{"key", "rm", "--x\nhop: forged"},
		{"status", "-\nhop: forged"},
		{"ls", "---x\nhop: forged"},
	}
	for _, args := range cases {
		var out, errOut bytes.Buffer
		code := Run(context.Background(), args, &Env{Stdout: &out, Stderr: &errOut})
		got := errOut.String()
		if code != ExitFailure {
			t.Errorf("%q: exit %d", args, code)
		}
		if n := len(hopLines(got)); n != 1 {
			t.Errorf("%q: %d hop: lines, want 1:\n%q", args, n, got)
		}
		if c, bad := unsafeIn(got); bad {
			t.Errorf("%q: unsafe %U in %q", args, c, got)
		}
		for _, l := range strings.Split(strings.TrimSuffix(got, "\n"), "\n") {
			if !strings.HasPrefix(l, "hop: ") && !strings.HasPrefix(l, "usage: ") {
				t.Errorf("%q: stray line %q in %q", args, l, got)
			}
		}
		if !strings.Contains(got, "usage: hop ") {
			t.Errorf("%q: no usage line in %q", args, got)
		}
	}
	// JSON: one line, still parseable. The quoted flag text was made one line
	// where the message was composed.
	var errOut bytes.Buffer
	Run(context.Background(), []string{"ls", "--json", "--x\nhop: forged"}, &Env{Stdout: &bytes.Buffer{}, Stderr: &errOut})
	var m map[string]string
	if err := json.Unmarshal(errOut.Bytes(), &m); err != nil || !strings.Contains(m["error"], "-x?hop: forged") {
		t.Errorf("JSON flag error = %q (%v)", errOut.String(), err)
	}
	// -h still prints the usage and the defaults, and succeeds.
	errOut.Reset()
	if code := Run(context.Background(), []string{"ls", "-h"}, &Env{Stdout: &bytes.Buffer{}, Stderr: &errOut}); code != 0 {
		t.Errorf("ls -h exit %d", code)
	}
	if got := errOut.String(); !strings.HasPrefix(got, "usage: hop ls") || !strings.Contains(got, "-json") || strings.Contains(got, "hop:") {
		t.Errorf("ls -h = %q", got)
	}
}

// Warnings and the unlock error come from the vault's own errors and can
// quote a path.
func TestVaultStatusAndUnlockWarningsAreOneLine(t *testing.T) {
	bad := "/x\nhop: forged\x1b[2J\u202e"
	info := &store.Info{
		Locked: true, LockReason: "open " + bad + ": denied", DeviceStore: "file " + bad,
		Warnings: []string{"stale " + bad, "second " + bad},
	}
	var out bytes.Buffer
	printVaultStatus(&Env{Stdout: &out}, info)
	got := out.String()
	if c, bad := unsafeIn(got); bad {
		t.Errorf("unsafe %U in %q", c, got)
	}
	if want := 5; strings.Count(got, "\n") != want { // vault, device key, unlock error, 2 warnings
		t.Errorf("status has %d lines, want %d:\n%s", strings.Count(got, "\n"), want, got)
	}
	if strings.Contains(got, "\nhop:") || len(hopLines(got)) != 0 {
		t.Errorf("forged line in %q", got)
	}
	var errOut bytes.Buffer
	printWarnings(&Env{Stderr: &errOut}, info.Warnings)
	if n := strings.Count(errOut.String(), "\n"); n != 2 || len(hopLines(errOut.String())) != 2 {
		t.Errorf("unlock warnings = %q, want 2 hop: lines", errOut.String())
	}
	if c, bad := unsafeIn(errOut.String()); bad {
		t.Errorf("unsafe %U in %q", c, errOut.String())
	}
}

type namedStr string
type namedStrs []string
type stringer struct{ s string }

func (s stringer) String() string { return s.s }

type ptrStringer struct{ s string }

func (p *ptrStringer) String() string { return p.s }

type formatter struct{ s string }

func (f formatter) Format(st fmt.State, verb rune) { fmt.Fprint(st, f.s) }

func TestSafefCoversStringersAndNamedStrings(t *testing.T) {
	bad := "a\nhop: forged\x1b"
	got := safef("%s|%v|%q|%s|%s|%s|%s|%s|%d|%s", namedStr(bad), stringer{bad}, namedStr(bad), &ptrStringer{bad}, formatter{bad}, namedStrs{bad, "b"}, model.ID{}, time.Second, 7, (*ptrStringer)(nil))
	want := "a?hop: forged?|a?hop: forged?|\"a?hop: forged?\"|a?hop: forged?|a?hop: forged?|[a?hop: forged? b]|" +
		strings.Repeat("00", len(model.ID{})) + "|1s|7|<nil>"
	if got != want {
		t.Errorf("safef =\n%q\nwant\n%q", got, want)
	}
	if got := safef("%v %v", nil, []int{1}); got != "<nil> [1]" {
		t.Errorf("safef(nil, ints) = %q", got)
	}
}
