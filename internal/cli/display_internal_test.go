package cli

import (
	"bytes"
	"encoding/json"
	"errors"
	"io/fs"
	"strings"
	"testing"

	"github.com/dalyem/hopkey/internal/resolve"
)

// hostile is text that could redraw, reorder or forge a terminal: a line
// break, a tab, an escape sequence, a bidi override, C1 controls (NEL and the
// CSI introducer), DEL and a carriage return.
var hostile = []struct{ name, text, want string }{
	{"newline", "a\nb", "a?b"},
	{"forged line", "a\nhop: forged", "a?hop: forged"},
	{"tab", "a\tb", "a?b"},
	{"carriage return", "a\rb", "a?b"},
	{"escape sequence", "a\x1b[2Jb", "a?[2Jb"},
	{"bidi override", "a\u202eb", "a?b"},
	{"bidi isolate", "a\u2066b", "a?b"},
	{"zero width", "a\u200bb", "a?b"},
	{"C1 next line", "a\u0085b", "a?b"},
	{"C1 CSI", "a\u009bb", "a?b"},
	{"DEL", "a\x7fb", "a?b"},
	{"tag character", "a\U000e0001b", "a?b"},
}

// unsafeIn returns the first character of s that could rewrite a terminal,
// other than a newline the caller means as layout.
func unsafeIn(s string) (rune, bool) {
	for _, c := range s {
		if c != '\n' && unsafeRune(c) {
			return c, true
		}
	}
	return 0, false
}

func TestOneLine(t *testing.T) {
	for _, h := range hostile {
		t.Run(h.name, func(t *testing.T) {
			got := oneLine(h.text)
			if got != h.want {
				t.Errorf("oneLine(%q) = %q, want %q", h.text, got, h.want)
			}
			if c, bad := unsafeIn(got); bad || strings.ContainsRune(got, '\n') {
				t.Errorf("oneLine(%q) = %q still has %U", h.text, got, c)
			}
		})
	}
	if got := oneLine("plain ünïcode 日本 -_./:@"); got != "plain ünïcode 日本 -_./:@" {
		t.Errorf("oneLine changed printable text: %q", got)
	}
	if long := strings.Repeat("x", 1000); oneLine(long) != long {
		t.Error("oneLine truncated")
	}
}

func TestSafefSanitizesTheArgumentsNotTheFormat(t *testing.T) {
	got := safef("line one\nopen %s: %v (%q) %d %s", "/x\nhop: forged", errors.New("e\x1b[2J"), "q\ru", 7, []string{"a\nb", "c"})
	want := "line one\nopen /x?hop: forged: e?[2J (\"q?u\") 7 [a?b c]"
	if got != want {
		t.Errorf("safef = %q, want %q", got, want)
	}
}

func TestCleanErrKeepsTheCause(t *testing.T) {
	cause := &fs.PathError{Op: "open", Path: "/x\nhop: forged", Err: fs.ErrNotExist}
	err := cleanErr(cause)
	if strings.ContainsRune(err.Error(), '\n') || !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("cleanErr = %q (not-exist: %v)", err, errors.Is(err, fs.ErrNotExist))
	}
	if plain := errors.New("plain"); cleanErr(plain) != plain {
		t.Error("cleanErr wrapped a message that was already safe")
	}
	if cleanErr(nil) != nil {
		t.Error("cleanErr(nil) is not nil")
	}
}

// describeUnresolved is multi-line on purpose; every value in it is one line.
func TestDescribeUnresolvedHasOnlyItsOwnLines(t *testing.T) {
	for _, h := range hostile {
		res := &resolve.Result{
			Target: h.text, Status: resolve.StatusAmbiguous, Matched: h.text,
			Candidates: []resolve.Candidate{
				{Name: h.text, Addresses: []string{h.text, "10.0.0.1"}, Detail: h.text},
				{Name: "plain", Detail: "d"},
			},
			Notes: []string{h.text},
		}
		got := describeUnresolved(res)
		if c, bad := unsafeIn(got); bad {
			t.Errorf("%s: %U in %q", h.name, c, got)
		}
		lines := strings.Split(got, "\n")
		if len(lines) != 1+2+1 {
			t.Errorf("%s: %d lines, want 4: %q", h.name, len(lines), got)
			continue
		}
		for _, l := range lines[1:] {
			if !strings.HasPrefix(l, "  candidate: ") && !strings.HasPrefix(l, "  note: ") {
				t.Errorf("%s: stray line %q in %q", h.name, l, got)
			}
		}
	}
}

// JSON keeps every value, but DEL, C1 and format characters leave it as
// \uXXXX escapes.
func TestJSONEscapesControlsAndRoundTrips(t *testing.T) {
	for _, h := range hostile {
		t.Run(h.name, func(t *testing.T) {
			var out bytes.Buffer
			e := &Env{Stdout: &out}
			in := map[string]any{"name": h.text, "list": []string{h.text}}
			if err := printJSON(e, in); err != nil {
				t.Fatal(err)
			}
			if c, bad := unsafeIn(out.String()); bad {
				t.Errorf("raw %U in %q", c, out.String())
			}
			var back struct {
				Name string   `json:"name"`
				List []string `json:"list"`
			}
			if err := json.Unmarshal(out.Bytes(), &back); err != nil {
				t.Fatalf("%v: %q", err, out.String())
			}
			if back.Name != h.text || len(back.List) != 1 || back.List[0] != h.text {
				t.Errorf("round trip changed the value: %q, %q", back.Name, back.List)
			}
		})
	}
	var out bytes.Buffer
	if err := printJSON(&Env{Stdout: &out}, "a\x7fb\u0085c\u009fd"); err != nil {
		t.Fatal(err)
	}
	if want := `"a\u007fb\u0085c\u009fd"` + "\n"; out.String() != want {
		t.Errorf("printJSON = %q, want %q", out.String(), want)
	}
	// Errors in JSON mode get the same treatment.
	var errOut bytes.Buffer
	reportError(&Env{Stderr: &errOut}, "bad \x7f \u009b name", []string{"--json"})
	if c, bad := unsafeIn(errOut.String()); bad || !strings.Contains(errOut.String(), `\u007f`) || !strings.Contains(errOut.String(), `\u009b`) {
		t.Errorf("JSON error = %q (%U)", errOut.String(), c)
	}
}
