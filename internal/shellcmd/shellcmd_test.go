package shellcmd

import (
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
)

func TestQuote(t *testing.T) {
	for in, want := range map[string]string{
		"":          "''",
		"web-1":     "web-1",
		"a b":       "'a b'",
		"it's":      `'it'\''s'`,
		"$(id)":     "'$(id)'",
		"x; rm -rf": "'x; rm -rf'",
		"line\nbrk": "'line\nbrk'",
	} {
		if got := Quote(in); got != want {
			t.Errorf("Quote(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestPlaceholders(t *testing.T) {
	cases := []struct {
		cmd     string
		want    []string
		wantErr string
	}{
		{"uptime", nil, ""},
		{"systemctl restart {{unit}}", []string{"unit"}, ""},
		{"journalctl -u {{ unit }} -n {{lines}} | grep {{unit}}", []string{"unit", "lines"}, ""},
		{"--unit={{u}}", []string{"u"}, ""},
		{"awk '{print $1}' f", nil, ""},          // single braces are not a placeholder
		{"echo {{1bad}}", nil, ""},               // not a name: left alone
		{"echo '{{x}}'", nil, "inside quotes"},   // would not expand
		{`echo "a {{x}}"`, nil, "inside quotes"}, // would nest the quotes
		{`echo \{{x}}`, nil, "inside quotes"},    // nor after a backslash
		{`echo 'a'{{x}}`, []string{"x"}, ""},     // after the quote closed: fine
		{`echo "a\"b" {{x}}`, []string{"x"}, ""},
		{"echo {{a-b}}", nil, "has a '-'"},                        // not a shell variable name
		{"true # it's {{x}}\necho {{y}}", []string{"x", "y"}, ""}, // a comment's apostrophe opens no quote
		{"echo a#'{{x}}'", nil, "inside quotes"},                  // # inside a word is not a comment
		{"echo {{" + strings.Repeat("p", 33) + "}}", nil, "longer than 32"},
	}
	for _, c := range cases {
		got, err := Placeholders(c.cmd)
		if c.wantErr != "" {
			if err == nil || !strings.Contains(err.Error(), c.wantErr) {
				t.Errorf("Placeholders(%q) error = %v, want %q", c.cmd, err, c.wantErr)
			}
			continue
		}
		if err != nil || !slices.Equal(got, c.want) {
			t.Errorf("Placeholders(%q) = %q, %v; want %q", c.cmd, got, err, c.want)
		}
	}
	var many []string
	for i := range 33 {
		many = append(many, "{{p"+strconv.Itoa(i)+"}}")
	}
	if _, err := Placeholders(strings.Join(many, " ")); err == nil || !strings.Contains(err.Error(), "at most 32") {
		t.Errorf("33 parameters: %v", err)
	}
}

func TestRender(t *testing.T) {
	cmd := "systemctl restart {{unit}} && journalctl -u {{unit}} -n {{lines}}"
	got, err := Render(cmd, map[string]string{"unit": "my unit; rm -rf /", "lines": "20"})
	if err != nil {
		t.Fatal(err)
	}
	if want := `HOP_P_unit='my unit; rm -rf /'; HOP_P_lines='20'; `; got.Assign != want {
		t.Errorf("Assign = %q, want %q", got.Assign, want)
	}
	if want := `systemctl restart "${HOP_P_unit}" && journalctl -u "${HOP_P_unit}" -n "${HOP_P_lines}"`; got.Body != want {
		t.Errorf("Body = %q, want %q", got.Body, want)
	}
	for _, tc := range []struct {
		values map[string]string
		want   string
	}{
		{map[string]string{"unit": "x"}, "missing parameter(s) lines"},
		{map[string]string{"unit": "x", "lines": "1", "extra": "y"}, "unknown parameter(s) extra"},
		{map[string]string{"unit": "x\x00", "lines": "1"}, "NUL"},
	} {
		if _, err := Render(cmd, tc.values); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("Render(%v) error = %v, want %q", tc.values, err, tc.want)
		}
	}
	if _, err := Render("uptime", map[string]string{"x": "1"}); err == nil || !strings.Contains(err.Error(), "no parameters") {
		t.Errorf("a value for a snippet without parameters: %v", err)
	}
	if got, err := Render("uptime", nil); err != nil || got.String() != "uptime" {
		t.Errorf("no parameters: %q, %v", got, err)
	}
	for _, c := range []string{"echo '{{x}}'", `echo "{{x}}"`} {
		if _, err := Render(c, map[string]string{"x": "1"}); err == nil {
			t.Errorf("%s: a quoted placeholder was rendered", c)
		}
	}
}

// hostile are values that would run something, or split into several
// words, if they reached the shell as source. The ones that run something
// try to create the file named by $MARK.
var hostile = []string{
	"plain", "a b", "", "*", "-n", "~", "$HOME", "${IFS}x",
	"it's", `"dq"`, `back\slash`, `\`, "'", `"`, ";", "new\nline",
	`$(touch "$MARK")`, "`touch \"$MARK\"`", `x; touch "$MARK"`, "x\ntouch \"$MARK\"",
	`'$(touch "$MARK")'`, `"$(touch "$MARK")"`, `'; touch "$MARK"; '`, `"; touch "$MARK"; "`,
	"x\nEOF\ntouch \"$MARK\"\ncat <<EOF", `$(touch "$MARK")\`, `x' && touch "$MARK" && '`,
}

// The rendered script, run by a real shell, gets each value as exactly the
// text given and runs nothing from it, wherever the placeholder stands: an
// unquoted word, a here-document body, a comment, $(...) and backticks, and
// with the caller's own text between Assign and Body.
func TestRenderRunsNothingInARealShell(t *testing.T) {
	sh, err := exec.LookPath("sh")
	if err != nil {
		t.Skip("no sh")
	}
	cases := []struct {
		name     string
		template string
		want     func(v string) string
	}{
		{"word", `printf '%s|' {{v}} "$0"`, func(v string) string { return v + "|END|" }},
		{"in a word", `printf '%s|' --opt={{v}}x`, func(v string) string { return "--opt=" + v + "x|" }},
		{"here-doc", "cat <<EOF\n{{v}}\nEOF", func(v string) string { return `"` + v + `"` + "\n" }},
		{"here-doc, assigned first", "w={{v}}; cat <<EOF\n[$w]\nEOF", func(v string) string { return "[" + v + "]\n" }},
		{"comment", "printf ok # {{v}}", func(string) string { return "ok" }},
		{"comment, own line", "# {{v}}\nprintf ok", func(string) string { return "ok" }},
		{"$(...)", `x=$(printf '%s' {{v}}); printf '%s|' "$x"`, func(v string) string { return strings.TrimRight(v, "\n") + "|" }},
		{"backticks", "x=`printf '%s' {{v}}`; printf '%s|' \"$x\"", func(v string) string { return strings.TrimRight(v, "\n") + "|" }},
	}
	for _, c := range cases {
		for _, v := range hostile {
			dir := t.TempDir()
			mark := filepath.Join(dir, "pwned")
			sc, err := Render(c.template, map[string]string{"v": v})
			if err != nil {
				t.Fatalf("%s: %v", c.name, err)
			}
			// What hop mcp puts between the two.
			script := sc.Assign + "export PAGER=cat; " + sc.Body
			cmd := exec.Command(sh, "-c", script, "END")
			cmd.Dir = dir
			cmd.Env = append(os.Environ(), "MARK="+mark)
			out, err := cmd.Output()
			if err != nil {
				t.Errorf("%s, value %q: %v (script %q)", c.name, v, err, script)
			}
			if got, want := string(out), c.want(v); got != want {
				t.Errorf("%s, value %q came out as %q, want %q (script %q)", c.name, v, got, want, script)
			}
			if _, err := os.Stat(mark); err == nil {
				t.Errorf("%s, value %q ran a command (script %q)", c.name, v, script)
			}
		}
	}
}

func TestJoin(t *testing.T) {
	for _, c := range []struct {
		words []string
		want  string
	}{
		{[]string{"cd /srv && make"}, "cd /srv && make"},
		{[]string{"systemctl", "restart", "{{unit}}"}, "systemctl restart {{unit}}"},
		{[]string{"echo", "a b{{x}}", "--unit={{u}}", ""}, "echo 'a b'{{x}} --unit={{u}} ''"},
	} {
		got := Join(c.words)
		if got != c.want {
			t.Errorf("Join(%q) = %q, want %q", c.words, got, c.want)
		}
		if _, err := Placeholders(got); err != nil {
			t.Errorf("Join(%q) = %q, which Placeholders refuses: %v", c.words, got, err)
		}
	}
}
