package shellcmd

import (
	"os/exec"
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
		{"echo '{{x}}'", nil, "inside quotes"},   // would not stay one word
		{`echo "a {{x}}"`, nil, "inside quotes"}, // nor here
		{`echo \{{x}}`, nil, "inside quotes"},    // nor after a backslash
		{`echo 'a'{{x}}`, []string{"x"}, ""},     // after the quote closed: fine
		{`echo "a\"b" {{x}}`, []string{"x"}, ""},
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
	if want := `systemctl restart 'my unit; rm -rf /' && journalctl -u 'my unit; rm -rf /' -n 20`; err != nil || got != want {
		t.Errorf("Render = %q, %v; want %q", got, err, want)
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
	if _, err := Render("echo '{{x}}'", map[string]string{"x": "1"}); err == nil {
		t.Error("a quoted placeholder was rendered")
	}
}

// The rendered command, run by a real shell, gets each value as exactly one
// argument, whatever it contains.
func TestRenderIsOneWordInARealShell(t *testing.T) {
	sh, err := exec.LookPath("sh")
	if err != nil {
		t.Skip("no sh")
	}
	hostile := []string{"plain", "a b", "it's", `"dq"`, "$(echo pwned)", "`id`", "x;echo pwned", "*", "-n", "back\\slash", "new\nline", ""}
	for _, v := range hostile {
		line, err := Render(`printf '%s|' {{v}} "$0"`, map[string]string{"v": v})
		if err != nil {
			t.Fatal(err)
		}
		out, err := exec.Command(sh, "-c", line, "END").Output()
		if err != nil {
			t.Fatalf("%q: %v", line, err)
		}
		if got := string(out); got != v+"|END|" {
			t.Errorf("value %q came out as %q (command %q)", v, got, line)
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
