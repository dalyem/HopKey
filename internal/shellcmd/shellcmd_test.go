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
		// Where the shell itself evaluates text, the value would run.
		{"echo $(( {{x}} + 1 ))", nil, "arithmetic"},
		{"(( {{x}} > 1 )) && echo big", nil, "arithmetic"},
		{"echo $[ {{x}} + 1 ]", nil, "arithmetic"},
		{"echo $(( $(printf %s {{x}}) ))", nil, "arithmetic"},
		{"echo ${a[{{x}}]}", nil, "${...}"},
		{"echo ${v:{{x}}:2}", nil, "${...}"},
		{"[[ {{x}} -eq 1 ]]", nil, "[[ ... ]]"},
		{"if [[ -n {{y}} && {{x}} == 1 ]]; then echo; fi", nil, "[[ ... ]]"},
		{"[[ $(printf %s {{x}}) -eq 1 ]]", nil, "[[ ... ]]"},
		// Over line breaks, to the end of each.
		{"[[ -n x &&\n{{x}} -eq 1 ]]", nil, "[[ ... ]]"},
		{"[[\n{{x}} -eq 1\n]]", nil, "[[ ... ]]"},
		{"if [[ -n $HOME ||\n  {{x}} == 1 ]]; then echo; fi", nil, "[[ ... ]]"},
		{"((\n{{x}} > 1\n)) && echo big", nil, "arithmetic"},
		{"echo $((\n1 +\n{{x}}\n))", nil, "arithmetic"},
		{"echo ${a[\n{{x}}]}", nil, "${...}"},
		{"echo ${v:\n{{x}}}", nil, "${...}"},
		{"v=$(\nprintf %s {{x}}\n)", nil, "assignment"},
		{"eval $(\ntrue\nprintf %s {{x}}\n)", nil, "eval"},
		{"[[ $(\nprintf %s {{x}}\n) -eq 1 ]]", nil, "[[ ... ]]"},
		{"[[ -n x ]]\nv={{x}}", nil, "assignment"}, // the line break after ]] ends the command
		{"eval {{x}}", nil, "eval"},
		{"eval echo {{x}}", nil, "eval"},
		{"true && eval {{x}}", nil, "eval"},
		{"eval 2>&1 {{x}}", nil, "eval"}, // a redirection's & ends no command
		{"eval $(printf %s {{x}})", nil, "eval"},
		{"let n={{x}}", nil, "let"},
		{"trap {{x}} EXIT", nil, "trap"},
		{"sh -c {{x}}", nil, "-c"},
		{"bash -c {{x}}", nil, "-c"},
		{"zsh -c {{x}}", nil, "-c"},
		{"dash -c {{x}}", nil, "-c"},
		{"/bin/bash -lc {{x}}", nil, "-c"},
		{"sudo -n sh -c {{x}}", nil, "-c"},
		{"bash -o pipefail -c {{x}}", nil, "-c"},
		{"su - root -c {{x}}", nil, "-c"},
		{"bash -c $(printf %s {{x}})", nil, "-c"},
		{"ref={{x}}; echo ${!ref}", nil, "assignment"},
		{"v={{x}}", nil, "assignment"},
		{"v+={{x}}", nil, "assignment"},
		{"a[{{x}}]=1", nil, "assignment"},
		{"export v={{x}}", nil, "assignment"},
		{"local -r v={{x}}", nil, "assignment"},
		{"declare -n r={{x}}", nil, "assignment"},
		{"PGPASSWORD={{x}} psql", nil, "assignment"},
		{"true; v={{x}}", nil, "assignment"},
		{"if true; then v={{x}}; fi", nil, "assignment"},
		{"v=$(printf %s {{x}})", nil, "assignment"},
		{"v=`printf %s {{x}}`", nil, "assignment"},
		// ... and where it does not.
		{"printf '%s\n' {{x}} | cat", []string{"x"}, ""},
		{"env PGPASSWORD={{x}} psql", []string{"x"}, ""},
		{"make CFLAGS={{x}}", []string{"x"}, ""},
		{`sh -c 'printf "%s" "$1"' sh {{x}}`, []string{"x"}, ""},
		{"bash script.sh {{x}}", []string{"x"}, ""},
		{"[ {{x}} -eq 1 ]", []string{"x"}, ""},
		{"echo $((1 + 1)) ${HOME} {{x}}", []string{"x"}, ""},
		{"echo $(printf %s {{x}})", []string{"x"}, ""},
		{"cat <<EOF\n$(printf '%s' {{x}})\nEOF", []string{"x"}, ""},
		{"case {{x}} in a) echo a;; esac", []string{"x"}, ""},
		{"true # eval {{x}}", []string{"x"}, ""},
		{"eval true; echo {{x}}", []string{"x"}, ""},
		{"[[ -n $HOME ]] && echo {{x}}", []string{"x"}, ""},
		{"[[ -n $HOME &&\n-n $PATH ]]\necho {{x}}", []string{"x"}, ""},
		{"echo $(\ntrue\n)\necho {{x}}", []string{"x"}, ""},
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
	for _, c := range []string{"echo '{{x}}'", `echo "{{x}}"`, "eval {{x}}", "echo $(( {{x}} ))", "v={{x}}"} {
		if _, err := Render(c, map[string]string{"x": "1"}); err == nil {
			t.Errorf("%s: a placeholder Placeholders refuses was rendered", c)
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
	// What bash's arithmetic would run, through an array index.
	`a[$(touch "$MARK")]`, `x[$(touch "$MARK")]+1`, `1+a[$(touch "$MARK")]`,
}

// The rendered script, run by a real shell, gets each value as exactly the
// text given and runs nothing from it, wherever Placeholders lets the
// placeholder stand: an unquoted word, a here-document body, a comment,
// $(...) and backticks, a test, a positional parameter of sh -c, and with
// the caller's own text between Assign and Body. bash runs each one too,
// since its arithmetic is the one that runs an array index.
func TestRenderRunsNothingInARealShell(t *testing.T) {
	var shells []string
	for _, name := range []string{"sh", "bash"} {
		if p, err := exec.LookPath(name); err == nil {
			shells = append(shells, p)
		}
	}
	if len(shells) == 0 {
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
		// The README's way to print a value in a here-document without
		// the quotes.
		{"here-doc, README workaround", "cat <<EOF\n[$(printf '%s' {{v}})]\nEOF", func(v string) string { return "[" + strings.TrimRight(v, "\n") + "]\n" }},
		{"comment", "printf ok # {{v}}", func(string) string { return "ok" }},
		{"comment, own line", "# {{v}}\nprintf ok", func(string) string { return "ok" }},
		{"backticks", "cat <<EOF\n[`printf '%s' {{v}}`]\nEOF", func(v string) string { return "[" + strings.TrimRight(v, "\n") + "]\n" }},
		{"test", "[ {{v}} = x ] 2>/dev/null || printf no", func(string) string { return "no" }},
		{"test -eq", "test {{v}} -eq 1 2>/dev/null; printf ok", func(string) string { return "ok" }},
		{"printf %d", "printf %d {{v}} >/dev/null 2>&1; printf ok", func(string) string { return "ok" }},
		{"env", `env V={{v}} sh -c 'printf "%s|" "$V"'`, func(v string) string { return v + "|" }},
		{"sh -c positional", `sh -c 'printf "%s|" "$1"' sh {{v}}`, func(v string) string { return v + "|" }},
		{"case", "case {{v}} in *) printf ok;; esac", func(string) string { return "ok" }},
		{"for", `for w in {{v}}; do printf '%s|' "$w"; done`, func(v string) string { return v + "|" }},
		{"pipe", `printf '%s|' {{v}} | cat`, func(v string) string { return v + "|" }},
	}
	for _, sh := range shells {
		for _, c := range cases {
			for _, v := range hostile {
				runProbe(t, sh, c.name, c.template, v, c.want(v))
			}
		}
	}
}

func runProbe(t *testing.T, sh, name, template, v, want string) {
	t.Helper()
	dir := t.TempDir()
	mark := filepath.Join(dir, "pwned")
	sc, err := Render(template, map[string]string{"v": v})
	if err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	// What hop mcp puts between the two.
	script := sc.Assign + "export PAGER=cat; " + sc.Body
	cmd := exec.Command(sh, "-c", script, "END")
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "MARK="+mark)
	out, err := cmd.Output()
	if err != nil {
		t.Errorf("%s, %s, value %q: %v (script %q)", sh, name, v, err, script)
	}
	if got := string(out); got != want {
		t.Errorf("%s, %s, value %q came out as %q, want %q (script %q)", sh, name, v, got, want, script)
	}
	if _, err := os.Stat(mark); err == nil {
		t.Errorf("%s, %s, value %q ran a command (script %q)", sh, name, v, script)
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

// A [[ ... ]] over two lines evaluates its operands as one on a line does:
// bash runs a command from a value in it. Placeholders refuses both, and
// this is why: the script Render would make without that check runs the
// value's command.
func TestDoubleBracketOverLinesWouldRunAValue(t *testing.T) {
	bash, err := exec.LookPath("bash")
	if err != nil {
		t.Skip("no bash")
	}
	const v = `a[$(touch "$MARK")]`
	for _, template := range []string{
		"[[ {{v}} -eq 1 ]] 2>/dev/null; printf ok",
		"[[ -n x &&\n{{v}} -eq 1 ]] 2>/dev/null; printf ok",
		"[[\n{{v}} -eq 1 ]] 2>/dev/null; printf ok",
	} {
		if _, err := Placeholders(template); err == nil || !strings.Contains(err.Error(), "[[ ... ]]") {
			t.Errorf("Placeholders(%q) = %v, want a refusal", template, err)
		}
		// Render's script, without the check.
		script := ParamVar("v") + "='" + strings.ReplaceAll(v, "'", `'\''`) + "'; " + strings.ReplaceAll(template, "{{v}}", `"${HOP_P_v}"`)
		dir := t.TempDir()
		mark := filepath.Join(dir, "pwned")
		cmd := exec.Command(bash, "-c", script)
		cmd.Dir = dir
		cmd.Env = append(os.Environ(), "MARK="+mark)
		if out, err := cmd.CombinedOutput(); err != nil || string(out) != "ok" {
			t.Errorf("bash %q: %q, %v", script, out, err)
		}
		if _, err := os.Stat(mark); err != nil {
			t.Errorf("bash %q ran nothing from the value, so the test shows nothing: %v", script, err)
		}
	}
}
