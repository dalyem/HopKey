// Package shellcmd builds POSIX shell command lines: it quotes words, and
// it finds and fills the {{name}} parameters of a saved snippet. The daemon
// uses it to check a snippet before saving it, and the CLI to run one, so
// both read a command the same way.
//
// A parameter's value never becomes shell source text. Render assigns each
// value, single-quoted, to a variable at the top of the script
// (HOP_P_unit='...';) and puts "${HOP_P_unit}" where {{unit}} was. The shell
// expands a variable without reading its value as code: in a word, a
// comment, a here-document or $(...). A template that itself evaluates a
// value (eval, sh -c, arithmetic, indirect expansion) can still run it, and
// that is the snippet author's responsibility. Placeholders refuses the
// common ways of doing so (evalContext); that check is a lint, not a
// parser. The remote login shell must be POSIX sh compatible (sh, bash,
// dash, zsh, ksh); fish and csh quote differently.
package shellcmd

import (
	"fmt"
	"regexp"
	"slices"
	"strings"
)

// Quote quotes one word for a POSIX shell. A word made only of characters
// no shell treats specially is returned as it is.
func Quote(s string) string {
	if s == "" {
		return "''"
	}
	safe := true
	for _, r := range s {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || strings.ContainsRune("_@%+=:,./-", r)) {
			safe = false
			break
		}
	}
	if safe {
		return s
	}
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// MaxParams and MaxParamName bound a snippet's parameters, as the vault
// schema does (crypto spec §6.5: params has string items of up to 32
// characters).
const (
	MaxParams    = 32
	MaxParamName = 32
)

// placeholderRe matches {{name}}, with optional spaces inside the braces.
// It also takes a '-' in the name, so that Placeholders can refuse one
// instead of leaving it in the command as text.
var placeholderRe = regexp.MustCompile(`\{\{\s*([A-Za-z_][A-Za-z0-9_-]*)\s*\}\}`)

// ParamVar is the shell variable that holds parameter name's value. A name
// is letters, digits and '_', not starting with a digit, so it is always a
// valid variable name.
func ParamVar(name string) string { return "HOP_P_" + name }

// Placeholders returns the parameter names in command, each once, in the
// order they first appear. A placeholder must stand outside quotes and not
// after a backslash: Render puts "${HOP_P_name}" in its place, which inside
// single quotes would not expand, and inside double quotes would nest the
// quotes. It must not stand where the shell evaluates text (evalContext).
func Placeholders(command string) ([]string, error) {
	quoted := quotedBytes(command)
	matches := placeholderRe.FindAllStringSubmatchIndex(command, -1)
	for _, m := range matches {
		if quoted[m[0]] {
			return nil, fmt.Errorf("{{%s}} is inside quotes or after a backslash; write it bare, since hop quotes each value itself", command[m[2]:m[3]])
		}
	}
	if err := evalContext(command, quoted); err != nil {
		return nil, err
	}
	var names []string
	seen := map[string]bool{}
	for _, m := range matches {
		name := command[m[2]:m[3]]
		if strings.Contains(name, "-") {
			return nil, fmt.Errorf("parameter name %q has a '-'; use letters, digits and '_'", name)
		}
		if len(name) > MaxParamName {
			return nil, fmt.Errorf("parameter name %q is longer than %d characters", name, MaxParamName)
		}
		if !seen[name] {
			seen[name] = true
			names = append(names, name)
		}
	}
	if len(names) > MaxParams {
		return nil, fmt.Errorf("a snippet can have at most %d parameters, not %d", MaxParams, len(names))
	}
	return names, nil
}

// quotedBytes reports, for each byte of s, whether a POSIX shell reads it
// inside single or double quotes or right after a backslash. It follows the
// quoting rules and skips comments (so an apostrophe in one does not open a
// quote), which is all Placeholders needs. It does not know here-documents:
// a quote character in one is taken as a quote. Getting it wrong can only
// refuse a placeholder, or leave a value's quotes visible; Render never puts
// a value into the command, so it cannot make one run.
func quotedBytes(s string) []bool {
	out := make([]bool, len(s))
	const (
		none = iota
		single
		double
	)
	state := none
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch state {
		case none:
			switch c {
			case '\\':
				if i+1 < len(s) {
					out[i+1] = true
					i++
				}
			case '\'':
				state = single
			case '"':
				state = double
			case '#':
				// A comment, when # starts a word. It runs to the end of
				// the line, and nothing in it is quoted.
				if i == 0 || strings.IndexByte(" \t\n;&|()<>", s[i-1]) >= 0 {
					for i+1 < len(s) && s[i+1] != '\n' {
						i++
					}
				}
			}
		case single:
			out[i] = true
			if c == '\'' {
				state = none
			}
		case double:
			out[i] = true
			switch c {
			case '\\':
				if i+1 < len(s) {
					out[i+1] = true
					i++
				}
			case '"':
				state = none
			}
		}
	}
	return out
}

// Script is a rendered snippet. Assign sets one variable per parameter to
// its value, single-quoted, and Body is the snippet's command with each
// {{name}} replaced by "${HOP_P_name}". A caller may put shell text of its
// own between the two; Assign must come first.
type Script struct {
	Assign string // HOP_P_a='...'; HOP_P_b='...'; (empty with no parameters)
	Body   string
}

// String is the script to run: Assign, then Body.
func (s Script) String() string { return s.Assign + s.Body }

// Render fills command's placeholders from values. Every placeholder needs a
// value and every value a placeholder: anything else is refused, so a
// misspelt name never runs a half-filled command.
//
// A value reaches the shell only inside a single-quoted assignment at the
// top level of the script, so here-documents, comments, newlines, $(...)
// and backticks in the template or the value cannot make it run. In a
// here-document body the double quotes around ${HOP_P_name} are printed
// with the value; print it with printf '%s\n' {{x}} instead to avoid them.
func Render(command string, values map[string]string) (Script, error) {
	names, err := Placeholders(command)
	if err != nil {
		return Script{}, err
	}
	want := map[string]bool{}
	var missing []string
	for _, n := range names {
		want[n] = true
		if _, ok := values[n]; !ok {
			missing = append(missing, n)
		}
	}
	var unknown []string
	for n := range values {
		if !want[n] {
			unknown = append(unknown, n)
		}
	}
	if len(unknown) > 0 {
		return Script{}, fmt.Errorf("unknown parameter(s) %s; this snippet takes %s", strings.Join(slices.Sorted(slices.Values(unknown)), ", "), paramList(names))
	}
	if len(missing) > 0 {
		return Script{}, fmt.Errorf("missing parameter(s) %s; this snippet takes %s", strings.Join(missing, ", "), paramList(names))
	}
	var assign strings.Builder
	for _, n := range names {
		if strings.ContainsRune(values[n], 0) {
			return Script{}, fmt.Errorf("the value of %s contains a NUL byte", n)
		}
		// Always single-quoted, even a plain word, so not even a leading
		// tilde is expanded.
		fmt.Fprintf(&assign, "%s='%s'; ", ParamVar(n), strings.ReplaceAll(values[n], "'", `'\''`))
	}
	body := placeholderRe.ReplaceAllStringFunc(command, func(m string) string {
		return `"${` + ParamVar(placeholderRe.FindStringSubmatch(m)[1]) + `}"`
	})
	return Script{Assign: assign.String(), Body: body}, nil
}

func paramList(names []string) string {
	if len(names) == 0 {
		return "no parameters"
	}
	return strings.Join(names, ", ")
}

// Join builds a snippet's command line from words given on a command line
// (hop snippet add NAME -- WORDS...). One word is a shell command line as it
// is, like ssh's. Several words are quoted one by one, except that their
// placeholders stay bare so they can be filled: "--unit={{u}}" stays as it
// is, and "a b{{x}}" becomes 'a b'{{x}}.
func Join(words []string) string {
	if len(words) == 1 {
		return words[0]
	}
	q := make([]string, len(words))
	for i, w := range words {
		var sb strings.Builder
		last := 0
		for _, m := range placeholderRe.FindAllStringIndex(w, -1) {
			if m[0] > last {
				sb.WriteString(Quote(w[last:m[0]]))
			}
			sb.WriteString(w[m[0]:m[1]])
			last = m[1]
		}
		if last < len(w) || len(w) == 0 {
			sb.WriteString(Quote(w[last:]))
		}
		q[i] = sb.String()
	}
	return strings.Join(q, " ")
}
