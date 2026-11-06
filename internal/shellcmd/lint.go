package shellcmd

import (
	"fmt"
	"path"
	"regexp"
	"slices"
	"strings"
)

// evalContext refuses a placeholder that stands where the shell evaluates
// text, so that a value, harmless as a variable's contents, would run there
// after all:
//
//   - inside $((...)), ((...)) or $[...], and inside ${...}, where bash
//     evaluates an array index or an offset as arithmetic, and an array
//     index in a value (a[$(cmd)]) runs cmd;
//   - inside [[ ... ]], whose -eq, -lt and the like are arithmetic too;
//     each of these runs to its end over line breaks;
//   - as an argument of eval, let or trap;
//   - as the command string of sh, bash, zsh, dash, ksh or su -c;
//   - in an assignment (v={{x}}, a[{{x}}]=1, export v={{x}}), since a
//     variable holding the value can be evaluated later: ${!v}, a nameref,
//     arithmetic.
//
// It is a lint, not a parser: it follows quotes, comments, $(...),
// backticks and command separators, and reads a here-document's lines as
// commands. It misses evaluation it does not know (ssh host {{x}}, xargs sh
// -c, a value piped to a shell, or saved by for or read and evaluated
// later), and can refuse a placeholder that only looks like one of these
// (echo eval {{x}}).
func evalContext(s string, quoted []bool) error {
	ph := map[int][]int{} // a placeholder's start: its match
	for _, m := range placeholderRe.FindAllStringSubmatchIndex(s, -1) {
		ph[m[0]] = m
	}
	name := func(start int) string { return s[ph[start][2]:ph[start][3]] }

	const (
		cmdFrame   = iota // the top level, $(...) or backticks
		arithFrame        // $((...)), ((...)), $[...]
		paramFrame        // ${...}
	)
	type frame struct {
		kind     int
		close    byte // ')' for $( and arithmetic, '`', ']' for $[, '}' for ${
		depth    int  // open parentheses, brackets or braces
		words    []string
		word     strings.Builder
		inWord   bool
		wordPh   []int // placeholders in the current word
		dbracket bool  // inside [[ ... ]]
		// inherit is why the output of this $(...) or backticks is
		// evaluated, from the word around it: x=$(...), eval $(...).
		inherit string
	}
	stack := []*frame{{kind: cmdFrame}}
	top := func() *frame { return stack[len(stack)-1] }
	evaluated := func() bool {
		return slices.ContainsFunc(stack, func(f *frame) bool { return f.kind != cmdFrame })
	}

	var err error
	endWord := func(f *frame) {
		if !f.inWord {
			return
		}
		w := f.word.String()
		f.word.Reset()
		f.inWord = false
		if len(f.wordPh) > 0 && err == nil {
			why := f.inherit
			if why == "" {
				why = wordContext(f.words, w, f.dbracket)
			}
			if why != "" {
				err = fmt.Errorf("{{%s}} is %s; hop refuses a placeholder there", name(f.wordPh[0]), why)
			}
		}
		f.wordPh = f.wordPh[:0]
		switch {
		case w == "[[" && len(f.words) == 0:
			f.dbracket = true
		case w == "]]" && f.dbracket:
			f.dbracket = false
		}
		if len(f.words) == 0 && reserved[w] {
			return // a new command starts after it
		}
		f.words = append(f.words, w)
	}
	endCommand := func(f *frame) {
		endWord(f)
		f.words = f.words[:0]
	}
	startsWord := func(i int) bool {
		return i == 0 || strings.IndexByte(" \t\n;&|()<>", s[i-1]) >= 0
	}
	// substitution opens a $(...) or backticks in f's current word.
	substitution := func(f *frame, close byte) *frame {
		why := f.inherit
		if why == "" {
			why = wordContext(f.words, f.word.String(), f.dbracket)
		}
		if why != "" {
			why = "in a command substitution whose output is " + why
		}
		return &frame{kind: cmdFrame, close: close, inherit: why}
	}

	for i := 0; i < len(s) && err == nil; i++ {
		f := top()
		if q := quoted[i]; q || s[i] == '\\' || s[i] == '\'' || s[i] == '"' {
			// Quoted text, or a quote or backslash that starts some: part of
			// the word, and nothing in it is structure.
			if f.kind == cmdFrame {
				f.word.WriteByte(s[i])
				f.inWord = true
			}
			continue
		}
		if p, ok := ph[i]; ok {
			if evaluated() {
				return fmt.Errorf("{{%s}} is inside $((...)), ((...)), $[...] or ${...}, where bash evaluates text as arithmetic and an array index in a value can run a command; hop refuses a placeholder there", name(i))
			}
			f.word.WriteString(s[i:p[1]])
			f.inWord = true
			f.wordPh = append(f.wordPh, i)
			i = p[1] - 1
			continue
		}
		c := s[i]
		if f.kind != cmdFrame {
			// Only the end of an arithmetic or ${...} matters here.
			switch {
			case c == f.close && f.depth == 1:
				stack = stack[:len(stack)-1]
			case c == f.close:
				f.depth--
			case c == '(' && f.close == ')', c == '[' && f.close == ']', c == '{' && f.close == '}':
				f.depth++
			}
			continue
		}
		switch {
		case strings.HasPrefix(s[i:], "$(("):
			f.word.WriteString("$((")
			f.inWord = true
			stack = append(stack, &frame{kind: arithFrame, close: ')', depth: 2})
			i += 2
		case strings.HasPrefix(s[i:], "((") && !f.inWord:
			stack = append(stack, &frame{kind: arithFrame, close: ')', depth: 2})
			i++
		case strings.HasPrefix(s[i:], "$["):
			f.word.WriteString("$[")
			f.inWord = true
			stack = append(stack, &frame{kind: arithFrame, close: ']', depth: 1})
			i++
		case strings.HasPrefix(s[i:], "${"):
			f.word.WriteString("${")
			f.inWord = true
			stack = append(stack, &frame{kind: paramFrame, close: '}', depth: 1})
			i++
		case strings.HasPrefix(s[i:], "$("):
			f.word.WriteString("$(")
			f.inWord = true
			stack = append(stack, substitution(f, ')'))
			i++
		case c == '`' && f.close == '`':
			endCommand(f)
			stack = stack[:len(stack)-1]
		case c == '`':
			f.word.WriteByte(c)
			f.inWord = true
			stack = append(stack, substitution(f, '`'))
		case c == ')' && f.close == ')' && f.depth == 0:
			endCommand(f)
			stack = stack[:len(stack)-1]
		case c == '#' && startsWord(i):
			// A comment, as quotedBytes reads one.
			for i+1 < len(s) && s[i+1] != '\n' {
				i++
			}
		case c == ' ' || c == '\t':
			endWord(f)
		case c == '\n' || c == ';':
			endWord(f) // which may be the ]] that ends a [[
			if c == '\n' && f.dbracket {
				continue // [[ ... ]] goes on past a line break, to its ]]
			}
			endCommand(f)
			f.dbracket = false
		case c == '&' && i > 0 && (s[i-1] == '>' || s[i-1] == '<'), c == '&' && i+1 < len(s) && s[i+1] == '>':
			f.word.WriteByte(c) // a redirection: 2>&1, &>file
			f.inWord = true
		case c == '&' || c == '|' || c == '(' || c == ')':
			if c == '(' {
				f.depth++
			} else if c == ')' {
				f.depth--
			}
			if f.dbracket {
				endWord(f) // && and || inside [[ ]] do not end it
			} else {
				endCommand(f)
			}
		default:
			f.word.WriteByte(c)
			f.inWord = true
		}
	}
	if err != nil {
		return err
	}
	for f := top(); ; f = top() {
		endCommand(f)
		if err != nil || len(stack) == 1 {
			return err
		}
		stack = stack[:len(stack)-1]
	}
}

// reserved words start a command rather than being one.
var reserved = map[string]bool{
	"!": true, "{": true, "}": true, "if": true, "then": true, "else": true, "elif": true,
	"while": true, "until": true, "do": true, "time": true,
}

// assignRe is a word the shell reads as an assignment: name=, name+=,
// name[index]=.
var assignRe = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*(\[.*\])?\+?=`)

// wordContext says why a placeholder in word w, after words in the same
// simple command, stands where the shell evaluates it, or "" when it does
// not.
func wordContext(words []string, w string, dbracket bool) string {
	if dbracket {
		return "inside [[ ... ]], where bash evaluates the operands of -eq, -lt and the like as arithmetic and an array index in a value can run a command; use [ ... ] instead"
	}
	for _, p := range words {
		switch bare(p) {
		case "eval":
			return "an argument of eval, which runs its arguments as shell code"
		case "let":
			return "an argument of let, which evaluates it as arithmetic"
		case "trap":
			return "an argument of trap, which runs its action as shell code"
		}
	}
	if shellCommandString(words) == len(words) {
		return `the command string of a shell's -c, which runs it as shell code; pass the value as a positional parameter instead: sh -c '... "$1"' sh {{name}}`
	}
	if assignRe.MatchString(w) && (len(words) > 0 && declaration[bare(words[0])] || !slices.ContainsFunc(words, func(p string) bool { return !assignRe.MatchString(p) })) {
		return "in an assignment, and a variable holding the value can be evaluated later (${!v}, a nameref, arithmetic); use the placeholder directly where the value is needed, or env NAME={{name}} command to pass it in a command's environment"
	}
	return ""
}

// declaration are the builtins whose arguments are assignments.
var declaration = map[string]bool{"export": true, "local": true, "declare": true, "typeset": true, "readonly": true, "alias": true}

// shells run their -c argument as shell code.
var shells = map[string]bool{"sh": true, "bash": true, "zsh": true, "dash": true, "ksh": true, "mksh": true, "ash": true, "su": true}

var cOption = regexp.MustCompile(`^-[A-Za-z]*c[A-Za-z]*$`)

// shellCommandString is the index, in words and the word that would follow
// them, of the command string a shell's -c runs, or -1 when words start no
// shell with -c.
func shellCommandString(words []string) int {
	at := slices.IndexFunc(words, func(w string) bool { return shells[path.Base(bare(w))] })
	if at < 0 {
		return -1
	}
	sawC := false
	for i := at + 1; i < len(words); i++ {
		w := bare(words[i])
		switch {
		case cOption.MatchString(w):
			sawC = true
		case w == "-o" || w == "+o":
			i++ // the option's argument
		case strings.HasPrefix(w, "-") || strings.HasPrefix(w, "+"):
		case sawC:
			return i
		}
	}
	if sawC {
		return len(words)
	}
	return -1
}

// bare is a word without its quotes and backslashes, as the shell would
// see it.
func bare(w string) string { return strings.NewReplacer(`'`, "", `"`, "", `\`, "").Replace(w) }
