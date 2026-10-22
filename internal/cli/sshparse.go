package cli

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// configAlias is one concrete name from a Host line.
type configAlias struct {
	Name   string
	Source string // file:line of the Host line that first named it
}

// configScan lists what an ssh_config file names, and nothing about what
// those names mean: ssh -G decides that (see sshprobe.go). It reads the file
// and every file it Includes (globs, ~ and paths relative to ~/.ssh, as
// OpenSSH expands them) and collects:
//
//   - the aliases: the whitespace-separated words of Host lines that hold no
//     wildcard and no leading "!", each once, in file order;
//   - the lines that use "Match exec", which make ssh -G run a command;
//   - the User and IdentityFile values the files set, so that a value ssh -G
//     prints as a default can be told from one the user wrote.
type configScan struct {
	home    string
	skipDir string // Include of anything under here is skipped: hop's own output

	aliases   []configAlias
	matchExec []string // file:line
	users     map[string]bool
	identity  map[string]bool // normalized by normIdentity
	warnings  []string

	seen      map[string]bool
	readFile  func(string) (io.ReadCloser, error)
	globFiles func(string) ([]string, error)
}

// maxIncludeDepth is OpenSSH's own limit.
const maxIncludeDepth = 16

func newConfigScan(home, skipDir string) *configScan {
	return &configScan{
		home: home, skipDir: skipDir,
		users: map[string]bool{}, identity: map[string]bool{}, seen: map[string]bool{},
		readFile:  func(p string) (io.ReadCloser, error) { return os.Open(p) },
		globFiles: filepath.Glob,
	}
}

func (s *configScan) warnf(format string, args ...any) {
	s.warnings = append(s.warnings, fmt.Sprintf(format, args...))
}

// scan reads path. A missing top-level file is an error; a missing included
// file is skipped, as ssh does.
func (s *configScan) scan(path string) error { return s.file(path, 0) }

func (s *configScan) file(path string, depth int) error {
	rc, err := s.readFile(path)
	if err != nil {
		return err
	}
	defer rc.Close()
	sc := bufio.NewScanner(rc)
	sc.Buffer(make([]byte, 0, 64<<10), 1<<20)
	for line := 1; sc.Scan(); line++ {
		key, args := splitDirective(sc.Text())
		source := fmt.Sprintf("%s:%d", path, line)
		switch key {
		case "host":
			for _, a := range args {
				if strings.ContainsAny(a, "*?") || strings.HasPrefix(a, "!") || s.seen[strings.ToLower(a)] {
					continue
				}
				s.seen[strings.ToLower(a)] = true
				s.aliases = append(s.aliases, configAlias{Name: a, Source: source})
			}
		case "match":
			for _, a := range args {
				if strings.EqualFold(a, "exec") {
					s.matchExec = append(s.matchExec, source)
					break
				}
			}
		case "user":
			if len(args) > 0 {
				s.users[args[0]] = true
			}
		case "identityfile":
			if len(args) > 0 {
				s.identity[normIdentity(s.home, args[0])] = true
			}
		case "include":
			for _, pat := range args {
				s.include(pat, depth)
			}
		}
	}
	return sc.Err()
}

func (s *configScan) include(pattern string, depth int) {
	if depth >= maxIncludeDepth {
		s.warnf("Include %q is nested too deeply and is skipped", pattern)
		return
	}
	pattern = s.expand(pattern)
	if strings.Contains(pattern, "%") || strings.Contains(pattern, "${") {
		s.warnf("Include %q uses a token or variable hop does not expand; the hosts in it may be missing", pattern)
		return
	}
	if !filepath.IsAbs(pattern) {
		pattern = filepath.Join(s.home, ".ssh", pattern) // relative paths are relative to ~/.ssh
	}
	matches, err := s.globFiles(pattern)
	if err != nil {
		s.warnf("Include %q: %v", pattern, err)
		return
	}
	for _, m := range matches {
		if s.skipDir != "" && (m == s.skipDir || strings.HasPrefix(m, s.skipDir+string(filepath.Separator))) {
			continue // hop's own generated config: importing it would copy the vault into itself
		}
		if err := s.file(m, depth+1); err != nil {
			s.warnf("Include %s: %v", m, err)
		}
	}
}

// expand resolves a leading ~ and the %d token (the home directory).
func (s *configScan) expand(path string) string { return expandHome(s.home, path) }

func expandHome(home, path string) string {
	path = strings.ReplaceAll(path, "%d", home)
	if path == "~" {
		return home
	}
	if strings.HasPrefix(path, "~/") {
		return filepath.Join(home, path[2:])
	}
	return path
}

// normIdentity makes the ways of writing one IdentityFile path comparable.
func normIdentity(home, path string) string { return filepath.Clean(expandHome(home, path)) }

// argSpan is one word of a config line: its text with quotes removed, and the
// byte range it occupies in the line (quotes included).
type argSpan struct {
	val        string
	start, end int
}

// splitDirective splits a config line into a lower-cased keyword and its
// arguments. It understands "Key Value", "Key=Value", "Key = Value", double
// quotes and # comments. A blank or comment line returns "".
func splitDirective(line string) (key string, args []string) {
	spans := directiveSpans(line)
	if len(spans) == 0 {
		return "", nil
	}
	for _, sp := range spans[1:] {
		args = append(args, sp.val)
	}
	return strings.ToLower(spans[0].val), args
}

// directiveSpans is splitDirective with positions: the keyword first, then
// the arguments, each with the byte range it covers in line.
func directiveSpans(line string) []argSpan {
	var tokens []argSpan
	var cur strings.Builder
	inQuote, have := false, false
	start := 0
	push := func(end int) {
		if have {
			tokens = append(tokens, argSpan{cur.String(), start, end})
			cur.Reset()
			have = false
		}
	}
	begin := func(i int) {
		if !have {
			start = i
		}
		have = true
	}
	for i := 0; i < len(line); i++ {
		c := line[i]
		switch {
		case inQuote:
			if c == '"' {
				inQuote = false
			} else {
				cur.WriteByte(c)
			}
		case c == '"':
			begin(i)
			inQuote = true
		case c == '#' && !have:
			push(i)
			i = len(line)
		case c == ' ' || c == '\t' || c == '\r':
			push(i)
		case c == '=' && len(tokens) == 0 && !have:
			// "=" right after the keyword, with nothing yet: separator.
		case c == '=' && len(tokens) == 0:
			push(i) // "Key=Value": the keyword ends here
		case c == '=' && len(tokens) == 1 && !have:
			// "Key = Value": a lone "=" between keyword and value.
		default:
			begin(i)
			cur.WriteByte(c)
		}
	}
	push(len(line))
	return tokens
}
