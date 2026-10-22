package cli

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
)

// configAlias is one concrete name from a Host line.
type configAlias struct {
	Name   string
	Source string // file:line of the Host line that first named it
}

// hostLoc is where a Host line sits: the file as ssh prints it, and the line.
type hostLoc struct {
	file string
	line int
}

// configScan lists what an ssh_config file names, and nothing about what
// those names mean: ssh -G decides that (see sshprobe.go). It reads the file
// and every file it Includes (globs, ~ and paths relative to ~/.ssh, as
// OpenSSH expands them) and collects:
//
//   - the aliases: the whitespace-separated words of Host lines that hold no
//     wildcard and no leading "!", each once, in file order;
//   - the words of every Host line, by file and line, so that a Host line ssh
//     reports as applied can be checked for the alias it applied to;
//   - the lines that use a Match criterion which runs a command (exec), which
//     make ssh -G run that command;
//   - the Include lines it could not resolve or read. ssh -G reads those
//     files all the same, so nothing the scan says about the config is
//     complete while that list is not empty.
type configScan struct {
	home    string // the passwd home: what OpenSSH expands ~ to
	skipDir string // Include of anything under here is skipped for aliases: hop's own output

	aliases   []configAlias
	hostLines map[hostLoc][]string // positive literal words of each Host line
	matchExec []string             // file:line
	unscanned []string             // file:line: Include "x": why it is not scanned

	seen      map[string]bool
	readFile  func(string) (io.ReadCloser, error)
	globFiles func(string) ([]string, error)
}

// maxIncludeDepth is OpenSSH's own limit.
const maxIncludeDepth = 16

func newConfigScan(home, skipDir string) *configScan {
	return &configScan{
		home: home, skipDir: skipDir,
		hostLines: map[hostLoc][]string{}, seen: map[string]bool{},
		readFile:  func(p string) (io.ReadCloser, error) { return os.Open(p) },
		globFiles: filepath.Glob,
	}
}

// scan reads path. A missing top-level file is an error; a missing included
// file is skipped, as ssh does.
func (s *configScan) scan(path string) error { return s.file(path, 0, true) }

// declares reports whether the Host line at file:line names alias literally,
// as a word that is not negated or a pattern. file is compared as ssh prints
// it, so ./a and a are the same file.
func (s *configScan) declares(file string, line int, alias string) bool {
	return slices.ContainsFunc(s.hostLines[hostLoc{filepath.Clean(file), line}], func(w string) bool {
		return strings.EqualFold(w, alias)
	})
}

// file scans one file. With aliases false (hop's own generated config) the
// file is still read for what it makes ssh do, but its Host lines name nothing
// to import.
func (s *configScan) file(path string, depth int, aliases bool) error {
	rc, err := s.readFile(path)
	if err != nil {
		return err
	}
	defer rc.Close()
	sc := bufio.NewScanner(rc)
	sc.Buffer(make([]byte, 0, 64<<10), 1<<20)
	for line := 1; sc.Scan(); line++ {
		text := sc.Text()
		key, args := splitDirective(text)
		source := fmt.Sprintf("%s:%d", path, line)
		switch key {
		case "host":
			var words []string
			for _, a := range args {
				if strings.ContainsAny(a, "*?") || strings.HasPrefix(a, "!") {
					continue
				}
				words = append(words, a)
				if aliases && !s.seen[strings.ToLower(a)] {
					s.seen[strings.ToLower(a)] = true
					s.aliases = append(s.aliases, configAlias{Name: a, Source: source})
				}
			}
			if aliases {
				s.hostLines[hostLoc{filepath.Clean(path), line}] = words
			}
		case "match":
			if matchRunsCommand(args) {
				s.matchExec = append(s.matchExec, source)
			}
		case "include":
			for _, pat := range args {
				s.include(source, pat, depth, aliases)
			}
		}
	}
	return sc.Err()
}

// include scans the files one Include argument names. Anything it cannot
// resolve or read goes to s.unscanned, because ssh -G will still read it.
func (s *configScan) include(source, raw string, depth int, aliases bool) {
	fail := func(why string) {
		s.unscanned = append(s.unscanned, fmt.Sprintf("%s: Include %q %s", source, raw, why))
	}
	if depth >= maxIncludeDepth {
		fail("is nested too deeply")
		return
	}
	pattern, why := s.resolveInclude(raw)
	if why != "" {
		fail(why)
		return
	}
	matches, err := s.globFiles(pattern)
	if err != nil {
		fail(fmt.Sprintf("is not a usable pattern (%v)", err))
		return
	}
	for _, m := range matches {
		sub := aliases
		if s.skipDir != "" && underDir(m, s.skipDir) {
			sub = false // hop's own generated config: importing it would copy the vault into itself
		}
		err := s.file(m, depth+1, sub)
		// ssh skips a file that is gone and reads nothing from a directory.
		if err != nil && !errors.Is(err, fs.ErrNotExist) && !errors.Is(err, syscall.EISDIR) {
			fail(fmt.Sprintf("names %s, which cannot be read (%v)", m, err))
		}
	}
}

func underDir(path, dir string) bool {
	path, dir = filepath.Clean(path), filepath.Clean(dir)
	return path == dir || strings.HasPrefix(path, dir+string(filepath.Separator))
}

// resolveInclude expands an Include argument the way OpenSSH does for a user
// config: %d and %% tokens, a leading ~ (the passwd home), and a path that is
// not absolute is relative to ~/.ssh. why says what it cannot expand: another
// token, ${VAR} or ~user depend on things hop does not know.
func (s *configScan) resolveInclude(raw string) (pattern, why string) {
	if strings.Contains(raw, "${") {
		return "", "uses an environment variable, which hop does not expand"
	}
	var sb strings.Builder
	for i := 0; i < len(raw); i++ {
		if raw[i] != '%' {
			sb.WriteByte(raw[i])
			continue
		}
		i++
		switch {
		case i < len(raw) && raw[i] == '%':
			sb.WriteByte('%')
		case i < len(raw) && raw[i] == 'd':
			sb.WriteString(s.home)
		default:
			return "", "uses a token hop does not expand"
		}
	}
	p := sb.String()
	switch {
	case p == "~":
		p = s.home
	case strings.HasPrefix(p, "~/"):
		p = filepath.Join(s.home, p[2:])
	case strings.HasPrefix(p, "~"):
		return "", "names another user's home (~user), which hop does not expand"
	case !filepath.IsAbs(p):
		p = filepath.Join(s.home, ".ssh", p)
	}
	return p, ""
}

// matchCriteriaWithArg are the Match criteria that take an argument. All,
// canonical and final stand alone.
var matchCriteriaWithArg = map[string]bool{
	"host": true, "originalhost": true, "user": true, "localuser": true,
	"localnetwork": true, "tagged": true, "command": true, "sessiontype": true, "version": true,
}

// matchRunsCommand reports whether a Match line makes ssh run a command: it
// has an exec criterion, negated or not, in any position. Criteria are read
// the way OpenSSH reads them (a word, an optional leading "!", then the
// argument of the criteria that take one), so `Match host exec` is a host
// named exec, not a command. A word hop does not know could take an argument
// or not, so a line with one counts as exec if any word is: this is a consent
// check, and it errs toward asking.
func matchRunsCommand(args []string) bool {
	for i := 0; i < len(args); i++ {
		name := strings.ToLower(strings.TrimPrefix(args[i], "!"))
		switch {
		case name == "exec":
			return true
		case name == "all" || name == "canonical" || name == "final":
		case matchCriteriaWithArg[name]:
			i++ // its argument is not a criterion
		default:
			return slices.ContainsFunc(args, func(a string) bool {
				return strings.EqualFold(strings.TrimLeft(a, "!"), "exec")
			})
		}
	}
	return false
}

// normIdentity makes the ways of writing one IdentityFile path comparable.
func normIdentity(home, path string) string {
	switch {
	case path == "~":
		path = home
	case strings.HasPrefix(path, "~/"):
		path = filepath.Join(home, path[2:])
	}
	return filepath.Clean(path)
}

// argSpan is one word of a config line: its text with quotes removed, and the
// byte range it occupies in the line (quotes included).
type argSpan struct {
	val        string
	start, end int
}

// splitDirective splits a config line into a lower-cased keyword and its
// arguments. It understands "Key Value", "Key=Value", "Key = Value", quotes
// and # comments. A blank or comment line returns "".
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
// the arguments, each with the byte range it covers in line. Words split as
// OpenSSH's argv_split does: single or double quotes group, and a backslash
// escapes a quote, a backslash, or (outside quotes) a space.
func directiveSpans(line string) []argSpan {
	var tokens []argSpan
	var cur strings.Builder
	var quote byte
	have := false
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
		case c == '\\' && i+1 < len(line) && (line[i+1] == '"' || line[i+1] == '\'' || line[i+1] == '\\' || (quote == 0 && line[i+1] == ' ')):
			begin(i)
			i++
			cur.WriteByte(line[i])
		case quote != 0:
			if c == quote {
				quote = 0
			} else {
				cur.WriteByte(c)
			}
		case c == '"' || c == '\'':
			begin(i)
			quote = c
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
