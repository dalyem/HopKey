package cli

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// sshBlock is one Host block of an ssh_config file, reduced to the keywords
// hop imports.
type sshBlock struct {
	Patterns      []string // from the Host line; may include wildcards
	HostName      string
	User          string
	Port          int
	ProxyJump     string
	IdentityFiles []string
	Source        string // file:line, for messages
}

// concrete returns the patterns that name one machine: no wildcards or
// negation.
func (b sshBlock) concrete() []string {
	var out []string
	for _, p := range b.Patterns {
		if !strings.ContainsAny(p, "*?!") {
			out = append(out, p)
		}
	}
	return out
}

// sshConfigParser reads ssh_config files. It handles Host blocks, quoting,
// "Key=Value", comments and Include (with globs, to a bounded depth). Match
// blocks are skipped. Everything else is ignored.
type sshConfigParser struct {
	home      string
	skipDir   string // Include of anything under here is skipped: hop's own output
	blocks    []sshBlock
	warnings  []string
	defaults  bool // saw settings outside a concrete Host block
	readFile  func(string) (io.ReadCloser, error)
	globFiles func(string) ([]string, error)
}

const maxIncludeDepth = 5

func newSSHConfigParser(home, skipDir string) *sshConfigParser {
	return &sshConfigParser{
		home: home, skipDir: skipDir,
		readFile:  func(p string) (io.ReadCloser, error) { return os.Open(p) },
		globFiles: filepath.Glob,
	}
}

func (p *sshConfigParser) warnf(format string, args ...any) {
	p.warnings = append(p.warnings, fmt.Sprintf(format, args...))
}

// parseFile reads path. A missing top-level file is an error; a missing
// included file is skipped, as ssh does.
func (p *sshConfigParser) parseFile(path string, depth int) error {
	rc, err := p.readFile(path)
	if err != nil {
		return err
	}
	defer rc.Close()
	return p.parse(rc, path, depth)
}

func (p *sshConfigParser) parse(r io.Reader, name string, depth int) error {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64<<10), 1<<20)
	var cur *sshBlock
	flush := func() {
		if cur != nil {
			p.blocks = append(p.blocks, *cur)
			cur = nil
		}
	}
	line := 0
	for sc.Scan() {
		line++
		key, args := splitDirective(sc.Text())
		if key == "" {
			continue
		}
		switch key {
		case "host":
			flush()
			cur = &sshBlock{Patterns: args, Source: fmt.Sprintf("%s:%d", name, line)}
			if len(cur.concrete()) == 0 {
				// "Host *" and the like: defaults, not importable hosts.
				p.defaults = true
				cur = nil
			}
			continue
		case "match":
			flush()
			p.defaults = true
			continue
		case "include":
			for _, pat := range args {
				p.include(pat, depth)
			}
			continue
		}
		if cur == nil || len(args) == 0 {
			continue
		}
		switch key {
		case "hostname":
			cur.HostName = args[0]
		case "user":
			cur.User = args[0]
		case "port":
			if n, err := strconv.Atoi(args[0]); err == nil && n > 0 && n < 65536 {
				cur.Port = n
			} else {
				p.warnf("%s:%d: ignoring Port %q", name, line, args[0])
			}
		case "proxyjump":
			cur.ProxyJump = args[0]
		case "identityfile":
			cur.IdentityFiles = append(cur.IdentityFiles, args[0])
		}
	}
	flush()
	return sc.Err()
}

func (p *sshConfigParser) include(pattern string, depth int) {
	if depth >= maxIncludeDepth {
		p.warnf("Include %q is nested too deeply and is skipped", pattern)
		return
	}
	pattern = p.expand(pattern)
	if !filepath.IsAbs(pattern) {
		pattern = filepath.Join(p.home, ".ssh", pattern) // relative paths are relative to ~/.ssh
	}
	matches, err := p.globFiles(pattern)
	if err != nil {
		p.warnf("Include %q: %v", pattern, err)
		return
	}
	for _, m := range matches {
		if p.skipDir != "" && (m == p.skipDir || strings.HasPrefix(m, p.skipDir+string(filepath.Separator))) {
			continue // hop's own generated config: importing it would copy the vault into itself
		}
		if err := p.parseFile(m, depth+1); err != nil {
			p.warnf("Include %s: %v", m, err)
		}
	}
}

// expand resolves a leading ~ and the %d token (the home directory), which are
// the forms that appear in Include and IdentityFile paths.
func (p *sshConfigParser) expand(path string) string {
	path = strings.ReplaceAll(path, "%d", p.home)
	if path == "~" {
		return p.home
	}
	if strings.HasPrefix(path, "~/") {
		return filepath.Join(p.home, path[2:])
	}
	return path
}

// splitDirective splits a config line into a lower-cased keyword and its
// arguments. It understands "Key Value", "Key=Value", "Key = Value", double
// quotes and # comments. A blank or comment line returns "".
func splitDirective(line string) (key string, args []string) {
	var tokens []string
	var cur strings.Builder
	inQuote, have := false, false
	push := func() {
		if have {
			tokens = append(tokens, cur.String())
			cur.Reset()
			have = false
		}
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
			inQuote, have = true, true
		case c == '#' && !have:
			push()
			i = len(line)
		case c == ' ' || c == '\t' || c == '\r':
			push()
		case c == '=' && len(tokens) == 0 && !have:
			// "=" right after the keyword, with nothing yet: separator.
		case c == '=' && len(tokens) == 0:
			push() // "Key=Value": the keyword ends here
		case c == '=' && len(tokens) == 1 && !have:
			// "Key = Value": a lone "=" between keyword and value.
		default:
			cur.WriteByte(c)
			have = true
		}
	}
	push()
	if len(tokens) == 0 {
		return "", nil
	}
	return strings.ToLower(tokens[0]), tokens[1:]
}
