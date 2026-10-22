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

// sshBlock is one Host line of an ssh_config file with the settings hop
// imports, merged the way ssh merges them (see sshConfigParser).
type sshBlock struct {
	Patterns      []string // from the Host line; may include wildcards
	HostName      string
	User          string
	Port          int
	ProxyJump     string
	IdentityFiles []string
	Source        string // file:line, for messages
	// Unsupported says why importing this host would not reproduce what ssh
	// does with it: a Match block, a wildcard Host block or a setting from
	// before the first Host line that decides one of its values, or a token
	// hop does not expand. A host with reasons is skipped, not imported
	// with different behavior.
	Unsupported []string
}

// concrete returns the patterns that name one machine: no wildcards or
// negation.
func (b sshBlock) concrete() []string { return concretePatterns(b.Patterns) }

func concretePatterns(patterns []string) []string {
	var out []string
	for _, p := range patterns {
		if !strings.ContainsAny(p, "*?!") {
			out = append(out, p)
		}
	}
	return out
}

type blockKind int

const (
	kindGlobal blockKind = iota // lines before the first Host or Match: they apply to every host
	kindHost
	kindMatch
)

// rawBlock is the lines under one Host or Match line (or before the first),
// across files: an Include inside a block adds its lines to that block.
type rawBlock struct {
	kind     blockKind
	patterns []string
	source   string
	dirs     []rawDirective
}

type rawDirective struct {
	key    string
	args   []string
	source string
}

// sshConfigParser reads ssh_config files the way ssh does for the settings it
// supports (HostName, User, Port, ProxyJump, IdentityFile):
//
//   - the first value of a single-valued setting wins, across every block that
//     applies to the host, in file order; IdentityFile accumulates;
//   - an Include inside a Host block adds the included file's lines to that
//     block, and a Host or Match line inside the included file ends with that
//     file;
//   - "Key=Value", quoting and comments are understood, and Include takes
//     globs, to a bounded depth.
//
// It does not evaluate Match blocks, merge settings that a wildcard Host
// block or a Match block supplies, or expand tokens beyond %h in HostName and
// %d in IdentityFile and Include. A host whose imported settings depend on
// any of those gets Unsupported reasons instead of a guess.
type sshConfigParser struct {
	home      string
	skipDir   string // Include of anything under here is skipped: hop's own output
	blocks    []sshBlock
	warnings  []string
	defaults  bool // saw settings outside a concrete Host block
	readFile  func(string) (io.ReadCloser, error)
	globFiles func(string) ([]string, error)

	raw []*rawBlock
	ctx *rawBlock // where the next setting goes
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
// included file is skipped, as ssh does. Reading a top-level file (depth 0)
// also works out the importable hosts.
func (p *sshConfigParser) parseFile(path string, depth int) error {
	rc, err := p.readFile(path)
	if err != nil {
		return err
	}
	defer rc.Close()
	if depth == 0 {
		global := &rawBlock{kind: kindGlobal, patterns: []string{"*"}, source: path}
		p.raw, p.ctx = []*rawBlock{global}, global
	}
	err = p.parse(rc, path, depth)
	if depth == 0 {
		p.finish()
	}
	return err
}

func (p *sshConfigParser) parse(r io.Reader, name string, depth int) error {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64<<10), 1<<20)
	line := 0
	for sc.Scan() {
		line++
		key, args := splitDirective(sc.Text())
		if key == "" {
			continue
		}
		source := fmt.Sprintf("%s:%d", name, line)
		switch key {
		case "host", "match":
			kind := kindHost
			if key == "match" {
				kind = kindMatch
			}
			p.ctx = &rawBlock{kind: kind, patterns: args, source: source}
			p.raw = append(p.raw, p.ctx)
			continue
		case "include":
			// The included lines belong to the block the Include is in, and
			// what the file opens ends with it.
			outer := p.ctx
			for _, pat := range args {
				p.include(pat, depth)
			}
			p.ctx = outer
			continue
		case "hostname", "user", "port", "proxyjump", "identityfile":
			if len(args) > 0 && p.ctx != nil {
				p.ctx.dirs = append(p.ctx.dirs, rawDirective{key, args, source})
			}
		}
	}
	return sc.Err()
}

// finish turns the blocks read into the hosts to import: one per Host line
// that names a machine, and none for a line whose names an earlier one
// already covers (ssh merges the two, so the earlier one carries both).
func (p *sshConfigParser) finish() {
	p.blocks, p.defaults = nil, false
	seen := map[string]bool{}
	for _, b := range p.raw {
		switch b.kind {
		case kindMatch:
			p.defaults = true
			continue
		case kindGlobal:
			continue
		}
		names := concretePatterns(b.patterns)
		if len(names) == 0 {
			// "Host *" and the like: defaults, not importable hosts.
			p.defaults = true
			continue
		}
		fresh := false
		for _, n := range names {
			if !seen[strings.ToLower(n)] {
				fresh = true
			}
			seen[strings.ToLower(n)] = true
		}
		if fresh {
			p.blocks = append(p.blocks, p.merge(b, names))
		}
	}
}

// merge works out the settings ssh would use for a host called by names, from
// every block that can apply to it, first value first.
func (p *sshConfigParser) merge(own *rawBlock, names []string) sshBlock {
	out := sshBlock{Patterns: own.patterns, Source: own.source}
	resolved := map[string]bool{}
	skip := func(format string, args ...any) {
		out.Unsupported = append(out.Unsupported, fmt.Sprintf(format, args...))
	}
	for _, b := range p.raw {
		isOwn := b.kind == kindHost && listsAny(b.patterns, names)
		var from string // for a block that is not the host's own
		switch {
		case isOwn:
		case b.kind == kindGlobal:
			from = "the settings before the first Host line in " + b.source
		case b.kind == kindMatch:
			from = "the Match block at " + b.source + ", which hop cannot evaluate"
		case matchesAny(b.patterns, names):
			from = fmt.Sprintf("the wildcard block \"Host %s\" at %s", strings.Join(b.patterns, " "), b.source)
		default:
			continue
		}
		for _, d := range b.dirs {
			val := d.args[0]
			switch {
			case d.key == "identityfile" && !isOwn:
				p.warnf("host %s: IdentityFile %s from %s is not imported", names[0], val, from)
				continue
			case d.key == "identityfile":
			case resolved[d.key]:
				continue // an earlier value wins
			case d.key == "port" && isOwn:
				if n, err := strconv.Atoi(val); err != nil || n <= 0 || n >= 65536 {
					p.warnf("%s: ignoring Port %q", d.source, val)
					continue
				}
			}
			if d.key != "identityfile" {
				resolved[d.key] = true
			}
			if !isOwn {
				skip("%s is set by %s, ahead of this host's own settings; hop does not merge settings from other blocks", d.key, from)
				continue
			}
			if unsupportedToken(d.key, val) {
				skip("%s %q at %s uses a %% token hop does not expand", d.key, val, d.source)
				continue
			}
			switch d.key {
			case "hostname":
				out.HostName = val
			case "user":
				out.User = val
			case "port":
				out.Port, _ = strconv.Atoi(val)
			case "proxyjump":
				out.ProxyJump = val
			case "identityfile":
				out.IdentityFiles = append(out.IdentityFiles, val)
			}
		}
	}
	return out
}

// unsupportedToken reports whether val holds a % token other than the ones
// hop expands: %h in HostName and %d in IdentityFile.
func unsupportedToken(key, val string) bool {
	switch key {
	case "hostname":
		val = strings.ReplaceAll(val, "%h", "")
	case "identityfile":
		val = strings.ReplaceAll(val, "%d", "")
	}
	return strings.Contains(val, "%")
}

// listsAny reports whether patterns name one of names literally.
func listsAny(patterns, names []string) bool {
	for _, p := range patterns {
		for _, n := range names {
			if !strings.HasPrefix(p, "!") && strings.EqualFold(p, n) {
				return true
			}
		}
	}
	return false
}

// matchesAny reports whether a Host line's patterns match any of names, as
// ssh does: case-insensitively, with * and ? wildcards, and a matching
// negated pattern rules the line out.
func matchesAny(patterns, names []string) bool {
	for _, n := range names {
		matched := false
		for _, p := range patterns {
			if neg, ok := strings.CutPrefix(p, "!"); ok {
				if wildMatch(neg, n) {
					matched = false
					break
				}
				continue
			}
			if wildMatch(p, n) {
				matched = true
			}
		}
		if matched {
			return true
		}
	}
	return false
}

// wildMatch matches name against pattern, where * is any run of characters
// and ? any one, ignoring case.
func wildMatch(pattern, name string) bool {
	pattern, name = strings.ToLower(pattern), strings.ToLower(name)
	var rec func(p, n string) bool
	rec = func(p, n string) bool {
		for p != "" {
			switch p[0] {
			case '*':
				for len(p) > 0 && p[0] == '*' {
					p = p[1:]
				}
				if p == "" {
					return true
				}
				for i := 0; i <= len(n); i++ {
					if rec(p, n[i:]) {
						return true
					}
				}
				return false
			case '?':
				if n == "" {
					return false
				}
			default:
				if n == "" || n[0] != p[0] {
					return false
				}
			}
			p, n = p[1:], n[1:]
		}
		return n == ""
	}
	return rec(pattern, name)
}

func (p *sshConfigParser) include(pattern string, depth int) {
	if depth >= maxIncludeDepth {
		p.warnf("Include %q is nested too deeply and is skipped", pattern)
		return
	}
	pattern = p.expand(pattern)
	if strings.Contains(pattern, "%") {
		p.warnf("Include %q uses a %% token hop does not expand and is skipped", pattern)
		return
	}
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
