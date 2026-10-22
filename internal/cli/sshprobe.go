package cli

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"
)

// sshSettings is what `ssh -G` reports for one name, for the settings hop
// imports.
type sshSettings struct {
	HostName      string
	User          string
	Port          string
	ProxyJump     string
	ProxyCommand  string
	HostKeyAlias  string
	IdentityFiles []string // as printed: defaults included, tokens unexpanded

	// Applied lists the Host declarations ssh's debug output says applied to
	// the name, by file and line. Traced says that the output named the config
	// ssh read, and Garbled that a line about an applied Host block was not in
	// the form hop knows. Without Traced and with Garbled, Applied cannot be
	// trusted (see traceProblem). ssh -G itself prints the same defaults for a
	// name the config never mentions.
	Applied []hostLoc
	Traced  bool
	Garbled bool
}

// traceProblem says why Applied cannot be trusted, or "".
func (s sshSettings) traceProblem() string {
	switch {
	case !s.Traced:
		return "ssh -v did not report which configuration files it read"
	case s.Garbled:
		return "ssh -v reported an applied Host block in a form hop cannot read"
	}
	return ""
}

// errTraceUnverified is the error of an ssh whose -v output hop cannot use to
// tell which Host blocks applied: missing, in a form hop does not know, or too
// long to keep. The import stops: guessing would import settings from blocks
// that ssh did not apply.
type errTraceUnverified struct{ why string }

func (e *errTraceUnverified) Error() string {
	return "can't verify which Host blocks applied with this OpenSSH version: " + e.why + "; nothing was imported"
}

func isTraceError(err error) bool {
	var te *errTraceUnverified
	return errors.As(err, &te)
}

// sshProbeTimeout bounds one ssh -G. ssh -G does no network I/O unless the
// config asks for CanonicalizeHostname, which does DNS.
const sshProbeTimeout = 15 * time.Second

// sshProber runs `ssh -G`. home is the passwd home: the HOME of the child, and
// what ssh expands ~ to whatever HOME says.
type sshProber struct {
	env  *Env
	bin  string
	home string
}

// environ is the whole environment ssh -G runs in: HOME and PATH, plus
// whatever the Env adds for itself (the tests' passwd shim). Nothing else from
// the caller's environment reaches ssh, so a variable cannot change what a
// Match line sees or what a command it runs inherits.
func (p *sshProber) environ() []string {
	path := ""
	if p.env.Getenv != nil {
		path = p.env.Getenv("PATH")
	}
	if path == "" {
		path = "/usr/local/bin:/usr/bin:/bin"
	}
	return append([]string{"HOME=" + p.home, "PATH=" + path}, p.env.SSHProbeEnv...)
}

// run runs `ssh -G -F config -- name` and parses its output. With trace it
// adds -v, whose debug lines on stderr say which Host lines applied.
func (p *sshProber) run(ctx context.Context, config, name string, trace bool) (sshSettings, error) {
	ctx, cancel := context.WithTimeout(ctx, sshProbeTimeout)
	defer cancel()
	args := []string{"-G"}
	if trace {
		args = append(args, "-v")
	}
	cmd := exec.CommandContext(ctx, p.bin, append(args, "-F", config, "--", name)...)
	cmd.Env = p.environ()
	cmd.Stdin = nil // /dev/null
	var stdout, stderr bytes.Buffer
	errBuf := &limitedBuffer{buf: &stderr, max: maxProbeStderr}
	cmd.Stdout, cmd.Stderr = &stdout, errBuf
	cmd.WaitDelay = time.Second
	err := cmd.Run()
	// Output that did not fit was dropped, and with it possibly the line that
	// says which Host blocks applied, so nothing read from this probe can be
	// trusted, whether or not ssh succeeded.
	if errBuf.overflow {
		return sshSettings{}, &errTraceUnverified{fmt.Sprintf("ssh wrote more than %d bytes to stderr, which hop does not keep", maxProbeStderr)}
	}
	if err != nil {
		if ctx.Err() != nil {
			return sshSettings{}, fmt.Errorf("ssh -G timed out after %v", sshProbeTimeout)
		}
		return sshSettings{}, fmt.Errorf("ssh -G failed: %s", sshError(stderr.String(), err))
	}
	return parseSSHG(stdout.String(), stderr.String()), nil
}

// defaults is what this ssh prints for name when no config says anything: the
// values hop must not mistake for the user's.
func (p *sshProber) defaults(ctx context.Context, name string) (sshSettings, error) {
	return p.run(ctx, os.DevNull, name, false)
}

// verifyTrace checks, once, that this ssh's -v output names the Host line that
// applied, on a config of hop's own.
func (p *sshProber) verifyTrace(ctx context.Context) error {
	dir, err := os.MkdirTemp("", "hop-trace")
	if err != nil {
		return err
	}
	defer os.RemoveAll(dir)
	config := filepath.Join(dir, "config")
	const name = "hop-trace-probe"
	if err := os.WriteFile(config, []byte("Host "+name+"\n  User hop\n"), 0o600); err != nil {
		return err
	}
	set, err := p.run(ctx, config, name, true)
	if err != nil {
		return err
	}
	if why := set.traceProblem(); why != "" {
		return &errTraceUnverified{why}
	}
	if !slices.Contains(set.Applied, hostLoc{filepath.Clean(config), 1}) {
		return &errTraceUnverified{"ssh -v did not report the Host line that applied to a test config"}
	}
	return nil
}

// maxProbeStderr is how much of one probe's stderr hop keeps.
const maxProbeStderr = 1 << 20

// limitedBuffer drops what exceeds max, so a noisy ssh cannot fill memory, and
// records that it did.
type limitedBuffer struct {
	buf      *bytes.Buffer
	max      int
	overflow bool
}

func (l *limitedBuffer) Write(p []byte) (int, error) {
	room := max(l.max-l.buf.Len(), 0)
	if len(p) > room {
		l.overflow = true
	}
	l.buf.Write(p[:min(len(p), room)])
	return len(p), nil
}

// sshError picks the explanation out of ssh's stderr: the last line that is
// not debug output.
func sshError(stderr string, err error) string {
	lines := strings.Split(strings.TrimSpace(stderr), "\n")
	for i := len(lines) - 1; i >= 0; i-- {
		if l := strings.TrimSpace(lines[i]); l != "" && !strings.HasPrefix(l, "debug") {
			return l
		}
	}
	return err.Error()
}

// appliedLine is ssh's debug line for a Host block that applies:
// "debug1: <file> line <n>: Applying options for <pattern>". The file is the
// text up to the last " line N: Applying options for ", whatever it holds.
var appliedLine = regexp.MustCompile(`^debug\d*: (.*) line ([0-9]+): Applying options for `)

// parseSSHG reads ssh -G's "key value" lines (lower-case keys) and the debug
// lines of -v.
func parseSSHG(stdout, stderr string) sshSettings {
	var s sshSettings
	for _, line := range strings.Split(stdout, "\n") {
		key, val, _ := strings.Cut(strings.TrimSpace(line), " ")
		val = strings.TrimSpace(val)
		switch key {
		case "hostname":
			s.HostName = val
		case "user":
			s.User = val
		case "port":
			s.Port = val
		case "proxyjump":
			s.ProxyJump = val
		case "proxycommand":
			s.ProxyCommand = val
		case "hostkeyalias":
			s.HostKeyAlias = val
		case "identityfile":
			s.IdentityFiles = append(s.IdentityFiles, val)
		}
	}
	for _, line := range strings.Split(stderr, "\n") {
		if strings.Contains(line, "Reading configuration data") {
			s.Traced = true
		}
		if !strings.Contains(line, "Applying options for") {
			continue
		}
		m := appliedLine.FindStringSubmatch(strings.TrimRight(line, "\r"))
		n, err := 0, error(nil)
		if m != nil {
			n, err = strconv.Atoi(m[2])
		}
		if m == nil || err != nil {
			s.Garbled = true
			continue
		}
		s.Applied = append(s.Applied, hostLoc{filepath.Clean(m[1]), n})
	}
	return s
}

// passwdHome is the home directory OpenSSH uses for ~.
func (e *Env) passwdHome() (string, error) {
	if e.PasswdHome != nil {
		return e.PasswdHome()
	}
	u, err := user.Current()
	if err != nil {
		return "", err
	}
	if u.HomeDir == "" {
		return "", errors.New("the passwd entry has no home directory")
	}
	return u.HomeDir, nil
}

// checkSSH finds the ssh client, or says why import cannot work without it.
func checkSSH(e *Env) (string, error) {
	p, err := exec.LookPath(e.sshBinary())
	if err != nil {
		if errors.Is(err, exec.ErrNotFound) || errors.Is(err, os.ErrNotExist) {
			return "", failf("import ssh-config needs the OpenSSH client to read your config (it runs `ssh -G`), and %q was not found; install OpenSSH and try again", e.sshBinary())
		}
		return "", failf("import ssh-config needs the OpenSSH client (ssh -G): %v", err)
	}
	return p, nil
}
