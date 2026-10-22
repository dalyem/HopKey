package cli

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
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

	// Traced says that ssh's debug output named the config it read, so that
	// Reached means something. Reached is true when a Host line that names
	// the alias literally applied to it. ssh -G itself prints the same
	// defaults for a name the config never mentions.
	Traced  bool
	Reached bool
}

// sshProbeTimeout bounds one ssh -G. ssh -G does no network I/O unless the
// config asks for CanonicalizeHostname, which does DNS.
const sshProbeTimeout = 15 * time.Second

// sshProbeEnviron is the whole environment ssh -G runs in: HOME and PATH,
// plus whatever the Env adds for itself (the tests' passwd shim). Nothing
// else from the caller's environment reaches ssh, so a variable cannot change
// what a Match line sees or what a command it runs inherits.
func (e *Env) sshProbeEnviron() []string {
	path := ""
	if e.Getenv != nil {
		path = e.Getenv("PATH")
	}
	if path == "" {
		path = "/usr/local/bin:/usr/bin:/bin"
	}
	return append([]string{"HOME=" + e.Home, "PATH=" + path}, e.SSHProbeEnv...)
}

// runSSHG runs `ssh -G -v -F config -- name` and parses its output. -v adds
// debug lines on stderr that say which Host lines applied.
func runSSHG(ctx context.Context, e *Env, sshBin, config, name string) (sshSettings, error) {
	ctx, cancel := context.WithTimeout(ctx, sshProbeTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, sshBin, "-G", "-v", "-F", config, "--", name)
	cmd.Env = e.sshProbeEnviron()
	cmd.Stdin = nil // /dev/null
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &limitedBuffer{buf: &stderr, max: 1 << 20}
	cmd.WaitDelay = time.Second
	if err := cmd.Run(); err != nil {
		if ctx.Err() != nil {
			return sshSettings{}, fmt.Errorf("ssh -G timed out after %v", sshProbeTimeout)
		}
		return sshSettings{}, fmt.Errorf("ssh -G failed: %s", sshError(stderr.String(), err))
	}
	return parseSSHG(stdout.String(), stderr.String(), name), nil
}

// limitedBuffer drops what exceeds max, so a noisy ssh cannot fill memory.
type limitedBuffer struct {
	buf *bytes.Buffer
	max int
}

func (l *limitedBuffer) Write(p []byte) (int, error) {
	if room := l.max - l.buf.Len(); room > 0 {
		l.buf.Write(p[:min(len(p), room)])
	}
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

// parseSSHG reads ssh -G's "key value" lines (lower-case keys) and the debug
// lines of -v.
func parseSSHG(stdout, stderr, name string) sshSettings {
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
		if _, pat, ok := strings.Cut(line, ": Applying options for "); ok && strings.EqualFold(strings.TrimSpace(pat), name) {
			s.Reached = true
		}
	}
	return s
}

// defaultSSHUser asks ssh which user it uses when no config says: the name
// ssh -G prints for a config with nothing in it.
func defaultSSHUser(ctx context.Context, e *Env, sshBin string) string {
	s, err := runSSHG(ctx, e, sshBin, os.DevNull, "hop-default-user-probe")
	if err != nil {
		return ""
	}
	return s.User
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
