package cli

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/dalyem/hopkey/internal/daemon"
	"github.com/dalyem/hopkey/internal/resolve"
	"github.com/dalyem/hopkey/internal/safepath"
)

// connect returns a client for the daemon, starting the daemon if its control
// socket is absent.
func connect(ctx context.Context, e *Env) (*daemon.Client, error) {
	path := e.Paths.ControlSocket()
	c, err := daemon.Dial(ctx, path)
	if err == nil {
		return c, nil
	}
	// Only a missing or dead socket means "start it". Anything else (a
	// permission error, say) is reported as it is.
	if !socketAbsent(err) {
		return nil, fmt.Errorf("cannot reach the hop daemon at %s: %w", path, err)
	}
	if err := startDaemon(ctx, e); err != nil {
		return nil, err
	}
	return daemon.Dial(ctx, path)
}

func socketAbsent(err error) bool {
	return errors.Is(err, os.ErrNotExist) || errors.Is(err, syscallECONNREFUSED)
}

// startDaemon launches the daemon and waits for its control socket.
func startDaemon(ctx context.Context, e *Env) error {
	wait := e.DaemonWait
	if wait == 0 {
		wait = 10 * time.Second
	}
	launch := e.StartDaemon
	if launch == nil {
		launch = func() error { return launchDaemon(e) }
	}
	if err := launch(); err != nil {
		return fmt.Errorf("starting the hop daemon: %w", err)
	}
	deadline := time.Now().Add(wait)
	for {
		c, err := daemon.Dial(ctx, e.Paths.ControlSocket())
		if err == nil {
			c.Close()
			return nil
		}
		if time.Now().After(deadline) || ctx.Err() != nil {
			return fmt.Errorf("the hop daemon did not come up within %s; see %s%s", wait, e.Paths.LogFile(), logTail(e.Paths.LogFile()))
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// maxLogSize is how big the daemon log may get before the next start moves it
// aside, keeping one previous generation.
const maxLogSize = 1 << 20

// launchDaemon runs `hop daemon` detached, with its output going to the log.
func launchDaemon(e *Env) error {
	if e.Executable == "" {
		return errors.New("do not know where the hop binary is")
	}
	if _, err := safepath.EnsurePrivateDir(e.Paths.StateDir); err != nil {
		return err
	}
	logf, err := openLog(e.Paths.LogFile(), os.Getuid())
	if err != nil {
		return err
	}
	defer logf.Close()
	devnull, err := os.Open(os.DevNull)
	if err != nil {
		return err
	}
	defer devnull.Close()

	cmd := exec.Command(e.Executable, "daemon")
	cmd.Stdin, cmd.Stdout, cmd.Stderr = devnull, logf, logf
	cmd.Env = e.environ()
	detach(cmd)
	if err := cmd.Start(); err != nil {
		return err
	}
	return cmd.Process.Release()
}

// logTail returns the last few lines of the daemon log for an error message.
func logTail(path string) string {
	b, err := os.ReadFile(path)
	if err != nil || len(b) == 0 {
		return ""
	}
	lines := strings.Split(strings.TrimSpace(string(b)), "\n")
	if len(lines) > 5 {
		lines = lines[len(lines)-5:]
	}
	return ":\n  " + strings.Join(lines, "\n  ")
}

func (e *Env) environ() []string {
	if e.Environ != nil {
		return e.Environ
	}
	return os.Environ()
}

// sshEnviron is the environment for ssh: the caller's, minus any agent
// socket. The generated config names its own agent.
func (e *Env) sshEnviron() []string {
	var out []string
	for _, kv := range e.environ() {
		if !strings.HasPrefix(kv, "SSH_AUTH_SOCK=") {
			out = append(out, kv)
		}
	}
	return out
}

func (e *Env) sshBinary() string {
	if e.SSHBinary != "" {
		return e.SSHBinary
	}
	return "ssh"
}

func (e *Env) sshConfigFile() string { return filepath.Join(e.Paths.ConfigDir, "config") }

// call connects to the daemon and makes one call. It is the shape most
// commands need.
func call(ctx context.Context, e *Env, op string, params, result any) error {
	c, err := connect(ctx, e)
	if err != nil {
		return err
	}
	defer c.Close()
	return c.Call(ctx, op, params, result)
}

// resolveTarget asks the daemon to resolve target. With interactive, an
// ambiguous result goes to a picker when stdin is a terminal.
func resolveTarget(ctx context.Context, e *Env, target string, interactive bool) (*daemon.ResolveResult, error) {
	var rr daemon.ResolveResult
	params := daemon.ResolveParams{Target: target, Interactive: interactive}
	if err := call(ctx, e, daemon.OpResolve, params, &rr); err != nil {
		return nil, err
	}
	if interactive && e.StdinTTY && rr.Result.Status == resolve.StatusAmbiguous {
		picked, err := pick(e, rr.Result)
		if err != nil {
			return nil, err
		}
		// Pick by the chosen host's name, and keep the user typed in user@target.
		params.Target = picked
		if u := rr.Result.User; u != "" {
			params.Target = u + "@" + picked
		}
		rr = daemon.ResolveResult{}
		if err := call(ctx, e, daemon.OpResolve, params, &rr); err != nil {
			return nil, err
		}
	}
	return &rr, nil
}

// pick shows the candidates and returns the name the user chose.
func pick(e *Env, res *resolve.Result) (string, error) {
	fmt.Fprintf(e.Stderr, "%q matches more than one host:\n", res.Target)
	var named []resolve.Candidate
	for _, c := range res.Candidates {
		if c.HostID == "" {
			continue // a tailnet node with no vault host cannot be connected to by name
		}
		named = append(named, c)
		fmt.Fprintf(e.Stderr, "  %d) %s  %s  (%s)\n", len(named), c.Name, strings.Join(c.Addresses, ","), c.Detail)
	}
	if len(named) == 0 {
		return "", failf("no vault host to pick; link the tailnet node with hop ts link <host> <node-id>")
	}
	fmt.Fprintf(e.Stderr, "pick 1-%d: ", len(named))
	line, err := readLine(e.Stdin)
	if err != nil && line == "" {
		return "", failf("no choice made")
	}
	var n int
	if _, err := fmt.Sscanf(strings.TrimSpace(line), "%d", &n); err != nil || n < 1 || n > len(named) {
		return "", failf("not a valid choice: %q", strings.TrimSpace(line))
	}
	return named[n-1].Name, nil
}

// describeUnresolved turns a Result that did not match into the error text
// the user sees, with candidates listed.
func describeUnresolved(res *resolve.Result) string {
	var sb strings.Builder
	switch res.Status {
	case resolve.StatusAmbiguous:
		fmt.Fprintf(&sb, "%q is ambiguous (%s)", res.Target, res.Matched)
	case resolve.StatusPlainSSH:
		fmt.Fprintf(&sb, "%q is not in the vault", res.Target)
	default:
		fmt.Fprintf(&sb, "no host matches %q", res.Target)
	}
	for _, c := range res.Candidates {
		id := c.Name
		if len(c.Addresses) > 0 {
			id += " (" + strings.Join(c.Addresses, ", ") + ")"
		}
		fmt.Fprintf(&sb, "\n  candidate: %s - %s", id, c.Detail)
	}
	for _, n := range res.Notes {
		fmt.Fprintf(&sb, "\n  note: %s", n)
	}
	return sb.String()
}
