package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/dalyem/hopkey/internal/daemon"
	"github.com/dalyem/hopkey/internal/resolve"
	"github.com/dalyem/hopkey/internal/safepath"
	"github.com/dalyem/hopkey/internal/store"
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
		return nil, fmt.Errorf("cannot reach the hop daemon at %s: %w", oneLine(path), cleanErr(err))
	}
	// A hop auth command stopped the daemon to run its flow, and starts
	// it again when it ends; one started now would take the vault.
	if pid, ok := e.authHolder(); ok {
		return nil, errHeld(pid)
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
		return fmt.Errorf("starting the hop daemon: %w", cleanErr(err))
	}
	deadline := time.Now().Add(wait)
	for {
		c, err := daemon.Dial(ctx, e.Paths.ControlSocket())
		if err == nil {
			c.Close()
			return nil
		}
		if time.Now().After(deadline) || ctx.Err() != nil {
			// Composed: the log tail's line breaks are layout (logTail
			// sanitizes each line), so the report keeps them.
			return &exitError{code: ExitFailure, composed: true, msg: fmt.Sprintf("the hop daemon did not come up within %s; see %s%s", wait, oneLine(e.Paths.LogFile()), logTail(e.Paths.LogFile()))}
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
	// The lines are the log's; the line breaks between them are ours.
	return ":\n  " + joinOne(lines, "\n  ")
}

// authSecretEnv are the variables that answer hop auth's prompts
// (authui.go). They are this command's input, never a child's: a daemon
// that a hop auth command restarts would otherwise keep the master
// password in its environment for as long as it runs.
var authSecretEnv = []string{envPassword, envNewPassword, envSecretKey, envRecoveryKey, envKitConfirm}

// environ is the environment for every process hop starts: the caller's,
// minus the hop auth secrets. Every exec in this package takes its
// environment from here, or from sshEnviron, which builds on it.
func (e *Env) environ() []string {
	base := e.Environ
	if base == nil {
		base = os.Environ()
	}
	return withoutEnv(base, authSecretEnv...)
}

// withoutEnv returns environ without the named variables.
func withoutEnv(environ []string, names ...string) []string {
	out := make([]string, 0, len(environ))
	for _, kv := range environ {
		name, _, _ := strings.Cut(kv, "=")
		if !slices.Contains(names, name) {
			out = append(out, kv)
		}
	}
	return out
}

// sshEnviron is the environment for ssh: environ, minus any agent socket
// (the generated config names its own agent) and the device key file's
// passphrase, which only hop itself and its daemon read.
func (e *Env) sshEnviron() []string {
	return withoutEnv(e.environ(), "SSH_AUTH_SOCK", store.PassphraseEnv)
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
	// What the daemon says can quote vault values.
	return cleanErr(c.Call(ctx, op, params, result))
}

// configStale adds a hint to the daemon's config_stale refusal: the daemon
// will not resolve a target, so nothing connects, while the ssh config it
// writes is out of date. Other errors pass through.
func configStale(e *Env, err error) error {
	if !daemon.IsCode(err, daemon.CodeConfigStale) {
		return err
	}
	return failf("%v. Check that you own %s and can write to it and the files in it (ls -la %s)", err, e.Paths.ConfigDir, e.Paths.ConfigDir)
}

// callChange is call for an op that changes the vault (put_host, put_key,
// delete). When the change took effect but the ssh config could not be
// written, the daemon answers with a success that carries the result (the
// saved host or key) and a config_not_written warning; callChange prints
// the warning and returns nil, with result filled in.
func callChange(ctx context.Context, e *Env, asJSON bool, op string, params, result any) error {
	c, err := connect(ctx, e)
	if err != nil {
		return err
	}
	defer c.Close()
	w, err := c.CallWarn(ctx, op, params, result)
	return changeWarning(e, asJSON, w, err)
}

// changeWarning prints the warning on a change's answer and returns its
// error. A daemon from before warnings answered config_not_written as an
// error with no result; the change took effect all the same, so that is
// a warning too, and a caller that needs the result finds it empty.
func changeWarning(e *Env, asJSON bool, w *daemon.Error, err error) error {
	err = cleanErr(err)
	if daemon.IsCode(err, daemon.CodeConfigNotWritten) {
		warn(e, asJSON, err.Error())
		return nil
	}
	if err != nil {
		return err
	}
	if w != nil {
		warn(e, asJSON, w.Message)
	}
	return nil
}

// warn prints a warning to stderr once per run: "hop: warning: ..." on one
// line, or a {"warning": ...} line when the caller asked for JSON, so
// stdout keeps its shape.
func warn(e *Env, asJSON bool, msg string) {
	if e.warned[msg] {
		return
	}
	if e.warned == nil {
		e.warned = map[string]bool{}
	}
	e.warned[msg] = true
	printWarning(e, asJSON, msg)
}

// printWarning is warn without the once-per-run check.
func printWarning(e *Env, asJSON bool, msg string) {
	if asJSON {
		b, _ := json.Marshal(map[string]string{"warning": msg})
		fmt.Fprintln(e.Stderr, string(escapeJSONControls(b)))
		return
	}
	fmt.Fprintf(e.Stderr, "hop: warning: %s\n", oneLine(msg))
}

// resolveTarget asks the daemon to resolve target. With interactive, an
// ambiguous result goes to a picker when stdin is a terminal.
func resolveTarget(ctx context.Context, e *Env, target string, interactive bool) (*daemon.ResolveResult, error) {
	var rr daemon.ResolveResult
	params := daemon.ResolveParams{Target: target, Interactive: interactive}
	if err := call(ctx, e, daemon.OpResolve, params, &rr); err != nil {
		return nil, configStale(e, err)
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
			return nil, configStale(e, err)
		}
	}
	return &rr, nil
}

// pick shows the candidates and returns the name the user chose.
func pick(e *Env, res *resolve.Result) (string, error) {
	// %q escapes what is unsafe; the candidate fields come from the vault and
	// the tailnet, so they go through oneLine.
	fmt.Fprintf(e.Stderr, "%q matches more than one host:\n", res.Target)
	var named []resolve.Candidate
	for _, c := range res.Candidates {
		if c.HostID == "" {
			continue // a tailnet node with no vault host cannot be connected to by name
		}
		named = append(named, c)
		fmt.Fprintf(e.Stderr, "  %d) %s  %s  (%s)\n", len(named), oneLine(c.Name), joinOne(c.Addresses, ","), oneLine(c.Detail))
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
// the user sees, with candidates listed. The line breaks are its layout, so
// every value in it is made single-line safe here; callers pass the result to
// failMsg, not failf.
func describeUnresolved(res *resolve.Result) string {
	var sb strings.Builder
	switch res.Status {
	case resolve.StatusAmbiguous:
		fmt.Fprintf(&sb, "%q is ambiguous (%s)", res.Target, oneLine(res.Matched))
	case resolve.StatusPlainSSH:
		fmt.Fprintf(&sb, "%q is not in the vault", res.Target)
	default:
		fmt.Fprintf(&sb, "no host matches %q", res.Target)
	}
	for _, c := range res.Candidates {
		id := oneLine(c.Name)
		if len(c.Addresses) > 0 {
			id += " (" + joinOne(c.Addresses, ", ") + ")"
		}
		fmt.Fprintf(&sb, "\n  candidate: %s - %s", id, oneLine(c.Detail))
	}
	for _, n := range res.Notes {
		fmt.Fprintf(&sb, "\n  note: %s", oneLine(n))
	}
	return sb.String()
}
