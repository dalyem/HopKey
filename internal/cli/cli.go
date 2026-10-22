// Package cli implements the hop command line. cmd/hop is a thin main around
// Run; keeping the commands here lets tests drive the real code path with a
// fake store and a daemon running in the same process.
//
// Conventions for every command: --json prints one stable JSON shape on
// stdout; human text goes to stdout and errors to stderr; hop's own failures
// exit 255, as ssh does, so a remote command's exit code passes through
// unchanged.
package cli

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/dalyem/hopkey/internal/daemon"
	"github.com/dalyem/hopkey/internal/model"
	"github.com/dalyem/hopkey/internal/version"
)

// ExitFailure is the exit status of hop's own failures.
const ExitFailure = 255

// Env is everything the commands touch outside their arguments, so tests can
// replace it.
type Env struct {
	Stdin  io.Reader
	Stdout io.Writer
	Stderr io.Writer
	Getenv func(string) string
	Home   string
	Paths  daemon.Paths

	// StdoutTTY and StdinTTY say whether the streams are terminals. Only a
	// terminal on stdout makes resolution interactive.
	StdoutTTY bool
	StdinTTY  bool

	// OpenStore opens the vault for `hop daemon`.
	OpenStore func() (model.Store, error)
	// ReadPassword prompts for a secret without echo. Nil disables prompts.
	ReadPassword func(prompt string) ([]byte, error)

	// Executable is this binary, for starting the daemon.
	Executable string
	// StartDaemon launches the daemon in the background. Nil means the
	// default: run Executable with the argument "daemon", detached, logging to
	// Paths.LogFile().
	StartDaemon func() error
	// SSHBinary is the system ssh. Empty means "ssh".
	SSHBinary string
	// ExecSSH replaces the process with ssh (hop <target>). Tests replace it.
	ExecSSH func(path string, argv, environ []string) error
	// Environ is the environment given to ssh. Nil means os.Environ().
	Environ []string
	// SSHProbeEnv is added to the otherwise bare environment (HOME, PATH) of
	// the ssh -G runs of `hop import ssh-config`. Tests use it for the passwd
	// shim that ssh needs under a uid with no passwd entry.
	SSHProbeEnv []string

	// DialTimeout bounds TCP and handshake probes. Zero means 5 seconds.
	DialTimeout time.Duration
	// DaemonWait is how long autostart waits for the control socket. Zero
	// means 10 seconds.
	DaemonWait time.Duration
}

func (e *Env) dialTimeout() time.Duration {
	if e.DialTimeout > 0 {
		return e.DialTimeout
	}
	return 5 * time.Second
}

func (e *Env) printf(format string, args ...any) { fmt.Fprintf(e.Stdout, format, args...) }

// exitError carries a specific exit status.
type exitError struct {
	code int
	msg  string
}

func (e *exitError) Error() string { return e.msg }

func failf(format string, args ...any) error {
	return &exitError{code: ExitFailure, msg: fmt.Sprintf(format, args...)}
}

// silent is a failure whose explanation was already printed.
func silent(code int) error { return &exitError{code: code} }

type command struct {
	run   func(ctx context.Context, e *Env, args []string) error
	usage string
}

var commands map[string]command

func init() {
	commands = map[string]command{
		"connect": {runConnect, "hop connect <target>"},
		"exec":    {runExec, "hop exec <target> [--timeout D] [--sudo] [--json] -- <command...>"},
		"check":   {runCheck, "hop check <target> [--json]"},
		"which":   {runWhich, "hop which <target> [--json]"},
		"trust":   {runTrust, "hop trust <target> [--yes] [--fingerprint SHA256:...] [--replace]"},
		"ls":      {runLs, "hop ls [tag] [--json]"},
		"info":    {runInfo, "hop info <target> [--json]"},
		"add":     {runAdd, "hop add <name> [--address A]... [--user U] [--port N] [--key NAME] [--jump HOST] [--tag T]... [--alias A]... [--host-key LINE]..."},
		"edit":    {runEdit, "hop edit <target> [--name N] [--address A]... [other flags as hop add]"},
		"rm":      {runRm, "hop rm <target> [--yes]"},
		"key":     {runKey, "hop key add <path> [--name N] | hop key ls | hop key rm <name> [--yes]"},
		"import":  {runImport, "hop import ssh-config [path] [--with-keys] [--dry-run] [--allow-match-exec] [--json]"},
		"ts":      {runTS, "hop ts import [name...] [--user U] [--key K] [--tag T] [--no-pin] [--dry-run] | hop ts link <host> <node-id-or-dns-name>"},
		"setup":   {runSetup, "hop setup [--yes]"},
		"daemon":  {runDaemon, "hop daemon [stop]"},
		"status":  {runStatus, "hop status [--json]"},
	}
}

const usageText = `usage: hop <target>           open a shell on a vault host (alias, hostname, IP, Tailscale name or IP)
       hop exec <target> -- <cmd>   run one command; exits with the remote status
       hop check|which|trust <target>
       hop ls [tag] | info <target> | add | edit | rm
       hop key add|ls|rm | import ssh-config | ts import|link
       hop setup | status | daemon

Every command takes --json. Run "hop <command> -h" for its flags.
`

// Run executes hop with args (without the program name) and returns the exit
// status.
func Run(ctx context.Context, args []string, e *Env) int {
	if e.Getenv == nil {
		e.Getenv = os.Getenv
	}
	err := dispatch(ctx, e, args)
	if err == nil {
		return 0
	}
	if errors.Is(err, flag.ErrHelp) {
		return 0
	}
	var ee *exitError
	if errors.As(err, &ee) {
		if ee.msg != "" {
			reportError(e, ee.msg, args)
		}
		return ee.code
	}
	reportError(e, err.Error(), args)
	return ExitFailure
}

// reportError prints a failure to stderr, as JSON when the caller asked for it.
func reportError(e *Env, msg string, args []string) {
	if wantsJSON(args) {
		b, _ := json.Marshal(map[string]string{"error": msg})
		fmt.Fprintln(e.Stderr, string(b))
		return
	}
	fmt.Fprintf(e.Stderr, "hop: %s\n", msg)
}

func wantsJSON(args []string) bool {
	for _, a := range args {
		if a == "--" {
			return false
		}
		if a == "--json" || a == "-json" || a == "--json=true" {
			return true
		}
	}
	return false
}

func dispatch(ctx context.Context, e *Env, args []string) error {
	if len(args) == 0 {
		fmt.Fprint(e.Stderr, usageText)
		return silent(ExitFailure)
	}
	switch args[0] {
	case "-h", "--help", "help":
		fmt.Fprint(e.Stdout, usageText)
		return nil
	case "-v", "--version", "version":
		fmt.Fprintln(e.Stdout, "hop", version.Version)
		return nil
	}
	if cmd, ok := commands[args[0]]; ok {
		return cmd.run(ctx, e, args[1:])
	}
	if strings.HasPrefix(args[0], "-") {
		fmt.Fprint(e.Stderr, usageText)
		return failf("unknown flag %s", args[0])
	}
	// Anything else is a target: hop <target>.
	return runConnect(ctx, e, args)
}

// newFlags makes a flag set that reports problems on stderr and does not exit.
func newFlags(e *Env, name, usage string) *flag.FlagSet {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(e.Stderr)
	fs.Usage = func() {
		fmt.Fprintf(e.Stderr, "usage: %s\n", usage)
		fs.PrintDefaults()
	}
	return fs
}

// parseFlags parses args allowing flags and positional arguments in any
// order, which the standard library does not. Arguments after a bare "--" are
// returned separately and untouched.
func parseFlags(fs *flag.FlagSet, args []string) (pos, rest []string, err error) {
	for i, a := range args {
		if a == "--" {
			args, rest = args[:i], args[i+1:]
			break
		}
	}
	for {
		if err := fs.Parse(args); err != nil {
			if errors.Is(err, flag.ErrHelp) {
				return nil, nil, err
			}
			return nil, nil, &exitError{code: ExitFailure} // flag already printed it
		}
		left := fs.Args()
		if len(left) == 0 {
			return pos, rest, nil
		}
		pos, args = append(pos, left[0]), left[1:]
	}
}

// stringList is a repeatable string flag.
type stringList struct {
	vals []string
	set  bool
}

func (s *stringList) String() string { return strings.Join(s.vals, ",") }
func (s *stringList) Set(v string) error {
	s.vals = append(s.vals, v)
	s.set = true
	return nil
}

// wasSet reports whether the named flag appeared on the command line.
func wasSet(fs *flag.FlagSet, name string) bool {
	found := false
	fs.Visit(func(f *flag.Flag) {
		if f.Name == name {
			found = true
		}
	})
	return found
}

func printJSON(e *Env, v any) error {
	enc := json.NewEncoder(e.Stdout)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	return enc.Encode(v)
}

// confirm asks a yes/no question on stderr. yes short-circuits it. Without a
// terminal on stdin the answer cannot be given, so it is an error.
func confirm(e *Env, yes bool, question string) (bool, error) {
	if yes {
		return true, nil
	}
	if !e.StdinTTY {
		return false, failf("%s: confirmation needed but stdin is not a terminal; pass --yes", question)
	}
	fmt.Fprintf(e.Stderr, "%s [y/N] ", question)
	line, err := readLine(e.Stdin)
	if err != nil && line == "" {
		return false, nil
	}
	switch strings.ToLower(strings.TrimSpace(line)) {
	case "y", "yes":
		return true, nil
	}
	return false, nil
}

// readLine reads up to a newline one byte at a time, so it never consumes
// input meant for a later reader.
func readLine(r io.Reader) (string, error) {
	var sb strings.Builder
	buf := make([]byte, 1)
	for {
		n, err := r.Read(buf)
		if n > 0 {
			if buf[0] == '\n' {
				return sb.String(), nil
			}
			sb.WriteByte(buf[0])
		}
		if err != nil {
			return sb.String(), err
		}
	}
}
