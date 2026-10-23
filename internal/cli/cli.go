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
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"time"
	"unicode/utf16"

	"github.com/dalyem/hopkey/internal/daemon"
	"github.com/dalyem/hopkey/internal/model"
	"github.com/dalyem/hopkey/internal/store"
	"github.com/dalyem/hopkey/internal/syncclient"
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
	// DataDir is where hop init creates the vault and the device key file.
	// Empty means $XDG_DATA_HOME/hop, or ~/.local/share/hop.
	DataDir string
	// Keyring is the OS keychain hop init uses. Nil means the real one.
	Keyring store.Keyring
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
	// Environ is the environment hop's child processes (ssh, the daemon)
	// start from, before the hop auth secrets are removed. Nil means
	// os.Environ().
	Environ []string
	// SSHProbeEnv is added to the otherwise bare environment (HOME, PATH) of
	// the ssh -G runs of `hop import ssh-config`. Tests use it for the passwd
	// shim that ssh needs under a uid with no passwd entry.
	SSHProbeEnv []string
	// PasswdHome is the home directory in the passwd database, which OpenSSH
	// expands ~ from whatever $HOME says. Nil asks os/user. Tests replace it.
	PasswdHome func() (string, error)

	// DialTimeout bounds TCP and handshake probes. Zero means 5 seconds.
	DialTimeout time.Duration
	// DaemonWait is how long autostart waits for the control socket. Zero
	// means 10 seconds.
	DaemonWait time.Duration

	// Now is the clock for "how long ago". Nil means time.Now.
	Now func() time.Time
	// GOOS picks the service manager hop setup --service writes for. Empty
	// means runtime.GOOS.
	GOOS string
	// RunCommand runs systemctl or launchctl for hop setup --service and
	// returns its combined output. Nil means os/exec. Tests replace it.
	RunCommand func(ctx context.Context, name string, args ...string) ([]byte, error)
	// SyncClient configures hop auth's connections to the server: a
	// private CA, say. Zero means the system's trusted roots.
	// HOP_DEV_INSECURE=1 also sets DevInsecure, as it does for the daemon.
	SyncClient syncclient.Options

	// Exit ends the process when Run's context is cancelled by a signal
	// and the command does not return on its own (see watchInterrupt). Nil
	// means a cancelled context is all that happens, as in tests.
	Exit func(code int)
	// InterruptGrace is how long a command that holds the vault gets to
	// return after its context is cancelled. Zero means 3 seconds.
	InterruptGrace time.Duration

	// warned holds the warnings already printed in this run, so a command
	// that makes many changes says each one once.
	warned map[string]bool

	// hold is the hop auth command's hold of the vault while it lasts.
	holdMu sync.Mutex
	hold   *vaultHold
}

// ExitInterrupted is the exit status after SIGINT or SIGTERM, as a shell
// reports a command killed by SIGINT.
const ExitInterrupted = 130

// watchInterrupt runs while a command does. cmd/hop cancels Run's context
// with ErrInterrupted on SIGINT and SIGTERM. A command that holds the vault for a hop auth
// flow gets InterruptGrace to return, and its deferred release starts the
// daemon again; one stuck where the context does not reach (a prompt
// reading the terminal) is abandoned: the daemon is launched to take the
// vault once this process is gone, and the process exits. A command that
// holds nothing exits at once, as it did when the signal killed it,
// unless it handles the context itself (ctxAware, decided before the
// command starts: see handlesInterrupt).
func (e *Env) watchInterrupt(ctx context.Context, done <-chan struct{}, ctxAware bool) {
	if e.Exit == nil {
		return
	}
	select {
	case <-done:
		return
	case <-ctx.Done():
	}
	if !errors.Is(context.Cause(ctx), ErrInterrupted) {
		return // a deadline, not a signal
	}
	if ctxAware {
		return
	}
	if h := e.currentHold(); h != nil {
		grace := e.InterruptGrace
		if grace <= 0 {
			grace = 3 * time.Second
		}
		select {
		case <-done:
			return
		case <-time.After(grace):
		}
		if h := e.currentHold(); h != nil {
			h.abandon()
		}
	}
	select {
	case <-done:
		return
	default:
	}
	e.Exit(ExitInterrupted)
}

// handlesInterrupt reports whether the command args runs returns on its
// own once a signal cancels the context, and so is never cut short:
// hop daemon, which closes cleanly. It is decided from the arguments
// alone, before the command and Run's signal watcher start.
func handlesInterrupt(args []string) bool {
	return len(args) == 1 && args[0] == "daemon"
}

// ErrInterrupted is the cause cmd/hop gives the context it cancels on
// SIGINT or SIGTERM (context.WithCancelCause).
var ErrInterrupted = errors.New("interrupted")

func (e *Env) now() time.Time {
	if e.Now != nil {
		return e.Now()
	}
	return time.Now()
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
	// composed marks a message whose own line breaks and tabs are deliberate
	// layout and whose parts were each made display-safe where they were
	// inserted. Only failMsg and composedErr set it. reportError checks it on
	// the top-level error only (never through a wrapper), so the text of a
	// wrapper around a composed error is not covered by it.
	composed bool
}

func (e *exitError) Error() string { return e.msg }

// failf fails with a message built by safef: untrusted string and error
// arguments are made single-line safe where they are inserted.
func failf(format string, args ...any) error {
	return &exitError{code: ExitFailure, msg: safef(format, args...)}
}

// failMsg fails with a message that was composed from constant text and
// display-safe parts and whose own line breaks are layout, such as
// describeUnresolved's. Every other error is flattened to one line by
// reportError, so use failMsg only where the layout is deliberate and each
// inserted value has already gone through oneLine.
func failMsg(msg string) error {
	return &exitError{code: ExitFailure, msg: msg, composed: true}
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
		"import":  {runImport, "hop import ssh-config [path] [--with-keys] [--dry-run] [--yes] [--json]"},
		"ts":      {runTS, "hop ts import [name...] [--user U] [--key K] [--tag T] [--no-pin] [--dry-run] | hop ts link <host> <node-id-or-dns-name>"},
		"setup":   {runSetup, "hop setup [--yes] | hop setup --service [--uninstall] [--yes] [--json]"},
		"daemon":  {runDaemon, "hop daemon [stop]"},
		"status":  {runStatus, "hop status [--json]"},
		"init":    {runInit, "hop init [--device-key-store keychain|file] [--kit-file PATH]"},
		"lock":    {runLock, "hop lock"},
		"unlock":  {runUnlock, "hop unlock [--password]"},
		"passwd":  {runPasswd, "hop passwd [--kit-file PATH] (on a server: the flags of hop auth passwd)"},
		"sync":    {runSync, "hop sync [--json] | hop sync resolve [N] [--keep-mine [--confirm TOKEN] | --edit --set FIELD=VALUE... [--confirm TOKEN] | --take-theirs [--yes] | --retry] [--json]"},
		"auth":    {runAuth, "hop auth <signup|login|approve|status|devices|logout|rotate|passwd|merge|resume> [--json]"},
		"login":   {runLogin, "hop login [flags of hop auth login]"},
		"logout":  {runLogout, "hop logout [flags of hop auth logout]"},
	}
}

const usageText = `usage: hop <target>           open a shell on a vault host (alias, hostname, IP, Tailscale name or IP)
       hop exec <target> -- <cmd>   run one command; exits with the remote status
       hop check|which|trust <target>
       hop ls [tag] | info <target> | add | edit | rm
       hop key add|ls|rm | import ssh-config | ts import|link
       hop setup [--service] | status | daemon
       hop init | lock | unlock [--password] | passwd
       hop sync [resolve]
       hop auth signup|login|approve|status|devices|logout|rotate|passwd|merge|resume
       hop login | logout       aliases of hop auth login and hop auth logout

Every command takes --json. Run "hop <command> -h" for its flags.
`

// Run executes hop with args (without the program name) and returns the exit
// status.
func Run(ctx context.Context, args []string, e *Env) int {
	if e.Getenv == nil {
		e.Getenv = os.Getenv
	}
	ctxAware := handlesInterrupt(args)
	done := make(chan struct{})
	go e.watchInterrupt(ctx, done, ctxAware)
	err := dispatch(ctx, e, args)
	close(done)
	// After a signal hop exits 130, however the command ended: with the
	// failure its cancelled context caused, or with success when it
	// finished as the signal came. hop daemon keeps its own status: it
	// stops on a signal by design, and a service manager reads 0 as a
	// clean stop.
	if !ctxAware && errors.Is(context.Cause(ctx), ErrInterrupted) {
		if err != nil && !errors.Is(err, context.Canceled) && !errors.Is(err, flag.ErrHelp) {
			report(e, err, args)
		}
		return ExitInterrupted
	}
	if err == nil {
		return 0
	}
	if errors.Is(err, flag.ErrHelp) {
		return 0
	}
	return report(e, err, args)
}

// report prints err (see reportError) and returns its exit status.
func report(e *Env, err error, args []string) int {
	// Only an exitError that is itself the error returned may keep its layout.
	// One found inside a wrapper supplies the exit status, but the wrapper's
	// text is not covered by its mark.
	if top, ok := err.(*exitError); ok {
		if top.msg != "" {
			reportError(e, top, args)
		}
		return top.code
	}
	var ee *exitError
	if errors.As(err, &ee) {
		if ee.msg != "" {
			reportError(e, err, args)
		}
		return ee.code
	}
	reportError(e, err, args)
	return ExitFailure
}

// reportError prints a failure to stderr, as JSON when the caller asked for it.
// Errors often quote paths and config text, so the human-readable message is
// flattened to one line (oneLine) and a quoted value cannot forge a "hop:"
// line. The exception is an error that is itself a composed exitError (see
// failMsg): its line breaks and tabs are kept, with the rest of displaySafe
// applied. JSON carries the full text either way, encoded by encoding/json and
// escapeJSONControls, for machines.
func reportError(e *Env, err error, args []string) {
	msg := err.Error()
	if wantsJSON(args) {
		b, _ := json.Marshal(map[string]string{"error": msg})
		fmt.Fprintln(e.Stderr, string(escapeJSONControls(b)))
		return
	}
	if top, ok := err.(*exitError); ok && top.composed {
		fmt.Fprintf(e.Stderr, "hop: %s\n", displaySafe(msg))
		return
	}
	fmt.Fprintf(e.Stderr, "hop: %s\n", oneLine(msg))
}

// displaySafe neutralizes what could redraw or reorder the terminal: C0
// controls other than newline and tab, DEL, C1 (which covers the CSI
// introducer) and Unicode format characters such as bidi overrides. It keeps
// layout, so reportError uses it only for composed messages. Callers that
// quote a single untrusted value use oneLine, which also maps newlines; see
// display.go.
func displaySafe(s string) string {
	return strings.Map(func(c rune) rune {
		if c == '\n' || c == '\t' {
			return c
		}
		if unsafeRune(c) {
			return '?'
		}
		return c
	}, s)
}

// escapeJSONControls rewrites Unicode format characters in encoded JSON as
// \uXXXX escapes, and so are DEL and C1 (U+0080 to U+009F). encoding/json
// already escapes C0 controls; this keeps values intact for machines while
// bidi overrides and the CSI introducer stay inert on a terminal. None of
// these is JSON syntax, so they only occur inside strings.
func escapeJSONControls(b []byte) []byte {
	if !bytes.ContainsFunc(b, jsonUnsafeRune) {
		return b
	}
	var out bytes.Buffer
	for _, c := range string(b) {
		if jsonUnsafeRune(c) {
			if c > 0xffff {
				hi, lo := utf16.EncodeRune(c)
				fmt.Fprintf(&out, "\\u%04x\\u%04x", hi, lo)
			} else {
				fmt.Fprintf(&out, "\\u%04x", c)
			}
			continue
		}
		out.WriteRune(c)
	}
	return out.Bytes()
}

// jsonUnsafeRune is unsafeRune without the C0 range, which encoding/json
// escapes itself.
func jsonUnsafeRune(c rune) bool { return c >= ' ' && unsafeRune(c) }

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

// flagOut collects what the flag package writes while parsing: for a bad
// flag, a message that quotes the offending text. It is never shown raw;
// parseFlags reports it through reportError, sanitized.
type flagOut struct {
	bytes.Buffer
	usage string
}

// newFlags makes a flag set that does not exit and does not write parse
// diagnostics to stderr itself. -h prints the usage (constant text) and the
// flag defaults to stderr; a parse error is returned by parseFlags.
func newFlags(e *Env, name, usage string) *flag.FlagSet {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	out := &flagOut{usage: usage}
	fs.SetOutput(out)
	fs.Usage = func() {
		// The flag package calls Usage after a parse error too, having
		// written the error to out first. That case is reported by
		// parseFlags; only -h prints the usage here.
		if out.Len() > 0 {
			return
		}
		fmt.Fprintf(e.Stderr, "usage: %s\n", usage)
		fs.SetOutput(e.Stderr)
		fs.PrintDefaults()
		fs.SetOutput(out)
	}
	return fs
}

// helpNote adds text after the flags that -h prints, and not after a
// parse error.
func helpNote(e *Env, fs *flag.FlagSet, note string) {
	base := fs.Usage
	fs.Usage = func() {
		base()
		if out, ok := fs.Output().(*flagOut); ok && out.Len() > 0 {
			return
		}
		fmt.Fprint(e.Stderr, note)
	}
}

// parseFlags parses args allowing flags and positional arguments in any
// order, which the standard library does not. Arguments after a bare "--" are
// returned separately and untouched. A parse error quotes the user's own
// text, so it is made single-line safe; the usage line after it is constant.
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
			msg := err.Error()
			usage := ""
			if out, ok := fs.Output().(*flagOut); ok {
				if t := strings.TrimSpace(out.String()); t != "" {
					msg = t
				}
				usage = out.usage
			}
			if usage == "" {
				return nil, nil, failf("%s", msg)
			}
			return nil, nil, failMsg(oneLine(msg) + "\nusage: " + usage)
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
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return err
	}
	_, err := e.Stdout.Write(escapeJSONControls(buf.Bytes()))
	return err
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
