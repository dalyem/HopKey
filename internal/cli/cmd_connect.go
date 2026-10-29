package cli

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"strconv"
	"strings"
	"time"
	"unicode"

	"golang.org/x/crypto/ssh"

	"github.com/dalyem/hopkey/internal/daemon"
	"github.com/dalyem/hopkey/internal/resolve"
	"github.com/dalyem/hopkey/internal/shellcmd"
	"github.com/dalyem/hopkey/internal/sshconfig"
	"github.com/dalyem/hopkey/internal/sshkeys"
	"github.com/dalyem/hopkey/internal/store"
	"github.com/dalyem/hopkey/internal/tailscale"
)

// interactiveResolution is true when resolution may use DNS, fuzzy matching
// and the picker: stdout is a terminal and the caller did not ask for JSON.
func interactiveResolution(e *Env, json bool) bool { return e.StdoutTTY && !json }

// connectable checks that rr names a host ssh can reach and returns what
// building the ssh command line needs.
type target struct {
	rr    *daemon.ResolveResult
	alias string // Host block in the generated config
	user  string // explicit user@, or ""
}

func connectable(rr *daemon.ResolveResult) (*target, error) { return connectableAs(rr, strconv.Quote) }

// connectableAs is connectable with what the user typed (the target, the
// user) quoted by quote, as describeUnresolvedAs.
func connectableAs(rr *daemon.ResolveResult, quote func(string) string) (*target, error) {
	res := rr.Result
	if res.Status != resolve.StatusMatched || rr.Host == nil {
		return nil, failMsg(describeUnresolvedAs(res, quote))
	}
	if rr.SSHAlias == "" {
		return nil, failf("%s cannot be used with ssh: %s", res.HostName, orUnknown(rr.SSHProblem))
	}
	if rr.Route == nil {
		return nil, failf("%s has no usable route: %s", res.HostName, orUnknown(rr.RouteError))
	}
	if rr.Route.Blocked != "" {
		return nil, failf("%s", rr.Route.Blocked)
	}
	if res.User != "" && !sshconfig.ValidUser(res.User) {
		return nil, failf("user %s is not usable in an ssh config", quote(res.User))
	}
	return &target{rr: rr, alias: rr.SSHAlias, user: res.User}, nil
}

// unpinnedNote is what hop says before it runs ssh for a host that has no
// pinned host key: the generated config makes ssh refuse such a host (it
// never trusts a key on first use), and ssh's own "Host key verification
// failed" does not say what to do. It is "" for a host with a pin.
func unpinnedNote(rr *daemon.ResolveResult) string {
	if rr.Host == nil {
		return ""
	}
	if pins, _ := parsePins(rr.Host.HostKeys); len(pins) > 0 {
		return ""
	}
	return safef("no host key is pinned for %s, so ssh will refuse it; pin the server's key with: %s", rr.Result.HostName, pinCommand(rr.Result.HostName, !rr.Host.JumpHostID.IsZero()))
}

// pinCommand is the command that pins a host key. hop trust reads the key
// from the server, which it cannot do for a host reached through a jump host,
// so that host's key is pinned by hand with hop edit.
func pinCommand(name string, viaJump bool) string {
	if viaJump {
		return safef("hop edit %s --host-key '<ssh-ed25519 AAAA...>'", name)
	}
	return safef("hop trust %s", name)
}

func orUnknown(s string) string {
	if s == "" {
		return "unknown reason"
	}
	return s
}

// chooseAddress returns the address to connect to. When the route is the
// tailnet only because "auto" chose it, and nothing answers there, it uses the
// direct fallback: "online" does not promise that ssh will answer.
func chooseAddress(ctx context.Context, e *Env, t *target) (addr, note string) {
	r := t.rr.Route
	if t.rr.Host != nil && !t.rr.Host.JumpHostID.IsZero() {
		return r.Address, "" // not reachable directly, so a direct probe says nothing
	}
	if r.Setting == resolve.RouteAuto && r.Chosen == resolve.RouteTailnet && r.Fallback != "" {
		if err := tcpReachable(ctx, r.Address, r.Port, e.dialTimeout()/2); err != nil {
			return r.Fallback, safef("%s:%d (tailnet) did not answer, using %s (direct)", r.Address, r.Port, r.Fallback)
		}
	}
	return r.Address, ""
}

// sshArgs builds the arguments up to and including the alias: options, then
// "--" so nothing after it can be read as an option.
func (e *Env) sshArgs(t *target, addr string, opts ...string) []string {
	args := []string{"-F", e.sshConfigFile()}
	args = append(args, opts...)
	args = append(args, "-o", "HostName="+addr)
	if t.user != "" {
		args = append(args, "-o", "User="+t.user)
	}
	return append(args, "--", t.alias)
}

// runConnect is hop <target>: an interactive shell.
func runConnect(ctx context.Context, e *Env, args []string) error {
	fs := newFlags(e, "connect", commands["connect"].usage)
	pos, rest, err := parseFlags(fs, args)
	if err != nil {
		return err
	}
	if len(pos) != 1 || len(rest) > 0 {
		fs.Usage()
		return failf("expected exactly one target")
	}
	rr, err := resolveTarget(ctx, e, pos[0], interactiveResolution(e, false))
	if err != nil {
		return err
	}
	if interactiveResolution(e, false) {
		syncNotice(ctx, e)
	}
	if rr.Result.Status == resolve.StatusPlainSSH {
		return plainSSH(ctx, e, rr.Result)
	}
	t, err := connectable(rr)
	if err != nil {
		return err
	}
	addr, note := chooseAddress(ctx, e, t)
	if note != "" {
		fmt.Fprintf(e.Stderr, "hop: %s\n", note)
	}
	if hint := unpinnedNote(rr); hint != "" {
		fmt.Fprintf(e.Stderr, "hop: %s\n", hint)
	}
	argv := append([]string{e.sshBinary()}, e.sshArgs(t, addr)...)
	// ssh takes over this process's terminal (or runs as a child on the same
	// streams). Its session is the user's own and is not sanitized, on purpose.
	return e.execSSH(argv)
}

// execSSH replaces this process with ssh, falling back to a child process
// where exec is not available.
func (e *Env) execSSH(argv []string) error {
	path, err := exec.LookPath(argv[0])
	if err != nil {
		return failf("cannot find %s: %v", argv[0], err)
	}
	run := e.ExecSSH
	if run == nil {
		run = execReplace
	}
	if err := run(path, argv, e.sshEnviron()); err != nil {
		return failf("cannot run %s: %v", path, err)
	}
	return nil
}

// plainSSH connects to a target that is not in the vault with the user's own
// ssh setup, then offers hop add.
func plainSSH(ctx context.Context, e *Env, res *resolve.Result) error {
	dest := res.Target
	if res.User != "" {
		dest = res.User + "@" + dest
	}
	fmt.Fprintf(e.Stderr, "hop: %q is not in the vault; connecting with plain ssh\n", res.Target)
	cmd := exec.CommandContext(ctx, e.sshBinary(), "--", dest)
	// The session's streams are not sanitized, on purpose: this is the user's
	// own terminal session with ssh, not output hop composes.
	cmd.Stdin, cmd.Stdout, cmd.Stderr = e.Stdin, e.Stdout, e.Stderr
	// The user's own agent stays: this is their ssh setup, not hop's.
	cmd.Env = withoutEnv(e.environ(), store.PassphraseEnv)
	err := cmd.Run()
	var ee *exec.ExitError
	switch {
	case err == nil:
		fmt.Fprintf(e.Stderr, "hop: to keep it, run: hop add %s --address %s\n", oneLine(suggestName(res.Target)), oneLine(res.Target))
		return nil
	case errors.As(err, &ee):
		code, _ := exitCode(ee)
		return silent(code)
	}
	return failf("cannot run ssh: %v", err)
}

// exitCode is the exit status of a command that ended with ee, and
// whether it exited on its own. A command killed by a signal has no exit
// status: ExitFailure, and false.
func exitCode(ee *exec.ExitError) (code int, exited bool) {
	if c := ee.ExitCode(); c >= 0 {
		return c, true
	}
	return ExitFailure, false
}

// suggestName turns a target or a machine's own name into something usable
// as a host name: lower case, letters, digits, '_' and '-', with runs of
// separators folded into one '-'.
func suggestName(t string) string {
	var sb strings.Builder
	lastDash := true // so the name never starts with '-'
	for _, r := range strings.ToLower(t) {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '_':
			sb.WriteRune(r)
			lastDash = false
		case r == '-' || r == '.' || r == ':' || r == '/' || unicode.IsSpace(r):
			if !lastDash {
				sb.WriteByte('-')
				lastDash = true
			}
		}
	}
	name := strings.TrimRight(sb.String(), "-")
	if len(name) > 64 {
		name = strings.TrimRight(name[:64], "-")
	}
	if name == "" || name[0] == '_' {
		return "host"
	}
	return name
}

// ---- hop exec ----

// ExecResult is the --json shape of hop exec.
type ExecResult struct {
	Host       string `json:"host"`
	ExitCode   int    `json:"exit_code"`
	Stdout     string `json:"stdout"`
	Stderr     string `json:"stderr"`
	DurationMS int64  `json:"duration_ms"`
	// Truncated is set when stdout or stderr kept only its last 64 KB, or
	// may have lost output for the reason in Warning.
	Truncated bool `json:"truncated"`
	// Error is set when hop itself failed to run the command, e.g. a timeout.
	Error string `json:"error,omitempty"`
	// Warning is set when the command ran but its output may be incomplete.
	Warning string `json:"warning,omitempty"`

	// The size of the whole of stdout and stderr, kept or not, for hop
	// mcp to report when it withholds them. They are not in the JSON.
	stdoutBytes, stdoutLines int64
	stderrBytes, stderrLines int64
}

// tailLimit is how much of each output stream --json keeps: the last 64 KB.
const tailLimit = 64 << 10

// tailBuffer keeps the last max bytes written to it, and counts them all.
type tailBuffer struct {
	max     int
	buf     []byte
	dropped bool

	total, newlines int64
	last            byte
}

func (t *tailBuffer) Write(p []byte) (int, error) {
	if len(p) > 0 {
		t.total += int64(len(p))
		t.newlines += int64(bytes.Count(p, []byte{'\n'}))
		t.last = p[len(p)-1]
	}
	t.buf = append(t.buf, p...)
	if len(t.buf) > 2*t.max {
		t.buf = append([]byte(nil), t.buf[len(t.buf)-t.max:]...)
		t.dropped = true
	}
	return len(p), nil
}

// lines is how many lines were written: one more than the line breaks
// when the last line has none.
func (t *tailBuffer) lines() int64 {
	if t.total > 0 && t.last != '\n' {
		return t.newlines + 1
	}
	return t.newlines
}

func (t *tailBuffer) Bytes() []byte {
	if len(t.buf) > t.max {
		t.dropped = true
		return t.buf[len(t.buf)-t.max:]
	}
	return t.buf
}

// remoteCommand turns the words after -- into the string ssh sends. Several
// words are quoted individually, so each stays one argument on the remote
// side. A single word is a shell command line, as with ssh itself
// (hop exec h -- 'cd /srv && make'). With sudo, it runs under sudo -n, which
// fails at once instead of waiting for a password.
func remoteCommand(words []string, sudo bool) string {
	line := words[0]
	if len(words) > 1 {
		q := make([]string, len(words))
		for i, w := range words {
			q[i] = shellcmd.Quote(w)
		}
		line = strings.Join(q, " ")
		if sudo {
			return "sudo -n " + line
		}
		return line
	}
	if sudo {
		return "sudo -n sh -c " + shellcmd.Quote(line)
	}
	return line
}

func runExec(ctx context.Context, e *Env, args []string) error {
	fs := newFlags(e, "exec", commands["exec"].usage)
	asJSON := fs.Bool("json", false, "print the result as JSON")
	timeout := fs.Duration("timeout", 0, "kill the command after this long (0 means no limit)")
	sudo := fs.Bool("sudo", false, "run the command with sudo -n")
	pos, rest, err := parseFlags(fs, args)
	if err != nil {
		return err
	}
	if len(pos) == 0 {
		fs.Usage()
		return failf("hop exec needs a target and a command")
	}
	tgt, words := pos[0], rest
	if words == nil {
		words = pos[1:] // no --: the rest is the command
	}
	if len(words) == 0 {
		fs.Usage()
		return failf("hop exec needs a command after the target")
	}
	if strings.ContainsRune(tgt, ',') || strings.HasPrefix(tgt, "tag:") {
		return failf("hop exec runs on one host in this version; %q names several", tgt)
	}

	// Never fuzzy: a command must not run on a host that merely resembled the
	// target.
	rr, err := resolveTarget(ctx, e, tgt, false)
	if err != nil {
		return err
	}
	t, err := connectable(rr)
	if err != nil {
		return err
	}
	addr, note := chooseAddress(ctx, e, t)
	if note != "" {
		fmt.Fprintf(e.Stderr, "hop: %s\n", note)
	}

	if hint := unpinnedNote(rr); hint != "" {
		fmt.Fprintf(e.Stderr, "hop: %s\n", hint)
	}

	r := remoteRun{command: remoteCommand(words, *sudo), timeout: *timeout, stdin: e.Stdin}
	if !*asJSON {
		// The remote command's output goes straight through, not sanitized, on
		// purpose: it is the user's own terminal session. With --json it is
		// captured and JSON-encoded (escapeJSONControls in printJSON).
		r.stdout, r.stderr = e.Stdout, e.Stderr
	}
	res, err := e.runRemote(ctx, t, addr, r)
	if err != nil {
		return err
	}
	if *asJSON {
		if err := printJSON(e, res); err != nil {
			return err
		}
	} else {
		if res.Error != "" {
			fmt.Fprintf(e.Stderr, "hop: %s\n", res.Error)
		}
		if res.Warning != "" {
			fmt.Fprintf(e.Stderr, "hop: warning: %s\n", res.Warning)
		}
	}
	if res.ExitCode != 0 {
		return silent(res.ExitCode)
	}
	return nil
}

// remoteRun is one command for runRemote.
type remoteRun struct {
	command string
	timeout time.Duration // 0 means no limit
	// stdin feeds the remote command. Nil means it gets none: ssh -n, so
	// a remote prompt reads end-of-file instead of waiting.
	stdin io.Reader
	// stdout and stderr receive the output as it comes. Nil keeps the last
	// tail bytes of that stream in the result instead.
	stdout, stderr io.Writer
	// tail is how much of a stream the result keeps; 0 means tailLimit.
	tail int
}

// runRemote runs one command on t at addr with ssh: no PTY, and BatchMode,
// so ssh fails instead of asking for a password or a host key. The remote
// exit status is in the result; a timeout is ExitFailure with Error set.
// The error is for ssh not running at all.
func (e *Env) runRemote(ctx context.Context, t *target, addr string, r remoteRun) (ExecResult, error) {
	connectTimeout := 10
	if r.timeout > 0 && r.timeout < 10*time.Second {
		connectTimeout = int((r.timeout + time.Second - 1) / time.Second)
	}
	opts := []string{"-T", "-o", "BatchMode=yes", "-o", fmt.Sprintf("ConnectTimeout=%d", connectTimeout)}
	if r.stdin == nil {
		opts = append(opts, "-n")
	}
	sshArgs := append(e.sshArgs(t, addr, opts...), r.command)

	runCtx := ctx
	if r.timeout > 0 {
		var cancel context.CancelFunc
		runCtx, cancel = context.WithTimeout(ctx, r.timeout)
		defer cancel()
	}
	cmd := exec.CommandContext(runCtx, e.sshBinary(), sshArgs...)
	cmd.Env = e.sshEnviron()
	cmd.Stdin = r.stdin
	cmd.WaitDelay = time.Second
	keep := tailLimit
	if r.tail > 0 {
		keep = r.tail
	}
	outTail, errTail := &tailBuffer{max: keep}, &tailBuffer{max: keep}
	cmd.Stdout, cmd.Stderr = r.stdout, r.stderr
	if r.stdout == nil {
		cmd.Stdout = outTail
	}
	if r.stderr == nil {
		cmd.Stderr = errTail
	}

	start := time.Now()
	runErr := cmd.Run()
	res := ExecResult{Host: t.rr.Result.HostName, DurationMS: time.Since(start).Milliseconds()}
	var ee *exec.ExitError
	switch {
	case runErr == nil:
	case errors.Is(runErr, exec.ErrWaitDelay):
		// ssh exited 0, but something it started (a ProxyJump ssh, say)
		// still held its output open, and WaitDelay cut that off. The exit
		// code stands; what was still to come is lost.
		res.Warning = "ssh exited 0, but a process it left behind still held its output open and was cut off after 1s, so the output may be incomplete"
	case r.timeout > 0 && errors.Is(runCtx.Err(), context.DeadlineExceeded):
		res.ExitCode = ExitFailure
		res.Error = fmt.Sprintf("timed out after %s", r.timeout)
	case errors.As(runErr, &ee):
		var exited bool
		res.ExitCode, exited = exitCode(ee)
		if !exited {
			res.Error = "ssh was stopped (" + ee.Error() + ")"
		}
	default:
		return res, failf("cannot run ssh: %v", runErr)
	}
	if r.stdout == nil {
		res.Stdout = string(outTail.Bytes())
		res.stdoutBytes, res.stdoutLines = outTail.total, outTail.lines()
	}
	if r.stderr == nil {
		res.Stderr = string(errTail.Bytes())
		res.stderrBytes, res.stderrLines = errTail.total, errTail.lines()
	}
	res.Truncated = outTail.dropped || errTail.dropped || res.Warning != ""
	return res, nil
}

// ---- hop which ----

type hostRef struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

// WhichResult is the --json shape of hop which.
type WhichResult struct {
	Target     string              `json:"target"`
	User       string              `json:"user,omitempty"`
	Status     resolve.Status      `json:"status"`
	Rule       resolve.Rule        `json:"rule"`
	Matched    string              `json:"matched,omitempty"`
	Host       *hostRef            `json:"host,omitempty"`
	Route      *resolve.Route      `json:"route,omitempty"`
	RouteError string              `json:"route_error,omitempty"`
	RouteHint  string              `json:"route_hint,omitempty"`
	SSHAlias   string              `json:"ssh_alias,omitempty"`
	SSHProblem string              `json:"ssh_problem,omitempty"`
	Candidates []resolve.Candidate `json:"candidates,omitempty"`
	Notes      []string            `json:"notes,omitempty"`
	Tailscale  *tailscale.Node     `json:"tailscale,omitempty"`
}

func whichResult(rr *daemon.ResolveResult) WhichResult {
	res := rr.Result
	w := WhichResult{
		Target: res.Target, User: res.User, Status: res.Status, Rule: res.Rule, Matched: res.Matched,
		Route: rr.Route, RouteError: rr.RouteError, RouteHint: rr.RouteHint, SSHAlias: rr.SSHAlias, SSHProblem: rr.SSHProblem,
		Candidates: res.Candidates, Notes: res.Notes, Tailscale: res.Tailscale,
	}
	if res.HostID != "" {
		w.Host = &hostRef{ID: res.HostID, Name: res.HostName}
	}
	return w
}

func runWhich(ctx context.Context, e *Env, args []string) error {
	fs := newFlags(e, "which", commands["which"].usage)
	asJSON := fs.Bool("json", false, "print the result as JSON")
	pos, _, err := parseFlags(fs, args)
	if err != nil {
		return err
	}
	if len(pos) != 1 {
		fs.Usage()
		return failf("expected exactly one target")
	}
	interactive := interactiveResolution(e, *asJSON)
	// The picker would make which prompt; it only explains, so show the
	// candidates instead.
	var rr daemon.ResolveResult
	if err := call(ctx, e, daemon.OpResolve, daemon.ResolveParams{Target: pos[0], Interactive: interactive}, &rr); err != nil {
		return configStale(e, err)
	}
	if interactive {
		syncNotice(ctx, e)
	}
	w := whichResult(&rr)
	matched := rr.Result.Status == resolve.StatusMatched
	if *asJSON {
		if err := printJSON(e, w); err != nil {
			return err
		}
	} else {
		printWhich(e, &rr, &w)
	}
	if !matched {
		return failMsg(strings.SplitN(describeUnresolved(rr.Result), "\n", 2)[0])
	}
	return nil
}

func printWhich(e *Env, rr *daemon.ResolveResult, w *WhichResult) {
	// Everything below is vault, daemon or network text: oneLine as inserted.
	res := rr.Result
	e.printf("target:   %s\n", oneLine(res.Target))
	switch res.Status {
	case resolve.StatusMatched:
		e.printf("host:     %s\n", oneLine(res.HostName))
		e.printf("rule:     %s (%s)\n", oneLine(string(res.Rule)), oneLine(res.Matched))
	case resolve.StatusAmbiguous:
		e.printf("host:     ambiguous\n")
		e.printf("rule:     %s (%s)\n", oneLine(string(res.Rule)), oneLine(res.Matched))
	case resolve.StatusPlainSSH:
		e.printf("host:     none; hop would use plain ssh\n")
	default:
		e.printf("host:     no match\n")
	}
	if rr.Route != nil {
		r := rr.Route
		e.printf("address:  %s:%d via %s\n", oneLine(r.Address), r.Port, oneLine(r.Label()))
		if r.Blocked != "" {
			e.printf("blocked:  %s\n", oneLine(r.Blocked))
		}
		if r.Fallback != "" {
			e.printf("fallback: %s (direct) if the tailnet address does not answer\n", oneLine(r.Fallback))
		}
	}
	if rr.RouteError != "" {
		e.printf("route:    %s\n", oneLine(rr.RouteError))
	}
	if rr.RouteHint != "" {
		e.printf("hint:     %s\n", oneLine(rr.RouteHint))
	}
	if rr.Host != nil {
		user := res.User
		if user == "" {
			user = rr.Host.User
		}
		if user != "" {
			e.printf("user:     %s\n", oneLine(user))
		}
		if rr.SSHAlias != "" {
			e.printf("ssh:      ssh %s  (config %s)\n", oneLine(rr.SSHAlias), oneLine(e.sshConfigFile()))
		} else {
			e.printf("ssh:      not available: %s\n", oneLine(orUnknown(rr.SSHProblem)))
		}
	}
	for _, c := range res.Candidates {
		e.printf("candidate: %s %s - %s\n", oneLine(c.Name), joinOne(c.Addresses, ","), oneLine(c.Detail))
	}
	for _, n := range res.Notes {
		e.printf("note:     %s\n", oneLine(n))
	}
}

// ---- hop check ----

// Step statuses.
const (
	stepPass    = "pass"
	stepFail    = "fail"
	stepSkipped = "skipped"
)

// Step is one line of a hop check.
type Step struct {
	Name   string `json:"name"`
	Status string `json:"status"`
	Detail string `json:"detail"`
}

// CheckResult is the --json shape of hop check.
type CheckResult struct {
	Target string `json:"target"`
	Host   string `json:"host,omitempty"`
	OK     bool   `json:"ok"`
	Steps  []Step `json:"steps"`
}

// checker runs steps in order. A step names the steps it depends on; if any
// of them did not pass it is skipped, with the reason. A step can also be
// skipped by design (it does not apply to this host), which satisfies the
// steps that depend on it.
type checker struct {
	steps     []Step
	status    map[string]string
	satisfied map[string]bool
}

func (c *checker) run(name string, deps []string, fn func() (string, string)) {
	for _, d := range deps {
		if c.status[d] != stepPass && !c.satisfied[d] {
			c.add(Step{Name: name, Status: stepSkipped, Detail: safef("skipped: %s did not pass", d)})
			return
		}
	}
	status, detail := fn()
	c.add(Step{Name: name, Status: status, Detail: detail})
}

// skip records a step that does not apply, and does not count against ok.
func (c *checker) skip(name, why string) {
	c.add(Step{Name: name, Status: stepSkipped, Detail: why})
	if c.satisfied == nil {
		c.satisfied = map[string]bool{}
	}
	c.satisfied[name] = true
}

func (c *checker) add(s Step) {
	if c.status == nil {
		c.status = map[string]string{}
	}
	c.steps = append(c.steps, s)
	c.status[s.Name] = s.Status
}

func (c *checker) ok() bool {
	for _, s := range c.steps {
		if s.Status != stepPass && !c.satisfied[s.Name] {
			return false
		}
	}
	return true
}

func parsePins(lines []string) (pins []ssh.PublicKey, bad int) {
	for _, l := range lines {
		p, err := sshkeys.ParsePublic(l)
		if err != nil {
			bad++
			continue
		}
		pins = append(pins, p)
	}
	return
}

func fingerprints(pins []ssh.PublicKey) string {
	var out []string
	for _, p := range pins {
		out = append(out, p.Type()+" "+sshkeys.Fingerprint(p))
	}
	return strings.Join(out, ", ")
}

func runCheck(ctx context.Context, e *Env, args []string) error {
	fs := newFlags(e, "check", commands["check"].usage)
	asJSON := fs.Bool("json", false, "print the result as JSON")
	pos, _, err := parseFlags(fs, args)
	if err != nil {
		return err
	}
	if len(pos) != 1 {
		fs.Usage()
		return failf("expected exactly one target")
	}
	rr, err := resolveTarget(ctx, e, pos[0], interactiveResolution(e, *asJSON))
	if err != nil {
		return err
	}
	if interactiveResolution(e, *asJSON) {
		syncNotice(ctx, e)
	}
	out := CheckResult{Target: pos[0], Host: rr.Result.HostName}
	out.Steps, out.OK = e.diagnose(ctx, rr, true, plainEcho)
	if *asJSON {
		if err := printJSON(e, out); err != nil {
			return err
		}
	} else {
		e.printf("check %s\n", oneLine(pos[0]))
		for _, s := range out.Steps {
			e.printf("  [%s] %-16s %s\n", s.Status, s.Name, strings.ReplaceAll(s.Detail, "\n", "\n"+strings.Repeat(" ", 28)))
		}
	}
	if !out.OK {
		return silent(ExitFailure)
	}
	return nil
}

// echo is how a message shows what the user typed. The CLI quotes it as %q
// does (plainEcho); hop mcp marks it too, so that its masker leaves it be
// (mcpEcho).
type echo struct {
	quote func(string) string
	// login, if set, is applied to ssh's stderr from a login to t at addr.
	login func(t *target, addr, stderr string) string
	// remote, if set, is applied to text the network supplied (ssh's
	// stderr, after login; a server's handshake error) as it came, before
	// hop puts it into a step's detail.
	remote func(text string) string
	// loginTail is how much of ssh's stderr from the login is kept for
	// login and remote; 0 means tailLimit. hop mcp keeps more, so that
	// remote checks the bytes before its own cut too.
	loginTail int
}

var plainEcho = echo{quote: strconv.Quote}

// authCheckTimeout bounds hop check's login, ssh's own start included.
const authCheckTimeout = 20 * time.Second

// diagnose runs hop check's steps for rr, in order, and says whether they
// all passed. Without login the last step, which logs in with ssh and runs
// true there, is skipped. What the user typed is shown as ec says.
func (e *Env) diagnose(ctx context.Context, rr *daemon.ResolveResult, login bool, ec echo) ([]Step, bool) {
	var c checker
	res := rr.Result
	c.run("resolved", nil, func() (string, string) {
		if res.Status != resolve.StatusMatched {
			return stepFail, describeUnresolvedAs(res, ec.quote)
		}
		return stepPass, safef("host %q by rule %s (%s)", res.HostName, res.Rule, res.Matched)
	})

	// A host behind a jump host is not expected to be reachable directly, so
	// the direct probes (TCP, host key) cannot say anything about it. ssh
	// itself goes through the jump host, which auth_ok exercises.
	viaJump := rr.Host != nil && !rr.Host.JumpHostID.IsZero()
	const jumpReason = "skipped: the host is reached through a jump host, so it is not probed directly"
	// Likewise for a host reached only through Tailscale SSH: the tailnet is
	// the one route, and ssh going over it is what auth_ok tests.
	tsOnly := rr.Route != nil && rr.Route.TailscaleSSH
	const tsReason = "skipped: the host is reached through Tailscale SSH, so a direct probe says nothing; auth_ok tries the real route"

	var addr string
	var port int
	var route *resolve.Route
	c.run("route", []string{"resolved"}, func() (string, string) {
		if rr.Route == nil {
			return stepFail, oneLine(orUnknown(rr.RouteError))
		}
		route = rr.Route
		addr, port = route.Address, route.Port
		if route.Blocked != "" {
			return stepFail, oneLine(route.Blocked)
		}
		detail := safef("%s:%d via %s", addr, port, route.Label())
		if rr.RouteHint != "" {
			detail += safef("; %s", rr.RouteHint)
		}
		return stepPass, detail
	})

	probe := func(name string, deps []string, fn func() (string, string)) {
		switch {
		case viaJump:
			c.skip(name, jumpReason)
		case tsOnly:
			c.skip(name, tsReason)
		default:
			c.run(name, deps, fn)
		}
	}
	probe("tcp_reachable", []string{"route"}, func() (string, string) {
		err := tcpReachable(ctx, addr, port, e.dialTimeout())
		if err == nil {
			return stepPass, safef("connected to %s:%d", addr, port)
		}
		if route.Fallback != "" {
			if ferr := tcpReachable(ctx, route.Fallback, port, e.dialTimeout()); ferr == nil {
				addr = route.Fallback
				return stepPass, safef("%s:%d (tailnet) did not answer (%v); %s:%d (direct) did", route.Address, port, err, addr, port)
			}
		}
		return stepFail, safef("cannot connect to %s:%d: %v", addr, port, err)
	})

	var pins []ssh.PublicKey
	c.run("host_key_pinned", []string{"resolved"}, func() (string, string) {
		var bad int
		pins, bad = parsePins(rr.Host.HostKeys)
		switch {
		case len(pins) > 0 && bad > 0:
			return stepPass, safef("%d host key(s) pinned (%d unreadable ones are ignored): %s", len(pins), bad, fingerprints(pins))
		case len(pins) > 0:
			return stepPass, safef("%d host key(s) pinned: %s", len(pins), fingerprints(pins))
		}
		return stepFail, safef("no host key is pinned for %s, so ssh refuses it; pin the server's key with: %s", res.HostName, pinCommand(res.HostName, viaJump))
	})

	probe("host_key_matches", []string{"tcp_reachable", "host_key_pinned"}, func() (string, string) {
		key, err := fetchHostKey(ctx, addr, port, algorithmsFor(pins), e.dialTimeout())
		if err != nil {
			// The error can quote the server: a disconnect's message.
			msg := err.Error()
			if ec.remote != nil {
				msg = ec.remote(msg)
			}
			return stepFail, safef("could not read the server's host key: %s", msg)
		}
		for _, p := range pins {
			if bytes.Equal(p.Marshal(), key.Marshal()) {
				return stepPass, safef("the server presents the pinned %s %s", key.Type(), sshkeys.Fingerprint(key))
			}
		}
		return stepFail, safef("the server presents %s %s, which is not pinned (pinned: %s); the machine may have been rebuilt, or something is intercepting the connection", key.Type(), sshkeys.Fingerprint(key), fingerprints(pins))
	})

	if !login {
		c.skip("auth_ok", "skipped: logging in runs a command (true) on the host, and this check may not run commands")
		return c.steps, c.ok()
	}
	c.run("auth_ok", []string{"host_key_pinned", "host_key_matches"}, func() (string, string) {
		t, err := connectableAs(rr, ec.quote)
		if err != nil {
			return stepFail, err.Error() // composed by failf/failMsg: already display-safe
		}
		// runRemote bounds it: stdin closed, output capped, and WaitDelay,
		// so a ProxyJump child that keeps stderr open cannot hold it past
		// the timeout.
		res, err := e.runRemote(ctx, t, addr, remoteRun{command: "true", timeout: authCheckTimeout, tail: ec.loginTail})
		if err != nil {
			return stepFail, err.Error() // composed by failf: already display-safe
		}
		if res.ExitCode != 0 || res.Error != "" {
			// ssh's stderr is remote text; lastLines makes each line safe.
			stderr := res.Stderr
			if ec.login != nil {
				stderr = ec.login(t, addr, stderr)
			}
			if ec.remote != nil {
				stderr = ec.remote(stderr)
			}
			msg := strings.TrimSpace(stderr)
			if msg == "" {
				msg = res.Error
			}
			if msg == "" {
				msg = fmt.Sprintf("exit status %d", res.ExitCode)
			}
			return stepFail, "ssh did not log in: " + lastLines(msg, 3)
		}
		return stepPass, safef("logged in with ssh %s", t.alias)
	})

	return c.steps, c.ok()
}

func lastLines(s string, n int) string {
	lines := strings.Split(strings.TrimSpace(s), "\n")
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	return joinOne(lines, "; ")
}

// ---- hop trust ----

func runTrust(ctx context.Context, e *Env, args []string) error {
	fs := newFlags(e, "trust", commands["trust"].usage)
	yes := fs.Bool("yes", false, "pin without asking")
	fp := fs.String("fingerprint", "", "pin only if the server's key has this SHA256 fingerprint")
	replace := fs.Bool("replace", false, "replace pinned keys of the same type")
	asJSON := fs.Bool("json", false, "print the result as JSON")
	pos, _, err := parseFlags(fs, args)
	if err != nil {
		return err
	}
	if len(pos) != 1 {
		fs.Usage()
		return failf("expected exactly one target")
	}
	rr, err := resolveTarget(ctx, e, pos[0], false)
	if err != nil {
		return err
	}
	if rr.Result.Status != resolve.StatusMatched || rr.Host == nil {
		return failMsg(describeUnresolved(rr.Result))
	}
	if rr.Route == nil {
		return failf("%s has no usable route: %s", rr.Result.HostName, orUnknown(rr.RouteError))
	}
	if rr.Route.Blocked != "" {
		return failf("%s", rr.Route.Blocked)
	}
	host := *rr.Host
	if !host.JumpHostID.IsZero() {
		return failf("%s is reached through a jump host, so hop cannot read its host key directly; pin it with: %s", host.Name, pinCommand(host.Name, true))
	}
	pins, _ := parsePins(host.HostKeys)
	r := rr.Route
	key, err := fetchHostKey(ctx, r.Address, r.Port, nil, e.dialTimeout())
	if err != nil && r.Fallback != "" {
		key, err = fetchHostKey(ctx, r.Fallback, r.Port, nil, e.dialTimeout())
	}
	if err != nil {
		return failf("cannot read the host key of %s: %v", host.Name, err)
	}
	got := sshkeys.Fingerprint(key)
	line := sshkeys.Line(key)

	for _, p := range pins {
		if bytes.Equal(p.Marshal(), key.Marshal()) {
			return reportTrust(e, *asJSON, host.Name, key, got, false, "already pinned")
		}
	}
	var sameType ssh.PublicKey // a pinned key of the same type, which this one would replace
	for _, p := range pins {
		if p.Type() == key.Type() {
			sameType = p
			break
		}
	}
	if sameType != nil && !*replace {
		return failf("%s already pins a different %s key (%s) and the server presents %s; a changed host key can mean the machine was rebuilt or the connection is intercepted. If you are sure, run again with --replace",
			host.Name, key.Type(), sshkeys.Fingerprint(sameType), got)
	}
	switch {
	case *fp != "":
		if *fp != got {
			return failf("the server presents %s, not the %s you gave; nothing was pinned", got, *fp)
		}
	default:
		fmt.Fprintf(e.Stderr, "%s presents %s %s\n", oneLine(host.Name), oneLine(key.Type()), oneLine(got))
		ok, err := confirm(e, *yes, "Pin this host key?")
		if err != nil {
			return err
		}
		if !ok {
			return failf("not pinned")
		}
	}

	var keep []string
	for _, l := range host.HostKeys {
		if p, err := sshkeys.ParsePublic(l); err == nil && p.Type() == key.Type() {
			continue // --replace: only reachable when sameType was allowed to go
		}
		keep = append(keep, l)
	}
	host.HostKeys = append(keep, line)
	if err := callChange(ctx, e, *asJSON, daemon.OpPutHost, daemon.PutHostParams{Host: host}, nil); err != nil {
		return err
	}
	return reportTrust(e, *asJSON, host.Name, key, got, true, "pinned")
}

func reportTrust(e *Env, asJSON bool, host string, key ssh.PublicKey, fp string, changed bool, what string) error {
	if asJSON {
		return printJSON(e, map[string]any{"host": host, "key_type": key.Type(), "fingerprint": fp, "pinned": true, "changed": changed})
	}
	e.printf("%s: %s %s %s\n", oneLine(host), what, oneLine(key.Type()), oneLine(fp))
	return nil
}
