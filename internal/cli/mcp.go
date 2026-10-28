package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/dalyem/hopkey/internal/daemon"
	"github.com/dalyem/hopkey/internal/model"
	"github.com/dalyem/hopkey/internal/resolve"
	"github.com/dalyem/hopkey/internal/shellcmd"
	"github.com/dalyem/hopkey/internal/store"
	"github.com/dalyem/hopkey/internal/version"
)

// hop mcp is a stdio MCP server for local AI agents. It is a thin layer
// over the daemon's control socket, as every other command is: it never
// opens the vault, and nothing the daemon answers carries a secret.
//
// Its rules (design: "MCP tools", "Local agents run as you"):
//   - a host with agent_access deny is invisible: resolution runs with
//     agent_only, and every list and answer is filtered again here;
//   - exec and run_snippet refuse a host with no pinned host key, and ssh
//     runs with StrictHostKeyChecking, so a changed key blocks the call;
//   - every exec and run_snippet is logged to mcpAuditFile before it runs
//     and after, and nothing runs if the log cannot be written;
//   - --read-only registers no tool that runs a command;
//   - the hop auth secrets leave this process's environment, and every
//     answer is scrubbed of them and of private key blocks.
//
// agent_access deny is a guardrail for well-behaved agents, not a security
// boundary: an agent runs as the user, and can reach the agent socket.

const (
	mcpParallel       = 8 // hosts an exec runs on at once
	mcpMaxHosts       = 64
	mcpDefaultTimeout = 60 * time.Second
	mcpMaxTimeout     = time.Hour
	mcpAuditFile      = "mcp-audit.jsonl"
)

// mcpEnvPrefix goes before every command an agent runs, so that a pager
// prints instead of waiting for a terminal that is not there.
const mcpEnvPrefix = "export PAGER=cat GIT_PAGER=cat SYSTEMD_PAGER=cat; "

const mcpInstructions = `hop reaches the user's SSH hosts from their HopKey vault.
Find hosts with list_hosts or resolve_host; a target that is not an exact name, alias or address comes back as candidates, never as a guess.
exec runs a non-interactive command: no terminal, stdin closed, a timeout per host. Use sudo -n, never plain sudo.
exec refuses a host with no pinned host key; the user pins one from a terminal with hop trust <host>.
Output keeps the last 64 KiB of stdout and of stderr per host.`

func runMCP(ctx context.Context, e *Env, args []string) error {
	if len(args) > 0 && args[0] == "install" {
		return runMCPInstall(ctx, e, args[1:])
	}
	fs := newFlags(e, "mcp", commands["mcp"].usage)
	readOnly := fs.Bool("read-only", false, "offer no tool that runs a command (no exec, no run_snippet)")
	helpNote(e, fs, "\nhop mcp speaks MCP on stdin and stdout; an AI client starts it. To register it, run hop mcp install.\n")
	pos, rest, err := parseFlags(fs, args)
	if err != nil {
		return err
	}
	if len(pos) > 0 || rest != nil {
		fs.Usage()
		return failf("hop mcp takes no arguments")
	}

	// The hop auth secrets answer that command's prompts. hop mcp has none,
	// so they leave its environment and its children's; their values are
	// also scrubbed from every answer, as is the device key passphrase.
	base := e.Environ
	if base == nil {
		base = os.Environ()
		for _, name := range authSecretEnv {
			os.Unsetenv(name)
		}
	}
	secrets := envValues(base, append(slices.Clone(authSecretEnv), store.PassphraseEnv)...)
	e.Environ = withoutEnv(base, authSecretEnv...)

	// Stdout carries the protocol and nothing else; stdin is the client's.
	in, out := e.Stdin, e.Stdout
	e.Stdout, e.Stdin = io.Discard, strings.NewReader("")
	e.StdoutTTY, e.StdinTTY = false, false

	srv := newMCPServer(e, *readOnly, secrets)
	t := &mcp.IOTransport{Reader: readCloser(in), Writer: writeCloser(out)}
	err = srv.Run(ctx, t)
	if err == nil || ctx.Err() != nil || errors.Is(err, io.EOF) || errors.Is(err, mcp.ErrConnectionClosed) {
		return nil
	}
	return failf("hop mcp: %v", err)
}

func envValues(environ []string, names ...string) []string {
	var out []string
	for _, kv := range environ {
		name, val, _ := strings.Cut(kv, "=")
		if slices.Contains(names, name) && val != "" {
			out = append(out, val)
		}
	}
	return out
}

func readCloser(r io.Reader) io.ReadCloser {
	if rc, ok := r.(io.ReadCloser); ok {
		return rc
	}
	return io.NopCloser(r)
}

type nopWriteCloser struct{ io.Writer }

func (nopWriteCloser) Close() error { return nil }

func writeCloser(w io.Writer) io.WriteCloser {
	if wc, ok := w.(io.WriteCloser); ok {
		return wc
	}
	return nopWriteCloser{w}
}

type mcpServer struct {
	e        *Env
	readOnly bool
	secrets  []string
	audit    *auditLog
}

func newMCPServer(e *Env, readOnly bool, secrets []string) *mcp.Server {
	s := &mcpServer{e: e, readOnly: readOnly, secrets: secrets, audit: newAuditLog(e)}
	srv := mcp.NewServer(&mcp.Implementation{Name: "hop", Title: "HopKey", Version: version.Version},
		&mcp.ServerOptions{Instructions: mcpInstructions})
	reads := &mcp.ToolAnnotations{ReadOnlyHint: true}
	addMCPTool(s, srv, &mcp.Tool{Name: "list_hosts", Annotations: reads, Description: "List the vault's hosts: names, aliases, addresses, user, port, tags, " +
		"description, how hop logs in (key, credential or agent-only), Tailscale status and whether a host key is pinned. Never secrets."}, s.listHosts)
	addMCPTool(s, srv, &mcp.Tool{Name: "resolve_host", Annotations: reads, Description: "Resolve a target (name, alias, address or Tailscale name, " +
		"optionally user@target) to one host, as hop which --json does. Anything that is not an exact match comes back as candidates; nothing is guessed."}, s.resolveHost)
	checkDesc := "Diagnose the connection to one host step by step, as hop check does: resolution, route, TCP, pinned host key, the server's key, and login."
	if readOnly {
		checkDesc += " In read-only mode the login step is skipped, since it runs a command."
	}
	addMCPTool(s, srv, &mcp.Tool{Name: "check_host", Annotations: reads, Description: checkDesc}, s.checkHost)
	addMCPTool(s, srv, &mcp.Tool{Name: "ssh_command", Annotations: reads, Description: "The ssh command line that connects to a host with hop's " +
		"generated config and agent, for an agent that runs commands in its own shell."}, s.sshCommand)
	addMCPTool(s, srv, &mcp.Tool{Name: "list_snippets", Annotations: reads, Description: "List saved command snippets with their {{name}} parameters."}, s.listSnippets)
	if readOnly {
		return srv
	}
	addMCPTool(s, srv, &mcp.Tool{Name: "exec", InputSchema: json.RawMessage(mcpExecSchema), Description: "Run a shell command on one or more hosts " +
		"over ssh, at most 8 at a time. No terminal, stdin closed, PAGER=cat, and a timeout per host: a prompt fails instead of waiting, so use sudo -n. " +
		"Returns per host exit_code, stdout and stderr (each the last 64 KiB) and truncated, and an error when hop could not run the command. " +
		"Hosts with no pinned host key are refused."}, s.exec)
	addMCPTool(s, srv, &mcp.Tool{Name: "run_snippet", InputSchema: json.RawMessage(mcpRunSnippetSchema), Description: "Run a saved snippet on one " +
		"or more hosts, as exec does. Each parameter value is quoted as one shell word; every parameter is required and unknown ones are refused."}, s.runSnippet)
	return srv
}

const mcpHostsSchema = `{
	"description": "One host, a list of hosts, or tag:<tag> for every host with that tag. A host is a name, alias or address, optionally user@host.",
	"anyOf": [{"type": "string"}, {"type": "array", "items": {"type": "string"}, "minItems": 1}]
}`

const mcpTimeoutSchema = `{"type": "integer", "minimum": 1, "maximum": 3600, "description": "seconds before the command is killed on each host; default 60"}`

var mcpExecSchema = `{
	"type": "object",
	"properties": {
		"hosts": ` + mcpHostsSchema + `,
		"command": {"type": "string", "description": "a shell command line, run by the remote user's shell"},
		"timeout_s": ` + mcpTimeoutSchema + `
	},
	"required": ["hosts", "command"],
	"additionalProperties": false
}`

var mcpRunSnippetSchema = `{
	"type": "object",
	"properties": {
		"name": {"type": "string", "description": "the snippet's name"},
		"hosts": ` + mcpHostsSchema + `,
		"params": {"type": "object", "additionalProperties": {"type": "string"}, "description": "a value for each of the snippet's parameters"},
		"timeout_s": ` + mcpTimeoutSchema + `
	},
	"required": ["name", "hosts"],
	"additionalProperties": false
}`

// addMCPTool registers h. Its errors become tool errors, never a crash: a
// panic is recovered. Every answer and error text is scrubbed (redact).
func addMCPTool[In, Out any](s *mcpServer, srv *mcp.Server, t *mcp.Tool, h func(context.Context, *mcp.CallToolRequest, In) (Out, error)) {
	mcp.AddTool(srv, t, func(ctx context.Context, req *mcp.CallToolRequest, in In) (_ *mcp.CallToolResult, out Out, err error) {
		defer func() {
			if r := recover(); r != nil {
				fmt.Fprintf(s.e.Stderr, "hop mcp: %s panicked: %v\n", t.Name, r)
				var zero Out
				out, err = zero, fmt.Errorf("hop failed inside %s; see the MCP client's log for hop's stderr", t.Name)
			}
		}()
		out, err = h(ctx, req, in)
		if err != nil {
			var zero Out
			return nil, zero, errors.New(s.redact(err.Error()))
		}
		return nil, redactValue(s, out), nil
	})
}

// ---- secrets ----

var (
	pemBlockRe = regexp.MustCompile(`(?s)-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----.*?(?:-----END [A-Z0-9 ]*PRIVATE KEY-----|\z)`)
	pemEndRe   = regexp.MustCompile(`(?s)\A.*?-----END [A-Z0-9 ]*PRIVATE KEY-----`)
)

const redacted = "[redacted by hop]"

// redact removes what must never reach an agent: the secret values this
// process was started with, and private key blocks, including one cut
// short at either end by the 64 KiB tail.
func (s *mcpServer) redact(text string) string {
	for _, v := range s.secrets {
		if len(v) >= 6 {
			text = strings.ReplaceAll(text, v, redacted)
		}
	}
	text = pemBlockRe.ReplaceAllString(text, "[private key "+redacted+"]")
	return pemEndRe.ReplaceAllString(text, "[private key "+redacted+"]")
}

// redactValue applies redact to every string in v.
func redactValue[T any](s *mcpServer, v T) T {
	b, err := json.Marshal(v)
	if err != nil {
		return v
	}
	var tree any
	if err := json.Unmarshal(b, &tree); err != nil {
		return v
	}
	var walk func(any) any
	walk = func(x any) any {
		switch x := x.(type) {
		case string:
			return s.redact(x)
		case []any:
			for i := range x {
				x[i] = walk(x[i])
			}
		case map[string]any:
			for k := range x {
				x[k] = walk(x[k])
			}
		}
		return x
	}
	b, err = json.Marshal(walk(tree))
	if err != nil {
		return v
	}
	var out T
	if err := json.Unmarshal(b, &out); err != nil {
		return v
	}
	return out
}

// ---- the daemon, as agents see it ----

// agentAllowed reports whether local agents may see and use h. Only
// "allow", and the empty value it defaults to, lets them.
func agentAllowed(h model.Host) bool { return h.AgentAccess == "allow" || h.AgentAccess == "" }

// daemonError turns the failures an agent can do something about into
// errors that name the fix.
func (s *mcpServer) daemonError(err error) error {
	if err == nil {
		return nil
	}
	if daemon.IsCode(err, daemon.CodeLocked) {
		return errors.New("the vault is locked; the user unlocks it from a terminal with hop unlock, then this can be tried again")
	}
	var de *daemon.Error
	if !errors.As(err, &de) {
		// No answer from the daemon. With no vault there is none to start.
		if ok, xerr := store.Exists(s.e.storeConfig().DataDir); xerr == nil && !ok {
			return errors.New("there is no vault on this device; the user creates one from a terminal with hop init, or signs in with hop auth login")
		}
	}
	return err
}

func (s *mcpServer) list(ctx context.Context) (*daemon.ListResult, error) {
	l, err := listAll(ctx, s.e)
	return l, s.daemonError(err)
}

// resolve resolves target as hop which --json does, among the hosts agents
// may use. A host the daemon matched or offered anyway (one from before
// agent_only, say) is taken out again here, with l.
func (s *mcpServer) resolve(ctx context.Context, target string, l *daemon.ListResult) (*daemon.ResolveResult, error) {
	var rr daemon.ResolveResult
	if err := call(ctx, s.e, daemon.OpResolve, daemon.ResolveParams{Target: target, AgentOnly: true}, &rr); err != nil {
		return nil, s.daemonError(configStale(s.e, err))
	}
	if rr.Result == nil {
		return nil, failf("the daemon did not resolve %q", target)
	}
	visible := func(id string) bool {
		for _, h := range l.Hosts {
			if h.ItemID.String() == id {
				return agentAllowed(h)
			}
		}
		return false // not in the list: not shown, to be safe
	}
	if rr.Host != nil && !visible(rr.Host.ItemID.String()) {
		rr = daemon.ResolveResult{Result: &resolve.Result{Target: rr.Result.Target, User: rr.Result.User, Status: resolve.StatusNoMatch, Rule: resolve.RuleNone}}
	}
	rr.Result.Candidates = slices.DeleteFunc(rr.Result.Candidates, func(c resolve.Candidate) bool { return c.HostID != "" && !visible(c.HostID) })
	return &rr, nil
}

func hostByID(l *daemon.ListResult, id model.ID) (model.Host, bool) {
	for _, h := range l.Hosts {
		if h.ItemID == id {
			return h, true
		}
	}
	return model.Host{}, false
}

// ---- list_hosts ----

// AgentHost is a host as hop mcp shows it. Nothing in it is secret.
type AgentHost struct {
	Name        string   `json:"name"`
	Aliases     []string `json:"aliases"`
	Addresses   []string `json:"addresses"`
	User        string   `json:"user,omitempty"`
	Port        uint32   `json:"port"`
	Tags        []string `json:"tags"`
	Description string   `json:"description,omitempty"`
	// Auth is how hop logs in: "key", "credential" (a password), or
	// "agent-only" (no key of its own, such as Tailscale SSH).
	Auth      string          `json:"auth"`
	Key       string          `json:"key,omitempty"` // the key's name
	JumpHost  string          `json:"jump_host,omitempty"`
	Route     string          `json:"route"`
	Tailscale *AgentTailscale `json:"tailscale,omitempty"`
	// HostKeyPinned is false for a host exec refuses until hop trust.
	HostKeyPinned bool       `json:"host_key_pinned"`
	HostKeys      []pinView  `json:"host_keys"`
	SSHAlias      string     `json:"ssh_alias,omitempty"`
	SSHProblem    string     `json:"ssh_problem,omitempty"`
	Sync          model.Mark `json:"sync,omitempty"` // pending or held
}

// AgentTailscale is a host's tailnet link.
type AgentTailscale struct {
	DNSName string   `json:"dns_name"`
	NodeID  string   `json:"node_id"`
	SSH     string   `json:"ssh"`    // Tailscale SSH: yes, no or unknown
	Online  string   `json:"online"` // yes, no, or unknown when the local tailnet cannot say
	IPs     []string `json:"ips,omitempty"`
}

func authType(h model.Host) string {
	switch {
	case !h.KeyID.IsZero():
		return "key"
	case !h.CredentialID.IsZero():
		return "credential"
	}
	return "agent-only"
}

func agentHost(h model.Host, l *daemon.ListResult) AgentHost {
	v := hostView(h, l)
	a := AgentHost{
		Name: v.Name, Aliases: v.Aliases, Addresses: v.Addresses, User: v.User, Port: v.Port, Tags: v.Tags,
		Description: v.Description, Auth: authType(h), Route: v.Route, HostKeyPinned: len(v.HostKeys) > 0,
		HostKeys: v.HostKeys, SSHAlias: v.SSHAlias, SSHProblem: v.SSHProblem, Sync: v.Mark,
	}
	if v.Key != nil {
		a.Key = v.Key.Name
	}
	if !h.JumpHostID.IsZero() {
		a.JumpHost = "(a host hidden from agents)"
		if j, ok := hostByID(l, h.JumpHostID); ok && agentAllowed(j) {
			a.JumpHost = j.Name
		}
	}
	if t := v.Tailscale; t != nil {
		at := &AgentTailscale{DNSName: t.DNSName, NodeID: t.StableNodeID, SSH: t.SSH, Online: "unknown", IPs: t.IPs}
		if t.Online != nil {
			at.Online = map[bool]string{true: "yes", false: "no"}[*t.Online]
		}
		a.Tailscale = at
	}
	return a
}

type mcpListHostsIn struct {
	Query string `json:"query,omitempty" jsonschema:"only hosts whose name, alias, address, tag, description or Tailscale name contains this text, ignoring case"`
	Tag   string `json:"tag,omitempty" jsonschema:"only hosts with this tag"`
}

// MCPHosts answers list_hosts.
type MCPHosts struct {
	Hosts []AgentHost `json:"hosts"`
}

func (s *mcpServer) listHosts(ctx context.Context, _ *mcp.CallToolRequest, in mcpListHostsIn) (MCPHosts, error) {
	l, err := s.list(ctx)
	if err != nil {
		return MCPHosts{}, err
	}
	q := strings.ToLower(strings.TrimSpace(in.Query))
	out := MCPHosts{Hosts: []AgentHost{}}
	for _, h := range l.Hosts {
		if !agentAllowed(h) {
			continue
		}
		if in.Tag != "" && !slices.ContainsFunc(h.Tags, func(t string) bool { return strings.EqualFold(t, in.Tag) }) {
			continue
		}
		if q != "" {
			fields := append(append(append([]string{h.Name, h.Description}, h.Aliases...), h.Addresses...), h.Tags...)
			if h.Tailscale != nil {
				fields = append(fields, h.Tailscale.DNSName)
			}
			if !slices.ContainsFunc(fields, func(f string) bool { return strings.Contains(strings.ToLower(f), q) }) {
				continue
			}
		}
		out.Hosts = append(out.Hosts, agentHost(h, l))
	}
	slices.SortFunc(out.Hosts, func(a, b AgentHost) int { return strings.Compare(strings.ToLower(a.Name), strings.ToLower(b.Name)) })
	return out, nil
}

// ---- resolve_host ----

type mcpTargetIn struct {
	Target string `json:"target" jsonschema:"a host name, alias, address or Tailscale name, optionally user@target"`
}

// MCPResolution answers resolve_host: hop which --json's fields, with the
// matched host as list_hosts shows it.
type MCPResolution struct {
	Target     string              `json:"target"`
	User       string              `json:"user,omitempty"`
	Status     resolve.Status      `json:"status"`
	Rule       resolve.Rule        `json:"rule"`
	Matched    string              `json:"matched,omitempty"`
	Host       *AgentHost          `json:"host,omitempty"`
	Route      *resolve.Route      `json:"route,omitempty"`
	RouteError string              `json:"route_error,omitempty"`
	Candidates []resolve.Candidate `json:"candidates"`
	Notes      []string            `json:"notes,omitempty"`
}

func (s *mcpServer) resolveHost(ctx context.Context, _ *mcp.CallToolRequest, in mcpTargetIn) (MCPResolution, error) {
	l, err := s.list(ctx)
	if err != nil {
		return MCPResolution{}, err
	}
	rr, err := s.resolve(ctx, in.Target, l)
	if err != nil {
		return MCPResolution{}, err
	}
	w := whichResult(rr)
	out := MCPResolution{
		Target: w.Target, User: w.User, Status: w.Status, Rule: w.Rule, Matched: w.Matched, Route: w.Route,
		RouteError: w.RouteError, Candidates: w.Candidates, Notes: w.Notes,
	}
	if out.Candidates == nil {
		out.Candidates = []resolve.Candidate{}
	}
	if rr.Host != nil {
		h := agentHost(*rr.Host, l)
		out.Host = &h
	}
	return out, nil
}

// ---- check_host and ssh_command ----

type mcpHostIn struct {
	Host string `json:"host" jsonschema:"a host name, alias or address, optionally user@host"`
}

func (s *mcpServer) checkHost(ctx context.Context, _ *mcp.CallToolRequest, in mcpHostIn) (CheckResult, error) {
	l, err := s.list(ctx)
	if err != nil {
		return CheckResult{}, err
	}
	rr, err := s.resolve(ctx, in.Host, l)
	if err != nil {
		return CheckResult{}, err
	}
	out := CheckResult{Target: in.Host, Host: rr.Result.HostName}
	out.Steps, out.OK = s.e.diagnose(ctx, rr, !s.readOnly)
	return out, nil
}

// MCPSSHCommand answers ssh_command.
type MCPSSHCommand struct {
	Host    string   `json:"host"`
	Command string   `json:"command"` // Argv quoted for a POSIX shell
	Argv    []string `json:"argv"`
	Note    string   `json:"note"`
}

func (s *mcpServer) sshCommand(ctx context.Context, _ *mcp.CallToolRequest, in mcpHostIn) (MCPSSHCommand, error) {
	l, err := s.list(ctx)
	if err != nil {
		return MCPSSHCommand{}, err
	}
	rr, err := s.resolve(ctx, in.Host, l)
	if err != nil {
		return MCPSSHCommand{}, err
	}
	t, err := connectable(rr)
	if err != nil {
		return MCPSSHCommand{}, err
	}
	addr, _ := chooseAddress(ctx, s.e, t)
	argv := append([]string{"ssh"}, s.e.sshArgs(t, addr)...)
	quoted := make([]string, len(argv))
	for i, a := range argv {
		quoted[i] = shellcmd.Quote(a)
	}
	out := MCPSSHCommand{Host: rr.Result.HostName, Argv: argv, Command: strings.Join(quoted, " "),
		Note: "To run one command without a terminal, put -T -o BatchMode=yes before -- and the command after the host."}
	if pins, _ := parsePins(rr.Host.HostKeys); len(pins) == 0 {
		out.Note = safef("No host key is pinned for %s, so ssh will refuse to connect; the user pins it from a terminal with hop trust %s.", rr.Result.HostName, rr.Result.HostName)
	}
	return out, nil
}

// ---- snippets ----

// MCPSnippets answers list_snippets.
type MCPSnippets struct {
	Snippets []SnippetView `json:"snippets"`
}

func (s *mcpServer) listSnippets(ctx context.Context, _ *mcp.CallToolRequest, _ struct{}) (MCPSnippets, error) {
	l, err := s.list(ctx)
	if err != nil {
		return MCPSnippets{}, err
	}
	out := MCPSnippets{Snippets: []SnippetView{}}
	for _, sn := range l.Snippets {
		out.Snippets = append(out.Snippets, snippetView(sn, l.Marks))
	}
	slices.SortFunc(out.Snippets, func(a, b SnippetView) int { return strings.Compare(strings.ToLower(a.Name), strings.ToLower(b.Name)) })
	return out, nil
}

// ---- exec and run_snippet ----

type mcpExecIn struct {
	Hosts    any    `json:"hosts"`
	Command  string `json:"command"`
	TimeoutS int    `json:"timeout_s,omitempty"`
}

type mcpRunSnippetIn struct {
	Name     string            `json:"name"`
	Hosts    any               `json:"hosts"`
	Params   map[string]string `json:"params,omitempty"`
	TimeoutS int               `json:"timeout_s,omitempty"`
}

// MCPExec answers exec and run_snippet: one result per host, in the order
// the hosts were given (a tag's hosts by name).
type MCPExec struct {
	Command string       `json:"command"`
	Results []ExecResult `json:"results"`
	// Warning is set when the command ran but its end could not be logged.
	Warning string `json:"warning,omitempty"`
}

func hostsArg(v any) ([]string, error) {
	var out []string
	switch v := v.(type) {
	case string:
		out = []string{v}
	case []any:
		for _, x := range v {
			s, ok := x.(string)
			if !ok {
				return nil, failf("hosts must be a string or a list of strings")
			}
			out = append(out, s)
		}
	default:
		return nil, failf("hosts must be a string or a list of strings")
	}
	for i, h := range out {
		out[i] = strings.TrimSpace(h)
		if out[i] == "" {
			return nil, failf("hosts has an empty name")
		}
	}
	if len(out) == 0 {
		return nil, failf("hosts is empty")
	}
	return out, nil
}

func timeoutArg(sec int) (time.Duration, error) {
	switch {
	case sec == 0:
		return mcpDefaultTimeout, nil
	case sec < 0 || time.Duration(sec)*time.Second > mcpMaxTimeout:
		return 0, failf("timeout_s must be between 1 and %d", int(mcpMaxTimeout/time.Second))
	}
	return time.Duration(sec) * time.Second, nil
}

func (s *mcpServer) exec(ctx context.Context, req *mcp.CallToolRequest, in mcpExecIn) (MCPExec, error) {
	targets, err := hostsArg(in.Hosts)
	if err != nil {
		return MCPExec{}, err
	}
	timeout, err := timeoutArg(in.TimeoutS)
	if err != nil {
		return MCPExec{}, err
	}
	if strings.TrimSpace(in.Command) == "" {
		return MCPExec{}, failf("command is empty")
	}
	l, err := s.list(ctx)
	if err != nil {
		return MCPExec{}, err
	}
	return s.run(ctx, req, l, "exec", "", targets, in.Command, timeout)
}

func (s *mcpServer) runSnippet(ctx context.Context, req *mcp.CallToolRequest, in mcpRunSnippetIn) (MCPExec, error) {
	targets, err := hostsArg(in.Hosts)
	if err != nil {
		return MCPExec{}, err
	}
	timeout, err := timeoutArg(in.TimeoutS)
	if err != nil {
		return MCPExec{}, err
	}
	l, err := s.list(ctx)
	if err != nil {
		return MCPExec{}, err
	}
	sn, err := findSnippet(l.Snippets, in.Name)
	if err != nil {
		return MCPExec{}, err
	}
	command, err := shellcmd.Render(sn.Command, in.Params)
	if err != nil {
		return MCPExec{}, failf("snippet %s: %v", sn.Name, err)
	}
	return s.run(ctx, req, l, "run_snippet", sn.Name, targets, command, timeout)
}

// execStep is one host an exec runs on, or why it will not.
type execStep struct {
	host string // the host's name, or the target as given when it did not resolve
	t    *target
	err  error
}

// plan expands tag: targets to the hosts agents may use, resolves each one
// as resolve_host does, and refuses what may not run: no single match, a
// host with no pinned key, or one behind a jump host with none.
func (s *mcpServer) plan(ctx context.Context, l *daemon.ListResult, targets []string) ([]execStep, error) {
	// Expand tags first, keeping the order: a tag's hosts by name, in
	// its place.
	var items []execStep
	for _, tg := range targets {
		tag, ok := strings.CutPrefix(tg, "tag:")
		if !ok {
			items = append(items, execStep{host: tg})
			continue
		}
		var tagged []string
		for _, h := range l.Hosts {
			if agentAllowed(h) && slices.ContainsFunc(h.Tags, func(t string) bool { return strings.EqualFold(t, tag) }) {
				tagged = append(tagged, h.Name)
			}
		}
		if len(tagged) == 0 {
			items = append(items, execStep{host: tg, err: failf("no host has the tag %q", tag)})
		}
		slices.SortFunc(tagged, func(a, b string) int { return strings.Compare(strings.ToLower(a), strings.ToLower(b)) })
		for _, n := range tagged {
			items = append(items, execStep{host: n})
		}
	}
	if len(items) > mcpMaxHosts {
		return nil, failf("that is %d hosts; exec runs on at most %d in one call", len(items), mcpMaxHosts)
	}
	var steps []execStep
	seen := map[string]bool{}
	for _, it := range items {
		if it.err != nil {
			steps = append(steps, it)
			continue
		}
		rr, err := s.resolve(ctx, it.host, l)
		if err != nil {
			return nil, err
		}
		t, err := runnable(rr, l)
		if err != nil {
			steps = append(steps, execStep{host: it.host, err: err})
			continue
		}
		key := rr.Host.ItemID.String() + "\x00" + t.user
		if seen[key] {
			continue // named twice, or by name and by tag: run it once
		}
		seen[key] = true
		steps = append(steps, execStep{host: rr.Result.HostName, t: t})
	}
	return steps, nil
}

// runnable is connectable, and also refuses a host with no pinned host key,
// or one reached through a jump host with none: an agent never trusts a key
// on first use. A pinned key the server no longer presents is refused by
// ssh itself (StrictHostKeyChecking yes, in the generated config).
func runnable(rr *daemon.ResolveResult, l *daemon.ListResult) (*target, error) {
	if rr.Result.Status != resolve.StatusMatched || rr.Host == nil {
		return nil, failMsg(describeUnresolved(rr.Result))
	}
	h := *rr.Host
	if pins, _ := parsePins(h.HostKeys); len(pins) == 0 {
		return nil, failf("%s has no pinned host key, and hop never trusts a host key on first use for an agent; the user pins it from a terminal with: hop trust %s", h.Name, h.Name)
	}
	for hop, seen := h, map[model.ID]bool{h.ItemID: true}; !hop.JumpHostID.IsZero(); {
		j, ok := hostByID(l, hop.JumpHostID)
		if !ok || seen[j.ItemID] {
			return nil, failf("%s is reached through a jump host that is not in the vault", h.Name)
		}
		seen[j.ItemID] = true
		if pins, _ := parsePins(j.HostKeys); len(pins) == 0 {
			if !agentAllowed(j) {
				return nil, failf("%s is reached through a jump host with no pinned host key", h.Name)
			}
			return nil, failf("%s is reached through %s, which has no pinned host key; the user pins it from a terminal with: hop trust %s", h.Name, j.Name, j.Name)
		}
		hop = j
	}
	return connectable(rr)
}

func (s *mcpServer) run(ctx context.Context, req *mcp.CallToolRequest, l *daemon.ListResult, tool, snippet string, targets []string, command string, timeout time.Duration) (MCPExec, error) {
	steps, err := s.plan(ctx, l, targets)
	if err != nil {
		return MCPExec{}, err
	}
	entry := auditEntry{Tool: tool, Snippet: snippet, Command: s.redact(command), Hosts: []string{}, TimeoutS: int(timeout / time.Second)}
	if ci := req.ClientInfo(); ci != nil {
		entry.Client, entry.ClientVersion = ci.Name, ci.Version
	}
	for _, st := range steps {
		entry.Hosts = append(entry.Hosts, st.host)
	}
	if err := s.audit.start(&entry); err != nil {
		return MCPExec{}, failf("nothing was run: the audit log could not be written (%v), and hop mcp runs nothing it cannot log", err)
	}

	out := MCPExec{Command: command, Results: make([]ExecResult, len(steps))}
	sem := make(chan struct{}, mcpParallel)
	var wg sync.WaitGroup
	for i, st := range steps {
		if st.err != nil {
			out.Results[i] = ExecResult{Host: st.host, ExitCode: ExitFailure, Error: st.err.Error()}
			continue
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			out.Results[i] = s.runOne(ctx, st.t, mcpEnvPrefix+command, timeout)
		}()
	}
	wg.Wait()

	if err := s.audit.end(&entry, out.Results, s.redact); err != nil {
		out.Warning = safef("the command ran, but the end of the run could not be written to the audit log: %v", err)
		fmt.Fprintf(s.e.Stderr, "hop mcp: warning: %s\n", oneLine(out.Warning))
	}
	return out, nil
}

func (s *mcpServer) runOne(ctx context.Context, t *target, command string, timeout time.Duration) ExecResult {
	addr, _ := chooseAddress(ctx, s.e, t)
	res, err := s.e.runRemote(ctx, t, addr, remoteRun{command: command, timeout: timeout})
	if err != nil {
		res.ExitCode, res.Error = ExitFailure, err.Error()
		return res
	}
	if res.Error == "" && ctx.Err() != nil {
		res.ExitCode, res.Error = ExitFailure, "cancelled by the client before the command finished"
		return res
	}
	if res.Error == "" && res.ExitCode == ExitFailure {
		name := t.rr.Result.HostName
		if strings.Contains(res.Stderr, "Host key verification failed") || strings.Contains(res.Stderr, "REMOTE HOST IDENTIFICATION HAS CHANGED") {
			res.Error = safef("the server does not present the host key pinned for %s, so ssh refused to connect: the machine may have been rebuilt, or something is intercepting the connection. The user checks it from a terminal with hop check %s, and re-pins with hop trust %s --replace", name, name, name)
		} else {
			res.Error = "ssh exited with status 255: it could not connect or log in, or the remote command itself exited 255; stderr has ssh's message"
		}
	}
	return res
}
