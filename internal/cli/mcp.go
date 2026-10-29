package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"os"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/dalyem/hopkey/internal/daemon"
	"github.com/dalyem/hopkey/internal/model"
	"github.com/dalyem/hopkey/internal/redact"
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
//   - the hop auth secrets and the device key passphrase leave this
//     process's environment, so neither ssh nor a daemon it starts gets
//     them;
//   - no answer carries a vault secret field: the daemon sends none.
//     Command output is the remote's, scrubbed best-effort (agentView) of
//     private key blocks, of the secret values this process was started
//     with, of the vault's secrets, which the daemon finds (daemon.OpRedact)
//     without sending them, and, unless the host's agent_output is full,
//     of well-known token formats (redact.Patterns); a host's agent_output
//     none withholds its output altogether. What a person runs (hop exec,
//     hop <target>, ssh) is never filtered;
//   - a denied host used as a jump host is named in no answer: its names
//     and addresses are masked in diagnostics (hide).
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
Output keeps the last 64 KiB of stdout and of stderr per host.
hop never returns the vault's secret fields (private keys, credential passwords, the Secret Key, auth values). Command output is what the remote printed, filtered by each host's agent_output policy: redacted (the default) replaces private key blocks, hop's own auth values, the vault's secrets and well-known token formats with [redacted by hop: <kind>]; full replaces only hop's and the vault's secrets; none returns no output, only its size and the exit code. This is best-effort: output can still hold a secret in a form hop does not recognise. Snippet commands are shown to agents as they are.`

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

	// The hop auth secrets answer that command's prompts, and the device
	// key passphrase opens a sealed key file. hop mcp has no prompt and
	// never opens the vault, so all of them leave its environment and its
	// children's: ssh, and a daemon it starts, which then comes up locked
	// on a sealed key file until the user runs hop unlock. Their values are
	// also scrubbed from every answer.
	scrubbed := append(slices.Clone(authSecretEnv), store.PassphraseEnv)
	base := e.Environ
	if base == nil {
		base = os.Environ()
		for _, name := range scrubbed {
			os.Unsetenv(name)
		}
	}
	secrets := envValues(base, scrubbed...)
	e.Environ = withoutEnv(base, scrubbed...)

	// Stdout carries the protocol and nothing else; stdin is the client's.
	in, out := e.Stdin, e.Stdout
	e.Stdout, e.Stdin = io.Discard, strings.NewReader("")
	e.StdoutTTY, e.StdinTTY = false, false

	srv, s := newMCPServer(e, *readOnly, secrets)
	t := &mcp.IOTransport{Reader: readCloser(in), Writer: writeCloser(out)}
	err = srv.Run(ctx, t)
	if err == nil || ctx.Err() != nil || errors.Is(err, io.EOF) || errors.Is(err, mcp.ErrConnectionClosed) {
		return nil
	}
	return failf("hop mcp: %s", s.auditText(err.Error()))
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

func newMCPServer(e *Env, readOnly bool, secrets []string) (*mcp.Server, *mcpServer) {
	s := &mcpServer{e: e, readOnly: readOnly, secrets: secrets, audit: newAuditLog(e)}
	srv := mcp.NewServer(&mcp.Implementation{Name: "hop", Title: "HopKey", Version: version.Version},
		&mcp.ServerOptions{Instructions: mcpInstructions})
	reads := &mcp.ToolAnnotations{ReadOnlyHint: true}
	addMCPTool(s, srv, &mcp.Tool{Name: "list_hosts", Annotations: reads, Description: "List the vault's hosts: names, aliases, addresses, user, port, tags, " +
		"description, how hop logs in (key, credential or agent-only), Tailscale status, whether a host key is pinned, " +
		"and agent_output: what of a command's output exec returns from it (redacted, full or none). Never secrets."}, s.listHosts)
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
		return srv, s
	}
	addMCPTool(s, srv, &mcp.Tool{Name: "exec", InputSchema: json.RawMessage(mcpExecSchema), Description: "Run a shell command on one or more hosts " +
		"over ssh, at most 8 at a time. No terminal, stdin closed, PAGER=cat, and a timeout per host: a prompt fails instead of waiting, so use sudo -n. " +
		"Returns per host exit_code, stdout and stderr (each the last 64 KiB) and truncated, an error when hop could not run the command, " +
		"and a warning when the output may be incomplete. Output is filtered by the host's agent_output policy (see list_hosts); " +
		"each result says which applied, counts the redactions by kind, and has withheld (sizes and a note) when the output is held back. " +
		"Hosts with no pinned host key are refused."}, s.exec)
	addMCPTool(s, srv, &mcp.Tool{Name: "run_snippet", InputSchema: json.RawMessage(mcpRunSnippetSchema), Description: "Run a saved snippet on one " +
		"or more hosts, as exec does. Each parameter value is passed in a shell variable and arrives as one word; a value never becomes shell source text. " +
		"A snippet that itself evaluates a value (eval, sh -c, arithmetic, indirect expansion) can still run it, and the snippet's author is responsible for that; " +
		"hop refuses the common cases when the snippet is saved and run. Every parameter is required and unknown ones are refused. " +
		"Snippet commands are visible to agents, so they hold no secrets; pass one as a parameter instead."}, s.runSnippet)
	return srv, s
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
// panic is recovered. Every answer and error text is scrubbed (redact),
// but for what an answer says h scrubbed, and cut to its limit, already
// (sanitized): scrubbed again, the markers in it would be, where hop
// mcp's own secret stands in them, and grow past the limit.
func addMCPTool[In, Out any](s *mcpServer, srv *mcp.Server, t *mcp.Tool, h func(context.Context, *mcp.CallToolRequest, In) (Out, error)) {
	mcp.AddTool(srv, t, func(ctx context.Context, req *mcp.CallToolRequest, in In) (_ *mcp.CallToolResult, out Out, err error) {
		defer func() {
			if r := recover(); r != nil {
				s.logf("%s panicked: %v", t.Name, r)
				var zero Out
				out, err = zero, fmt.Errorf("hop failed inside %s; see the MCP client's log for hop's stderr", t.Name)
			}
		}()
		out, err = h(ctx, req, in)
		if err != nil {
			var zero Out
			return nil, zero, errors.New(s.redact(err.Error()))
		}
		red := redactValue(s, out)
		if k, ok := any(&red).(sanitized[Out]); ok {
			k.keepSanitized(&out)
		}
		return nil, red, nil
	})
}

// sanitized is an answer some of whose text its tool scrubbed, and cut
// to its limit, already: keepSanitized puts that text back from what the
// tool returned, after redactValue.
type sanitized[T any] interface{ keepSanitized(from *T) }

// ---- secrets ----

var (
	pemBlockRe = regexp.MustCompile(`(?s)-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----.*?(?:-----END [A-Z0-9 ]*PRIVATE KEY-----|\z)`)
	pemEndRe   = regexp.MustCompile(`-----END [A-Z0-9 ]*PRIVATE KEY-----`)
)

const redacted = "[redacted by hop]"

// redact removes, best-effort, what must never reach an agent: private key
// blocks, including one cut short at either end by the 64 KiB tail, and the
// secret values this process was started with (every non-empty one, however
// short, so a short value is not handed over because it is short; such a
// value also masks the same text where it is not a secret), all of them
// found before any is replaced (redactSpans). It cannot catch a secret the
// remote prints in another form. The marks of text the agent typed (typed)
// are removed with it. Command output gets more (agentView).
func (s *mcpServer) redact(text string) string {
	return joinSpans(redactSpans([]span{{text: unmark.Replace(text)}}, s.secrets, nil))
}

// keyRedacted stands where a private key block was.
const keyRedacted = "[private key " + redacted + "]"

// span is a piece of a message: hop's own text, text the agent typed
// (typed), a marker redaction put in, a server's message that an error of
// hop's ssh client quotes, as it quotes it (quotedMsgs), or the
// placeholder a denied host's name became (maskSpans).
type span struct {
	text string
	kind spanKind
	what string // a marker's: the kind of secret it stands for (redact.Hit)
}

type spanKind int

const (
	hopText spanKind = iota
	typedText
	markerText
	quotedText
	hiddenText
)

// whole says that a span of kind k is what hop put in for a secret or a
// denied host: it is kept whole, never cut, joined or scanned again.
func (k spanKind) whole() bool { return k == markerText || k == hiddenText }

// redactSpans redacts the text of ss as one string. Every key block, every
// secret and every stretch in more (offsets into that string: what the
// daemon and redact.Patterns found) is looked for in that same text before
// any is replaced, so that none breaks up another (a secret "-" replaced in
// a block's -----BEGIN line would leave its body unrecognised), and one
// that runs across two spans, or over a block's edge, goes whole.
// Overlapping stretches become one marker span, named for the kind that
// comes first (redact.Before).
func redactSpans(ss []span, secrets []string, more []redact.Hit) []span {
	return applyHits(ss, findHits(joinSpans(ss), secrets, more))
}

// findHits is what redactSpans replaces in t: the stretches it finds, in
// order, overlapping ones joined.
func findHits(t string, secrets []string, more []redact.Hit) []redact.Hit {
	var hits []redact.Hit
	blocks := pemBlockRe.FindAllStringIndex(t, -1)
	for _, b := range blocks {
		hits = append(hits, redact.Hit{Lo: b[0], Hi: b[1], Kind: redact.KindPrivateKey})
	}
	// A block the tail cut short at its start runs from the start of the
	// text to the first END line that ends no whole block.
	for _, e := range pemEndRe.FindAllStringIndex(t, -1) {
		if !slices.ContainsFunc(blocks, func(b []int) bool { return b[0] <= e[0] && e[1] <= b[1] }) {
			hits = append(hits, redact.Hit{Lo: 0, Hi: e[1], Kind: redact.KindPrivateKey})
			break
		}
	}
	// t has had the marks of typed text taken out (unmark), so a secret
	// holding a mark rune is looked for as it stands there too (Literals).
	own := make([]redact.Secret, len(secrets))
	for i, v := range secrets {
		own[i] = redact.Secret{Kind: redact.KindHopSecret, Value: v}
	}
	hits = append(hits, redact.Literals(t, own)...)
	for _, h := range more {
		if h.Lo, h.Hi = max(h.Lo, 0), min(h.Hi, len(t)); h.Lo < h.Hi {
			hits = append(hits, h)
		}
	}
	slices.SortFunc(hits, func(a, b redact.Hit) int { return a.Lo - b.Lo })
	var out []redact.Hit
	for i := 0; i < len(hits); {
		h := hits[i]
		for i++; i < len(hits) && hits[i].Lo < h.Hi; i++ {
			h.Hi = max(h.Hi, hits[i].Hi)
			if redact.Before(hits[i].Kind, h.Kind) {
				h.Kind = hits[i].Kind
			}
		}
		out = append(out, h)
	}
	return out
}

// applyHits replaces each of hits, offsets into the text of ss in order
// and apart (findHits), with a marker span.
func applyHits(ss []span, hits []redact.Hit) []span {
	var out []span
	last := 0
	for _, h := range hits {
		out = append(cutSpans(out, ss, last, h.Lo), span{text: markerFor(h.Kind), kind: markerText, what: h.Kind})
		last = h.Hi
	}
	return cutSpans(out, ss, last, len(joinSpans(ss)))
}

// keepTail cuts ss, whose hits findHits found, to its last n bytes, and
// says whether it cut. The cut never falls inside a hit: it moves on past
// one it would split, so what is kept holds no part of a secret, only
// whole markers. Nor does it split a character (runeEnd). hits come back
// as offsets into what is kept.
func keepTail(ss []span, hits []redact.Hit, n int) ([]span, []redact.Hit, bool) {
	t := joinSpans(ss)
	size := len(t)
	if size <= n {
		return ss, hits, false
	}
	cut := size - n
	for moved := true; moved; {
		moved = false
		for _, h := range hits {
			if h.Lo < cut && cut < h.Hi {
				cut, moved = h.Hi, true
			}
		}
		if c := runeEnd(t, cut); c != cut {
			cut, moved = c, true
		}
	}
	var kept []redact.Hit
	for _, h := range hits {
		if h.Lo >= cut {
			kept = append(kept, redact.Hit{Lo: h.Lo - cut, Hi: h.Hi - cut, Kind: h.Kind})
		}
	}
	return cutSpans(nil, ss, cut, size), kept, true
}

// capSpans keeps the last n bytes of the text of ss, which redaction and
// masking have made, and says whether it cut. The cut moves on past what
// it would split: a marker, a hidden host's placeholder, an escape of
// quoted text (quotedText), a character. So what is kept is whole
// markers, escapes and runes, and at most n bytes.
func capSpans(ss []span, n int) ([]span, bool) {
	size := len(joinSpans(ss))
	if size <= n {
		return ss, false
	}
	cut, at := size-n, 0
	for i, sp := range ss {
		lo := at
		at += len(sp.text)
		switch {
		case at <= cut:
			continue
		case lo == cut:
			return ss[i:], true
		case sp.kind.whole():
			return ss[i+1:], true
		}
		k := cut - lo
		if sp.kind == hopText || sp.kind == quotedText {
			from := max(0, k-len(hiddenHost)+1)
			if j := strings.Index(sp.text[from:min(len(sp.text), k+len(hiddenHost)-1)], hiddenHost); j >= 0 {
				k = from + j + len(hiddenHost)
			}
		}
		if sp.kind == quotedText {
			k = escapeEnd(sp.text, k)
		}
		k = runeEnd(sp.text, k)
		return append([]span{{text: sp.text[k:], kind: sp.kind}}, ss[i+1:]...), true
	}
	return nil, true
}

// validSpans is ss with each byte that is not UTF-8 written as U+FFFD, as
// JSON writes it, so that capSpans measures what the agent gets.
func validSpans(ss []span) []span {
	out := slices.Clone(ss)
	for i, sp := range out {
		if utf8.ValidString(sp.text) {
			continue
		}
		var b strings.Builder
		for _, c := range sp.text {
			b.WriteRune(c) // a byte that is not UTF-8 comes as utf8.RuneError
		}
		out[i].text = b.String()
	}
	return out
}

// runeEnd is i, or, where i falls inside a character of t, the end of
// that character. Bytes that are not UTF-8 are cut where they stand.
func runeEnd(t string, i int) int {
	for s := i - 1; s >= 0 && s > i-utf8.UTFMax; s-- {
		if !utf8.RuneStart(t[s]) {
			continue
		}
		if _, n := utf8.DecodeRuneInString(t[s:]); n > 1 && s+n > i {
			return s + n
		}
		return i
	}
	return i
}

// markerFor is what stands where a secret of kind was: hop's own values
// and key blocks keep the markers they always had.
func markerFor(kind string) string {
	switch kind {
	case redact.KindPrivateKey:
		return keyRedacted
	case redact.KindHopSecret:
		return redacted
	}
	return redact.Marker(kind)
}

// countMarkers adds the marker spans of ss to counts, by kind.
func countMarkers(counts map[string]int, ss []span) {
	for _, sp := range ss {
		if sp.kind == markerText {
			counts[sp.what]++
		}
	}
}

// cutSpans appends to out the bytes from to to of run's text, each piece
// with the kind of the span it came from, joining a piece to the last span
// of out when they are of one kind.
func cutSpans(out, run []span, from, to int) []span {
	at := 0
	for _, sp := range run {
		base := at
		at += len(sp.text)
		lo, hi := max(from, base), min(to, at)
		if lo >= hi {
			continue
		}
		piece := sp.text[lo-base : hi-base]
		if k := len(out) - 1; k >= 0 && out[k].kind == sp.kind && !sp.kind.whole() {
			out[k].text += piece
		} else {
			out = append(out, span{text: piece, kind: sp.kind, what: sp.what})
		}
	}
	return out
}

func joinSpans(ss []span) string {
	var b strings.Builder
	for _, sp := range ss {
		b.WriteString(sp.text)
	}
	return b.String()
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
	if daemon.IsCode(err, daemon.CodeRevoked) {
		return errors.New("this device was revoked from the account, so hop serves no hosts or keys here; " +
			"the user can check hop auth status from a terminal, and sign in again with hop auth login")
	}
	if daemon.IsCode(err, daemon.CodeOffline) {
		return errors.New("the vault is locked because this device has been offline too long; the user connects it to the server, " +
			"then unlocks it from a terminal with hop unlock")
	}
	if daemon.IsCode(err, daemon.CodeLocked) {
		return errors.New("the vault is locked; the user unlocks it from a terminal with hop unlock, then this can be tried again")
	}
	if daemon.IsCode(err, daemon.CodeRedactBudget) {
		return errors.New("the hop daemon's redaction budget is exhausted; try again shortly")
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
	if err != nil {
		return nil, s.daemonError(err)
	}
	unmarkValue(l)
	return l, nil
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
	unmarkValue(&rr)
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
	// A tailnet node a denied host is linked to is that host by another
	// name: the daemon leaves such nodes out, and so does this, for a
	// daemon from before it did.
	res := rr.Result
	nodes := deniedNodes(l)
	before := len(res.Candidates)
	res.Candidates = slices.DeleteFunc(res.Candidates, func(c resolve.Candidate) bool {
		return (c.HostID != "" && !visible(c.HostID)) || (c.NodeID != "" && nodes[c.NodeID])
	})
	res.Notes = slices.DeleteFunc(res.Notes, func(n string) bool {
		for id := range nodes {
			if strings.Contains(n, id) {
				return true
			}
		}
		return false
	})
	if len(res.Candidates) != before {
		// What the daemon said of all the candidates, how many matched
		// or that there are suggestions, is said again of the ones left,
		// so it counts no hidden host. The status stays as it was: one
		// candidate left of an ambiguity is still not a match.
		switch {
		case len(res.Candidates) == 0:
			if res.Status == resolve.StatusAmbiguous {
				res.Status, res.Rule, res.Matched = resolve.StatusNoMatch, resolve.RuleNone, ""
			}
			res.Notes = slices.DeleteFunc(res.Notes, func(n string) bool { return strings.HasPrefix(n, suggestionsNote) })
		case res.Rule == resolve.RuleTailscale:
			res.Matched = fmt.Sprintf("%d tailscale nodes or hosts match", len(res.Candidates))
		}
	}
	res.Matched = markMatched(res)
	return &rr, nil
}

// suggestionsNote starts the note the resolver adds to the suggestions of a
// non-interactive resolution.
const suggestionsNote = "non-interactive:"

// deniedNodes is the stable IDs of the tailnet nodes that belong to hosts
// agents may not use (daemon.HostOwnsNode).
func deniedNodes(l *daemon.ListResult) map[string]bool {
	out := map[string]bool{}
	for _, h := range l.Hosts {
		if agentAllowed(h) {
			continue
		}
		all := l.Tailscale.Nodes()
		for _, n := range all {
			if daemon.HostOwnsNode(h, n, all) {
				out[n.ID] = true
			}
		}
		if h.Tailscale != nil && h.Tailscale.StableNodeID != "" {
			out[h.Tailscale.StableNodeID] = true
		}
	}
	delete(out, "")
	return out
}

// ---- hiding denied hosts in diagnostics ----

// hiddenHost replaces a denied host's name or address in text an agent
// sees.
const hiddenHost = "<hidden host>"

// masker hides the hosts agents may not use from diagnostics: ssh_problem,
// check steps, errors and ssh's stderr. A denied host can still be another
// host's jump host, and ssh and the daemon name it when it fails.
type masker struct {
	names   []string
	secrets []string // replaced before any name is hidden
}

// masker collects what names the denied hosts: names, aliases, addresses,
// and the Tailscale name, node ID and IPs of their nodes. A word an allowed
// host is also known by is not hidden: it says nothing about the denied
// host, and hiding it would garble the allowed host's answers.
func (s *mcpServer) masker(l *daemon.ListResult) masker {
	known := func(h model.Host) []string {
		out := append(resolve.Names(h), h.Addresses...)
		all := l.Tailscale.Nodes()
		for _, n := range all {
			if daemon.HostOwnsNode(h, n, all) {
				out = append(out, n.ID, n.HostName, n.DNSName, n.ShortName())
				out = append(out, n.IPs...)
			}
		}
		if t := h.Tailscale; t != nil {
			out = append(out, t.StableNodeID, t.DNSName)
		}
		return out
	}
	allowed := map[string]bool{}
	for _, h := range l.Hosts {
		if agentAllowed(h) {
			for _, n := range known(h) {
				allowed[strings.ToLower(strings.Trim(n, "[]."))] = true
			}
		}
	}
	seen := map[string]bool{}
	m := masker{secrets: s.secrets}
	for _, h := range l.Hosts {
		if agentAllowed(h) {
			continue
		}
		for _, n := range known(h) {
			n = strings.Trim(n, "[].")
			k := strings.ToLower(n)
			if n == "" || allowed[k] || seen[k] {
				continue
			}
			seen[k] = true
			m.names = append(m.names, n)
		}
	}
	slices.SortFunc(m.names, func(a, b string) int { return len(b) - len(a) })
	return m
}

// hide scrubs text as redact does, then replaces each hidden name in hop's
// own text, ignoring case, where it stands as a whole host token
// (replaceWord). Key blocks and secrets are found over the whole text
// first, so that neither a hidden name (a host called PRIVATE) nor text the
// agent typed breaks one up before it is found; what redaction put in is
// never masked.
//
// Text the agent typed, marked where hop echoes it in the message (typed),
// is not masked either: masking a denied name in "no host matches %q"
// would answer differently about it than about a name that does not exist
// ("<hidden host>." for "vault-secret."), which tells the agent the name
// is there. Everything else in text is hop's, and is masked, ssh's stderr
// included, but for the user the agent gave where ssh names it on its own
// login to the target (markSSHUser).
func (m masker) hide(text string) string { return joinSpans(m.hidden(text)) }

// hideSpans joins ss, the spans of a text redactSpans has redacted, with
// each hidden name replaced in hop's own text, as hide does.
func (m masker) hideSpans(ss []span) string { return joinSpans(m.maskSpans(ss)) }

// maskSpans is ss with each hidden name replaced in hop's own text, and
// in a server's message as hop's ssh client quotes it (quotedText), by a
// span of its own (hiddenText).
func (m masker) maskSpans(ss []span) []span {
	out := slices.Clone(ss)
	for _, n := range m.names {
		var next []span
		for _, sp := range out {
			words := findWords(sp.text, n)
			if sp.kind != hopText && sp.kind != quotedText || words == nil {
				next = append(next, sp)
				continue
			}
			last := 0
			for _, w := range words {
				if last < w[0] {
					next = append(next, span{text: sp.text[last:w[0]], kind: sp.kind})
				}
				next = append(next, span{text: hiddenHost, kind: hiddenText})
				last = w[1]
			}
			if last < len(sp.text) {
				next = append(next, span{text: sp.text[last:], kind: sp.kind})
			}
		}
		out = next
	}
	return out
}

// hidden is text with hop's own secrets replaced and the denied hosts
// hidden, as hide makes it, in its spans.
func (m masker) hidden(text string) []span {
	return m.maskSpans(redactSpans(typedSpans(text), m.secrets, nil))
}

// The marks around text the agent typed. Only hop puts them in a message
// (typed); they are removed from what the daemon answers (unmarkValue),
// from command output, and from what typed marks.
const (
	markOpen  = redact.MarkOpen
	markClose = redact.MarkClose
)

var unmark = redact.Unmark

// typed marks s as text the agent typed, for hide. It goes where a message
// echoes the agent's own input: a target, the host or user parsed from it,
// a tag's name.
func typed(s string) string { return markOpen + unmark.Replace(s) + markClose }

// typedQ is typed for s quoted as %q quotes it.
func typedQ(s string) string { return typed(strconv.Quote(s)) }

var mcpEcho = echo{quote: typedQ, login: markSSHUser, loginTail: mcpTail}

// markSSHUser removes any marks from stderr, ssh's on a login to t at
// addr, and marks the user the agent gave where ssh names it on that login
// (user@addr: Permission denied ...). The address is the target's, so the
// line is not about a jump host, whose user is the vault's.
func markSSHUser(t *target, addr, stderr string) string {
	stderr = unmark.Replace(stderr)
	if t.user == "" {
		return stderr
	}
	lines := strings.SplitAfter(stderr, "\n")
	for i, l := range lines {
		rest, ok := strings.CutPrefix(l, t.user+"@")
		if ok && len(rest) > len(addr) && strings.EqualFold(rest[:len(addr)], addr) && strings.HasPrefix(rest[len(addr):], ": ") {
			lines[i] = typed(t.user) + "@" + rest
		}
	}
	return strings.Join(lines, "")
}

// typedSpans splits text into hop's text and the agent's (typed), without
// the marks. A mark that is not one of a pair is dropped, and the text
// after it is hop's.
func typedSpans(text string) []span {
	var out []span
	for {
		i := strings.Index(text, markOpen)
		j := -1
		if i >= 0 {
			j = strings.Index(text[i:], markClose)
		}
		if j < 0 {
			return append(out, span{text: unmark.Replace(text)})
		}
		out = append(out, span{text: unmark.Replace(text[:i])},
			span{text: unmark.Replace(text[i+len(markOpen) : i+j]), kind: typedText})
		text = text[i+j+len(markClose):]
	}
}

// unmarkValue removes the marks of typed from every string in *v, an
// answer from the daemon: none of its text was typed by the agent here.
func unmarkValue[T any](v *T) {
	b, err := json.Marshal(v)
	if err != nil || !bytes.Contains(b, []byte(markOpen)) && !bytes.Contains(b, []byte(markClose)) {
		return
	}
	var out T
	if err := json.Unmarshal([]byte(unmark.Replace(string(b))), &out); err == nil {
		*v = out
	}
}

// markMatched marks the target where the resolver quotes it in what
// matched (resolve.Resolve: alias or name "x", stored address "x", "x"
// resolves to ...). Anything else it says is hop's own text.
func markMatched(res *resolve.Result) string {
	q := strconv.Quote(res.Target)
	switch res.Rule {
	case resolve.RuleAlias, resolve.RuleAddress, resolve.RulePrefix:
		for _, p := range []string{"alias or name ", "stored address ", "prefix or fuzzy match for "} {
			if res.Matched == p+q {
				return p + typed(q)
			}
		}
	case resolve.RuleDNS:
		if rest, ok := strings.CutPrefix(res.Matched, q+" resolves to "); ok {
			return typed(q) + " resolves to " + rest
		}
	}
	return res.Matched
}

// replaceWord replaces word in text, ignoring case, where it is a whole
// host token: not inside a longer name or address. A letter, digit, '_' or
// '-' next to it makes it part of a longer one, and so does a '.' with
// another of those beyond it: a denied db is not hidden inside
// db.prod.example or 10.0.0.1 inside 10.0.0.10, but is in "db:5432",
// "10.0.0.1:22" and at the end of a sentence ("... to db.").
func replaceWord(text, word, with string) string {
	words := findWords(text, word)
	if words == nil {
		return text
	}
	var b strings.Builder
	last := 0
	for _, w := range words {
		b.WriteString(text[last:w[0]])
		b.WriteString(with)
		last = w[1]
	}
	b.WriteString(text[last:])
	return b.String()
}

// findWords is where replaceWord replaces word in text: the start and end
// of each place, in order and apart.
func findWords(text, word string) [][2]int {
	inWord := func(c byte) bool {
		return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_' || c == '-'
	}
	before := func(i int) bool { // text[i-1] continues a token that ends at i
		return i > 0 && (inWord(text[i-1]) || text[i-1] == '.' && i > 1 && inWord(text[i-2]))
	}
	after := func(i int) bool { // text[i] continues a token that starts before i
		return i < len(text) && (inWord(text[i]) || text[i] == '.' && i+1 < len(text) && inWord(text[i+1]))
	}
	var out [][2]int
	for i := 0; word != "" && i+len(word) <= len(text); {
		end := i + len(word)
		if strings.EqualFold(text[i:end], word) && !before(i) && !after(end) {
			out = append(out, [2]int{i, end})
			i = end
			continue
		}
		i++
	}
	return out
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
	// AgentOutput is what of a command's output on the host exec hands
	// back: redacted, full or none (model.Host.AgentOutput).
	AgentOutput string `json:"agent_output"`
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

func agentHost(h model.Host, l *daemon.ListResult, m masker) AgentHost {
	v := hostView(h, l)
	a := AgentHost{
		Name: v.Name, Aliases: v.Aliases, Addresses: v.Addresses, User: v.User, Port: v.Port, Tags: v.Tags,
		Description: v.Description, Auth: authType(h), Route: v.Route, HostKeyPinned: len(v.HostKeys) > 0,
		HostKeys: v.HostKeys, SSHAlias: v.SSHAlias, SSHProblem: m.hide(v.SSHProblem), Sync: v.Mark,
		AgentOutput: model.AgentOutputPolicy(h),
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
	m := s.masker(l)
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
		out.Hosts = append(out.Hosts, agentHost(h, l, m))
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
	m := s.masker(l)
	out := MCPResolution{
		Target: w.Target, User: w.User, Status: w.Status, Rule: w.Rule, Matched: m.hide(w.Matched), Route: w.Route,
		RouteError: m.hide(w.RouteError), Candidates: w.Candidates,
	}
	for _, n := range w.Notes {
		out.Notes = append(out.Notes, m.hide(n))
	}
	if out.Candidates == nil {
		out.Candidates = []resolve.Candidate{}
	}
	if rr.Host != nil {
		h := agentHost(*rr.Host, l, m)
		out.Host = &h
	}
	return out, nil
}

// ---- check_host and ssh_command ----

type mcpHostIn struct {
	Host string `json:"host" jsonschema:"a host name, alias or address, optionally user@host"`
}

// mcpCheckResult answers check_host: hop check's answer, and which steps'
// details remoteText made, which addMCPTool does not scrub again.
type mcpCheckResult struct {
	CheckResult
	final []bool
}

// keepSanitized puts back the details remoteText made (addMCPTool).
func (c *mcpCheckResult) keepSanitized(from *mcpCheckResult) {
	for i, f := range from.final {
		if f && i < len(c.Steps) {
			c.Steps[i].Detail = from.Steps[i].Detail
		}
	}
}

func (s *mcpServer) checkHost(ctx context.Context, _ *mcp.CallToolRequest, in mcpHostIn) (mcpCheckResult, error) {
	l, err := s.list(ctx)
	if err != nil {
		return mcpCheckResult{}, err
	}
	rr, err := s.resolve(ctx, in.Host, l)
	if err != nil {
		return mcpCheckResult{}, err
	}
	out := mcpCheckResult{CheckResult: CheckResult{Target: in.Host, Host: rr.Result.HostName}}
	// Steps quote what the network supplied: a server's handshake error,
	// and ssh's stderr from the login, which carries what the remote
	// prints too (a banner, a shell's startup files). That is filtered as
	// exec's output is, by the host's agent_output policy (remoteText),
	// which makes the step's whole detail: it is not scrubbed again.
	policy := model.AgentOutputRedacted
	if rr.Host != nil {
		policy = model.AgentOutputPolicy(*rr.Host)
	}
	m := s.masker(l)
	ec := mcpEcho
	made := map[string]bool{}
	remote := s.remoteText(ctx, policy, m)
	ec.remote = func(lead, text string, lines int, fromGo bool) string {
		d := remote(lead, text, lines, fromGo)
		made[d] = true
		return d
	}
	out.Steps, out.OK = s.e.diagnose(ctx, rr, !s.readOnly, ec)
	out.final = make([]bool, len(out.Steps))
	for i := range out.Steps {
		if out.final[i] = made[out.Steps[i].Detail]; !out.final[i] {
			out.Steps[i].Detail = m.hide(out.Steps[i].Detail)
		}
	}
	return out, nil
}

// remoteText makes a step's detail of lead, hop's own words, and text the
// network supplied, as it came, under a host's agent_output policy: under
// none, a note that it is withheld; otherwise the text redacted as exec's
// output is (agentView), all of it checked before hop keeps its last
// lines, makes it one line (lastLines, oneLine), hides the denied hosts
// in it (maskSpans) and cuts it so that the detail is at most 64 KiB
// (capSpans), saying so when it cut. A server's message that an error of
// hop's own ssh client quotes is checked as it stands there and as the
// server sent it (quotedMsgs). Text that cannot be checked is withheld.
// Last, the whole detail, lead and notes too, is checked again as the
// agent gets it (scrubSpans): what those steps wrote, a '?' for a tab, can
// make a secret that was not there. What comes back is that detail.
func (s *mcpServer) remoteText(ctx context.Context, policy string, m masker) func(lead, text string, lines int, fromGo bool) string {
	return func(lead, text string, lines int, fromGo bool) string {
		// withheld is lead and why the text is withheld, hop's words
		// alone: its own secrets go, and the denied hosts.
		withheld := func(why ...span) string {
			ss := append(append([]span{{text: lead + "(withheld: "}}, why...), span{text: ")"})
			out, _ := s.scrubSpans(ctx, [][]span{ss}, []bool{true}, m, false, false) // no daemon: no error
			return joinSpans(out[0])
		}
		if policy == model.AgentOutputNone {
			return withheld(span{text: "the host's agent_output policy is none"})
		}
		var ss []span
		var msgs []quotedMsg
		if fromGo {
			ss, msgs = quotedMsgs(unmark.Replace(text))
		} else {
			ss = typedSpans(text)
		}
		t := joinSpans(ss)
		texts := []string{t}
		for _, q := range msgs {
			texts = append(texts, q.raw)
		}
		patterns := policy == model.AgentOutputRedacted
		found, err := s.findSecrets(ctx, texts, patterns)
		if err != nil {
			return withheld(append([]span{{text: "hop could not check it for the vault's secrets: "}}, m.hidden(err.Error())...)...)
		}
		more := found[0]
		for i, q := range msgs {
			more = append(more, q.mapHits(findHits(q.raw, m.secrets, found[i+1]))...)
		}
		hits := findHits(t, m.secrets, more)
		if len(msgs) > 0 {
			// A stretch that runs into a message ends at whole escapes.
			for i := range hits {
				for _, q := range msgs {
					hits[i].Lo, hits[i].Hi = q.unitStart(hits[i].Lo), q.unitEnd(hits[i].Hi)
				}
			}
			hits = findHits(t, nil, hits)
		}
		ss = applyHits(ss, hits)
		if lines > 0 {
			ss = lastLinesSpans(ss, lines)
		}
		for i := range ss {
			if ss[i].kind != markerText {
				ss[i].text = oneLine(ss[i].text)
			}
		}
		body, cut := capSpans(m.maskSpans(ss), tailLimit-len(lead)-len(cutNote))
		cut = cut || len(t) > tailLimit
		// The markers the last check puts in can make the detail longer
		// than the limit: then less of the text is kept, and checked again.
		for {
			head := lead
			if cut {
				head += cutNote
			}
			d, err := s.scrubSpans(ctx, [][]span{append([]span{{text: head}}, body...)}, []bool{true}, m, true, patterns)
			if err != nil {
				return withheld(append([]span{{text: "hop could not check it for the vault's secrets: "}}, m.hidden(err.Error())...)...)
			}
			over := len(joinSpans(d[0])) - tailLimit
			if over <= 0 || len(body) == 0 {
				return joinSpans(d[0])
			}
			body, _ = capSpans(body, len(joinSpans(body))-over)
			cut = true
		}
	}
}

// scrubSpans is the last check of lists, each a text as the agent gets
// it, once every step that writes it is done. In each stretch of it
// between the markers and the placeholders of hidden hosts, which stay as
// they are (spanKind.whole), hop's own secrets are replaced, and with
// check what the daemon finds (findSecrets), the token formats as well
// with patterns; in a list masked says, the denied hosts are hidden again,
// since a marker put in can leave a name standing alone. It checks again
// until it finds nothing, as each marker makes new stretches: each time,
// fewer bytes are left to check.
func (s *mcpServer) scrubSpans(ctx context.Context, lists [][]span, masked []bool, m masker, check, patterns bool) ([][]span, error) {
	lists = slices.Clone(lists)
	for {
		var texts []string
		for _, ss := range lists {
			for _, r := range openRuns(ss) {
				texts = append(texts, joinSpans(ss[r[0]:r[1]]))
			}
		}
		found := make([][]redact.Hit, len(texts))
		if check {
			var err error
			if found, err = s.findSecrets(ctx, texts, patterns); err != nil {
				return nil, err
			}
		}
		k, again := 0, false
		for i, ss := range lists {
			var out []span
			last, hit := 0, false
			for _, r := range openRuns(ss) {
				hits := findHits(texts[k], s.secrets, found[k])
				k++
				hit = hit || len(hits) > 0
				out = append(append(out, ss[last:r[0]]...), applyHits(ss[r[0]:r[1]], hits)...)
				last = r[1]
			}
			if !hit {
				continue
			}
			again, lists[i] = true, append(out, ss[last:]...)
			if masked[i] {
				lists[i] = m.maskSpans(lists[i])
			}
		}
		if !again {
			return lists, nil
		}
	}
}

// openRuns is where ss has stretches of spans that are not whole
// (spanKind.whole): the first span of each and the one after its last.
func openRuns(ss []span) [][2]int {
	var out [][2]int
	for i := 0; i < len(ss); {
		if ss[i].kind.whole() {
			i++
			continue
		}
		j := i
		for j < len(ss) && !ss[j].kind.whole() {
			j++
		}
		out = append(out, [2]int{i, j})
		i = j
	}
	return out
}

// lastLinesSpans is lastLines for ss, which redaction has made: the last
// n lines of its text, without the space around them, joined by "; ".
// The markers, which hold neither a line break nor space at either end,
// go whole.
func lastLinesSpans(ss []span, n int) []span {
	t := joinSpans(ss)
	hi := len(strings.TrimRightFunc(t, unicode.IsSpace))
	lo := len(t) - len(strings.TrimLeftFunc(t, unicode.IsSpace))
	if lo >= hi {
		return nil
	}
	from := lo
	for j := hi; n > 0; n-- {
		i := strings.LastIndexByte(t[lo:j], '\n')
		if i < 0 {
			from = lo
			break
		}
		j, from = lo+i, lo+i+1
	}
	out := cutSpans(nil, ss, from, hi)
	for i := range out {
		if out[i].kind != markerText {
			out[i].text = strings.ReplaceAll(out[i].text, "\n", "; ")
		}
	}
	return out
}

// disconnectQuote begins where x/crypto's ssh writes a server's disconnect
// message into its error: "ssh: disconnect, reason %d: %q".
const disconnectQuote = "ssh: disconnect, reason "

// quotedMsg is a server's message that a disconnect error quotes: lo and
// hi bound its quoted text, inside the quotes, in the error; raw is the
// message as the server sent it; at[j] is where, in the error, the piece
// of quoted text that wrote raw[j] begins (an escape such as \x00 or
// \u00e9 writes one or more bytes; any other byte writes itself), and
// at[len(raw)] is hi.
type quotedMsg struct {
	lo, hi int
	raw    string
	at     []int
}

// quotedMsgs splits text, an error of hop's own ssh client, into hop's
// text and, in a span of their own (quotedText), the server messages it
// quotes (disconnectQuote), as it quotes them; msgs is each of these as
// the server sent it. A message that does not unquote is withheld, and so
// is the rest of the text: hop cannot tell where the server's text ends.
func quotedMsgs(text string) (ss []span, msgs []quotedMsg) {
	var t strings.Builder
	hop := func(s string) {
		t.WriteString(s)
		if k := len(ss) - 1; k >= 0 && ss[k].kind == hopText {
			ss[k].text += s
		} else if s != "" {
			ss = append(ss, span{text: s})
		}
	}
	for {
		i := strings.Index(text, disconnectQuote)
		if i < 0 {
			break
		}
		j := i + len(disconnectQuote)
		for j < len(text) && '0' <= text[j] && text[j] <= '9' {
			j++
		}
		if !strings.HasPrefix(text[j:], ": ") {
			hop(text[:j])
			text = text[j:]
			continue
		}
		j += len(": ")
		q, err := strconv.QuotedPrefix(text[j:])
		var msg quotedMsg
		if err == nil && q[0] == '"' {
			msg, err = unquoteAt(q[1:len(q)-1], t.Len()+j+1)
		} else if err == nil {
			err = errors.New("not quoted as %q quotes")
		}
		if err != nil {
			hop(text[:j] + "(withheld: hop could not read the server's message)")
			return ss, msgs
		}
		hop(text[:j+1])
		t.WriteString(q[1 : len(q)-1])
		ss = append(ss, span{text: q[1 : len(q)-1], kind: quotedText})
		msgs = append(msgs, msg)
		hop(`"`)
		text = text[j+len(q):]
	}
	hop(text)
	return ss, msgs
}

// unquoteAt unquotes in, the text inside a pair of double quotes that
// begins at offset at of the error, keeping where each byte came from.
func unquoteAt(in string, at int) (quotedMsg, error) {
	q := quotedMsg{lo: at, hi: at + len(in)}
	var raw []byte
	for s := in; s != ""; {
		pos := at + len(in) - len(s)
		if s[0] != '\\' {
			// A byte as it stands writes itself, a character's every byte too.
			raw, q.at = append(raw, s[0]), append(q.at, pos)
			s = s[1:]
			continue
		}
		c, multibyte, rest, err := strconv.UnquoteChar(s, '"')
		if err != nil {
			return quotedMsg{}, err
		}
		n := len(raw)
		if c < utf8.RuneSelf || !multibyte {
			raw = append(raw, byte(c))
		} else {
			raw = utf8.AppendRune(raw, c)
		}
		for range len(raw) - n {
			q.at = append(q.at, pos)
		}
		s = rest
	}
	q.raw, q.at = string(raw), append(q.at, q.hi)
	return q, nil
}

// mapHits is hits, offsets into q.raw, as offsets into the error. A hit
// that does not begin and end where pieces of the quoted text do (inside
// the bytes one escape writes) cannot be told apart from its neighbours
// there, so the whole message goes in its stead.
func (q quotedMsg) mapHits(hits []redact.Hit) []redact.Hit {
	var out []redact.Hit
	for _, h := range hits {
		whole := h.Lo > 0 && q.at[h.Lo-1] == q.at[h.Lo] || h.Hi < len(q.raw) && q.at[h.Hi-1] == q.at[h.Hi]
		if whole {
			h.Lo, h.Hi = q.lo, q.hi
		} else {
			h.Lo, h.Hi = q.at[h.Lo], q.at[h.Hi]
		}
		out = append(out, h)
	}
	return out
}

// unitStart is i, or, where i falls inside an escape of q's quoted text,
// the escape's start.
func (q quotedMsg) unitStart(i int) int {
	if i <= q.lo || i >= q.hi {
		return i
	}
	k, _ := slices.BinarySearch(q.at, i)
	if q.at[k] == i {
		return i
	}
	return q.at[k-1]
}

// unitEnd is i, or, where i falls inside an escape of q's quoted text,
// the escape's end.
func (q quotedMsg) unitEnd(i int) int {
	if i <= q.lo || i >= q.hi {
		return i
	}
	k, _ := slices.BinarySearch(q.at, i)
	return q.at[k]
}

// escapeEnd is i, or, where i falls inside an escape of t, quoted text
// that begins at a whole escape, the end of that escape.
func escapeEnd(t string, i int) int {
	for at := 0; at < i; {
		if t[at] != '\\' {
			at++
			continue
		}
		_, _, rest, err := strconv.UnquoteChar(t[at:], '"')
		if err != nil {
			at++
			continue
		}
		if at = len(t) - len(rest); at > i {
			return at
		}
	}
	return i
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
	t, err := connectableAs(rr, typedQ)
	if err != nil {
		return MCPSSHCommand{}, failMsg(s.masker(l).hide(err.Error()))
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
// the hosts were given (a tag's hosts by name). exec echoes the command;
// run_snippet names the snippet, and never shows the command with the
// parameters filled in.
type MCPExec struct {
	Command string          `json:"command,omitempty"`
	Snippet string          `json:"snippet,omitempty"`
	Results []MCPExecResult `json:"results"`
	// Warning is set when the command ran but its end could not be logged.
	Warning string `json:"warning,omitempty"`
}

// keepSanitized puts back each result's stdout and stderr: agentView
// scrubbed them and cut them to their limit (addMCPTool).
func (x *MCPExec) keepSanitized(from *MCPExec) {
	for i := range min(len(x.Results), len(from.Results)) {
		x.Results[i].Stdout, x.Results[i].Stderr = from.Results[i].Stdout, from.Results[i].Stderr
	}
}

// MCPExecResult is one host's result as an agent gets it (agentView): hop
// exec --json's, filtered by the host's agent_output policy.
type MCPExecResult struct {
	ExecResult
	// AgentOutput is the policy that applied: redacted, full or none.
	// It is empty for a host the command did not run on.
	AgentOutput string `json:"agent_output,omitempty"`
	// Redactions counts the markers in the stdout and stderr returned, by
	// kind (redact.Hit): one the tail limit cut off is not counted.
	Redactions map[string]int `json:"redactions,omitempty"`
	// Withheld is set when no output is returned: the policy is none, or
	// hop could not check the output for the vault's secrets.
	Withheld *WithheldOutput `json:"withheld,omitempty"`
}

// WithheldOutput is what an agent learns of output it does not get: its
// size, and why. Truncated, beside it, says the tail limit cut the output.
type WithheldOutput struct {
	StdoutBytes int64  `json:"stdout_bytes"`
	StdoutLines int64  `json:"stdout_lines"`
	StderrBytes int64  `json:"stderr_bytes"`
	StderrLines int64  `json:"stderr_lines"`
	Note        string `json:"note"`
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
	// The audit log records the command as the agent sent it: that is
	// what it is for. redact scrubs what it can.
	out, err := s.run(ctx, req, l, auditEntry{Tool: "exec", Command: in.Command}, targets, mcpEnvPrefix+in.Command, timeout)
	out.Command = in.Command
	return out, err
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
	script, err := shellcmd.Render(sn.Command, in.Params)
	if err != nil {
		return MCPExec{}, failf("snippet %s: %v", sn.Name, err)
	}
	// A value can be a password (env PGPASSWORD={{password}}), so neither the
	// values nor the filled-in command go to the audit log or the answer:
	// the snippet's name and the parameters' names do.
	params := slices.Sorted(maps.Keys(in.Params))
	entry := auditEntry{Tool: "run_snippet", Snippet: sn.Name, Params: params}
	out, err := s.run(ctx, req, l, entry, targets, script.Assign+mcpEnvPrefix+script.Body, timeout)
	out.Snippet = sn.Name
	return out, err
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
			items = append(items, execStep{host: tg, err: failf("no host has the tag %s", typedQ(tag))})
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
		return nil, failMsg(describeUnresolvedAs(rr.Result, typedQ))
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
	return connectableAs(rr, typedQ)
}

// run runs script on targets, logging entry (Tool, and Command or Snippet
// and Params, filled in) before and after. Every string the log records
// passes through auditText.
func (s *mcpServer) run(ctx context.Context, req *mcp.CallToolRequest, l *daemon.ListResult, entry auditEntry, targets []string, script string, timeout time.Duration) (MCPExec, error) {
	steps, err := s.plan(ctx, l, targets)
	if err != nil {
		return MCPExec{}, err
	}
	entry.Command = s.auditText(entry.Command)
	entry.Snippet = s.auditText(entry.Snippet)
	for i, p := range entry.Params {
		entry.Params[i] = s.auditText(p)
	}
	entry.Hosts, entry.TimeoutS = []string{}, int(timeout/time.Second)
	if ci := req.ClientInfo(); ci != nil {
		entry.Client, entry.ClientVersion = s.auditText(ci.Name), s.auditText(ci.Version)
	}
	for _, st := range steps {
		entry.Hosts = append(entry.Hosts, s.auditText(st.host))
	}
	if err := s.audit.start(&entry); err != nil {
		return MCPExec{}, failf("nothing was run: the audit log could not be written (%v), and hop mcp runs nothing it cannot log", err)
	}

	out := MCPExec{Results: make([]MCPExecResult, len(steps))}
	sem := make(chan struct{}, mcpParallel)
	var wg sync.WaitGroup
	m := s.masker(l)
	for i, st := range steps {
		if st.err != nil {
			out.Results[i] = MCPExecResult{ExecResult: ExecResult{Host: st.host, ExitCode: ExitFailure, Error: m.hide(st.err.Error())}}
			continue
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			// Each host's own policy applies, so one call can return the
			// output of one host and withhold another's.
			out.Results[i] = s.agentView(ctx, *st.t.rr.Host, s.runOne(ctx, st.t, script, timeout), m)
		}()
	}
	wg.Wait()

	if err := s.audit.end(&entry, out.Results, s.auditText); err != nil {
		out.Warning = safef("the command ran, but the end of the run could not be written to the audit log: %v", err)
		s.logf("warning: %s", out.Warning)
	}
	return out, nil
}

// agentView is r, the result of a command on h, as an agent gets it under
// h's agent_output policy (model.AgentOutputPolicy):
//
//   - redacted: what redact removes, the vault's secrets (the daemon finds
//     them, daemon.OpRedact) and well-known token formats
//     (redact.Patterns) are replaced, all of them found in one pass over
//     each stream (redactSpans);
//   - full: the same without the token formats: hop's and the vault's
//     secrets go whatever the policy;
//   - none: no output at all, only its size (withhold).
//
// Output that cannot be checked for the vault's secrets (the vault locked
// since, or a daemon without OpRedact) is withheld too. stderr has ssh's
// own messages as well, which name a jump host that failed, so the denied
// hosts are hidden in it (hide); stdout is the command's alone.
func (s *mcpServer) agentView(ctx context.Context, h model.Host, r ExecResult, m masker) MCPExecResult {
	out := MCPExecResult{ExecResult: r, AgentOutput: model.AgentOutputPolicy(h)}
	out.Error = m.hide(unmark.Replace(r.Error))
	if out.AgentOutput == model.AgentOutputNone {
		return withhold(out, "the host's agent_output policy is none, so hop returns none of its output to agents, only its size")
	}
	stdout, stderr := []span{{text: unmark.Replace(r.Stdout)}}, typedSpans(r.Stderr)
	more, err := s.findSecrets(ctx, []string{joinSpans(stdout), joinSpans(stderr)}, out.AgentOutput == model.AgentOutputRedacted)
	if err != nil {
		return withhold(out, "hop could not check the output for the vault's secrets, so it is withheld: "+m.hide(err.Error()))
	}
	// runOne kept twice the tail an agent gets (mcpTail), all of it
	// checked: a secret the last tailLimit bytes would begin inside is
	// found whole, and the cut moves past it (keepTail).
	tail := func(ss []span, secrets []string, more []redact.Hit) []span {
		ss, hits, cut := keepTail(ss, findHits(joinSpans(ss), secrets, more), tailLimit)
		out.Truncated = out.Truncated || cut
		return applyHits(ss, hits)
	}
	so, se := tail(stdout, s.secrets, more[0]), m.maskSpans(tail(stderr, m.secrets, more[1]))
	// A marker can be longer than what it stands for, and so can a hidden
	// host's placeholder, and JSON writes a byte that is not UTF-8 as
	// U+FFFD, three bytes (validSpans): the limit holds for what is
	// returned, and the counts are of the markers in it.
	so, se = validSpans(so), validSpans(se)
	so, cutOut := capSpans(so, tailLimit)
	se, cutErr := capSpans(se, tailLimit)
	out.Truncated = out.Truncated || cutOut || cutErr
	// What those steps wrote, a U+FFFD for a byte that is not UTF-8, and
	// where a cut makes the text begin, can make a secret that was not
	// there: both streams are checked again as the agent gets them
	// (scrubSpans), and cut again while the markers put in pass the limit.
	for {
		ss, err := s.scrubSpans(ctx, [][]span{so, se}, []bool{false, true}, m, true, out.AgentOutput == model.AgentOutputRedacted)
		if err != nil {
			return withhold(out, "hop could not check the output for the vault's secrets, so it is withheld: "+m.hide(err.Error()))
		}
		so, cutOut = capSpans(ss[0], tailLimit)
		se, cutErr = capSpans(ss[1], tailLimit)
		out.Truncated = out.Truncated || cutOut || cutErr
		if !cutOut && !cutErr {
			break
		}
	}
	out.Stdout, out.Stderr = joinSpans(so), joinSpans(se)
	counts := map[string]int{}
	countMarkers(counts, so)
	countMarkers(counts, se)
	if len(counts) > 0 {
		out.Redactions = counts
	}
	return out
}

// withhold empties r's output, and says how much there was and why.
func withhold(r MCPExecResult, why string) MCPExecResult {
	r.Withheld = &WithheldOutput{StdoutBytes: r.stdoutBytes, StdoutLines: r.stdoutLines,
		StderrBytes: r.stderrBytes, StderrLines: r.stderrLines, Note: why}
	r.Stdout, r.Stderr = "", ""
	return r
}

// findSecrets asks the daemon where the vault's secrets stand in each of
// texts, and adds, with patterns, the well-known token formats. Every
// offset is checked against its text: an answer that does not fit is an
// error, so that nothing goes out half-checked.
func (s *mcpServer) findSecrets(ctx context.Context, texts []string, patterns bool) ([][]redact.Hit, error) {
	out := make([][]redact.Hit, len(texts))
	if !slices.ContainsFunc(texts, func(t string) bool { return t != "" }) {
		return out, nil
	}
	p := daemon.RedactParams{Texts: make([][]byte, len(texts))}
	for i, t := range texts {
		p.Texts[i] = []byte(t)
	}
	var res daemon.RedactResult
	if err := call(ctx, s.e, daemon.OpRedact, p, &res); err != nil {
		return nil, s.daemonError(err)
	}
	if len(res.Hits) != len(texts) {
		return nil, failf("the daemon answered for %d texts of %d", len(res.Hits), len(texts))
	}
	for i, hits := range res.Hits {
		for _, h := range hits {
			if h.Lo < 0 || h.Hi > len(texts[i]) || h.Lo >= h.Hi || !strings.HasPrefix(h.Kind, "vault-") {
				return nil, failf("the daemon's answer does not fit the output")
			}
		}
		out[i] = hits
		if patterns {
			out[i] = append(out[i], redact.Patterns(texts[i])...)
		}
	}
	return out, nil
}

// logf writes a line to hop mcp's stderr, which the MCP client keeps in its
// log, passed through auditText: every write to it goes this way.
func (s *mcpServer) logf(format string, args ...any) {
	fmt.Fprintf(s.e.Stderr, "hop mcp: %s\n", s.auditText(fmt.Sprintf(format, args...)))
}

// auditText is a string as the audit log records it: redacted, and with
// every control character written as an escape, so the log holds no
// secret hop knows of and nothing a terminal would act on.
func (s *mcpServer) auditText(text string) string { return exact(s.redact(text)) }

// mcpTail is how much of each stream runOne keeps: twice what an agent
// gets, so that agentView checks the bytes before the cut too.
const mcpTail = 2 * tailLimit

func (s *mcpServer) runOne(ctx context.Context, t *target, command string, timeout time.Duration) ExecResult {
	addr, _ := chooseAddress(ctx, s.e, t)
	res, err := s.e.runRemote(ctx, t, addr, remoteRun{command: command, timeout: timeout, tail: mcpTail})
	res.Stderr = markSSHUser(t, addr, res.Stderr)
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
