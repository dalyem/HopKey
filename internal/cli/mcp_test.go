package cli_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"golang.org/x/crypto/ssh"

	"github.com/dalyem/hopkey/internal/cli"
	"github.com/dalyem/hopkey/internal/daemon"
	"github.com/dalyem/hopkey/internal/model"
)

// These tests run hop mcp as a client would: cli.Run with "mcp", speaking
// MCP over pipes, against the e2e harness (a daemon in this process, the
// system ssh client and an in-process ssh server) or the fake daemon.

// mcpEnvPrefix is what hop mcp puts before every command it runs.
const mcpEnvPrefix = "export PAGER=cat GIT_PAGER=cat SYSTEMD_PAGER=cat; "

// lockedBuffer is a bytes.Buffer safe for the server's goroutines.
type lockedBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (l *lockedBuffer) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}

func (l *lockedBuffer) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.String()
}

// mcpSession is a client connected to a hop mcp. raw collects every answer
// as JSON, for the secret scan.
type mcpSession struct {
	t      *testing.T
	cs     *mcp.ClientSession
	stderr *lockedBuffer

	mu  sync.Mutex
	raw []string
}

// startMCP runs hop mcp with args in env and connects a client to it. The
// server must exit 0 once the client closes.
func startMCP(t *testing.T, env *cli.Env, args ...string) *mcpSession {
	t.Helper()
	clientIn, serverOut := io.Pipe()
	serverIn, clientOut := io.Pipe()
	stderr := &lockedBuffer{}
	env.Stdin, env.Stdout, env.Stderr = serverIn, serverOut, stderr
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan int, 1)
	go func() {
		code := cli.Run(ctx, append([]string{"mcp"}, args...), env)
		serverOut.Close()
		done <- code
	}()
	client := mcp.NewClient(&mcp.Implementation{Name: "mcp-test-client", Version: "1.2.3"}, nil)
	cs, err := client.Connect(ctx, &mcp.IOTransport{Reader: clientIn, Writer: clientOut}, nil)
	if err != nil {
		cancel()
		t.Fatalf("connecting to hop mcp: %v (stderr %q)", err, stderr.String())
	}
	t.Cleanup(func() {
		cs.Close()
		clientOut.Close()
		select {
		case code := <-done:
			if code != 0 {
				t.Errorf("hop mcp exited %d after the client closed; stderr %q", code, stderr.String())
			}
		case <-time.After(15 * time.Second):
			t.Error("hop mcp did not exit after the client closed")
		}
		cancel()
	})
	return &mcpSession{t: t, cs: cs, stderr: stderr}
}

func (e *e2e) startMCP(t *testing.T, args ...string) *mcpSession {
	t.Helper()
	return startMCP(t, e.env(t, nil, nil, nil), args...)
}

// call calls a tool and returns its result, recording the raw answer.
func (m *mcpSession) call(name string, args map[string]any) *mcp.CallToolResult {
	m.t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	res, err := m.cs.CallTool(ctx, &mcp.CallToolParams{Name: name, Arguments: args})
	if err != nil {
		m.t.Fatalf("%s %v: protocol error %v", name, args, err)
	}
	b, _ := json.Marshal(res)
	m.mu.Lock()
	m.raw = append(m.raw, name+": "+string(b))
	m.mu.Unlock()
	return res
}

func toolText(res *mcp.CallToolResult) string {
	var sb strings.Builder
	for _, c := range res.Content {
		if tc, ok := c.(*mcp.TextContent); ok {
			sb.WriteString(tc.Text)
		}
	}
	return sb.String()
}

// mcpCall calls a tool that must succeed and decodes its structured answer.
func mcpCall[T any](m *mcpSession, name string, args map[string]any) T {
	m.t.Helper()
	res := m.call(name, args)
	if res.IsError {
		m.t.Fatalf("%s %v: tool error: %s", name, args, toolText(res))
	}
	b, err := json.Marshal(res.StructuredContent)
	if err != nil {
		m.t.Fatal(err)
	}
	var v T
	if err := json.Unmarshal(b, &v); err != nil {
		m.t.Fatalf("%s: %v\n%s", name, err, b)
	}
	return v
}

// mcpError calls a tool that must fail and returns the error text.
func (m *mcpSession) mcpError(name string, args map[string]any) string {
	m.t.Helper()
	res := m.call(name, args)
	if !res.IsError {
		m.t.Fatalf("%s %v succeeded, want a tool error: %s", name, args, toolText(res))
	}
	return toolText(res)
}

// refused calls a tool with arguments it must refuse, as a tool error or
// as invalid params, and returns the message.
func (m *mcpSession) refused(name string, args map[string]any) string {
	m.t.Helper()
	res, err := m.cs.CallTool(context.Background(), &mcp.CallToolParams{Name: name, Arguments: args})
	if err != nil {
		return err.Error()
	}
	if !res.IsError {
		m.t.Errorf("%s %v succeeded: %s", name, args, toolText(res))
	}
	return toolText(res)
}

func (m *mcpSession) toolNames() []string {
	m.t.Helper()
	res, err := m.cs.ListTools(context.Background(), nil)
	if err != nil {
		m.t.Fatal(err)
	}
	b, _ := json.Marshal(res)
	m.mu.Lock()
	m.raw = append(m.raw, "tools/list: "+string(b))
	m.mu.Unlock()
	var names []string
	for _, tool := range res.Tools {
		names = append(names, tool.Name)
	}
	slices.Sort(names)
	return names
}

func (e *e2e) pin() string {
	e.server.mu.Lock()
	defer e.server.mu.Unlock()
	return strings.TrimSpace(string(ssh.MarshalAuthorizedKey(e.server.hostKey)))
}

// addHost puts a host on the test ssh server into the vault, pinned to the
// server's key unless mod says otherwise.
func (e *e2e) addHost(t *testing.T, name string, mod func(*model.Host)) model.Host {
	t.Helper()
	h := model.Host{
		Name: name, Addresses: []string{"127.0.0.1"}, Port: uint32(e.server.port), User: "deploy",
		KeyID: e.keyID, Route: "auto", AgentAccess: "allow", HostKeys: []string{e.pin()},
	}
	if mod != nil {
		mod(&h)
	}
	saved, err := e.store.PutHost(context.Background(), h)
	if err != nil {
		t.Fatal(err)
	}
	return saved
}

func execResults(t *testing.T, out cli.MCPExec) map[string]cli.ExecResult {
	t.Helper()
	m := map[string]cli.ExecResult{}
	for _, r := range out.Results {
		if _, dup := m[r.Host]; dup {
			t.Errorf("host %s has two results", r.Host)
		}
		m[r.Host] = r
	}
	return m
}

var (
	readTools = []string{"check_host", "list_hosts", "list_snippets", "resolve_host", "ssh_command"}
	allTools  = []string{"check_host", "exec", "list_hosts", "list_snippets", "resolve_host", "run_snippet", "ssh_command"}
)

func TestMCPToolsAndReadOnly(t *testing.T) {
	e := newE2E(t)
	if got := e.startMCP(t).toolNames(); !slices.Equal(got, allTools) {
		t.Errorf("tools = %v, want %v", got, allTools)
	}
	ro := e.startMCP(t, "--read-only")
	if got := ro.toolNames(); !slices.Equal(got, readTools) {
		t.Errorf("--read-only tools = %v, want %v", got, readTools)
	}
	// Calling one that is not offered is refused, and nothing runs.
	ctx := context.Background()
	res, err := ro.cs.CallTool(ctx, &mcp.CallToolParams{Name: "exec", Arguments: map[string]any{"hosts": "web-1", "command": "echo ok"}})
	if err == nil && !res.IsError {
		t.Errorf("exec in --read-only answered %s", toolText(res))
	}
	// check_host does not log in, which would run a command.
	check := mcpCall[cli.CheckResult](ro, "check_host", map[string]any{"host": "web-1"})
	last := check.Steps[len(check.Steps)-1]
	if last.Name != "auth_ok" || last.Status != "skipped" || !check.OK {
		t.Errorf("read-only check: ok=%v steps=%+v", check.OK, check.Steps)
	}
	if got := e.server.commands(); len(got) != 0 {
		t.Errorf("read-only mode ran %q", got)
	}
}

func TestMCPListAndResolveHosts(t *testing.T) {
	e := newE2E(t)
	e.addHost(t, "db-1", func(h *model.Host) {
		h.Tags = []string{"db"}
		h.Description = "primary database"
		h.Addresses = []string{"192.0.2.7"}
	})
	m := e.startMCP(t)

	list := mcpCall[cli.MCPHosts](m, "list_hosts", nil)
	var names []string
	for _, h := range list.Hosts {
		names = append(names, h.Name)
	}
	if !slices.Equal(names, []string{"db-1", "web-1", "web-2"}) {
		t.Fatalf("list_hosts = %v", names)
	}
	web1, web2 := list.Hosts[1], list.Hosts[2]
	if !web1.HostKeyPinned || web2.HostKeyPinned || web1.Auth != "key" || web1.Key != "deploy-key" || web1.User != "deploy" ||
		web1.SSHAlias != "web-1" || len(web1.HostKeys) != 1 {
		t.Errorf("web-1 = %+v, web-2 = %+v", web1, web2)
	}
	if got := mcpCall[cli.MCPHosts](m, "list_hosts", map[string]any{"tag": "DB"}); len(got.Hosts) != 1 || got.Hosts[0].Name != "db-1" {
		t.Errorf("tag DB = %+v", got.Hosts)
	}
	if got := mcpCall[cli.MCPHosts](m, "list_hosts", map[string]any{"query": "Primary"}); len(got.Hosts) != 1 || got.Hosts[0].Name != "db-1" {
		t.Errorf("query Primary = %+v", got.Hosts)
	}

	r := mcpCall[cli.MCPResolution](m, "resolve_host", map[string]any{"target": "root@web-1"})
	if r.Status != "matched" || r.Host == nil || r.Host.Name != "web-1" || r.User != "root" || r.Route == nil {
		t.Errorf("resolve root@web-1 = %+v", r)
	}
	// Two hosts share 127.0.0.1: candidates, never a pick.
	r = mcpCall[cli.MCPResolution](m, "resolve_host", map[string]any{"target": "127.0.0.1"})
	if r.Status != "ambiguous" || r.Host != nil || len(r.Candidates) != 2 {
		t.Errorf("resolve 127.0.0.1 = %+v", r)
	}
	// A prefix is a suggestion, as in hop which --json.
	r = mcpCall[cli.MCPResolution](m, "resolve_host", map[string]any{"target": "web"})
	if r.Status != "no_match" || r.Host != nil || len(r.Candidates) != 2 {
		t.Errorf("resolve web = %+v", r)
	}
}

func TestMCPDeniedHostsAreInvisible(t *testing.T) {
	e := newE2E(t)
	e.addHost(t, "vault-secret", func(h *model.Host) { h.AgentAccess = "deny"; h.Tags = []string{"web"}; h.Aliases = []string{"vs"} })
	e.addHost(t, "front-1", func(h *model.Host) { h.Tags = []string{"web"} })
	e.addHost(t, "inner", func(h *model.Host) { h.JumpHostID = mustHost(t, e, "vault-secret").ItemID })
	if _, err := e.store.PutSnippet(context.Background(), model.Snippet{Name: "up", Command: "uptime"}); err != nil {
		t.Fatal(err)
	}
	m := e.startMCP(t)

	for _, args := range []map[string]any{nil, {"tag": "web"}, {"query": "secret"}, {"query": "vs"}} {
		for _, h := range mcpCall[cli.MCPHosts](m, "list_hosts", args).Hosts {
			if h.Name == "vault-secret" {
				t.Errorf("list_hosts %v shows the denied host", args)
			}
		}
	}
	for _, target := range []string{"vault-secret", "vs", "deploy@vault-secret", "vault", "127.0.0.1"} {
		r := mcpCall[cli.MCPResolution](m, "resolve_host", map[string]any{"target": target})
		if r.Host != nil && r.Host.Name == "vault-secret" {
			t.Errorf("resolve_host %s matched the denied host", target)
		}
		for _, c := range r.Candidates {
			if c.Name == "vault-secret" {
				t.Errorf("resolve_host %s offers the denied host", target)
			}
		}
	}
	if c := mcpCall[cli.CheckResult](m, "check_host", map[string]any{"host": "vault-secret"}); c.OK || c.Steps[0].Status != "fail" {
		t.Errorf("check_host vault-secret = %+v", c)
	}
	if msg := m.mcpError("ssh_command", map[string]any{"host": "vs"}); !strings.Contains(msg, "no host matches") {
		t.Errorf("ssh_command vs: %s", msg)
	}

	out := mcpCall[cli.MCPExec](m, "exec", map[string]any{"hosts": []string{"vault-secret", "tag:web"}, "command": "echo ok"})
	res := execResults(t, out)
	if r := res["vault-secret"]; !strings.Contains(r.Error, "no host matches") {
		t.Errorf("exec on the denied host: %+v", r)
	}
	if r := res["front-1"]; r.ExitCode != 0 || r.Stdout != "ok\n" {
		t.Errorf("exec on front-1: %+v", r)
	}
	if len(out.Results) != 2 {
		t.Errorf("tag:web expanded to %+v; the denied host must be skipped", out.Results)
	}
	snip := mcpCall[cli.MCPExec](m, "run_snippet", map[string]any{"name": "up", "hosts": "vault-secret"})
	if len(snip.Results) != 1 || !strings.Contains(snip.Results[0].Error, "no host matches") {
		t.Errorf("run_snippet on the denied host: %+v", snip.Results)
	}
	// Used as a jump host it is not named either.
	h := mcpCall[cli.MCPHosts](m, "list_hosts", map[string]any{"query": "inner"})
	if len(h.Hosts) != 1 || h.Hosts[0].JumpHost == "vault-secret" {
		t.Errorf("inner = %+v", h.Hosts)
	}
	if got := e.server.commands(); len(got) != 1 {
		t.Errorf("the server ran %q, want only front-1's command", got)
	}
	// Answers that list the vault never name it. The others name it only
	// where they echo the agent's own target back.
	for _, raw := range m.raw {
		if strings.HasPrefix(raw, "list_hosts:") && (strings.Contains(raw, "vault-secret") || strings.Contains(raw, `"vs"`)) {
			t.Errorf("list_hosts names the denied host: %s", raw)
		}
	}
}

func mustHost(t *testing.T, e *e2e, name string) model.Host {
	t.Helper()
	snap, err := e.store.Snapshot(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	for _, h := range snap.Hosts {
		if h.Name == name {
			return h
		}
	}
	t.Fatalf("no host %s", name)
	return model.Host{}
}

func TestMCPRefusesUnpinnedHostsAndChangedKeys(t *testing.T) {
	e := newE2E(t)
	e.addHost(t, "behind", func(h *model.Host) { h.JumpHostID = mustHost(t, e, "web-2").ItemID })
	if _, err := e.store.PutSnippet(context.Background(), model.Snippet{Name: "up", Command: "uptime"}); err != nil {
		t.Fatal(err)
	}
	m := e.startMCP(t)

	out := mcpCall[cli.MCPExec](m, "exec", map[string]any{"hosts": []string{"web-2", "behind"}, "command": "echo ok"})
	res := execResults(t, out)
	if r := res["web-2"]; r.ExitCode != 255 || !strings.Contains(r.Error, "no pinned host key") || !strings.Contains(r.Error, "hop trust web-2") {
		t.Errorf("unpinned web-2: %+v", r)
	}
	if r := res["behind"]; !strings.Contains(r.Error, "through web-2, which has no pinned host key") || !strings.Contains(r.Error, "hop trust web-2") {
		t.Errorf("behind an unpinned jump host: %+v", r)
	}
	snip := mcpCall[cli.MCPExec](m, "run_snippet", map[string]any{"name": "up", "hosts": "web-2"})
	if len(snip.Results) != 1 || !strings.Contains(snip.Results[0].Error, "hop trust web-2") {
		t.Errorf("run_snippet on unpinned web-2: %+v", snip.Results)
	}
	// Refused before any connection: not even the key is fetched.
	if n := e.server.connections(); n != 0 {
		t.Errorf("the server saw %d connections; an unpinned host must not be contacted", n)
	}
	// ssh_command says why ssh will refuse it.
	if sc := mcpCall[cli.MCPSSHCommand](m, "ssh_command", map[string]any{"host": "web-2"}); !strings.Contains(sc.Note, "hop trust web-2") {
		t.Errorf("ssh_command web-2 note = %q", sc.Note)
	}

	// A pinned key the server no longer presents blocks the call.
	e.server.useNewHostKey(t)
	out = mcpCall[cli.MCPExec](m, "exec", map[string]any{"hosts": "web-1", "command": "echo ok"})
	if r := out.Results[0]; r.ExitCode != 255 || !strings.Contains(r.Error, "does not present the host key pinned for web-1") {
		t.Errorf("changed key: %+v", r)
	}
	if got := e.server.commands(); len(got) != 0 {
		t.Errorf("the server ran %q", got)
	}
}

func TestMCPExecOnSeveralHostsWhereOneFails(t *testing.T) {
	e := newE2E(t)
	e.addHost(t, "web-3", nil)
	// A pinned host where nothing listens.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	deadPort := ln.Addr().(*net.TCPAddr).Port
	ln.Close()
	e.addHost(t, "dead", func(h *model.Host) { h.Port = uint32(deadPort) })
	m := e.startMCP(t)

	out := mcpCall[cli.MCPExec](m, "exec", map[string]any{"hosts": []string{"web-1", "web-3", "nope", "dead", "web-1"}, "command": "echo ok", "timeout_s": 20})
	var order []string
	for _, r := range out.Results {
		order = append(order, r.Host)
	}
	if !slices.Equal(order, []string{"web-1", "web-3", "nope", "dead"}) {
		t.Errorf("results for %v; want the hosts in order, web-1 once", order)
	}
	res := execResults(t, out)
	for _, h := range []string{"web-1", "web-3"} {
		if r := res[h]; r.ExitCode != 0 || r.Stdout != "ok\n" || r.Error != "" || r.Truncated {
			t.Errorf("%s: %+v", h, r)
		}
	}
	if r := res["nope"]; r.ExitCode != 255 || !strings.Contains(r.Error, "no host matches") {
		t.Errorf("nope: %+v", r)
	}
	if r := res["dead"]; r.ExitCode != 255 || !strings.Contains(r.Error, "could not connect") || r.Stderr == "" {
		t.Errorf("dead: %+v", r)
	}
	// Every command went out with the pager settings, and no PTY.
	for _, c := range e.server.commands() {
		if c != mcpEnvPrefix+"echo ok" {
			t.Errorf("the server saw %q", c)
		}
	}
	if n := len(e.server.commands()); n != 2 {
		t.Errorf("the server ran %d commands, want 2", n)
	}
	// A remote exit status passes through.
	out = mcpCall[cli.MCPExec](m, "exec", map[string]any{"hosts": "web-1", "command": "exit 3"})
	if r := out.Results[0]; r.ExitCode != 3 || r.Error != "" {
		t.Errorf("exit 3: %+v", r)
	}
	// Bad arguments are refused, and run nothing.
	for _, args := range []map[string]any{
		{"hosts": []string{}, "command": "true"},
		{"hosts": "web-1", "command": "  "},
		{"hosts": "web-1", "command": "true", "timeout_s": 7200},
		{"hosts": 5, "command": "true"},
		{"hosts": []any{"web-1", 5}, "command": "true"},
	} {
		m.refused("exec", args)
	}
	if n := len(e.server.commands()); n != 3 {
		t.Errorf("the server ran %d commands, want 3", n)
	}
	empty := mcpCall[cli.MCPExec](m, "exec", map[string]any{"hosts": "tag:nothing-has-this", "command": "true"})
	if len(empty.Results) != 1 || !strings.Contains(empty.Results[0].Error, `no host has the tag "nothing-has-this"`) {
		t.Errorf("empty tag: %+v", empty.Results)
	}
}

func TestMCPExecKeepsTheLast64KiB(t *testing.T) {
	e := newE2E(t)
	m := e.startMCP(t)
	r := mcpCall[cli.MCPExec](m, "exec", map[string]any{"hosts": "web-1", "command": "big"}).Results[0]
	if r.ExitCode != 0 || !r.Truncated || len(r.Stdout) != 64<<10 || !strings.HasSuffix(r.Stdout, "zzzEND\n") {
		t.Errorf("big: exit=%d truncated=%v len=%d tail=%q", r.ExitCode, r.Truncated, len(r.Stdout), r.Stdout[max(0, len(r.Stdout)-10):])
	}
}

func TestMCPExecTimeoutAndClosedStdin(t *testing.T) {
	e := newE2E(t)
	m := e.startMCP(t)
	start := time.Now()
	r := mcpCall[cli.MCPExec](m, "exec", map[string]any{"hosts": "web-1", "command": "sleep", "timeout_s": 1}).Results[0]
	if d := time.Since(start); d > 10*time.Second {
		t.Errorf("took %s; timeout_s 1 should have cut it off", d)
	}
	if r.ExitCode != 255 || !strings.Contains(r.Error, "timed out after 1s") {
		t.Errorf("sleep: %+v", r)
	}
	// stdin is closed: cat ends at once instead of waiting for input.
	start = time.Now()
	r = mcpCall[cli.MCPExec](m, "exec", map[string]any{"hosts": "web-1", "command": "cat", "timeout_s": 20}).Results[0]
	if d := time.Since(start); d > 10*time.Second || r.ExitCode != 0 || r.Stdout != "" || r.Error != "" {
		t.Errorf("cat: %+v after %s", r, d)
	}
}

func TestMCPCheckHostAndSSHCommand(t *testing.T) {
	e := newE2E(t)
	m := e.startMCP(t)
	c := mcpCall[cli.CheckResult](m, "check_host", map[string]any{"host": "web-1"})
	if !c.OK || c.Host != "web-1" {
		t.Errorf("check web-1 = %+v", c)
	}
	if got := statuses(c); got["auth_ok"] != "pass" || got["host_key_matches"] != "pass" {
		t.Errorf("check web-1 steps = %v", got)
	}
	if c := mcpCall[cli.CheckResult](m, "check_host", map[string]any{"host": "web-2"}); c.OK || statuses(c)["host_key_pinned"] != "fail" {
		t.Errorf("check web-2 = %+v", c)
	}
	sc := mcpCall[cli.MCPSSHCommand](m, "ssh_command", map[string]any{"host": "web-1"})
	cfg := filepath.Join(e.paths.ConfigDir, "config")
	if sc.Host != "web-1" || len(sc.Argv) < 4 || sc.Argv[0] != "ssh" || !slices.Contains(sc.Argv, cfg) || sc.Argv[len(sc.Argv)-1] != "web-1" ||
		sc.Argv[len(sc.Argv)-2] != "--" || !strings.HasPrefix(sc.Command, "ssh -F ") {
		t.Errorf("ssh_command web-1 = %+v", sc)
	}
	// The command it gives works: ssh with it reaches the host.
	cmd := exec.Command(sc.Argv[0], append(append([]string{"-T", "-o", "BatchMode=yes"}, sc.Argv[1:]...), "echo", "ok")...)
	cmd.Env = append(withoutSSHAgent(os.Environ()), passwdShimEnv()...)
	if out, err := cmd.CombinedOutput(); err != nil || string(out) != "ok\n" {
		t.Errorf("running ssh_command's argv: %v %q", err, out)
	}
}

func withoutSSHAgent(environ []string) []string {
	return slices.DeleteFunc(slices.Clone(environ), func(kv string) bool { return strings.HasPrefix(kv, "SSH_AUTH_SOCK=") })
}

func TestMCPSnippets(t *testing.T) {
	e := newE2E(t)
	code, stdout, stderr := e.hop(t, "snippet", "add", "restart", "--description", "restart a unit", "--", "systemctl", "restart", "{{unit}}")
	if code != 0 || !strings.Contains(stdout, "parameters: unit") {
		t.Fatalf("snippet add: %d %q %q", code, stdout, stderr)
	}
	if code, _, stderr := e.hop(t, "snippet", "add", "quoted", "--", "echo '{{x}}'"); code != 255 || !strings.Contains(stderr, "inside quotes") {
		t.Errorf("snippet add with a quoted placeholder: %d %q", code, stderr)
	}
	if code, _, stderr := e.hop(t, "snippet", "add", "Restart", "--", "true"); code != 255 || !strings.Contains(stderr, "already exists") {
		t.Errorf("duplicate snippet: %d %q", code, stderr)
	}
	code, stdout, _ = e.hop(t, "snippet", "ls", "--json")
	var views []cli.SnippetView
	decodeJSON(t, stdout, &views)
	if code != 0 || len(views) != 1 || views[0].Command != "systemctl restart {{unit}}" || !slices.Equal(views[0].Params, []string{"unit"}) ||
		views[0].Description != "restart a unit" {
		t.Errorf("snippet ls --json = %d %+v", code, views)
	}
	if code, stdout, _ := e.hop(t, "snippet", "ls"); code != 0 || !strings.Contains(stdout, "restart") || !strings.Contains(stdout, "unit") {
		t.Errorf("snippet ls = %d %q", code, stdout)
	}

	m := e.startMCP(t)
	list := mcpCall[cli.MCPSnippets](m, "list_snippets", nil)
	if len(list.Snippets) != 1 || list.Snippets[0].Name != "restart" {
		t.Errorf("list_snippets = %+v", list)
	}
	out := mcpCall[cli.MCPExec](m, "run_snippet", map[string]any{"name": "restart", "hosts": []string{"web-1"}, "params": map[string]any{"unit": "my unit; rm -rf /"}})
	want := "systemctl restart 'my unit; rm -rf /'"
	if out.Command != want || out.Results[0].ExitCode != 0 {
		t.Errorf("run_snippet = %+v", out)
	}
	if got := e.server.commands(); !slices.Equal(got, []string{mcpEnvPrefix + want}) {
		t.Errorf("the server saw %q", got)
	}
	if msg := m.mcpError("run_snippet", map[string]any{"name": "restart", "hosts": "web-1"}); !strings.Contains(msg, "missing parameter(s) unit") {
		t.Errorf("missing param: %s", msg)
	}
	if msg := m.mcpError("run_snippet", map[string]any{"name": "restart", "hosts": "web-1", "params": map[string]any{"unit": "x", "lines": "3"}}); !strings.Contains(msg, "unknown parameter(s) lines") {
		t.Errorf("unknown param: %s", msg)
	}
	if msg := m.mcpError("run_snippet", map[string]any{"name": "nope", "hosts": "web-1"}); !strings.Contains(msg, "no snippet named") {
		t.Errorf("unknown snippet: %s", msg)
	}
	if n := len(e.server.commands()); n != 1 {
		t.Errorf("the server ran %d commands, want 1", n)
	}

	if code, _, stderr := e.hop(t, "snippet", "rm", "restart", "--yes"); code != 0 {
		t.Errorf("snippet rm: %d %q", code, stderr)
	}
	if list := mcpCall[cli.MCPSnippets](m, "list_snippets", nil); len(list.Snippets) != 0 {
		t.Errorf("after rm: %+v", list)
	}
}

type auditLine struct {
	Event   string   `json:"event"`
	Run     string   `json:"run"`
	Tool    string   `json:"tool"`
	Client  string   `json:"client"`
	Snippet string   `json:"snippet"`
	Hosts   []string `json:"hosts"`
	Command string   `json:"command"`
	Results []struct {
		Host     string `json:"host"`
		ExitCode int    `json:"exit_code"`
		Error    string `json:"error"`
	} `json:"results"`
}

func readAudit(t *testing.T, path string) []auditLine {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var out []auditLine
	for _, l := range strings.Split(strings.TrimSpace(string(b)), "\n") {
		var a auditLine
		if err := json.Unmarshal([]byte(l), &a); err != nil {
			t.Fatalf("audit line %q: %v", l, err)
		}
		out = append(out, a)
	}
	return out
}

func TestMCPAuditLog(t *testing.T) {
	e := newE2E(t)
	if _, err := e.store.PutSnippet(context.Background(), model.Snippet{Name: "say", Command: "echo {{what}}"}); err != nil {
		t.Fatal(err)
	}
	m := e.startMCP(t)
	mcpCall[cli.MCPExec](m, "exec", map[string]any{"hosts": []string{"web-1", "web-2"}, "command": "big"})
	mcpCall[cli.MCPExec](m, "run_snippet", map[string]any{"name": "say", "hosts": "web-1", "params": map[string]any{"what": "hi"}})

	path := filepath.Join(e.paths.StateDir, "mcp-audit.jsonl")
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Errorf("audit log mode %v, want 0600", fi.Mode().Perm())
	}
	raw, _ := os.ReadFile(path)
	if bytes.Contains(raw, []byte("zzzzzzzz")) || bytes.Contains(raw, []byte("aaaaaaaa")) {
		t.Error("the audit log holds command output")
	}
	lines := readAudit(t, path)
	if len(lines) != 4 {
		t.Fatalf("audit has %d lines, want 4: %s", len(lines), raw)
	}
	start, end := lines[0], lines[1]
	if start.Event != "start" || end.Event != "end" || start.Run == "" || start.Run != end.Run || start.Tool != "exec" ||
		start.Client != "mcp-test-client" || start.Command != "big" || !slices.Equal(start.Hosts, []string{"web-1", "web-2"}) {
		t.Errorf("exec audit: %+v / %+v", start, end)
	}
	if len(end.Results) != 2 || end.Results[0].Host != "web-1" || end.Results[0].ExitCode != 0 ||
		end.Results[1].ExitCode != 255 || !strings.Contains(end.Results[1].Error, "no pinned host key") {
		t.Errorf("exec audit results: %+v", end.Results)
	}
	if s := lines[2]; s.Tool != "run_snippet" || s.Snippet != "say" || s.Command != "echo hi" {
		t.Errorf("run_snippet audit: %+v", s)
	}

	// No log, no run.
	os.Remove(path)
	if err := os.Mkdir(path, 0o700); err != nil {
		t.Fatal(err)
	}
	before := len(e.server.commands())
	if msg := m.mcpError("exec", map[string]any{"hosts": "web-1", "command": "echo ok"}); !strings.Contains(msg, "audit log") {
		t.Errorf("exec without an audit log: %s", msg)
	}
	if msg := m.mcpError("run_snippet", map[string]any{"name": "say", "hosts": "web-1", "params": map[string]any{"what": "x"}}); !strings.Contains(msg, "audit log") {
		t.Errorf("run_snippet without an audit log: %s", msg)
	}
	if after := len(e.server.commands()); after != before {
		t.Errorf("a command ran though it could not be logged")
	}
}

// secretEnv are hop auth secrets and the device key passphrase, as a
// user's shell might hold them when an AI client starts hop mcp.
var secretEnv = map[string]string{
	"HOP_PASSWORD":          "correct-horse-battery-staple",
	"HOP_NEW_PASSWORD":      "new-horse-battery-staple",
	"HOP_SECRET_KEY":        "A3-ABCDEF-GHJKLM-NPQRST-VWXYZ2-345678-9ABCDE",
	"HOP_RECOVERY_KEY":      "R1-QWERTY-UIOPAS-DFGHJK-LZXCVB-NM2345-678912",
	"HOP_KIT_CONFIRM":       "KITCONFIRM-9ABCDE",
	"HOP_DEVICE_PASSPHRASE": "device-passphrase-for-the-key-file",
}

func withSecretEnv(base []string) []string {
	out := slices.Clone(base)
	for k, v := range secretEnv {
		out = append(out, k+"="+v)
	}
	return out
}

func TestMCPNeverReturnsSecrets(t *testing.T) {
	e := newE2E(t)
	ctx := context.Background()
	cred, err := e.store.PutCredential(ctx, model.Credential{Name: "legacy", Username: "admin", Password: "hunter2-credential-password"})
	if err != nil {
		t.Fatal(err)
	}
	e.addHost(t, "pw-host", func(h *model.Host) { h.KeyID = model.ID{}; h.CredentialID = cred.ItemID })
	if _, err := e.store.PutSnippet(ctx, model.Snippet{Name: "say", Command: "echo {{what}}"}); err != nil {
		t.Fatal(err)
	}
	snap, err := e.store.Snapshot(ctx)
	if err != nil {
		t.Fatal(err)
	}
	pem := snap.Keys[0].PrivateKey
	// The remote prints the vault's private key (a copy deployed there) and
	// the Secret Key; hop must not hand either to the agent.
	e.server.mu.Lock()
	e.server.leak = pem + "\n" + secretEnv["HOP_SECRET_KEY"] + "\n"
	e.server.mu.Unlock()

	env := e.env(t, nil, nil, nil)
	env.Environ = withSecretEnv(os.Environ())
	m := startMCP(t, env)
	m.toolNames()
	for _, c := range []struct {
		tool string
		args map[string]any
	}{
		{"list_hosts", nil},
		{"list_hosts", map[string]any{"query": "pw"}},
		{"resolve_host", map[string]any{"target": "pw-host"}},
		{"resolve_host", map[string]any{"target": "127.0.0.1"}},
		{"resolve_host", map[string]any{"target": "nothing-here"}},
		{"check_host", map[string]any{"host": "web-1"}},
		{"check_host", map[string]any{"host": "pw-host"}},
		{"ssh_command", map[string]any{"host": "pw-host"}},
		{"ssh_command", map[string]any{"host": "nothing-here"}},
		{"list_snippets", nil},
		{"exec", map[string]any{"hosts": []string{"web-1", "pw-host", "web-2", "nothing-here"}, "command": "leak"}},
		{"run_snippet", map[string]any{"name": "say", "hosts": "web-1", "params": map[string]any{"what": "x"}}},
		{"run_snippet", map[string]any{"name": "say", "hosts": "web-1", "params": map[string]any{}}},
	} {
		m.call(c.tool, c.args)
	}
	// A key cut short by the 64 KiB tail, with no BEGIN line left.
	e.server.mu.Lock()
	e.server.leak = pem[strings.Index(pem, "\n")+1:]
	e.server.mu.Unlock()
	cut := mcpCall[cli.MCPExec](m, "exec", map[string]any{"hosts": "web-1", "command": "leak"})
	if !strings.Contains(cut.Results[0].Stdout, "redacted") {
		t.Errorf("the cut key was not redacted: %q", cut.Results[0].Stdout)
	}

	secrets := []string{"hunter2-credential-password"}
	for _, v := range secretEnv {
		secrets = append(secrets, v)
	}
	for _, l := range strings.Split(pem, "\n") {
		if len(l) >= 16 && !strings.HasPrefix(l, "-----") {
			secrets = append(secrets, l)
		}
	}
	if len(secrets) < 8 {
		t.Fatalf("only %d secrets to look for", len(secrets))
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.raw) < 15 {
		t.Fatalf("only %d answers recorded", len(m.raw))
	}
	for _, raw := range m.raw {
		for _, s := range secrets {
			// Answers are JSON: look for the secret as JSON encodes it, too.
			enc, _ := json.Marshal(s)
			if strings.Contains(raw, s) || strings.Contains(raw, strings.Trim(string(enc), `"`)) {
				t.Errorf("an answer holds a secret (%.12s...): %.300s", s, raw)
			}
		}
	}
	if !slices.ContainsFunc(m.raw, func(r string) bool { return strings.Contains(r, "[private key [redacted by hop]]") }) {
		t.Error("no answer shows a redacted key; did the leak command run?")
	}
}

// hop mcp keeps the hop auth secrets from its children: the ssh it runs
// (here a stand-in that records its environment) and its own environment.
func TestMCPChildrenGetNoAuthSecrets(t *testing.T) {
	e := newE2E(t)
	dump := filepath.Join(e.base, "env")
	fake := filepath.Join(e.base, "env-ssh")
	if err := os.WriteFile(fake, []byte("#!/bin/sh\nenv > \"$HOPKEY_TEST_ENV_DUMP\"\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	env := e.env(t, nil, nil, nil)
	env.SSHBinary = fake
	env.Environ = append(withSecretEnv(os.Environ()), "HOPKEY_TEST_ENV_DUMP="+dump)
	m := startMCP(t, env)
	mcpCall[cli.MCPExec](m, "exec", map[string]any{"hosts": "web-1", "command": "true"})
	b, err := os.ReadFile(dump)
	if err != nil {
		t.Fatalf("the stand-in ssh did not run: %v", err)
	}
	for k := range secretEnv {
		if strings.Contains(string(b), k+"=") {
			t.Errorf("ssh got %s", k)
		}
	}

	// With the real process environment, the variables leave it.
	for k, v := range secretEnv {
		t.Setenv(k, v)
	}
	env = e.env(t, nil, nil, nil)
	m = startMCP(t, env)
	m.toolNames()
	for _, k := range []string{"HOP_PASSWORD", "HOP_NEW_PASSWORD", "HOP_SECRET_KEY", "HOP_RECOVERY_KEY", "HOP_KIT_CONFIRM"} {
		if v, ok := os.LookupEnv(k); ok {
			t.Errorf("hop mcp left %s=%s in its environment", k, v)
		}
	}
}

func TestMCPLockedAndAbsentVault(t *testing.T) {
	f := newFakeDaemon(t)
	f.fail(daemon.OpList, daemon.CodeLocked, "model: vault is locked; run hop unlock")
	m := startMCP(t, f.env(t, nil, nil, nil))
	for _, c := range []struct {
		tool string
		args map[string]any
	}{
		{"list_hosts", nil},
		{"resolve_host", map[string]any{"target": "x"}},
		{"exec", map[string]any{"hosts": "x", "command": "true"}},
		{"list_snippets", nil},
	} {
		if msg := m.mcpError(c.tool, c.args); !strings.Contains(msg, "vault is locked") || !strings.Contains(msg, "hop unlock") {
			t.Errorf("%s while locked: %s", c.tool, msg)
		}
	}
	// The server is still there, and answers once the vault opens.
	f.reply(daemon.OpList, daemon.ListResult{Hosts: []model.Host{}, Snippets: []model.Snippet{}})
	if got := mcpCall[cli.MCPHosts](m, "list_hosts", nil); len(got.Hosts) != 0 {
		t.Errorf("after unlock: %+v", got)
	}

	// No vault: no daemon, and none can start.
	base, err := os.MkdirTemp("", "hkn")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(base) })
	var stderr lockedBuffer
	env := &cli.Env{
		Getenv: func(string) string { return "" }, Home: filepath.Join(base, "home"), DataDir: filepath.Join(base, "data"),
		Paths:       daemon.Paths{RunDir: filepath.Join(base, "run"), ConfigDir: filepath.Join(base, "cfg"), StateDir: filepath.Join(base, "state")},
		StartDaemon: func() error { return errors.New("store: there is no vault on this device; run hop init") },
		DaemonWait:  200 * time.Millisecond,
		Stderr:      &stderr,
	}
	m = startMCP(t, env)
	for range 2 {
		if msg := m.mcpError("list_hosts", nil); !strings.Contains(msg, "no vault") || !strings.Contains(msg, "hop init") {
			t.Errorf("no vault: %s", msg)
		}
	}
}

func TestMCPInstall(t *testing.T) {
	exe := filepath.Join(t.TempDir(), "hop bin", "hop")
	run := func(args ...string) (int, string, string, [][]string) {
		var so, se bytes.Buffer
		var ran [][]string
		env := &cli.Env{
			Stdout: &so, Stderr: &se, Getenv: func(string) string { return "" }, Executable: exe,
			RunCommand: func(_ context.Context, name string, a ...string) ([]byte, error) {
				ran = append(ran, append([]string{name}, a...))
				if name == "codex" && slices.Contains(a, "--read-only") {
					return nil, fmt.Errorf("exec: %q: %w", name, exec.ErrNotFound)
				}
				return []byte("Added stdio MCP server hop\n"), nil
			},
		}
		code := cli.Run(context.Background(), append([]string{"mcp", "install"}, args...), env)
		return code, so.String(), se.String(), ran
	}

	code, stdout, _, ran := run()
	if code != 0 || len(ran) != 0 || !strings.Contains(stdout, "claude mcp add --scope user hop -- '"+exe+"' mcp") ||
		!strings.Contains(stdout, `"command": "`+exe+`"`) || !strings.Contains(stdout, "[mcp_servers.hop]") ||
		!strings.Contains(stdout, `args = ["mcp"]`) || !strings.Contains(stdout, "codex mcp add hop -- '"+exe+"' mcp") {
		t.Errorf("print: %d %q %v", code, stdout, ran)
	}
	code, _, stderr, ran := run("--client", "claude")
	if want := []string{"claude", "mcp", "add", "--scope", "user", "hop", "--", exe, "mcp"}; code != 0 || len(ran) != 1 || !slices.Equal(ran[0], want) {
		t.Errorf("claude: %d %v, want %v", code, ran, want)
	}
	if !strings.Contains(stderr, "hop: running claude mcp add") || !strings.Contains(stderr, "Added stdio MCP server hop") {
		t.Errorf("claude stderr %q", stderr)
	}
	code, _, _, ran = run("--client", "codex")
	if want := []string{"codex", "mcp", "add", "hop", "--", exe, "mcp"}; code != 0 || len(ran) != 1 || !slices.Equal(ran[0], want) {
		t.Errorf("codex: %d %v", code, ran)
	}
	code, stdout, stderr, ran = run("--client", "codex", "--read-only")
	if want := []string{"codex", "mcp", "add", "hop", "--", exe, "mcp", "--read-only"}; code != 255 || len(ran) != 1 || !slices.Equal(ran[0], want) ||
		!strings.Contains(stderr, "not on PATH") || !strings.Contains(stdout, `args = ["mcp", "--read-only"]`) {
		t.Errorf("codex not found: %d %v %q %q", code, ran, stdout, stderr)
	}
	if code, _, stderr, _ := run("--client", "vim"); code != 255 || !strings.Contains(stderr, "unknown client") {
		t.Errorf("unknown client: %d %q", code, stderr)
	}
}
