package cli_test

import (
	"bufio"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/zalando/go-keyring"
	"golang.org/x/crypto/ssh"

	"github.com/dalyem/hopkey/internal/cli"
	"github.com/dalyem/hopkey/internal/daemon"
	"github.com/dalyem/hopkey/internal/model"
	"github.com/dalyem/hopkey/internal/store"
)

// What hop mcp filters applies to agents alone: the same remote output
// reaches a person through hop exec byte for byte.

// agentExec is exec's answer as an agent reads it, decoded by name.
type agentExec struct {
	Results []agentResult `json:"results"`
}

type agentResult struct {
	Host        string         `json:"host"`
	ExitCode    int            `json:"exit_code"`
	Stdout      string         `json:"stdout"`
	Stderr      string         `json:"stderr"`
	Truncated   bool           `json:"truncated"`
	Error       string         `json:"error"`
	AgentOutput string         `json:"agent_output"`
	Redactions  map[string]int `json:"redactions"`
	Withheld    *struct {
		StdoutBytes int64  `json:"stdout_bytes"`
		StdoutLines int64  `json:"stdout_lines"`
		StderrBytes int64  `json:"stderr_bytes"`
		StderrLines int64  `json:"stderr_lines"`
		Note        string `json:"note"`
	} `json:"withheld"`
}

const (
	vaultPassword = "hunter2-credential-password"
	githubToken   = "ghp_A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8"
	commitSHA     = "3f786850e387550fdab836ed7e6dc881de23001b"
)

// redactWorld is the e2e harness with a credential in the vault, and the
// remote's "leak" printing that credential's password, a line of the
// vault's private key, a GitHub token and a commit SHA.
func redactWorld(t *testing.T) (*e2e, string, string) {
	t.Helper()
	e := newE2E(t)
	ctx := context.Background()
	if _, err := e.store.PutCredential(ctx, model.Credential{Name: "legacy", Username: "admin", Password: vaultPassword}); err != nil {
		t.Fatal(err)
	}
	snap, err := e.store.Snapshot(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var keyLine string
	for _, l := range strings.Split(snap.Keys[0].PrivateKey, "\n") {
		if len(l) >= 40 && !strings.HasPrefix(l, "-----") {
			keyLine = l
			break
		}
	}
	if keyLine == "" {
		t.Fatal("the vault key has no body line")
	}
	leak := "db password: " + vaultPassword + "\n" + vaultPassword + "\n" + keyLine + "\n" +
		"token " + githubToken + "\ncommit " + commitSHA + "\n"
	e.server.mu.Lock()
	e.server.leak = leak
	e.server.mu.Unlock()
	return e, leak, keyLine
}

func TestHopExecShowsWhatMCPRedacts(t *testing.T) {
	e, leak, keyLine := redactWorld(t)

	// A person sees everything, on a terminal and in --json.
	if code, stdout, stderr := e.hop(t, "exec", "web-1", "--", "leak"); code != 0 || stdout != leak {
		t.Errorf("hop exec leak: exit %d, stdout %q (want the remote's bytes unchanged), stderr %q", code, stdout, stderr)
	}
	if code, _, stderr := e.hop(t, "exec", "web-1", "--", "leakerr"); code != 0 || stderr != leak {
		t.Errorf("hop exec leakerr: exit %d, stderr %q, want the remote's bytes unchanged", code, stderr)
	}
	code, stdout, _ := e.hop(t, "exec", "web-1", "--json", "--", "leak")
	var res map[string]any
	if err := json.Unmarshal([]byte(stdout), &res); err != nil || code != 0 || res["stdout"] != leak {
		t.Errorf("hop exec --json leak: exit %d, %s", code, stdout)
	}
	if _, ok := res["agent_output"]; ok {
		t.Errorf("hop exec --json grew an agent field: %s", stdout)
	}

	// An agent sees the vault's secrets and the token replaced, and the
	// rest as it was.
	m := e.startMCP(t)
	for _, cmd := range []string{"leak", "leakerr"} {
		out := mcpCall[agentExec](m, "exec", map[string]any{"hosts": "web-1", "command": cmd})
		r := out.Results[0]
		got := r.Stdout + r.Stderr
		for _, secret := range []string{vaultPassword, keyLine, githubToken} {
			if strings.Contains(got, secret) {
				t.Errorf("%s: the agent got %.20s...: %q", cmd, secret, got)
			}
		}
		for _, want := range []string{"[redacted by hop: vault-password]", "[redacted by hop: vault-private-key]", "token [redacted by hop: github-token]", "commit " + commitSHA} {
			if !strings.Contains(got, want) {
				t.Errorf("%s: no %q in %q", cmd, want, got)
			}
		}
		if r.AgentOutput != "redacted" || r.Redactions["vault-password"] != 2 || r.Redactions["github-token"] != 1 || r.Redactions["vault-private-key"] != 1 {
			t.Errorf("%s: policy %q, redactions %v", cmd, r.AgentOutput, r.Redactions)
		}
	}
}

func TestMCPAgentOutputPolicy(t *testing.T) {
	e, leak, keyLine := redactWorld(t)
	e.addHost(t, "web-3", nil)

	// none: the agent learns the size of the output, never its content.
	if code, _, stderr := e.hop(t, "edit", "web-1", "--agent-output", "none"); code != 0 {
		t.Fatalf("hop edit --agent-output none: exit %d: %s", code, stderr)
	}
	code, stdout, _ := e.hop(t, "info", "web-1")
	if code != 0 || !strings.Contains(stdout, "agent output: none") {
		t.Errorf("hop info does not show the policy:\n%s", stdout)
	}
	var info map[string]any
	_, stdout, _ = e.hop(t, "info", "web-1", "--json")
	if json.Unmarshal([]byte(stdout), &info); info["agent_output"] != "none" {
		t.Errorf("hop info --json agent_output = %v", info["agent_output"])
	}
	// hop exec is not filtered at all.
	if code, stdout, _ := e.hop(t, "exec", "web-1", "--", "leak"); code != 0 || stdout != leak {
		t.Errorf("hop exec on a none host: exit %d, %q", code, stdout)
	}

	m := e.startMCP(t)
	hosts := mcpCall[struct {
		Hosts []struct {
			Name        string `json:"name"`
			AgentOutput string `json:"agent_output"`
		} `json:"hosts"`
	}](m, "list_hosts", nil)
	policies := map[string]string{}
	for _, h := range hosts.Hosts {
		policies[h.Name] = h.AgentOutput
	}
	if policies["web-1"] != "none" || policies["web-3"] != "redacted" {
		t.Errorf("list_hosts policies: %v", policies)
	}

	for _, cmd := range []string{"leak", "leakerr"} {
		r := mcpCall[agentExec](m, "exec", map[string]any{"hosts": "web-1", "command": cmd}).Results[0]
		w := r.Withheld
		if r.Stdout != "" || r.Stderr != "" || r.AgentOutput != "none" || w == nil || r.ExitCode != 0 {
			t.Fatalf("%s on a none host: %+v", cmd, r)
		}
		bytes, lines := w.StdoutBytes, w.StdoutLines
		if cmd == "leakerr" {
			bytes, lines = w.StderrBytes, w.StderrLines
		}
		if bytes != int64(len(leak)) || lines != 5 || !strings.Contains(w.Note, "agent_output") {
			t.Errorf("%s: withheld %+v, want %d bytes in 5 lines", cmd, *w, len(leak))
		}
	}
	raw := m.raw[len(m.raw)-1]
	for _, s := range []string{vaultPassword, githubToken, commitSHA, "db password"} {
		if strings.Contains(raw, s) {
			t.Errorf("a none host's answer holds %q: %s", s, raw)
		}
	}

	// run_snippet on two hosts applies each one's policy.
	if _, err := e.store.PutSnippet(context.Background(), model.Snippet{Name: "show", Command: "leak"}); err != nil {
		t.Fatal(err)
	}
	both := mcpCall[agentExec](m, "run_snippet", map[string]any{"name": "show", "hosts": []string{"web-1", "web-3"}})
	if len(both.Results) != 2 {
		t.Fatalf("run_snippet: %+v", both)
	}
	byHost := map[string]agentResult{}
	for _, r := range both.Results {
		byHost[r.Host] = r
	}
	if r := byHost["web-1"]; r.Stdout != "" || r.AgentOutput != "none" || r.Withheld == nil {
		t.Errorf("run_snippet on the none host: %+v", r)
	}
	if r := byHost["web-3"]; r.AgentOutput != "redacted" || !strings.Contains(r.Stdout, "commit "+commitSHA) ||
		strings.Contains(r.Stdout, githubToken) || strings.Contains(r.Stdout, vaultPassword) {
		t.Errorf("run_snippet on the redacted host: %+v", r)
	}

	// full: patterns are not scanned, but the vault's secrets still go.
	if code, _, stderr := e.hop(t, "edit", "web-1", "--agent-output", "full"); code != 0 {
		t.Fatalf("hop edit --agent-output full: exit %d: %s", code, stderr)
	}
	r := mcpCall[agentExec](m, "exec", map[string]any{"hosts": "web-1", "command": "leak"}).Results[0]
	if r.AgentOutput != "full" || !strings.Contains(r.Stdout, "token "+githubToken) {
		t.Errorf("full: the token is not shown: %+v", r)
	}
	if strings.Contains(r.Stdout, vaultPassword) || strings.Contains(r.Stdout, keyLine) || r.Redactions["vault-password"] != 2 {
		t.Errorf("full: a vault secret reached the agent: %+v", r)
	}

	// Back to the default.
	if code, _, stderr := e.hop(t, "edit", "web-1", "--agent-output", "redacted"); code != 0 {
		t.Fatalf("hop edit --agent-output redacted: exit %d: %s", code, stderr)
	}
	r = mcpCall[agentExec](m, "exec", map[string]any{"hosts": "web-1", "command": "leak"}).Results[0]
	if r.AgentOutput != "redacted" || strings.Contains(r.Stdout, githubToken) {
		t.Errorf("redacted again: %+v", r)
	}
	if code, _, _ := e.hop(t, "edit", "web-1", "--agent-output", "some"); code == 0 {
		t.Error("hop edit took an unknown agent_output")
	}
}

// The audit log says which policy applied and how much was redacted, by
// kind, and never what.
func TestMCPAuditCountsRedactions(t *testing.T) {
	e, _, keyLine := redactWorld(t)
	m := e.startMCP(t)
	mcpCall[agentExec](m, "exec", map[string]any{"hosts": "web-1", "command": "leak"})

	raw, err := os.ReadFile(filepath.Join(e.paths.StateDir, "mcp-audit.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range []string{vaultPassword, githubToken, keyLine, commitSHA} {
		if strings.Contains(string(raw), s) {
			t.Errorf("the audit log holds %.20s...: %s", s, raw)
		}
	}
	lines := strings.Split(strings.TrimSpace(string(raw)), "\n")
	var end struct {
		Event   string `json:"event"`
		Results []struct {
			Host        string         `json:"host"`
			AgentOutput string         `json:"agent_output"`
			Redactions  map[string]int `json:"redactions"`
		} `json:"results"`
	}
	if err := json.Unmarshal([]byte(lines[len(lines)-1]), &end); err != nil || end.Event != "end" || len(end.Results) != 1 {
		t.Fatalf("audit end line: %v %s", err, lines[len(lines)-1])
	}
	r := end.Results[0]
	if r.AgentOutput != "redacted" || r.Redactions["vault-password"] != 2 || r.Redactions["github-token"] != 1 || r.Redactions["vault-private-key"] != 1 {
		t.Errorf("audit result: %+v", r)
	}
}

// The daemon holds the account's Secret Key while the vault is unlocked,
// and redacts it in every form a remote may print it, though hop mcp never
// sees the key itself.
func TestMCPRedactsTheSecretKey(t *testing.T) {
	requireSSH(t)
	keyring.MockInit()
	base, err := os.MkdirTemp("", "hk")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(base) })
	v := &vaultE2E{
		base: base, home: filepath.Join(base, "home"), dataDir: filepath.Join(base, "data"),
		paths: daemon.Paths{
			RunDir:    filepath.Join(base, "run"),
			ConfigDir: filepath.Join(base, "home", ".ssh", "hop"),
			StateDir:  filepath.Join(base, "state"),
		},
	}
	t.Cleanup(func() {
		if v.daemon != nil {
			v.daemon.Close()
		}
	})
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	block, err := ssh.MarshalPrivateKey(priv, "")
	if err != nil {
		t.Fatal(err)
	}
	keyFile := filepath.Join(base, "id_ed25519")
	if err := os.WriteFile(keyFile, pem.EncodeToMemory(block), 0o600); err != nil {
		t.Fatal(err)
	}
	srv := startSSHServer(t, signer.PublicKey())
	pin := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(srv.hostKey)))

	v.answers = []string{"a master password", "a master password"}
	code, stdout, stderr := v.hop(t, "init")
	if code != 0 {
		t.Fatalf("hop init: exit %d\n%s", code, stderr)
	}
	sk, _ := kitKeys(t, stdout)
	v.startDaemon(t)
	if code, _, stderr := v.hop(t, "key", "add", keyFile, "--name", "k"); code != 0 {
		t.Fatalf("hop key add: %d %s", code, stderr)
	}
	if code, _, stderr := v.hop(t, "add", "vh", "--address", "127.0.0.1", "--port", strconv.Itoa(srv.port),
		"--user", "deploy", "--key", "k", "--host-key", pin); code != 0 {
		t.Fatalf("hop add: %d %s", code, stderr)
	}
	bare := strings.ReplaceAll(sk, "-", "")
	secretPart := sk[strings.Index(sk[3:], "-")+4:] // after H1-HINT-
	leak := "kit " + sk + "\nlower " + strings.ToLower(sk) + "\nbare " + bare + "\nsecret part " + secretPart + "\n"
	srv.mu.Lock()
	srv.leak = leak
	srv.mu.Unlock()

	if code, stdout, _ := v.hop(t, "exec", "vh", "--", "leak"); code != 0 || stdout != leak {
		t.Errorf("hop exec: exit %d, %q, want the remote's bytes unchanged", code, stdout)
	}

	env := &cli.Env{
		Getenv: func(string) string { return "" },
		Home:   v.home, Paths: v.paths, DataDir: v.dataDir, Keyring: store.OSKeyring{},
		SSHProbeEnv: passwdShimEnv(),
		StartDaemon: func() error {
			t.Error("hop mcp tried to start a daemon")
			return errors.New("unexpected daemon start")
		},
		DialTimeout: 5 * time.Second,
	}
	m := startMCP(t, env)
	r := mcpCall[agentExec](m, "exec", map[string]any{"hosts": "vh", "command": "leak"}).Results[0]
	for _, form := range []string{sk, strings.ToLower(sk), bare, secretPart, strings.ToLower(secretPart)} {
		if strings.Contains(r.Stdout, form) {
			t.Errorf("the agent got the Secret Key as %q: %q", form, r.Stdout)
		}
	}
	for _, want := range []string{"kit [redacted by hop: vault-secret-key]\n", "lower [redacted by hop: vault-secret-key]\n",
		"bare [redacted by hop: vault-secret-key]\n", "secret part [redacted by hop: vault-secret-key]\n"} {
		if !strings.Contains(r.Stdout, want) {
			t.Errorf("no %q in %q", want, r.Stdout)
		}
	}
	if r.Redactions["vault-secret-key"] != 4 {
		t.Errorf("redactions %v", r.Redactions)
	}

	// Locked, the daemon has no secrets to redact with, and exec is refused.
	if code, _, stderr := v.hop(t, "lock"); code != 0 {
		t.Fatalf("hop lock: %d %s", code, stderr)
	}
	if msg := m.mcpError("exec", map[string]any{"hosts": "vh", "command": "leak"}); !strings.Contains(msg, "locked") {
		t.Errorf("exec while locked: %s", msg)
	}
}

// The tail limit cuts what an agent gets only after it is checked: a
// secret that the last 64 KiB would start inside goes whole, and the cut
// moves past it, so its tail is not left for a pattern to miss. A person
// still gets the remote's bytes.
func TestMCPRedactsASecretTheTailLimitCuts(t *testing.T) {
	e, _, _ := redactWorld(t)
	m := e.startMCP(t)
	// The cut keeps cli.MCPCutRoom bytes less than the 64 KiB limit: the
	// last limit-MCPCutRoom bytes begin 5 bytes before the secret's end.
	const limit = 64<<10 - cli.MCPCutRoom
	after := " " + strings.Repeat("x", limit-7) + "\n"
	for _, c := range []struct{ name, secret string }{{"password", vaultPassword}, {"token", githubToken}} {
		leak := strings.Repeat("y", 1000) + " " + c.secret + after
		e.server.mu.Lock()
		e.server.leak = leak
		e.server.mu.Unlock()
		if code, stdout, _ := e.hop(t, "exec", "web-1", "--", "leak"); code != 0 || stdout != leak {
			t.Errorf("%s: hop exec: exit %d, %d bytes, want the remote's %d unchanged", c.name, code, len(stdout), len(leak))
		}
		for _, cmd := range []string{"leak", "leakerr"} {
			r := mcpCall[agentExec](m, "exec", map[string]any{"hosts": "web-1", "command": cmd}).Results[0]
			got := r.Stdout
			if cmd == "leakerr" {
				got = r.Stderr
			}
			if tail := c.secret[len(c.secret)-5:]; strings.Contains(r.Stdout+r.Stderr, tail) {
				t.Errorf("%s %s: the agent got the secret's tail %q: %.40q...", c.name, cmd, tail, got)
			}
			if got != after || !r.Truncated || r.Withheld != nil {
				t.Errorf("%s %s: %d bytes beginning %.20q, truncated %v, withheld %v; want the %d bytes after the secret",
					c.name, cmd, len(got), got, r.Truncated, r.Withheld, len(after))
			}
		}
	}
}

// startDisconnectServer listens for ssh and answers each connection with
// a version line and then a disconnect whose message is msg, as a server
// that turns a client away does before any key is exchanged. It returns
// the port.
func startDisconnectServer(t *testing.T, msg string) int {
	return startDisconnectServerFor(t, msg, 0)
}

// startDisconnectServerFor is startDisconnectServer, except that a client
// whose version line says it is Go's (hop's host key probe) is passed
// through to the ssh server on port upstream, when that is not 0: hop
// check's probe sees that server's key, and only ssh's login is turned
// away.
func startDisconnectServerFor(t *testing.T, msg string, upstream int) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	payload := ssh.Marshal(struct {
		Reason   uint32 `sshtype:"1"`
		Message  string
		Language string
	}{Reason: 11, Message: msg})
	pad := 8 - (5+len(payload))%8
	if pad < 4 {
		pad += 8
	}
	pkt := binary.BigEndian.AppendUint32(nil, uint32(1+len(payload)+pad))
	pkt = append(append(append(pkt, byte(pad)), payload...), make([]byte, pad)...)
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				c.SetDeadline(time.Now().Add(10 * time.Second))
				// The client's version line: both ssh and Go's client send
				// it unprompted. A TCP probe sends none.
				r := bufio.NewReader(c)
				version, err := r.ReadString('\n')
				if err != nil {
					return
				}
				if upstream != 0 && strings.HasPrefix(version, "SSH-2.0-Go") {
					u, err := net.Dial("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(upstream)))
					if err != nil {
						return
					}
					defer u.Close()
					if _, err := io.WriteString(u, version); err != nil {
						return
					}
					go io.Copy(u, r)
					io.Copy(c, u)
					return
				}
				if _, err := io.WriteString(c, "SSH-2.0-test\r\n"); err != nil {
					return
				}
				if _, err := c.Write(pkt); err != nil {
					return
				}
				io.Copy(io.Discard, r)
			}()
		}
	}()
	return ln.Addr().(*net.TCPAddr).Port
}

// agentCheck is check_host's answer as an agent reads it.
type agentCheck struct {
	OK    bool `json:"ok"`
	Steps []struct {
		Name   string `json:"name"`
		Status string `json:"status"`
		Detail string `json:"detail"`
	} `json:"steps"`
}

func (c agentCheck) step(t *testing.T, name string) (status, detail string) {
	t.Helper()
	for _, s := range c.Steps {
		if s.Name == name {
			return s.Status, s.Detail
		}
	}
	t.Fatalf("no step %s in %+v", name, c.Steps)
	return "", ""
}

// What a server says while hop reads its host key is the remote's text,
// filtered by the host's policy as a command's output is, in read-only
// hop mcp too: under none no word of it reaches the agent.
func TestMCPCheckFiltersTheHandshake(t *testing.T) {
	e, _, _ := redactWorld(t)
	port := startDisconnectServer(t, "go away: db password "+vaultPassword+" token "+githubToken)
	e.addHost(t, "gate", func(h *model.Host) { h.Port = uint32(port) })
	m := e.startMCP(t, "--read-only")

	c := mcpCall[agentCheck](m, "check_host", map[string]any{"host": "gate"})
	status, detail := c.step(t, "host_key_matches")
	if status != "fail" || !strings.Contains(detail, "go away") {
		t.Fatalf("host_key_matches: %s %q, want the server's message", status, detail)
	}
	for _, s := range []string{vaultPassword, githubToken} {
		if strings.Contains(m.raw[len(m.raw)-1], s) {
			t.Errorf("redacted: the answer holds %.20s...: %q", s, detail)
		}
	}
	for _, want := range []string{"[redacted by hop: vault-password]", "[redacted by hop: github-token]"} {
		if !strings.Contains(detail, want) {
			t.Errorf("redacted: no %q in %q", want, detail)
		}
	}

	if code, _, stderr := e.hop(t, "edit", "gate", "--agent-output", "none"); code != 0 {
		t.Fatalf("hop edit --agent-output none: exit %d: %s", code, stderr)
	}
	c = mcpCall[agentCheck](m, "check_host", map[string]any{"host": "gate"})
	status, detail = c.step(t, "host_key_matches")
	if status != "fail" || c.OK {
		t.Errorf("none: host_key_matches %s, ok %v; the step still fails", status, c.OK)
	}
	for _, s := range []string{vaultPassword, githubToken, "go away", "db password", "disconnect"} {
		if strings.Contains(m.raw[len(m.raw)-1], s) {
			t.Errorf("none: the answer holds %q: %q", s, detail)
		}
	}
}

// ssh's stderr from hop check's login is scanned as the remote printed
// it, line by line, before hop joins its last lines into one: a line
// "password: ..." goes whole.
func TestMCPCheckScansLoginStderrAsPrinted(t *testing.T) {
	e, _, _ := redactWorld(t)
	e.server.mu.Lock()
	e.server.trueErr = "Last login: never\npassword: correct horse battery\n"
	e.server.mu.Unlock()
	m := e.startMCP(t)
	c := mcpCall[agentCheck](m, "check_host", map[string]any{"host": "web-1"})
	status, detail := c.step(t, "auth_ok")
	if status != "fail" || !strings.Contains(detail, "Last login: never") {
		t.Fatalf("auth_ok: %s %q, want ssh's messages", status, detail)
	}
	for _, s := range []string{"correct", "horse", "battery"} {
		if strings.Contains(detail, s) {
			t.Errorf("the agent got %q of the password: %q", s, detail)
		}
	}
	if !strings.Contains(detail, "password: [redacted by hop: secret-value]") {
		t.Errorf("no whole redaction in %q", detail)
	}
}

// When the daemon's redaction budget is spent, exec withholds the output
// rather than return it unchecked, and says why. One call on 16 hosts,
// each printing 120 KiB to stdout and to stderr, asks to check close to
// 4 MiB at once, far past the 1 MiB burst however slowly it runs.
func TestMCPWithholdsOutputPastTheRedactionBudget(t *testing.T) {
	e, _, _ := redactWorld(t)
	e.server.mu.Lock()
	e.server.leak = strings.Repeat("x", 120<<10) + "\n" + vaultPassword + "\n"
	e.server.mu.Unlock()
	hosts := []string{"web-1"}
	for i := range 15 {
		name := fmt.Sprintf("many-%d", i)
		e.addHost(t, name, nil)
		hosts = append(hosts, name)
	}
	m := e.startMCP(t)
	out := mcpCall[agentExec](m, "exec", map[string]any{"hosts": hosts, "command": "leakboth"})
	withheld := 0
	for _, r := range out.Results {
		if strings.Contains(r.Stdout+r.Stderr, vaultPassword) {
			t.Errorf("%s: the agent got the password", r.Host)
		}
		if r.Withheld == nil {
			continue
		}
		withheld++
		if r.Stdout != "" || r.Stderr != "" || !strings.Contains(r.Withheld.Note, "redaction budget is exhausted; try again shortly") {
			t.Errorf("%s: withheld %+v, stdout %d bytes", r.Host, *r.Withheld, len(r.Stdout))
		}
	}
	if withheld == 0 {
		t.Errorf("16 hosts of 240 KiB each never ran out of the daemon's 1 MiB burst: %d results", len(out.Results))
	}
}

// x/crypto writes a server's disconnect message into its error quoted
// (%q), so a password with a " or a \ in it stands there escaped. hop
// checks the message as the server sent it, under redacted and full, in
// read-only hop mcp too: no form of the password reaches the agent.
func TestMCPCheckFindsSecretsInAQuotedDisconnect(t *testing.T) {
	const password = `ab"cd\ef-quoted-vault-secret`
	e, _, _ := redactWorld(t)
	if _, err := e.store.PutCredential(context.Background(), model.Credential{Name: "quoted", Username: "admin", Password: password}); err != nil {
		t.Fatal(err)
	}
	port := startDisconnectServer(t, "go away: db password "+password+" token "+githubToken)
	e.addHost(t, "gate", func(h *model.Host) { h.Port = uint32(port) })
	for _, args := range [][]string{nil, {"--read-only"}} {
		m := e.startMCP(t, args...)
		for _, policy := range []string{"redacted", "full"} {
			if code, _, stderr := e.hop(t, "edit", "gate", "--agent-output", policy); code != 0 {
				t.Fatalf("hop edit --agent-output %s: exit %d: %s", policy, code, stderr)
			}
			name := strings.TrimSpace(strings.Join(args, " ") + " " + policy)
			c := mcpCall[agentCheck](m, "check_host", map[string]any{"host": "gate"})
			status, detail := c.step(t, "host_key_matches")
			if status != "fail" || !strings.Contains(detail, "go away: db password [redacted by hop: vault-password] token ") {
				t.Errorf("%s: host_key_matches %s %q, want the server's message with the password replaced", name, status, detail)
			}
			for _, s := range []string{password, strconv.Quote(password), `ab\"cd\\ef`, "quoted-vault-secret"} {
				if strings.Contains(detail, s) {
					t.Errorf("%s: the agent got %q: %q", name, s, detail)
				}
			}
			// full leaves token formats be; redacted replaces them.
			if got, want := strings.Contains(detail, githubToken), policy == "full"; got != want {
				t.Errorf("%s: token shown %v, want %v: %q", name, got, want, detail)
			}
		}
	}
}

// ssh prints what a server says during its login escaped, and not as
// x/crypto does: a disconnect's message through its log, which doubles a
// backslash and writes other control bytes and every non-ASCII byte in
// octal (strnvis VIS_SAFE|VIS_OCTAL), and a banner with the backslash as
// it is but those bytes in octal too (fmprintf). Both forms here are what
// the OpenSSH 9.2 client prints. hop finds the vault's password in each,
// under redacted and full: no form of it reaches the agent.
func TestMCPCheckFindsSecretsSSHEscaped(t *testing.T) {
	const password = "pw\\vault\tsecret\x01\u00e9-zq9-login"
	const logForm = `pw\\vault` + "\t" + `secret\001\303\251-zq9-login`
	const bannerForm = `pw\vault` + "\t" + `secret\001\303\251-zq9-login`
	const bannerUTF8 = `pw\vault` + "\t" + "secret\\001\u00e9-zq9-login"
	e, _, _ := redactWorld(t)
	if _, err := e.store.PutCredential(context.Background(), model.Credential{Name: "escaped", Username: "admin", Password: password}); err != nil {
		t.Fatal(err)
	}
	e.server.mu.Lock()
	e.server.banner = "Welcome. db password " + password + "\n"
	e.server.trueErr = "startup failed\n"
	e.server.mu.Unlock()
	port := startDisconnectServerFor(t, "go away: db password "+password, e.server.port)
	e.addHost(t, "gate", func(h *model.Host) { h.Port = uint32(port) })
	m := e.startMCP(t)
	for _, host := range []string{"web-1", "gate"} {
		for _, policy := range []string{"redacted", "full"} {
			if code, _, stderr := e.hop(t, "edit", host, "--agent-output", policy); code != 0 {
				t.Fatalf("hop edit %s --agent-output %s: exit %d: %s", host, policy, code, stderr)
			}
			name := host + " " + policy
			c := mcpCall[agentCheck](m, "check_host", map[string]any{"host": host})
			status, detail := c.step(t, "auth_ok")
			if status != "fail" || !strings.Contains(detail, "db password [redacted by hop: vault-password]") {
				t.Errorf("%s: auth_ok %s %q, want ssh's stderr with the password replaced", name, status, detail)
			}
			for _, s := range []string{password, logForm, bannerForm, bannerUTF8, "zq9"} {
				if strings.Contains(detail, s) || strings.Contains(m.raw[len(m.raw)-1], s) {
					t.Errorf("%s: the agent got %q: %q", name, s, detail)
				}
			}
		}
	}
}

// hop mcp's check keeps twice the tail of ssh's stderr from its login,
// checks all of it, and only then cuts to the last 64 KiB, as exec does:
// a password the cut would split goes whole, and the detail says that
// earlier output was cut. A person's hop check is unchanged.
func TestMCPCheckScansLoginStderrBeforeTheTailCut(t *testing.T) {
	e, _, _ := redactWorld(t)
	// The last 64 KiB begin 5 bytes before the password's end.
	pad := strings.Repeat("x", 65531)
	e.server.mu.Lock()
	e.server.trueErr = vaultPassword + pad
	e.server.mu.Unlock()
	tail := vaultPassword[len(vaultPassword)-5:]
	if _, stdout, _ := e.hop(t, "check", "web-1"); !strings.Contains(stdout, tail+"xxxx") || strings.Contains(stdout, "earlier output cut") {
		t.Errorf("hop check: no %q before the padding, or a cut noted, in %.200q", tail, stdout)
	}
	m := e.startMCP(t)
	c := mcpCall[agentCheck](m, "check_host", map[string]any{"host": "web-1"})
	status, detail := c.step(t, "auth_ok")
	if status != "fail" || !strings.HasSuffix(detail, "xxxxxxxx") {
		t.Fatalf("auth_ok: %s %.200q, want ssh's stderr", status, detail)
	}
	if rest := strings.TrimRight(detail, "x"); !strings.HasSuffix(rest, "ssh did not log in: (earlier output cut) ") || strings.Contains(detail, tail) {
		t.Errorf("the agent got part of the password: %.200q", rest)
	}
}

// The 64 KiB limit holds for what an agent gets, after the markers are in:
// a one-character password repeated 65,536 times is 2 MiB of markers, cut
// to whole ones, and the counts are of the markers returned.
func TestMCPOutputLimitHoldsAfterRedaction(t *testing.T) {
	e := newE2E(t)
	if _, err := e.store.PutCredential(context.Background(), model.Credential{Name: "short", Username: "admin", Password: "Q"}); err != nil {
		t.Fatal(err)
	}
	leak := strings.Repeat("Q", 64<<10)
	e.server.mu.Lock()
	e.server.leak = leak
	e.server.mu.Unlock()
	if code, stdout, _ := e.hop(t, "exec", "web-1", "--", "leak"); code != 0 || stdout != leak {
		t.Errorf("hop exec: exit %d, %d bytes, want the remote's %d unchanged", code, len(stdout), len(leak))
	}
	m := e.startMCP(t)
	const marker = "[redacted by hop: vault-password]"
	for _, cmd := range []string{"leak", "leakerr"} {
		r := mcpCall[agentExec](m, "exec", map[string]any{"hosts": "web-1", "command": cmd}).Results[0]
		got := r.Stdout
		if cmd == "leakerr" {
			got = r.Stderr
		}
		if len(got) > 64<<10 || len(got) < 60<<10 || !r.Truncated || !utf8.ValidString(got) {
			t.Errorf("%s: %d bytes, truncated %v, valid UTF-8 %v; want at most 64 KiB, cut", cmd, len(got), r.Truncated, utf8.ValidString(got))
		}
		if rest := strings.ReplaceAll(got, marker, ""); rest != "" {
			t.Errorf("%s: %d bytes that are not whole markers: %.40q", cmd, len(rest), rest)
		}
		if n := strings.Count(got, marker); r.Redactions["vault-password"] != n {
			t.Errorf("%s: redactions %v, but %d markers returned", cmd, r.Redactions, n)
		}
	}
}

// The tail cut never splits a character: the agent gets whole runes, not
// a stray byte the JSON encoding turns into U+FFFD.
func TestMCPTailCutKeepsWholeRunes(t *testing.T) {
	e := newE2E(t)
	// 80,001 bytes: the last 64 KiB, less cli.MCPCutRoom, begin inside an
	// é.
	leak := strings.Repeat("é", 40000) + "\n"
	e.server.mu.Lock()
	e.server.leak = leak
	e.server.mu.Unlock()
	m := e.startMCP(t)
	for _, cmd := range []string{"leak", "leakerr"} {
		r := mcpCall[agentExec](m, "exec", map[string]any{"hosts": "web-1", "command": cmd}).Results[0]
		got := r.Stdout
		if cmd == "leakerr" {
			got = r.Stderr
		}
		if want := strings.Repeat("é", (64<<10-cli.MCPCutRoom)/2-1) + "\n"; got != want || !r.Truncated {
			t.Errorf("%s: %d bytes beginning %.8q, truncated %v; want the last %d bytes, whole runes", cmd, len(got), got, r.Truncated, len(want))
		}
	}
}

// A vault password written with a backslash, `left\nright`, stands as it
// is in what ssh's stderr prints, and in the error hop's own ssh client
// makes of a server's disconnect message holding a newline, which %q
// writes `left\nright`. hop looks for it in the text as it came as well
// as in the server's message unquoted: under redacted and full, in both,
// the password is replaced, not decoded into a form that hides it.
func TestMCPCheckFindsALiteralBackslashSecret(t *testing.T) {
	const password = `left\nright`
	e, _, _ := redactWorld(t)
	if _, err := e.store.PutCredential(context.Background(), model.Credential{Name: "backslash", Username: "admin", Password: password}); err != nil {
		t.Fatal(err)
	}
	e.server.mu.Lock()
	e.server.trueErr = `ssh: disconnect, reason 2: "` + password + `"` + "\n"
	e.server.mu.Unlock()
	port := startDisconnectServer(t, "go away left\nright")
	e.addHost(t, "gate", func(h *model.Host) { h.Port = uint32(port) })
	m := e.startMCP(t)
	for _, c := range []struct{ host, step, want string }{
		{"web-1", "auth_ok", `ssh did not log in: ssh: disconnect, reason 2: "[redacted by hop: vault-password]"`},
		{"gate", "host_key_matches", `"go away [redacted by hop: vault-password]"`},
	} {
		for _, policy := range []string{"redacted", "full"} {
			if code, _, stderr := e.hop(t, "edit", c.host, "--agent-output", policy); code != 0 {
				t.Fatalf("hop edit %s --agent-output %s: exit %d: %s", c.host, policy, code, stderr)
			}
			name := c.host + " " + policy
			status, detail := mcpCall[agentCheck](m, "check_host", map[string]any{"host": c.host}).step(t, c.step)
			if status != "fail" || !strings.Contains(detail, c.want) {
				t.Errorf("%s: %s %s %q, want %q in it", name, c.step, status, detail, c.want)
			}
			if strings.Contains(detail, password) || strings.Contains(detail, "right") {
				t.Errorf("%s: the agent got the password: %q", name, detail)
			}
		}
	}
}

// What exec returns is not scrubbed a second time on its way out: the
// markers it put in stay whole, however often hop mcp's own secret
// stands in them, so the 64 KiB limit and the counts hold for what the
// agent gets.
func TestMCPDoesNotRescanItsOwnMarkers(t *testing.T) {
	e := newE2E(t)
	leak := strings.Repeat("e", 64<<10)
	e.server.mu.Lock()
	e.server.leak = leak
	e.server.mu.Unlock()
	if code, stdout, _ := e.hop(t, "exec", "web-1", "--", "leak"); code != 0 || stdout != leak {
		t.Errorf("hop exec: exit %d, %d bytes, want the remote's %d unchanged", code, len(stdout), len(leak))
	}
	env := e.env(t, nil, nil, nil)
	env.Environ = append(os.Environ(), "HOP_KIT_CONFIRM=e")
	m := startMCP(t, env)
	const marker = "[redacted by hop]"
	for _, cmd := range []string{"leak", "leakerr"} {
		r := mcpCall[agentExec](m, "exec", map[string]any{"hosts": "web-1", "command": cmd}).Results[0]
		got := r.Stdout
		if cmd == "leakerr" {
			got = r.Stderr
		}
		if len(got) > 64<<10 || len(got) < 60<<10 || !r.Truncated {
			t.Errorf("%s: %d bytes, truncated %v; want at most 64 KiB, cut", cmd, len(got), r.Truncated)
		}
		if rest := strings.ReplaceAll(got, marker, ""); rest != "" {
			t.Errorf("%s: %d bytes that are not whole markers: %.60q", cmd, len(rest), rest)
		}
		if n := strings.Count(got, marker); r.Redactions["hop-secret"] != n || len(r.Redactions) != 1 {
			t.Errorf("%s: redactions %v, but %d markers returned", cmd, r.Redactions, n)
		}
	}
}

// check_host's limit holds for the detail as the agent gets it: a server
// message of 20,000 NUL bytes is 80,000 bytes once x/crypto quotes it,
// and the detail is cut to 64 KiB, at a whole escape, and says so.
func TestMCPCheckLimitHoldsAfterQuoting(t *testing.T) {
	e := newE2E(t)
	port := startDisconnectServer(t, strings.Repeat("\x00", 20000))
	e.addHost(t, "gate", func(h *model.Host) { h.Port = uint32(port) })
	m := e.startMCP(t)
	status, detail := mcpCall[agentCheck](m, "check_host", map[string]any{"host": "gate"}).step(t, "host_key_matches")
	const lead = "could not read the server's host key: (earlier output cut) "
	if status != "fail" || len(detail) > 64<<10 || !strings.HasPrefix(detail, lead) {
		t.Fatalf("host_key_matches: %s, %d bytes beginning %.80q; want at most 64 KiB, the cut noted", status, len(detail), detail)
	}
	body, ok := strings.CutSuffix(strings.TrimPrefix(detail, lead), `"`)
	if !ok || len(body) < 60<<10 || strings.ReplaceAll(body, `\x00`, "") != "" {
		t.Errorf("%d bytes after the note, beginning %.20q: want whole \\x00 escapes and the closing quote", len(body), body)
	}
}

// JSON writes each byte of output that is not UTF-8 as U+FFFD, three
// bytes: the 64 KiB limit holds for what the agent decodes. A person's
// hop exec still gets the bytes.
func TestMCPOutputLimitHoldsForBytesNotUTF8(t *testing.T) {
	e := newE2E(t)
	leak := strings.Repeat("\xff", 30000) + "\n"
	e.server.mu.Lock()
	e.server.leak = leak
	e.server.mu.Unlock()
	if code, stdout, _ := e.hop(t, "exec", "web-1", "--", "leak"); code != 0 || stdout != leak {
		t.Errorf("hop exec: exit %d, %d bytes, want the remote's %d unchanged", code, len(stdout), len(leak))
	}
	m := e.startMCP(t)
	for _, cmd := range []string{"leak", "leakerr"} {
		r := mcpCall[agentExec](m, "exec", map[string]any{"hosts": "web-1", "command": cmd}).Results[0]
		got := r.Stdout
		if cmd == "leakerr" {
			got = r.Stderr
		}
		if len(got) > 64<<10 || len(got) < 60<<10 || !r.Truncated || strings.Trim(got, "�") != "\n" {
			t.Errorf("%s: %d bytes, truncated %v, ending %q; want at most 64 KiB of U+FFFD, cut", cmd, len(got), r.Truncated, got[max(0, len(got)-8):])
		}
	}
}

// mcpWithSecret is hop mcp started with value as one of hop's own secrets
// (HOP_KIT_CONFIRM), which it scrubs from every answer.
func mcpWithSecret(t *testing.T, e *e2e, value string) *mcpSession {
	t.Helper()
	env := e.env(t, nil, nil, nil)
	env.Environ = append(os.Environ(), "HOP_KIT_CONFIRM="+value)
	return startMCP(t, env)
}

// What hop writes into a check's detail after it scanned the server's
// text is scanned too: oneLine turns ssh's stderr "left<TAB>right" into
// "left?right", hop's own secret, which goes as a whole. A person's hop
// check is unchanged.
func TestMCPCheckScrubsWhatFormattingMakes(t *testing.T) {
	e := newE2E(t)
	e.server.mu.Lock()
	e.server.trueErr = "left\tright\n"
	e.server.mu.Unlock()
	if _, stdout, _ := e.hop(t, "check", "web-1"); !strings.Contains(stdout, "ssh did not log in: left?right") {
		t.Errorf("hop check: no %q in %q", "ssh did not log in: left?right", stdout)
	}
	m := mcpWithSecret(t, e, "left?right")
	for _, policy := range []string{"redacted", "full"} {
		if code, _, stderr := e.hop(t, "edit", "web-1", "--agent-output", policy); code != 0 {
			t.Fatalf("hop edit --agent-output %s: exit %d: %s", policy, code, stderr)
		}
		status, detail := mcpCall[agentCheck](m, "check_host", map[string]any{"host": "web-1"}).step(t, "auth_ok")
		if want := "ssh did not log in: [redacted by hop]"; status != "fail" || detail != want {
			t.Errorf("%s: auth_ok %s %q, want %q", policy, status, detail, want)
		}
		if raw := m.raw[len(m.raw)-1]; strings.Contains(raw, "left") || strings.Contains(raw, "right") {
			t.Errorf("%s: the agent got part of the secret: %.300s", policy, raw)
		}
	}
}

// hop's own words in a check's detail, the lead and the note on what is
// withheld, are scrubbed as the server's text is: hop's secret "ssh"
// stands nowhere in what the agent gets, under every policy. A person's
// hop check is unchanged.
func TestMCPCheckScrubsItsOwnWords(t *testing.T) {
	e := newE2E(t)
	e.server.mu.Lock()
	e.server.trueErr = "startup failed\n"
	e.server.mu.Unlock()
	if _, stdout, _ := e.hop(t, "check", "web-1"); !strings.Contains(stdout, "ssh did not log in: startup failed") {
		t.Errorf("hop check: no %q in %q", "ssh did not log in: startup failed", stdout)
	}
	m := mcpWithSecret(t, e, "ssh")
	for _, c := range []struct{ policy, want string }{
		{"redacted", "[redacted by hop] did not log in: startup failed"},
		{"full", "[redacted by hop] did not log in: startup failed"},
		{"none", "[redacted by hop] did not log in: (withheld: the host's agent_output policy is none)"},
	} {
		if code, _, stderr := e.hop(t, "edit", "web-1", "--agent-output", c.policy); code != 0 {
			t.Fatalf("hop edit --agent-output %s: exit %d: %s", c.policy, code, stderr)
		}
		status, detail := mcpCall[agentCheck](m, "check_host", map[string]any{"host": "web-1"}).step(t, "auth_ok")
		if status != "fail" || detail != c.want {
			t.Errorf("%s: auth_ok %s %q, want %q", c.policy, status, detail, c.want)
		}
	}
	// The note on what is withheld names nothing hop could not scrub.
	m = mcpWithSecret(t, e, "withheld")
	status, detail := mcpCall[agentCheck](m, "check_host", map[string]any{"host": "web-1"}).step(t, "auth_ok")
	if want := "ssh did not log in: ([redacted by hop]: the host's agent_output policy is none)"; status != "fail" || detail != want {
		t.Errorf("none, secret %q: auth_ok %s %q, want %q", "withheld", status, detail, want)
	}
}

// exec's streams are scanned after hop writes each byte that is not
// UTF-8 as U+FFFD, as the agent gets them: output "a\xffb" is hop's
// secret "a�b" there, and goes as a whole. A person's hop exec gets
// the bytes.
func TestMCPExecScrubsWhatEncodingMakes(t *testing.T) {
	e := newE2E(t)
	leak := "a\xffb\n"
	e.server.mu.Lock()
	e.server.leak = leak
	e.server.mu.Unlock()
	if code, stdout, _ := e.hop(t, "exec", "web-1", "--", "leak"); code != 0 || stdout != leak {
		t.Errorf("hop exec: exit %d, stdout %q, want %q", code, stdout, leak)
	}
	m := mcpWithSecret(t, e, "a�b")
	for _, cmd := range []string{"leak", "leakerr"} {
		r := mcpCall[agentExec](m, "exec", map[string]any{"hosts": "web-1", "command": cmd}).Results[0]
		got := r.Stdout
		if cmd == "leakerr" {
			got = r.Stderr
		}
		if got != "[redacted by hop]\n" || r.Redactions["hop-secret"] != 1 {
			t.Errorf("%s: %q, redactions %v; want the secret replaced and counted", cmd, got, r.Redactions)
		}
	}
}
