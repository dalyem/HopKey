package cli_test

import (
	"bytes"
	"context"
	"encoding/json"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/dalyem/hopkey/internal/cli"
	"github.com/dalyem/hopkey/internal/model"
)

// retag changes a host's tags and agent_access in the vault.
func (e *e2e) retag(t *testing.T, name string, tags []string, access string) {
	t.Helper()
	h := mustHost(t, e, name)
	h.Tags, h.AgentAccess = tags, access
	if _, err := e.store.PutHost(context.Background(), h); err != nil {
		t.Fatal(err)
	}
}

func hostNames(hs []cli.AgentHost) []string {
	var out []string
	for _, h := range hs {
		out = append(out, h.Name)
	}
	return out
}

// hop mcp --tag shows an agent the hosts with one of the tags, and no
// other host: it is hidden as a host agent_access denies is, in every tool.
// The proof is that each answer about the hidden host is the answer the same
// vault gives, to a server with no --tag, once the host is denied.
func TestMCPTagScopeHidesAHostLikeADeniedOne(t *testing.T) {
	e := newE2E(t)
	e.retag(t, "web-1", []string{"work"}, "allow")
	e.retag(t, "web-2", []string{"work"}, "allow")
	e.addHost(t, "other-box", func(h *model.Host) {
		h.Tags = []string{"personal", "web"}
		h.Aliases = []string{"ob"}
		h.Addresses = []string{"192.0.2.9"}
	})
	e.addHost(t, "inner", func(h *model.Host) {
		h.Tags = []string{"work"}
		h.JumpHostID = mustHost(t, e, "other-box").ItemID
	})
	if _, err := e.store.PutSnippet(context.Background(), model.Snippet{Name: "up", Command: "uptime"}); err != nil {
		t.Fatal(err)
	}

	type probe struct {
		tool string
		args map[string]any
	}
	var probes []probe
	for _, args := range []map[string]any{nil, {"tag": "personal"}, {"tag": "web"}, {"tag": "work"}, {"query": "other"}, {"query": "192.0.2.9"}, {"query": "ob"}} {
		probes = append(probes, probe{"list_hosts", args})
	}
	for _, target := range []string{
		"other-box", "OTHER-box", "ob", "deploy@other-box", "other-box:22", "192.0.2.9", "other", "tag:personal", "tag:web", "tag:work",
	} {
		probes = append(probes,
			probe{"resolve_host", map[string]any{"target": target}},
			probe{"check_host", map[string]any{"host": target}},
			probe{"ssh_command", map[string]any{"host": target}},
			probe{"exec", map[string]any{"hosts": target, "command": "echo ok"}},
			probe{"exec", map[string]any{"hosts": []string{"web-1", target}, "command": "echo ok"}},
			probe{"run_snippet", map[string]any{"name": "up", "hosts": target}},
		)
	}
	probes = append(probes,
		probe{"exec", map[string]any{"hosts": []string{"tag:personal", "tag:web"}, "command": "echo ok"}},
		probe{"exec", map[string]any{"hosts": "inner", "command": "echo ok"}},
		probe{"check_host", map[string]any{"host": "inner"}},
		probe{"list_hosts", map[string]any{"query": "inner"}},
	)

	answers := func(m *mcpSession) (out []string, ran int) {
		t.Helper()
		before := len(e.server.commands())
		for _, p := range probes {
			b, err := json.Marshal(m.call(p.tool, p.args))
			if err != nil {
				t.Fatal(err)
			}
			out = append(out, durationRe.ReplaceAllString(string(b), "${1}:0"))
		}
		return out, len(e.server.commands()) - before
	}

	scoped := e.startMCP(t, "--tag", "work")
	got, gotRan := answers(scoped)

	// The same vault with the host denied, and a server with no tag.
	e.retag(t, "other-box", []string{"personal", "web"}, "deny")
	denied := e.startMCP(t)
	want, wantRan := answers(denied)

	for i, p := range probes {
		if got[i] != want[i] {
			t.Errorf("%s %v with --tag work answered\n%s\nbut the denied host's answer is\n%s", p.tool, p.args, got[i], want[i])
		}
	}
	if gotRan != wantRan || gotRan == 0 {
		t.Errorf("--tag work ran %d commands, a denied host's vault %d (and some must run)", gotRan, wantRan)
	}

	// And what is visible is what the tag says.
	list := mcpCall[cli.MCPHosts](scoped, "list_hosts", nil)
	if names := hostNames(list.Hosts); !slices.Equal(names, []string{"inner", "web-1", "web-2"}) {
		t.Errorf("--tag work lists %v", names)
	}
	r := mcpCall[cli.MCPResolution](scoped, "resolve_host", map[string]any{"target": "other-box"})
	if r.Status != "no_match" || r.Host != nil {
		t.Errorf("resolve other-box under --tag work = %+v", r)
	}
	for _, h := range list.Hosts {
		if h.Name == "inner" && h.JumpHost != "(a host hidden from agents)" {
			t.Errorf("inner's jump host = %q", h.JumpHost)
		}
	}
}

// Several tags are a union, in any case; the list_hosts tag filter narrows
// what is left; a tag no host carries leaves the agent no host.
func TestMCPTagScopeIsAUnion(t *testing.T) {
	e := newE2E(t)
	e.retag(t, "web-1", []string{"red"}, "allow")
	e.retag(t, "web-2", []string{"Blue", "green"}, "allow")
	e.addHost(t, "c-box", func(h *model.Host) { h.Tags = []string{"green"} })
	e.addHost(t, "d-box", func(h *model.Host) { h.Tags = []string{"red"}; h.AgentAccess = "deny" })
	e.addHost(t, "e-box", nil)

	names := func(m *mcpSession, args map[string]any) []string {
		t.Helper()
		return hostNames(mcpCall[cli.MCPHosts](m, "list_hosts", args).Hosts)
	}
	m := e.startMCP(t, "--tag", "RED", "--tag", "blue")
	if got := names(m, nil); !slices.Equal(got, []string{"web-1", "web-2"}) {
		t.Errorf("--tag RED --tag blue lists %v, want web-1 and web-2 (d-box is denied, c-box and e-box are out of scope)", got)
	}
	if got := names(m, map[string]any{"tag": "green"}); !slices.Equal(got, []string{"web-2"}) {
		t.Errorf("tag green under --tag RED --tag blue lists %v", got)
	}
	if got := names(m, map[string]any{"tag": "red"}); !slices.Equal(got, []string{"web-1"}) {
		t.Errorf("tag red lists %v", got)
	}
	// tag: expands only among the hosts in scope.
	out := mcpCall[cli.MCPExec](m, "exec", map[string]any{"hosts": []string{"tag:green", "tag:red"}, "command": "echo ok"})
	res := execResults(t, out)
	if len(out.Results) != 2 || res["web-1"].ExitCode != 0 || res["web-1"].Stdout != "ok\n" || res["web-2"].Host == "" {
		t.Errorf("exec tag:green tag:red = %+v", out.Results)
	}
	for _, name := range []string{"c-box", "d-box", "e-box"} {
		if r := mcpCall[cli.MCPResolution](m, "resolve_host", map[string]any{"target": name}); r.Host != nil || r.Status != "no_match" {
			t.Errorf("resolve %s = %+v", name, r)
		}
	}

	none := e.startMCP(t, "--tag", "nobody-has-this")
	if got := names(none, nil); len(got) != 0 {
		t.Errorf("a tag no host has lists %v", got)
	}
	if r := mcpCall[cli.MCPResolution](none, "resolve_host", map[string]any{"target": "web-1"}); r.Host != nil {
		t.Errorf("resolve web-1 = %+v", r)
	}
	// Without --tag every host that is not denied is shown.
	if got := names(e.startMCP(t), nil); !slices.Equal(got, []string{"c-box", "e-box", "web-1", "web-2"}) {
		t.Errorf("no --tag lists %v", got)
	}
}

func TestMCPTagNeedsAValue(t *testing.T) {
	var so, se bytes.Buffer
	env := &cli.Env{Stdout: &so, Stderr: &se, Getenv: func(string) string { return "" }}
	if code := cli.Run(context.Background(), []string{"mcp", "--tag", " "}, env); code != 255 || !strings.Contains(se.String(), "needs a tag") {
		t.Errorf("hop mcp --tag ' ': %d %q", code, se.String())
	}
}

func TestMCPInstallPassesTagsThrough(t *testing.T) {
	exe := filepath.Join(t.TempDir(), "hop")
	run := func(args ...string) (int, string, string, [][]string) {
		var so, se bytes.Buffer
		var ran [][]string
		env := &cli.Env{
			Stdout: &so, Stderr: &se, Getenv: func(string) string { return "" }, Executable: exe,
			RunCommand: func(_ context.Context, name string, a ...string) ([]byte, error) {
				ran = append(ran, append([]string{name}, a...))
				return []byte("Added\n"), nil
			},
		}
		code := cli.Run(context.Background(), append([]string{"mcp", "install"}, args...), env)
		return code, so.String(), se.String(), ran
	}

	code, _, _, ran := run("--client", "claude", "--read-only", "--tag", "work", "--tag", "lab", "--tag", "WORK")
	want := []string{"claude", "mcp", "add", "--scope", "user", "hop", "--", exe, "mcp", "--read-only", "--tag", "work", "--tag", "lab"}
	if code != 0 || len(ran) != 1 || !slices.Equal(ran[0], want) {
		t.Errorf("claude: %d %v, want %v", code, ran, want)
	}
	code, _, _, ran = run("--client", "codex", "--tag", "work")
	want = []string{"codex", "mcp", "add", "hop", "--", exe, "mcp", "--tag", "work"}
	if code != 0 || len(ran) != 1 || !slices.Equal(ran[0], want) {
		t.Errorf("codex: %d %v, want %v", code, ran, want)
	}

	code, stdout, _, _ := run("--tag", "work", "--tag", "lab", "--json")
	var rep struct {
		Server struct {
			Command string
			Args    []string
		} `json:"server"`
		Commands map[string]string `json:"commands"`
	}
	if err := json.Unmarshal([]byte(stdout), &rep); err != nil {
		t.Fatalf("%v\n%s", err, stdout)
	}
	if code != 0 || !slices.Equal(rep.Server.Args, []string{"mcp", "--tag", "work", "--tag", "lab"}) ||
		!strings.HasSuffix(rep.Commands["claude"], " mcp --tag work --tag lab") {
		t.Errorf("print --json: %d %+v", code, rep)
	}
	code, stdout, _, _ = run("--tag", "work")
	if code != 0 || !strings.Contains(stdout, `args = ["mcp", "--tag", "work"]`) {
		t.Errorf("print: %d %q", code, stdout)
	}
	if code, _, stderr, ran := run("--tag", ""); code != 255 || !strings.Contains(stderr, "needs a tag") || len(ran) != 0 {
		t.Errorf("empty tag: %d %q %v", code, stderr, ran)
	}
}
