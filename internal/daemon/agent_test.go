package daemon

import (
	"context"
	"encoding/json"
	"slices"
	"strings"
	"testing"

	"github.com/dalyem/hopkey/internal/model"
	"github.com/dalyem/hopkey/internal/resolve"
	"github.com/dalyem/hopkey/internal/tailscale"
)

// agent_only resolution (hop mcp) leaves out hosts with agent_access deny:
// not matched by name or address, and not offered as a candidate.
func TestResolveAgentOnlyLeavesOutDeniedHosts(t *testing.T) {
	f := newFixture(t, nil)
	f.put(f.host("db-open", nil))
	f.put(f.host("db-secret", func(h *model.Host) { h.AgentAccess = "deny"; h.Addresses = []string{"203.0.113.99"} }))
	c := f.client()
	ctx := context.Background()

	resolveAs := func(target string, agentOnly bool) ResolveResult {
		t.Helper()
		var rr ResolveResult
		if err := c.Call(ctx, OpResolve, ResolveParams{Target: target, AgentOnly: agentOnly}, &rr); err != nil {
			t.Fatal(err)
		}
		return rr
	}
	// Without agent_only nothing changes: hop itself sees every host.
	if rr := resolveAs("db-secret", false); rr.Host == nil || rr.Host.Name != "db-secret" {
		t.Fatalf("plain resolve of db-secret = %+v", rr.Result)
	}
	for _, target := range []string{"db-secret", "203.0.113.99", "root@db-secret"} {
		rr := resolveAs(target, true)
		if rr.Host != nil || rr.Result.Status == resolve.StatusMatched || rr.Route != nil {
			t.Errorf("agent_only %q matched %+v", target, rr.Result)
		}
		if names := candidateNames(rr.Result); slices.Contains(names, "db-secret") {
			t.Errorf("agent_only %q offers db-secret: %v", target, names)
		}
	}
	// A prefix that fits both offers only the allowed one.
	rr := resolveAs("db", true)
	if names := candidateNames(rr.Result); !slices.Equal(names, []string{"db-open"}) {
		t.Errorf("agent_only candidates for db = %v, want [db-open]", names)
	}
	if rr := resolveAs("db-open", true); rr.Host == nil || rr.Host.Name != "db-open" {
		t.Errorf("agent_only db-open = %+v", rr.Result)
	}
}

// agent_only resolution also leaves out the tailnet nodes of denied hosts,
// so a lookup by the node's Tailscale name or IP does not come back with
// it as an unlinked node, in a note or a candidate.
func TestResolveAgentOnlyLeavesOutDeniedHostsTailnetNodes(t *testing.T) {
	node := func(id, name, ip string) tailscale.Node {
		return tailscale.Node{ID: id, HostName: name, DNSName: name + ".tn.ts.net", Online: true, IPs: []string{ip}}
	}
	ts := &tailscale.Status{Available: true, MagicDNSSuffix: "tn.ts.net",
		Self: tailscale.Node{ID: "nSELF", HostName: "me", DNSName: "me.tn.ts.net", Online: true, IPs: []string{"100.64.0.1"}},
		Peers: []tailscale.Node{
			node("nDENY", "secretbox", "100.64.0.9"),
			node("nTWINA", "twin", "100.64.0.11"),
			node("nTWINB", "twin", "100.64.0.12"),
			node("nBYIP", "byip", "100.64.0.13"),
			node("nDNS", "bydns", "100.64.0.14"),
		}}
	f := newFixture(t, fakeTS{ts})
	link := func(id, dns string) *model.Tailscale {
		return &model.Tailscale{StableNodeID: id, DNSName: dns, SSH: "unknown"}
	}
	f.put(f.host("db-secret", func(h *model.Host) { h.AgentAccess = "deny"; h.Tailscale = link("nDENY", "secretbox.tn.ts.net") }))
	f.put(f.host("twin-open", func(h *model.Host) {
		h.Addresses = []string{"203.0.113.11"}
		h.Tailscale = link("nTWINA", "twin.tn.ts.net")
	}))
	f.put(f.host("twin-secret", func(h *model.Host) {
		h.AgentAccess = "deny"
		h.Addresses = []string{"203.0.113.12"}
		h.Tailscale = link("nTWINB", "")
	}))
	// Not linked, but it lists the node's Tailscale IP.
	f.put(f.host("ip-secret", func(h *model.Host) { h.AgentAccess = "deny"; h.Addresses = []string{"100.64.0.13"} }))
	// Linked by its MagicDNS name only.
	f.put(f.host("dns-secret", func(h *model.Host) {
		h.AgentAccess = "deny"
		h.Addresses = []string{"203.0.113.14"}
		h.Tailscale = link("", "bydns.tn.ts.net.")
	}))
	c := f.client()
	ctx := context.Background()
	resolveAs := func(target string, agentOnly bool) ResolveResult {
		t.Helper()
		var rr ResolveResult
		if err := c.Call(ctx, OpResolve, ResolveParams{Target: target, AgentOnly: agentOnly}, &rr); err != nil {
			t.Fatal(err)
		}
		return rr
	}
	if rr := resolveAs("100.64.0.9", false); rr.Host == nil || rr.Host.Name != "db-secret" {
		t.Fatalf("plain resolve of db-secret's Tailscale IP = %+v", rr.Result)
	}
	hidden := []string{"nDENY", "secretbox", "nTWINB", "100.64.0.12", "nBYIP", "byip", "nDNS", "bydns"}
	for _, target := range []string{"100.64.0.9", "secretbox", "secretbox.tn.ts.net", "100.64.0.12", "byip", "100.64.0.13", "bydns", "100.64.0.14", "twin"} {
		rr := resolveAs(target, true)
		if rr.Host != nil && rr.Host.AgentAccess == "deny" {
			t.Errorf("agent_only %q matched the denied %s", target, rr.Host.Name)
		}
		b, _ := json.Marshal(struct {
			C []resolve.Candidate
			N []string
			T *tailscale.Node
			M string
		}{rr.Result.Candidates, rr.Result.Notes, rr.Result.Tailscale, rr.Result.Matched})
		for _, h := range hidden {
			if h != target && strings.Contains(string(b), h) {
				t.Errorf("agent_only %q names %s: %s", target, h, b)
			}
		}
	}
	// The name an allowed and a denied host's nodes share is the allowed
	// one's alone.
	if rr := resolveAs("twin", true); rr.Host == nil || rr.Host.Name != "twin-open" || rr.Route == nil {
		t.Errorf("agent_only twin = %+v", rr.Result)
	}
}

// A denied host whose address is its node's MagicDNS name, in any case and
// with a trailing dot, or the name's first label, owns that node though it
// is not linked to it: agent_only resolution by the node's name or IP does
// not come back with the node.
func TestResolveAgentOnlyLeavesOutNodesDeniedHostsNameByDNS(t *testing.T) {
	node := func(id, name, ip string) tailscale.Node {
		return tailscale.Node{ID: id, HostName: name + "-host", DNSName: name + ".tn.ts.net.", Online: true, IPs: []string{ip}}
	}
	ts := &tailscale.Status{Available: true, MagicDNSSuffix: "tn.ts.net",
		Peers: []tailscale.Node{node("nVAULT", "vaultbox", "100.64.0.9"), node("nSHORT", "shortbox", "100.64.0.10"), node("nOPEN", "openbox", "100.64.0.11")}}
	f := newFixture(t, fakeTS{ts})
	f.put(f.host("vault-secret", func(h *model.Host) { h.AgentAccess = "deny"; h.Addresses = []string{"VaultBox.TN.ts.net."} }))
	f.put(f.host("short-secret", func(h *model.Host) { h.AgentAccess = "deny"; h.Addresses = []string{"shortbox"} }))
	c := f.client()
	hidden := []string{"nVAULT", "vaultbox", "100.64.0.9", "nSHORT", "shortbox", "100.64.0.10"}
	for _, target := range []string{"vaultbox", "vaultbox.tn.ts.net", "vaultbox-host", "100.64.0.9", "shortbox", "shortbox-host", "100.64.0.10"} {
		var rr ResolveResult
		if err := c.Call(context.Background(), OpResolve, ResolveParams{Target: target, AgentOnly: true}, &rr); err != nil {
			t.Fatal(err)
		}
		b, _ := json.Marshal([]any{rr.Result.Candidates, rr.Result.Notes, rr.Result.Tailscale, rr.Result.Matched, rr.Host})
		for _, h := range hidden {
			if !strings.Contains(target, h) && strings.Contains(string(b), h) {
				t.Errorf("agent_only %q names %s: %s", target, h, b)
			}
		}
	}
	// A node no denied host names is still found.
	var rr ResolveResult
	if err := c.Call(context.Background(), OpResolve, ResolveParams{Target: "openbox", AgentOnly: true}, &rr); err != nil {
		t.Fatal(err)
	}
	if b, _ := json.Marshal(rr.Result.Notes); !strings.Contains(string(b), "nOPEN") {
		t.Errorf("agent_only openbox lost the allowed node: %+v", rr.Result)
	}
}

// Two machines can report the same host name; Tailscale names the second
// build-1. A denied host linked to the first by stable ID and addressed as
// build owns that node only: build is a name both answer to, and does not
// say which one it is. The second, an allowed host's, is found by its IP
// and its names, and the first stays hidden.
func TestResolveAgentOnlyRepeatedHostNamesOwnOnlyTheLinkedNode(t *testing.T) {
	ts := &tailscale.Status{Available: true, MagicDNSSuffix: "tn.ts.net",
		Peers: []tailscale.Node{
			{ID: "nBUILD1", HostName: "build", DNSName: "build.tn.ts.net", Online: true, IPs: []string{"100.64.0.21"}},
			{ID: "nBUILD2", HostName: "build", DNSName: "build-1.tn.ts.net", Online: true, IPs: []string{"100.64.0.22"}},
		}}
	f := newFixture(t, fakeTS{ts})
	link := func(id, dns string) *model.Tailscale {
		return &model.Tailscale{StableNodeID: id, DNSName: dns, SSH: "unknown"}
	}
	f.put(f.host("build-secret", func(h *model.Host) {
		h.AgentAccess, h.Addresses, h.Tailscale = "deny", []string{"build"}, link("nBUILD1", "build.tn.ts.net")
	}))
	f.put(f.host("ci-runner", func(h *model.Host) {
		h.Addresses = []string{"203.0.113.22"}
		h.Tailscale = link("nBUILD2", "build-1.tn.ts.net")
	}))
	c := f.client()
	resolveAs := func(target string) ResolveResult {
		t.Helper()
		var rr ResolveResult
		if err := c.Call(context.Background(), OpResolve, ResolveParams{Target: target, AgentOnly: true}, &rr); err != nil {
			t.Fatal(err)
		}
		return rr
	}
	for _, target := range []string{"100.64.0.22", "build-1", "build-1.tn.ts.net"} {
		if rr := resolveAs(target); rr.Host == nil || rr.Host.Name != "ci-runner" || rr.Route == nil {
			t.Errorf("agent_only %q = %+v, want ci-runner", target, rr.Result)
		}
	}
	for _, target := range []string{"100.64.0.21", "build.tn.ts.net", "build"} {
		rr := resolveAs(target)
		if rr.Host != nil && rr.Host.Name != "ci-runner" {
			t.Errorf("agent_only %q matched %s", target, rr.Host.Name)
		}
		b, _ := json.Marshal([]any{rr.Result.Candidates, rr.Result.Notes, rr.Result.Tailscale, rr.Result.Matched})
		for _, h := range []string{"nBUILD1", "100.64.0.21", "build-secret"} {
			if h != target && strings.Contains(string(b), h) {
				t.Errorf("agent_only %q names %s: %s", target, h, b)
			}
		}
	}
}

// A stable ID, a MagicDNS name or a Tailscale IP names one node; a short
// name or a host name owns a node only when no other node has it, and the
// host is not linked to another node.
func TestHostOwnsNode(t *testing.T) {
	b1 := tailscale.Node{ID: "nB1", HostName: "build", DNSName: "build.tn.ts.net.", IPs: []string{"100.64.0.21", "fd7a::21"}}
	b2 := tailscale.Node{ID: "nB2", HostName: "build", DNSName: "build-1.tn.ts.net.", IPs: []string{"100.64.0.22"}}
	solo := tailscale.Node{ID: "nS", HostName: "solo-host", DNSName: "solo.tn.ts.net.", IPs: []string{"100.64.0.23"}}
	all := []tailscale.Node{b1, b2, solo}
	for _, c := range []struct {
		name string
		h    model.Host
		n    tailscale.Node
		want bool
	}{
		{"stable ID", model.Host{Tailscale: &model.Tailscale{StableNodeID: "nB2"}}, b2, true},
		{"linked MagicDNS name", model.Host{Tailscale: &model.Tailscale{DNSName: "BUILD-1.tn.ts.net"}}, b2, true},
		{"address: MagicDNS name", model.Host{Addresses: []string{"build.TN.ts.net."}}, b1, true},
		{"address: Tailscale IP", model.Host{Addresses: []string{"[fd7a::21]"}}, b1, true},
		{"address: a short name no other node has", model.Host{Addresses: []string{"build-1"}}, b2, true},
		{"address: a host name no other node has", model.Host{Addresses: []string{"solo-host"}}, solo, true},
		{"address: a host name two nodes have", model.Host{Addresses: []string{"build"}}, b2, false},
		{"address: a host name two nodes have, linked to the other", model.Host{Addresses: []string{"build"}, Tailscale: &model.Tailscale{StableNodeID: "nB1"}}, b2, false},
		{"address: a short name, linked to another node", model.Host{Addresses: []string{"build-1"}, Tailscale: &model.Tailscale{StableNodeID: "nB1"}}, b2, false},
		{"linked, and the short name of another", model.Host{Addresses: []string{"build-1"}, Tailscale: &model.Tailscale{StableNodeID: "nB1"}}, b1, true},
	} {
		if got := HostOwnsNode(c.h, c.n, all); got != c.want {
			t.Errorf("%s: HostOwnsNode(%s) = %v, want %v", c.name, c.n.ID, got, c.want)
		}
	}
}

func candidateNames(r *resolve.Result) []string {
	var out []string
	for _, c := range r.Candidates {
		out = append(out, c.Name)
	}
	return out
}

func TestPutSnippetDerivesParamsAndRefusesBadInput(t *testing.T) {
	f := newFixture(t, nil)
	c := f.client()
	ctx := context.Background()

	var saved model.Snippet
	err := c.Call(ctx, OpPutSnippet, PutSnippetParams{Snippet: model.Snippet{
		Name: "restart", Command: "systemctl restart {{unit}} && journalctl -u {{ unit }} -n {{lines}}",
		Params: []string{"ignored"}, Description: "restart a unit",
	}}, &saved)
	if err != nil {
		t.Fatal(err)
	}
	if saved.ItemID.IsZero() || !slices.Equal(saved.Params, []string{"unit", "lines"}) {
		t.Errorf("saved = %+v, want params [unit lines]", saved)
	}
	if l := f.list(); len(l.Snippets) != 1 || l.Snippets[0].Name != "restart" {
		t.Errorf("list snippets = %+v", l.Snippets)
	}

	for _, tc := range []struct {
		sn   model.Snippet
		want string
	}{
		{model.Snippet{Name: "Restart", Command: "true"}, "already exists"},
		{model.Snippet{Name: "", Command: "true"}, "not a valid snippet name"},
		{model.Snippet{Name: "bad name", Command: "true"}, "not a valid snippet name"},
		{model.Snippet{Name: "empty", Command: "  "}, "needs a command"},
		{model.Snippet{Name: "quoted", Command: "echo '{{x}}'"}, "inside quotes"},
		{model.Snippet{Name: "dquoted", Command: `echo "{{x}}"`}, "inside quotes"},
		{model.Snippet{Name: "dashed", Command: "echo {{a-b}}"}, "has a '-'"},
		{model.Snippet{Name: "evals", Command: "eval {{x}}"}, "eval"},
		{model.Snippet{Name: "arith", Command: "echo $(( {{x}} + 1 ))"}, "arithmetic"},
		{model.Snippet{Name: "dbracket", Command: "[[ {{x}} -eq 1 ]]"}, "[[ ... ]]"},
		{model.Snippet{Name: "shc", Command: "bash -c {{x}}"}, "-c"},
		{model.Snippet{Name: "assign", Command: "ref={{x}}; echo ${!ref}"}, "assignment"},
		{model.Snippet{Name: "long", Command: strings.Repeat("x", 8193)}, "longer than 8192"},
	} {
		err := c.Call(ctx, OpPutSnippet, PutSnippetParams{Snippet: tc.sn}, nil)
		if !IsCode(err, CodeInvalid) || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("put %+v: %v, want invalid with %q", tc.sn, err, tc.want)
		}
	}
	// Replacing it by ID keeps the name free for itself.
	saved.Command = "systemctl restart {{unit}}"
	var again model.Snippet
	if err := c.Call(ctx, OpPutSnippet, PutSnippetParams{Snippet: saved}, &again); err != nil {
		t.Fatalf("update: %v", err)
	}
	if !slices.Equal(again.Params, []string{"unit"}) || again.ItemID != saved.ItemID {
		t.Errorf("updated = %+v", again)
	}
}

// A host whose bare address names a tailnet node gets the hop ts link hint
// from a plain resolution, and never from an agent_only one, or from a host
// behind a jump host.
func TestResolveRouteHintIsNotForAgents(t *testing.T) {
	ts := &tailscale.Status{Available: true, MagicDNSSuffix: "tn.ts.net",
		Peers: []tailscale.Node{{ID: "nOPEN", HostName: "openbox", DNSName: "openbox.tn.ts.net.", Online: true, IPs: []string{"100.64.0.11"}}}}
	f := newFixture(t, fakeTS{ts})
	bastion := f.put(f.host("bastion", func(h *model.Host) { h.Addresses = []string{"203.0.113.1"} }))
	f.put(f.host("web", func(h *model.Host) { h.Addresses = []string{"openbox"} }))
	f.put(f.host("inner", func(h *model.Host) { h.Addresses = []string{"openbox"}; h.JumpHostID = bastion.ItemID }))
	c := f.client()
	resolve := func(target string, agentOnly bool) ResolveResult {
		t.Helper()
		var rr ResolveResult
		if err := c.Call(context.Background(), OpResolve, ResolveParams{Target: target, AgentOnly: agentOnly}, &rr); err != nil {
			t.Fatal(err)
		}
		return rr
	}
	const want = "openbox matches tailnet node openbox; to route over Tailscale: hop ts link web nOPEN"
	if rr := resolve("web", false); rr.RouteHint != want || rr.Route == nil || rr.Route.Chosen != "direct" {
		t.Errorf("plain resolve: hint %q, route %+v; want %q and a direct route", rr.RouteHint, rr.Route, want)
	}
	if rr := resolve("web", true); rr.Host == nil || rr.RouteHint != "" {
		t.Errorf("agent_only resolve: host %v, hint %q; want the host and no hint", rr.Host, rr.RouteHint)
	}
	if rr := resolve("inner", false); rr.Host == nil || rr.RouteHint != "" {
		t.Errorf("jump host: host %v, hint %q; want the host and no hint", rr.Host, rr.RouteHint)
	}
}
