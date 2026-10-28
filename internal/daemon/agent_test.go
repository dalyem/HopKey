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
