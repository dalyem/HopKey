package daemon

import (
	"context"
	"slices"
	"strings"
	"testing"

	"github.com/dalyem/hopkey/internal/model"
	"github.com/dalyem/hopkey/internal/resolve"
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
