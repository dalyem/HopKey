package resolve

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/dalyem/hopkey/internal/model"
	"github.com/dalyem/hopkey/internal/tailscale"
)

func id(n byte) model.ID { return model.ID{15: n} }

func host(n byte, name string, mod func(*model.Host)) model.Host {
	h := model.Host{
		Header: model.Header{V: 1, ItemID: id(n), Type: model.TypeHost, ItemVersion: 1},
		Name:   name, Port: 22, Route: "auto", AgentAccess: "allow",
	}
	if mod != nil {
		mod(&h)
	}
	return h
}

func node(nodeID, hostName, dns string, online bool, ips ...string) tailscale.Node {
	return tailscale.Node{ID: nodeID, HostName: hostName, DNSName: dns, IPs: ips, Online: online}
}

func tsStatus(nodes ...tailscale.Node) *tailscale.Status {
	return &tailscale.Status{Available: true, MagicDNSSuffix: "tn.ts.net", Self: node("nSELF", "laptop", "laptop.tn.ts.net", true, "100.64.0.1"), Peers: nodes}
}

func linked(nodeID, dns string) func(*model.Host) {
	return func(h *model.Host) {
		h.Tailscale = &model.Tailscale{StableNodeID: nodeID, DNSName: dns, SSH: "unknown"}
	}
}

func names(r *Result) []string {
	var out []string
	for _, c := range r.Candidates {
		out = append(out, c.Name)
	}
	return out
}

func TestParseTarget(t *testing.T) {
	tests := []struct {
		in, user, target string
		wantErr          bool
	}{
		{in: "web-1", target: "web-1"},
		{in: "deploy@web-1", user: "deploy", target: "web-1"},
		{in: "me@corp@web-1", user: "me@corp", target: "web-1"},
		{in: "root@10.0.0.1", user: "root", target: "10.0.0.1"},
		{in: "[fd7a:115c:a1e0::1]", target: "fd7a:115c:a1e0::1"},
		{in: "u@[::1]", user: "u", target: "::1"},
		{in: "fd7a:115c:a1e0::1", target: "fd7a:115c:a1e0::1"},
		{in: "", wantErr: true},
		{in: "@host", wantErr: true},
		{in: "user@", wantErr: true},
		{in: "-oProxyCommand=x", wantErr: true},
		{in: "u@-oProxyCommand=x", wantErr: true},
		{in: "-u@host", wantErr: true},
		{in: "a b", wantErr: true},
		{in: "host\n", wantErr: true},
	}
	for _, tt := range tests {
		user, target, err := ParseTarget(tt.in)
		if (err != nil) != tt.wantErr || user != tt.user || target != tt.target {
			t.Errorf("ParseTarget(%q) = %q, %q, %v; want %q, %q, wantErr=%v", tt.in, user, target, err, tt.user, tt.target, tt.wantErr)
		}
	}
}

func TestResolveRules(t *testing.T) {
	hosts := []model.Host{
		host(1, "prod-db", func(h *model.Host) {
			h.Aliases = []string{"db", "Primary"}
			h.Addresses = []string{"db.example.com", "203.0.113.10", "fd00::10"}
			linked("nPRODDB", "prod-db.tn.ts.net")(h)
		}),
		host(2, "prod-web", func(h *model.Host) { h.Addresses = []string{"203.0.113.20"} }),
		host(3, "staging", func(h *model.Host) { h.Addresses = []string{"staging.example.com"} }),
		host(4, "build", linked("nBUILD1", "build.tn.ts.net")),
	}
	ts := tsStatus(
		node("nPRODDB", "prod-db", "prod-db.tn.ts.net", true, "100.64.0.2", "fd7a:115c:a1e0::2"),
		node("nBUILD1", "build", "build.tn.ts.net", true, "100.64.0.3"),
		node("nBUILD2", "build", "build-1.tn.ts.net", true, "100.64.0.4"),
		node("nSTRAY", "stray", "stray.tn.ts.net", true, "100.64.0.9"),
	)
	dns := func(_ context.Context, name string) ([]string, error) {
		switch name {
		case "db.internal":
			return []string{"203.0.113.10"}, nil
		case "pair.internal":
			return []string{"203.0.113.10", "203.0.113.20"}, nil
		}
		return nil, errors.New("no such host")
	}

	tests := []struct {
		name        string
		target      string
		interactive bool
		status      Status
		rule        Rule
		host        string   // matched host name
		candidates  []string // expected candidate names (sorted)
		noteContain string
	}{
		// 1. alias or name
		{name: "exact name", target: "prod-db", status: StatusMatched, rule: RuleAlias, host: "prod-db"},
		{name: "exact alias", target: "db", status: StatusMatched, rule: RuleAlias, host: "prod-db"},
		{name: "alias is case-insensitive", target: "PRIMARY", status: StatusMatched, rule: RuleAlias, host: "prod-db"},
		{name: "user@ is stripped", target: "ops@prod-db", status: StatusMatched, rule: RuleAlias, host: "prod-db"},
		{name: "name beats a later rule that would also match", target: "build", status: StatusMatched, rule: RuleAlias, host: "build"},

		// 2. stored address
		{name: "stored hostname", target: "db.example.com", status: StatusMatched, rule: RuleAddress, host: "prod-db"},
		{name: "stored hostname, other case and trailing dot", target: "DB.Example.COM.", status: StatusMatched, rule: RuleAddress, host: "prod-db"},
		{name: "stored IPv4", target: "203.0.113.20", status: StatusMatched, rule: RuleAddress, host: "prod-web"},
		{name: "stored IPv6, written differently", target: "fd00:0:0:0:0:0:0:10", status: StatusMatched, rule: RuleAddress, host: "prod-db"},
		{name: "tailscale DNS name stored on the host", target: "prod-db.tn.ts.net", status: StatusMatched, rule: RuleAddress, host: "prod-db"},

		// 3. tailscale status
		{name: "tailscale ip, linked by node id", target: "100.64.0.2", status: StatusMatched, rule: RuleTailscale, host: "prod-db"},
		{name: "tailscale ipv6", target: "fd7a:115c:a1e0::2", status: StatusMatched, rule: RuleTailscale, host: "prod-db"},
		{name: "peer known only by its DNS name, not linked", target: "build-1.tn.ts.net", status: StatusNoMatch, rule: RuleNone, noteContain: "not linked to a vault host"},
		{name: "ip of one of two same-named peers", target: "100.64.0.3", status: StatusMatched, rule: RuleTailscale, host: "build"},
		{name: "unlinked peer is a note, not a match", target: "stray", status: StatusNoMatch, rule: RuleNone, noteContain: "stray"},
		{name: "unlinked peer by ip", target: "100.64.0.9", status: StatusNoMatch, rule: RuleNone, noteContain: "hop ts import"},

		// ambiguity at steps 1-3
		{name: "an address nobody has", target: "203.0.113.99", status: StatusNoMatch, rule: RuleNone},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r, err := Resolve(context.Background(), Input{Target: tt.target, Hosts: hosts, Tailscale: ts, Interactive: tt.interactive, LookupHost: dns})
			if err != nil {
				t.Fatal(err)
			}
			if r.Status != tt.status || r.Rule != tt.rule || r.HostName != tt.host {
				t.Fatalf("got status=%s rule=%s host=%q (candidates %v, notes %v); want status=%s rule=%s host=%q",
					r.Status, r.Rule, r.HostName, names(r), r.Notes, tt.status, tt.rule, tt.host)
			}
			if tt.status == StatusMatched && (r.Host == nil || r.Host.Name != tt.host || r.HostID == "") {
				t.Errorf("matched without a host: %+v", r)
			}
			if tt.noteContain != "" {
				found := false
				for _, n := range r.Notes {
					found = found || strings.Contains(n, tt.noteContain)
				}
				if !found {
					t.Errorf("notes %q lack %q", r.Notes, tt.noteContain)
				}
			}
		})
	}
}

func TestResolveAmbiguity(t *testing.T) {
	t.Run("two hosts share a name", func(t *testing.T) {
		hosts := []model.Host{host(1, "web", nil), host(2, "api", func(h *model.Host) { h.Aliases = []string{"web"} })}
		r, _ := Resolve(context.Background(), Input{Target: "web", Hosts: hosts})
		if r.Status != StatusAmbiguous || r.Rule != RuleAlias || !slices.Equal(names(r), []string{"api", "web"}) || r.Host != nil {
			t.Errorf("got %+v", r)
		}
	})
	t.Run("two hosts share an address", func(t *testing.T) {
		hosts := []model.Host{
			host(1, "b", func(h *model.Host) { h.Addresses = []string{"10.0.0.1"} }),
			host(2, "a", func(h *model.Host) { h.Addresses = []string{"10.0.0.1"} }),
		}
		r, _ := Resolve(context.Background(), Input{Target: "10.0.0.1", Hosts: hosts})
		if r.Status != StatusAmbiguous || r.Rule != RuleAddress || !slices.Equal(names(r), []string{"a", "b"}) {
			t.Errorf("got %+v", r)
		}
	})
	t.Run("a name shared by a name in step 1 stops before addresses", func(t *testing.T) {
		hosts := []model.Host{
			host(1, "x", func(h *model.Host) { h.Addresses = []string{"y"} }),
			host(2, "y", nil),
		}
		r, _ := Resolve(context.Background(), Input{Target: "y", Hosts: hosts})
		if r.Status != StatusMatched || r.HostName != "y" || r.Rule != RuleAlias {
			t.Errorf("the name rule must win over the address rule: %+v", r)
		}
	})
	t.Run("duplicate tailscale host name", func(t *testing.T) {
		hosts := []model.Host{host(1, "build-a", linked("nB1", "")), host(2, "build-b", linked("nB2", ""))}
		ts := tsStatus(node("nB1", "build", "build.tn.ts.net", true, "100.64.0.3"), node("nB2", "build", "build-1.tn.ts.net", false, "100.64.0.4"))
		r, _ := Resolve(context.Background(), Input{Target: "build", Hosts: hosts, Tailscale: ts})
		if r.Status != StatusAmbiguous || r.Rule != RuleTailscale || !slices.Equal(names(r), []string{"build-a", "build-b"}) {
			t.Fatalf("got %+v", r)
		}
		if r.Candidates[0].NodeID != "nB1" || r.Candidates[1].NodeID != "nB2" {
			t.Errorf("candidate node ids = %q, %q", r.Candidates[0].NodeID, r.Candidates[1].NodeID)
		}
		// The unique label disambiguates.
		r, _ = Resolve(context.Background(), Input{Target: "build-1", Hosts: hosts, Tailscale: ts})
		if r.Status != StatusMatched || r.HostName != "build-b" {
			t.Errorf("build-1 should be build-b: %+v", r)
		}
	})
	t.Run("duplicate tailscale host name, one node unlinked", func(t *testing.T) {
		hosts := []model.Host{host(1, "build-a", linked("nB1", ""))}
		ts := tsStatus(node("nB1", "build", "build.tn.ts.net", true), node("nB2", "build", "build-1.tn.ts.net", true))
		r, _ := Resolve(context.Background(), Input{Target: "build", Hosts: hosts, Tailscale: ts})
		if r.Status != StatusAmbiguous || len(r.Candidates) != 2 || r.Candidates[1].HostID != "" {
			t.Errorf("got %+v", r)
		}
	})
	t.Run("two hosts claim one node", func(t *testing.T) {
		hosts := []model.Host{host(1, "a", linked("nB1", "")), host(2, "b", linked("nB1", ""))}
		ts := tsStatus(node("nB1", "build", "build.tn.ts.net", true))
		r, _ := Resolve(context.Background(), Input{Target: "build", Hosts: hosts, Tailscale: ts})
		if r.Status != StatusAmbiguous || len(r.Candidates) != 2 {
			t.Errorf("got %+v", r)
		}
	})
	t.Run("unavailable tailscale skips step 3", func(t *testing.T) {
		hosts := []model.Host{host(1, "a", linked("nB1", ""))}
		r, _ := Resolve(context.Background(), Input{Target: "100.64.0.3", Hosts: hosts, Tailscale: tailscale.Unavailable("stopped")})
		if r.Status != StatusNoMatch {
			t.Errorf("got %+v", r)
		}
		r, _ = Resolve(context.Background(), Input{Target: "100.64.0.3", Hosts: hosts, Tailscale: nil})
		if r.Status != StatusNoMatch {
			t.Errorf("nil status: got %+v", r)
		}
	})
}

func TestInteractiveOnlyRules(t *testing.T) {
	hosts := []model.Host{
		host(1, "prod-db", func(h *model.Host) { h.Addresses = []string{"203.0.113.10"} }),
		host(2, "prod-web", func(h *model.Host) { h.Addresses = []string{"203.0.113.20"} }),
		host(3, "staging-db", nil),
	}
	dns := func(_ context.Context, name string) ([]string, error) {
		switch name {
		case "db.internal":
			return []string{"203.0.113.10"}, nil
		case "pair.internal":
			return []string{"203.0.113.10", "203.0.113.20"}, nil
		case "nobody.internal":
			return []string{"198.51.100.1"}, nil
		}
		return nil, fmt.Errorf("no such host %s", name)
	}
	run := func(target string, interactive bool) *Result {
		t.Helper()
		r, err := Resolve(context.Background(), Input{Target: target, Hosts: hosts, Interactive: interactive, LookupHost: dns})
		if err != nil {
			t.Fatal(err)
		}
		return r
	}

	// 4. DNS.
	if r := run("db.internal", true); r.Status != StatusMatched || r.Rule != RuleDNS || r.HostName != "prod-db" {
		t.Errorf("dns: %+v", r)
	}
	if r := run("pair.internal", true); r.Status != StatusAmbiguous || r.Rule != RuleDNS || !slices.Equal(names(r), []string{"prod-db", "prod-web"}) {
		t.Errorf("dns, two hosts: %+v", r)
	}
	// Non-interactive never looks anything up.
	if r := run("db.internal", false); r.Status != StatusNoMatch {
		t.Errorf("non-interactive dns: %+v", r)
	}
	if r := run("nobody.internal", true); r.Status != StatusPlainSSH {
		t.Errorf("dns result matching nothing, interactive: %+v", r)
	}

	// 5. prefix / fuzzy.
	if r := run("prod-w", true); r.Status != StatusMatched || r.Rule != RulePrefix || r.HostName != "prod-web" {
		t.Errorf("unique prefix: %+v", r)
	}
	if r := run("prod", true); r.Status != StatusAmbiguous || r.Rule != RulePrefix || !slices.Equal(names(r), []string{"prod-db", "prod-web"}) {
		t.Errorf("ambiguous prefix: %+v", r)
	}
	if r := run("web", true); r.Status != StatusMatched || r.HostName != "prod-web" {
		t.Errorf("substring: %+v", r)
	}
	if r := run("pdd", true); r.Status != StatusMatched || r.HostName != "prod-db" {
		// "pdd" is a subsequence of prod-db only: prod-web has one d, staging-db no p.
		t.Errorf("subsequence: %+v", r)
	}
	if r := run("zz", true); r.Status != StatusPlainSSH || len(r.Candidates) != 0 {
		t.Errorf("no match, interactive: %+v", r)
	}
	// A prefix match is preferred over a substring match.
	if r := run("staging", true); r.HostName != "staging-db" || r.Rule != RulePrefix {
		t.Errorf("prefix tier: %+v", r)
	}

	// Non-interactive: prefix matches are suggestions, never a match.
	r := run("prod", false)
	if r.Status != StatusNoMatch || r.Rule != RuleNone || r.Host != nil || r.HostName != "" || !slices.Equal(names(r), []string{"prod-db", "prod-web"}) || len(r.Notes) == 0 {
		t.Errorf("non-interactive ambiguous prefix: %+v", r)
	}
	r = run("zz", false)
	if r.Status != StatusNoMatch || len(r.Candidates) != 0 {
		t.Errorf("non-interactive, nothing close: %+v", r)
	}
	// A bad target is an error, not a result.
	if _, err := Resolve(context.Background(), Input{Target: "-x", Hosts: hosts}); err == nil {
		t.Error("an option-looking target was accepted")
	}
}

func TestDNSIsNotAskedAboutIPsOrOddNames(t *testing.T) {
	called := 0
	in := Input{
		Hosts: []model.Host{host(1, "a", nil)}, Interactive: true,
		LookupHost: func(context.Context, string) ([]string, error) { called++; return nil, nil },
	}
	for _, target := range []string{"192.0.2.1", "fd00::1", "a/b", "x;y"} {
		in.Target = target
		Resolve(context.Background(), in)
	}
	if called != 0 {
		t.Errorf("the resolver was asked %d times for IPs and non-host-names", called)
	}
}
