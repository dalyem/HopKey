package resolve

import (
	"strings"
	"testing"

	"github.com/dalyem/hopkey/internal/model"
	"github.com/dalyem/hopkey/internal/tailscale"
)

func TestIsTailnetAddr(t *testing.T) {
	tests := map[string]bool{
		"100.64.0.1":             true,
		"100.127.255.254":        true,
		"100.128.0.1":            false,
		"100.63.255.255":         false,
		"10.0.0.1":               false,
		"fd7a:115c:a1e0::1":      true,
		"fd7a:115c:a1e1::1":      false,
		"2001:db8::1":            false,
		"host.tn.ts.net":         true,
		"HOST.TN.TS.NET.":        true,
		"host.example.com":       false,
		"host.corp-tailnet.test": false, // not a ts.net name and no suffix given
	}
	for addr, want := range tests {
		if got := IsTailnetAddr(addr, ""); got != want {
			t.Errorf("IsTailnetAddr(%q) = %v, want %v", addr, got, want)
		}
	}
	if !IsTailnetAddr("host.corp-tailnet.test", "corp-tailnet.test") {
		t.Error("a name under the MagicDNS suffix is on the tailnet")
	}
}

func TestChooseRoute(t *testing.T) {
	online := tsStatus(node("nA", "prod", "prod.tn.ts.net", true, "100.64.0.2", "fd7a:115c:a1e0::2"))
	offline := tsStatus(node("nA", "prod", "prod.tn.ts.net", false, "100.64.0.2"))
	stopped := tailscale.Unavailable("tailscale is Stopped")
	twoNodes := tsStatus(node("nA", "a", "a.tn.ts.net", true, "100.64.0.2"), node("nB", "b", "b.tn.ts.net", true, "100.64.0.3"))

	both := func(route string) model.Host {
		return host(1, "prod", func(h *model.Host) {
			h.Route = route
			h.Port = 2222
			h.Addresses = []string{"203.0.113.10", "prod.example.com"}
			linked("nA", "prod.tn.ts.net")(h)
		})
	}
	tests := []struct {
		name     string
		host     model.Host
		ts       *tailscale.Status
		chosen   string
		address  string
		fallback string
		reason   string // substring
		blocked  string // substring of Route.Blocked; "" means not blocked
		wantErr  string
	}{
		{name: "auto, online: tailnet, direct as fallback", host: both("auto"), ts: online, chosen: "tailnet", address: "100.64.0.2", fallback: "203.0.113.10", reason: "online"},
		{name: "empty route means auto", host: both(""), ts: online, chosen: "tailnet", address: "100.64.0.2", fallback: "203.0.113.10"},
		{name: "auto, peer offline: direct", host: both("auto"), ts: offline, chosen: "direct", address: "203.0.113.10", reason: "offline"},
		{name: "auto, tailscale stopped: direct", host: both("auto"), ts: stopped, chosen: "direct", address: "203.0.113.10", reason: "not running"},
		{name: "auto, no status at all: direct", host: both("auto"), ts: nil, chosen: "direct", address: "203.0.113.10"},
		{name: "direct ignores a running tailnet", host: both("direct"), ts: online, chosen: "direct", address: "203.0.113.10"},
		{name: "tailnet when online", host: both("tailnet"), ts: online, chosen: "tailnet", address: "100.64.0.2"},
		{name: "tailnet, tailscale stopped: blocked, never direct", host: both("tailnet"), ts: stopped, chosen: "tailnet", address: "prod.tn.ts.net", blocked: "tailscale is not available here (tailscale is Stopped)"},
		{name: "tailnet, no status at all: blocked", host: both("tailnet"), ts: nil, chosen: "tailnet", blocked: "does not fall back to a direct address"},
		{name: "tailnet, peer offline: still the tailnet, no fallback", host: both("tailnet"), ts: offline, chosen: "tailnet", address: "100.64.0.2"},
		{
			name: "auto with only a tailnet address uses it", ts: stopped, chosen: "tailnet", address: "100.64.0.7", reason: "no other address",
			host: host(1, "p", func(h *model.Host) { h.Addresses = []string{"100.64.0.7"} }),
		},
		{
			name: "direct with only a tailnet address is an error", ts: online, wantErr: "no address outside the tailnet",
			host: host(1, "p", func(h *model.Host) { h.Route = "direct"; h.Addresses = []string{"100.64.0.7"} }),
		},
		{
			name: "tailnet with no tailnet address is an error", ts: online, wantErr: "no tailnet address",
			host: host(1, "p", func(h *model.Host) { h.Route = "tailnet"; h.Addresses = []string{"203.0.113.10"} }),
		},
		{
			name: "no addresses", ts: online, wantErr: "no addresses",
			host: host(1, "p", nil),
		},
		{
			name: "unknown route", ts: online, wantErr: "unknown route",
			host: host(1, "p", func(h *model.Host) { h.Route = "wormhole"; h.Addresses = []string{"1.2.3.4"} }),
		},
		{
			name: "a stored tailnet IP finds its node without a link", ts: online, chosen: "tailnet", address: "100.64.0.2", fallback: "203.0.113.10",
			host: host(1, "p", func(h *model.Host) { h.Addresses = []string{"100.64.0.2", "203.0.113.10"} }),
		},
		{
			name: "the live ipv4 beats a stored name", ts: online, chosen: "tailnet", address: "100.64.0.2",
			host: host(1, "p", func(h *model.Host) { h.Addresses = []string{"prod.tn.ts.net"}; linked("nA", "")(h) }),
		},
		{
			name: "the link's DNS name is used when the node is not in the status", ts: stopped, chosen: "tailnet", address: "prod.tn.ts.net",
			host: host(1, "p", func(h *model.Host) { linked("nA", "prod.tn.ts.net.")(h) }),
		},
		{
			name: "a short name that matches a node stays direct, with no DNS asked", ts: online, chosen: "direct", address: "prod", reason: "no tailnet address",
			host: host(1, "p", func(h *model.Host) { h.Addresses = []string{"prod"} }),
		},
		{
			name: "a short name beside another direct address is the first direct address", ts: online, chosen: "direct", address: "PROD",
			host: host(1, "p", func(h *model.Host) { h.Addresses = []string{"PROD", "203.0.113.10"} }),
		},
		{
			name: "a short name of an unknown node stays direct", ts: online, chosen: "direct", address: "other", reason: "no tailnet address",
			host: host(1, "p", func(h *model.Host) { h.Addresses = []string{"other"} }),
		},
		{
			name: "a short name two nodes share stays direct", ts: tsStatus(node("nA", "prod", "prod.tn.ts.net", true, "100.64.0.2"), node("nB", "prod", "prod.tn.ts.net", true, "100.64.0.3")),
			chosen: "direct", address: "prod", reason: "no tailnet address",
			host: host(1, "p", func(h *model.Host) { h.Addresses = []string{"prod"} }),
		},
		{
			name: "a short name with tailscale stopped stays direct", ts: stopped, chosen: "direct", address: "prod", reason: "no tailnet address",
			host: host(1, "p", func(h *model.Host) { h.Addresses = []string{"prod"} }),
		},
		{
			name: "route direct keeps a short name that shares a node's name", ts: online,
			chosen: "direct", address: "prod",
			host: host(1, "p", func(h *model.Host) { h.Route = "direct"; h.Addresses = []string{"prod"} }),
		},
		{
			name: "route direct with a short name and a tailnet link", ts: online,
			chosen: "direct", address: "prod",
			host: host(1, "p", func(h *model.Host) {
				h.Route = "direct"
				h.Addresses = []string{"prod"}
				linked("nA", "prod.tn.ts.net")(h)
			}),
		},
		{
			name: "auto keeps the short name as the fallback of a linked node", ts: online,
			chosen: "tailnet", address: "100.64.0.2", fallback: "prod",
			host: host(1, "p", func(h *model.Host) { h.Addresses = []string{"prod"}; linked("nA", "prod.tn.ts.net")(h) }),
		},
		{
			name: "an exact FQDN beats a short name of another node", ts: twoNodes,
			chosen: "tailnet", address: "100.64.0.2", fallback: "b",
			host: host(1, "p", func(h *model.Host) { h.Addresses = []string{"b", "a.tn.ts.net"} }),
		},
		{
			name: "route direct with a short name beside an FQDN", ts: twoNodes,
			chosen: "direct", address: "b",
			host: host(1, "p", func(h *model.Host) { h.Route = "direct"; h.Addresses = []string{"b", "a.tn.ts.net"} }),
		},
		{
			name: "a Tailscale IP beats a short name of another node", ts: twoNodes,
			chosen: "tailnet", address: "100.64.0.2", fallback: "b",
			host: host(1, "p", func(h *model.Host) { h.Addresses = []string{"b", "100.64.0.2"} }),
		},
		{
			name: "the stable node ID beats a short name of another node", ts: twoNodes,
			chosen: "tailnet", address: "100.64.0.2", fallback: "b",
			host: host(1, "p", func(h *model.Host) { h.Addresses = []string{"b"}; linked("nA", "")(h) }),
		},
		{
			name: "a short name alone stays direct", ts: twoNodes,
			chosen: "direct", address: "b",
			host: host(1, "p", func(h *model.Host) { h.Addresses = []string{"b"} }),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r, err := ChooseRoute(tt.host, tt.ts)
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("err = %v, want one containing %q", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if (tt.blocked == "") != (r.Blocked == "") || !strings.Contains(r.Blocked, tt.blocked) {
				t.Errorf("blocked = %q, want one containing %q", r.Blocked, tt.blocked)
			}
			if r.Chosen != tt.chosen || (tt.address != "" && r.Address != tt.address) || r.Fallback != tt.fallback || !strings.Contains(r.Reason, tt.reason) {
				t.Errorf("got %+v; want chosen=%s address=%s fallback=%s reason~%q", r, tt.chosen, tt.address, tt.fallback, tt.reason)
			}
			wantPort := 22
			if tt.host.Port != 0 {
				wantPort = int(tt.host.Port)
			}
			if r.Port != wantPort {
				t.Errorf("port = %d, want %d", r.Port, wantPort)
			}
		})
	}
}

func TestTailscaleSSHOnlyRoutes(t *testing.T) {
	n := node("nA", "prod", "prod.tn.ts.net", true, "100.64.0.2")
	online := tsStatus(n)
	stopped := tailscale.Unavailable("tailscale is Stopped")

	mk := func(mod func(*model.Host)) model.Host {
		return host(1, "prod", func(h *model.Host) {
			h.Addresses = []string{"203.0.113.10"}
			linked("nA", "prod.tn.ts.net")(h)
			h.Tailscale.SSH = "yes"
			if mod != nil {
				mod(h)
			}
		})
	}
	keyed := func(h *model.Host) { h.KeyID = id(9) }
	tests := []struct {
		name    string
		host    model.Host
		ts      *tailscale.Status
		only    bool
		address string
		blocked bool
		wantErr string
	}{
		{name: "keyless", host: mk(nil), ts: online, only: true, address: "100.64.0.2"},
		{name: "keyless, tailscale not running here: blocked", host: mk(nil), ts: stopped, only: true, address: "prod.tn.ts.net", blocked: true},
		{name: "keyless with route tailnet", host: mk(func(h *model.Host) { h.Route = "tailnet" }), ts: online, only: true, address: "100.64.0.2"},
		{name: "keyless with route direct is refused", host: mk(func(h *model.Host) { h.Route = "direct" }), ts: online, wantErr: "route direct cannot work"},
		{name: "keyless but Tailscale SSH unknown", host: mk(func(h *model.Host) { h.Tailscale.SSH = "unknown" }), ts: online, address: "100.64.0.2"},
		// A keyed host is kept to the tailnet by what is stored on it, not by
		// what Tailscale shows now.
		{name: "keyed, route auto, tailscale running: the usual auto", host: mk(keyed), ts: online, address: "100.64.0.2"},
		{name: "keyed, route auto, tailscale stopped: direct", host: mk(keyed), ts: stopped, address: "203.0.113.10"},
		{name: "keyed, route tailnet", host: mk(func(h *model.Host) { keyed(h); h.Route = "tailnet" }), ts: online, address: "100.64.0.2"},
		{name: "keyed, route tailnet, tailscale stopped: blocked, not direct", host: mk(func(h *model.Host) { keyed(h); h.Route = "tailnet" }), ts: stopped, address: "prod.tn.ts.net", blocked: true},
		{name: "keyed, route tailnet, node not visible: blocked, not direct", host: mk(func(h *model.Host) { keyed(h); h.Route = "tailnet" }), ts: nil, address: "prod.tn.ts.net", blocked: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, only := TailscaleSSHOnly(tt.host)
			r, err := ChooseRoute(tt.host, tt.ts)
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("err = %v, want %q", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if only != tt.only || r.TailscaleSSH != tt.only {
				t.Errorf("only = %v, route.TailscaleSSH = %v, want %v", only, r.TailscaleSSH, tt.only)
			}
			if r.Address != tt.address {
				t.Errorf("address = %q, want %q", r.Address, tt.address)
			}
			if (r.Blocked != "") != tt.blocked {
				t.Errorf("blocked = %q, want blocked=%v", r.Blocked, tt.blocked)
			}
			if tt.only || tt.host.Route == "tailnet" {
				if r.Chosen != RouteTailnet || r.Fallback != "" {
					t.Errorf("route = %+v: the tailnet, no fallback", r)
				}
			}
			if tt.only && r.Label() != "tailnet (Tailscale SSH)" {
				t.Errorf("label = %q", r.Label())
			}
		})
	}
}

func TestSuggestLink(t *testing.T) {
	online := tsStatus(node("nA", "prod", "prod.tn.ts.net", true, "100.64.0.2"))
	twins := tsStatus(node("nA", "prod", "prod.tn.ts.net", true, "100.64.0.2"), node("nB", "prod", "prod-1.tn.ts.net", true, "100.64.0.3"))
	with := func(mod func(*model.Host), addrs ...string) model.Host {
		return host(1, "web", func(h *model.Host) {
			h.Addresses = addrs
			if mod != nil {
				mod(h)
			}
		})
	}
	const hint = "prod matches tailnet node prod; to route over Tailscale: hop ts link web nA"
	tests := []struct {
		name string
		host model.Host
		ts   *tailscale.Status
		want string
	}{
		{name: "a short name of one node", host: with(nil, "prod"), ts: online, want: hint},
		{name: "case does not matter", host: with(nil, "PROD", "203.0.113.10"), ts: online, want: "PROD matches tailnet node prod; to route over Tailscale: hop ts link web nA"},
		{name: "a host name that is not the first label names the label", host: with(nil, "prod"), ts: tsStatus(node("nA", "prod", "prod-1.tn.ts.net", true, "100.64.0.2")), want: "prod matches tailnet node prod-1; to route over Tailscale: hop ts link web nA"},
		{name: "a node name two nodes share says nothing", host: with(nil, "prod"), ts: twins},
		{name: "a name no node has says nothing", host: with(nil, "other"), ts: online},
		{name: "an FQDN is not a short name", host: with(nil, "prod.example.com"), ts: online},
		{name: "an IP says nothing", host: with(nil, "203.0.113.10"), ts: online},
		{name: "a linked host says nothing", host: with(linked("nA", "prod.tn.ts.net"), "prod"), ts: online},
		{name: "a link to a node not in the status says nothing", host: with(linked("nGone", "gone.tn.ts.net"), "prod"), ts: online},
		{name: "a host with a tailnet address says nothing", host: with(nil, "prod", "100.64.0.2"), ts: online},
		{name: "a host behind a jump host says nothing", host: with(func(h *model.Host) { h.JumpHostID = id(7) }, "prod"), ts: online},
		{name: "tailscale stopped says nothing", host: with(nil, "prod"), ts: tailscale.Unavailable("tailscale is Stopped")},
		{name: "no status says nothing", host: with(nil, "prod")},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, got, ok := SuggestLink(tt.host, tt.ts)
			if got != tt.want || ok != (tt.want != "") {
				t.Errorf("SuggestLink = %q, %v; want %q", got, ok, tt.want)
			}
		})
	}
}
