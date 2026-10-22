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
		wantErr  string
	}{
		{name: "auto, online: tailnet, direct as fallback", host: both("auto"), ts: online, chosen: "tailnet", address: "100.64.0.2", fallback: "203.0.113.10", reason: "online"},
		{name: "empty route means auto", host: both(""), ts: online, chosen: "tailnet", address: "100.64.0.2", fallback: "203.0.113.10"},
		{name: "auto, peer offline: direct", host: both("auto"), ts: offline, chosen: "direct", address: "203.0.113.10", reason: "offline"},
		{name: "auto, tailscale stopped: direct", host: both("auto"), ts: stopped, chosen: "direct", address: "203.0.113.10", reason: "not running"},
		{name: "auto, no status at all: direct", host: both("auto"), ts: nil, chosen: "direct", address: "203.0.113.10"},
		{name: "direct ignores a running tailnet", host: both("direct"), ts: online, chosen: "direct", address: "203.0.113.10"},
		{name: "tailnet when online", host: both("tailnet"), ts: online, chosen: "tailnet", address: "100.64.0.2"},
		{name: "tailnet even when stopped", host: both("tailnet"), ts: stopped, chosen: "tailnet", reason: "tailscale is not running"},
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
