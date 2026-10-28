package cli_test

import (
	"context"
	"encoding/json"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/dalyem/hopkey/internal/cli"
	"github.com/dalyem/hopkey/internal/model"
	"github.com/dalyem/hopkey/internal/tailscale"
)

type fixedTS struct{ st *tailscale.Status }

func (f fixedTS) Status(context.Context) (*tailscale.Status, error) { return f.st, nil }

func tailnet(t *testing.T) (*tailscale.Status, string) {
	t.Helper()
	signer := newSigner(t)
	pubLine := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(signer.PublicKey())))
	st := &tailscale.Status{
		Available: true, MagicDNSSuffix: "tn.ts.net",
		Self: tailscale.Node{ID: "nSELF", HostName: "laptop", DNSName: "laptop.tn.ts.net", Online: true, IPs: []string{"100.64.0.1"}, Self: true},
		Peers: []tailscale.Node{
			{ID: "nBUILD1", HostName: "build", DNSName: "build.tn.ts.net", Online: true, IPs: []string{"100.64.0.3", "fd7a:115c:a1e0::3"}},
			{ID: "nBUILD2", HostName: "build", DNSName: "build-1.tn.ts.net", Online: false, IPs: []string{"100.64.0.4"}},
			{ID: "nPHONE", HostName: "Daly's iPhone", DNSName: "dalys-iphone.tn.ts.net", IPs: []string{"100.64.0.5"}},
			{ID: "nPRODDB", HostName: "prod-db", DNSName: "prod-db.tn.ts.net", Online: true, IPs: []string{"100.64.0.2"}, SSHHostKeys: []string{pubLine, "not a key"}},
		},
	}
	return st, pubLine
}

func decodeTS(t *testing.T, stdout string) map[string]cli.TSEntry {
	t.Helper()
	var entries []cli.TSEntry
	if err := json.Unmarshal([]byte(stdout), &entries); err != nil {
		t.Fatalf("%v\n%s", err, stdout)
	}
	m := map[string]cli.TSEntry{}
	for _, e := range entries {
		m[e.NodeID] = e
	}
	return m
}

// The text report is for people: the JSON statuses are identifiers
// (would_created), the text says "would create".
func TestTSImportDryRunTextIsPlainEnglish(t *testing.T) {
	st, _ := tailnet(t)
	e := newE2EWith(t, fixedTS{st})
	code, stdout, stderr := e.hop(t, "ts", "import", "--dry-run")
	if code != 0 {
		t.Fatalf("dry run: %d %s", code, stderr)
	}
	if strings.Contains(stdout, "would_") || strings.Contains(stdout, "_") {
		t.Errorf("text report has a status identifier in it:\n%s", stdout)
	}
	if !strings.Contains(stdout, "would create") {
		t.Errorf("text report does not say \"would create\":\n%s", stdout)
	}
}

func TestTSImportCreatesAndLinksHosts(t *testing.T) {
	st, _ := tailnet(t)
	e := newE2EWith(t, fixedTS{st})
	// An existing host that is evidently the prod-db node, not yet linked.
	if _, err := e.store.PutHost(context.Background(), model.Host{
		Name: "prod-db", Addresses: []string{"203.0.113.10"}, Port: 22, Route: "auto", AgentAccess: "allow",
	}); err != nil {
		t.Fatal(err)
	}

	before := e.store.Writes()
	code, stdout, stderr := e.hop(t, "ts", "import", "--dry-run", "--json")
	if code != 0 {
		t.Fatalf("dry run: %d %s", code, stderr)
	}
	if e.store.Writes() != before {
		t.Error("--dry-run wrote to the vault")
	}
	if got := decodeTS(t, stdout); got["nPRODDB"].Status != "would_linked" || got["nBUILD1"].Status != "would_created" {
		t.Errorf("dry run report = %+v", got)
	}

	code, stdout, stderr = e.hop(t, "ts", "import", "--json", "--user", "ops", "--key", "deploy-key", "--tag", "tailnet")
	if code != 0 {
		t.Fatalf("import: %d %s", code, stderr)
	}
	got := decodeTS(t, stdout)
	want := map[string][2]string{ // node -> host, status
		"nPRODDB": {"prod-db", "linked"},
		"nBUILD1": {"build", "created"},
		"nBUILD2": {"build-1", "created"}, // "build" is taken: use the MagicDNS label
		"nPHONE":  {"dalys-iphone", "created"},
	}
	for id, w := range want {
		if got[id].Host != w[0] || got[id].Status != w[1] {
			t.Errorf("%s: %+v, want host %s status %s", id, got[id], w[0], w[1])
		}
	}
	if _, ok := got["nSELF"]; ok {
		t.Error("this machine was imported without --include-self")
	}

	_, stdout, _ = e.hop(t, "ls", "--json")
	var views []cli.HostView
	if err := json.Unmarshal([]byte(stdout), &views); err != nil {
		t.Fatal(err)
	}
	byName := map[string]cli.HostView{}
	for _, v := range views {
		byName[v.Name] = v
	}
	prod := byName["prod-db"]
	if prod.Tailscale == nil || prod.Tailscale.StableNodeID != "nPRODDB" || prod.Tailscale.SSH != "yes" || prod.Tailscale.Online == nil || !*prod.Tailscale.Online {
		t.Errorf("prod-db link = %+v", prod.Tailscale)
	}
	if len(prod.HostKeys) != 1 || !slices.Contains(prod.Addresses, "203.0.113.10") || !slices.Contains(prod.Addresses, "prod-db.tn.ts.net") {
		t.Errorf("prod-db after linking: pins=%v addresses=%v (the unparseable key must be dropped; the old address kept)", prod.HostKeys, prod.Addresses)
	}
	// prod-db is Tailscale SSH and now pinned to Tailscale's keys: the vault
	// says it is tailnet-only. build says nothing about SSH, so it stays auto.
	if prod.Route != "tailnet" || byName["dalys-iphone"].Route != "auto" || byName["build"].Route != "auto" {
		t.Errorf("routes: prod-db %q, dalys-iphone %q, build %q", prod.Route, byName["dalys-iphone"].Route, byName["build"].Route)
	}
	build := byName["build"]
	if build.User != "ops" || build.Key == nil || build.Key.Name != "deploy-key" || !slices.Equal(build.Tags, []string{"tailnet"}) ||
		build.Tailscale == nil || build.Tailscale.SSH != "unknown" || len(build.HostKeys) != 0 || build.Addresses[0] != "100.64.0.3" {
		t.Errorf("build = %+v", build)
	}
	if online := byName["build-1"].Tailscale.Online; online == nil || *online {
		t.Error("build-1 should be offline")
	}

	// The import stored the tailnet address, so the address rule finds them,
	// and the route follows the live status.
	code, stdout, _ = e.hop(t, "which", "--json", "100.64.0.3")
	var w cli.WhichResult
	json.Unmarshal([]byte(stdout), &w)
	if code != 0 || w.Rule != "address" || w.Host == nil || w.Host.Name != "build" || w.Route == nil || w.Route.Chosen != "tailnet" {
		t.Errorf("which 100.64.0.3: code=%d %+v", code, w)
	}
	// The other node with the same host name is reachable by its own DNS name.
	code, stdout, _ = e.hop(t, "which", "--json", "build-1.tn.ts.net")
	json.Unmarshal([]byte(stdout), &w)
	if code != 0 || w.Host == nil || w.Host.Name != "build-1" {
		t.Errorf("which build-1.tn.ts.net: code=%d %+v", code, w)
	}

	// Running it again changes nothing.
	before = e.store.Writes()
	_, stdout, _ = e.hop(t, "ts", "import", "--json")
	for id, en := range decodeTS(t, stdout) {
		if en.Status != "already_linked" {
			t.Errorf("second import: %s is %q", id, en.Status)
		}
	}
	if e.store.Writes() != before {
		t.Error("the second import wrote to the vault")
	}

	// Hosts that now have a key are in the generated config.
	if cfg := e.configFile(t); !strings.Contains(cfg, "Host build\n") || !strings.Contains(cfg, "HostName 100.64.0.3") {
		t.Errorf("imported host build is not in the config:\n%s", cfg)
	}
}

func TestTSImportNamedPeersAndErrors(t *testing.T) {
	st, _ := tailnet(t)
	e := newE2EWith(t, fixedTS{st})

	code, stdout, _ := e.hop(t, "ts", "import", "--json", "prod-db", "--no-pin")
	got := decodeTS(t, stdout)
	if code != 0 || len(got) != 1 || got["nPRODDB"].Status != "created" {
		t.Errorf("named import: code=%d %+v", code, got)
	}
	_, stdout, _ = e.hop(t, "info", "--json", "prod-db")
	var v cli.HostView
	json.Unmarshal([]byte(stdout), &v)
	if len(v.HostKeys) != 0 {
		t.Errorf("--no-pin still pinned %v", v.HostKeys)
	}

	if code, _, stderr := e.hop(t, "ts", "import", "nonesuch"); code != 255 || !strings.Contains(stderr, "no tailscale node matches") {
		t.Errorf("unknown peer: code=%d stderr=%q", code, stderr)
	}
	// Two nodes share the host name "build": naming it imports both.
	_, stdout, _ = e.hop(t, "ts", "import", "--json", "build")
	if got := decodeTS(t, stdout); len(got) != 2 {
		t.Errorf("import of a duplicated host name: %+v", got)
	}
	_, stdout, _ = e.hop(t, "ts", "import", "--json", "--include-self")
	if got := decodeTS(t, stdout); got["nSELF"].Status != "created" {
		t.Errorf("--include-self: %+v", got["nSELF"])
	}
}

func TestTSLink(t *testing.T) {
	st, _ := tailnet(t)
	e := newE2EWith(t, fixedTS{st})

	code, stdout, stderr := e.hop(t, "ts", "link", "web-1", "prod-db.tn.ts.net", "--json")
	got := decodeTS(t, stdout)
	if code != 0 || got["nPRODDB"].Host != "web-1" || got["nPRODDB"].Status != "linked" {
		t.Fatalf("link: code=%d %+v stderr=%q", code, got, stderr)
	}
	// web-1 already had a pin, so Tailscale's key was not added on top.
	_, stdout, _ = e.hop(t, "info", "--json", "web-1")
	var v cli.HostView
	json.Unmarshal([]byte(stdout), &v)
	if v.Tailscale == nil || v.Tailscale.StableNodeID != "nPRODDB" || len(v.HostKeys) != 1 {
		t.Errorf("web-1 = %+v", v)
	}
	// The node runs Tailscale SSH, so linking restricts the host to the tailnet.
	if v.Route != "tailnet" {
		t.Errorf("web-1 route = %q after linking a Tailscale SSH node", v.Route)
	}
	// And now the node resolves to web-1.
	if code, out, _ := e.hop(t, "which", "100.64.0.2"); code != 0 || !strings.Contains(out, "host:     web-1") {
		t.Errorf("which after link: code=%d\n%s", code, out)
	}

	for _, tc := range []struct {
		args []string
		want string
	}{
		{[]string{"ts", "link", "web-2", "prod-db"}, "already linked to host"},        // the node belongs to web-1
		{[]string{"ts", "link", "web-1", "build-1.tn.ts.net"}, "pass --force"},        // web-1 is linked elsewhere
		{[]string{"ts", "link", "web-2", "build"}, "matches several tailscale nodes"}, // duplicate host name
		{[]string{"ts", "link", "web-2", "nothing"}, "no tailscale node matches"},
		{[]string{"ts", "link", "nobody", "prod-db"}, "no host matches"},
		{[]string{"ts", "link", "web-2"}, "expected a host and a tailscale name"},
	} {
		if code, _, stderr := e.hop(t, tc.args...); code != 255 || !strings.Contains(stderr, tc.want) {
			t.Errorf("hop %v: code=%d stderr=%q, want %q", tc.args, code, stderr, tc.want)
		}
	}
	if code, _, stderr := e.hop(t, "ts", "link", "web-1", "build-1.tn.ts.net", "--force"); code != 0 {
		t.Errorf("--force: %d %s", code, stderr)
	}
}

func TestTSCommandsWithoutTailscale(t *testing.T) {
	e := newE2E(t) // noTailscale
	for _, args := range [][]string{{"ts", "import"}, {"ts", "link", "web-1", "x"}} {
		if code, _, stderr := e.hop(t, args...); code != 255 || !strings.Contains(stderr, "tailscale is not available") {
			t.Errorf("hop %v: code=%d stderr=%q", args, code, stderr)
		}
	}
}

// twinTailnet is a tailnet with two peers called "build", both publishing SSH
// host keys, in the order given.
func twinTailnet(t *testing.T, reversed bool) *tailscale.Status {
	t.Helper()
	pub := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(newSigner(t).PublicKey())))
	a := tailscale.Node{ID: "nBUILDA", HostName: "build", DNSName: "build.tn.ts.net", Online: true, IPs: []string{"100.64.0.10"}, SSHHostKeys: []string{pub}}
	b := tailscale.Node{ID: "nBUILDB", HostName: "build", DNSName: "build-1.tn.ts.net", Online: true, IPs: []string{"100.64.0.11"}, SSHHostKeys: []string{pub}}
	peers := []tailscale.Node{a, b}
	if reversed {
		peers = []tailscale.Node{b, a}
	}
	return &tailscale.Status{
		Available: true, MagicDNSSuffix: "tn.ts.net",
		Self:  tailscale.Node{ID: "nSELF", HostName: "laptop", DNSName: "laptop.tn.ts.net", Online: true, IPs: []string{"100.64.0.1"}, Self: true},
		Peers: peers,
	}
}

func TestTSImportNeverLinksAnAmbiguousHost(t *testing.T) {
	for _, reversed := range []bool{false, true} {
		name := "peers in order"
		if reversed {
			name = "peers reversed"
		}
		t.Run(name, func(t *testing.T) {
			e := newE2EWith(t, fixedTS{twinTailnet(t, reversed)})
			// An existing, unlinked, unpinned host that could be either peer.
			if _, err := e.store.PutHost(context.Background(), model.Host{
				Name: "build", Addresses: []string{"203.0.113.50"}, Port: 22, Route: "auto", AgentAccess: "allow",
			}); err != nil {
				t.Fatal(err)
			}
			before := e.store.Writes()
			code, stdout, stderr := e.hop(t, "ts", "import", "--json")
			if code != 0 {
				t.Fatalf("import: %d %s", code, stderr)
			}
			got := decodeTS(t, stdout)
			for _, id := range []string{"nBUILDA", "nBUILDB"} {
				if got[id].Status != "ambiguous" || !strings.Contains(got[id].Reason, "hop ts link <host> "+id) {
					t.Errorf("%s: %+v, want ambiguous with a pointer to hop ts link", id, got[id])
				}
			}
			if e.store.Writes() != before {
				t.Errorf("an ambiguous import wrote %d times; nothing may be linked, pinned or created", e.store.Writes()-before)
			}
			snap, err := e.store.Snapshot(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			for _, h := range snap.Hosts {
				if h.Name == "build" && (h.Tailscale != nil || len(h.HostKeys) != 0) {
					t.Errorf("host build was linked or pinned: tailscale=%+v pins=%v", h.Tailscale, h.HostKeys)
				}
			}

			// Picking a node by its ID is the way out, and then it pins.
			if code, _, stderr := e.hop(t, "ts", "link", "build", "nBUILDB"); code != 0 {
				t.Fatalf("ts link by node ID: %d %s", code, stderr)
			}
			_, stdout, _ = e.hop(t, "info", "--json", "build")
			var v cli.HostView
			json.Unmarshal([]byte(stdout), &v)
			if v.Tailscale == nil || v.Tailscale.StableNodeID != "nBUILDB" || len(v.HostKeys) != 1 {
				t.Errorf("after ts link: %+v", v)
			}
		})
	}
}

func TestTSImportAmbiguousInTheOtherDirection(t *testing.T) {
	// One node, two hosts that both look like it: neither gets linked.
	st, _ := tailnet(t)
	e := newE2EWith(t, fixedTS{st})
	ctx := context.Background()
	for _, h := range []model.Host{
		{Name: "prod-db", Addresses: []string{"203.0.113.10"}, Port: 22, Route: "auto", AgentAccess: "allow"},
		{Name: "pdb", Aliases: []string{"prod-db.tn.ts.net"}, Addresses: []string{"100.64.0.2"}, Port: 22, Route: "auto", AgentAccess: "allow"},
	} {
		if _, err := e.store.PutHost(ctx, h); err != nil {
			t.Fatal(err)
		}
	}
	before := e.store.Writes()
	_, stdout, _ := e.hop(t, "ts", "import", "--json", "prod-db")
	if got := decodeTS(t, stdout); got["nPRODDB"].Status != "ambiguous" {
		t.Errorf("report = %+v", got)
	}
	if e.store.Writes() != before {
		t.Error("an ambiguous import wrote to the vault")
	}
}

// swapTS is a Tailscale source the test can change under a running daemon.
type swapTS struct {
	mu sync.Mutex
	st *tailscale.Status
}

func (s *swapTS) Status(context.Context) (*tailscale.Status, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.st, nil
}

func (s *swapTS) set(st *tailscale.Status) {
	s.mu.Lock()
	s.st = st
	s.mu.Unlock()
	time.Sleep(2200 * time.Millisecond) // the daemon caches the status for 2 seconds
}

// TestTSImportedHostStaysOnTheTailnetWhileTailscaleIsDown: the restriction is
// stored on the host by ts import and ts link, so it holds when Tailscale is
// not running and the node is not visible. The host has a direct address and
// a key, which hop must not fall back to.
func TestTSImportedHostStaysOnTheTailnetWhileTailscaleIsDown(t *testing.T) {
	st, _ := tailnet(t)
	src := &swapTS{st: st}
	e := newE2EWith(t, src)
	// A host with a key and a direct address that is the prod-db node.
	if _, err := e.store.PutHost(context.Background(), model.Host{
		Name: "prod-db", Addresses: []string{"127.0.0.1"}, Port: uint32(e.server.port), User: "deploy",
		KeyID: e.keyID, Route: "auto", AgentAccess: "allow",
	}); err != nil {
		t.Fatal(err)
	}
	if code, _, stderr := e.hop(t, "ts", "import", "prod-db"); code != 0 {
		t.Fatalf("ts import: %d %s", code, stderr)
	}
	if v := e.view(t, "prod-db"); v.Route != "tailnet" || len(v.HostKeys) == 0 {
		t.Fatalf("prod-db after import: route %q, pins %v", v.Route, v.HostKeys)
	}

	src.set(tailscale.Unavailable("tailscale is Stopped"))
	before := e.server.connections()

	code, stdout, stderr := e.hop(t, "which", "--json", "prod-db")
	var w cli.WhichResult
	if err := json.Unmarshal([]byte(stdout), &w); err != nil || code != 0 || w.Route == nil {
		t.Fatalf("which: %d %v %s %s", code, err, stdout, stderr)
	}
	if w.Route.Chosen != "tailnet" || w.Route.Fallback != "" || w.Route.Address == "127.0.0.1" || !strings.Contains(w.Route.Blocked, "tailscale is not available here") {
		t.Errorf("route = %+v: the tailnet, blocked, no direct address", w.Route)
	}
	for _, args := range [][]string{
		{"exec", "prod-db", "--", "echo", "ok"},
		{"trust", "prod-db", "--yes"},
		{"connect", "prod-db"},
	} {
		code, _, stderr := e.hop(t, args...)
		if code != 255 || !strings.Contains(stderr, "tailscale is not available here") || !strings.Contains(stderr, "does not fall back to a direct address") {
			t.Errorf("hop %v: code=%d stderr=%q, want a clear refusal", args, code, stderr)
		}
	}
	code, stdout, _ = e.hop(t, "check", "prod-db", "--json")
	var res cli.CheckResult
	if err := json.Unmarshal([]byte(stdout), &res); err != nil {
		t.Fatal(err)
	}
	for _, s := range res.Steps {
		if s.Name == "route" && (s.Status != "fail" || !strings.Contains(s.Detail, "tailscale is not available here")) {
			t.Errorf("route step = %+v", s)
		}
	}
	if code == 0 {
		t.Error("check passed for a blocked host")
	}
	if got := e.server.connections() - before; got != 0 {
		t.Errorf("hop connected %d times to the direct address of a tailnet-only host", got)
	}

	// With Tailscale back, the route is the tailnet address again.
	src.set(st)
	_, stdout, _ = e.hop(t, "which", "--json", "prod-db")
	w = cli.WhichResult{}
	json.Unmarshal([]byte(stdout), &w)
	if w.Route == nil || w.Route.Blocked != "" || w.Route.Address != "100.64.0.2" {
		t.Errorf("route with tailscale back = %+v", w.Route)
	}
}

func TestTSLinkSetsTailnetOnlyForTailscaleSSHHosts(t *testing.T) {
	for _, tc := range []struct{ name, route, node, want string }{
		{"a node with published keys", "auto", "nPRODDB", "tailnet"},
		{"a node without any", "auto", "nBUILD1", "auto"},
		{"a route the user chose is not overridden", "direct", "nPRODDB", "direct"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			st, _ := tailnet(t)
			e := newE2EWith(t, fixedTS{st})
			if _, err := e.store.PutHost(context.Background(), model.Host{
				Name: "h", Addresses: []string{"203.0.113.9"}, Port: 22, Route: tc.route, AgentAccess: "allow",
			}); err != nil {
				t.Fatal(err)
			}
			if code, _, stderr := e.hop(t, "ts", "link", "h", tc.node); code != 0 {
				t.Fatalf("ts link: %d %s", code, stderr)
			}
			if got := e.view(t, "h").Route; got != tc.want {
				t.Errorf("route = %q, want %q", got, tc.want)
			}
		})
	}
}
