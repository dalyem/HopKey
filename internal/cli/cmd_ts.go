package cli

import (
	"context"
	"fmt"
	"slices"
	"strings"

	"github.com/dalyem/hopkey/internal/daemon"
	"github.com/dalyem/hopkey/internal/model"
	"github.com/dalyem/hopkey/internal/resolve"
	"github.com/dalyem/hopkey/internal/sshconfig"
	"github.com/dalyem/hopkey/internal/sshkeys"
	"github.com/dalyem/hopkey/internal/tailscale"
)

func runTS(ctx context.Context, e *Env, args []string) error {
	if len(args) == 0 {
		fmt.Fprintf(e.Stderr, "usage: %s\n", commands["ts"].usage)
		return failf("ts needs a subcommand: import or link")
	}
	switch args[0] {
	case "import":
		return runTSImport(ctx, e, args[1:])
	case "link":
		return runTSLink(ctx, e, args[1:])
	}
	return failf("unknown ts subcommand %q (import, link)", args[0])
}

func tailnetStatus(ctx context.Context, e *Env) (*tailscale.Status, error) {
	var st tailscale.Status
	if err := call(ctx, e, daemon.OpTailscale, nil, &st); err != nil {
		return nil, err
	}
	if !st.Available {
		return nil, failf("tailscale is not available here: %s", orUnknown(st.Reason))
	}
	return &st, nil
}

// TSEntry is one line of the --json report of hop ts import and hop ts link.
type TSEntry struct {
	Node   string `json:"node"`
	NodeID string `json:"node_id"`
	Host   string `json:"host,omitempty"`
	Status string `json:"status"` // created, linked, already_linked, ambiguous, skipped (or would_* with --dry-run)
	Reason string `json:"reason,omitempty"`
}

// tsLink fills in h's Tailscale link from n. Pins come from the node's
// published SSH host keys, which the control plane vouches for, but only when
// the host has none of its own. It reports how many pins it added.
func tsLink(h *model.Host, n tailscale.Node, pin bool) int {
	h.Tailscale = &model.Tailscale{StableNodeID: n.ID, DNSName: n.DNSName, SSH: n.SSH()}
	if n.DNSName != "" && !slices.ContainsFunc(h.Addresses, func(a string) bool { return strings.EqualFold(a, n.DNSName) }) {
		h.Addresses = append(h.Addresses, n.DNSName)
	}
	if ip := firstV4(n.IPs); ip != "" && !slices.Contains(h.Addresses, ip) {
		h.Addresses = append(h.Addresses, ip)
	}
	added := 0
	if pin && len(h.HostKeys) == 0 {
		for _, line := range n.SSHHostKeys {
			if p, err := sshkeys.ParsePublic(line); err == nil {
				h.HostKeys = append(h.HostKeys, sshkeys.Line(p))
				added++
			}
		}
	}
	return added
}

// tsMatch reports whether the unlinked host h is evidently the node n: one of
// its names is the node's host name or MagicDNS label, or one of its stored
// addresses names the node.
func tsMatch(st *tailscale.Status, h model.Host, n tailscale.Node) bool {
	byName := slices.ContainsFunc(resolve.Names(h), func(x string) bool {
		return strings.EqualFold(x, n.HostName) || strings.EqualFold(x, n.ShortName())
	})
	return byName || slices.ContainsFunc(h.Addresses, func(a string) bool {
		return slices.ContainsFunc(st.Find(a), func(f tailscale.Node) bool { return f.ID == n.ID })
	})
}

// tsPairs is the candidate graph between unlinked vault hosts and tailnet
// nodes, built before anything is linked so that the order of the peers in
// the status output cannot decide who gets which host.
type tsPairs struct {
	byNode map[string][]int // node ID -> indexes of the hosts it could be
	byHost map[int][]string // host index -> IDs of the nodes it could be
	nodes  map[string]tailscale.Node
}

func tsCandidates(st *tailscale.Status, hosts []model.Host) *tsPairs {
	p := &tsPairs{byNode: map[string][]int{}, byHost: map[int][]string{}, nodes: map[string]tailscale.Node{}}
	for _, n := range st.Nodes() {
		p.nodes[n.ID] = n
		for i, h := range hosts {
			if h.Tailscale == nil && tsMatch(st, h, n) {
				p.byNode[n.ID] = append(p.byNode[n.ID], i)
				p.byHost[i] = append(p.byHost[i], n.ID)
			}
		}
	}
	return p
}

func (p *tsPairs) hostsFor(nodeID string) []int { return p.byNode[nodeID] }

// ambiguous is true when the node matches several hosts, or when a host it
// matches could equally be another node.
func (p *tsPairs) ambiguous(nodeID string) bool {
	hs := p.byNode[nodeID]
	if len(hs) > 1 {
		return true
	}
	return len(hs) == 1 && len(p.byHost[hs[0]]) > 1
}

func (p *tsPairs) reason(hosts []model.Host, n tailscale.Node) string {
	var names []string
	for _, i := range p.byNode[n.ID] {
		names = append(names, hosts[i].Name)
		for _, other := range p.byHost[i] {
			if other != n.ID {
				names = append(names, "node "+p.nodes[other].DNSName)
			}
		}
	}
	slices.Sort(names)
	names = slices.Compact(names)
	return fmt.Sprintf("could be more than one host or node (%s); nothing was linked or pinned. Pick one: hop ts link <host> %s", strings.Join(names, ", "), n.ID)
}

// findNode finds the node a user means for hop ts link: by stable node ID,
// else by name or IP.
func findNode(st *tailscale.Status, s string) []tailscale.Node {
	if n, ok := st.NodeByID(s); ok {
		return []tailscale.Node{n}
	}
	return st.Find(s)
}

func firstV4(ips []string) string {
	for _, ip := range ips {
		if !strings.Contains(ip, ":") {
			return ip
		}
	}
	return ""
}

// hostNameFor derives a vault host name from a tailnet node: its host name
// made safe for ssh, then its MagicDNS label, then the label plus the node ID.
func hostNameFor(n tailscale.Node, taken func(string) bool) string {
	for _, c := range []string{n.HostName, n.ShortName()} {
		if name := suggestName(c); c != "" && sshconfig.ValidAlias(name) && !taken(name) {
			return name
		}
	}
	id := strings.ToLower(strings.TrimSuffix(strings.TrimPrefix(n.ID, "n"), "CNTRL"))
	base := suggestName(n.ShortName())
	if n.ShortName() == "" {
		base = suggestName(n.HostName)
	}
	name := base + "-" + id
	for i := 2; taken(name); i++ {
		name = fmt.Sprintf("%s-%s-%d", base, id, i)
	}
	return name
}

func runTSImport(ctx context.Context, e *Env, args []string) error {
	fs := newFlags(e, "ts import", "hop ts import [name...] [--user U] [--key K] [--tag T]... [--no-pin] [--dry-run] [--include-self] [--json]")
	user := fs.String("user", "", "ssh user for the hosts it creates")
	keyName := fs.String("key", "", "key for the hosts it creates")
	var tags stringList
	fs.Var(&tags, "tag", "tag for the hosts it creates (repeatable)")
	noPin := fs.Bool("no-pin", false, "do not pin the host keys Tailscale publishes")
	dryRun := fs.Bool("dry-run", false, "show what would change")
	self := fs.Bool("include-self", false, "also import this machine")
	asJSON := fs.Bool("json", false, "print the report as JSON")
	pos, _, err := parseFlags(fs, args)
	if err != nil {
		return err
	}
	st, err := tailnetStatus(ctx, e)
	if err != nil {
		return err
	}
	l, err := listAll(ctx, e)
	if err != nil {
		return err
	}
	var keyID model.ID
	if *keyName != "" {
		if keyID, err = findKey(l, *keyName); err != nil {
			return err
		}
	}

	nodes := st.Peers
	if *self {
		nodes = append([]tailscale.Node{st.Self}, nodes...)
	}
	if len(pos) > 0 {
		var picked []tailscale.Node
		for _, name := range pos {
			found := st.Find(name)
			if len(found) == 0 {
				return failf("no tailscale node matches %q", name)
			}
			for _, n := range found {
				if !slices.ContainsFunc(picked, func(p tailscale.Node) bool { return p.ID == n.ID }) {
					picked = append(picked, n)
				}
			}
		}
		nodes = picked
	}

	var report []TSEntry
	hosts := slices.Clone(l.Hosts)
	taken := func(name string) bool {
		return slices.ContainsFunc(hosts, func(h model.Host) bool {
			return slices.ContainsFunc(resolve.Names(h), func(n string) bool { return strings.EqualFold(n, name) })
		})
	}
	save := func(h model.Host) (model.Host, error) {
		if *dryRun {
			return h, nil
		}
		var saved model.Host
		err := call(ctx, e, daemon.OpPutHost, daemon.PutHostParams{Host: h}, &saved)
		return saved, err
	}
	ambiguity := tsCandidates(st, hosts)
	for _, n := range nodes {
		entry := TSEntry{Node: n.HostName, NodeID: n.ID}
		would := func(s string) string {
			if *dryRun {
				return "would_" + s
			}
			return s
		}

		// Already linked by node ID.
		if i := slices.IndexFunc(hosts, func(h model.Host) bool { return h.Tailscale != nil && h.Tailscale.StableNodeID == n.ID }); i >= 0 {
			entry.Host, entry.Status = hosts[i].Name, "already_linked"
			report = append(report, entry)
			continue
		}
		// An unlinked host that is evidently this node. A host that could
		// be several nodes, or a node that could be several hosts, is never
		// linked automatically: the pin from Tailscale would go to a guess.
		matches := ambiguity.hostsFor(n.ID)
		switch {
		case ambiguity.ambiguous(n.ID):
			entry.Status, entry.Reason = "ambiguous", ambiguity.reason(hosts, n)
		case len(matches) == 1:
			h := hosts[matches[0]]
			tsLink(&h, n, !*noPin)
			saved, err := save(h)
			if err != nil {
				entry.Status, entry.Reason = "skipped", err.Error()
				break
			}
			hosts[matches[0]] = saved
			entry.Host, entry.Status = saved.Name, would("linked")
		default:
			h := model.Host{
				Name: hostNameFor(n, taken), Port: 22, User: *user, KeyID: keyID, Tags: tags.vals,
				Route: resolve.RouteAuto, AgentAccess: "allow", Addresses: []string{},
				Description: "Imported from Tailscale",
			}
			if ip := firstV4(n.IPs); ip != "" {
				h.Addresses = append(h.Addresses, ip)
			}
			tsLink(&h, n, !*noPin)
			saved, err := save(h)
			if err != nil {
				entry.Status, entry.Reason = "skipped", err.Error()
				break
			}
			hosts = append(hosts, saved)
			entry.Host, entry.Status = saved.Name, would("created")
		}
		report = append(report, entry)
	}
	return printTSReport(e, *asJSON, report)
}

func printTSReport(e *Env, asJSON bool, report []TSEntry) error {
	if asJSON {
		if report == nil {
			report = []TSEntry{}
		}
		return printJSON(e, report)
	}
	if len(report) == 0 {
		fmt.Fprintln(e.Stderr, "no tailscale nodes")
	}
	for _, r := range report {
		line := fmt.Sprintf("%-14s %s", r.Status, r.Node)
		if r.Host != "" && r.Host != r.Node {
			line += " -> " + r.Host
		}
		if r.Reason != "" {
			line += ": " + r.Reason
		}
		e.printf("%s\n", line)
	}
	return nil
}

func runTSLink(ctx context.Context, e *Env, args []string) error {
	fs := newFlags(e, "ts link", "hop ts link <host> <node-id-or-dns-name> [--force] [--no-pin] [--json]")
	force := fs.Bool("force", false, "replace an existing link")
	noPin := fs.Bool("no-pin", false, "do not pin the host keys Tailscale publishes")
	asJSON := fs.Bool("json", false, "print the report as JSON")
	pos, _, err := parseFlags(fs, args)
	if err != nil {
		return err
	}
	if len(pos) != 2 {
		fs.Usage()
		return failf("expected a host and a tailscale name")
	}
	st, err := tailnetStatus(ctx, e)
	if err != nil {
		return err
	}
	rr, err := resolveTarget(ctx, e, pos[0], false)
	if err != nil {
		return err
	}
	if rr.Result.Status != resolve.StatusMatched || rr.Host == nil {
		return failf("%s", describeUnresolved(rr.Result))
	}
	nodes := findNode(st, pos[1])
	switch {
	case len(nodes) == 0:
		return failf("no tailscale node matches %q", pos[1])
	case len(nodes) > 1:
		var ids []string
		for _, n := range nodes {
			ids = append(ids, fmt.Sprintf("%s (%s)", n.DNSName, n.ID))
		}
		return failf("%q matches several tailscale nodes: %s; use the node ID, the full DNS name or the IP", pos[1], strings.Join(ids, ", "))
	}
	n := nodes[0]
	l, err := listAll(ctx, e)
	if err != nil {
		return err
	}
	for _, o := range l.Hosts {
		if o.ItemID != rr.Host.ItemID && o.Tailscale != nil && o.Tailscale.StableNodeID == n.ID {
			return failf("tailscale node %s is already linked to host %q", n.ID, o.Name)
		}
	}
	h := *rr.Host
	if h.Tailscale != nil && h.Tailscale.StableNodeID != n.ID && !*force {
		return failf("%s is already linked to tailscale node %s; pass --force to relink it", h.Name, h.Tailscale.StableNodeID)
	}
	tsLink(&h, n, !*noPin)
	var saved model.Host
	if err := call(ctx, e, daemon.OpPutHost, daemon.PutHostParams{Host: h}, &saved); err != nil {
		return err
	}
	return printTSReport(e, *asJSON, []TSEntry{{Node: n.HostName, NodeID: n.ID, Host: saved.Name, Status: "linked"}})
}
