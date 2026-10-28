package resolve

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"slices"
	"strings"
	"time"

	"github.com/dalyem/hopkey/internal/model"
	"github.com/dalyem/hopkey/internal/tailscale"
)

// Route settings and choices, as stored in model.Host.Route.
const (
	RouteAuto    = "auto"
	RouteTailnet = "tailnet"
	RouteDirect  = "direct"
)

// Route is the address hop would connect to and why.
type Route struct {
	Setting string `json:"setting"` // the host's route: auto, tailnet or direct
	Chosen  string `json:"chosen"`  // tailnet or direct
	Address string `json:"address"`
	Port    int    `json:"port"`
	Reason  string `json:"reason"`
	// TailscaleSSH is set when the host is reached only through Tailscale SSH:
	// it has no key of its own to offer. The route is then the tailnet with no
	// direct fallback.
	TailscaleSSH bool `json:"tailscale_ssh,omitempty"`
	// Blocked is why this route cannot be used right now: the host is kept to
	// the tailnet (route tailnet, or Tailscale SSH) and Tailscale is not
	// available here. hop will not connect, and will not try a direct address.
	Blocked string `json:"blocked,omitempty"`
	// Fallback is the address to try if Chosen was the tailnet under
	// "auto" and the connection fails. "Online" only means the peer reaches
	// Tailscale's control plane, not that ssh answers.
	Fallback string `json:"fallback,omitempty"`
}

var (
	cgnat      = netip.MustParsePrefix("100.64.0.0/10")
	tailnetULA = netip.MustParsePrefix("fd7a:115c:a1e0::/48")
)

// Label describes the route for people: the route chosen and why.
func (r Route) Label() string {
	if r.TailscaleSSH {
		return r.Chosen + " (Tailscale SSH)"
	}
	return r.Chosen + " (" + r.Reason + ")"
}

// TailscaleSSHOnly reports whether h can only be reached through Tailscale
// SSH, and why: Tailscale marks it as running Tailscale SSH and it has no key
// of its own, so a direct sshd would have nothing to authenticate with. It
// looks only at what is stored on the host. A host with a key that should be
// kept to the tailnet says so with route tailnet, which hop ts import and
// hop ts link set; nothing here guesses from what Tailscale shows right now.
func TailscaleSSHOnly(h model.Host) (why string, only bool) {
	if h.Tailscale != nil && h.Tailscale.SSH == "yes" && h.KeyID.IsZero() {
		return "the host has no key", true
	}
	return "", false
}

// IsTailnetAddr reports whether addr lives on the tailnet: a Tailscale IP, a
// *.ts.net name, or a name under the given MagicDNS suffix (which may be "").
func IsTailnetAddr(addr, magicDNSSuffix string) bool {
	a := normAddr(addr)
	if ip, err := netip.ParseAddr(a); err == nil {
		return cgnat.Contains(ip) || tailnetULA.Contains(ip)
	}
	if strings.HasSuffix(a, ".ts.net") {
		return true
	}
	suffix := strings.ToLower(strings.Trim(magicDNSSuffix, "."))
	return suffix != "" && strings.HasSuffix(a, "."+suffix)
}

// ChooseRoute picks the address for h. ts may be nil or unavailable.
//
//   - direct: the first stored address that is not on the tailnet. A
//     single-label name counts as the tailnet only as place says.
//   - tailnet: the host's tailnet address and never a direct one. If Tailscale
//     is not available here the route is Blocked, so the connection fails with
//     a message that says why, rather than going around the restriction.
//   - auto: the tailnet address when local Tailscale is running and the peer
//     is online, otherwise the direct address, and the tailnet address only
//     if the host has nothing else.
//
// A host reached only through Tailscale SSH (see TailscaleSSHOnly) always gets
// its tailnet address, with no direct fallback, and is Blocked like route
// tailnet; asking for "direct" is an error.
func ChooseRoute(h model.Host, ts *tailscale.Status) (Route, error) {
	return ChooseRouteWith(h, ts, SystemLookup)
}

// ChooseRouteWith is ChooseRoute with the resolver that decides whether a
// single-label address names a tailnet node (see place). A nil lookup
// resolves nothing, so no such address counts as the tailnet.
func ChooseRouteWith(h model.Host, ts *tailscale.Status, lookup Lookup) (Route, error) {
	setting := h.Route
	if setting == "" {
		setting = RouteAuto
	}
	port := int(h.Port)
	if port == 0 {
		port = 22
	}

	p := place(h, ts, lookup)
	direct := p.direct
	tailnet, node, haveNode := tailnetAddress(h, p)

	r := Route{Setting: setting, Port: port}
	unavailable := ts == nil || !ts.Available
	blocked := func() string {
		if !unavailable {
			return ""
		}
		reason := "no status"
		if ts != nil && ts.Reason != "" {
			reason = ts.Reason
		}
		return fmt.Sprintf("host %q is kept to the tailnet, but tailscale is not available here (%s), and hop does not fall back to a direct address; start Tailscale, or change the route with: hop edit %s --route auto", h.Name, reason, h.Name)
	}
	if why, only := TailscaleSSHOnly(h); only {
		switch {
		case setting == RouteDirect:
			return Route{}, fmt.Errorf("host %q is reached only through Tailscale SSH (%s), so route direct cannot work; set the route to tailnet or auto", h.Name, why)
		case tailnet == "":
			return Route{}, fmt.Errorf("host %q is reached only through Tailscale SSH (%s) but has no tailnet address", h.Name, why)
		}
		r.Chosen, r.Address, r.TailscaleSSH = RouteTailnet, tailnet, true
		r.Reason = "Tailscale SSH: " + why
		r.Blocked = blocked()
		return r, nil
	}
	useDirect := func(why string) (Route, error) {
		if len(direct) == 0 {
			return Route{}, fmt.Errorf("host %q has no address outside the tailnet (%s)", h.Name, why)
		}
		r.Chosen, r.Address, r.Reason = RouteDirect, direct[0], why
		return r, nil
	}
	useTailnet := func(why string) (Route, error) {
		if tailnet == "" {
			return Route{}, fmt.Errorf("host %q has no tailnet address (%s)", h.Name, why)
		}
		r.Chosen, r.Address, r.Reason = RouteTailnet, tailnet, why
		return r, nil
	}

	switch setting {
	case RouteDirect:
		return useDirect("route is direct")
	case RouteTailnet:
		out, err := useTailnet("route is tailnet")
		out.Blocked = blocked()
		return out, err
	case RouteAuto:
	default:
		return Route{}, fmt.Errorf("host %q has unknown route %q", h.Name, setting)
	}

	online := ts != nil && ts.Available && haveNode && node.Online
	switch {
	case tailnet != "" && online:
		out, err := useTailnet("tailscale is running and the peer is online")
		if len(direct) > 0 {
			out.Fallback = direct[0]
		}
		return out, err
	case len(direct) > 0:
		why := "no tailnet address"
		switch {
		case tailnet == "":
		case ts == nil || !ts.Available:
			why = "tailscale is not running here"
		case !haveNode:
			why = "the host is not a node in the local tailnet view"
		default:
			why = "the tailscale peer is offline"
		}
		return useDirect(why)
	case tailnet != "":
		return useTailnet("the host has no other address")
	}
	return Route{}, fmt.Errorf("host %q has no addresses", h.Name)
}

// placement is how a host's stored addresses divide, and the node the host
// is on the local tailnet, if any.
type placement struct {
	tailnet, direct []string
	node            tailscale.Node
	haveNode        bool
}

// Lookup resolves a host name to addresses.
type Lookup func(ctx context.Context, host string) ([]string, error)

// lookupTimeout bounds the lookup of one short name.
const lookupTimeout = 2 * time.Second

// SystemLookup resolves a name with the system resolver, which is what a
// direct connection uses (/etc/hosts, the DNS search domains, MagicDNS).
func SystemLookup(ctx context.Context, host string) ([]string, error) {
	return net.DefaultResolver.LookupHost(ctx, host)
}

// place sorts h's addresses into the tailnet's and the direct ones, in the
// same order HostOwnsNode decides which node a host is. The authoritative
// ones come first: the stable node ID, the stored MagicDNS name, and an
// address that is a Tailscale IP or an exact MagicDNS name. A node found
// that way is the host's node, and a short name of any node beside it is
// only a direct address.
//
// Only when there is no such link can a single-label address make a node
// the host's: it must name exactly one node by host name or first label,
// and the system resolver, as a direct connection uses it, must answer with
// that node's Tailscale IPs only (MagicDNS answering for it). Otherwise the
// name is a LAN name that happens to match, as with /etc/hosts or corporate
// DNS, and it stays direct.
func place(h model.Host, ts *tailscale.Status, lookup Lookup) placement {
	var p placement
	suffix := ""
	if ts != nil {
		suffix = ts.MagicDNSSuffix
	}
	linked := linkedNodes(h, ts.Nodes())
	if len(linked) > 0 {
		p.node, p.haveNode = linked[0], true
	}
	for _, a := range h.Addresses {
		if IsTailnetAddr(a, suffix) {
			p.tailnet = append(p.tailnet, a)
			continue
		}
		if len(linked) == 0 {
			// Several short names may name different nodes; the first
			// decides, and the others stay direct.
			if n, ok := namedByResolver(a, ts, lookup); ok && (!p.haveNode || n.ID == p.node.ID) {
				p.node, p.haveNode = n, true
				p.tailnet = append(p.tailnet, a)
				continue
			}
		}
		p.direct = append(p.direct, a)
	}
	return p
}

// namedByResolver is the node that the single-label address addr names, if
// it names exactly one by host name or first MagicDNS label and lookup
// answers with that node's Tailscale IPs and nothing else.
func namedByResolver(addr string, ts *tailscale.Status, lookup Lookup) (tailscale.Node, bool) {
	a := normAddr(addr)
	if lookup == nil || a == "" || strings.Contains(a, ".") {
		return tailscale.Node{}, false
	}
	if _, err := netip.ParseAddr(a); err == nil {
		return tailscale.Node{}, false
	}
	found := ts.Find(a)
	if len(found) != 1 {
		return tailscale.Node{}, false
	}
	ctx, cancel := context.WithTimeout(context.Background(), lookupTimeout)
	defer cancel()
	answers, err := lookup(ctx, a)
	if err != nil || len(answers) == 0 {
		return tailscale.Node{}, false
	}
	for _, s := range answers {
		if !addrNamesNode(s, found[0]) {
			return tailscale.Node{}, false
		}
	}
	return found[0], true
}

// tailnetAddress finds the host's tailnet address from its placement. A live
// status wins: the node's IPv4 address, then a stored tailnet address, then a
// MagicDNS name, then IPv6.
func tailnetAddress(h model.Host, p placement) (addr string, node tailscale.Node, haveNode bool) {
	node, haveNode = p.node, p.haveNode
	var cands []string
	if haveNode {
		cands = append(cands, node.IPs...)
	}
	cands = append(cands, p.tailnet...)
	if h.Tailscale != nil && h.Tailscale.DNSName != "" {
		cands = append(cands, strings.TrimSuffix(h.Tailscale.DNSName, "."))
	}
	if haveNode && node.DNSName != "" {
		cands = append(cands, node.DNSName)
	}
	// Prefer v4 IPs, then names, then v6.
	rank := func(a string) int {
		ip, err := netip.ParseAddr(normAddr(a))
		switch {
		case err != nil:
			return 1
		case ip.Is4():
			return 0
		}
		return 2
	}
	slices.SortStableFunc(cands, func(a, b string) int { return rank(a) - rank(b) })
	if len(cands) == 0 {
		return "", node, haveNode
	}
	return cands[0], node, haveNode
}
