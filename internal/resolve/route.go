package resolve

import (
	"fmt"
	"net/netip"
	"slices"
	"strings"

	"github.com/dalyem/hopkey/internal/model"
	"github.com/dalyem/hopkey/internal/sshkeys"
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
	// it has no key of its own to offer, or its pinned host keys are the ones
	// Tailscale publishes, which the direct sshd does not share. The route is
	// then the tailnet with no direct fallback.
	TailscaleSSH bool `json:"tailscale_ssh,omitempty"`
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

// TailscaleSSHOnly reports whether h can only be reached through Tailscale SSH,
// and why. That is a host Tailscale marks as running Tailscale SSH that either
// has no key (Tailscale authenticates the tailnet identity, so no key is
// offered) or is pinned to the host keys Tailscale publishes for its node
// (the direct sshd has different ones, so a direct connection could only
// fail the pin). The second case needs the live node to compare against;
// without it the host takes the ordinary route.
func TailscaleSSHOnly(h model.Host, ts *tailscale.Status) (why string, only bool) {
	if h.Tailscale == nil || h.Tailscale.SSH != "yes" {
		return "", false
	}
	if h.KeyID.IsZero() {
		return "the host has no key", true
	}
	n, ok := ts.NodeByID(h.Tailscale.StableNodeID)
	if !ok || len(h.HostKeys) == 0 || len(n.SSHHostKeys) == 0 {
		return "", false
	}
	published := map[string]bool{}
	for _, line := range n.SSHHostKeys {
		if k, err := sshkeys.ParsePublic(line); err == nil {
			published[string(k.Marshal())] = true
		}
	}
	for _, line := range h.HostKeys {
		k, err := sshkeys.ParsePublic(line)
		if err != nil || !published[string(k.Marshal())] {
			return "", false
		}
	}
	return "its pinned host keys are the ones Tailscale publishes", true
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
//   - direct: the first stored address that is not on the tailnet.
//   - tailnet: the host's tailnet address, whether or not Tailscale looks to
//     be running here.
//   - auto: the tailnet address when local Tailscale is running and the peer
//     is online, otherwise the direct address, and the tailnet address only
//     if the host has nothing else.
//
// A host reached only through Tailscale SSH (see TailscaleSSHOnly) always gets
// its tailnet address, with no direct fallback; asking for "direct" is an
// error.
func ChooseRoute(h model.Host, ts *tailscale.Status) (Route, error) {
	setting := h.Route
	if setting == "" {
		setting = RouteAuto
	}
	port := int(h.Port)
	if port == 0 {
		port = 22
	}
	suffix := ""
	if ts != nil {
		suffix = ts.MagicDNSSuffix
	}

	var direct []string
	for _, a := range h.Addresses {
		if !IsTailnetAddr(a, suffix) {
			direct = append(direct, a)
		}
	}
	tailnet, node, haveNode := tailnetAddress(h, ts)

	r := Route{Setting: setting, Port: port}
	if why, only := TailscaleSSHOnly(h, ts); only {
		switch {
		case setting == RouteDirect:
			return Route{}, fmt.Errorf("host %q is reached only through Tailscale SSH (%s), so route direct cannot work; set the route to tailnet or auto", h.Name, why)
		case tailnet == "":
			return Route{}, fmt.Errorf("host %q is reached only through Tailscale SSH (%s) but has no tailnet address", h.Name, why)
		}
		r.Chosen, r.Address, r.TailscaleSSH = RouteTailnet, tailnet, true
		r.Reason = "Tailscale SSH: " + why
		if ts == nil || !ts.Available {
			r.Reason += "; tailscale is not running here, so the connection may fail"
		}
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
		why := "route is tailnet"
		if ts == nil || !ts.Available {
			why += "; tailscale is not running here, so the connection may fail"
		}
		return useTailnet(why)
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

// tailnetAddress finds the host's tailnet address and, when the host is
// linked to a node the local Tailscale knows, that node. A live status wins:
// its IPv4 address, then a stored tailnet address, then a MagicDNS name, then
// IPv6.
func tailnetAddress(h model.Host, ts *tailscale.Status) (addr string, node tailscale.Node, haveNode bool) {
	suffix := ""
	if ts != nil {
		suffix = ts.MagicDNSSuffix
	}
	var cands []string
	if h.Tailscale != nil {
		if n, ok := ts.NodeByID(h.Tailscale.StableNodeID); ok {
			node, haveNode = n, true
			cands = append(cands, n.IPs...)
		}
	}
	var stored []string
	for _, a := range h.Addresses {
		if IsTailnetAddr(a, suffix) {
			stored = append(stored, a)
		}
	}
	cands = append(cands, stored...)
	if !haveNode {
		// Not linked by node ID: a stored tailnet address may still name
		// exactly one node.
		for _, a := range stored {
			if found := ts.Find(a); len(found) == 1 {
				node, haveNode = found[0], true
				cands = append(cands, node.IPs...)
				break
			}
		}
	}
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
