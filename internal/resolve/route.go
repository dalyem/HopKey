package resolve

import (
	"fmt"
	"net/netip"
	"slices"
	"strings"

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
//   - direct: the first stored address that is not on the tailnet.
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
