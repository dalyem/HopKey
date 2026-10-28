package resolve

import (
	"net/netip"
	"slices"
	"strings"

	"github.com/dalyem/hopkey/internal/model"
	"github.com/dalyem/hopkey/internal/tailscale"
)

// HostOwnsNode reports whether tailnet node n, one of all (the whole
// tailnet), is host h by another name. A link that names one node only
// decides: h's stable node ID or MagicDNS name, or an address of h that is
// one of n's IPs or its MagicDNS name, ignoring case and a trailing dot.
// Failing that, an address of h that is n's short name (the MagicDNS
// name's first label) or its host name owns n only when no other node in
// all has that name, and h is not linked as above to another node: two
// machines can report the same host name ("build", given the MagicDNS
// names build and build-1), and such a name does not say which one h is.
//
// Routing follows the same order (see linkedNodes): the links decide, and a
// short name counts only when there are none.
func HostOwnsNode(h model.Host, n tailscale.Node, all []tailscale.Node) bool {
	if hostLinksNode(h, n) {
		return true
	}
	if slices.ContainsFunc(all, func(o tailscale.Node) bool { return o.ID != n.ID && hostLinksNode(h, o) }) {
		return false
	}
	named := func(o tailscale.Node, k string) bool { return k == normDNS(o.ShortName()) || k == normDNS(o.HostName) }
	for _, a := range h.Addresses {
		k := normDNS(strings.Trim(strings.TrimSpace(a), "[]"))
		if k == "" || !named(n, k) {
			continue
		}
		if !slices.ContainsFunc(all, func(o tailscale.Node) bool { return o.ID != n.ID && named(o, k) }) {
			return true
		}
	}
	return false
}

// hostLinksNode is HostOwnsNode's links that name one node only.
func hostLinksNode(h model.Host, n tailscale.Node) bool {
	if linksByRecord(h, n) {
		return true
	}
	return slices.ContainsFunc(h.Addresses, func(a string) bool { return addrNamesNode(a, n) })
}

// linksByRecord is the host's Tailscale link: the stable node ID or the
// MagicDNS name it was linked with.
func linksByRecord(h model.Host, n tailscale.Node) bool {
	t := h.Tailscale
	if t == nil {
		return false
	}
	return (t.StableNodeID != "" && t.StableNodeID == n.ID) ||
		(t.DNSName != "" && normDNS(t.DNSName) == normDNS(n.DNSName))
}

// addrNamesNode reports whether a is one of n's IPs or its MagicDNS name.
func addrNamesNode(a string, n tailscale.Node) bool {
	a = strings.Trim(strings.TrimSpace(a), "[]")
	if ip, err := netip.ParseAddr(a); err == nil {
		ip = ip.Unmap().WithZone("")
		return slices.ContainsFunc(n.IPs, func(s string) bool {
			nip, err := netip.ParseAddr(s)
			return err == nil && nip.Unmap().WithZone("") == ip
		})
	}
	k := normDNS(a)
	return k != "" && k == normDNS(n.DNSName)
}

// linkedNodes is the nodes of all that h names with a link (hostLinksNode),
// in the order routing trusts them: the stable node ID, then the stored
// MagicDNS name, then h's addresses in order.
func linkedNodes(h model.Host, all []tailscale.Node) []tailscale.Node {
	var out []tailscale.Node
	add := func(keep func(tailscale.Node) bool) {
		for _, n := range all {
			if keep(n) && !slices.ContainsFunc(out, func(o tailscale.Node) bool { return o.ID == n.ID }) {
				out = append(out, n)
			}
		}
	}
	if t := h.Tailscale; t != nil {
		add(func(n tailscale.Node) bool { return t.StableNodeID != "" && t.StableNodeID == n.ID })
		add(func(n tailscale.Node) bool { return linksByRecord(h, n) })
	}
	for _, a := range h.Addresses {
		add(func(n tailscale.Node) bool { return addrNamesNode(a, n) })
	}
	return out
}

func normDNS(s string) string { return strings.ToLower(strings.TrimSuffix(strings.TrimSpace(s), ".")) }
