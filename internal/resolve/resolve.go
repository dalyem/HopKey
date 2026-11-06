// Package resolve turns what the user typed (an alias, hostname, IP,
// Tailscale name or Tailscale IP, optionally with user@) into a vault host
// and says which rule matched.
//
// The rules run in a fixed order and the first step that matches anything
// ends the search:
//
//  1. exact alias or name
//  2. exact stored address (hostname, IP, Tailscale DNS name, Tailscale IP)
//  3. Tailscale status: host name, DNS name or 100.x IP, matched to a vault
//     host through the stable node ID
//  4. DNS lookup, matched against stored IP addresses (interactive only)
//  5. prefix, substring or fuzzy match (interactive only)
//  6. no vault entry: plain ssh (interactive only)
//
// A step that matches several hosts is ambiguous and the search stops there:
// resolve never guesses between two hosts. Non-interactive callers (stdout not
// a terminal, --json, MCP) stop after step 3; for them a failed search
// returns the prefix matches as suggestions only.
package resolve

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"slices"
	"strings"
	"time"
	"unicode"

	"github.com/dalyem/hopkey/internal/model"
	"github.com/dalyem/hopkey/internal/tailscale"
)

// Rule names the step that matched.
type Rule string

const (
	RuleAlias     Rule = "alias"     // exact alias or name
	RuleAddress   Rule = "address"   // exact stored address
	RuleTailscale Rule = "tailscale" // tailscale status, linked by stable node ID
	RuleDNS       Rule = "dns"       // DNS lookup matched a stored IP
	RulePrefix    Rule = "prefix"    // prefix, substring or fuzzy match
	RuleNone      Rule = "none"
)

// Status is the outcome of a resolution.
type Status string

const (
	StatusMatched   Status = "matched"
	StatusAmbiguous Status = "ambiguous"
	StatusNoMatch   Status = "no_match"
	// StatusPlainSSH means no vault entry matched and the caller is
	// interactive, so plain ssh to the target is the next step.
	StatusPlainSSH Status = "plain_ssh"
)

// Candidate is a host (or tailnet node) a target could mean.
type Candidate struct {
	HostID    string   `json:"host_id,omitempty"` // empty for a tailnet node with no vault host
	Name      string   `json:"name"`
	Addresses []string `json:"addresses,omitempty"`
	Detail    string   `json:"detail,omitempty"` // why it is a candidate
	NodeID    string   `json:"tailscale_node_id,omitempty"`
}

// Result is what Resolve decided.
type Result struct {
	Target string `json:"target"`         // as typed, without user@
	User   string `json:"user,omitempty"` // from user@target, if given
	Status Status `json:"status"`
	Rule   Rule   `json:"rule"`
	// Matched says what matched, e.g. `alias "prod-db"`.
	Matched    string      `json:"matched,omitempty"`
	HostID     string      `json:"host_id,omitempty"`
	HostName   string      `json:"host_name,omitempty"`
	Candidates []Candidate `json:"candidates,omitempty"`
	// Notes carry things worth knowing that did not decide the outcome, such
	// as a tailnet peer that no vault host is linked to.
	Notes     []string        `json:"notes,omitempty"`
	Tailscale *tailscale.Node `json:"tailscale,omitempty"` // the node that matched under RuleTailscale

	// Host is the matched host. It is not part of the JSON; callers that
	// report a host build their own view of it.
	Host *model.Host `json:"-"`
}

// Input is everything Resolve needs.
type Input struct {
	Target      string
	Hosts       []model.Host
	Tailscale   *tailscale.Status // nil or unavailable: step 3 is skipped
	Interactive bool

	// LookupHost resolves a name to IP addresses for step 4. Nil means the
	// system resolver.
	LookupHost func(ctx context.Context, name string) ([]string, error)
}

// ParseTarget splits [user@]target. The target must be non-empty, must not
// start with "-" (ssh would read it as an option) and must hold no spaces or
// control characters. A bracketed IPv6 literal loses its brackets.
func ParseTarget(s string) (user, target string, err error) {
	target = s
	if i := strings.LastIndex(s, "@"); i >= 0 {
		user, target = s[:i], s[i+1:]
		if user == "" {
			return "", "", fmt.Errorf("empty user in %q", s)
		}
		if strings.HasPrefix(user, "-") || strings.ContainsFunc(user, badRune) {
			return "", "", fmt.Errorf("invalid user in %q", s)
		}
	}
	if len(target) > 2 && target[0] == '[' && target[len(target)-1] == ']' {
		target = target[1 : len(target)-1]
	}
	switch {
	case target == "":
		return "", "", errors.New("empty target")
	case strings.HasPrefix(target, "-"):
		return "", "", fmt.Errorf("invalid target %q: starts with -", target)
	case strings.ContainsFunc(target, badRune):
		return "", "", fmt.Errorf("invalid target %q", target)
	}
	return user, target, nil
}

func badRune(r rune) bool { return unicode.IsSpace(r) || unicode.IsControl(r) }

// Resolve runs the rules. The error is for failures of the machinery (a bad
// target); "nothing matched" is a Result with StatusNoMatch or StatusPlainSSH.
func Resolve(ctx context.Context, in Input) (*Result, error) {
	user, target, err := ParseTarget(in.Target)
	if err != nil {
		return nil, err
	}
	r := &Result{Target: target, User: user, Status: StatusNoMatch, Rule: RuleNone}
	hosts := in.Hosts
	norm := normName(target)

	// 1. Exact alias or name.
	if m := filterHosts(hosts, func(h model.Host) bool {
		return slices.ContainsFunc(Names(h), func(n string) bool { return normName(n) == norm })
	}); len(m) > 0 {
		return r.decide(RuleAlias, fmt.Sprintf("alias or name %q", target), m, "has this name or alias"), nil
	}

	// 2. Exact stored address.
	nAddr := normAddr(target)
	if m := filterHosts(hosts, func(h model.Host) bool {
		return slices.ContainsFunc(storedAddrs(h), func(a string) bool { return normAddr(a) == nAddr })
	}); len(m) > 0 {
		return r.decide(RuleAddress, fmt.Sprintf("stored address %q", target), m, "has this address"), nil
	}

	// 3. Tailscale status.
	if nodes := in.Tailscale.Find(target); len(nodes) > 0 {
		if done := r.byTailscale(nodes, hosts); done {
			return r, nil
		}
	}

	if !in.Interactive {
		// Stop here. Prefix matches are offered as suggestions only.
		r.Candidates = candidates(fuzzy(hosts, target), "name resembles the target")
		if len(r.Candidates) > 0 {
			r.Notes = append(r.Notes, "non-interactive: prefix and fuzzy matching are off, so these are suggestions, not a match")
		}
		return r, nil
	}

	// 4. DNS, matched against stored IPs.
	if ips := lookup(ctx, in, target); len(ips) > 0 {
		if m := filterHosts(hosts, func(h model.Host) bool { return hasAnyIP(storedAddrs(h), ips) }); len(m) > 0 {
			return r.decide(RuleDNS, fmt.Sprintf("%q resolves to %s", target, strings.Join(ips, ", ")), m, "has an address this name resolves to"), nil
		}
	}

	// 5. Prefix / fuzzy.
	if m := fuzzy(hosts, target); len(m) > 0 {
		return r.decide(RulePrefix, fmt.Sprintf("prefix or fuzzy match for %q", target), m, "name resembles the target"), nil
	}

	// 6. No vault entry.
	r.Status = StatusPlainSSH
	return r, nil
}

// decide records a unique match or an ambiguity among hosts.
func (r *Result) decide(rule Rule, matched string, hosts []model.Host, why string) *Result {
	r.Rule = rule
	if len(hosts) == 1 {
		h := hosts[0]
		r.Status, r.Matched = StatusMatched, matched
		r.HostID, r.HostName, r.Host = h.ItemID.String(), h.Name, &h
		return r
	}
	r.Status = StatusAmbiguous
	r.Matched = matched
	r.Candidates = candidates(hosts, why)
	return r
}

// byTailscale handles step 3 once at least one node matched. It reports
// whether the search is over (a match or an ambiguity); false means the nodes
// are not linked to any vault host and the search goes on.
func (r *Result) byTailscale(nodes []tailscale.Node, hosts []model.Host) bool {
	type pair struct {
		node tailscale.Node
		host model.Host
	}
	var linked []pair
	var unlinked []tailscale.Node
	for _, n := range nodes {
		found := false
		for _, h := range hosts {
			if h.Tailscale != nil && h.Tailscale.StableNodeID == n.ID && n.ID != "" {
				linked = append(linked, pair{n, h})
				found = true
			}
		}
		if !found {
			unlinked = append(unlinked, n)
		}
	}

	switch {
	case len(nodes) == 1 && len(linked) == 1:
		p := linked[0]
		r.Rule, r.Status = RuleTailscale, StatusMatched
		r.Matched = fmt.Sprintf("tailscale node %s (%s)", p.node.HostName, p.node.ID)
		r.HostID, r.HostName, r.Host = p.host.ItemID.String(), p.host.Name, &p.host
		n := p.node
		r.Tailscale = &n
		return true
	case len(nodes) == 1 && len(linked) == 0:
		// One node and no vault host for it: a note, and the search goes on.
		n := unlinked[0]
		r.Notes = append(r.Notes, fmt.Sprintf("tailscale node %q (%s) is not linked to a vault host; hop ts import or hop ts link links it", n.HostName, n.ID))
		return false
	}

	// Several nodes share the name (linked or not), or several hosts claim one
	// node. Falling through to DNS or fuzzy matching would pick among them.
	r.Rule, r.Status = RuleTailscale, StatusAmbiguous
	r.Matched = fmt.Sprintf("%d tailscale nodes or hosts match", len(nodes))
	for _, p := range linked {
		r.Candidates = append(r.Candidates, Candidate{
			HostID: p.host.ItemID.String(), Name: p.host.Name, Addresses: slices.Clone(p.host.Addresses),
			Detail: fmt.Sprintf("linked to tailscale node %s (%s, %s)", p.node.HostName, p.node.ID, onlineWord(p.node.Online)),
			NodeID: p.node.ID,
		})
	}
	for _, n := range unlinked {
		r.Candidates = append(r.Candidates, Candidate{
			Name: n.HostName, Addresses: slices.Clone(n.IPs),
			Detail: fmt.Sprintf("tailscale node %s (%s), not linked to a vault host", n.ID, onlineWord(n.Online)),
			NodeID: n.ID,
		})
	}
	return true
}

func onlineWord(on bool) string {
	if on {
		return "online"
	}
	return "offline"
}

// Names returns the host's name followed by its aliases.
func Names(h model.Host) []string { return append([]string{h.Name}, h.Aliases...) }

// normName is model.NameKey, the selector key the merge uses for names and
// aliases too (crypto spec rev 17, §5.4).
func normName(s string) string { return model.NameKey(s) }

// normAddr canonicalises an address for comparison: an IP is parsed and
// printed in its canonical form, a name is lower-cased without a trailing dot.
func normAddr(s string) string {
	s = strings.TrimSuffix(strings.TrimSpace(s), ".")
	if a, err := netip.ParseAddr(strings.Trim(s, "[]")); err == nil {
		return a.Unmap().WithZone("").String()
	}
	return strings.ToLower(s)
}

// storedAddrs is every address the host is known by: its addresses plus the
// Tailscale DNS name.
func storedAddrs(h model.Host) []string {
	out := slices.Clone(h.Addresses)
	if h.Tailscale != nil && h.Tailscale.DNSName != "" {
		out = append(out, h.Tailscale.DNSName)
	}
	return out
}

func filterHosts(hosts []model.Host, keep func(model.Host) bool) []model.Host {
	var out []model.Host
	for _, h := range hosts {
		if keep(h) {
			out = append(out, h)
		}
	}
	return out
}

func candidates(hosts []model.Host, why string) []Candidate {
	hosts = slices.Clone(hosts)
	slices.SortStableFunc(hosts, func(a, b model.Host) int { return strings.Compare(strings.ToLower(a.Name), strings.ToLower(b.Name)) })
	out := make([]Candidate, 0, len(hosts))
	for _, h := range hosts {
		out = append(out, Candidate{HostID: h.ItemID.String(), Name: h.Name, Addresses: slices.Clone(h.Addresses), Detail: why})
	}
	return out
}

// lookup resolves target to IPs for step 4. A target that is already an IP,
// or that is not shaped like a host name, is not looked up.
func lookup(ctx context.Context, in Input, target string) []string {
	if _, err := netip.ParseAddr(target); err == nil || !looksLikeHostName(target) {
		return nil
	}
	fn := in.LookupHost
	if fn == nil {
		fn = net.DefaultResolver.LookupHost
	}
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	ips, err := fn(ctx, target)
	if err != nil {
		return nil
	}
	return ips
}

func looksLikeHostName(s string) bool {
	if s == "" || len(s) > 253 {
		return false
	}
	for _, r := range s {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-' || r == '.' || r == '_') {
			return false
		}
	}
	return true
}

func hasAnyIP(addrs, ips []string) bool {
	want := make(map[string]bool, len(ips))
	for _, ip := range ips {
		want[normAddr(ip)] = true
	}
	for _, a := range addrs {
		if _, err := netip.ParseAddr(strings.Trim(a, "[]")); err == nil && want[normAddr(a)] {
			return true
		}
	}
	return false
}

// maxFuzzy caps how many candidates a fuzzy search returns.
const maxFuzzy = 20

// fuzzy returns the hosts that resemble target, from the best tier that has
// any: a prefix of a name or alias, then a substring, then (for targets of
// three or more characters) the target's characters in order. Within a tier
// the hosts are sorted by name.
func fuzzy(hosts []model.Host, target string) []model.Host {
	t := normName(target)
	if t == "" {
		return nil
	}
	tiers := []func(name string) bool{
		func(n string) bool { return strings.HasPrefix(n, t) },
		func(n string) bool { return strings.Contains(n, t) },
		func(n string) bool { return len(t) >= 3 && isSubsequence(t, n) },
	}
	for _, match := range tiers {
		m := filterHosts(hosts, func(h model.Host) bool {
			return slices.ContainsFunc(Names(h), func(n string) bool { return match(normName(n)) })
		})
		if len(m) == 0 {
			continue
		}
		slices.SortFunc(m, func(a, b model.Host) int { return strings.Compare(strings.ToLower(a.Name), strings.ToLower(b.Name)) })
		if len(m) > maxFuzzy {
			m = m[:maxFuzzy]
		}
		return m
	}
	return nil
}

func isSubsequence(needle, hay string) bool {
	i := 0
	for _, r := range hay {
		if i < len(needle) && rune(needle[i]) == r {
			i++
		}
	}
	return i == len(needle)
}
