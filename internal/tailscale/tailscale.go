// Package tailscale reads the local Tailscale node's view of the tailnet by
// running `tailscale status --json` and parsing the few fields HopKey needs.
// It does not depend on the tailscale.com module.
//
// When Tailscale is not installed, not running, or not logged in, Status
// returns an unavailable Status and a nil error: callers treat that as "no
// tailnet information" and carry on.
package tailscale

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net/netip"
	"os/exec"
	"slices"
	"strings"
	"time"
)

// Node is one machine in the tailnet.
type Node struct {
	ID          string   `json:"id"`        // stable node ID, e.g. nABCD1CNTRL
	HostName    string   `json:"host_name"` // as the machine reports it; may repeat
	DNSName     string   `json:"dns_name"`  // MagicDNS FQDN without the trailing dot
	IPs         []string `json:"ips"`
	Online      bool     `json:"online"` // connected to the control plane
	OS          string   `json:"os,omitempty"`
	SSHHostKeys []string `json:"ssh_host_keys,omitempty"` // OpenSSH public-key lines
	Self        bool     `json:"self,omitempty"`
}

// SSH is the stored hint for Tailscale SSH: "yes" when the node publishes
// SSH host keys, otherwise "unknown". Status has no reliable "enabled" flag,
// so a node is never reported as "no" here.
func (n Node) SSH() string {
	if len(n.SSHHostKeys) > 0 {
		return "yes"
	}
	return "unknown"
}

// ShortName is the first label of the MagicDNS name. Tailscale gives the
// second machine named "build" the label "build-1", so this can differ from
// HostName.
func (n Node) ShortName() string {
	if n.DNSName == "" {
		return ""
	}
	label, _, _ := strings.Cut(n.DNSName, ".")
	return label
}

// Status is the local node's view of the tailnet.
type Status struct {
	Available      bool   `json:"available"`
	Reason         string `json:"reason,omitempty"` // why not, when !Available
	MagicDNSSuffix string `json:"magic_dns_suffix,omitempty"`
	Self           Node   `json:"self"`
	Peers          []Node `json:"peers"` // sorted by host name, then ID
}

// Unavailable returns a Status for a tailnet that cannot be read.
func Unavailable(reason string) *Status { return &Status{Reason: reason} }

// Nodes returns Self followed by the peers. It is empty when unavailable.
func (s *Status) Nodes() []Node {
	if s == nil || !s.Available {
		return nil
	}
	return append([]Node{s.Self}, s.Peers...)
}

// NodeByID finds a node by its stable ID.
func (s *Status) NodeByID(id string) (Node, bool) {
	if id == "" {
		return Node{}, false
	}
	for _, n := range s.Nodes() {
		if n.ID == id {
			return n, true
		}
	}
	return Node{}, false
}

// Find returns every node that target names: by host name, by MagicDNS name
// (with or without the trailing dot, or just its first label), or by one of
// its Tailscale IPs. Names compare without regard to case. A host name that
// two machines share returns both.
func (s *Status) Find(target string) []Node {
	t := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(target), "."))
	if t == "" {
		return nil
	}
	ip, ipErr := netip.ParseAddr(t)
	var out []Node
	for _, n := range s.Nodes() {
		if n.matches(t, ip, ipErr == nil) {
			out = append(out, n)
		}
	}
	return out
}

func (n Node) matches(t string, ip netip.Addr, isIP bool) bool {
	if isIP {
		return slices.ContainsFunc(n.IPs, func(s string) bool {
			a, err := netip.ParseAddr(s)
			return err == nil && a == ip
		})
	}
	return strings.ToLower(n.HostName) == t ||
		strings.ToLower(n.DNSName) == t ||
		strings.ToLower(n.ShortName()) == t
}

// rawStatus is the subset of ipnstate.Status that Parse reads.
type rawStatus struct {
	BackendState   string `json:"BackendState"`
	MagicDNSSuffix string `json:"MagicDNSSuffix"`
	CurrentTailnet *struct {
		MagicDNSSuffix string `json:"MagicDNSSuffix"`
	} `json:"CurrentTailnet"`
	Self rawNode            `json:"Self"`
	Peer map[string]rawNode `json:"Peer"`
}

type rawNode struct {
	ID           string   `json:"ID"`
	HostName     string   `json:"HostName"`
	DNSName      string   `json:"DNSName"`
	OS           string   `json:"OS"`
	TailscaleIPs []string `json:"TailscaleIPs"`
	Online       bool     `json:"Online"`
	SSHHostKeys  []string `json:"sshHostKeys"`
}

func (r rawNode) node(self bool) Node {
	return Node{
		ID:          r.ID,
		HostName:    r.HostName,
		DNSName:     strings.TrimSuffix(r.DNSName, "."),
		IPs:         slices.Clone(r.TailscaleIPs),
		Online:      r.Online,
		OS:          r.OS,
		SSHHostKeys: slices.Clone(r.SSHHostKeys),
		Self:        self,
	}
}

// Parse reads the output of `tailscale status --json`. A node that is not in
// the Running state yields an unavailable Status, not an error; malformed
// JSON is an error.
func Parse(data []byte) (*Status, error) {
	var raw rawStatus
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("tailscale: parsing status: %w", err)
	}
	if raw.BackendState != "Running" {
		state := raw.BackendState
		if state == "" {
			state = "in an unknown state"
		}
		return Unavailable("tailscale is " + state), nil
	}
	suffix := raw.MagicDNSSuffix
	if suffix == "" && raw.CurrentTailnet != nil {
		suffix = raw.CurrentTailnet.MagicDNSSuffix
	}
	st := &Status{Available: true, MagicDNSSuffix: suffix, Self: raw.Self.node(true)}
	for _, p := range raw.Peer {
		st.Peers = append(st.Peers, p.node(false))
	}
	slices.SortFunc(st.Peers, func(a, b Node) int {
		if c := strings.Compare(strings.ToLower(a.HostName), strings.ToLower(b.HostName)); c != 0 {
			return c
		}
		return strings.Compare(a.ID, b.ID)
	})
	return st, nil
}

// Client runs the tailscale command line.
type Client struct {
	// Binaries are tried in order; the first that exists is used. Empty means
	// DefaultBinaries.
	Binaries []string
	// Timeout bounds one `tailscale status --json`. Zero means 3 seconds.
	Timeout time.Duration
	// Run executes a binary and returns its stdout. Tests replace it.
	Run func(ctx context.Context, bin string, args ...string) ([]byte, error)
}

// DefaultBinaries is where the tailscale command lives: on PATH, then inside
// the macOS app bundle.
var DefaultBinaries = []string{"tailscale", "/Applications/Tailscale.app/Contents/MacOS/Tailscale"}

// Status reads the tailnet. It returns an error only for output it cannot
// parse; a missing binary or a stopped daemon is an unavailable Status.
func (c *Client) Status(ctx context.Context) (*Status, error) {
	bins := c.Binaries
	if len(bins) == 0 {
		bins = DefaultBinaries
	}
	timeout := c.Timeout
	if timeout == 0 {
		timeout = 3 * time.Second
	}
	run := c.Run
	if run == nil {
		run = runCommand
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	for _, bin := range bins {
		out, err := run(ctx, bin, "status", "--json")
		switch {
		case err == nil:
			return Parse(out)
		case errors.Is(err, exec.ErrNotFound) || errors.Is(err, fs.ErrNotExist):
			continue
		default:
			return Unavailable("tailscale is not running: " + err.Error()), nil
		}
	}
	return Unavailable("tailscale is not installed"), nil
}

func runCommand(ctx context.Context, bin string, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, bin, args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Run(); err != nil {
		if msg := firstLine(stderr.String()); msg != "" {
			return nil, fmt.Errorf("%w: %s", err, msg)
		}
		return nil, err
	}
	return stdout.Bytes(), nil
}

func firstLine(s string) string {
	s = strings.TrimSpace(s)
	line, _, _ := strings.Cut(s, "\n")
	return line
}
