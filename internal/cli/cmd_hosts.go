package cli

import (
	"context"
	"flag"
	"fmt"
	"slices"
	"strings"
	"text/tabwriter"

	"github.com/dalyem/hopkey/internal/daemon"
	"github.com/dalyem/hopkey/internal/model"
	"github.com/dalyem/hopkey/internal/resolve"
	"github.com/dalyem/hopkey/internal/sshkeys"
)

func listAll(ctx context.Context, e *Env) (*daemon.ListResult, error) {
	var l daemon.ListResult
	if err := call(ctx, e, daemon.OpList, nil, &l); err != nil {
		return nil, err
	}
	return &l, nil
}

// ---- views: what ls and info print. Nothing here is secret. ----

type keyRef struct {
	Name        string `json:"name"`
	Fingerprint string `json:"fingerprint"`
}

type pinView struct {
	Type        string `json:"type"`
	Fingerprint string `json:"fingerprint"`
}

type tsView struct {
	StableNodeID string   `json:"stable_node_id"`
	DNSName      string   `json:"dns_name"`
	SSH          string   `json:"ssh"`
	Online       *bool    `json:"online"` // null when the local tailnet cannot say
	IPs          []string `json:"ips,omitempty"`
}

// HostView is the --json shape of hop ls (a list of them) and hop info.
type HostView struct {
	ID          string         `json:"id"`
	Name        string         `json:"name"`
	Aliases     []string       `json:"aliases"`
	Addresses   []string       `json:"addresses"`
	Port        uint32         `json:"port"`
	User        string         `json:"user"`
	Key         *keyRef        `json:"key"`
	JumpHost    string         `json:"jump_host,omitempty"`
	Tags        []string       `json:"tags"`
	Description string         `json:"description"`
	Route       string         `json:"route"`
	AgentAccess string         `json:"agent_access"`
	Tailscale   *tsView        `json:"tailscale"`
	HostKeys    []pinView      `json:"host_keys"`
	SSHAlias    string         `json:"ssh_alias,omitempty"`
	SSHProblem  string         `json:"ssh_problem,omitempty"`
	ChosenRoute *resolve.Route `json:"chosen_route,omitempty"` // hop info only
}

func hostView(h model.Host, l *daemon.ListResult) HostView {
	v := HostView{
		ID: h.ItemID.String(), Name: h.Name, Aliases: nonNil(h.Aliases), Addresses: nonNil(h.Addresses),
		Port: h.Port, User: h.User, Tags: nonNil(h.Tags), Description: h.Description,
		Route: h.Route, AgentAccess: h.AgentAccess, HostKeys: []pinView{},
	}
	if !h.KeyID.IsZero() {
		for _, k := range l.Keys {
			if k.ID == h.KeyID.String() {
				v.Key = &keyRef{Name: k.Name, Fingerprint: k.Fingerprint}
			}
		}
	}
	if !h.JumpHostID.IsZero() {
		for _, o := range l.Hosts {
			if o.ItemID == h.JumpHostID {
				v.JumpHost = o.Name
			}
		}
	}
	if t := h.Tailscale; t != nil {
		tv := &tsView{StableNodeID: t.StableNodeID, DNSName: t.DNSName, SSH: t.SSH}
		if l.Tailscale != nil {
			if n, ok := l.Tailscale.NodeByID(t.StableNodeID); ok {
				online := n.Online
				tv.Online, tv.IPs = &online, n.IPs
			}
		}
		v.Tailscale = tv
	}
	for _, line := range h.HostKeys {
		if p, err := sshkeys.ParsePublic(line); err == nil {
			v.HostKeys = append(v.HostKeys, pinView{Type: p.Type(), Fingerprint: sshkeys.Fingerprint(p)})
		}
	}
	info := l.SSH[v.ID]
	v.SSHAlias, v.SSHProblem = info.Alias, info.Problem
	return v
}

func nonNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

func runLs(ctx context.Context, e *Env, args []string) error {
	fs := newFlags(e, "ls", commands["ls"].usage)
	asJSON := fs.Bool("json", false, "print the hosts as JSON")
	pos, _, err := parseFlags(fs, args)
	if err != nil {
		return err
	}
	if len(pos) > 1 {
		fs.Usage()
		return failf("expected at most one tag")
	}
	l, err := listAll(ctx, e)
	if err != nil {
		return err
	}
	hosts := slices.Clone(l.Hosts)
	if len(pos) == 1 {
		hosts = slices.DeleteFunc(hosts, func(h model.Host) bool {
			return !slices.ContainsFunc(h.Tags, func(t string) bool { return strings.EqualFold(t, pos[0]) })
		})
	}
	slices.SortFunc(hosts, func(a, b model.Host) int {
		return strings.Compare(strings.ToLower(a.Name), strings.ToLower(b.Name))
	})
	views := make([]HostView, 0, len(hosts))
	for _, h := range hosts {
		views = append(views, hostView(h, l))
	}
	if *asJSON {
		return printJSON(e, views)
	}
	if len(views) == 0 {
		fmt.Fprintln(e.Stderr, "no hosts")
		return nil
	}
	tw := tabwriter.NewWriter(e.Stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "NAME\tADDRESS\tUSER\tKEY\tTAGS\tTAILSCALE\tPINS\tSSH")
	for _, v := range views {
		addr := ""
		if len(v.Addresses) > 0 {
			addr = v.Addresses[0]
			if len(v.Addresses) > 1 {
				addr += fmt.Sprintf(" +%d", len(v.Addresses)-1)
			}
		}
		key := "-"
		if v.Key != nil {
			key = v.Key.Name
		}
		ts := "-"
		if v.Tailscale != nil {
			switch {
			case v.Tailscale.Online == nil:
				ts = "linked"
			case *v.Tailscale.Online:
				ts = "online"
			default:
				ts = "offline"
			}
		}
		sshState := "ok"
		if v.SSHProblem != "" {
			sshState = "blocked"
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\t%d\t%s\n", v.Name, addr, dash(v.User), key, dash(strings.Join(v.Tags, ",")), ts, len(v.HostKeys), sshState)
	}
	return tw.Flush()
}

func dash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

func runInfo(ctx context.Context, e *Env, args []string) error {
	fs := newFlags(e, "info", commands["info"].usage)
	asJSON := fs.Bool("json", false, "print the host as JSON")
	pos, _, err := parseFlags(fs, args)
	if err != nil {
		return err
	}
	if len(pos) != 1 {
		fs.Usage()
		return failf("expected exactly one target")
	}
	rr, err := resolveTarget(ctx, e, pos[0], interactiveResolution(e, *asJSON))
	if err != nil {
		return err
	}
	if rr.Result.Status != resolve.StatusMatched || rr.Host == nil {
		return failf("%s", describeUnresolved(rr.Result))
	}
	l, err := listAll(ctx, e)
	if err != nil {
		return err
	}
	v := hostView(*rr.Host, l)
	v.ChosenRoute = rr.Route
	if *asJSON {
		return printJSON(e, v)
	}
	e.printf("name:         %s\n", v.Name)
	e.printf("id:           %s\n", v.ID)
	if len(v.Aliases) > 0 {
		e.printf("aliases:      %s\n", strings.Join(v.Aliases, ", "))
	}
	e.printf("addresses:    %s\n", strings.Join(v.Addresses, ", "))
	e.printf("port:         %d\n", v.Port)
	e.printf("user:         %s\n", dash(v.User))
	if v.Key != nil {
		e.printf("key:          %s (%s)\n", v.Key.Name, v.Key.Fingerprint)
	} else {
		e.printf("key:          none\n")
	}
	if v.JumpHost != "" {
		e.printf("jump host:    %s\n", v.JumpHost)
	}
	e.printf("tags:         %s\n", dash(strings.Join(v.Tags, ", ")))
	if v.Description != "" {
		e.printf("description:  %s\n", v.Description)
	}
	e.printf("route:        %s\n", v.Route)
	if v.ChosenRoute != nil {
		e.printf("would use:    %s:%d via %s\n", v.ChosenRoute.Address, v.ChosenRoute.Port, v.ChosenRoute.Label())
	}
	e.printf("agent access: %s\n", v.AgentAccess)
	if t := v.Tailscale; t != nil {
		state := "unknown"
		if t.Online != nil {
			state = map[bool]string{true: "online", false: "offline"}[*t.Online]
		}
		e.printf("tailscale:    %s, %s, node %s, ssh %s\n", t.DNSName, state, t.StableNodeID, t.SSH)
	}
	if len(v.HostKeys) == 0 {
		e.printf("host keys:    none pinned (ssh will refuse this host until you run hop trust %s)\n", v.Name)
	}
	for _, p := range v.HostKeys {
		e.printf("host key:     %s %s\n", p.Type, p.Fingerprint)
	}
	if v.SSHAlias != "" {
		e.printf("ssh:          ssh %s\n", v.SSHAlias)
	} else {
		e.printf("ssh:          not available: %s\n", orUnknown(v.SSHProblem))
	}
	return nil
}

// ---- hop add / edit ----

// hostFlags are the flags hop add and hop edit share.
type hostFlags struct {
	fs          *flag.FlagSet
	name        *string
	user        *string
	key         *string
	jump        *string
	description *string
	route       *string
	agentAccess *string
	port        *int
	addresses   stringList
	aliases     stringList
	tags        stringList
	hostKeys    stringList
}

func newHostFlags(fs *flag.FlagSet, withName bool) *hostFlags {
	hf := &hostFlags{fs: fs}
	if withName {
		hf.name = fs.String("name", "", "new name for the host")
	}
	hf.user = fs.String("user", "", "ssh user")
	hf.key = fs.String("key", "", "name of the key to log in with (see hop key ls)")
	hf.jump = fs.String("jump", "", "host to reach this one through (ProxyJump)")
	hf.description = fs.String("description", "", "free-text description")
	hf.route = fs.String("route", "", "auto, tailnet or direct")
	hf.agentAccess = fs.String("agent-access", "", "allow or deny; deny keeps the host out of agent tool results")
	hf.port = fs.Int("port", 0, "ssh port")
	fs.Var(&hf.addresses, "address", "hostname or IP (repeatable; replaces the list on edit)")
	fs.Var(&hf.aliases, "alias", "another name for the host (repeatable)")
	fs.Var(&hf.tags, "tag", "tag (repeatable)")
	fs.Var(&hf.hostKeys, "host-key", "pinned server key as an OpenSSH public-key line (repeatable)")
	return hf
}

// apply copies the flags that were given onto h.
func (hf *hostFlags) apply(ctx context.Context, e *Env, h *model.Host, l *daemon.ListResult) error {
	set := func(name string) bool { return wasSet(hf.fs, name) }
	if hf.name != nil && set("name") {
		h.Name = *hf.name
	}
	if set("user") {
		h.User = *hf.user
	}
	if set("description") {
		h.Description = *hf.description
	}
	if set("route") {
		h.Route = *hf.route
	}
	if set("agent-access") {
		h.AgentAccess = *hf.agentAccess
	}
	if set("port") {
		if *hf.port < 1 || *hf.port > 65535 {
			return failf("port %d is out of range", *hf.port)
		}
		h.Port = uint32(*hf.port)
	}
	if hf.addresses.set {
		h.Addresses = hf.addresses.vals
	}
	if hf.aliases.set {
		h.Aliases = hf.aliases.vals
	}
	if hf.tags.set {
		h.Tags = hf.tags.vals
	}
	if hf.hostKeys.set {
		h.HostKeys = nil
		for _, line := range hf.hostKeys.vals {
			pub, err := sshkeys.ParsePublic(line)
			if err != nil {
				return failf("--host-key %q: %v", line, err)
			}
			h.HostKeys = append(h.HostKeys, sshkeys.Line(pub))
		}
	}
	if set("key") {
		if *hf.key == "" {
			h.KeyID = model.ID{}
		} else {
			id, err := findKey(l, *hf.key)
			if err != nil {
				return err
			}
			h.KeyID = id
		}
	}
	if set("jump") {
		if *hf.jump == "" {
			h.JumpHostID = model.ID{}
		} else {
			rr, err := resolveTarget(ctx, e, *hf.jump, false)
			if err != nil {
				return err
			}
			if rr.Result.Status != resolve.StatusMatched {
				return failf("--jump: %s", describeUnresolved(rr.Result))
			}
			id, err := model.ParseID(rr.Result.HostID)
			if err != nil {
				return err
			}
			h.JumpHostID = id
		}
	}
	return nil
}

// findKey finds a key by name (any case) or by full ID.
func findKey(l *daemon.ListResult, ref string) (model.ID, error) {
	for _, k := range l.Keys {
		if strings.EqualFold(k.Name, ref) || k.ID == ref {
			return model.ParseID(k.ID)
		}
	}
	var names []string
	for _, k := range l.Keys {
		names = append(names, k.Name)
	}
	if len(names) == 0 {
		return model.ID{}, failf("no key named %q; the vault has no keys yet (hop key add <path>)", ref)
	}
	return model.ID{}, failf("no key named %q; keys: %s", ref, strings.Join(names, ", "))
}

func runAdd(ctx context.Context, e *Env, args []string) error {
	fs := newFlags(e, "add", commands["add"].usage)
	asJSON := fs.Bool("json", false, "print the saved host as JSON")
	hf := newHostFlags(fs, false)
	pos, _, err := parseFlags(fs, args)
	if err != nil {
		return err
	}
	if len(pos) != 1 {
		fs.Usage()
		return failf("expected exactly one host name")
	}
	l, err := listAll(ctx, e)
	if err != nil {
		return err
	}
	h := model.Host{
		Name: pos[0], Port: 22, Route: resolve.RouteAuto, AgentAccess: "allow",
		Addresses: []string{pos[0]}, // like ssh: the name is the address unless told otherwise
	}
	if err := hf.apply(ctx, e, &h, l); err != nil {
		return err
	}
	var saved model.Host
	if err := call(ctx, e, daemon.OpPutHost, daemon.PutHostParams{Host: h}, &saved); err != nil {
		return err
	}
	return reportHost(ctx, e, *asJSON, saved, "added")
}

func reportHost(ctx context.Context, e *Env, asJSON bool, h model.Host, verb string) error {
	l, err := listAll(ctx, e)
	if err != nil {
		return err
	}
	v := hostView(h, l)
	if asJSON {
		return printJSON(e, v)
	}
	e.printf("%s %s\n", verb, v.Name)
	if v.SSHProblem != "" {
		fmt.Fprintf(e.Stderr, "hop: note: %s is not usable with ssh yet: %s\n", v.Name, v.SSHProblem)
	} else if len(v.HostKeys) == 0 {
		fmt.Fprintf(e.Stderr, "hop: note: no host key is pinned for %s; pin it with: hop trust %s\n", v.Name, v.Name)
	}
	return nil
}

func runEdit(ctx context.Context, e *Env, args []string) error {
	fs := newFlags(e, "edit", commands["edit"].usage)
	asJSON := fs.Bool("json", false, "print the saved host as JSON")
	hf := newHostFlags(fs, true)
	pos, _, err := parseFlags(fs, args)
	if err != nil {
		return err
	}
	if len(pos) != 1 {
		fs.Usage()
		return failf("expected exactly one target")
	}
	rr, err := resolveTarget(ctx, e, pos[0], false)
	if err != nil {
		return err
	}
	if rr.Result.Status != resolve.StatusMatched || rr.Host == nil {
		return failf("%s", describeUnresolved(rr.Result))
	}
	l, err := listAll(ctx, e)
	if err != nil {
		return err
	}
	h := *rr.Host
	if err := hf.apply(ctx, e, &h, l); err != nil {
		return err
	}
	var saved model.Host
	if err := call(ctx, e, daemon.OpPutHost, daemon.PutHostParams{Host: h}, &saved); err != nil {
		return err
	}
	return reportHost(ctx, e, *asJSON, saved, "updated")
}

func runRm(ctx context.Context, e *Env, args []string) error {
	fs := newFlags(e, "rm", commands["rm"].usage)
	yes := fs.Bool("yes", false, "do not ask")
	asJSON := fs.Bool("json", false, "print the result as JSON")
	pos, _, err := parseFlags(fs, args)
	if err != nil {
		return err
	}
	if len(pos) != 1 {
		fs.Usage()
		return failf("expected exactly one target")
	}
	rr, err := resolveTarget(ctx, e, pos[0], false)
	if err != nil {
		return err
	}
	if rr.Result.Status != resolve.StatusMatched || rr.Host == nil {
		return failf("%s", describeUnresolved(rr.Result))
	}
	h := rr.Host
	ok, err := confirm(e, *yes, fmt.Sprintf("Remove host %s (%s)?", h.Name, strings.Join(h.Addresses, ", ")))
	if err != nil {
		return err
	}
	if !ok {
		return failf("not removed")
	}
	if err := call(ctx, e, daemon.OpDelete, daemon.DeleteParams{ID: h.ItemID.String()}, nil); err != nil {
		return err
	}
	if *asJSON {
		return printJSON(e, map[string]any{"removed": h.Name, "id": h.ItemID.String()})
	}
	e.printf("removed %s\n", h.Name)
	return nil
}
