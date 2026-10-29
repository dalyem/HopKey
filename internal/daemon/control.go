package daemon

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"slices"
	"strings"
	"time"

	"github.com/dalyem/hopkey/internal/model"
	"github.com/dalyem/hopkey/internal/resolve"
	"github.com/dalyem/hopkey/internal/shellcmd"
	"github.com/dalyem/hopkey/internal/sshagent"
	"github.com/dalyem/hopkey/internal/sshconfig"
	"github.com/dalyem/hopkey/internal/sshkeys"
	"github.com/dalyem/hopkey/internal/store"
	"github.com/dalyem/hopkey/internal/tailscale"
)

const maxRequest = 4 << 20 // bytes in one request line

// Deadlines for one connection. The whole of a request line has to arrive
// within idleTimeout of the previous response, so a client that stops sending,
// or drips bytes, is cut off without holding up the others. They are
// variables so tests can shorten them.
var (
	requestTimeout = 30 * time.Second // handling a request, and writing its response
	idleTimeout    = 2 * time.Minute  // waiting for a whole request
)

func (d *Daemon) serveControl() {
	l := d.control
	for {
		c, err := l.ln.AcceptUnix()
		if err != nil {
			l.mu.Lock()
			closed := l.closed
			l.mu.Unlock()
			if !closed {
				d.logf("control socket: %v", err)
			}
			return
		}
		if err := sshagent.RequireSameUID(c); err != nil {
			d.logf("control socket: rejected connection: %v", err)
			c.Close()
			continue
		}
		if !l.track(c) {
			c.Close()
			return
		}
		go d.serveConn(c)
	}
}

func (d *Daemon) serveConn(c net.Conn) {
	defer d.control.untrack(c)
	sc := bufio.NewScanner(c)
	sc.Buffer(make([]byte, 0, 64<<10), maxRequest)
	enc := json.NewEncoder(c)
	for {
		c.SetReadDeadline(time.Now().Add(idleTimeout))
		ok := sc.Scan()
		// A read error ends the connection even when Scan hands back the
		// half-line it had: a request cut off by the deadline is not a request.
		if err := sc.Err(); err != nil {
			if errors.Is(err, bufio.ErrTooLong) {
				rejectOversize(c, enc)
			}
			return
		}
		if !ok {
			return
		}
		var req Request
		var resp Response
		if err := json.Unmarshal(sc.Bytes(), &req); err != nil {
			resp = errorResponse(invalidf("malformed request: %v", err))
		} else {
			resp = d.handle(req)
		}
		c.SetWriteDeadline(time.Now().Add(requestTimeout))
		if err := enc.Encode(resp); err != nil {
			return
		}
		if req.Op == OpShutdown && resp.OK {
			// Close waits for this handler, so it runs on its own.
			go d.Close()
			return
		}
	}
}

// rejectOversize answers a request line longer than maxRequest and then reads
// (and drops) what the client is still sending, for a short while and up to a
// bound, so that closing the socket does not reset the connection before the
// client has read the refusal.
func rejectOversize(c net.Conn, enc *json.Encoder) {
	c.SetWriteDeadline(time.Now().Add(requestTimeout))
	if err := enc.Encode(errorResponse(invalidf("request is larger than %d bytes", maxRequest))); err != nil {
		return
	}
	c.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
	io.Copy(io.Discard, io.LimitReader(c, 64<<20))
}

func errorResponse(err error) Response {
	var e *Error
	if !errors.As(err, &e) {
		e = vaultError(err)
	}
	if e == nil {
		switch {
		case errors.Is(err, model.ErrNotFound):
			e = &Error{Code: CodeNotFound, Message: err.Error()}
		case errors.Is(err, model.ErrLocked):
			e = &Error{Code: CodeLocked, Message: err.Error()}
		default:
			e = &Error{Code: CodeInternal, Message: err.Error()}
		}
	}
	return Response{Error: e}
}

func (d *Daemon) handle(req Request) Response {
	ctx, cancel := context.WithTimeout(d.ctx, requestTimeout)
	defer cancel()
	result, err := d.dispatch(ctx, req)
	warning := configWarning(err)
	if err != nil && warning == nil {
		d.mu.Lock()
		d.followStore(err)
		d.mu.Unlock()
		return errorResponse(err)
	}
	var raw json.RawMessage
	if result != nil {
		b, err := json.Marshal(result)
		if err != nil {
			return errorResponse(err)
		}
		raw = b
	}
	return Response{OK: true, Result: raw, Warning: warning}
}

// configWarning is the warning for an op whose change took effect but
// whose ssh config could not be written (a configWriteError from the
// reload after it, or the CodeConfigNotWritten error an op built from
// one), or nil for any other outcome. Such an op returns its result
// together with that error, and the response is a success that carries
// both: the caller gets the saved item, and the warning. With any other
// error the result is dropped.
func configWarning(err error) *Error {
	var e *Error
	switch {
	case err == nil:
		return nil
	case errors.As(err, &e):
		if e.Code == CodeConfigNotWritten {
			return e
		}
		return nil
	case errors.Is(err, errConfigWrite):
		return &Error{Code: CodeConfigNotWritten, Message: err.Error()}
	}
	return nil
}

// reloadAfter reloads after a change (what: "saved", "deleted",
// "resolved") that has already taken effect. A config that could not be
// written is a CodeConfigNotWritten error, which the caller returns with
// its result (configWarning); any other failure to reload is an error.
// The caller holds d.mu.
func (d *Daemon) reloadAfter(ctx context.Context, what string) error {
	_, err := d.reloadLocked(ctx)
	if err == nil {
		return nil
	}
	if cw := (*configWriteError)(nil); errors.As(err, &cw) {
		return &Error{Code: CodeConfigNotWritten, Message: fmt.Sprintf(
			"%s; the ssh config could not be updated (%v), the daemon tries again every %v", what, cw.cause, d.configRetry())}
	}
	return fmt.Errorf("%s, but reloading failed: %w", what, err)
}

func (d *Daemon) dispatch(ctx context.Context, req Request) (any, error) {
	decode := func(v any) error {
		if err := json.Unmarshal(req.Params, v); err != nil {
			return invalidf("bad params for %s: %v", req.Op, err)
		}
		return nil
	}
	switch req.Op {
	case OpStatus:
		return d.opStatus(ctx)
	case OpList:
		return d.opList(ctx)
	case OpResolve:
		var p ResolveParams
		if err := decode(&p); err != nil {
			return nil, err
		}
		return d.opResolve(ctx, p)
	case OpTailscale:
		return d.tsStatus(ctx), nil
	case OpPutHost:
		var p PutHostParams
		if err := decode(&p); err != nil {
			return nil, err
		}
		return d.opPutHost(ctx, p)
	case OpSetHostKey:
		var p SetHostKeyParams
		if err := decode(&p); err != nil {
			return nil, err
		}
		return d.opSetHostKey(ctx, p)
	case OpPutKey:
		var p PutKeyParams
		if err := decode(&p); err != nil {
			return nil, err
		}
		return d.opPutKey(ctx, p)
	case OpPutSnippet:
		var p PutSnippetParams
		if err := decode(&p); err != nil {
			return nil, err
		}
		return d.opPutSnippet(ctx, p)
	case OpDelete:
		var p DeleteParams
		if err := decode(&p); err != nil {
			return nil, err
		}
		return nil, d.opDelete(ctx, p)
	case OpReload:
		return nil, d.reload(ctx)
	case OpShutdown:
		return nil, nil
	}
	if result, ok, err := d.dispatchVault(ctx, req, decode); ok {
		return result, err
	}
	if result, ok, err := d.dispatchSync(ctx, req); ok {
		return result, err
	}
	return nil, invalidf("unknown op %q", req.Op)
}

func (d *Daemon) opStatus(ctx context.Context) (*StatusResult, error) {
	snap, st, err := d.fresh(ctx)
	if errors.Is(err, model.ErrLocked) || errors.Is(err, store.ErrDeviceRevoked) {
		snap, st, err = model.Snapshot{}, lockedState(), nil
	}
	if err != nil {
		return nil, err
	}
	ts := d.tsStatus(ctx)
	out := &StatusResult{
		Version: d.opts.Version, PID: pid(), StartedAt: d.started,
		ConfigDir: d.opts.Paths.ConfigDir, AgentSocket: d.agent.Path(), ControlSocket: d.control.path,
		Hosts: len(snap.Hosts), Keys: len(snap.Keys), KeysInAgent: st.keysInAgent, SSHHosts: st.sshHosts,
		Warnings: slices.Clone(st.warnings), LoadedAt: st.loadedAt, LastError: st.lastError,
		Vault: d.vaultStatus(),
	}
	if why := d.pendingClear(); why != "" {
		out.Warnings = append(out.Warnings, d.clearWarning(why))
	}
	if d.sync != nil {
		out.Sync = d.syncStatus(false)
	}
	out.Tailscale.Available, out.Tailscale.Reason = ts.Available, ts.Reason
	return out, nil
}

func keyInfo(k model.Key) KeyInfo {
	info := KeyInfo{ID: k.ItemID.String(), Name: k.Name, KeyType: k.KeyType, PublicKey: k.PublicKey, ItemVersion: k.ItemVersion}
	if pub, err := sshkeys.ParsePublic(k.PublicKey); err == nil {
		info.Fingerprint = sshkeys.Fingerprint(pub)
	}
	if !k.DedicatedGrant.IsZero() {
		info.DedicatedGrant = k.DedicatedGrant.String()
	}
	return info
}

func (d *Daemon) opList(ctx context.Context) (*ListResult, error) {
	snap, st, err := d.fresh(ctx)
	if err != nil {
		return nil, err
	}
	out := &ListResult{
		Hosts: snap.Hosts, Snippets: snap.Snippets, SSH: st.ssh, Tailscale: d.tsStatus(ctx),
		Keys: []KeyInfo{}, Credentials: []CredentialInfo{},
	}
	if out.Hosts == nil {
		out.Hosts = []model.Host{}
	}
	if out.Snippets == nil {
		out.Snippets = []model.Snippet{}
	}
	for _, k := range snap.Keys {
		out.Keys = append(out.Keys, keyInfo(k))
	}
	for _, c := range snap.Credentials {
		out.Credentials = append(out.Credentials, CredentialInfo{ID: c.ItemID.String(), Name: c.Name, Username: c.Username})
	}
	if len(snap.Marks) > 0 {
		out.Marks = map[string]model.Mark{}
		for id, m := range snap.Marks {
			out.Marks[id.String()] = m
		}
	}
	if d.sync != nil {
		out.SyncedAt = d.sync.status().SyncedAt
	}
	return out, nil
}

func (d *Daemon) opResolve(ctx context.Context, p ResolveParams) (*ResolveResult, error) {
	snap, st, err := d.fresh(ctx)
	if err != nil {
		return nil, err
	}
	// hop status and hop list still work while the ssh config is out of
	// date; connecting does not.
	if st.configErr != "" {
		return nil, d.configStale(st.configErr)
	}
	ts := d.tsStatus(ctx)
	in := resolve.Input{Target: p.Target, Hosts: resolvable(snap.Hosts, p.AgentOnly), Tailscale: ts, Interactive: p.Interactive}
	if p.AgentOnly {
		in.Tailscale = agentTailnet(ts, snap.Hosts)
	}
	res, err := resolve.Resolve(ctx, in)
	if err != nil {
		return nil, invalidf("%v", err)
	}
	caughtUp := false
	if (res.Status == resolve.StatusNoMatch || res.Status == resolve.StatusPlainSSH) && d.sync.catchUp(ctx) {
		// A host added on another device a moment ago (design: "Fresh
		// enough to trust").
		caughtUp = true
		if snap, st, err = d.fresh(ctx); err != nil {
			return nil, err
		}
		if st.configErr != "" {
			return nil, d.configStale(st.configErr)
		}
		in.Hosts = resolvable(snap.Hosts, p.AgentOnly)
		if p.AgentOnly {
			in.Tailscale = agentTailnet(ts, snap.Hosts)
		}
		if res, err = resolve.Resolve(ctx, in); err != nil {
			return nil, invalidf("%v", err)
		}
	}
	out := &ResolveResult{Result: res, CaughtUp: caughtUp}
	if res.Host != nil {
		h := *res.Host
		out.Host = &h
		route, err := resolve.ChooseRoute(h, ts)
		switch {
		case err != nil:
			out.RouteError = err.Error()
		case !sshconfig.ValidHostName(route.Address) || (route.Fallback != "" && !sshconfig.ValidHostName(route.Fallback)):
			// The CLI hands these to ssh and to net.Dial; the store is not
			// the only thing standing between it and a strange string.
			out.RouteError = fmt.Sprintf("address %q is not usable", route.Address)
		default:
			out.Route = &route
		}
		info := st.ssh[h.ItemID.String()]
		out.SSHAlias, out.SSHProblem = info.Alias, info.Problem
		out.Mark = snap.Marks[h.ItemID]
	}
	return out, nil
}

// resolvable is the hosts a resolution may match: all of them, or with
// agentOnly only those whose agent_access allows local agents. Only
// "allow", and the empty value it defaults to, lets an agent in.
func resolvable(hosts []model.Host, agentOnly bool) []model.Host {
	if !agentOnly {
		return hosts
	}
	return slices.DeleteFunc(slices.Clone(hosts), func(h model.Host) bool {
		return h.AgentAccess != "allow" && h.AgentAccess != ""
	})
}

// agentTailnet is ts without the nodes of the hosts local agents may not
// use, for agent_only resolution: otherwise a denied host's node would come
// back as an unlinked node, by its Tailscale name or IP, in a note or among
// the candidates. A node is left out when a denied host owns it
// (HostOwnsNode), even if an allowed host is linked to it too. The route of
// a matched host is still chosen with the whole of ts.
func agentTailnet(ts *tailscale.Status, hosts []model.Host) *tailscale.Status {
	if ts == nil || !ts.Available {
		return ts
	}
	var deniedHosts []model.Host
	for _, h := range hosts {
		if h.AgentAccess != "allow" && h.AgentAccess != "" {
			deniedHosts = append(deniedHosts, h)
		}
	}
	all := ts.Nodes()
	denied := func(n tailscale.Node) bool {
		return slices.ContainsFunc(deniedHosts, func(h model.Host) bool { return HostOwnsNode(h, n, all) })
	}
	out := *ts
	if denied(out.Self) {
		out.Self = tailscale.Node{Self: true}
	}
	out.Peers = slices.DeleteFunc(slices.Clone(ts.Peers), denied)
	return &out
}

// HostOwnsNode reports whether tailnet node n, one of all (the whole
// tailnet), is host h by another name. A link that names one node only
// decides: h's stable node ID or MagicDNS name, or an address of h that is
// one of n's IPs or its MagicDNS name, ignoring case and a trailing dot.
// Failing that, an address of h that is n's short name (the MagicDNS
// name's first label) or its host name owns n only when no other node in
// all has that name, and h is not linked as above to another node: two
// machines can report the same host name ("build", given the MagicDNS
// names build and build-1), and such a name does not say which one h is.
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
	if t := h.Tailscale; t != nil {
		if t.StableNodeID != "" && t.StableNodeID == n.ID {
			return true
		}
		if t.DNSName != "" && normDNS(t.DNSName) == normDNS(n.DNSName) {
			return true
		}
	}
	for _, a := range h.Addresses {
		a = strings.Trim(strings.TrimSpace(a), "[]")
		if ip, err := netip.ParseAddr(a); err == nil {
			ip = ip.Unmap().WithZone("")
			if slices.ContainsFunc(n.IPs, func(s string) bool {
				nip, err := netip.ParseAddr(s)
				return err == nil && nip.Unmap().WithZone("") == ip
			}) {
				return true
			}
			continue
		}
		if k := normDNS(a); k != "" && k == normDNS(n.DNSName) {
			return true
		}
	}
	return false
}

func normDNS(s string) string { return strings.ToLower(strings.TrimSuffix(strings.TrimSpace(s), ".")) }

// checkHostInput fills defaults and refuses a host the ssh config could not
// represent or that would share a name with another host.
func checkHostInput(h model.Host, all []model.Host) (model.Host, error) {
	if h.Route == "" {
		h.Route = resolve.RouteAuto
	}
	if h.AgentAccess == "" {
		h.AgentAccess = "allow"
	}
	if h.Port == 0 {
		h.Port = 22
	}
	if h.Name == "" {
		return h, invalidf("a host needs a name")
	}
	seen := map[string]bool{}
	for _, n := range resolve.Names(h) {
		if !sshconfig.ValidAlias(n) {
			return h, invalidf("%q is not a valid host name or alias: use letters, digits, '.', '_' and '-', starting with a letter or digit, up to 64 characters", n)
		}
		l := strings.ToLower(n)
		if seen[l] {
			return h, invalidf("%q is listed twice for this host", n)
		}
		seen[l] = true
	}
	for _, other := range all {
		if other.ItemID == h.ItemID {
			continue
		}
		for _, n := range resolve.Names(other) {
			if seen[strings.ToLower(n)] {
				return h, invalidf("%q is already a name or alias of host %q", n, other.Name)
			}
		}
	}
	if len(h.Addresses) == 0 {
		return h, invalidf("a host needs at least one address")
	}
	for _, a := range h.Addresses {
		if !sshconfig.ValidHostName(a) {
			return h, invalidf("address %q is not usable (letters, digits, '.', ':', '_' and '-' only)", a)
		}
	}
	if h.User != "" && !sshconfig.ValidUser(h.User) {
		return h, invalidf("user %q is not usable in an ssh config", h.User)
	}
	if h.Port > 65535 {
		return h, invalidf("port %d is out of range", h.Port)
	}
	switch h.Route {
	case resolve.RouteAuto, resolve.RouteTailnet, resolve.RouteDirect:
	default:
		return h, invalidf("route must be auto, tailnet or direct, not %q", h.Route)
	}
	if h.AgentAccess != "allow" && h.AgentAccess != "deny" {
		return h, invalidf("agent_access must be allow or deny, not %q", h.AgentAccess)
	}
	for _, line := range h.HostKeys {
		if _, err := sshkeys.ParsePublic(line); err != nil {
			return h, invalidf("host key %q: %v", line, err)
		}
	}
	return h, nil
}

func (d *Daemon) opPutHost(ctx context.Context, p PutHostParams) (*model.Host, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	snap, err := d.store.Snapshot(ctx)
	if err != nil {
		return nil, err
	}
	h, err := checkHostInput(p.Host, snap.Hosts)
	if err != nil {
		return nil, err
	}
	saved, err := d.store.PutHost(ctx, h)
	if err != nil {
		return nil, storeError(err)
	}
	d.localWrite()
	return &saved, d.reloadAfter(ctx, "saved")
}

func (d *Daemon) opSetHostKey(ctx context.Context, p SetHostKeyParams) (*model.Host, error) {
	hostID, err := model.ParseID(p.HostID)
	if err != nil {
		return nil, invalidf("host_id: %v", err)
	}
	keyID, err := model.ParseID(p.KeyID)
	if err != nil {
		return nil, invalidf("key_id: %v", err)
	}
	if len(p.Chain) == 0 || p.Chain[0].ID != hostID.String() {
		return nil, invalidf("chain must start with the host")
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	snap, err := d.store.Snapshot(ctx)
	if err != nil {
		return nil, err
	}
	if !slices.ContainsFunc(snap.Keys, func(k model.Key) bool { return k.ItemID == keyID }) {
		return nil, &Error{Code: CodeNotFound, Message: "no key " + keyID.String()}
	}
	byID := map[model.ID]model.Host{}
	for _, h := range snap.Hosts {
		byID[h.ItemID] = h
	}
	changed := func(what string) error {
		return &Error{Code: CodeChanged, Message: what + " changed; nothing was written"}
	}
	host, ok := byID[hostID]
	if !ok {
		return nil, &Error{Code: CodeNotFound, Message: "no host " + hostID.String()}
	}
	cur := host
	for i, want := range p.Chain {
		if cur.ItemID.String() != want.ID || cur.ItemVersion != want.Version {
			if i == 0 {
				return nil, changed("the host " + host.Name)
			}
			return nil, changed("the way to " + host.Name + " (jump host " + cur.Name + ")")
		}
		if cur.JumpHostID.IsZero() {
			if i != len(p.Chain)-1 {
				return nil, changed("the way to " + host.Name)
			}
			break
		}
		if i == len(p.Chain)-1 {
			return nil, changed("the way to " + host.Name)
		}
		if cur, ok = byID[cur.JumpHostID]; !ok {
			return nil, changed("the way to " + host.Name + " (a jump host is missing)")
		}
	}
	host.KeyID = keyID
	h, err := checkHostInput(host, snap.Hosts)
	if err != nil {
		return nil, err
	}
	saved, err := d.store.PutHost(ctx, h)
	if err != nil {
		return nil, storeError(err)
	}
	d.localWrite()
	return &saved, d.reloadAfter(ctx, "saved")
}

func (d *Daemon) opPutKey(ctx context.Context, p PutKeyParams) (*KeyInfo, error) {
	name := strings.TrimSpace(p.Name)
	if name == "" {
		return nil, invalidf("a key needs a name")
	}
	priv, err := sshkeys.Parse([]byte(p.PrivateKey))
	if errors.Is(err, sshkeys.ErrPassphrase) {
		return nil, invalidf("the key is passphrase-protected; give hop the passphrase or remove it first")
	}
	if err != nil {
		return nil, invalidf("%v", err)
	}
	pem, err := priv.MarshalPrivate(name)
	if err != nil {
		return nil, invalidf("%v", err)
	}

	d.mu.Lock()
	defer d.mu.Unlock()
	snap, err := d.store.Snapshot(ctx)
	if err != nil {
		return nil, err
	}
	for _, k := range snap.Keys {
		if strings.EqualFold(k.Name, name) {
			return nil, invalidf("a key named %q already exists", k.Name)
		}
		if pub, err := sshkeys.ParsePublic(k.PublicKey); err == nil && slices.Equal(pub.Marshal(), priv.Public.Marshal()) {
			return nil, invalidf("this key is already in the vault as %q", k.Name)
		}
	}
	saved, err := d.store.PutKey(ctx, model.Key{
		Name: name, KeyType: priv.Type, PrivateKey: pem, PublicKey: sshkeys.Line(priv.Public),
	})
	if err != nil {
		return nil, storeError(err)
	}
	d.localWrite()
	info := keyInfo(saved)
	return &info, d.reloadAfter(ctx, "saved")
}

// checkSnippetInput derives the snippet's parameters from its command and
// refuses one hop could not run, or that would share a name with another
// snippet.
func checkSnippetInput(s model.Snippet, all []model.Snippet) (model.Snippet, error) {
	s.Name = strings.TrimSpace(s.Name)
	if !sshconfig.ValidAlias(s.Name) {
		return s, invalidf("%q is not a valid snippet name: use letters, digits, '.', '_' and '-', starting with a letter or digit, up to 64 characters", s.Name)
	}
	if strings.TrimSpace(s.Command) == "" {
		return s, invalidf("a snippet needs a command")
	}
	if len(s.Command) > 8192 {
		return s, invalidf("the command is longer than 8192 bytes")
	}
	if len(s.Description) > 1024 {
		return s, invalidf("the description is longer than 1024 bytes")
	}
	params, err := shellcmd.Placeholders(s.Command)
	if err != nil {
		return s, invalidf("%v", err)
	}
	s.Params = params
	for _, o := range all {
		if o.ItemID != s.ItemID && strings.EqualFold(o.Name, s.Name) {
			return s, invalidf("a snippet named %q already exists", o.Name)
		}
	}
	return s, nil
}

func (d *Daemon) opPutSnippet(ctx context.Context, p PutSnippetParams) (*model.Snippet, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	snap, err := d.store.Snapshot(ctx)
	if err != nil {
		return nil, err
	}
	sn, err := checkSnippetInput(p.Snippet, snap.Snippets)
	if err != nil {
		return nil, err
	}
	saved, err := d.store.PutSnippet(ctx, sn)
	if err != nil {
		return nil, storeError(err)
	}
	d.localWrite()
	return &saved, d.reloadAfter(ctx, "saved")
}

func (d *Daemon) opDelete(ctx context.Context, p DeleteParams) error {
	id, err := model.ParseID(p.ID)
	if err != nil {
		return invalidf("%v", err)
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if err := d.store.Delete(ctx, id); err != nil {
		return storeError(err)
	}
	d.localWrite()
	return d.reloadAfter(ctx, "deleted")
}

// storeError passes the store's own sentinel errors through and presents any
// other refusal (reference integrity, a stale version) as invalid input.
func storeError(err error) error {
	if errors.Is(err, model.ErrNotFound) || errors.Is(err, model.ErrLocked) {
		return err
	}
	return invalidf("%v", err)
}
