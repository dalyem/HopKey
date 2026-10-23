package daemon

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"slices"
	"strings"
	"time"

	"github.com/dalyem/hopkey/internal/model"
	"github.com/dalyem/hopkey/internal/resolve"
	"github.com/dalyem/hopkey/internal/sshagent"
	"github.com/dalyem/hopkey/internal/sshconfig"
	"github.com/dalyem/hopkey/internal/sshkeys"
	"github.com/dalyem/hopkey/internal/store"
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
		case errors.Is(err, errConfigWrite):
			e = &Error{Code: CodeConfigNotWritten, Message: err.Error()}
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
	if err != nil {
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
	return Response{OK: true, Result: raw}
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
	case OpPutKey:
		var p PutKeyParams
		if err := decode(&p); err != nil {
			return nil, err
		}
		return d.opPutKey(ctx, p)
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
	in := resolve.Input{Target: p.Target, Hosts: snap.Hosts, Tailscale: ts, Interactive: p.Interactive}
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
		in.Hosts = snap.Hosts
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
	if _, err := d.reloadLocked(ctx); err != nil {
		return nil, fmt.Errorf("saved, but reloading failed: %w", err)
	}
	return &saved, nil
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
	if _, err := d.reloadLocked(ctx); err != nil {
		return nil, fmt.Errorf("saved, but reloading failed: %w", err)
	}
	info := keyInfo(saved)
	return &info, nil
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
	if _, err := d.reloadLocked(ctx); err != nil {
		return fmt.Errorf("deleted, but reloading failed: %w", err)
	}
	return nil
}

// storeError passes the store's own sentinel errors through and presents any
// other refusal (reference integrity, a stale version) as invalid input.
func storeError(err error) error {
	if errors.Is(err, model.ErrNotFound) || errors.Is(err, model.ErrLocked) {
		return err
	}
	return invalidf("%v", err)
}
