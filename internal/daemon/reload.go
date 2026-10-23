package daemon

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/dalyem/hopkey/internal/model"
	"github.com/dalyem/hopkey/internal/resolve"
	"github.com/dalyem/hopkey/internal/sshagent"
	"github.com/dalyem/hopkey/internal/sshconfig"
	"github.com/dalyem/hopkey/internal/sshkeys"
	"github.com/dalyem/hopkey/internal/store"
	"github.com/dalyem/hopkey/internal/tailscale"
)

// state is what the last successful reload produced.
type state struct {
	fingerprint string // of the snapshot it came from
	loadedAt    time.Time
	ssh         map[string]HostSSH // by host ID
	keysInAgent int
	sshHosts    int
	warnings    []string
	lastError   string // set on a copy of the state when a later reload failed

	locked  bool           // the vault is locked: nothing is loaded
	revoked bool           // and for good: this device was revoked
	snap    model.Snapshot // what it was built from, when head is set
	head    store.Head     // the store's head at the time, if it has one
	hasHead bool
	// outboxGen is the daemon's outboxGen when snap was read.
	outboxGen uint64
	// configErr says why the ssh config could not be written from snap.
	// The keyring came from snap all the same; the config is retried
	// (retryConfig).
	configErr string
}

// configRetryInterval is how often a config that could not be written is
// tried again, whatever sync is doing.
const configRetryInterval = 30 * time.Second

// errConfigWrite marks a reload whose ssh config could not be written.
var errConfigWrite = errors.New("writing the ssh config")

// fingerprint identifies a snapshot by the IDs and versions of its items.
// Every change to an item bumps its version, so this changes whenever the
// store's contents do.
func fingerprint(s model.Snapshot) string {
	var lines []string
	for _, h := range s.Hosts {
		lines = append(lines, fmt.Sprintf("host %s %d", h.ItemID, h.ItemVersion))
	}
	for _, k := range s.Keys {
		lines = append(lines, fmt.Sprintf("key %s %d", k.ItemID, k.ItemVersion))
	}
	for _, c := range s.Credentials {
		lines = append(lines, fmt.Sprintf("credential %s %d", c.ItemID, c.ItemVersion))
	}
	for _, sn := range s.Snippets {
		lines = append(lines, fmt.Sprintf("snippet %s %d", sn.ItemID, sn.ItemVersion))
	}
	for id, m := range s.Marks {
		lines = append(lines, fmt.Sprintf("mark %s %s", id, m))
	}
	slices.Sort(lines)
	sum := sha256.Sum256([]byte(strings.Join(lines, "\n")))
	return hex.EncodeToString(sum[:])
}

// reload takes the lock, reads the store and rebuilds the keyring and ssh
// config from it.
func (d *Daemon) reload(ctx context.Context) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	_, err := d.reloadLocked(ctx)
	return err
}

// reloadLocked reads a fresh snapshot, rebuilds everything from it and
// returns it. On failure the previous keyring and config stay in place and
// the failure is recorded in the state, except when only the ssh config
// could not be written (errConfigWrite): the keyring and the state are the
// snapshot's then, and it is returned with the error.
func (d *Daemon) reloadLocked(ctx context.Context) (model.Snapshot, error) {
	// The generation is read before the snapshot: if the store locks or
	// unlocks in between, the keyring is fenced off until the next reload.
	gen := d.live.generation()
	outboxGen := d.outboxGen.Load()
	head, hasHead := d.storeHead()
	snap, err := d.store.Snapshot(ctx)
	if err != nil {
		d.noteError(err)
		d.followStore(err)
		return model.Snapshot{}, err
	}
	next, err := d.apply(ctx, snap, gen)
	if next == nil {
		d.noteError(err)
		return model.Snapshot{}, err
	}
	next.snap, next.head, next.hasHead, next.outboxGen = snap, head, hasHead, outboxGen
	if err != nil {
		// The keyring is snap's; only the ssh config lags behind it.
		d.logf("reload failed: %v", err)
		next.lastError = err.Error()
	}
	d.state.Store(next)
	return snap, err
}

func (d *Daemon) noteError(err error) {
	d.logf("reload failed: %v", err)
	if cur := d.state.Load(); cur != nil {
		cp := *cur
		cp.lastError = err.Error()
		d.state.Store(&cp)
	}
}

// fresh returns the current snapshot, reloading first if the store has
// changed since the last reload (another device synced, say). A store that
// reports its log head is asked only for that while neither it nor the
// outbox has changed. A keyring from an earlier store generation (the
// vault locked and unlocked again) is always reloaded.
func (d *Daemon) fresh(ctx context.Context) (model.Snapshot, *state, error) {
	if cur, ok := d.current(); ok {
		return cur.snap, cur, nil
	}
	snap, err := d.store.Snapshot(ctx)
	if err != nil {
		d.mu.Lock()
		d.followStore(err)
		d.mu.Unlock()
		return model.Snapshot{}, nil, err
	}
	if cur := d.state.Load(); cur != nil && cur.fingerprint == fingerprint(snap) && cur.configErr == "" && !d.live.stale() {
		return snap, cur, nil
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	snap, err = d.reloadLocked(ctx)
	if err != nil && !errors.Is(err, errConfigWrite) {
		return model.Snapshot{}, nil, err
	}
	// A config that could not be written is a warning in the state.
	return snap, d.state.Load(), nil
}

// current returns the last reload's state when it still matches the
// store: the same head, the same outbox and the same store generation,
// with the ssh config written. One whose config could not be written is
// never current, so the next reload tries again.
func (d *Daemon) current() (*state, bool) {
	h, ok := d.storeHead()
	if !ok {
		return nil, false
	}
	cur := d.state.Load()
	if cur == nil || !cur.hasHead || cur.head != h || cur.outboxGen != d.outboxGen.Load() || cur.configErr != "" || d.live.stale() {
		return nil, false
	}
	return cur, true
}

// refreshAfterSync rebuilds the keyring and ssh config after a pull, a
// push or a resolution, if the verified head or the outbox moved.
func (d *Daemon) refreshAfterSync(ctx context.Context) {
	if _, ok := d.current(); ok {
		return
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if _, ok := d.current(); ok {
		return
	}
	if _, err := d.reloadLocked(ctx); err != nil {
		d.logf("reload after sync: %v", err)
	}
}

// localWrite notes a write through the daemon: in a server-backed vault it
// queued a record, so the overlay changed even though the head did not,
// and the sync loop should push it now. The caller holds d.mu and reloads
// next.
func (d *Daemon) localWrite() {
	d.outboxGen.Add(1)
	d.sync.wake()
}

// tsStatus reads the tailnet, reusing a result that is a couple of seconds
// old so a burst of requests runs the tailscale command once.
func (d *Daemon) tsStatus(ctx context.Context) *tailscale.Status {
	d.tsMu.Lock()
	defer d.tsMu.Unlock()
	if d.tsCached != nil && time.Since(d.tsAt) < 2*time.Second {
		return d.tsCached
	}
	st, err := d.ts.Status(ctx)
	if err != nil {
		st = tailscale.Unavailable("tailscale status could not be read: " + err.Error())
	}
	d.tsCached, d.tsAt = st, time.Now()
	return st
}

// plan is one vault host on its way into the ssh config.
type plan struct {
	host     model.Host
	hostName string
	port     int
	pub      ssh.PublicKey
	keyless  bool // Tailscale SSH: the block offers no key
	pins     []ssh.PublicKey
	aliases  []string // the Host blocks it gets; the first is the primary
	problem  string   // why the host gets none
}

// apply builds the keyring and ssh config from snap, read in store
// generation gen, and installs them: the keyring first, since serving
// exactly the keys snap has is always right, then the config. When the
// config can't be written it returns the state with configErr set and the
// error; the agent no longer serves a key snap deleted, whatever happens
// to the config. Any other failure returns a nil state.
func (d *Daemon) apply(ctx context.Context, snap model.Snapshot, gen uint64) (*state, error) {
	st := &state{fingerprint: fingerprint(snap), loadedAt: time.Now(), ssh: map[string]HostSSH{}}
	warn := func(format string, args ...any) {
		st.warnings = append(st.warnings, fmt.Sprintf(format, args...))
	}

	// Keys: everything parseable goes to the agent. ssh picks the right one
	// through the public key file in each Host block.
	kr := sshagent.NewKeyring()
	pubs := map[model.ID]ssh.PublicKey{}
	keyProblem := map[model.ID]string{}
	for _, k := range snap.Keys {
		priv, err := sshkeys.Parse([]byte(k.PrivateKey))
		if err != nil {
			keyProblem[k.ItemID] = fmt.Sprintf("key %q cannot be loaded: %v", k.Name, err)
			warn("%s", keyProblem[k.ItemID])
			continue
		}
		if err := kr.Add(priv.Raw, k.Name); err != nil {
			keyProblem[k.ItemID] = fmt.Sprintf("key %q cannot be loaded: %v", k.Name, err)
			warn("%s", keyProblem[k.ItemID])
			continue
		}
		pubs[k.ItemID] = priv.Public
		if k.PublicKey != "" {
			if stored, err := sshkeys.ParsePublic(k.PublicKey); err != nil || !slices.Equal(stored.Marshal(), priv.Public.Marshal()) {
				warn("key %q: the stored public key does not match the private key; using the private key's", k.Name)
			}
		}
		st.keysInAgent++
	}

	ts := d.tsStatus(ctx)
	plans := d.plan(snap, ts, pubs, keyProblem, warn)

	var hosts []sshconfig.Host
	for _, p := range plans {
		if p.problem != "" {
			st.ssh[p.host.ItemID.String()] = HostSSH{Problem: p.problem}
			continue
		}
		st.ssh[p.host.ItemID.String()] = HostSSH{Alias: p.aliases[0], Aliases: slices.Clone(p.aliases)}
		st.sshHosts++
		jump := ""
		if !p.host.JumpHostID.IsZero() {
			for _, q := range plans {
				if q.host.ItemID == p.host.JumpHostID {
					jump = q.aliases[0]
				}
			}
		}
		for _, alias := range p.aliases {
			hosts = append(hosts, sshconfig.Host{
				Alias: alias, HostName: p.hostName, Port: p.port, User: p.host.User,
				ProxyJump: jump, PublicKey: p.pub, Keyless: p.keyless, HostKeys: p.pins,
			})
		}
	}
	old := d.live.swap(kr, gen)
	old.RemoveAll() // best effort: drop the old key material

	err := d.writeConfig(sshconfig.Options{Dir: d.opts.Paths.ConfigDir, AgentSocket: d.agent.Path()}, hosts)
	if err != nil {
		err = fmt.Errorf("%w: %w", errConfigWrite, err)
		st.configErr = err.Error()
		warn("%s", d.configWarning(st.configErr))
	}
	slices.Sort(st.warnings)
	return st, err
}

// configWarning tells the user that the ssh config could not be written.
func (d *Daemon) configWarning(why string) string {
	return fmt.Sprintf("the ssh config in %s is out of date (%s): the agent already serves only the vault's current keys, "+
		"but ssh may still see hosts as they were; the daemon tries again on each sync and unlock, and every %v",
		d.opts.Paths.ConfigDir, why, d.configRetry())
}

func (d *Daemon) configRetry() time.Duration {
	if d.opts.configRetry > 0 {
		return d.opts.configRetry
	}
	return configRetryInterval
}

// retryConfig rebuilds from the store while the last reload could not
// write the ssh config, on a timer of its own, so a sync loop that is
// halted or idle does not leave the config stale. Each reload, unlock and
// reconcile tries again too, since such a state is never current.
func (d *Daemon) retryConfig() {
	dirty := func() bool { cur := d.state.Load(); return cur != nil && cur.configErr != "" }
	d.wg.Add(1)
	go func() {
		defer d.wg.Done()
		t := time.NewTicker(d.configRetry())
		defer t.Stop()
		for {
			select {
			case <-d.ctx.Done():
				return
			case <-t.C:
			}
			if !dirty() {
				continue
			}
			d.mu.Lock()
			if dirty() && d.ctx.Err() == nil {
				d.reloadLocked(d.ctx) // a failure is recorded and logged
			}
			d.mu.Unlock()
		}
	}()
}

// plan decides, for each host, whether it gets Host blocks and what they say.
// A host that cannot be written gets a problem instead, and the hosts that
// jump through it do too.
func (d *Daemon) plan(snap model.Snapshot, ts *tailscale.Status, pubs map[model.ID]ssh.PublicKey, keyProblem map[model.ID]string, warn func(string, ...any)) []*plan {
	hosts := slices.Clone(snap.Hosts)
	slices.SortStableFunc(hosts, func(a, b model.Host) int {
		return strings.Compare(strings.ToLower(a.Name), strings.ToLower(b.Name))
	})
	plans := make([]*plan, 0, len(hosts))
	byID := map[model.ID]*plan{}
	owner := map[string]model.ID{} // lower-cased alias -> host

	release := func(p *plan, why string) {
		for _, a := range p.aliases {
			if owner[strings.ToLower(a)] == p.host.ItemID {
				delete(owner, strings.ToLower(a))
			}
		}
		p.aliases, p.problem = nil, why
	}

	for _, h := range hosts {
		p := &plan{host: h, port: int(h.Port)}
		plans = append(plans, p)
		byID[h.ItemID] = p
		if p.port == 0 {
			p.port = 22
		}
		p.problem = d.checkHost(h, ts, pubs, keyProblem, p, warn)
		if p.problem != "" {
			continue
		}
		for _, name := range resolve.Names(h) {
			holder, taken := owner[strings.ToLower(name)]
			switch {
			case !sshconfig.ValidAlias(name):
				warn("host %q: %q is not a valid ssh alias and is skipped", h.Name, name)
			case taken && holder == h.ItemID:
				// The same name listed twice.
			case taken:
				warn("host %q: alias %q is already used by host %q and is skipped", h.Name, name, byID[holder].host.Name)
			default:
				owner[strings.ToLower(name)] = h.ItemID
				p.aliases = append(p.aliases, name)
			}
		}
		if len(p.aliases) == 0 {
			p.problem = "no usable ssh alias (names may use letters, digits, '.', '_' and '-')"
		}
	}

	// A host that jumps through an unusable host is unusable too. Repeat until
	// nothing changes, since the chain can be several hosts long.
	for changed := true; changed; {
		changed = false
		for _, p := range plans {
			if p.problem != "" || p.host.JumpHostID.IsZero() {
				continue
			}
			j := byID[p.host.JumpHostID]
			switch {
			case j == nil:
				release(p, "its jump host does not exist")
			case j.problem != "":
				release(p, fmt.Sprintf("its jump host %q is not usable: %s", j.host.Name, j.problem))
			default:
				continue
			}
			changed = true
		}
	}
	return plans
}

// checkHost fills in p's connection details and returns the reason the host
// cannot go in the ssh config, or "".
func (d *Daemon) checkHost(h model.Host, ts *tailscale.Status, pubs map[model.ID]ssh.PublicKey, keyProblem map[model.ID]string, p *plan, warn func(string, ...any)) string {
	// A Tailscale SSH host needs no key: Tailscale authenticates the tailnet
	// identity, so its block offers none and the route is forced to the tailnet.
	if _, only := resolve.TailscaleSSHOnly(h); only && h.KeyID.IsZero() {
		p.keyless = true
	} else {
		switch {
		case !h.CredentialID.IsZero() && h.KeyID.IsZero():
			return "password hosts are not supported yet; assign a key"
		case h.KeyID.IsZero():
			return "no key assigned; set one with hop edit " + h.Name + " --key <name>"
		case keyProblem[h.KeyID] != "":
			return keyProblem[h.KeyID]
		}
		pub, ok := pubs[h.KeyID]
		if !ok {
			return "its key is missing from the vault"
		}
		p.pub = pub
	}

	route, err := resolve.ChooseRoute(h, ts)
	if err != nil {
		return err.Error()
	}
	if !sshconfig.ValidHostName(route.Address) {
		return fmt.Sprintf("address %q is not usable in an ssh config", route.Address)
	}
	p.hostName = route.Address
	if h.User != "" && !sshconfig.ValidUser(h.User) {
		return fmt.Sprintf("user %q is not usable in an ssh config", h.User)
	}
	for _, line := range h.HostKeys {
		pin, err := sshkeys.ParsePublic(line)
		if err != nil {
			warn("host %q: ignoring a host key that does not parse: %v", h.Name, err)
			continue
		}
		p.pins = append(p.pins, pin)
	}
	return ""
}
