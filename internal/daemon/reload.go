package daemon

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
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
}

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
// the failure is recorded in the state.
func (d *Daemon) reloadLocked(ctx context.Context) (model.Snapshot, error) {
	snap, err := d.store.Snapshot(ctx)
	if err != nil {
		d.noteError(err)
		return model.Snapshot{}, err
	}
	next, err := d.apply(ctx, snap)
	if err != nil {
		d.noteError(err)
		return model.Snapshot{}, err
	}
	d.state.Store(next)
	return snap, nil
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
// changed since the last reload (another device synced, say).
func (d *Daemon) fresh(ctx context.Context) (model.Snapshot, *state, error) {
	snap, err := d.store.Snapshot(ctx)
	if err != nil {
		return model.Snapshot{}, nil, err
	}
	if cur := d.state.Load(); cur != nil && cur.fingerprint == fingerprint(snap) {
		return snap, cur, nil
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	snap, err = d.reloadLocked(ctx)
	if err != nil {
		return model.Snapshot{}, nil, err
	}
	return snap, d.state.Load(), nil
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
	pins     []ssh.PublicKey
	aliases  []string // the Host blocks it gets; the first is the primary
	problem  string   // why the host gets none
}

// apply builds the keyring and ssh config from snap and installs them.
func (d *Daemon) apply(ctx context.Context, snap model.Snapshot) (*state, error) {
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
				ProxyJump: jump, PublicKey: p.pub, HostKeys: p.pins,
			})
		}
	}
	err := sshconfig.Write(sshconfig.Options{Dir: d.opts.Paths.ConfigDir, AgentSocket: d.agent.Path()}, hosts)
	if err != nil {
		return nil, fmt.Errorf("writing the ssh config: %w", err)
	}

	slices.Sort(st.warnings)
	old := d.live.swap(kr)
	old.RemoveAll() // best effort: drop the old key material
	return st, nil
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
