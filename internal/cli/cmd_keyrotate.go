package cli

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"text/tabwriter"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"

	"github.com/dalyem/hopkey/internal/daemon"
	"github.com/dalyem/hopkey/internal/model"
	"github.com/dalyem/hopkey/internal/shellcmd"
	"github.com/dalyem/hopkey/internal/sshagent"
	"github.com/dalyem/hopkey/internal/sshkeys"
)

// ---- hop key rotate ----
//
// hop key rotate replaces a key on every host that uses it, over the access
// hop still has: a new key goes into the vault, then for each host, in
// turn, hop logs in with the old key the normal way (pinned host key, jump
// hosts), adds the new public key to ~/.ssh/authorized_keys with the old
// line's options, logs in again offering only the new key, and only then
// removes the old key's lines and points the host at the new key. A host
// where any step fails is put back as it was and keeps the old key. A host
// hop cannot put back, or cannot tell the state of, needs attention: both
// keys stay in the vault, and the report names the command that finishes
// it.
//
// The checks that log in with one key (the new key works, the old one is
// refused) run ssh on a config of their own, which offers that key alone
// from an agent that holds it alone. The new private key is made in this
// process. It goes to the daemon as hop key add sends a key, and to ssh
// only through an agent this process serves on a socket in hop's private
// run directory for the length of the run. No private key is written to a
// file.

// Host results in the report.
const (
	rotRotated   = "rotated"
	rotAlready   = "already-rotated" // the server took the new key through another record
	rotFailed    = "failed"          // put back as it was: the host keeps the old key
	rotAttention = "needs-attention" // see RotateHost.Fix
	rotSkipped   = "skipped"
	rotPlanned   = "planned" // --dry-run, and the plan before a run
)

// RotateHost is one host in hop key rotate's report.
type RotateHost struct {
	Host   string `json:"host"`
	HostID string `json:"host_id"`
	Status string `json:"status"`
	// Reason says why a host was skipped or failed.
	Reason string `json:"reason,omitempty"`
	// RemoteState is where the host's authorized_keys stands after the
	// run, for a host hop started on: unchanged, new_key_added,
	// old_key_removed or unknown.
	RemoteState string `json:"remote_state,omitempty"`
	// Fix, on a host that needs attention, is the command that finishes
	// it: a run that reuses the new key and finds out what the host takes.
	Fix string `json:"fix,omitempty"`
}

// RotateKey is one key in hop key rotate's report.
type RotateKey struct {
	Key         string `json:"key"`
	KeyID       string `json:"key_id"`
	Fingerprint string `json:"fingerprint"`
	// Skipped says why the key was left alone as a whole.
	Skipped        string `json:"skipped,omitempty"`
	NewKey         string `json:"new_key,omitempty"`
	NewKeyType     string `json:"new_key_type,omitempty"`
	NewKeyID       string `json:"new_key_id,omitempty"`
	NewFingerprint string `json:"new_fingerprint,omitempty"`
	// NewKeyRemoved: no host took the new key, so it was deleted again.
	NewKeyRemoved bool `json:"new_key_removed,omitempty"`
	// OldKey is what happened to the old key in the vault: "deleted" or
	// "kept", with OldKeyReason. Empty for a plan.
	OldKey       string       `json:"old_key,omitempty"`
	OldKeyReason string       `json:"old_key_reason,omitempty"`
	Hosts        []RotateHost `json:"hosts"`
}

// RotateResult is the --json shape of hop key rotate.
type RotateResult struct {
	DryRun bool `json:"dry_run"`
	// OK is false when a host failed, needs attention or has a warning.
	OK   bool        `json:"ok"`
	Keys []RotateKey `json:"keys"`
}

type rotateOpts struct {
	all, dryRun, yes, keepOld, asJSON bool
	hosts                             []string
	keyType                           string // as model.Key.KeyType; "" keeps each key's type
	newKey                            string // a vault key to use as the new key, instead of making one
}

// rotHost is a host in a plan.
type rotHost struct {
	host model.Host
	t    *target // nil when skipped
	// jump is the ssh alias of the host's jump host, "" for none.
	jump string
	// ident is the record's connection as planned (connIdentity), and
	// chain the versions and connections of the record and of each jump
	// host on its way (hostChain): hop points the host at the new key only
	// while they still hold.
	ident string
	chain []daemon.ItemVersion
	out   *RotateHost
	// state is where the host's authorized_keys stands (remUnchanged and
	// so on) once hop has started on it, and "" before.
	state string
}

// rotPlan is the plan for one key.
type rotPlan struct {
	key     daemon.KeyInfo
	keyID   model.ID
	oldPub  ssh.PublicKey
	newType string
	newName string
	// reuse is the vault key --new-key names, with its public key: the new
	// key, instead of one made by this run.
	reuse  *daemon.KeyInfo
	newPub ssh.PublicKey
	hosts  []*rotHost
	out    *RotateKey
}

func (p *rotPlan) runnable() []*rotHost {
	var out []*rotHost
	for _, h := range p.hosts {
		if h.t != nil {
			out = append(out, h)
		}
	}
	return out
}

// rotateStepTimeout bounds each ssh run of a rotation. A variable, so a
// test can shorten it.
var rotateStepTimeout = 30 * time.Second

func runKeyRotate(ctx context.Context, e *Env, args []string) error {
	fs := newFlags(e, "key rotate", "hop key rotate <key> | --all [--hosts h1,h2] [--type ed25519|ecdsa|rsa] [--new-key K] [--dry-run] [--yes] [--keep-old] [--json]")
	var o rotateOpts
	fs.BoolVar(&o.all, "all", false, "rotate every key in the vault")
	hosts := fs.String("hosts", "", "only these hosts, by name, comma-separated")
	typ := fs.String("type", "", "type of the new key: ed25519, ecdsa or rsa (default: the old key's type)")
	fs.BoolVar(&o.dryRun, "dry-run", false, "show the plan and change nothing")
	fs.BoolVar(&o.yes, "yes", false, "do not ask")
	fs.BoolVar(&o.keepOld, "keep-old", false, "keep the old key in the vault even when no host uses it any more")
	fs.BoolVar(&o.asJSON, "json", false, "print the result as JSON")
	fs.StringVar(&o.newKey, "new-key", "", "use this vault key as the new key instead of making one (finishes a host that needs attention)")
	pos, _, err := parseFlags(fs, args)
	if err != nil {
		return err
	}
	switch {
	case o.all && len(pos) > 0:
		fs.Usage()
		return failf("name one key or pass --all, not both")
	case !o.all && len(pos) != 1:
		fs.Usage()
		return failf("expected one key name, or --all")
	case o.newKey != "" && o.all:
		return failf("--new-key goes with one key, not --all")
	case o.newKey != "" && *typ != "":
		return failf("--new-key uses that key's type; leave out --type")
	}
	switch *typ {
	case "":
	case "ed25519", "rsa", "ecdsa-p256":
		o.keyType = *typ
	case "ecdsa":
		o.keyType = "ecdsa-p256"
	default:
		return failf("unknown key type %q (ed25519, ecdsa or rsa)", *typ)
	}
	for _, h := range strings.Split(*hosts, ",") {
		if h = strings.TrimSpace(h); h != "" {
			o.hosts = append(o.hosts, h)
		}
	}

	l, err := listAll(ctx, e)
	if err != nil {
		return err
	}
	plans, err := e.planRotation(ctx, l, pos, &o)
	if err != nil {
		return err
	}
	res := &RotateResult{DryRun: o.dryRun, OK: true}
	for _, p := range plans {
		res.Keys = append(res.Keys, *p.out)
	}
	work := 0
	for _, p := range plans {
		work += len(p.runnable())
	}

	if o.dryRun || work == 0 {
		if o.asJSON {
			return printJSON(e, res)
		}
		printRotatePlan(e.Stdout, plans, &o)
		return nil
	}
	if !o.yes {
		if !e.StdinTTY {
			if o.asJSON {
				if err := printJSON(e, res); err != nil {
					return err
				}
			} else {
				printRotatePlan(e.Stdout, plans, &o)
			}
			return failf("hop key rotate changes authorized_keys on %d host(s) and needs confirmation, but stdin is not a terminal; pass --yes (or --dry-run to only see the plan)", work)
		}
		w := e.Stdout
		if o.asJSON {
			w = e.Stderr // stdout keeps its one JSON result
		}
		printRotatePlan(w, plans, &o)
		ok, err := confirmCtx(ctx, e, safef("Rotate %d key(s) on %d host(s)?", countKeys(plans), work))
		if err != nil {
			return err
		}
		if !ok {
			return failf("nothing was rotated")
		}
	}

	// From here a signal lets the rotation finish the host it is on, also
	// when it runs inside another command (watchInterrupt).
	defer e.beginRotation()()
	res.Keys = nil
	for _, p := range plans {
		if p.out.Skipped == "" && len(p.runnable()) > 0 {
			if ctx.Err() != nil {
				for _, h := range p.runnable() {
					h.out.Status, h.out.Reason = rotSkipped, "interrupted before this host was started"
				}
			} else {
				e.rotateKey(ctx, p, &o)
			}
		}
		for _, h := range p.hosts {
			if h.out.Status == rotFailed || h.out.Status == rotAttention {
				res.OK = false
			}
		}
		p.out.Hosts = hostResults(p.hosts)
		res.Keys = append(res.Keys, *p.out)
	}
	if o.asJSON {
		if err := printJSON(e, res); err != nil {
			return err
		}
	} else {
		printRotateResult(e, res)
	}
	if !res.OK {
		return silent(ExitFailure)
	}
	return nil
}

func countKeys(plans []*rotPlan) int {
	n := 0
	for _, p := range plans {
		if len(p.runnable()) > 0 {
			n++
		}
	}
	return n
}

// confirmCtx is confirm that gives up when ctx is cancelled: hop key rotate
// handles a signal itself, so a prompt must not outlive one.
func confirmCtx(ctx context.Context, e *Env, question string) (bool, error) {
	type answer struct {
		ok  bool
		err error
	}
	ch := make(chan answer, 1)
	go func() {
		ok, err := confirm(e, false, question)
		ch <- answer{ok, err}
	}()
	select {
	case a := <-ch:
		return a.ok, a.err
	case <-ctx.Done():
		fmt.Fprintln(e.Stderr)
		return false, failf("interrupted; nothing was rotated")
	}
}

func hostResults(hosts []*rotHost) []RotateHost {
	out := make([]RotateHost, 0, len(hosts))
	for _, h := range hosts {
		out = append(out, *h.out)
	}
	return out
}

// planRotation picks the keys and hosts and checks that hop can reach each
// host.
func (e *Env) planRotation(ctx context.Context, l *daemon.ListResult, pos []string, o *rotateOpts) ([]*rotPlan, error) {
	var keys []daemon.KeyInfo
	if o.all {
		keys = slices.Clone(l.Keys)
		slices.SortFunc(keys, func(a, b daemon.KeyInfo) int {
			return strings.Compare(strings.ToLower(a.Name), strings.ToLower(b.Name))
		})
	} else {
		id, err := findKey(l, pos[0])
		if err != nil {
			return nil, err
		}
		for _, k := range l.Keys {
			if k.ID == id.String() {
				keys = append(keys, k)
			}
		}
	}

	var reuse *daemon.KeyInfo
	var reusePub ssh.PublicKey
	if o.newKey != "" {
		id, err := findKey(l, o.newKey)
		if err != nil {
			return nil, err
		}
		i := slices.IndexFunc(l.Keys, func(k daemon.KeyInfo) bool { return k.ID == id.String() })
		reuse = &l.Keys[i]
		switch {
		case reuse.ID == keys[0].ID:
			return nil, failf("--new-key names the key being rotated")
		case reuse.DedicatedGrant != "":
			return nil, failf("key %s is a token grant's dedicated key", reuse.Name)
		}
		if reusePub, err = sshkeys.ParsePublic(reuse.PublicKey); err != nil {
			return nil, failf("key %s: its public key does not parse: %v", reuse.Name, err)
		}
	}

	// --hosts names vault hosts that use one of the keys.
	only := map[model.ID]bool{}
	for _, name := range o.hosts {
		var found *model.Host
		for i, h := range l.Hosts {
			if strings.EqualFold(h.Name, name) {
				found = &l.Hosts[i]
			}
		}
		if found == nil {
			return nil, failf("no host named %q in the vault", name)
		}
		// With --new-key, a host already on that key is finished: hop checks
		// that the old key is gone from it.
		onNew := reuse != nil && found.KeyID.String() == reuse.ID
		if !onNew && !slices.ContainsFunc(keys, func(k daemon.KeyInfo) bool { return k.ID == found.KeyID.String() }) {
			if o.all {
				return nil, failf("host %s does not log in with a key", found.Name)
			}
			return nil, failf("host %s does not use key %s", found.Name, keys[0].Name)
		}
		only[found.ItemID] = true
	}

	names := map[string]bool{}
	for _, k := range l.Keys {
		names[strings.ToLower(k.Name)] = true
	}
	var plans []*rotPlan
	for _, k := range keys {
		id, err := model.ParseID(k.ID)
		if err != nil {
			return nil, failf("%v", err)
		}
		p := &rotPlan{key: k, keyID: id}
		p.out = &RotateKey{Key: k.Name, KeyID: k.ID, Fingerprint: k.Fingerprint, Hosts: []RotateHost{}}
		plans = append(plans, p)
		for _, h := range l.Hosts {
			onNew := reuse != nil && h.KeyID.String() == reuse.ID && only[h.ItemID]
			if (h.KeyID == id || onNew) && (len(only) == 0 || only[h.ItemID]) {
				p.hosts = append(p.hosts, &rotHost{host: h, out: &RotateHost{Host: h.Name, HostID: h.ItemID.String()}})
			}
		}
		slices.SortFunc(p.hosts, func(a, b *rotHost) int { return strings.Compare(a.host.Name, b.host.Name) })

		switch {
		case k.DedicatedGrant != "":
			p.out.Skipped = "it is a token grant's dedicated key; reissue the grant instead"
		case len(p.hosts) == 0:
			p.out.Skipped = "no host uses it"
		}
		if p.out.Skipped == "" {
			if p.oldPub, err = sshkeys.ParsePublic(k.PublicKey); err != nil {
				p.out.Skipped = safef("its public key does not parse: %v", err)
			}
		}
		if p.out.Skipped != "" {
			if !o.all && k.DedicatedGrant != "" {
				return nil, failf("key %s: %s", k.Name, p.out.Skipped)
			}
			for _, h := range p.hosts {
				h.out.Status, h.out.Reason = rotSkipped, p.out.Skipped
			}
			p.out.Hosts = hostResults(p.hosts)
			continue
		}

		if reuse != nil {
			p.reuse, p.newPub, p.newType, p.newName = reuse, reusePub, reuse.KeyType, reuse.Name
		} else {
			p.newType = o.keyType
			if p.newType == "" {
				p.newType = k.KeyType
			}
			p.newName = rotatedName(k.Name, e.now(), names)
			names[strings.ToLower(p.newName)] = true
		}
		p.out.NewKey, p.out.NewKeyType = p.newName, p.newType

		for _, h := range p.hosts {
			t, jump, why := e.rotateReach(ctx, h.host, l)
			if why != "" {
				h.out.Status, h.out.Reason = rotSkipped, why
				continue
			}
			h.t, h.jump, h.out.Status = t, jump, rotPlanned
			h.ident, h.chain = connIdentity(h.host, l.Hosts), hostChain(h.host, l.Hosts)
		}
		p.out.Hosts = hostResults(p.hosts)
	}
	return plans, nil
}

var rotatedSuffix = regexp.MustCompile(`-rotated-\d{4}-\d{2}-\d{2}(-\d+)?$`)

// rotatedName names the new key after the old one and the day:
// deploy-rotated-2026-10-28, with a counter if that is taken. A name that
// already ends in such a suffix has it replaced, so names do not grow.
func rotatedName(old string, now time.Time, taken map[string]bool) string {
	base := rotatedSuffix.ReplaceAllString(old, "") + "-rotated-" + now.UTC().Format("2006-01-02")
	name := base
	for n := 2; taken[strings.ToLower(name)]; n++ {
		name = fmt.Sprintf("%s-%d", base, n)
	}
	return name
}

// rotateReach says why hop cannot log in to h to rotate its key, or
// returns what ssh needs to: the target, and the ssh alias of its jump
// host ("" for none).
func (e *Env) rotateReach(ctx context.Context, h model.Host, l *daemon.ListResult) (t *target, jump, why string) {
	t, why = e.reach(ctx, h, l)
	if why == "" && !h.JumpHostID.IsZero() {
		if jump = l.SSH[h.JumpHostID.String()].Alias; jump == "" {
			why = "its jump host is not in the ssh config"
		}
	}
	return t, jump, why
}

func (e *Env) reach(ctx context.Context, h model.Host, l *daemon.ListResult) (*target, string) {
	if s := l.SSH[h.ItemID.String()]; s.Alias == "" {
		return nil, safef("it is not in the ssh config: %s", orUnknown(s.Problem))
	}
	if pins, _ := parsePins(h.HostKeys); len(pins) == 0 {
		return nil, safef("no host key is pinned, so hop cannot log in safely; pin it first with: hop trust %s", h.Name)
	}
	seen := map[model.ID]bool{h.ItemID: true}
	for cur := h; !cur.JumpHostID.IsZero(); {
		i := slices.IndexFunc(l.Hosts, func(j model.Host) bool { return j.ItemID == cur.JumpHostID })
		if i < 0 {
			return nil, "its jump host is missing from the vault"
		}
		j := l.Hosts[i]
		if seen[j.ItemID] {
			return nil, "its chain of jump hosts loops"
		}
		seen[j.ItemID] = true
		if pins, _ := parsePins(j.HostKeys); len(pins) == 0 {
			return nil, safef("its jump host %s has no pinned host key; pin it first with: hop trust %s", j.Name, j.Name)
		}
		cur = j
	}
	rr, err := resolveTarget(ctx, e, h.Name, false)
	if err != nil {
		return nil, err.Error() // composed by failf: already display-safe
	}
	if rr.Host == nil || rr.Host.ItemID != h.ItemID {
		return nil, safef("the name %s does not resolve to this host", h.Name)
	}
	if rr.Route != nil && rr.Route.TailscaleSSH {
		return nil, "it is reached through Tailscale SSH, which does not use the key"
	}
	t, err := connectable(rr)
	if err != nil {
		return nil, err.Error() // composed by failf/failMsg: already display-safe
	}
	return t, ""
}

func printRotatePlan(w io.Writer, plans []*rotPlan, o *rotateOpts) {
	for _, p := range plans {
		if p.out.Skipped != "" {
			fmt.Fprintf(w, "key %s: skipped, %s\n", oneLine(p.key.Name), oneLine(p.out.Skipped))
			continue
		}
		if p.reuse != nil {
			fmt.Fprintf(w, "key %s (%s %s) -> existing key %s\n", oneLine(p.key.Name), oneLine(p.key.KeyType), oneLine(p.key.Fingerprint), oneLine(p.newName))
		} else {
			fmt.Fprintf(w, "key %s (%s %s) -> new %s key %s\n", oneLine(p.key.Name), oneLine(p.key.KeyType), oneLine(p.key.Fingerprint), oneLine(p.newType), oneLine(p.newName))
		}
		tw := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
		for _, h := range p.hosts {
			detail := "rotate"
			if h.out.Status == rotSkipped {
				detail = "skip: " + oneLine(h.out.Reason)
			}
			fmt.Fprintf(tw, "  %s\t%s\n", oneLine(h.host.Name), detail)
		}
		tw.Flush()
		switch {
		case o.keepOld:
			fmt.Fprintf(w, "  the old key stays in the vault (--keep-old)\n")
		case len(p.runnable()) < len(p.hosts):
			fmt.Fprintf(w, "  the old key stays in the vault: the skipped hosts still use it\n")
		default:
			fmt.Fprintf(w, "  the old key is deleted from the vault once every host has the new one\n")
		}
	}
	fmt.Fprintf(w, "On each host hop logs in with the old key, adds the new key to %s with the old line's options,\n"+
		"logs in offering only the new key, and only then removes the old key's lines and points the host at the new key.\n"+
		"A host where a step fails is put back as it was and keeps the old key. If hop cannot put a host back, or cannot tell\n"+
		"which key it takes, both keys stay in the vault and hop names the command that finishes it.\n", akFile)
	if o.dryRun {
		fmt.Fprintf(w, "Dry run: nothing was changed.\n")
	}
}

func printRotateResult(e *Env, res *RotateResult) {
	tw := tabwriter.NewWriter(e.Stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "KEY\tHOST\tRESULT\tDETAIL")
	for _, k := range res.Keys {
		for _, h := range k.Hosts {
			detail := h.Reason
			switch h.Status {
			case rotRotated, rotAlready:
				detail = "now uses " + k.NewKey
				if h.Status == rotAlready {
					detail += "; " + h.Reason
				}
			case rotAttention:
				if h.Fix != "" {
					detail += "; to finish, run: " + h.Fix
				}
			}
			fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n", oneLine(k.Key), oneLine(h.Host), h.Status, dash(oneLine(detail)))
		}
	}
	tw.Flush()
	for _, k := range res.Keys {
		switch {
		case k.Skipped != "":
			e.printf("key %s: skipped, %s\n", oneLine(k.Key), oneLine(k.Skipped))
			continue
		case k.NewKeyID == "":
			continue
		case k.NewKeyRemoved:
			e.printf("key %s: no host took the new key, so it was removed from the vault again\n", oneLine(k.Key))
		default:
			e.printf("key %s: new key %s (%s %s) is in the vault\n", oneLine(k.Key), oneLine(k.NewKey), oneLine(k.NewKeyType), oneLine(k.NewFingerprint))
		}
		switch k.OldKey {
		case "deleted":
			e.printf("key %s: deleted from the vault\n", oneLine(k.Key))
		case "kept":
			e.printf("key %s: kept in the vault: %s\n", oneLine(k.Key), oneLine(k.OldKeyReason))
		}
	}
}

// generateKey makes a new private key of a model.Key.KeyType.
func generateKey(typ string) (*sshkeys.Private, error) {
	var raw any
	var err error
	switch typ {
	case "ed25519":
		_, raw, err = ed25519.GenerateKey(rand.Reader)
	case "ecdsa-p256":
		raw, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	case "rsa":
		raw, err = rsa.GenerateKey(rand.Reader, 3072)
	default:
		return nil, fmt.Errorf("cannot make a %s key", typ)
	}
	if err != nil {
		return nil, err
	}
	signer, err := ssh.NewSignerFromKey(raw)
	if err != nil {
		return nil, err
	}
	return &sshkeys.Private{Raw: raw, Public: signer.PublicKey(), Type: typ}, nil
}

// rotateKey carries out one key's plan and fills in its report.
func (e *Env) rotateKey(ctx context.Context, p *rotPlan, o *rotateOpts) {
	hosts := p.runnable()
	fail := func(why string) {
		for _, h := range hosts {
			h.out.Status, h.out.Reason = rotFailed, why
		}
	}
	k := &rotKeys{oldPub: p.oldPub, oldName: p.key.Name, newName: p.newName}
	var priv *sshkeys.Private
	if p.reuse != nil {
		k.newPub = p.newPub
		k.newID, _ = model.ParseID(p.reuse.ID)
		p.out.NewKeyID, p.out.NewFingerprint = p.reuse.ID, p.reuse.Fingerprint
	} else {
		var err error
		if priv, err = generateKey(p.newType); err != nil {
			fail(safef("could not make the new key: %v", err))
			return
		}
		pem, err := priv.MarshalPrivate(p.newName)
		if err != nil {
			fail(safef("could not encode the new key: %v", err))
			return
		}
		// The new key is in the vault before any host has it, so a host
		// that ends up with only the new key never depends on this process.
		info, err := putKey(ctx, e, o.asJSON, p.newName, pem)
		if err != nil {
			fail(safef("could not add the new key to the vault: %v", err))
			return
		}
		k.newPub = priv.Public
		k.newID, _ = model.ParseID(info.ID)
		p.out.NewKeyID, p.out.NewFingerprint = info.ID, info.Fingerprint
	}

	run, err := e.startRotateRun(k, priv)
	if err != nil {
		fail(safef("could not start the agents for the ssh checks: %v", err))
	} else {
		k.run = run
		stamp := "hop-rotated " + e.now().UTC().Format("2006-01-02")
		for _, h := range hosts {
			if ctx.Err() != nil {
				h.out.Status, h.out.Reason = rotSkipped, "interrupted before this host was started"
				continue
			}
			// A host is finished or put back once started: a signal stops
			// the run between hosts, not in the middle of one.
			e.rotateHost(context.WithoutCancel(ctx), h, k, stamp, o.asJSON)
		}
		run.close()
	}

	// The vault: the new key goes again only when every host hop started on
	// is known to be as it was, so no server can depend on it, and the old
	// one goes once nothing uses it.
	needed := slices.ContainsFunc(hosts, func(h *rotHost) bool {
		return (h.state != "" && h.state != remUnchanged) || h.out.Status == rotAttention
	})
	vctx := context.WithoutCancel(ctx)
	if p.reuse == nil && !needed {
		if err := callChange(vctx, e, o.asJSON, daemon.OpDelete, daemon.DeleteParams{ID: p.out.NewKeyID}, nil); err != nil {
			warn(e, o.asJSON, safef("no host took the new key %s, but it could not be removed from the vault: %v", p.newName, err))
		} else {
			p.out.NewKeyRemoved = true
		}
	}
	p.out.OldKey, p.out.OldKeyReason = e.retireOldKey(vctx, p, o)
}

// retireOldKey deletes the old key from the vault unless --keep-old, a
// host needs attention, or a host still uses it.
func (e *Env) retireOldKey(ctx context.Context, p *rotPlan, o *rotateOpts) (state, reason string) {
	if o.keepOld {
		return "kept", "--keep-old"
	}
	if slices.ContainsFunc(p.hosts, func(h *rotHost) bool { return h.out.Status == rotAttention }) {
		return "kept", "a host needs attention"
	}
	l, err := listAll(ctx, e)
	if err != nil {
		return "kept", safef("could not check which hosts still use it: %v", err)
	}
	var using []string
	for _, h := range l.Hosts {
		if h.KeyID == p.keyID {
			using = append(using, h.Name)
		}
	}
	if len(using) > 0 {
		slices.Sort(using)
		return "kept", "still used by " + joinOne(using, ", ")
	}
	if err := callChange(ctx, e, o.asJSON, daemon.OpDelete, daemon.DeleteParams{ID: p.key.ID}, nil); err != nil {
		return "kept", safef("could not delete it: %v", err)
	}
	return "deleted", ""
}

// rotKeys is what every host of one key's rotation shares.
type rotKeys struct {
	oldPub, newPub   ssh.PublicKey
	oldName, newName string
	newID            model.ID
	run              *rotateRun
}

// rotWays are the three ways rotateHost reaches a host: old, as hop always
// logs in (the generated config, the old key), and two checks, new and
// oldCheck, that offer one key alone.
type rotWays struct {
	old, new, oldCheck rotSSH
	// For oldRefused: the old key, the user and port oldCheck connects
	// as and to, and the jump host, if any.
	oldPub ssh.PublicKey
	user   string
	port   int
	jump   string
}

func (e *Env) rotWays(h *rotHost, k *rotKeys, addr string) (*rotWays, error) {
	newCfg, err := e.checkConfig(h, addr, k.run.new)
	if err != nil {
		return nil, err
	}
	oldCfg, err := e.checkConfig(h, addr, k.run.old)
	if err != nil {
		return nil, err
	}
	return &rotWays{
		old:      rotSSH{e: e, t: h.t, addr: addr},
		new:      rotSSH{e: e, t: h.t, addr: addr, cfg: newCfg, dir: k.run.dir},
		oldCheck: rotSSH{e: e, t: h.t, addr: addr, cfg: oldCfg, dir: k.run.dir},
		oldPub:   k.oldPub,
		user:     checkUser(h),
		port:     checkPort(h.t.rr.Host),
		jump:     h.jump,
	}, nil
}

// fail records a host that is as it was.
func (h *rotHost) fail(why string) { h.out.Status, h.out.Reason = rotFailed, why }

// remText says what each remote state means for the user.
var remText = map[string]string{
	remUnchanged:  "the server takes the old key, as before",
	remAdded:      "the server takes both keys",
	remOldRemoved: "the server takes only the new key in " + akFile,
	remUnknown:    "hop cannot tell which of the two keys the server takes now",
}

// attention reports a host hop could not finish or put back. Both keys
// stay in the vault, and Fix is the command that finishes the job: it
// reuses the new key, finds out which key the server takes, and carries on
// from there, whether the record still names the old key or already the
// new one.
func (h *rotHost) attention(k *rotKeys, why string) {
	h.out.Status = rotAttention
	h.out.Reason = why + "; " + remText[h.state] + safef("; both keys stay in the vault: %s (old) and %s (new)", k.oldName, k.newName)
	h.out.Fix = rotateFix(k, h.host.Name)
}

func rotateFix(k *rotKeys, host string) string {
	return "hop key rotate " + shellcmd.Quote(k.oldName) + " --hosts " + shellcmd.Quote(host) + " --new-key " + shellcmd.Quote(k.newName)
}

// movedText is remText for the server hop changed, once the record no
// longer reaches it.
var movedText = map[string]string{
	remUnchanged:  "takes the old key, as before",
	remAdded:      "takes both keys",
	remOldRemoved: "takes only the new key",
	remUnknown:    "may take either key: hop cannot tell",
}

// moved reports a host whose record changed while its key was rotated, so
// that it may no longer reach the server hop changed. hop leaves the record
// alone, and the way to finish fits the record as it is now.
func (h *rotHost) moved(k *rotKeys, m *hostMovedError) {
	h.out.Status = rotAttention
	h.out.Reason = "the host's record changed while its key was rotated (on another device, or by another command), so hop left the record alone" +
		safef("; the server hop checked (%s@%s port %d, as the record was then) %s", h.host.User, strings.Join(h.host.Addresses, ","), h.host.Port, movedText[h.state])
	h.out.Fix = ""
	switch {
	case m.fresh == nil:
		h.out.Reason += "; the record was deleted"
	case m.fresh.KeyID == k.newID:
		// --new-key takes a host already on the new key, and only checks
		// that the old key is gone from the server the record reaches now.
		h.out.Reason += "; the record already names the new key"
		h.out.Fix = rotateFix(k, m.fresh.Name)
	case m.fresh.KeyID == h.host.KeyID:
		h.out.Reason += "; the record still names the old key"
		h.out.Fix = rotateFix(k, m.fresh.Name)
	default:
		h.out.Reason += "; the record no longer uses either key"
	}
	h.out.Reason += safef("; both keys stay in the vault: %s (old) and %s (new)", k.oldName, k.newName)
}

// rotateHost rotates one host and records the result in h.out, and where
// the host's authorized_keys stands in h.state.
func (e *Env) rotateHost(ctx context.Context, h *rotHost, k *rotKeys, stamp string, asJSON bool) {
	defer func() { h.out.RemoteState = h.state }()
	addr, _ := chooseAddress(ctx, e, h.t)
	w, err := e.rotWays(h, k, addr)
	if err != nil {
		h.fail(safef("could not set up the ssh checks: %v; nothing was changed", err))
		return
	}
	h.state = remUnchanged

	// A host the vault points at the new key already (--new-key, after a
	// host that needed attention): what is left is the old key's lines.
	if h.host.KeyID == k.newID {
		e.finishOnNewKey(ctx, h, k, w, false, asJSON)
		return
	}

	// 1. Read authorized_keys with the old key.
	orig, why, noLogin := w.old.readAK(ctx)
	if why != "" {
		// The server may take the new key already: another record for the
		// same account was rotated first, or an earlier run got that far.
		if noLogin && sshOK(w.new.run(ctx, "true", nil, nil)) {
			e.finishOnNewKey(ctx, h, k, w, true, asJSON)
			return
		}
		h.fail(why + "; nothing was changed")
		return
	}
	ed, err := planAKEdit(orig, k.oldPub, k.newPub, stamp)
	if err != nil {
		h.fail(err.Error())
		return
	}

	// 2. Add the new key's lines.
	if len(ed.added) > 0 {
		switch out, why, _ := w.old.writeAK(ctx, orig, ed.appended); out {
		case akNotDone:
			h.fail(why + "; nothing was changed")
			return
		case akUnknown:
			h.state = remUnknown
			e.putBack(ctx, h, k, w, ed, why)
			return
		}
	}
	h.state = remAdded

	// 3. Log in offering only the new key.
	if res, err := w.new.run(ctx, "true", nil, nil); !sshOK(res, err) {
		e.putBack(ctx, h, k, w, ed, "the new key did not log in ("+sshFailure(res, err)+")")
		return
	}

	// 4. Remove the old key's lines. From here the new key is the way in.
	switch out, why, _ := w.new.writeAK(ctx, ed.appended, ed.final); out {
	case akNotDone:
		e.putBack(ctx, h, k, w, ed, why)
		return
	case akUnknown:
		h.state = remUnknown
		e.putBack(ctx, h, k, w, ed, why)
		return
	}
	h.state = remOldRemoved

	// 5. The old key should now be refused. Unless that is shown, the host
	// needs attention, and the old key stays in the vault.
	problem := w.oldRefused(ctx)

	// 6. Point the host at the new key, which logs in alone.
	if !e.repoint(ctx, h, k, w, ed, asJSON) {
		return
	}
	if problem != "" {
		h.attention(k, "the host now uses the new key, but "+problem)
		return
	}
	h.out.Status, h.out.Reason = rotRotated, ""
}

// finishOnNewKey finishes a host whose server takes the new key already.
// Over the new key alone it removes any line of the old key still in
// authorized_keys, with the same guarded edit, and checks that the old key
// is refused; with repoint it then points the record at the new key, which
// is known to log in. The host is already-rotated only once the old key is
// shown to be refused. Otherwise it needs attention, and the old key stays
// in the vault.
func (e *Env) finishOnNewKey(ctx context.Context, h *rotHost, k *rotKeys, w *rotWays, repoint, asJSON bool) {
	h.state = remUnknown
	problem := w.removeOld(ctx, h, k)
	if problem == "" {
		problem = w.oldRefused(ctx)
	}
	if repoint && !e.repoint(ctx, h, k, w, nil, asJSON) {
		return
	}
	if problem != "" {
		h.attention(k, "the server takes the new key, but "+problem)
		return
	}
	h.out.Status, h.out.Reason = rotAlready, "the server already took the new key, and refuses the old one: another host record for the same account, or an earlier run, got that far"
	if !repoint {
		h.out.Reason = "the host was on the new key already, and the server refuses the old one"
	}
}

// removeOld removes the old key's lines from authorized_keys, over the new
// key alone, and says why it could not, or "". It keeps h.state.
func (w *rotWays) removeOld(ctx context.Context, h *rotHost, k *rotKeys) string {
	cur, why, _ := w.new.readAK(ctx)
	if why != "" {
		return "hop could not read " + akFile + " with the new key (" + why + ")"
	}
	h.state = akState(cur, k.oldPub, k.newPub)
	next, removed := withoutKey(cur, k.oldPub)
	if removed == 0 {
		return ""
	}
	switch out, why, _ := w.new.writeAK(ctx, cur, next); out {
	case akNotDone:
		return "hop could not remove the old key's lines: " + why
	case akUnknown:
		h.state = remUnknown
		return "hop could not remove the old key's lines: " + why
	}
	h.state = akState(next, k.oldPub, k.newPub)
	return ""
}

// oldRefused offers the old key alone and says, unless the server is
// shown to refuse it, what it saw instead. The proof is the ssh client's
// own debug log, in a file of its own: the ProxyCommand's ssh writes to
// stderr, so a jump host's "Permission denied" can't pass for the
// server's. The log counts only once ssh has exited on its own with
// sshAuthFailed, having written its own last line.
func (w *rotWays) oldRefused(ctx context.Context) string {
	f, err := os.CreateTemp(w.oldCheck.dir, "oldcheck-*.log")
	if err != nil {
		return safef("hop could not confirm that the old key is refused (no file for the ssh log: %v)", err)
	}
	logFile := f.Name()
	f.Close()
	defer os.Remove(logFile)
	res, err := w.oldCheck.runOpts(ctx, []string{"-vv", "-E", logFile}, "true", nil, nil)
	switch {
	case sshOK(res, err):
		return "the old key still logs in: the server accepts it from somewhere other than " + akFile + " (AuthorizedKeysFile, authorized_keys2)"
	case err != nil || !res.exited:
		// Cut off or killed, ssh never wrote its own last line: the log may
		// end with one the server sent.
		return "hop could not confirm that the old key is refused (" + sshFailure(res, err) + ")"
	case res.ExitCode != sshAuthFailed:
		return "hop could not confirm that the old key is refused (" + sshFailure(res, nil) + ")"
	}
	log, cut, rerr := readCapped(logFile, sshLogMax)
	if rerr != nil {
		return safef("hop could not confirm that the old key is refused (it could not read the ssh log: %v)", rerr)
	}
	why := oldKeyVerdict(log, cut, ssh.FingerprintSHA256(w.oldPub), w.user, w.oldCheck.addr, w.port)
	if why == "" {
		return ""
	}
	if why == whyNotReached && w.jump != "" {
		why = safef("the check did not get through the jump host %s to the server", w.jump)
	}
	// stderr has the ProxyCommand's errors and the remote's; ssh's own
	// are in the log.
	if strings.TrimSpace(res.Stderr) != "" {
		why += " (" + sshFailure(res, nil) + ")"
	}
	return "hop could not confirm that the old key is refused: " + why
}

// sshLogMax bounds the ssh debug log hop reads.
const sshLogMax = 1 << 20

// readCapped reads up to max bytes of the file name, and says whether
// there was more.
func readCapped(name string, max int64) (string, bool, error) {
	f, err := os.Open(name)
	if err != nil {
		return "", false, err
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, max+1))
	if int64(len(b)) > max {
		return string(b[:max]), true, err
	}
	return string(b), false, err
}

const whyNotReached = "the check did not reach the server"

// oldKeyVerdict reads the -vv log of a login that offered the old key, of
// fingerprint fp, alone to addr:port as user, and returns "" only if it
// shows that server refuse it; otherwise what it shows instead. cut says
// the log was longer than hop read. All of these must hold:
//   - the server's transport came up ("Remote protocol version",
//     "Authenticating to addr:port"),
//   - ssh offered the old key ("Offering public key: ... fp"), and the
//     server never accepted it ("Server accepts key: ... fp"),
//   - the log is whole: not cut, and its last line ends,
//   - nothing after the offer says the server ended the connection itself
//     ("Received disconnect from", "Disconnected from"),
//   - the last line is ssh's own verdict, and the whole of it is
//     "user@addr: Permission denied (methods)." with publickey among the
//     methods: the fatal error ssh ends with once the server has turned
//     down every method it offered.
//
// Server-supplied text reaches the log: the remote software version,
// "Remote: " debug messages, a disconnect's description. ssh passes a
// newline in the last two through, so a server can write a line of its
// own; no line counts for its content alone. A forged verdict is followed
// by ssh's real last line, or preceded by the disconnect that carried it.
//
// These are OpenSSH's debug1 and fatal lines, the same from 8.x to 9.x,
// checked against 9.2p1 (Debian 12) runs and 9.6p1's format strings
// (Ubuntu 24.04): "%s@%s: Permission denied (%s).", unquoted, with the
// host as in "Authenticating to", lower-cased. The refusal comes after
// the key exchange, so from the server whose pinned host key ssh checked;
// the jump host's ssh and the server's banner write to stderr, not to the
// log.
func oldKeyVerdict(log string, cut bool, fp, user, addr string, port int) string {
	var reached, authTo, offered, accepted, signFailed, endedByServer bool
	host := strings.Trim(addr, "[]")
	authPrefix := strings.ToLower(fmt.Sprintf("Authenticating to %s:%d ", host, port))
	last := ""
	for _, l := range strings.Split(log, "\n") {
		l = strings.TrimSpace(l)
		if l == "" {
			continue
		}
		last = l
		if p, rest, ok := strings.Cut(l, ": "); ok && strings.HasPrefix(p, "debug") {
			l = rest
		}
		if strings.HasPrefix(l, "Remote: ") {
			continue // a debug message the server sent
		}
		hasFP := slices.Contains(strings.Fields(l), fp)
		switch {
		case strings.HasPrefix(l, "Remote protocol version "):
			reached = true
		case strings.HasPrefix(strings.ToLower(l), authPrefix):
			authTo = true
		case strings.HasPrefix(l, "Offering public key: ") && hasFP:
			offered = true
		case strings.HasPrefix(l, "Server accepts key: ") && hasFP:
			accepted = true
		case strings.Contains(l, "signing failed") || strings.Contains(l, "no such identity") || strings.HasPrefix(l, "Load key "):
			signFailed = true
		case offered && (strings.HasPrefix(l, "Received disconnect from ") || strings.HasPrefix(l, "Disconnected from ")):
			endedByServer = true
		}
	}
	switch {
	case !reached:
		return whyNotReached
	case !authTo:
		return safef("the ssh log does not show a login to %s port %d", addr, port)
	case accepted && signFailed:
		return "the server still accepts the old key, from somewhere other than " + akFile + " (AuthorizedKeysFile, authorized_keys2); hop could not sign with it, so the login itself failed"
	case accepted:
		return "the server still accepts the old key, from somewhere other than " + akFile + " (AuthorizedKeysFile, authorized_keys2)"
	case !offered:
		return "ssh did not offer the old key (hop's agent could not list it)"
	case cut || !strings.HasSuffix(log, "\n"):
		return "the ssh log is cut short"
	case endedByServer:
		return "the server ended the connection itself after the old key was offered"
	case !sshDenied(last, user, host):
		return "the login ended without the server refusing the old key"
	}
	return ""
}

// sshDenied says whether line is the whole of ssh's verdict when the
// server refused every method: "user@host: Permission denied (methods).",
// with publickey among the methods. ssh writes host lower-cased.
func sshDenied(line, user, host string) bool {
	if user == "" || host == "" {
		return false
	}
	rest, ok := strings.CutPrefix(line, user+"@")
	if !ok || len(rest) < len(host) || !strings.EqualFold(rest[:len(host)], host) {
		return false
	}
	methods, ok := strings.CutPrefix(rest[len(host):], ": Permission denied (")
	if !ok {
		return false
	}
	methods, ok = strings.CutSuffix(methods, ").")
	return ok && slices.Contains(strings.Split(methods, ","), "publickey")
}

// putBack undoes ed on the host after why, and reports the host as failed
// if it is as it was, or as needing attention if not.
func (e *Env) putBack(ctx context.Context, h *rotHost, k *rotKeys, w *rotWays, ed *akEdit, why string) {
	h.state = w.rollback(ctx, ed, h.state)
	if h.state == remUnchanged {
		h.fail(why + "; put back as it was, and it keeps the old key")
		return
	}
	h.attention(k, why+"; hop could not put "+akFile+" back")
}

// repoint points the host's record at the new key once the server takes
// it, and says whether it did. If not, h.out says why. ed is the edit hop
// made, or nil for none. It is undone when the record does not name the
// new key. When the record names the new key now, or hop cannot tell, the
// old key's lines come back beside the new ones instead, so that the key
// the record names logs in.
func (e *Env) repoint(ctx context.Context, h *rotHost, k *rotKeys, w *rotWays, ed *akEdit, asJSON bool) bool {
	err := e.repointHost(ctx, h, k, asJSON)
	if err == nil {
		return true
	}
	var mv *hostMovedError
	switch {
	case errors.As(err, &mv):
		if ed != nil {
			undo := ed
			if mv.fresh != nil && mv.fresh.KeyID == k.newID {
				undo = ed.oldLinesOnly()
			}
			h.state = w.rollback(ctx, undo, h.state)
		}
		h.moved(k, mv)
	case errors.Is(err, errRepointUnknown):
		if ed != nil {
			h.state = w.rollback(ctx, ed.oldLinesOnly(), h.state)
		}
		h.attention(k, safef("the new key works, but hop could not tell whether the vault points the host at it (%v)", err))
	default:
		why := safef("the new key works, but the vault could not point the host at it (%v)", err)
		if ed != nil {
			h.state = w.rollback(ctx, ed, h.state)
		}
		if h.state == remUnchanged {
			h.fail(why + "; put back as it was, and it keeps the old key")
		} else {
			h.attention(k, why)
		}
	}
	return false
}

// hostMovedError: the host's record no longer reaches the server hop
// checked. fresh is the record now, nil when it was deleted.
type hostMovedError struct{ fresh *model.Host }

func (*hostMovedError) Error() string { return "the host's record changed" }

// errRepointUnknown: the write failed, and hop could not read the record
// back to see whether it took effect.
var errRepointUnknown = errors.New("the vault did not answer")

// setHostKey is the daemon's conditional write of a host's key
// (daemon.OpSetHostKey). A variable, so a test can lose its answer.
var setHostKey = func(ctx context.Context, e *Env, asJSON bool, p daemon.SetHostKeyParams) error {
	return callChange(ctx, e, asJSON, daemon.OpSetHostKey, p, nil)
}

// repointHost sets the host's key to the new key in one conditional write:
// the daemon makes it only while the record and every jump host on its way
// are at the versions and connections hop planned with (h.chain), so
// nothing that changes where ssh connects can slip in between. When the
// write fails hop reads the record back:
//   - it names the new key and still reaches the server hop checked
//     (connIdentity): the write went through and only its answer was lost,
//     or another device made the same change. Done.
//   - it no longer reaches that server, or names another key: a
//     *hostMovedError.
//   - it still names the old key and reaches that server: after a version
//     conflict (a description or a tag changed, say) the write is tried once
//     more at the versions just read, which the daemon checks again; any
//     other failure is returned.
//
// When the record cannot be read back, errRepointUnknown.
func (e *Env) repointHost(ctx context.Context, h *rotHost, k *rotKeys, asJSON bool) error {
	chain := h.chain
	for retried := false; ; retried = true {
		err := setHostKey(ctx, e, asJSON, daemon.SetHostKeyParams{HostID: h.host.ItemID.String(), KeyID: k.newID.String(), Chain: chain})
		if err == nil {
			return nil
		}
		l, lerr := listAll(ctx, e)
		if lerr != nil {
			return fmt.Errorf("%w: %v; reading it back: %v", errRepointUnknown, err, lerr)
		}
		i := slices.IndexFunc(l.Hosts, func(x model.Host) bool { return x.ItemID == h.host.ItemID })
		if i < 0 {
			return &hostMovedError{}
		}
		fresh := l.Hosts[i]
		if connIdentity(fresh, l.Hosts) != h.ident {
			return &hostMovedError{fresh: &fresh}
		}
		switch fresh.KeyID {
		case k.newID:
			return nil
		case h.host.KeyID:
		default:
			return &hostMovedError{fresh: &fresh}
		}
		if retried || !daemon.IsCode(err, daemon.CodeChanged) {
			return err
		}
		chain = hostChain(fresh, l.Hosts)
	}
}

// connIdentity is what decides which server a record reaches and how:
// model.ConnString of the record and of each jump host on the way, in
// order.
func connIdentity(h model.Host, hosts []model.Host) string {
	var b strings.Builder
	seen := map[model.ID]bool{}
	for cur := h; ; {
		b.WriteString(model.ConnString(cur) + ";")
		if cur.JumpHostID.IsZero() || seen[cur.JumpHostID] {
			return b.String()
		}
		seen[cur.JumpHostID] = true
		i := slices.IndexFunc(hosts, func(j model.Host) bool { return j.ItemID == cur.JumpHostID })
		if i < 0 {
			return b.String() + "missing " + cur.JumpHostID.String()
		}
		cur = hosts[i]
	}
}

// hostChain is h and each jump host on its way, in order, as
// daemon.OpSetHostKey checks them: each one's version and connection
// (model.ConnDigest; h's with its key). It stops at a jump host that is
// missing or seen before; the daemon refuses such a way.
func hostChain(h model.Host, hosts []model.Host) []daemon.ItemVersion {
	var out []daemon.ItemVersion
	seen := map[model.ID]bool{}
	for cur := h; ; {
		out = append(out, daemon.ItemVersion{ID: cur.ItemID.String(), Version: cur.ItemVersion, Conn: model.ConnDigest(cur, cur.ItemID == h.ItemID)})
		seen[cur.ItemID] = true
		if cur.JumpHostID.IsZero() || seen[cur.JumpHostID] {
			return out
		}
		i := slices.IndexFunc(hosts, func(j model.Host) bool { return j.ItemID == cur.JumpHostID })
		if i < 0 {
			return out
		}
		cur = hosts[i]
	}
}

// rollback undoes ed on the host as far as it can and returns where the
// host stands then. state is where it stood as far as hop knew. It reads
// the file over whichever key logs in, and tries again if the file changed
// under it.
func (w *rotWays) rollback(ctx context.Context, ed *akEdit, state string) string {
	for range 3 {
		cur, way := w.readAny(ctx)
		if way == nil {
			return state
		}
		state = akState(cur, ed.oldPub, ed.newPub)
		next, changed := rollbackAK(cur, ed)
		if !changed {
			return state
		}
		switch out, _, code := way.writeAK(ctx, cur, next); {
		case out == akDone:
			return akState(next, ed.oldPub, ed.newPub)
		case out == akUnknown:
			state = remUnknown
		case code != akExitChanged && code != akExitLocked:
			return state
		}
	}
	return state
}

// readAny reads authorized_keys with the old key, or else with the new one.
func (w *rotWays) readAny(ctx context.Context) ([]byte, *rotSSH) {
	if b, why, _ := w.old.readAK(ctx); why == "" {
		return b, &w.old
	}
	if b, why, _ := w.new.readAK(ctx); why == "" {
		return b, &w.new
	}
	return nil, nil
}

// rotResult is how one ssh run of a rotation ended.
type rotResult struct {
	ExecResult
	// exited says ssh exited on its own, and ExitCode is its exit status.
	// When it did not (cut off at rotateStepTimeout, or killed by a
	// signal), Error says why, and nothing ssh wrote is its answer: its
	// last words may be the server's.
	exited bool
}

// sshAuthFailed is the exit status ssh exits with on its own when it
// fails, a login the server refused among them.
const sshAuthFailed = 255

func sshOK(res rotResult, err error) bool { return err == nil && res.exited && res.ExitCode == 0 }

// sshFailure describes a failed ssh run in a few safe words.
func sshFailure(res rotResult, err error) string {
	if err != nil {
		return err.Error() // composed by failf: already display-safe
	}
	if !res.exited {
		return res.Error
	}
	// When only the new key is offered, ssh may also say that a key file
	// has no private half ("no such identity"), which is the point and not
	// the failure.
	var lines []string
	for _, l := range strings.Split(strings.ReplaceAll(res.Stderr, "\r", ""), "\n") {
		if !strings.HasPrefix(l, "no such identity: ") {
			lines = append(lines, l)
		}
	}
	msg := strings.TrimSpace(strings.Join(lines, "\n"))
	if msg == "" {
		msg = fmt.Sprintf("exit status %d", res.ExitCode)
	}
	return lastLines(msg, 2)
}

// rotSSH runs commands on a host for hop key rotate, on a fresh connection
// every time: no ControlMaster. Without cfg it is hop's normal way in, the
// generated config. With cfg it is a check: ssh reads that config and no
// other (checkConfig).
type rotSSH struct {
	e    *Env
	t    *target
	addr string
	cfg  string // the config of a check
	dir  string // where a check runs ssh
}

// rotCheckAlias is the one Host block of a check's config.
const rotCheckAlias = "hop-rotate-check"

func (r rotSSH) run(ctx context.Context, command string, stdin []byte, stdout io.Writer) (rotResult, error) {
	return r.runOpts(ctx, nil, command, stdin, stdout)
}

// runOpts is run with extra ssh options.
func (r rotSSH) runOpts(ctx context.Context, extra []string, command string, stdin []byte, stdout io.Writer) (rotResult, error) {
	opts := append([]string{"-T", "-o", "ConnectTimeout=10"}, extra...)
	if stdin == nil {
		opts = append(opts, "-n")
	}
	var args []string
	if r.cfg == "" {
		opts = append(opts, "-o", "BatchMode=yes", "-o", "ControlMaster=no", "-o", "ControlPath=none")
		args = append(r.e.sshArgs(r.t, r.addr, opts...), command)
	} else {
		args = append(append([]string{"-F", r.cfg}, opts...), "--", rotCheckAlias, command)
	}
	runCtx, cancel := context.WithTimeout(ctx, rotateStepTimeout)
	defer cancel()
	cmd := exec.CommandContext(runCtx, r.e.sshBinary(), args...)
	cmd.Env = r.e.sshEnviron()
	cmd.Dir = r.dir
	if stdin != nil {
		cmd.Stdin = bytes.NewReader(stdin)
	}
	cmd.WaitDelay = time.Second
	errTail := &tailBuffer{max: tailLimit}
	cmd.Stdout, cmd.Stderr = stdout, errTail
	if stdout == nil {
		cmd.Stdout = io.Discard
	}
	alias := r.t.alias
	if r.cfg != "" {
		alias = rotCheckAlias
	}
	endedWhy, runErr := r.e.runSSH(ctx, cmd, alias, "hop key rotate")
	res := rotResult{ExecResult: ExecResult{Host: r.t.rr.Result.HostName}}
	var ee *exec.ExitError
	switch {
	case runErr == nil, errors.Is(runErr, exec.ErrWaitDelay):
		// ssh exited 0; with ErrWaitDelay something it started still held
		// stderr open.
		res.exited = true
	case errors.Is(runCtx.Err(), context.DeadlineExceeded):
		// Even if ssh exited just before the deadline, hop cannot tell.
		res.ExitCode, res.Error = ExitFailure, fmt.Sprintf("timed out after %s", rotateStepTimeout)
	case errors.As(runErr, &ee):
		res.ExitCode, res.exited = exitCode(ee)
		if !res.exited {
			res.Error = "ssh was stopped (" + ee.Error() + ")"
		}
	default:
		return res, failf("cannot run ssh: %v", runErr)
	}
	if endedWhy != "" && runErr != nil {
		res.Error = endedError(endedWhy)
	}
	res.Stderr = string(errTail.Bytes())
	return res, nil
}

// sh wraps a script so it runs under sh whatever the login shell is.
func sh(script string) string { return "sh -c " + shellcmd.Quote(script) }

// readAK returns authorized_keys, or why it could not, and whether that
// was because ssh did not get in.
func (r rotSSH) readAK(ctx context.Context) (content []byte, why string, noLogin bool) {
	out := &capBuffer{max: akMaxSize}
	res, err := r.run(ctx, sh(akReadScript), nil, out)
	switch {
	case err != nil || !res.exited || res.ExitCode == sshAuthFailed:
		return nil, "could not log in to read " + akFile + " (" + sshFailure(res, err) + ")", true
	case res.ExitCode == akExitMissing:
		return nil, akFile + " does not exist; the server may read authorized keys from somewhere else (AuthorizedKeysFile)", false
	case res.ExitCode != 0:
		return nil, "could not read " + akFile + " (" + sshFailure(res, err) + ")", false
	case out.over:
		return nil, akFile + " is larger than 1 MiB", false
	}
	return out.buf.Bytes(), "", false
}

// akOutcome is how an authorized_keys write ended.
type akOutcome int

const (
	akDone    akOutcome = iota // the new file is in place
	akNotDone                  // the script stopped before the rename: nothing changed
	akUnknown                  // the connection failed or timed out: the rename may have happened
)

// writeAK replaces authorized_keys content from with to. It says how that
// ended, why when it did not end well, and the script's exit status.
func (r rotSSH) writeAK(ctx context.Context, from, to []byte) (akOutcome, string, int) {
	res, err := r.run(ctx, sh(akWriteScript(cksum(from), cksum(to))), to, nil)
	switch {
	case sshOK(res, err):
		return akDone, "", 0
	case err == nil && res.exited && akRefused(res.ExitCode):
		return akNotDone, "could not write " + akFile + " (" + sshFailure(res, err) + ")", res.ExitCode
	}
	return akUnknown, "lost the connection while writing " + akFile + " (" + sshFailure(res, err) + ")", res.ExitCode
}

// capBuffer keeps up to max bytes and notes anything beyond.
type capBuffer struct {
	buf  bytes.Buffer
	max  int
	over bool
}

func (c *capBuffer) Write(p []byte) (int, error) {
	if c.buf.Len()+len(p) > c.max {
		c.over = true
		return len(p), nil
	}
	return c.buf.Write(p)
}

// rotateRun is what the ssh checks of one key's rotation share: a private
// directory under hop's run directory with two agents, each serving one key
// next to its public key file. new serves the key being put in; old serves
// the key being replaced, from the daemon's agent. Nothing secret is
// written: the private keys stay in memory.
type rotateRun struct {
	dir      string
	kr       *sshagent.Keyring // the new key, when this run made it
	new, old *keyAgent
}

// keyAgent is an agent socket and the IdentityFile that selects its key:
// the public key file's path without ".pub", where no private key is.
type keyAgent struct {
	sock, identity string
	srv            *sshagent.Server
	done           chan struct{}
}

func (e *Env) startRotateRun(k *rotKeys, priv *sshkeys.Private) (*rotateRun, error) {
	if err := os.MkdirAll(e.Paths.RunDir, 0o700); err != nil {
		return nil, err
	}
	dir, err := os.MkdirTemp(e.Paths.RunDir, "rotate-")
	if err != nil {
		return nil, err
	}
	r := &rotateRun{dir: dir}
	newAgent := agent.ExtendedAgent(daemonKey{sock: e.Paths.AgentSocket(), pub: k.newPub})
	if priv != nil {
		r.kr = sshagent.NewKeyring()
		if err := r.kr.Add(priv.Raw, k.newName); err != nil {
			r.close()
			return nil, err
		}
		newAgent = r.kr.Agent()
	}
	if r.new, err = serveKeyAgent(filepath.Join(dir, "new"), k.newPub, newAgent); err != nil {
		r.close()
		return nil, err
	}
	if r.old, err = serveKeyAgent(filepath.Join(dir, "old"), k.oldPub, daemonKey{sock: e.Paths.AgentSocket(), pub: k.oldPub}); err != nil {
		r.close()
		return nil, err
	}
	return r, nil
}

// serveKeyAgent serves ag on a socket in a new directory dir, next to the
// public key file of pub.
func serveKeyAgent(dir string, pub ssh.PublicKey, ag agent.ExtendedAgent) (*keyAgent, error) {
	if err := os.Mkdir(dir, 0o700); err != nil {
		return nil, err
	}
	a := &keyAgent{sock: filepath.Join(dir, "agent.sock"), identity: filepath.Join(dir, "key"), done: make(chan struct{})}
	if err := os.WriteFile(a.identity+".pub", ssh.MarshalAuthorizedKey(pub), 0o600); err != nil {
		return nil, err
	}
	srv, err := sshagent.Listen(a.sock, ag)
	if err != nil {
		return nil, err
	}
	a.srv = srv
	go func() {
		defer close(a.done)
		srv.Serve()
	}()
	return a, nil
}

func (a *keyAgent) close() {
	a.srv.Close()
	<-a.done
}

func (r *rotateRun) close() {
	for _, a := range []*keyAgent{r.new, r.old} {
		if a != nil {
			a.close()
		}
	}
	if r.kr != nil {
		r.kr.RemoveAll()
	}
	os.RemoveAll(r.dir)
}

// checkConfig writes the ssh config of a check that offers a's key to h,
// and returns its path. ssh -F reads this file and no other: nothing of
// the generated config applies (OpenSSH adds up IdentityFile lines, so the
// old key's would stay in effect beside the one under test), and nothing
// of the user's. The check reaches the server as hop's config does: the
// same address, port and user, the host's pinned keys and nothing else,
// and its jump host through hop's config, so only the last hop is checked.
func (e *Env) checkConfig(h *rotHost, addr string, a *keyAgent) (string, error) {
	rec := h.t.rr.Host
	alias := strings.ToLower(h.t.alias)
	user := configUser(h)
	port := checkPort(rec)
	for _, v := range []string{addr, alias, user} {
		if strings.ContainsFunc(v, func(r rune) bool { return r <= ' ' || r == 0x7f || strings.ContainsRune(`"\%#'`, r) }) {
			return "", fmt.Errorf("%q cannot go in an ssh config", v)
		}
	}
	base := filepath.Join(filepath.Dir(a.sock), h.host.ItemID.String())
	var kh bytes.Buffer
	pins, _ := parsePins(rec.HostKeys)
	for _, p := range pins {
		fmt.Fprintf(&kh, "%s %s", alias, ssh.MarshalAuthorizedKey(p))
	}
	if err := os.WriteFile(base+".known_hosts", kh.Bytes(), 0o600); err != nil {
		return "", err
	}
	paths := map[string]string{}
	for name, p := range map[string]string{"kh": base + ".known_hosts", "agent": a.sock, "id": a.identity} {
		q, err := sshCfgPath(p)
		if err != nil {
			return "", err
		}
		paths[name] = q
	}

	var c strings.Builder
	fmt.Fprintf(&c, "Host %s\n", rotCheckAlias)
	fmt.Fprintf(&c, "  HostName %s\n  Port %d\n", addr, port)
	if user != "" {
		fmt.Fprintf(&c, "  User %s\n", user)
	}
	fmt.Fprintf(&c, "  HostKeyAlias %s\n  GlobalKnownHostsFile none\n  UserKnownHostsFile %s\n", alias, paths["kh"])
	c.WriteString("  StrictHostKeyChecking yes\n  UpdateHostKeys no\n  FingerprintHash sha256\n")
	fmt.Fprintf(&c, "  IdentityAgent %s\n  IdentityFile none\n  IdentityFile %s\n", paths["agent"], paths["id"])
	c.WriteString("  IdentitiesOnly yes\n  PubkeyAuthentication yes\n  PreferredAuthentications publickey\n" +
		"  PasswordAuthentication no\n  KbdInteractiveAuthentication no\n  GSSAPIAuthentication no\n  HostbasedAuthentication no\n" +
		"  ForwardAgent no\n  ControlMaster no\n  ControlPath none\n  BatchMode yes\n")
	if h.jump != "" {
		// ssh runs it with sh -c "exec ...", after expanding % tokens.
		var cmd []string
		for _, arg := range []string{e.sshBinary(), "-F", e.sshConfigFile(), "-o", "BatchMode=yes", "-o", "ControlMaster=no", "-o", "ControlPath=none", "-W", "%h:%p", "--", h.jump} {
			if arg != "%h:%p" {
				arg = strings.ReplaceAll(shellcmd.Quote(arg), "%", "%%")
			}
			cmd = append(cmd, arg)
		}
		fmt.Fprintf(&c, "  ProxyCommand %s\n", strings.Join(cmd, " "))
	}
	file := base + ".config"
	if err := os.WriteFile(file, []byte(c.String()), 0o600); err != nil {
		return "", err
	}
	return file, nil
}

// checkPort is the port a check connects to.
// configUser is the user a check's config names, "" for none.
func configUser(h *rotHost) string {
	if h.t.user != "" {
		return h.t.user
	}
	return h.t.rr.Host.User
}

// checkUser is the user a check logs in as: the one its config names, or
// else, as ssh does, the local user. "" when hop cannot tell.
func checkUser(h *rotHost) string {
	if u := configUser(h); u != "" {
		return u
	}
	if u, err := user.Current(); err == nil {
		return u.Username
	}
	return ""
}

func checkPort(rec *model.Host) int {
	if rec.Port == 0 {
		return 22
	}
	return int(rec.Port)
}

// sshCfgPath quotes a path for an ssh config, with % doubled. A path that
// has a double quote, a backslash or a control character is refused.
func sshCfgPath(p string) (string, error) {
	if strings.ContainsFunc(p, func(r rune) bool { return r < ' ' || r == 0x7f || r == '"' || r == '\\' }) {
		return "", fmt.Errorf("the path %q cannot go in an ssh config", p)
	}
	return `"` + strings.ReplaceAll(p, "%", "%%") + `"`, nil
}

// daemonKey is one key of the daemon's agent served as an agent of its
// own: it lists that key alone and signs with it alone, so ssh offered it
// sees no other key in the vault.
type daemonKey struct {
	sock string
	pub  ssh.PublicKey
}

var errOneKeyAgent = errors.New("hop: this agent only signs with the key under test")

func (d daemonKey) call(f func(agent.ExtendedAgent) error) error {
	c, err := net.Dial("unix", d.sock)
	if err != nil {
		return err
	}
	defer c.Close()
	return f(agent.NewClient(c))
}

func (d daemonKey) List() ([]*agent.Key, error) {
	var out []*agent.Key
	err := d.call(func(a agent.ExtendedAgent) error {
		keys, err := a.List()
		for _, k := range keys {
			if bytes.Equal(k.Blob, d.pub.Marshal()) {
				out = append(out, k)
			}
		}
		return err
	})
	return out, err
}

func (d daemonKey) Sign(key ssh.PublicKey, data []byte) (*ssh.Signature, error) {
	return d.SignWithFlags(key, data, 0)
}

func (d daemonKey) SignWithFlags(key ssh.PublicKey, data []byte, flags agent.SignatureFlags) (*ssh.Signature, error) {
	if !bytes.Equal(key.Marshal(), d.pub.Marshal()) {
		return nil, errOneKeyAgent
	}
	var sig *ssh.Signature
	err := d.call(func(a agent.ExtendedAgent) error {
		var err error
		sig, err = a.SignWithFlags(key, data, flags)
		return err
	})
	return sig, err
}

func (daemonKey) Signers() ([]ssh.Signer, error)           { return nil, errOneKeyAgent }
func (daemonKey) Add(agent.AddedKey) error                 { return errOneKeyAgent }
func (daemonKey) Remove(ssh.PublicKey) error               { return errOneKeyAgent }
func (daemonKey) RemoveAll() error                         { return errOneKeyAgent }
func (daemonKey) Lock([]byte) error                        { return errOneKeyAgent }
func (daemonKey) Unlock([]byte) error                      { return errOneKeyAgent }
func (daemonKey) Extension(string, []byte) ([]byte, error) { return nil, agent.ErrExtensionUnsupported }

// ---- after hop auth devices revoke ----

// rotateAllCommand is what hop auth devices revoke suggests.
const rotateAllCommand = "hop key rotate --all"

// offerKeyRotation ends hop auth devices revoke's output: the revoked
// device could decrypt every key in the vault, and revoking it does not
// take them back. It names them and the command that replaces them, and on
// a terminal offers to run it. With --json the report's rotate_command
// says it instead.
func offerKeyRotation(ctx context.Context, e *Env, asJSON bool) error {
	if asJSON {
		return nil
	}
	l, err := listAll(ctx, e)
	if err != nil {
		e.printf("That device could decrypt every SSH key in the vault, and revoking it does not take them back. Run `%s` to replace them on your hosts.\n", rotateAllCommand)
		return nil
	}
	if len(l.Keys) == 0 {
		return nil
	}
	names := make([]string, len(l.Keys))
	for i, k := range l.Keys {
		names[i] = k.Name
	}
	slices.SortFunc(names, func(a, b string) int { return strings.Compare(strings.ToLower(a), strings.ToLower(b)) })
	e.printf("That device could decrypt these %d keys: %s. Revoking it does not take them back. Run `%s` to replace them on your hosts.\n",
		len(names), joinOne(names, ", "), rotateAllCommand)
	if !e.StdinTTY {
		return nil
	}
	ok, err := confirmCtx(ctx, e, "Rotate them now?")
	if err != nil || !ok {
		return nil
	}
	return runKeyRotate(ctx, e, []string{"--all", "--yes"})
}
