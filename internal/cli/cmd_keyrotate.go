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
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"text/tabwriter"
	"time"

	"golang.org/x/crypto/ssh"

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
// where any step fails is put back as it was and keeps the old key.
//
// The new private key is made in this process. It goes to the daemon as
// hop key add sends a key, and to ssh only through an agent this process
// serves on a socket in hop's private run directory for the length of the
// run. No private key is written to a file.

// Host results in the report.
const (
	rotRotated = "rotated"
	rotFailed  = "failed"
	rotSkipped = "skipped"
	rotPlanned = "planned" // --dry-run, and the plan before a run
)

// RotateHost is one host in hop key rotate's report.
type RotateHost struct {
	Host   string `json:"host"`
	HostID string `json:"host_id"`
	Status string `json:"status"`
	// Reason says why a host was skipped or failed.
	Reason string `json:"reason,omitempty"`
	// Warning is set on a rotated host when something after the rotation
	// is not as it should be: the old key still logs in, say.
	Warning string `json:"warning,omitempty"`
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
	// OK is false when a host failed or has a warning.
	OK   bool        `json:"ok"`
	Keys []RotateKey `json:"keys"`
}

type rotateOpts struct {
	all, dryRun, yes, keepOld, asJSON bool
	hosts                             []string
	keyType                           string // as model.Key.KeyType; "" keeps each key's type
}

// rotHost is a host in a plan.
type rotHost struct {
	host model.Host
	t    *target // nil when skipped
	out  *RotateHost
	// onlyNew is set when the host was left accepting only the new key
	// while the vault still points it at the old one: the new key must then
	// stay in the vault.
	onlyNew bool
}

// rotPlan is the plan for one key.
type rotPlan struct {
	key     daemon.KeyInfo
	keyID   model.ID
	oldPub  ssh.PublicKey
	newType string
	newName string
	hosts   []*rotHost
	out     *RotateKey
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

// rotateStepTimeout bounds each ssh run of a rotation.
const rotateStepTimeout = 30 * time.Second

func runKeyRotate(ctx context.Context, e *Env, args []string) error {
	fs := newFlags(e, "key rotate", "hop key rotate <key> | --all [--hosts h1,h2] [--type ed25519|ecdsa|rsa] [--dry-run] [--yes] [--keep-old] [--json]")
	var o rotateOpts
	fs.BoolVar(&o.all, "all", false, "rotate every key in the vault")
	hosts := fs.String("hosts", "", "only these hosts, by name, comma-separated")
	typ := fs.String("type", "", "type of the new key: ed25519, ecdsa or rsa (default: the old key's type)")
	fs.BoolVar(&o.dryRun, "dry-run", false, "show the plan and change nothing")
	fs.BoolVar(&o.yes, "yes", false, "do not ask")
	fs.BoolVar(&o.keepOld, "keep-old", false, "keep the old key in the vault even when no host uses it any more")
	fs.BoolVar(&o.asJSON, "json", false, "print the result as JSON")
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
			if h.out.Status == rotFailed || h.out.Warning != "" {
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
		if !slices.ContainsFunc(keys, func(k daemon.KeyInfo) bool { return k.ID == found.KeyID.String() }) {
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
			if h.KeyID == id && (len(only) == 0 || only[h.ItemID]) {
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

		p.newType = o.keyType
		if p.newType == "" {
			p.newType = k.KeyType
		}
		p.newName = rotatedName(k.Name, e.now(), names)
		names[strings.ToLower(p.newName)] = true
		p.out.NewKey, p.out.NewKeyType = p.newName, p.newType

		for _, h := range p.hosts {
			t, why := e.rotateReach(ctx, h.host, l)
			if why != "" {
				h.out.Status, h.out.Reason = rotSkipped, why
				continue
			}
			h.t, h.out.Status = t, rotPlanned
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
// returns what ssh needs to.
func (e *Env) rotateReach(ctx context.Context, h model.Host, l *daemon.ListResult) (*target, string) {
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
		fmt.Fprintf(w, "key %s (%s %s) -> new %s key %s\n", oneLine(p.key.Name), oneLine(p.key.KeyType), oneLine(p.key.Fingerprint), oneLine(p.newType), oneLine(p.newName))
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
		"A host where a step fails is put back as it was and keeps the old key.\n", akFile)
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
			if h.Status == rotRotated {
				detail = "now uses " + k.NewKey
				if h.Warning != "" {
					detail += "; warning: " + h.Warning
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
	priv, err := generateKey(p.newType)
	if err != nil {
		fail(safef("could not make the new key: %v", err))
		return
	}
	pem, err := priv.MarshalPrivate(p.newName)
	if err != nil {
		fail(safef("could not encode the new key: %v", err))
		return
	}
	// The new key is in the vault before any host has it, so a host that
	// ends up with only the new key never depends on this process.
	info, err := putKey(ctx, e, o.asJSON, p.newName, pem)
	if err != nil {
		fail(safef("could not add the new key to the vault: %v", err))
		return
	}
	newID, _ := model.ParseID(info.ID)
	p.out.NewKeyID, p.out.NewFingerprint = info.ID, info.Fingerprint

	ag, err := e.startRotateAgent(priv, p.newName)
	if err != nil {
		fail(safef("could not start the agent for the new key: %v", err))
	} else {
		k := &rotKeys{oldPub: p.oldPub, newPub: priv.Public, newName: p.newName, newID: newID, agent: ag}
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
		ag.close()
	}

	// The vault: the new key stays if any host took it, and the old one
	// goes once nothing uses it.
	took := slices.ContainsFunc(hosts, func(h *rotHost) bool { return h.out.Status == rotRotated || h.onlyNew })
	vctx := context.WithoutCancel(ctx)
	if !took {
		if err := callChange(vctx, e, o.asJSON, daemon.OpDelete, daemon.DeleteParams{ID: info.ID}, nil); err != nil {
			warn(e, o.asJSON, safef("no host took the new key %s, but it could not be removed from the vault: %v", p.newName, err))
		} else {
			p.out.NewKeyRemoved = true
		}
	}
	p.out.OldKey, p.out.OldKeyReason = e.retireOldKey(vctx, p, o)
}

// retireOldKey deletes the old key from the vault unless --keep-old or a
// host still uses it.
func (e *Env) retireOldKey(ctx context.Context, p *rotPlan, o *rotateOpts) (state, reason string) {
	if o.keepOld {
		return "kept", "--keep-old"
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
	oldPub, newPub ssh.PublicKey
	newName        string
	newID          model.ID
	agent          *rotateAgent
}

// rotateHost rotates one host and records the result in h.out.
func (e *Env) rotateHost(ctx context.Context, h *rotHost, k *rotKeys, stamp string, asJSON bool) {
	t := h.t
	addr, _ := chooseAddress(ctx, e, t)
	oldWay := rotSSH{e: e, t: t, addr: addr}
	newWay := rotSSH{e: e, t: t, addr: addr, opts: k.agent.sshOpts()}
	failed := func(why string) { h.out.Status, h.out.Reason = rotFailed, why }

	// 1. Read authorized_keys with the old key.
	orig, why := oldWay.readAK(ctx)
	if why != "" {
		failed(why + "; nothing was changed")
		return
	}
	ed, err := planAKEdit(orig, k.oldPub, k.newPub, stamp)
	if err != nil {
		failed(err.Error())
		return
	}

	// 2. Add the new key's lines.
	if len(ed.added) > 0 {
		if why := oldWay.writeAK(ctx, orig, ed.appended); why != "" {
			failed(why + oldWay.rollback(ctx, ed))
			return
		}
	}

	// 3. Log in offering only the new key.
	res, err := newWay.run(ctx, "true", nil, nil, "PreferredAuthentications=publickey")
	if err != nil || res.ExitCode != 0 || res.Error != "" {
		failed("the new key did not log in (" + sshFailure(res, err) + ")" + oldWay.rollback(ctx, ed))
		return
	}

	// 4. Remove the old key's lines. From here the new key is the way in.
	if why := newWay.writeAK(ctx, ed.appended, ed.final); why != "" {
		failed(why + newWay.rollback(ctx, ed))
		return
	}

	// 5. The old key should now be refused.
	res, err = oldWay.run(ctx, "true", nil, nil, "PreferredAuthentications=publickey")
	switch {
	case err == nil && res.ExitCode == 0 && res.Error == "":
		h.out.Warning = "the old key still logs in: the server accepts it from somewhere other than " + akFile + " (AuthorizedKeysFile, authorized_keys2)"
	case err == nil && strings.Contains(res.Stderr, "Permission denied"):
	default:
		h.out.Warning = "could not confirm that the old key is refused (" + sshFailure(res, err) + ")"
	}

	// 6. Point the host at the new key.
	if err := e.repointHost(ctx, h.host, k.newID, asJSON); err != nil {
		why := safef("the new key works, but the vault could not be updated (%v)", err)
		if back := newWay.rollback(ctx, ed); strings.HasPrefix(back, "; put back") {
			failed(why + back)
		} else {
			h.onlyNew = true
			failed(why + back + safef("; the host now accepts only %s: run hop edit %s --key %s", k.newName, h.host.Name, k.newName))
		}
		return
	}
	h.out.Status, h.out.Reason = rotRotated, ""
}

// repointHost sets h's key to id, retrying once on a fresh copy if the
// host changed meanwhile (a sync, say).
func (e *Env) repointHost(ctx context.Context, h model.Host, id model.ID, asJSON bool) error {
	h.KeyID = id
	_, err := putHost(ctx, e, asJSON, h)
	if err == nil {
		return nil
	}
	l, lerr := listAll(ctx, e)
	if lerr != nil {
		return err
	}
	i := slices.IndexFunc(l.Hosts, func(x model.Host) bool { return x.ItemID == h.ItemID })
	if i < 0 {
		return err
	}
	fresh := l.Hosts[i]
	fresh.KeyID = id
	_, err = putHost(ctx, e, asJSON, fresh)
	return err
}

// sshFailure describes a failed ssh run in a few safe words.
func sshFailure(res ExecResult, err error) string {
	if err != nil {
		return err.Error() // composed by failf: already display-safe
	}
	// When only the new key is offered, ssh also says the old key's
	// identity file has no private half ("no such identity"), which is the
	// point and not the failure.
	var lines []string
	for _, l := range strings.Split(strings.ReplaceAll(res.Stderr, "\r", ""), "\n") {
		if !strings.HasPrefix(l, "no such identity: ") {
			lines = append(lines, l)
		}
	}
	msg := strings.TrimSpace(strings.Join(lines, "\n"))
	if msg == "" {
		msg = res.Error
	}
	if msg == "" {
		msg = fmt.Sprintf("exit status %d", res.ExitCode)
	}
	return lastLines(msg, 2)
}

// rotSSH runs commands on a host for hop key rotate. Without opts it is
// hop's normal way in, the generated config; with the new key's agent
// options it offers that key alone.
type rotSSH struct {
	e    *Env
	t    *target
	addr string
	opts []string
}

// run is runRemote with extra -o options, and a fresh connection every
// time: no ControlMaster.
func (r rotSSH) run(ctx context.Context, command string, stdin []byte, stdout io.Writer, extra ...string) (ExecResult, error) {
	opts := []string{"-T", "-o", "BatchMode=yes", "-o", "ConnectTimeout=10", "-o", "ControlMaster=no", "-o", "ControlPath=none"}
	opts = append(opts, r.opts...)
	for _, x := range extra {
		opts = append(opts, "-o", x)
	}
	if stdin == nil {
		opts = append(opts, "-n")
	}
	args := append(r.e.sshArgs(r.t, r.addr, opts...), command)
	runCtx, cancel := context.WithTimeout(ctx, rotateStepTimeout)
	defer cancel()
	cmd := exec.CommandContext(runCtx, r.e.sshBinary(), args...)
	cmd.Env = r.e.sshEnviron()
	if stdin != nil {
		cmd.Stdin = bytes.NewReader(stdin)
	}
	cmd.WaitDelay = time.Second
	errTail := &tailBuffer{max: tailLimit}
	cmd.Stdout, cmd.Stderr = stdout, errTail
	if stdout == nil {
		cmd.Stdout = io.Discard
	}
	runErr := cmd.Run()
	res := ExecResult{Host: r.t.rr.Result.HostName}
	var ee *exec.ExitError
	switch {
	case runErr == nil:
	case errors.Is(runErr, exec.ErrWaitDelay):
	case errors.Is(runCtx.Err(), context.DeadlineExceeded):
		res.ExitCode, res.Error = ExitFailure, fmt.Sprintf("timed out after %s", rotateStepTimeout)
	case errors.As(runErr, &ee):
		res.ExitCode = exitCode(ee)
	default:
		return res, failf("cannot run ssh: %v", runErr)
	}
	res.Stderr = string(errTail.Bytes())
	return res, nil
}

// sh wraps a script so it runs under sh whatever the login shell is.
func sh(script string) string { return "sh -c " + shellcmd.Quote(script) }

// readAK returns authorized_keys, or why it could not.
func (r rotSSH) readAK(ctx context.Context) ([]byte, string) {
	out := &capBuffer{max: akMaxSize}
	res, err := r.run(ctx, sh(akReadScript), nil, out)
	switch {
	case err != nil || res.ExitCode == ExitFailure || res.Error != "":
		return nil, "could not log in to read " + akFile + " (" + sshFailure(res, err) + ")"
	case res.ExitCode == akExitMissing:
		return nil, akFile + " does not exist; the server may read authorized keys from somewhere else (AuthorizedKeysFile)"
	case res.ExitCode != 0:
		return nil, "could not read " + akFile + " (" + sshFailure(res, err) + ")"
	case out.over:
		return nil, akFile + " is larger than 1 MiB"
	}
	return out.buf.Bytes(), ""
}

// writeAK replaces authorized_keys content from with to, or says why not.
func (r rotSSH) writeAK(ctx context.Context, from, to []byte) string {
	res, err := r.run(ctx, sh(akWriteScript(cksum(from), cksum(to))), to, nil)
	switch {
	case err != nil || res.ExitCode == ExitFailure || res.Error != "":
		return "could not log in to write " + akFile + " (" + sshFailure(res, err) + ")"
	case res.ExitCode != 0:
		return "could not write " + akFile + " (" + sshFailure(res, err) + ")"
	}
	return ""
}

// rollback undoes ed on the host and says how that went, as a clause to
// append to the failure: "; put back as it was" or why not.
func (r rotSSH) rollback(ctx context.Context, ed *akEdit) string {
	for range 2 { // once more if the file changed under the first try
		cur, why := r.readAK(ctx)
		if why != "" {
			return "; could not put " + akFile + " back: " + why
		}
		next, changed := rollbackAK(cur, ed)
		if !changed {
			return "; put back as it was, and it keeps the old key"
		}
		why = r.writeAK(ctx, cur, next)
		if why == "" {
			return "; put back as it was, and it keeps the old key"
		}
		if !strings.Contains(why, "changed while hop was editing it") {
			return "; could not put " + akFile + " back: " + why
		}
	}
	return "; could not put " + akFile + " back: it kept changing"
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

// rotateAgent serves the new key, alone, to the ssh runs that check it.
type rotateAgent struct {
	dir  string
	kr   *sshagent.Keyring
	srv  *sshagent.Server
	done chan struct{}
}

// startRotateAgent serves priv on a socket in a new private directory under
// hop's run directory, next to the public key file ssh's IdentityFile
// names. Nothing secret is written: the private key stays in memory.
func (e *Env) startRotateAgent(priv *sshkeys.Private, name string) (*rotateAgent, error) {
	if err := os.MkdirAll(e.Paths.RunDir, 0o700); err != nil {
		return nil, err
	}
	dir, err := os.MkdirTemp(e.Paths.RunDir, "rotate-")
	if err != nil {
		return nil, err
	}
	a := &rotateAgent{dir: dir, kr: sshagent.NewKeyring(), done: make(chan struct{})}
	if err := os.WriteFile(filepath.Join(dir, "new.pub"), ssh.MarshalAuthorizedKey(priv.Public), 0o600); err != nil {
		os.RemoveAll(dir)
		return nil, err
	}
	if err := a.kr.Add(priv.Raw, name); err != nil {
		os.RemoveAll(dir)
		return nil, err
	}
	if a.srv, err = sshagent.Listen(filepath.Join(dir, "agent.sock"), a.kr.Agent()); err != nil {
		a.kr.RemoveAll()
		os.RemoveAll(dir)
		return nil, err
	}
	go func() {
		defer close(a.done)
		a.srv.Serve()
	}()
	return a, nil
}

// sshOpts makes ssh offer the new key and nothing else: the agent holds
// only that key, and IdentitiesOnly limits ssh to the identity files, whose
// other entry (the old key's, from the generated config) has no private
// half on disk to sign with.
func (a *rotateAgent) sshOpts() []string {
	return []string{
		"-o", "IdentityAgent=" + sshOptPath(filepath.Join(a.dir, "agent.sock")),
		"-o", "IdentityFile=" + sshOptPath(filepath.Join(a.dir, "new")),
		"-o", "IdentitiesOnly=yes",
	}
}

func (a *rotateAgent) close() {
	a.srv.Close()
	<-a.done
	a.kr.RemoveAll()
	os.RemoveAll(a.dir)
}

// sshOptPath quotes a path for an ssh -o option, as sshconfig does for the
// config: % doubled, then double quotes.
func sshOptPath(p string) string {
	p = strings.ReplaceAll(p, "%", "%%")
	p = strings.NewReplacer(`\`, `\\`, `"`, `\"`).Replace(p)
	return `"` + p + `"`
}

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
	ok, err := confirm(e, false, "Rotate them now?")
	if err != nil || !ok {
		return nil
	}
	return runKeyRotate(ctx, e, []string{"--all", "--yes"})
}
