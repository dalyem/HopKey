package cli

import (
	"bytes"
	"cmp"
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"slices"
	"strings"
	"unicode/utf8"

	"golang.org/x/crypto/ssh"

	"github.com/dalyem/hopkey/internal/access"
	"github.com/dalyem/hopkey/internal/crypto"
	"github.com/dalyem/hopkey/internal/daemon"
	"github.com/dalyem/hopkey/internal/model"
)

// hop access (crypto spec rev 17, Part 2): a colleague's public key on the
// user's hosts, as a line hop manages and tracks, removed later with a
// tombstone. The guarantee (§7.0): when one device at a time runs hop
// access against a host, and the server serves the latest log, every line
// hop manages is named by a live record, and a removed record's line is
// gone, with a tombstone. hop access check finds what it can of the rest.

func runAccess(ctx context.Context, e *Env, args []string) error {
	if len(args) == 0 {
		fmt.Fprintf(e.Stderr, "usage: %s\n", commands["access"].usage)
		return failf("access needs a subcommand: add, rm, ls, check, migrate or forget")
	}
	switch args[0] {
	case "add":
		return runAccessAdd(ctx, e, args[1:])
	case "rm":
		return runAccessRm(ctx, e, args[1:])
	case "ls":
		return runAccessLs(ctx, e, args[1:])
	case "check":
		return runAccessCheck(ctx, e, args[1:])
	case "migrate":
		return runAccessMigrate(ctx, e, args[1:])
	case "forget":
		return runAccessForget(ctx, e, args[1:])
	}
	return failf("unknown access subcommand %q (add, rm, ls, check, migrate, forget)", args[0])
}

// AccessTargetResult is one target in the --json output of a hop access
// run.
type AccessTargetResult struct {
	Host    string `json:"host"`
	HostID  string `json:"host_id"`
	User    string `json:"user,omitempty"`
	Binding string `json:"binding,omitempty"`
	State   string `json:"state"`
	Gen     uint64 `json:"gen,omitempty"`
	// State is what the run found or did on the host. Recorded says the
	// put that stores it was journaled; when it is false, Message says
	// why nothing was stored, and the run exits non-zero.
	Recorded bool     `json:"recorded"`
	Message  string   `json:"message,omitempty"`
	Lines    []string `json:"lines,omitempty"`
	Warnings []string `json:"warnings,omitempty"`
	ok       bool
}

// AccessRunResult is the --json output of hop access add, rm and migrate.
type AccessRunResult struct {
	Label    string               `json:"label"`
	RecordID string               `json:"record_id,omitempty"`
	Targets  []AccessTargetResult `json:"targets"`
	Notes    []string             `json:"notes,omitempty"`
	Deleted  bool                 `json:"deleted,omitempty"`
}

// accessVault is the vault side of a run: the daemon's access ops.
type accessVault struct {
	e     *Env
	local bool
}

var errNotCommitted = errors.New("recorded, not applied: run it again once synced")

func (v *accessVault) caps(ctx context.Context) error {
	var r daemon.AccessCapabilitiesResult
	if err := call(ctx, v.e, daemon.OpAccessCapabilities, nil, &r); err != nil {
		return err
	}
	v.local = r.Local
	return nil
}

// list returns the vault's access records. It changes nothing in v: a
// fence that runs past its session's deadline still calls it (byID), so
// local is set only by caps and lookup, when a command starts.
func (v *accessVault) list(ctx context.Context) (*daemon.AccessListResult, error) {
	var r daemon.AccessListResult
	if err := call(ctx, v.e, daemon.OpAccessList, nil, &r); err != nil {
		return nil, err
	}
	return &r, nil
}

// sync pulls and pushes in a server-backed vault: the planners' commits
// and fences (§7.1, §7.7).
func (v *accessVault) sync(ctx context.Context) error {
	if v.local {
		return nil
	}
	var st daemon.SyncStatusResult
	return call(ctx, v.e, daemon.OpSyncNow, nil, &st)
}

// pullOnly pulls and verifies in a server-backed vault, and never pushes:
// hop access check journals and posts nothing (§7.8).
func (v *accessVault) pullOnly(ctx context.Context) error {
	if v.local {
		return nil
	}
	var st daemon.SyncStatusResult
	return call(ctx, v.e, daemon.OpSyncPull, nil, &st)
}

// lookup resolves label to a live record, once, when a command starts.
// Labels compare under K_alias (model.NameKey), and a label that two live
// records match is refused rather than guessed. From then on the command
// names the record by its item ID and record ID (byID): a label may name
// another record by the time a run records its results.
func (v *accessVault) lookup(ctx context.Context, label string) (*model.Access, error) {
	l, err := v.list(ctx)
	if err != nil {
		return nil, err
	}
	v.local = l.Local
	var found *model.Access
	for i := range l.Access {
		if model.NameKey(l.Access[i].Label) != model.NameKey(label) {
			continue
		}
		if found != nil {
			return nil, failf("two hop access records match the label %s (%s and %s); hop won't guess which one you mean", label, found.RecordID, l.Access[i].RecordID)
		}
		found = &l.Access[i]
	}
	return found, nil
}

// byID returns the live record with item ID id and record ID rid, as the
// vault shows it, and whether a queued change marks it; nil when there is
// none.
func (v *accessVault) byID(ctx context.Context, id, rid model.ID) (*model.Access, bool, error) {
	l, err := v.list(ctx)
	if err != nil {
		return nil, false, err
	}
	for i := range l.Access {
		if l.Access[i].ItemID == id {
			if l.Access[i].RecordID != rid {
				return nil, false, nil
			}
			_, marked := l.Marks[id.String()]
			return &l.Access[i], marked, nil
		}
	}
	return nil, false, nil
}

// commit writes a and waits until it is in verified state (§7.1): in a
// local-only vault that is the write itself; in a published one the
// outbox record must commit. It returns the committed record, found by
// the item ID the write was given (a create's is new) and a's record ID.
func (v *accessVault) commit(ctx context.Context, a model.Access) (*model.Access, error) {
	var saved model.Access
	if err := call(ctx, v.e, daemon.OpAccessPut, daemon.AccessPutParams{Access: a}, &saved); err != nil {
		return nil, err
	}
	if saved.ItemID.IsZero() || saved.RecordID != a.RecordID {
		return nil, errNotCommitted
	}
	if v.local {
		return &saved, nil
	}
	if err := v.sync(ctx); err != nil {
		return nil, errNotCommitted
	}
	cur, marked, err := v.byID(ctx, saved.ItemID, saved.RecordID)
	if err != nil || cur == nil || marked {
		return nil, errNotCommitted
	}
	return cur, nil
}

// committed returns a as verified state holds it, with no queued change,
// syncing first if it has one. A run that resumes a target commits
// nothing first (§7.1), but it still acts only on committed state: a
// queued create that Take theirs may yet discard authorizes no write.
func (v *accessVault) committed(ctx context.Context, a *model.Access) (*model.Access, error) {
	if v.local {
		return a, nil
	}
	if cur, marked, err := v.byID(ctx, a.ItemID, a.RecordID); err == nil && cur != nil && !marked {
		return cur, nil
	}
	if err := v.sync(ctx); err != nil {
		return nil, errNotCommitted
	}
	cur, marked, err := v.byID(ctx, a.ItemID, a.RecordID)
	if err != nil || cur == nil || marked {
		return nil, errNotCommitted
	}
	return cur, nil
}

// hostIndex finds host records by name or alias.
type hostIndex struct{ hosts []model.Host }

func (x hostIndex) byName(name string) (model.Host, bool) {
	for _, h := range x.hosts {
		if strings.EqualFold(h.Name, name) || slices.ContainsFunc(h.Aliases, func(a string) bool { return strings.EqualFold(a, name) }) {
			return h, true
		}
	}
	return model.Host{}, false
}

func (x hostIndex) byID(id model.ID) (model.Host, bool) {
	i := slices.IndexFunc(x.hosts, func(h model.Host) bool { return h.ItemID == id })
	if i < 0 {
		return model.Host{}, false
	}
	return x.hosts[i], true
}

func (x hostIndex) name(id model.ID) string {
	if h, ok := x.byID(id); ok {
		return h.Name
	}
	return "host deleted (" + id.String() + ")"
}

// sharedPins are the other live host records that pin fp (§7.6, a known
// shared pin), sorted by item ID.
func (x hostIndex) sharedPins(fp string, self model.ID) []model.Host {
	var out []model.Host
	for _, h := range x.hosts {
		if h.ItemID != self && boundPin(h, fp) != nil {
			out = append(out, h)
		}
	}
	slices.SortFunc(out, func(a, b model.Host) int { return bytes.Compare(a.ItemID[:], b.ItemID[:]) })
	return out
}

func targetFor(a *model.Access, host model.ID) *model.AccessTarget {
	for i := range a.Targets {
		if a.Targets[i].HostItemID == host && !model.AccessTerminal(a.Targets[i].State) {
			return &a.Targets[i]
		}
	}
	return nil
}

func sortAccessTargets(ts []model.AccessTarget) {
	slices.SortFunc(ts, func(a, b model.AccessTarget) int {
		if c := bytes.Compare(a.HostItemID[:], b.HostItemID[:]); c != 0 {
			return c
		}
		return strings.Compare(a.ServerKeyFP, b.ServerKeyFP)
	})
}

// storedError makes text fit an access target's error: one line, no
// control characters, at most 256 bytes.
func storedError(s string) string {
	s = strings.Join(strings.Fields(strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return ' '
		}
		return r
	}, s)), " ")
	if len(s) <= 256 {
		return s
	}
	s = s[:253]
	for !utf8.ValidString(s) {
		s = s[:len(s)-1]
	}
	return s + "..."
}

func (e *Env) now64() model.Timestamp { return model.TimestampOf(e.now()) }

// ---- hop access add ----

type accessAddOpts struct {
	pubkey, fingerprint string
	from                []string
	restrict, noFwd     bool
	alongside, yes      bool
	asJSON              bool
}

func runAccessAdd(ctx context.Context, e *Env, args []string) error {
	fs := newFlags(e, "access add", commands["access"].usage)
	var o accessAddOpts
	var from string
	fs.StringVar(&o.pubkey, "pubkey", "", "the colleague's public key: TYPE BASE64 [COMMENT]")
	fs.StringVar(&o.fingerprint, "fingerprint", "", "the key's SHA256 fingerprint; it proves something only if it reached you over a different channel from the key")
	fs.StringVar(&from, "from", "", "CIDR[,CIDR...]: the addresses the colleague may log in from")
	fs.BoolVar(&o.restrict, "restrict", false, "restrict the login (no forwarding, no pty)")
	fs.BoolVar(&o.noFwd, "no-forwarding", false, "no agent, port or X11 forwarding")
	fs.BoolVar(&o.alongside, "alongside", false, "add hop's line even if the key is already authorized by another line")
	fs.BoolVar(&o.yes, "yes", false, "don't ask")
	fs.BoolVar(&o.asJSON, "json", false, "print the result as JSON")
	pos, _, err := parseFlags(fs, args)
	if err != nil {
		return err
	}
	if len(pos) < 1 {
		return failf("usage: %s", commands["access"].usage)
	}
	if from != "" {
		o.from = strings.Split(from, ",")
	}
	label, hosts := pos[0], pos[1:]
	v := &accessVault{e: e}
	if err := v.caps(ctx); err != nil {
		return err
	}
	l, err := listAll(ctx, e)
	if err != nil {
		return err
	}
	ix := hostIndex{l.Hosts}
	rec, err := v.lookup(ctx, label)
	if err != nil {
		return err
	}
	res := &AccessRunResult{Label: label}
	var next *model.Access
	if rec == nil {
		al, err := v.list(ctx)
		if err != nil {
			return err
		}
		if next, err = newAccessRecord(e, label, &o, l, len(al.Access) == 0); err != nil {
			return err
		}
		if len(hosts) == 0 {
			return failf("name at least one host for a new record")
		}
	} else {
		if o.pubkey != "" || o.from != nil || o.restrict || o.noFwd {
			return failf("record %s exists; its key and options can't change. Create a new record for another key or other options", label)
		}
		next = access.Clone(rec)
	}

	// The binding preflight for each new target, before anything is
	// committed (§7.6).
	var act []model.ID // hosts to act on
	warnings := map[model.ID][]string{}
	changed := false
	for _, name := range hosts {
		h, ok := ix.byName(name)
		if !ok {
			return failf("no host %s in the vault", name)
		}
		if slices.Contains(act, h.ItemID) {
			continue
		}
		tr := AccessTargetResult{Host: h.Name, HostID: h.ItemID.String()}
		if t := targetFor(next, h.ItemID); t != nil {
			// The binding check comes before anything is committed: a
			// binding the pins no longer include stores nothing (§7.6).
			if boundPin(h, t.ServerKeyFP) == nil {
				tr.State, tr.Gen, tr.Binding, tr.Message = t.State, t.Gen, t.ServerKeyFP, unbound(*t, label, h.Name)
				res.Targets = append(res.Targets, tr)
				continue
			}
			switch t.State {
			case model.AccessFailed, model.AccessInstalled:
				t.State, t.Gen, t.Error, t.Time = model.AccessPending, t.Gen+1, "", e.now64()
				t.Alongside = t.Alongside || o.alongside
				changed = true
			case model.AccessRemoving:
				tr.State, tr.Message = t.State, "this target is being removed; finish that with hop access rm "+label
				res.Targets = append(res.Targets, tr)
				continue
			case model.AccessPending:
				if o.alongside && !t.Alongside {
					tr.State, tr.Message = t.State, "--alongside takes effect only through a new attempt; finish this one first"
					res.Targets = append(res.Targets, tr)
					continue
				}
			}
			act = append(act, h.ItemID)
			continue
		}
		nt, why := e.accessBind(ctx, h, l, next)
		if why != "" {
			tr.Message = why
			res.Targets = append(res.Targets, tr)
			continue
		}
		nt.Alongside = o.alongside
		if shared := ix.sharedPins(nt.ServerKeyFP, h.ItemID); len(shared) > 0 {
			warnings[h.ItemID] = append(warnings[h.ItemID], safef("host %s pins the same key %s; removing this target will need --same-machine (if it reaches this same machine and account) or --abandon", shared[0].Name, nt.ServerKeyFP))
		}
		next.Targets = append(next.Targets, *nt)
		changed = true
		act = append(act, h.ItemID)
	}
	if rec != nil && len(hosts) == 0 {
		for _, t := range next.Targets {
			if t.State == model.AccessPending {
				act = append(act, t.HostItemID)
			}
		}
	}
	sortAccessTargets(next.Targets)
	if changed {
		if rec == nil && !o.yes {
			if ok, err := confirmCtx(ctx, e, safef("Add record %s (%s) to %d host(s)?", label, next.Fingerprint, len(act))); err != nil || !ok {
				return errors.Join(err, failf("nothing was changed"))
			}
		}
		committed, err := v.commit(ctx, *next)
		if err != nil {
			if errors.Is(err, errNotCommitted) {
				return failf("%v", err)
			}
			return err
		}
		next = committed
		// The commit pulled, so the host records may have changed since
		// the list above: addOne checks each binding against them again,
		// right before it connects.
	} else if len(act) > 0 {
		accessTestHook("before-resume", next)
		if next, err = v.committed(ctx, next); err != nil {
			return failf("%v", err)
		}
	}
	res.RecordID = next.RecordID.String()
	var results []access.Result
	for _, hid := range act {
		t := targetFor(next, hid)
		if t == nil || t.State != model.AccessPending {
			continue
		}
		accessTestHook("before-session", next)
		tr, r := e.addOne(ctx, v, next, *t)
		tr.Warnings = append(warnings[hid], tr.Warnings...)
		res.Targets = append(res.Targets, tr)
		if r != nil {
			results = append(results, *r)
		}
	}
	e.recordResults(ctx, v, next, results, res)
	return e.finishAccessRun(res, o.asJSON)
}

// accessTestHook is called at points of a planner run (before-resume,
// before-session, before-record) with the record the run acts for. Tests replace it to
// interleave runs.
var accessTestHook = func(point string, a *model.Access) {}

// newAccessRecord builds a new record from the input policy of §6.2.
func newAccessRecord(e *Env, label string, o *accessAddOpts, l *daemon.ListResult, first bool) (*model.Access, error) {
	if o.pubkey == "" || o.fingerprint == "" {
		return nil, failf("a new record needs --pubkey and --fingerprint")
	}
	if err := crypto.CheckStr("label", label, 64); err != nil || label == "" {
		return nil, failf("the label must be 1 to 64 characters with no control characters")
	}
	line, fp, err := accessKeyInput(o.pubkey)
	if err != nil {
		return nil, err
	}
	if strings.HasPrefix(o.fingerprint, "MD5:") {
		return nil, failf("an MD5 fingerprint proves nothing; give the SHA256 one (ssh-keygen -lf KEY)")
	}
	if strings.TrimRight(o.fingerprint, "=") != fp {
		return nil, failf("the key's fingerprint is %s, not %s; nothing was changed", fp, o.fingerprint)
	}
	for _, k := range l.Keys {
		if k.Fingerprint == fp {
			return nil, failf("%s is the vault's own key %s; hop key rotate and deploy look after it, not hop access", fp, k.Name)
		}
	}
	opts := model.AccessOptions{From: []string{}, Restrict: o.restrict, NoForwarding: o.noFwd}
	for _, f := range o.from {
		c, err := crypto.CanonicalFrom(strings.TrimSpace(f))
		if err != nil {
			return nil, failf("--from: %v", err)
		}
		if !slices.Contains(opts.From, c) {
			opts.From = append(opts.From, c)
		}
	}
	if o.restrict && o.noFwd {
		return nil, failf("--restrict already turns forwarding off; give one of --restrict and --no-forwarding")
	}
	var rid model.ID
	rand.Read(rid[:])
	a := &model.Access{
		Header: model.Header{V: 1, ItemID: model.ID{1}, Type: model.TypeAccess},
		Label:  label, RecordID: rid, PublicKey: line, Fingerprint: fp, Options: opts, By: model.ID{1},
		Targets: []model.AccessTarget{{HostItemID: model.ID{1}, User: "x", ServerKeyFP: fp, Gen: 1, State: model.AccessPending}},
	}
	if err := crypto.ValidateAccess(a); err != nil {
		return nil, failf("%v", err)
	}
	a.ItemID, a.By, a.Targets = model.ID{}, model.ID{}, nil
	if !o.asJSON {
		if len(opts.From) == 0 && !o.restrict && !o.noFwd {
			fmt.Fprintln(e.Stderr, "note: with no --from, --restrict or --no-forwarding, the colleague gets a full login with forwarding (--restrict also turns off the pty)")
		}
	}
	if first {
		fmt.Fprintln(e.Stderr, "warning: this is the vault's first hop access record. Devices running hop older than this version will stop syncing, and those that already synced it can't unlock the vault until upgraded")
	}
	return a, nil
}

// accessKeyInput is the --pubkey rule of §6.2: one bare key, printable
// ASCII, an allowed type, strict base64, the blob's own type, at most a
// comment after it (discarded). It returns the key as stored and its
// fingerprint.
func accessKeyInput(in string) (string, string, error) {
	for i := 0; i < len(in); i++ {
		if in[i] < 0x20 || in[i] > 0x7e {
			return "", "", failf("--pubkey holds a byte that isn't printable ASCII (a line break, a tab or a non-ASCII character)")
		}
	}
	f := strings.Fields(in)
	if len(f) < 2 {
		return "", "", failf("--pubkey must be TYPE BASE64 [COMMENT]")
	}
	for i := 2; i+1 < len(f); i++ {
		if _, err := crypto.CheckAccessPublicKey(f[i] + " " + f[i+1]); err == nil {
			return "", "", failf("--pubkey holds more than one key")
		}
	}
	line := f[0] + " " + f[1]
	if _, err := crypto.CheckAccessPublicKey(line); err != nil {
		return "", "", failf("--pubkey: %v", err)
	}
	fp, err := crypto.SSHFingerprint(line)
	if err != nil {
		return "", "", failf("--pubkey: %v", err)
	}
	return line, fp, nil
}

// accessBind runs the binding preflight for a new target of a on h
// (§7.6). It refuses a host with no pins, a key it can't name, a user it
// can't tell, and a binding the record already has (N8). It also refuses
// a host whose ~/.ssh/authorized_keys the read script refuses (81, a
// symbolic link; 82, missing) or that is over 1 MiB: the log still names
// the key, but an add couldn't write there, so nothing is committed and
// the run reports why. A file that becomes a link or goes missing after
// its target was added is the session's 81 or 82: the add records failed,
// a removal stays removing with the advice of §7.3.
func (e *Env) accessBind(ctx context.Context, h model.Host, l *daemon.ListResult, a *model.Access) (*model.AccessTarget, string) {
	pins, _ := parsePins(h.HostKeys)
	c, why := e.accessConnect(ctx, h, l, pins)
	if why != "" {
		return nil, "not added: " + why
	}
	defer c.close()
	if c.user == "" {
		return nil, "not added: hop can't tell which user it logs in as there"
	}
	key, _, why := c.preflight(ctx, pins)
	if key == nil {
		return nil, "not added: " + why
	}
	fp := ssh.FingerprintSHA256(key)
	for _, t := range a.Targets {
		if t.HostItemID == h.ItemID && t.ServerKeyFP == fp {
			return nil, safef("record %s already has a target for %s bound to %s (state %s); targets are never reused: create a new record with hop access add NEWLABEL ...", a.Label, h.Name, fp, t.State)
		}
	}
	if why != "" {
		return nil, "not added: " + why
	}
	return &model.AccessTarget{HostItemID: h.ItemID, User: c.user, ServerKeyFP: fp, Gen: 1, State: model.AccessPending, Time: e.now64()}, ""
}

// unbound is the diagnostic of a target whose bound key the host's pins
// no longer include (§7.6). Nothing connects, nothing is stored.
func unbound(t model.AccessTarget, label, host string) string {
	return safef("the host's pinned keys no longer include %s, the key this target is bound to; nothing was changed. Use hop access migrate %s %s or hop access rm %s --abandon %s",
		t.ServerKeyFP, label, host, label, host)
}

// addOne acts on one pending target (§7.2). It returns the target's
// report and the result to record, nil when nothing is stored.
func (e *Env) addOne(ctx context.Context, v *accessVault, a *model.Access, t model.AccessTarget) (AccessTargetResult, *access.Result) {
	tr := AccessTargetResult{HostID: t.HostItemID.String(), User: t.User, Binding: t.ServerKeyFP, State: t.State, Gen: t.Gen}
	b := e.bindingNow(ctx, t)
	tr.Host = b.name
	switch {
	case b.err != nil:
		tr.Message = safef("not applied: %v", b.err)
		return tr, nil
	case b.pin == nil:
		tr.Message = unbound(t, a.Label, b.name)
		return tr, nil
	}
	c, why := e.accessConnect(ctx, b.host, b.l, []ssh.PublicKey{b.pin})
	if why != "" {
		tr.Message = "not applied: " + why
		return tr, nil
	}
	defer c.close()
	end := c.session(ctx, func(ctx context.Context, user string, content []byte) sessionDecision {
		if user != t.User {
			return sessionDecision{userChanged: true}
		}
		if why := e.accessFence(ctx, v, a, t, model.AccessPending); why != "" {
			return sessionDecision{fenced: why}
		}
		d := access.DecideAdd(content, a, t.Alongside)
		if d.Outcome == access.OutWrite {
			return sessionDecision{to: d.New, d: d}
		}
		return sessionDecision{d: d}
	})
	d, gotUser := end.decision.d, end.user
	// The host's outcome; recordResults marks it recorded once the put
	// that stores it is journaled.
	res := func(state, errText string) *access.Result {
		tr.State, tr.Message = state, errText
		tr.ok = state == model.AccessInstalled
		return &access.Result{ItemID: a.ItemID, RecordID: a.RecordID, Host: t.HostItemID, FP: t.ServerKeyFP, From: model.AccessPending, Gen: t.Gen, State: state, Error: storedError(errText)}
	}
	notApplied := func(why string) (AccessTargetResult, *access.Result) {
		tr.Message = "not applied: " + why
		return tr, nil
	}
	switch {
	case end.exited && end.code == akExitSymlink:
		return tr, res(model.AccessFailed, akFile+" is a symbolic link, which hop doesn't edit")
	case end.exited && end.code == akExitMissing:
		return tr, res(model.AccessFailed, akFile+" does not exist")
	case end.exited && (end.code == akExitChanged || end.code == akExitWrite):
		return tr, res(model.AccessFailed, "could not write "+akFile+" ("+end.why+")")
	case end.exited && end.code == akExitLocked:
		return notApplied(strings.TrimSuffix(end.why, ".") + "; run hop access add " + a.Label + " again")
	case end.exited && end.code == akExitDecision && end.sent == sentAbort:
		switch {
		case !end.gotHeader || end.abortWhy != "" || !end.decided:
			return notApplied(strings.TrimPrefix(end.abortWhy+"; ", "; ") + "run hop access add " + a.Label + " again")
		case end.decision.userChanged:
			return tr, res(model.AccessFailed, "the host now logs in as "+gotUser)
		case end.decision.fenced != "":
			return notApplied(end.decision.fenced)
		case d.Outcome == access.OutInstalled:
			return tr, res(model.AccessInstalled, "")
		case d.Outcome == access.OutRefused:
			tr.Lines = d.Show
			return tr, res(model.AccessFailed, d.Err)
		}
		return notApplied("the session ended without a decision")
	case end.exited && end.code == akExitDecision, end.sent != sentWrite:
		// The client's own reason, when it gave up, says more than how
		// ssh ended after that.
		return notApplied("the session ended before hop sent its change (" + cmp.Or(end.abortWhy, end.why) + "); run hop access add " + a.Label + " again")
	case end.exited && end.code == 0:
		return tr, res(model.AccessInstalled, "")
	}
	// 86, 89, 255, any other status, a lost connection: the rename may
	// have happened. Re-read on the restricted connection (§7.7).
	if end.exited && end.code == akExitCleanup {
		tr.Warnings = append(tr.Warnings, end.why+"; run hop access check")
	}
	got, why := e.reread(ctx, c, a, t)
	if why != "" {
		return tr, res(model.AccessFailed, "hop could not tell whether it changed "+akFile+": "+why)
	}
	switch access.Reread(got, end.content, d.New) {
	case access.RereadIntended:
		return tr, res(model.AccessInstalled, "")
	case access.RereadUnchanged:
		return notApplied("run hop access add " + a.Label + " again")
	}
	return tr, res(model.AccessFailed, "the file changed in a way hop didn't expect")
}

// accessFence is the pull under the lock (§7.2 step 3, §7.3 step 3): the
// newest verified state must still hold the record a (the same item ID and
// record ID) with t in state at t's gen, with the same binding, user and
// alongside, and the host's pins must still include the binding (§7.6):
// the pull may bring in another device's change to them. A pull that
// fails, or a record with a queued change, fails the fence. The pull
// pushes nothing. It returns why it failed, or "".
func (e *Env) accessFence(ctx context.Context, v *accessVault, a *model.Access, t model.AccessTarget, state string) string {
	const owned = "another hop run owns this target now"
	if err := v.pullOnly(ctx); err != nil {
		return safef("hop could not sync under the lock (%v); run it again", err)
	}
	cur, marked, err := v.byID(ctx, a.ItemID, a.RecordID)
	if err != nil || cur == nil || marked {
		return owned
	}
	i := slices.IndexFunc(cur.Targets, func(x model.AccessTarget) bool {
		return x.HostItemID == t.HostItemID && x.ServerKeyFP == t.ServerKeyFP
	})
	if i < 0 {
		return owned
	}
	if x := cur.Targets[i]; x.State != state || x.Gen != t.Gen || x.User != t.User || x.Alongside != t.Alongside {
		return owned
	}
	if b := e.bindingNow(ctx, t); b.err != nil || b.pin == nil {
		return unbound(t, a.Label, b.name)
	}
	return ""
}

// binding is a target's host as the vault holds it now.
type binding struct {
	l    *daemon.ListResult
	host model.Host
	name string
	// pin is the host's pin with the target's binding; nil when the host
	// is gone or its pins no longer include it.
	pin ssh.PublicKey
	err error
}

// bindingNow reads the host records again and finds t's host and bound
// pin in them (§7.6). Every connection after a target's preflight comes
// after this check, and trusts only the pin it returns: a commit, a
// resume's sync or an earlier session's fence may have brought in
// another device's change to the pins since the run listed the hosts, and
// that list would still trust a key the change removed.
func (e *Env) bindingNow(ctx context.Context, t model.AccessTarget) binding {
	l, err := listAll(ctx, e)
	if err != nil {
		return binding{name: "host " + t.HostItemID.String(), err: err}
	}
	ix := hostIndex{l.Hosts}
	b := binding{l: l, name: ix.name(t.HostItemID)}
	if h, ok := ix.byID(t.HostItemID); ok {
		b.host, b.pin = h, boundPin(h, t.ServerKeyFP)
	}
	return b
}

// reread reads the file again after a session whose end leaves the
// rename uncertain (§7.7), on the session's restricted connection, once
// the binding check passes again: the session's pull may have brought in
// a change to the pins.
func (e *Env) reread(ctx context.Context, c *accessConn, a *model.Access, t model.AccessTarget) ([]byte, string) {
	switch b := e.bindingNow(ctx, t); {
	case b.err != nil:
		return nil, safef("%v", b.err)
	case b.pin == nil:
		return nil, unbound(t, a.Label, b.name)
	}
	return c.read(ctx)
}

// recordResults writes the run's results in one put, built against the
// newest verified state of the record the run acted for, a (§7.1);
// results whose target moved on are dropped. A target's report says
// recorded only once the put that stores its result is journaled; every
// other target that has a result is reported not recorded, which fails
// the run. It returns the record as written, or nil when nothing was.
func (e *Env) recordResults(ctx context.Context, v *accessVault, a *model.Access, results []access.Result, res *AccessRunResult) *model.Access {
	if len(results) == 0 {
		return nil
	}
	accessTestHook("before-record", a)
	notRecorded := func(why string) {
		for i := range res.Targets {
			tr := &res.Targets[i]
			if slices.ContainsFunc(results, func(r access.Result) bool { return r.Host.String() == tr.HostID && r.FP == tr.Binding }) {
				tr.Recorded, tr.ok = false, false
				tr.Message = strings.TrimPrefix(tr.Message+"; ", "; ") + "not recorded: " + why
			}
		}
	}
	if err := v.pullOnly(ctx); err != nil {
		res.Notes = append(res.Notes, safef("could not sync before recording the results (%v); they are built on the local copy of the vault", err))
	}
	cur, _, err := v.byID(ctx, a.ItemID, a.RecordID)
	if err != nil || cur == nil {
		if err != nil {
			notRecorded(safef("%v", err))
		} else {
			notRecorded("the record is gone")
		}
		return nil
	}
	next, kept := access.ApplyResults(cur, results, e.now64())
	if len(kept) == 0 || !access.Substantive(cur, next) {
		notRecorded("another run owns this target now")
		return nil
	}
	var saved model.Access
	if err := call(ctx, v.e, daemon.OpAccessPut, daemon.AccessPutParams{Access: *next}, &saved); err != nil {
		notRecorded(safef("%v", err))
		return nil
	}
	for i := range res.Targets {
		tr := &res.Targets[i]
		if slices.ContainsFunc(kept, func(r access.Result) bool { return r.Host.String() == tr.HostID && r.FP == tr.Binding }) {
			tr.Recorded = true
		} else if slices.ContainsFunc(results, func(r access.Result) bool { return r.Host.String() == tr.HostID && r.FP == tr.Binding }) {
			tr.Recorded, tr.ok = false, false
			tr.Message = strings.TrimPrefix(tr.Message+"; ", "; ") + "not recorded: another run owns this target now"
		}
	}
	if !v.local {
		if err := v.sync(ctx); err != nil {
			res.Notes = append(res.Notes, "the results are queued and go to the server on the next sync")
		} else if _, marked, _ := v.byID(ctx, a.ItemID, a.RecordID); marked {
			res.Notes = append(res.Notes, "the results are held: another device changed the record meanwhile, so the hosts may now disagree with it. Run hop sync resolve, then hop access check")
		}
	}
	return &saved
}

func (e *Env) finishAccessRun(res *AccessRunResult, asJSON bool) error {
	fail := false
	for _, t := range res.Targets {
		fail = fail || !t.ok
	}
	if asJSON {
		if err := printJSON(e, res); err != nil {
			return err
		}
	} else {
		for _, t := range res.Targets {
			state := t.State
			if !t.Recorded && t.State != "" {
				state += " (nothing recorded)"
			}
			e.printf("%s: %s", t.Host, state)
			if t.Message != "" {
				e.printf(": %s", oneLine(t.Message))
			}
			e.printf("\n")
			for _, l := range t.Lines {
				e.printf("    %s\n", oneLine(l))
			}
			for _, w := range t.Warnings {
				e.printf("  warning: %s\n", oneLine(w))
			}
		}
		for _, n := range res.Notes {
			e.printf("%s\n", oneLine(n))
		}
	}
	if fail {
		return silent(1)
	}
	return nil
}

// ---- hop access rm ----

type accessRmOpts struct {
	abandon     string
	sameMachine bool
	yes, asJSON bool
}

func runAccessRm(ctx context.Context, e *Env, args []string) error {
	fs := newFlags(e, "access rm", commands["access"].usage)
	var o accessRmOpts
	fs.StringVar(&o.abandon, "abandon", "", "record that you give up on HOST: the line may remain there")
	fs.BoolVar(&o.sameMachine, "same-machine", false, "state that the other host records that pin HOST's key reach the same machine and account")
	fs.BoolVar(&o.yes, "yes", false, "don't ask")
	fs.BoolVar(&o.asJSON, "json", false, "print the result as JSON")
	helpNote(e, fs, accessRmHelp)
	pos, _, err := parseFlags(fs, args)
	if err != nil {
		return err
	}
	if len(pos) < 1 {
		return failf("usage: %s", commands["access"].usage)
	}
	label, hosts := pos[0], pos[1:]
	v := &accessVault{e: e}
	if err := v.caps(ctx); err != nil {
		return err
	}
	l, err := listAll(ctx, e)
	if err != nil {
		return err
	}
	ix := hostIndex{l.Hosts}
	rec, err := v.lookup(ctx, label)
	if err != nil {
		return err
	}
	if rec == nil {
		return failf("no hop access record %s", label)
	}
	if o.abandon != "" {
		return e.accessAbandon(ctx, v, ix, rec, o)
	}
	next := access.Clone(rec)
	var act []model.ID
	var pick []model.ID
	if len(hosts) == 0 {
		for _, t := range next.Targets {
			if !model.AccessTerminal(t.State) {
				pick = append(pick, t.HostItemID)
			}
		}
	}
	for _, name := range hosts {
		h, ok := ix.byName(name)
		if !ok {
			return failf("no host %s in the vault", name)
		}
		pick = append(pick, h.ItemID)
	}
	if o.sameMachine && len(hosts) != 1 {
		return failf("--same-machine is a statement about one host: name it")
	}
	changed := false
	res := &AccessRunResult{Label: label, RecordID: next.RecordID.String()}
	for _, hid := range pick {
		t := targetFor(next, hid)
		if t == nil {
			return failf("record %s has no target on %s that isn't removed or abandoned", label, ix.name(hid))
		}
		// The binding check comes before anything is committed: a binding
		// the pins no longer include stores nothing (§7.6).
		if h, ok := ix.byID(hid); !ok || boundPin(h, t.ServerKeyFP) == nil {
			msg := unbound(*t, label, ix.name(hid))
			if !ok {
				msg = "the host was deleted; nothing was changed. Only hop access rm " + label + " --abandon " + hid.String() + " applies"
			}
			res.Targets = append(res.Targets, AccessTargetResult{Host: ix.name(hid), HostID: hid.String(), User: t.User, Binding: t.ServerKeyFP, State: t.State, Gen: t.Gen, Message: msg})
			continue
		}
		if o.sameMachine {
			sm, err := e.sameMachine(ctx, ix, rec, *t, o.yes)
			if err != nil {
				return err
			}
			t.State, t.Gen, t.Error, t.Time, t.SameMachine = model.AccessRemoving, t.Gen+1, "", e.now64(), sm
			sm.Gen = t.Gen
			changed = true
		} else if t.State != model.AccessRemoving {
			t.State, t.Gen, t.Error, t.Time = model.AccessRemoving, t.Gen+1, "", e.now64()
			changed = true
		}
		act = append(act, hid)
	}
	if changed {
		committed, err := v.commit(ctx, *next)
		if err != nil {
			if errors.Is(err, errNotCommitted) {
				return failf("%v", err)
			}
			return err
		}
		next = committed
	} else if len(act) > 0 {
		accessTestHook("before-resume", next)
		if next, err = v.committed(ctx, next); err != nil {
			return failf("%v", err)
		}
	}
	var results []access.Result
	for _, hid := range act {
		t := targetFor(next, hid)
		if t == nil || t.State != model.AccessRemoving {
			continue
		}
		accessTestHook("before-session", next)
		tr, r := e.rmOne(ctx, v, next, *t)
		res.Targets = append(res.Targets, tr)
		if r != nil {
			results = append(results, *r)
		}
	}
	if saved := e.recordResults(ctx, v, next, results, res); saved != nil {
		e.closeRecord(ctx, v, saved, res)
	}
	if !o.asJSON && len(res.Targets) > 0 {
		e.printf("%s\n", accessRmReport)
	}
	return e.finishAccessRun(res, o.asJSON)
}

// closeRecord deletes the record a (its item ID and record ID) once every
// target is removed (§5.1).
func (e *Env) closeRecord(ctx context.Context, v *accessVault, a *model.Access, res *AccessRunResult) {
	cur, _, err := v.byID(ctx, a.ItemID, a.RecordID)
	if err != nil || cur == nil {
		return
	}
	all, abandoned := true, false
	for _, t := range cur.Targets {
		all = all && model.AccessTerminal(t.State)
		abandoned = abandoned || t.State == model.AccessAbandoned
	}
	switch {
	case !all:
	case abandoned:
		res.Notes = append(res.Notes, "abandoned targets remain; hop access forget "+a.Label+" deletes the record")
	default:
		if err := call(ctx, e, daemon.OpAccessDelete, daemon.AccessDeleteParams{ID: cur.ItemID.String(), RecordID: cur.RecordID.String()}, nil); err != nil {
			res.Notes = append(res.Notes, safef("could not delete the record: %v", err))
			return
		}
		res.Deleted = true
		res.Notes = append(res.Notes, "record "+a.Label+" deleted: every target is removed")
	}
}

const accessRmHelp = `
hop access rm removes the line hop added to the host's ~/.ssh/authorized_keys
and, in the same step, adds a comment line, # hop-access-removed <record id>
<number>. hop never adds that record's line to that file again while the
comment is there. hop doesn't remove these comment lines; you may, but then
that protection is gone for that record on that host. Anyone who can read the
file sees the record's ID and a number that counts hop's steps on that host;
the same ID on several hosts shows that one record covered all of them. It
doesn't name the person, the key or your label.

If the host loses power or crashes within seconds of hop access rm, the change
may not have reached its disk, and the line can come back when it restarts. If
the host, or its disk, is later restored from a snapshot or backup taken
before the removal, the line comes back with it. hop won't notice by itself;
hop access check finds it while the record still exists, or with --all-hosts
afterwards.
`

const accessRmReport = `managed authorization removed where it says removed. hop removed the line from the machine that presented the bound host key; machines that share that host key aren't distinguished. If a host loses power soon after this, or is later restored from a snapshot or backup taken before it, the line can come back: hop access check finds it. hop can't see other AuthorizedKeysFile paths or other login users, AuthorizedKeysCommand, certificates from a CA the host trusts, passwords, or keys the colleague added while logged in. Removal doesn't end open sessions or multiplexed control connections.`

// sameMachine asks for and builds the --same-machine statement (§7.6).
func (e *Env) sameMachine(ctx context.Context, ix hostIndex, a *model.Access, t model.AccessTarget, yes bool) (*model.SameMachine, error) {
	host := ix.name(t.HostItemID)
	H := ix.sharedPins(t.ServerKeyFP, t.HostItemID)
	switch {
	case len(H) == 0:
		return nil, failf("no other host record pins %s; --same-machine isn't needed", t.ServerKeyFP)
	case len(H) > crypto.AccessMaxSameMachine:
		return nil, failf("%d other host records pin %s; that is more than one statement can cover. Use hop access rm %s --abandon %s", len(H), t.ServerKeyFP, a.Label, host)
	}
	var names []string
	ids := make([]model.ID, 0, len(H))
	for _, h := range H {
		names = append(names, h.Name+" (id "+h.ItemID.String()+")")
		ids = append(ids, h.ItemID)
	}
	q := safef("Record %s, host %s, user %s, bound key %s. These host records reach the same machine, and the same account %s, as %s: %s. hop will record the removal of this target as done for all of them, on your word. Confirm?",
		a.Label, host, t.User, t.ServerKeyFP, t.User, host, strings.Join(names, ", "))
	ok, err := confirmCtxYes(ctx, e, yes, q)
	if err != nil || !ok {
		return nil, errors.Join(err, failf("nothing was changed"))
	}
	return &model.SameMachine{ServerKeyFP: t.ServerKeyFP, HostItemIDs: ids}, nil
}

func confirmCtxYes(ctx context.Context, e *Env, yes bool, q string) (bool, error) {
	if yes {
		return true, nil
	}
	return confirmCtx(ctx, e, q)
}

// accessAbandon is hop access rm LABEL --abandon HOST: no host is touched.
func (e *Env) accessAbandon(ctx context.Context, v *accessVault, ix hostIndex, a *model.Access, o accessRmOpts) error {
	h, ok := ix.byName(o.abandon)
	var hid model.ID
	if ok {
		hid = h.ItemID
	} else if id, err := model.ParseID(o.abandon); err == nil {
		hid = id // a deleted host, by the ID hop access ls shows
	} else {
		return failf("no host %s in the vault", o.abandon)
	}
	next := access.Clone(a)
	t := targetFor(next, hid)
	if t == nil {
		return failf("record %s has no target on %s that isn't removed or abandoned", a.Label, o.abandon)
	}
	q := safef("Abandon record %s on %s? The line may remain on the machine that presents %s.", a.Label, ix.name(hid), t.ServerKeyFP)
	if shared := ix.sharedPins(t.ServerKeyFP, hid); len(shared) > 0 {
		var names []string
		for _, s := range shared {
			names = append(names, s.Name)
		}
		q += safef(" Other host records pin that key too: %s.", strings.Join(names, ", "))
	}
	if ok, err := confirmCtxYes(ctx, e, o.yes, q); err != nil || !ok {
		return errors.Join(err, failf("nothing was changed"))
	}
	// An abandoned target has no error (§5.1): what failed before is
	// superseded by the user's statement.
	t.State, t.Gen, t.Error, t.Time = model.AccessAbandoned, t.Gen+1, "", e.now64()
	committed, err := v.commit(ctx, *next)
	if err != nil {
		if errors.Is(err, errNotCommitted) {
			return failf("%v", err)
		}
		return err
	}
	res := &AccessRunResult{Label: a.Label, RecordID: a.RecordID.String(), Targets: []AccessTargetResult{{
		Host: ix.name(hid), HostID: hid.String(), User: t.User, Binding: t.ServerKeyFP, State: model.AccessAbandoned, Gen: t.Gen,
		Recorded: true, ok: true, Message: "abandoned: the line may remain on the machine that presents " + t.ServerKeyFP,
	}}}
	e.closeRecord(ctx, v, committed, res)
	return e.finishAccessRun(res, o.asJSON)
}

// rmOne acts on one removing target (§7.3).
func (e *Env) rmOne(ctx context.Context, v *accessVault, a *model.Access, t model.AccessTarget) (AccessTargetResult, *access.Result) {
	tr := AccessTargetResult{HostID: t.HostItemID.String(), User: t.User, Binding: t.ServerKeyFP, State: t.State, Gen: t.Gen}
	b := e.bindingNow(ctx, t)
	name := b.name
	tr.Host = name
	switch {
	case b.err != nil:
		tr.Message = safef("not applied: %v", b.err)
		return tr, nil
	case b.pin == nil:
		tr.Message = unbound(t, a.Label, name)
		return tr, nil
	}
	ix := hostIndex{b.l.Hosts}
	c, why := e.accessConnect(ctx, b.host, b.l, []ssh.PublicKey{b.pin})
	if why != "" {
		tr.Message = "not applied: " + why
		return tr, nil
	}
	defer c.close()
	end := c.session(ctx, func(ctx context.Context, user string, content []byte) sessionDecision {
		if user != t.User {
			return sessionDecision{userChanged: true}
		}
		if why := e.accessFence(ctx, v, a, t, model.AccessRemoving); why != "" {
			return sessionDecision{fenced: why}
		}
		d := access.DecideRemove(content, a, t.Gen, name)
		if d.Outcome == access.OutWrite {
			return sessionDecision{to: d.New, d: d}
		}
		return sessionDecision{d: d}
	})
	d, gotUser := end.decision.d, end.user
	if d.Warn != "" {
		tr.Warnings = append(tr.Warnings, d.Warn)
	}
	stay := func(errText string) *access.Result {
		tr.State, tr.Message = model.AccessRemoving, errText
		return &access.Result{ItemID: a.ItemID, RecordID: a.RecordID, Host: t.HostItemID, FP: t.ServerKeyFP, From: model.AccessRemoving, Gen: t.Gen, State: model.AccessRemoving, Error: storedError(errText)}
	}
	removed := func() *access.Result {
		// A known shared pin needs a matching statement (§7.3 step 6). H
		// is computed now, from the host records as they are after the
		// session's pull.
		if fresh, err := listAll(ctx, e); err == nil {
			ix = hostIndex{fresh.Hosts}
		}
		H := ix.sharedPins(t.ServerKeyFP, t.HostItemID)
		if len(H) > 0 {
			sm := t.SameMachine
			match := sm != nil && sm.Gen == t.Gen && sm.ServerKeyFP == t.ServerKeyFP && len(sm.HostItemIDs) == len(H)
			for i := 0; match && i < len(H); i++ {
				match = sm.HostItemIDs[i] == H[i].ItemID
			}
			if !match {
				return stay(safef("removed from the machine hop reached, but host %s pins the same key %s, so another machine may still have the line. If %s reaches this same machine and account, confirm with hop access rm %s %s --same-machine; otherwise use hop access rm %s --abandon %s",
					H[0].Name, t.ServerKeyFP, H[0].Name, a.Label, name, a.Label, name))
			}
			var names []string
			for _, x := range H {
				names = append(names, x.Name)
			}
			tr.Warnings = append(tr.Warnings, "removed, on your statement that "+strings.Join(names, ", ")+" reach the same machine and account as "+name)
		}
		tr.State, tr.ok = model.AccessRemoved, true
		return &access.Result{ItemID: a.ItemID, RecordID: a.RecordID, Host: t.HostItemID, FP: t.ServerKeyFP, From: model.AccessRemoving, Gen: t.Gen, State: model.AccessRemoved}
	}
	notApplied := func(why string) (AccessTargetResult, *access.Result) {
		tr.Message = "not applied: " + why
		return tr, nil
	}
	switch {
	case end.exited && end.code == akExitSymlink:
		return tr, stay(safef("~/.ssh/authorized_keys on %s is a symbolic link, which hop doesn't edit, so hop can't record the removal there. Check by hand that the file it points to has no line ending in hop-access:%s, and remove any such line yourself. Then record the target as abandoned: hop access rm %s --abandon %s", name, a.RecordID, a.Label, name))
	case end.exited && end.code == akExitMissing:
		return tr, stay(safef("~/.ssh/authorized_keys doesn't exist on %s for %s, so hop can't record the removal there. If you want hop to finish, create the file only if it is still missing (sh -c 'umask 077; set -C; : > ~/.ssh/authorized_keys'), then run hop access rm %s again. Or: hop access rm %s --abandon %s", name, t.User, a.Label, a.Label, name))
	case end.exited && (end.code == akExitChanged || end.code == akExitWrite):
		return tr, stay("could not write " + akFile + " (" + end.why + ")")
	case end.exited && end.code == akExitLocked:
		return notApplied(strings.TrimSuffix(end.why, ".") + "; run hop access rm " + a.Label + " again")
	case end.exited && end.code == akExitDecision && end.sent == sentAbort:
		switch {
		case !end.gotHeader || end.abortWhy != "" || !end.decided:
			return notApplied(strings.TrimPrefix(end.abortWhy+"; ", "; ") + "run hop access rm " + a.Label + " again")
		case end.decision.userChanged:
			return tr, stay("the host now logs in as " + gotUser)
		case end.decision.fenced != "":
			return notApplied(end.decision.fenced)
		case d.Outcome == access.OutRemoved:
			return tr, removed()
		case d.Outcome == access.OutRefused:
			tr.Lines = d.Show
			return tr, stay(d.Err)
		}
		return notApplied("the session ended without a decision")
	case end.exited && end.code == akExitDecision, end.sent != sentWrite:
		// The client's own reason, when it gave up, says more than how
		// ssh ended after that.
		return notApplied("the session ended before hop sent its change (" + cmp.Or(end.abortWhy, end.why) + "); run hop access rm " + a.Label + " again")
	case end.exited && end.code == 0:
		return tr, removed()
	}
	if end.exited && end.code == akExitCleanup {
		tr.Warnings = append(tr.Warnings, end.why+"; run hop access check")
	}
	got, why := e.reread(ctx, c, a, t)
	if why != "" {
		return tr, stay("hop could not tell whether it changed " + akFile + ": " + why)
	}
	switch access.Reread(got, end.content, d.New) {
	case access.RereadIntended:
		return tr, removed()
	case access.RereadUnchanged:
		return notApplied("run hop access rm " + a.Label + " again")
	}
	return tr, stay("the file changed in a way hop didn't expect")
}

// ---- hop access migrate ----

func runAccessMigrate(ctx context.Context, e *Env, args []string) error {
	fs := newFlags(e, "access migrate", commands["access"].usage)
	yes := fs.Bool("yes", false, "don't ask")
	asJSON := fs.Bool("json", false, "print the result as JSON")
	pos, _, err := parseFlags(fs, args)
	if err != nil {
		return err
	}
	if len(pos) != 2 {
		return failf("usage: hop access migrate LABEL HOST")
	}
	label := pos[0]
	v := &accessVault{e: e}
	if err := v.caps(ctx); err != nil {
		return err
	}
	l, err := listAll(ctx, e)
	if err != nil {
		return err
	}
	ix := hostIndex{l.Hosts}
	rec, err := v.lookup(ctx, label)
	if err != nil {
		return err
	}
	if rec == nil {
		return failf("no hop access record %s", label)
	}
	h, ok := ix.byName(pos[1])
	if !ok {
		return failf("no host %s in the vault", pos[1])
	}
	next := access.Clone(rec)
	old := targetFor(next, h.ItemID)
	switch {
	case old == nil:
		return failf("record %s has no target on %s that isn't removed or abandoned", label, h.Name)
	case boundPin(h, old.ServerKeyFP) != nil:
		return failf("%s still pins %s, the key this target is bound to; migrate is only for a target whose key is no longer pinned", h.Name, old.ServerKeyFP)
	}
	nt, why := e.accessBind(ctx, h, l, next)
	if why != "" {
		return failf("%s", why)
	}
	q := safef("Migrate record %s on %s from %s to %s? hop will treat the machine that presents the new key as a different machine; the line may remain on the one that presents the old key.",
		label, h.Name, old.ServerKeyFP, nt.ServerKeyFP)
	if ok, err := confirmCtxYes(ctx, e, *yes, q); err != nil || !ok {
		return errors.Join(err, failf("nothing was changed"))
	}
	nt.State = model.AccessPending
	if old.State == model.AccessRemoving {
		nt.State = model.AccessRemoving
	}
	// The old target is abandoned, and an abandoned target has no error
	// (§5.1).
	old.State, old.Gen, old.Error, old.Time = model.AccessAbandoned, old.Gen+1, "", e.now64()
	next.Targets = append(next.Targets, *nt)
	sortAccessTargets(next.Targets)
	committed, err := v.commit(ctx, *next)
	if err != nil {
		if errors.Is(err, errNotCommitted) {
			return failf("%v", err)
		}
		return err
	}
	res := &AccessRunResult{Label: label, RecordID: committed.RecordID.String()}
	t := targetFor(committed, h.ItemID)
	if t == nil || t.ServerKeyFP != nt.ServerKeyFP {
		res.Notes = append(res.Notes, "the migrated target changed before hop could act on it: run hop access ls "+label)
		if err := e.finishAccessRun(res, *asJSON); err != nil {
			return err
		}
		return silent(1)
	}
	var tr AccessTargetResult
	var r *access.Result
	accessTestHook("before-session", committed)
	if t.State == model.AccessRemoving {
		tr, r = e.rmOne(ctx, v, committed, *t)
	} else {
		tr, r = e.addOne(ctx, v, committed, *t)
	}
	res.Targets = append(res.Targets, tr)
	var results []access.Result
	if r != nil {
		results = append(results, *r)
	}
	if saved := e.recordResults(ctx, v, committed, results, res); saved != nil && t.State == model.AccessRemoving {
		e.closeRecord(ctx, v, saved, res)
	}
	return e.finishAccessRun(res, *asJSON)
}

// ---- hop access forget ----

func runAccessForget(ctx context.Context, e *Env, args []string) error {
	fs := newFlags(e, "access forget", commands["access"].usage)
	yes := fs.Bool("yes", false, "don't ask")
	pos, _, err := parseFlags(fs, args)
	if err != nil {
		return err
	}
	if len(pos) != 1 {
		return failf("usage: hop access forget LABEL")
	}
	v := &accessVault{e: e}
	if err := v.caps(ctx); err != nil {
		return err
	}
	l, err := listAll(ctx, e)
	if err != nil {
		return err
	}
	ix := hostIndex{l.Hosts}
	rec, err := v.lookup(ctx, pos[0])
	if err != nil {
		return err
	}
	if rec == nil {
		return failf("no hop access record %s", pos[0])
	}
	var lines []string
	for _, t := range rec.Targets {
		if !model.AccessTerminal(t.State) {
			return failf("target %s is %s; finish it (hop access rm %s) or abandon it first", ix.name(t.HostItemID), t.State, rec.Label)
		}
		if t.State == model.AccessAbandoned {
			lines = append(lines, safef("the line may remain on the machine that presents %s (%s)", t.ServerKeyFP, ix.name(t.HostItemID)))
		}
	}
	q := "Forget record " + rec.Label + "?"
	if len(lines) > 0 {
		q += " " + strings.Join(lines, "; ") + ". After this, hop access check reports such a line as untracked until you delete it."
	}
	if ok, err := confirmCtxYes(ctx, e, *yes, q); err != nil || !ok {
		return errors.Join(err, failf("nothing was changed"))
	}
	if err := call(ctx, e, daemon.OpAccessDelete, daemon.AccessDeleteParams{ID: rec.ItemID.String(), RecordID: rec.RecordID.String(), Forget: true}, nil); err != nil {
		return err
	}
	e.printf("record %s forgotten\n", oneLine(rec.Label))
	return nil
}

// ---- hop access ls ----

// AccessView is one record in hop access ls --json.
type AccessView struct {
	Label       string             `json:"label"`
	RecordID    string             `json:"record_id"`
	Fingerprint string             `json:"fingerprint"`
	Options     string             `json:"options"`
	By          string             `json:"by"`
	ByRetired   bool               `json:"by_retired_device"`
	Mark        string             `json:"mark,omitempty"`
	Targets     []AccessTargetView `json:"targets"`
}

// AccessTargetView is one target in hop access ls --json.
type AccessTargetView struct {
	Host       string `json:"host"`
	HostID     string `json:"host_id"`
	User       string `json:"user"`
	Binding    string `json:"binding"`
	State      string `json:"state"`
	Gen        uint64 `json:"gen"`
	Error      string `json:"error,omitempty"`
	Diagnostic string `json:"diagnostic,omitempty"`
}

func runAccessLs(ctx context.Context, e *Env, args []string) error {
	fs := newFlags(e, "access ls", commands["access"].usage)
	asJSON := fs.Bool("json", false, "print the records as JSON")
	pos, _, err := parseFlags(fs, args)
	if err != nil {
		return err
	}
	v := &accessVault{e: e}
	al, err := v.list(ctx)
	if err != nil {
		return err
	}
	l, err := listAll(ctx, e)
	if err != nil {
		return err
	}
	ix := hostIndex{l.Hosts}
	var out []AccessView
	for _, a := range al.Access {
		if len(pos) > 0 && !slices.ContainsFunc(pos, func(p string) bool { return model.NameKey(p) == model.NameKey(a.Label) }) {
			continue
		}
		av := AccessView{Label: a.Label, RecordID: a.RecordID.String(), Fingerprint: a.Fingerprint, Options: access.Render(a.Options),
			By: a.By.String(), ByRetired: slices.Contains(al.Retired, a.By.String()), Mark: string(al.Marks[a.ItemID.String()])}
		for _, t := range a.Targets {
			tv := AccessTargetView{Host: ix.name(t.HostItemID), HostID: t.HostItemID.String(), User: t.User, Binding: t.ServerKeyFP,
				State: t.State, Gen: t.Gen, Error: t.Error}
			h, ok := ix.byID(t.HostItemID)
			switch {
			case t.State == model.AccessAbandoned:
				tv.Diagnostic = "abandoned: the line may remain on the machine that presents " + t.ServerKeyFP
			case t.State == model.AccessRemoved && t.SameMachine != nil:
				var names []string
				for _, id := range t.SameMachine.HostItemIDs {
					names = append(names, ix.name(id))
				}
				tv.Diagnostic = "removed (on your statement that " + strings.Join(names, ", ") + " reach the same machine)"
			case model.AccessTerminal(t.State):
			case !ok:
				tv.Diagnostic = "host deleted; only hop access rm " + a.Label + " --abandon " + t.HostItemID.String() + " applies"
			case boundPin(h, t.ServerKeyFP) == nil:
				tv.Diagnostic = unbound(t, a.Label, h.Name)
			}
			av.Targets = append(av.Targets, tv)
		}
		out = append(out, av)
	}
	// Notes of checkpoints that revoked the devices which last changed
	// records (§7.5): shown here, on stderr, and then acknowledged. Until
	// then hop status shows them too, after every restart.
	if len(al.Reviews) > 0 || al.ReviewsEvicted > 0 {
		ack := daemon.AccessReviewAckParams{Evicted: al.ReviewsEvicted}
		for _, r := range al.Reviews {
			fmt.Fprintf(e.Stderr, "note: %s\n", oneLine(r.Text))
			ack.IDs = append(ack.IDs, r.ID)
		}
		if al.ReviewsEvicted > 0 {
			fmt.Fprintf(e.Stderr, "note: %d older notes of hop access records to review were dropped before they were shown\n", al.ReviewsEvicted)
		}
		if err := call(ctx, e, daemon.OpAccessReviewAck, ack, nil); err != nil {
			fmt.Fprintf(e.Stderr, "warning: could not mark these notes as shown (%v); they will be shown again\n", err)
		}
	}
	if *asJSON {
		if out == nil {
			out = []AccessView{}
		}
		return printJSON(e, out)
	}
	if len(out) == 0 {
		e.printf("no hop access records\n")
		return nil
	}
	for _, av := range out {
		e.printf("%s  %s", oneLine(av.Label), av.Fingerprint)
		if av.Options != "" {
			e.printf("  %s", oneLine(av.Options))
		}
		if av.Mark != "" {
			e.printf("  (%s)", av.Mark)
		}
		if av.ByRetired {
			e.printf("  last changed by a device that was revoked or retired (%s)", av.By)
		}
		e.printf("\n")
		for _, t := range av.Targets {
			e.printf("  %s  %s@  %s  %s (gen %d)", oneLine(t.Host), oneLine(t.User), t.Binding, t.State, t.Gen)
			if t.Error != "" {
				e.printf(": %s", oneLine(t.Error))
			}
			if t.Diagnostic != "" {
				e.printf("  [%s]", oneLine(t.Diagnostic))
			}
			e.printf("\n")
		}
	}
	return nil
}
