package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"slices"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/dalyem/hopkey/internal/daemon"
	"github.com/dalyem/hopkey/internal/merge"
	"github.com/dalyem/hopkey/internal/model"
	"github.com/dalyem/hopkey/internal/shellcmd"
)

// The daemon syncs on its own (design: "Automatic sync"). hop sync is an
// escape hatch for debugging and scripts, and hop sync resolve settles a
// change the daemon held because it conflicts with the server.

const syncHelp = `hop sync pulls and pushes now and prints the result. You never need it:
the daemon syncs on its own while this device is signed in. It is an escape
hatch for debugging and scripts. It exits non-zero when sync is stopped,
this device was revoked, or the server can't be reached.

hop sync resolve settles a queued change the daemon held because it
conflicts with the server. Without a choice it lists the held change and its
proposals; on a terminal it asks what to do. With --json, or when stdin or
stdout is not a terminal, it never asks: keep-mine and edit need --confirm
with the proposal's token, and take-theirs needs --yes. --edit starts from
the server's current version, so --set names only what you change in it.`

// SyncReport is the --json shape of hop sync: the daemon's sync status, with
// the error when the sync could not run. synced_at is always present (null
// when there has been no successful pull since the daemon started).
type SyncReport struct {
	*daemon.SyncStatusResult
	Error *daemon.Error `json:"error,omitempty"`
}

func runSync(ctx context.Context, e *Env, args []string) error {
	if len(args) > 0 && args[0] == "resolve" {
		return runSyncResolve(ctx, e, args[1:])
	}
	fs := newFlags(e, "sync", commands["sync"].usage)
	asJSON := fs.Bool("json", false, "print the sync status as JSON")
	help := fs.Usage
	fs.Usage = func() {
		// After a parse error the flag package calls Usage too; the error
		// is reported by parseFlags, and only -h gets the help.
		if out, ok := fs.Output().(*flagOut); ok && out.Len() > 0 {
			return
		}
		help()
		fmt.Fprintf(e.Stderr, "\n%s\n", syncHelp)
	}
	pos, _, err := parseFlags(fs, args)
	if err != nil {
		return err
	}
	if len(pos) != 0 {
		fs.Usage()
		return failf("unknown sync subcommand %q (resolve)", pos[0])
	}
	c, err := connect(ctx, e)
	if err != nil {
		return err
	}
	defer c.Close()

	var st daemon.SyncStatusResult
	nowErr := cleanErr(c.Call(ctx, daemon.OpSyncNow, nil, &st))
	if daemon.IsCode(nowErr, daemon.CodeLocalOnly) {
		return failf("this vault is local-only, so there is nothing to sync")
	}
	if nowErr != nil {
		// Report where sync stands all the same, then fail.
		st = daemon.SyncStatusResult{}
		if err := c.Call(ctx, daemon.OpSyncStatus, nil, &st); err != nil {
			return nowErr
		}
	}
	if *asJSON {
		rep := SyncReport{SyncStatusResult: &st}
		if nowErr != nil {
			rep.Error = &daemon.Error{Code: errCode(nowErr), Message: nowErr.Error()}
		}
		if err := printJSON(e, rep); err != nil {
			return err
		}
	} else {
		printSyncBlock(e, e.Stdout, &st, syncBlockOpts{})
	}
	if nowErr != nil {
		return failf("sync did not run: %v", nowErr)
	}
	switch st.State {
	case daemon.SyncHalted, daemon.SyncRevoked, daemon.SyncBackingOff, daemon.SyncLoggedOut:
		return failf("sync is not working (%s); see above", st.State)
	}
	return nil
}

// errCode is the daemon's code for err, or "" for an error of another kind.
func errCode(err error) string {
	var de *daemon.Error
	if errors.As(err, &de) {
		return de.Code
	}
	return ""
}

// ---- the sync block of hop status and hop sync ----

type syncBlockOpts struct {
	device   string          // this device's ID, if known
	skipHead bool            // the head was already printed
	shown    map[string]bool // warnings already printed
}

// stateText says what a sync state means.
func stateText(s *daemon.SyncStatusResult) string {
	switch s.State {
	case daemon.SyncOff:
		return "off (this vault is not signed in to a server)"
	case daemon.SyncLocked:
		return "paused while the vault is locked (hop unlock)"
	case daemon.SyncStarting:
		return "starting"
	case daemon.SyncOnline:
		return "online"
	case daemon.SyncBackingOff:
		return "retrying: the last attempt failed"
	case daemon.SyncHalted:
		if s.Equivocation {
			return "stopped: the server showed two different histories (equivocation)"
		}
		return "stopped"
	case daemon.SyncRevoked:
		return "stopped: this device was revoked"
	case daemon.SyncLoggingOut:
		return "logging out"
	case daemon.SyncLoggedOut:
		return "logged out"
	}
	return oneLine(s.State)
}

// when formats t for people: the time, and how long ago it was.
func (e *Env) when(t time.Time) string {
	s := t.Local().Format(time.RFC3339)
	d := e.now().Sub(t)
	switch {
	case d < 0:
		return s
	case d < time.Minute:
		return s + " (just now)"
	case d < time.Hour:
		return fmt.Sprintf("%s (%dm ago)", s, int(d/time.Minute))
	case d < 48*time.Hour:
		return fmt.Sprintf("%s (%dh ago)", s, int(d/time.Hour))
	}
	return fmt.Sprintf("%s (%dd ago)", s, int(d/(24*time.Hour)))
}

// printSyncBlock writes the sync status as "label: value" lines. Every
// string in it came from the daemon, and much of that from the server
// (errors, the halt reason), so each goes through oneLine.
func printSyncBlock(e *Env, w io.Writer, s *daemon.SyncStatusResult, o syncBlockOpts) {
	line := func(label, format string, args ...any) {
		fmt.Fprintf(w, "%-14s%s\n", label+":", fmt.Sprintf(format, args...))
	}
	line("sync", "%s", stateText(s))
	if s.Server != "" {
		line("server", "%s", oneLine(s.Server))
	}
	if s.Email != "" {
		line("account", "%s", oneLine(s.Email))
	}
	if o.device != "" {
		line("device", "%s", oneLine(o.device))
	}
	if s.Head != nil && !o.skipHead {
		line("log head", "seq %s", oneLine(s.Head.Short()))
	}
	if s.State != daemon.SyncOff {
		if s.SyncedAt != nil {
			line("last sync", "%s", e.when(*s.SyncedAt))
		} else {
			line("last sync", "none since the daemon started")
		}
	}
	if s.Pending > 0 || s.Held > 0 {
		q := fmt.Sprintf("%d pending, %d held", s.Pending, s.Held)
		if s.Held > 0 {
			q += " (hop sync resolve)"
		}
		line("queued", "%s", q)
	}
	if s.LastError != "" {
		at := ""
		if s.LastErrorAt != nil {
			at = " at " + e.when(*s.LastErrorAt)
		}
		line("last error", "%s%s", oneLine(s.LastError), at)
	}
	if b := s.Backoff; b != nil && s.State == daemon.SyncBackingOff {
		line("next try", "%s (attempt %d)", e.when(b.RetryAt), b.Attempt)
	}
	if r := s.ServerRetirement; r != nil && r.Wiped {
		line("retirement", "verified: this device was %s at seq %d, and its copy of the vault was wiped", oneLine(r.How), r.Seq)
	} else if r != nil {
		line("retirement", "server-reported, unverified: the server says this device was %s at seq %d; the vault stays locked", oneLine(r.How), r.Seq)
	}
	for _, msg := range s.Warnings {
		if o.shown[msg] {
			continue
		}
		line("warning", "%s", oneLine(msg))
	}
}

// longOutage is how long sync may fail before interactive commands say so.
const longOutage = 10 * time.Minute

// syncNotice prints one line to stderr when sync has been failing for more
// than longOutage, with the time of the last sync, and one when a queued
// change is held. Interactive commands call it; a failure to ask is
// ignored, since the command does not depend on it.
func syncNotice(ctx context.Context, e *Env) {
	c, err := dialExisting(ctx, e)
	if err != nil || c == nil {
		return
	}
	defer c.Close()
	var st daemon.StatusResult
	if err := c.Call(ctx, daemon.OpStatus, nil, &st); err != nil || st.Sync == nil {
		return
	}
	if msg := outageNotice(e, st.Sync, st.StartedAt); msg != "" {
		fmt.Fprintf(e.Stderr, "hop: %s\n", msg)
	}
	if st.Sync.Held > 0 {
		fmt.Fprintf(e.Stderr, "hop: %d queued change(s) held, and nothing queued behind them is sent: run hop sync resolve\n", st.Sync.Held)
	}
}

// outageNotice is the long-outage line, or "". The outage is measured from
// the last successful pull, or from the daemon's start when there has
// been none since.
func outageNotice(e *Env, s *daemon.SyncStatusResult, started time.Time) string {
	if s.State != daemon.SyncBackingOff {
		return ""
	}
	since := started
	if s.SyncedAt != nil {
		since = *s.SyncedAt
	}
	if since.IsZero() || e.now().Sub(since) <= longOutage {
		return ""
	}
	if s.SyncedAt == nil {
		return safef("sync has been failing since the daemon started at %s; the vault may be out of date", e.when(started))
	}
	return safef("sync has been failing; last sync %s, so the vault may be out of date", e.when(*s.SyncedAt))
}

// ---- hop sync resolve ----

const resolveUsage = "hop sync resolve [N] [--keep-mine [--confirm TOKEN] | --edit --set FIELD=VALUE... [--new-id ID] [--confirm TOKEN] | --take-theirs [--yes] | --retry] [--json]"

func runSyncResolve(ctx context.Context, e *Env, args []string) error {
	fs := newFlags(e, "sync resolve", resolveUsage)
	keepMine := fs.Bool("keep-mine", false, "write your change over the server's (needs the proposal's --confirm token)")
	edit := fs.Bool("edit", false, "write an edited version: the server's, or yours when the server no longer has the item, with --set applied (hosts and snippets; needs the --confirm token)")
	takeTheirs := fs.Bool("take-theirs", false, "drop your change and keep the server's")
	retry := fs.Bool("retry", false, "try the change again as it is")
	token := fs.String("confirm", "", "the confirmation token of the proposal to apply")
	newID := fs.String("new-id", "", "for --edit: the new_id of the proposal the token confirms")
	yes := fs.Bool("yes", false, "take theirs without asking")
	asJSON := fs.Bool("json", false, "print the held changes, the proposal or the result as JSON")
	var sets stringList
	fs.Var(&sets, "set", "for --edit: FIELD=VALUE to change in your version (repeatable)")
	pos, _, err := parseFlags(fs, args)
	if err != nil {
		return err
	}
	if len(pos) > 1 {
		fs.Usage()
		return failf("expected at most one change number")
	}
	var n uint64
	haveN := len(pos) == 1
	if haveN {
		if n, err = strconv.ParseUint(pos[0], 10, 64); err != nil {
			return failf("%q is not a change number", pos[0])
		}
	}
	choice := ""
	for _, f := range []struct {
		set  bool
		name string
	}{{*keepMine, daemon.ChoiceKeepMine}, {*edit, daemon.ChoiceEdit}, {*takeTheirs, daemon.ChoiceTakeTheirs}, {*retry, daemon.ChoiceRetry}} {
		if !f.set {
			continue
		}
		if choice != "" {
			return failf("choose one of --keep-mine, --edit, --take-theirs and --retry")
		}
		choice = f.name
	}
	if *token != "" && choice != daemon.ChoiceKeepMine && choice != daemon.ChoiceEdit {
		return failf("--confirm goes with --keep-mine or --edit")
	}
	if (sets.set || *newID != "") && choice != daemon.ChoiceEdit {
		return failf("--set and --new-id go with --edit")
	}

	c, err := connect(ctx, e)
	if err != nil {
		return err
	}
	defer c.Close()
	// Only a terminal session asks anything: with --json, or stdin or
	// stdout redirected, every write needs its flag (--confirm, --yes).
	r := &resolver{ctx: ctx, e: e, c: c, asJSON: *asJSON, interactive: e.StdinTTY && e.StdoutTTY && !*asJSON}
	held, err := r.held()
	if err != nil {
		return err
	}
	if choice == "" && (!r.interactive || len(held) == 0) {
		return r.list(held)
	}
	if !haveN {
		// A choice applies to the change named, never to whatever happens
		// to be held when it runs; only a terminal session that shows the
		// change first may leave N out.
		if !r.interactive || (choice != "" && len(held) != 1) {
			return failf("name the change: hop sync resolve N --%s (see hop sync resolve for N)", choice)
		}
		n = held[0].N
	}
	h := findHeld(held, n)
	if h == nil {
		return failf("change %d is not held; run hop sync resolve to see what is", n)
	}
	if choice == "" {
		return r.ask(h)
	}
	return r.apply(h, choice, request{token: *token, sets: sets.vals, newID: *newID, yes: *yes})
}

type resolver struct {
	ctx         context.Context
	e           *Env
	c           *daemon.Client
	asJSON      bool
	interactive bool
}

// request is what the command line said about one resolution.
type request struct {
	token string
	sets  []string
	newID string
	yes   bool
}

func findHeld(held []daemon.HeldChange, n uint64) *daemon.HeldChange {
	for i := range held {
		if held[i].N == n {
			return &held[i]
		}
	}
	return nil
}

// held lists the held changes, without secrets. The daemon leaves a key's
// private half and a credential's password out already; this keeps it so
// should that ever change.
func (r *resolver) held() ([]daemon.HeldChange, error) {
	var res daemon.SyncHeldResult
	if err := r.c.Call(r.ctx, daemon.OpSyncHeld, nil, &res); err != nil {
		if daemon.IsCode(err, daemon.CodeLocalOnly) {
			return nil, failf("this vault is local-only, so nothing is ever held")
		}
		return nil, cleanErr(err)
	}
	for i := range res.Held {
		h := &res.Held[i]
		h.Seen, h.Want, h.Current = stripSecrets(h.Seen), stripSecrets(h.Want), stripSecrets(h.Current)
		if h.KeepMine != nil {
			h.KeepMine.Seen, h.KeepMine.Want = stripSecrets(h.KeepMine.Seen), stripSecrets(h.KeepMine.Want)
		}
	}
	if res.Held == nil {
		res.Held = []daemon.HeldChange{}
	}
	return res.Held, nil
}

// secretMembers never leave the daemon; stripSecrets drops them if they do.
var secretMembers = []string{"private_key", "password"}

func stripSecrets(raw json.RawMessage) json.RawMessage {
	m, ok := members(raw)
	if !ok {
		return raw
	}
	changed := false
	for _, k := range secretMembers {
		if _, ok := m[k]; ok {
			delete(m, k)
			changed = true
		}
	}
	if !changed {
		return raw
	}
	b, err := json.Marshal(m)
	if err != nil {
		return json.RawMessage("null")
	}
	return b
}

// members decodes an item's plaintext JSON; ok is false for null or
// anything that is not an object.
func members(raw json.RawMessage) (map[string]json.RawMessage, bool) {
	var m map[string]json.RawMessage
	if len(raw) == 0 || json.Unmarshal(raw, &m) != nil || m == nil {
		return nil, false
	}
	return m, true
}

// list prints the held changes and how to resolve each. It applies
// nothing. The JSON carries each keep-mine proposal with its token.
func (r *resolver) list(held []daemon.HeldChange) error {
	if r.asJSON {
		return printJSON(r.e, daemon.SyncHeldResult{Held: held})
	}
	if len(held) == 0 {
		r.e.printf("nothing is held\n")
		return nil
	}
	for i := range held {
		h := &held[i]
		r.describe(h)
		if h.KeepMine != nil {
			r.showProposal(h, h.KeepMine)
		}
		if len(h.Choices) == 0 {
			continue
		}
		r.e.printf("to resolve it, run one of:\n")
		for _, ch := range h.Choices {
			switch ch {
			case daemon.ChoiceKeepMine:
				if h.KeepMine != nil {
					r.e.printf("  hop sync resolve %d --keep-mine --confirm %s\n", h.N, oneLine(h.KeepMine.Confirm))
				}
			case daemon.ChoiceEdit:
				r.e.printf("  hop sync resolve %d --edit --set FIELD=VALUE...   (prints a proposal to confirm)\n", h.N)
			case daemon.ChoiceTakeTheirs:
				r.e.printf("  hop sync resolve %d --take-theirs --yes\n", h.N)
			case daemon.ChoiceRetry:
				r.e.printf("  hop sync resolve %d --retry\n", h.N)
			}
		}
	}
	return nil
}

// causeText says why a change is held, for people.
func causeText(c merge.Cause) string {
	switch c {
	case merge.CauseGuardedConflict:
		return "this device and another both changed its protected fields"
	case merge.CauseNotLive:
		return "another device deleted it"
	case merge.CauseRuleFailure:
		return "applied to the server's version, it would break a vault rule"
	case merge.CauseIDTaken:
		return "its ID is already taken on the server"
	case merge.CauseDeleteChanged:
		return "you deleted it, but another device changed it since"
	}
	return oneLine(string(c))
}

// itemName is the name in an item's plaintext, or "".
func itemName(raws ...json.RawMessage) string {
	for _, raw := range raws {
		if m, ok := members(raw); ok {
			var s string
			if json.Unmarshal(m["name"], &s) == nil && s != "" {
				return s
			}
		}
	}
	return ""
}

// describe prints one held change: what it does, why it is held, and the
// fields that differ between where it started, this device's version and
// the server's.
func (r *resolver) describe(h *daemon.HeldChange) {
	e := r.e
	name := itemName(h.Want, h.Current, h.Seen)
	e.printf("change %d is held: %s %s %q (%s)\n", h.N, oneLine(string(h.Action)), oneLine(string(h.Type)), oneLine(name), oneLine(h.ItemID))
	if h.Import {
		e.printf("  it comes from a login merge: finish it with hop auth merge\n")
	}
	switch {
	case h.Hold == nil:
		e.printf("  why:     nothing holds it any more; --retry sends it\n")
	default:
		e.printf("  why:     %s\n", causeText(h.Hold.Cause))
		if len(h.Hold.Local) > 0 || len(h.Hold.Remote) > 0 {
			e.printf("  changed: here %s; on the server %s\n", dash(joinOne(h.Hold.Local, ", ")), dash(joinOne(h.Hold.Remote, ", ")))
		}
		if h.Hold.Reason != "" {
			e.printf("  reason:  %s\n", oneLine(h.Hold.Reason))
		}
	}
	fields := differing(h.Seen, h.Want, h.Current)
	if len(fields) > 0 {
		tw := tabwriter.NewWriter(e.Stdout, 0, 4, 2, ' ', 0)
		fmt.Fprintln(tw, "  FIELD\tBEFORE\tYOURS\tSERVER")
		for _, f := range fields {
			fmt.Fprintf(tw, "  %s\t%s\t%s\t%s\n", oneLine(f), memberText(h.Seen, f), memberText(h.Want, f), memberText(h.Current, f))
		}
		tw.Flush()
	}
	if h.KeepMineRefused != "" {
		e.printf("  keep mine is not offered: %s\n", oneLine(h.KeepMineRefused))
	}
	e.printf("  choices: %s\n", dash(joinOne(h.Choices, ", ")))
}

// headerMembers are the item header, which every version has its own of.
var headerMembers = []string{"v", "item_id", "type", "item_version"}

// differing lists the non-header members whose values are not the same in
// every one of raws, sorted.
func differing(raws ...json.RawMessage) []string {
	var maps []map[string]json.RawMessage
	keys := map[string]bool{}
	for _, raw := range raws {
		m, _ := members(raw)
		maps = append(maps, m)
		for k := range m {
			keys[k] = true
		}
	}
	var out []string
	for k := range keys {
		if slices.Contains(headerMembers, k) || slices.Contains(secretMembers, k) {
			continue
		}
		first := compact(maps[0][k])
		for _, m := range maps[1:] {
			if compact(m[k]) != first {
				out = append(out, k)
				break
			}
		}
	}
	slices.Sort(out)
	return out
}

func compact(raw json.RawMessage) string {
	var b bytes.Buffer
	if len(raw) == 0 || json.Compact(&b, raw) != nil {
		return string(raw)
	}
	return b.String()
}

// memberText shows one member of an item for a table cell: a string as
// it is, anything else (a list included) as compact JSON, through exact.
// These cells are what keep-mine and edit ask the user to approve, so
// nothing is cut and no two values look alike: a list keeps its quotes,
// so an element with ", " in it is not two elements. An absent item or
// member is "-".
func memberText(raw json.RawMessage, member string) string {
	m, ok := members(raw)
	if !ok {
		return "-"
	}
	v, ok := m[member]
	if !ok || compact(v) == "null" {
		return "-"
	}
	var s string
	if json.Unmarshal(v, &s) == nil {
		if s == "" {
			return `""`
		}
		return exact(s)
	}
	return exact(compact(v))
}

// showProposal prints what a keep-mine or edit would write: for a delete,
// that it deletes; otherwise the item's guarded group (every member that
// is not free text) as it would be, beside the server's.
func (r *resolver) showProposal(h *daemon.HeldChange, p *daemon.Proposal) {
	e := r.e
	what := "keep mine"
	if p.Choice == daemon.ChoiceEdit {
		what = "your edit"
	}
	if p.Action == merge.ActionDelete {
		e.printf("%s deletes %s %q (%s)\n", what, oneLine(string(p.Type)), oneLine(itemName(p.Seen, h.Current)), oneLine(p.ItemID))
		return
	}
	id := p.ItemID
	if p.NewID != "" {
		id = p.NewID
	}
	e.printf("%s writes %s %s %q (%s); its protected fields would be:\n", what, oneLine(string(p.Action)), oneLine(string(p.Type)), oneLine(itemName(p.Want)), oneLine(id))
	m, _ := members(p.Want)
	var guarded []string
	for k := range m {
		if merge.IsGuarded(p.Type, k) && !slices.Contains(secretMembers, k) {
			guarded = append(guarded, k)
		}
	}
	slices.Sort(guarded)
	tw := tabwriter.NewWriter(e.Stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "  FIELD\tWOULD BE\tSERVER NOW")
	for _, k := range guarded {
		mark := ""
		if compact(m[k]) != compactMember(h.Current, k) {
			mark = "  (changes)"
		}
		fmt.Fprintf(tw, "  %s\t%s\t%s%s\n", oneLine(k), memberText(p.Want, k), memberText(h.Current, k), mark)
	}
	tw.Flush()
}

func compactMember(raw json.RawMessage, k string) string {
	m, _ := members(raw)
	return compact(m[k])
}

// ask resolves h interactively.
func (r *resolver) ask(h *daemon.HeldChange) error {
	r.describe(h)
	keys := map[string]string{"k": daemon.ChoiceKeepMine, "e": daemon.ChoiceEdit, "t": daemon.ChoiceTakeTheirs, "r": daemon.ChoiceRetry}
	var offered []string
	for _, k := range []string{"k", "e", "t", "r"} {
		if slices.Contains(h.Choices, keys[k]) {
			offered = append(offered, fmt.Sprintf("%s) %s", k, keys[k]))
		}
	}
	if len(offered) == 0 {
		return failf("nothing can resolve change %d here", h.N)
	}
	fmt.Fprintf(r.e.Stderr, "%s, or q) leave it held: ", strings.Join(offered, ", "))
	line, err := readLine(r.e.Stdin)
	if err != nil && line == "" {
		return failf("no choice made; change %d stays held", h.N)
	}
	choice, ok := keys[strings.ToLower(strings.TrimSpace(line))]
	if !ok || !slices.Contains(h.Choices, choice) {
		return failf("change %d stays held", h.N)
	}
	return r.apply(h, choice, request{})
}

// maxStale is how many times an interactive resolution fetches a fresh
// proposal after the one shown went stale before giving up.
const maxStale = 3

// apply carries out choice for h. keep-mine and edit write only with the
// proposal's token: from --confirm, or, on a terminal, after the user saw
// the proposal and said yes. Without either they print the proposal and
// apply nothing.
func (r *resolver) apply(h *daemon.HeldChange, choice string, req request) error {
	if !slices.Contains(h.Choices, choice) {
		msg := safef("%s is not offered for change %d (offered: %s)", choice, h.N, dash(joinOne(h.Choices, ", ")))
		if choice == daemon.ChoiceKeepMine && h.KeepMineRefused != "" {
			msg += safef(": %s", h.KeepMineRefused)
		}
		return failf("%s", msg)
	}
	params := daemon.SyncResolveParams{N: h.N, Choice: choice}
	switch choice {
	case daemon.ChoiceTakeTheirs:
		if !req.yes && !r.interactive {
			// --json, or stdin or stdout not a terminal: nothing may
			// prompt, even when stdin could answer.
			return failf("take-theirs drops your change %d: pass --yes to confirm (it can't be asked here: --json, or no terminal)", h.N)
		}
		ok, err := confirm(r.e, req.yes, safef("Drop your change %d and keep the server's version?", h.N))
		if err != nil {
			return err
		}
		if !ok {
			return failf("change %d stays held", h.N)
		}
	case daemon.ChoiceKeepMine, daemon.ChoiceEdit:
		for attempt := 1; ; attempt++ {
			p, edited, err := r.propose(h, choice, req)
			if err != nil {
				return err
			}
			params.Edited, params.NewID, params.Confirm = edited, p.NewID, req.token
			if choice == daemon.ChoiceEdit && req.newID != "" {
				params.NewID = req.newID
			}
			if req.token == "" {
				if !r.interactive {
					return r.unconfirmed(h, p, req)
				}
				r.showProposal(h, p)
				ok, err := confirm(r.e, false, "Write this?")
				if err != nil {
					return err
				}
				if !ok {
					return failf("change %d stays held", h.N)
				}
				params.Confirm = p.Confirm
			}
			res, err := r.resolve(params)
			if !daemon.IsCode(err, daemon.CodeStaleConfirm) {
				return r.report(h, choice, res, err)
			}
			if !r.interactive || req.token != "" {
				return failf("the proposal changed since its token was issued (something about the item changed); nothing was written. Run hop sync resolve %d again for a new proposal and token", h.N)
			}
			if attempt == maxStale {
				return failf("the proposal kept changing while you confirmed it; nothing was written. Try again with hop sync resolve")
			}
			fmt.Fprintln(r.e.Stderr, "hop: the change was updated while you looked at it; here it is again")
			held, err := r.held()
			if err != nil {
				return err
			}
			if h = findHeld(held, h.N); h == nil {
				return failf("change %d is no longer held; nothing was written", params.N)
			}
			r.describe(h)
			if !slices.Contains(h.Choices, choice) {
				return failf("%s is no longer offered for change %d", choice, h.N)
			}
		}
	}
	res, err := r.resolve(params)
	return r.report(h, choice, res, err)
}

// propose returns the proposal for keep-mine (from the held listing) or
// for edit (from the daemon, for the edited item).
func (r *resolver) propose(h *daemon.HeldChange, choice string, req request) (*daemon.Proposal, json.RawMessage, error) {
	if choice == daemon.ChoiceKeepMine {
		if h.KeepMine == nil {
			return nil, nil, failf("keep mine is not offered for change %d: %s", h.N, orUnknown(h.KeepMineRefused))
		}
		return h.KeepMine, nil, nil
	}
	sets := req.sets
	if len(sets) == 0 && r.interactive {
		var err error
		if sets, err = r.readSets(h); err != nil {
			return nil, nil, err
		}
	}
	if len(sets) == 0 {
		return nil, nil, failf("--edit needs at least one --set FIELD=VALUE")
	}
	edited, err := editItem(h, sets)
	if err != nil {
		return nil, nil, err
	}
	params := daemon.SyncResolveParams{N: h.N, Choice: daemon.ChoiceEdit, Edited: edited, NewID: req.newID, Propose: true}
	res, err := r.resolve(params)
	if err != nil {
		return nil, nil, r.resolveError(h.N, err)
	}
	if res.Proposal == nil {
		return nil, nil, failf("the daemon returned no proposal for the edit")
	}
	p := res.Proposal
	p.Seen, p.Want = stripSecrets(p.Seen), stripSecrets(p.Want)
	return p, edited, nil
}

// readSets asks for FIELD=VALUE lines on the terminal, up to an empty one.
func (r *resolver) readSets(h *daemon.HeldChange) ([]string, error) {
	fmt.Fprintln(r.e.Stderr, "The edit starts from the server's version (SERVER above), or yours when the server no longer has the item.")
	fmt.Fprintln(r.e.Stderr, "Change it: one FIELD=VALUE per line (lists comma-separated), an empty line to finish.")
	var out []string
	for {
		fmt.Fprint(r.e.Stderr, "> ")
		line, err := readLine(r.e.Stdin)
		line = strings.TrimSpace(line)
		if line == "" {
			return out, nil
		}
		out = append(out, line)
		if err != nil {
			return out, nil
		}
	}
}

// editItem applies FIELD=VALUE edits to the version of the item an edit
// starts from (merge.EditStart): for a put of a live item, the server's
// version as it is now (current), so whatever another device changed and
// --set does not name is kept; for a create, or a put of an item the
// server no longer has, this device's version. It returns the edited
// plaintext, which the daemon turns into a proposal. A value takes the type
// of the member it replaces: a string, a number, a boolean, or a list of
// strings given comma-separated. Only members the item already has can be
// set, and never the header.
func editItem(h *daemon.HeldChange, sets []string) (json.RawMessage, error) {
	start, err := editStart(h)
	if err != nil {
		return nil, err
	}
	base, ok := members(start)
	if !ok {
		return nil, failf("change %d has no version of the item to edit", h.N)
	}
	for _, s := range sets {
		k, v, found := strings.Cut(s, "=")
		k = strings.TrimSpace(k)
		if !found || k == "" {
			return nil, failf("--set %q: want FIELD=VALUE", s)
		}
		if slices.Contains(headerMembers, k) {
			return nil, failf("--set %s: the item header can't be edited", k)
		}
		old, ok := base[k]
		if !ok {
			var names []string
			for n := range base {
				if !slices.Contains(headerMembers, n) {
					names = append(names, n)
				}
			}
			slices.Sort(names)
			return nil, failf("--set %s: the %s has no such field (fields: %s)", k, string(h.Type), joinOne(names, ", "))
		}
		nv, err := typedLike(old, v)
		if err != nil {
			return nil, failf("--set %s: %v", k, err)
		}
		base[k] = nv
	}
	b, err := json.Marshal(base)
	if err != nil {
		return nil, err
	}
	return b, nil
}

// editStart is the plaintext merge.EditStart picks for h: S (the server's
// current version) or this device's want, by the hold's row.
func editStart(h *daemon.HeldChange) (json.RawMessage, error) {
	if h.Hold == nil {
		return nil, failf("nothing holds change %d any more; send it as it is with --retry", h.N)
	}
	id, err := model.ParseID(h.ItemID)
	if err != nil {
		return nil, failf("change %d: %v", h.N, err)
	}
	parse := func(raw json.RawMessage) (*merge.Item, error) {
		if _, ok := members(raw); !ok {
			return nil, nil
		}
		return merge.ParseItem(raw)
	}
	held := merge.Intent{Action: h.Action, ItemID: id, Type: h.Type}
	var s *merge.Item
	if held.Seen, err = parse(h.Seen); err == nil {
		if held.Want, err = parse(h.Want); err == nil {
			s, err = parse(h.Current)
		}
	}
	if err != nil {
		return nil, failf("change %d: %v", h.N, err)
	}
	start, err := merge.EditStart(held, h.Hold.Cause, s)
	if err != nil {
		return nil, failf("--edit can't start for change %d: %v", h.N, err)
	}
	return start.Plaintext(), nil
}

// typedLike encodes v as JSON of the same kind as old.
func typedLike(old json.RawMessage, v string) (json.RawMessage, error) {
	o := compact(old)
	switch {
	case strings.HasPrefix(o, `"`), o == "null":
		return json.Marshal(v)
	case strings.HasPrefix(o, "["):
		items := []string{}
		for _, p := range strings.Split(v, ",") {
			if p = strings.TrimSpace(p); p != "" {
				items = append(items, p)
			}
		}
		return json.Marshal(items)
	case o == "true" || o == "false":
		b, err := strconv.ParseBool(v)
		if err != nil {
			return nil, fmt.Errorf("want true or false")
		}
		return json.Marshal(b)
	case strings.HasPrefix(o, "{"):
		return nil, fmt.Errorf("this field is an object and can't be set here; change it after resolving")
	default:
		n, err := strconv.ParseUint(v, 10, 64)
		if err != nil {
			return nil, fmt.Errorf("want a number")
		}
		return json.Marshal(n)
	}
}

// unconfirmed prints the proposal without applying it, and fails: the
// caller asked for keep-mine or edit without a token and there is no
// terminal to confirm on.
func (r *resolver) unconfirmed(h *daemon.HeldChange, p *daemon.Proposal, req request) error {
	if r.asJSON {
		if err := printJSON(r.e, map[string]any{"proposal": p}); err != nil {
			return err
		}
	} else {
		r.showProposal(h, p)
		cmd := fmt.Sprintf("hop sync resolve %d --keep-mine --confirm %s", h.N, oneLine(p.Confirm))
		if p.Choice == daemon.ChoiceEdit {
			cmd = fmt.Sprintf("hop sync resolve %d --edit", h.N)
			for _, s := range req.sets {
				cmd += " --set " + shellcmd.Quote(oneLine(s))
			}
			if p.NewID != "" {
				cmd += " --new-id " + oneLine(p.NewID)
			}
			cmd += " --confirm " + oneLine(p.Confirm)
		}
		r.e.printf("to write it, run:\n  %s\n", cmd)
	}
	return failf("nothing was written: %s needs --confirm with the proposal's token", p.Choice)
}

// resolve calls sync.resolve. A resolution that took effect while the ssh
// config could not be written is a success with a warning, which it
// prints.
func (r *resolver) resolve(p daemon.SyncResolveParams) (*daemon.SyncResolveResult, error) {
	var res daemon.SyncResolveResult
	w, err := r.c.CallWarn(r.ctx, daemon.OpSyncResolve, p, &res)
	if err := changeWarning(r.e, r.asJSON, w, err); err != nil {
		return nil, err
	}
	return &res, nil
}

// resolveError explains the daemon's refusals of a resolution.
func (r *resolver) resolveError(n uint64, err error) error {
	switch {
	case daemon.IsCode(err, daemon.CodeNotHeld):
		return failf("change %d is no longer held (%v); run hop sync resolve to see what is", n, err)
	case daemon.IsCode(err, daemon.CodeStillHeld):
		return failf("change %d is still held: %v", n, err)
	case daemon.IsCode(err, daemon.CodeConfirm):
		return failf("%v; nothing was written", err)
	case daemon.IsCode(err, daemon.CodeStaleConfirm):
		return failf("the proposal changed since its token was issued; nothing was written. Run hop sync resolve %d again", n)
	}
	return err
}

// report prints the outcome of a resolution.
func (r *resolver) report(h *daemon.HeldChange, choice string, res *daemon.SyncResolveResult, err error) error {
	if err != nil {
		return r.resolveError(h.N, err)
	}
	if r.asJSON {
		return printJSON(r.e, map[string]any{"resolved": h.N, "choice": choice, "status": res.Status})
	}
	r.e.printf("change %d resolved: %s\n", h.N, choice)
	if res.Status != nil {
		printSyncBlock(r.e, r.e.Stdout, res.Status, syncBlockOpts{})
	}
	return nil
}

// markText describes an item's sync mark for hop info.
func markText(m model.Mark) string {
	switch m {
	case model.MarkPending:
		return "pending: changed here, not on the server yet"
	case model.MarkHeld:
		return "held: conflicts with the server; run hop sync resolve"
	}
	return oneLine(string(m))
}
