package cli

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"text/tabwriter"
	"unicode"
	"unicode/utf8"

	"github.com/dalyem/hopkey/internal/daemon"
	"github.com/dalyem/hopkey/internal/model"
	"github.com/dalyem/hopkey/internal/resolve"
	"github.com/dalyem/hopkey/internal/shellcmd"
	"github.com/dalyem/hopkey/internal/termpanel"
)

// Shortcuts are commands bound to one or two keys of the session panel
// that Ctrl-] opens during hop connect: choosing one types its command
// into the ssh session, then Enter unless it was added with --no-enter.
// A global shortcut is in every host's panel; a host shortcut is in its
// host's only, and there takes the place of a global one whose keys clash
// with its own (model.EffectiveShortcuts). They are their own item type,
// so hop snippet ls does not show them.

func runShortcut(ctx context.Context, e *Env, args []string) error {
	if len(args) == 0 {
		fmt.Fprintf(e.Stderr, "usage: %s\n", commands["shortcut"].usage)
		return failf("shortcut needs a subcommand: add, ls or rm")
	}
	switch args[0] {
	case "add":
		return runShortcutAdd(ctx, e, args[1:])
	case "ls":
		return runShortcutLs(ctx, e, args[1:])
	case "rm":
		return runShortcutRm(ctx, e, args[1:])
	}
	return failf("unknown shortcut subcommand %q (add, ls, rm)", args[0])
}

// ShortcutView is the --json shape of hop shortcut ls and hop shortcut
// add. Scope is "global" or "host"; Host names the host of a host
// shortcut. HiddenBy, in hop shortcut ls --host, is the keys of the
// shortcut that keeps this one out of that host's panel.
type ShortcutView struct {
	ID          string     `json:"id"`
	Keys        string     `json:"keys"`
	Scope       string     `json:"scope"`
	HostID      string     `json:"host_id,omitempty"`
	Host        string     `json:"host,omitempty"`
	Name        string     `json:"name"`
	Command     string     `json:"command"`
	Enter       bool       `json:"enter"`
	Description string     `json:"description"`
	HiddenBy    string     `json:"hidden_by,omitempty"`
	Mark        model.Mark `json:"mark,omitempty"` // pending or held, as for hosts
}

func shortcutView(s model.Shortcut, hosts []model.Host, marks map[string]model.Mark) ShortcutView {
	v := ShortcutView{
		ID: s.ItemID.String(), Keys: s.Keys, Scope: "global", Name: s.Name, Command: s.Command, Enter: s.Enter,
		Description: s.Description, Mark: marks[s.ItemID.String()],
	}
	if !s.HostID.IsZero() {
		v.Scope, v.HostID = "host", s.HostID.String()
		if i := slices.IndexFunc(hosts, func(h model.Host) bool { return h.ItemID == s.HostID }); i >= 0 {
			v.Host = hosts[i].Name
		}
	}
	return v
}

// shortcutHost resolves --host to a vault host, as hop add --jump does.
func shortcutHost(ctx context.Context, e *Env, target string) (*model.Host, error) {
	rr, err := resolveTarget(ctx, e, target, false)
	if err != nil {
		return nil, err
	}
	if rr.Result.Status != resolve.StatusMatched || rr.Host == nil {
		return nil, failMsg("--host: " + describeUnresolved(rr.Result))
	}
	return rr.Host, nil
}

func runShortcutAdd(ctx context.Context, e *Env, args []string) error {
	const usage = "hop shortcut add <keys> [--host H] [--name N] [--description D] [--no-enter] [--json] -- <command...>"
	fs := newFlags(e, "shortcut add", usage)
	hostRef := fs.String("host", "", "only in this host's panel (default: every host's)")
	name := fs.String("name", "", "what the panel shows (default: the command)")
	desc := fs.String("description", "", "what the shortcut does")
	noEnter := fs.Bool("no-enter", false, "type the command without pressing Enter, so you can check it first")
	asJSON := fs.Bool("json", false, "print the saved shortcut as JSON")
	helpNote(e, fs, "\nKeys are one or two printable characters, pressed one after the other in the panel that Ctrl-] opens\n"+
		"during hop connect (HOP_SHORTCUT_KEY changes that key). '?' is the panel's own. A one-key shortcut can't share\n"+
		"a panel with a two-key one it starts: a host shortcut then hides the global one in that host's panel.\n"+
		"One word after -- is the command line as typed; several words are quoted one by one. The command is one line\n"+
		"without tabs, typed into the remote shell as it is, so it has no {{parameters}}: use hop snippet for those.\n")
	pos, rest, err := parseFlags(fs, args)
	if err != nil {
		return err
	}
	if len(pos) != 1 || len(rest) == 0 {
		fs.Usage()
		return failf("expected the keys, then -- and the command")
	}
	keys := pos[0]
	// The daemon checks the same; asking here first gives the error before
	// the daemon starts.
	if err := model.CheckShortcutKeys(keys); err != nil {
		return failf("%v", err)
	}
	sc := model.Shortcut{Keys: keys, Name: *name, Command: shellcmd.Join(rest), Enter: !*noEnter, Description: *desc}
	if *hostRef != "" {
		h, err := shortcutHost(ctx, e, *hostRef)
		if err != nil {
			return err
		}
		sc.HostID = h.ItemID
	}
	var res daemon.PutShortcutResult
	if err := callChange(ctx, e, *asJSON, daemon.OpPutShortcut, daemon.PutShortcutParams{Shortcut: sc}, &res); err != nil {
		return err
	}
	saved := res.Shortcut
	if saved.ItemID.IsZero() {
		return failf("the daemon saved the shortcut %s but did not say as what; see hop shortcut ls", keys)
	}
	l, err := listAll(ctx, e)
	if err != nil {
		return err
	}
	view := shortcutView(saved, l.Hosts, nil)
	if *asJSON {
		return printJSON(e, view)
	}
	where := "global shortcut"
	if view.Scope == "host" {
		where = "shortcut of host " + oneLine(view.Host)
	}
	enter := ""
	if !saved.Enter {
		enter = " (typed without Enter)"
	}
	e.printf("added %s %s: %s%s\n", where, oneLine(saved.Keys), printable(saved.Command), enter)
	for _, c := range res.Hides {
		e.printf("in this host's panel it hides the global shortcut %s: %s\n", oneLine(c.Shortcut.Keys), printable(c.Shortcut.Command))
	}
	for _, c := range res.HiddenIn {
		e.printf("host %s's own shortcut %s hides it in that host's panel\n", oneLine(hostName(l.Hosts, c.HostID)), oneLine(c.Shortcut.Keys))
	}
	return nil
}

func hostName(hosts []model.Host, id string) string {
	for _, h := range hosts {
		if h.ItemID.String() == id {
			return h.Name
		}
	}
	return id
}

func runShortcutLs(ctx context.Context, e *Env, args []string) error {
	fs := newFlags(e, "shortcut ls", "hop shortcut ls [--host H] [--json]")
	hostRef := fs.String("host", "", "show this host's panel: its shortcuts and the global ones it keeps")
	asJSON := fs.Bool("json", false, "print the shortcuts as JSON")
	if _, _, err := parseFlags(fs, args); err != nil {
		return err
	}
	var host *model.Host
	if *hostRef != "" {
		h, err := shortcutHost(ctx, e, *hostRef)
		if err != nil {
			return err
		}
		host = h
	}
	l, err := listAll(ctx, e)
	if err != nil {
		return err
	}
	var views []ShortcutView
	if host == nil {
		for _, s := range l.Shortcuts {
			views = append(views, shortcutView(s, l.Hosts, l.Marks))
		}
		slices.SortFunc(views, func(a, b ShortcutView) int {
			if c := strings.Compare(a.Host, b.Host); c != 0 {
				return c
			}
			return strings.Compare(a.Keys, b.Keys)
		})
	} else {
		for _, p := range model.EffectiveShortcuts(l.Shortcuts, host.ItemID) {
			views = append(views, shortcutView(p.Shortcut, l.Hosts, l.Marks))
			for _, h := range p.Hides {
				v := shortcutView(h, l.Hosts, l.Marks)
				v.HiddenBy = p.Shortcut.Keys
				views = append(views, v)
			}
		}
	}
	if views == nil {
		views = []ShortcutView{}
	}
	if *asJSON {
		return printJSON(e, views)
	}
	if len(views) == 0 {
		fmt.Fprintln(e.Stderr, "no shortcuts; add one with hop shortcut add <keys> [--host H] -- <command>")
		return nil
	}
	marked := slices.ContainsFunc(views, func(v ShortcutView) bool { return v.Mark != "" })
	tw := tabwriter.NewWriter(e.Stdout, 0, 4, 2, ' ', 0)
	header := "KEYS\tSCOPE\tNAME\tCOMMAND\tENTER"
	if marked {
		header += "\tSYNC"
	}
	fmt.Fprintln(tw, header)
	for _, v := range views {
		scope := v.Scope
		if v.Scope == "host" {
			scope = "host " + v.Host
		}
		if v.HiddenBy != "" {
			scope += " (hidden by " + v.HiddenBy + ")"
		}
		enter := "yes"
		if !v.Enter {
			enter = "no"
		}
		// Vault text: no tabs or newlines may break the table.
		row := fmt.Sprintf("%s\t%s\t%s\t%s\t%s", oneLine(v.Keys), oneLine(scope), dash(printable(v.Name)), printable(v.Command), enter)
		if marked {
			row += "\t" + dash(oneLine(string(v.Mark)))
		}
		fmt.Fprintln(tw, row)
	}
	return tw.Flush()
}

func runShortcutRm(ctx context.Context, e *Env, args []string) error {
	fs := newFlags(e, "shortcut rm", "hop shortcut rm <keys|id> [--host H] [--yes] [--json]")
	hostRef := fs.String("host", "", "the host whose shortcut it is (default: a global shortcut)")
	yes := fs.Bool("yes", false, "do not ask")
	asJSON := fs.Bool("json", false, "print the result as JSON")
	pos, _, err := parseFlags(fs, args)
	if err != nil {
		return err
	}
	if len(pos) != 1 {
		fs.Usage()
		return failf("expected exactly one shortcut: its keys or its ID")
	}
	var host model.ID
	if *hostRef != "" {
		h, err := shortcutHost(ctx, e, *hostRef)
		if err != nil {
			return err
		}
		host = h.ItemID
	}
	l, err := listAll(ctx, e)
	if err != nil {
		return err
	}
	sc, err := findShortcut(l.Shortcuts, pos[0], host, *hostRef != "")
	if err != nil {
		return err
	}
	view := shortcutView(sc, l.Hosts, nil)
	what := "global shortcut " + view.Keys
	if view.Scope == "host" {
		what = "shortcut " + view.Keys + " of host " + view.Host
	}
	ok, err := confirm(e, *yes, safef("Remove %s (%s)?", what, sc.Command))
	if err != nil {
		return err
	}
	if !ok {
		return failf("not removed")
	}
	if err := callChange(ctx, e, *asJSON, daemon.OpDelete, daemon.DeleteParams{ID: sc.ItemID.String()}, nil); err != nil {
		return err
	}
	if *asJSON {
		return printJSON(e, map[string]any{"removed": sc.Keys, "id": sc.ItemID.String(), "scope": view.Scope, "host_id": view.HostID})
	}
	e.printf("removed %s\n", oneLine(what))
	return nil
}

// findShortcut finds a shortcut by ID, or by keys in one scope: host's
// when byHost, else the global one. Two devices can each add one on the
// same keys; then the ID picks.
func findShortcut(all []model.Shortcut, ref string, host model.ID, byHost bool) (model.Shortcut, error) {
	for _, s := range all {
		if s.ItemID.String() == ref && (!byHost || s.HostID == host) {
			return s, nil
		}
	}
	var found []model.Shortcut
	for _, s := range all {
		if s.Keys == ref && s.HostID == host {
			found = append(found, s)
		}
	}
	switch {
	case len(found) == 1:
		return found[0], nil
	case len(found) > 1:
		var ids []string
		for _, s := range found {
			ids = append(ids, s.ItemID.String())
		}
		return model.Shortcut{}, failf("more than one shortcut is on %q (added on two devices at once); remove one by ID: %s", ref, strings.Join(ids, ", "))
	}
	where := "no global shortcut"
	if byHost {
		where = "this host has no shortcut"
	}
	if !byHost && slices.ContainsFunc(all, func(s model.Shortcut) bool { return s.Keys == ref }) {
		return model.Shortcut{}, failf("%s is on %q; for a host's own, add --host H", where, ref)
	}
	return model.Shortcut{}, failf("%s is on %q (hop shortcut ls)", where, ref)
}

// sessionShortcuts is the panel of the session rr resolved: the host's own
// shortcuts first, then the global ones it keeps (daemon OpShortcuts). A
// session to no vault host gets the global shortcuts. An entry this build
// could not type safely is left out rather than passed on.
func (e *Env) sessionShortcuts(ctx context.Context, rr *daemon.ResolveResult) ([]termpanel.Shortcut, error) {
	var p daemon.ShortcutsParams
	if rr != nil && rr.Host != nil {
		p.HostID = rr.Host.ItemID.String()
	}
	var res daemon.ShortcutsResult
	if err := call(ctx, e, daemon.OpShortcuts, p, &res); err != nil {
		return nil, err
	}
	out := []termpanel.Shortcut{}
	for _, ps := range res.Panel {
		s := ps.Shortcut
		if model.CheckShortcutKeys(s.Keys) != nil || strings.ContainsAny(s.Keys, model.ShortcutReservedKeys) || !typeable(s.Command) {
			continue
		}
		name := s.Name
		if name == "" {
			name = s.Command
		}
		out = append(out, termpanel.Shortcut{Keys: s.Keys, Name: printable(name), Command: s.Command, Enter: s.Enter, Host: !s.HostID.IsZero()})
	}
	return out, nil
}

// typeable reports whether command is safe to type into a remote shell: a
// non-empty line of valid text with no control character, not even TAB.
func typeable(command string) bool {
	if command == "" || !utf8.ValidString(command) {
		return false
	}
	return !strings.ContainsFunc(command, unicode.IsControl)
}

// The session panel's hotkey: Ctrl-] unless HOP_SHORTCUT_KEY says
// otherwise, as ctrl-X (or ^X) for a letter or one of \ ] ^ _, or off.
const (
	shortcutKeyEnv     = "HOP_SHORTCUT_KEY"
	defaultShortcutKey = 0x1d // Ctrl-]
)

// shortcutHotkey is the byte that opens the session panel, and whether the
// panel is on. Keys the panel or a terminal needs are refused: Ctrl-[ is
// Esc, Ctrl-H Backspace, Ctrl-I Tab, Ctrl-J and Ctrl-M Enter, Ctrl-@ NUL,
// and in the panel Ctrl-C closes it and Ctrl-Z suspends hop. Every key it
// gives is one termpanel takes as the hotkey; for a letter, \ and ], so
// are Ctrl with that key in the kitty keyboard protocol and in xterm's
// modifyOtherKeys.
func (e *Env) shortcutHotkey() (key byte, on bool, err error) {
	v := ""
	if e.Getenv != nil {
		v = strings.TrimSpace(e.Getenv(shortcutKeyEnv))
	}
	switch l := strings.ToLower(v); {
	case v == "":
		return defaultShortcutKey, true, nil
	case l == "off" || l == "none":
		return 0, false, nil
	case strings.HasPrefix(l, "ctrl-") && len(v) == len("ctrl-")+1:
		key = v[len(v)-1]
	case strings.HasPrefix(l, "ctrl+") && len(v) == len("ctrl+")+1:
		key = v[len(v)-1]
	case strings.HasPrefix(v, "^") && len(v) == 2:
		key = v[1]
	default:
		return 0, false, failf("%s=%s: write ctrl-X (or ^X), where X is a letter or one of \\ ] ^ _, or off", shortcutKeyEnv, oneLine(v))
	}
	c := unicode.ToUpper(rune(key))
	switch {
	case c == 'H' || c == 'I' || c == 'J' || c == 'M':
		return 0, false, failf("%s=%s: Ctrl-%c is a key the terminal needs (Backspace, Tab or Enter); pick another", shortcutKeyEnv, oneLine(v), c)
	case c == 'C' || c == 'Z':
		return 0, false, failf("%s=%s: Ctrl-%c is a key of the panel itself (Ctrl-C closes it, Ctrl-Z suspends hop); pick another", shortcutKeyEnv, oneLine(v), c)
	case c >= 'A' && c <= 'Z', c == '\\', c == ']', c == '^', c == '_':
		return byte(c) & 0x1f, true, nil
	}
	return 0, false, failf("%s=%s: write ctrl-X (or ^X), where X is a letter or one of \\ ] ^ _, or off", shortcutKeyEnv, oneLine(v))
}
