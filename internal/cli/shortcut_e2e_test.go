package cli_test

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"slices"
	"strings"
	"syscall"
	"testing"

	"github.com/dalyem/hopkey/internal/cli"
	"github.com/dalyem/hopkey/internal/daemon"
	"github.com/dalyem/hopkey/internal/model"
	"github.com/dalyem/hopkey/internal/termpanel"
)

func (e *e2e) shortcuts(t *testing.T, args ...string) []cli.ShortcutView {
	t.Helper()
	code, stdout, stderr := e.hop(t, append([]string{"shortcut", "ls", "--json"}, args...)...)
	if code != 0 {
		t.Fatalf("hop shortcut ls: exit %d: %s", code, stderr)
	}
	var out []cli.ShortcutView
	if err := json.Unmarshal([]byte(stdout), &out); err != nil {
		t.Fatalf("not JSON: %v\n%s", err, stdout)
	}
	return out
}

func (e *e2e) mustHop(t *testing.T, args ...string) string {
	t.Helper()
	code, stdout, stderr := e.hop(t, args...)
	if code != 0 {
		t.Fatalf("hop %s: exit %d: %s", strings.Join(args, " "), code, stderr)
	}
	return stdout
}

func (e *e2e) hostID(t *testing.T, name string) model.ID {
	t.Helper()
	snap, _ := e.store.Snapshot(context.Background())
	for _, h := range snap.Hosts {
		if h.Name == name {
			return h.ItemID
		}
	}
	t.Fatalf("no host %s", name)
	return model.ID{}
}

func viewKeys(vs []cli.ShortcutView) []string {
	var out []string
	for _, v := range vs {
		k := v.Keys + "/" + v.Scope
		if v.HiddenBy != "" {
			k += "/hidden-by-" + v.HiddenBy
		}
		out = append(out, k)
	}
	return out
}

// hop shortcut add, ls and rm, for a global shortcut and a host's: ls
// --host shows that host's panel, its own first, with what they hide.
func TestShortcutAddListRemove(t *testing.T) {
	e := newE2E(t)
	out := e.mustHop(t, "shortcut", "add", "gl", "--name", "log", "--", "git", "log", "--oneline")
	if !strings.Contains(out, "added global shortcut gl: git log --oneline") {
		t.Errorf("add said %q", out)
	}
	e.mustHop(t, "shortcut", "add", "u", "--no-enter", "--", "sudo systemctl restart app")
	out = e.mustHop(t, "shortcut", "add", "g", "--host", "web-1", "--", "git status")
	if !strings.Contains(out, "shortcut of host web-1 g") || !strings.Contains(out, "hides the global shortcut gl") {
		t.Errorf("a host shortcut over a global one said %q", out)
	}

	all := e.shortcuts(t)
	if got, want := viewKeys(all), []string{"gl/global", "u/global", "g/host"}; !slices.Equal(got, want) {
		t.Errorf("ls: %v, want %v", got, want)
	}
	for _, v := range all {
		switch v.Keys {
		case "gl":
			if v.Name != "log" || v.Command != "git log --oneline" || !v.Enter || v.HostID != "" {
				t.Errorf("gl: %+v", v)
			}
		case "u":
			if v.Enter {
				t.Errorf("--no-enter: %+v", v)
			}
		case "g":
			if v.Host != "web-1" || v.HostID != e.hostID(t, "web-1").String() {
				t.Errorf("g: %+v", v)
			}
		}
	}
	if got, want := viewKeys(e.shortcuts(t, "--host", "web-1")), []string{"g/host", "gl/global/hidden-by-g", "u/global"}; !slices.Equal(got, want) {
		t.Errorf("web-1's panel: %v, want %v", got, want)
	}
	if got, want := viewKeys(e.shortcuts(t, "--host", "web-2")), []string{"gl/global", "u/global"}; !slices.Equal(got, want) {
		t.Errorf("web-2's panel: %v, want %v", got, want)
	}
	table := e.mustHop(t, "shortcut", "ls", "--host", "web-1")
	if !strings.Contains(table, "KEYS") || !strings.Contains(table, "host web-1") || !strings.Contains(table, "(hidden by g)") {
		t.Errorf("table:\n%s", table)
	}
	// Snippets are another type: hop snippet ls doesn't show shortcuts.
	if code, stdout, stderr := e.hop(t, "snippet", "ls", "--json"); code != 0 || strings.TrimSpace(stdout) != "[]" {
		t.Errorf("snippet ls: %d %q %q", code, stdout, stderr)
	}

	// rm takes the global one by keys unless --host names the host.
	e.mustHop(t, "shortcut", "rm", "g", "--host", "web-1", "--yes")
	if code, _, stderr := e.hop(t, "shortcut", "rm", "g", "--yes"); code == 0 || !strings.Contains(stderr, "no global shortcut") {
		t.Errorf("rm of a gone shortcut: %d %s", code, stderr)
	}
	id := all[0].ID
	e.mustHop(t, "shortcut", "rm", id, "--yes")
	if got := viewKeys(e.shortcuts(t)); !slices.Equal(got, []string{"u/global"}) {
		t.Errorf("after rm: %v", got)
	}
}

// What the panel could not use, or that would make two shortcuts of one
// panel clash, is refused, and nothing is written.
func TestShortcutAddRefusals(t *testing.T) {
	e := newE2E(t)
	e.mustHop(t, "shortcut", "add", "g", "--", "git status")
	e.mustHop(t, "shortcut", "add", "x", "--host", "web-1", "--", "exit")
	writes := e.store.Writes()
	for _, c := range []struct {
		args []string
		want string
	}{
		{[]string{"abc", "--", "ls"}, "one or two characters"},
		{[]string{" ", "--", "ls"}, "printable"},
		{[]string{"?", "--", "ls"}, "panel itself"},
		{[]string{"a", "--", "ls\nrm -rf /"}, "one line"},
		{[]string{"a", "--", "ls\r"}, "one line"},
		{[]string{"a", "--", "printf '\x1b[2J'"}, "control character"},
		{[]string{"a", "--", "ls\x00"}, "control character"},
		{[]string{"a", "--", "cat {{file}}"}, "{{parameters}}"},
		{[]string{"a", "--", "echo\thello"}, "can't have a tab"},
		{[]string{"g", "--", "git log"}, "already has a shortcut on \"g\""},
		{[]string{"gu", "--", "git pull"}, "can't both be shortcuts"},
		{[]string{"xa", "--host", "web-1", "--", "ls"}, "can't both be shortcuts"},
		{[]string{"a", "--host", "nowhere", "--", "ls"}, "--host"},
		{[]string{"a", "--name", "n\x1b]0;x\x07", "--", "ls"}, "control character"},
	} {
		code, _, stderr := e.hop(t, append([]string{"shortcut", "add"}, c.args...)...)
		if code == 0 || !strings.Contains(stderr, c.want) {
			t.Errorf("add %q: exit %d, stderr %q, want %q", c.args, code, stderr, c.want)
		}
	}
	if got := e.store.Writes(); got != writes {
		t.Errorf("refusals wrote %d changes", got-writes)
	}
	// A docker-style template is not a parameter.
	e.mustHop(t, "shortcut", "add", "d", "--", "docker ps --format '{{.Names}}'")
	// The same keys in the other scope are allowed: the host's wins there.
	out := e.mustHop(t, "shortcut", "add", "gu", "--host", "web-1", "--", "git pull")
	if !strings.Contains(out, "hides the global shortcut g") {
		t.Errorf("host over global: %q", out)
	}
	out = e.mustHop(t, "shortcut", "add", "xy", "--", "ls")
	if !strings.Contains(out, "host web-1's own shortcut x hides it") {
		t.Errorf("global under a host's: %q", out)
	}
}

// hop rm of a host with shortcuts names them and removes them with it;
// the daemon refuses a delete of the host alone.
func TestRemoveHostWithShortcuts(t *testing.T) {
	e := newE2E(t)
	e.mustHop(t, "shortcut", "add", "x", "--host", "web-2", "--", "exit")
	e.mustHop(t, "shortcut", "add", "u", "--", "uptime")
	web2 := e.hostID(t, "web-2")

	ctx := context.Background()
	c, err := daemon.Dial(ctx, e.paths.ControlSocket())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	err = c.Call(ctx, daemon.OpDelete, daemon.DeleteParams{ID: web2.String()}, nil)
	if err == nil || !strings.Contains(err.Error(), "the host has shortcuts (x)") {
		t.Fatalf("delete of a host with shortcuts: %v", err)
	}

	code, _, stderr := e.hop(t, "rm", "web-2")
	if code == 0 || !strings.Contains(stderr, "and its shortcuts x") {
		t.Errorf("hop rm without --yes and no terminal: %d %s", code, stderr)
	}
	e.mustHop(t, "rm", "web-2", "--yes")
	snap, _ := e.store.Snapshot(ctx)
	if len(snap.Shortcuts) != 1 || snap.Shortcuts[0].Keys != "u" {
		t.Errorf("shortcuts after hop rm: %+v", snap.Shortcuts)
	}
	if slices.ContainsFunc(snap.Hosts, func(h model.Host) bool { return h.ItemID == web2 }) {
		t.Error("the host is still there")
	}
}

// The session panel's lookup: the host's shortcuts first, then the global
// ones it keeps; a session to no vault host gets the global ones.
func TestSessionShortcuts(t *testing.T) {
	e := newE2E(t)
	e.mustHop(t, "shortcut", "add", "u", "--name", "up", "--", "uptime")
	e.mustHop(t, "shortcut", "add", "gl", "--", "git log")
	e.mustHop(t, "shortcut", "add", "g", "--host", "web-1", "--no-enter", "--", "git status")
	e.mustHop(t, "shortcut", "add", "z", "--host", "web-2", "--", "zsh")

	ctx := context.Background()
	host, _ := e.store.Snapshot(ctx)
	var web1 *model.Host
	for i := range host.Hosts {
		if host.Hosts[i].Name == "web-1" {
			web1 = &host.Hosts[i]
		}
	}
	env := e.env(t, strings.NewReader(""), new(strings.Builder), new(strings.Builder))
	got, err := cli.SessionShortcuts(ctx, env, &daemon.ResolveResult{Host: web1})
	if err != nil {
		t.Fatal(err)
	}
	want := []termpanel.Shortcut{
		{Keys: "g", Name: "git status", Command: "git status", Enter: false, Host: true},
		{Keys: "u", Name: "up", Command: "uptime", Enter: true},
	}
	if !slices.Equal(got, want) {
		t.Errorf("web-1's panel: %+v, want %+v", got, want)
	}
	got, err = cli.SessionShortcuts(ctx, env, &daemon.ResolveResult{})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0].Keys != "gl" || got[1].Keys != "u" || got[0].Host {
		t.Errorf("no host: %+v", got)
	}
}

func TestShortcutHotkey(t *testing.T) {
	for _, c := range []struct {
		v   string
		key byte
		on  bool
		bad bool
	}{
		{"", 0x1d, true, false}, {"ctrl-]", 0x1d, true, false}, {"Ctrl-B", 0x02, true, false}, {"^g", 0x07, true, false},
		{"ctrl+\\", 0x1c, true, false}, {"off", 0, false, false}, {"None", 0, false, false},
		{"ctrl-[", 0, false, true}, {"ctrl-m", 0, false, true}, {"ctrl-i", 0, false, true}, {"ctrl-h", 0, false, true},
		{"ctrl-j", 0, false, true}, {"x", 0, false, true}, {"ctrl-1", 0, false, true}, {"ctrl-ab", 0, false, true}, {"ctrl-@", 0, false, true},
		{"ctrl-c", 0, false, true}, {"^Z", 0, false, true}, {"ctrl+z", 0, false, true},
	} {
		v := c.v
		env := &cli.Env{Getenv: func(k string) string {
			if k == "HOP_SHORTCUT_KEY" {
				return v
			}
			return ""
		}}
		key, on, err := cli.ShortcutHotkey(env)
		if (err != nil) != c.bad || key != c.key || on != c.on {
			t.Errorf("HOP_SHORTCUT_KEY=%q: %#x %v %v", c.v, key, on, err)
		}
	}
}

// Every hotkey HOP_SHORTCUT_KEY gives is one the panel takes, in its
// kitty keyboard protocol and modifyOtherKeys forms too (Run refuses a
// hotkey it has none for), and none is a key the panel itself reads:
// Ctrl-C, Ctrl-Z, Esc, Backspace, Enter.
func TestShortcutHotkeysThePanelTakes(t *testing.T) {
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	defer w.Close()
	accepted := 0
	for c := byte(0x21); c < 0x7f; c++ {
		v := "ctrl-" + string(c)
		env := &cli.Env{Getenv: func(k string) string {
			if k == "HOP_SHORTCUT_KEY" {
				return v
			}
			return ""
		}}
		key, on, err := cli.ShortcutHotkey(env)
		if err != nil {
			continue
		}
		accepted++
		if !on || slices.Contains([]byte{0x03, 0x1a, 0x1b, 0x08, 0x7f, 0x0d, 0x0a}, key) {
			t.Errorf("HOP_SHORTCUT_KEY=%s gives %#x (on %v): a key of the panel itself", v, key, on)
		}
		// Run checks the hotkey before it looks at the terminal.
		err = termpanel.Run(context.Background(), termpanel.Options{In: r, Out: w, Hotkey: key}, func(*os.File, *syscall.SysProcAttr) (func() error, error) {
			t.Fatal("Run started a child on pipes")
			return nil, nil
		})
		if !errors.Is(err, termpanel.ErrNotTerminal) && !errors.Is(err, termpanel.ErrUnsupported) {
			t.Errorf("HOP_SHORTCUT_KEY=%s gives %#x, which the panel refuses: %v", v, key, err)
		}
	}
	if accepted != 2*20+4 { // 20 letters, in either case, and \ ] ^ _
		t.Errorf("%d values accepted", accepted)
	}
}
