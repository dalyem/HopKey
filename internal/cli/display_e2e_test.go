package cli_test

import (
	"context"
	"encoding/json"
	"fmt"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"unicode"

	"github.com/dalyem/hopkey/internal/cli"
	"github.com/dalyem/hopkey/internal/model"
)

// hostile payloads: a line break, a tab, escape sequences, bidi controls, C1
// controls (NEL and the CSI introducer), DEL and a forged diagnostic.
var hostilePayloads = []string{
	"a\nb",
	"a\tb",
	"a\x1b[2Jb\x1b]0;title\x07",
	"a‮b⁦c",
	"a\u0085b\u009bc",
	"a\x7fb\rc",
	"a\nhop: forged",
}

// unsafeRune is a character that could rewrite a terminal. A newline is
// allowed here: the callers check line structure separately.
func unsafeRune(c rune) bool {
	return c != '\n' && (c < ' ' || c == 0x7f || (c >= 0x80 && c < 0xa0) || unicode.Is(unicode.Cf, c))
}

func assertDisplaySafe(t *testing.T, what, out string) {
	t.Helper()
	for _, c := range out {
		if unsafeRune(c) {
			t.Errorf("%s: raw %U in output %q", what, c, out)
			return
		}
	}
}

func lines(s string) []string { return strings.Split(strings.TrimRight(s, "\n"), "\n") }

// infoLabel is every label hop info prints at the start of a line.
var infoLabel = regexp.MustCompile(`^(name|id|aliases|addresses|port|user|key|jump host|tags|description|route|would use|agent access|tailscale|host keys|host key|ssh): `)

// Vault text reaches ls, info and which. Whatever a host's fields hold, the
// table has one line per host, info has one line per field, and nothing in
// the output can rewrite the terminal.
func TestHostFieldsCannotBreakLsInfoOrWhich(t *testing.T) {
	e := newE2E(t)
	ctx := context.Background()
	fields := []struct {
		name string
		set  func(h *model.Host, i int, v string)
	}{
		{"name", func(h *model.Host, i int, v string) {
			// A hostile name is not a valid target, so the host is reached by an alias.
			h.Name, h.Aliases = "n-"+v, []string{fmt.Sprintf("nm-%d", i)}
		}},
		{"alias", func(h *model.Host, i int, v string) { h.Aliases = []string{"al-" + v} }},
		{"description", func(h *model.Host, i int, v string) { h.Description = v }},
		{"address", func(h *model.Host, i int, v string) { h.Addresses = []string{v} }},
		{"tag", func(h *model.Host, i int, v string) { h.Tags = []string{v, "ok"} }},
		{"user", func(h *model.Host, i int, v string) { h.User = v }},
		{"tailscale", func(h *model.Host, i int, v string) {
			h.Tailscale = &model.Tailscale{StableNodeID: v, DNSName: v, SSH: "yes"}
		}},
	}
	type target struct{ name, field, payload string }
	var targets []target
	hosts := 2 // web-1 and web-2 from newE2E
	for _, f := range fields {
		for i, p := range hostilePayloads {
			h := model.Host{
				Name: fmt.Sprintf("h-%s-%d", f.name, i), Addresses: []string{"127.0.0.1"}, Port: 22,
				Route: "auto", AgentAccess: "allow",
			}
			f.set(&h, i, p)
			if _, err := e.store.PutHost(ctx, h); err != nil {
				t.Fatal(err)
			}
			name := h.Name
			if f.name == "name" {
				name = fmt.Sprintf("nm-%d", i)
			}
			targets = append(targets, target{name, f.name, p})
			hosts++
		}
	}
	// A hostile key name shows in the KEY column and in info.
	snap, err := e.store.Snapshot(ctx)
	if err != nil {
		t.Fatal(err)
	}
	key := snap.Keys[0]
	key.Name = "key-" + hostilePayloads[0] + "\t" + hostilePayloads[2]
	if _, err := e.store.PutKey(ctx, key); err != nil {
		t.Fatal(err)
	}

	code, out, errOut := e.hop(t, "ls")
	if code != 0 {
		t.Fatalf("ls: %d %s", code, errOut)
	}
	assertDisplaySafe(t, "ls", out+errOut)
	if got := lines(out); len(got) != hosts+1 {
		t.Errorf("ls printed %d lines for %d hosts (plus the header):\n%s", len(got), hosts, out)
	}
	for _, l := range lines(out)[1:] {
		if n := len(strings.Fields(l)); n < 8 {
			t.Errorf("ls row has %d columns, want at least 8: %q", n, l)
		}
	}

	for _, tg := range targets {
		what := tg.field + " " + fmt.Sprintf("%q", tg.payload)
		name := tg.name

		code, out, errOut := e.hop(t, "info", name)
		if code != 0 {
			t.Errorf("info (%s): %d %s", what, code, errOut)
			continue
		}
		assertDisplaySafe(t, "info "+what, out+errOut)
		seen := map[string]int{}
		for _, l := range lines(out) {
			m := infoLabel.FindStringSubmatch(l)
			if m == nil {
				t.Errorf("info (%s): stray line %q in:\n%s", what, l, out)
				continue
			}
			seen[m[1]]++
		}
		for label, n := range seen {
			if n > 1 && label != "host key" {
				t.Errorf("info (%s): %d %q lines, an injected one among them:\n%s", what, n, label, out)
			}
		}

		code, out, errOut = e.hop(t, "which", name)
		if code != 0 {
			t.Errorf("which (%s): %d %s", what, code, errOut)
			continue
		}
		assertDisplaySafe(t, "which "+what, out+errOut)
		for _, l := range lines(out) {
			if !regexp.MustCompile(`^(target|host|rule|address|blocked|fallback|route|user|ssh|candidate|note): ?`).MatchString(l) {
				t.Errorf("which (%s): stray line %q in:\n%s", what, l, out)
			}
		}
	}
	for _, args := range [][]string{{"key", "ls"}, {"info", "h-name-0"}} {
		_, out, errOut := e.hop(t, args...)
		assertDisplaySafe(t, strings.Join(args, " "), out+errOut)
	}
	if _, out, _ := e.hop(t, "key", "ls"); len(lines(out)) != 2 {
		t.Errorf("key ls printed %d lines for one key plus the header:\n%s", len(lines(out)), out)
	}

	// JSON keeps the values and escapes what could redraw a terminal.
	code, out, errOut = e.hop(t, "ls", "--json")
	if code != 0 {
		t.Fatalf("ls --json: %d %s", code, errOut)
	}
	assertDisplaySafe(t, "ls --json", out)
	var views []cli.HostView
	if err := json.Unmarshal([]byte(out), &views); err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	byName := map[string]cli.HostView{}
	for _, v := range views {
		byName[v.Name] = v
	}
	for _, p := range hostilePayloads {
		if _, ok := byName["n-"+p]; !ok {
			t.Errorf("ls --json lost the host named %q", "n-"+p)
		}
	}
}

// Candidates in an ambiguous result and the errors that list them: the
// message has its own lines, and each value is one line.
func TestAmbiguousCandidatesAreDisplaySafe(t *testing.T) {
	e := newE2E(t)
	ctx := context.Background()
	for i, p := range hostilePayloads {
		h := model.Host{
			Name: fmt.Sprintf("amb-%d-%s", i, p), Addresses: []string{"10.0.0." + fmt.Sprint(i+1) + p}, Port: 22,
			Route: "auto", AgentAccess: "allow",
		}
		if _, err := e.store.PutHost(ctx, h); err != nil {
			t.Fatal(err)
		}
	}
	for _, args := range [][]string{{"which", "amb"}, {"info", "amb"}, {"check", "amb"}, {"trust", "amb"}} {
		_, out, errOut := e.hop(t, args...)
		what := strings.Join(args, " ")
		assertDisplaySafe(t, what, out+errOut)
		for _, l := range lines(out + errOut) {
			ok := strings.HasPrefix(l, "hop: ") || strings.HasPrefix(l, "  candidate: ") || strings.HasPrefix(l, "  note: ") ||
				regexp.MustCompile(`^(target|host|rule|address|route|candidate|note|check|  \[)`).MatchString(l) || strings.HasPrefix(l, strings.Repeat(" ", 28))
			if !ok {
				t.Errorf("%s: stray line %q in:\n%s", what, l, out+errOut)
			}
		}
		if n := countPrefix(errOut, "hop:"); n > 1 {
			t.Errorf("%s: %d hop: lines, a forged one among them:\n%s", what, n, errOut)
		}
	}
}

func countPrefix(s, prefix string) int {
	n := 0
	for _, l := range strings.Split(s, "\n") {
		if strings.HasPrefix(l, prefix) {
			n++
		}
	}
	return n
}

// A path the user passes can quote hostile text into an error. The error is
// built from the path, so the path is made one line where it is quoted: a
// final filter over the message could not tell a forged "hop:" line from the
// message's own.
func TestUnreadablePathCannotForgeADiagnostic(t *testing.T) {
	e := newE2E(t)
	for _, p := range hostilePayloads {
		bad := filepath.Join(e.home, "no-such-"+p)
		for _, args := range [][]string{
			{"import", "ssh-config", "--yes", bad},
			{"import", "ssh-config", bad},
			{"import", "ssh-config", "--json", "--yes", bad},
			{"key", "add", bad},
		} {
			code, out, errOut := e.hop(t, args...)
			what := fmt.Sprintf("%v", args)
			if code == 0 {
				t.Errorf("%s: succeeded", what)
			}
			assertDisplaySafe(t, what, out+errOut)
			if n := countPrefix(errOut, "hop:"); n != 1 && !slicesContains(args, "--json") {
				t.Errorf("%s: %d hop: lines, want exactly 1:\n%s", what, n, errOut)
			}
			if got := lines(errOut); len(got) != 1 {
				t.Errorf("%s: the error spans %d lines, want 1:\n%s", what, len(got), errOut)
			}
			if code == 0 || len(args) < 3 {
				continue
			}
			if slicesContains(args, "--json") {
				var m map[string]string
				if err := json.Unmarshal([]byte(errOut), &m); err != nil || m["error"] == "" {
					t.Errorf("%s: JSON error does not parse: %v %q", what, err, errOut)
				}
			}
		}
	}
}

func slicesContains(ss []string, s string) bool {
	for _, x := range ss {
		if x == s {
			return true
		}
	}
	return false
}

// key rm echoes the name it was given. A hostile name is one line in the
// confirmation question, in the result and in the failure.
func TestKeyRmWithAHostileNameCannotForgeALine(t *testing.T) {
	e := newE2E(t)
	ctx := context.Background()
	snap, err := e.store.Snapshot(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for i, p := range hostilePayloads {
		name := fmt.Sprintf("k%d-", i) + p
		k := snap.Keys[0]
		k.ItemID, k.Name = model.ID{}, name
		if _, err := e.store.PutKey(ctx, k); err != nil {
			t.Fatal(err)
		}
		code, out, errOut := e.hop(t, "key", "rm", "--yes", name)
		if code != 0 {
			t.Errorf("key rm %q: %d %s", name, code, errOut)
			continue
		}
		assertDisplaySafe(t, "key rm "+name, out+errOut)
		if got := lines(out); len(got) != 1 || !strings.HasPrefix(got[0], "removed key k") {
			t.Errorf("key rm %q printed %d lines, want one \"removed key\" line:\n%s", name, len(got), out)
		}
		if n := countPrefix(out+errOut, "hop:"); n != 0 {
			t.Errorf("key rm %q: a forged hop: line in %q %q", name, out, errOut)
		}
	}
	// The failure when the name is unknown is one line too.
	code, _, errOut := e.hop(t, "key", "rm", "--yes", "nope\nhop: forged")
	if n := countPrefix(errOut, "hop:"); code == 0 || n != 1 || len(lines(errOut)) != 1 {
		t.Errorf("key rm of an unknown name: %d, %d hop: lines:\n%s", code, n, errOut)
	}
}
