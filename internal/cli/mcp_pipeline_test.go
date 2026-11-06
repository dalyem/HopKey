package cli_test

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"testing"

	"github.com/dalyem/hopkey/internal/cli"
	"github.com/dalyem/hopkey/internal/model"
)

// hop mcp redacts what an agent gets in one pass that never goes back to
// text it has not checked: the raw tail, then what formatting writes,
// then one cut at the limit that moves past every marker. These tests
// put a secret that formatting makes, or a marker longer than its
// secret, at the places near the 64 KiB limit where a cut could split
// one or the other: no piece of the secret reaches the agent. (Each pad
// costs the daemon's redaction budget 64 KiB, so they are few.) The cut
// keeps cli.MCPCutRoom bytes less than the limit, so each text begins
// with that many w's (filler) in place of as many x's of its pad: the
// cut falls where it fell, before the cut kept less, from the secret.

// filler goes before the secret, so that the cut falls near it.
var filler = strings.Repeat("w", cli.MCPCutRoom)

// onlyPadding reports whether rest, what follows hop's lead in a detail
// or the whole of a stream, is at most a "z", the marker, and then
// padding x's: nothing of the secret between them.
func onlyPadding(rest, marker string) bool {
	rest = strings.TrimPrefix(rest, "z")
	rest = strings.TrimPrefix(rest, marker)
	return strings.Trim(rest, "x") == ""
}

// oneLine writes ssh's "zleft<TAB>right" as "zleft?right", hop's own
// secret, and the marker for it is longer than the secret. Wherever the
// limit falls near it, the detail is cut past the marker, never into
// the secret.
func TestMCPCheckCutLeavesNoPieceOfWhatOneLineMakes(t *testing.T) {
	e := newE2E(t)
	m := mcpWithSecret(t, e, "left?right")
	const lead, note = "ssh did not log in: ", "(earlier output cut) "
	// The detail is the lead, "z", the marker and the padding up to pad
	// 65498; past it the cut falls in "z" and the marker. Before the cut
	// moved past them, it fell in the secret from pad 65485 to 65494.
	for _, pad := range []int{65480, 65484, 65485, 65487, 65490, 65494, 65498, 65499, 65502} {
		e.server.mu.Lock()
		e.server.trueErr = filler + "zleft\tright" + strings.Repeat("x", pad-len(filler)) + "\n"
		e.server.mu.Unlock()
		status, detail := mcpCall[agentCheck](m, "check_host", map[string]any{"host": "web-1"}).step(t, "auth_ok")
		rest, ok := strings.CutPrefix(detail, lead)
		cut := strings.HasPrefix(rest, note)
		rest = strings.TrimPrefix(rest, note)
		if status != "fail" || !ok || len(detail) > 64<<10 || !strings.HasSuffix(detail, "xxxx") || !onlyPadding(strings.TrimPrefix(rest, filler), "[redacted by hop]") {
			t.Errorf("pad %d: auth_ok %s, %d bytes: %.80q...; want the lead, the marker or nothing, and padding", pad, status, len(detail), detail)
		}
		if !cut && rest != filler+"z[redacted by hop]"+strings.Repeat("x", pad-len(filler)) {
			t.Errorf("pad %d: %d bytes not cut, but not the whole text: %.80q", pad, len(detail), detail)
		}
	}
}

// lastLines joins ssh's "zleft" and "right" lines into "zleft; right",
// a vault password the daemon finds where formatting wrote "; ", and
// its marker is three times as long. Wherever the limit falls near it,
// no piece of the password reaches the agent.
func TestMCPCheckCutLeavesNoPieceOfAJoinedVaultSecret(t *testing.T) {
	e := newE2E(t)
	if _, err := e.store.PutCredential(context.Background(), model.Credential{Name: "joined", Username: "admin", Password: "left; right"}); err != nil {
		t.Fatal(err)
	}
	m := e.startMCP(t)
	const lead, note = "ssh did not log in: ", "(earlier output cut) "
	// The cut falls in "z" and the marker from pad 65483 to 65494.
	for _, pad := range []int{65470, 65482, 65483, 65485, 65488, 65492, 65494, 65496} {
		e.server.mu.Lock()
		e.server.trueErr = filler + "zleft\nright" + strings.Repeat("x", pad-len(filler)) + "\n"
		e.server.mu.Unlock()
		status, detail := mcpCall[agentCheck](m, "check_host", map[string]any{"host": "web-1"}).step(t, "auth_ok")
		rest, ok := strings.CutPrefix(detail, lead)
		rest = strings.TrimPrefix(strings.TrimPrefix(rest, note), filler)
		if status != "fail" || !ok || len(detail) > 64<<10 || !strings.HasSuffix(detail, "xxxx") || !onlyPadding(rest, "[redacted by hop: vault-password]") {
			t.Errorf("pad %d: auth_ok %s, %d bytes: %.80q...; want the lead, the marker or nothing, and padding", pad, status, len(detail), detail)
		}
	}
}

// JSON writes the byte 0xff in "za\xffb" as U+FFFD, which makes hop's
// secret "a�b" three bytes longer than the output. Wherever the limit
// falls near it, neither stream holds a piece of the secret, and the
// counts are of the markers returned.
func TestMCPExecCutLeavesNoPieceOfWhatEncodingMakes(t *testing.T) {
	e := newE2E(t)
	m := mcpWithSecret(t, e, "a�b")
	// The stream is "z", the marker and the padding up to pad 65518; past
	// it the cut falls in "z" and the marker. Cut before the scan, the
	// encoded output would keep "\uFFFDb" or "b" at pads 65532 to 65534.
	for i, pad := range []int{65516, 65518, 65519, 65520, 65528, 65532, 65532, 65533, 65534} {
		e.server.mu.Lock()
		e.server.leak = filler + "za\xffb" + strings.Repeat("x", pad-len(filler))
		e.server.mu.Unlock()
		cmd := []string{"leak", "leakerr"}[i%2] // each stream at about half the pads
		r := mcpCall[agentExec](m, "exec", map[string]any{"hosts": "web-1", "command": cmd}).Results[0]
		got := r.Stdout
		if cmd == "leakerr" {
			got = r.Stderr
		}
		if len(got) > 64<<10 || !strings.HasSuffix(got, "xxxx") || !onlyPadding(strings.TrimPrefix(got, filler), "[redacted by hop]") {
			t.Errorf("pad %d %s: %d bytes: %.40q...; want the marker or nothing, and padding", pad, cmd, len(got), got)
		}
		if n := strings.Count(got, "[redacted by hop]"); r.Redactions["hop-secret"] != n {
			t.Errorf("pad %d %s: redactions %v, but %d markers returned", pad, cmd, r.Redactions, n)
		}
	}
}

// redactCalls records the texts of each OpRedact call hop mcp makes.
type redactCalls struct {
	mu    sync.Mutex
	calls [][]int // each call's texts, by length
}

func recordRedactCalls(t *testing.T) *redactCalls {
	rc := &redactCalls{}
	t.Cleanup(cli.SetRedactHook(func(texts [][]byte) {
		rc.mu.Lock()
		defer rc.mu.Unlock()
		var lens []int
		for _, x := range texts {
			lens = append(lens, len(x))
		}
		rc.calls = append(rc.calls, lens)
	}))
	return rc
}

func (rc *redactCalls) take() [][]int {
	rc.mu.Lock()
	defer rc.mu.Unlock()
	out := rc.calls
	rc.calls = nil
	return out
}

// Output that formatting does not change is checked by the daemon once:
// one call, each stream's bytes once, though it holds secrets and a
// denied host is hidden in stderr. A byte that is not UTF-8 makes a
// second call, of the stretch around it alone.
func TestMCPExecScansUnchangedOutputOnce(t *testing.T) {
	e, _, _ := redactWorld(t)
	e.addHost(t, "vault-db", func(h *model.Host) { h.AgentAccess = "deny" })
	m := e.startMCP(t)
	rc := recordRedactCalls(t)
	body := strings.Repeat("ok line\n", 4000)
	leak := body + "db password: " + vaultPassword + "\nssh: connect to host vault-db port 22\n"
	e.server.mu.Lock()
	e.server.leak = leak
	e.server.mu.Unlock()
	r := mcpCall[agentExec](m, "exec", map[string]any{"hosts": "web-1", "command": "leakboth"}).Results[0]
	if strings.Contains(r.Stdout+r.Stderr, vaultPassword) || !strings.Contains(r.Stderr, "<hidden host>") || r.Redactions["vault-password"] != 2 {
		t.Errorf("redactions %v, stderr ending %q", r.Redactions, r.Stderr[max(0, len(r.Stderr)-120):])
	}
	if calls := rc.take(); len(calls) != 1 || fmt.Sprint(calls[0]) != fmt.Sprint([]int{len(leak), len(leak)}) {
		t.Errorf("OpRedact calls %v, want one of [%d %d]", calls, len(leak), len(leak))
	}

	e.server.mu.Lock()
	e.server.leak = body + "\xff" + body
	e.server.mu.Unlock()
	r = mcpCall[agentExec](m, "exec", map[string]any{"hosts": "web-1", "command": "leak"}).Results[0]
	if !strings.Contains(r.Stdout, "ok line\n�ok line") {
		t.Errorf("no U+FFFD where the byte was: %d bytes", len(r.Stdout))
	}
	calls := rc.take()
	if len(calls) != 2 || calls[0][0] != len(body)*2+1 {
		t.Fatalf("OpRedact calls %v, want the whole stream and then the stretch around the byte", calls)
	}
	total := 0
	for _, n := range calls[1] {
		total += n
	}
	if total == 0 || total > 8<<10 {
		t.Errorf("the second call checks %d bytes, want the stretch around the byte alone", total)
	}
}

// Eight hosts at once, each printing 64 KiB to stdout and to stderr,
// are checked within the daemon's 1 MiB burst: nothing is withheld.
func TestMCPEightHostsFitTheRedactionBudget(t *testing.T) {
	e, _, _ := redactWorld(t)
	line := vaultPassword + "\n"
	leak := strings.Repeat("x", 64<<10-len(line)-1) + "\n" + line
	e.server.mu.Lock()
	e.server.leak = leak
	e.server.mu.Unlock()
	hosts := []string{"web-1"}
	for i := range 7 {
		name := fmt.Sprintf("many-%d", i)
		e.addHost(t, name, nil)
		hosts = append(hosts, name)
	}
	m := e.startMCP(t)
	out := mcpCall[agentExec](m, "exec", map[string]any{"hosts": hosts, "command": "leakboth"})
	if len(out.Results) != 8 {
		t.Fatalf("%d results", len(out.Results))
	}
	for _, r := range out.Results {
		if r.Withheld != nil || r.Redactions["vault-password"] != 2 || strings.Contains(r.Stdout+r.Stderr, vaultPassword) {
			t.Errorf("%s: withheld %+v, redactions %v", r.Host, r.Withheld, r.Redactions)
		}
	}
}

// A denied host's name is hidden after the scan of what formatting
// wrote, not before: ssh's stderr "left<TAB>right" is the vault password
// "left?right" once oneLine writes it, and "left" names a denied host.
// Hidden first, the name would have split the password before the scan
// saw it whole, and "?right" gone to the agent. Under redacted and full,
// it goes whole.
func TestMCPCheckHidesHostsAfterTheRescan(t *testing.T) {
	e := newE2E(t)
	e.addHost(t, "left", func(h *model.Host) { h.AgentAccess = "deny" })
	if _, err := e.store.PutCredential(context.Background(), model.Credential{Name: "tabbed", Username: "admin", Password: "left?right"}); err != nil {
		t.Fatal(err)
	}
	e.server.mu.Lock()
	e.server.trueErr = "left\tright\n"
	e.server.mu.Unlock()
	m := e.startMCP(t)
	for _, policy := range []string{"redacted", "full"} {
		if code, _, stderr := e.hop(t, "edit", "web-1", "--agent-output", policy); code != 0 {
			t.Fatalf("hop edit --agent-output %s: exit %d: %s", policy, code, stderr)
		}
		status, detail := mcpCall[agentCheck](m, "check_host", map[string]any{"host": "web-1"}).step(t, "auth_ok")
		if want := "ssh did not log in: [redacted by hop: vault-password]"; status != "fail" || detail != want {
			t.Errorf("%s: auth_ok %s %q, want %q", policy, status, detail, want)
		}
		if raw := m.raw[len(m.raw)-1]; strings.Contains(raw, "right") {
			t.Errorf("%s: the agent got part of the password: %.300s", policy, raw)
		}
	}
}

// A token that hop's own value stood against goes once the value is a
// marker: in "prefix" and a GitHub token, the scan of the text as it
// came saw the token inside a longer word, but the agent gets it whole
// after "[redacted by hop]". The text is scanned again as returned.
func TestMCPExecRedactsATokenAMarkerExposes(t *testing.T) {
	e := newE2E(t)
	e.server.mu.Lock()
	e.server.leak = "prefix" + githubToken + "\n"
	e.server.mu.Unlock()
	m := mcpWithSecret(t, e, "prefix")
	for _, cmd := range []string{"leak", "leakerr"} {
		r := mcpCall[agentExec](m, "exec", map[string]any{"hosts": "web-1", "command": cmd}).Results[0]
		got := r.Stdout
		if cmd == "leakerr" {
			got = r.Stderr
		}
		if want := "[redacted by hop][redacted by hop: github-token]\n"; got != want || r.Redactions["hop-secret"] != 1 || r.Redactions["github-token"] != 1 {
			t.Errorf("%s: %q, redactions %v; want %q", cmd, got, r.Redactions, want)
		}
	}
}

// The cut to the limit never leaves a key's name shorter than it was:
// "xpassword=" names no secret, "password=" does. Where the cut would
// take the "x", the value goes, and where a newline follows, the rest of
// the line goes with the cut. A value that reaches the agent stands
// after "xpassword=", as the remote printed it.
func TestMCPExecCutLeavesNoKeyItShortens(t *testing.T) {
	e := newE2E(t)
	m := e.startMCP(t)
	const value = "sup3r-s3cret-value"
	const limit = 64 << 10
	kept := limit - cli.MCPCutRoom // what a cut keeps
	line := "xpassword=" + value
	pad := func(s string, n int) string { return strings.Repeat(s, n/len(s)+1)[:n] }
	for _, c := range []struct {
		name, leak, prefix string
	}{
		// Cut at the limit, the cut would take the "x".
		{"at the limit", line + " " + pad("x", limit-len(line)), ""},
		// Cut where the cut does, it takes the "x".
		{"no newline", pad("y", 2047) + line + " " + pad("x", kept+1-len(line)-1), "password="},
		{"newline", pad("y", 2047) + line + "\n" + pad("ok\n", kept+1-len(line)-1), "ok\n"},
	} {
		e.server.mu.Lock()
		e.server.leak = c.leak
		e.server.mu.Unlock()
		r := mcpCall[agentExec](m, "exec", map[string]any{"hosts": "web-1", "command": "leak"}).Results[0]
		got := r.Stdout
		if len(got) > limit || !r.Truncated || !strings.HasPrefix(got, c.prefix) {
			t.Errorf("%s: %d bytes beginning %.40q, truncated %v; want at most 64 KiB, cut, beginning %q", c.name, len(got), got, r.Truncated, c.prefix)
		}
		if strings.Count(got, value) != strings.Count(got, line) {
			t.Errorf("%s: the value without its key's whole name: %.60q", c.name, got)
		}
	}
}

// hop's lead and the text after it are scanned apart, and a secret can
// run across where they meet: the vault password "in: hunter2" stands in
// "ssh did not log in: " and ssh's "hunter2". The text from where it
// begins goes, with the secret's end; hop's words stay.
func TestMCPCheckFindsASecretAcrossTheLead(t *testing.T) {
	e := newE2E(t)
	if _, err := e.store.PutCredential(context.Background(), model.Credential{Name: "lead", Username: "admin", Password: "in: hunter2"}); err != nil {
		t.Fatal(err)
	}
	e.server.mu.Lock()
	e.server.trueErr = "hunter2 more\n"
	e.server.mu.Unlock()
	m := e.startMCP(t)
	for _, policy := range []string{"redacted", "full"} {
		if code, _, stderr := e.hop(t, "edit", "web-1", "--agent-output", policy); code != 0 {
			t.Fatalf("hop edit --agent-output %s: exit %d: %s", policy, code, stderr)
		}
		status, detail := mcpCall[agentCheck](m, "check_host", map[string]any{"host": "web-1"}).step(t, "auth_ok")
		if want := "ssh did not log in: [redacted by hop: vault-password] more"; status != "fail" || detail != want {
			t.Errorf("%s: auth_ok %s %q, want %q", policy, status, detail, want)
		}
	}
}

// Nor does the cut leave a denied host's name standing on its own where
// it stood inside a longer word: "xleft:22" names no host, "left:22"
// names the denied "left", which is hidden there.
func TestMCPExecCutLeavesNoDeniedNameItShortens(t *testing.T) {
	e := newE2E(t)
	e.addHost(t, "left", func(h *model.Host) { h.AgentAccess = "deny" })
	m := e.startMCP(t)
	const limit = 64 << 10
	kept := limit - cli.MCPCutRoom
	pad := func(s string, n int) string { return strings.Repeat(s, n/len(s)+1)[:n] }
	for _, c := range []struct{ name, leak, prefix string }{
		{"at the limit", "x" + "left:22 " + pad("z", limit-8), ""},
		{"where the cut is", pad("y", 2047) + "x" + "left:22 " + pad("z", kept-8), "<hidden host>:22 "},
	} {
		e.server.mu.Lock()
		e.server.leak = c.leak
		e.server.mu.Unlock()
		r := mcpCall[agentExec](m, "exec", map[string]any{"hosts": "web-1", "command": "leakerr"}).Results[0]
		got := r.Stderr
		if len(got) > limit || !r.Truncated || !strings.HasPrefix(got, c.prefix) || strings.HasPrefix(got, "left") {
			t.Errorf("%s: %d bytes beginning %.40q, truncated %v; want at most 64 KiB, cut, beginning %q", c.name, len(got), got, r.Truncated, c.prefix)
		}
	}
}
