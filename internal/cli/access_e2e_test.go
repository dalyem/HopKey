package cli_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/dalyem/hopkey/internal/cli"
	"github.com/dalyem/hopkey/internal/daemon"
	"github.com/dalyem/hopkey/internal/model"
	"github.com/dalyem/hopkey/internal/model/modeltest"
)

// hop access (spec rev 17, Part 2) end to end: the system ssh client
// against akServer, which decides logins from its home's authorized_keys
// and runs the session script with the real sh.

type accessWorld struct {
	*e2e
	srv       []*akServer
	user      string
	colleague ssh.Signer
	pub, fp   string
	orig      []string
}

// localUser is what id -un says: the user every akServer session runs as.
func localUser(t *testing.T) string {
	t.Helper()
	out, err := exec.Command("id", "-un").Output()
	if err != nil {
		t.Skipf("id -un: %v", err)
	}
	return strings.TrimSpace(string(out))
}

func newAccessWorld(t *testing.T, servers int) *accessWorld {
	t.Helper()
	requireSSH(t)
	cli.SetAKLockWait(t, 1)
	base, err := os.MkdirTemp("", "hka")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(base) })
	tmp := filepath.Join(base, "tmp")
	os.Mkdir(tmp, 0o700)
	t.Setenv("TMPDIR", tmp)
	home := filepath.Join(base, "home")
	paths := daemon.Paths{RunDir: filepath.Join(base, "run"), ConfigDir: filepath.Join(home, ".ssh", "hop"), StateDir: filepath.Join(base, "state")}
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	login, _ := ssh.NewSignerFromKey(priv)
	block, _ := ssh.MarshalPrivateKey(priv, "")
	st := modeltest.New()
	ctx := context.Background()
	key, err := st.PutKey(ctx, model.Key{Name: "deploy-key", KeyType: "ed25519",
		PrivateKey: string(pem.EncodeToMemory(block)), PublicKey: authorizedKeysLine(login.PublicKey())})
	if err != nil {
		t.Fatal(err)
	}
	w := &accessWorld{user: localUser(t), colleague: newSigner(t)}
	w.pub = authorizedKeysLine(w.colleague.PublicKey())
	w.fp = ssh.FingerprintSHA256(w.colleague.PublicKey())
	for i := range servers {
		rhome := filepath.Join(base, fmt.Sprintf("remote%d", i+1))
		os.MkdirAll(filepath.Join(rhome, ".ssh"), 0o700)
		content := "# hop test\n" + authorizedKeysLine(login.PublicKey()) + " deploy\n" +
			authorizedKeysLine(newSigner(t).PublicKey()) + " other@laptop\n"
		os.WriteFile(filepath.Join(rhome, ".ssh", "authorized_keys"), []byte(content), 0o600)
		s := startAKServer(t, rhome)
		w.srv = append(w.srv, s)
		w.orig = append(w.orig, content)
		if _, err := st.PutHost(ctx, model.Host{
			Name: fmt.Sprintf("web-%d", i+1), Addresses: []string{"127.0.0.1"}, Port: uint32(s.port), User: w.user,
			KeyID: key.ItemID, Route: "auto", AgentAccess: "allow", HostKeys: []string{authorizedKeysLine(s.hostKey)},
		}); err != nil {
			t.Fatal(err)
		}
	}
	d, err := daemon.Start(daemon.Options{Paths: paths, Store: st, Version: "test", Tailscale: noTailscale{}, Logf: t.Logf})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { d.Close() })
	w.e2e = &e2e{base: base, home: home, paths: paths, store: st, daemon: d, keyID: key.ItemID}
	return w
}

func (w *accessWorld) ak(t *testing.T, i int) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(w.srv[i].home, ".ssh", "authorized_keys"))
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func (w *accessWorld) setAK(t *testing.T, i int, content string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(w.srv[i].home, ".ssh", "authorized_keys"), []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

func (w *accessWorld) record(t *testing.T, label string) *model.Access {
	t.Helper()
	snap, err := w.store.Snapshot(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	for i := range snap.Access {
		if snap.Access[i].Label == label {
			return &snap.Access[i]
		}
	}
	return nil
}

func (w *accessWorld) host(t *testing.T, name string) model.Host {
	t.Helper()
	snap, _ := w.store.Snapshot(context.Background())
	for _, h := range snap.Hosts {
		if h.Name == name {
			return h
		}
	}
	t.Fatalf("no host %s", name)
	return model.Host{}
}

func (w *accessWorld) run(t *testing.T, args ...string) (int, cli.AccessRunResult, string) {
	t.Helper()
	start := time.Now()
	code, out, errOut := w.hop(t, append([]string{"access"}, args...)...)
	defer func() { t.Logf("(took %s)", time.Since(start).Round(time.Millisecond)) }()
	var res cli.AccessRunResult
	if strings.HasPrefix(strings.TrimSpace(out), "{") {
		if err := json.Unmarshal([]byte(out), &res); err != nil {
			t.Fatalf("output %q: %v", out, err)
		}
	}
	t.Logf("hop access %s: exit %d\n%s%s", strings.Join(args, " "), code, out, errOut)
	return code, res, out + errOut
}

func (w *accessWorld) add(t *testing.T, label string, hosts ...string) (int, cli.AccessRunResult, string) {
	return w.run(t, append(append([]string{"add", label}, hosts...), "--pubkey", w.pub+" colleague@laptop", "--fingerprint", w.fp, "--yes", "--json")...)
}

func (w *accessWorld) check(t *testing.T, args ...string) (int, []cli.AccessFinding) {
	t.Helper()
	code, out, errOut := w.hop(t, append([]string{"access", "check", "--json"}, args...)...)
	var fs []cli.AccessFinding
	if err := json.Unmarshal([]byte(out), &fs); err != nil {
		t.Fatalf("check output %q %q: %v", out, errOut, err)
	}
	t.Logf("hop access check: exit %d %+v", code, fs)
	return code, fs
}

func kinds(fs []cli.AccessFinding) map[string]int {
	out := map[string]int{}
	for _, f := range fs {
		out[f.Kind]++
	}
	return out
}

func targetStates(res cli.AccessRunResult) map[string]string {
	out := map[string]string{}
	for _, t := range res.Targets {
		out[t.Host] = t.State
	}
	return out
}

// Add installs one managed line per host, bound to the host key it
// presented; the colleague logs in; rm removes it with a tombstone in the
// same rename, and every other line is kept byte for byte.
func TestAccessAddThenRemove(t *testing.T) {
	w := newAccessWorld(t, 2)
	code, res, out := w.add(t, "alice", "web-1", "web-2")
	if code != 0 || targetStates(res)["web-1"] != model.AccessInstalled || targetStates(res)["web-2"] != model.AccessInstalled {
		t.Fatalf("add: %d %+v", code, res)
	}
	if !strings.Contains(out, "first hop access record") {
		t.Error("no warning before the vault's first record")
	}
	a := w.record(t, "alice")
	rid := a.RecordID.String()
	line := w.pub + " hop-access:" + rid
	for i := range w.srv {
		if got := w.ak(t, i); got != w.orig[i]+line+"\n" {
			t.Fatalf("server %d: %q", i, got)
		}
		if err := login(w.srv[i], w.colleague); err != nil {
			t.Fatalf("the colleague can't log in to server %d: %v", i, err)
		}
	}
	for _, x := range a.Targets {
		if x.State != model.AccessInstalled || x.Gen != 1 || x.User != w.user || x.ServerKeyFP == "" || x.SameMachine != nil {
			t.Fatalf("target %+v", x)
		}
	}
	if a.By != modeltest.DefaultDeviceID {
		t.Errorf("by %v", a.By)
	}
	// A repair finds the line there and writes nothing.
	if code, res, _ := w.run(t, "add", "alice", "web-1", "--json"); code != 0 || targetStates(res)["web-1"] != model.AccessInstalled {
		t.Fatalf("repair: %d %+v", code, res)
	}
	if w.ak(t, 0) != w.orig[0]+line+"\n" {
		t.Fatal("the repair changed the file")
	}
	if code, _ := w.check(t); code != 0 {
		t.Fatalf("check after add: exit %d", code)
	}

	code, res, out = w.run(t, "rm", "alice", "--yes", "--json")
	if code != 0 || !res.Deleted || targetStates(res)["web-1"] != model.AccessRemoved {
		t.Fatalf("rm: %d %+v", code, res)
	}
	gen := map[int]uint64{0: 3, 1: 2} // web-1 was repaired once (gen 2), then removed
	for i := range w.srv {
		want := w.orig[i] + fmt.Sprintf("# hop-access-removed %s %d\n", rid, gen[i])
		if got := w.ak(t, i); got != want {
			t.Fatalf("server %d after rm: %q, want %q", i, got, want)
		}
		if err := login(w.srv[i], w.colleague); err == nil {
			t.Fatalf("the colleague still logs in to server %d", i)
		}
		if entries, _ := os.ReadDir(filepath.Join(w.srv[i].home, ".ssh")); len(entries) != 1 {
			t.Fatalf("server %d ~/.ssh holds %d entries", i, len(entries))
		}
	}
	if w.record(t, "alice") != nil {
		t.Fatal("the record outlived its last target")
	}
	// With the record gone, --all-hosts lists the tombstones as
	// information only.
	code, fs := w.check(t, "--all-hosts")
	if code != 0 || kinds(fs)["tombstone"] != 2 {
		t.Fatalf("check --all-hosts: %d %+v", code, fs)
	}
}

// A tombstone for the record blocks every later add of it on that file;
// check reports the tombstone and never offers add there.
func TestAccessTombstoneBlocksAdd(t *testing.T) {
	w := newAccessWorld(t, 1)
	if code, _, _ := w.add(t, "alice", "web-1"); code != 0 {
		t.Fatal("add")
	}
	a := w.record(t, "alice")
	line := w.pub + " hop-access:" + a.RecordID.String()
	// Another device removed it (gen 5), and this vault never heard: the
	// line is still there next to the tombstone, so a repair would match.
	w.setAK(t, 0, w.orig[0]+line+"\n"+fmt.Sprintf("# hop-access-removed %s 5\n", a.RecordID))
	code, res, _ := w.run(t, "add", "alice", "web-1", "--json")
	if code == 0 || targetStates(res)["web-1"] != model.AccessFailed || !strings.Contains(res.Targets[0].Message, "was removed here (gen 5)") {
		t.Fatalf("add over a tombstone: %d %+v", code, res)
	}
	w.setAK(t, 0, w.orig[0]+fmt.Sprintf("# hop-access-removed %s 5\n", a.RecordID))
	code, fs := w.check(t)
	if code != 1 || kinds(fs)["tombstone-not-removed"] != 1 {
		t.Fatalf("check: %d %+v", code, fs)
	}
	for _, f := range fs {
		if strings.Contains(f.Fix, "hop access add") {
			t.Errorf("check offers add over a tombstone: %+v", f)
		}
	}
	// rm records removed without writing.
	if code, res, _ := w.run(t, "rm", "alice", "--yes", "--json"); code != 0 || !res.Deleted {
		t.Fatalf("rm: %d %+v", code, res)
	}
	if w.ak(t, 0) != w.orig[0]+fmt.Sprintf("# hop-access-removed %s 5\n", a.RecordID) {
		t.Fatal("rm wrote")
	}
}

// A held lock stops the session with nothing changed and nothing stored;
// the next run resumes the pending target.
func TestAccessHeldLock(t *testing.T) {
	w := newAccessWorld(t, 1)
	lock := filepath.Join(w.srv[0].home, ".ssh", ".hop-authorized_keys.lock.d")
	os.Mkdir(lock, 0o700)
	os.WriteFile(filepath.Join(lock, "owner"), []byte("abc 42 2026-10-29T00:00:00Z\n"), 0o600)
	code, res, _ := w.add(t, "alice", "web-1")
	if code == 0 || len(res.Targets) != 1 || res.Targets[0].Recorded || !strings.Contains(res.Targets[0].Message, "not applied") {
		t.Fatalf("add under a held lock: %d %+v", code, res)
	}
	if a := w.record(t, "alice"); a == nil || a.Targets[0].State != model.AccessPending || a.Targets[0].Gen != 1 {
		t.Fatalf("record %+v", a)
	}
	if w.ak(t, 0) != w.orig[0] {
		t.Fatal("the file changed")
	}
	code, fs := w.check(t)
	if code != 1 || kinds(fs)["unfinished-target"] != 1 || kinds(fs)["lock-or-session-directory"] != 1 {
		t.Fatalf("check: %d %+v", code, fs)
	}
	os.RemoveAll(lock)
	if code, res, _ := w.run(t, "add", "alice", "--json"); code != 0 || targetStates(res)["web-1"] != model.AccessInstalled {
		t.Fatalf("resume: %d %+v", code, res)
	}
}

// Every connection is bound to the pinned key the target was added with:
// a host with no pin gets no target; a binding the pins no longer include
// connects nowhere and stores nothing; migrate moves the target to the
// new key as a new target.
func TestAccessBinding(t *testing.T) {
	w := newAccessWorld(t, 1)
	ctx := context.Background()
	h := w.host(t, "web-1")
	unpinned := h
	unpinned.ItemID, unpinned.ItemVersion, unpinned.Name, unpinned.HostKeys = model.ID{}, 0, "web-3", nil
	if _, err := w.store.PutHost(ctx, unpinned); err != nil {
		t.Fatal(err)
	}
	if code, res, _ := w.add(t, "alice", "web-3"); code == 0 || !strings.Contains(res.Targets[0].Message, "no host key is pinned") {
		t.Fatalf("unpinned: %d %+v", code, res)
	}
	if w.record(t, "alice") != nil {
		t.Fatal("a record was committed for an unpinned host")
	}
	if code, _, _ := w.add(t, "alice", "web-1"); code != 0 {
		t.Fatal("add")
	}
	before := *w.record(t, "alice")
	// The same machine, with a new host key, on a new port.
	s2 := startAKServer(t, w.srv[0].home)
	h = w.host(t, "web-1")
	h.Port, h.HostKeys = uint32(s2.port), []string{authorizedKeysLine(s2.hostKey)}
	if _, err := w.store.PutHost(ctx, h); err != nil {
		t.Fatal(err)
	}
	code, res, _ := w.run(t, "rm", "alice", "--yes", "--json")
	if code == 0 || !strings.Contains(res.Targets[0].Message, "no longer include") {
		t.Fatalf("rm with a lost binding: %d %+v", code, res)
	}
	after := w.record(t, "alice")
	if after.ItemVersion != before.ItemVersion || after.Targets[0] != before.Targets[0] {
		t.Fatalf("a put was journaled: %+v -> %+v", before, after)
	}
	if code, fs := w.check(t); code != 2 || kinds(fs)["cant-read"] != 1 {
		t.Fatalf("check: %d %+v", code, fs)
	}
	code, res, _ = w.run(t, "migrate", "alice", "web-1", "--yes", "--json")
	if code != 0 || targetStates(res)["web-1"] != model.AccessInstalled {
		t.Fatalf("migrate: %d %+v", code, res)
	}
	a := w.record(t, "alice")
	if len(a.Targets) != 2 {
		t.Fatalf("targets %+v", a.Targets)
	}
	for _, x := range a.Targets {
		switch x.ServerKeyFP {
		case ssh.FingerprintSHA256(w.srv[0].hostKey):
			if x.State != model.AccessAbandoned || x.Gen != 2 {
				t.Errorf("old target %+v", x)
			}
		case ssh.FingerprintSHA256(s2.hostKey):
			if x.State != model.AccessInstalled || x.Gen != 1 {
				t.Errorf("new target %+v", x)
			}
		default:
			t.Errorf("target %+v", x)
		}
	}
	if strings.Count(w.ak(t, 0), "hop-access:") != 1 {
		t.Fatalf("file %q", w.ak(t, 0))
	}
	// A migrate back to the old binding would reuse a target (N8).
	h = w.host(t, "web-1")
	h.Port, h.HostKeys = uint32(w.srv[0].port), []string{authorizedKeysLine(w.srv[0].hostKey)}
	w.store.PutHost(ctx, h)
	if code, _, out := w.run(t, "migrate", "alice", "web-1", "--yes"); code == 0 || !strings.Contains(out, "targets are never reused") {
		t.Fatalf("migrate back: %d %s", code, out)
	}
}

// A known shared pin: add warns, rm writes the tombstone but records
// removing until the user states that both records reach the same
// machine; then removed, on that statement.
func TestAccessSharedPin(t *testing.T) {
	w := newAccessWorld(t, 1)
	ctx := context.Background()
	twin := w.host(t, "web-1")
	twin.ItemID, twin.ItemVersion, twin.Name = model.ID{}, 0, "web-1b"
	twin, err := w.store.PutHost(ctx, twin)
	if err != nil {
		t.Fatal(err)
	}
	code, res, _ := w.add(t, "alice", "web-1")
	if code != 0 || len(res.Targets[0].Warnings) == 0 || !strings.Contains(res.Targets[0].Warnings[0], "web-1b") {
		t.Fatalf("add: %d %+v", code, res)
	}
	a := w.record(t, "alice")
	code, res, _ = w.run(t, "rm", "alice", "--yes", "--json")
	if code == 0 || targetStates(res)["web-1"] != model.AccessRemoving || !strings.Contains(res.Targets[0].Message, "--same-machine") {
		t.Fatalf("rm: %d %+v", code, res)
	}
	tomb := fmt.Sprintf("# hop-access-removed %s 2\n", a.RecordID)
	if w.ak(t, 0) != w.orig[0]+tomb {
		t.Fatalf("file %q", w.ak(t, 0))
	}
	code, res, _ = w.run(t, "rm", "alice", "web-1", "--same-machine", "--yes", "--json")
	if code != 0 || targetStates(res)["web-1"] != model.AccessRemoved || !res.Deleted {
		t.Fatalf("rm --same-machine: %d %+v", code, res)
	}
	if w.ak(t, 0) != w.orig[0]+tomb {
		t.Fatal("the second rm wrote")
	}
	_ = twin
}

// check reads terminal targets too: a removed target whose line came back
// (the host restored from before the removal) and a forgotten record's
// line left on an abandoned host.
func TestAccessCheckTerminalTargets(t *testing.T) {
	w := newAccessWorld(t, 2)
	if code, _, _ := w.add(t, "alice", "web-1", "web-2"); code != 0 {
		t.Fatal("add")
	}
	before := w.ak(t, 0)
	if code, _, _ := w.run(t, "rm", "alice", "web-1", "--yes"); code != 0 {
		t.Fatal("rm web-1")
	}
	after := w.ak(t, 0)
	w.setAK(t, 0, before)
	code, fs := w.check(t)
	if code != 1 || kinds(fs)["line-present-removed"] != 1 || kinds(fs)["tombstone-missing"] != 1 {
		t.Fatalf("check after a rollback: %d %+v", code, fs)
	}
	w.setAK(t, 0, after)
	if code, _, _ := w.run(t, "rm", "alice", "--abandon", "web-2", "--yes"); code != 0 {
		t.Fatal("abandon")
	}
	code, fs = w.check(t)
	if code != 0 || kinds(fs)["line-present-abandoned"] != 1 {
		t.Fatalf("check with an abandoned line: %d %+v", code, fs)
	}
	if code, _, _ := w.run(t, "forget", "alice", "--yes"); code != 0 {
		t.Fatal("forget")
	}
	if code, fs := w.check(t); code != 0 || len(fs) != 0 {
		t.Fatalf("check without --all-hosts reads no host: %d %+v", code, fs)
	}
	code, fs = w.check(t, "--all-hosts")
	if code != 1 || kinds(fs)["untracked-line"] != 1 {
		t.Fatalf("check --all-hosts after forget: %d %+v", code, fs)
	}
}

// hop mcp never shows an access record.
func TestAccessNotInMCP(t *testing.T) {
	w := newAccessWorld(t, 1)
	if code, _, _ := w.add(t, "alice", "web-1"); code != 0 {
		t.Fatal("add")
	}
	rid := w.record(t, "alice").RecordID.String()
	m := w.startMCP(t)
	mcpCall[json.RawMessage](m, "list_hosts", map[string]any{})
	for _, raw := range m.raw {
		if strings.Contains(raw, "alice") || strings.Contains(raw, rid) || strings.Contains(raw, w.fp) {
			t.Errorf("hop mcp shows the access record: %s", raw)
		}
	}
	code, out, _ := w.hop(t, "ls", "--json")
	if code != 0 || strings.Contains(out, "alice") || strings.Contains(out, rid) {
		t.Errorf("hop ls shows it: %s", out)
	}
	// A host with a live target can't be deleted.
	if code, _, errOut := w.hop(t, "rm", "web-1", "--yes"); code == 0 || !strings.Contains(errOut, "hop access record alice") {
		t.Errorf("host delete: %d %s", code, errOut)
	}
}
