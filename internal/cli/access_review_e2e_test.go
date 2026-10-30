package cli_test

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/dalyem/hopkey/internal/cli"
	"github.com/dalyem/hopkey/internal/model"
)

// hop access against akServer, for the review of D2: results recorded
// only for the record they were observed for, every branch of the
// session's outcome table, output that never blocks a session's end,
// what check can't read, and abandon and migrate of errored targets.

type accessRun struct {
	code int
	res  cli.AccessRunResult
	out  string
}

// runAsync runs hop access args in the background, with its own stdin, so
// several runs can overlap.
func (w *accessWorld) runAsync(t *testing.T, args ...string) <-chan accessRun {
	t.Helper()
	ch := make(chan accessRun, 1)
	go func() {
		var so, se bytes.Buffer
		env := w.env(t, strings.NewReader(""), &so, &se)
		ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
		defer cancel()
		code := cli.Run(ctx, append([]string{"access"}, args...), env)
		var res cli.AccessRunResult
		if strings.HasPrefix(strings.TrimSpace(so.String()), "{") {
			json.Unmarshal(so.Bytes(), &res)
		}
		ch <- accessRun{code: code, res: res, out: so.String() + se.String()}
	}()
	return ch
}

func wait(t *testing.T, ch <-chan accessRun, what string) accessRun {
	t.Helper()
	select {
	case r := <-ch:
		t.Logf("%s: exit %d\n%s", what, r.code, r.out)
		return r
	case <-time.After(100 * time.Second):
		t.Fatalf("%s did not finish", what)
	}
	return accessRun{}
}

// gate blocks a run at one hook point until it is opened.
type gate struct {
	reached chan struct{}
	open    chan struct{}
	once    sync.Once
}

func newGate() *gate { return &gate{reached: make(chan struct{}), open: make(chan struct{})} }

func (g *gate) pass() {
	g.once.Do(func() { close(g.reached) })
	<-g.open
}

func (g *gate) await(t *testing.T, what string) {
	t.Helper()
	select {
	case <-g.reached:
	case <-time.After(60 * time.Second):
		t.Fatalf("no run reached %s", what)
	}
}

// hooks routes the access test hook to callbacks by point and record ID
// (the zero ID: any record). Each callback runs once.
type hooks struct {
	mu  sync.Mutex
	fns map[string]func()
}

func installHooks(t *testing.T) *hooks {
	h := &hooks{fns: map[string]func(){}}
	cli.SetAccessTestHook(t, func(point string, a *model.Access) {
		h.mu.Lock()
		key := point + " " + a.RecordID.String()
		f, ok := h.fns[key]
		if !ok {
			key = point + " " + model.ID{}.String()
			f = h.fns[key]
		}
		delete(h.fns, key)
		h.mu.Unlock()
		if f != nil {
			f()
		}
	})
	return h
}

func (h *hooks) on(point string, rid model.ID, f func()) {
	h.mu.Lock()
	h.fns[point+" "+rid.String()] = f
	h.mu.Unlock()
}

func (h *hooks) at(point string, rid model.ID) *gate {
	g := newGate()
	h.on(point, rid, g.pass)
	return g
}

// pending adds record label on hosts, each target committed pending and
// never acted on: every host is down from the first session on.
func (w *accessWorld) pending(t *testing.T, h *hooks, label string, hosts ...string) *model.Access {
	t.Helper()
	h.on("before-session", model.ID{}, func() {
		for _, s := range w.srv {
			s.down.Store(true)
		}
	})
	code, res, _ := w.add(t, label, hosts...)
	for _, s := range w.srv {
		s.down.Store(false)
	}
	a := w.record(t, label)
	if code == 0 || a == nil || len(res.Targets) != len(hosts) {
		t.Fatalf("pending add: %d %+v", code, res)
	}
	for _, x := range a.Targets {
		if x.State != model.AccessPending || x.Gen != 1 {
			t.Fatalf("target %+v", x)
		}
	}
	return a
}

// The P1 interleaving of the review. An old rm of A removes A's line
// under removing/gen 2 and is held before it records. Another run
// finishes A and deletes it. A new record B takes A's label, installs,
// commits removing/gen 2 for the same host and binding, and is held
// before its session. The old run's observation (host, binding, removing,
// gen 2) would match B's target exactly; it must not be recorded for B.
func TestAccessResultsKeepTheRecordTheyWereFor(t *testing.T) {
	w := newAccessWorld(t, 1)
	h := installHooks(t)
	if code, _, _ := w.add(t, "alice", "web-1"); code != 0 {
		t.Fatal("add A")
	}
	a := w.record(t, "alice")
	oldRecord := h.at("before-record", a.RecordID)
	old := w.runAsync(t, "rm", "alice", "--yes", "--json")
	oldRecord.await(t, "the old rm's record step")
	if strings.Contains(w.ak(t, 0), "hop-access:"+a.RecordID.String()) {
		t.Fatal("the old rm did not remove A's line")
	}

	// Another run finds A's line gone and its tombstone there, and
	// finishes A: removed, and the record deleted.
	if code, res, _ := w.run(t, "rm", "alice", "--yes", "--json"); code != 0 || !res.Deleted {
		t.Fatalf("finishing A: %d %+v", code, res)
	}
	// B: the same label, the same colleague, the same host and binding.
	if code, _, _ := w.add(t, "alice", "web-1"); code != 0 {
		t.Fatal("add B")
	}
	b := w.record(t, "alice")
	if b.RecordID == a.RecordID || b.ItemID == a.ItemID {
		t.Fatal("B is A")
	}
	bLine := w.pub + " hop-access:" + b.RecordID.String()
	if !strings.Contains(w.ak(t, 0), bLine) {
		t.Fatal("B's line is not there")
	}
	bSession := h.at("before-session", b.RecordID)
	newer := w.runAsync(t, "rm", "alice", "--yes", "--json")
	bSession.await(t, "B's rm's session")
	if x := w.record(t, "alice"); x == nil || x.Targets[0].State != model.AccessRemoving || x.Targets[0].Gen != 2 || x.Targets[0].ServerKeyFP != a.Targets[0].ServerKeyFP {
		t.Fatalf("B before its session: %+v", x)
	}

	close(oldRecord.open)
	r := wait(t, old, "the old rm")
	if r.code == 0 || len(r.res.Targets) != 1 || r.res.Targets[0].Recorded || r.res.Deleted {
		t.Fatalf("the old rm recorded something: %+v", r.res)
	}
	if x := w.record(t, "alice"); x == nil || x.RecordID != b.RecordID || x.Targets[0].State != model.AccessRemoving {
		t.Fatalf("B after the old run recorded: %+v", x)
	}

	close(bSession.open)
	if r := wait(t, newer, "B's rm"); r.code != 0 || !r.res.Deleted {
		t.Fatalf("B's rm: %+v", r.res)
	}
	if got := w.ak(t, 0); strings.Contains(got, bLine) || !strings.Contains(got, fmt.Sprintf("# hop-access-removed %s 2", b.RecordID)) {
		t.Fatalf("B's line is still there, or its tombstone isn't: %q", got)
	}
	if code, fs := w.check(t, "--all-hosts"); code != 0 || kinds(fs)["untracked-line"] != 0 {
		t.Fatalf("check: %d %+v", code, fs)
	}
}

// A delayed observation: an add run installs web-1's line and is held
// before it records; meanwhile an rm of web-1 removes it. The add's
// result for web-1 is dropped (the newer operation owns the target), its
// result for web-2 is recorded, and the run reports web-1 as not recorded
// and exits non-zero.
func TestAccessDelayedObservationIsDropped(t *testing.T) {
	w := newAccessWorld(t, 2)
	h := installHooks(t)
	a := w.pending(t, h, "alice", "web-1", "web-2")
	held := h.at("before-record", a.RecordID)
	addRun := w.runAsync(t, "add", "alice", "--json")
	held.await(t, "the add's record step")
	if code, res, _ := w.run(t, "rm", "alice", "web-1", "--yes", "--json"); code != 0 || targetStates(res)["web-1"] != model.AccessRemoved {
		t.Fatalf("rm web-1: %d %+v", code, res)
	}
	close(held.open)
	r := wait(t, addRun, "the held add")
	byHost := map[string]cli.AccessTargetResult{}
	for _, x := range r.res.Targets {
		byHost[x.Host] = x
	}
	if r.code == 0 || byHost["web-1"].Recorded || !strings.Contains(byHost["web-1"].Message, "not recorded: another run owns this target now") ||
		!byHost["web-2"].Recorded || byHost["web-2"].State != model.AccessInstalled {
		t.Fatalf("the held add: %d %+v", r.code, r.res)
	}
	got := w.record(t, "alice")
	for _, x := range got.Targets {
		host := w.hostName(t, x.HostItemID)
		if (host == "web-1") != (x.State == model.AccessRemoved) || (host == "web-2") != (x.State == model.AccessInstalled) {
			t.Errorf("%s: %+v", host, x)
		}
	}
}

func (w *accessWorld) hostName(t *testing.T, id model.ID) string {
	t.Helper()
	snap, _ := w.store.Snapshot(context.Background())
	for _, h := range snap.Hosts {
		if h.ItemID == id {
			return h.Name
		}
	}
	return ""
}

// A result the vault refuses to store is reported as the host's outcome,
// not recorded, and fails the run (review P2-7).
func TestAccessUnrecordedResultFails(t *testing.T) {
	w := newAccessWorld(t, 1)
	refuse := func(a model.Access) error {
		if len(a.Targets) > 0 && a.Targets[0].State == model.AccessInstalled {
			return errors.New("the vault refused the write")
		}
		return nil
	}
	w.store.PutAccessHook.Store(&refuse)
	code, res, _ := w.add(t, "alice", "web-1")
	w.store.PutAccessHook.Store(nil)
	if code == 0 || len(res.Targets) != 1 || res.Targets[0].Recorded || res.Targets[0].State != model.AccessInstalled ||
		!strings.Contains(res.Targets[0].Message, "not recorded") {
		t.Fatalf("add: %d %+v", code, res)
	}
	if a := w.record(t, "alice"); a.Targets[0].State != model.AccessPending {
		t.Fatalf("the record says %s", a.Targets[0].State)
	}
	// The line is there; the next run records it.
	if code, res, _ := w.run(t, "add", "alice", "--json"); code != 0 || !res.Targets[0].Recorded {
		t.Fatalf("resume: %d %+v", code, res)
	}
}

// Labels compare under K_alias: another case, or a trailing dot, names
// the same record, and a second record with such a label is refused.
func TestAccessLabelsCompareUnderKAlias(t *testing.T) {
	w := newAccessWorld(t, 1)
	if code, _, _ := w.add(t, "alice", "web-1"); code != 0 {
		t.Fatal("add")
	}
	code, out, errOut := w.hop(t, "access", "ls", "ALICE.", "--json")
	var views []cli.AccessView
	if code != 0 || json.Unmarshal([]byte(out), &views) != nil || len(views) != 1 || views[0].Label != "alice" {
		t.Fatalf("ls ALICE.: %d %s %s", code, out, errOut)
	}
	if code, res, _ := w.run(t, "rm", " Alice.", "--yes", "--json"); code != 0 || !res.Deleted {
		t.Fatalf("rm by another spelling: %d %+v", code, res)
	}
	if code, _, _ := w.add(t, "bob", "web-1"); code != 0 {
		t.Fatal("add bob")
	}
	before := w.ak(t, 0)
	// The existing record, not a new one: its key can't change.
	other := newSigner(t)
	code, _, out = w.run(t, "add", "BOB", "web-1", "--pubkey", authorizedKeysLine(other.PublicKey()), "--fingerprint", ssh.FingerprintSHA256(other.PublicKey()), "--yes")
	if code == 0 || !strings.Contains(out, "its key and options can't change") || w.ak(t, 0) != before {
		t.Fatalf("add BOB with another key: %d %s", code, out)
	}
}

// The session's statuses and re-reads (§7.7 tables), on a real ssh client
// against akServer: each way a session can end, what the target records,
// and that the file holds what the outcome says.
func TestAccessSessionOutcomes(t *testing.T) {
	type outcome struct {
		code     int    // 0 or non-zero (1)
		state    string // the target's state in the vault afterwards
		recorded bool
		message  string // in the target's message
		line     bool   // the record's line is in the file
	}
	// dropOnDecision waits for the client's decision to start arriving,
	// and drops the connection before the script gets any of it: the
	// client decided while the host was still waiting.
	dropOnDecision := func(command string, stdin io.Writer, client io.Reader) bool {
		if !strings.Contains(command, ".hop-s.") {
			io.Copy(stdin, client)
			return false
		}
		io.ReadFull(client, make([]byte, 1))
		return true
	}
	cases := []struct {
		name  string
		setup func(t *testing.T, w *accessWorld)
		want  outcome
	}{
		{"87 without abort: input ended", func(t *testing.T, w *accessWorld) {
			w.srv[0].setOnStdin(func(command string, stdin io.Writer, client io.Reader) bool {
				if strings.Contains(command, ".hop-s.") {
					return false // the script's stdin closes with no decision
				}
				io.Copy(stdin, client)
				return false
			})
		}, outcome{1, model.AccessPending, false, "the session ended before hop sent its change", false}},
		{"disconnect before the decision arrives", func(t *testing.T, w *accessWorld) {
			w.srv[0].setOnStdin(dropOnDecision)
		}, outcome{1, model.AccessPending, false, "run hop access add alice again", false}},
		{"disconnect during the payload", func(t *testing.T, w *accessWorld) {
			// The decision line, and a few bytes of the new file.
			w.srv[0].setOnStdin(func(command string, stdin io.Writer, client io.Reader) bool {
				if !strings.Contains(command, ".hop-s.") {
					io.Copy(stdin, client)
					return false
				}
				br := bufio.NewReader(client)
				line, _ := br.ReadString('\n')
				io.WriteString(stdin, line)
				io.CopyN(stdin, br, 10)
				time.Sleep(200 * time.Millisecond)
				return true
			})
		}, outcome{1, model.AccessPending, false, "run hop access add alice again", false}},
		{"disconnect after the rename", func(t *testing.T, w *accessWorld) {
			w.srv[0].setOnExec(func(command string) bool { return isAKWrite(command) })
		}, outcome{0, model.AccessInstalled, true, "", true}},
		{"re-read finds something else", func(t *testing.T, w *accessWorld) {
			wrote := false
			w.srv[0].setOnExec(func(command string) bool {
				if isAKWrite(command) {
					wrote = true
					return true
				}
				if wrote {
					f, _ := os.OpenFile(filepath.Join(w.srv[0].home, ".ssh", "authorized_keys"), os.O_APPEND|os.O_WRONLY, 0)
					f.WriteString("# someone else\n")
					f.Close()
				}
				return false
			})
		}, outcome{1, model.AccessFailed, true, "the file changed in a way hop didn't expect", true}},
		{"re-read fails", func(t *testing.T, w *accessWorld) {
			w.srv[0].setOnExec(func(command string) bool {
				if isAKWrite(command) {
					w.srv[0].down.Store(true)
					return true
				}
				return false
			})
		}, outcome{1, model.AccessFailed, true, "hop could not tell whether it changed", true}},
		{"89: cleanup not confirmed", func(t *testing.T, w *accessWorld) {
			w.srv[0].setPath(fakeServerBin(t, map[string]string{"rmdir": "exit 1"}))
		}, outcome{0, model.AccessInstalled, true, "", true}},
		{"86: mv failed", func(t *testing.T, w *accessWorld) {
			w.srv[0].setPath(fakeServerBin(t, map[string]string{"mv": "exit 1"}))
		}, outcome{1, model.AccessPending, false, "run hop access add alice again", false}},
		{"84: the probe failed", func(t *testing.T, w *accessWorld) {
			w.srv[0].setPath(fakeServerBin(t, map[string]string{"ln": "exit 1"}))
		}, outcome{1, model.AccessFailed, true, "can't be hard-linked", false}},
		{"83: the file changed before the rename", func(t *testing.T, w *accessWorld) {
			w.srv[0].setOnStdin(func(command string, stdin io.Writer, client io.Reader) bool {
				if strings.Contains(command, ".hop-s.") {
					br := bufio.NewReader(client)
					line, _ := br.ReadString('\n')
					f, _ := os.OpenFile(filepath.Join(w.srv[0].home, ".ssh", "authorized_keys"), os.O_APPEND|os.O_WRONLY, 0)
					f.WriteString("# a writer that ignores the lock\n")
					f.Close()
					io.WriteString(stdin, line)
					io.Copy(stdin, br)
					return false
				}
				io.Copy(stdin, client)
				return false
			})
		}, outcome{1, model.AccessFailed, true, "changed while hop was editing it", false}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			w := newAccessWorld(t, 1)
			// The binding preflight is a plain read; the hooks act on the
			// session only.
			c.setup(t, w)
			code, res, _ := w.add(t, "alice", "web-1")
			w.srv[0].setOnExec(nil)
			w.srv[0].setOnStdin(nil)
			w.srv[0].setPath("")
			w.srv[0].down.Store(false)
			a := w.record(t, "alice")
			line := strings.Contains(w.ak(t, 0), "hop-access:"+a.RecordID.String())
			if (code == 0) != (c.want.code == 0) || len(res.Targets) != 1 || res.Targets[0].Recorded != c.want.recorded ||
				!strings.Contains(res.Targets[0].Message, c.want.message) || a.Targets[0].State != c.want.state || a.Targets[0].Gen != 1 || line != c.want.line {
				t.Fatalf("exit %d %+v; vault %+v; line %v", code, res, a.Targets[0], line)
			}
			if c.want.state == model.AccessFailed && a.Targets[0].Error == "" {
				t.Error("a failed target with no error")
			}
		})
	}
}

// The same tables for rm: a rename whose status was lost is re-read and
// recorded removed; a failed mv stays removing with nothing stored; a
// re-read that fails stays removing with the error.
func TestAccessRemoveSessionOutcomes(t *testing.T) {
	cases := []struct {
		name     string
		setup    func(t *testing.T, w *accessWorld)
		code     int
		state    string
		recorded bool
		message  string
	}{
		{"disconnect after the rename", func(t *testing.T, w *accessWorld) {
			w.srv[0].setOnExec(func(command string) bool { return isAKWrite(command) })
		}, 0, model.AccessRemoved, true, ""},
		{"86: mv failed", func(t *testing.T, w *accessWorld) {
			w.srv[0].setPath(fakeServerBin(t, map[string]string{"mv": "exit 1"}))
		}, 1, model.AccessRemoving, false, "run hop access rm alice again"},
		{"re-read fails", func(t *testing.T, w *accessWorld) {
			w.srv[0].setOnExec(func(command string) bool {
				if isAKWrite(command) {
					w.srv[0].down.Store(true)
					return true
				}
				return false
			})
		}, 1, model.AccessRemoving, true, "hop could not tell whether it changed"},
		{"disconnect before the decision arrives", func(t *testing.T, w *accessWorld) {
			w.srv[0].setOnStdin(func(command string, stdin io.Writer, client io.Reader) bool {
				if !strings.Contains(command, ".hop-s.") {
					io.Copy(stdin, client)
					return false
				}
				return true
			})
		}, 1, model.AccessRemoving, false, "run hop access rm alice again"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			w := newAccessWorld(t, 2)
			if code, _, _ := w.add(t, "alice", "web-1", "web-2"); code != 0 {
				t.Fatal("add")
			}
			c.setup(t, w)
			code, res, _ := w.run(t, "rm", "alice", "web-1", "--yes", "--json")
			w.srv[0].setOnExec(nil)
			w.srv[0].setOnStdin(nil)
			w.srv[0].setPath("")
			w.srv[0].down.Store(false)
			a := w.record(t, "alice")
			var x model.AccessTarget
			for _, tg := range a.Targets {
				if w.hostName(t, tg.HostItemID) == "web-1" {
					x = tg
				}
			}
			if (code == 0) != (c.code == 0) || len(res.Targets) != 1 || res.Targets[0].Recorded != c.recorded ||
				!strings.Contains(res.Targets[0].Message, c.message) || x.State != c.state || x.Gen != 2 {
				t.Fatalf("exit %d %+v; vault %+v", code, res, x)
			}
		})
	}
}

// A session whose header hop refuses (a file over 1 MiB, an overlong or
// malformed header) ends at once, whatever the host goes on writing:
// hop sends abort and reads the rest of the output to its end, so ssh's
// copy never blocks and the session's end (or a timeout's kill) doesn't
// wait for it (review P2-2).
func TestAccessRefusedHeaderDoesNotBlock(t *testing.T) {
	cli.SetAccessSessionTimeout(t, 20*time.Second)
	// 3 MiB of comment lines: more than ssh's channel window and a pipe
	// buffer together.
	filler := strings.Repeat("# "+strings.Repeat("x", 1021)+"\n", 3*1024)
	cases := []struct {
		name string
		path map[string]string // fake commands on the host
	}{
		{"a file over 1 MiB", nil},
		{"a header over 256 bytes", map[string]string{"id": `printf '%0300d\n' 0`}},
		{"a malformed header", map[string]string{"id": `echo two words`}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			w := newAccessWorld(t, 1)
			if code, _, _ := w.add(t, "alice", "web-1"); code != 0 {
				t.Fatal("add")
			}
			big := w.ak(t, 0) + filler
			w.setAK(t, 0, big)
			if c.path != nil {
				w.srv[0].setPath(fakeServerBin(t, c.path))
			}
			start := time.Now()
			code, res, _ := w.run(t, "rm", "alice", "--yes", "--json")
			took := time.Since(start)
			if took > 15*time.Second {
				t.Errorf("rm took %s", took)
			}
			if code == 0 || len(res.Targets) != 1 || res.Targets[0].Recorded || !strings.Contains(res.Targets[0].Message, "not applied") {
				t.Fatalf("rm: %d %+v", code, res)
			}
			if w.ak(t, 0) != big {
				t.Fatal("the file changed")
			}
			if entries, _ := os.ReadDir(filepath.Join(w.srv[0].home, ".ssh")); len(entries) != 1 {
				t.Fatalf("~/.ssh holds %d entries: the session left something", len(entries))
			}
		})
	}
}

// hop access check reports every file it couldn't read, terminal targets
// and the other host records of a shared pin included, with exit status 2
// and the host and binding in the JSON (review P2-6).
func TestAccessCheckReportsWhatItCantRead(t *testing.T) {
	w := newAccessWorld(t, 2)
	ctx := context.Background()
	if code, _, _ := w.add(t, "alice", "web-1", "web-2"); code != 0 {
		t.Fatal("add")
	}
	if code, _, _ := w.run(t, "rm", "alice", "web-1", "--yes"); code != 0 {
		t.Fatal("rm web-1")
	}
	a := w.record(t, "alice")
	fp1 := ssh.FingerprintSHA256(w.srv[0].hostKey)
	// web-1's target is removed; its host's pins change.
	h := w.host(t, "web-1")
	h.HostKeys = []string{authorizedKeysLine(newSigner(t).PublicKey())}
	if _, err := w.store.PutHost(ctx, h); err != nil {
		t.Fatal(err)
	}
	code, fs := w.check(t)
	if code != 2 || kinds(fs)["cant-read"] != 1 {
		t.Fatalf("check with an unpinned removed target: %d %+v", code, fs)
	}
	f := fs[slices.IndexFunc(fs, func(f cli.AccessFinding) bool { return f.Kind == "cant-read" })]
	if f.Host != "web-1" || f.Binding != fp1 || f.TargetState != model.AccessRemoved || f.HostID != h.ItemID.String() || f.RecordID != a.RecordID.String() {
		t.Fatalf("finding %+v", f)
	}
	// The host deleted (its only target is terminal, so that is allowed).
	if code, _, errOut := w.hop(t, "rm", "web-1", "--yes"); code != 0 {
		t.Fatalf("host delete: %s", errOut)
	}
	code, fs = w.check(t)
	i := slices.IndexFunc(fs, func(f cli.AccessFinding) bool { return f.Kind == "cant-read" })
	if code != 2 || kinds(fs)["cant-read"] != 1 || !strings.Contains(fs[i].Message, "deleted") || fs[i].Binding != fp1 {
		t.Fatalf("check with a deleted host: %d %+v", code, fs)
	}

	// A shared pin whose other host record can't be read.
	twin := w.host(t, "web-2")
	twin.ItemID, twin.ItemVersion, twin.Name, twin.Port = model.ID{}, 0, "web-2b", 1
	if _, err := w.store.PutHost(ctx, twin); err != nil {
		t.Fatal(err)
	}
	code, fs = w.check(t, "--host", "web-2")
	var through *cli.AccessFinding
	for i := range fs {
		if fs[i].Kind == "cant-read" && fs[i].Host == "web-2b" {
			through = &fs[i]
		}
	}
	if code != 2 || through == nil || through.Binding != ssh.FingerprintSHA256(w.srv[1].hostKey) || !through.Unread {
		t.Fatalf("check with an unreadable twin: %d %+v", code, fs)
	}
}

// Abandon and migrate give the target no error, whatever error it had
// (the schema allows one only on failed and removing targets): a failed
// add, a failed removal, a removal held back by a shared pin, and migrate
// of a failed and of an errored removing target (review P2-3).
func TestAccessAbandonAndMigrateClearTheError(t *testing.T) {
	ctx := context.Background()
	target := func(t *testing.T, w *accessWorld, host string) model.AccessTarget {
		t.Helper()
		for _, x := range w.record(t, "alice").Targets {
			if w.hostName(t, x.HostItemID) == host && !model.AccessTerminal(x.State) {
				return x
			}
		}
		t.Fatalf("no live target on %s", host)
		return model.AccessTarget{}
	}
	abandoned := func(t *testing.T, w *accessWorld, host string, gen uint64) {
		t.Helper()
		for _, x := range w.record(t, "alice").Targets {
			if w.hostName(t, x.HostItemID) == host && x.State == model.AccessAbandoned {
				if x.Gen != gen || x.Error != "" {
					t.Fatalf("abandoned target %+v", x)
				}
				return
			}
		}
		t.Fatalf("no abandoned target on %s", host)
	}
	// failed: the key is already authorized by a line hop doesn't manage.
	failedAdd := func(t *testing.T) *accessWorld {
		w := newAccessWorld(t, 1)
		w.setAK(t, 0, w.orig[0]+w.pub+" by hand\n")
		if code, _, _ := w.add(t, "alice", "web-1"); code == 0 {
			t.Fatal("the add succeeded")
		}
		if x := target(t, w, "web-1"); x.State != model.AccessFailed || x.Error == "" {
			t.Fatalf("target %+v", x)
		}
		return w
	}
	// removing with an error: the file became a symbolic link.
	failedRemove := func(t *testing.T) *accessWorld {
		w := newAccessWorld(t, 1)
		if code, _, _ := w.add(t, "alice", "web-1"); code != 0 {
			t.Fatal("add")
		}
		dir := filepath.Join(w.srv[0].home, ".ssh")
		os.Rename(filepath.Join(dir, "authorized_keys"), filepath.Join(dir, "real_keys"))
		os.Symlink("real_keys", filepath.Join(dir, "authorized_keys"))
		if code, _, _ := w.run(t, "rm", "alice", "--yes"); code == 0 {
			t.Fatal("rm succeeded on a symlink")
		}
		if x := target(t, w, "web-1"); x.State != model.AccessRemoving || !strings.Contains(x.Error, "symbolic link") {
			t.Fatalf("target %+v", x)
		}
		return w
	}
	t.Run("abandon a failed add", func(t *testing.T) {
		w := failedAdd(t)
		if code, _, out := w.run(t, "rm", "alice", "--abandon", "web-1", "--yes"); code != 0 {
			t.Fatalf("abandon: %s", out)
		}
		abandoned(t, w, "web-1", 2)
	})
	t.Run("abandon a failed removal", func(t *testing.T) {
		w := failedRemove(t)
		if code, _, out := w.run(t, "rm", "alice", "--abandon", "web-1", "--yes"); code != 0 {
			t.Fatalf("abandon: %s", out)
		}
		abandoned(t, w, "web-1", 3)
	})
	t.Run("abandon a removal held by a shared pin", func(t *testing.T) {
		w := newAccessWorld(t, 1)
		twin := w.host(t, "web-1")
		twin.ItemID, twin.ItemVersion, twin.Name = model.ID{}, 0, "web-1b"
		if _, err := w.store.PutHost(ctx, twin); err != nil {
			t.Fatal(err)
		}
		if code, _, _ := w.add(t, "alice", "web-1"); code != 0 {
			t.Fatal("add")
		}
		if code, _, _ := w.run(t, "rm", "alice", "--yes"); code == 0 {
			t.Fatal("rm recorded removed on a shared pin")
		}
		if x := target(t, w, "web-1"); x.State != model.AccessRemoving || !strings.Contains(x.Error, "pins the same key") {
			t.Fatalf("target %+v", x)
		}
		if code, _, out := w.run(t, "rm", "alice", "--abandon", "web-1", "--yes"); code != 0 {
			t.Fatalf("abandon: %s", out)
		}
		abandoned(t, w, "web-1", 3)
	})
	newKey := func(t *testing.T, w *accessWorld) {
		t.Helper()
		s2 := startAKServer(t, w.srv[0].home)
		h := w.host(t, "web-1")
		h.Port, h.HostKeys = uint32(s2.port), []string{authorizedKeysLine(s2.hostKey)}
		if _, err := w.store.PutHost(ctx, h); err != nil {
			t.Fatal(err)
		}
	}
	t.Run("migrate a failed target", func(t *testing.T) {
		w := failedAdd(t)
		newKey(t, w)
		// The new target's add fails again on the same hand line, but the
		// migrate itself is committed.
		w.run(t, "migrate", "alice", "web-1", "--yes", "--json")
		abandoned(t, w, "web-1", 2)
		if x := target(t, w, "web-1"); x.Gen != 1 {
			t.Fatalf("new target %+v", x)
		}
	})
	t.Run("migrate an errored removing target", func(t *testing.T) {
		w := failedRemove(t)
		dir := filepath.Join(w.srv[0].home, ".ssh")
		os.Remove(filepath.Join(dir, "authorized_keys"))
		os.Rename(filepath.Join(dir, "real_keys"), filepath.Join(dir, "authorized_keys"))
		newKey(t, w)
		code, res, out := w.run(t, "migrate", "alice", "web-1", "--yes", "--json")
		if code != 0 || targetStates(res)["web-1"] != model.AccessRemoved {
			t.Fatalf("migrate: %d %s", code, out)
		}
		abandoned(t, w, "web-1", 3)
	})
}

// Every ssh that runs an access session carries the keepalive options
// (§7.7, Keepalives); rotate's are pinned by
// TestKeyRotateWritesCarryKeepalives.
func TestAccessSessionsCarryKeepalives(t *testing.T) {
	w := newAccessWorld(t, 1)
	sshPath, err := exec.LookPath("ssh")
	if err != nil {
		t.Fatal(err)
	}
	argvLog := filepath.Join(w.base, "ssh-argv")
	wrapper := filepath.Join(w.base, "ssh-wrapper")
	script := "#!/bin/sh\n{ printf '%s\\037' \"$@\"; echo; } >> '" + argvLog + "'\nexec '" + sshPath + "' \"$@\"\n"
	if err := os.WriteFile(wrapper, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	w.sshBin = wrapper
	if code, _, _ := w.add(t, "alice", "web-1"); code != 0 {
		t.Fatal("add")
	}
	if code, _, _ := w.run(t, "rm", "alice", "--yes"); code != 0 {
		t.Fatal("rm")
	}
	b, err := os.ReadFile(argvLog)
	if err != nil {
		t.Fatal(err)
	}
	sessions := 0
	for _, line := range strings.Split(strings.TrimSuffix(string(b), "\n"), "\n") {
		argv := strings.Split(strings.TrimSuffix(line, "\x1f"), "\x1f")
		if !strings.Contains(argv[len(argv)-1], ".hop-s.") {
			continue
		}
		sessions++
		for _, o := range []string{"ServerAliveInterval=15", "ServerAliveCountMax=3"} {
			if i := slices.Index(argv, o); i < 1 || argv[i-1] != "-o" {
				t.Errorf("a session runs without -o %s: %q", o, argv[:len(argv)-1])
			}
		}
	}
	if sessions != 2 {
		t.Errorf("%d sessions seen, want the add's and the rm's", sessions)
	}
}
