package cli_test

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/dalyem/hopkey/internal/cli"
	"github.com/dalyem/hopkey/internal/daemon"
	"github.com/dalyem/hopkey/internal/merge"
	"github.com/dalyem/hopkey/internal/model"
	"github.com/dalyem/hopkey/internal/resolve"
	"github.com/dalyem/hopkey/internal/store"
)

func ago(f *fakeDaemon, d time.Duration) *time.Time {
	t := f.now.Add(-d)
	return &t
}

// ---- hop sync ----

func TestSyncPrintsTheStatus(t *testing.T) {
	f := newFakeDaemon(t)
	f.reply(daemon.OpSyncNow, daemon.SyncStatusResult{
		State: daemon.SyncOnline, Server: "https://hop.example/" + hostile, Email: "me@example.com" + hostile,
		Pending: 2, Held: 1, SyncedAt: ago(f, 3*time.Minute),
		Warnings: []string{"1 queued change(s) are held " + hostile},
	})
	code, out, errOut := f.hop(t, "sync")
	if code != 0 {
		t.Fatalf("exit %d: %s", code, errOut)
	}
	for _, want := range []string{"sync:", "online", "last sync:", "(3m ago)", "queued:", "2 pending, 1 held (hop sync resolve)", "server:", "account:"} {
		if !strings.Contains(out, want) {
			t.Errorf("output lacks %q:\n%s", want, out)
		}
	}
	assertNoForgery(t, "hop sync", out)
	if n := strings.Count(out, "warning:"); n != 1 {
		t.Errorf("%d warning lines, want 1:\n%s", n, out)
	}
	if got := len(lines(out)); got != 6 { // sync, server, account, last sync, queued, warning
		t.Errorf("%d lines, want 6 (each value on one line):\n%s", got, out)
	}
	if len(f.called(daemon.OpSyncNow)) != 1 {
		t.Errorf("sync.now calls = %d", len(f.called(daemon.OpSyncNow)))
	}
}

func TestSyncJSONAlwaysHasSyncedAt(t *testing.T) {
	f := newFakeDaemon(t)
	for _, at := range []*time.Time{nil, ago(f, time.Minute)} {
		f.reply(daemon.OpSyncNow, daemon.SyncStatusResult{State: daemon.SyncStarting, SyncedAt: at})
		code, out, errOut := f.hop(t, "sync", "--json")
		if code != 0 {
			t.Fatalf("exit %d: %s", code, errOut)
		}
		var m map[string]any
		decodeJSON(t, out, &m)
		v, ok := m["synced_at"]
		if !ok {
			t.Errorf("no synced_at in %s", out)
		}
		if (at == nil) != (v == nil) {
			t.Errorf("synced_at = %v for %v", v, at)
		}
		if m["state"] != daemon.SyncStarting {
			t.Errorf("state = %v", m["state"])
		}
		if _, ok := m["error"]; ok {
			t.Errorf("error in a successful sync: %s", out)
		}
	}
}

func TestSyncExitsNonZeroWhenSyncIsNotWorking(t *testing.T) {
	tests := []struct {
		name    string
		nowCode string // sync.now fails with this code, if set
		state   string
		want    string // in stderr
	}{
		{"unreachable", daemon.CodeUnreachable, daemon.SyncBackingOff, "sync did not run"},
		{"revoked", daemon.CodeRevoked, daemon.SyncRevoked, "sync did not run"},
		{"halted error", daemon.CodeSyncHalted, daemon.SyncHalted, "sync did not run"},
		{"halted state", "", daemon.SyncHalted, "sync is not working (halted)"},
		{"backoff state", "", daemon.SyncBackingOff, "sync is not working (backoff)"},
		{"locked", daemon.CodeLocked, daemon.SyncLocked, "sync did not run"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := newFakeDaemon(t)
			st := daemon.SyncStatusResult{State: tt.state, LastError: "dial tcp: " + hostile, LastErrorAt: ago(f, time.Minute), SyncedAt: ago(f, time.Hour)}
			if tt.nowCode != "" {
				f.fail(daemon.OpSyncNow, tt.nowCode, "server said "+hostile)
				f.reply(daemon.OpSyncStatus, st)
			} else {
				f.reply(daemon.OpSyncNow, st)
			}
			code, out, errOut := f.hop(t, "sync")
			if code != 255 {
				t.Fatalf("exit %d, want 255", code)
			}
			if !strings.Contains(errOut, tt.want) || !strings.Contains(out, "sync:") {
				t.Errorf("stdout %q, stderr %q", out, errOut)
			}
			assertNoForgery(t, "stdout", out)
			assertNoForgery(t, "stderr", errOut)
			if len(lines(errOut)) != 1 {
				t.Errorf("stderr is not one line: %q", errOut)
			}

			code, out, errOut = f.hop(t, "sync", "--json")
			if code != 255 {
				t.Fatalf("--json: exit %d", code)
			}
			var rep cli.SyncReport
			decodeJSON(t, out, &rep)
			if rep.SyncStatusResult == nil || rep.State != tt.state {
				t.Errorf("--json: %s", out)
			}
			if tt.nowCode != "" && (rep.Error == nil || rep.Error.Code != tt.nowCode) {
				t.Errorf("--json error = %+v, want code %s", rep.Error, tt.nowCode)
			}
			var e map[string]string
			decodeJSON(t, errOut, &e)
			if e["error"] == "" {
				t.Errorf("--json stderr = %q", errOut)
			}
		})
	}
}

func TestSyncOnALocalOnlyVault(t *testing.T) {
	f := newFakeDaemon(t)
	f.fail(daemon.OpSyncNow, daemon.CodeLocalOnly, "this vault store does not sync")
	code, _, errOut := f.hop(t, "sync")
	if code != 255 || !strings.Contains(errOut, "local-only") {
		t.Errorf("exit %d, stderr %q", code, errOut)
	}
}

func TestSyncHelpSaysItIsNeverNeeded(t *testing.T) {
	f := newFakeDaemon(t)
	code, _, errOut := f.hop(t, "sync", "-h")
	if code != 0 || !strings.Contains(errOut, "You never need it") || !strings.Contains(errOut, "escape") {
		t.Errorf("exit %d, help %q", code, errOut)
	}
}

// ---- hop status ----

func TestStatusShowsTheSyncBlock(t *testing.T) {
	f := newFakeDaemon(t)
	dup := "the ssh config in /x is out of date " + hostile
	st := daemon.StatusResult{
		Version: "test", PID: 1, StartedAt: f.now.Add(-time.Hour),
		Vault:    &store.Info{DeviceStore: "keychain", DeviceID: "d3v1ce" + hostile, Head: &store.Head{Seq: 9, H: "0123456789abcdef0123"}},
		Warnings: []string{dup},
		Sync: &daemon.SyncStatusResult{
			State: daemon.SyncLocked, Server: "https://hop.example" + hostile, Email: "me@example.com" + hostile,
			Head:      &store.Head{Seq: 9, H: "0123456789abcdef0123"},
			LastError: "refused: " + hostile, LastErrorAt: ago(f, 2*time.Minute),
			ServerRetirement: &daemon.ServerRetirement{How: "revoked" + hostile, Seq: 12, Unverified: true},
			Warnings:         []string{"server-reported, unverified: " + hostile, dup},
			Pending:          1,
		},
	}
	f.reply(daemon.OpStatus, st)
	code, out, errOut := f.hop(t, "status")
	if code != 0 {
		t.Fatalf("exit %d: %s", code, errOut)
	}
	for _, want := range []string{"sync:         paused while the vault is locked", "server:", "account:", "device:       d3v1ce", "last sync:    none since the daemon started",
		"queued:       1 pending, 0 held", "last error:", "retirement:   server-reported, unverified: the server says this device was revoked", "at seq 12"} {
		if !strings.Contains(out, want) {
			t.Errorf("status lacks %q:\n%s", want, out)
		}
	}
	assertNoForgery(t, "hop status", out)
	if n := strings.Count(out, "out of date"); n != 1 {
		t.Errorf("a warning in both lists is shown %d times:\n%s", n, out)
	}
	if n := strings.Count(out, "log head:"); n != 1 {
		t.Errorf("the head is shown %d times:\n%s", n, out)
	}

	code, out, _ = f.hop(t, "status", "--json")
	if code != 0 {
		t.Fatalf("--json: exit %d", code)
	}
	var m struct {
		Sync map[string]json.RawMessage `json:"sync"`
	}
	decodeJSON(t, out, &m)
	if _, ok := m.Sync["synced_at"]; !ok {
		t.Errorf("no sync.synced_at: %s", out)
	}
	var r daemon.ServerRetirement
	if err := json.Unmarshal(m.Sync["server_retirement"], &r); err != nil || !r.Unverified {
		t.Errorf("server_retirement = %s", m.Sync["server_retirement"])
	}
}

// ---- the long-outage and held notices ----

func lsFixture(f *fakeDaemon, marks map[string]model.Mark) []model.Host {
	hosts := []model.Host{
		{Header: model.Header{ItemID: model.ID{1}}, Name: "web-1", Addresses: []string{"10.0.0.1"}, Port: 22},
		{Header: model.Header{ItemID: model.ID{2}}, Name: "web-2", Addresses: []string{"10.0.0.2"}, Port: 22},
		{Header: model.Header{ItemID: model.ID{3}}, Name: "web-3", Addresses: []string{"10.0.0.3"}, Port: 22},
	}
	f.reply(daemon.OpList, daemon.ListResult{Hosts: hosts, Keys: []daemon.KeyInfo{}, SSH: map[string]daemon.HostSSH{}, Marks: marks, SyncedAt: ago(f, time.Minute)})
	return hosts
}

func TestLongOutageNotice(t *testing.T) {
	tests := []struct {
		name     string
		tty      bool
		args     []string
		state    string
		syncedAt time.Duration // 0: none since the daemon started
		held     int
		want     []string // notice lines that must appear; none means no notice
	}{
		{"backoff for 20m", true, []string{"ls"}, daemon.SyncBackingOff, 20 * time.Minute, 0, []string{"sync has been failing; last sync", "(20m ago)"}},
		{"backoff for 5m", true, []string{"ls"}, daemon.SyncBackingOff, 5 * time.Minute, 0, nil},
		{"online but old", true, []string{"ls"}, daemon.SyncOnline, time.Hour, 0, nil},
		{"never synced, daemon up 30m", true, []string{"ls"}, daemon.SyncBackingOff, 0, 0, []string{"since the daemon started"}},
		{"not a terminal", false, []string{"ls"}, daemon.SyncBackingOff, 20 * time.Minute, 0, nil},
		{"json", true, []string{"ls", "--json"}, daemon.SyncBackingOff, 20 * time.Minute, 0, nil},
		{"held", true, []string{"ls"}, daemon.SyncOnline, time.Minute, 1, []string{"1 queued change(s) held", "hop sync resolve"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := newFakeDaemon(t)
			lsFixture(f, nil)
			s := &daemon.SyncStatusResult{State: tt.state, Held: tt.held, LastError: "boom " + hostile}
			if tt.syncedAt > 0 {
				s.SyncedAt = ago(f, tt.syncedAt)
			}
			f.reply(daemon.OpStatus, daemon.StatusResult{StartedAt: f.now.Add(-30 * time.Minute), Sync: s})
			f.tty = tt.tty
			code, _, errOut := f.hop(t, tt.args...)
			if code != 0 {
				t.Fatalf("exit %d: %s", code, errOut)
			}
			assertNoForgery(t, "stderr", errOut)
			if len(tt.want) == 0 {
				if errOut != "" {
					t.Errorf("unexpected notice %q", errOut)
				}
				return
			}
			if len(lines(errOut)) != 1 {
				t.Errorf("notice is not one line: %q", errOut)
			}
			for _, w := range tt.want {
				if !strings.Contains(errOut, w) {
					t.Errorf("notice %q lacks %q", errOut, w)
				}
			}
		})
	}
}

// ---- markers in ls, info and key ls ----

func TestMarksInLsAndInfo(t *testing.T) {
	f := newFakeDaemon(t)
	hosts := lsFixture(f, map[string]model.Mark{model.ID{1}.String(): model.MarkPending, model.ID{2}.String(): model.MarkHeld})

	code, out, errOut := f.hop(t, "ls")
	if code != 0 {
		t.Fatalf("exit %d: %s", code, errOut)
	}
	ls := lines(out)
	if !strings.HasSuffix(strings.TrimSpace(ls[0]), "SYNC") {
		t.Errorf("no SYNC column: %q", ls[0])
	}
	for i, want := range []string{"pending", "held", "-"} {
		if fl := strings.Fields(ls[i+1]); fl[len(fl)-1] != want {
			t.Errorf("row %d = %q, want mark %s", i, ls[i+1], want)
		}
	}

	code, out, _ = f.hop(t, "ls", "--json")
	if code != 0 {
		t.Fatalf("--json exit %d", code)
	}
	var views []cli.HostView
	decodeJSON(t, out, &views)
	if len(views) != 3 || views[0].Mark != model.MarkPending || views[1].Mark != model.MarkHeld || views[2].Mark != "" {
		t.Errorf("marks = %+v", views)
	}
	if strings.Count(out, `"mark"`) != 2 {
		t.Errorf("an unmarked host has a mark member:\n%s", out)
	}

	h := hosts[1]
	f.reply(daemon.OpResolve, daemon.ResolveResult{
		Result: &resolve.Result{Target: "web-2", Status: resolve.StatusMatched, HostID: h.ItemID.String(), HostName: h.Name},
		Host:   &h, SSHAlias: "web-2", Mark: model.MarkHeld,
	})
	code, out, errOut = f.hop(t, "info", "web-2")
	if code != 0 {
		t.Fatalf("info: exit %d: %s", code, errOut)
	}
	if !strings.Contains(out, "sync:         held: conflicts with the server; run hop sync resolve") {
		t.Errorf("info:\n%s", out)
	}
	code, out, _ = f.hop(t, "info", "web-2", "--json")
	var v cli.HostView
	decodeJSON(t, out, &v)
	if code != 0 || v.Mark != model.MarkHeld {
		t.Errorf("info --json: exit %d, mark %q", code, v.Mark)
	}
}

func TestLsWithoutMarksHasNoSyncColumn(t *testing.T) {
	f := newFakeDaemon(t)
	lsFixture(f, nil)
	_, out, _ := f.hop(t, "ls")
	if strings.Contains(out, "SYNC") {
		t.Errorf("SYNC column with nothing marked:\n%s", out)
	}
}

func TestKeyLsShowsMarks(t *testing.T) {
	f := newFakeDaemon(t)
	f.reply(daemon.OpList, daemon.ListResult{
		Hosts: []model.Host{}, SSH: map[string]daemon.HostSSH{},
		Keys:  []daemon.KeyInfo{{ID: model.ID{7}.String(), Name: "deploy", KeyType: "ssh-ed25519", Fingerprint: "SHA256:x"}},
		Marks: map[string]model.Mark{model.ID{7}.String(): model.MarkPending},
	})
	_, out, _ := f.hop(t, "key", "ls")
	if !strings.Contains(out, "SYNC") || !strings.Contains(out, "pending") {
		t.Errorf("key ls:\n%s", out)
	}
	_, out, _ = f.hop(t, "key", "ls", "--json")
	var keys []cli.KeyView
	decodeJSON(t, out, &keys)
	if len(keys) != 1 || keys[0].Mark != model.MarkPending {
		t.Errorf("key ls --json: %s", out)
	}
}

// ---- hop sync resolve ----

const (
	token1 = "1111111111111111111111111111111111111111111111111111111111111111"
	token2 = "2222222222222222222222222222222222222222222222222222222222222222"
	editTk = "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
)

func hostJSON(version int, addr, desc string) json.RawMessage {
	b, _ := json.Marshal(map[string]any{
		"v": 1, "item_id": model.ID{1}.String(), "type": "host", "item_version": version,
		"name": "web-1", "aliases": []string{}, "addresses": []string{addr}, "port": 22, "user": "deploy",
		"tags": []string{}, "description": desc, "route": "auto", "host_keys": []string{}, "agent_access": "allow",
	})
	return b
}

func heldHost(token string) daemon.SyncHeldResult {
	mine := hostJSON(3, "10.0.0.2", "")
	theirs := hostJSON(4, "10.0.0.3", "theirs "+hostile)
	return daemon.SyncHeldResult{Held: []daemon.HeldChange{{
		N: 7, Action: merge.ActionPut, ItemID: model.ID{1}.String(), Type: model.TypeHost,
		Seen: hostJSON(3, "10.0.0.1", ""), Want: mine, Current: theirs,
		Hold:    &store.HoldInfo{Cause: merge.CauseGuardedConflict, Local: []string{"addresses"}, Remote: []string{"addresses"}, Reason: "both " + hostile},
		Choices: []string{daemon.ChoiceKeepMine, daemon.ChoiceEdit, daemon.ChoiceTakeTheirs, daemon.ChoiceRetry},
		KeepMine: &daemon.Proposal{
			N: 7, Choice: daemon.ChoiceKeepMine, Action: merge.ActionPut, ItemID: model.ID{1}.String(), Type: model.TypeHost,
			Seen: theirs, Want: hostJSON(4, "10.0.0.2", "theirs "+hostile), Confirm: token,
		},
	}}}
}

func resolveParams(t *testing.T, raw json.RawMessage) daemon.SyncResolveParams {
	t.Helper()
	var p daemon.SyncResolveParams
	if err := json.Unmarshal(raw, &p); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestSyncResolveListsAndAppliesNothingWithoutAChoice(t *testing.T) {
	f := newFakeDaemon(t)
	f.reply(daemon.OpSyncHeld, heldHost(token1))
	f.fail(daemon.OpSyncResolve, daemon.CodeInternal, "must not be called")

	code, out, errOut := f.hop(t, "sync", "resolve", "--json")
	if code != 0 {
		t.Fatalf("exit %d: %s", code, errOut)
	}
	var res daemon.SyncHeldResult
	decodeJSON(t, out, &res)
	if len(res.Held) != 1 || res.Held[0].KeepMine == nil || res.Held[0].KeepMine.Confirm != token1 {
		t.Errorf("--json: %s", out)
	}

	code, out, errOut = f.hop(t, "sync", "resolve")
	if code != 0 {
		t.Fatalf("text: exit %d: %s", code, errOut)
	}
	for _, want := range []string{"change 7 is held: put host \"web-1\"", "both changed its protected fields", "addresses", "10.0.0.2", "10.0.0.3",
		"hop sync resolve 7 --keep-mine --confirm " + token1, "hop sync resolve 7 --take-theirs --yes", "hop sync resolve 7 --retry"} {
		if !strings.Contains(out, want) {
			t.Errorf("listing lacks %q:\n%s", want, out)
		}
	}
	assertNoForgery(t, "listing", out)
	if n := len(f.called(daemon.OpSyncResolve)); n != 0 {
		t.Errorf("sync.resolve called %d times without a choice", n)
	}
}

func TestSyncResolveNothingHeld(t *testing.T) {
	f := newFakeDaemon(t)
	f.reply(daemon.OpSyncHeld, daemon.SyncHeldResult{})
	code, out, _ := f.hop(t, "sync", "resolve")
	if code != 0 || !strings.Contains(out, "nothing is held") {
		t.Errorf("exit %d: %q", code, out)
	}
	code, out, _ = f.hop(t, "sync", "resolve", "--json")
	if code != 0 || !strings.Contains(out, `"held": []`) {
		t.Errorf("--json: exit %d: %q", code, out)
	}
}

func TestSyncResolveKeepMineNeedsTheToken(t *testing.T) {
	f := newFakeDaemon(t)
	f.reply(daemon.OpSyncHeld, heldHost(token1))
	f.reply(daemon.OpSyncResolve, daemon.SyncResolveResult{Status: &daemon.SyncStatusResult{State: daemon.SyncOnline}})

	// Without --confirm and without a terminal: the proposal, nothing applied.
	code, out, errOut := f.hop(t, "sync", "resolve", "7", "--keep-mine")
	if code != 255 || !strings.Contains(errOut, "needs --confirm") {
		t.Errorf("exit %d, stderr %q", code, errOut)
	}
	for _, want := range []string{"keep mine writes put host \"web-1\"", "WOULD BE", "addresses", "--confirm " + token1} {
		if !strings.Contains(out, want) {
			t.Errorf("proposal lacks %q:\n%s", want, out)
		}
	}
	assertNoForgery(t, "proposal", out)
	code, out, _ = f.hop(t, "sync", "resolve", "7", "--keep-mine", "--json")
	var prop struct{ Proposal daemon.Proposal }
	decodeJSON(t, out, &prop)
	if code != 255 || prop.Proposal.Confirm != token1 {
		t.Errorf("--json: exit %d, %s", code, out)
	}
	// A terminal with --json is not interactive either.
	f.tty = true
	if code, _, _ := f.hop(t, "sync", "resolve", "7", "--keep-mine", "--json"); code != 255 {
		t.Errorf("--json on a terminal: exit %d", code)
	}
	if n := len(f.called(daemon.OpSyncResolve)); n != 0 {
		t.Fatalf("sync.resolve called %d times without a token", n)
	}

	// With the token.
	code, out, errOut = f.hop(t, "sync", "resolve", "7", "--keep-mine", "--confirm", token1)
	if code != 0 || !strings.Contains(out, "change 7 resolved: keep-mine") {
		t.Fatalf("exit %d: %s %s", code, out, errOut)
	}
	calls := f.called(daemon.OpSyncResolve)
	if len(calls) != 1 {
		t.Fatalf("sync.resolve calls = %d", len(calls))
	}
	if p := resolveParams(t, calls[0]); p.N != 7 || p.Choice != daemon.ChoiceKeepMine || p.Confirm != token1 || p.Propose {
		t.Errorf("params = %+v", p)
	}
}

func TestSyncResolveStaleConfirm(t *testing.T) {
	t.Run("non-interactive fails", func(t *testing.T) {
		f := newFakeDaemon(t)
		f.reply(daemon.OpSyncHeld, heldHost(token2))
		f.fail(daemon.OpSyncResolve, daemon.CodeStaleConfirm, "store: the confirmation no longer matches")
		code, _, errOut := f.hop(t, "sync", "resolve", "7", "--keep-mine", "--confirm", token1)
		if code != 255 || !strings.Contains(errOut, "nothing was written") || !strings.Contains(errOut, "hop sync resolve 7 again") {
			t.Errorf("exit %d, stderr %q", code, errOut)
		}
		if n := len(f.called(daemon.OpSyncResolve)); n != 1 {
			t.Errorf("sync.resolve calls = %d, want 1", n)
		}
	})
	t.Run("interactive fetches again and asks again", func(t *testing.T) {
		f := newFakeDaemon(t)
		fetches := 0
		f.on(daemon.OpSyncHeld, func(json.RawMessage) (any, error) {
			fetches++
			if fetches == 1 {
				return heldHost(token1), nil
			}
			return heldHost(token2), nil
		})
		f.on(daemon.OpSyncResolve, func(raw json.RawMessage) (any, error) {
			var p daemon.SyncResolveParams
			json.Unmarshal(raw, &p)
			if p.Confirm != token2 {
				return nil, &daemon.Error{Code: daemon.CodeStaleConfirm, Message: "stale"}
			}
			return daemon.SyncResolveResult{Status: &daemon.SyncStatusResult{State: daemon.SyncOnline}}, nil
		})
		f.tty, f.stdin = true, "k\ny\ny\n"
		code, out, errOut := f.hop(t, "sync", "resolve")
		if code != 0 {
			t.Fatalf("exit %d: %s\n%s", code, out, errOut)
		}
		if !strings.Contains(errOut, "updated while you looked") || strings.Count(out, "keep mine writes") != 2 {
			t.Errorf("not asked again:\n%s\n%s", out, errOut)
		}
		calls := f.called(daemon.OpSyncResolve)
		if len(calls) != 2 || resolveParams(t, calls[0]).Confirm != token1 || resolveParams(t, calls[1]).Confirm != token2 {
			t.Errorf("calls = %s", calls)
		}
	})
	t.Run("interactive no applies nothing", func(t *testing.T) {
		f := newFakeDaemon(t)
		f.reply(daemon.OpSyncHeld, heldHost(token1))
		f.tty, f.stdin = true, "k\nn\n"
		if code, _, _ := f.hop(t, "sync", "resolve"); code != 255 {
			t.Errorf("exit %d", code)
		}
		if n := len(f.called(daemon.OpSyncResolve)); n != 0 {
			t.Errorf("sync.resolve calls = %d after no", n)
		}
	})
}

func TestSyncResolveTakeTheirsAndRetry(t *testing.T) {
	f := newFakeDaemon(t)
	f.reply(daemon.OpSyncHeld, heldHost(token1))
	f.reply(daemon.OpSyncResolve, daemon.SyncResolveResult{Status: &daemon.SyncStatusResult{State: daemon.SyncOnline}})

	if code, _, errOut := f.hop(t, "sync", "resolve", "7", "--take-theirs"); code != 255 || !strings.Contains(errOut, "--yes") {
		t.Errorf("take-theirs without --yes: exit %d, %q", code, errOut)
	}
	if code, _, errOut := f.hop(t, "sync", "resolve", "--take-theirs", "--yes"); code != 255 || !strings.Contains(errOut, "name the change") {
		t.Errorf("without N: exit %d, %q", code, errOut)
	}
	if code, _, errOut := f.hop(t, "sync", "resolve", "8", "--take-theirs", "--yes"); code != 255 || !strings.Contains(errOut, "change 8 is not held") {
		t.Errorf("wrong N: exit %d, %q", code, errOut)
	}
	if code, _, errOut := f.hop(t, "sync", "resolve", "7", "--retry", "--confirm", token1); code != 255 || !strings.Contains(errOut, "--confirm goes with") {
		t.Errorf("retry with a token: exit %d, %q", code, errOut)
	}
	if n := len(f.called(daemon.OpSyncResolve)); n != 0 {
		t.Fatalf("sync.resolve called %d times on refused input", n)
	}

	code, out, errOut := f.hop(t, "sync", "resolve", "7", "--take-theirs", "--yes", "--json")
	if code != 0 {
		t.Fatalf("exit %d: %s", code, errOut)
	}
	var res map[string]any
	decodeJSON(t, out, &res)
	if res["choice"] != daemon.ChoiceTakeTheirs || res["resolved"] != float64(7) {
		t.Errorf("--json: %s", out)
	}
	if p := resolveParams(t, f.called(daemon.OpSyncResolve)[0]); p.Choice != daemon.ChoiceTakeTheirs || p.Confirm != "" || p.N != 7 {
		t.Errorf("params = %+v", p)
	}

	f.fail(daemon.OpSyncResolve, daemon.CodeStillHeld, "still held: "+hostile)
	code, _, errOut = f.hop(t, "sync", "resolve", "7", "--retry")
	if code != 255 || !strings.Contains(errOut, "change 7 is still held") {
		t.Errorf("retry: exit %d, %q", code, errOut)
	}
	assertNoForgery(t, "retry", errOut)

	f.fail(daemon.OpSyncResolve, daemon.CodeNotHeld, "queued change 7 is not the held one")
	if code, _, errOut := f.hop(t, "sync", "resolve", "7", "--retry"); code != 255 || !strings.Contains(errOut, "no longer held") {
		t.Errorf("not_held: exit %d, %q", code, errOut)
	}
}

func TestSyncResolveEdit(t *testing.T) {
	f := newFakeDaemon(t)
	f.reply(daemon.OpSyncHeld, heldHost(token1))
	newID := model.ID{9}.String()
	f.on(daemon.OpSyncResolve, func(raw json.RawMessage) (any, error) {
		var p daemon.SyncResolveParams
		json.Unmarshal(raw, &p)
		if p.Propose {
			return daemon.SyncResolveResult{Proposal: &daemon.Proposal{N: 7, Choice: daemon.ChoiceEdit, Action: merge.ActionPut, ItemID: model.ID{1}.String(),
				Type: model.TypeHost, Want: p.Edited, NewID: newID, Confirm: editTk}}, nil
		}
		return daemon.SyncResolveResult{Status: &daemon.SyncStatusResult{State: daemon.SyncOnline}}, nil
	})

	code, out, errOut := f.hop(t, "sync", "resolve", "7", "--edit", "--set", "addresses=10.0.0.9, 10.0.0.10", "--set", "port=2222")
	if code != 255 || !strings.Contains(errOut, "needs --confirm") {
		t.Fatalf("without a token: exit %d: %s", code, errOut)
	}
	if !strings.Contains(out, "--new-id "+newID+" --confirm "+editTk) {
		t.Errorf("no command to apply it:\n%s", out)
	}
	calls := f.called(daemon.OpSyncResolve)
	if len(calls) != 1 || !resolveParams(t, calls[0]).Propose {
		t.Fatalf("calls = %s", calls)
	}
	var edited map[string]any
	json.Unmarshal(resolveParams(t, calls[0]).Edited, &edited)
	if a, _ := edited["addresses"].([]any); len(a) != 2 || a[1] != "10.0.0.10" || edited["port"] != float64(2222) || edited["name"] != "web-1" {
		t.Errorf("edited = %v", edited)
	}

	f.reset()
	code, _, errOut = f.hop(t, "sync", "resolve", "7", "--edit", "--set", "addresses=10.0.0.9, 10.0.0.10", "--set", "port=2222", "--new-id", newID, "--confirm", editTk)
	if code != 0 {
		t.Fatalf("with the token: exit %d: %s", code, errOut)
	}
	calls = f.called(daemon.OpSyncResolve)
	if len(calls) != 2 {
		t.Fatalf("calls = %s", calls)
	}
	if p := resolveParams(t, calls[1]); p.Propose || p.Confirm != editTk || p.NewID != newID || p.Choice != daemon.ChoiceEdit || len(p.Edited) == 0 {
		t.Errorf("apply params = %+v", p)
	}

	for _, bad := range [][]string{{"--set", "nosuch=1"}, {"--set", "item_id=x"}, {"--set", "port=many"}, {}} {
		args := append([]string{"sync", "resolve", "7", "--edit"}, bad...)
		if code, _, errOut := f.hop(t, args...); code != 255 {
			t.Errorf("%q: exit %d, %q", bad, code, errOut)
		}
	}
}

func TestSyncResolveKeepMineRefused(t *testing.T) {
	f := newFakeDaemon(t)
	held := heldHost(token1)
	held.Held[0].KeepMine = nil
	held.Held[0].KeepMineRefused = "the server's version is gone " + hostile
	held.Held[0].Choices = []string{daemon.ChoiceTakeTheirs, daemon.ChoiceRetry}
	f.reply(daemon.OpSyncHeld, held)
	code, _, errOut := f.hop(t, "sync", "resolve", "7", "--keep-mine", "--confirm", token1)
	if code != 255 || !strings.Contains(errOut, "keep-mine is not offered") || !strings.Contains(errOut, "the server's version is gone") {
		t.Errorf("exit %d, %q", code, errOut)
	}
	assertNoForgery(t, "refusal", errOut)
}

func TestSyncResolveNeverPrintsSecrets(t *testing.T) {
	f := newFakeDaemon(t)
	key := func(name string) json.RawMessage {
		b, _ := json.Marshal(map[string]any{"v": 1, "item_id": model.ID{5}.String(), "type": "key", "item_version": 1,
			"name": name, "key_type": "ssh-ed25519", "public_key": "ssh-ed25519 AAAA", "private_key": "-----BEGIN SECRET-----"})
		return b
	}
	f.reply(daemon.OpSyncHeld, daemon.SyncHeldResult{Held: []daemon.HeldChange{{
		N: 3, Action: merge.ActionPut, ItemID: model.ID{5}.String(), Type: model.TypeKey,
		Seen: key("a"), Want: key("b"), Current: key("c"),
		Hold:     &store.HoldInfo{Cause: merge.CauseNotLive},
		Choices:  []string{daemon.ChoiceKeepMine, daemon.ChoiceTakeTheirs, daemon.ChoiceRetry},
		KeepMine: &daemon.Proposal{N: 3, Choice: daemon.ChoiceKeepMine, Action: merge.ActionCreate, ItemID: model.ID{5}.String(), Type: model.TypeKey, Want: key("b"), Confirm: token1},
	}}})
	for _, args := range [][]string{{"sync", "resolve"}, {"sync", "resolve", "--json"}, {"sync", "resolve", "3", "--keep-mine"}, {"sync", "resolve", "3", "--keep-mine", "--json"}} {
		_, out, errOut := f.hop(t, args...)
		if strings.Contains(out+errOut, "SECRET") || strings.Contains(out+errOut, "private_key") {
			t.Errorf("%q printed a secret:\n%s%s", args, out, errOut)
		}
	}
}

// ---- hop auth ----

func TestAuthDevices(t *testing.T) {
	f := newFakeDaemon(t)
	seen := f.now.Add(-2 * time.Hour)
	f.reply(daemon.OpDevicesList, daemon.DevicesResult{Devices: []store.DeviceListing{
		{ID: model.ID{1}, Name: "laptop", How: "signup", AddedAt: f.now.Add(-48 * time.Hour), LastSeen: &seen, This: true},
		{ID: model.ID{2}, Name: "phone" + hostile, How: "approval", AddedAt: f.now.Add(-time.Hour), Undelivered: true},
		{ID: model.ID{3}, Name: "old", How: "bootstrap", AddedAt: f.now.Add(-72 * time.Hour), Stale: true},
	}})
	code, out, errOut := f.hop(t, "auth", "devices")
	if code != 0 {
		t.Fatalf("exit %d: %s", code, errOut)
	}
	assertNoForgery(t, "devices", out)
	if got := len(lines(out)); got != 4 {
		t.Errorf("%d lines, want a header and 3 devices:\n%s", got, out)
	}
	for _, want := range []string{"NAME", "LAST SEEN", "this device", "undelivered", "stale", model.ID{2}.String(), "(2h ago)", "approval"} {
		if !strings.Contains(out, want) {
			t.Errorf("devices lack %q:\n%s", want, out)
		}
	}
	code, out, _ = f.hop(t, "auth", "devices", "--json")
	var res daemon.DevicesResult
	decodeJSON(t, out, &res)
	if code != 0 || len(res.Devices) != 3 || !res.Devices[0].This || !res.Devices[1].Undelivered {
		t.Errorf("--json: exit %d: %s", code, out)
	}

	f.fail(daemon.OpDevicesList, daemon.CodeLocked, "the vault is locked")
	if code, _, errOut := f.hop(t, "auth", "devices"); code != 255 || !strings.Contains(errOut, "hop unlock") {
		t.Errorf("locked: exit %d, %q", code, errOut)
	}
	f.fail(daemon.OpDevicesList, daemon.CodeLocalOnly, "this vault store does not sync")
	if code, _, errOut := f.hop(t, "auth", "devices"); code != 255 || !strings.Contains(errOut, "local-only") {
		t.Errorf("local-only: exit %d, %q", code, errOut)
	}
}

func TestAuthSubcommandsNotYetAvailable(t *testing.T) {
	f := newFakeDaemon(t)
	for _, args := range [][]string{
		{"auth", "login"}, {"auth", "signup"}, {"auth", "approve"}, {"auth", "logout"}, {"auth", "rotate"},
		{"auth", "passwd"}, {"auth", "merge"}, {"auth", "status"}, {"auth", "devices", "revoke", "phone"},
		{"login", "--server", "https://x"}, {"logout"},
	} {
		code, _, errOut := f.hop(t, args...)
		if code != 255 || !strings.Contains(errOut, "not available yet") {
			t.Errorf("%q: exit %d, %q", args, code, errOut)
		}
	}
	if code, _, errOut := f.hop(t, "auth"); code != 255 || !strings.Contains(errOut, "hop auth devices") {
		t.Errorf("bare auth: exit %d, %q", code, errOut)
	}
	if code, _, errOut := f.hop(t, "auth", "nope"); code != 255 || !strings.Contains(errOut, "unknown auth subcommand") {
		t.Errorf("unknown: exit %d, %q", code, errOut)
	}
	f.mu.Lock()
	n := len(f.calls)
	f.mu.Unlock()
	if n != 0 {
		t.Errorf("the stubs made %d daemon calls", n)
	}
}

// ---- config_stale: no connection while the ssh config is out of date ----

func TestConfigStaleRefusesToConnect(t *testing.T) {
	f := newFakeDaemon(t)
	msg := "the ssh config in " + f.paths.ConfigDir + " is out of date (open config: permission denied " + hostile + "), so ssh could use old host keys"
	f.fail(daemon.OpResolve, daemon.CodeConfigStale, msg)
	for _, args := range [][]string{
		{"web-1"}, {"connect", "web-1"}, {"exec", "web-1", "--", "true"}, {"check", "web-1"}, {"which", "web-1"}, {"info", "web-1"},
	} {
		for _, tty := range []bool{false, true} {
			f.tty = tty
			code, out, errOut := f.hop(t, args...)
			if code != 255 {
				t.Errorf("%q (tty %v): exit %d", args, tty, code)
			}
			if !strings.Contains(errOut, "is out of date") || !strings.Contains(errOut, "ls -la "+f.paths.ConfigDir) {
				t.Errorf("%q: stderr %q", args, errOut)
			}
			if out != "" {
				t.Errorf("%q: stdout %q", args, out)
			}
			assertNoForgery(t, "stderr", errOut)
			if len(lines(errOut)) != 1 {
				t.Errorf("%q: stderr is not one line: %q", args, errOut)
			}
		}
	}
	if n := len(f.called(daemon.OpStatus)); n != 0 {
		t.Errorf("a refused command asked for the sync notice %d times", n)
	}
}

// ---- config_not_written: the change happened; only the config is behind ----

const notWritten = "saved, but the ssh config could not be updated (permission denied " + hostile + "); the daemon tries again"

func TestConfigNotWrittenOnUnlockIsAWarning(t *testing.T) {
	f := newFakeDaemon(t)
	f.fail(daemon.OpUnlock, daemon.CodeConfigNotWritten, "vault unlocked and keys loaded; "+notWritten)
	f.reply(daemon.OpStatus, daemon.StatusResult{Vault: &store.Info{Warnings: []string{"1 stale device " + hostile}}})
	f.reply(daemon.OpKit, json.RawMessage(`{"kit":{}}`))
	code, out, errOut := f.hop(t, "unlock")
	if code != 0 {
		t.Fatalf("exit %d: %s", code, errOut)
	}
	if out != "vault unlocked\n" {
		t.Errorf("stdout %q", out)
	}
	for _, want := range []string{"hop: warning: vault unlocked and keys loaded", "hop: warning: 1 stale device", "Emergency Kit is not confirmed"} {
		if !strings.Contains(errOut, want) {
			t.Errorf("stderr lacks %q:\n%s", want, errOut)
		}
	}
	assertNoForgery(t, "unlock", errOut)
	if got := len(lines(errOut)); got != 3 {
		t.Errorf("%d stderr lines, want 3:\n%s", got, errOut)
	}

	// Any other refusal is still a failure.
	f.fail(daemon.OpUnlock, daemon.CodeLocked, "the device key can't be read")
	if code, _, _ := f.hop(t, "unlock"); code != 255 {
		t.Errorf("a failed unlock exits %d", code)
	}
}

func TestConfigNotWrittenOnChangesIsAWarning(t *testing.T) {
	f := newFakeDaemon(t)
	web1 := model.Host{Header: model.Header{ItemID: model.ID{1}}, Name: "web-1", Addresses: []string{"10.0.0.1"}, Port: 22}
	added := model.Host{Header: model.Header{ItemID: model.ID{4}}, Name: "new-1", Addresses: []string{"new-1"}, Port: 22}
	f.reply(daemon.OpList, daemon.ListResult{
		Hosts: []model.Host{web1, added}, SSH: map[string]daemon.HostSSH{},
		Keys: []daemon.KeyInfo{{ID: model.ID{8}.String(), Name: "mykey", KeyType: "ssh-ed25519", Fingerprint: "SHA256:k"}},
	})
	f.reply(daemon.OpResolve, daemon.ResolveResult{
		Result: &resolve.Result{Target: "web-1", Status: resolve.StatusMatched, HostID: web1.ItemID.String(), HostName: "web-1"}, Host: &web1,
	})
	for _, op := range []string{daemon.OpPutHost, daemon.OpPutKey, daemon.OpDelete} {
		f.fail(op, daemon.CodeConfigNotWritten, notWritten)
	}
	keyPath := f.base + "/id_test"
	writeKey(t, keyPath, "")

	tests := []struct {
		args []string
		want string
	}{
		{[]string{"add", "new-1"}, "added new-1\n"},
		{[]string{"edit", "web-1", "--user", "root"}, "updated web-1\n"},
		{[]string{"rm", "web-1", "--yes"}, "removed web-1\n"},
		{[]string{"key", "add", keyPath, "--name", "mykey"}, "added key mykey (ssh-ed25519 SHA256:k)\n"},
		{[]string{"key", "rm", "mykey", "--yes"}, "removed key mykey\n"},
	}
	for _, tt := range tests {
		code, out, errOut := f.hop(t, tt.args...)
		if code != 0 {
			t.Errorf("%q: exit %d: %s", tt.args, code, errOut)
			continue
		}
		if !strings.HasPrefix(out, tt.want) {
			t.Errorf("%q: stdout %q, want %q", tt.args, out, tt.want)
		}
		if n := strings.Count(errOut, "hop: warning: saved, but the ssh config could not be updated"); n != 1 {
			t.Errorf("%q: %d warnings in %q", tt.args, n, errOut)
		}
		assertNoForgery(t, "stderr", errOut)
	}

	// --json keeps stdout's shape and puts the warning on stderr as JSON.
	code, out, errOut := f.hop(t, "add", "new-1", "--json")
	if code != 0 {
		t.Fatalf("add --json: exit %d: %s", code, errOut)
	}
	var v cli.HostView
	decodeJSON(t, out, &v)
	if v.ID != added.ItemID.String() || v.Name != "new-1" {
		t.Errorf("add --json read back %+v", v)
	}
	var w map[string]string
	decodeJSON(t, strings.TrimSpace(errOut), &w)
	if !strings.HasPrefix(w["warning"], "saved, but") {
		t.Errorf("stderr %q", errOut)
	}

	// Another refusal is still a failure.
	f.fail(daemon.OpPutHost, daemon.CodeInvalid, "a host needs at least one address")
	if code, _, _ := f.hop(t, "add", "new-2"); code != 255 {
		t.Errorf("a refused add exits %d", code)
	}
}
