package cli_test

import (
	"encoding/json"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/dalyem/hopkey/internal/cli"
	"github.com/dalyem/hopkey/internal/daemon"
	"github.com/dalyem/hopkey/internal/merge"
	"github.com/dalyem/hopkey/internal/model"
	"github.com/dalyem/hopkey/internal/store"
)

const (
	tokenKM = "4444444444444444444444444444444444444444444444444444444444444444"
	tokenTM = "5555555555555555555555555555555555555555555555555555555555555555"
)

// hostWith is hostJSON with aliases and addresses set.
func hostWith(version int, aliases []string, addr string) json.RawMessage {
	var m map[string]any
	json.Unmarshal(hostJSON(version, addr, ""), &m)
	m["aliases"] = aliases
	b, _ := json.Marshal(m)
	return b
}

// heldCoupling is vector C1/R2: this device added the alias test-db while
// the server moved the host. keepMineMerge is the proposal sync.proposal
// returns for it.
func heldCoupling() daemon.SyncHeldResult {
	id := model.ID{1}.String()
	current := hostWith(4, []string{}, "new.example")
	return daemon.SyncHeldResult{Held: []daemon.HeldChange{{
		N: 7, Action: merge.ActionPut, ItemID: id, Type: model.TypeHost,
		Seen: hostWith(3, []string{}, "old.example"), Want: hostWith(3, []string{"test-db"}, "old.example"), Current: current,
		Hold: &store.HoldInfo{
			Cause: merge.CauseGuardedConflict, Local: []string{"aliases"}, Remote: []string{"addresses"},
			Conflicts: []merge.Conflict{{
				Kind: merge.ConflictCoupling, Name: merge.CouplingSelectorAdded, Trigger: merge.TriggerLocal,
				Local: []string{"aliases"}, Remote: []string{"addresses"},
			}},
		},
		Choices: []string{daemon.ChoiceKeepMine, daemon.ChoiceKeepMineMerge, daemon.ChoiceEdit, daemon.ChoiceTakeTheirs, daemon.ChoiceRetry},
		KeepMine: &daemon.Proposal{N: 7, Choice: daemon.ChoiceKeepMine, Action: merge.ActionPut, ItemID: id, Type: model.TypeHost,
			Seen: current, Want: hostWith(4, []string{"test-db"}, "new.example"), Confirm: token1},
		TakeTheirsMergeRefused: "merge: take theirs --merge is refused for a put, item live, guarded conflict hold: nothing to merge: use --take-theirs",
	}}}
}

func keepMineMerge() *daemon.Proposal {
	return &daemon.Proposal{N: 7, Choice: daemon.ChoiceKeepMineMerge, Action: merge.ActionPut, ItemID: model.ID{1}.String(), Type: model.TypeHost,
		Seen: hostWith(4, []string{}, "new.example"), Want: hostWith(4, []string{"test-db"}, "old.example"), Confirm: tokenKM}
}

// proposeFrom makes sync.proposal answer from props, by choice, and refuse
// any other choice as the daemon does.
func proposeFrom(t *testing.T, f *fakeDaemon, props map[string]*daemon.Proposal) {
	f.on(daemon.OpSyncProposal, func(raw json.RawMessage) (any, error) {
		var p daemon.SyncProposalParams
		if err := json.Unmarshal(raw, &p); err != nil {
			t.Errorf("sync.proposal params %s: %v", raw, err)
		}
		if pr := props[p.Choice]; pr != nil && pr.N == p.N {
			return daemon.SyncProposalResult{Proposal: pr}, nil
		}
		return nil, &daemon.Error{Code: daemon.CodeInvalid, Message: "merge: refused"}
	})
}

func TestSyncResolveNamesTheCoupling(t *testing.T) {
	f := newFakeDaemon(t)
	f.reply(daemon.OpSyncHeld, heldCoupling())
	proposeFrom(t, f, map[string]*daemon.Proposal{daemon.ChoiceKeepMineMerge: keepMineMerge()})
	f.fail(daemon.OpSyncResolve, daemon.CodeInternal, "must not be called")
	code, out, errOut := f.hop(t, "sync", "resolve")
	if code != 0 {
		t.Fatalf("exit %d: %s", code, errOut)
	}
	for _, want := range []string{
		"conflict: coupling selector-added: this device gave it a new name, alias or tag (aliases: [\"test-db\"]) while the server changed how it connects (addresses)",
		// Plain keep mine writes the coupled combination, and says so.
		"note: this combines what coupling selector-added held apart",
		"keep mine --merge writes put host",
		"hop sync resolve 7 --keep-mine --merge --confirm " + tokenKM,
		"hop sync resolve 7 --keep-mine --confirm " + token1,
		"take theirs --merge is not offered: ",
		"nothing to merge",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("listing lacks %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "--take-theirs --merge --confirm") {
		t.Errorf("a refused choice is listed:\n%s", out)
	}
	// The keep-mine proposal shows the conflict members and what changes.
	if !strings.Contains(out, "aliases") || !strings.Contains(out, "addresses") {
		t.Errorf("the proposal lacks the conflict members:\n%s", out)
	}

	// The listing asked for the offered --merge proposal only.
	if calls := f.called(daemon.OpSyncProposal); len(calls) != 1 || !strings.Contains(string(calls[0]), daemon.ChoiceKeepMineMerge) {
		t.Errorf("sync.proposal calls %s", calls)
	}

	// --json carries the proposals with their tokens, beside keep mine's.
	_, out, _ = f.hop(t, "sync", "resolve", "--json")
	var res struct {
		Held []struct {
			daemon.HeldChange
			KeepMineMerge   *daemon.Proposal `json:"keep_mine_merge"`
			TakeTheirsMerge *daemon.Proposal `json:"take_theirs_merge"`
		} `json:"held"`
	}
	decodeJSON(t, out, &res)
	h := res.Held[0]
	if h.KeepMineMerge == nil || h.KeepMineMerge.Confirm != tokenKM || h.KeepMine == nil || h.KeepMine.Confirm != token1 ||
		h.TakeTheirsMerge != nil || h.TakeTheirsMergeRefused == "" ||
		h.Hold == nil || len(h.Hold.Conflicts) != 1 || h.Hold.Conflicts[0].Name != merge.CouplingSelectorAdded {
		t.Errorf("--json: %s", out)
	}
}

// A --merge proposal the daemon can no longer give (the held change moved
// on since the listing) is left out of the listing with the reason, and
// the rest of it still shows.
func TestSyncResolveListsWithoutAMissingProposal(t *testing.T) {
	f := newFakeDaemon(t)
	f.reply(daemon.OpSyncHeld, heldCoupling())
	f.fail(daemon.OpSyncProposal, daemon.CodeNotHeld, "queued change 7 is not the held one")
	code, out, errOut := f.hop(t, "sync", "resolve")
	if code != 0 {
		t.Fatalf("exit %d: %s", code, errOut)
	}
	if strings.Contains(out, "--keep-mine --merge --confirm") || !strings.Contains(out, "keep mine --merge is not offered: its proposal could not be read") ||
		!strings.Contains(out, "hop sync resolve 7 --keep-mine --confirm "+token1) {
		t.Errorf("listing:\n%s", out)
	}
}

// Every resolution starts from the listing, which never carries a --merge
// proposal: take theirs never asks for one.
func TestSyncResolveTakeTheirsNeedsNoProposal(t *testing.T) {
	f := newFakeDaemon(t)
	f.reply(daemon.OpSyncHeld, heldCoupling())
	f.fail(daemon.OpSyncProposal, daemon.CodeInternal, "must not be called")
	f.reply(daemon.OpSyncResolve, daemon.SyncResolveResult{Status: &daemon.SyncStatusResult{State: daemon.SyncOnline}})
	if code, out, errOut := f.hop(t, "sync", "resolve", "7", "--take-theirs", "--yes"); code != 0 {
		t.Fatalf("exit %d: %s %s", code, out, errOut)
	}
	if n := len(f.called(daemon.OpSyncProposal)); n != 0 {
		t.Errorf("sync.proposal called %d times", n)
	}
}

func TestSyncResolveMerge(t *testing.T) {
	f := newFakeDaemon(t)
	held := heldCoupling()
	f.reply(daemon.OpSyncHeld, held)
	props := map[string]*daemon.Proposal{daemon.ChoiceKeepMineMerge: keepMineMerge()}
	proposeFrom(t, f, props)
	f.reply(daemon.OpSyncResolve, daemon.SyncResolveResult{Status: &daemon.SyncStatusResult{State: daemon.SyncOnline}})

	// Without a token: the proposal and the command, nothing applied.
	code, out, errOut := f.hop(t, "sync", "resolve", "7", "--keep-mine", "--merge")
	if code != 255 || !strings.Contains(errOut, "needs --confirm") || !strings.Contains(out, "hop sync resolve 7 --keep-mine --merge --confirm "+tokenKM) {
		t.Errorf("exit %d\n%s\n%s", code, out, errOut)
	}
	if n := len(f.called(daemon.OpSyncResolve)); n != 0 {
		t.Fatalf("sync.resolve called %d times without a token", n)
	}
	// With it.
	code, out, errOut = f.hop(t, "sync", "resolve", "7", "--keep-mine", "--merge", "--confirm", tokenKM)
	if code != 0 || !strings.Contains(out, "change 7 resolved: keep-mine-merge") {
		t.Fatalf("exit %d: %s %s", code, out, errOut)
	}
	calls := f.called(daemon.OpSyncResolve)
	if len(calls) != 1 {
		t.Fatalf("calls %d", len(calls))
	}
	if p := resolveParams(t, calls[0]); p.Choice != daemon.ChoiceKeepMineMerge || p.Confirm != tokenKM || p.N != 7 {
		t.Errorf("params %+v", p)
	}

	// A refused --merge says why.
	code, _, errOut = f.hop(t, "sync", "resolve", "7", "--take-theirs", "--merge", "--confirm", tokenTM)
	if code != 255 || !strings.Contains(errOut, "nothing to merge") {
		t.Errorf("take theirs --merge: exit %d %q", code, errOut)
	}
	// Once offered, it goes as take-theirs-merge.
	props[daemon.ChoiceTakeTheirsMerge] = &daemon.Proposal{N: 7, Choice: daemon.ChoiceTakeTheirsMerge, Action: merge.ActionPut,
		ItemID: model.ID{1}.String(), Type: model.TypeHost, Seen: held.Held[0].Current, Want: held.Held[0].Current, Confirm: tokenTM}
	held.Held[0].TakeTheirsMergeRefused = ""
	held.Held[0].Choices = append(held.Held[0].Choices, daemon.ChoiceTakeTheirsMerge)
	f.reply(daemon.OpSyncHeld, held)
	if code, out, errOut := f.hop(t, "sync", "resolve", "7", "--take-theirs", "--merge", "--confirm", tokenTM); code != 0 {
		t.Fatalf("exit %d: %s %s", code, out, errOut)
	}
	calls = f.called(daemon.OpSyncResolve)
	if p := resolveParams(t, calls[len(calls)-1]); p.Choice != daemon.ChoiceTakeTheirsMerge || p.Confirm != tokenTM {
		t.Errorf("params %+v", p)
	}

	// --merge goes only with --keep-mine or --take-theirs, and never with
	// --yes: it writes a merge, which needs its token.
	for _, args := range [][]string{
		{"7", "--merge"}, {"7", "--edit", "--merge", "--set", "user=x"}, {"7", "--retry", "--merge"},
		{"7", "--take-theirs", "--merge", "--yes"},
	} {
		if code, _, errOut := f.hop(t, append([]string{"sync", "resolve"}, args...)...); code == 0 || !strings.Contains(errOut, "--merge") {
			t.Errorf("%v: exit %d %q", args, code, errOut)
		}
	}
}

// proposalFields are the fields the proposal headed by header shows.
func proposalFields(t *testing.T, out, header string) []string {
	t.Helper()
	i := strings.Index(out, header)
	if i < 0 {
		t.Fatalf("no %q in:\n%s", header, out)
	}
	lines := strings.Split(out[i:], "\n")[1:]
	var fields []string
	for _, l := range lines {
		if !strings.HasPrefix(l, "  ") {
			break
		}
		f := strings.Fields(l)
		if len(f) == 0 || f[0] == "FIELD" || f[0] == "note:" || strings.HasPrefix(f[0], "(") {
			continue
		}
		fields = append(fields, f[0])
	}
	return fields
}

// withMembers is raw with members set (a nil value removes one).
func withMembers(raw json.RawMessage, set map[string]any) json.RawMessage {
	var m map[string]any
	json.Unmarshal(raw, &m)
	for k, v := range set {
		if v == nil {
			delete(m, k)
		} else {
			m[k] = v
		}
	}
	b, _ := json.Marshal(m)
	return b
}

// A unit conflict shows every member of the unit, not only those either
// side changed: here this device changed the port and the server the
// user, and keep mine still shows where the host is, its pinned keys, its
// jump host, key and credential, which it writes as the server has them.
func TestSyncResolveShowsTheWholeConflictingUnit(t *testing.T) {
	id := model.ID{1}.String()
	base := withMembers(hostJSON(3, "old.example", ""), map[string]any{"key_id": model.ID{2}.String()})
	seen := base
	want := withMembers(base, map[string]any{"port": 2222})
	cur := withMembers(withMembers(base, map[string]any{"user": "root"}), map[string]any{"item_version": "4"})
	held := daemon.SyncHeldResult{Held: []daemon.HeldChange{{
		N: 7, Action: merge.ActionPut, ItemID: id, Type: model.TypeHost, Seen: seen, Want: want, Current: cur,
		Hold: &store.HoldInfo{
			Cause: merge.CauseGuardedConflict, Local: []string{"port"}, Remote: []string{"user"},
			Conflicts: []merge.Conflict{{Kind: merge.ConflictUnit, Name: merge.UnitConnection, Local: []string{"port"}, Remote: []string{"user"}}},
		},
		Choices: []string{daemon.ChoiceKeepMine, daemon.ChoiceEdit, daemon.ChoiceTakeTheirs, daemon.ChoiceRetry},
		KeepMine: &daemon.Proposal{N: 7, Choice: daemon.ChoiceKeepMine, Action: merge.ActionPut, ItemID: id, Type: model.TypeHost,
			Seen: cur, Want: withMembers(cur, map[string]any{"port": 2222}), Confirm: token1},
	}}}
	f := newFakeDaemon(t)
	f.reply(daemon.OpSyncHeld, held)
	code, out, errOut := f.hop(t, "sync", "resolve")
	if code != 0 {
		t.Fatalf("exit %d: %s", code, errOut)
	}
	got := proposalFields(t, out, "keep mine writes")
	for _, m := range []string{"addresses", "port", "user", "route", "tailscale", "host_keys", "jump_host_id", "key_id", "credential_id"} {
		if !slices.Contains(got, m) {
			t.Errorf("keep mine does not show %s (shows %v):\n%s", m, got, out)
		}
	}
	// Outside the unit, only what the replacement changes.
	for _, m := range []string{"tags", "aliases", "name", "agent_access"} {
		if slices.Contains(got, m) {
			t.Errorf("keep mine shows %s, which neither the conflict nor the replacement touches:\n%s", m, out)
		}
	}
}

// The agent unit is shown whole too: both sides changed agent_output, so
// agent_access, which neither changed, is part of the conflict and shown.
func TestSyncResolveShowsTheUnchangedHalfOfTheAgentUnit(t *testing.T) {
	id := model.ID{1}.String()
	seen := withMembers(hostJSON(3, "old.example", ""), map[string]any{"agent_output": "none"})
	want := withMembers(seen, map[string]any{"agent_output": "full"})
	cur := withMembers(seen, map[string]any{"agent_output": nil, "item_version": "4"})
	held := daemon.SyncHeldResult{Held: []daemon.HeldChange{{
		N: 7, Action: merge.ActionPut, ItemID: id, Type: model.TypeHost, Seen: seen, Want: want, Current: cur,
		Hold: &store.HoldInfo{
			Cause: merge.CauseGuardedConflict, Local: []string{"agent_output"}, Remote: []string{"agent_output"},
			Conflicts: []merge.Conflict{{Kind: merge.ConflictUnit, Name: merge.UnitAgent, Local: []string{"agent_output"}, Remote: []string{"agent_output"}}},
		},
		Choices: []string{daemon.ChoiceKeepMine, daemon.ChoiceEdit, daemon.ChoiceTakeTheirs, daemon.ChoiceRetry},
		KeepMine: &daemon.Proposal{N: 7, Choice: daemon.ChoiceKeepMine, Action: merge.ActionPut, ItemID: id, Type: model.TypeHost,
			Seen: cur, Want: withMembers(cur, map[string]any{"agent_output": "full"}), Confirm: token1},
	}}}
	f := newFakeDaemon(t)
	f.reply(daemon.OpSyncHeld, held)
	code, out, errOut := f.hop(t, "sync", "resolve")
	if code != 0 {
		t.Fatalf("exit %d: %s", code, errOut)
	}
	got := proposalFields(t, out, "keep mine writes")
	if !slices.Contains(got, "agent_access") || !slices.Contains(got, "agent_output") {
		t.Errorf("keep mine shows %v, not the whole agent unit:\n%s", got, out)
	}
}

// A coupling shows its whole coupled group beside the trigger, and a
// credential's conflict names its password without showing it.
func TestSyncResolveShowsTheCoupledGroupAndNamesSecrets(t *testing.T) {
	f := newFakeDaemon(t)
	f.reply(daemon.OpSyncHeld, heldCoupling())
	proposeFrom(t, f, map[string]*daemon.Proposal{daemon.ChoiceKeepMineMerge: keepMineMerge()})
	_, out, _ := f.hop(t, "sync", "resolve")
	got := proposalFields(t, out, "keep mine writes")
	if mm := proposalFields(t, out, "keep mine --merge writes"); !slices.Contains(mm, "port") || !slices.Contains(mm, "aliases") {
		t.Errorf("keep mine --merge shows %v:\n%s", mm, out)
	}
	for _, m := range []string{"aliases", "addresses", "port", "user", "host_keys", "key_id"} {
		if !slices.Contains(got, m) {
			t.Errorf("keep mine past a coupling does not show %s (shows %v):\n%s", m, got, out)
		}
	}

	id := model.ID{3}.String()
	cred := func(version int, name, username string) json.RawMessage {
		b, _ := json.Marshal(map[string]any{"v": 1, "item_id": id, "type": "credential", "item_version": strconv.Itoa(version), "name": name, "username": username})
		return b
	}
	seen, want, cur := cred(3, "db", "app"), cred(3, "db-main", "app"), cred(4, "db", "admin")
	held := daemon.SyncHeldResult{Held: []daemon.HeldChange{{
		N: 8, Action: merge.ActionPut, ItemID: id, Type: model.TypeCredential, Seen: seen, Want: want, Current: cur,
		Hold: &store.HoldInfo{
			Cause: merge.CauseGuardedConflict, Local: []string{"name"}, Remote: []string{"username"},
			Conflicts: []merge.Conflict{{Kind: merge.ConflictUnit, Name: merge.UnitCredential, Local: []string{"name"}, Remote: []string{"username"}}},
		},
		Choices: []string{daemon.ChoiceKeepMine, daemon.ChoiceTakeTheirs, daemon.ChoiceRetry},
		KeepMine: &daemon.Proposal{N: 8, Choice: daemon.ChoiceKeepMine, Action: merge.ActionPut, ItemID: id, Type: model.TypeCredential,
			Seen: cur, Want: cred(4, "db-main", "admin"), Confirm: token1},
	}}}
	f.reply(daemon.OpSyncHeld, held)
	_, out, _ = f.hop(t, "sync", "resolve")
	got = proposalFields(t, out, "keep mine writes")
	if !slices.Contains(got, "password") || !regexp.MustCompile(`(?m)^  password +\(secret, not shown\)`).MatchString(out) {
		t.Errorf("the credential's password is not named as a secret (shows %v):\n%s", got, out)
	}
}

// heldPortUser is a connection conflict: this device changed the port and
// the server the user.
func heldPortUser() (daemon.SyncHeldResult, json.RawMessage) {
	id := model.ID{1}.String()
	seen := hostJSON(3, "old.example", "")
	cur := withMembers(seen, map[string]any{"user": "root", "item_version": "4"})
	return daemon.SyncHeldResult{Held: []daemon.HeldChange{{
		N: 7, Action: merge.ActionPut, ItemID: id, Type: model.TypeHost, Seen: seen, Want: withMembers(seen, map[string]any{"port": 2222}), Current: cur,
		Hold: &store.HoldInfo{
			Cause: merge.CauseGuardedConflict, Local: []string{"port"}, Remote: []string{"user"},
			Conflicts: []merge.Conflict{{Kind: merge.ConflictUnit, Name: merge.UnitConnection, Local: []string{"port"}, Remote: []string{"user"}}},
		},
		Choices: []string{daemon.ChoiceKeepMine, daemon.ChoiceKeepMineMerge, daemon.ChoiceEdit, daemon.ChoiceTakeTheirs, daemon.ChoiceRetry},
		KeepMine: &daemon.Proposal{N: 7, Choice: daemon.ChoiceKeepMine, Action: merge.ActionPut, ItemID: id, Type: model.TypeHost,
			Seen: cur, Want: withMembers(cur, map[string]any{"port": 2222}), Confirm: token1},
	}}}, cur
}

// The server changes between the listing and the proposal: it widens
// agent_output, which adds a coupling. The confirmation says so, shows the
// new conflict and the server's values as the proposal was computed from
// them, and confirming sends that proposal's token, which the daemon binds
// to them.
func TestSyncResolveMergeConfirmsTheServerAsProposed(t *testing.T) {
	held, cur := heldPortUser()
	now := withMembers(cur, map[string]any{"agent_output": "full", "item_version": "5"})
	fresh := &daemon.Proposal{N: 7, Choice: daemon.ChoiceKeepMineMerge, Action: merge.ActionPut, ItemID: model.ID{1}.String(), Type: model.TypeHost,
		Seen: now, Want: withMembers(now, map[string]any{"port": 2222, "user": "deploy", "agent_output": nil}), Confirm: tokenKM,
		Current: now,
		Hold: &store.HoldInfo{
			Cause: merge.CauseGuardedConflict, Local: []string{"port"}, Remote: []string{"agent_output", "user"},
			Conflicts: []merge.Conflict{
				{Kind: merge.ConflictUnit, Name: merge.UnitConnection, Local: []string{"port"}, Remote: []string{"user"}},
				{Kind: merge.ConflictCoupling, Name: merge.CouplingAgentWidening, Trigger: merge.TriggerRemote,
					Local: []string{"port"}, Remote: []string{"agent_access", "agent_output"}},
			},
		},
	}
	f := newFakeDaemon(t)
	f.reply(daemon.OpSyncHeld, held)
	proposeFrom(t, f, map[string]*daemon.Proposal{daemon.ChoiceKeepMineMerge: fresh})
	f.reply(daemon.OpSyncResolve, daemon.SyncResolveResult{Status: &daemon.SyncStatusResult{State: daemon.SyncOnline}})
	terminal := func(e *cli.Env) { e.StdinTTY, e.StdoutTTY = true, true }

	f.stdin = "y\n"
	code, out, errOut := f.hopWith(t, terminal, "sync", "resolve", "7", "--keep-mine", "--merge")
	if code != 0 {
		t.Fatalf("exit %d: %s %s", code, out, errOut)
	}
	// The proposal comes after what changed, and the question after both.
	moved := strings.Index(out, "changed since it was listed")
	table := strings.Index(out, "keep mine --merge writes")
	if moved < 0 || table < moved {
		t.Fatalf("no notice before the proposal:\n%s", out)
	}
	for _, re := range []string{
		`(?m)^  conflict: coupling agent-widening: the server widened what agents may do on it \(agent_access, agent_output\) while this device changed how it connects \(port\)`,
		`(?m)^  FIELD +LISTED +SERVER NOW$`,
		`(?m)^  agent_output +- +full$`,
		// The proposal beside the server as it is now, not as listed.
		`(?m)^  agent_output +- +full +\(changes\)$`,
		`(?m)^  user +deploy +root +\(changes\)$`,
		`(?m)^  agent_access +allow +allow$`,
	} {
		if !regexp.MustCompile(re).MatchString(out[moved:]) {
			t.Errorf("no %s in:\n%s", re, out)
		}
	}
	calls := f.called(daemon.OpSyncResolve)
	if len(calls) != 1 {
		t.Fatalf("sync.resolve called %d times", len(calls))
	}
	if p := resolveParams(t, calls[0]); p.Choice != daemon.ChoiceKeepMineMerge || p.Confirm != tokenKM {
		t.Errorf("params %+v", p)
	}

	// Without a terminal the proposal prints the same way, with its token.
	_, out, _ = f.hop(t, "sync", "resolve")
	if i := strings.Index(out, "changed since it was listed"); i < 0 || !regexp.MustCompile(`(?m)^  agent_output +- +full +\(changes\)$`).MatchString(out[i:]) ||
		!strings.Contains(out, "hop sync resolve 7 --keep-mine --merge --confirm "+tokenKM) {
		t.Errorf("listing:\n%s", out)
	}

	// A proposal computed from the listed server says nothing of a change.
	same := *fresh
	same.Current, same.Hold, same.Seen = cur, held.Held[0].Hold, cur
	same.Want = withMembers(cur, map[string]any{"port": 2222, "user": "deploy"})
	proposeFrom(t, f, map[string]*daemon.Proposal{daemon.ChoiceKeepMineMerge: &same})
	f.stdin = "y\n"
	if _, out, _ := f.hopWith(t, terminal, "sync", "resolve", "7", "--keep-mine", "--merge"); strings.Contains(out, "changed since it was listed") ||
		!strings.Contains(out, "keep mine --merge writes") {
		t.Errorf("an unchanged server:\n%s", out)
	}
}

// A class conflict's strings come from the three versions: the listing
// carries none.
func TestSyncResolveSpellsAClassConflict(t *testing.T) {
	held, _ := heldPortUser()
	h := &held.Held[0]
	h.Seen = withMembers(h.Seen, map[string]any{"tags": []string{"prod"}})
	h.Want = withMembers(h.Want, map[string]any{"tags": []string{"PROD"}})
	h.Current = withMembers(h.Current, map[string]any{"tags": []string{"Prod"}})
	h.Hold.Conflicts = append(h.Hold.Conflicts, merge.Conflict{Kind: merge.ConflictClass, Name: "tags", Local: []string{"tags"}, Remote: []string{"tags"}})
	h.Choices, h.KeepMine = []string{daemon.ChoiceTakeTheirs}, nil
	f := newFakeDaemon(t)
	f.reply(daemon.OpSyncHeld, held)
	_, out, _ := f.hop(t, "sync", "resolve")
	if !strings.Contains(out, `conflict: tags: the same tag was changed differently on each side (["PROD","Prod","prod"])`) {
		t.Errorf("listing:\n%s", out)
	}
}
