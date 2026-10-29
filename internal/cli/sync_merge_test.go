package cli_test

import (
	"encoding/json"
	"strings"
	"testing"

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
// the server moved the host.
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
				Local: []string{"aliases"}, Remote: []string{"addresses"}, Spellings: []string{"test-db"},
			}},
		},
		Choices: []string{daemon.ChoiceKeepMine, daemon.ChoiceKeepMineMerge, daemon.ChoiceEdit, daemon.ChoiceTakeTheirs, daemon.ChoiceRetry},
		KeepMine: &daemon.Proposal{N: 7, Choice: daemon.ChoiceKeepMine, Action: merge.ActionPut, ItemID: id, Type: model.TypeHost,
			Seen: current, Want: hostWith(4, []string{"test-db"}, "new.example"), Confirm: token1},
		KeepMineMerge: &daemon.Proposal{N: 7, Choice: daemon.ChoiceKeepMineMerge, Action: merge.ActionPut, ItemID: id, Type: model.TypeHost,
			Seen: current, Want: hostWith(4, []string{"test-db"}, "old.example"), Confirm: tokenKM},
		TakeTheirsMergeRefused: "merge: take theirs --merge is refused for a put, item live, guarded conflict hold: nothing to merge: use --take-theirs",
	}}}
}

func TestSyncResolveNamesTheCoupling(t *testing.T) {
	f := newFakeDaemon(t)
	f.reply(daemon.OpSyncHeld, heldCoupling())
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

	// --json carries both proposals with their tokens.
	_, out, _ = f.hop(t, "sync", "resolve", "--json")
	var res daemon.SyncHeldResult
	decodeJSON(t, out, &res)
	h := res.Held[0]
	if h.KeepMineMerge == nil || h.KeepMineMerge.Confirm != tokenKM || h.Hold == nil || len(h.Hold.Conflicts) != 1 ||
		h.Hold.Conflicts[0].Name != merge.CouplingSelectorAdded {
		t.Errorf("--json: %s", out)
	}
}

func TestSyncResolveMerge(t *testing.T) {
	f := newFakeDaemon(t)
	held := heldCoupling()
	f.reply(daemon.OpSyncHeld, held)
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
	held.Held[0].TakeTheirsMerge = &daemon.Proposal{N: 7, Choice: daemon.ChoiceTakeTheirsMerge, Action: merge.ActionPut,
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
