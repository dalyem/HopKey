package daemon

import (
	"encoding/json"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/dalyem/hopkey/internal/merge"
	"github.com/dalyem/hopkey/internal/model"
	"github.com/dalyem/hopkey/internal/store"
)

// sync.proposal answers with the server's version and the hold it
// computed the proposal from, which can be newer than the listing's. Here
// the server widens agent_output after the listing: the proposal shows it,
// with the coupling it adds, and confirming that proposal writes exactly
// its want.
func TestSyncProposalCarriesTheServerItWasComputedFrom(t *testing.T) {
	x := newSyncSetup(t)
	x.w.start(x.n1, x.n1.st, SyncOptions{})
	x.w.start(x.n2, x.n2.st, SyncOptions{})
	x.n1.putHost(webHost("web", x.keyID, "203.0.113.62"))
	eventually(t, 20*time.Second, "web reaches the laptop", func() bool { return x.n2.host("web") != nil })
	x.n2.pause(true)
	time.Sleep(100 * time.Millisecond)
	desk := *x.n1.host("web")
	desk.User = "root"
	desk = x.n1.putHost(desk)
	eventually(t, 20*time.Second, "the desk's edit is pushed", func() bool { return x.n1.status().Pending == 0 })
	laptop := *x.n2.host("web")
	laptop.Port = 2222
	x.n2.putHost(laptop)
	x.n2.pause(false)
	eventually(t, 20*time.Second, "the laptop's change is held", func() bool { return x.n2.status().Held == 1 })

	var held SyncHeldResult
	x.n2.must(OpSyncHeld, nil, &held)
	listed := held.Held[0]
	if km := listed.KeepMine; km == nil || km.Current != nil || km.Hold != nil {
		t.Fatalf("the listing's keep mine %+v", km)
	}
	if !slices.Contains(listed.Choices, ChoiceKeepMineMerge) || strings.Contains(string(listed.Current), "agent_output") {
		t.Fatalf("listed %v %s", listed.Choices, listed.Current)
	}

	// The server widens agent_output after the listing.
	desk.AgentOutput = model.AgentOutputFull
	x.n1.putHost(desk)
	eventually(t, 20*time.Second, "the widening is pushed", func() bool { return x.n1.status().Pending == 0 })
	eventually(t, 20*time.Second, "the laptop sees the widening", func() bool {
		x.n2.call(OpSyncNow, nil, nil)
		var h SyncHeldResult
		x.n2.must(OpSyncHeld, nil, &h)
		return len(h.Held) == 1 && strings.Contains(string(h.Held[0].Current), `"agent_output":"full"`)
	})

	var res SyncProposalResult
	x.n2.must(OpSyncProposal, SyncProposalParams{N: listed.N, Choice: ChoiceKeepMineMerge}, &res)
	p := res.Proposal
	if p == nil || !strings.Contains(string(p.Current), `"agent_output":"full"`) || p.Hold == nil {
		t.Fatalf("proposal %+v", p)
	}
	widening := slices.ContainsFunc(p.Hold.Conflicts, func(c merge.Conflict) bool {
		return c.Kind == merge.ConflictCoupling && c.Name == merge.CouplingAgentWidening && c.Trigger == merge.TriggerRemote
	})
	if !widening || sameHold(p.Hold, listed.Hold) {
		t.Fatalf("the proposal's hold %+v, the listing's %+v", p.Hold, listed.Hold)
	}
	// keep mine --merge takes the agent unit as this device has it: no
	// agent_output, so the widening is not combined with the new port.
	var want map[string]json.RawMessage
	if err := json.Unmarshal(p.Want, &want); err != nil {
		t.Fatal(err)
	}
	if _, ok := want["agent_output"]; ok || string(want["port"]) != "2222" || string(want["user"]) != `"deploy"` {
		t.Fatalf("keep mine --merge writes %s", p.Want)
	}
	// The listing's keep-mine token was for the server before the widening.
	if err := x.n2.call(OpSyncResolve, SyncResolveParams{N: listed.N, Choice: ChoiceKeepMine, Confirm: listed.KeepMine.Confirm}, nil); !IsCode(err, CodeStaleConfirm) {
		t.Fatalf("the listing's keep-mine token: %v", err)
	}
	var done SyncResolveResult
	x.n2.must(OpSyncResolve, SyncResolveParams{N: listed.N, Choice: ChoiceKeepMineMerge, Confirm: p.Confirm}, &done)
	eventually(t, 20*time.Second, "the merge reaches the desk", func() bool {
		got := x.n1.host("web")
		return got != nil && got.Port == 2222
	})
	if got := x.n1.host("web"); got.User != "deploy" || got.AgentOutput != "" {
		t.Errorf("the desk has user %q, agent_output %q", got.User, got.AgentOutput)
	}
}

// The token confirms the server's version and the hold beside the
// replacement: either changing makes another token, the hold's reason text
// aside.
func TestConfirmTokenCoversTheSnapshot(t *testing.T) {
	e := newSyncer(nil, nil, SyncOptions{})
	hold := &store.HoldInfo{Cause: merge.CauseGuardedConflict, Local: []string{"port"}, Remote: []string{"user"},
		Conflicts: []merge.Conflict{{Kind: merge.ConflictUnit, Name: merge.UnitConnection, Local: []string{"port"}, Remote: []string{"user"}}}}
	base := store.Proposal{N: 7, Current: []byte(`{"port":22}`), Hold: hold}
	tok := e.confirmToken(base)
	for name, p := range map[string]store.Proposal{
		"another server version": {N: 7, Current: []byte(`{"port":23}`), Hold: hold},
		"no server version":      {N: 7, Hold: hold},
		"another hold": {N: 7, Current: base.Current, Hold: &store.HoldInfo{Cause: hold.Cause, Local: hold.Local, Remote: hold.Remote,
			Conflicts: append(slices.Clone(hold.Conflicts), merge.Conflict{Kind: merge.ConflictCoupling, Name: merge.CouplingAgentWidening})}},
		"no hold": {N: 7, Current: base.Current},
	} {
		if e.confirmToken(p) == tok {
			t.Errorf("%s: the same token", name)
		}
	}
	reason := *hold
	reason.Reason = "an error's text"
	if e.confirmToken(store.Proposal{N: 7, Current: base.Current, Hold: &reason}) != tok {
		t.Error("the hold's reason changes the token")
	}
}
