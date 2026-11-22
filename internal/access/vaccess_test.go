package access

import (
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"

	"github.com/dalyem/hopkey/internal/crypto"
	"github.com/dalyem/hopkey/internal/model"
)

func tid(b byte) model.ID {
	var x model.ID
	for i := range x {
		x[i] = b
	}
	return x
}

func edPub(t testing.TB, seed byte) ssh.PublicKey {
	t.Helper()
	s := make([]byte, 32)
	s[0] = seed
	pk, err := ssh.NewPublicKey(ed25519.NewKeyFromSeed(s).Public())
	if err != nil {
		t.Fatal(err)
	}
	return pk
}

func keyLine(pk ssh.PublicKey) string {
	return pk.Type() + " " + base64.StdEncoding.EncodeToString(pk.Marshal())
}

var (
	hostA, hostB = tid(0x0a), tid(0x0b)
	devA, devB   = tid(0xd1), tid(0xd2)
)

// record is alice with web (hostA) in state sa/gen ga and db (hostB) in
// state sb/gen gb.
func record(t testing.TB, sa string, ga uint64, sb string, gb uint64) *model.Access {
	t.Helper()
	pk := edPub(t, 1)
	fp := ssh.FingerprintSHA256(edPub(t, 2))
	a := &model.Access{
		Header: model.Header{V: 1, ItemID: tid(1), Type: model.TypeAccess, ItemVersion: 3},
		Label:  "alice", RecordID: tid(2), PublicKey: keyLine(pk), Fingerprint: ssh.FingerprintSHA256(pk),
		Options: model.AccessOptions{From: []string{}}, By: devB,
		Targets: []model.AccessTarget{
			{HostItemID: hostA, User: "root", ServerKeyFP: fp, Gen: ga, State: sa, Time: 100},
			{HostItemID: hostB, User: "root", ServerKeyFP: fp, Gen: gb, State: sb, Time: 100},
		},
	}
	if err := crypto.ValidateAccess(a); err != nil {
		t.Fatal(err)
	}
	return a
}

func stamp(a *model.Access) *model.Access { a.By = devA; return a }

func wantRefused(t testing.TB, err error, rule string) {
	t.Helper()
	var r *Refusal
	if !errors.As(err, &r) || r.Rule != rule || !errors.Is(err, ErrRefused) {
		t.Fatalf("got %v, want a %s refusal", err, rule)
	}
}

// Every row of the §7.1 table passes; the rows it doesn't have are
// refused.
func TestCheckTransitions(t *testing.T) {
	type row struct {
		from string
		fg   uint64
		to   string
		tg   uint64
		ok   bool
	}
	P, I, F, R, D, A := model.AccessPending, model.AccessInstalled, model.AccessFailed, model.AccessRemoving, model.AccessRemoved, model.AccessAbandoned
	for _, r := range []row{
		{F, 2, P, 3, true}, {I, 2, P, 3, true}, {P, 2, P, 3, false}, {F, 2, P, 2, false},
		{P, 2, I, 2, true}, {P, 2, F, 2, true}, {P, 2, I, 3, false}, {I, 2, F, 2, false},
		{P, 2, R, 3, true}, {I, 2, R, 3, true}, {F, 2, R, 3, true}, {I, 2, R, 2, false}, {R, 2, R, 3, false},
		{R, 2, D, 2, true}, {R, 2, D, 3, false}, {I, 2, D, 2, false},
		{P, 2, A, 3, true}, {I, 2, A, 3, true}, {R, 2, A, 3, true}, {I, 2, A, 2, false},
		{R, 2, I, 2, false}, {D, 2, I, 3, false}, {D, 2, P, 3, false}, {A, 2, R, 3, false},
	} {
		s := record(t, r.from, r.fg, I, 1)
		next := stamp(Clone(s))
		next.Targets[0].State, next.Targets[0].Gen = r.to, r.tg
		err := Check(s, next, PathWrite)
		if (err == nil) != r.ok {
			t.Errorf("%s/%d -> %s/%d: ok %v, got %v", r.from, r.fg, r.to, r.tg, r.ok, err)
		}
	}
}

// Keep mine that would move a removed target back to installed is refused
// with a message that names the target.
func TestCheckRefusesTerminalRegression(t *testing.T) {
	s := record(t, model.AccessRemoved, 4, model.AccessInstalled, 1)
	next := stamp(Clone(s))
	next.Targets[0].State, next.Targets[0].Gen = model.AccessInstalled, 3
	err := Check(s, next, PathResolve)
	wantRefused(t, err, RuleTerminal)
	if r := err.(*Refusal); r.Host != hostA || !strings.Contains(err.Error(), "removed") || !strings.Contains(err.Error(), "hop access check") {
		t.Fatalf("message %q host %v", err, r.Host)
	}
}

// A result put records an observation only from the gen the run acted
// under; a target that moved on keeps its newer state, and the rest of the
// put is still recorded.
func TestApplyResultsFences(t *testing.T) {
	s := record(t, model.AccessPending, 4, model.AccessPending, 2)
	fp := s.Targets[0].ServerKeyFP
	next, kept := ApplyResults(s, []Result{
		{ItemID: s.ItemID, RecordID: s.RecordID, Host: hostA, FP: fp, From: model.AccessPending, Gen: 3, State: model.AccessInstalled},
		{ItemID: s.ItemID, RecordID: s.RecordID, Host: hostB, FP: fp, From: model.AccessPending, Gen: 2, State: model.AccessFailed, Error: "no"},
	}, 200)
	if len(kept) != 1 || kept[0].Host != hostB {
		t.Fatalf("kept %+v", kept)
	}
	if next.Targets[0].State != model.AccessPending || next.Targets[0].Gen != 4 || next.Targets[1].State != model.AccessFailed {
		t.Fatalf("next %+v", next.Targets)
	}
	if err := Check(s, stamp(next), PathWrite); err != nil {
		t.Fatal(err)
	}
	// Every observation dropped: nothing to record.
	none, kept := ApplyResults(s, []Result{{ItemID: s.ItemID, RecordID: s.RecordID, Host: hostA, FP: fp, From: model.AccessPending, Gen: 3, State: model.AccessInstalled}}, 200)
	if len(kept) != 0 || Substantive(s, stamp(none)) {
		t.Fatal("a put with every observation dropped is substantive")
	}
	wantRefused(t, Check(s, none, PathWrite), RuleNothing)
}

// An observation is for the record it was made for, never for another
// record that has the same label now (review P1): record B reused A's
// label, and its target on the same host, bound to the same key, is in
// the state and gen A's run acted under.
func TestApplyResultsNeedTheSameRecord(t *testing.T) {
	a := record(t, model.AccessRemoving, 2, model.AccessRemoved, 2)
	b := record(t, model.AccessRemoving, 2, model.AccessRemoved, 2)
	b.ItemID, b.RecordID = tid(3), tid(4)
	fp := a.Targets[0].ServerKeyFP
	obs := Result{ItemID: a.ItemID, RecordID: a.RecordID, Host: hostA, FP: fp, From: model.AccessRemoving, Gen: 2, State: model.AccessRemoved}
	if next, kept := ApplyResults(b, []Result{obs}, 200); len(kept) != 0 || Substantive(b, next) {
		t.Fatalf("A's observation was applied to B: kept %+v", kept)
	}
	// The same item with another record ID is not A either.
	c := Clone(b)
	c.ItemID = a.ItemID
	if _, kept := ApplyResults(c, []Result{obs}, 200); len(kept) != 0 {
		t.Fatalf("applied across record IDs: %+v", kept)
	}
	if _, kept := ApplyResults(a, []Result{obs}, 200); len(kept) != 1 {
		t.Fatal("A's own observation was dropped")
	}
}

func TestCheckDelete(t *testing.T) {
	wantRefused(t, CheckDelete(record(t, model.AccessRemoved, 2, model.AccessRemoving, 2), true), RuleDelete)
	abandoned := record(t, model.AccessRemoved, 2, model.AccessAbandoned, 2)
	wantRefused(t, CheckDelete(abandoned, false), RuleDelete) // rm leaves it live
	if err := CheckDelete(abandoned, true); err != nil {      // forget deletes it
		t.Fatal(err)
	}
	if err := CheckDelete(record(t, model.AccessRemoved, 2, model.AccessRemoved, 2), false); err != nil {
		t.Fatal(err)
	}
}

// The attestation: only the before-acting put of rm --same-machine (and
// its rebase, PathWrite) sets it, with the new gen; no resolution creates,
// changes or clears one, and a planner's result put carries S's value.
func TestCheckAttestation(t *testing.T) {
	s := record(t, model.AccessInstalled, 2, model.AccessInstalled, 1)
	next := stamp(Clone(s))
	t0 := &next.Targets[0]
	t0.State, t0.Gen = model.AccessRemoving, 3
	t0.SameMachine = &model.SameMachine{Gen: 3, ServerKeyFP: t0.ServerKeyFP, HostItemIDs: []model.ID{hostB}}
	if err := Check(s, next, PathWrite); err != nil {
		t.Fatalf("rm --same-machine put: %v", err)
	}
	wantRefused(t, Check(s, next, PathResolve), RuleAttestation)
	wantRefused(t, CheckAttestationUnchanged(s, next), RuleAttestation)
	t0.SameMachine.Gen = 2
	if err := Check(s, next, PathWrite); err == nil {
		t.Fatal("an attestation for an older gen was accepted")
	}
	// On a target already removing: gen + 1 with the statement.
	r := record(t, model.AccessRemoving, 3, model.AccessInstalled, 1)
	n2 := stamp(Clone(r))
	n2.Targets[0].Gen = 4
	n2.Targets[0].SameMachine = &model.SameMachine{Gen: 4, ServerKeyFP: r.Targets[0].ServerKeyFP, HostItemIDs: []model.ID{hostB}}
	if err := Check(r, n2, PathWrite); err != nil {
		t.Fatal(err)
	}
	// A result put (removed) carries it byte for byte; clearing is refused.
	n3 := stamp(Clone(n2))
	n3.Targets[0].State = model.AccessRemoved
	if err := Check(n2, n3, PathWrite); err != nil {
		t.Fatal(err)
	}
	n3.Targets[0].SameMachine = nil
	if err := Check(n2, n3, PathWrite); err == nil {
		t.Fatal("clearing the attestation was accepted")
	}
	wantRefused(t, CheckAttestationUnchanged(n2, n3), RuleAttestation)
}

// A new target starts pending with gen 1; a migrate's new target takes the
// old one's intent in the put that abandons it.
func TestCheckNewTargets(t *testing.T) {
	s := record(t, model.AccessRemoving, 3, model.AccessInstalled, 1)
	newFP := ssh.FingerprintSHA256(edPub(t, 9))
	add := func(state string, gen uint64, abandon bool) error {
		next := stamp(Clone(s))
		if abandon {
			next.Targets[0].State, next.Targets[0].Gen = model.AccessAbandoned, 4
		}
		next.Targets = append(next.Targets, model.AccessTarget{HostItemID: hostA, User: "root", ServerKeyFP: newFP, Gen: gen, State: state})
		sortTargets(next.Targets)
		if err := crypto.ValidateAccess(next); err != nil {
			return err
		}
		return Check(s, next, PathWrite)
	}
	if err := add(model.AccessRemoving, 1, true); err != nil {
		t.Fatalf("migrate of a removing target: %v", err)
	}
	if err := add(model.AccessPending, 1, true); err != nil {
		t.Fatalf("migrate to pending: %v", err)
	}
	if add(model.AccessRemoving, 1, false) == nil || add(model.AccessPending, 2, true) == nil || add(model.AccessInstalled, 1, true) == nil {
		t.Fatal("a new target that doesn't start pending (or removing in a migrate) was accepted")
	}
}
