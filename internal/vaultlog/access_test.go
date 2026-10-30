package vaultlog

import (
	"strings"
	"testing"

	"github.com/dalyem/hopkey/internal/canonjson"
	"github.com/dalyem/hopkey/internal/crypto"
	"github.com/dalyem/hopkey/internal/model"
)

var (
	idAccess = fixedID(0xac)
	idRecID  = fixedID(0xad)
)

// accessItem is a record by A with H1 installed (gen 2) and H2 removed
// (gen 3).
func accessItem(t testing.TB) *model.Access {
	t.Helper()
	pub, fp := sshKey(t, "colleague")
	pub = strings.Join(strings.Fields(pub)[:2], " ")
	_, hfp := sshKey(t, "hostkey")
	at := ts(t, "2026-10-29T00:00:00Z")
	return &model.Access{
		Header: model.Header{ItemID: idAccess, Type: model.TypeAccess},
		Label:  "alice", RecordID: idRecID, PublicKey: pub, Fingerprint: fp,
		Options: model.AccessOptions{From: []string{}}, By: idDevA,
		Targets: []model.AccessTarget{
			{HostItemID: idH1, User: "root", ServerKeyFP: hfp, Gen: 2, State: model.AccessInstalled, Time: at},
			{HostItemID: idH2, User: "deploy", ServerKeyFP: hfp, Gen: 3, State: model.AccessRemoved, Time: at},
		},
	}
}

func withAccess(t testing.TB) *world {
	w := newWorld(t).withItems()
	w.normal(Changes{Put: []crypto.Item{accessItem(t)}})
	return w
}

// access is a deep copy of A's access item: item() copies the struct only,
// and its targets would alias verified state.
func (w *world) access() *model.Access { return deepAccess(w.t, w.item(idAccess)) }

func deepAccess(t testing.TB, it crypto.Item) *model.Access {
	t.Helper()
	b, err := canonjson.Marshal(it)
	if err != nil {
		t.Fatal(err)
	}
	var a model.Access
	if err := canonjson.Unmarshal(b, &a); err != nil {
		t.Fatal(err)
	}
	return &a
}

// The log rules of the access item (spec rev 17, Part 2, §5.1), against a
// verifier: each change is a plaintext-stage violation.
func TestAccessLogRules(t *testing.T) {
	w := withAccess(t)
	_, otherFP := sshKey(t, "other")
	otherPub, _ := sshKey(t, "other")
	otherPub = strings.Join(strings.Fields(otherPub)[:2], " ")
	cases := []struct {
		name string
		rule Rule
		f    func(a *model.Access)
	}{
		{"label", RuleAccessIdentity, func(a *model.Access) { a.Label = "bob" }},
		{"record_id", RuleAccessIdentity, func(a *model.Access) { a.RecordID = fixedID(0xae) }},
		{"public_key", RuleAccessIdentity, func(a *model.Access) { a.PublicKey, a.Fingerprint = otherPub, otherFP }},
		{"options", RuleAccessIdentity, func(a *model.Access) { a.Options.NoForwarding = true }},
		{"drops a target", RuleAccessTargets, func(a *model.Access) { a.Targets = a.Targets[:1] }},
		{"changes a user", RuleAccessTargets, func(a *model.Access) { a.Targets[0].User = "admin" }},
		{"changes a binding", RuleAccessTargets, func(a *model.Access) { a.Targets[0].ServerKeyFP = otherFP }},
		{"by is not the author", RuleAccessAuthor, func(a *model.Access) { a.By = idDevB; a.Targets[0].Gen++ }},
		{"removed target changes", RuleAccessTerminal, func(a *model.Access) { a.Targets[1].Time++ }},
		{"removed target's error", RuleAccessTerminal, func(a *model.Access) { a.Targets[1].State = model.AccessRemoving; a.Targets[1].Error = "x" }},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			a := w.access()
			c.f(a)
			wantRule(t, w.transition(w.unverified(Changes{Put: []crypto.Item{a}})), c.rule)
		})
	}
	t.Run("a valid state change", func(t *testing.T) {
		a := w.access()
		a.Targets[0].State, a.Targets[0].Gen = model.AccessRemoving, 3
		mustAccept(t, w.transition(w.unverified(Changes{Put: []crypto.Item{a}})))
	})
	t.Run("a create by another device", func(t *testing.T) {
		a := accessItem(t)
		a.ItemID, a.By = fixedID(0xaf), idDevB
		wantRule(t, w.transition(w.unverified(Changes{Put: []crypto.Item{a}})), RuleAccessAuthor)
	})
}

// A checkpoint re-puts an access item with every non-header member
// unchanged, by included; anything else is a violation. A device that
// anchors at the checkpoint has no pre-state and accepts it, and rejects
// the next entry that changes a terminal target.
func TestAccessCheckpointRule(t *testing.T) {
	w := withAccess(t)
	p := w.checkpointParams()
	base := w.unverifiedCheckpoint(p)
	mustAccept(t, w.transition(base))
	if got := putFor(t, &base.Entry, idAccess).ItemVersion; got != w.st.Items[idAccess].ItemVersion+1 {
		t.Fatalf("checkpoint re-puts the access item at version %d", got)
	}
	signers := w.checkpointSigners(p.NewAccount)
	for _, c := range []struct {
		name string
		f    func(a *model.Access)
	}{
		{"by", func(a *model.Access) { a.By = idDevC }},
		{"a target's time", func(a *model.Access) { a.Targets[0].Time++ }},
	} {
		t.Run(c.name, func(t *testing.T) {
			bad := cloneWire(t, base)
			ik, err := crypto.NewSymKey()
			if err != nil {
				t.Fatal(err)
			}
			a := w.access()
			c.f(a)
			reseal(t, bad, w.st, p.NewVK, ik, a, nil)
			resign(t, bad, signers)
			wantRule(t, w.transition(bad), RuleAccessCheckpoint)
		})
	}
	t.Run("anchor", func(t *testing.T) {
		cp := cloneWire(t, base)
		ik, err := crypto.NewSymKey()
		if err != nil {
			t.Fatal(err)
		}
		a := w.access()
		a.By = idDevC // authored no put
		reseal(t, cp, w.st, p.NewVK, ik, a, nil)
		resign(t, cp, signers)
		w.record(cp)
		fst, fsec, _, err := Anchor(p.NewAccount.Pin(), p.NewAccount, cp, w.archive, nil)
		if err != nil {
			t.Fatalf("anchor: %v", err)
		}
		next := deepAccess(t, withHeaderOf(t, fsec.Items[idAccess].Item, fst.Items[idAccess].ItemVersion))
		next.By = idDevA
		next.Targets[1].Error, next.Targets[1].State = "back", model.AccessRemoving
		wire, err := buildNormalWire(fst, fsec, w.devA(), Changes{Put: []crypto.Item{next}}, w.now())
		if err != nil {
			t.Fatal(err)
		}
		_, _, err = Transition(fst, fsec, w.devA(), wire, w.archive)
		wantRule(t, err, RuleAccessTerminal)
	})
}

func withHeaderOf(t testing.TB, it crypto.Item, v uint64) crypto.Item {
	t.Helper()
	out, _, err := withHeader(it, v)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// access is one of the item types this build and its server accept.
func TestItemTypesListAccess(t *testing.T) {
	types := ItemTypes()
	for i, typ := range types {
		if !isItemType(typ) {
			t.Errorf("%s is listed but not accepted", typ)
		}
		if i > 0 && types[i-1] >= typ {
			t.Errorf("not sorted: %v", types)
		}
	}
	if len(types) != 7 || !isItemType(model.TypeAccess) {
		t.Errorf("types %v", types)
	}
}
