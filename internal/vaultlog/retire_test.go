package vaultlog

import (
	"bytes"
	"errors"
	"fmt"
	"slices"
	"testing"

	"github.com/dalyem/hopkey/internal/crypto"
	"github.com/dalyem/hopkey/internal/model"
)

// retire builds, verifies and applies the device_retire entry of id.
func (w *world) retire(id model.ID) *Wire {
	w.t.Helper()
	wire, st, sec, err := BuildRetire(w.st, w.sec, w.devs[id], w.now())
	if err != nil {
		w.t.Fatal(err)
	}
	w.record(wire)
	w.st, w.sec = st, sec
	return wire
}

// bootstrap builds, verifies and applies a bootstrap entry adding id.
func (w *world) bootstrap(id model.ID) *Wire {
	w.t.Helper()
	wire, st, sec, err := BuildBootstrap(w.st, w.sec, w.infos[id], w.now())
	if err != nil {
		w.t.Fatal(err)
	}
	w.record(wire)
	w.st, w.sec = st, sec
	return wire
}

// checkpoint builds, verifies and applies a checkpoint by A.
func (w *world) checkpoint(p CheckpointParams) *Wire {
	w.t.Helper()
	wire, st, sec, err := BuildCheckpoint(w.st, w.sec, w.devA(), p)
	if err != nil {
		w.t.Fatal(err)
	}
	w.record(wire)
	w.st, w.sec = st, sec
	return wire
}

// §5.3 device_retire (rev 16): a device retires only itself, with a normal
// entry that holds nothing else, and only while it is active.
func TestRetireRules(t *testing.T) {
	w := full(t)
	base, err := buildRetireWire(w.st, w.sec, w.devA(), w.now())
	if err != nil {
		t.Fatal(err)
	}
	runMutations(t, w.transition, base, w.normalSigners(), []mutation{
		// device_retire naming a device other than the author (§13).
		{"names another active device", RuleRetireSelf, func(e *Entry, _ *Wire) {
			opsOf[*DeviceRetireOp](e)[0].DeviceID = idDevB
		}},
		{"names an inactive device", RuleRetireSelf, func(e *Entry, _ *Wire) {
			opsOf[*DeviceRetireOp](e)[0].DeviceID = idDevC
		}},
		// device_retire with a second op, or in a non-normal entry (§13).
		{"with an item_put", RuleRetireContents, func(e *Entry, _ *Wire) {
			e.Ops = append(e.Ops, &ItemPutOp{Op: OpItemPut, ItemID: idS1, Type: model.TypeSnippet, ItemVersion: 2, IV: 1, KV: 1})
		}},
		{"with a second device_retire", RuleRetireContents, func(e *Entry, _ *Wire) {
			e.Ops = append(e.Ops, &DeviceRetireOp{Op: OpDeviceRetire, DeviceID: idDevB})
		}},
		{"retiring the author twice", RuleOpDupID, func(e *Entry, _ *Wire) {
			e.Ops = append(e.Ops, &DeviceRetireOp{Op: OpDeviceRetire, DeviceID: idDevA})
		}},
		{"in a checkpoint", RuleOpKind, func(e *Entry, _ *Wire) { e.Kind = KindCheckpoint }},
		{"in a bootstrap", RuleOpKind, func(e *Entry, _ *Wire) { e.Kind = KindBootstrap }},
		{"in a genesis", RuleOpKind, func(e *Entry, _ *Wire) { e.Kind = KindGenesis }},
	})
	// device_retire by an inactive device (§13). The author of a normal
	// entry must be active, and device_id must equal author.
	t.Run("by a device never added", func(t *testing.T) {
		devC := w.devs[idDevC]
		bad := mutate(t, base, map[Role]signer{RoleDevice: devSigner(devC)}, func(e *Entry, _ *Wire) {
			e.Author = idDevC
			opsOf[*DeviceRetireOp](e)[0].DeviceID = idDevC
		})
		wantRule(t, w.transition(bad), RuleAuthorState)
	})
	t.Run("by a retired device", func(t *testing.T) {
		w := full(t)
		w.retire(idDevB)
		again, err := buildRetireWire(w.st, w.sec, w.devs[idDevB], w.now())
		if err != nil {
			t.Fatal(err)
		}
		wantRule(t, w.transition(again), RuleAuthorState)
		_, _, _, err = BuildRetire(w.st, w.sec, w.devs[idDevB], w.now())
		wantRule(t, err, RuleAuthorState)
	})
	t.Run("by a revoked device", func(t *testing.T) {
		w := full(t)
		w.checkpoint(w.checkpointParams(idDevB))
		bad, err := buildRetireWire(w.st, w.sec, w.devs[idDevB], w.now())
		if err != nil {
			t.Fatal(err)
		}
		wantRule(t, w.transition(bad), RuleAuthorState)
	})
	t.Run("signed by another device", func(t *testing.T) {
		bad := mutate(t, base, map[Role]signer{RoleDevice: devSigner(w.devs[idDevB])}, func(*Entry, *Wire) {})
		wantRule(t, w.transition(bad), RuleSigDevice)
	})
}

// The post-state of a retirement removes the device from the active set,
// adds it to retired.device_ids, and changes nothing else (§5.3).
func TestRetireTransition(t *testing.T) {
	w := full(t)
	pre := w.st
	w.retire(idDevB)
	post := w.st
	if _, ok := post.Devices[idDevB]; ok {
		t.Fatal("retired device B is still active")
	}
	if !slices.Equal(post.Retired.DeviceIDs, []model.ID{idDevB}) {
		t.Fatalf("retired.device_ids = %v, want [B]", post.Retired.DeviceIDs)
	}
	// Everything but head, devices and retired.device_ids is unchanged.
	want := pre.clone()
	want.Head = post.Head
	delete(want.Devices, idDevB)
	want.Retired.DeviceIDs = []model.ID{idDevB}
	if !sameJCS(want, post) {
		t.Fatal("retirement changed more than the device and the retired set")
	}
	// BuildRetire verified the entry as a transition by B itself; A's
	// view of the same entry agrees.
	if st, _, err := Transition(pre, w.sec, w.devA(), w.log[len(w.log)-1], w.archive); err != nil || !sameJCS(st, post) {
		t.Fatalf("A's view of B's retirement: %v", err)
	}

	// Retiring the last active device is valid. Only a bootstrap can then
	// add a device, and the retired author can no longer write.
	w.retire(idDevA)
	if len(w.st.Devices) != 0 {
		t.Fatalf("%d devices active after retiring the last one", len(w.st.Devices))
	}
	wantRule(t, w.transition(w.unverified(Changes{Put: []crypto.Item{w.item(idS1)}})), RuleAuthorState)
	_, _, _, err := BuildCheckpoint(w.st, w.sec, w.devA(), w.checkpointParams())
	wantRule(t, err, RuleAuthorState)
	w.bootstrap(idDevC)
	if _, ok := w.st.Devices[idDevC]; !ok {
		t.Fatal("bootstrap after the last retirement did not add C")
	}
}

// Re-adding a retired ID fails the uniqueness rule (§13): IDs are never
// reused, by a bootstrap, an enrollment or a checkpoint.
func TestRetiredIDNotReused(t *testing.T) {
	w := full(t)
	w.retire(idDevB)
	_, _, _, err := BuildBootstrap(w.st, w.sec, w.infos[idDevB], w.now())
	wantRule(t, err, RuleUniqueID)

	enroll := w.unverified(Changes{Devices: []DeviceInfo{w.enrolled(idDevB)}})
	wantRule(t, w.transition(enroll), RuleUniqueID)

	// A checkpoint that recertifies B as if it were still active.
	p := w.checkpointParams()
	cp := w.unverifiedCheckpoint(p)
	bad := mutate(t, cp, w.checkpointSigners(p.NewAccount), func(e *Entry, wr *Wire) {
		b := *deviceAddFor(t, e, idDevA)
		b.Cert.DeviceID, b.Cert.Name = idDevB, "dev-b"
		b.Cert.KEMFp, b.Cert.SigFp = crypto.FpKEM(w.infos[idDevB].KEMPK), crypto.FpSig(w.infos[idDevB].SigPK)
		b.KEMPK, b.SigPK = w.infos[idDevB].KEMPK, w.infos[idDevB].SigPK
		resignCert(t, &b, p.NewAccount)
		e.Ops = append(e.Ops, &b)
		r := opsOf[*RetiredOp](e)[0]
		r.DeviceIDs = []model.ID{}
	})
	wantRule(t, w.transition(bad), RuleDeviceCover)
}

// A checkpoint's retired includes every device retired since the last
// checkpoint (§5.3, rev 16), and survivor/revoked coverage concerns only
// the pre-state active devices.
func TestCheckpointRetiredDevices(t *testing.T) {
	w := full(t).deleteC1()
	w.bootstrap(idDevC)
	w.retire(idDevB)
	p := w.checkpointParams(idDevC)
	base := w.unverifiedCheckpoint(p)
	r := opsOf[*RetiredOp](&base.Entry)[0]
	if !slices.Equal(r.DeviceIDs, setOf([]model.ID{idDevB, idDevC}).sorted()) {
		t.Fatalf("checkpoint retired.device_ids = %v, want B and C", r.DeviceIDs)
	}
	if n := len(opsOf[*DeviceRevokeOp](&base.Entry)); n != 1 {
		t.Fatalf("checkpoint holds %d device_revoke ops, want 1 (C only)", n)
	}
	runMutations(t, w.transition, base, w.checkpointSigners(p.NewAccount), []mutation{
		// A checkpoint whose retired omits a retired device (§13).
		{"retired omits the retired device", RuleCheckpointRetired, func(e *Entry, _ *Wire) {
			opsOf[*RetiredOp](e)[0].DeviceIDs = []model.ID{idDevC}
		}},
		{"retired omits the revoked device", RuleCheckpointRetired, func(e *Entry, _ *Wire) {
			opsOf[*RetiredOp](e)[0].DeviceIDs = []model.ID{idDevB}
		}},
		// Retired IDs are already in retired and are not revoked again.
		{"revokes the retired device", RuleDeviceCover, func(e *Entry, _ *Wire) {
			e.Ops = append(e.Ops, &DeviceRevokeOp{Op: OpDeviceRevoke, DeviceID: idDevB})
		}},
	})
	// A fresh client anchors at the checkpoint and holds the same state.
	cp := w.checkpoint(p)
	st, _, _, err := Anchor(p.NewAccount.Pin(), p.NewAccount, cp, w.archive, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !sameJCS(st, w.st) {
		t.Fatal("anchor and transition disagree after a retirement")
	}
}

// retireLog is the scenario log for ApplyPublic: genesis, a bootstrap,
// normal edits, a grant and deploy ops, a deletion, a second bootstrap, a
// retirement, another edit, a checkpoint revoking a device, and an edit
// after it.
func retireLog(t *testing.T) *world {
	w := full(t).deleteC1()
	w.bootstrap(idDevC)
	w.retire(idDevB)
	w.normal(Changes{Put: []crypto.Item{w.host(idH2)}})
	w.checkpoint(w.checkpointParams(idDevC))
	w.normal(Changes{Put: []crypto.Item{w.item(idS1)}})
	return w
}

// clientStates replays w.log as device A, anchored at genesis, and returns
// the verified state after each entry.
func clientStates(t *testing.T, w *world) []*State {
	t.Helper()
	st, sec, _, err := Anchor(w.acct.Pin(), w.acct, w.log[0], w.archive, nil)
	if err != nil {
		t.Fatal(err)
	}
	out := []*State{st}
	for _, wire := range w.log[1:] {
		if st, sec, err = Transition(st, sec, w.devA(), wire, w.archive); err != nil {
			t.Fatalf("seq %d: %v", wire.Entry.Seq, err)
		}
		out = append(out, st)
	}
	return out
}

// publicStates replays w.log with ApplyPublic from the empty state.
func publicStates(t *testing.T, w *world) []*PublicState {
	t.Helper()
	var ps *PublicState
	var out []*PublicState
	for _, wire := range w.log {
		var err error
		if ps, err = ApplyPublic(ps, wire, w.archive); err != nil {
			t.Fatalf("seq %d: %v", wire.Entry.Seq, err)
		}
		out = append(out, ps)
	}
	return out
}

// ApplyPublic over the scenario log agrees with the client's Transition on
// every public field, and reports each entry's departures.
func TestApplyPublicAgreesWithTransition(t *testing.T) {
	w := retireLog(t)
	states := clientStates(t, w)
	pubs := publicStates(t, w)
	if !sameJCS(states[len(states)-1], w.st) {
		t.Fatal("replayed client state differs from the author's")
	}
	all := []model.ID{idDevA, idDevB, idDevC}
	for i, ps := range pubs {
		st := states[i]
		wire := w.log[i]
		if !sameJCS(ps.s, st) {
			a, _ := ps.s.Marshal()
			b, _ := st.Marshal()
			t.Fatalf("seq %d: public and verified state differ:\n%s\n%s", i, a, b)
		}
		if ps.Head() != st.Head || ps.VaultID() != st.VaultID || ps.AccountID() != st.Account.AccountID {
			t.Fatalf("seq %d: head, vault or account accessor differs", i)
		}
		creds, ok := ps.Creds()
		if !ok || !sameJCS(&creds, &st.Creds) {
			t.Fatalf("seq %d: creds differ", i)
		}
		acct, ok := ps.Account()
		if !ok || acct.AKV != st.Account.AKV || !bytes.Equal(acct.SigPK, st.Account.SigPK) || !bytes.Equal(acct.KEMPK, st.Account.KEMPK) {
			t.Fatalf("seq %d: account keys differ", i)
		}
		for _, id := range all {
			d, active := st.Devices[id]
			if ps.DeviceActive(id) != active {
				t.Fatalf("seq %d: DeviceActive(%v) = %v, want %v", i, id, !active, active)
			}
			if got, ok := ps.Device(id); ok != active || active && !sameJCS(&got, &d) {
				t.Fatalf("seq %d: Device(%v) differs", i, id)
			}
		}
		if !slices.Equal(sortedHashes(ps.ObjectDigests()), sortedHashes(st.ObjectDigests())) {
			t.Fatalf("seq %d: object digests differ", i)
		}

		var want []Departure
		h := Head{Seq: wire.Entry.Seq, H: st.Head.H}
		for _, o := range wire.Entry.Ops {
			switch o := o.(type) {
			case *DeviceRetireOp:
				want = append(want, Departure{DeviceID: o.DeviceID, How: DepartRetired, Head: h})
			case *DeviceRevokeOp:
				want = append(want, Departure{DeviceID: o.DeviceID, How: DepartRevoked, Head: h})
			}
		}
		if got := ps.Departures(); !slices.Equal(got, want) {
			t.Fatalf("seq %d: departures %v, want %v", i, got, want)
		}

		// The serialization round-trips, and neither parser accepts the
		// other type's form.
		b, err := ps.Marshal()
		if err != nil {
			t.Fatal(err)
		}
		back, err := ParsePublicState(b)
		if err != nil {
			t.Fatalf("seq %d: %v", i, err)
		}
		if b2, _ := back.Marshal(); !bytes.Equal(b, b2) || !slices.Equal(back.Departures(), ps.Departures()) {
			t.Fatalf("seq %d: public state does not round-trip", i)
		}
		if _, err := ParseState(b); err == nil {
			t.Fatalf("seq %d: ParseState accepted a public state", i)
		}
		sb, _ := st.Marshal()
		if _, err := ParsePublicState(sb); err == nil {
			t.Fatalf("seq %d: ParsePublicState accepted a verified state", i)
		}
	}
	// The scenario reached both departure kinds.
	var kinds []DepartureKind
	for _, ps := range pubs {
		for _, d := range ps.Departures() {
			kinds = append(kinds, d.How)
		}
	}
	if !slices.Equal(kinds, []DepartureKind{DepartRetired, DepartRevoked}) {
		t.Fatalf("departures over the log: %v", kinds)
	}
}

// ApplyPublic rejects exactly what CheckPublic rejects, with the same rule.
func TestApplyPublicRejectsLikeCheckPublic(t *testing.T) {
	w := retireLog(t)
	states := clientStates(t, w)
	pubs := publicStates(t, w)
	same := func(t *testing.T, st *State, ps *PublicState, wire *Wire) {
		t.Helper()
		_, errC := CheckPublic(st, wire, w.archive)
		got, errA := ApplyPublic(ps, wire, w.archive)
		if errC == nil {
			t.Fatalf("CheckPublic accepted a bad entry at seq %d", wire.Entry.Seq)
		}
		if errA == nil || got != nil {
			t.Fatalf("ApplyPublic accepted what CheckPublic rejects: %v", errC)
		}
		if RuleOf(errA) != RuleOf(errC) || RuleOf(errC) == "" && errA.Error() != errC.Error() {
			t.Fatalf("CheckPublic: %v\nApplyPublic: %v", errC, errA)
		}
	}
	// Mutations of each entry against its own pre-state. They are not
	// re-signed: whichever rule fires first must be the same for both.
	ms := []struct {
		name string
		f    func(e *Entry, wr *Wire)
	}{
		{"seq skips", func(e *Entry, _ *Wire) { e.Seq++ }},
		{"prev changed", func(e *Entry, _ *Wire) { e.Prev = crypto.SomeHash(crypto.Hash{1}) }},
		{"other vault", func(e *Entry, _ *Wire) { e.VaultID = fixedID(0xee) }},
		{"other author", func(e *Entry, _ *Wire) { e.Author = idDevC }},
		{"time changed", func(e *Entry, _ *Wire) { e.Time++ }},
		{"no signatures", func(_ *Entry, wr *Wire) { wr.Sigs = []Sig{} }},
		{"signature corrupted", func(_ *Entry, wr *Wire) { wr.Sigs[0].Sig[0] ^= 1 }},
		{"objects dropped", func(_ *Entry, wr *Wire) { wr.Objects = []Object{} }},
		{"akv changed", func(e *Entry, _ *Wire) { e.AKV++ }},
		{"kind normal", func(e *Entry, _ *Wire) { e.Kind = KindNormal }},
	}
	for i, wire := range w.log {
		var st *State
		var ps *PublicState
		if i > 0 {
			st, ps = states[i-1], pubs[i-1]
		}
		for _, m := range ms {
			t.Run(fmt.Sprintf("seq %d %s", i, m.name), func(t *testing.T) {
				bad := cloneWire(t, wire)
				m.f(&bad.Entry, bad)
				if _, err := CheckPublic(st, bad, w.archive); err == nil {
					// The mutation left the entry valid (for example kind
					// normal on a normal entry); ApplyPublic must agree.
					if _, err := ApplyPublic(ps, bad, w.archive); err != nil {
						t.Fatalf("ApplyPublic rejects what CheckPublic accepts: %v", err)
					}
					return
				}
				same(t, st, ps, bad)
			})
		}
		if i == 0 {
			continue
		}
		// Replays, stale entries, gaps and entries with no prior state.
		t.Run(fmt.Sprintf("seq %d already applied", i), func(t *testing.T) { same(t, states[i], pubs[i], wire) })
		if i+1 < len(w.log) {
			t.Run(fmt.Sprintf("seq %d stale", i), func(t *testing.T) { same(t, states[i+1], pubs[i+1], wire) })
			t.Run(fmt.Sprintf("seq %d gap", i), func(t *testing.T) { same(t, states[i-1], pubs[i-1], w.log[i+1]) })
		}
		t.Run(fmt.Sprintf("seq %d from nil", i), func(t *testing.T) { same(t, nil, nil, wire) })
		t.Run(fmt.Sprintf("seq %d from the zero value", i), func(t *testing.T) { same(t, nil, &PublicState{}, wire) })
	}
	t.Run("equivocation", func(t *testing.T) {
		// Another entry at the head's seq.
		i := len(w.log) - 1
		other := mutate(t, w.log[i], w.normalSigners(), func(e *Entry, _ *Wire) { e.Time++ })
		same(t, states[i], pubs[i], other)
		var eq *EquivocationError
		if _, err := ApplyPublic(pubs[i], other, w.archive); !errors.As(err, &eq) {
			t.Fatalf("ApplyPublic: %v, want an equivocation", err)
		}
	})
	t.Run("genesis over a non-empty state", func(t *testing.T) { same(t, states[1], pubs[1], w.log[0]) })

	// The retirement and checkpoint rules, through both entry points.
	t.Run("retire rules", func(t *testing.T) {
		w := full(t)
		ps := publicStates(t, w)[len(w.log)-1]
		base, err := buildRetireWire(w.st, w.sec, w.devA(), w.now())
		if err != nil {
			t.Fatal(err)
		}
		if _, err := ApplyPublic(ps, base, w.archive); err != nil {
			t.Fatal(err)
		}
		for _, f := range []func(e *Entry, _ *Wire){
			func(e *Entry, _ *Wire) { opsOf[*DeviceRetireOp](e)[0].DeviceID = idDevB },
			func(e *Entry, _ *Wire) {
				e.Ops = append(e.Ops, &DeviceRetireOp{Op: OpDeviceRetire, DeviceID: idDevB})
			},
			func(e *Entry, _ *Wire) { e.Kind = KindCheckpoint },
			func(e *Entry, _ *Wire) { e.Author = idDevC; opsOf[*DeviceRetireOp](e)[0].DeviceID = idDevC },
		} {
			bad := mutate(t, base, map[Role]signer{RoleDevice: devSigner(w.devA())}, f)
			same(t, w.st, ps, bad)
		}
	})
	t.Run("checkpoint omits a retired device", func(t *testing.T) {
		w := full(t)
		w.retire(idDevB)
		ps := publicStates(t, w)[len(w.log)-1]
		p := w.checkpointParams()
		bad := mutate(t, w.unverifiedCheckpoint(p), w.checkpointSigners(p.NewAccount), func(e *Entry, _ *Wire) {
			opsOf[*RetiredOp](e)[0].DeviceIDs = []model.ID{}
		})
		same(t, w.st, ps, bad)
		wantRule(t, func() error { _, err := ApplyPublic(ps, bad, w.archive); return err }(), RuleCheckpointRetired)
	})
}

func sortedHashes(hs []crypto.Hash) []crypto.Hash {
	out := slices.Clone(hs)
	slices.SortFunc(out, func(a, b crypto.Hash) int { return bytes.Compare(a[:], b[:]) })
	return out
}
