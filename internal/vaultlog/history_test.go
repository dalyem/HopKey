package vaultlog

import (
	"testing"

	"github.com/dalyem/hopkey/internal/crypto"
)

func historyOf(e *Entry) *HistoryOp { return opsOf[*HistoryOp](e)[0] }

func isHistory(o Op) bool { return o.Name() == OpHistory }

// The history op (rev 12) in a checkpoint, checked as a transition: exactly
// one, lists contiguous from version 1 through the entry's akv and kv, the
// pre-state history extended by exactly one account row matching
// account_keys and one VK row, and a new VK that matches its row.
func TestHistoryTransitionRules(t *testing.T) {
	w := newWorld(t).withItems()
	p := w.checkpointParams(idDevB)
	base := w.unverifiedCheckpoint(p)
	if h := historyOf(&base.Entry); len(h.Accounts) != 2 || len(h.VKCommits) != 2 {
		t.Fatalf("built history: %+v", h)
	}
	runMutations(t, w.transition, base, w.checkpointSigners(p.NewAccount), []mutation{
		{"history.count: missing history", RuleHistoryCount, func(e *Entry, _ *Wire) { removeOps(e, isHistory) }},
		{"history.count: two history ops", RuleHistoryCount, func(e *Entry, _ *Wire) {
			h := *historyOf(e)
			e.Ops = append(e.Ops, &h)
		}},
		{"history.rows: account rows not contiguous", RuleHistoryRows, func(e *Entry, _ *Wire) { historyOf(e).Accounts[1].AKV = 3 }},
		{"history.rows: VK rows not contiguous", RuleHistoryRows, func(e *Entry, _ *Wire) { historyOf(e).VKCommits[0].KV = 2 }},
		{"history.rows: rows start at version 2", RuleHistoryRows, func(e *Entry, _ *Wire) {
			h := historyOf(e)
			h.Accounts = h.Accounts[1:]
		}},
		{"history.rows: empty VK list", RuleHistoryRows, func(e *Entry, _ *Wire) { historyOf(e).VKCommits = []VKRow{} }},
		{"history.rows: missing new account row", RuleHistoryRows, func(e *Entry, _ *Wire) {
			h := historyOf(e)
			h.Accounts = h.Accounts[:1]
		}},
		{"history.rows: missing new VK row", RuleHistoryRows, func(e *Entry, _ *Wire) {
			h := historyOf(e)
			h.VKCommits = h.VKCommits[:1]
		}},
		{"history.rows: a row beyond the entry's akv", RuleHistoryRows, func(e *Entry, _ *Wire) {
			h := historyOf(e)
			h.Accounts = append(h.Accounts, AccountRow{AKV: 3, FpKEM: crypto.Hash{3}, FpSig: crypto.Hash{3}})
		}},
		{"history.extend: modified earlier account row (fp_sig)", RuleHistoryExtend, func(e *Entry, _ *Wire) {
			historyOf(e).Accounts[0].FpSig[0] ^= 1
		}},
		{"history.extend: modified earlier account row (fp_kem)", RuleHistoryExtend, func(e *Entry, _ *Wire) {
			historyOf(e).Accounts[0].FpKEM[0] ^= 1
		}},
		{"history.extend: modified earlier VK row", RuleHistoryExtend, func(e *Entry, _ *Wire) {
			historyOf(e).VKCommits[0].Commit[0] ^= 1
		}},
		{"history.account: new row fp_kem differs from account_keys", RuleHistoryAccount, func(e *Entry, _ *Wire) {
			historyOf(e).Accounts[1].FpKEM[0] ^= 1
		}},
		{"history.account: new row fp_sig differs from account_keys", RuleHistoryAccount, func(e *Entry, _ *Wire) {
			historyOf(e).Accounts[1].FpSig = historyOf(e).Accounts[0].FpSig
		}},
		// Only the plaintext stage can open the new VK.
		{"history.vk-commit: new VK row does not match the new VK", RuleHistoryVKCommit, func(e *Entry, _ *Wire) {
			historyOf(e).VKCommits[1].Commit[0] ^= 1
		}},
	})
	t.Run("history.vk-commit: pre-state VK does not match its row", func(t *testing.T) {
		sec := *w.sec
		sec.VK[0] ^= 1
		_, _, err := Transition(w.st, &sec, w.devA(), base, w.archive)
		wantRule(t, err, RuleHistoryVKCommit)
	})
	t.Run("history.vk-commit: new VK row mismatch passes the public stage", func(t *testing.T) {
		bad := mutate(t, base, w.checkpointSigners(p.NewAccount), func(e *Entry, _ *Wire) { historyOf(e).VKCommits[1].Commit[0] ^= 1 })
		if _, err := CheckPublic(w.st, bad, w.archive); err != nil {
			t.Fatalf("public stage: %v", err)
		}
	})
	t.Run("op.kind: history in a normal entry", func(t *testing.T) {
		wire := w.unverified(Changes{Put: []crypto.Item{newSnippet(fixedID(0x62))}})
		bad := mutate(t, wire, w.normalSigners(), func(e *Entry, _ *Wire) { e.Ops = append(e.Ops, historyOf(&base.Entry)) })
		wantRule(t, w.transition(bad), RuleOpKind)
	})
	t.Run("op.kind: history in a bootstrap entry", func(t *testing.T) {
		wire, _, _, err := BuildBootstrap(w.st, w.sec, w.infos[idDevC], w.now())
		if err != nil {
			t.Fatal(err)
		}
		bad := mutate(t, wire, map[Role]signer{RoleAccount: acctSigner(w.acct)}, func(e *Entry, _ *Wire) {
			e.Ops = append(e.Ops, historyOf(&base.Entry))
		})
		wantRule(t, w.transition(bad), RuleOpKind)
	})
	t.Run("normal entries keep the history", func(t *testing.T) {
		before := w.st.History
		w.normal(Changes{Put: []crypto.Item{newSnippet(fixedID(0x63))}})
		if !sameJCS(&before, &w.st.History) {
			t.Fatal("a normal entry changed the history")
		}
	})
}

// The history op in genesis: exactly one, rows for akv 1 and kv 1 that
// match account_keys and VK[1].
func TestHistoryGenesisRules(t *testing.T) {
	w := newWorld(t)
	g := w.log[0]
	if h := historyOf(&g.Entry); len(h.Accounts) != 1 || !h.Accounts[0].matches(&w.st.Account) ||
		len(h.VKCommits) != 1 || h.VKCommits[0].Commit != crypto.VKCommit(&w.sec.VK) {
		t.Fatalf("genesis history: %+v", h)
	}
	signers := map[Role]signer{RoleAccount: acctSigner(w.acct)}
	check := func(wr *Wire) error { _, err := CheckPublic(nil, wr, nil); return err }
	runMutations(t, check, g, signers, []mutation{
		{"history.count: missing history", RuleHistoryCount, func(e *Entry, _ *Wire) { removeOps(e, isHistory) }},
		{"history.count: two history ops", RuleHistoryCount, func(e *Entry, _ *Wire) {
			h := *historyOf(e)
			e.Ops = append(e.Ops, &h)
		}},
		{"history.rows: a row for akv 2", RuleHistoryRows, func(e *Entry, _ *Wire) {
			h := historyOf(e)
			h.Accounts = append(h.Accounts, AccountRow{AKV: 2, FpKEM: crypto.Hash{2}, FpSig: crypto.Hash{2}})
		}},
		{"history.rows: no VK row", RuleHistoryRows, func(e *Entry, _ *Wire) { historyOf(e).VKCommits = []VKRow{} }},
		{"history.account: row does not match account_keys", RuleHistoryAccount, func(e *Entry, _ *Wire) {
			historyOf(e).Accounts[0].FpKEM[0] ^= 1
		}},
	})
	t.Run("history.vk-commit: anchor VK does not match its row", func(t *testing.T) {
		bad := mutate(t, g, signers, func(e *Entry, _ *Wire) { historyOf(e).VKCommits[0].Commit[0] ^= 1 })
		mustAccept(t, check(bad)) // only the plaintext stage can tell
		_, _, _, err := Anchor(w.acct.Pin(), w.acct, bad, w.archive, nil)
		wantRule(t, err, RuleHistoryVKCommit)
	})
}

// A fresh client imports the history signed into its anchor, so it holds
// the same state as a client that verified every entry, and it applies the
// freshness rules to keys and VKs from before its anchor.
func TestHistoryAnchorRules(t *testing.T) {
	w := newWorld(t).withItems()
	p := w.checkpointParams()
	cp, st2, _, err := BuildCheckpoint(w.st, w.sec, w.devA(), p)
	if err != nil {
		t.Fatal(err)
	}
	w.record(cp)
	na := p.NewAccount
	anchor := func(wr *Wire) error {
		_, _, _, err := Anchor(na.Pin(), na, wr, w.archive, nil)
		return err
	}
	signers := map[Role]signer{RoleDevice: devSigner(w.devA()), RoleAccountOld: acctSigner(w.acct), RoleAccountNew: acctSigner(na)}
	runMutations(t, anchor, cp, signers, []mutation{
		{"history.count: missing history", RuleHistoryCount, func(e *Entry, _ *Wire) { removeOps(e, isHistory) }},
		{"history.rows: missing earlier rows", RuleHistoryRows, func(e *Entry, _ *Wire) {
			h := historyOf(e)
			h.Accounts = h.Accounts[1:]
			h.Accounts[0].AKV = 1
		}},
		{"anchor.pin: last row does not match the pin (fp_sig)", RuleAnchorPin, func(e *Entry, _ *Wire) {
			historyOf(e).Accounts[1].FpSig[0] ^= 1
		}},
		{"anchor.pin: last row does not match the pin (fp_kem)", RuleAnchorPin, func(e *Entry, _ *Wire) {
			historyOf(e).Accounts[1].FpKEM[0] ^= 1
		}},
		{"history.vk-commit: anchor VK does not match the last row", RuleHistoryVKCommit, func(e *Entry, _ *Wire) {
			historyOf(e).VKCommits[1].Commit[0] ^= 1
		}},
		// A transition into this checkpoint would have refused reused keys
		// or a reused VK, so the anchor refuses them too.
		{"checkpoint.fresh-keys: anchor history reuses an earlier key", RuleCheckpointFreshKeys, func(e *Entry, _ *Wire) {
			h := historyOf(e)
			h.Accounts[0].FpSig = h.Accounts[1].FpSig
		}},
		{"checkpoint.fresh-vk: anchor history reuses an earlier VK", RuleCheckpointFreshVK, func(e *Entry, _ *Wire) {
			h := historyOf(e)
			h.VKCommits[0].Commit = h.VKCommits[1].Commit
		}},
	})

	// The anchored state imports the history and is byte-identical to the
	// transition-verified one.
	fst, _, _, err := Anchor(na.Pin(), na, cp, w.archive, nil)
	if err != nil {
		t.Fatal(err)
	}
	if want := historyOf(&cp.Entry).History(); !sameJCS(&fst.History, &want) || len(want.Accounts) != 2 {
		t.Fatalf("anchored history: %+v", fst.History)
	}
	if !sameJCS(fst, st2) {
		t.Fatal("anchored state differs from the transition-verified state")
	}
}

// The case of the rev 11 review: a client anchored at akv 2 knew no key
// before akv 2, so a checkpoint reusing akv 1's keys, or VK[1], got past
// it. With the history it rejects both. The entries are built by hand,
// past the builder's own checks.
func TestHistoryFreshClientRejectsOldKeys(t *testing.T) {
	w := newWorld(t).withItems()
	var vk1 crypto.SymKey
	copy(vk1[:], fixedBytes("vk1", 32)) // the genesis VK
	p2 := w.checkpointParams()
	cp2, st2, sec2, err := BuildCheckpoint(w.st, w.sec, w.devA(), p2)
	if err != nil {
		t.Fatal(err)
	}
	w.record(cp2)

	// B logs in afresh with the akv 2 keys and anchors at the checkpoint.
	fst, fsec, _, err := Anchor(p2.NewAccount.Pin(), p2.NewAccount, cp2, w.archive, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !sameJCS(fst, st2) {
		t.Fatal("fresh client's state differs from A's")
	}
	fresh := &client{name: "fresh B", dev: w.devs[idDevB], st: fst, sec: fsec}

	var vk3 crypto.SymKey
	copy(vk3[:], fixedBytes("vk3", 32))
	for _, c := range []struct {
		name string
		na   *crypto.AccountKeys
		vk   crypto.SymKey
		rule Rule
	}{
		{"checkpoint.fresh-keys: akv 3 reuses akv 1's keys", mixedAccount(t, 3, "account1", "account1"), vk3, RuleCheckpointFreshKeys},
		{"checkpoint.fresh-keys: akv 3 reuses akv 1's KEM key", mixedAccount(t, 3, "account1", "account3"), vk3, RuleCheckpointFreshKeys},
		{"checkpoint.fresh-keys: akv 3 reuses akv 1's signing key", mixedAccount(t, 3, "account3", "account1"), vk3, RuleCheckpointFreshKeys},
		{"checkpoint.fresh-vk: VK1 → VK2 → VK1", mixedAccount(t, 3, "account3", "account3"), vk1, RuleCheckpointFreshVK},
	} {
		t.Run(c.name, func(t *testing.T) {
			p := CheckpointParams{NewAccount: c.na, NewVK: c.vk, Creds: credsFor(t, c.na, "creds3"), Time: w.now()}
			_, _, _, err := BuildCheckpoint(st2, sec2, w.devA(), p)
			wantRule(t, err, c.rule)
			bad, err := buildCheckpointWire(st2, sec2, w.devA(), p)
			if err != nil {
				t.Fatal(err)
			}
			_, _, err = Transition(fresh.st, fresh.sec, fresh.dev, bad, w.archive)
			wantRule(t, err, c.rule)
			_, _, err = Transition(st2, sec2, w.devA(), bad, w.archive)
			wantRule(t, err, c.rule)
		})
	}
	t.Run("akv 3 with fresh keys and VK", func(t *testing.T) {
		na := mixedAccount(t, 3, "account3", "account3")
		p := CheckpointParams{NewAccount: na, NewVK: vk3, Creds: credsFor(t, na, "creds3"), Time: w.now()}
		wire, st3, sec3, err := BuildCheckpoint(st2, sec2, w.devA(), p)
		if err != nil {
			t.Fatal(err)
		}
		fresh.apply(t, wire, w.archive)
		sameView(t, &client{name: "A", st: st3, sec: sec3}, fresh)
	})
}
