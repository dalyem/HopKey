package vaultlog

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/dalyem/hopkey/internal/canonjson"
	"github.com/dalyem/hopkey/internal/crypto"
	"github.com/dalyem/hopkey/internal/model"
)

type mutation struct {
	name string
	rule Rule
	f    func(e *Entry, w *Wire)
}

// runMutations checks that base is accepted and that each mutation (after
// re-signing with signers) is rejected by exactly its rule.
func runMutations(t *testing.T, check func(*Wire) error, base *Wire, signers map[Role]signer, ms []mutation) {
	t.Helper()
	mustAccept(t, check(base))
	for _, m := range ms {
		t.Run(m.name, func(t *testing.T) {
			wantRule(t, check(mutate(t, base, signers, m.f)), m.rule)
		})
	}
}

func (w *world) deleteC1() *world {
	w.t.Helper()
	h2 := w.host(idH2)
	h2.CredentialID = model.ID{}
	w.normal(Changes{Put: []crypto.Item{h2}, Delete: []model.ID{idC1}})
	return w
}

func (w *world) revokeGrant() *world {
	w.t.Helper()
	w.normal(Changes{Revoke: []model.ID{idGrant}})
	return w
}

func newSnippet(id model.ID) *model.Snippet {
	return &model.Snippet{Header: model.Header{ItemID: id, Type: model.TypeSnippet}, Name: "new", Command: "true", Params: []string{}}
}

// §5.3 header rules, op placement and the within-entry ID rule (§5.2).
func TestHeaderRules(t *testing.T) {
	w := full(t)
	base := w.unverified(Changes{Put: []crypto.Item{w.item(idS1)}})
	runMutations(t, w.transition, base, w.normalSigners(), []mutation{
		{"vault_id differs", RuleVault, func(e *Entry, _ *Wire) { e.VaultID = fixedID(0xee) }},
		{"seq skips", RuleSeq, func(e *Entry, _ *Wire) { e.Seq++ }},
		{"prev is not the head", RulePrev, func(e *Entry, _ *Wire) {
			h, _ := e.Prev.Get()
			h[0] ^= 1
			e.Prev = crypto.SomeHash(h)
		}},
		{"prev empty", RulePrev, func(e *Entry, _ *Wire) { e.Prev = crypto.OptHash{} }},
		{"normal changes kv", RuleVersions, func(e *Entry, _ *Wire) { e.KV++ }},
		{"normal changes akv", RuleVersions, func(e *Entry, _ *Wire) { e.AKV++ }},
		{"device_revoke in normal", RuleOpKind, func(e *Entry, _ *Wire) {
			e.Ops = append(e.Ops, &DeviceRevokeOp{Op: OpDeviceRevoke, DeviceID: idDevB})
		}},
		{"retired in normal", RuleOpKind, func(e *Entry, _ *Wire) {
			e.Ops = append(e.Ops, &RetiredOp{Op: OpRetired, ItemIDs: []model.ID{}, DeviceIDs: []model.ID{}, GrantIDs: []model.ID{}})
		}},
		{"two ops name one item", RuleOpDupID, func(e *Entry, _ *Wire) {
			p := *putFor(t, e, idS1)
			e.Ops = append(e.Ops, &p)
		}},
		{"item_put and item_delete of one item", RuleOpDupID, func(e *Entry, _ *Wire) {
			e.Ops = append(e.Ops, &ItemDeleteOp{Op: OpItemDelete, ItemID: idS1, ItemVersion: 3})
		}},
		{"bundle_put and grant_revoke share a grant", RuleOpDupID, func(e *Entry, _ *Wire) {
			e.Ops = append(e.Ops, &GrantRevokeOp{Op: OpGrantRevoke, GrantID: idGrant})
		}},
		{"extra signature", RuleSigRoles, func(_ *Entry, wr *Wire) {
			wr.Sigs = append(wr.Sigs, Sig{Role: RoleAccount, Sig: make([]byte, 64)})
		}},
		{"no signature", RuleSigRoles, func(_ *Entry, wr *Wire) { wr.Sigs = nil }},
	})
	t.Run("signed by another device", func(t *testing.T) {
		bad := mutate(t, base, map[Role]signer{RoleDevice: devSigner(w.devs[idDevB])}, func(*Entry, *Wire) {})
		wantRule(t, w.transition(bad), RuleSigDevice)
	})
	t.Run("author is not an active device", func(t *testing.T) {
		bad := mutate(t, base, map[Role]signer{RoleDevice: devSigner(w.devs[idDevC])}, func(e *Entry, _ *Wire) { e.Author = idDevC })
		wantRule(t, w.transition(bad), RuleAuthorState)
	})
	t.Run("author is the account", func(t *testing.T) {
		bad := mutate(t, base, w.normalSigners(), func(e *Entry, _ *Wire) { e.Author = idAccount })
		wantRule(t, w.transition(bad), RuleAuthorState)
	})
	t.Run("every certificate uses the resulting akv", func(t *testing.T) {
		enroll := w.unverified(Changes{Devices: []DeviceInfo{w.enrolled(idDevC)}})
		mustAccept(t, w.transition(enroll))
		bad := mutate(t, enroll, w.normalSigners(), func(e *Entry, _ *Wire) {
			opsOf[*DeviceAddOp](e)[0].Cert.AKV = 2
		})
		wantRule(t, w.transition(bad), RuleCertAKV)
	})
}

func TestGenesisRules(t *testing.T) {
	w := newWorld(t)
	g := w.log[0]
	check := func(wr *Wire) error { _, err := CheckPublic(nil, wr, nil); return err }
	runMutations(t, check, g, map[Role]signer{RoleAccount: acctSigner(w.acct)}, []mutation{
		{"seq 1", RuleGenesisHdr, func(e *Entry, _ *Wire) { e.Seq = 1 }},
		{"prev set", RuleGenesisHdr, func(e *Entry, _ *Wire) { e.Prev = crypto.SomeHash(crypto.Hash{1}) }},
		{"akv 2", RuleGenesisHdr, func(e *Entry, _ *Wire) { e.AKV = 2 }},
		{"kv 2", RuleGenesisHdr, func(e *Entry, _ *Wire) { e.KV = 2 }},
		{"creds gen 2", RuleGenesis, func(e *Entry, _ *Wire) { opsOf[*CredsOp](e)[0].Gen = 2 }},
		{"vk_wrap kv 2", RuleGenesis, func(e *Entry, _ *Wire) { opsOf[*VKWrapOp](e)[0].KV = 2 }},
		{"no vk_wrap", RuleGenesis, func(e *Entry, _ *Wire) {
			removeOps(e, func(o Op) bool { return o.Name() == OpVKWrap })
		}},
		{"two device_adds", RuleGenesis, func(e *Entry, _ *Wire) {
			d := *opsOf[*DeviceAddOp](e)[0]
			d.Cert.DeviceID = idDevB
			e.Ops = append(e.Ops, &d)
		}},
		{"item_put in genesis", RuleOpKind, func(e *Entry, _ *Wire) {
			e.Ops = append(e.Ops, &ItemPutOp{Op: OpItemPut, ItemID: idS1, Type: model.TypeSnippet, ItemVersion: 1, IV: 1, KV: 1})
		}},
		{"author is a device", RuleAuthor, func(e *Entry, _ *Wire) { e.Author = idDevA }},
		{"vk_wrap to another recipient", RuleSnapRecipient, func(e *Entry, _ *Wire) { opsOf[*VKWrapOp](e)[0].Recipient = idDevA }},
		// creds.kdf_version MUST be 1 in suite 1 (rev 10 item 15).
		{"creds kdf_version 2", RuleKDFVersion, func(e *Entry, _ *Wire) { opsOf[*CredsOp](e)[0].KDFVersion = 2 }},
		{"creds kdf_version 0", RuleKDFVersion, func(e *Entry, _ *Wire) { opsOf[*CredsOp](e)[0].KDFVersion = 0 }},
	})
	t.Run("signed by another key", func(t *testing.T) {
		other := fixedAccount(t, 1, "other")
		wantRule(t, check(mutate(t, g, map[Role]signer{RoleAccount: acctSigner(other)}, func(*Entry, *Wire) {})), RuleSigAccount)
	})
	t.Run("account_keys not the signer", func(t *testing.T) {
		other := fixedAccount(t, 1, "other")
		bad := mutate(t, g, map[Role]signer{RoleAccount: acctSigner(w.acct)}, func(e *Entry, _ *Wire) {
			*opsOf[*AccountKeysOp](e)[0] = *accountKeysOp(other)
		})
		wantRule(t, check(bad), RuleSigAccount)
	})
	t.Run("genesis after genesis", func(t *testing.T) {
		bad := mutate(t, g, map[Role]signer{RoleAccount: acctSigner(w.acct)}, func(e *Entry, _ *Wire) {
			e.Seq = w.st.Head.Seq + 1
		})
		wantRule(t, w.transition(bad), RuleGenesisHdr)
	})
	t.Run("only genesis without a state", func(t *testing.T) {
		wantRule(t, check(w.log[1]), RuleAnchorKind)
	})
}

func TestBootstrapRules(t *testing.T) {
	w := newWorld(t)
	base, _, _, err := BuildBootstrap(w.st, w.sec, w.infos[idDevC], w.now())
	if err != nil {
		t.Fatal(err)
	}
	signers := map[Role]signer{RoleAccount: acctSigner(w.acct)}
	runMutations(t, w.transition, base, signers, []mutation{
		{"enroll_transcript set", RuleBootstrap, func(e *Entry, _ *Wire) {
			opsOf[*DeviceAddOp](e)[0].Cert.EnrollTranscript = crypto.SomeHash(crypto.Hash{1})
		}},
		{"two device_adds", RuleBootstrap, func(e *Entry, _ *Wire) {
			d := *opsOf[*DeviceAddOp](e)[0]
			d.Cert.DeviceID = fixedID(0xd0)
			e.Ops = append(e.Ops, &d)
		}},
		{"item_put in bootstrap", RuleOpKind, func(e *Entry, _ *Wire) {
			e.Ops = append(e.Ops, &ItemPutOp{Op: OpItemPut, ItemID: idS1, Type: model.TypeSnippet, ItemVersion: 1, IV: 1, KV: 1})
		}},
		{"existing device_id", RuleUniqueID, func(e *Entry, _ *Wire) { opsOf[*DeviceAddOp](e)[0].Cert.DeviceID = idDevB }},
		{"author is a device", RuleAuthor, func(e *Entry, _ *Wire) { e.Author = idDevA }},
		{"certificate akv", RuleCertAKV, func(e *Entry, _ *Wire) { opsOf[*DeviceAddOp](e)[0].Cert.AKV = 2 }},
	})
	t.Run("signed by a device key", func(t *testing.T) {
		bad := mutate(t, base, map[Role]signer{RoleAccount: devSigner(w.devA())}, func(*Entry, *Wire) {})
		wantRule(t, w.transition(bad), RuleSigAccount)
	})
}

func TestCheckpointRules(t *testing.T) {
	w := full(t).deleteC1()
	p := w.checkpointParams(idDevB)
	base := w.unverifiedCheckpoint(p)
	signers := w.checkpointSigners(p.NewAccount)
	runMutations(t, w.transition, base, signers, []mutation{
		// A checkpoint missing a required op (§13).
		{"no retired", RuleCheckpointOps, func(e *Entry, _ *Wire) {
			removeOps(e, func(o Op) bool { return o.Name() == OpRetired })
		}},
		{"no creds", RuleCheckpointOps, func(e *Entry, _ *Wire) {
			removeOps(e, func(o Op) bool { return o.Name() == OpCreds })
		}},
		{"no account_keys", RuleCheckpointOps, func(e *Entry, _ *Wire) {
			removeOps(e, func(o Op) bool { return o.Name() == OpAccountKeys })
		}},
		{"no vk_wrap", RuleCheckpointOps, func(e *Entry, _ *Wire) {
			removeOps(e, func(o Op) bool { return o.Name() == OpVKWrap })
		}},
		// A checkpoint missing a required signature (§13).
		{"no account_old signature", RuleSigRoles, func(_ *Entry, wr *Wire) {
			wr.Sigs = wr.Sigs[:1]
		}},
		{"header akv differs from account_keys", RuleVersions, func(e *Entry, _ *Wire) { e.AKV++ }},
		{"header kv differs from vk_wrap", RuleVersions, func(e *Entry, _ *Wire) { e.KV++ }},
		{"creds gen skips", RuleCheckpointGen, func(e *Entry, _ *Wire) { opsOf[*CredsOp](e)[0].Gen++ }},
		{"vk_wrap kv skips", RuleCheckpointKV, func(e *Entry, _ *Wire) {
			opsOf[*VKWrapOp](e)[0].KV++
			e.KV++
		}},
		// A checkpoint where a survivor changes its public keys (§13).
		{"survivor changes sig key", RuleSurvivorKeys, func(e *Entry, _ *Wire) {
			opsOf[*DeviceAddOp](e)[0].SigPK = w.infos[idDevC].SigPK
		}},
		{"survivor changes KEM key", RuleSurvivorKeys, func(e *Entry, _ *Wire) {
			opsOf[*DeviceAddOp](e)[0].KEMPK = w.infos[idDevC].KEMPK
		}},
		{"device neither kept nor revoked", RuleDeviceCover, func(e *Entry, _ *Wire) {
			removeOps(e, func(o Op) bool { return o.Name() == OpDeviceRevoke })
			r := opsOf[*RetiredOp](e)[0]
			r.DeviceIDs = []model.ID{}
		}},
		{"author revoked", RuleDeviceCover, func(e *Entry, _ *Wire) {
			removeOps(e, func(o Op) bool { return o.Name() == OpDeviceAdd })
			e.Ops = append(e.Ops, &DeviceRevokeOp{Op: OpDeviceRevoke, DeviceID: idDevA})
			r := opsOf[*RetiredOp](e)[0]
			r.DeviceIDs = []model.ID{idDevA, idDevB}
		}},
		{"revoke an inactive device", RuleDeviceCover, func(e *Entry, _ *Wire) {
			e.Ops = append(e.Ops, &DeviceRevokeOp{Op: OpDeviceRevoke, DeviceID: idDevC})
			r := opsOf[*RetiredOp](e)[0]
			r.DeviceIDs = []model.ID{idDevB, idDevC}
		}},
		{"item not re-put", RuleCheckpointItems, func(e *Entry, _ *Wire) {
			removeOps(e, func(o Op) bool { p, ok := o.(*ItemPutOp); return ok && p.ItemID == idS1 })
		}},
		{"new item in checkpoint", RuleCheckpointItems, func(e *Entry, _ *Wire) {
			p := *putFor(t, e, idS1)
			p.ItemID = fixedID(0x66)
			e.Ops = append(e.Ops, &p)
		}},
		{"item iv unchanged", RuleItemIV, func(e *Entry, _ *Wire) { putFor(t, e, idS1).IV-- }},
		{"item version skips", RuleItemVersion, func(e *Entry, _ *Wire) { putFor(t, e, idS1).ItemVersion++ }},
		{"item keeps the old kv", RuleSnapKV, func(e *Entry, _ *Wire) { putFor(t, e, idS1).KV-- }},
		{"active grant not revoked", RuleCheckpointGrants, func(e *Entry, _ *Wire) {
			removeOps(e, func(o Op) bool { return o.Name() == OpGrantRevoke })
			opsOf[*RetiredOp](e)[0].GrantIDs = []model.ID{}
		}},
		{"bundle_put in checkpoint", RuleOpKind, func(e *Entry, _ *Wire) {
			e.Ops = append(e.Ops, &BundlePutOp{Op: OpBundlePut, GrantID: fixedID(0x82), BundleVersion: 1})
		}},
		{"grant_add in checkpoint", RuleOpKind, func(e *Entry, _ *Wire) {
			e.Ops = append(e.Ops, &GrantAddOp{Op: OpGrantAdd, GrantID: fixedID(0x82), RecordItemID: idS1, TokenKEMPK: w.st.Account.KEMPK})
		}},
		{"item_delete in checkpoint", RuleOpKind, func(e *Entry, _ *Wire) {
			e.Ops = append(e.Ops, &ItemDeleteOp{Op: OpItemDelete, ItemID: fixedID(0x67), ItemVersion: 1})
		}},
		// A checkpoint dropping a deploy op (§13), incomplete or closed.
		{"drops incomplete deploy_op", RuleCheckpointDeploy, func(e *Entry, _ *Wire) {
			removeOps(e, func(o Op) bool { d, ok := o.(*DeployOp); return ok && d.OpID == idOpD1 })
		}},
		{"drops closed deploy_op", RuleCheckpointDeploy, func(e *Entry, _ *Wire) {
			removeOps(e, func(o Op) bool { d, ok := o.(*DeployOp); return ok && d.OpID == idOpD2 })
		}},
		{"changes a deploy_op", RuleCheckpointDeploy, func(e *Entry, _ *Wire) {
			for _, d := range opsOf[*DeployOp](e) {
				if d.OpID == idOpD1 {
					d.Targets[0].State = TargetFailed
				}
			}
		}},
		{"new deploy_op", RuleCheckpointDeploy, func(e *Entry, _ *Wire) {
			e.Ops = append(e.Ops, &DeployOp{Op: OpDeploy, OpID: fixedID(0x93), Action: ActionDeploy, SSHPKFp: w.fpK1,
				KeyItemID: idK1, KeyItemVersion: 1, Targets: []Target{{HostItemID: idH1, State: TargetPending}}})
		}},
		// A checkpoint missing a retired ID (§13).
		{"retired misses a deleted item", RuleCheckpointRetired, func(e *Entry, _ *Wire) {
			opsOf[*RetiredOp](e)[0].ItemIDs = []model.ID{}
		}},
		{"retired misses the revoked device", RuleCheckpointRetired, func(e *Entry, _ *Wire) {
			opsOf[*RetiredOp](e)[0].DeviceIDs = []model.ID{}
		}},
		{"retired misses the revoked grant", RuleCheckpointRetired, func(e *Entry, _ *Wire) {
			opsOf[*RetiredOp](e)[0].GrantIDs = []model.ID{}
		}},
		{"retired lists a live item", RuleOpDupID, func(e *Entry, _ *Wire) {
			opsOf[*RetiredOp](e)[0].ItemIDs = []model.ID{idK1, idC1}
		}},
		{"vk_wrap to another recipient", RuleSnapRecipient, func(e *Entry, _ *Wire) { opsOf[*VKWrapOp](e)[0].Recipient = idDevA }},
		{"creds kdf_version 2", RuleKDFVersion, func(e *Entry, _ *Wire) { opsOf[*CredsOp](e)[0].KDFVersion = 2 }},
		// A survivor's certificate keeps name and enroll_transcript, and
		// issued_at is the entry's time (rev 10 item 13).
		{"survivor certificate renamed", RuleSurvivorCert, func(e *Entry, _ *Wire) {
			d := deviceAddFor(t, e, idDevA)
			d.Cert.Name = "renamed"
			resignCert(t, d, p.NewAccount)
		}},
		{"survivor certificate gains an enroll_transcript", RuleSurvivorCert, func(e *Entry, _ *Wire) {
			d := deviceAddFor(t, e, idDevA)
			d.Cert.EnrollTranscript = crypto.SomeHash(crypto.Hash{1})
			resignCert(t, d, p.NewAccount)
		}},
		{"survivor certificate issued earlier", RuleSurvivorCert, func(e *Entry, _ *Wire) {
			d := deviceAddFor(t, e, idDevA)
			d.Cert.IssuedAt--
			resignCert(t, d, p.NewAccount)
		}},
		{"entry time differs from issued_at", RuleSurvivorCert, func(e *Entry, _ *Wire) { e.Time++ }},
	})
	t.Run("account_old signed by the new key", func(t *testing.T) {
		bad := mutate(t, base, map[Role]signer{RoleAccountOld: acctSigner(p.NewAccount)}, func(*Entry, *Wire) {})
		wantRule(t, w.transition(bad), RuleSigAcctOld)
	})
	t.Run("account_new signed by the old key", func(t *testing.T) {
		bad := mutate(t, base, map[Role]signer{RoleAccountNew: acctSigner(w.acct)}, func(*Entry, *Wire) {})
		wantRule(t, w.transition(bad), RuleSigAcctNew)
	})
	t.Run("device signature by another device", func(t *testing.T) {
		bad := mutate(t, base, map[Role]signer{RoleDevice: devSigner(w.devs[idDevB])}, func(*Entry, *Wire) {})
		wantRule(t, w.transition(bad), RuleSigDevice)
	})
	t.Run("account_keys akv skips", func(t *testing.T) {
		q := w.checkpointParams(idDevB)
		q.NewAccount = fixedAccount(t, 3, "account3")
		q.Creds = credsFor(t, q.NewAccount, "creds3")
		bad := w.unverifiedCheckpoint(q)
		wantRule(t, w.transition(bad), RuleCheckpointAKV)
	})
	t.Run("checkpoint adds a new device", func(t *testing.T) {
		bad := cloneWire(t, base)
		b := &builder{w: *bad, seen: map[crypto.Hash]bool{}}
		if err := b.deviceAdd(p.NewAccount, w.infos[idDevC], p.Time); err != nil {
			t.Fatal(err)
		}
		*bad = b.w
		resign(t, bad, signers)
		wantRule(t, w.transition(bad), RuleDeviceCover)
	})
	t.Run("unlock blob holds other account keys", func(t *testing.T) {
		bad := cloneWire(t, base)
		other := fixedAccount(t, 2, "impostor")
		var mine *DeviceAddOp
		for _, d := range opsOf[*DeviceAddOp](&bad.Entry) {
			if d.Cert.DeviceID == idDevA {
				mine = d
			}
		}
		env, err := crypto.SealUnlock(mine.KEMPK, &mine.Cert, other)
		if err != nil {
			t.Fatal(err)
		}
		mine.UnlockSHA256 = addObject(t, bad, env)
		resign(t, bad, signers)
		wantRule(t, w.transition(bad), RuleCheckpointUnlock)
	})
	t.Run("items keep their old IK", func(t *testing.T) {
		q := w.checkpointParams(idDevB)
		q.reuseIK = true
		wantRule(t, w.transition(w.unverifiedCheckpoint(q)), RuleItemIK)
	})
	t.Run("revoked here", func(t *testing.T) {
		_, _, err := Transition(w.st, w.sec, w.devs[idDevB], base, w.archive)
		var re *RevokedError
		if !errors.As(err, &re) || re.DeviceID != idDevB {
			t.Fatalf("got %v, want a RevokedError for B", err)
		}
	})
}

// mixedAccount returns account keys for akv whose KEM key comes from
// kemLabel and whose signing key comes from sigLabel (labels as in
// fixedAccount).
func mixedAccount(t testing.TB, akv uint32, kemLabel, sigLabel string) *crypto.AccountKeys {
	t.Helper()
	kem, err := crypto.DeriveKEMKey(fixedBytes(kemLabel+"-kem", 32))
	if err != nil {
		t.Fatal(err)
	}
	k, err := crypto.NewAccountKeys(idAccount, akv, kem, fixedBytes(sigLabel+"-sig", 32))
	if err != nil {
		t.Fatal(err)
	}
	return k
}

// A checkpoint's account_keys.kem_pk and sig_pk MUST both differ from every
// earlier account key, and the new VK MUST differ from the pre-state VK
// (rev 11). The builder refuses each before building; a hand-built entry
// is refused by Transition.
func TestCheckpointFreshKeys(t *testing.T) {
	w := newWorld(t).withItems()
	var vk1 crypto.SymKey
	copy(vk1[:], fixedBytes("vk1", 32)) // the genesis VK
	if !sameKey(&vk1, &w.sec.VK) {
		t.Fatal("fixture VK changed")
	}
	cases := []struct {
		name string
		rule Rule
		f    func(p *CheckpointParams)
	}{
		{"reused KEM key", RuleCheckpointFreshKeys, func(p *CheckpointParams) {
			p.NewAccount = mixedAccount(t, 2, "account1", "account2")
		}},
		{"reused signing key", RuleCheckpointFreshKeys, func(p *CheckpointParams) {
			p.NewAccount = mixedAccount(t, 2, "account2", "account1")
		}},
		{"both keys reused", RuleCheckpointFreshKeys, func(p *CheckpointParams) {
			p.NewAccount = mixedAccount(t, 2, "account1", "account1")
		}},
		{"reused VK", RuleCheckpointFreshVK, func(p *CheckpointParams) { p.NewVK = vk1 }},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			p := w.checkpointParams(idDevB)
			c.f(&p)
			p.Creds = credsFor(t, p.NewAccount, "creds2")
			_, _, _, err := BuildCheckpoint(w.st, w.sec, w.devA(), p)
			wantRule(t, err, c.rule)
			wantRule(t, w.transition(w.unverifiedCheckpoint(p)), c.rule)
		})
	}
	t.Run("reused VK passes the public stage", func(t *testing.T) {
		// Only the plaintext stage can see the VK.
		p := w.checkpointParams(idDevB)
		p.NewVK = vk1
		if _, err := CheckPublic(w.st, w.unverifiedCheckpoint(p), w.archive); err != nil {
			t.Fatalf("public stage: %v", err)
		}
	})

	// The history reaches back past the pre-state key: after akv 1 → 2,
	// akv 3 may not reuse akv 1's keys either.
	p2 := w.checkpointParams()
	wire, st2, sec2, err := BuildCheckpoint(w.st, w.sec, w.devA(), p2)
	if err != nil {
		t.Fatal(err)
	}
	w.record(wire)
	if len(st2.PastAccounts) != 1 || st2.PastAccounts[0].AKV != 1 || !st2.PastAccounts[0].FpSig.Equal(w.st.Account.FpSig) ||
		!st2.PastAccounts[0].FpKEM.Equal(w.st.Account.FpKEM) {
		t.Fatalf("past accounts after the checkpoint: %+v", st2.PastAccounts)
	}
	var vk3 crypto.SymKey
	copy(vk3[:], fixedBytes("vk3", 32))
	for _, c := range []struct {
		name string
		na   *crypto.AccountKeys
		vk   crypto.SymKey
		rule Rule
	}{
		{"akv 3 reuses the akv 1 KEM key", mixedAccount(t, 3, "account1", "account3"), vk3, RuleCheckpointFreshKeys},
		{"akv 3 reuses the akv 1 signing key", mixedAccount(t, 3, "account3", "account1"), vk3, RuleCheckpointFreshKeys},
		{"akv 3 reuses the akv 2 signing key", mixedAccount(t, 3, "account3", "account2"), vk3, RuleCheckpointFreshKeys},
		{"akv 3 keeps VK[2]", mixedAccount(t, 3, "account3", "account3"), p2.NewVK, RuleCheckpointFreshVK},
	} {
		t.Run(c.name, func(t *testing.T) {
			p := CheckpointParams{NewAccount: c.na, NewVK: c.vk, Creds: credsFor(t, c.na, "creds3"), Time: w.now()}
			_, _, _, err := BuildCheckpoint(st2, sec2, w.devA(), p)
			wantRule(t, err, c.rule)
			bad, err := buildCheckpointWire(st2, sec2, w.devA(), p)
			if err != nil {
				t.Fatal(err)
			}
			_, _, err = Transition(st2, sec2, w.devA(), bad, w.archive)
			wantRule(t, err, c.rule)
		})
	}
	t.Run("akv 3 with fresh keys and VK", func(t *testing.T) {
		na := mixedAccount(t, 3, "account3", "account3")
		p := CheckpointParams{NewAccount: na, NewVK: vk3, Creds: credsFor(t, na, "creds3"), Time: w.now()}
		_, st3, _, err := BuildCheckpoint(st2, sec2, w.devA(), p)
		mustAccept(t, err)
		if len(st3.PastAccounts) != 2 || st3.PastAccounts[1].AKV != 2 {
			t.Fatalf("past accounts: %+v", st3.PastAccounts)
		}
	})
}

func TestItemRules(t *testing.T) {
	w := full(t).deleteC1()
	base := w.unverified(Changes{Put: []crypto.Item{w.item(idH2), newSnippet(fixedID(0x68))}})
	newID := fixedID(0x68)
	runMutations(t, w.transition, base, w.normalSigners(), []mutation{
		// item_put on a tombstone (§13) and re-adding a live ID.
		{"item_put on a tombstone", RuleUniqueID, func(e *Entry, _ *Wire) { putFor(t, e, newID).ItemID = idC1 }},
		{"new item reuses a device ID", RuleUniqueID, func(e *Entry, _ *Wire) { putFor(t, e, newID).ItemID = idDevB }},
		{"new item reuses a grant ID", RuleUniqueID, func(e *Entry, _ *Wire) { putFor(t, e, newID).ItemID = idGrant }},
		{"new item reuses an op_id", RuleUniqueID, func(e *Entry, _ *Wire) { putFor(t, e, newID).ItemID = idOpD1 }},
		{"new item version 2", RuleItemVersion, func(e *Entry, _ *Wire) { putFor(t, e, newID).ItemVersion = 2 }},
		{"new item iv 2", RuleItemIV, func(e *Entry, _ *Wire) { putFor(t, e, newID).IV = 2 }},
		{"edit skips a version", RuleItemVersion, func(e *Entry, _ *Wire) { putFor(t, e, idH2).ItemVersion++ }},
		{"edit repeats a version", RuleItemVersion, func(e *Entry, _ *Wire) { putFor(t, e, idH2).ItemVersion-- }},
		{"edit changes type", RuleItemType, func(e *Entry, _ *Wire) { putFor(t, e, idH2).Type = model.TypeKey }},
		{"edit changes iv", RuleItemIV, func(e *Entry, _ *Wire) { putFor(t, e, idH2).IV++ }},
		{"edit uses another kv", RuleSnapKV, func(e *Entry, _ *Wire) { putFor(t, e, idH2).KV++ }},
		{"delete a tombstone", RuleItemLive, func(e *Entry, _ *Wire) {
			e.Ops = append(e.Ops, &ItemDeleteOp{Op: OpItemDelete, ItemID: idC1, ItemVersion: 3})
		}},
		{"delete an unknown item", RuleItemLive, func(e *Entry, _ *Wire) {
			e.Ops = append(e.Ops, &ItemDeleteOp{Op: OpItemDelete, ItemID: fixedID(0x69), ItemVersion: 1})
		}},
		{"delete with a wrong version", RuleItemVersion, func(e *Entry, _ *Wire) {
			e.Ops = append(e.Ops, &ItemDeleteOp{Op: OpItemDelete, ItemID: idK2, ItemVersion: 1})
		}},
		{"delete the record of an active grant", RuleGrantRecordDelete, func(e *Entry, _ *Wire) {
			e.Ops = append(e.Ops, &ItemDeleteOp{Op: OpItemDelete, ItemID: idRecord, ItemVersion: 2})
		}},
		{"object missing", RuleObjectMissing, func(_ *Entry, wr *Wire) { wr.Objects = wr.Objects[:len(wr.Objects)-1] }},
		{"object body tampered", RuleObjectDigest, func(_ *Entry, wr *Wire) {
			o := &wr.Objects[0]
			o.Body = bytes.Replace(o.Body, []byte(`"v":1`), []byte(`"v":2`), 1)
		}},
		// Wire objects are envelopes only (rev 10 item 17).
		{"certificate as a wire object", RuleObjectEnvelope, func(_ *Entry, wr *Wire) {
			body, err := canonjson.Marshal(w.st.Devices[idDevA].Cert)
			if err != nil {
				t.Fatal(err)
			}
			wr.Objects = append(wr.Objects, Object{SHA256: crypto.SHA256(body), Body: body})
		}},
		{"envelope with an extra member", RuleObjectEnvelope, func(_ *Entry, wr *Wire) {
			body := bytes.Replace(wr.Objects[0].Body, []byte(`"v":1`), []byte(`"v":1,"x":1`), 1)
			wr.Objects = append(wr.Objects, Object{SHA256: crypto.SHA256(body), Body: body})
		}},
	})
	t.Run("edit changes the IK", func(t *testing.T) {
		bad := cloneWire(t, base)
		ik, _ := crypto.NewSymKey()
		reseal(t, bad, w.st, w.sec.VK, ik, w.item(idH2), nil)
		resign(t, bad, w.normalSigners())
		wantRule(t, w.transition(bad), RuleItemIK)
	})
	t.Run("body sealed under another IK", func(t *testing.T) {
		bad := cloneWire(t, base)
		p := putFor(t, &bad.Entry, idH2)
		ik, _ := crypto.NewSymKey()
		ctx := itemContext(w.st, p)
		it, _, _ := withHeader(w.item(idH2), p.ItemVersion)
		body, err := crypto.SealItem(&ik, ctx, it)
		if err != nil {
			t.Fatal(err)
		}
		p.BodySHA256 = addObject(t, bad, body)
		resign(t, bad, w.normalSigners())
		wantRule(t, w.transition(bad), RuleDecrypt)
	})
	t.Run("fetcher returns another object", func(t *testing.T) {
		bad := cloneWire(t, base)
		p := putFor(t, &bad.Entry, idH2)
		var kept []Object
		var body []byte
		for _, o := range bad.Objects {
			if o.SHA256 == p.BodySHA256 {
				continue
			}
			kept = append(kept, o)
			body = o.Body
		}
		bad.Objects = kept
		_, _, err := Transition(w.st, w.sec, w.devA(), bad, ObjectMap{p.BodySHA256: body})
		wantRule(t, err, RuleObjectDigest)
	})
	// An object digest found only in history (§13): H2's version-1 body is
	// still on the server, but only the current state's digests are usable.
	t.Run("digest found only in history", func(t *testing.T) {
		var oldBody crypto.Hash
		for _, p := range opsOf[*ItemPutOp](&w.log[2].Entry) {
			if p.ItemID == idH2 {
				oldBody = p.BodySHA256
			}
		}
		if _, ok := w.archive[oldBody]; !ok || w.st.Usable(oldBody) {
			t.Fatal("fixture: the old body should be archived and not usable")
		}
		if !w.st.Usable(w.st.Items[idH2].BodySHA256) {
			t.Fatal("the current body should be usable")
		}
		bad := mutate(t, base, w.normalSigners(), func(e *Entry, _ *Wire) { putFor(t, e, idH2).BodySHA256 = oldBody })
		wantRule(t, w.transition(bad), RuleDecrypt)
	})
}

func TestGrantRules(t *testing.T) {
	w := full(t)
	g2 := fixedID(0x82)
	rec2 := fixedID(0x72)
	newGrant := func() NewGrant {
		r := w.grantRecord()
		r.ItemID, r.GrantID = rec2, g2
		return NewGrant{Record: r, TAuthSHA256: crypto.SHA256([]byte("tauth2"))}
	}
	add := w.unverified(Changes{Grants: []NewGrant{newGrant()}})
	runMutations(t, w.transition, add, w.normalSigners(), []mutation{
		{"grant_add without bundle_put", RuleGrantAdd, func(e *Entry, _ *Wire) {
			removeOps(e, func(o Op) bool { return o.Name() == OpBundlePut })
		}},
		{"grant_add without its record", RuleGrantAdd, func(e *Entry, _ *Wire) {
			removeOps(e, func(o Op) bool { return o.Name() == OpItemPut })
		}},
		{"record without grant_add", RuleGrantNewRecord, func(e *Entry, _ *Wire) {
			removeOps(e, func(o Op) bool { return o.Name() == OpGrantAdd })
		}},
		{"first bundle version 2", RuleBundleVersion, func(e *Entry, _ *Wire) { opsOf[*BundlePutOp](e)[0].BundleVersion = 2 }},
		{"grant_add reuses a grant ID", RuleUniqueID, func(e *Entry, _ *Wire) {
			opsOf[*GrantAddOp](e)[0].GrantID = idGrant
			opsOf[*BundlePutOp](e)[0].GrantID = idGrant
		}},
		{"record differs from grant_add", RuleGrantRecordMeta, func(e *Entry, _ *Wire) {
			opsOf[*GrantAddOp](e)[0].ExpiresAt++
		}},
		{"record token key differs from grant_add", RuleGrantRecordMeta, func(e *Entry, _ *Wire) {
			opsOf[*GrantAddOp](e)[0].TokenKEMPK = w.st.Account.KEMPK
		}},
	})

	edit := w.unverified(Changes{Put: []crypto.Item{w.item(idS1)}})
	runMutations(t, w.transition, edit, w.normalSigners(), []mutation{
		// A normal entry editing a granted item without a bundle_put (§13).
		{"granted item edited without bundle_put", RuleBundleRequired, func(e *Entry, _ *Wire) {
			removeOps(e, func(o Op) bool { return o.Name() == OpBundlePut })
		}},
		{"bundle version skips", RuleBundleVersion, func(e *Entry, _ *Wire) { opsOf[*BundlePutOp](e)[0].BundleVersion++ }},
		{"revoke an unknown grant", RuleGrantActive, func(e *Entry, _ *Wire) {
			e.Ops = append(e.Ops, &GrantRevokeOp{Op: OpGrantRevoke, GrantID: g2})
		}},
	})
	t.Run("record edited without bundle_put", func(t *testing.T) {
		r := w.item(idRecord).(*model.Grant)
		r.Name = "renamed"
		bad := mutate(t, w.unverified(Changes{Put: []crypto.Item{r}}), w.normalSigners(), func(e *Entry, _ *Wire) {
			removeOps(e, func(o Op) bool { return o.Name() == OpBundlePut })
		})
		wantRule(t, w.transition(bad), RuleBundleRequired)
	})
	t.Run("granted item deleted without bundle_put", func(t *testing.T) {
		bad := mutate(t, w.unverified(Changes{Delete: []model.ID{idS1}}), w.normalSigners(), func(e *Entry, _ *Wire) {
			removeOps(e, func(o Op) bool { return o.Name() == OpBundlePut })
		})
		wantRule(t, w.transition(bad), RuleBundleRequired)
	})
	t.Run("record changes expires_at", func(t *testing.T) {
		r := w.item(idRecord).(*model.Grant)
		r.ExpiresAt++
		wantRule(t, w.transition(w.unverified(Changes{Put: []crypto.Item{r}})), RuleGrantRecordMeta)
	})
	t.Run("record breaks §8.7 binding", func(t *testing.T) {
		r := w.item(idRecord).(*model.Grant)
		r.Name = "renamed"
		bad := w.unverified(Changes{Put: []crypto.Item{r}})
		// Replace the record with one listing H2, whose key K2 the grant
		// does not list; the bundle_put stays.
		r2 := w.item(idRecord).(*model.Grant)
		r2.Items = []model.ID{idK1, idH1, idH2, idS1}
		reseal(t, bad, w.st, w.sec.VK, w.sec.Items[idRecord].IK, r2, nil)
		resign(t, bad, w.normalSigners())
		wantRule(t, w.transition(bad), RuleGrantRecordBinding)
	})

	// After the grant is revoked.
	w.revokeGrant()
	t.Run("bundle_put after grant_revoke", func(t *testing.T) {
		bad := mutate(t, w.unverified(Changes{Put: []crypto.Item{w.item(idS1)}}), w.normalSigners(), func(e *Entry, _ *Wire) {
			e.Ops = append(e.Ops, &BundlePutOp{Op: OpBundlePut, GrantID: idGrant, BundleVersion: 3, EnvelopeSHA256: w.st.VKWrap.EnvelopeSHA256})
		})
		wantRule(t, w.transition(bad), RuleGrantActive)
	})
	t.Run("revoke twice", func(t *testing.T) {
		bad := mutate(t, w.unverified(Changes{Put: []crypto.Item{w.item(idS1)}}), w.normalSigners(), func(e *Entry, _ *Wire) {
			e.Ops = append(e.Ops, &GrantRevokeOp{Op: OpGrantRevoke, GrantID: idGrant})
		})
		wantRule(t, w.transition(bad), RuleGrantActive)
	})
	t.Run("re-adding a revoked grant ID", func(t *testing.T) {
		ng := newGrant()
		ng.Record.GrantID = idGrant
		wantRule(t, w.transition(w.unverified(Changes{Grants: []NewGrant{ng}})), RuleUniqueID)
	})
	t.Run("revoked grant's items edit without bundle", func(t *testing.T) {
		wire := w.unverified(Changes{Put: []crypto.Item{w.item(idS1)}})
		if len(opsOf[*BundlePutOp](&wire.Entry)) != 0 {
			t.Fatal("a revoked grant needs no bundle_put")
		}
		mustAccept(t, w.transition(wire))
	})
	t.Run("revoked record keeps reference integrity", func(t *testing.T) {
		// The record is put explicitly, so the builder leaves it listing S1.
		bad := w.unverified(Changes{Put: []crypto.Item{w.item(idRecord)}, Delete: []model.ID{idS1}})
		wantRule(t, w.transition(bad), RuleRefIntegrity)
	})
	t.Run("record of a revoked grant can be deleted", func(t *testing.T) {
		mustAccept(t, w.transition(w.unverified(Changes{Delete: []model.ID{idRecord}})))
	})
}

func TestDeployRules(t *testing.T) {
	w := full(t)
	d1 := w.st.DeployOps[idOpD1]
	d2 := w.st.DeployOps[idOpD2]
	update := func(f func(d *DeployOp), base DeployOp) Changes {
		d := base
		d.Targets = append([]Target(nil), base.Targets...)
		f(&d)
		return Changes{Deploy: []DeployOp{d}}
	}
	cases := []struct {
		name string
		rule Rule
		ch   Changes
	}{
		{"ssh_pk_fp changes", RuleDeployImmutable, update(func(d *DeployOp) { d.SSHPKFp = w.fpK2 }, d1)},
		{"key_item_version changes", RuleDeployImmutable, update(func(d *DeployOp) { d.KeyItemVersion = 2 }, d1)},
		{"action changes", RuleDeployImmutable, update(func(d *DeployOp) { d.Action = ActionRemove }, d1)},
		{"target added", RuleDeployImmutable, update(func(d *DeployOp) {
			d.Targets = append(d.Targets, Target{HostItemID: idH2, State: TargetPending})
		}, d1)},
		{"target replaced", RuleDeployImmutable, update(func(d *DeployOp) { d.Targets[0].HostItemID = idH2 }, d1)},
		{"done reverts", RuleDeployState, update(func(d *DeployOp) { d.Targets[0].State = TargetPending }, d2)},
		{"new op names a snippet as its key", RuleDeployRefs, Changes{Deploy: []DeployOp{{OpID: fixedID(0x94), Action: ActionDeploy,
			SSHPKFp: w.fpK1, KeyItemID: idS1, KeyItemVersion: 1, Targets: []Target{{HostItemID: idH1, State: TargetPending}}}}}},
		{"new op targets a key", RuleDeployRefs, Changes{Deploy: []DeployOp{{OpID: fixedID(0x94), Action: ActionDeploy,
			SSHPKFp: w.fpK1, KeyItemID: idK1, KeyItemVersion: 1, Targets: []Target{{HostItemID: idK2, State: TargetPending}}}}}},
		{"new op with the wrong fingerprint", RuleDeployFingerprint, Changes{Deploy: []DeployOp{{OpID: fixedID(0x94), Action: ActionDeploy,
			SSHPKFp: w.fpK2, KeyItemID: idK1, KeyItemVersion: 1, Targets: []Target{{HostItemID: idH1, State: TargetPending}}}}}},
		{"new op reuses an item ID", RuleUniqueID, Changes{Deploy: []DeployOp{{OpID: idS1, Action: ActionDeploy,
			SSHPKFp: w.fpK1, KeyItemID: idK1, KeyItemVersion: 1, Targets: []Target{{HostItemID: idH1, State: TargetPending}}}}}},
		{"delete a host an incomplete op targets", RuleDeployRefs, Changes{Delete: []model.ID{idH1}}},
		// A deploy_op MUST have at least one target (rev 10 item 9).
		{"new op without targets", RuleDeployTargets, Changes{Deploy: []DeployOp{{OpID: fixedID(0x94), Action: ActionDeploy,
			SSHPKFp: w.fpK1, KeyItemID: idK1, KeyItemVersion: 1, Targets: []Target{}}}}},
		{"update drops every target", RuleDeployTargets, update(func(d *DeployOp) { d.Targets = []Target{} }, d2)},
		// A new op's key_item_version is the key's current version (rev 10
		// item 10).
		{"new op names a future key version", RuleDeployKeyVersion, Changes{Deploy: []DeployOp{{OpID: fixedID(0x94), Action: ActionDeploy,
			SSHPKFp: w.fpK1, KeyItemID: idK1, KeyItemVersion: 2, Targets: []Target{{HostItemID: idH1, State: TargetPending}}}}}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) { wantRule(t, w.transition(w.unverified(c.ch)), c.rule) })
	}
	t.Run("key material changes while incomplete", func(t *testing.T) {
		k := w.item(idK1).(*model.Key)
		k.PrivateKey += " changed"
		wantRule(t, w.transition(w.unverified(Changes{Put: []crypto.Item{k}})), RuleDeployMaterial)
		k = w.item(idK1).(*model.Key)
		k.PublicKey, _ = sshKey(t, "k3")
		wantRule(t, w.transition(w.unverified(Changes{Put: []crypto.Item{k}})), RuleDeployMaterial)
		// key_type is SSH material too (rev 10 item 8).
		k = w.item(idK1).(*model.Key)
		k.KeyType = "rsa"
		wantRule(t, w.transition(w.unverified(Changes{Put: []crypto.Item{k}})), RuleDeployMaterial)
	})
	t.Run("key_type changes once the op is closed", func(t *testing.T) {
		// Rev 11: SSH material is frozen whether or not an op is pending.
		k := w.item(idK2).(*model.Key)
		k.KeyType = "rsa"
		wantRule(t, w.transition(w.unverified(Changes{Put: []crypto.Item{k}})), RuleKeyMaterial)
	})
	t.Run("key rename while incomplete is fine", func(t *testing.T) {
		k := w.item(idK1).(*model.Key)
		k.Name = "renamed"
		mustAccept(t, w.transition(w.unverified(Changes{Put: []crypto.Item{k}})))
	})
	t.Run("closed ops may reference deleted items", func(t *testing.T) {
		h2 := w.host(idH2)
		h2.KeyID = model.ID{}
		mustAccept(t, w.transition(w.unverified(Changes{Put: []crypto.Item{h2}, Delete: []model.ID{idK2}})))
	})
	// Abandoning releases the deletion restriction; abandoned is terminal.
	w.normal(update(func(d *DeployOp) { d.Targets[0].State = TargetAbandoned }, d1))
	t.Run("abandoned reverts", func(t *testing.T) {
		wantRule(t, w.transition(w.unverified(update(func(d *DeployOp) { d.Targets[0].State = TargetDone }, d1))), RuleDeployState)
	})
	t.Run("host of an abandoned op can be deleted", func(t *testing.T) {
		mustAccept(t, w.transition(w.unverified(Changes{Delete: []model.ID{idH1}})))
	})
}

// An item_put on an existing key item keeps key_type, private_key and
// public_key whether or not a deploy_op is pending; replacing an SSH key
// always creates a new item ID (rev 11). Metadata edits and rewraps stay
// allowed.
func TestKeyMaterialFrozen(t *testing.T) {
	w := newWorld(t).withItems() // no deploy_op exists at all
	if len(w.st.DeployOps) != 0 {
		t.Fatal("fixture has deploy ops")
	}
	replaced := func(f func(k *model.Key)) *model.Key {
		k := w.item(idK1).(*model.Key)
		f(k)
		return k
	}
	cases := []struct {
		name string
		k    *model.Key
	}{
		{"whole key replaced", func() *model.Key {
			n := keyItem(t, idK1, "k3")
			n.Name = "k1"
			return n
		}()},
		{"public_key replaced", replaced(func(k *model.Key) { k.PublicKey, _ = sshKey(t, "k3") })},
		{"private_key replaced", replaced(func(k *model.Key) { k.PrivateKey += " changed" })},
		{"key_type changed", replaced(func(k *model.Key) { k.KeyType = "rsa" })},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			// The builder refuses it, and so does a transition.
			_, _, _, err := BuildNormal(w.st, w.sec, w.devA(), Changes{Put: []crypto.Item{c.k}}, w.now(), w.archive)
			wantRule(t, err, RuleKeyMaterial)
			wantRule(t, w.transition(w.unverified(Changes{Put: []crypto.Item{c.k}})), RuleKeyMaterial)
		})
	}
	t.Run("metadata-only edit", func(t *testing.T) {
		k := w.item(idK1).(*model.Key)
		k.Name = "renamed"
		mustAccept(t, w.transition(w.unverified(Changes{Put: []crypto.Item{k}})))
	})
	t.Run("dedicated_grant edit", func(t *testing.T) {
		k := w.item(idK2).(*model.Key)
		k.DedicatedGrant = fixedID(0x83)
		mustAccept(t, w.transition(w.unverified(Changes{Put: []crypto.Item{k}})))
	})
	t.Run("rewrap in a checkpoint", func(t *testing.T) {
		_, _, _, err := BuildCheckpoint(w.st, w.sec, w.devA(), w.checkpointParams())
		mustAccept(t, err)
	})
	t.Run("new key under a new ID", func(t *testing.T) {
		mustAccept(t, w.transition(w.unverified(Changes{Put: []crypto.Item{keyItem(t, idK3, "k3")}})))
	})
}

// A new deploy_op's key_item_version is the key item's current version in
// the candidate post-state (rev 10 item 10).
func TestDeployKeyVersion(t *testing.T) {
	w := full(t)
	k2 := w.item(idK2).(*model.Key)
	k2.Name = "renamed"
	w.normal(Changes{Put: []crypto.Item{k2}}) // K2 is at version 2
	op := func(id model.ID, key model.ID, fp string, v uint64) DeployOp {
		return DeployOp{OpID: id, Action: ActionRemove, SSHPKFp: fp, KeyItemID: key, KeyItemVersion: v,
			Targets: []Target{{HostItemID: idH2, State: TargetPending}}}
	}
	t.Run("stale version", func(t *testing.T) {
		ch := Changes{Deploy: []DeployOp{op(fixedID(0x94), idK2, w.fpK2, 1)}}
		wantRule(t, w.transition(w.unverified(ch)), RuleDeployKeyVersion)
	})
	t.Run("current version", func(t *testing.T) {
		ch := Changes{Deploy: []DeployOp{op(fixedID(0x94), idK2, w.fpK2, 2)}}
		mustAccept(t, w.transition(w.unverified(ch)))
	})
	t.Run("key edited in the same entry", func(t *testing.T) {
		k := w.item(idK2).(*model.Key)
		k.Name = "again"
		ch := Changes{Put: []crypto.Item{k}, Deploy: []DeployOp{op(fixedID(0x94), idK2, w.fpK2, 2)}}
		wantRule(t, w.transition(w.unverified(ch)), RuleDeployKeyVersion)
		ch.Deploy[0].KeyItemVersion = 3
		mustAccept(t, w.transition(w.unverified(ch)))
	})
	t.Run("key created in the same entry", func(t *testing.T) {
		_, fp3 := sshKey(t, "k3")
		ch := Changes{Put: []crypto.Item{keyItem(t, idK3, "k3")}, Deploy: []DeployOp{op(fixedID(0x94), idK3, fp3, 1)}}
		mustAccept(t, w.transition(w.unverified(ch)))
	})
	t.Run("new op names a deleted key", func(t *testing.T) {
		h2 := w.host(idH2)
		h2.KeyID = model.ID{}
		d := op(fixedID(0x94), idK2, w.fpK2, 2)
		d.Targets[0].State = TargetDone
		ch := Changes{Put: []crypto.Item{h2}, Delete: []model.ID{idK2}, Deploy: []DeployOp{d}}
		wantRule(t, w.transition(w.unverified(ch)), RuleDeployRefs)
	})
}

// key.public_key and every host.host_keys entry MUST parse as an OpenSSH
// authorized_keys line, "<type> <base64> [comment]" (rev 10 item 11). The
// rule lives in crypto.ValidateKey and crypto.ValidateHost, so the builder
// refuses such a plaintext, and a transition refuses one sealed by hand.
func TestSSHKeyLines(t *testing.T) {
	w := full(t)
	pub, _ := sshKey(t, "k3")
	f := strings.Fields(pub)
	key := func(line string) crypto.Item {
		k := keyItem(t, idK3, "k3")
		k.PublicKey = line
		return k
	}
	hostKeys := func(lines ...string) crypto.Item {
		h := w.host(idH2)
		h.HostKeys = lines
		return h
	}
	cases := []struct {
		name string
		it   crypto.Item
	}{
		{"public_key empty", key("")},
		{"public_key without a blob", key(f[0])},
		{"public_key blob is not base64", key(f[0] + " !!!!")},
		{"public_key blob is not a key", key(f[0] + " " + base64.StdEncoding.EncodeToString([]byte("not a key")))},
		{"public_key type differs from its blob", key("ssh-rsa " + f[1])},
		{"public_key with options", key(`from="10.0.0.1" ` + pub)},
		{"host_keys entry is not a key line", hostKeys(pub, "not a key")},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := buildNormalWire(w.st, w.sec, w.devA(), Changes{Put: []crypto.Item{c.it}}, w.now())
			wantRule(t, err, RuleSSHKeyLine)
			_, _, _, err = BuildNormal(w.st, w.sec, w.devA(), Changes{Put: []crypto.Item{c.it}}, w.now(), w.archive)
			wantRule(t, err, RuleSSHKeyLine)

			// By hand: a valid entry for the same item, resealed with the
			// malformed plaintext and re-signed.
			h, _ := crypto.ItemHeader(c.it)
			var good crypto.Item = keyItem(t, idK3, "k3")
			ik, err := crypto.NewSymKey()
			if err != nil {
				t.Fatal(err)
			}
			if h.ItemID == idH2 {
				good, ik = w.item(idH2), w.sec.Items[idH2].IK
			}
			wire := w.unverified(Changes{Put: []crypto.Item{good}})
			resealRaw(t, wire, w.st, w.sec.VK, ik, c.it)
			resign(t, wire, w.normalSigners())
			wantRule(t, w.transition(wire), RuleSSHKeyLine)
		})
	}
	t.Run("lines with and without a comment", func(t *testing.T) {
		mustAccept(t, w.transition(w.unverified(Changes{Put: []crypto.Item{key(f[0] + " " + f[1])}})))
		mustAccept(t, w.transition(w.unverified(Changes{Put: []crypto.Item{hostKeys(pub, f[0]+" "+f[1])}})))
	})
	t.Run("raw reseal of a valid plaintext is accepted", func(t *testing.T) {
		// The by-hand path itself is sound: the same reseal of a valid
		// plaintext passes.
		wire := w.unverified(Changes{Put: []crypto.Item{w.item(idH2)}})
		resealRaw(t, wire, w.st, w.sec.VK, w.sec.Items[idH2].IK, hostKeys(pub))
		resign(t, wire, w.normalSigners())
		mustAccept(t, w.transition(wire))
	})
}

func TestReferenceIntegrity(t *testing.T) {
	w := full(t)
	h2 := func(f func(h *model.Host)) Changes {
		h := w.host(idH2)
		f(h)
		return Changes{Put: []crypto.Item{h}}
	}
	cases := []struct {
		name string
		ch   Changes
	}{
		{"delete a referenced key", Changes{Delete: []model.ID{idK2}}},
		{"delete a referenced credential", Changes{Delete: []model.ID{idC1}}},
		{"key_id names a snippet", h2(func(h *model.Host) { h.KeyID = idS1 })},
		{"credential_id names nothing", h2(func(h *model.Host) { h.CredentialID = fixedID(0x6a) })},
		{"jump_host_id names a key", h2(func(h *model.Host) { h.JumpHostID = idK1 })},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) { wantRule(t, w.transition(w.unverified(c.ch)), RuleRefIntegrity) })
	}
	t.Run("deletion with cleanup", func(t *testing.T) {
		mustAccept(t, w.transition(w.unverified(h2(func(h *model.Host) { h.JumpHostID = idH1 }))))
		ch := h2(func(h *model.Host) { h.CredentialID = model.ID{} })
		ch.Delete = []model.ID{idC1}
		mustAccept(t, w.transition(w.unverified(ch)))
	})
}

func TestSnapshotCertRules(t *testing.T) {
	w := full(t)
	enroll := w.unverified(Changes{Devices: []DeviceInfo{w.enrolled(idDevC)}})
	runMutations(t, w.transition, enroll, w.normalSigners(), []mutation{
		// A device_add in a normal entry comes only from enrollment
		// (rev 10 item 14).
		{"enrolled certificate without enroll_transcript", RuleEnrollTranscript, func(e *Entry, _ *Wire) {
			d := opsOf[*DeviceAddOp](e)[0]
			d.Cert.EnrollTranscript = crypto.OptHash{}
			resignCert(t, d, w.acct)
		}},
		{"certificate not signed by the account", RuleSnapCert, func(e *Entry, _ *Wire) {
			opsOf[*DeviceAddOp](e)[0].Cert.Name = "forged"
		}},
		{"device keys do not match the certificate", RuleSnapCert, func(e *Entry, _ *Wire) {
			opsOf[*DeviceAddOp](e)[0].SigPK = w.infos[idDevB].SigPK
		}},
		{"certificate for another account", RuleSnapCert, func(e *Entry, _ *Wire) {
			opsOf[*DeviceAddOp](e)[0].Cert.AccountID = fixedID(0xef)
		}},
		{"re-adding an active device", RuleUniqueID, func(e *Entry, _ *Wire) {
			opsOf[*DeviceAddOp](e)[0].Cert.DeviceID = idDevB
		}},
	})
	t.Run("builder refuses a device without enroll_transcript", func(t *testing.T) {
		_, _, _, err := BuildNormal(w.st, w.sec, w.devA(), Changes{Devices: []DeviceInfo{w.infos[idDevC]}}, w.now(), w.archive)
		wantRule(t, err, RuleEnrollTranscript)
	})
}

// Re-adding a revoked ID (§13): devices revoked by a checkpoint stay
// retired.
func TestRevokedIDsStayRetired(t *testing.T) {
	w := full(t)
	_, st, sec, err := BuildCheckpoint(w.st, w.sec, w.devA(), w.checkpointParams(idDevB))
	if err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := BuildBootstrap(st, sec, w.infos[idDevB], w.now()); RuleOf(err) != RuleUniqueID {
		t.Fatalf("re-adding revoked device B: %v, want %s", err, RuleUniqueID)
	}
	// A new item reusing the grant ID the checkpoint revoked.
	wire, err := buildNormalWire(st, sec, w.devA(), Changes{Put: []crypto.Item{newSnippet(idGrant)}}, w.now())
	if err != nil {
		t.Fatal(err)
	}
	_, _, err = Transition(st, sec, w.devA(), wire, nil)
	wantRule(t, err, RuleUniqueID)
}

func TestEquivocation(t *testing.T) {
	w := full(t)
	head := w.log[len(w.log)-1]
	t.Run("same seq, different H", func(t *testing.T) {
		fork := mutate(t, head, w.normalSigners(), func(e *Entry, _ *Wire) { e.Time++ })
		err := w.transition(fork)
		var eq *EquivocationError
		if !errors.As(err, &eq) || eq.Seq != w.st.Head.Seq || eq.Have != w.st.Head.H {
			t.Fatalf("got %v, want an EquivocationError at the head", err)
		}
	})
	t.Run("same entry again", func(t *testing.T) {
		if err := w.transition(head); !errors.Is(err, ErrAlreadyApplied) {
			t.Fatalf("got %v", err)
		}
	})
	t.Run("older entry", func(t *testing.T) {
		if err := w.transition(w.log[1]); !errors.Is(err, ErrStale) {
			t.Fatalf("got %v", err)
		}
		h1, _ := w.log[1].Entry.Hash()
		if err := CheckHeld(1, h1, &w.log[1].Entry); err != nil {
			t.Fatal(err)
		}
		fork := mutate(t, w.log[1], map[Role]signer{RoleAccount: acctSigner(w.acct)}, func(e *Entry, _ *Wire) { e.Time++ })
		var eq *EquivocationError
		if err := CheckHeld(1, h1, &fork.Entry); !errors.As(err, &eq) {
			t.Fatalf("got %v", err)
		}
	})
}

func TestAnchorRules(t *testing.T) {
	w := full(t).deleteC1()
	p := w.checkpointParams(idDevB)
	cp, _, _, err := BuildCheckpoint(w.st, w.sec, w.devA(), p)
	if err != nil {
		t.Fatal(err)
	}
	na := p.NewAccount
	h, _ := cp.Entry.Hash()
	trusted := &Head{Seq: cp.Entry.Seq, H: h}
	anchor := func(wr *Wire) error {
		_, _, _, err := Anchor(na.Pin(), na, wr, nil, nil)
		return err
	}
	signers := map[Role]signer{RoleDevice: devSigner(w.devA()), RoleAccountNew: acctSigner(na), RoleAccountOld: acctSigner(w.acct)}
	runMutations(t, anchor, cp, signers, []mutation{
		// The anchor algorithm given a snapshot with a duplicate ID (§13).
		{"item ID equals a device ID", RuleSnapDisjoint, func(e *Entry, _ *Wire) { putFor(t, e, idS1).ItemID = idDevA }},
		{"item ID equals a retired grant ID", RuleSnapDisjoint, func(e *Entry, _ *Wire) { putFor(t, e, idS1).ItemID = idGrant }},
		{"item ID also retired", RuleOpDupID, func(e *Entry, _ *Wire) { putFor(t, e, idS1).ItemID = idC1 }},
		{"two puts of one item", RuleOpDupID, func(e *Entry, _ *Wire) {
			q := *putFor(t, e, idS1)
			e.Ops = append(e.Ops, &q)
		}},
		{"item with another kv", RuleSnapKV, func(e *Entry, _ *Wire) { putFor(t, e, idS1).KV = 1 }},
		{"certificate akv", RuleCertAKV, func(e *Entry, _ *Wire) { opsOf[*DeviceAddOp](e)[0].Cert.AKV = 1 }},
		{"certificate not signed by the new key", RuleSnapCert, func(e *Entry, _ *Wire) { opsOf[*DeviceAddOp](e)[0].Cert.Name = "x" }},
		{"vk_wrap to another recipient", RuleSnapRecipient, func(e *Entry, _ *Wire) { opsOf[*VKWrapOp](e)[0].Recipient = idDevA }},
		{"incomplete op names a missing key", RuleDeployRefs, func(e *Entry, _ *Wire) {
			removeOps(e, func(o Op) bool { q, ok := o.(*ItemPutOp); return ok && q.ItemID == idK1 })
		}},
		{"revoked device not retired", RuleCheckpointRetired, func(e *Entry, _ *Wire) {
			opsOf[*RetiredOp](e)[0].DeviceIDs = []model.ID{}
		}},
		{"grant record names a grant that is not retired", RuleAnchorGrants, func(e *Entry, _ *Wire) {
			removeOps(e, func(o Op) bool { return o.Name() == OpGrantRevoke })
			opsOf[*RetiredOp](e)[0].GrantIDs = []model.ID{}
		}},
		{"missing device signature", RuleSigRoles, func(_ *Entry, wr *Wire) { wr.Sigs = wr.Sigs[1:] }},
		{"author does not survive", RuleDeviceCover, func(e *Entry, _ *Wire) { e.Author = idDevB }},
		// A survivor certificate's issued_at is the entry's time; that is
		// the only part of rev 10 item 13 an anchor can check.
		{"survivor certificate issued earlier", RuleSurvivorCert, func(e *Entry, _ *Wire) {
			d := deviceAddFor(t, e, idDevA)
			d.Cert.IssuedAt--
			resignCert(t, d, na)
		}},
		{"entry time differs from issued_at", RuleSurvivorCert, func(e *Entry, _ *Wire) { e.Time++ }},
	})
	t.Run("account_new signed by another key", func(t *testing.T) {
		bad := mutate(t, cp, map[Role]signer{RoleAccountNew: acctSigner(w.acct)}, func(*Entry, *Wire) {})
		wantRule(t, anchor(bad), RuleSigAcctNew)
	})
	t.Run("normal entry", func(t *testing.T) {
		wantRule(t, anchor(w.log[len(w.log)-1]), RuleAnchorKind)
	})
	t.Run("pin for akv 1", func(t *testing.T) {
		_, _, _, err := Anchor(w.acct.Pin(), w.acct, cp, nil, nil)
		wantRule(t, err, RuleAnchorPin)
	})
	t.Run("keys do not match the pin", func(t *testing.T) {
		_, _, _, err := Anchor(na.Pin(), fixedAccount(t, 2, "impostor"), cp, nil, nil)
		wantRule(t, err, RuleAnchorPin)
	})
	t.Run("trusted anchor", func(t *testing.T) {
		if _, _, _, err := Anchor(na.Pin(), na, cp, nil, trusted); err != nil {
			t.Fatal(err)
		}
		other := *trusted
		other.H[0] ^= 1
		_, _, _, err := Anchor(na.Pin(), na, cp, nil, &other)
		wantRule(t, err, RuleAnchorTrusted)
	})
}

func TestParse(t *testing.T) {
	w := full(t)
	wire := w.log[len(w.log)-1]
	b, err := wire.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name     string
		from, to string
		rule     Rule
	}{
		{"unknown op", `"op":"deploy_op"`, `"op":"deploy_now"`, RuleUnknownOp},
		{"unknown member in an op", `"op":"deploy_op"`, `"op":"deploy_op","extra":1`, RuleSchema},
		{"duplicate member in an op", `"op":"deploy_op"`, `"op":"deploy_op","op":"deploy_op"`, RuleSchema},
		{"unknown member in E", `"suite":1`, `"suite":1,"x":true`, RuleSchema},
		{"missing member in E", `"suite":1,`, ``, RuleSchema},
		{"unknown kind", `"kind":"normal"`, `"kind":"other"`, RuleSchema},
		{"bad target state", `"state":"pending"`, `"state":"started"`, RuleSchema},
		{"bad signature role", `"role":"device"`, `"role":"server"`, RuleSchema},
		{"seq with a leading zero", `"seq":"`, `"seq":"0`, RuleSchema},
		{"trailing data", ``, ``, RuleSchema},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			in := bytes.Replace(b, []byte(c.from), []byte(c.to), 1)
			if c.from == "" {
				in = append(bytes.Clone(b), []byte(" {}")...)
			} else if bytes.Equal(in, b) {
				t.Fatalf("fixture: %q not found", c.from)
			}
			_, err := ParseWire(in)
			wantRule(t, err, c.rule)
		})
	}
	t.Run("non-canonical input hashes like its JCS form", func(t *testing.T) {
		in := bytes.ReplaceAll(b, []byte(`,"`), []byte(", \n\""))
		in = bytes.Replace(in, []byte(`"v":1,`), []byte(`"v" : 1 ,`), 1)
		got, err := ParseWire(in)
		if err != nil {
			t.Fatal(err)
		}
		h1, _ := wire.Entry.Hash()
		h2, _ := got.Entry.Hash()
		if h1 != h2 {
			t.Fatal("hash depends on the input bytes")
		}
	})
	t.Run("schema of ops", func(t *testing.T) {
		bad := []Op{
			&RetiredOp{Op: OpRetired, ItemIDs: []model.ID{idK2, idK1}, DeviceIDs: []model.ID{}, GrantIDs: []model.ID{}},
			&RetiredOp{Op: OpRetired, ItemIDs: []model.ID{idK1, idK1}, DeviceIDs: []model.ID{}, GrantIDs: []model.ID{}},
			&CredsOp{Op: OpCreds, KDFVersion: 1, Salt: make([]byte, 15)},
			&DeployOp{Op: OpDeploy, OpID: idOpD1, Action: ActionDeploy, KeyItemID: idK1,
				Targets: []Target{{HostItemID: idH1, State: TargetDone}, {HostItemID: idH1, State: TargetDone}}},
			&ItemPutOp{Op: OpItemPut, ItemID: idK1, Type: "note"},
			&ItemPutOp{Op: OpItemDelete, ItemID: idK1, Type: model.TypeKey},
			&AccountKeysOp{Op: OpAccountKeys, KEMPK: []byte{1}, SigPK: make([]byte, 32)},
			&GrantRevokeOp{Op: OpGrantRevoke},
		}
		for i, o := range bad {
			if err := o.validate(); RuleOf(err) != RuleSchema {
				t.Errorf("op %d (%s): %v", i, o.Name(), err)
			}
		}
	})
}

func TestStateSerialization(t *testing.T) {
	w := full(t)
	b, err := w.st.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	s, err := ParseState(b)
	if err != nil {
		t.Fatal(err)
	}
	b2, err := s.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(b, b2) {
		t.Fatal("state does not round-trip")
	}
	if _, err := ParseState(bytes.Replace(b, []byte(`"kv":`), []byte(`"x":1,"kv":`), 1)); err == nil {
		t.Fatal("unknown member accepted")
	}
	// past_accounts (rev 11) round-trips and must stay below the current
	// akv in ascending order.
	_, st2, _, err := BuildCheckpoint(w.st, w.sec, w.devA(), w.checkpointParams())
	if err != nil {
		t.Fatal(err)
	}
	b2, err = st2.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(b2, []byte(`"past_accounts":[{"akv":1,`)) {
		t.Fatalf("past_accounts not serialized: %s", b2)
	}
	if s2, err := ParseState(b2); err != nil || len(s2.PastAccounts) != 1 {
		t.Fatalf("parse with past_accounts: %v", err)
	}
	if _, err := ParseState(bytes.Replace(b2, []byte(`"past_accounts":[{"akv":1,`), []byte(`"past_accounts":[{"akv":2,`), 1)); err == nil {
		t.Fatal("past account at the current akv accepted")
	}
	if _, err := ParseState(bytes.Replace(b, []byte(`"past_accounts":[],`), nil, 1)); err == nil {
		t.Fatal("state without past_accounts accepted")
	}
	// A parsed state keeps working as a pre-state.
	if _, _, err := Transition(s, w.sec, w.devA(), w.unverified(Changes{Put: []crypto.Item{w.item(idH2)}}), nil); err != nil {
		t.Fatal(err)
	}
}

// A checkpoint whose item is resealed under the wrong iv and validly
// re-signed. When the item_put declares the wrong iv, the public stage
// rejects it from the op alone, before any decryption. When the item_put
// declares the right iv but the objects were sealed under another one, the
// iv is bound only inside the AEAD AADs (§6.4), which the public stage can't
// open: it passes, and the plaintext stage refuses to decrypt.
func TestCheckpointResealedWrongIV(t *testing.T) {
	w := full(t).deleteC1()
	p := w.checkpointParams(idDevB)
	base := w.unverifiedCheckpoint(p)
	signers := w.checkpointSigners(p.NewAccount)
	oldIV := w.st.Items[idS1].IV

	t.Run("item_put declares the old iv", func(t *testing.T) {
		bad := cloneWire(t, base)
		ik, err := crypto.NewSymKey()
		if err != nil {
			t.Fatal(err)
		}
		reseal(t, bad, w.st, p.NewVK, ik, w.item(idS1), func(q *ItemPutOp) { q.IV = oldIV })
		resign(t, bad, signers)
		// Consistent objects: the item opens under its declared context.
		q := putFor(t, &bad.Entry, idS1)
		if _, err := crypto.UnwrapItemKey(&p.NewVK, itemContext(w.st, q), mustAEAD(t, bad, q.WrapSHA256)); err != nil {
			t.Fatalf("fixture: resealed wrap does not open: %v", err)
		}
		_, err = CheckPublic(w.st, bad, w.archive)
		wantRule(t, err, RuleItemIV)
	})
	t.Run("objects sealed under the old iv", func(t *testing.T) {
		bad := cloneWire(t, base)
		ik, err := crypto.NewSymKey()
		if err != nil {
			t.Fatal(err)
		}
		reseal(t, bad, w.st, p.NewVK, ik, w.item(idS1), func(q *ItemPutOp) { q.IV = oldIV })
		putFor(t, &bad.Entry, idS1).IV = oldIV + 1 // the op is right again
		resign(t, bad, signers)
		c, err := CheckPublic(w.st, bad, w.archive)
		if err != nil {
			t.Fatalf("public stage: %v", err)
		}
		_, _, err = c.CheckPlaintext(w.sec, w.devA())
		wantRule(t, err, RuleDecrypt)
		wantRule(t, w.transition(bad), RuleDecrypt)
	})
}

func mustAEAD(t testing.TB, w *Wire, h crypto.Hash) crypto.AEADEnvelope {
	t.Helper()
	objs, err := WireObjects(w)
	if err != nil {
		t.Fatal(err)
	}
	env, err := crypto.ParseAEADEnvelope(objs[h])
	if err != nil {
		t.Fatal(err)
	}
	return env
}

// Expired-but-unrevoked grants are active for every log rule (§5.3, §8.6):
// editing an item an expired grant lists still needs a bundle_put, and the
// builder writes one. Only the token client enforces expiry.
func TestExpiredGrantMaintenance(t *testing.T) {
	w := newWorld(t).withItems()
	tok, err := crypto.NewToken(idGrant, ed25519.PublicKey(w.st.Account.SigPK))
	if err != nil {
		t.Fatal(err)
	}
	w.token = tok
	tauth, err := tok.Auth()
	if err != nil {
		t.Fatal(err)
	}
	rec := w.grantRecord()
	rec.ExpiresAt = ts(t, "2020-01-01T00:00:00Z") // long before every entry's time
	w.normal(Changes{Grants: []NewGrant{{Record: rec, TAuthSHA256: crypto.SHA256(tauth)}}})
	if _, ok := w.st.Grants[idGrant]; !ok {
		t.Fatal("expired grant is not active")
	}

	s1 := w.item(idS1).(*model.Snippet)
	s1.Command = "uptime -p"
	ch := Changes{Put: []crypto.Item{s1}}

	t.Run("edit without a bundle_put", func(t *testing.T) {
		bad := w.unverified(ch)
		removeOps(&bad.Entry, func(o Op) bool { return o.Name() == OpBundlePut })
		resign(t, bad, w.normalSigners())
		wantRule(t, w.transition(bad), RuleBundleRequired)
	})
	t.Run("the builder adds the bundle_put", func(t *testing.T) {
		wire, st, _, err := BuildNormal(w.st, w.sec, w.devA(), ch, w.now(), w.archive)
		if err != nil {
			t.Fatal(err)
		}
		puts := opsOf[*BundlePutOp](&wire.Entry)
		if len(puts) != 1 || puts[0].GrantID != idGrant || puts[0].BundleVersion != 2 || st.Grants[idGrant].BundleVersion != 2 {
			t.Fatalf("bundle_puts %+v", puts)
		}
		// The token client refuses the bundle: it has expired.
		objs, err := WireObjects(wire)
		if err != nil {
			t.Fatal(err)
		}
		env, err := crypto.ParseHPKEEnvelope(objs[puts[0].EnvelopeSHA256])
		if err != nil {
			t.Fatal(err)
		}
		if _, err := crypto.OpenBundle(tok, env, 2, rec.ExpiresAt.Time().Add(-time.Hour)); err != nil {
			t.Fatalf("bundle before expiry: %v", err)
		}
		if _, err := crypto.OpenBundle(tok, env, 2, rec.ExpiresAt.Time()); err == nil {
			t.Fatal("token client accepted an expired bundle")
		}
	})
}

// substFetcher answers one digest with another object's bytes.
type substFetcher struct {
	ObjectMap
	from, to crypto.Hash
}

func (f substFetcher) FetchObject(h crypto.Hash) ([]byte, error) {
	if h.Equal(f.from) {
		h = f.to
	}
	return f.ObjectMap.FetchObject(h)
}

// OpenSecrets uses only objects whose SHA-256 equals the digest the state
// names (§5.5). A server that substitutes another object, or a state that
// names a digest found only in history, is refused.
func TestOpenSecretsDigestSubstitution(t *testing.T) {
	w := full(t)
	h2 := w.host(idH2)
	oldBody := w.st.Items[idH2].BodySHA256
	h2.Name = "h2-renamed"
	w.normal(Changes{Put: []crypto.Item{h2}})
	if _, err := OpenSecrets(w.st, w.devA(), w.archive); err != nil {
		t.Fatal(err)
	}
	st := w.st
	d := st.Devices[idDevA]
	for name, f := range map[string]substFetcher{
		"item body":         {w.archive, st.Items[idS1].BodySHA256, st.Items[idK1].BodySHA256},
		"item wrap":         {w.archive, st.Items[idS1].WrapSHA256, st.Items[idK1].WrapSHA256},
		"older item body":   {w.archive, st.Items[idH2].BodySHA256, oldBody},
		"VK envelope":       {w.archive, st.VKWrap.EnvelopeSHA256, d.UnlockSHA256},
		"unlock blob":       {w.archive, d.UnlockSHA256, st.Devices[idDevB].UnlockSHA256},
		"grant record body": {w.archive, st.Items[idRecord].BodySHA256, st.Items[idS1].BodySHA256},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := OpenSecrets(st, w.devA(), f)
			wantRule(t, err, RuleObjectDigest)
		})
	}
	t.Run("state names a digest found only in history", func(t *testing.T) {
		s := st.clone()
		it := s.Items[idH2]
		it.BodySHA256 = oldBody // present in the archive, with the right digest
		s.Items[idH2] = it
		if st.Usable(oldBody) || !s.Usable(oldBody) {
			t.Fatal("fixture: the old body must be usable only in the tampered state")
		}
		_, err := OpenSecrets(s, w.devA(), w.archive)
		wantRule(t, err, RuleDecrypt)
	})
}
