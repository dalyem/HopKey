package store

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/dalyem/hopkey/internal/canonjson"
	"github.com/dalyem/hopkey/internal/crypto"
	"github.com/dalyem/hopkey/internal/merge"
	"github.com/dalyem/hopkey/internal/model"
	"github.com/dalyem/hopkey/internal/vaultlog"
)

// pair is two devices of one server-backed account on a fake server. Both
// verify a key, a host using it with credential c1, and credentials c1
// and c2.
type pair struct {
	a, b   *fixture
	r      *fakeRemote
	key    model.Key
	host   model.Host
	c1, c2 model.Credential
}

func newPair(t *testing.T) *pair {
	t.Helper()
	ctx := context.Background()
	f := newVault(t, testConfig(t))
	key, host := addHost(t, f.s, "web")
	c1 := newCredential(t, f.s, "c1")
	c2 := newCredential(t, f.s, "c2")
	host.CredentialID = c1.ItemID
	host, err := f.s.PutHost(ctx, host)
	if err != nil {
		t.Fatal(err)
	}
	r := newFakeRemote(t, f.cfg.DataDir)
	if err := f.s.EnableServerMode(); err != nil {
		t.Fatal(err)
	}
	b := secondDevice(t, f, r)
	return &pair{a: f, b: b, r: r, key: key, host: host, c1: c1, c2: c2}
}

// editHost changes the host id as the overlay shows it and queues the
// change.
func editHost(t *testing.T, s *Store, id model.ID, change func(h *model.Host)) model.Host {
	t.Helper()
	h, ok := hostByID(t, s, id)
	if !ok {
		t.Fatalf("no host %v", id)
	}
	change(&h)
	out, err := s.PutHost(context.Background(), h)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// conflict queues on A a credential change of the host and commits on B an
// address change: a guarded conflict (§5.4).
func (p *pair) conflict(t *testing.T) {
	t.Helper()
	editHost(t, p.a.s, p.host.ItemID, func(h *model.Host) { h.CredentialID = p.c2.ItemID })
	editHost(t, p.b.s, p.host.ItemID, func(h *model.Host) { h.Addresses = []string{"10.0.0.2"} })
	if res := pushAll(t, p.b.s, p.r); res.Outcome != PushEmpty {
		t.Fatalf("B's push: %+v", res)
	}
}

func outboxFiles(t *testing.T, dataDir string) []string {
	t.Helper()
	ents, err := os.ReadDir(filepath.Join(dataDir, "vault", "outbox"))
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		t.Fatal(err)
	}
	var out []string
	for _, e := range ents {
		out = append(out, e.Name())
	}
	return out
}

// §13: a local-only vault never creates outbox records. It writes straight
// to the local log, as in phase 1.
func TestLocalOnlyVaultNeverQueues(t *testing.T) {
	ctx := context.Background()
	f := newVault(t, testConfig(t))
	before := headOf(t, f.s)
	k, h := addHost(t, f.s, "web")
	h.Description = "edited"
	if _, err := f.s.PutHost(ctx, h); err != nil {
		t.Fatal(err)
	}
	if err := f.s.Delete(ctx, h.ItemID); err != nil {
		t.Fatal(err)
	}
	if err := f.s.Delete(ctx, k.ItemID); err != nil {
		t.Fatal(err)
	}
	if got := headOf(t, f.s); got.Seq != before.Seq+5 {
		t.Errorf("head %d, want %d: local writes go straight to the log", got.Seq, before.Seq+5)
	}
	if files := outboxFiles(t, f.cfg.DataDir); len(files) != 0 {
		t.Errorf("outbox files %v", files)
	}
	if _, err := os.Stat(filepath.Join(f.cfg.DataDir, "vault", "outbox.json")); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("outbox.json exists: %v", err)
	}
	if snapshot(t, f.s).Marks != nil {
		t.Error("a local-only snapshot has marks")
	}
	if empty, err := f.s.OutboxEmpty(); err != nil || !empty {
		t.Errorf("OutboxEmpty = %v, %v", empty, err)
	}
	r := newFakeRemote(t, f.cfg.DataDir)
	if err := f.s.Pull(ctx, r); !errors.Is(err, ErrNotServerBacked) {
		t.Errorf("pull in a local-only vault: %v", err)
	}
	if _, err := f.s.PushHead(ctx, r); !errors.Is(err, ErrNotServerBacked) {
		t.Errorf("push in a local-only vault: %v", err)
	}
}

// Every host, key, credential and snippet write of a server-backed vault
// is queued, the overlay shows it, and pushing commits each record in
// order. The next edit's seen is the overlay item.
func TestServerVaultQueuesEveryWrite(t *testing.T) {
	ctx := context.Background()
	f, r := serverVault(t)
	s := f.s
	before := headOf(t, s)
	k, h := addHost(t, s, "web")
	c := newCredential(t, s, "c")
	sn, err := s.PutSnippet(ctx, model.Snippet{Name: "up", Command: "uptime"})
	if err != nil {
		t.Fatal(err)
	}
	h2 := editHost(t, s, h.ItemID, func(h *model.Host) { h.Description = "queued twice" })
	if h2.ItemVersion != 2 {
		t.Errorf("overlay version %d after a queued edit, want 2", h2.ItemVersion)
	}
	if err := s.Delete(ctx, sn.ItemID); err != nil {
		t.Fatal(err)
	}
	if got := headOf(t, s); got != before {
		t.Errorf("a queued write moved the verified head: %v → %v", before, got)
	}
	recs := records(t, s)
	if len(recs) != 6 {
		t.Fatalf("%d records, want 6", len(recs))
	}
	for i, want := range []merge.Action{merge.ActionCreate, merge.ActionCreate, merge.ActionCreate, merge.ActionCreate, merge.ActionPut, merge.ActionDelete} {
		if recs[i].N != uint64(i+1) || recs[i].Intent.Action != want {
			t.Errorf("record %d: n %d action %s, want %s", i, recs[i].N, recs[i].Intent.Action, want)
		}
	}
	// The put's seen is the overlay item, which only the queued create made.
	if seen := recs[4].Intent.Seen; seen == nil || !seen.Equal(recs[1].Intent.Want) {
		t.Error("the queued edit's seen is not the overlay item")
	}
	snap := snapshot(t, s)
	if got := hostNamed(t, snap, "web"); got.Description != "queued twice" || got.KeyID != k.ItemID {
		t.Errorf("overlay host %+v", got)
	}
	if len(snap.Snippets) != 0 || len(snap.Credentials) != 1 {
		t.Errorf("overlay: %d snippets, %d credentials", len(snap.Snippets), len(snap.Credentials))
	}
	for _, id := range []model.ID{k.ItemID, h.ItemID, c.ItemID, sn.ItemID} {
		if snap.Marks[id] != model.MarkPending {
			t.Errorf("mark of %v = %q", id, snap.Marks[id])
		}
	}
	if st, err := s.Status(); err != nil || st.Pending != 6 || st.Held != 0 || !st.ServerBacked {
		t.Errorf("status %+v, %v", st, err)
	}
	// The overlay is the same after a restart.
	s = open(t, f.cfg)
	if got := hostNamed(t, snapshot(t, s), "web"); got.Description != "queued twice" {
		t.Errorf("overlay after reopen: %+v", got)
	}

	if res := pushAll(t, s, r); res.Outcome != PushEmpty {
		t.Fatalf("push: %+v", res)
	}
	if got := headOf(t, s); got.Seq != before.Seq+6 || r.head().Seq != got.Seq {
		t.Errorf("head %d (server %d), want %d", got.Seq, r.head().Seq, before.Seq+6)
	}
	snap = snapshot(t, s)
	if snap.Marks != nil || len(outboxFiles(t, f.cfg.DataDir)) != 0 {
		t.Errorf("after the push: marks %v, files %v", snap.Marks, outboxFiles(t, f.cfg.DataDir))
	}
	if got, ok := verifiedHost(t, s, h.ItemID); !ok || got.Description != "queued twice" || got.ItemVersion != 2 {
		t.Errorf("verified host %+v", got)
	}
	// Two queued edits of a verified item: the second one's seen is the
	// first one's result in the overlay, not verified state.
	editHost(t, s, h.ItemID, func(h *model.Host) { h.User = "first" })
	editHost(t, s, h.ItemID, func(h *model.Host) { h.Port = 2200 })
	recs = records(t, s)
	verified := mergeItem(t, func() *model.Host { v, _ := verifiedHost(t, s, h.ItemID); return &v }())
	if len(recs) != 2 || !recs[1].Intent.Seen.Equal(recs[0].Intent.Want) || recs[1].Intent.Seen.Equal(verified) {
		t.Error("the second queued edit's seen is not the overlay item")
	}
	if got := hostNamed(t, snapshot(t, s), "web"); got.User != "first" || got.Port != 2200 || got.ItemVersion != 4 {
		t.Errorf("overlay after two edits: %+v", got)
	}
	pushAll(t, s, r)
	// Overlay checks: a reference to nothing, and a stale version.
	if _, err := s.PutHost(ctx, model.Host{Name: "bad", KeyID: c.ItemID, Route: "auto", AgentAccess: "allow", Port: 22}); !errors.Is(err, errDangling) {
		t.Errorf("a host naming a credential as its key: %v", err)
	}
	stale := hostNamed(t, snapshot(t, s), "web")
	stale.ItemVersion--
	if _, err := s.PutHost(ctx, stale); err == nil {
		t.Error("a stale version was queued")
	}
	if err := s.Delete(ctx, k.ItemID); err == nil {
		t.Error("deleting a key a host uses was queued")
	}
	if _, err := s.ChangePassword(ctx, []byte(testPassword), []byte("another long password")); !errors.Is(err, ErrServerBacked) {
		t.Errorf("a local checkpoint in a server-backed vault: %v", err)
	}
	if err := open(t, f.cfg).UnlockWithPassword(ctx, []byte(testPassword), ""); !errors.Is(err, ErrServerBacked) {
		t.Errorf("a local bootstrap in a server-backed vault: %v", err)
	}
}

// §13: AAD mutations. The record is AEAD(local_key, state, aad =
// lp("hopkey/v1/outbox") || lp(vault_id) || u64(n)): every AAD field
// changed fails, and so does a record moved to another n or vault.
func TestOutboxAAD(t *testing.T) {
	f, _ := serverVault(t)
	s := f.s
	addHost(t, s, "web")
	key, err := s.rec.localKey()
	if err != nil {
		t.Fatal(err)
	}
	vaultID := s.state.VaultID
	path1 := filepath.Join(f.cfg.DataDir, "vault", "outbox", "1.json")
	raw, err := os.ReadFile(path1)
	if err != nil {
		t.Fatal(err)
	}
	var file, file2 recordFile
	if err := canonjson.Unmarshal(raw, &file); err != nil {
		t.Fatal(err)
	}
	raw2, err := os.ReadFile(filepath.Join(f.cfg.DataDir, "vault", "outbox", "2.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := canonjson.Unmarshal(raw2, &file2); err != nil {
		t.Fatal(err)
	}
	// The AAD, built byte for byte from the spec.
	lp := func(b []byte) []byte {
		return append([]byte{byte(len(b) >> 24), byte(len(b) >> 16), byte(len(b) >> 8), byte(len(b))}, b...)
	}
	u64 := func(n uint64) []byte {
		b := make([]byte, 8)
		for i := range 8 {
			b[7-i] = byte(n >> (8 * i))
		}
		return b
	}
	aad := func(label string, vault []byte, n uint64) []byte {
		return slices.Concat(lp([]byte(label)), lp(vault), u64(n))
	}
	if _, err := crypto.OpenAEAD(key, file.Sealed, aad("hopkey/v1/outbox", vaultID[:], 1)); err != nil {
		t.Fatalf("the spec AAD does not open the record: %v", err)
	}
	other := vaultID
	other[0] ^= 1
	for name, a := range map[string][]byte{
		"label":          aad("hopkey/v1/outbox2", vaultID[:], 1),
		"vault_id":       aad("hopkey/v1/outbox", other[:], 1),
		"vault_id text":  aad("hopkey/v1/outbox", []byte(vaultID.String()), 1),
		"n":              aad("hopkey/v1/outbox", vaultID[:], 2),
		"n 0":            aad("hopkey/v1/outbox", vaultID[:], 0),
		"no lp on label": slices.Concat([]byte("hopkey/v1/outbox"), lp(vaultID[:]), u64(1)),
		"empty":          {},
	} {
		if _, err := crypto.OpenAEAD(key, file.Sealed, a); err == nil {
			t.Errorf("AAD with a changed %s opens the record", name)
		}
	}
	if _, err := openRecord(key, vaultID, 1, raw); err != nil {
		t.Fatalf("the record does not open: %v", err)
	}
	if _, err := openRecord(key, other, 1, raw); !errors.Is(err, ErrCorrupt) {
		t.Errorf("opened under another vault: %v", err)
	}
	wrong := *key
	wrong[0] ^= 1
	if _, err := openRecord(&wrong, vaultID, 1, raw); !errors.Is(err, ErrCorrupt) {
		t.Errorf("opened under another local_key: %v", err)
	}

	// File-level tampering, each read back through the store.
	mutate := func(change func(f *recordFile)) []byte {
		c := file
		c.Sealed.CT = slices.Clone(file.Sealed.CT)
		change(&c)
		b, err := canonjson.Marshal(c)
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	cases := map[string]struct {
		name string
		body []byte
	}{
		"n in the file":           {"1.json", mutate(func(f *recordFile) { f.N = 2 })},
		"moved to n 2":            {"2.json", mutate(func(f *recordFile) { f.N = 2 })},
		"vault_id in the file":    {"1.json", mutate(func(f *recordFile) { f.VaultID = other })},
		"ciphertext":              {"1.json", mutate(func(f *recordFile) { f.Sealed.CT[0] ^= 1 })},
		"nonce":                   {"1.json", mutate(func(f *recordFile) { f.Sealed.Nonce = slices.Clone(f.Sealed.Nonce); f.Sealed.Nonce[0] ^= 1 })},
		"record 2's sealed state": {"1.json", mutate(func(f *recordFile) { f.Sealed = file2.Sealed })},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			dir := filepath.Join(f.cfg.DataDir, "vault", "outbox")
			if err := os.Remove(path1); err != nil && !errors.Is(err, os.ErrNotExist) {
				t.Fatal(err)
			}
			for _, n := range []string{"1.json", "2.json"} {
				os.Remove(filepath.Join(dir, n))
			}
			if err := os.WriteFile(filepath.Join(dir, c.name), c.body, 0o600); err != nil {
				t.Fatal(err)
			}
			// The vault fails closed: it does not unlock.
			if _, err := tryOpen(t, f.cfg); !errors.Is(err, ErrCorrupt) {
				t.Errorf("open with %s changed: %v", name, err)
			}
			os.Remove(filepath.Join(dir, c.name))
		})
	}
	// The untouched record still opens.
	if err := os.WriteFile(path1, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := open(t, f.cfg).Snapshot(context.Background()); err != nil {
		t.Errorf("the original record: %v", err)
	}
}

// §13: head-of-line blocking. A held head blocks every record behind it,
// and nothing behind it is posted until it is resolved.
func TestHeadOfLineBlocking(t *testing.T) {
	p := newPair(t)
	p.conflict(t)
	a := p.a.s
	editHost(t, a, p.host.ItemID, func(h *model.Host) { h.Description = "behind the held head" })
	_, other := addHost(t, a, "other")
	posts := p.r.postCount()
	serverHead := p.r.head()
	for range 3 {
		res, err := a.PushHead(context.Background(), p.r)
		if err != nil {
			t.Fatal(err)
		}
		if res.Outcome != PushHeld || res.N != 1 || res.Hold == nil || res.Hold.Cause != merge.CauseGuardedConflict {
			t.Fatalf("push: %+v", res)
		}
	}
	if p.r.postCount() != posts || p.r.head() != serverHead {
		t.Errorf("records behind a held head were posted: %d posts, head %d", p.r.postCount()-posts, p.r.head().Seq)
	}
	if res := res0(t, p.a.s); len(res) != 4 || !res[0].Held || res[1].Held || res[2].Held {
		t.Errorf("records %v", res)
	}
	st, err := a.Status()
	if err != nil || st.Held != 1 || st.Pending != 3 {
		t.Errorf("status %+v %v", st, err)
	}
	snap := snapshot(t, a)
	if snap.Marks[p.host.ItemID] != model.MarkHeld || snap.Marks[other.ItemID] != model.MarkPending {
		t.Errorf("marks %v", snap.Marks)
	}

	// Taking theirs releases the queue: the rest goes up in order.
	if err := a.Resolve(Resolution{Choice: merge.ChoiceTakeTheirs}); err != nil {
		t.Fatal(err)
	}
	if res := pushAll(t, a, p.r); res.Outcome != PushEmpty {
		t.Fatalf("push: %+v", res)
	}
	got, _ := verifiedHost(t, a, p.host.ItemID)
	if got.CredentialID != p.c1.ItemID || !slices.Equal(got.Addresses, []string{"10.0.0.2"}) || got.Description != "behind the held head" {
		t.Errorf("host after take theirs: %+v", got)
	}
	if _, ok := verifiedHost(t, a, other.ItemID); !ok {
		t.Error("the record behind the head never committed")
	}
}

func res0(t *testing.T, s *Store) []*record { return records(t, s) }

// §13: a create followed by a host that references it, where the create is
// held. The dependent create waits; once the held one is resolved by an
// edit, both commit in order.
func TestHeldCreateBlocksDependentCreate(t *testing.T) {
	ctx := context.Background()
	p := newPair(t)
	a, b := p.a.s, p.b.s
	_, jump := addHost(t, b, "jump")
	pushAll(t, b, p.r)
	pull(t, a, p.r)
	// A creates h1 behind the jump host, and h2 behind h1.
	h1, err := a.PutHost(ctx, model.Host{Name: "h1", Addresses: []string{"h1"}, Port: 22, JumpHostID: jump.ItemID, KeyID: p.key.ItemID, Route: "auto", AgentAccess: "allow"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := a.PutHost(ctx, model.Host{Name: "h2", Addresses: []string{"h2"}, Port: 22, JumpHostID: h1.ItemID, KeyID: p.key.ItemID, Route: "auto", AgentAccess: "allow"}); err != nil {
		t.Fatal(err)
	}
	// B deletes the jump host first: h1's create now fails §5.3.
	if err := b.Delete(ctx, jump.ItemID); err != nil {
		t.Fatal(err)
	}
	pushAll(t, b, p.r)
	head := p.r.head()
	res := pushAll(t, a, p.r)
	if res.Outcome != PushHeld || res.N != 1 || res.Hold.Cause != merge.CauseRuleFailure {
		t.Fatalf("push: %+v", res)
	}
	if p.r.head() != head {
		t.Error("the dependent create was posted behind a held head")
	}
	// Keep mine is refused for a rule failure; edit starts from want.
	if _, err := a.Propose(Resolution{Choice: merge.ChoiceKeepMine}); !errors.Is(err, merge.ErrRefused) {
		t.Errorf("keep mine on a held create: %v", err)
	}
	held, err := a.HeldHead()
	if err != nil || held == nil || held.Want == nil {
		t.Fatalf("held head %+v %v", held, err)
	}
	var edited model.Host
	if err := canonjson.Unmarshal(held.Want, &edited); err != nil {
		t.Fatal(err)
	}
	edited.JumpHostID = model.ID{}
	prop, err := a.Propose(Resolution{Choice: merge.ChoiceEdit, Edited: &edited})
	if err != nil {
		t.Fatal(err)
	}
	if err := a.Resolve(Resolution{Choice: merge.ChoiceEdit, Edited: &edited, Confirm: prop.Digest}); err != nil {
		t.Fatal(err)
	}
	if res := pushAll(t, a, p.r); res.Outcome != PushEmpty {
		t.Fatalf("push after the edit: %+v", res)
	}
	snap := snapshot(t, a)
	g1, g2 := hostNamed(t, snap, "h1"), hostNamed(t, snap, "h2")
	if !g1.JumpHostID.IsZero() || g2.JumpHostID != h1.ItemID || snap.Marks != nil {
		t.Errorf("h1 %+v, h2 jump %v", g1, g2.JumpHostID)
	}
}

// §13: companion grant ops on a host delete. The candidate entry holds the
// item_delete, the grant record without the host (§8.6) and a new bundle,
// all built from verified state and not from the overlay.
func TestCompanionGrantOpsOnHostDelete(t *testing.T) {
	ctx := context.Background()
	p := newPair(t)
	a := p.a.s
	// The host uses a credential, which a token bundle can't carry without
	// listing it; drop it first.
	editHost(t, a, p.host.ItemID, func(h *model.Host) { h.CredentialID = model.ID{} })
	pushAll(t, a, p.r)
	grant, tok := grantWithToken(t, a, []model.ID{p.key.ItemID, p.host.ItemID}, map[model.ID]model.ID{p.host.ItemID: p.key.ItemID})
	direct(t, a, p.r, grant)
	a.mu.Lock()
	var grantID, recordID model.ID
	for g, gs := range a.state.Grants {
		grantID, recordID = g, gs.RecordItemID
	}
	bundleBefore := a.state.Grants[grantID].BundleVersion
	a.mu.Unlock()

	if err := a.Delete(ctx, p.host.ItemID); err != nil {
		t.Fatal(err)
	}
	// A later queued edit of the key must not leak into the delete's entry.
	if _, err := a.PutKey(ctx, func() model.Key {
		snap := snapshot(t, a)
		k := snap.Keys[0]
		k.Name = "renamed in the overlay"
		return k
	}()); err != nil {
		t.Fatal(err)
	}
	var posted *vaultlog.Wire
	p.r.onPost = func(w *vaultlog.Wire) (bool, error) {
		if posted == nil {
			posted = w
		}
		return true, nil
	}
	if res := pushAll(t, a, p.r); res.Outcome != PushEmpty {
		t.Fatalf("push: %+v", res)
	}
	var ops []string
	for _, o := range posted.Entry.Ops {
		switch o := o.(type) {
		case *vaultlog.ItemDeleteOp:
			ops = append(ops, "delete:"+name(o.ItemID, p.host.ItemID, recordID))
		case *vaultlog.ItemPutOp:
			ops = append(ops, "put:"+name(o.ItemID, p.host.ItemID, recordID))
		case *vaultlog.BundlePutOp:
			if o.GrantID == grantID && o.BundleVersion == bundleBefore+1 {
				ops = append(ops, "bundle")
			}
		default:
			ops = append(ops, o.Name())
		}
	}
	slices.Sort(ops)
	if want := []string{"bundle", "delete:host", "put:record"}; !slices.Equal(ops, want) {
		t.Errorf("the delete's entry has ops %v, want %v", ops, want)
	}
	a.mu.Lock()
	rec := a.sec.Items[recordID].Item.(*model.Grant)
	a.mu.Unlock()
	if slices.Contains(rec.Items, p.host.ItemID) || len(rec.HostKeyMap) != 0 || !slices.Contains(rec.Items, p.key.ItemID) {
		t.Errorf("grant record after the delete: items %v, map %v", rec.Items, rec.HostKeyMap)
	}

	// Open the new bundle as the token client would: it carries the key as
	// verified state has it, without the overlay's later rename, and no
	// longer the host.
	var opened *crypto.OpenedBundle
	for _, o := range posted.Entry.Ops {
		bp, ok := o.(*vaultlog.BundlePutOp)
		if !ok || bp.GrantID != grantID {
			continue
		}
		for _, obj := range posted.Objects {
			if !obj.SHA256.Equal(bp.EnvelopeSHA256) {
				continue
			}
			env, err := crypto.ParseHPKEEnvelope(obj.Body)
			if err != nil {
				t.Fatal(err)
			}
			if opened, err = crypto.OpenBundle(tok, env, bp.BundleVersion, time.Now()); err != nil {
				t.Fatal(err)
			}
		}
	}
	if opened == nil {
		t.Fatal("the delete's entry carries no bundle for the grant")
	}
	key, ok := opened.Items[p.key.ItemID].(*model.Key)
	if !ok || key.Name != p.key.Name || key.ItemVersion != p.key.ItemVersion {
		t.Errorf("the bundle's key: %+v", opened.Items[p.key.ItemID])
	}
	if _, ok := opened.Items[p.host.ItemID]; ok || len(opened.Items) != 1 {
		t.Errorf("the bundle still carries the host, or %d items", len(opened.Items))
	}
	b, err := canonjson.Marshal(opened.Bundle)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(b, []byte("renamed in the overlay")) {
		t.Error("the bundle carries an overlay value")
	}
}

func name(id, host, record model.ID) string {
	switch id {
	case host:
		return "host"
	case record:
		return "record"
	}
	return id.String()
}

var errCrash = errors.New("injected crash")

// §13: a crash between journaling a candidate and posting it, then
// re-posting the identical wire.
func TestCrashBetweenJournalAndPost(t *testing.T) {
	p := newPair(t)
	a := p.a.s
	posts := p.r.postCount()
	editHost(t, a, p.host.ItemID, func(h *model.Host) { h.Description = "after a crash" })
	a.testHook = func(stage string) error {
		if stage == "outbox:journaled" {
			return errCrash
		}
		return nil
	}
	if _, err := a.PushHead(context.Background(), p.r); !errors.Is(err, errCrash) {
		t.Fatalf("push with a crash after journaling: %v", err)
	}
	recs := records(t, a)
	c := recs[0].live()
	if c == nil || recs[0].Wires[c.H] == nil || p.r.postCount() != posts {
		t.Fatalf("after the crash: %+v, %d posts", recs[0].Cands, p.r.postCount()-posts)
	}
	journaled, _ := recs[0].Wires[c.H].Marshal()

	// After a restart the identical wire is posted.
	a = open(t, p.a.cfg)
	var reposted []byte
	p.r.onPost = func(w *vaultlog.Wire) (bool, error) {
		reposted, _ = w.Marshal()
		return true, nil
	}
	if res := pushAll(t, a, p.r); res.Outcome != PushEmpty {
		t.Fatalf("push after restart: %+v", res)
	}
	if !bytes.Equal(reposted, journaled) || !p.r.committed(c.H) || p.r.postCount() != posts+1 {
		t.Errorf("re-post: identical %v, committed %v, posts %d", bytes.Equal(reposted, journaled), p.r.committed(c.H), p.r.postCount()-posts)
	}

	// A lost response: the post committed, but the client never heard.
	// The next push settles it from verified history and posts nothing.
	editHost(t, a, p.host.ItemID, func(h *model.Host) { h.Description = "lost response" })
	p.r.onPost = func(*vaultlog.Wire) (bool, error) { return true, errLostResponse }
	if _, err := a.PushHead(context.Background(), p.r); !errors.Is(err, errLostResponse) {
		t.Fatalf("push with a lost response: %v", err)
	}
	if len(records(t, a)) != 1 {
		t.Fatal("an uncertain outcome dropped the record")
	}
	p.r.onPost = nil
	posts = p.r.postCount()
	if res := pushAll(t, a, p.r); res.Outcome != PushEmpty {
		t.Fatalf("push: %+v", res)
	}
	if p.r.postCount() != posts {
		t.Error("a committed candidate was posted again")
	}
	if got, _ := verifiedHost(t, a, p.host.ItemID); got.Description != "lost response" {
		t.Errorf("host %+v", got)
	}
}

// §13: a delayed original commit after the head moved. The first post is
// held back by the network; another device commits first; the record's
// candidate dies by verified history, the change is rebuilt and commits
// once, and the delayed original can never commit.
func TestDelayedOriginalCommit(t *testing.T) {
	p := newPair(t)
	a, b := p.a.s, p.b.s
	editHost(t, a, p.host.ItemID, func(h *model.Host) { h.Description = "from A" })
	var first crypto.Hash
	p.r.onPost = func(w *vaultlog.Wire) (bool, error) {
		p.r.mu.Lock()
		p.r.delayed = append(p.r.delayed, w)
		p.r.mu.Unlock()
		first, _ = w.Entry.Hash()
		return false, context.DeadlineExceeded
	}
	if _, err := a.PushHead(context.Background(), p.r); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("push: %v", err)
	}
	p.r.onPost = nil
	editHost(t, b, p.host.ItemID, func(h *model.Host) { h.Addresses = []string{"10.9.9.9"} })
	pushAll(t, b, p.r)

	if res := pushAll(t, a, p.r); res.Outcome != PushEmpty {
		t.Fatalf("push: %+v", res)
	}
	for _, err := range p.r.deliverDelayed() {
		if !errors.Is(err, ErrHeadConflict) {
			t.Errorf("the delayed original: %v", err)
		}
	}
	if p.r.committed(first) {
		t.Error("the original candidate committed after the head moved")
	}
	pull(t, b, p.r)
	for _, s := range []*Store{a, b} {
		got, _ := verifiedHost(t, s, p.host.ItemID)
		if got.Description != "from A" || !slices.Equal(got.Addresses, []string{"10.9.9.9"}) {
			t.Errorf("host %+v", got)
		}
	}
	if headOf(t, a) != headOf(t, b) || len(records(t, a)) != 0 {
		t.Error("the devices did not converge")
	}
}

// §13: a wire whose H isn't listed in the sealed state is ignored: it is
// never posted, and it can't stand in for a listed candidate.
func TestWireNotInSealedIsIgnored(t *testing.T) {
	p := newPair(t)
	a := p.a.s
	posts := p.r.postCount()
	editHost(t, a, p.host.ItemID, func(h *model.Host) { h.Description = "mine" })
	a.testHook = func(stage string) error {
		if stage == "outbox:journaled" {
			return errCrash
		}
		return nil
	}
	if _, err := a.PushHead(context.Background(), p.r); !errors.Is(err, errCrash) {
		t.Fatal(err)
	}
	a.testHook = nil
	listed := records(t, a)[0].live().H

	// A foreign wire, validly signed by this device: another change.
	a.mu.Lock()
	foreign, _, _, err := vaultlog.BuildNormal(a.state, a.sec, a.dev, vaultlog.Changes{Delete: []model.ID{p.c2.ItemID}}, a.now(), objectDir(a.l.objects()))
	a.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	fh, _ := foreign.Entry.Hash()
	fb, err := foreign.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(p.a.cfg.DataDir, "vault", "outbox", "1.json")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var file recordFile
	if err := canonjson.Unmarshal(raw, &file); err != nil {
		t.Fatal(err)
	}
	write := func(wires []canonjson.Raw) {
		c := file
		c.Wires = wires
		b, err := canonjson.Marshal(c)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, b, 0o600); err != nil {
			t.Fatal(err)
		}
	}

	// Replacing the listed wire: the store has no wire for its candidate
	// and refuses to post anything.
	write([]canonjson.Raw{fb})
	a = open(t, p.a.cfg)
	if _, err := a.PushHead(context.Background(), p.r); !errors.Is(err, ErrCorrupt) {
		t.Errorf("push with only a foreign wire: %v", err)
	}
	// Adding one beside it: only the listed wire is posted.
	write(append([]canonjson.Raw{fb}, file.Wires...))
	a = open(t, p.a.cfg)
	if res := pushAll(t, a, p.r); res.Outcome != PushEmpty {
		t.Fatalf("push: %+v", res)
	}
	if p.r.committed(fh) || !p.r.committed(listed) || p.r.postCount() != posts+1 {
		t.Errorf("foreign committed %v, listed committed %v, %d posts", p.r.committed(fh), p.r.committed(listed), p.r.postCount()-posts)
	}
}

// keepMine proposes and confirms keep mine on a's held head.
func keepMine(t *testing.T, s *Store) Proposal {
	t.Helper()
	prop, err := s.Propose(Resolution{Choice: merge.ChoiceKeepMine})
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Resolve(Resolution{Choice: merge.ChoiceKeepMine, Confirm: prop.Digest}); err != nil {
		t.Fatal(err)
	}
	return prop
}

// §13: keep mine rebuilding only L₀ (the credential versus address case),
// and L₀ recomputed after a second hold.
func TestKeepMineRebuildsOnlyL0(t *testing.T) {
	p := newPair(t)
	a, b := p.a.s, p.b.s
	p.conflict(t)
	res := pushAll(t, a, p.r)
	if res.Outcome != PushHeld || !slices.Equal(res.Hold.Local, []string{"credential_id"}) || !slices.Equal(res.Hold.Remote, []string{"addresses"}) {
		t.Fatalf("push: %+v %+v", res, res.Hold)
	}
	prop := keepMine(t, a)
	var want model.Host
	if err := canonjson.Unmarshal(prop.Want, &want); err != nil {
		t.Fatal(err)
	}
	if want.CredentialID != p.c2.ItemID || !slices.Equal(want.Addresses, []string{"10.0.0.2"}) {
		t.Errorf("keep mine proposes %+v", want)
	}
	recs := records(t, a)
	if recs[0].N != 1 || recs[0].Held || len(recs) != 1 {
		t.Errorf("after keep mine: %+v", recs)
	}

	// A second hold before the push: B changes the user. L₀ is now only
	// the credential: the address A absorbed from S is not A's change.
	editHost(t, b, p.host.ItemID, func(h *model.Host) { h.User = "root" })
	pushAll(t, b, p.r)
	res = pushAll(t, a, p.r)
	if res.Outcome != PushHeld || !slices.Equal(res.Hold.Local, []string{"credential_id"}) || !slices.Equal(res.Hold.Remote, []string{"user"}) {
		t.Fatalf("second push: %+v %+v", res, res.Hold)
	}
	editHost(t, b, p.host.ItemID, func(h *model.Host) { h.Addresses = []string{"10.0.0.3"} })
	pushAll(t, b, p.r)
	pull(t, a, p.r)
	keepMine(t, a)
	if res := pushAll(t, a, p.r); res.Outcome != PushEmpty {
		t.Fatalf("push: %+v", res)
	}
	got, _ := verifiedHost(t, a, p.host.ItemID)
	if got.CredentialID != p.c2.ItemID || got.User != "root" || !slices.Equal(got.Addresses, []string{"10.0.0.3"}) {
		t.Errorf("host %+v: want A's credential with B's user and latest address", got)
	}
}

// §13: keep mine on a held delete, and the refused combinations of the
// resolution table.
func TestHeldDeleteAndRefusals(t *testing.T) {
	ctx := context.Background()
	p := newPair(t)
	a, b := p.a.s, p.b.s
	if err := a.Delete(ctx, p.host.ItemID); err != nil {
		t.Fatal(err)
	}
	editHost(t, b, p.host.ItemID, func(h *model.Host) { h.Description = "changed meanwhile" })
	pushAll(t, b, p.r)
	res := pushAll(t, a, p.r)
	if res.Outcome != PushHeld || res.Hold.Cause != merge.CauseDeleteChanged {
		t.Fatalf("push: %+v", res)
	}
	snap := snapshot(t, a)
	if h, ok := hostByID(t, a, p.host.ItemID); !ok || snap.Marks[p.host.ItemID] != model.MarkHeld || h.Description != "changed meanwhile" {
		t.Errorf("a held delete in the overlay: %v %q", ok, snap.Marks[p.host.ItemID])
	}
	if _, err := a.Propose(Resolution{Choice: merge.ChoiceEdit, Edited: &p.host}); !errors.Is(err, merge.ErrRefused) {
		t.Errorf("edit on a held delete: %v", err)
	}
	if err := a.Resolve(Resolution{Choice: merge.ChoiceRetry}); !errors.Is(err, ErrStillHeld) {
		t.Errorf("retry of a held delete whose item changed: %v", err)
	}
	// A stale confirmation: S changes after the proposal.
	prop, err := a.Propose(Resolution{Choice: merge.ChoiceKeepMine})
	if err != nil {
		t.Fatal(err)
	}
	editHost(t, b, p.host.ItemID, func(h *model.Host) { h.Description = "changed again" })
	pushAll(t, b, p.r)
	pull(t, a, p.r)
	if err := a.Resolve(Resolution{Choice: merge.ChoiceKeepMine, Confirm: prop.Digest}); !errors.Is(err, ErrStaleConfirm) {
		t.Errorf("a stale confirmation: %v", err)
	}
	if err := a.Resolve(Resolution{Choice: merge.ChoiceKeepMine}); !errors.Is(err, ErrStaleConfirm) {
		t.Errorf("keep mine without a confirmation: %v", err)
	}
	if recs := records(t, a); !recs[0].Held {
		t.Error("a refused resolution cleared held")
	}
	keepMine(t, a)
	if res := pushAll(t, a, p.r); res.Outcome != PushEmpty {
		t.Fatalf("push: %+v", res)
	}
	if _, ok := verifiedHost(t, a, p.host.ItemID); ok {
		t.Error("keep mine on a held delete did not delete")
	}
	if err := a.Resolve(Resolution{Choice: merge.ChoiceTakeTheirs}); !errors.Is(err, ErrNotHeld) {
		t.Errorf("resolve with nothing held: %v", err)
	}

	// A put on an item B deleted: keep mine is refused.
	_, h2 := addHost(t, b, "gone")
	pushAll(t, b, p.r)
	pull(t, a, p.r)
	editHost(t, a, h2.ItemID, func(h *model.Host) { h.User = "edited" })
	if err := b.Delete(ctx, h2.ItemID); err != nil {
		t.Fatal(err)
	}
	pushAll(t, b, p.r)
	if res := pushAll(t, a, p.r); res.Outcome != PushHeld || res.Hold.Cause != merge.CauseNotLive {
		t.Fatalf("push: %+v", res)
	}
	if _, err := a.Propose(Resolution{Choice: merge.ChoiceKeepMine}); !errors.Is(err, merge.ErrRefused) {
		t.Errorf("keep mine on a put whose item is gone: %v", err)
	}
	if err := a.Resolve(Resolution{Choice: merge.ChoiceTakeTheirs}); err != nil {
		t.Fatal(err)
	}

	// An import record refuses every resolution, take theirs included.
	a.mu.Lock()
	unlock, err := a.lockFile()
	if err != nil {
		t.Fatal(err)
	}
	in := merge.Intent{Action: merge.ActionCreate, ItemID: p.c2.ItemID, Type: model.TypeCredential, Want: mergeItem(t, p.c2)}
	tx := &txn{}
	err = a.putRecord(tx, &record{N: 50, Held: true, Intent: in, Import: p.c1.ItemID, Cands: []candidate{}})
	if err == nil {
		err = a.commitTxn(tx)
	}
	unlock()
	a.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []merge.Choice{merge.ChoiceTakeTheirs, merge.ChoiceKeepMine, merge.ChoiceRetry} {
		if err := a.Resolve(Resolution{Choice: c}); !errors.Is(err, ErrImportRecord) {
			t.Errorf("%s on an import record: %v", c, err)
		}
	}
	if held, err := a.HeldHead(); err != nil || held == nil || !held.Import {
		t.Errorf("held head %+v %v", held, err)
	}
}

// §13: a put after a discarded create, converted to a fresh create.
func TestPutAfterDiscardedCreateBecomesCreate(t *testing.T) {
	ctx := context.Background()
	p := newPair(t)
	a, b := p.a.s, p.b.s
	_, jump := addHost(t, b, "jump")
	pushAll(t, b, p.r)
	pull(t, a, p.r)
	h1, err := a.PutHost(ctx, model.Host{Name: "h1", Addresses: []string{"h1"}, Port: 22, JumpHostID: jump.ItemID, KeyID: p.key.ItemID, Route: "auto", AgentAccess: "allow"})
	if err != nil {
		t.Fatal(err)
	}
	editHost(t, a, h1.ItemID, func(h *model.Host) { h.Name = "h1-renamed"; h.JumpHostID = model.ID{} })
	if err := b.Delete(ctx, jump.ItemID); err != nil {
		t.Fatal(err)
	}
	pushAll(t, b, p.r)
	if res := pushAll(t, a, p.r); res.Outcome != PushHeld || res.N != 1 {
		t.Fatalf("push: %+v", res)
	}
	if err := a.Resolve(Resolution{Choice: merge.ChoiceTakeTheirs}); err != nil {
		t.Fatal(err)
	}
	res := pushAll(t, a, p.r)
	if res.Outcome != PushHeld || res.N != 2 || res.Hold.Cause != merge.CauseNotLive {
		t.Fatalf("the put after the discarded create: %+v", res)
	}
	if _, err := a.Propose(Resolution{Choice: merge.ChoiceKeepMine}); !errors.Is(err, merge.ErrRefused) {
		t.Errorf("keep mine: %v", err)
	}
	prop, err := a.Propose(Resolution{Choice: merge.ChoiceEdit})
	if err != nil {
		t.Fatal(err)
	}
	if prop.Action != merge.ActionCreate || prop.NewID.IsZero() || prop.NewID == h1.ItemID || prop.ItemID != prop.NewID || prop.Seen != nil {
		t.Fatalf("proposal %+v", prop)
	}
	// Without the proposal's ID the digest differs.
	if err := a.Resolve(Resolution{Choice: merge.ChoiceEdit, Confirm: prop.Digest}); !errors.Is(err, ErrStaleConfirm) {
		t.Errorf("resolve with a different fresh ID: %v", err)
	}
	if err := a.Resolve(Resolution{Choice: merge.ChoiceEdit, NewID: prop.NewID, Confirm: prop.Digest}); err != nil {
		t.Fatal(err)
	}
	if res := pushAll(t, a, p.r); res.Outcome != PushEmpty {
		t.Fatalf("push: %+v", res)
	}
	got, ok := verifiedHost(t, a, prop.NewID)
	if !ok || got.Name != "h1-renamed" || got.ItemVersion != 1 {
		t.Errorf("the fresh create: %v %+v", ok, got)
	}
	if _, ok := verifiedHost(t, a, h1.ItemID); ok {
		t.Error("the discarded ID came back")
	}
}

// §13: a held head resolved in place while a dependent put waits behind
// it. The resolved record keeps its n; the put behind keeps its original
// seen and is merged against S when its turn comes, so the remote address
// it never saw is not overwritten.
func TestHeldHeadResolvedInPlaceWhileDependentPutWaits(t *testing.T) {
	p := newPair(t)
	a, b := p.a.s, p.b.s
	editHost(t, a, p.host.ItemID, func(h *model.Host) { h.CredentialID = p.c2.ItemID })
	// A's first candidate is lost on the way; B commits first, so it dies.
	p.r.onPost = func(*vaultlog.Wire) (bool, error) { return false, errLostResponse }
	if _, err := a.PushHead(context.Background(), p.r); !errors.Is(err, errLostResponse) {
		t.Fatal(err)
	}
	p.r.onPost = nil
	editHost(t, b, p.host.ItemID, func(h *model.Host) { h.Addresses = []string{"10.0.0.2"} })
	pushAll(t, b, p.r)
	editHost(t, a, p.host.ItemID, func(h *model.Host) { h.Description = "second edit" })
	if res := pushAll(t, a, p.r); res.Outcome != PushHeld || res.N != 1 {
		t.Fatalf("push: %+v", res)
	}
	before := records(t, a)
	if len(before[0].Cands) != 1 || before[0].Cands[0].Status != statusDead {
		t.Fatalf("the held head's candidates: %+v", before[0].Cands)
	}
	keepMine(t, a)
	after := records(t, a)
	if len(after) != 2 || after[0].N != 1 || after[1].N != 2 || after[0].Held {
		t.Fatalf("records after keep mine: %+v", after)
	}
	if !after[1].Intent.Seen.Equal(before[1].Intent.Seen) || !after[1].Intent.Want.Equal(before[1].Intent.Want) {
		t.Error("the record behind the head changed")
	}
	if !slices.Equal(stringsOf(after[0].Cands), stringsOf(before[0].Cands)) {
		t.Error("the resolution dropped the head's candidates")
	}
	if res := pushAll(t, a, p.r); res.Outcome != PushEmpty {
		t.Fatalf("push: %+v", res)
	}
	got, _ := verifiedHost(t, a, p.host.ItemID)
	if got.CredentialID != p.c2.ItemID || got.Description != "second edit" || !slices.Equal(got.Addresses, []string{"10.0.0.2"}) {
		t.Errorf("host %+v", got)
	}
}

func stringsOf(cs []candidate) []string {
	var out []string
	for _, c := range cs {
		out = append(out, c.H.String()+c.Status)
	}
	return out
}

// §13: a delete blocked by a deploy op, then retried after the targets are
// abandoned; and a deploy_op update while the outbox is held.
func TestDeleteBlockedByDeployOpThenRetried(t *testing.T) {
	ctx := context.Background()
	p := newPair(t)
	a := p.a.s
	fp, err := vaultlog.SSHFingerprint(p.key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	opID, err := vaultlog.NewID()
	if err != nil {
		t.Fatal(err)
	}
	deploy := vaultlog.DeployOp{OpID: opID, Action: vaultlog.ActionDeploy, SSHPKFp: fp, KeyItemID: p.key.ItemID, KeyItemVersion: 1,
		Targets: []vaultlog.Target{{HostItemID: p.host.ItemID, State: vaultlog.TargetPending}}}
	direct(t, a, p.r, vaultlog.Changes{Deploy: []vaultlog.DeployOp{deploy}})
	if err := a.Delete(ctx, p.host.ItemID); err != nil {
		t.Fatal(err)
	}
	res := pushAll(t, a, p.r)
	if res.Outcome != PushHeld || res.Hold.Cause != merge.CauseRuleFailure {
		t.Fatalf("push: %+v", res)
	}
	if err := a.Resolve(Resolution{Choice: merge.ChoiceRetry}); !errors.Is(err, ErrStillHeld) {
		t.Errorf("retry while the op is incomplete: %v", err)
	}
	// The deploy update goes to the server directly while the outbox is
	// held (§11.1).
	deploy.Targets = []vaultlog.Target{{HostItemID: p.host.ItemID, State: vaultlog.TargetAbandoned}}
	direct(t, a, p.r, vaultlog.Changes{Deploy: []vaultlog.DeployOp{deploy}})
	if recs := records(t, a); len(recs) != 1 || !recs[0].Held {
		t.Fatal("the deploy update changed the held record")
	}
	if err := a.Resolve(Resolution{Choice: merge.ChoiceRetry}); err != nil {
		t.Fatalf("retry after the targets are abandoned: %v", err)
	}
	if res := pushAll(t, a, p.r); res.Outcome != PushEmpty {
		t.Fatalf("push: %+v", res)
	}
	if _, ok := verifiedHost(t, a, p.host.ItemID); ok {
		t.Error("the retried delete did not commit")
	}
}

// §13: an in-flight pull response is discarded at lock, and the verified
// head doesn't advance while locked (§11.2).
func TestLockDiscardsInFlightPull(t *testing.T) {
	ctx := context.Background()
	p := newPair(t)
	a, b := p.a.s, p.b.s
	editHost(t, b, p.host.ItemID, func(h *model.Host) { h.Description = "from B" })
	pushAll(t, b, p.r)
	before := headOf(t, a)

	// pullAcross starts a pull, runs between while the server's response
	// is in flight, and then lets the response arrive.
	pullAcross := func(between func()) (bool, error) {
		entered, release := make(chan struct{}), make(chan struct{})
		var once sync.Once
		var sawCancel bool
		p.r.onSince = func(ctx context.Context) {
			once.Do(func() {
				close(entered)
				<-release
				sawCancel = ctx.Err() != nil
			})
		}
		defer func() { p.r.onSince = nil }()
		done := make(chan error)
		go func() { done <- a.Pull(ctx, p.r) }()
		<-entered
		between()
		close(release)
		err := <-done
		return sawCancel, err
	}

	// Locked while the response is in flight.
	cancelled, err := pullAcross(a.Lock)
	if !errors.Is(err, ErrSyncInterrupted) || !errors.Is(err, model.ErrLocked) || !cancelled {
		t.Errorf("pull across a lock: %v, request cancelled %v", err, cancelled)
	}
	if err := a.Pull(ctx, p.r); !errors.Is(err, model.ErrLocked) {
		t.Errorf("pull while locked: %v", err)
	}
	if _, err := a.PushHead(ctx, p.r); !errors.Is(err, model.ErrLocked) {
		t.Errorf("push while locked: %v", err)
	}
	if got := stateHead(t, p.a.cfg); got.Seq != before.Seq {
		t.Errorf("the head advanced on disk while locked: %d → %d", before.Seq, got.Seq)
	}
	if err := a.Unlock(ctx); err != nil {
		t.Fatal(err)
	}
	if got := headOf(t, a); got != before {
		t.Errorf("unlock resumed from %v, want %v", got, before)
	}
	// Locked and unlocked again before the response arrives: it belongs
	// to the earlier session and is still discarded.
	cancelled, err = pullAcross(func() {
		a.Lock()
		if err := a.Unlock(ctx); err != nil {
			t.Error(err)
		}
	})
	if !errors.Is(err, ErrSyncInterrupted) || !cancelled {
		t.Errorf("pull across a lock and unlock: %v, request cancelled %v", err, cancelled)
	}
	if got := headOf(t, a); got != before {
		t.Errorf("a discarded response moved the head: %v → %v", before, got)
	}
	pull(t, a, p.r)
	if got, _ := verifiedHost(t, a, p.host.ItemID); got.Description != "from B" {
		t.Errorf("host after the next pull: %+v", got)
	}
}

// Two devices editing offline converge through the server.
func TestTwoStoresConverge(t *testing.T) {
	ctx := context.Background()
	p := newPair(t)
	a, b := p.a.s, p.b.s
	editHost(t, a, p.host.ItemID, func(h *model.Host) { h.Description = "A's description" })
	editHost(t, b, p.host.ItemID, func(h *model.Host) { h.Port = 2222 })
	_, ha := addHost(t, a, "a-host")
	_, hb := addHost(t, b, "b-host")
	if err := b.Delete(ctx, p.c2.ItemID); err != nil {
		t.Fatal(err)
	}
	if _, err := a.PutSnippet(ctx, model.Snippet{Name: "s", Command: "true"}); err != nil {
		t.Fatal(err)
	}
	// Interleave single pushes.
	for range 20 {
		for _, s := range []*Store{a, b} {
			if _, err := s.PushHead(ctx, p.r); err != nil {
				t.Fatal(err)
			}
		}
	}
	for _, s := range []*Store{a, b} {
		if res := pushAll(t, s, p.r); res.Outcome != PushEmpty {
			t.Fatalf("push: %+v", res)
		}
		pull(t, s, p.r)
	}
	if headOf(t, a) != headOf(t, b) || headOf(t, a).H != p.r.head().H.String() {
		t.Fatal("heads differ")
	}
	sa, sb := snapshot(t, a), snapshot(t, b)
	ja, _ := json.Marshal(sa)
	jb, _ := json.Marshal(sb)
	if !bytes.Equal(ja, jb) || sa.Marks != nil {
		t.Error("snapshots differ")
	}
	got := hostNamed(t, sa, "web")
	if got.Description != "A's description" || got.Port != 2222 {
		t.Errorf("merged host %+v", got)
	}
	hostNamed(t, sa, ha.Name)
	hostNamed(t, sa, hb.Name)
	if len(sa.Credentials) != 1 || len(sa.Snippets) != 1 {
		t.Errorf("%d credentials, %d snippets", len(sa.Credentials), len(sa.Snippets))
	}
}

// An entry at a held seq with another H is an equivocation (§5.6): sync
// stops and stays stopped.
func TestPullEquivocation(t *testing.T) {
	ctx := context.Background()
	p := newPair(t)
	a, b := p.a.s, p.b.s
	// A fork of the server at the common head, which commits another
	// entry at the next seq.
	fork := newFakeRemote(t, p.a.cfg.DataDir)
	a.mu.Lock()
	other, _, _, err := vaultlog.BuildNormal(a.state, a.sec, a.dev, vaultlog.Changes{Delete: []model.ID{p.c2.ItemID}}, a.now(), objectDir(a.l.objects()))
	a.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fork.Post(ctx, other); err != nil {
		t.Fatal(err)
	}
	editHost(t, b, p.host.ItemID, func(h *model.Host) { h.Description = "one branch" })
	pushAll(t, b, p.r)
	pull(t, a, p.r)

	var eq *vaultlog.EquivocationError
	if err := a.Pull(ctx, fork); !errors.As(err, &eq) || !errors.Is(err, ErrSyncHalted) {
		t.Fatalf("pull from a forked server: %v", err)
	}
	if err := a.Pull(ctx, p.r); !errors.Is(err, ErrSyncHalted) {
		t.Errorf("pull after an equivocation: %v", err)
	}
	if _, err := a.PushHead(ctx, p.r); !errors.Is(err, ErrSyncHalted) {
		t.Errorf("push after an equivocation: %v", err)
	}
	if st, _ := a.Status(); st.Halted == "" {
		t.Error("status does not show the halt")
	}
	// A server behind this device's head is refused, not trusted.
	behind := newFakeRemote(t, p.a.cfg.DataDir)
	c := open(t, p.b.cfg)
	behind.entries, behind.hashes = behind.entries[:len(behind.entries)-1], behind.hashes[:len(behind.hashes)-1]
	if err := c.Pull(ctx, behind); !errors.Is(err, ErrServerBehind) {
		t.Errorf("pull from a server that lost an entry: %v", err)
	}
}

// An edit that replaces another device's description is reported once,
// when verified history settles its candidate, whichever call does that:
// the push after one whose answer was lost, a pull, or a push after a
// restart, including a re-post of a candidate that had not committed.
func TestReplacementIsReportedWhenVerifiedHistorySettlesIt(t *testing.T) {
	reopen := func(t *testing.T, p *pair) *Store {
		t.Helper()
		if err := p.a.s.Close(); err != nil {
			t.Fatal(err)
		}
		return open(t, p.a.cfg)
	}
	for _, tc := range []struct {
		name   string
		commit bool // whether the post whose answer is lost commits
		settle func(t *testing.T, p *pair) *Store
	}{
		{"the next push", true, func(t *testing.T, p *pair) *Store { pushAll(t, p.a.s, p.r); return p.a.s }},
		{"a pull", true, func(t *testing.T, p *pair) *Store { pull(t, p.a.s, p.r); return p.a.s }},
		{"a push after a restart", true, func(t *testing.T, p *pair) *Store { a := reopen(t, p); pushAll(t, a, p.r); return a }},
		{"a re-post after a restart", false, func(t *testing.T, p *pair) *Store { a := reopen(t, p); pushAll(t, a, p.r); return a }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := newPair(t)
			a, b := p.a.s, p.b.s
			editHost(t, b, p.host.ItemID, func(h *model.Host) { h.Description = "from B" })
			pushAll(t, b, p.r)
			editHost(t, a, p.host.ItemID, func(h *model.Host) { h.Description = "from A" })
			p.r.onPost = func(*vaultlog.Wire) (bool, error) { return tc.commit, errLostResponse }
			if _, err := a.PushHead(context.Background(), p.r); !errors.Is(err, errLostResponse) {
				t.Fatalf("push with a lost answer: %v", err)
			}
			p.r.onPost = nil
			if got := takeReplacements(t, a); len(got) != 0 {
				t.Errorf("reported before verified history settled it: %+v", got)
			}

			s := tc.settle(t, p)
			if len(records(t, s)) != 0 {
				t.Fatal("the edit is still queued")
			}
			got := takeReplacements(t, s)
			if len(got) != 1 || got[0].ItemID != p.host.ItemID || got[0].Type != model.TypeHost || got[0].Name != "web" ||
				!slices.Equal(got[0].Fields, []string{"description"}) {
				t.Errorf("replacements: %+v", got)
			}
			if again := takeReplacements(t, s); len(again) != 0 {
				t.Errorf("reported twice: %+v", again)
			}
			if h, _ := verifiedHost(t, s, p.host.ItemID); h.Description != "from A" {
				t.Errorf("host %+v", h)
			}
		})
	}
}

// takeReplacements reads s's notes of replaced edits and acknowledges
// them, as the daemon does.
func takeReplacements(t *testing.T, s *Store) []Replacement {
	t.Helper()
	rs, err := s.Replacements()
	if err != nil {
		t.Fatal(err)
	}
	if err := s.AckReplacements(rs); err != nil {
		t.Fatal(err)
	}
	return rs.Notes
}

// The notes of replaced edits stay, sealed, until they are acknowledged:
// a store that settles one and closes leaves it for the next. An
// acknowledgement removes only what was read, and past maxReplaced the
// oldest go, counted, until that count is acknowledged too.
func TestReplacementNotesStayUntilAcknowledged(t *testing.T) {
	p := newPair(t)
	a := p.a.s
	add := func(s *Store, names ...string) {
		t.Helper()
		var rs []Replacement
		for _, n := range names {
			rs = append(rs, Replacement{ItemID: p.host.ItemID, Type: model.TypeHost, Name: n, Fields: []string{"description"}})
		}
		s.mu.Lock()
		defer s.mu.Unlock()
		tx := &txn{}
		if err := s.addNotes(tx, s.rec, s.state.VaultID, rs); err != nil {
			t.Fatal(err)
		}
		if err := s.commitTxn(tx); err != nil {
			t.Fatal(err)
		}
	}
	names := func(rs Replacements) []string {
		var out []string
		for _, r := range rs.Notes {
			out = append(out, r.Name)
		}
		return out
	}
	read := func(s *Store) Replacements {
		t.Helper()
		rs, err := s.Replacements()
		if err != nil {
			t.Fatal(err)
		}
		return rs
	}

	add(a, "secret-host-name", "two")
	if b, err := os.ReadFile(a.l.replacedFile()); err != nil || bytes.Contains(b, []byte("secret-host-name")) || bytes.Contains(b, []byte("description")) {
		t.Fatalf("the notes file is not sealed: %v\n%s", err, b)
	}
	if err := a.Close(); err != nil {
		t.Fatal(err)
	}
	a = open(t, p.a.cfg)
	rs := read(a)
	if got := names(rs); !slices.Equal(got, []string{"secret-host-name", "two"}) || rs.Evicted != 0 {
		t.Fatalf("after a reopen: %q, %d evicted", got, rs.Evicted)
	}
	add(a, "three")
	if err := a.AckReplacements(rs); err != nil {
		t.Fatal(err)
	}
	if got := names(read(a)); !slices.Equal(got, []string{"three"}) {
		t.Fatalf("after an acknowledgement: %q", got)
	}

	var many []string
	for i := range maxReplaced + 2 {
		many = append(many, fmt.Sprint("h", i))
	}
	add(a, many...)
	rs = read(a)
	if len(rs.Notes) != maxReplaced || rs.Evicted != 3 || rs.Notes[0].Name != "h2" || rs.Notes[maxReplaced-1].Name != many[len(many)-1] {
		t.Fatalf("past the cap: %d notes from %q, %d evicted", len(rs.Notes), rs.Notes[0].Name, rs.Evicted)
	}
	if err := a.AckReplacements(rs); err != nil {
		t.Fatal(err)
	}
	if rs := read(a); len(rs.Notes) != 0 || rs.Evicted != 0 {
		t.Fatalf("after acknowledging everything: %+v", rs)
	}
	// Numbers are never reused, so an old read can't remove a new note.
	add(a, "fresh")
	if err := a.AckReplacements(Replacements{Notes: []Replacement{{N: 1}}}); err != nil {
		t.Fatal(err)
	}
	if got := names(read(a)); !slices.Equal(got, []string{"fresh"}) {
		t.Fatalf("a stale acknowledgement removed a new note: %q", got)
	}
}

// A crash in the commit that settles a replacing edit, once the journal
// has deleted its outbox record, keeps the note: the replay finishes the
// commit, and the next store to open the vault reports it.
func TestReplacementSurvivesACrashAfterItsRecordIsDeleted(t *testing.T) {
	// The commit's operations: the entry, state.json, the record's
	// deletion, then the note.
	for _, stage := range []string{"wal:op:2:sync", "wal:op:3", "wal:applied", "wal:removed"} {
		t.Run(stage, func(t *testing.T) {
			ctx := context.Background()
			p := newPair(t)
			a, b := p.a.s, p.b.s
			editHost(t, b, p.host.ItemID, func(h *model.Host) { h.Description = "from B" })
			pushAll(t, b, p.r)
			editHost(t, a, p.host.ItemID, func(h *model.Host) { h.Description = "from A" })
			p.r.onPost = func(*vaultlog.Wire) (bool, error) { return true, errLostResponse }
			if _, err := a.PushHead(ctx, p.r); !errors.Is(err, errLostResponse) {
				t.Fatalf("push with a lost answer: %v", err)
			}
			p.r.onPost = nil

			a.testHook = crashAt(stage)
			if err := a.Pull(ctx, p.r); !errors.Is(err, errCrash) {
				t.Fatalf("pull with a crash at %s: %v", stage, err)
			}
			a.Close()
			s := open(t, p.a.cfg)
			if len(records(t, s)) != 0 {
				t.Fatal("the edit is still queued")
			}
			got := takeReplacements(t, s)
			if len(got) != 1 || got[0].ItemID != p.host.ItemID || got[0].Name != "web" || !slices.Equal(got[0].Fields, []string{"description"}) {
				t.Errorf("replacements after the crash: %+v", got)
			}
		})
	}
}

// A record written before the sealed state recorded replacements (record
// version 1) still opens and is pushed.
func TestVersion1RecordStillOpens(t *testing.T) {
	p := newPair(t)
	a := p.a.s
	editHost(t, a, p.host.ItemID, func(h *model.Host) { h.Description = "queued before the upgrade" })
	r := records(t, a)[0]
	a.mu.Lock()
	vaultID := a.state.VaultID
	key, err := a.rec.localKey()
	a.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	pt, err := canonjson.Marshal(sealedStateV1{V: 1, Intent: intentToJSON(r.Intent, r.Import), Held: r.Held, Candidates: []candidate{}})
	if err != nil {
		t.Fatal(err)
	}
	env, err := crypto.SealAEAD(key, pt, outboxAAD(vaultID, r.N))
	key.Zero()
	if err != nil {
		t.Fatal(err)
	}
	b, err := canonjson.Marshal(recordFile{V: 1, VaultID: vaultID, N: r.N, Sealed: env, Wires: []canonjson.Raw{}})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(p.a.cfg.DataDir, "vault", outboxRel(r.N)), b, 0o600); err != nil {
		t.Fatal(err)
	}
	if res := pushAll(t, a, p.r); res.Outcome != PushEmpty {
		t.Fatalf("push: %+v", res)
	}
	if h, _ := verifiedHost(t, a, p.host.ItemID); h.Description != "queued before the upgrade" {
		t.Errorf("host %+v", h)
	}
}
