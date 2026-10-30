package store

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/dalyem/hopkey/internal/canonjson"
	"github.com/dalyem/hopkey/internal/crypto"
	"github.com/dalyem/hopkey/internal/merge"
	"github.com/dalyem/hopkey/internal/model"
	"github.com/dalyem/hopkey/internal/vaultlog"
)

// mergeFix is a local-only source vault and a destination account on a
// fake server, with the destination's account keys as a login opens them.
// The source holds a key, a credential, a jump host, a host that uses all
// three, and a snippet.
type mergeFix struct {
	src     *fixture
	dst     *fixture
	r       *fakeRemote
	srv     *fakeServer
	acct    *crypto.AccountKeys
	key     model.Key
	cred    model.Credential
	jump    model.Host
	host    model.Host
	snippet model.Snippet
}

func newMergeFix(t *testing.T, srcCfg Config) *mergeFix {
	t.Helper()
	ctx := context.Background()
	dst := newVault(t, testConfig(t))
	addHost(t, dst.s, "dest-web")
	r := newFakeRemote(t, dst.cfg.DataDir)
	if err := dst.s.EnableServerMode(); err != nil {
		t.Fatal(err)
	}
	m := &mergeFix{dst: dst, r: r, srv: newFakeServer(t, r), acct: cloneAccount(t, dst.s)}
	m.src = newVault(t, srcCfg)
	m.key, m.jump = addHost(t, m.src.s, "jump")
	m.cred = newCredential(t, m.src.s, "cred")
	h, err := m.src.s.PutHost(ctx, model.Host{
		Name: "web", Addresses: []string{"web.internal.example"}, Port: 22, User: "deploy",
		KeyID: m.key.ItemID, CredentialID: m.cred.ItemID, JumpHostID: m.jump.ItemID, Route: "auto", AgentAccess: "allow",
	})
	if err != nil {
		t.Fatal(err)
	}
	m.host = h
	if m.snippet, err = m.src.s.PutSnippet(ctx, model.Snippet{Name: "up", Command: "uptime"}); err != nil {
		t.Fatal(err)
	}
	return m
}

// cloneAccount copies s's account keys, as a login opens its own from
// pw_blob.
func cloneAccount(t *testing.T, s *Store) *crypto.AccountKeys {
	t.Helper()
	s.mu.Lock()
	defer s.mu.Unlock()
	return cloneAccountKeys(t, s.sec.Account)
}

func (m *mergeFix) params(t *testing.T) SignInParams {
	t.Helper()
	return SignInParams{ServerURL: m.srv.origin, Email: testEmail, Account: cloneAccountKeys(t, m.acct), SecretKey: m.dst.kit.SecretKey}
}

func cloneAccountKeys(t *testing.T, a *crypto.AccountKeys) *crypto.AccountKeys {
	t.Helper()
	kb, err := a.KEM.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	kem, err := crypto.ParseKEMPrivateKey(kb)
	if err != nil {
		t.Fatal(err)
	}
	c, err := crypto.NewAccountKeys(a.AccountID, a.AKV, kem, a.Sig.Seed())
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func (m *mergeFix) sourceIDs() []model.ID {
	ids := []model.ID{m.key.ItemID, m.cred.ItemID, m.jump.ItemID, m.host.ItemID, m.snippet.ItemID}
	slices.SortFunc(ids, func(a, b model.ID) int { return bytes.Compare(a[:], b[:]) })
	return ids
}

// signIn runs MergeSignIn on s against the fixture's server.
func (m *mergeFix) signIn(t *testing.T, s *Store) (MergeStatus, error) {
	t.Helper()
	return s.MergeSignIn(context.Background(), m.srv.login(t), m.params(t))
}

func mergeFileExists(t *testing.T, cfg Config) bool {
	t.Helper()
	_, err := os.Stat(filepath.Join(cfg.DataDir, "vault", mergeRel))
	return err == nil
}

// itemIDs is every item in a snapshot.
func itemIDs(snap model.Snapshot) []model.ID {
	var ids []model.ID
	for _, h := range snap.Hosts {
		ids = append(ids, h.ItemID)
	}
	for _, k := range snap.Keys {
		ids = append(ids, k.ItemID)
	}
	for _, c := range snap.Credentials {
		ids = append(ids, c.ItemID)
	}
	for _, sn := range snap.Snippets {
		ids = append(ids, sn.ItemID)
	}
	slices.SortFunc(ids, func(a, b model.ID) int { return bytes.Compare(a[:], b[:]) })
	return ids
}

// sourceIntact requires the source vault to be there, as it was: its
// items, unlocked with its own device key, local-only.
func (m *mergeFix) sourceIntact(t *testing.T, s *Store) {
	t.Helper()
	if s.ServerBacked() {
		t.Fatal("the source vault is server-backed")
	}
	if got, want := itemIDs(snapshot(t, s)), m.sourceIDs(); !slices.Equal(got, want) {
		t.Errorf("source items %v; want %v", got, want)
	}
	if info := s.Info(); info.AccountID != m.src.kit.AccountID {
		t.Errorf("the store is account %s, not the source's", info.AccountID)
	}
}

// imported requires the destination's other device to see every source
// item, by its source ID, exactly once, with the destination's own item.
func (m *mergeFix) imported(t *testing.T) {
	t.Helper()
	pull(t, m.dst.s, m.r)
	got := itemIDs(snapshot(t, m.dst.s))
	for _, id := range m.sourceIDs() {
		if n := countID(got, id); n != 1 {
			t.Errorf("source item %v is in the destination %d times", id, n)
		}
	}
	if len(got) != len(m.sourceIDs())+2 { // dest-web and its key
		t.Errorf("the destination holds %d items; want %d", len(got), len(m.sourceIDs())+2)
	}
	host, ok := verifiedHost(t, m.dst.s, m.host.ItemID)
	if !ok || host.KeyID != m.key.ItemID || host.JumpHostID != m.jump.ItemID || host.CredentialID != m.cred.ItemID || host.ItemVersion != 1 {
		t.Errorf("imported host %+v", host)
	}
}

func countID(ids []model.ID, id model.ID) int {
	n := 0
	for _, x := range ids {
		if x == id {
			n++
		}
	}
	return n
}

func importRecords(t *testing.T, s *Store, txn model.ID) []*record {
	t.Helper()
	var out []*record
	for _, r := range records(t, s) {
		if r.Import == txn {
			out = append(out, r)
		}
	}
	return out
}

// §4.4: a local-only vault merged into an account: sealed, signed in,
// imported in dependency order with a receipt in each import's commit, and
// the file deleted once every receipt is present.
func TestLoginMergeImportsEveryItem(t *testing.T) {
	ctx := context.Background()
	m := newMergeFix(t, testConfig(t))
	s := m.src.s
	srcIDs := idsOf(t, m.src.cfg)
	st, err := s.MergeStart()
	if err != nil {
		t.Fatal(err)
	}
	if st.State != MergeSealed || len(st.Items) != 5 {
		t.Fatalf("status %+v", st)
	}
	// The source is frozen.
	if _, err := s.PutHost(ctx, model.Host{Name: "x", Port: 22, Route: "auto", AgentAccess: "allow"}); !errors.Is(err, ErrMergeFrozen) {
		t.Errorf("a write to the sealed source: %v", err)
	}
	if _, err := s.ChangePassword(ctx, []byte(testPassword), []byte(newPassword)); !errors.Is(err, ErrMergeFrozen) {
		t.Errorf("hop passwd on the sealed source: %v", err)
	}
	if _, err := s.MergeStart(); !errors.Is(err, ErrMergeState) {
		t.Errorf("a second merge: %v", err)
	}
	// Digests and items live only inside the AEAD.
	raw, err := os.ReadFile(filepath.Join(m.src.cfg.DataDir, "vault", mergeRel))
	if err != nil {
		t.Fatal(err)
	}
	for _, needle := range []string{"web.internal.example", "uptime", m.host.ItemID.String(), "p-cred"} {
		if bytes.Contains(raw, []byte(needle)) {
			t.Errorf("merge.json holds %q in the clear", needle)
		}
	}

	st, err = m.signIn(t, s)
	if err != nil {
		t.Fatal(err)
	}
	if st.State != MergeImporting || st.VaultID != m.dst.s.state.VaultID {
		t.Fatalf("after sign-in: %+v", st)
	}
	// One vault state, the destination's: server-backed, its account, and
	// the source's device record gone.
	if !s.ServerBacked() || s.Info().AccountID != m.dst.kit.AccountID {
		t.Fatalf("after sign-in the store is %+v", s.Info())
	}
	if _, err := m.src.cfg.Keyring.Get(keychainService, slotOf(srcIDs.acct, srcIDs.dev)); err == nil {
		t.Error("the source device record is still in the keychain")
	}
	if dc := diskDeviceConfig(t, m.src.cfg); dc.AccountID != m.acct.AccountID || dc.Next != nil {
		t.Errorf("device.json %+v; want the destination, with no next", dc)
	}
	// Ordinary writes wait while importing.
	if _, err := s.PutCredential(ctx, model.Credential{Name: "x", Username: "u", Password: "p"}); !errors.Is(err, ErrMergeImporting) {
		t.Errorf("a write while importing: %v", err)
	}
	if err := s.Delete(ctx, m.host.ItemID); !errors.Is(err, ErrMergeImporting) {
		t.Errorf("a delete while importing: %v", err)
	}
	// Dependency order: keys and credentials, hosts after their jump host,
	// then snippets.
	recs := importRecords(t, s, st.TxnID)
	var order []model.ID
	for _, r := range recs {
		order = append(order, r.Intent.ItemID)
		if r.Intent.Action != merge.ActionCreate || r.Intent.Seen != nil || version(r.Intent.Want) != 1 {
			t.Errorf("import %v is not a create of version 1", r.Intent.ItemID)
		}
	}
	pos := func(id model.ID) int { return slices.Index(order, id) }
	if len(order) != 5 || pos(m.jump.ItemID) > pos(m.host.ItemID) || pos(m.key.ItemID) > pos(m.jump.ItemID) ||
		pos(m.cred.ItemID) > pos(m.jump.ItemID) || pos(m.snippet.ItemID) != 4 {
		t.Errorf("import order %v", order)
	}
	// The bundle file stays until the last receipt, and goes with it.
	for i := range 5 {
		if !mergeFileExists(t, m.src.cfg) {
			t.Fatalf("the merge file is gone after %d of 5 imports", i)
		}
		res, err := s.PushHead(ctx, m.r)
		if err != nil || res.Outcome != PushCommitted {
			t.Fatalf("push %d: %+v %v", i, res, err)
		}
		if i < 4 {
			ms, err := s.MergeStatus()
			if err != nil || ms == nil {
				t.Fatalf("status after %d imports: %v", i+1, err)
			}
			n := 0
			for _, it := range ms.Items {
				if it.Imported {
					n++
				}
			}
			if n != i+1 {
				t.Errorf("%d receipts after %d imports", n, i+1)
			}
		}
	}
	if mergeFileExists(t, m.src.cfg) {
		t.Error("the merge file is still there with every receipt present")
	}
	if ms, err := s.MergeStatus(); err != nil || ms != nil {
		t.Errorf("status after the merge: %+v %v", ms, err)
	}
	m.imported(t)
	if _, err := s.PutCredential(ctx, model.Credential{Name: "x", Username: "u", Password: "p"}); err != nil {
		t.Errorf("a write after the merge: %v", err)
	}
	// After a restart it is the destination's vault.
	s = open(t, m.src.cfg)
	if !s.ServerBacked() || s.Info().AccountID != m.dst.kit.AccountID {
		t.Errorf("after a restart: %+v", s.Info())
	}
}

// A source with nothing in it merges to nothing: the file goes at once.
func TestLoginMergeEmptySource(t *testing.T) {
	m := newMergeFix(t, testConfig(t))
	e := newVault(t, testConfig(t))
	if _, err := e.s.MergeStart(); err != nil {
		t.Fatal(err)
	}
	st, err := m.signIn(t, e.s)
	if err != nil || !st.Done {
		t.Fatalf("sign-in: %+v %v", st, err)
	}
	if mergeFileExists(t, e.cfg) || len(records(t, e.s)) != 0 {
		t.Error("an empty merge left its file or records")
	}
}

// §13: preflight refusal of grants, deploy ops, a checkpoint journal or
// an unacknowledged kit, and a published vault.
func TestLoginMergePreflight(t *testing.T) {
	ctx := context.Background()
	directLocal := func(t *testing.T, s *Store, ch vaultlog.Changes) {
		t.Helper()
		s.mu.Lock()
		defer s.mu.Unlock()
		if err := s.write(ch, nil); err != nil {
			t.Fatal(err)
		}
	}
	t.Run("grant", func(t *testing.T) {
		f := newVault(t, testConfig(t))
		k, h := addHost(t, f.s, "web")
		directLocal(t, f.s, grantChanges(t, f.s, []model.ID{k.ItemID, h.ItemID}, map[model.ID]model.ID{h.ItemID: k.ItemID}))
		if _, err := f.s.MergeStart(); !errors.Is(err, ErrMergeRefused) {
			t.Errorf("with a grant: %v", err)
		}
		if mergeFileExists(t, f.cfg) {
			t.Error("a refused merge wrote its file")
		}
	})
	t.Run("revoked grant's record", func(t *testing.T) {
		f := newVault(t, testConfig(t))
		k, h := addHost(t, f.s, "web")
		ch := grantChanges(t, f.s, []model.ID{k.ItemID, h.ItemID}, map[model.ID]model.ID{h.ItemID: k.ItemID})
		directLocal(t, f.s, ch)
		directLocal(t, f.s, vaultlog.Changes{Revoke: []model.ID{ch.Grants[0].Record.GrantID}})
		f.s.mu.Lock()
		active := len(f.s.state.Grants)
		f.s.mu.Unlock()
		if active != 0 {
			t.Fatal("the grant is still active")
		}
		if _, err := f.s.MergeStart(); !errors.Is(err, ErrMergeRefused) {
			t.Errorf("with a grant record: %v", err)
		}
	})
	t.Run("deploy op", func(t *testing.T) {
		f := newVault(t, testConfig(t))
		k, h := addHost(t, f.s, "web")
		fp, err := vaultlog.SSHFingerprint(k.PublicKey)
		if err != nil {
			t.Fatal(err)
		}
		opID, err := vaultlog.NewID()
		if err != nil {
			t.Fatal(err)
		}
		directLocal(t, f.s, vaultlog.Changes{Deploy: []vaultlog.DeployOp{{OpID: opID, Action: vaultlog.ActionDeploy, SSHPKFp: fp,
			KeyItemID: k.ItemID, KeyItemVersion: 1, Targets: []vaultlog.Target{{HostItemID: h.ItemID, State: vaultlog.TargetPending}}}}})
		if _, err := f.s.MergeStart(); !errors.Is(err, ErrMergeRefused) {
			t.Errorf("with a deploy op: %v", err)
		}
	})
	t.Run("kit", func(t *testing.T) {
		f := newVault(t, testConfig(t))
		if _, err := f.s.ChangePassword(ctx, []byte(testPassword), []byte(newPassword)); err != nil {
			t.Fatal(err)
		}
		if _, err := f.s.MergeStart(); !errors.Is(err, ErrCheckpointPending) {
			t.Errorf("with a pending kit: %v", err)
		}
		if err := f.s.AckKit(); err != nil {
			t.Fatal(err)
		}
		if _, err := f.s.MergeStart(); err != nil {
			t.Errorf("once the kit is confirmed: %v", err)
		}
	})
	t.Run("checkpoint journal", func(t *testing.T) {
		f := newVault(t, testConfig(t))
		if _, err := f.s.ChangePassword(ctx, []byte(testPassword), []byte(newPassword)); err != nil {
			t.Fatal(err)
		}
		b, err := os.ReadFile(filepath.Join(f.cfg.DataDir, "vault", "journal", journalFiles(t, f.cfg)[0]))
		if err != nil {
			t.Fatal(err)
		}
		g := newVault(t, testConfig(t))
		if err := os.WriteFile(filepath.Join(g.cfg.DataDir, "vault", "journal", "99.json"), b, 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := g.s.MergeStart(); !errors.Is(err, ErrCheckpointPending) {
			t.Errorf("with a checkpoint journal: %v", err)
		}
	})
	t.Run("published", func(t *testing.T) {
		f, _ := serverVault(t)
		if _, err := f.s.MergeStart(); !errors.Is(err, ErrMergeRefused) {
			t.Errorf("a server-backed vault: %v", err)
		}
	})
	t.Run("own account", func(t *testing.T) {
		m := newMergeFix(t, testConfig(t))
		if _, err := m.src.s.MergeStart(); err != nil {
			t.Fatal(err)
		}
		p := SignInParams{ServerURL: m.srv.origin, Email: testEmail, Account: cloneAccount(t, m.src.s), SecretKey: m.src.kit.SecretKey}
		if _, err := m.src.s.MergeSignIn(ctx, m.srv.login(t), p); !errors.Is(err, ErrMergeRefused) {
			t.Errorf("signing in to the source's own account: %v", err)
		}
	})
}

// MergeCancel, while no destination record exists, unfreezes the source.
func TestLoginMergeCancel(t *testing.T) {
	ctx := context.Background()
	m := newMergeFix(t, testConfig(t))
	if _, err := m.src.s.MergeStart(); err != nil {
		t.Fatal(err)
	}
	if err := m.src.s.MergeCancel(MergeCancelOptions{}); err != nil {
		t.Fatal(err)
	}
	if mergeFileExists(t, m.src.cfg) {
		t.Error("cancel left the file")
	}
	if _, err := m.src.s.PutSnippet(ctx, model.Snippet{Name: "after", Command: "true"}); err != nil {
		t.Errorf("a write after cancel: %v", err)
	}
	// With the destination record durable, the sign-in must finish.
	g := newMergeFix(t, testConfig(t))
	if _, err := g.src.s.MergeStart(); err != nil {
		t.Fatal(err)
	}
	g.src.s.testHook = crashAt("signin:post")
	if _, err := g.signIn(t, g.src.s); !errors.Is(err, errCrash) {
		t.Fatal(err)
	}
	if err := g.src.s.MergeCancel(MergeCancelOptions{}); !errors.Is(err, ErrMergeState) {
		t.Errorf("cancel with a destination record: %v", err)
	}
}

// §13: a crash at each merge state, especially between sign-in and
// dropping the source, resumes to exactly one destination vault holding
// every item once. The source is deleted only once the bundle and the
// destination record are both durable.
func TestLoginMergeCrashAtEachState(t *testing.T) {
	type crash struct {
		name string
		hook func() func(string) error
	}
	var crashes []crash
	for _, st := range []string{"wal:before", "wal:install:sync", "wal:op:0", "wal:removed",
		"signin:record", "signin:intent", "signin:next", "signin:fetch", "signin:post", "signin:drop", "signin:promote", "merge:enqueue"} {
		crashes = append(crashes, crash{st, func() func(string) error { return crashAt(st) }})
	}
	for _, st := range []string{"wal:install:sync", "wal:op:0", "wal:op:3", "wal:op:7", "wal:applied", "wal:removed"} {
		crashes = append(crashes, crash{"drop " + st, func() func(string) error { return crashAfter("signin:drop", st) }})
	}
	for _, st := range []string{"wal:install:sync", "wal:op:0", "wal:op:5", "wal:removed"} {
		crashes = append(crashes, crash{"enqueue " + st, func() func(string) error { return crashAfter("merge:enqueue", st) }})
	}
	for _, store := range []string{DeviceStoreKeychain, DeviceStoreFile} {
		for _, c := range crashes {
			t.Run(store+" "+c.name, func(t *testing.T) {
				m := newMergeFix(t, testConfig(t))
				if store == DeviceStoreFile {
					m.src = fileSource(t, m)
				}
				s := m.src.s
				s.testHook = c.hook()
				_, err := s.MergeStart()
				if err == nil {
					_, err = m.signIn(t, s)
				}
				if !errors.Is(err, errCrash) {
					t.Fatalf("merge: %v", err)
				}
				dc := diskDeviceConfig(t, m.src.cfg)
				if dc.AccountID.String() == m.src.kit.AccountID && dc.Next != nil {
					// The destination record is durable: it must read back,
					// unless the crash came between naming it in device.json
					// and creating it (the intent), when it must be absent.
					ns := (&Store{cfg: m.src.cfg, l: layout{data: m.src.cfg.DataDir}}).nextStore(dc)
					state, rec, err := ns.probeSlot(dc.Next.DeviceID)
					if rec != nil {
						rec.zero()
					}
					if want := map[bool]slotState{true: slotAbsent, false: slotRecord}[c.name == "signin:intent"]; err != nil || state != want {
						t.Errorf("device.json names a destination record in state %v (%v); want %v", state, err, want)
					}
				}
				noUntrackedRecords(t, m.src.cfg, "after the crash")
				s = open(t, m.src.cfg)
				if !s.ServerBacked() {
					// Still the source: whole, until both are durable.
					m.sourceIntact(t, s)
					ms, err := s.MergeStatus()
					if err != nil {
						t.Fatal(err)
					}
					if ms == nil {
						if _, err := s.MergeStart(); err != nil {
							t.Fatal(err)
						}
					}
					if _, err := m.signIn(t, s); err != nil {
						t.Fatal(err)
					}
				}
				ms, err := s.MergeStatus()
				if err != nil || ms == nil || ms.State != MergeImporting {
					t.Fatalf("after recovery: %+v %v", ms, err)
				}
				if res := pushAll(t, s, m.r); res.Outcome != PushEmpty {
					t.Fatalf("push: %+v", res)
				}
				if mergeFileExists(t, m.src.cfg) {
					t.Error("the merge file is still there")
				}
				m.imported(t)
				// One device was added, however often the sign-in ran.
				pub, _, _ := m.srv.public(t)
				if n := len(m.srv.activeDevices(t, pub)); n != 2 {
					t.Errorf("%d active devices; want the destination's and one more", n)
				}
				if dc := diskDeviceConfig(t, m.src.cfg); dc.AccountID != m.acct.AccountID || dc.Next != nil {
					t.Errorf("device.json %+v", dc)
				}
				if _, err := os.Stat(filepath.Join(m.src.cfg.DataDir, nextKeyName)); !errors.Is(err, os.ErrNotExist) {
					t.Errorf("%s is still there: %v", nextKeyName, err)
				}
			})
		}
	}
}

// fileSource replaces the fixture's source with one that keeps its device
// key in the file store.
func fileSource(t *testing.T, m *mergeFix) *fixture {
	t.Helper()
	ctx := context.Background()
	cfg := testConfig(t)
	p, err := PrepareInit(cfg, InitOptions{Password: []byte(testPassword), DeviceStore: DeviceStoreFile})
	if err != nil {
		t.Fatal(err)
	}
	s, err := p.Commit()
	if err != nil {
		t.Fatal(err)
	}
	track(t, cfg, s)
	f := &fixture{cfg: cfg, kit: p.Kit(), s: s}
	m.key, m.jump = addHost(t, s, "jump")
	m.cred = newCredential(t, s, "cred")
	if m.host, err = s.PutHost(ctx, model.Host{Name: "web", Port: 22, KeyID: m.key.ItemID, CredentialID: m.cred.ItemID,
		JumpHostID: m.jump.ItemID, Route: "auto", AgentAccess: "allow"}); err != nil {
		t.Fatal(err)
	}
	if m.snippet, err = s.PutSnippet(ctx, model.Snippet{Name: "up", Command: "uptime"}); err != nil {
		t.Fatal(err)
	}
	return f
}

// refusingRing refuses to store any entry of one account.
type refusingRing struct {
	*memRing
	account string
}

func (r *refusingRing) Set(service, user, secret string) error {
	if strings.Contains(user, r.account) {
		return errors.New("keychain write refused")
	}
	return r.memRing.Set(service, user, secret)
}

// §13: source deletion only once both the bundle and the destination
// record are durable. A destination record that can't be stored durably
// stops the sign-in before anything is posted, with the source whole.
func TestLoginMergeSourceDeletedOnlyWithDurableDestination(t *testing.T) {
	cfg := testConfig(t)
	ring := &refusingRing{memRing: newMemRing(), account: "none"}
	cfg.Keyring = ring
	m := newMergeFix(t, cfg)
	ring.account = m.acct.AccountID.String()
	s := m.src.s
	if _, err := s.MergeStart(); err != nil {
		t.Fatal(err)
	}
	posts := len(m.r.hashes)
	if _, err := m.signIn(t, s); err == nil {
		t.Fatal("signed in without a durable destination record")
	}
	// device.json names the destination device before its record is
	// stored (the intent), so no record is ever untracked; the keychain
	// refused the record, so there is none.
	dc := diskDeviceConfig(t, m.src.cfg)
	if dc.Next == nil {
		t.Fatal("device.json does not name the destination device it tried to store")
	}
	if _, err := ring.memRing.Get(keychainService, slotOf(dc.Next.AccountID, dc.Next.DeviceID)); err == nil {
		t.Error("the keychain holds the refused destination record")
	}
	if len(m.r.hashes) != posts {
		t.Error("a bootstrap was posted for a device whose record is not durable")
	}
	m.sourceIntact(t, s)
	s = open(t, m.src.cfg)
	m.sourceIntact(t, s)
	ring.account = "nothing"
	if _, err := m.signIn(t, s); err != nil {
		t.Fatal(err)
	}
	pushAll(t, s, m.r)
	m.imported(t)
}

// heldMerge signs in and makes the destination hold the snippet's ID
// already, so the keys, credentials and hosts import and the snippet's
// import, the last, holds at the head of the queue.
func heldMerge(t *testing.T) (*mergeFix, MergeStatus) {
	t.Helper()
	m := newMergeFix(t, testConfig(t))
	if _, err := m.src.s.MergeStart(); err != nil {
		t.Fatal(err)
	}
	st, err := m.signIn(t, m.src.s)
	if err != nil {
		t.Fatal(err)
	}
	taken := model.Snippet{Header: model.Header{ItemID: m.snippet.ItemID, Type: model.TypeSnippet}, Name: "taken", Command: "true", Params: []string{}}
	direct(t, m.dst.s, m.r, vaultlog.Changes{Put: []crypto.Item{&taken}})
	res := pushAll(t, m.src.s, m.r)
	if res.Outcome != PushHeld || res.Hold.Cause != merge.CauseIDTaken {
		t.Fatalf("push: %+v", res)
	}
	return m, st
}

func importedCount(st MergeStatus) int {
	n := 0
	for _, it := range st.Items {
		if it.Imported {
			n++
		}
	}
	return n
}

// §13: pause deletes only this transaction's imports, resume re-enqueues
// only items with no receipt, a duplicate resume is rejected, "take
// theirs" is refused on an import, and discard is refused unless paused
// with no transaction records and no live candidate, and without its
// confirmation.
func TestLoginMergePauseResumeDiscard(t *testing.T) {
	ctx := context.Background()
	m, st := heldMerge(t)
	s := m.src.s
	if !mergeFileExists(t, m.src.cfg) {
		t.Fatal("the merge file went with a held import")
	}
	// A held import: take theirs and edit are refused, a retry still holds.
	for _, c := range []merge.Choice{merge.ChoiceTakeTheirs, merge.ChoiceEdit} {
		if err := s.Resolve(Resolution{Choice: c}); !errors.Is(err, ErrImportRecord) {
			t.Errorf("%s on an import: %v", c, err)
		}
	}
	if err := s.MergeRetry(); !errors.Is(err, ErrStillHeld) {
		t.Errorf("retry of the held import: %v", err)
	}
	if _, err := s.MergeResume(); !errors.Is(err, ErrMergeState) {
		t.Errorf("resume while importing: %v", err)
	}
	if _, err := s.MergeDiscard(crypto.Hash{1}); !errors.Is(err, ErrMergeState) {
		t.Errorf("discard while importing: %v", err)
	}
	before := len(importRecords(t, s, st.TxnID))
	if before == 0 {
		t.Fatal("no import records")
	}

	ps, err := s.MergePause(ctx, m.r)
	if err != nil {
		t.Fatal(err)
	}
	if ps.State != MergePaused || len(importRecords(t, s, st.TxnID)) != 0 {
		t.Fatalf("after pause: %+v, %d import records", ps, len(importRecords(t, s, st.TxnID)))
	}
	imported := importedCount(ps)
	if imported != 4 || before != 1 {
		t.Fatalf("%d imported with %d queued; want 4 with the snippet held", imported, before)
	}
	if imported != 5-before {
		t.Errorf("pause reports %d imported; %d were queued of 5", imported, before)
	}
	if _, err := s.MergePause(ctx, m.r); !errors.Is(err, ErrMergeState) {
		t.Errorf("a second pause: %v", err)
	}
	// Ordinary writes work while paused; items not imported are invisible.
	other := newCredential(t, s, "while paused")
	snap := snapshot(t, s)
	for _, it := range ps.Items {
		if !it.Imported && slices.Contains(itemIDs(snap), it.ItemID) && it.ItemID != m.snippet.ItemID {
			t.Errorf("item %v, not imported, is visible while paused", it.ItemID)
		}
	}
	// A record of another transaction is never touched by this merge.
	foreign := randomID(t)
	s.mu.Lock()
	unlock, err := s.lockFile()
	if err != nil {
		t.Fatal(err)
	}
	ftx := &txn{}
	fin := merge.Intent{Action: merge.ActionCreate, ItemID: randomID(t), Type: model.TypeCredential}
	fc := model.Credential{Header: model.Header{V: 1, ItemID: fin.ItemID, Type: model.TypeCredential, ItemVersion: 1}, Name: "f", Username: "u", Password: "p"}
	fin.Want = mergeItem(t, &fc)
	err = s.putRecord(ftx, &record{N: 900, Intent: fin, Import: foreign, Cands: []candidate{}})
	if err == nil {
		err = s.commitTxn(ftx)
	}
	unlock()
	s.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}

	rs, err := s.MergeResume()
	if err != nil {
		t.Fatal(err)
	}
	if rs.State != MergeImporting {
		t.Errorf("after resume: %+v", rs)
	}
	if _, err := s.MergeResume(); !errors.Is(err, ErrMergeState) {
		t.Errorf("a duplicate resume: %v", err)
	}
	recs := importRecords(t, s, st.TxnID)
	if len(recs) != 5-imported {
		t.Errorf("resume queued %d imports; %d items have no receipt", len(recs), 5-imported)
	}
	for _, r := range recs {
		for _, it := range ps.Items {
			if it.ItemID == r.Intent.ItemID && it.Imported {
				t.Errorf("resume re-queued %v, which has its receipt", it.ItemID)
			}
		}
	}
	if all := records(t, s); all[0].Intent.ItemID != other.ItemID {
		t.Errorf("the record queued while paused is not first")
	}
	// Pause again at once: only this merge's imports go.
	if _, err := s.MergePause(ctx, nil); err != nil {
		t.Fatal(err)
	}
	left := records(t, s)
	if len(left) != 2 || left[0].Intent.ItemID != other.ItemID || left[1].Import != foreign {
		t.Fatalf("after pause the outbox holds %d records; want the ordinary one and the foreign import", len(left))
	}

	// Discard: refused with a record of this transaction queued.
	s.mu.Lock()
	unlock, _ = s.lockFile()
	ttx := &txn{}
	tin := recs[0].Intent
	err = s.putRecord(ttx, &record{N: 901, Intent: tin, Import: st.TxnID, Cands: []candidate{}})
	if err == nil {
		err = s.commitTxn(ttx)
	}
	unlock()
	s.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.MergeDiscard(crypto.Hash{1}); !errors.Is(err, ErrMergeState) {
		t.Errorf("discard with a transaction record queued: %v", err)
	}
	removeRecord(t, s, 901)
	removeRecord(t, s, 900)
	// Refused with a live candidate.
	m.r.onPost = func(*vaultlog.Wire) (bool, error) { return false, errLostResponse }
	if _, err := s.PushHead(ctx, m.r); !errors.Is(err, errLostResponse) {
		t.Fatalf("push: %v", err)
	}
	m.r.onPost = nil
	if _, err := s.MergeDiscard(crypto.Hash{1}); !errors.Is(err, ErrLiveCandidate) {
		t.Errorf("discard with a live candidate: %v", err)
	}
	if res := pushAll(t, s, m.r); res.Outcome != PushEmpty {
		t.Fatalf("push: %+v", res)
	}
	// No confirmation: the digest, and nothing happens.
	p, err := s.MergeDiscard(crypto.Hash{})
	if !errors.Is(err, ErrConfirmRequired) || !mergeFileExists(t, m.src.cfg) {
		t.Fatalf("discard without confirmation: %v", err)
	}
	var rows []merge.ManifestRow
	ms, _ := s.MergeStatus()
	s.mu.Lock()
	unlock, _ = s.lockFile()
	om, err := s.readMerge(s.rec)
	unlock()
	s.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range om.j.Manifest {
		if om.j.receipt(r.ItemID) == nil {
			rows = append(rows, r)
		}
	}
	slices.Reverse(rows)
	want, err := merge.MergeDiscardDigest(ms.VaultID, ms.TxnID, rows)
	if err != nil || !want.Equal(p.digest) {
		t.Errorf("proposal digest %v; want %v (%v)", p.digest, want, err)
	}
	if len(p.Items) != 5-imported || !slices.IsSortedFunc(p.Items, func(a, b MergeItem) int { return bytes.Compare(a.ItemID[:], b.ItemID[:]) }) {
		t.Errorf("proposal items %+v", p.Items)
	}
	if _, err := s.MergeDiscard(crypto.Hash{2}); !errors.Is(err, ErrStaleConfirm) {
		t.Errorf("discard with another digest: %v", err)
	}
	if !mergeFileExists(t, m.src.cfg) {
		t.Fatal("a refused discard deleted the file")
	}
	if _, err := s.MergeDiscard(p.digest); !errors.Is(err, ErrStaleConfirm) {
		t.Errorf("discard confirmed by the raw digest: %v", err)
	}
	if _, err := s.MergeDiscard(p.Token); err != nil {
		t.Fatal(err)
	}
	if mergeFileExists(t, m.src.cfg) {
		t.Error("discard left the file")
	}
	if ms, err := s.MergeStatus(); err != nil || ms != nil {
		t.Errorf("status after discard: %+v %v", ms, err)
	}
}

func removeRecord(t *testing.T, s *Store, n uint64) {
	t.Helper()
	s.mu.Lock()
	defer s.mu.Unlock()
	unlock, err := s.lockFile()
	if err != nil {
		t.Fatal(err)
	}
	defer unlock()
	tx := &txn{}
	tx.remove(outboxRel(n))
	if err := s.commitTxn(tx); err != nil {
		t.Fatal(err)
	}
}

// Pause first waits until no import has a live candidate: offline it
// refuses; online it settles the candidate (re-posting the identical wire)
// and records its receipt before pausing.
func TestLoginMergePauseWaitsForLiveCandidate(t *testing.T) {
	ctx := context.Background()
	for _, committed := range []bool{true, false} {
		m := newMergeFix(t, testConfig(t))
		s := m.src.s
		if _, err := s.MergeStart(); err != nil {
			t.Fatal(err)
		}
		st, err := m.signIn(t, s)
		if err != nil {
			t.Fatal(err)
		}
		m.r.onPost = func(*vaultlog.Wire) (bool, error) { return committed, errLostResponse }
		if _, err := s.PushHead(ctx, m.r); !errors.Is(err, errLostResponse) {
			t.Fatalf("push: %v", err)
		}
		m.r.onPost = nil
		head := importRecords(t, s, st.TxnID)[0]
		if head.live() == nil {
			t.Fatal("no live candidate")
		}
		if _, err := s.MergePause(ctx, nil); !errors.Is(err, ErrLiveCandidate) {
			t.Errorf("an offline pause with a live import: %v", err)
		}
		ps, err := s.MergePause(ctx, m.r)
		if err != nil {
			t.Fatal(err)
		}
		for _, it := range ps.Items {
			if it.ItemID == head.Intent.ItemID && !it.Imported {
				t.Errorf("the settled import has no receipt (committed=%v)", committed)
			}
		}
		if importedCount(ps) != 1 {
			t.Errorf("%d imported; want the one that was in flight", importedCount(ps))
		}
	}
}

// §13: a crash between an import's commit and its receipt is impossible:
// they share one durable commit. A crash at every step of the commit that
// verifies an import leaves either the record and no receipt, or the
// receipt and no record.
func TestImportReceiptSharesTheCommit(t *testing.T) {
	for _, stage := range []string{"wal:before", "wal:install", "wal:install:sync", "wal:op:0", "wal:op:1", "wal:op:2", "wal:op:3", "wal:applied", "wal:removed"} {
		t.Run(stage, func(t *testing.T) {
			ctx := context.Background()
			m := newMergeFix(t, testConfig(t))
			s := m.src.s
			if _, err := s.MergeStart(); err != nil {
				t.Fatal(err)
			}
			st, err := m.signIn(t, s)
			if err != nil {
				t.Fatal(err)
			}
			m.r.onPost = func(*vaultlog.Wire) (bool, error) { return true, errLostResponse }
			if _, err := s.PushHead(ctx, m.r); !errors.Is(err, errLostResponse) {
				t.Fatal(err)
			}
			m.r.onPost = nil
			id := importRecords(t, s, st.TxnID)[0].Intent.ItemID
			s.testHook = crashAt(stage)
			if err := s.Pull(ctx, m.r); !errors.Is(err, errCrash) {
				t.Fatalf("pull: %v", err)
			}
			s = open(t, m.src.cfg)
			ms, err := s.MergeStatus()
			if err != nil {
				t.Fatal(err)
			}
			queued := false
			for _, r := range importRecords(t, s, st.TxnID) {
				queued = queued || r.Intent.ItemID == id
			}
			receipted := false
			for _, it := range ms.Items {
				receipted = receipted || (it.ItemID == id && it.Imported)
			}
			if queued == receipted {
				t.Errorf("after a crash at %s: queued %v, receipt %v", stage, queued, receipted)
			}
		})
	}
}

// §13: journal and bundle AAD mutations: each AEAD opens only under its
// own label and its own txn_id.
func TestLoginMergeAAD(t *testing.T) {
	m := newMergeFix(t, testConfig(t))
	s := m.src.s
	st, err := s.MergeStart()
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(m.src.cfg.DataDir, "vault", mergeRel)
	orig, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var f mergeFileJSON
	if err := canonjson.Unmarshal(orig, &f); err != nil {
		t.Fatal(err)
	}
	s.mu.Lock()
	key, err := s.rec.localKey()
	s.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	jpt, err := crypto.OpenAEAD(key, f.Journal, mergeAAD(labelMergeJournal, st.TxnID))
	if err != nil {
		t.Fatal(err)
	}
	bpt, err := crypto.OpenAEAD(key, f.Bundle, mergeAAD(labelMergeBundle, st.TxnID))
	if err != nil {
		t.Fatal(err)
	}
	other := randomID(t)
	seal := func(pt []byte, label string, txn model.ID) crypto.AEADEnvelope {
		env, err := crypto.SealAEAD(key, pt, mergeAAD(label, txn))
		if err != nil {
			t.Fatal(err)
		}
		return env
	}
	for name, mutate := range map[string]func(g *mergeFileJSON){
		"file txn_id":                func(g *mergeFileJSON) { g.TxnID = other },
		"journal under another txn":  func(g *mergeFileJSON) { g.Journal = seal(jpt, labelMergeJournal, other) },
		"journal under bundle label": func(g *mergeFileJSON) { g.Journal = seal(jpt, labelMergeBundle, st.TxnID) },
		"bundle under another txn":   func(g *mergeFileJSON) { g.Bundle = seal(bpt, labelMergeBundle, other) },
		"bundle under journal label": func(g *mergeFileJSON) { g.Bundle = seal(bpt, labelMergeJournal, st.TxnID) },
		"journal and bundle swapped": func(g *mergeFileJSON) { g.Journal, g.Bundle = g.Bundle, g.Journal },
		"journal under outbox label": func(g *mergeFileJSON) { g.Journal = seal(jpt, labelOutbox, st.TxnID) },
		"bundle replaced by journal": func(g *mergeFileJSON) { g.Bundle = g.Journal },
	} {
		g := f
		mutate(&g)
		b, err := canonjson.Marshal(g)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, b, 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := s.MergeStatus(); !errors.Is(err, ErrCorrupt) {
			t.Errorf("%s: status %v; want ErrCorrupt", name, err)
		}
	}
	if err := os.WriteFile(path, orig, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := s.MergeStatus(); err != nil {
		t.Errorf("the original file: %v", err)
	}
}

// §13: logout refuses while a merge file exists, even with
// --discard-pending or --local-only.
func TestLogoutRefusedWithMergeFile(t *testing.T) {
	ctx := context.Background()
	m, _ := heldMerge(t)
	srv := newFakeServer(t, m.r)
	for _, opts := range []LogoutOptions{{}, {DiscardPending: true}, {DiscardPending: true, LocalOnly: true}} {
		if _, err := m.src.s.Logout(ctx, retirer{srv}, opts); !errors.Is(err, ErrMergeInProgress) {
			t.Errorf("%+v with a merge file: %v", opts, err)
		}
	}
	if readRetire(t, m.src.cfg) != nil || m.src.s.Info().Locked {
		t.Error("a refused logout journaled or locked")
	}
}

// The dependency order (§4.4) does not depend on the item IDs: a host
// whose ID sorts first still follows the jump host chain it names.
func TestImportOrder(t *testing.T) {
	id := func(b byte) model.ID { var x model.ID; x[0] = b; return x }
	host := func(b byte, jump model.ID) *merge.Item {
		h := &model.Host{Header: model.Header{V: 1, ItemID: id(b), Type: model.TypeHost, ItemVersion: 1}, Name: "h", Aliases: []string{},
			Addresses: []string{}, Tags: []string{}, HostKeys: []string{}, Port: 22, JumpHostID: jump, Route: "auto", AgentAccess: "allow"}
		return mergeItem(t, h)
	}
	items := map[model.ID]*merge.Item{
		id(1): host(1, id(2)), // 1 jumps through 2,
		id(2): host(2, id(3)), // which jumps through 3
		id(3): host(3, model.ID{}),
		id(4): mergeItem(t, &model.Snippet{Header: model.Header{V: 1, ItemID: id(4), Type: model.TypeSnippet, ItemVersion: 1}, Name: "s", Command: "c", Params: []string{}}),
		id(5): mergeItem(t, &model.Credential{Header: model.Header{V: 1, ItemID: id(5), Type: model.TypeCredential, ItemVersion: 1}, Name: "c"}),
	}
	var rows []merge.ManifestRow
	for i := byte(1); i <= 5; i++ {
		rows = append(rows, merge.ManifestRow{ItemID: id(i), Type: items[id(i)].Type()})
	}
	var got []byte
	for _, r := range importOrder(rows, items) {
		got = append(got, r.ItemID[0])
	}
	if !bytes.Equal(got, []byte{5, 3, 2, 1, 4}) {
		t.Errorf("order %v; want the credential, hosts 3, 2, 1, then the snippet", got)
	}
}

// The discard confirmation is a token keyed by local_key, never the
// digest c: it differs from c, encodes without c, is the same in another
// process on the same device, differs on another device, and a token for
// an earlier state of the merge no longer confirms it.
func TestMergeDiscardToken(t *testing.T) {
	ctx := context.Background()
	m, _ := heldMerge(t)
	s := m.src.s
	if _, err := s.MergePause(ctx, m.r); err != nil {
		t.Fatal(err)
	}
	p, err := s.MergeDiscardProposal()
	if err != nil {
		t.Fatal(err)
	}
	if p.Token == (crypto.Hash{}) || p.Token.Equal(p.digest) {
		t.Fatalf("token %v, digest %v: the token must be set and differ from the digest", p.Token, p.digest)
	}
	b, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), p.digest.String()) || !strings.Contains(string(b), p.Token.String()) {
		t.Errorf("the proposal encodes as %s", b)
	}
	if _, err := s.MergeDiscard(p.digest); !errors.Is(err, ErrStaleConfirm) {
		t.Errorf("the raw digest confirmed a discard: %v", err)
	}

	// Another process on this device: the same token.
	s2, err := tryOpen(t, m.src.cfg)
	if err != nil {
		t.Fatal(err)
	}
	p2, err := s2.MergeDiscardProposal()
	if err != nil {
		t.Fatal(err)
	}
	if !p2.Token.Equal(p.Token) || !p2.digest.Equal(p.digest) {
		t.Errorf("token after reopening %v; want %v", p2.Token, p.Token)
	}

	// Another device: the same digest gives another token.
	other := newVault(t, testConfig(t))
	other.s.mu.Lock()
	t2, err := discardToken(other.s.rec, p.digest)
	other.s.mu.Unlock()
	if err != nil || t2.Equal(p.Token) {
		t.Errorf("another device's token for the same digest: %v %v", t2, err)
	}

	// The state changes (a receipt goes, so one more item is left): the
	// old token is stale and deletes nothing.
	s2.mu.Lock()
	unlock, err := s2.lockFile()
	if err != nil {
		s2.mu.Unlock()
		t.Fatal(err)
	}
	om, err := s2.readMerge(s2.rec)
	if err == nil {
		om.j.Receipts = om.j.Receipts[1:]
		tx := &txn{}
		if err = putMerge(tx, s2.rec, om); err == nil {
			err = s2.commitTxn(tx)
		}
	}
	unlock()
	s2.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s2.MergeDiscard(p.Token); !errors.Is(err, ErrStaleConfirm) {
		t.Fatalf("a token of an earlier state: %v; want ErrStaleConfirm", err)
	}
	if !mergeFileExists(t, m.src.cfg) {
		t.Fatal("a stale token deleted the merge")
	}
	p3, err := s2.MergeDiscardProposal()
	if err != nil {
		t.Fatal(err)
	}
	if p3.Token.Equal(p.Token) || len(p3.Items) != len(p.Items)+1 {
		t.Errorf("the proposal after the change: %d items, token %v", len(p3.Items), p3.Token)
	}
	if _, err := s2.MergeDiscard(p3.Token); err != nil {
		t.Fatal(err)
	}
	if mergeFileExists(t, m.src.cfg) {
		t.Error("discard left the file")
	}
}
