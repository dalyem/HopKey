package store

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/dalyem/hopkey/internal/model"
)

const forkPassword = "a new master password for the fork"

// forkFixture is a server-backed vault, its log pushed to a fake server:
// a key, a credential, a jump host and a host behind it using both, a
// snippet and a max-offline policy. Then, never pushed: a new host, an
// edit of the jump host and the delete of the snippet.
type forkFix struct {
	f                *fixture
	r                *fakeRemote
	key              model.Key
	cred             model.Credential
	jump, web, added model.Host
}

func forkFixture(t *testing.T) *forkFix {
	t.Helper()
	ctx := context.Background()
	f, r := serverVault(t)
	key, jump := addHost(t, f.s, "jump")
	cred := newCredential(t, f.s, "db-login")
	web, err := f.s.PutHost(ctx, model.Host{
		Name: "web", Addresses: []string{"10.0.0.5"}, Port: 22, User: "deploy", KeyID: key.ItemID,
		CredentialID: cred.ItemID, JumpHostID: jump.ItemID, Route: "auto", AgentAccess: "allow",
	})
	if err != nil {
		t.Fatal(err)
	}
	sn, err := f.s.PutSnippet(ctx, model.Snippet{Name: "uptime", Command: "uptime", Params: []string{}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.s.PutPolicy(ctx, model.Policy{MaxOffline: 60}); err != nil {
		t.Fatal(err)
	}
	if res := pushAll(t, f.s, r); res.Outcome != PushEmpty {
		t.Fatalf("push: %+v", res)
	}
	added, err := f.s.PutHost(ctx, model.Host{Name: "added", Addresses: []string{"10.0.0.9"}, Port: 22, User: "ops", KeyID: key.ItemID, Route: "auto", AgentAccess: "allow"})
	if err != nil {
		t.Fatal(err)
	}
	jump = editHost(t, f.s, jump.ItemID, func(h *model.Host) { h.Description = "edited, never pushed" })
	if err := f.s.Delete(ctx, sn.ItemID); err != nil {
		t.Fatal(err)
	}
	return &forkFix{f: f, r: r, key: key, cred: cred, jump: jump, web: web, added: added}
}

// fork runs a whole fork of cfg's vault, as hop vault fork does once the
// daemon is stopped.
func fork(t *testing.T, cfg Config, discardOld bool) *ForkResult {
	t.Helper()
	release(cfg)
	p, err := PrepareFork(context.Background(), cfg, ForkOptions{})
	if err != nil {
		t.Fatalf("prepare: %v", err)
	}
	defer p.Close()
	if _, err := p.Generate([]byte(forkPassword), ""); err != nil {
		t.Fatal(err)
	}
	res, err := p.Commit(context.Background(), discardOld)
	if err != nil {
		t.Fatalf("commit: %v", err)
	}
	return res
}

// itemsByName is a snapshot's items by type and name, with their IDs.
func itemsByName(snap model.Snapshot) map[string]model.ID {
	out := map[string]model.ID{}
	for _, h := range snap.Hosts {
		out["host:"+h.Name] = h.ItemID
	}
	for _, k := range snap.Keys {
		out["key:"+k.Name] = k.ItemID
	}
	for _, c := range snap.Credentials {
		out["credential:"+c.Name] = c.ItemID
	}
	for _, s := range snap.Snippets {
		out["snippet:"+s.Name] = s.ItemID
	}
	for i, p := range snap.Policies {
		out["policy:"+string(rune('0'+i))] = p.ItemID
	}
	return out
}

// A3c: an orphaned server-backed vault forks into a local-only vault with
// new account, vault, device and item IDs; references follow the new IDs;
// the queued changes are kept as the device showed them; the old vault is
// kept, whole, as a backup; and the new vault works as any local vault.
func TestForkOrphanedVault(t *testing.T) {
	ctx := context.Background()
	x := forkFixture(t)
	cfg := x.f.cfg
	before := snapshot(t, x.f.s)
	if len(before.Marks) == 0 {
		t.Fatal("setup: nothing queued")
	}
	oldIDs := map[model.ID]bool{}
	for _, id := range itemsByName(before) {
		oldIDs[id] = true
	}
	old := idsOf(t, cfg)
	oldVault := x.f.s.state.VaultID
	res := fork(t, cfg, false)

	if res.Old.AccountID != old.acct || res.Old.DeviceID != old.dev || res.Old.VaultID != oldVault {
		t.Errorf("old IDs %+v; want %v %v %v", res.Old, old.acct, oldVault, old.dev)
	}
	if res.New.AccountID == old.acct || res.New.VaultID == oldVault || res.New.DeviceID == old.dev || res.New.AccountID.IsZero() {
		t.Errorf("new IDs %+v reuse or lack an old one", res.New)
	}
	if res.Pending != 3 || res.Held != 0 || res.Hosts != 3 || res.Keys != 1 || res.Credentials != 1 || res.Snippets != 0 || res.Policies != 1 {
		t.Errorf("plan counts: %+v", res.ForkPlan)
	}
	if !strings.HasPrefix(filepath.Base(res.Backup), filepath.Base(cfg.DataDir)+".forked-") || res.Discarded {
		t.Errorf("backup %q discarded %v", res.Backup, res.Discarded)
	}

	s := open(t, cfg)
	info := s.Info()
	if info.Locked || info.AccountID != res.New.AccountID.String() || info.DeviceID != res.New.DeviceID.String() {
		t.Fatalf("new vault: %+v", info)
	}
	if _, err := s.ServerInfo(); !errors.Is(err, ErrNotServerBacked) {
		t.Errorf("the new vault is not local-only: %v", err)
	}
	snap := snapshot(t, s)
	if snap.Marks != nil {
		t.Errorf("marks in a local vault: %v", snap.Marks)
	}
	got := itemsByName(snap)
	want := []string{"host:added", "host:jump", "host:web", "key:jump-key", "credential:db-login", "policy:0"}
	if len(got) != len(want) {
		t.Errorf("items %v; want %v", got, want)
	}
	for _, n := range want {
		id, ok := got[n]
		if !ok {
			t.Errorf("%s is missing", n)
		}
		if oldIDs[id] {
			t.Errorf("%s kept its old item ID", n)
		}
	}
	web := hostNamed(t, snap, "web")
	if web.KeyID != got["key:jump-key"] || web.CredentialID != got["credential:db-login"] || web.JumpHostID != got["host:jump"] ||
		!slices.Equal(web.Addresses, []string{"10.0.0.5"}) {
		t.Errorf("web's references did not follow: %+v", web)
	}
	if j := hostNamed(t, snap, "jump"); j.Description != "edited, never pushed" {
		t.Errorf("the pending edit was lost: %q", j.Description)
	}
	if a := hostNamed(t, snap, "added"); a.KeyID != got["key:jump-key"] {
		t.Errorf("the pending create: %+v", a)
	}
	if snap.Keys[0].PrivateKey != x.key.PrivateKey {
		t.Error("the key's private half changed")
	}

	// A normal local-only vault: add, edit, delete, lock and unlock with
	// the device key and with the new master password.
	h := web
	h.Description = "after the fork"
	if _, err := s.PutHost(ctx, h); err != nil {
		t.Fatal(err)
	}
	extra, err := s.PutHost(ctx, model.Host{Name: "extra", Addresses: []string{"10.0.0.7"}, Port: 22, Route: "auto", AgentAccess: "allow"})
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Delete(ctx, extra.ItemID); err != nil {
		t.Fatal(err)
	}
	s.Lock()
	if err := s.Unlock(ctx); err != nil {
		t.Fatal(err)
	}
	s.Lock()
	if err := s.UnlockWithPassword(ctx, []byte(forkPassword), ""); err != nil {
		t.Fatalf("the new master password: %v", err)
	}
	release(cfg)
	s = open(t, cfg)
	if hostNamed(t, snapshot(t, s), "web").Description != "after the fork" {
		t.Error("the edit after the fork did not persist")
	}

	// The old vault, as it was, in the backup.
	bcfg := cfg
	bcfg.DataDir = res.Backup
	b := open(t, bcfg)
	if b.Info().Locked {
		t.Fatalf("the backup does not open: %+v", b.Info())
	}
	if after := snapshot(t, b); len(after.Marks) != len(before.Marks) || len(after.Hosts) != len(before.Hosts) {
		t.Errorf("the backup changed: %v hosts, %v marks", len(after.Hosts), after.Marks)
	}
	if rec, err := ForkRecord(cfg.DataDir); err != nil || rec == nil || rec.New != res.New || rec.Backup != res.Backup {
		t.Errorf("fork record %+v %v", rec, err)
	}
	if pending, err := ForkInProgress(cfg.DataDir); err != nil || pending {
		t.Errorf("in progress after it finished: %v %v", pending, err)
	}
}

// A held change is kept as the device made it, a held delete keeps its
// item, and the counts say so.
func TestForkKeepsHeldChanges(t *testing.T) {
	p := newPair(t)
	a := p.a.s
	p.conflict(t)
	if res := pushAll(t, a, p.r); res.Outcome != PushHeld {
		t.Fatalf("setup: a's push: %+v", res)
	}
	newCredential(t, a, "c3") // queued behind the held head
	res := fork(t, p.a.cfg, false)
	if res.Held != 1 || res.Pending != 1 {
		t.Errorf("counts: %+v", res.ForkPlan)
	}
	snap := snapshot(t, open(t, p.a.cfg))
	creds := map[string]model.ID{}
	for _, c := range snap.Credentials {
		creds[c.Name] = c.ItemID
	}
	if h := hostNamed(t, snap, "web"); h.CredentialID != creds["c2"] || h.CredentialID.IsZero() {
		t.Errorf("the held change (credential c2) was lost: %+v, credentials %v", h, creds)
	}
	if len(creds) != 3 || creds["c3"].IsZero() {
		t.Errorf("the change behind the held head: %v", creds)
	}
}

// A held delete is not applied: the item stays, with a warning.
func TestForkHeldDeleteKeepsTheItem(t *testing.T) {
	ctx := context.Background()
	p := newPair(t)
	a, b := p.a.s, p.b.s
	if err := a.Delete(ctx, p.host.ItemID); err != nil {
		t.Fatal(err)
	}
	editHost(t, b, p.host.ItemID, func(h *model.Host) { h.Description = "changed meanwhile" })
	pushAll(t, b, p.r)
	if res := pushAll(t, a, p.r); res.Outcome != PushHeld {
		t.Fatalf("setup: %+v", res)
	}
	res := fork(t, p.a.cfg, false)
	if res.HeldDeletes != 1 || len(res.Warnings) != 1 || !strings.Contains(res.Warnings[0], `host "web"`) {
		t.Errorf("plan: %+v", res.ForkPlan)
	}
	if h := hostNamed(t, snapshot(t, open(t, p.a.cfg)), "web"); h.Description != "changed meanwhile" {
		t.Errorf("held delete: %+v", h)
	}
}

// A vault whose logout is journaled and pending (RETIRING: a deleted
// account's devices end there) forks, with its queued changes.
func TestForkRetiringVault(t *testing.T) {
	ctx := context.Background()
	f, srv := retireFixture(t)
	newCredential(t, f.s, "queued")
	srv.down = errDown
	if res, err := f.s.Logout(ctx, retirer{srv}, LogoutOptions{DiscardPending: true}); !errors.Is(err, ErrLogoutPending) || res.State != StateRetiring {
		t.Fatalf("logout: %+v %v", res, err)
	}
	res := fork(t, f.cfg, false)
	if res.Logout != StateRetiring || res.Pending != 1 {
		t.Errorf("plan: %+v", res.ForkPlan)
	}
	s := open(t, f.cfg)
	snap := snapshot(t, s)
	if len(snap.Hosts) != 1 || snap.Hosts[0].Name != "web" || len(snap.Credentials) != 1 {
		t.Errorf("items: %v %v", names(snap), snap.Credentials)
	}
	if r, err := s.Retirement(); err != nil || r != "" {
		t.Errorf("the new vault has a logout: %q %v", r, err)
	}
	bcfg := f.cfg
	bcfg.DataDir = res.Backup
	b := open(t, bcfg)
	if r, err := b.Retirement(); err != nil || r != StateRetiring {
		t.Errorf("the backup's logout: %q %v", r, err)
	}
}

// A device the server reported as departed, or one a checkpoint revoked,
// is not forked, and nothing is written.
func TestForkRefusesARevokedDevice(t *testing.T) {
	f, _ := serverVault(t)
	addHost(t, f.s, "web")
	f.s.mu.Lock()
	err := f.s.writeReport(f.s.rec, ServerReport{AccountID: f.s.state.Account.AccountID, DeviceID: f.s.dev.ID, How: "revoked", Seq: 9})
	f.s.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	release(f.cfg)
	if _, err := PrepareFork(context.Background(), f.cfg, ForkOptions{}); !errors.Is(err, ErrForkRevoked) {
		t.Errorf("reported: %v", err)
	}
	noForkFiles(t, f.cfg)

	g, _ := serverVault(t)
	g.s.mu.Lock()
	err = writeFileAtomic(g.s.l.revokedFile(), []byte(`{"v":1}`))
	g.s.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	release(g.cfg)
	if _, err := PrepareFork(context.Background(), g.cfg, ForkOptions{}); !errors.Is(err, ErrForkRevoked) {
		t.Errorf("revoked: %v", err)
	}
	noForkFiles(t, g.cfg)

	// A local-only vault has nothing to fork from.
	h := newVault(t, testConfig(t))
	release(h.cfg)
	if _, err := PrepareFork(context.Background(), h.cfg, ForkOptions{}); !errors.Is(err, ErrNotServerBacked) {
		t.Errorf("local-only: %v", err)
	}
}

func noForkFiles(t *testing.T, cfg Config) {
	t.Helper()
	matches, _ := filepath.Glob(cfg.DataDir + ".*")
	if len(matches) != 0 {
		t.Errorf("a refused fork wrote %v", matches)
	}
}

// forkCrash is what a crash hook panics with.
type forkCrash struct{}

// crashForkAt runs a fork that stops, as a crash would, at stage: the
// process's memory is gone (the PendingFork is closed without its
// cleanup), and the files are what it left.
func crashForkAt(t *testing.T, cfg Config, stage string, discardOld bool) {
	t.Helper()
	release(cfg)
	p, err := PrepareFork(context.Background(), cfg, ForkOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := p.Generate([]byte(forkPassword), ""); err != nil {
		t.Fatal(err)
	}
	forkHook = func(s string) error {
		if s == stage {
			panic(forkCrash{})
		}
		return nil
	}
	defer func() { forkHook = nil }()
	func() {
		defer func() {
			if r := recover(); r != nil {
				if _, ok := r.(forkCrash); !ok {
					panic(r)
				}
			}
		}()
		p.Commit(context.Background(), discardOld)
		t.Fatalf("the fork did not reach %s", stage)
	}()
	forkHook = nil
	p.Close()
}

// A crash at every step: before the new vault is verified, the old vault
// is as it was, and the next run deletes the staging directory and its
// device key and can fork again; from verified on, the next run finishes
// the fork.
func TestForkCrashAtEachStep(t *testing.T) {
	for _, c := range []struct {
		stage    string
		finishes bool
		discard  bool
	}{
		{"fork:staging", false, false},
		{"fork:imported", false, false},
		{"fork:verified", true, false},
		{"fork:moved-old", true, false},
		{"fork:moved-new", true, false},
		{"fork:moved-new", true, true},
		{"fork:discarded", true, true},
	} {
		t.Run(c.stage, func(t *testing.T) {
			x := forkFixture(t)
			cfg := x.f.cfg
			before := itemsByName(snapshot(t, x.f.s))
			old := idsOf(t, cfg)
			ring := cfg.Keyring.(*memRing)
			crashForkAt(t, cfg, c.stage, c.discard)
			if pending, err := ForkInProgress(cfg.DataDir); err != nil || !pending {
				t.Fatalf("in progress after the crash: %v %v", pending, err)
			}
			if !c.finishes {
				// The old vault opens as it was in the meantime.
				if s := open(t, cfg); s.Info().Locked || len(itemsByName(snapshot(t, s))) != len(before) {
					t.Errorf("the old vault after the crash: %+v", s.Info())
				}
				release(cfg)
			}
			res, abandoned, err := ResumeFork(context.Background(), cfg)
			if err != nil {
				t.Fatal(err)
			}
			if abandoned == c.finishes || (res != nil) != c.finishes {
				t.Fatalf("resume: %+v abandoned %v", res, abandoned)
			}
			if pending, err := ForkInProgress(cfg.DataDir); err != nil || pending {
				t.Errorf("in progress after the resume: %v %v", pending, err)
			}
			if !c.finishes {
				if _, err := os.Lstat(cfg.DataDir + forkNewSuffix); !errors.Is(err, os.ErrNotExist) {
					t.Errorf("the staging directory is left: %v", err)
				}
				ring.mu.Lock()
				n := len(ring.m)
				ring.mu.Unlock()
				if n != 1 {
					t.Errorf("the keychain holds %d entries; want only the old device's", n)
				}
				res = fork(t, cfg, false)
			}
			s := open(t, cfg)
			if got := s.Info(); got.Locked || got.AccountID != res.New.AccountID.String() {
				t.Fatalf("the new vault: %+v", got)
			}
			// The fixture's snapshot already shows the queued changes.
			if got := itemsByName(snapshot(t, s)); len(got) != len(before) {
				t.Errorf("items %v; before %v", got, before)
			}
			_, err = os.Lstat(res.Backup)
			if c.discard {
				if !errors.Is(err, os.ErrNotExist) {
					t.Errorf("the discarded backup is there: %v", err)
				}
				if _, err := cfg.Keyring.Get(keychainService, slotOf(old.acct, old.dev)); err == nil {
					t.Error("the old device key is still in the keychain")
				}
			} else if err != nil {
				t.Errorf("the backup: %v", err)
			}
		})
	}
}

// --discard-old deletes the old vault and its device key once the new
// vault is verified.
func TestForkDiscardOld(t *testing.T) {
	x := forkFixture(t)
	cfg := x.f.cfg
	old := idsOf(t, cfg)
	res := fork(t, cfg, true)
	if !res.Discarded {
		t.Error("not discarded")
	}
	if _, err := os.Lstat(res.Backup); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("the backup is there: %v", err)
	}
	if _, err := cfg.Keyring.Get(keychainService, slotOf(old.acct, old.dev)); err == nil {
		t.Error("the old device key is still in the keychain")
	}
	if s := open(t, cfg); s.Info().Locked {
		t.Errorf("the new vault: %+v", s.Info())
	}
}

// The forked vault publishes to a new server with the ordinary publish
// flow, and is then server-backed under its new identity.
func TestForkThenPublish(t *testing.T) {
	ctx := context.Background()
	x := forkFixture(t)
	res := fork(t, x.f.cfg, false)
	s := open(t, x.f.cfg)
	srv := newEmptyServer(testEmail, "invite-1")
	pub, err := s.Publish(ctx, publisher{srv}, pubOpts)
	if err != nil {
		t.Fatalf("publish: %v", err)
	}
	if pub.AccountID != res.New.AccountID || pub.VaultID != res.New.VaultID {
		t.Errorf("published %+v; want %+v", pub, res.New)
	}
	sameLog(t, x.f.cfg, srv)
	if _, err := s.ServerInfo(); err != nil {
		t.Errorf("not server-backed after publishing: %v", err)
	}
}

// A refused or failed stage before verified leaves no staging directory
// and no new device key behind.
func TestForkFailureCleansUp(t *testing.T) {
	x := forkFixture(t)
	cfg := x.f.cfg
	release(cfg)
	p, err := PrepareFork(context.Background(), cfg, ForkOptions{})
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	if _, err := p.Generate([]byte(forkPassword), ""); err != nil {
		t.Fatal(err)
	}
	boom := errors.New("boom")
	forkHook = func(s string) error {
		if s == "fork:imported" {
			return boom
		}
		return nil
	}
	defer func() { forkHook = nil }()
	if _, err := p.Commit(context.Background(), false); !errors.Is(err, boom) {
		t.Fatalf("commit: %v", err)
	}
	if _, err := os.Lstat(cfg.DataDir + forkNewSuffix); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("staging left: %v", err)
	}
	ring := cfg.Keyring.(*memRing)
	ring.mu.Lock()
	n := len(ring.m)
	ring.mu.Unlock()
	if n != 1 {
		t.Errorf("keychain entries: %d", n)
	}
}
