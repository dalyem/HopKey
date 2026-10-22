package store

import (
	"bytes"
	"context"
	"errors"
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

// revokeOn posts to r a checkpoint, built by s, that revokes victim: what
// hop auth devices revoke on another device does (§10.1).
func revokeOn(t *testing.T, s *Store, r *fakeRemote, victim model.ID) {
	t.Helper()
	pull(t, s, r)
	sk, err := crypto.NewSecretKey()
	if err != nil {
		t.Fatal(err)
	}
	rk, err := crypto.NewRecoveryKey()
	if err != nil {
		t.Fatal(err)
	}
	vk, err := crypto.NewSymKey()
	if err != nil {
		t.Fatal(err)
	}
	s.mu.Lock()
	acct, err := crypto.GenerateAccountKeys(s.state.Account.AccountID, s.state.Account.AKV+1)
	if err != nil {
		s.mu.Unlock()
		t.Fatal(err)
	}
	creds, err := newCreds([]byte(testPassword), &sk, &rk, acct)
	if err != nil {
		s.mu.Unlock()
		t.Fatal(err)
	}
	w, _, _, err := vaultlog.BuildCheckpoint(s.state, s.sec, s.dev, vaultlog.CheckpointParams{
		NewAccount: acct, NewVK: vk, Creds: creds, Time: s.now(), Revoke: []model.ID{victim},
	})
	s.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := r.Post(context.Background(), w); err != nil {
		t.Fatal(err)
	}
}

func deviceOf(s *Store) model.ID {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.dev.ID
}

// §5.5, "Revoked here?": a checkpoint that revokes this device records a
// terminal revocation, wipes the decrypted vault and disables it, for
// reads, writes, sync and every kind of unlock, after a restart too. The
// revoking checkpoint is never written.
func TestRevocationIsTerminal(t *testing.T) {
	ctx := context.Background()
	p := newPair(t)
	a, b := p.a.s, p.b.s
	editHost(t, a, p.host.ItemID, func(h *model.Host) { h.Description = "queued before the revocation" })
	before := stateHead(t, p.a.cfg)
	revokeOn(t, b, p.r, deviceOf(a))

	if err := a.Pull(ctx, p.r); !errors.Is(err, ErrDeviceRevoked) {
		t.Fatalf("pull of a checkpoint that revokes this device: %v", err)
	}
	a.mu.Lock()
	wiped := a.state == nil && a.sec == nil && a.dev == nil && a.rec == nil
	a.mu.Unlock()
	if !wiped {
		t.Error("the decrypted vault is still in memory after the revocation")
	}
	refused := func(s *Store, when string) {
		t.Helper()
		_, err := s.Snapshot(ctx)
		check := func(op string, err error) {
			t.Helper()
			if !errors.Is(err, ErrDeviceRevoked) {
				t.Errorf("%s, %s: %v", when, op, err)
			}
		}
		check("snapshot", err)
		_, err = s.PutCredential(ctx, model.Credential{Name: "after", Username: "u", Password: "p"})
		check("put", err)
		check("delete", s.Delete(ctx, p.c1.ItemID))
		_, err = s.Head()
		check("head", err)
		check("pull", s.Pull(ctx, p.r))
		_, err = s.PushHead(ctx, p.r)
		check("push", err)
		check("unlock", s.Unlock(ctx))
		check("password unlock", s.UnlockWithPassword(ctx, []byte(testPassword), p.a.kit.SecretKey))
		check("password unlock through the server", s.UnlockWithPasswordRemote(ctx, p.r, []byte(testPassword), p.a.kit.SecretKey))
		if info := s.Info(); !info.Locked || !info.Revoked {
			t.Errorf("%s: info %+v", when, info)
		}
	}
	refused(a, "at once")

	s, err := tryOpen(t, p.a.cfg)
	if err != nil {
		t.Fatalf("open after the revocation: %v", err)
	}
	refused(s, "after a restart")
	rseq := p.r.head().Seq
	if got := stateHead(t, p.a.cfg); got.Seq != before.Seq || got.Seq >= rseq {
		t.Errorf("the head moved from %d to %d (the checkpoint is %d)", before.Seq, got.Seq, rseq)
	}
	if _, err := os.Stat(s.l.entryFile(rseq)); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("the revoking checkpoint was written: %v", err)
	}
}

// §11.2: a password unlock through the server never holds the store's
// mutex while it waits on the server. Lock is not blocked behind it,
// cancels its request, and discards a response that arrives afterwards:
// nothing from it is committed, saved or installed.
func TestLockInterruptsAPasswordUnlock(t *testing.T) {
	for _, late := range []bool{false, true} {
		name := "request cancelled"
		if late {
			name = "late response"
		}
		t.Run(name, func(t *testing.T) {
			ctx := context.Background()
			p := newPair(t)
			a, b := p.a.s, p.b.s
			editHost(t, b, p.host.ItemID, func(h *model.Host) { h.Description = "from B" })
			pushAll(t, b, p.r)
			before := stateHead(t, p.a.cfg)
			oldDev := deviceOf(a)

			entered, release, giveUp := make(chan struct{}), make(chan struct{}), make(chan struct{})
			cancelled := make(chan bool, 1)
			var once sync.Once
			p.r.onSince = func(ctx context.Context) {
				once.Do(func() {
					close(entered)
					wait := ctx.Done()
					if late {
						wait = release // the response arrives whatever the client does
					}
					select {
					case <-wait:
					case <-giveUp:
					}
					cancelled <- ctx.Err() != nil
				})
			}
			done := make(chan error, 1)
			go func() { done <- a.UnlockWithPasswordRemote(ctx, p.r, []byte(testPassword), "") }()
			<-entered
			locked := make(chan struct{})
			go func() {
				a.Lock()
				close(locked)
			}()
			select {
			case <-locked:
			case <-time.After(5 * time.Second):
				close(giveUp)
				<-done
				t.Fatal("Lock waited for the password unlock's request to the server")
			}
			close(release)
			if err := <-done; !errors.Is(err, ErrSyncInterrupted) {
				t.Errorf("password unlock across a lock: %v", err)
			}
			if !<-cancelled {
				t.Error("the lock did not cancel the request")
			}
			if got := stateHead(t, p.a.cfg); got.Seq != before.Seq {
				t.Errorf("the discarded response was committed: head %d → %d", before.Seq, got.Seq)
			}
			if stored := storedRecord(t, p.a.cfg, p.a.kit.AccountID); stored.DeviceID != oldDev {
				t.Error("the new device record was saved after the lock")
			}
			if !a.Info().Locked {
				t.Error("the store is unlocked")
			}
			if err := a.Unlock(ctx); err != nil {
				t.Fatal(err)
			}
			if deviceOf(a) != oldDev {
				t.Error("the interrupted password unlock replaced the device")
			}
			pull(t, a, p.r)
			if got, _ := verifiedHost(t, a, p.host.ItemID); got.Description != "from B" {
				t.Errorf("host after the next pull: %+v", got)
			}
		})
	}
}

// §11.1: a password unlock commits each entry it pulls together with the
// outbox records it settles, with the local_key the new record carries
// over. A crash before the new record is saved leaves no record whose
// candidate verified history has already committed.
func TestPasswordUnlockSettlesACommittedCandidate(t *testing.T) {
	ctx := context.Background()
	f, r := serverVault(t)
	s := f.s
	_, h := addHost(t, s, "web")
	pushAll(t, s, r)
	editHost(t, s, h.ItemID, func(h *model.Host) { h.Description = "committed, response lost" })
	r.onPost = func(*vaultlog.Wire) (bool, error) { return true, errLostResponse }
	if _, err := s.PushHead(ctx, r); !errors.Is(err, errLostResponse) {
		t.Fatal(err)
	}
	r.onPost = nil
	recs := records(t, s)
	if len(recs) != 1 || recs[0].live() == nil {
		t.Fatal("setup: no live candidate")
	}
	cand := recs[0].live().Seq

	s.testHook = crashAt("passwd:save")
	if err := s.UnlockWithPasswordRemote(ctx, r, []byte(testPassword), ""); !errors.Is(err, errCrash) {
		t.Fatalf("password unlock with a crash before the record is saved: %v", err)
	}
	// The store, still unlocked with the old key, moved to what was
	// committed: the settled edit stays visible.
	if got, _ := hostByID(t, s, h.ItemID); got.Description != "committed, response lost" {
		t.Errorf("host in the overlay after the failed password unlock: %+v", got)
	}
	if got := stateHead(t, f.cfg); got.Seq < cand {
		t.Fatalf("the candidate's entry was not committed: head %d, candidate %d", got.Seq, cand)
	}
	if files := outboxFiles(t, f.cfg.DataDir); len(files) != 0 {
		t.Errorf("the record survived the commit that verified its candidate: %v", files)
	}
	s = open(t, f.cfg)
	if got, _ := verifiedHost(t, s, h.ItemID); got.Description != "committed, response lost" {
		t.Errorf("host %+v", got)
	}
	if lost, err := s.LostIntents(); err != nil || lost != 0 {
		t.Errorf("lost %d, %v", lost, err)
	}
	if res := pushAll(t, s, r); res.Outcome != PushEmpty {
		t.Fatalf("push: %+v", res)
	}
}

// Every unlock fails closed when settling the outbox fails: the device key
// unlock and the password unlock both leave the store locked.
func TestUnlockFailsClosedOnASettlementError(t *testing.T) {
	ctx := context.Background()
	f := newVault(t, testConfig(t))
	if err := os.WriteFile(filepath.Join(f.cfg.DataDir, "vault", "outbox", "1.json"), []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := f.s.UnlockWithPassword(ctx, []byte(testPassword), f.kit.SecretKey); !errors.Is(err, ErrCorrupt) {
		t.Errorf("password unlock: %v", err)
	}
	if _, err := f.s.Snapshot(ctx); !errors.Is(err, model.ErrLocked) {
		t.Errorf("a password unlock that could not settle the outbox left the store unlocked: %v", err)
	}
	if _, err := tryOpen(t, f.cfg); !errors.Is(err, ErrCorrupt) {
		t.Errorf("open: %v", err)
	}
}

// §11.1: a failed directory fsync after wal.json is renamed into place
// leaves the commit uncertain. The store locks, the journal stays, and the
// next unlock finishes it.
func TestWALInstallFsyncFailureLocks(t *testing.T) {
	ctx := context.Background()
	f, _ := serverVault(t)
	s := f.s
	vault := s.l.vault()
	failed := false
	syncDir = func(dir string) error {
		if dir == vault && !failed && walExists(t, f.cfg) {
			failed = true
			return errors.New("injected directory fsync failure")
		}
		return fsyncDir(dir)
	}
	t.Cleanup(func() { syncDir = fsyncDir })
	if _, err := s.PutCredential(ctx, model.Credential{Name: "c", Username: "u", Password: "p"}); err == nil || !failed {
		t.Fatalf("put with the journal's fsync failing: %v (failed %v)", err, failed)
	}
	if _, err := s.Snapshot(ctx); !errors.Is(err, model.ErrLocked) {
		t.Errorf("the store stayed unlocked past an uncertain commit: %v", err)
	}
	if !walExists(t, f.cfg) {
		t.Error("the journal is gone")
	}
	syncDir = fsyncDir
	s = open(t, f.cfg)
	if recs := records(t, s); len(recs) != 1 || walExists(t, f.cfg) {
		t.Errorf("after the replay: %d records, journal there %v", len(recs), walExists(t, f.cfg))
	}
}

// A journal still in place when a commit starts is never overwritten: the
// commit fails, the store locks, and the next unlock replays it.
func TestWALOutstandingIsNotOverwritten(t *testing.T) {
	ctx := context.Background()
	f, _ := serverVault(t)
	s := f.s
	meta, err := canonjson.Marshal(outboxMeta{V: outboxVersion, Next: 1, Lost: 5})
	if err != nil {
		t.Fatal(err)
	}
	wal, err := canonjson.Marshal(walFile{V: walVersion, Ops: []walOp{{Op: walPut, Path: outboxMetaRel, Data: meta}}})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(f.cfg.DataDir, "vault", "wal.json"), wal, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := s.PutCredential(ctx, model.Credential{Name: "c", Username: "u", Password: "p"}); !errors.Is(err, errWALOutstanding) {
		t.Errorf("a commit over an outstanding journal: %v", err)
	}
	if _, err := s.Snapshot(ctx); !errors.Is(err, model.ErrLocked) {
		t.Errorf("the store stayed unlocked: %v", err)
	}
	s = open(t, f.cfg)
	if lost, _ := s.LostIntents(); lost != 5 {
		t.Errorf("the outstanding journal was not replayed: lost %d", lost)
	}
	if recs := records(t, s); len(recs) != 0 {
		t.Errorf("%d records", len(recs))
	}
}

// §11.1: a replay that finds a journaled entry already in place finishes
// its durability, the file and its directory, before it goes on. The crash
// here is a failed fsync of entries/ just after the entry was linked.
func TestWALReplayMakesAnExistingEntryDurable(t *testing.T) {
	ctx := context.Background()
	f, r := serverVault(t)
	s := f.s
	_, h := addHost(t, s, "web")
	pushAll(t, s, r)
	editHost(t, s, h.ItemID, func(h *model.Host) { h.Description = "edited" })
	r.onPost = func(*vaultlog.Wire) (bool, error) { return true, errLostResponse }
	if _, err := s.PushHead(ctx, r); !errors.Is(err, errLostResponse) {
		t.Fatal(err)
	}
	r.onPost = nil
	seq := headOf(t, s).Seq + 1
	entries, entry := s.l.entries(), s.l.entryFile(seq)

	s.testHook = crashAt("wal:op:0:sync")
	if err := s.Pull(ctx, r); !errors.Is(err, errCrash) {
		t.Fatalf("pull with the entry's directory fsync failing: %v", err)
	}
	if _, err := os.Stat(entry); err != nil {
		t.Fatalf("setup: the entry was not linked: %v", err)
	}
	var mu sync.Mutex
	var dirs, files []string
	syncDir = func(dir string) error {
		mu.Lock()
		dirs = append(dirs, dir)
		mu.Unlock()
		return fsyncDir(dir)
	}
	syncFile = func(p string) error {
		mu.Lock()
		files = append(files, p)
		mu.Unlock()
		return fsyncFile(p)
	}
	t.Cleanup(func() { syncDir, syncFile = fsyncDir, fsyncFile })
	s = open(t, f.cfg)
	syncDir, syncFile = fsyncDir, fsyncFile
	if !slices.Contains(dirs, entries) {
		t.Error("the replay did not fsync entries/ for the entry it found in place")
	}
	if !slices.Contains(files, entry) {
		t.Error("the replay did not fsync the entry it found in place")
	}
	if got := headOf(t, s); got.Seq != seq || len(records(t, s)) != 0 {
		t.Errorf("after the replay: head %d, %d records", got.Seq, len(records(t, s)))
	}
}

// §11.1: a keep mine or edit replacement is checked against verified state
// before Propose returns a digest and again before Resolve clears held: a
// reference to an item that only a later queued record creates, a
// reference to a missing item, and a deploy-op blocker are refused.
func TestReplacementIsCheckedAgainstVerifiedState(t *testing.T) {
	ctx := context.Background()
	p := newPair(t)
	a := p.a.s
	p.conflict(t)
	if res := pushAll(t, a, p.r); res.Outcome != PushHeld || res.Hold.Cause != merge.CauseGuardedConflict {
		t.Fatalf("push: %+v", res)
	}
	later := newCredential(t, a, "c3") // queued behind the held head
	missing, err := vaultlog.NewID()
	if err != nil {
		t.Fatal(err)
	}
	cur, _ := verifiedHost(t, a, p.host.ItemID)
	held := records(t, a)[0]
	for name, ref := range map[string]model.ID{"a later queued create": later.ItemID, "a missing item": missing} {
		edited := cloneHost(cur)
		edited.CredentialID = ref
		if _, err := a.Propose(Resolution{Choice: merge.ChoiceEdit, Edited: &edited}); !errors.Is(err, ErrReplacementRefused) {
			t.Errorf("%s: propose: %v", name, err)
		}
		// The digest of that replacement, as a client that skipped Propose
		// would compute it: Resolve checks again.
		repl, err := merge.Edit(held.Intent, merge.CauseGuardedConflict, mergeItem(t, &cur), mergeItem(t, &edited), nil)
		if err != nil {
			t.Fatal(err)
		}
		d, err := merge.ResolveDigest(held.N, repl)
		if err != nil {
			t.Fatal(err)
		}
		if err := a.Resolve(Resolution{Choice: merge.ChoiceEdit, Edited: &edited, Confirm: d}); !errors.Is(err, ErrReplacementRefused) {
			t.Errorf("%s: resolve: %v", name, err)
		}
	}
	if recs := records(t, a); !recs[0].Held || len(recs) != 2 {
		t.Fatal("a refused replacement changed the outbox")
	}
	edited := cloneHost(cur)
	edited.CredentialID = p.c2.ItemID
	prop, err := a.Propose(Resolution{Choice: merge.ChoiceEdit, Edited: &edited})
	if err != nil {
		t.Fatal(err)
	}
	if err := a.Resolve(Resolution{Choice: merge.ChoiceEdit, Edited: &edited, Confirm: prop.Digest}); err != nil {
		t.Fatal(err)
	}
	if res := pushAll(t, a, p.r); res.Outcome != PushEmpty {
		t.Fatalf("push: %+v", res)
	}

	// Keep mine of a held delete, once a deploy op names the host.
	q := newPair(t)
	a, b := q.a.s, q.b.s
	if err := a.Delete(ctx, q.host.ItemID); err != nil {
		t.Fatal(err)
	}
	editHost(t, b, q.host.ItemID, func(h *model.Host) { h.Description = "changed meanwhile" })
	pushAll(t, b, q.r)
	if res := pushAll(t, a, q.r); res.Outcome != PushHeld || res.Hold.Cause != merge.CauseDeleteChanged {
		t.Fatalf("push: %+v", res)
	}
	fp, err := vaultlog.SSHFingerprint(q.key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	opID, err := vaultlog.NewID()
	if err != nil {
		t.Fatal(err)
	}
	direct(t, a, q.r, vaultlog.Changes{Deploy: []vaultlog.DeployOp{{OpID: opID, Action: vaultlog.ActionDeploy, SSHPKFp: fp,
		KeyItemID: q.key.ItemID, KeyItemVersion: 1, Targets: []vaultlog.Target{{HostItemID: q.host.ItemID, State: vaultlog.TargetPending}}}}})
	if _, err := a.Propose(Resolution{Choice: merge.ChoiceKeepMine}); !errors.Is(err, ErrReplacementRefused) {
		t.Errorf("keep mine of a delete a deploy op blocks: propose: %v", err)
	}
	held = records(t, a)[0]
	cur, _ = verifiedHost(t, a, q.host.ItemID)
	repl, err := merge.KeepMine(held.Intent, merge.CauseDeleteChanged, mergeItem(t, &cur))
	if err != nil {
		t.Fatal(err)
	}
	d, err := merge.ResolveDigest(held.N, repl)
	if err != nil {
		t.Fatal(err)
	}
	if err := a.Resolve(Resolution{Choice: merge.ChoiceKeepMine, Confirm: d}); !errors.Is(err, ErrReplacementRefused) {
		t.Errorf("keep mine of a delete a deploy op blocks: resolve: %v", err)
	}
	if recs := records(t, a); !recs[0].Held {
		t.Error("a refused keep mine cleared held")
	}
}

// §11: init stores the device record durably and reads it back. A keychain
// that keeps another value under the account's name stops init before a
// vault exists that this device cannot open.
func TestInitReadsTheDeviceRecordBack(t *testing.T) {
	cfg := testConfig(t)
	ring := &staleRing{memRing: newMemRing()}
	cfg.Keyring = ring
	p, err := PrepareInit(cfg, InitOptions{Password: []byte(testPassword)})
	if err != nil {
		t.Fatal(err)
	}
	if err := ring.memRing.Set(keychainService, "device:"+p.Kit().AccountID, "not a device record"); err != nil {
		t.Fatal(err)
	}
	if s, err := p.Commit(); err == nil {
		s.Close()
		t.Fatal("init committed while the keychain gives back another record")
	}
	if ok, err := Exists(cfg.DataDir); err != nil || ok {
		t.Errorf("a vault exists without its device record: %v %v", ok, err)
	}
}

// §11: the pending kit's Secret Key goes through the same durability and
// readback as every other device-record write, and the "already saved"
// check compares the whole record, local_key included. AckKit keeps the
// journal while the device key store holds the wrong record.
func TestAckKitKeepsTheJournalWhileTheWrongRecordIsStored(t *testing.T) {
	ctx := context.Background()
	cfg := testConfig(t)
	ring := &staleRing{memRing: newMemRing()}
	cfg.Keyring = ring
	f := newVault(t, cfg)
	user := "device:" + f.kit.AccountID
	kit, err := f.s.ChangePassword(ctx, []byte(testPassword), []byte(newPassword))
	if err != nil {
		t.Fatal(err)
	}
	if err := f.s.AckKit(); err == nil {
		t.Error("AckKit went through while the keychain gives back the old Secret Key")
	}
	if n := len(journalFiles(t, cfg)); n != 1 {
		t.Fatalf("%d journals", n)
	}

	// The new Secret Key, but another local_key.
	wrong := f.s.rec.clone()
	wrong.SecretKey = kit.SecretKey
	wrong.LocalKey = bytes.Repeat([]byte{7}, localKeySize)
	b, err := wrong.jcs()
	if err != nil {
		t.Fatal(err)
	}
	ring.memRing.Set(keychainService, user, string(b))
	if err := f.s.AckKit(); err == nil {
		t.Error("AckKit took a stored record with another local_key as saved")
	}
	if n := len(journalFiles(t, cfg)); n != 1 {
		t.Fatalf("%d journals", n)
	}

	// Once the keychain stores what it is given, AckKit goes through.
	ring.memRing.Delete(keychainService, user)
	if err := f.s.AckKit(); err != nil {
		t.Fatal(err)
	}
	stored := storedRecord(t, cfg, f.kit.AccountID)
	if n := len(journalFiles(t, cfg)); n != 0 || stored.SecretKey != kit.SecretKey || !bytes.Equal(stored.LocalKey, f.s.rec.LocalKey) {
		t.Errorf("after the ack: %d journals, stored record right %v", n, stored.SecretKey == kit.SecretKey)
	}
}
