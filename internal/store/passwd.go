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
	"strconv"
	"strings"

	"github.com/dalyem/hopkey/internal/crypto"
	"github.com/dalyem/hopkey/internal/model"
	"github.com/dalyem/hopkey/internal/vaultlog"
)

// UnlockWithPassword is the path for a lost or broken device key (§4.4): it
// opens pw_blob with the master password and the Secret Key (secretKey, or
// the one stored with the device key when secretKey is ""), verifies the
// log with the account keys it yields, and then adds a new device key by a
// bootstrap entry and stores it. The old device stays in the log, recorded
// in device.json as stale, and the next hop passwd revokes it.
//
// The new device is recorded in device.json as the pending replacement
// before its bootstrap is built, and installed (named as this device, with
// pending cleared, in one write) once its record is saved. An attempt that
// stops in between leaves it pending; the next one resolves it first: a
// replacement whose bootstrap is in the verified log and whose record can
// be read is installed instead of enrolling another device, and any other
// is abandoned, its record discarded and the device recorded as stale.
//
// A kit from a committed password change that is still waiting to be
// confirmed is sealed to the old device key. If that key can still be read,
// the kit is sealed to the new one too before the old one is replaced. If it
// cannot, the journal is kept and Info warns that its kit is lost.
//
// A wrong password leaves the store as it was, locked or not.
//
// The new device record keeps the old one's local_key when the old record
// is readable, so queued outbox records stay valid (§11). If it is not,
// every queued record is sealed under a key that is gone: they are deleted
// and their number is recorded before anything else is written, and Info
// and LostIntents report it until AckLostIntents.
//
// A server-backed vault needs the server for the bootstrap: use
// UnlockWithPasswordRemote.
func (s *Store) UnlockWithPassword(ctx context.Context, password []byte, secretKey string) error {
	return s.unlockWithPassword(ctx, nil, password, secretKey)
}

// UnlockWithPasswordRemote is UnlockWithPassword for a server-backed vault:
// it catches up with the server through verified transitions, posts the
// bootstrap entry there, and uses it only once it is verified from the
// server's log. If the post fails or its outcome is unknown, nothing is
// saved and the new device stays pending, so the next attempt abandons it
// and the hop passwd after revokes it if it committed.
//
// It runs only on a locked vault, and returns ErrAlreadyUnlocked otherwise:
// it is for a lost device key. The vault stays locked until the new device
// record is saved and installed, so no read or write sees a state or an
// outbox in between, and every failure leaves it locked.
//
// A checkpoint on the server that revokes this machine (the device
// device.json names, or the pending replacement, this attempt's included)
// is met in the public stage, before anything is decrypted: the data
// directory is revoked (§5.5) and it returns ErrDeviceRevoked. So does a
// tombstone in either device's record, without asking the server anything.
//
// It waits on the server without holding the store's mutex, so Lock is
// never blocked behind it. A lock (§11.2), or an unlock with the device
// key, cancels its in-flight request and discards whatever arrives
// afterwards: it then returns ErrSyncInterrupted, having saved no device
// record and installed nothing. Verified entries it committed before stay
// committed.
func (s *Store) UnlockWithPasswordRemote(ctx context.Context, r Remote, password []byte, secretKey string) error {
	if r == nil {
		return errors.New("store: no server")
	}
	return s.unlockWithPassword(ctx, r, password, secretKey)
}

func (s *Store) unlockWithPassword(ctx context.Context, r Remote, password []byte, secretKey string) (err error) {
	if r != nil {
		// The bootstrap waits on the server without s.mu or the file lock;
		// syncMu keeps Pull and PushHead out meanwhile.
		s.syncMu.Lock()
		defer s.syncMu.Unlock()
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.owner == nil {
		return errClosed
	}
	if err := s.checkRevoked(); err != nil {
		return err
	}
	if r != nil && s.state != nil {
		return ErrAlreadyUnlocked
	}
	cfg, err := s.readDeviceConfig()
	if err != nil {
		return err
	}
	// The device key this device has now, if it can still be read: the
	// record of the device device.json names, or of its pending
	// replacement (load). A tombstone of either is a revocation whose
	// revoked.json was lost: it is as terminal as the marker (§5.5).
	var old *deviceRecord
	if s.rec != nil {
		old = s.rec.clone()
	} else if rec, err := s.deviceStore(cfg).load(); err == nil {
		old = rec
	} else if errors.Is(err, ErrDeviceRevoked) {
		s.setRevoked(err)
		return err
	} else if errors.Is(err, ErrKeyStoreUnavailable) {
		// A self record that cannot be read may be a tombstone.
		return err
	}
	defer func() {
		if old != nil {
			old.zero()
		}
	}()
	// The devices this machine is in the log as, public: the one device.json
	// names and the pending replacement an earlier attempt left, if any
	// (deviceConfig.self). A checkpoint that revokes either revokes this
	// machine (transition). Stale devices never count.
	self := cfg.self()
	var oldID model.ID
	if old != nil {
		oldID = old.DeviceID
	}
	var sk *crypto.SecretKey
	switch {
	case secretKey != "":
		parsed, err := crypto.ParseSecretKey(secretKey)
		if err != nil {
			return fmt.Errorf("store: that is not a Secret Key: %w", err)
		}
		sk = &parsed
	case old != nil:
		if sk, err = old.secretKey(); err != nil {
			return ErrNeedSecretKey
		}
	default:
		return ErrNeedSecretKey
	}

	fl := &fileHold{s: s}
	if err := fl.lock(); err != nil {
		return err
	}
	defer fl.unlock()
	defer func() {
		if rev := (*vaultlog.RevokedError)(nil); errors.As(err, &rev) {
			err = s.revoke(rev)
		}
	}()
	if err := s.replayWAL(); err != nil {
		return err
	}
	server, err := s.l.serverBacked()
	if err != nil {
		return err
	}
	if server && r == nil {
		return fmt.Errorf("%w: use the server to unlock with the password", ErrServerBacked)
	}
	a, stored, raw, err := s.readAccountFile()
	if err != nil {
		return err
	}
	acct, err := openWithPassword(a, password, sk)
	if err != nil {
		return err
	}
	if !acct.Pin().Equal(stored.Pin()) {
		return fmt.Errorf("%w: account.json does not match state.json", ErrCorrupt)
	}
	st, sec, repaired, err := s.replay(stored, raw, acct, nil, self)
	if err != nil {
		return err
	}
	// An earlier attempt left a pending replacement. Resolve it first: if
	// its bootstrap is in the verified log and its record can be read, it
	// is installed and nothing new is enrolled. Otherwise it is abandoned:
	// its record is discarded, and it is recorded as stale, so the next hop
	// passwd revokes it if its bootstrap committed. Pending is cleared in
	// the same write that names this attempt's device (next).
	next := cfg.withPending(model.ID{})
	if p := cfg.pendingID(); !p.IsZero() {
		if _, active := st.Devices[p]; active {
			if prec, err := s.deviceStore(cfg).loadID(p); err == nil {
				return s.installPending(cfg, prec, oldID, st, sec, repaired, server)
			}
		}
		var keep *deviceRecord
		if s.rec != nil && s.rec.DeviceID != p {
			keep = s.rec
		}
		if err := s.deviceStore(cfg).discard(p, keep); err != nil {
			return fmt.Errorf("store: discarding the device key of an abandoned password unlock: %w", err)
		}
		next.StaleDevices = append(next.StaleDevices, p)
	}
	rec, info, err := newDeviceRecord(acct.AccountID, sk.String())
	if err != nil {
		return err
	}
	defer func() {
		if err != nil && s.rec != rec {
			rec.zero()
		}
	}()
	info.Name = s.deviceName()
	// §11: local_key carries over from a readable record. Otherwise the
	// queued records can never be opened again: report how many are lost
	// before going on.
	if old != nil && old.V == 2 {
		copy(rec.LocalKey, old.LocalKey)
	} else if err := s.dropLostRecords(); err != nil {
		return err
	}
	dev, err := rec.device()
	if err != nil {
		return err
	}
	if old != nil {
		if oldDev, err := old.device(); err == nil {
			if err := s.resealJournals(st, oldDev, dev); err != nil {
				return err
			}
		}
	}
	// The new device is the pending replacement, durably, before its
	// bootstrap is built: from then on it is self, and if this stops, the
	// next attempt or unlock resolves it. It is installed (reconcileDevice)
	// only once its record is saved.
	next.Pending = &pendingDevice{DeviceID: rec.DeviceID}
	self = next.self()
	// From here device.json may be ahead of memory. If the replacement
	// fails and the store stays unlocked with the old key, memory takes the
	// file's bookkeeping, so the next hop passwd resolves the pending device.
	defer func() {
		if err != nil && s.state != nil {
			if c, rerr := s.readDeviceConfig(); rerr == nil {
				s.devCfg = c
			}
		}
	}()
	if err := s.writeDeviceConfig(next); err != nil {
		return err
	}
	if r == nil {
		var w *vaultlog.Wire
		if w, st, sec, err = vaultlog.BuildBootstrap(st, sec, info, s.now()); err != nil {
			return err
		}
		if err := s.commit(w, st); err != nil {
			return err
		}
	} else {
		// From here every request to the server runs outside s.mu, and a
		// lock or an unlock in the meantime discards its result. The store
		// stays locked throughout.
		rctx, gen, untrack := s.trackRequest(ctx)
		defer untrack()
		if st, sec, err = s.bootstrapRemote(rctx, r, fl, gen, st, sec, info, rec, self); err != nil {
			return err
		}
		if s.gen.Load() != gen || s.state != nil {
			return ErrSyncInterrupted
		}
	}
	if err := s.hook("passwd:save"); err != nil {
		return err
	}
	// The new record is used only once it is durable (§11).
	if err := s.deviceStore(cfg).storeDurably(rec); err != nil {
		return fmt.Errorf("store: the new device key was not saved: %w", err)
	}
	return s.install(next, rec, dev, oldID, st, sec, repaired, server)
}

// install unlocks the store with rec, the pending replacement in cfg, and
// the verified (st, sec), and installs it: device.json names it and no
// longer a pending device (reconcileDevice). A failure locks the store, as
// a failed Unlock does. The keychain entries of the device it replaced
// (cfg's DeviceID, and oldID, the record read before) go after, best
// effort: an entry left behind belongs to a stale device, which the next
// hop passwd revokes. The caller holds s.mu and the file lock.
func (s *Store) install(cfg deviceConfig, rec *deviceRecord, dev *vaultlog.LocalDevice, oldID model.ID, st *vaultlog.State, sec *vaultlog.Secrets, repaired string, server bool) error {
	if err := s.hook("passwd:install"); err != nil {
		return err
	}
	s.dropLocked(nil)
	s.state, s.sec, s.dev, s.rec, s.devCfg, s.repaired, s.server = st, sec, dev, rec, cfg, repaired, server
	s.gen.Add(1)
	if err := s.finishUnlock(); err != nil {
		s.dropLocked(err)
		return err
	}
	if s.devCfg.DeviceID == rec.DeviceID {
		ds := s.deviceStore(s.devCfg)
		for _, id := range []model.ID{cfg.DeviceID, oldID} {
			if !id.IsZero() && id != rec.DeviceID {
				ds.deleteSlot(id)
			}
		}
	}
	return nil
}

// installPending finishes the attempt that left rec, cfg's pending
// replacement, readable with its bootstrap in the verified log (st): rec is
// made durable again, as a record found on disk must be before it is used
// (upgradeRecord), and installed. The caller holds s.mu and the file lock.
func (s *Store) installPending(cfg deviceConfig, rec *deviceRecord, oldID model.ID, st *vaultlog.State, sec *vaultlog.Secrets, repaired string, server bool) error {
	if err := s.deviceStore(cfg).upgradeRecord(rec); err != nil {
		rec.zero()
		return err
	}
	dev, err := rec.device()
	if err != nil {
		rec.zero()
		return err
	}
	return s.install(cfg, rec, dev, oldID, st, sec, repaired, server)
}

// fileHold is the file lock as one operation holds it, given up and taken
// again around requests to the server (outside).
type fileHold struct {
	s       *Store
	release func()
}

func (h *fileHold) lock() error {
	release, err := h.s.lockFile()
	if err != nil {
		return err
	}
	h.release = release
	return nil
}

func (h *fileHold) unlock() {
	if h.release != nil {
		h.release()
		h.release = nil
	}
}

// outside runs f, a request to the server, without s.mu or the file lock,
// and then takes both back (§11.2). The caller holds both on a locked
// store, and holds s.mu again when outside returns; it holds the file lock
// again unless outside fails. A lock or an unlock while f ran (the
// generation gen changed, or the store is unlocked) discards f's result:
// outside returns ErrSyncInterrupted.
func (s *Store) outside(fl *fileHold, gen uint64, f func() error) error {
	fl.unlock()
	s.mu.Unlock()
	err := f()
	s.mu.Lock()
	if s.gen.Load() != gen || s.state != nil {
		return ErrSyncInterrupted
	}
	if lerr := fl.lock(); lerr != nil {
		return lerr
	}
	return err
}

// dropLostRecords deletes every queued outbox record, which no readable
// device record can open, and adds their number to the count LostIntents
// reports, in one commit (§11). The caller holds the file lock.
func (s *Store) dropLostRecords() error {
	ns, err := s.l.outboxNumbers()
	if err != nil || len(ns) == 0 {
		return err
	}
	m, err := s.readOutboxMeta()
	if err != nil {
		return err
	}
	t := &txn{}
	for _, n := range ns {
		t.remove(outboxRel(n))
		m.Next = max(m.Next, n+1)
	}
	m.Lost += uint64(len(ns))
	if err := putOutboxMeta(t, m); err != nil {
		return err
	}
	return s.commitTxn(t)
}

// bootstrapRemote catches (st, sec) up with the server through verified
// transitions, posts a bootstrap entry for info, and returns the state once
// the server's log shows it, verified. With an error it returns the last
// state it committed, (st, sec) if none. Each verified entry is committed
// with the outbox records it settles, opened with rec's local_key (carried
// over from the old record). self are the devices this machine is in the
// log as (see transition). Every request runs outside s.mu (see outside),
// and nothing is committed once the store has left generation gen or been
// unlocked. The caller holds s.mu and the file lock (fl) on a locked store.
func (s *Store) bootstrapRemote(ctx context.Context, r Remote, fl *fileHold, gen uint64, st *vaultlog.State, sec *vaultlog.Secrets, info vaultlog.DeviceInfo, rec *deviceRecord, self []model.ID) (*vaultlog.State, *vaultlog.Secrets, error) {
	catchUp := func() error {
		for {
			var entries []Committed
			var head vaultlog.Head
			after := st.Head.Seq
			if err := s.outside(fl, gen, func() (err error) {
				if err := s.hook("passwd:since"); err != nil {
					return err
				}
				entries, head, err = r.Since(ctx, after)
				return err
			}); err != nil {
				return err
			}
			before := st.Head.Seq
			var err error
			st, sec, err = s.applyEntries(st, sec, nil, self, entries, rec)
			if err != nil {
				return err
			}
			if head.Seq <= st.Head.Seq {
				return nil
			}
			if st.Head.Seq == before {
				return fmt.Errorf("store: the server reports head %d but returned no entry past %d", head.Seq, before)
			}
		}
	}
	for attempt := 0; attempt < maxPushAttempts; attempt++ {
		if err := catchUp(); err != nil {
			return st, sec, err
		}
		w, _, _, err := vaultlog.BuildBootstrap(st, sec, info, s.now())
		if err != nil {
			return st, sec, err
		}
		h, err := w.Entry.Hash()
		if err != nil {
			return st, sec, err
		}
		if err := s.outside(fl, gen, func() error {
			if _, err := r.Post(ctx, w); err != nil && !errors.Is(err, ErrHeadConflict) {
				return err
			}
			return nil
		}); err != nil {
			return st, sec, err
		}
		if err := catchUp(); err != nil {
			return st, sec, err
		}
		if st.Head.Seq >= w.Entry.Seq {
			got, err := s.entryHash(w.Entry.Seq)
			if err != nil {
				return st, sec, err
			}
			if got.Equal(h) {
				return st, sec, nil
			}
		}
	}
	return st, sec, errors.New("store: the bootstrap entry did not commit; another device keeps writing first")
}

// ChangePassword changes the master password (§10.1). It is a full
// checkpoint: new account keys, VK, item keys, salt, Secret Key and
// Recovery Key, with every grant revoked. It revokes the stale devices that
// password unlocks on this machine left behind, and only those; every
// other active device is recertified. current must open
// the account. This device's key is first saved durably in the device key
// store, and nothing is written to the log unless that succeeds. The
// candidate is journaled, sealed to the device key, before anything is
// written; the returned kit comes from a candidate verified as committed
// in the log (§5.4). The kit stays pending until AckKit.
func (s *Store) ChangePassword(ctx context.Context, current, next []byte) (Kit, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.sec == nil {
		return Kit{}, s.lockedErr()
	}
	if s.kit != nil {
		return Kit{}, ErrKitPending
	}
	if s.server {
		// A checkpoint goes to the server directly, with its own journal
		// (§10.1, §11.1); it never commits locally.
		return Kit{}, ErrServerBacked
	}
	unlock, err := s.lockFile()
	if err != nil {
		return Kit{}, err
	}
	defer unlock()
	if err := s.catchUp(); err != nil {
		return Kit{}, err
	}
	// The stale devices to revoke come from device.json, not memory: a
	// failed password unlock in this process may have left a pending
	// replacement there, which reconciling abandons and makes stale.
	if err := s.reloadDeviceConfig(); err != nil {
		return Kit{}, fmt.Errorf("store: the password was not changed: %w", err)
	}
	sk, err := s.rec.secretKey()
	if err != nil {
		return Kit{}, err
	}
	a, err := accountOf(s.state, objectDir(s.l.objects()))
	if err != nil {
		return Kit{}, err
	}
	old, err := openWithPassword(a, current, sk)
	if err != nil {
		return Kit{}, err
	}
	old.Zero()
	// This device survives the checkpoint and gets a new unlock blob, and
	// its journal is sealed to it alone. Its key must be durably in the
	// device key store before anything is built: a password unlock that
	// failed may have left there the key of a stale device, which this
	// checkpoint revokes. If the new Secret Key then fails to save and the
	// process stops, the key on disk still opens the new checkpoint and
	// its journal.
	if err := s.deviceStore(s.devCfg).storeDurably(s.rec); err != nil {
		return Kit{}, fmt.Errorf("store: the password was not changed: this device's key could not be saved durably first: %w", err)
	}

	acctID := s.state.Account.AccountID
	newSK, err := crypto.NewSecretKey()
	if err != nil {
		return Kit{}, err
	}
	defer newSK.Zero()
	newRK, err := crypto.NewRecoveryKey()
	if err != nil {
		return Kit{}, err
	}
	defer newRK.Zero()
	newAcct, err := crypto.GenerateAccountKeys(acctID, s.state.Account.AKV+1)
	if err != nil {
		return Kit{}, err
	}
	creds, err := newCreds(next, &newSK, &newRK, newAcct)
	if err != nil {
		return Kit{}, err
	}
	newVK, err := crypto.NewSymKey()
	if err != nil {
		return Kit{}, err
	}
	defer newVK.Zero()
	now := s.now()
	w, st, sec, err := vaultlog.BuildCheckpoint(s.state, s.sec, s.dev, vaultlog.CheckpointParams{
		NewAccount: newAcct, NewVK: newVK, Creds: creds, Time: now, Revoke: s.staleActive(s.devCfg),
	})
	if err != nil {
		return Kit{}, err
	}
	kit := Kit{AccountID: acctID.String(), SecretKey: newSK.String(), RecoveryKey: newRK.String(), Created: now.Time()}
	if err := s.writeJournal(w, kit); err != nil {
		return Kit{}, err
	}
	if err := s.hook("journaled"); err != nil {
		return Kit{}, err
	}
	if err := s.l.writeObjects(w); err != nil {
		return Kit{}, err
	}
	if err := s.l.writeEntry(w); err != nil {
		return Kit{}, err
	}
	if err := s.hook("entry"); err != nil {
		return Kit{}, err
	}
	if err := s.writeState(st); err != nil {
		return Kit{}, err
	}
	s.state, s.sec = st, sec
	// Committed. Finish from the journal, as a restart would: it verifies
	// that this candidate is the entry in the log, updates account.json and
	// the stored Secret Key, and makes the kit pending. A Secret Key that
	// could not be stored does not hide the kit; AckKit retries it.
	if err := s.writeAccountFile(); err != nil {
		return Kit{}, fmt.Errorf("the password change is committed, but %w; run hop unlock, then hop passwd to see your new Emergency Kit", err)
	}
	if err := s.recoverJournal(); err != nil {
		return Kit{}, fmt.Errorf("the password change is committed, but %w; run hop passwd to see your new Emergency Kit", err)
	}
	if s.kit == nil || s.kit.SecretKey != kit.SecretKey {
		return Kit{}, errors.New("store: the committed checkpoint is not the one this change journaled")
	}
	if err := s.reconcileDevice(); err != nil {
		return Kit{}, fmt.Errorf("the password change is committed, but %w", err)
	}
	return *s.kit, nil
}

// PendingKit returns the Emergency Kit of a committed password change that
// has not been confirmed, or nil.
func (s *Store) PendingKit() *Kit {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.kit == nil {
		return nil
	}
	k := *s.kit
	return &k
}

// AckKit records that the user has the pending kit: its Secret Key is
// durably in the device key store (stored, or made durable, again if an
// earlier attempt failed), and then its journal is deleted. It refuses,
// and the kit stays pending, while the Secret Key cannot be stored durably.
func (s *Store) AckKit() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.state == nil {
		return s.lockedErr()
	}
	if s.kit == nil {
		return nil
	}
	unlock, err := s.lockFile()
	if err != nil {
		return err
	}
	defer unlock()
	if err := s.persistKitSK(); err != nil {
		return fmt.Errorf("store: the new Secret Key is not saved on this device (%w), so the Emergency Kit stays pending; run hop passwd to try again", err)
	}
	if !s.kitSKDurable {
		return errors.New("store: the new Secret Key is not saved durably on this device, so the Emergency Kit stays pending; run hop passwd to try again")
	}
	if err := s.removeJournal(s.kitSeq); err != nil {
		return err
	}
	s.kit = nil
	return nil
}

// persistKitSK makes the device key store hold the pending kit's Secret
// Key, durably: the record in memory with that Secret Key, byte for byte,
// local_key included. It reads the stored record first, so a retry after a
// failure, or after a crash, does only what is still missing. A record that
// reads back is not yet durable: a file save can rename device.key into
// place and then fail to fsync the directory. So unless a save of this kit
// fully succeeded (kitSKDurable), the record found is made durable again
// before it is relied on. Anything else is stored with storeDurably, which
// rereads it. The record in memory changes only after that. The caller
// holds the file lock.
func (s *Store) persistKitSK() error {
	k := s.kit
	if _, err := crypto.ParseSecretKey(k.SecretKey); err != nil {
		s.skErr = fmt.Errorf("%w: the journaled Secret Key does not parse", ErrCorrupt)
		return s.skErr
	}
	ds := s.deviceStore(s.devCfg)
	next := s.rec.clone()
	next.SecretKey = k.SecretKey
	fail := func(err error) error {
		next.zero()
		s.skErr = err
		return err
	}
	want, err := next.jcs()
	if err != nil {
		return fail(err)
	}
	defer clear(want)
	if cur, err := ds.loadID(next.DeviceID); err == nil {
		got, err := cur.jcs()
		cur.zero()
		done := err == nil && bytes.Equal(got, want)
		clear(got)
		if done {
			if !s.kitSKDurable {
				if err := ds.sync(); err != nil {
					return fail(err)
				}
			}
			s.rec.zero()
			s.rec, s.skErr, s.kitSKDurable = next, nil, true
			return nil
		}
	}
	s.kitSKDurable = false
	if err := ds.storeDurably(next); err != nil {
		return fail(err)
	}
	s.rec.zero()
	s.rec, s.skErr, s.kitSKDurable = next, nil, true
	return nil
}

// hook is a test seam that simulates a crash at a named point.
func (s *Store) hook(stage string) error {
	if s.testHook != nil {
		return s.testHook(stage)
	}
	return nil
}

// journalFile is journal/<seq>.json, one checkpoint candidate (§10.1). The
// entry and its objects are public log data (the new account keys, VK and
// item keys travel inside it, sealed to this device and the new account),
// so they are kept as they are. The new Secret Key and Recovery Key, which
// the log does not hold, are sealed to device KEM keys: to the device that
// wrote it, and to the device a password unlock replaced that one with.
type journalFile struct {
	V     int             `json:"v"`
	Seq   uint64          `json:"seq,string"`
	H     crypto.Hash     `json:"h"`
	Wire  json.RawMessage `json:"wire"`
	Seals []journalSeal   `json:"seals"`
}

type journalSeal struct {
	DeviceID model.ID            `json:"device_id"`
	Kit      crypto.HPKEEnvelope `json:"kit"`
}

const journalVersion = 2

func (j *journalFile) seal(dev model.ID) *journalSeal {
	for i := range j.Seals {
		if j.Seals[i].DeviceID == dev {
			return &j.Seals[i]
		}
	}
	return nil
}

const labelJournal = "hopkey/v1/local-journal"

func journalInfo(dev model.ID, seq uint64, h crypto.Hash) []byte {
	info := append(crypto.LP([]byte(labelJournal)), crypto.LP(dev[:])...)
	info = append(info, crypto.U64(seq)...)
	return append(info, crypto.LP(h[:])...)
}

func sealKit(dev *vaultlog.LocalDevice, seq uint64, h crypto.Hash, pt []byte) (journalSeal, error) {
	env, err := crypto.SealHPKE(dev.KEM.PublicKey().Bytes(), journalInfo(dev.ID, seq, h), nil, pt)
	if err != nil {
		return journalSeal{}, err
	}
	return journalSeal{DeviceID: dev.ID, Kit: env}, nil
}

func (s *Store) writeJournal(w *vaultlog.Wire, kit Kit) error {
	h, err := w.Entry.Hash()
	if err != nil {
		return err
	}
	wire, err := w.Marshal()
	if err != nil {
		return err
	}
	pt, err := json.Marshal(kit)
	if err != nil {
		return err
	}
	defer clear(pt)
	seq := w.Entry.Seq
	seal, err := sealKit(s.dev, seq, h, pt)
	if err != nil {
		return err
	}
	return s.writeJournalFile(&journalFile{V: journalVersion, Seq: seq, H: h, Wire: wire, Seals: []journalSeal{seal}})
}

func (s *Store) writeJournalFile(j *journalFile) error {
	b, err := json.Marshal(j)
	if err != nil {
		return err
	}
	return writeFileAtomic(s.l.journalFile(j.Seq), b)
}

func (s *Store) readJournal(seq uint64) (*journalFile, error) {
	b, err := os.ReadFile(s.l.journalFile(seq))
	if err != nil {
		return nil, err
	}
	var j journalFile
	if err := json.Unmarshal(b, &j); err != nil || j.V != journalVersion || j.Seq != seq || len(j.Seals) == 0 {
		return nil, fmt.Errorf("%w: journal %s does not parse", ErrCorrupt, filepath.Base(s.l.journalFile(seq)))
	}
	return &j, nil
}

func (s *Store) journalSeqs() ([]uint64, error) {
	ents, err := os.ReadDir(s.l.journal())
	if err != nil {
		return nil, err
	}
	var out []uint64
	for _, e := range ents {
		num, ok := strings.CutSuffix(e.Name(), ".json")
		if seq, err := strconv.ParseUint(num, 10, 64); ok && err == nil {
			out = append(out, seq)
		}
	}
	slices.Sort(out)
	return out, nil
}

func (s *Store) removeJournal(seq uint64) error {
	if err := os.Remove(s.l.journalFile(seq)); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return syncDir(s.l.journal())
}

// currentCheckpoint reports whether j committed (the log holds its H at
// its seq) as the checkpoint that set st's credentials: its creds.gen is
// st's. Only that candidate's kit is the account's; an older one, even if
// it committed, would install a Secret Key that no longer works.
func (s *Store) currentCheckpoint(st *vaultlog.State, j *journalFile) (bool, error) {
	if j.Seq > st.Head.Seq {
		return false, nil
	}
	w, err := s.l.readEntry(j.Seq)
	if err != nil {
		return false, err
	}
	h, err := w.Entry.Hash()
	if err != nil {
		return false, err
	}
	if !h.Equal(j.H) {
		return false, nil
	}
	for _, o := range w.Entry.Ops {
		if c, ok := o.(*vaultlog.CredsOp); ok {
			return c.Gen == st.Creds.Gen, nil
		}
	}
	return false, nil
}

// resealJournals seals the kit of the current checkpoint's journal, if it
// is sealed to from, to to as well. A password unlock runs it before it
// replaces from with to. The caller holds the file lock.
func (s *Store) resealJournals(st *vaultlog.State, from, to *vaultlog.LocalDevice) error {
	seqs, err := s.journalSeqs()
	if err != nil {
		return err
	}
	for _, seq := range seqs {
		j, err := s.readJournal(seq)
		if err != nil {
			return err
		}
		ok, err := s.currentCheckpoint(st, j)
		if err != nil {
			return err
		}
		old := j.seal(from.ID)
		if !ok || old == nil || j.seal(to.ID) != nil {
			continue
		}
		pt, err := crypto.OpenHPKE(from.KEM, old.Kit, journalInfo(from.ID, seq, j.H), nil)
		if err != nil {
			return fmt.Errorf("%w: journal %d: the kit does not open", ErrCorrupt, seq)
		}
		seal, err := sealKit(to, seq, j.H, pt)
		clear(pt)
		if err != nil {
			return err
		}
		j.Seals = append(j.Seals, seal)
		if err := s.writeJournalFile(j); err != nil {
			return err
		}
	}
	return nil
}

// recoverJournal settles every journaled checkpoint candidate against the
// verified log (§5.4, §10.1). The caller holds the file lock and the store
// is unlocked.
//
//   - The log ends just before it and the head is still its prev: the
//     identical entry is written again, after the transition algorithm has
//     verified it, and it is then settled as below. A candidate this device
//     cannot read is deleted instead: it never committed and was never
//     shown, and nothing could verify it now.
//   - It committed as the checkpoint that set the current credentials: its
//     kit becomes pending and the device key store gets its Secret Key. If
//     no seal opens with this device's key (a password unlock replaced the
//     key it was sealed to), the file is kept and Info warns that the kit
//     is lost; the next hop passwd supersedes it.
//   - Anything else, superseded by another entry at its seq or by a later
//     checkpoint, is deleted without being shown.
func (s *Store) recoverJournal() error {
	s.kit, s.kitOrphaned, s.skErr, s.kitSKDurable = nil, false, nil, false
	seqs, err := s.journalSeqs()
	if err != nil {
		return err
	}
	for _, seq := range seqs {
		j, err := s.readJournal(seq)
		if err != nil {
			return err
		}
		head := s.state.Head
		if seq == head.Seq+1 {
			w, err := vaultlog.ParseWire(j.Wire)
			if err != nil {
				return fmt.Errorf("%w: journal %d: %v", ErrCorrupt, seq, err)
			}
			if h, err := w.Entry.Hash(); err != nil || !h.Equal(j.H) {
				return fmt.Errorf("%w: journal %d: entry does not match its H", ErrCorrupt, seq)
			}
			if !w.Entry.Prev.Equal(head.H) || j.seal(s.dev.ID) == nil {
				if err := s.removeJournal(seq); err != nil {
					return err
				}
				continue
			}
			objs := objectDir(s.l.objects())
			st, sec, err := vaultlog.Transition(s.state, s.sec, s.dev, w, objs)
			if err != nil {
				return fmt.Errorf("%w: journaled entry %d: %w", ErrCorrupt, seq, err)
			}
			if err := s.commit(w, st); err != nil {
				return err
			}
			s.state, s.sec = st, sec
			if err := s.writeAccountFile(); err != nil {
				return err
			}
			head = st.Head
		}
		if seq > head.Seq {
			return fmt.Errorf("%w: journal %d is ahead of the log (head %d)", ErrCorrupt, seq, head.Seq)
		}
		current, err := s.currentCheckpoint(s.state, j)
		if err != nil {
			return err
		}
		if !current {
			if err := s.removeJournal(seq); err != nil {
				return err
			}
			continue
		}
		seal := j.seal(s.dev.ID)
		if seal == nil {
			s.kitOrphaned = true
			continue
		}
		pt, err := crypto.OpenHPKE(s.dev.KEM, seal.Kit, journalInfo(s.dev.ID, seq, j.H), nil)
		if err != nil {
			return fmt.Errorf("%w: journal %d: the kit does not open", ErrCorrupt, seq)
		}
		var kit Kit
		err = json.Unmarshal(pt, &kit)
		clear(pt)
		if err != nil {
			return fmt.Errorf("%w: journal %d: %v", ErrCorrupt, seq, err)
		}
		if kit.AccountID != s.state.Account.AccountID.String() {
			return fmt.Errorf("%w: journal %d belongs to another account", ErrCorrupt, seq)
		}
		s.kit, s.kitSeq = &kit, seq
	}
	if s.kit != nil {
		// A failure is kept in skErr: the kit stays pending, AckKit retries.
		s.persistKitSK()
	}
	return nil
}
