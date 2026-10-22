package store

import (
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
// saved and the new device stays listed as stale, so the next hop passwd
// revokes it if it committed.
func (s *Store) UnlockWithPasswordRemote(ctx context.Context, r Remote, password []byte, secretKey string) error {
	if r == nil {
		return errors.New("store: no server")
	}
	return s.unlockWithPassword(ctx, r, password, secretKey)
}

func (s *Store) unlockWithPassword(ctx context.Context, r Remote, password []byte, secretKey string) (err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.owner == nil {
		return errClosed
	}
	cfg, err := s.readDeviceConfig()
	if err != nil {
		return err
	}
	// The device key this device has now, if it can still be read.
	var old *deviceRecord
	if s.rec != nil {
		old = s.rec.clone()
	} else if rec, err := s.deviceStore(cfg).load(); err == nil {
		old = rec
	}
	defer func() {
		if old != nil {
			old.zero()
		}
	}()
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

	unlock, err := s.lockFile()
	if err != nil {
		return err
	}
	defer unlock()
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
	st, sec, repaired, err := s.replay(stored, raw, acct, nil)
	if err != nil {
		return err
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
	// The new device counts as stale until its key is saved: if this stops
	// after the bootstrap commits, the next hop passwd revokes it.
	next := cfg
	if next.DeviceID.IsZero() && old != nil {
		next.DeviceID = old.DeviceID
	}
	next.StaleDevices = append(slices.Clone(cfg.StaleDevices), rec.DeviceID)
	// From here device.json may be ahead of memory. If the replacement
	// fails and the store stays unlocked with the old key, memory takes the
	// file's bookkeeping, so the next hop passwd revokes the new device.
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
	} else if st, sec, err = s.bootstrapRemote(ctx, r, st, sec, info); err != nil {
		return err
	}
	// The new record is used only once it is durable (§11).
	if err := s.deviceStore(cfg).storeDurably(rec); err != nil {
		return fmt.Errorf("store: the new device key was not saved: %w", err)
	}
	s.dropLocked(nil)
	s.state, s.sec, s.dev, s.rec, s.devCfg, s.repaired, s.server = st, sec, dev, rec, next, repaired, server
	// device.json still names the old device: reconciling moves it to the
	// stale list and takes the new one off.
	if err := s.reconcileDevice(); err != nil {
		return err
	}
	if err := s.writeAccountFile(); err != nil {
		return err
	}
	if err := s.settleAtUnlock(); err != nil {
		return err
	}
	return s.recoverJournal()
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
// the server's log shows it, verified. Outbox records are settled later, by
// settleAtUnlock. The caller holds s.mu and the file lock.
func (s *Store) bootstrapRemote(ctx context.Context, r Remote, st *vaultlog.State, sec *vaultlog.Secrets, info vaultlog.DeviceInfo) (*vaultlog.State, *vaultlog.Secrets, error) {
	catchUp := func() error {
		for {
			entries, head, err := r.Since(ctx, st.Head.Seq)
			if err != nil {
				return err
			}
			before := st.Head.Seq
			st, sec, err = s.applyEntries(st, sec, nil, entries, false)
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
			return nil, nil, err
		}
		w, _, _, err := vaultlog.BuildBootstrap(st, sec, info, s.now())
		if err != nil {
			return nil, nil, err
		}
		h, err := w.Entry.Hash()
		if err != nil {
			return nil, nil, err
		}
		if _, err := r.Post(ctx, w); err != nil && !errors.Is(err, ErrHeadConflict) {
			return nil, nil, err
		}
		if err := catchUp(); err != nil {
			return nil, nil, err
		}
		if st.Head.Seq >= w.Entry.Seq {
			got, err := s.entryHash(w.Entry.Seq)
			if err != nil {
				return nil, nil, err
			}
			if got.Equal(h) {
				return st, sec, nil
			}
		}
	}
	return nil, nil, errors.New("store: the bootstrap entry did not commit; another device keeps writing first")
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
		return Kit{}, errLocked
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
	// failed password unlock in this process may have recorded one there.
	if err := s.reloadDeviceConfig(); err != nil {
		return Kit{}, err
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
		return errLocked
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
// Key, durably. It reads the stored record first, so a retry after a
// failure, or after a crash, does only what is still missing. A record that
// reads back is not yet durable: a file save can rename device.key into
// place and then fail to fsync the directory. So unless a save of this kit
// fully succeeded (kitSKDurable), the record found is made durable again
// before it is relied on. The record in memory changes only after that.
// The caller holds the file lock.
func (s *Store) persistKitSK() error {
	k := s.kit
	if _, err := crypto.ParseSecretKey(k.SecretKey); err != nil {
		s.skErr = fmt.Errorf("%w: the journaled Secret Key does not parse", ErrCorrupt)
		return s.skErr
	}
	ds := s.deviceStore(s.devCfg)
	if cur, err := ds.load(); err == nil {
		done := cur.DeviceID == s.rec.DeviceID && cur.SecretKey == k.SecretKey
		cur.zero()
		if done {
			if !s.kitSKDurable {
				if err := ds.sync(); err != nil {
					s.skErr = err
					return err
				}
			}
			s.rec.SecretKey, s.skErr, s.kitSKDurable = k.SecretKey, nil, true
			return nil
		}
	}
	s.kitSKDurable = false
	next := s.rec.clone()
	next.SecretKey = k.SecretKey
	if err := ds.save(next); err != nil {
		next.zero()
		s.skErr = err
		return err
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
