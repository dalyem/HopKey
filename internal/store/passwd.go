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
// bootstrap entry and stores it. The old device stays in the log; phase 1
// has no revocation outside a checkpoint.
//
// A wrong password leaves the store as it was, locked or not.
func (s *Store) UnlockWithPassword(ctx context.Context, password []byte, secretKey string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	cfg, err := s.readDeviceConfig()
	if err != nil {
		return err
	}
	var sk *crypto.SecretKey
	switch {
	case secretKey != "":
		parsed, err := crypto.ParseSecretKey(secretKey)
		if err != nil {
			return fmt.Errorf("store: that is not a Secret Key: %w", err)
		}
		sk = &parsed
	case s.rec != nil:
		if sk, err = s.rec.secretKey(); err != nil {
			return err
		}
	default:
		rec, err := s.deviceStore(cfg).load()
		if err != nil {
			return ErrNeedSecretKey
		}
		sk, err = rec.secretKey()
		rec.zero()
		if err != nil {
			return ErrNeedSecretKey
		}
	}

	unlock, err := s.lockFile()
	if err != nil {
		return err
	}
	defer unlock()
	a, stored, err := s.readAccountFile()
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
	st, sec, err := s.replay(stored, acct, nil)
	if err != nil {
		return err
	}
	rec, info, err := newDeviceRecord(acct.AccountID, sk.String())
	if err != nil {
		return err
	}
	info.Name = s.deviceName()
	w, st, sec, err := vaultlog.BuildBootstrap(st, sec, info, s.now())
	if err != nil {
		return err
	}
	if err := s.commit(w, st); err != nil {
		return err
	}
	dev, err := rec.device()
	if err != nil {
		return err
	}
	if err := s.deviceStore(cfg).save(rec); err != nil {
		return fmt.Errorf("the vault is open, but %w", err)
	}
	s.dropLocked(nil)
	s.state, s.sec, s.dev, s.rec, s.devCfg = st, sec, dev, rec, cfg
	if err := s.writeAccountFile(); err != nil {
		return err
	}
	return s.recoverJournal()
}

// ChangePassword changes the master password (§10.1). It is a full
// checkpoint: new account keys, VK, item keys, salt, Secret Key and
// Recovery Key, with every grant revoked and this device the only one
// recertified as before (phase 1 revokes no devices). current must open
// the account. The candidate is journaled, sealed to the device key, before
// anything is written; the returned kit comes from a candidate verified as
// committed in the log (§5.4). The kit stays pending until AckKit.
func (s *Store) ChangePassword(ctx context.Context, current, next []byte) (Kit, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.sec == nil {
		return Kit{}, errLocked
	}
	if s.kit != nil {
		return Kit{}, ErrKitPending
	}
	unlock, err := s.lockFile()
	if err != nil {
		return Kit{}, err
	}
	defer unlock()
	if err := s.catchUp(); err != nil {
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
		NewAccount: newAcct, NewVK: newVK, Creds: creds, Time: now,
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
	if err := s.l.writeState(st); err != nil {
		return Kit{}, err
	}
	s.state, s.sec = st, sec
	// Committed. Finish from the journal, as a restart would: it verifies
	// that this candidate is the entry in the log, updates account.json and
	// the stored Secret Key, and makes the kit pending.
	if err := s.writeAccountFile(); err != nil {
		return Kit{}, fmt.Errorf("the password change is committed, but %w; run hop unlock, then hop passwd to see your new Emergency Kit", err)
	}
	if err := s.recoverJournal(); err != nil {
		return Kit{}, fmt.Errorf("the password change is committed, but %w; run hop passwd to see your new Emergency Kit", err)
	}
	if s.kit == nil || s.kit.SecretKey != kit.SecretKey {
		return Kit{}, errors.New("store: the committed checkpoint is not the one this change journaled")
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

// AckKit records that the user has the pending kit: its journal is deleted.
func (s *Store) AckKit() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.state == nil {
		return errLocked
	}
	unlock, err := s.lockFile()
	if err != nil {
		return err
	}
	defer unlock()
	if err := s.removeJournalUpTo(s.state.Head.Seq); err != nil {
		return err
	}
	s.kit = nil
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
// so they are kept as they are; the new Secret Key and Recovery Key, which
// the log does not hold, are sealed to this device's KEM key.
type journalFile struct {
	V        int                 `json:"v"`
	Seq      uint64              `json:"seq,string"`
	H        crypto.Hash         `json:"h"`
	DeviceID model.ID            `json:"device_id"`
	Wire     json.RawMessage     `json:"wire"`
	Kit      crypto.HPKEEnvelope `json:"kit"`
}

const labelJournal = "hopkey/v1/local-journal"

func journalInfo(dev model.ID, seq uint64, h crypto.Hash) []byte {
	info := append(crypto.LP([]byte(labelJournal)), crypto.LP(dev[:])...)
	info = append(info, crypto.U64(seq)...)
	return append(info, crypto.LP(h[:])...)
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
	env, err := crypto.SealHPKE(s.dev.KEM.PublicKey().Bytes(), journalInfo(s.dev.ID, seq, h), nil, pt)
	if err != nil {
		return err
	}
	b, err := json.Marshal(journalFile{V: 1, Seq: seq, H: h, DeviceID: s.dev.ID, Wire: wire, Kit: env})
	if err != nil {
		return err
	}
	return writeFileAtomic(s.l.journalFile(seq), b)
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

func (s *Store) removeJournalUpTo(seq uint64) error {
	seqs, err := s.journalSeqs()
	if err != nil {
		return err
	}
	for _, j := range seqs {
		if j <= seq {
			if err := os.Remove(s.l.journalFile(j)); err != nil && !errors.Is(err, os.ErrNotExist) {
				return err
			}
		}
	}
	return syncDir(s.l.journal())
}

// recoverJournal settles every journaled checkpoint candidate against the
// verified log (§5.4, §10.1). The caller holds the file lock and the store
// is unlocked.
//
//   - The log holds the candidate's H at its seq: it committed. Its kit
//     becomes pending and the stored Secret Key is brought up to date.
//   - The log holds another entry at that seq: it can never commit, and the
//     committed entry has been verified, so the candidate is deleted.
//   - The log ends just before it and the head is still its prev: the
//     identical entry is written again, after the transition algorithm has
//     verified it, and it is then committed as above.
//
// A candidate sealed to another device (left behind before a password
// unlock replaced the device key) has no readable kit; it is deleted once
// the log has settled its seq.
func (s *Store) recoverJournal() error {
	seqs, err := s.journalSeqs()
	if err != nil {
		return err
	}
	for _, seq := range seqs {
		b, err := os.ReadFile(s.l.journalFile(seq))
		if err != nil {
			return err
		}
		var j journalFile
		if err := json.Unmarshal(b, &j); err != nil || j.V != 1 || j.Seq != seq {
			return fmt.Errorf("%w: journal %s does not parse", ErrCorrupt, filepath.Base(s.l.journalFile(seq)))
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
			if !w.Entry.Prev.Equal(head.H) || j.DeviceID != s.dev.ID {
				// It cannot apply to this head, and this device did not
				// write it: nothing can commit it now.
				if err := os.Remove(s.l.journalFile(seq)); err != nil {
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
		w, err := s.l.readEntry(seq)
		if err != nil {
			return err
		}
		h, err := w.Entry.Hash()
		if err != nil {
			return err
		}
		if !h.Equal(j.H) {
			// Superseded: the entry the log verified at this seq is another.
			if err := os.Remove(s.l.journalFile(seq)); err != nil {
				return err
			}
			continue
		}
		if j.DeviceID != s.dev.ID {
			if err := os.Remove(s.l.journalFile(seq)); err != nil {
				return err
			}
			continue
		}
		pt, err := crypto.OpenHPKE(s.dev.KEM, j.Kit, journalInfo(j.DeviceID, seq, j.H), nil)
		if err != nil {
			return fmt.Errorf("%w: journal %d: the kit does not open", ErrCorrupt, seq)
		}
		var kit Kit
		err = json.Unmarshal(pt, &kit)
		clear(pt)
		if err != nil {
			return fmt.Errorf("%w: journal %d: %v", ErrCorrupt, seq, err)
		}
		s.kit = &kit // seqs ascend: the newest committed change wins
	}
	if s.kit != nil && s.rec.SecretKey != s.kit.SecretKey && s.kit.AccountID == s.state.Account.AccountID.String() {
		if err := s.checkKitSK(); err != nil {
			return err
		}
		s.rec.SecretKey = s.kit.SecretKey
		if err := s.deviceStore(s.devCfg).save(s.rec); err != nil {
			return fmt.Errorf("storing the new Secret Key: %w", err)
		}
	}
	return nil
}

// checkKitSK makes sure the kit's Secret Key parses before it replaces the
// stored one.
func (s *Store) checkKitSK() error {
	if _, err := crypto.ParseSecretKey(s.kit.SecretKey); err != nil {
		return fmt.Errorf("%w: journaled Secret Key does not parse", ErrCorrupt)
	}
	return nil
}
