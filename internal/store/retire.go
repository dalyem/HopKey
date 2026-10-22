package store

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/dalyem/hopkey/internal/canonjson"
	"github.com/dalyem/hopkey/internal/crypto"
	"github.com/dalyem/hopkey/internal/model"
	"github.com/dalyem/hopkey/internal/vaultlog"
)

// Logout: the retirement journal (§11.1, §9 retirement status, rev 16).
//
//	vault/retire.json = JCS({"v":1, "state":"RETIRING"|"RETIRED", "account_id":id, "vault_id":id,
//	                         "device_id":id, "outcome":""|"committed"|"departed"|"unknown",
//	                         "candidates":[{"seq":u64s, "prev":h, "h":h, "status":"live"|"committed"|"dead"}],
//	                         "wires":[wire, ...]})
//
// It is plain JCS: the candidates are public log data, and RETIRED must
// stay readable after the device record (and local_key with it) is gone. A
// local attacker who can write it can at worst make this device delete its
// own copy of the vault, which deleting the files does too.
//
// Logout refuses while a merge file, a checkpoint journal or an
// unacknowledged kit exists, and while the outbox holds anything unless
// discard-pending is given (which never overrides the first three). It
// journals the exact device_retire wire and its H under RETIRING, in one
// durable commit, locks the vault for good, and posts. The outcome comes
// from verified history, or from retire-status once the server has ended
// the session:
//
//   - Committed, or the device already left (a receipt, including a
//     revocation by a concurrent checkpoint): RETIRED is recorded, then the
//     outbox, the cache and the device record are deleted, in that order,
//     and the journal last.
//   - Dead because the head moved while the device is still active: it
//     reauthenticates, catches up through verified transitions (opening the
//     new unlock blob across a checkpoint) and journals a rebuilt candidate.
//   - Server unreachable: the logout stays pending; Logout resumes it.
//
// --local-only records RETIRED with the outcome unknown and cleans up. On
// restart, RETIRING resumes resolution (Logout) and RETIRED resumes cleanup
// (Open). Neither unlocks the vault: the resolution verifies and decrypts
// what it needs in memory of its own, never installed for the application.

var (
	// ErrLoggingOut means a logout is in progress: the vault can't be
	// unlocked. hop auth logout finishes it.
	ErrLoggingOut = errors.New("store: this device is logging out; run hop auth logout to finish")
	// ErrLoggedOut means a logout finished: the vault, its outbox and the
	// device key are gone from this machine.
	ErrLoggedOut = fmt.Errorf("%w: this device logged out", ErrNoVault)
	// ErrOutboxNotEmpty means logout found queued changes. Push them, or
	// pass --discard-pending.
	ErrOutboxNotEmpty = errors.New("store: queued changes have not reached the server; wait for them, or log out with --discard-pending")
	// ErrMergeInProgress means a login merge file exists (§4.4).
	ErrMergeInProgress = errors.New("store: a login merge is not finished; finish, pause and discard it first")
	// ErrSessionEnded is what a Retirer returns when the server has ended
	// this device's session (a retirement or a checkpoint committed) and
	// gives it no other.
	ErrSessionEnded = errors.New("store: the server ended this device's session")
	// ErrLogoutPending means the logout's outcome is not known yet (the
	// server is unreachable, or kept moving): run hop auth logout again.
	ErrLogoutPending = errors.New("store: the logout is pending")
)

const (
	retireRel     = "retire.json"
	retireVersion = 1

	StateRetiring = "RETIRING"
	StateRetired  = "RETIRED"

	OutcomeCommitted = "committed" // this device's device_retire committed
	OutcomeDeparted  = "departed"  // the device already left (a retire receipt, or a revocation)
	OutcomeUnknown   = "unknown"   // --local-only: the server was not asked

	maxRetireAttempts = 16
)

func (l layout) retireFile() string { return filepath.Join(l.vault(), retireRel) }

// Retirer is the server as a logout uses it (§9, §11.1; plan /v1/vaults,
// /v1/retire-status). Slice E implements it over HTTP. Every call that
// needs it authenticates with auth, which signs as the retiring device;
// the store is locked meanwhile, so Store.DeviceAuth is not available.
// Nothing it returns advances verified state except entries that pass the
// transition algorithm. Retire-status answers only decide local cleanup.
type Retirer interface {
	// Since and Post are Remote's, under the device's session. Both return
	// an error matching ErrSessionEnded once the server has ended it.
	Since(ctx context.Context, auth DeviceAuth, after uint64) ([]Committed, vaultlog.Head, error)
	Post(ctx context.Context, auth DeviceAuth, w *vaultlog.Wire) (vaultlog.Head, error)
	// RetireStatus is POST /v1/retire-status for the candidate H h (zero
	// when there is no live candidate).
	RetireStatus(ctx context.Context, auth DeviceAuth, h crypto.Hash) (RetireStatus, error)
	// RetirePost is POST /v1/retire-status/post: the identical retirement
	// wire, re-posted while the device is active and the head is its prev.
	RetirePost(ctx context.Context, auth DeviceAuth, w *vaultlog.Wire) (vaultlog.Head, error)
	// Reauthenticate gets a new session by a §9 device-signature challenge.
	Reauthenticate(ctx context.Context, auth DeviceAuth) error
}

// RetireStatus is the server's retire-status answer (§9).
type RetireStatus struct {
	Receipt   *DeviceReceipt // this device's permanent receipt, if it left
	Committed bool           // whether the entry with the asked H is committed
	Seq       uint64         // its seq, when committed
	Head      vaultlog.Head  // the server's head
}

// DeviceReceipt is a permanent receipt: how the device left and the entry
// that removed it.
type DeviceReceipt struct {
	DeviceID model.ID
	How      string // "retired" or "revoked"
	Seq      uint64
	H        crypto.Hash
}

// LogoutOptions are hop auth logout's flags.
type LogoutOptions struct {
	// DiscardPending logs out even with queued changes, which are lost. It
	// never overrides a merge file, a checkpoint journal or a pending kit.
	DiscardPending bool
	// LocalOnly skips the server: RETIRED with the outcome unknown.
	LocalOnly bool
}

// LogoutResult says where a logout stands.
type LogoutResult struct {
	State   string `json:"state"`             // StateRetiring or StateRetired
	Outcome string `json:"outcome,omitempty"` // for StateRetired
	// Done means the cleanup finished: nothing of the vault is left here.
	Done bool `json:"done"`
	// RevokeElsewhere means the server was not asked: if the device is
	// still listed, revoke it from another device.
	RevokeElsewhere bool `json:"revoke_elsewhere,omitempty"`
}

type retireJournal struct {
	V          int             `json:"v"`
	State      string          `json:"state"`
	AccountID  model.ID        `json:"account_id"`
	VaultID    model.ID        `json:"vault_id"`
	DeviceID   model.ID        `json:"device_id"`
	Outcome    string          `json:"outcome"`
	Candidates []candidate     `json:"candidates"`
	Wires      []canonjson.Raw `json:"wires"`
}

func (j *retireJournal) live() *candidate {
	for i := range j.Candidates {
		if j.Candidates[i].Status == statusLive {
			return &j.Candidates[i]
		}
	}
	return nil
}

// wire returns the journaled wire of candidate h. A wire whose H is not a
// listed candidate is ignored.
func (j *retireJournal) wire(h crypto.Hash) (*vaultlog.Wire, error) {
	for _, raw := range j.Wires {
		w, err := vaultlog.ParseWire(raw)
		if err != nil {
			continue
		}
		if wh, err := w.Entry.Hash(); err == nil && wh.Equal(h) {
			return w, nil
		}
	}
	return nil, fmt.Errorf("%w: the retirement journal has lost the wire of its candidate", ErrCorrupt)
}

// readRetirement replays an interrupted commit and reads vault/retire.json,
// or returns nil if there is none. The caller holds s.mu, and not the file
// lock.
func (s *Store) readRetirement() (*retireJournal, error) {
	unlock, err := s.lockFile()
	if err != nil {
		return nil, err
	}
	defer unlock()
	if err := s.replayWAL(); err != nil {
		return nil, err
	}
	return s.readRetireFile()
}

// readRetireFile reads vault/retire.json. The caller holds the file lock.
func (s *Store) readRetireFile() (*retireJournal, error) {
	b, err := os.ReadFile(s.l.retireFile())
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var j retireJournal
	if canonjson.Unmarshal(b, &j) != nil || j.V != retireVersion || (j.State != StateRetiring && j.State != StateRetired) {
		return nil, fmt.Errorf("%w: %s does not parse", ErrCorrupt, s.l.retireFile())
	}
	return &j, nil
}

// refuseRetiring fails with ErrLoggingOut while a retirement journal
// exists. It reads only the name.
func (s *Store) refuseRetiring() error {
	if _, err := os.Lstat(s.l.retireFile()); err == nil {
		return ErrLoggingOut
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

func putRetirement(t *txn, j *retireJournal) error {
	if j.Candidates == nil {
		j.Candidates = []candidate{}
	}
	if j.Wires == nil {
		j.Wires = []canonjson.Raw{}
	}
	b, err := canonjson.Marshal(j)
	if err != nil {
		return err
	}
	t.put(retireRel, b)
	return nil
}

// Retirement returns the state of a logout in progress ("" for none).
func (s *Store) Retirement() (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	j, err := s.readRetirement()
	if err != nil || j == nil {
		return "", err
	}
	return j.State, nil
}

// openRetirement handles a retirement journal at Open: RETIRING leaves the
// store locked, RETIRED finishes its cleanup and returns ErrLoggedOut.
func (s *Store) openRetirement() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	j, err := s.readRetirement()
	if err != nil || j == nil {
		return err
	}
	if s.state != nil {
		s.dropLocked(ErrLoggingOut)
	}
	s.lockErr = ErrLoggingOut
	if j.State == StateRetired {
		if err := s.cleanupRetired(); err != nil {
			return fmt.Errorf("store: finishing the logout: %w", err)
		}
		return ErrLoggedOut
	}
	return nil
}

// logoutGuards refuses a logout (§11.1). A merge file, a checkpoint
// journal and a pending kit always refuse; a non-empty outbox refuses
// unless discardPending. They read files only, so they work while the vault
// is locked. The caller holds s.mu and the file lock.
func (s *Store) logoutGuards(discardPending bool) error {
	if exists, err := s.l.mergeExists(); err != nil {
		return err
	} else if exists {
		return ErrMergeInProgress
	}
	if err := s.refuseCheckpoint(); err != nil {
		return err
	}
	if discardPending {
		return nil
	}
	if ns, err := s.l.outboxNumbers(); err != nil {
		return err
	} else if len(ns) > 0 {
		return ErrOutboxNotEmpty
	}
	return nil
}

// Logout retires this device from the account (§11.1), or resumes a logout
// in progress: RETIRING resumes its resolution, RETIRED its cleanup (opts
// are then ignored, except LocalOnly, which turns a pending RETIRING into
// RETIRED with the outcome unknown). r may be nil only for LocalOnly or a
// RETIRED cleanup. An error with ErrLogoutPending means the logout is
// journaled and stays pending; run it again.
//
// Once RETIRING is journaled the vault is locked and never unlocks again;
// the resolution works on its own verified copy.
func (s *Store) Logout(ctx context.Context, r Retirer, opts LogoutOptions) (LogoutResult, error) {
	s.syncMu.Lock()
	defer s.syncMu.Unlock()
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.owner == nil {
		return LogoutResult{}, errClosed
	}
	j, err := s.readRetirement()
	if err != nil {
		return LogoutResult{}, err
	}
	if j == nil {
		if j, err = s.beginLogout(opts); err != nil {
			return LogoutResult{}, err
		}
	} else if j.State == StateRetiring && opts.LocalOnly {
		if err := s.recordRetired(j, OutcomeUnknown); err != nil {
			return LogoutResult{}, err
		}
	}
	if j.State == StateRetired {
		return s.finishLogout(j)
	}
	if r == nil {
		return LogoutResult{State: StateRetiring}, fmt.Errorf("%w: no server", ErrLogoutPending)
	}
	return s.resolveRetirement(ctx, r, j)
}

// beginLogout runs the guards and journals the logout: RETIRED at once for
// LocalOnly, otherwise RETIRING with a device_retire candidate built from
// verified state. The vault is locked from then on. The caller holds s.mu.
func (s *Store) beginLogout(opts LogoutOptions) (*retireJournal, error) {
	unlock, err := s.lockFile()
	if err != nil {
		return nil, err
	}
	server, err := s.l.serverBacked()
	if err == nil && !server {
		err = fmt.Errorf("%w: there is no server to log out of", ErrNotServerBacked)
	}
	if err == nil {
		err = s.logoutGuards(opts.DiscardPending)
	}
	if err != nil {
		unlock()
		return nil, err
	}
	if opts.LocalOnly {
		defer unlock()
		cfg, err := s.readDeviceConfig()
		j := &retireJournal{V: retireVersion, State: StateRetired, Outcome: OutcomeUnknown}
		if err == nil {
			j.AccountID, j.DeviceID = cfg.AccountID, cfg.DeviceID
		}
		if s.state != nil {
			j.VaultID = s.state.VaultID
		}
		t := &txn{}
		if err := putRetirement(t, j); err != nil {
			return nil, err
		}
		if err := s.commitTxn(t); err != nil {
			return nil, err
		}
		s.dropLocked(ErrLoggingOut)
		return j, nil
	}
	unlock()
	// The candidate is built from the vault as verified on disk, by the same
	// load a resumed logout uses.
	v, unlock, err := s.loadVault(true)
	if err != nil {
		return nil, err
	}
	defer unlock()
	defer v.zero()
	if err := s.logoutGuards(opts.DiscardPending); err != nil {
		return nil, err
	}
	w, err := s.buildRetire(v)
	if err != nil {
		return nil, err
	}
	j := &retireJournal{V: retireVersion, State: StateRetiring, AccountID: v.st.Account.AccountID, VaultID: v.st.VaultID, DeviceID: v.dev.ID}
	if err := addRetireCandidate(j, w); err != nil {
		return nil, err
	}
	t := &txn{}
	if err := putRetirement(t, j); err != nil {
		return nil, err
	}
	if err := s.commitTxn(t); err != nil {
		return nil, err
	}
	s.dropLocked(ErrLoggingOut)
	return j, nil
}

func (s *Store) buildRetire(v *loaded) (*vaultlog.Wire, error) {
	w, _, _, err := vaultlog.BuildRetire(v.st, v.sec, v.dev, s.now())
	return w, err
}

func addRetireCandidate(j *retireJournal, w *vaultlog.Wire) error {
	h, err := w.Entry.Hash()
	if err != nil {
		return err
	}
	prev, _ := w.Entry.Prev.Get()
	b, err := w.Marshal()
	if err != nil {
		return err
	}
	j.Candidates = append(j.Candidates, candidate{Seq: w.Entry.Seq, Prev: prev, H: h, Status: statusLive})
	// Only the live candidate's wire is kept: a dead one is never posted.
	j.Wires = []canonjson.Raw{b}
	return nil
}

// recordRetired durably records RETIRED with outcome. The caller holds
// s.mu.
func (s *Store) recordRetired(j *retireJournal, outcome string) error {
	unlock, err := s.lockFile()
	if err != nil {
		return err
	}
	defer unlock()
	if err := s.hook("retire:record"); err != nil {
		return err
	}
	j.State, j.Outcome = StateRetired, outcome
	for i := range j.Candidates {
		c := &j.Candidates[i]
		if c.Status == statusLive {
			if outcome == OutcomeCommitted {
				c.Status = statusCommitted
			} else {
				c.Status = statusDead
			}
		}
	}
	t := &txn{}
	if err := putRetirement(t, j); err != nil {
		return err
	}
	return s.commitTxn(t)
}

// finishLogout runs the cleanup of a RETIRED logout. The caller holds s.mu.
func (s *Store) finishLogout(j *retireJournal) (LogoutResult, error) {
	res := LogoutResult{State: StateRetired, Outcome: j.Outcome, RevokeElsewhere: j.Outcome == OutcomeUnknown}
	if s.state != nil {
		s.dropLocked(ErrLoggingOut)
	}
	if err := s.cleanupRetired(); err != nil {
		return res, fmt.Errorf("store: the logout is recorded, but its cleanup failed (%w); run hop auth logout again", err)
	}
	res.Done = true
	return res, nil
}

// cleanupRetired deletes, in order, the outbox, the cache (every other file
// in vault/), the device record (every self record, and device.json), and
// last the retirement journal. Each step is idempotent, and a crash resumes
// the cleanup at the next Open. The caller holds s.mu; the store is locked.
func (s *Store) cleanupRetired() error {
	unlock, err := s.lockFile()
	if err != nil {
		return err
	}
	defer unlock()
	if err := s.replayWAL(); err != nil {
		return err
	}
	// The outbox, in one commit.
	ns, err := s.l.outboxNumbers()
	if err != nil {
		return err
	}
	t := &txn{}
	for _, n := range ns {
		t.remove(outboxRel(n))
	}
	if _, err := os.Lstat(s.l.outboxMeta()); err == nil {
		t.remove(outboxMetaRel)
	}
	if err := s.commitTxn(t); err != nil {
		return err
	}
	if err := s.hook("retire:outbox"); err != nil {
		return err
	}
	// The cache: everything else the vault holds, but its locks and the
	// retirement journal.
	ents, err := os.ReadDir(s.l.vault())
	if err != nil {
		return err
	}
	for _, e := range ents {
		switch e.Name() {
		case retireRel, "lock", "owner.lock":
			continue
		}
		if err := os.RemoveAll(filepath.Join(s.l.vault(), e.Name())); err != nil {
			return err
		}
	}
	if err := syncDir(s.l.vault()); err != nil {
		return err
	}
	if err := s.hook("retire:cache"); err != nil {
		return err
	}
	// The device record: every self record, then device.json.
	if cfg, err := s.readDeviceConfig(); err == nil {
		ds := s.deviceStore(cfg)
		if cfg.Store == DeviceStoreKeychain {
			for _, id := range cfg.self() {
				if err := ds.deleteSlot(id); err != nil {
					return fmt.Errorf("deleting the device key of %v: %w", id, err)
				}
			}
			for _, id := range cfg.StaleDevices {
				ds.deleteSlot(id) // best effort: a stale device's key is useless here
			}
		}
	}
	for _, name := range []string{"device.key", nextKeyName} {
		if err := os.Remove(filepath.Join(s.l.data, name)); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	if err := s.hook("retire:device"); err != nil {
		return err
	}
	if err := os.Remove(s.l.deviceConfig()); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if err := syncDir(s.l.data); err != nil {
		return err
	}
	if err := s.hook("retire:journal"); err != nil {
		return err
	}
	if err := os.Remove(s.l.retireFile()); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return syncDir(s.l.vault())
}

// resolveRetirement resolves RETIRING (§11.1) and, once RETIRED, cleans up.
// It loads its own verified copy of the vault and never installs it. The
// caller holds s.mu, which every request to the server runs without.
func (s *Store) resolveRetirement(ctx context.Context, r Retirer, j *retireJournal) (LogoutResult, error) {
	pending := LogoutResult{State: StateRetiring}
	v, unlock, err := s.loadVault(true)
	if err != nil {
		return pending, err
	}
	unlock()
	defer v.zero()
	if v.dev.ID != j.DeviceID || v.st.VaultID != j.VaultID {
		return pending, fmt.Errorf("%w: the retirement journal names another device or vault", ErrCorrupt)
	}
	key := &sessionAuth{key: v.dev.Sig}
	defer key.close()
	auth := key.auth(v.st.Account.AccountID, v.dev.ID)

	// outside runs a request without s.mu; owner says the store is still
	// open when it returns.
	outside := func(f func() error) error {
		s.mu.Unlock()
		err := f()
		s.mu.Lock()
		if s.owner == nil {
			return errClosed
		}
		return err
	}
	for attempt := 0; attempt < maxRetireAttempts; attempt++ {
		var entries []Committed
		var head vaultlog.Head
		after := v.st.Head.Seq
		err := outside(func() (err error) {
			if err := s.hook("retire:since"); err != nil {
				return err
			}
			entries, head, err = r.Since(ctx, auth, after)
			return err
		})
		switch {
		case errors.Is(err, ErrSessionEnded):
			outcome, err := s.retireStatus(ctx, r, auth, j, outside)
			if err != nil {
				return pending, err
			}
			if outcome != "" {
				if err := s.recordRetired(j, outcome); err != nil {
					return pending, err
				}
				return s.finishLogout(j)
			}
			continue
		case err != nil:
			return pending, fmt.Errorf("%w: %w", ErrLogoutPending, err)
		}
		outcome, w, err := s.retireVerified(v, j, entries, head)
		if err != nil {
			return pending, err
		}
		if outcome != "" {
			if err := s.recordRetired(j, outcome); err != nil {
				return pending, err
			}
			return s.finishLogout(j)
		}
		if w == nil {
			continue // another page to verify
		}
		err = outside(func() error {
			if err := s.hook("retire:post"); err != nil {
				return err
			}
			_, err := r.Post(ctx, auth, w)
			if errors.Is(err, ErrSessionEnded) {
				_, err = r.RetirePost(ctx, auth, w)
			}
			return err
		})
		if err != nil && !errors.Is(err, ErrHeadConflict) && !errors.Is(err, ErrSessionEnded) {
			return pending, fmt.Errorf("%w: %w", ErrLogoutPending, err)
		}
	}
	return pending, fmt.Errorf("%w: the retirement did not settle after %d attempts", ErrLogoutPending, maxRetireAttempts)
}

// retireVerified applies one page of verified history to the logout's own
// copy of the vault (each entry committed with what it settles) and decides
// from it: an outcome, or the wire to post (the live candidate again, or a
// rebuilt one, journaled first), or neither when the server's head is not
// reached yet. The caller holds s.mu.
func (s *Store) retireVerified(v *loaded, j *retireJournal, entries []Committed, head vaultlog.Head) (string, *vaultlog.Wire, error) {
	unlock, err := s.lockFile()
	if err != nil {
		return "", nil, err
	}
	defer unlock()
	before := v.st.Head.Seq
	st, sec, err := s.applyEntries(v.st, v.sec, v.dev, nil, entries, v.rec)
	v.st, v.sec = st, sec
	if rev := (*vaultlog.RevokedError)(nil); errors.As(err, &rev) {
		// A concurrent checkpoint revoked this device: it has left.
		return OutcomeDeparted, nil, nil
	}
	if err != nil {
		return "", nil, err
	}
	// Verified history settles the live candidate.
	if c := j.live(); c != nil && c.Seq <= v.st.Head.Seq {
		h, err := s.entryHash(c.Seq)
		if err != nil {
			return "", nil, err
		}
		if h.Equal(c.H) {
			return OutcomeCommitted, nil, nil
		}
		c.Status = statusDead
		j.Wires = []canonjson.Raw{}
		t := &txn{}
		if err := putRetirement(t, j); err != nil {
			return "", nil, err
		}
		if err := s.commitTxn(t); err != nil {
			return "", nil, err
		}
	}
	if _, active := v.st.Devices[v.dev.ID]; !active {
		return OutcomeDeparted, nil, nil
	}
	if head.Seq > v.st.Head.Seq {
		if v.st.Head.Seq == before {
			return "", nil, fmt.Errorf("%w: the server reports head %d but returned no entry past %d", ErrLogoutPending, head.Seq, before)
		}
		return "", nil, nil
	}
	if head.Seq < v.st.Head.Seq || !head.H.Equal(v.st.Head.H) {
		return "", nil, fmt.Errorf("%w: the server's head (seq %d) does not match this device's (seq %d)", ErrLogoutPending, head.Seq, v.st.Head.Seq)
	}
	if c := j.live(); c != nil {
		w, err := j.wire(c.H)
		return "", w, err
	}
	// Every candidate is dead: rebuild against the new verified state, and
	// journal it before it is posted.
	w, err := s.buildRetire(v)
	if err != nil {
		return "", nil, err
	}
	if err := addRetireCandidate(j, w); err != nil {
		return "", nil, err
	}
	t := &txn{}
	if err := putRetirement(t, j); err != nil {
		return "", nil, err
	}
	if err := s.commitTxn(t); err != nil {
		return "", nil, err
	}
	if err := s.hook("retire:rebuilt"); err != nil {
		return "", nil, err
	}
	return "", w, nil
}

// retireStatus asks retire-status once the session has ended (§9). It
// returns the outcome its receipt or commit status gives, or "" after
// re-posting the identical wire (the device is active and the head is still
// its prev) or reauthenticating (the head moved, so verified history decides
// next). The answers are not verified: they only decide local cleanup. The
// caller holds s.mu.
func (s *Store) retireStatus(ctx context.Context, r Retirer, auth DeviceAuth, j *retireJournal, outside func(func() error) error) (string, error) {
	var h crypto.Hash
	c := j.live()
	if c != nil {
		h = c.H
	}
	var st RetireStatus
	if err := outside(func() (err error) {
		if err := s.hook("retire:status"); err != nil {
			return err
		}
		st, err = r.RetireStatus(ctx, auth, h)
		return err
	}); err != nil {
		return "", fmt.Errorf("%w: %w", ErrLogoutPending, err)
	}
	if rc := st.Receipt; rc != nil && rc.DeviceID == j.DeviceID {
		if c != nil && rc.How == "retired" && rc.H.Equal(c.H) {
			return OutcomeCommitted, nil
		}
		return OutcomeDeparted, nil
	}
	if c != nil && st.Committed {
		return OutcomeCommitted, nil
	}
	if c != nil && st.Head.Seq+1 == c.Seq && st.Head.H.Equal(c.Prev) {
		w, err := j.wire(c.H)
		if err != nil {
			return "", err
		}
		err = outside(func() error {
			_, err := r.RetirePost(ctx, auth, w)
			return err
		})
		if err != nil && !errors.Is(err, ErrHeadConflict) {
			return "", fmt.Errorf("%w: %w", ErrLogoutPending, err)
		}
		return "", nil
	}
	if err := outside(func() error { return r.Reauthenticate(ctx, auth) }); err != nil {
		return "", fmt.Errorf("%w: %w", ErrLogoutPending, err)
	}
	return "", nil
}
