package store

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/dalyem/hopkey/internal/canonjson"
	"github.com/dalyem/hopkey/internal/crypto"
	"github.com/dalyem/hopkey/internal/model"
	"github.com/dalyem/hopkey/internal/vaultlog"
)

// Checkpoints in a server-backed vault (§10.1, §5.4). A server-backed vault
// never commits a checkpoint locally: it journals the candidate, posts it,
// and installs it only once a pull has verified it from the server's log,
// in the same durable commit that settles the journal.
//
// Survivors are chosen by device ID when the checkpoint starts (§10.1,
// "Choosing survivors (rev 16)"): a password change keeps every active
// device (except the stale devices this machine's password unlocks left
// behind, which it revokes as phase 1 does, journaled as its targets); a
// rotation, a revocation and a recovery's follow-up keep only this device
// and the devices named in CheckpointOptions.Keep. The chosen IDs are
// journaled and reused on every rebuild, and only the ones still active
// count: a survivor or target retired meanwhile is simply gone. A device
// that first appears during a rebuild is revoked by a rotation, a
// revocation or a recovery. A password change does not decide for the
// user: it refuses to rebuild (NewDevicesError) until the call names each
// new device in CheckpointOptions.Keep or Exclude, and journals the answer.
//
// The journal is vault/checkpoint.json:
//
//	file    = JCS({"v":1, "vault_id":id, "sealed":AEAD(local_key, journal,
//	              aad = lp("hopkey/v1/checkpoint-journal") || lp(vault_id_bytes))})
//	journal = JCS({"v":1, "kind":"passwd"|"rotate"|"revoke"|"recovery", "author":id,
//	              "survivors":[id], "targets":[id],
//	              "candidates":[{"seq":u64s, "prev":h, "h":h, "status":"live"|"committed"|"dead",
//	                             "wire":wire, "secret_key":str, "recovery_key":str, "created":ts}]})
//
// A candidate holds the exact wire and the new kit secrets, and is written,
// durably, before it is posted. It is rewritten under a fresh nonce on
// every change. Only verified history settles a candidate (commitVerified):
// the entry at its seq has its H (committed) or another (dead). A dead
// candidate is kept until one commits; the commit that installs the
// committed one also drops the others, and, for a recovery's follow-up,
// ends CheckpointDue (clearRecoveryDue). The new kit is shown (PendingKit)
// only from a committed candidate, and AckKit deletes the journal once the
// new Secret Key is in the device key store.
//
// An uncertain post (a timeout, a crash) leaves the candidate live: the
// next attempt, or ResumeCheckpoint, posts the identical wire again while
// the server's head is still its prev. A 409 or a moved head makes it dead
// once the entry at its seq is verified, and the checkpoint is rebuilt with
// fresh secrets, which needs the password again.

// Checkpoint kinds, as journaled.
const (
	CheckpointPasswd   = "passwd"
	CheckpointRotate   = "rotate"
	CheckpointRevoke   = "revoke"
	CheckpointRecovery = "recovery"
)

const (
	labelCheckpointJournal = "hopkey/v1/checkpoint-journal"
	checkpointRel          = "checkpoint.json"
	checkpointVersion      = 1
)

var (
	// ErrUnknownDevice means a device named for a checkpoint is not active.
	ErrUnknownDevice = errors.New("store: no active device has that ID or name")
	// ErrAmbiguousDevice means a name given for a checkpoint matches more
	// than one active device (§10.1): name it by its device ID.
	ErrAmbiguousDevice = errors.New("store: more than one active device has that name; give its device ID instead")
	// ErrCheckpointRebuild means the journaled checkpoint did not commit and
	// the server's head has moved, so it must be rebuilt with fresh secrets
	// (§5.4), which needs the password: run the same command again.
	ErrCheckpointRebuild = errors.New("store: the pending checkpoint did not commit and must be rebuilt; run the same command again")
	// ErrNoCheckpoint means no checkpoint is journaled.
	ErrNoCheckpoint = errors.New("store: no checkpoint is pending")
	// ErrRecoveryDue means a recovery sign-in's checkpoint (§4.5) is due:
	// RecoveryCheckpoint is the only checkpoint allowed until it commits.
	ErrRecoveryDue = errors.New("store: this device signed in with the Recovery Key; set a new password first to finish the recovery")
	// ErrNoRecoveryDue means RecoveryCheckpoint was called with no recovery
	// checkpoint due.
	ErrNoRecoveryDue = errors.New("store: no recovery checkpoint is due")

	errExcludeOnlyPasswd = errors.New("store: only a password change takes Exclude, to answer the devices that appeared during it")
	errPasswdKeep        = errors.New("store: a password change keeps every device; use rotate to choose survivors")
)

// NewDevicesError means a password change must be rebuilt, and devices
// that were not active when it started are active now (§10.1: a device
// that first appears during a rebuild is not kept without the user's
// choice). Run it again naming each of Devices in CheckpointOptions.Keep
// (it survives) or Exclude (it is revoked). It matches
// ErrCheckpointRebuild.
type NewDevicesError struct {
	Devices []model.ID
}

func (e *NewDevicesError) Error() string {
	ids := make([]string, len(e.Devices))
	for i, id := range e.Devices {
		ids[i] = id.String()
	}
	return fmt.Sprintf("store: the password change must be rebuilt, and %d device(s) appeared since it started (%s); "+
		"run it again keeping or excluding each of them", len(ids), strings.Join(ids, ", "))
}

func (e *NewDevicesError) Is(target error) bool { return target == ErrCheckpointRebuild }

// CheckpointPendingError means another kind of checkpoint is journaled, or
// the same kind with other survivors: it must finish first. It matches
// ErrCheckpointPending.
type CheckpointPendingError struct {
	Kind string
}

func (e *CheckpointPendingError) Error() string {
	return fmt.Sprintf("store: a %s checkpoint with its own survivors is pending; finish it first (run it again, or hop auth resume)", e.Kind)
}

func (e *CheckpointPendingError) Is(target error) bool { return target == ErrCheckpointPending }

// CheckpointOptions are the choices of a server-backed checkpoint.
type CheckpointOptions struct {
	// Keep are the survivors besides this device (§10.1), each a device ID
	// or a name exactly one active device has. A rotation, a revocation
	// and a recovery's follow-up revoke every other active device. A
	// password change keeps every device; it takes Keep, with Exclude,
	// only to answer a NewDevicesError.
	Keep []string
	// Exclude answers a password change's NewDevicesError: the new devices
	// it names are revoked. Every new device must be in Keep or Exclude.
	// Only a password change takes it.
	Exclude []string
	// SecretKey is the account's current Secret Key, for a device that
	// stores none (enrolled by approval, §11 addendum). "" uses the stored
	// one; a device without one then fails with ErrNeedSecretKey.
	SecretKey string
}

// ChangePasswordRemote is ChangePassword for a server-backed vault: a full
// checkpoint (§10.1) with the new password, journaled, posted through r and
// installed only once verified from the server's log. It keeps every active
// device, except the stale devices of this machine's password unlocks. The
// returned kit comes from the verified commit and stays pending until
// AckKit. It refuses while a recovery's checkpoint is due (ErrRecoveryDue).
// Called again after an interrupted attempt, it finishes the journaled
// password change (reposting it, or rebuilding it with fresh secrets and
// the same survivors), and returns the kit once it is verified.
//
// A rebuild that would revoke a device which appeared after the change
// started stops with a NewDevicesError: the call then names each such
// device in opts.Keep or opts.Exclude. Otherwise Keep and Exclude are
// refused.
func (s *Store) ChangePasswordRemote(ctx context.Context, r Remote, current, next []byte, opts CheckpointOptions) (Kit, error) {
	return s.runCheckpoint(ctx, r, &ckptRequest{kind: CheckpointPasswd, verify: current, password: next, sk: opts.SecretKey,
		keep: opts.Keep, exclude: opts.Exclude})
}

// Rotate is hop auth rotate (§10.1, §5.3 device_retire): a checkpoint that
// rotates every credential without changing the password, and revokes every
// active device but this one and opts.Keep. password is the current master
// password, which the new credentials keep.
func (s *Store) Rotate(ctx context.Context, r Remote, password []byte, opts CheckpointOptions) (Kit, error) {
	if len(opts.Exclude) > 0 {
		return Kit{}, errExcludeOnlyPasswd
	}
	return s.runCheckpoint(ctx, r, &ckptRequest{kind: CheckpointRotate, verify: password, password: password, sk: opts.SecretKey, keep: opts.Keep})
}

// RevokeDevices is hop auth devices revoke (§10.1): a checkpoint that
// revokes the devices ids names (each a device ID or a unique name; none
// may be this device or in opts.Keep). As a response to possible
// compromise, it keeps only this device and opts.Keep: every other active
// device is revoked too. password is the current master password, which the
// new credentials keep.
func (s *Store) RevokeDevices(ctx context.Context, r Remote, password []byte, ids []string, opts CheckpointOptions) (Kit, error) {
	if len(ids) == 0 {
		return Kit{}, errors.New("store: name at least one device to revoke")
	}
	if len(opts.Exclude) > 0 {
		return Kit{}, errExcludeOnlyPasswd
	}
	return s.runCheckpoint(ctx, r, &ckptRequest{kind: CheckpointRevoke, verify: password, password: password, sk: opts.SecretKey, keep: opts.Keep, targets: ids})
}

// RecoveryCheckpoint is the checkpoint a recovery sign-in owes (§4.5): new
// credentials under the password next, keeping only this device and
// opts.Keep. It is the only checkpoint allowed while
// ServerInfo.CheckpointDue, and the commit that installs it ends that.
func (s *Store) RecoveryCheckpoint(ctx context.Context, r Remote, next []byte, opts CheckpointOptions) (Kit, error) {
	if len(opts.Exclude) > 0 {
		return Kit{}, errExcludeOnlyPasswd
	}
	return s.runCheckpoint(ctx, r, &ckptRequest{kind: CheckpointRecovery, password: next, keep: opts.Keep})
}

// ResumeCheckpoint finishes a journaled checkpoint without a password, as
// far as that is possible (§5.4): a candidate the server committed is
// installed and its kit returned; one whose prev is still the server's head
// is posted again, identically. One that can no longer commit needs a
// rebuild, which needs the password: ErrCheckpointRebuild. With nothing
// journaled it returns ErrNoCheckpoint, or the pending kit if one is.
func (s *Store) ResumeCheckpoint(ctx context.Context, r Remote) (Kit, error) {
	return s.runCheckpoint(ctx, r, &ckptRequest{})
}

// CheckpointStatus describes the journaled checkpoint.
type CheckpointStatus struct {
	Kind      string     `json:"kind"`
	Survivors []model.ID `json:"survivors"`
	Targets   []model.ID `json:"targets,omitempty"`
	// Live is the candidate posted, or about to be, whose outcome verified
	// history has not settled yet.
	Live *Head `json:"live,omitempty"`
	// Committed means a candidate is verified as committed: its kit is
	// pending (PendingKit) until AckKit.
	Committed bool `json:"committed,omitempty"`
}

// PendingCheckpoint returns the journaled checkpoint, or nil.
func (s *Store) PendingCheckpoint() (*CheckpointStatus, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.state == nil {
		if ok, err := s.l.checkpointExists(); err != nil || !ok {
			return nil, err
		}
		return nil, s.lockedErr()
	}
	unlock, err := s.lockFile()
	if err != nil {
		return nil, err
	}
	defer unlock()
	j, err := s.readCheckpointJournal(s.rec, s.state.VaultID)
	if err != nil || j == nil {
		return nil, err
	}
	st := &CheckpointStatus{Kind: j.Kind, Survivors: slices.Clone(j.Survivors), Targets: slices.Clone(j.Targets)}
	for _, c := range j.Candidates {
		switch c.Status {
		case statusLive:
			st.Live = &Head{Seq: c.Seq, H: c.H.String()}
		case statusCommitted:
			st.Committed = true
		}
	}
	return st, nil
}

// ckptJournal is the sealed journal (see above).
type ckptJournal struct {
	V          int             `json:"v"`
	Kind       string          `json:"kind"`
	Author     model.ID        `json:"author"`
	Survivors  []model.ID      `json:"survivors"`
	Targets    []model.ID      `json:"targets"`
	Candidates []ckptCandidate `json:"candidates"`
}

// ckptCandidate is one journaled candidate: its entry's seq, prev and H,
// what verified history says about it, the exact wire, and the kit secrets
// it carries.
type ckptCandidate struct {
	Seq         uint64          `json:"seq,string"`
	Prev        crypto.Hash     `json:"prev"`
	H           crypto.Hash     `json:"h"`
	Status      string          `json:"status"`
	Wire        canonjson.Raw   `json:"wire"`
	SecretKey   string          `json:"secret_key"`
	RecoveryKey string          `json:"recovery_key"`
	Created     model.Timestamp `json:"created"`
}

type ckptFile struct {
	V       int                 `json:"v"`
	VaultID model.ID            `json:"vault_id"`
	Sealed  crypto.AEADEnvelope `json:"sealed"`
}

func (l layout) checkpointFile() string { return filepath.Join(l.vault(), checkpointRel) }

// checkpointExists reports whether vault/checkpoint.json exists. It reads
// only the name, so it works while the vault is locked.
func (l layout) checkpointExists() (bool, error) {
	_, err := os.Lstat(l.checkpointFile())
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	return err == nil, err
}

func checkpointAAD(vaultID model.ID) []byte {
	return append(crypto.LP([]byte(labelCheckpointJournal)), crypto.LP(vaultID[:])...)
}

func (j *ckptJournal) live() *ckptCandidate {
	for i := range j.Candidates {
		if j.Candidates[i].Status == statusLive {
			return &j.Candidates[i]
		}
	}
	return nil
}

func (j *ckptJournal) committed() *ckptCandidate {
	for i := range j.Candidates {
		if j.Candidates[i].Status == statusCommitted {
			return &j.Candidates[i]
		}
	}
	return nil
}

// zero clears the kit secrets j holds in memory.
func (j *ckptJournal) zero() {
	if j == nil {
		return
	}
	for i := range j.Candidates {
		j.Candidates[i].SecretKey, j.Candidates[i].RecoveryKey = "", ""
	}
}

// putCheckpointJournal adds vault/checkpoint.json, sealed under rec's
// local_key for vault vaultID, to t.
func putCheckpointJournal(t *txn, rec *deviceRecord, vaultID model.ID, j *ckptJournal) error {
	key, err := rec.localKey()
	if err != nil {
		return err
	}
	defer key.Zero()
	j.V = checkpointVersion
	for _, l := range []*[]model.ID{&j.Survivors, &j.Targets} {
		if *l == nil {
			*l = []model.ID{}
		}
	}
	if j.Candidates == nil {
		j.Candidates = []ckptCandidate{}
	}
	pt, err := canonjson.Marshal(j)
	if err != nil {
		return err
	}
	defer clear(pt)
	env, err := crypto.SealAEAD(key, pt, checkpointAAD(vaultID))
	if err != nil {
		return err
	}
	b, err := canonjson.Marshal(ckptFile{V: checkpointVersion, VaultID: vaultID, Sealed: env})
	if err != nil {
		return err
	}
	t.put(checkpointRel, b)
	return nil
}

// readCheckpointJournal opens vault/checkpoint.json with rec's local_key,
// or returns nil when there is none. Anything that does not open or parse
// is ErrCorrupt: only hop writes it. The caller holds the file lock.
func (s *Store) readCheckpointJournal(rec *deviceRecord, vaultID model.ID) (*ckptJournal, error) {
	b, err := os.ReadFile(s.l.checkpointFile())
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	bad := fmt.Errorf("%w: %s does not open", ErrCorrupt, s.l.checkpointFile())
	var f ckptFile
	if canonjson.Unmarshal(b, &f) != nil || f.V != checkpointVersion || f.VaultID != vaultID {
		return nil, bad
	}
	if rec == nil {
		return nil, s.lockedErr()
	}
	key, err := rec.localKey()
	if err != nil {
		return nil, err
	}
	defer key.Zero()
	pt, err := crypto.OpenAEAD(key, f.Sealed, checkpointAAD(vaultID))
	if err != nil {
		return nil, bad
	}
	defer clear(pt)
	var j ckptJournal
	if canonjson.Unmarshal(pt, &j) != nil || j.V != checkpointVersion {
		return nil, bad
	}
	switch j.Kind {
	case CheckpointPasswd, CheckpointRotate, CheckpointRevoke, CheckpointRecovery:
	default:
		return nil, bad
	}
	live, committed := 0, 0
	for _, c := range j.Candidates {
		switch c.Status {
		case statusLive:
			live++
		case statusCommitted:
			committed++
		case statusDead:
		default:
			return nil, bad
		}
	}
	if live > 1 || committed > 1 || (committed == 1 && len(j.Candidates) != 1) || j.Author.IsZero() || !slices.Contains(j.Survivors, j.Author) {
		return nil, bad
	}
	return &j, nil
}

// wire parses the candidate's wire and checks it against its seq, prev
// and H.
func (c *ckptCandidate) wire() (*vaultlog.Wire, error) {
	w, err := vaultlog.ParseWire(c.Wire)
	if err != nil {
		return nil, fmt.Errorf("%w: the checkpoint journal's candidate at seq %d: %v", ErrCorrupt, c.Seq, err)
	}
	h, err := w.Entry.Hash()
	if err != nil || !h.Equal(c.H) || w.Entry.Seq != c.Seq || !w.Entry.Prev.Equal(c.Prev) {
		return nil, fmt.Errorf("%w: the checkpoint journal's candidate at seq %d does not match its H", ErrCorrupt, c.Seq)
	}
	return w, nil
}

// settleCheckpointJournal adds to t what the verified entry w, with H h,
// leading to st, decides for the journaled checkpoint (§5.4): a live
// candidate at w's seq is committed if it is w and dead otherwise. Once one
// is committed the superseded ones are dropped, and a recovery's follow-up
// authored by this device ends CheckpointDue (clearRecoveryDue), all in t,
// the commit that installs w. rec opens the journal. The caller holds s.mu
// and the file lock.
func (s *Store) settleCheckpointJournal(t *txn, w *vaultlog.Wire, h crypto.Hash, st *vaultlog.State, rec *deviceRecord) error {
	if ok, err := s.l.checkpointExists(); err != nil || !ok {
		return err
	}
	j, err := s.readCheckpointJournal(rec, st.VaultID)
	if err != nil || j == nil {
		return err
	}
	defer j.zero()
	changed, committed := false, false
	for i := range j.Candidates {
		c := &j.Candidates[i]
		if c.Status != statusLive || c.Seq != w.Entry.Seq {
			continue
		}
		changed = true
		if c.H.Equal(h) {
			c.Status, committed = statusCommitted, true
		} else {
			c.Status = statusDead
		}
	}
	if !changed {
		return nil
	}
	if committed {
		// The committed candidate is verified: the superseded ones go now,
		// and only now (§5.4).
		if err := s.commitCandidate(t, j, w, st); err != nil {
			return err
		}
	}
	return putCheckpointJournal(t, rec, st.VaultID, j)
}

// commitCandidate adds to t what a verified commit of j's committed
// candidate w, leading to st, settles: the superseded candidates go now,
// and only now (§5.4), and a recovery's follow-up authored by this device
// ends CheckpointDue (clearRecoveryDue). The caller writes j to t.
func (s *Store) commitCandidate(t *txn, j *ckptJournal, w *vaultlog.Wire, st *vaultlog.State) error {
	j.Candidates = slices.DeleteFunc(j.Candidates, func(c ckptCandidate) bool { return c.Status != statusCommitted })
	if j.Kind == CheckpointRecovery && s.dev != nil && s.dev.ID == j.Author {
		if _, err := s.clearRecoveryDue(t, w, st); err != nil {
			return err
		}
	}
	return nil
}

// recoverServerJournal makes the kit of a committed journaled checkpoint
// pending (§10.1: shown only once verified), and drops a journal whose
// committed checkpoint a later one superseded: its Secret Key no longer
// opens anything. A pending server kit goes with that journal, so nothing
// shows or stores superseded credentials; with no journal left, a pending
// server kit goes too. A live candidate at a seq verified history has
// passed is settled here as the commit would have (a crash in an older
// build). Pull runs it whenever verified history advances. The caller
// holds the file lock, and the store is unlocked.
func (s *Store) recoverServerJournal() error {
	j, err := s.readCheckpointJournal(s.rec, s.state.VaultID)
	if err != nil {
		return err
	}
	if j == nil {
		s.dropServerKit()
		return nil
	}
	defer j.zero()
	if c := j.live(); c != nil && c.Seq <= s.state.Head.Seq {
		// Every verified commit settles the candidate at its seq
		// (commitVerified); one that did not (an install by another path)
		// is settled here from the verified log.
		got, err := s.entryHash(c.Seq)
		if err != nil {
			return err
		}
		t := &txn{}
		if got.Equal(c.H) {
			c.Status = statusCommitted
			w, err := c.wire()
			if err != nil {
				return err
			}
			if err := s.commitCandidate(t, j, w, s.state); err != nil {
				return err
			}
		} else {
			c.Status = statusDead
		}
		if err := putCheckpointJournal(t, s.rec, s.state.VaultID, j); err != nil {
			return err
		}
		if err := s.commitTxn(t); err != nil {
			return err
		}
	}
	c := j.committed()
	if c == nil {
		return nil
	}
	w, err := c.wire()
	if err != nil {
		return err
	}
	current := c.Seq <= s.state.Head.Seq
	if current {
		got, err := s.entryHash(c.Seq)
		if err != nil {
			return err
		}
		current = got.Equal(c.H)
	}
	if !current {
		return fmt.Errorf("%w: the checkpoint journal's committed candidate at seq %d is not in the verified log", ErrCorrupt, c.Seq)
	}
	gen := uint32(0)
	for _, o := range w.Entry.Ops {
		if cr, ok := o.(*vaultlog.CredsOp); ok {
			gen = cr.Gen
		}
	}
	if gen != s.state.Creds.Gen {
		// A later checkpoint set other credentials: this kit would install
		// a Secret Key that no longer works. The kit in memory goes with
		// the journal, whether or not the removal commits: a journal left
		// behind is dropped by the next pull or unlock.
		s.dropServerKit()
		t := &txn{}
		t.remove(checkpointRel)
		return s.commitTxn(t)
	}
	if s.kit != nil && s.kitServer && s.kitSeq == c.Seq && s.kit.SecretKey == c.SecretKey {
		// Already pending: persistKitSK has run (a failure is in skErr).
		return nil
	}
	s.kit = &Kit{AccountID: s.state.Account.AccountID.String(), SecretKey: c.SecretKey, RecoveryKey: c.RecoveryKey, Created: c.Created.Time()}
	s.kitSeq, s.kitServer, s.kitKind = c.Seq, true, j.Kind
	// A failure is kept in skErr: the kit stays pending, AckKit retries.
	s.persistKitSK()
	return nil
}

// dropServerKit forgets a pending server-backed checkpoint's kit (not a
// local password change's), and why its Secret Key was not stored.
func (s *Store) dropServerKit() {
	if s.kit == nil || !s.kitServer {
		return
	}
	s.kit.SecretKey, s.kit.RecoveryKey = "", ""
	s.kit, s.kitServer, s.kitKind, s.kitSeq = nil, false, "", 0
	s.skErr, s.kitSKDurable = nil, false
}

// ckptRequest is one call's checkpoint. kind "" resumes whatever is
// journaled, without a password.
type ckptRequest struct {
	kind     string
	verify   []byte // the current password, checked first; a recovery has none
	password []byte // the password of the new credentials
	sk       string // the current Secret Key, when the device stores none
	keep     []string
	exclude  []string // a password change's answer to NewDevicesError
	targets  []string
	verified bool
	// matched means the journal was started, or found to be req's, earlier
	// in this call: a rebuild reuses its survivors without resolving the
	// names in keep again against a state that may have gained a device.
	matched bool
}

// runCheckpoint drives one checkpoint to its verified commit (see above):
// pull, then journal and post the candidate (or post a live one again),
// then pull, until the journal holds a committed candidate. Every request
// to the server runs without s.mu (syncMu keeps Pull and PushHead out), and
// a lock discards what is in flight (§11.2).
func (s *Store) runCheckpoint(ctx context.Context, r Remote, req *ckptRequest) (Kit, error) {
	if r == nil {
		return Kit{}, errors.New("store: no server")
	}
	if err := s.lockSync(); err != nil {
		return Kit{}, err
	}
	defer s.syncMu.Unlock()
	// Each rebuild means another device committed first; a live candidate
	// posted again and again without committing means the server is not
	// committing it.
	for attempt := 0; attempt < 2*maxPushAttempts; attempt++ {
		if err := s.pullLocked(ctx, r); err != nil {
			return Kit{}, err
		}
		ctx2, gen, done, err := s.syncContext(ctx)
		if err != nil {
			return Kit{}, err
		}
		kit, w, err := s.prepareCheckpoint(gen, req, attempt < maxPushAttempts)
		if err != nil || w == nil {
			done()
			return kit, err
		}
		if err := s.hook("checkpoint:post"); err != nil {
			done()
			return Kit{}, err
		}
		_, err = r.Post(ctx2, w)
		done()
		if err != nil && !errors.Is(err, ErrHeadConflict) {
			return Kit{}, err
		}
		if err := s.hook("checkpoint:posted"); err != nil {
			return Kit{}, err
		}
	}
	return Kit{}, errors.New("store: the server did not commit the checkpoint; run the same command again")
}

// prepareCheckpoint decides the next step after a pull: the kit of a
// committed candidate, or the wire to post, journaled first. The caller
// holds syncMu.
func (s *Store) prepareCheckpoint(gen uint64, req *ckptRequest, mayBuild bool) (Kit, *vaultlog.Wire, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.current(gen); err != nil {
		return Kit{}, nil, err
	}
	unlock, err := s.lockFile()
	if err != nil {
		return Kit{}, nil, err
	}
	defer unlock()
	if s.kit != nil {
		if s.kitServer && (req.kind == "" || req.kind == s.kitKind) {
			return *s.kit, nil, nil
		}
		return Kit{}, nil, ErrKitPending
	}
	if s.kitOrphaned {
		return Kit{}, nil, ErrCheckpointPending
	}
	if seqs, err := s.journalSeqs(); err != nil && !errors.Is(err, os.ErrNotExist) {
		return Kit{}, nil, err
	} else if len(seqs) > 0 {
		return Kit{}, nil, ErrCheckpointPending
	}
	j, err := s.readCheckpointJournal(s.rec, s.state.VaultID)
	if err != nil {
		return Kit{}, nil, err
	}
	defer func() { j.zero() }()
	if j == nil {
		if req.kind == "" {
			return Kit{}, nil, ErrNoCheckpoint
		}
		if j, err = s.newCheckpointJournal(req); err != nil {
			return Kit{}, nil, err
		}
		req.matched = true
	} else if req.kind != "" && !req.matched {
		if err := s.sameCheckpoint(j, req); err != nil {
			return Kit{}, nil, err
		}
		req.matched = true
	}
	if j.committed() != nil {
		// Settled, but recoverServerJournal found its kit superseded or
		// could not make it pending: nothing is left to post.
		return Kit{}, nil, fmt.Errorf("%w: the committed checkpoint's kit can't be shown", ErrCheckpointPending)
	}
	if c := j.live(); c != nil {
		head := s.state.Head
		if c.Seq != head.Seq+1 || !c.Prev.Equal(head.H) {
			return Kit{}, nil, fmt.Errorf("%w: the checkpoint journal has a live candidate at seq %d that verified history has not settled", ErrCorrupt, c.Seq)
		}
		// An uncertain outcome: the identical wire again (§5.4).
		w, err := c.wire()
		return Kit{}, w, err
	}
	if req.kind == "" {
		return Kit{}, nil, ErrCheckpointRebuild
	}
	if !mayBuild {
		return Kit{}, nil, fmt.Errorf("store: the checkpoint did not commit after %d attempts; another device keeps writing first", maxPushAttempts)
	}
	if j.Kind == CheckpointPasswd {
		if err := s.decideNewDevices(j, req); err != nil {
			return Kit{}, nil, err
		}
	}
	if err := s.verifyCheckpointPassword(req); err != nil {
		return Kit{}, nil, err
	}
	w, err := s.buildCandidate(j, req)
	if err != nil {
		return Kit{}, nil, err
	}
	if err := s.hook("checkpoint:journal"); err != nil {
		return Kit{}, nil, err
	}
	t := &txn{}
	if err := putCheckpointJournal(t, s.rec, s.state.VaultID, j); err != nil {
		return Kit{}, nil, err
	}
	if err := s.commitTxn(t); err != nil {
		return Kit{}, nil, err
	}
	return Kit{}, w, nil
}

// newCheckpointJournal starts the journal of req, unwritten: its kind, this
// device as author, and the survivors (and targets) chosen now, by device
// ID, from the verified state (§10.1). The caller holds the file lock.
func (s *Store) newCheckpointJournal(req *ckptRequest) (*ckptJournal, error) {
	sf, err := s.l.readServerFile()
	if err != nil {
		return nil, err
	}
	due := sf != nil && sf.RecoveryGen != 0
	switch {
	case due && req.kind != CheckpointRecovery:
		return nil, ErrRecoveryDue
	case !due && req.kind == CheckpointRecovery:
		return nil, ErrNoRecoveryDue
	case req.kind == CheckpointPasswd && len(req.keep)+len(req.exclude) > 0:
		// Nothing has appeared since it started: there is nothing to answer.
		return nil, errPasswdKeep
	}
	// The stale devices come from device.json, as phase 1's password change
	// reads them.
	if err := s.reloadDeviceConfig(); err != nil {
		return nil, err
	}
	survivors, targets, err := s.chooseSurvivors(req)
	if err != nil {
		return nil, err
	}
	return &ckptJournal{V: checkpointVersion, Kind: req.kind, Author: s.dev.ID, Survivors: survivors, Targets: targets}, nil
}

// chooseSurvivors resolves req's survivors and targets against the
// verified state. The caller holds s.mu.
func (s *Store) chooseSurvivors(req *ckptRequest) (survivors, targets []model.ID, err error) {
	self := s.dev.ID
	if _, ok := s.state.Devices[self]; !ok {
		return nil, nil, fmt.Errorf("%w: this device is not active", ErrDeviceKey)
	}
	keep, err := s.resolveDevices(req.keep)
	if err != nil {
		return nil, nil, err
	}
	switch req.kind {
	case CheckpointPasswd:
		// The stale devices are its targets: decided, so a rebuild does not
		// take them for new ones.
		stale := s.staleActive(s.devCfg)
		for id := range s.state.Devices {
			if slices.Contains(stale, id) {
				targets = append(targets, id)
			} else {
				survivors = append(survivors, id)
			}
		}
	case CheckpointRevoke:
		if targets, err = s.resolveDevices(req.targets); err != nil {
			return nil, nil, err
		}
		for _, id := range targets {
			if id == self {
				return nil, nil, errors.New("store: this device can't revoke itself; use hop auth logout")
			}
			if slices.Contains(keep, id) {
				return nil, nil, fmt.Errorf("store: device %v is both kept and revoked", id)
			}
		}
		fallthrough
	default:
		survivors = append([]model.ID{self}, keep...)
	}
	return sortIDs(survivors), sortIDs(targets), nil
}

// sameCheckpoint checks that req is the journaled checkpoint j, with the
// survivors chosen when it started: the journaled choice is reused on a
// rebuild (§10.1), and a call that asks for another must not be finished
// with it. Only the devices still active are compared: one the journal
// names that retired since is gone, and the same command, run again, must
// still finish the checkpoint (a device ID that is no longer active is
// accepted, and a name no active device has is passed over). The caller
// holds s.mu.
func (s *Store) sameCheckpoint(j *ckptJournal, req *ckptRequest) error {
	if req.kind != j.Kind || j.Author != s.dev.ID {
		return &CheckpointPendingError{Kind: j.Kind}
	}
	if j.Kind == CheckpointPasswd {
		// Its Keep and Exclude answer new devices (decideNewDevices).
		return nil
	}
	keep, err := s.resolveJournaled(req.keep)
	if err != nil {
		return err
	}
	want := s.activeOf(append([]model.ID{s.dev.ID}, keep...))
	if !slices.Equal(want, s.activeOf(j.Survivors)) {
		return &CheckpointPendingError{Kind: j.Kind}
	}
	if j.Kind == CheckpointRevoke {
		targets, err := s.resolveJournaled(req.targets)
		if err != nil {
			return err
		}
		if !slices.Equal(s.activeOf(targets), s.activeOf(j.Targets)) {
			return &CheckpointPendingError{Kind: j.Kind}
		}
	}
	return nil
}

// resolveJournaled resolves device references against a journaled
// checkpoint: as resolveDevices, except that a device ID needs not be
// active and a name no active device has is passed over (its device may
// have retired since the checkpoint started). The caller holds s.mu.
func (s *Store) resolveJournaled(refs []string) ([]model.ID, error) {
	var out []model.ID
	for _, ref := range refs {
		if id, err := model.ParseID(ref); err == nil {
			out = append(out, id)
			continue
		}
		id, err := s.resolveDevice(ref)
		if errors.Is(err, ErrUnknownDevice) {
			continue
		}
		if err != nil {
			return nil, err
		}
		out = append(out, id)
	}
	return sortIDs(out), nil
}

// activeOf returns the devices of ids that are active in the verified
// state, sorted. The caller holds s.mu.
func (s *Store) activeOf(ids []model.ID) []model.ID {
	var out []model.ID
	for _, id := range ids {
		if _, ok := s.state.Devices[id]; ok {
			out = append(out, id)
		}
	}
	return sortIDs(out)
}

// decideNewDevices settles, before a password change's candidate is built,
// the devices active now that it neither keeps nor revokes: devices that
// appeared since it started (§10.1). Without req's answer it refuses with
// a NewDevicesError naming them; with one (each in req.keep or
// req.exclude), the answer goes into j, journaled with the candidate. Keep
// and Exclude with nothing to answer are refused. The caller holds s.mu.
func (s *Store) decideNewDevices(j *ckptJournal, req *ckptRequest) error {
	var fresh []model.ID
	for id := range s.state.Devices {
		if !slices.Contains(j.Survivors, id) && !slices.Contains(j.Targets, id) {
			fresh = append(fresh, id)
		}
	}
	fresh = sortIDs(fresh)
	if len(req.keep)+len(req.exclude) == 0 {
		if len(fresh) > 0 {
			return &NewDevicesError{Devices: fresh}
		}
		return nil
	}
	if len(fresh) == 0 {
		return errPasswdKeep
	}
	keep, err := s.resolveDevices(req.keep)
	if err != nil {
		return err
	}
	exclude, err := s.resolveDevices(req.exclude)
	if err != nil {
		return err
	}
	for _, id := range append(slices.Clone(keep), exclude...) {
		if !slices.Contains(fresh, id) {
			return fmt.Errorf("store: device %v did not appear during the password change; Keep and Exclude name only the devices that did", id)
		}
		if slices.Contains(keep, id) && slices.Contains(exclude, id) {
			return fmt.Errorf("store: device %v is both kept and excluded", id)
		}
	}
	var missing []model.ID
	for _, id := range fresh {
		if !slices.Contains(keep, id) && !slices.Contains(exclude, id) {
			missing = append(missing, id)
		}
	}
	if len(missing) > 0 {
		return &NewDevicesError{Devices: missing}
	}
	j.Survivors = sortIDs(append(j.Survivors, keep...))
	j.Targets = sortIDs(append(j.Targets, exclude...))
	return nil
}

// verifyCheckpointPassword checks req's current password against the
// account once per call (§10.1: a checkpoint needs the master password,
// and the Secret Key with it, which an enrolled device must be given).
// Only a recovery's follow-up has none to check: the recovery sign-in
// proved the Recovery Key. The caller holds s.mu.
func (s *Store) verifyCheckpointPassword(req *ckptRequest) error {
	if req.verified || req.kind == CheckpointRecovery {
		return nil
	}
	sk, err := s.currentSecretKey(req.sk)
	if err != nil {
		return err
	}
	a, err := accountOf(s.state, objectDir(s.l.objects()))
	if err != nil {
		return err
	}
	acct, err := openWithPassword(a, req.verify, sk)
	if err != nil {
		return err
	}
	acct.Zero()
	req.verified = true
	return nil
}

// currentSecretKey is the account's Secret Key: given (an enrolled device
// stores none), else the stored one.
func (s *Store) currentSecretKey(given string) (*crypto.SecretKey, error) {
	if given != "" {
		sk, err := crypto.ParseSecretKey(given)
		if err != nil {
			return nil, fmt.Errorf("store: that is not a Secret Key: %w", err)
		}
		return &sk, nil
	}
	return s.rec.secretKey()
}

// buildCandidate builds a checkpoint against the verified head with fresh
// secrets (§10.1) and adds it to j as its live candidate: the journaled
// survivors that are still active survive, and every other active device,
// one that appeared since included, is revoked. The candidate's secrets are
// dropped from memory once its wire is built. The caller holds s.mu.
func (s *Store) buildCandidate(j *ckptJournal, req *ckptRequest) (*vaultlog.Wire, error) {
	if _, ok := s.state.Devices[j.Author]; !ok || j.Author != s.dev.ID {
		return nil, fmt.Errorf("%w: the checkpoint's author is not this active device", ErrDeviceKey)
	}
	var revoke []model.ID
	for id := range s.state.Devices {
		if !slices.Contains(j.Survivors, id) {
			revoke = append(revoke, id)
		}
	}
	newSK, err := crypto.NewSecretKey()
	if err != nil {
		return nil, err
	}
	defer newSK.Zero()
	newRK, err := crypto.NewRecoveryKey()
	if err != nil {
		return nil, err
	}
	defer newRK.Zero()
	newAcct, err := crypto.GenerateAccountKeys(s.state.Account.AccountID, s.state.Account.AKV+1)
	if err != nil {
		return nil, err
	}
	defer newAcct.Zero()
	creds, err := newCreds(req.password, &newSK, &newRK, newAcct)
	if err != nil {
		return nil, err
	}
	newVK, err := crypto.NewSymKey()
	if err != nil {
		return nil, err
	}
	defer newVK.Zero()
	now := s.now()
	w, _, csec, err := vaultlog.BuildCheckpoint(s.state, s.sec, s.dev, vaultlog.CheckpointParams{
		NewAccount: newAcct, NewVK: newVK, Creds: creds, Time: now, Revoke: sortIDs(revoke),
	})
	if err != nil {
		return nil, err
	}
	// The candidate's own secrets are for verification only (§5.5); the
	// pull that verifies the commit derives them again.
	zeroSecrets(csec)
	h, err := w.Entry.Hash()
	if err != nil {
		return nil, err
	}
	raw, err := w.Marshal()
	if err != nil {
		return nil, err
	}
	prev, _ := w.Entry.Prev.Get()
	j.Candidates = append(j.Candidates, ckptCandidate{
		Seq: w.Entry.Seq, Prev: prev, H: h, Status: statusLive, Wire: raw,
		SecretKey: newSK.String(), RecoveryKey: newRK.String(), Created: now,
	})
	return w, nil
}

// resolveDevices resolves device references (§10.1, --keep): a device ID
// that is active, or a name exactly one active device has. A name several
// active devices share is ErrAmbiguousDevice, and anything else
// ErrUnknownDevice. The result is sorted, without duplicates. The caller
// holds s.mu.
func (s *Store) resolveDevices(refs []string) ([]model.ID, error) {
	var out []model.ID
	for _, ref := range refs {
		id, err := s.resolveDevice(ref)
		if err != nil {
			return nil, err
		}
		if !slices.Contains(out, id) {
			out = append(out, id)
		}
	}
	return sortIDs(out), nil
}

func (s *Store) resolveDevice(ref string) (model.ID, error) {
	if id, err := model.ParseID(ref); err == nil {
		if _, ok := s.state.Devices[id]; ok {
			return id, nil
		}
		return model.ID{}, fmt.Errorf("%w: %v", ErrUnknownDevice, id)
	}
	var found []model.ID
	for id, d := range s.state.Devices {
		if d.Cert.Name == ref {
			found = append(found, id)
		}
	}
	switch len(found) {
	case 0:
		return model.ID{}, fmt.Errorf("%w: %q", ErrUnknownDevice, ref)
	case 1:
		return found[0], nil
	}
	return model.ID{}, fmt.Errorf("%w: %q names %d devices", ErrAmbiguousDevice, ref, len(found))
}

// ResolveDevices resolves device references as the checkpoints do: each a
// device ID that is active, or a name exactly one active device has.
func (s *Store) ResolveDevices(refs []string) ([]model.ID, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.state == nil {
		return nil, s.lockedErr()
	}
	return s.resolveDevices(refs)
}

func sortIDs(ids []model.ID) []model.ID {
	slices.SortFunc(ids, func(a, b model.ID) int { return bytes.Compare(a[:], b[:]) })
	return slices.Compact(ids)
}

// How a device was added (DeviceListing.How).
const (
	AddedBySignup    = "signup"    // the genesis entry's device (§4.3)
	AddedByBootstrap = "bootstrap" // a password or recovery login (§4.4, §4.5)
	AddedByApproval  = "approval"  // enrollment by an approving device (§7)
)

// DeviceListing is one active device as hop auth devices lists it, for
// choosing survivors (§10.1): names are not unique, so the ID is the key.
type DeviceListing struct {
	ID      model.ID  `json:"device_id"`
	Name    string    `json:"name"`
	AddedAt time.Time `json:"added_at"`
	// How is AddedBySignup, AddedByBootstrap or AddedByApproval.
	How string `json:"how"`
	// LastSeen is the time of the newest entry the device authored, if it
	// authored any.
	LastSeen *time.Time `json:"last_seen,omitempty"`
	// This is this device; Stale is a device this machine's password
	// unlocks left behind, which the next password change revokes.
	This  bool `json:"this,omitempty"`
	Stale bool `json:"stale,omitempty"`
	// Undelivered is a device an approval on this device added that never
	// received its delivery (the attempt ended first, or has not
	// delivered yet): it can't be used, and unless that approval is still
	// running, it should be revoked.
	Undelivered bool `json:"undelivered,omitempty"`
}

// Devices lists the active devices of the verified state, oldest first,
// from the verified log on disk: when and how each was first added, and
// when it last authored an entry.
func (s *Store) Devices() ([]DeviceListing, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.state == nil {
		return nil, s.lockedErr()
	}
	unlock, err := s.lockFile()
	if err != nil {
		return nil, err
	}
	defer unlock()
	byID := map[model.ID]*DeviceListing{}
	stale := s.staleActive(s.devCfg)
	var undelivered []model.ID
	if s.server {
		if undelivered, _, err = s.undelivered(); err != nil {
			return nil, err
		}
	}
	for id, d := range s.state.Devices {
		byID[id] = &DeviceListing{ID: id, Name: d.Cert.Name, This: id == s.dev.ID, Stale: slices.Contains(stale, id),
			Undelivered: slices.Contains(undelivered, id)}
	}
	added := map[model.ID]bool{}
	for seq := uint64(0); seq <= s.state.Head.Seq; seq++ {
		w, err := s.l.readEntry(seq)
		if err != nil {
			return nil, err
		}
		e := &w.Entry
		if l, ok := byID[e.Author]; ok && (e.Kind == vaultlog.KindNormal || e.Kind == vaultlog.KindCheckpoint) {
			t := e.Time.Time()
			l.LastSeen = &t
		}
		for _, o := range e.Ops {
			d, ok := o.(*vaultlog.DeviceAddOp)
			if !ok || added[d.Cert.DeviceID] {
				continue
			}
			added[d.Cert.DeviceID] = true
			l, ok := byID[d.Cert.DeviceID]
			if !ok {
				continue
			}
			l.AddedAt = e.Time.Time()
			switch e.Kind {
			case vaultlog.KindGenesis:
				l.How = AddedBySignup
			case vaultlog.KindBootstrap:
				l.How = AddedByBootstrap
			default:
				l.How = AddedByApproval
			}
		}
	}
	out := make([]DeviceListing, 0, len(byID))
	for _, l := range byID {
		out = append(out, *l)
	}
	slices.SortFunc(out, func(a, b DeviceListing) int {
		if c := a.AddedAt.Compare(b.AddedAt); c != 0 {
			return c
		}
		return bytes.Compare(a.ID[:], b.ID[:])
	})
	return out, nil
}
