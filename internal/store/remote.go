package store

import (
	"context"
	"errors"
	"fmt"

	"github.com/dalyem/hopkey/internal/crypto"
	"github.com/dalyem/hopkey/internal/merge"
	"github.com/dalyem/hopkey/internal/model"
	"github.com/dalyem/hopkey/internal/vaultlog"
)

// Remote is the server's log, as the store needs it (§5.4, plan slice E:
// GET /v1/vaults/{id}/log and POST /v1/vaults/{id}/log). Slice E implements
// it over HTTP. Nothing a Remote returns is trusted: every entry is
// verified with the transition algorithm before it is written.
type Remote interface {
	// Since returns committed entries with seq > after, in ascending order
	// (possibly only a page of them), and the server's head. Each wire
	// carries the objects its entry names.
	Since(ctx context.Context, after uint64) ([]Committed, vaultlog.Head, error)
	// Post posts a wire whose prev must be the server's head (§5.4). It
	// returns the commit, which for an identical H already committed is
	// that commit. If prev isn't the head it returns an error that matches
	// ErrHeadConflict, normally a *HeadConflictError.
	Post(ctx context.Context, w *vaultlog.Wire) (vaultlog.Head, error)
}

// Committed is one committed entry as the server returns it.
type Committed struct {
	Seq  uint64
	H    crypto.Hash
	Wire *vaultlog.Wire
}

// ErrHeadConflict is the server's 409: the posted prev isn't its head.
var ErrHeadConflict = errors.New("store: the server's head has moved")

// HeadConflictError is ErrHeadConflict with the server's head (the R11
// head_conflict error).
type HeadConflictError struct {
	Head vaultlog.Head
}

func (e *HeadConflictError) Error() string {
	return fmt.Sprintf("store: the server's head has moved (seq %d)", e.Head.Seq)
}

func (e *HeadConflictError) Is(target error) bool { return target == ErrHeadConflict }

var (
	// ErrSyncInterrupted means the vault was locked while a pull or push
	// was in flight. Its response was discarded and the head did not move
	// (§11.2).
	ErrSyncInterrupted = fmt.Errorf("%w: sync was interrupted by a lock; its result was discarded", model.ErrLocked)
	// ErrServerBehind means the server's head is behind this device's
	// verified head: the server lost or withheld entries.
	ErrServerBehind = errors.New("store: the server's head is behind this device's verified head")
	// ErrSyncHalted wraps the error that stopped syncing: an equivocation
	// (§5.6) or a rule violation in a server entry (§5.3). Sync stays
	// stopped until the store is opened again. A revocation is terminal
	// instead (ErrDeviceRevoked).
	ErrSyncHalted = errors.New("store: sync is stopped")
)

// maxPushAttempts bounds PushHead's rebuild loop: each 409 or new head
// means another device committed first.
const maxPushAttempts = 8

// syncContext derives a context for one pull or push that Lock cancels
// (§11.2), and returns the lock generation it started in.
func (s *Store) syncContext(ctx context.Context) (context.Context, uint64, func(), error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.state == nil {
		return nil, 0, nil, s.lockedErr()
	}
	if !s.server {
		return nil, 0, nil, ErrNotServerBacked
	}
	if s.syncHalt != nil {
		return nil, 0, nil, s.syncHalt
	}
	ctx, gen, untrack := s.trackRequest(ctx)
	done := func() {
		s.mu.Lock()
		untrack()
		s.mu.Unlock()
	}
	return ctx, gen, done, nil
}

// trackRequest derives a context for requests to the server that Lock
// cancels (§11.2). It returns the lock generation it started in, and a func
// that stops tracking the context and cancels it. The caller holds s.mu,
// and holds it when it calls that func.
func (s *Store) trackRequest(ctx context.Context) (context.Context, uint64, func()) {
	ctx, cancel := context.WithCancel(ctx)
	if s.cancels == nil {
		s.cancels = map[uint64]context.CancelFunc{}
	}
	s.cancelID++
	id := s.cancelID
	s.cancels[id] = cancel
	return ctx, s.gen.Load(), func() {
		delete(s.cancels, id)
		cancel()
	}
}

// current reports whether the store is still unlocked in generation gen.
// The caller holds s.mu.
func (s *Store) current(gen uint64) error {
	if s.gen.Load() != gen || s.state == nil {
		return ErrSyncInterrupted
	}
	if s.syncHalt != nil {
		return s.syncHalt
	}
	return nil
}

// halt stops syncing with err. The caller holds s.mu.
func (s *Store) halt(err error) error {
	s.syncHalt = fmt.Errorf("%w: %w", ErrSyncHalted, err)
	return s.syncHalt
}

// Pull verifies the server's entries past the verified head with the
// transition algorithm and commits each one, together with what it settles
// in the outbox, in one durable commit (§5.5, §11.1). It stops at the
// server's head. An entry at a seq this device already holds with a
// different H is an equivocation (§5.6): Pull returns a
// *vaultlog.EquivocationError and sync stops. So does any rule violation.
// A checkpoint that revokes this device locks the vault for good (revoke):
// Pull returns ErrDeviceRevoked. A lock while Pull waits discards the
// response (§11.2).
func (s *Store) Pull(ctx context.Context, r Remote) error {
	s.syncMu.Lock()
	defer s.syncMu.Unlock()
	return s.pullLocked(ctx, r)
}

// pullLocked is Pull. The caller holds s.syncMu.
func (s *Store) pullLocked(ctx context.Context, r Remote) error {
	ctx, gen, done, err := s.syncContext(ctx)
	if err != nil {
		return err
	}
	defer done()
	for {
		s.mu.Lock()
		err := s.current(gen)
		var after uint64
		if err == nil {
			after = s.state.Head.Seq
		}
		s.mu.Unlock()
		if err != nil {
			return err
		}
		if err := s.hook("pull:request"); err != nil {
			return err
		}
		entries, head, err := r.Since(ctx, after)
		if err != nil {
			return err
		}
		caughtUp, err := s.applyPulled(gen, entries, head)
		if err != nil || caughtUp {
			return err
		}
	}
}

// applyPulled verifies and commits one page. It reports whether the
// verified head has reached the server's.
func (s *Store) applyPulled(gen uint64, entries []Committed, head vaultlog.Head) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.current(gen); err != nil {
		return false, err
	}
	unlock, err := s.lockFile()
	if err != nil {
		return false, err
	}
	defer unlock()
	before := s.state.Head.Seq
	st, sec, err := s.applyEntries(s.state, s.sec, s.dev, nil, entries, s.rec)
	if rev := (*vaultlog.RevokedError)(nil); errors.As(err, &rev) {
		return false, s.revoke(rev)
	}
	// An interrupted commit locks the store (commitTxn): then nothing is
	// installed, and the next unlock replays the journal.
	if s.current(gen) == nil && st != s.state {
		s.state, s.sec = st, sec
	}
	if err != nil {
		return false, s.haltOn(err)
	}
	ours := s.state.Head
	switch {
	case head.Seq < ours.Seq:
		return false, fmt.Errorf("%w: the server is at seq %d, this device at %d", ErrServerBehind, head.Seq, ours.Seq)
	case head.Seq == ours.Seq:
		if !head.H.Equal(ours.H) {
			return false, s.halt(&vaultlog.EquivocationError{Seq: ours.Seq, Have: ours.H, Got: head.H})
		}
		return true, nil
	case ours.Seq == before:
		return false, fmt.Errorf("store: the server reports head %d but returned no entry past %d", head.Seq, before)
	}
	return false, nil
}

// haltOn stops syncing for errors that say the server's log is wrong, and
// passes every other error through.
func (s *Store) haltOn(err error) error {
	var eq *vaultlog.EquivocationError
	if errors.As(err, &eq) || vaultlog.RuleOf(err) != "" {
		return s.halt(err)
	}
	return err
}

// applyEntries verifies entries on top of (st, sec) and commits each one,
// with the outbox records it settles. It returns the last committed state,
// even with an error. Entries this device already holds are compared with
// what it holds (§5.6). rec is the device record whose local_key opens the
// outbox: a password unlock passes the new record, which carries the old
// one's local_key, before it is saved. A password unlock has no dev, and
// passes in self the devices this machine is (see transition). The caller
// holds s.mu and the file lock.
func (s *Store) applyEntries(st *vaultlog.State, sec *vaultlog.Secrets, dev vaultlog.DeviceKey, self []model.ID, entries []Committed, rec *deviceRecord) (*vaultlog.State, *vaultlog.Secrets, error) {
	objs := objectDir(s.l.objects())
	for _, c := range entries {
		if c.Wire == nil {
			return st, sec, errors.New("store: the server returned an entry without its wire")
		}
		e := &c.Wire.Entry
		h, err := e.Hash()
		if err != nil {
			return st, sec, err
		}
		if e.Seq != c.Seq || !h.Equal(c.H) {
			return st, sec, fmt.Errorf("store: the server's entry %d does not match its seq and H", c.Seq)
		}
		if c.Seq <= st.Head.Seq {
			held, err := s.l.readEntry(c.Seq)
			if err != nil {
				return st, sec, err
			}
			have, err := held.Entry.Hash()
			if err != nil {
				return st, sec, err
			}
			if err := vaultlog.CheckHeld(c.Seq, have, e); err != nil {
				return st, sec, err
			}
			continue
		}
		if c.Seq != st.Head.Seq+1 {
			return st, sec, fmt.Errorf("store: the server skipped from seq %d to %d", st.Head.Seq, c.Seq)
		}
		next, nsec, err := transition(st, sec, dev, self, c.Wire, objs)
		if err != nil {
			return st, sec, err
		}
		if err := s.commitVerified(c.Wire, h, next, rec); err != nil {
			return st, sec, err
		}
		st, sec = next, nsec
	}
	return st, sec, nil
}

// commitVerified writes a verified entry: its objects (content-addressed,
// harmless if a crash leaves them unreferenced), then, in one transaction,
// the entry, state.json and every outbox record it settles (§11.1). A
// record whose candidate is this entry is deleted; a record whose live
// candidate was at this seq with another H has it marked dead, and a login
// merge's receipt for an import it settles is written with it (§4.4). rec
// opens the outbox. The caller holds s.mu and the file lock.
func (s *Store) commitVerified(w *vaultlog.Wire, h crypto.Hash, st *vaultlog.State, rec *deviceRecord) error {
	if err := s.l.writeObjects(w); err != nil {
		return err
	}
	bare := *w
	bare.Objects = []vaultlog.Object{}
	eb, err := bare.Marshal()
	if err != nil {
		return err
	}
	sb, err := st.Marshal()
	if err != nil {
		return err
	}
	t := &txn{}
	t.create(entryRel(w.Entry.Seq), eb)
	t.put(stateRel, sb)
	if err := s.settle(t, w.Entry.Seq, func(seq uint64) (crypto.Hash, error) {
		if seq == w.Entry.Seq {
			return h, nil
		}
		return s.entryHash(seq)
	}, rec, st.VaultID); err != nil {
		return err
	}
	return s.commitTxn(t)
}

// transition is vaultlog.Transition. With no dev (a password unlock, whose
// device key is lost) it still takes the "revoked here" exit (§5.5) for
// the devices in self, the ones this machine is in the log as: a
// checkpoint that revokes one of them returns a *vaultlog.RevokedError
// from the public stage, before anything is decrypted.
func transition(st *vaultlog.State, sec *vaultlog.Secrets, dev vaultlog.DeviceKey, self []model.ID, w *vaultlog.Wire, objs vaultlog.ObjectFetcher) (*vaultlog.State, *vaultlog.Secrets, error) {
	if dev != nil {
		return vaultlog.Transition(st, sec, dev, w, objs)
	}
	c, err := vaultlog.CheckPublic(st, w, objs)
	if err != nil {
		return nil, nil, err
	}
	for _, id := range self {
		if c.Revokes(id) {
			return nil, nil, &vaultlog.RevokedError{DeviceID: id, Head: c.Post.Head}
		}
	}
	return c.CheckPlaintext(sec, nil)
}

func (s *Store) entryHash(seq uint64) (crypto.Hash, error) {
	w, err := s.l.readEntry(seq)
	if err != nil {
		return crypto.Hash{}, err
	}
	return w.Entry.Hash()
}

// settle adds to t the outbox changes that verified history up to head
// decides: every live candidate at a seq ≤ head is committed if the
// verified entry there has its H, and dead otherwise. A record with a
// committed candidate is deleted. Nothing else ever settles a candidate.
// rec's local_key opens the outbox of vault vaultID. The caller holds the
// file lock.
func (s *Store) settle(t *txn, head uint64, hashAt func(uint64) (crypto.Hash, error), rec *deviceRecord, vaultID model.ID) error {
	if ns, err := s.l.outboxNumbers(); err != nil || len(ns) == 0 {
		return err
	}
	recs, err := s.readOutboxAs(rec, vaultID)
	if err != nil {
		return err
	}
	receipts := map[model.ID][]mergeReceipt{}
	for _, r := range recs {
		c := r.live()
		if c == nil || c.Seq > head {
			continue
		}
		h, err := hashAt(c.Seq)
		if err != nil {
			return err
		}
		if h.Equal(c.H) {
			t.remove(outboxRel(r.N))
			if !r.Import.IsZero() {
				// A login merge's import: its receipt is written in this
				// same commit (§4.4).
				receipts[r.Import] = append(receipts[r.Import], mergeReceipt{ItemID: r.Intent.ItemID, Seq: c.Seq, H: c.H})
			}
			continue
		}
		c.Status = statusDead
		delete(r.Wires, c.H)
		if err := s.putRecordAs(t, r, rec, vaultID); err != nil {
			return err
		}
	}
	for txnID, rs := range receipts {
		if err := s.addReceipts(t, rec, txnID, rs); err != nil {
			return err
		}
	}
	return nil
}

// settleAtUnlock settles candidates that verified history already decides.
// Every verified commit settles its own, so this finds work only in a vault
// whose commits did not (a crash in an older build). The caller holds s.mu
// and the file lock.
func (s *Store) settleAtUnlock() error {
	t := &txn{}
	if err := s.settle(t, s.state.Head.Seq, s.entryHash, s.rec, s.state.VaultID); err != nil {
		return err
	}
	return s.commitTxn(t)
}

// PushOutcome says what PushHead did.
type PushOutcome string

const (
	// PushEmpty: the outbox is empty.
	PushEmpty PushOutcome = "empty"
	// PushCommitted: the head record's candidate committed and the record
	// is gone.
	PushCommitted PushOutcome = "committed"
	// PushHeld: the head record is held. Nothing behind it is pushed until
	// the user resolves it.
	PushHeld PushOutcome = "held"
	// PushDropped: the head record was a delete that is already complete
	// (§5.4); it is gone and nothing was written.
	PushDropped PushOutcome = "dropped"
)

// PushResult is what PushHead did with the head record.
type PushResult struct {
	Outcome PushOutcome
	N       uint64    // the head record's number; 0 for PushEmpty
	Hold    *HoldInfo // for PushHeld
	Head    Head      // the verified head afterwards
}

// HoldInfo says why a record is held: the §5.4 cause, the guarded members
// each side changed for a guarded conflict, and the failed rule otherwise.
type HoldInfo struct {
	Cause  merge.Cause `json:"cause"`
	Local  []string    `json:"local,omitempty"`
	Remote []string    `json:"remote,omitempty"`
	Reason string      `json:"reason,omitempty"`
}

func holdInfo(res merge.Result) *HoldInfo {
	h := &HoldInfo{Cause: res.Cause, Local: res.Local, Remote: res.Remote}
	if res.Err != nil {
		h.Reason = res.Err.Error()
	}
	return h
}

// PushHead pushes the head record of the outbox (§5.4, §11.1). It first
// pulls to the server's head. Then:
//
//   - A live candidate (its prev is still the verified head, so it may
//     have committed or not) is re-posted as the identical wire.
//   - Otherwise every earlier candidate is dead, and the intent is rebuilt
//     against verified state with the merge rule. A hold sets the record's
//     held flag; a completed delete drops the record. A write becomes a
//     normal entry built by vaultlog.BuildNormal from verified state, with
//     every companion op (§5.3, §8.6). The exact wire and its (seq, prev,
//     H) are journaled in the record before it is posted.
//
// After a post it pulls again: only verified history settles a candidate,
// and the record is deleted in the commit that verifies it. A 409 means
// another device committed first: the candidate is dead once its seq is
// verified, and the intent is rebuilt. Any other post error leaves the
// candidate live (an uncertain outcome) and is returned; the next PushHead
// resolves it. A held head blocks every record behind it. A lock discards
// whatever is in flight (§11.2).
func (s *Store) PushHead(ctx context.Context, r Remote) (PushResult, error) {
	s.syncMu.Lock()
	defer s.syncMu.Unlock()
	pushed := uint64(0)
	for attempt := 0; attempt < maxPushAttempts; attempt++ {
		if err := s.pullLocked(ctx, r); err != nil {
			return PushResult{}, err
		}
		ctx2, gen, done, err := s.syncContext(ctx)
		if err != nil {
			return PushResult{}, err
		}
		res, w, err := s.prepareHead(gen, pushed)
		if err != nil || w == nil {
			done()
			return res, err
		}
		pushed = res.N
		if err := s.hook("push:post"); err != nil {
			done()
			return PushResult{}, err
		}
		_, err = r.Post(ctx2, w)
		done()
		if err != nil && !errors.Is(err, ErrHeadConflict) {
			return PushResult{}, err
		}
	}
	return PushResult{}, fmt.Errorf("store: record %d did not commit after %d attempts; another device keeps writing first", pushed, maxPushAttempts)
}

// prepareHead decides what to do with the head record, after a pull. It
// returns the wire to post, or nil with the final result. pushed is the
// record this call has posted, if any: if it is gone, it committed.
func (s *Store) prepareHead(gen, pushed uint64) (PushResult, *vaultlog.Wire, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.current(gen); err != nil {
		return PushResult{}, nil, err
	}
	unlock, err := s.lockFile()
	if err != nil {
		return PushResult{}, nil, err
	}
	defer unlock()
	out := PushResult{Head: Head{Seq: s.state.Head.Seq, H: s.state.Head.H.String()}}
	recs, err := s.readOutbox()
	if err != nil {
		return out, nil, err
	}
	if pushed != 0 && (len(recs) == 0 || recs[0].N != pushed) {
		out.Outcome, out.N = PushCommitted, pushed
		return out, nil, nil
	}
	if len(recs) == 0 {
		out.Outcome = PushEmpty
		return out, nil, nil
	}
	rec := recs[0]
	out.N = rec.N
	if c := rec.live(); c != nil {
		head := s.state.Head
		if c.Seq != head.Seq+1 || !c.Prev.Equal(head.H) {
			return out, nil, fmt.Errorf("%w: outbox record %d has a live candidate at seq %d that verified history has not settled", ErrCorrupt, rec.N, c.Seq)
		}
		w, ok := rec.Wires[c.H]
		if !ok {
			return out, nil, fmt.Errorf("%w: outbox record %d has lost the wire of its live candidate", ErrCorrupt, rec.N)
		}
		return out, w, nil
	}
	if rec.Held {
		ev, err := s.evaluate(rec.Intent)
		if err != nil {
			return out, nil, err
		}
		out.Outcome = PushHeld
		out.Hold = &HoldInfo{Reason: "it would apply now: retry it"}
		if ev.res.Kind == merge.KindHold {
			out.Hold = holdInfo(ev.res)
		}
		return out, nil, nil
	}
	ev, err := s.evaluate(rec.Intent)
	if err != nil {
		return out, nil, err
	}
	t := &txn{}
	switch ev.res.Kind {
	case merge.KindDrop:
		t.remove(outboxRel(rec.N))
		out.Outcome = PushDropped
		return out, nil, s.commitTxn(t)
	case merge.KindHold:
		rec.Held = true
		if err := s.putRecord(t, rec); err != nil {
			return out, nil, err
		}
		out.Outcome, out.Hold = PushHeld, holdInfo(ev.res)
		return out, nil, s.commitTxn(t)
	}
	// Journal the candidate before posting it (§11.1).
	w := ev.wire
	h, err := w.Entry.Hash()
	if err != nil {
		return out, nil, err
	}
	prev, _ := w.Entry.Prev.Get()
	rec.Cands = append(rec.Cands, candidate{Seq: w.Entry.Seq, Prev: prev, H: h, Status: statusLive})
	rec.Wires[h] = w
	if err := s.putRecord(t, rec); err != nil {
		return out, nil, err
	}
	if err := s.commitTxn(t); err != nil {
		return out, nil, err
	}
	if err := s.hook("outbox:journaled"); err != nil {
		return out, nil, err
	}
	return out, w, nil
}

// SyncStatus is the outbox and sync state for hop status.
type SyncStatus struct {
	ServerBacked bool   `json:"server_backed"`
	Pending      int    `json:"pending"` // queued records that are not held
	Held         int    `json:"held"`
	Head         Head   `json:"head"` // the last verified head
	Halted       string `json:"halted,omitempty"`
}

// Status returns the outbox counts and the last verified head.
func (s *Store) Status() (SyncStatus, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.state == nil {
		return SyncStatus{}, s.lockedErr()
	}
	st := SyncStatus{ServerBacked: s.server, Head: Head{Seq: s.state.Head.Seq, H: s.state.Head.H.String()}}
	if s.syncHalt != nil {
		st.Halted = s.syncHalt.Error()
	}
	unlock, err := s.lockFile()
	if err != nil {
		return st, err
	}
	defer unlock()
	recs, err := s.readOutbox()
	if err != nil {
		return st, err
	}
	for _, r := range recs {
		if r.Held {
			st.Held++
		} else {
			st.Pending++
		}
	}
	return st, nil
}

// needServer requires an unlocked, server-backed vault. The caller holds
// s.mu.
func (s *Store) needServer() error {
	if s.state == nil {
		return s.lockedErr()
	}
	if !s.server {
		return ErrNotServerBacked
	}
	return nil
}
