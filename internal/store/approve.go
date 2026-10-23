package store

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/dalyem/hopkey/internal/canonjson"
	"github.com/dalyem/hopkey/internal/crypto"
	"github.com/dalyem/hopkey/internal/model"
	"github.com/dalyem/hopkey/internal/vaultlog"
)

// Enrollment by approval, the approving device A's side (§7). The §7 state
// machine is crypto.Approval; the store persists it and posts the normal
// entry with its device_add. Slice E3 relays the messages and shows the
// SAS; each step here is one call that loads the attempt, runs one
// transition (persisted before the call returns its message), and holds
// the store's mutex and file lock throughout:
//
//	ApproveStart(enroll_id)  reserve a budget attempt (hop auth approve CODE)
//	ApproveCommit(commit)    → chal
//	ApproveOpen(open)        → SAS and the device name to show
//	ApproveConfirm(match)    the user compared the SAS
//	ApproveFinish(ctx, r)    post the device_add, verify it from the server's log, → the delivery
//	ApproveAbort()           end an unfinished attempt as a failure
//
// Files, both under vault/:
//
//	approval-budget.json = JCS({"v":1, "budget":<crypto.ApprovalBudget state>})
//	approval.json        = JCS({"v":1, "vault_id":id, "sealed":AEAD(local_key, journal,
//	                           aad = lp("hopkey/v1/approval-journal") || lp(vault_id_bytes))})
//	journal              = JCS({"v":1, "attempt":<crypto.Approval state>,
//	                           "candidates":[{"seq":u64s, "prev":h, "h":h, "status":"live"|"committed"|"dead"}],
//	                           "wires":[wire]})
//
// The budget (3 attempts per rolling hour, one outstanding challenge) holds
// no secret; it survives restarts, locks and new approvals. The journal is
// sealed so that nothing on disk can change what the user confirmed (the
// open message whose keys Prepare certifies) without local_key. Its
// candidates follow the outbox's rules (§5.4): the exact wire is journaled
// before it is posted, only verified history settles it, a live one is
// posted again identically, and a dead one is rebuilt against the new head
// with the same prepared device_add.

const (
	labelApprovalJournal = "hopkey/v1/approval-journal"
	approvalRel          = "approval.json"
	approvalBudgetRel    = "approval-budget.json"
	approvalVersion      = 1
)

var (
	// ErrNoApproval means no approval is in progress.
	ErrNoApproval = errors.New("store: no approval is in progress; run hop auth approve with the code the new device shows")
	// ErrApprovalPending means an unfinished approval exists: finish or
	// abort it first.
	ErrApprovalPending = errors.New("store: another approval is in progress; finish or abort it first")
)

func (l layout) approvalFile() string       { return filepath.Join(l.vault(), approvalRel) }
func (l layout) approvalBudgetFile() string { return filepath.Join(l.vault(), approvalBudgetRel) }

// approvalExists reports whether vault/approval.json exists.
func (l layout) approvalExists() (bool, error) {
	_, err := os.Lstat(l.approvalFile())
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	return err == nil, err
}

type approvalJournal struct {
	V          int             `json:"v"`
	Attempt    canonjson.Raw   `json:"attempt"`
	Candidates []candidate     `json:"candidates"`
	Wires      []canonjson.Raw `json:"wires"`
}

type approvalFileJSON struct {
	V       int                 `json:"v"`
	VaultID model.ID            `json:"vault_id"`
	Sealed  crypto.AEADEnvelope `json:"sealed"`
}

type budgetFileJSON struct {
	V      int           `json:"v"`
	Budget canonjson.Raw `json:"budget"`
}

func approvalAAD(vaultID model.ID) []byte {
	return append(crypto.LP([]byte(labelApprovalJournal)), crypto.LP(vaultID[:])...)
}

func (j *approvalJournal) live() *candidate {
	for i := range j.Candidates {
		if j.Candidates[i].Status == statusLive {
			return &j.Candidates[i]
		}
	}
	return nil
}

// clock is the store's clock for the §7 deadlines and the budget.
func (s *Store) clock() time.Time {
	if s.cfg.Now != nil {
		return s.cfg.Now()
	}
	return time.Now()
}

// approvalPersister persists the attempt into its journal, durably, with
// the journal's candidates. The caller holds s.mu and the file lock.
type approvalPersister struct {
	s *Store
	j *approvalJournal
}

func (p *approvalPersister) Persist(state []byte) error {
	next := *p.j
	next.Attempt = canonjson.Raw(bytes.Clone(state))
	if err := p.s.writeApproval(&next); err != nil {
		return err
	}
	*p.j = next
	return nil
}

// budgetPersister persists the approval budget, durably. The caller holds
// s.mu and the file lock.
type budgetPersister struct{ s *Store }

func (p budgetPersister) Persist(state []byte) error {
	if err := p.s.hook("approve:budget"); err != nil {
		return err
	}
	b, err := canonjson.Marshal(budgetFileJSON{V: approvalVersion, Budget: canonjson.Raw(state)})
	if err != nil {
		return err
	}
	t := &txn{}
	t.put(approvalBudgetRel, b)
	return p.s.commitTxn(t)
}

// writeApproval writes the journal, sealed under local_key, durably.
func (s *Store) writeApproval(j *approvalJournal) error {
	if err := s.hook("approve:journal"); err != nil {
		return err
	}
	key, err := s.outboxKey()
	if err != nil {
		return err
	}
	defer key.Zero()
	j.V = approvalVersion
	if j.Candidates == nil {
		j.Candidates = []candidate{}
	}
	if j.Wires == nil {
		j.Wires = []canonjson.Raw{}
	}
	pt, err := canonjson.Marshal(j)
	if err != nil {
		return err
	}
	defer clear(pt)
	env, err := crypto.SealAEAD(key, pt, approvalAAD(s.state.VaultID))
	if err != nil {
		return err
	}
	b, err := canonjson.Marshal(approvalFileJSON{V: approvalVersion, VaultID: s.state.VaultID, Sealed: env})
	if err != nil {
		return err
	}
	t := &txn{}
	t.put(approvalRel, b)
	return s.commitTxn(t)
}

// readApproval opens the journal, or returns nil when there is none.
func (s *Store) readApproval() (*approvalJournal, error) {
	b, err := os.ReadFile(s.l.approvalFile())
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	bad := fmt.Errorf("%w: %s does not open", ErrCorrupt, s.l.approvalFile())
	var f approvalFileJSON
	if canonjson.Unmarshal(b, &f) != nil || f.V != approvalVersion || f.VaultID != s.state.VaultID {
		return nil, bad
	}
	key, err := s.outboxKey()
	if err != nil {
		return nil, err
	}
	defer key.Zero()
	pt, err := crypto.OpenAEAD(key, f.Sealed, approvalAAD(s.state.VaultID))
	if err != nil {
		return nil, bad
	}
	defer clear(pt)
	var j approvalJournal
	if canonjson.Unmarshal(pt, &j) != nil || j.V != approvalVersion {
		return nil, bad
	}
	live := 0
	for _, c := range j.Candidates {
		switch c.Status {
		case statusLive:
			live++
		case statusCommitted, statusDead:
		default:
			return nil, bad
		}
	}
	if live > 1 {
		return nil, bad
	}
	return &j, nil
}

// loadBudget reads the approval budget, empty when there is none.
func (s *Store) loadBudget() (*crypto.ApprovalBudget, error) {
	var state []byte
	b, err := os.ReadFile(s.l.approvalBudgetFile())
	switch {
	case errors.Is(err, os.ErrNotExist):
	case err != nil:
		return nil, err
	default:
		var f budgetFileJSON
		if canonjson.Unmarshal(b, &f) != nil || f.V != approvalVersion {
			return nil, fmt.Errorf("%w: %s does not parse", ErrCorrupt, s.l.approvalBudgetFile())
		}
		state = f.Budget
	}
	budget, err := crypto.LoadApprovalBudget(budgetPersister{s}, s.clock, state)
	if err != nil {
		return nil, fmt.Errorf("%w: %s: %v", ErrCorrupt, s.l.approvalBudgetFile(), err)
	}
	return budget, nil
}

// loadApproval loads the budget and the attempt in the journal, if any.
// Restoring an attempt whose deadline passed fails it (persisted). The
// caller holds s.mu and the file lock, on an unlocked server-backed store.
func (s *Store) loadApproval() (*crypto.ApprovalBudget, *crypto.Approval, *approvalJournal, error) {
	budget, err := s.loadBudget()
	if err != nil {
		return nil, nil, nil, err
	}
	j, err := s.readApproval()
	if err != nil || j == nil {
		return budget, nil, nil, err
	}
	a, err := crypto.RestoreApproval(budget, &approvalPersister{s: s, j: j}, j.Attempt)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("%w: %s: %v", ErrCorrupt, s.l.approvalFile(), err)
	}
	return budget, a, j, nil
}

// withApproval runs f on the approval in progress, under s.mu and the file
// lock.
func (s *Store) withApproval(f func(a *crypto.Approval, j *approvalJournal) error) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.needServer(); err != nil {
		return err
	}
	unlock, err := s.lockFile()
	if err != nil {
		return err
	}
	defer unlock()
	_, a, j, err := s.loadApproval()
	if err != nil {
		return err
	}
	if a == nil {
		return ErrNoApproval
	}
	return f(a, j)
}

func approvalDone(st crypto.ApprovalState) bool {
	return st == crypto.ApprovalDelivered || st == crypto.ApprovalFailed
}

// ApproveStart starts approving the new device whose commit the server
// relays as enrollID (hop auth approve CODE): it reserves an attempt in the
// persistent approval budget (3 per rolling hour, one outstanding
// challenge, crypto.ErrBudgetExhausted and crypto.ErrChallengeOutstanding)
// and persists the attempt. A finished attempt is replaced; an unfinished
// one is ErrApprovalPending.
func (s *Store) ApproveStart(enrollID model.ID) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.needServer(); err != nil {
		return err
	}
	unlock, err := s.lockFile()
	if err != nil {
		return err
	}
	defer unlock()
	budget, a, _, err := s.loadApproval()
	if err != nil {
		return err
	}
	if a != nil && !approvalDone(a.State()) {
		return ErrApprovalPending
	}
	_, err = crypto.StartApproval(budget, &approvalPersister{s: s, j: &approvalJournal{}}, enrollID, s.state.Pin(), s.dev.ID)
	return err
}

// ApproveCommit accepts the new device's commit and returns chal (§7 step
// 2), persisted first.
func (s *Store) ApproveCommit(c *crypto.EnrollCommit) (crypto.EnrollChal, error) {
	var ch crypto.EnrollChal
	err := s.withApproval(func(a *crypto.Approval, _ *approvalJournal) (err error) {
		ch, err = a.HandleCommit(c)
		return err
	})
	return ch, err
}

// ApproveChal returns the persisted chal again, for re-sending.
func (s *Store) ApproveChal() (crypto.EnrollChal, error) {
	var ch crypto.EnrollChal
	err := s.withApproval(func(a *crypto.Approval, _ *approvalJournal) (err error) {
		ch, err = a.Chal()
		return err
	})
	return ch, err
}

// ApproveOpen checks the new device's open against its commit (§7 step 4)
// and returns the SAS and the device name for the user to compare. An open
// that does not match changes nothing.
func (s *Store) ApproveOpen(o *crypto.EnrollOpen) (sas, name string, err error) {
	err = s.withApproval(func(a *crypto.Approval, _ *approvalJournal) (err error) {
		sas, name, err = a.HandleOpen(o)
		return err
	})
	return sas, name, err
}

// ApproveSAS returns the SAS and name again once the open was accepted.
func (s *Store) ApproveSAS() (sas, name string, err error) {
	err = s.withApproval(func(a *crypto.Approval, _ *approvalJournal) (err error) {
		sas, name, err = a.SAS()
		return err
	})
	return sas, name, err
}

// ApproveConfirm records the user's comparison of the SAS on this device.
// A mismatch ends the attempt as a failure; its budget slot stays spent.
func (s *Store) ApproveConfirm(match bool) error {
	return s.withApproval(func(a *crypto.Approval, _ *approvalJournal) error { return a.Confirm(match) })
}

// ApproveAbort ends an unfinished attempt as a failure. If its device_add
// already committed, the device stays in the log until a checkpoint
// revokes it.
func (s *Store) ApproveAbort() error {
	return s.withApproval(func(a *crypto.Approval, _ *approvalJournal) error { return a.Abort() })
}

// ApprovalInfo describes the approval in progress, or the last one.
type ApprovalInfo struct {
	EnrollID model.ID             `json:"enroll_id"`
	State    crypto.ApprovalState `json:"state"`
	Deadline time.Time            `json:"deadline"`
	// Live is the device_add's candidate posted, or about to be, that
	// verified history has not settled yet.
	Live *Head `json:"live,omitempty"`
}

// Approval returns the approval in progress, or the last one, or nil.
func (s *Store) Approval() (*ApprovalInfo, error) {
	var info *ApprovalInfo
	err := s.withApproval(func(a *crypto.Approval, j *approvalJournal) error {
		info = &ApprovalInfo{EnrollID: a.EnrollID(), State: a.State(), Deadline: a.Deadline()}
		if c := j.live(); c != nil {
			info.Live = &Head{Seq: c.Seq, H: c.H.String()}
		}
		return nil
	})
	if errors.Is(err, ErrNoApproval) {
		return nil, nil
	}
	return info, err
}

// ApprovalsRemaining reports how many approvals the budget allows now.
func (s *Store) ApprovalsRemaining() (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.needServer(); err != nil {
		return 0, err
	}
	unlock, err := s.lockFile()
	if err != nil {
		return 0, err
	}
	defer unlock()
	budget, err := s.loadBudget()
	if err != nil {
		return 0, err
	}
	return budget.Remaining(), nil
}

// ApproveFinish adds the confirmed device (§7 step 5): it prepares its
// device_add (a fresh device ID, the certificate with enroll_transcript =
// SHA-256(T), and the unlock blob for its KEM key), posts it in a normal
// entry through r, and once a pull has verified that entry from the
// server's log, seals the delivery, with the genesis or checkpoint entry of
// the certificate's akv as its anchor. It returns the delivery for the
// relay. Called again, it returns the same delivery.
//
// The candidate is journaled before it is posted. A post with an uncertain
// outcome is posted again identically while the server's head is its prev;
// a 409 or a moved head rebuilds it against the new head, with the same
// device_add. Past the deadline nothing new is posted. A checkpoint that
// changes the account keys before the entry commits fails the attempt.
func (s *Store) ApproveFinish(ctx context.Context, r Remote) (crypto.HPKEEnvelope, error) {
	if r == nil {
		return crypto.HPKEEnvelope{}, errors.New("store: no server")
	}
	if err := s.lockSync(); err != nil {
		return crypto.HPKEEnvelope{}, err
	}
	defer s.syncMu.Unlock()
	for attempt := 0; attempt < 2*maxPushAttempts; attempt++ {
		if err := s.pullLocked(ctx, r); err != nil {
			return crypto.HPKEEnvelope{}, err
		}
		ctx2, gen, done, err := s.syncContext(ctx)
		if err != nil {
			return crypto.HPKEEnvelope{}, err
		}
		env, w, err := s.prepareApproval(gen, attempt < maxPushAttempts)
		if err != nil || w == nil {
			done()
			return env, err
		}
		if err := s.hook("approve:post"); err != nil {
			done()
			return crypto.HPKEEnvelope{}, err
		}
		_, err = r.Post(ctx2, w)
		done()
		if err != nil && !errors.Is(err, ErrHeadConflict) {
			return crypto.HPKEEnvelope{}, err
		}
	}
	return crypto.HPKEEnvelope{}, errors.New("store: the server did not commit the new device; run hop auth approve again")
}

// prepareApproval decides the next step after a pull: the delivery once
// the device_add is verified as committed, or the wire to post, journaled
// first. The caller holds syncMu.
func (s *Store) prepareApproval(gen uint64, mayBuild bool) (crypto.HPKEEnvelope, *vaultlog.Wire, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.current(gen); err != nil {
		return crypto.HPKEEnvelope{}, nil, err
	}
	unlock, err := s.lockFile()
	if err != nil {
		return crypto.HPKEEnvelope{}, nil, err
	}
	defer unlock()
	_, a, j, err := s.loadApproval()
	if err != nil {
		return crypto.HPKEEnvelope{}, nil, err
	}
	if a == nil {
		return crypto.HPKEEnvelope{}, nil, ErrNoApproval
	}
	switch a.State() {
	case crypto.ApprovalDelivered:
		env, err := a.Deliver(0, crypto.Hash{})
		return env, nil, err
	case crypto.ApprovalConfirmed:
		id, err := vaultlog.NewID()
		if err != nil {
			return crypto.HPKEEnvelope{}, nil, err
		}
		if _, err := a.Prepare(s.sec.Account, id, s.now()); err != nil {
			return crypto.HPKEEnvelope{}, nil, err
		}
	case crypto.ApprovalPrepared:
	default:
		return crypto.HPKEEnvelope{}, nil, fmt.Errorf("%w: the approval is %s, not confirmed", crypto.ErrEnrollState, a.State())
	}
	pd, err := a.Prepared()
	if err != nil {
		return crypto.HPKEEnvelope{}, nil, err
	}
	head := s.state.Head
	// Only verified history settles the candidate.
	if c := j.live(); c != nil && c.Seq <= head.Seq {
		h, err := s.entryHash(c.Seq)
		if err != nil {
			return crypto.HPKEEnvelope{}, nil, err
		}
		next := *j
		next.Candidates = append([]candidate(nil), j.Candidates...)
		for i := range next.Candidates {
			if next.Candidates[i].Status == statusLive {
				if h.Equal(c.H) {
					next.Candidates[i].Status = statusCommitted
				} else {
					next.Candidates[i].Status = statusDead
				}
			}
		}
		next.Wires = []canonjson.Raw{}
		if err := s.writeApproval(&next); err != nil {
			return crypto.HPKEEnvelope{}, nil, err
		}
		*j = next
	}
	for _, c := range j.Candidates {
		if c.Status != statusCommitted {
			continue
		}
		if err := s.hook("approve:deliver"); err != nil {
			return crypto.HPKEEnvelope{}, nil, err
		}
		seq, h, err := s.anchorFor(pd.Cert.AKV, c.Seq)
		if err != nil {
			return crypto.HPKEEnvelope{}, nil, err
		}
		env, err := a.Deliver(seq, h)
		return env, nil, err
	}
	if c := j.live(); c != nil {
		if c.Seq != head.Seq+1 || !c.Prev.Equal(head.H) || len(j.Wires) != 1 {
			return crypto.HPKEEnvelope{}, nil, fmt.Errorf("%w: the approval journal has a live candidate at seq %d that verified history has not settled", ErrCorrupt, c.Seq)
		}
		w, err := vaultlog.ParseWire(j.Wires[0])
		if err != nil {
			return crypto.HPKEEnvelope{}, nil, fmt.Errorf("%w: the approval journal's wire: %v", ErrCorrupt, err)
		}
		if h, err := w.Entry.Hash(); err != nil || !h.Equal(c.H) {
			return crypto.HPKEEnvelope{}, nil, fmt.Errorf("%w: the approval journal's wire does not match its H", ErrCorrupt)
		}
		return crypto.HPKEEnvelope{}, w, nil
	}
	if !mayBuild {
		return crypto.HPKEEnvelope{}, nil, errors.New("store: the new device did not commit; another device keeps writing first")
	}
	if pd.Cert.AKV != s.state.Account.AKV {
		// A checkpoint replaced the account keys the user confirmed: the
		// certificate can't be used now.
		if err := a.Abort(); err != nil {
			return crypto.HPKEEnvelope{}, nil, err
		}
		return crypto.HPKEEnvelope{}, nil, errors.New("store: the account keys changed during the approval; start it again on the new device")
	}
	w, _, nsec, err := vaultlog.BuildNormal(s.state, s.sec, s.dev, vaultlog.Changes{Enrolled: []vaultlog.EnrolledDevice{{
		Cert: pd.Cert, CertSig: pd.CertSig, KEMPK: pd.KEMPK, SigPK: pd.SigPK, Unlock: pd.Unlock,
	}}}, s.now(), objectDir(s.l.objects()))
	if err != nil {
		return crypto.HPKEEnvelope{}, nil, err
	}
	// The candidate's secrets are for its verification only.
	supersede(nsec, s.sec)
	h, err := w.Entry.Hash()
	if err != nil {
		return crypto.HPKEEnvelope{}, nil, err
	}
	raw, err := w.Marshal()
	if err != nil {
		return crypto.HPKEEnvelope{}, nil, err
	}
	prev, _ := w.Entry.Prev.Get()
	next := *j
	next.Candidates = append(append([]candidate(nil), j.Candidates...), candidate{Seq: w.Entry.Seq, Prev: prev, H: h, Status: statusLive})
	next.Wires = []canonjson.Raw{raw}
	if err := s.writeApproval(&next); err != nil {
		return crypto.HPKEEnvelope{}, nil, err
	}
	*j = next
	return crypto.HPKEEnvelope{}, w, nil
}

// anchorFor returns the genesis or checkpoint entry at or before seq, which
// must be the anchor of akv (§7: anchor_seq and anchor_h name the entry of
// the akv the delivered certificate uses). The caller holds the file lock.
func (s *Store) anchorFor(akv uint32, seq uint64) (uint64, crypto.Hash, error) {
	for {
		w, err := s.l.readEntry(seq)
		if err != nil {
			return 0, crypto.Hash{}, err
		}
		if k := w.Entry.Kind; k == vaultlog.KindGenesis || k == vaultlog.KindCheckpoint {
			if w.Entry.AKV != akv {
				return 0, crypto.Hash{}, fmt.Errorf("%w: the anchor before seq %d has akv %d, not %d", ErrCorrupt, seq, w.Entry.AKV, akv)
			}
			h, err := w.Entry.Hash()
			return seq, h, err
		}
		if seq == 0 {
			return 0, crypto.Hash{}, fmt.Errorf("%w: no anchor before the enrollment entry", ErrCorrupt)
		}
		seq--
	}
}
