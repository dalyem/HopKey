package crypto

import (
	"crypto/ed25519"
	"crypto/hpke"
	"crypto/rand"
	"crypto/subtle"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/dalyem/hopkey/internal/canonjson"
	"github.com/dalyem/hopkey/internal/model"
)

// Persister durably stores the latest state of one enrollment party or of
// the approval budget. Persist must not return until the bytes are durable
// (fsynced); the state machines call it before they return any message to
// send, so a message never leaves ahead of the state that produced it.
//
// Device enrollment state contains the new device's private keys. The
// caller stores it the way §11 stores device keys.
//
// The serialized form is local state, not a wire format, and may change.
type Persister interface {
	Persist(state []byte) error
}

// Clock returns the current time. Tests inject a fake one.
type Clock func() time.Time

// Errors from the enrollment state machines.
var (
	ErrEnrollState          = errors.New("crypto: enrollment message not valid in the current state")
	ErrChalAfterReveal      = errors.New("crypto: a challenge was already accepted for this enrollment")
	ErrWrongEnrollID        = errors.New("crypto: challenge is for a different enrollment")
	ErrCommitMismatch       = errors.New("crypto: open does not match the commitment")
	ErrBudgetExhausted      = errors.New("crypto: approval budget exhausted (3 attempts per rolling hour)")
	ErrChallengeOutstanding = errors.New("crypto: this device already has an outstanding approval")
)

// --- the approving device's budget ---

const (
	budgetAttempts = 3
	budgetWindow   = time.Hour
)

type budgetRecord struct {
	V            int               `json:"v"`
	Reservations []model.Timestamp `json:"reservations"`
	Outstanding  model.ID          `json:"outstanding"` // "" when none
}

// ApprovalBudget is A's persistent approval budget (§7 step 2): at most 3
// reserved attempts per rolling hour, outstanding challenges counted, and
// at most one outstanding challenge at a time. A slot stays spent after its
// attempt ends, whatever the outcome. Restarting does not reset it, because
// every change is persisted before it takes effect.
//
// A reservation whose time lies in the future (the clock moved back) keeps
// counting until the clock passes it plus an hour.
//
// Methods are not safe for concurrent use, and two processes must not load
// the same budget at once; the caller serializes approvals (for example
// with internal/filelock).
//
// SPEC GAP (§7): nothing bounds how long a challenge stays outstanding. If
// D never answers, the approving device stays blocked until the caller ends
// the attempt (Approval.Abort). No timeout is invented here.
type ApprovalBudget struct {
	p   Persister
	now Clock
	rec budgetRecord
}

// LoadApprovalBudget restores a budget from its persisted bytes, or starts
// an empty one when state is empty.
func LoadApprovalBudget(p Persister, now Clock, state []byte) (*ApprovalBudget, error) {
	b := &ApprovalBudget{p: p, now: now, rec: budgetRecord{V: Version}}
	if len(state) == 0 {
		return b, nil
	}
	if err := canonjson.Unmarshal(state, &b.rec); err != nil {
		return nil, err
	}
	if b.rec.V != Version {
		return nil, ErrUnsupported
	}
	return b, nil
}

func (b *ApprovalBudget) live(now time.Time) []model.Timestamp {
	var out []model.Timestamp
	for _, r := range b.rec.Reservations {
		if now.Before(r.Time().Add(budgetWindow)) {
			out = append(out, r)
		}
	}
	return out
}

// Remaining reports how many attempts could be reserved now.
func (b *ApprovalBudget) Remaining() int {
	if !b.rec.Outstanding.IsZero() {
		return 0
	}
	return max(0, budgetAttempts-len(b.live(b.now())))
}

// Reserve atomically reserves an attempt for enrollID and persists it.
func (b *ApprovalBudget) Reserve(enrollID model.ID) error {
	if enrollID.IsZero() {
		return errors.New("crypto: zero enroll ID")
	}
	now := b.now()
	if !b.rec.Outstanding.IsZero() {
		return ErrChallengeOutstanding
	}
	live := b.live(now)
	if len(live) >= budgetAttempts {
		return ErrBudgetExhausted
	}
	next := budgetRecord{V: Version, Reservations: append(live, model.TimestampOf(now)), Outstanding: enrollID}
	if err := b.persist(next); err != nil {
		return err
	}
	b.rec = next
	return nil
}

// finish ends the outstanding attempt for enrollID. Its slot stays spent.
func (b *ApprovalBudget) finish(enrollID model.ID) error {
	if b.rec.Outstanding != enrollID {
		return nil
	}
	next := budgetRecord{V: Version, Reservations: slices.Clone(b.rec.Reservations)}
	if err := b.persist(next); err != nil {
		return err
	}
	b.rec = next
	return nil
}

func (b *ApprovalBudget) persist(r budgetRecord) error {
	j, err := canonjson.Marshal(r)
	if err != nil {
		return err
	}
	return b.p.Persist(j)
}

// --- D: the new device ---

// DeviceEnrollState names D's states.
type DeviceEnrollState string

const (
	DeviceCommitted DeviceEnrollState = "committed"
	DeviceRevealed  DeviceEnrollState = "revealed"
	DeviceDone      DeviceEnrollState = "done"
)

type deviceRecord struct {
	V        int               `json:"v"`
	State    DeviceEnrollState `json:"state"`
	KEMSK    []byte            `json:"kem_sk"`
	SigSeed  []byte            `json:"sig_seed"`
	ND       []byte            `json:"nD"`
	Name     string            `json:"name"`
	EnrollID model.ID          `json:"enroll_id"` // "" until the server assigns it
	Chal     *EnrollChal       `json:"chal"`
	Cert     *Cert             `json:"cert"`
	CertSig  []byte            `json:"cert_sig"`
}

// DeviceEnrollment is D's side of §7. Every transition is persisted before
// the method returns the message it produces.
type DeviceEnrollment struct {
	p    Persister
	rec  deviceRecord
	kem  hpke.PrivateKey
	sig  ed25519.PrivateKey
	open EnrollOpen
}

// NewDeviceEnrollment generates D's keys and nD, persists them (state
// COMMITTED) and returns the commit message to post.
func NewDeviceEnrollment(p Persister, name string) (*DeviceEnrollment, EnrollCommit, error) {
	if err := CheckStr("name", name, 64); err != nil {
		return nil, EnrollCommit{}, err
	}
	kem, err := GenerateKEMKey()
	if err != nil {
		return nil, EnrollCommit{}, err
	}
	kemSK, err := kem.Bytes()
	if err != nil {
		return nil, EnrollCommit{}, err
	}
	_, sig, err := ed25519.GenerateKey(nil)
	if err != nil {
		return nil, EnrollCommit{}, err
	}
	nD := make([]byte, EnrollNonceSize)
	if _, err := rand.Read(nD); err != nil {
		return nil, EnrollCommit{}, err
	}
	rec := deviceRecord{V: Version, State: DeviceCommitted, KEMSK: kemSK, SigSeed: sig.Seed(), ND: nD, Name: name}
	d, err := newDevice(p, rec)
	if err != nil {
		return nil, EnrollCommit{}, err
	}
	if err := d.save(rec); err != nil {
		return nil, EnrollCommit{}, err
	}
	return d, d.Commit(), nil
}

// RestoreDeviceEnrollment loads D's persisted state after a restart.
func RestoreDeviceEnrollment(p Persister, state []byte) (*DeviceEnrollment, error) {
	var rec deviceRecord
	if err := canonjson.Unmarshal(state, &rec); err != nil {
		return nil, err
	}
	if rec.V != Version {
		return nil, ErrUnsupported
	}
	switch rec.State {
	case DeviceCommitted, DeviceRevealed, DeviceDone:
	default:
		return nil, fmt.Errorf("crypto: unknown enrollment state %q", rec.State)
	}
	if (rec.State != DeviceCommitted) != (rec.Chal != nil) || (rec.State == DeviceDone) != (rec.Cert != nil) {
		return nil, errors.New("crypto: inconsistent enrollment state")
	}
	return newDevice(p, rec)
}

func newDevice(p Persister, rec deviceRecord) (*DeviceEnrollment, error) {
	kem, err := ParseKEMPrivateKey(rec.KEMSK)
	if err != nil {
		return nil, err
	}
	if len(rec.SigSeed) != ed25519.SeedSize || len(rec.ND) != EnrollNonceSize {
		return nil, errors.New("crypto: corrupt enrollment state")
	}
	sig := ed25519.NewKeyFromSeed(rec.SigSeed)
	d := &DeviceEnrollment{p: p, rec: rec, kem: kem, sig: sig}
	d.open = EnrollOpen{V: Version, KEMPK: kem.PublicKey().Bytes(), SigPK: sig.Public().(ed25519.PublicKey), ND: rec.ND, Name: rec.Name}
	return d, nil
}

func (d *DeviceEnrollment) save(rec deviceRecord) error {
	j, err := canonjson.Marshal(rec)
	if err != nil {
		return err
	}
	defer clear(j)
	if err := d.p.Persist(j); err != nil {
		return err
	}
	d.rec = rec
	return nil
}

// State returns D's current state.
func (d *DeviceEnrollment) State() DeviceEnrollState { return d.rec.State }

// Commit returns the commit message. It is the same after a restart, so an
// uncertain post can be repeated.
func (d *DeviceEnrollment) Commit() EnrollCommit {
	return EnrollCommit{V: Version, C: Commitment(&d.open)}
}

// SetEnrollID records the enroll_id the server returned for the commit.
// It can be set once.
func (d *DeviceEnrollment) SetEnrollID(id model.ID) error {
	if id.IsZero() {
		return errors.New("crypto: zero enroll ID")
	}
	if d.rec.State != DeviceCommitted {
		return ErrEnrollState
	}
	if !d.rec.EnrollID.IsZero() {
		if d.rec.EnrollID == id {
			return nil
		}
		return errors.New("crypto: enroll ID already set")
	}
	rec := d.rec
	rec.EnrollID = id
	return d.save(rec)
}

// HandleChal accepts exactly one chal, whose enroll_id must equal the
// persisted session ID, persists it (REVEALED) and returns open. Any chal
// after that is rejected. A chal that fails validation changes nothing.
func (d *DeviceEnrollment) HandleChal(ch *EnrollChal) (EnrollOpen, error) {
	switch d.rec.State {
	case DeviceCommitted:
	case DeviceRevealed, DeviceDone:
		return EnrollOpen{}, ErrChalAfterReveal
	default:
		return EnrollOpen{}, ErrEnrollState
	}
	if d.rec.EnrollID.IsZero() {
		return EnrollOpen{}, ErrEnrollState
	}
	if err := ch.Validate(); err != nil {
		return EnrollOpen{}, err
	}
	if ch.EnrollID != d.rec.EnrollID {
		return EnrollOpen{}, ErrWrongEnrollID
	}
	rec := d.rec
	rec.State = DeviceRevealed
	c := *ch
	c.NA = slices.Clone(ch.NA)
	rec.Chal = &c
	if err := d.save(rec); err != nil {
		return EnrollOpen{}, err
	}
	return d.open, nil
}

// Open returns the open message once REVEALED, for re-sending after a
// restart.
func (d *DeviceEnrollment) Open() (EnrollOpen, error) {
	if d.rec.State != DeviceRevealed {
		return EnrollOpen{}, ErrEnrollState
	}
	return d.open, nil
}

func (d *DeviceEnrollment) transcript() []byte {
	return Transcript(Commitment(&d.open), d.rec.Chal, &d.open)
}

// SAS returns the 8-digit code D shows once REVEALED.
func (d *DeviceEnrollment) SAS() (string, error) {
	if d.rec.Chal == nil {
		return "", ErrEnrollState
	}
	return SAS(d.transcript())
}

// HandleDelivery verifies A's delivery (VerifyDelivery) and persists DONE.
// A delivery that fails verification changes nothing. The caller then runs
// the anchor algorithm from AnchorSeq/AnchorH and the transitions, and
// requires the result to contain this device's device_add with the
// delivered certificate.
func (d *DeviceEnrollment) HandleDelivery(e HPKEEnvelope) (*VerifiedDelivery, error) {
	if d.rec.State != DeviceRevealed {
		return nil, ErrEnrollState
	}
	v, err := VerifyDelivery(d.kem, d.open.SigPK, d.rec.Chal, d.transcript(), e)
	if err != nil {
		return nil, err
	}
	rec := d.rec
	rec.State = DeviceDone
	cert := v.Cert
	rec.Cert = &cert
	rec.CertSig = v.CertSig
	if err := d.save(rec); err != nil {
		v.Account.Zero()
		return nil, err
	}
	return v, nil
}

// DeviceKeys returns D's new device keys.
func (d *DeviceEnrollment) DeviceKeys() (hpke.PrivateKey, ed25519.PrivateKey) { return d.kem, d.sig }

// --- A: the approving device ---

// ApprovalState names A's states.
type ApprovalState string

const (
	ApprovalReserved   ApprovalState = "reserved"
	ApprovalChallenged ApprovalState = "challenged"
	ApprovalOpened     ApprovalState = "opened"
	ApprovalConfirmed  ApprovalState = "confirmed"
	ApprovalPrepared   ApprovalState = "prepared"
	ApprovalDelivered  ApprovalState = "delivered"
	ApprovalFailed     ApprovalState = "failed"
)

type approvalRecord struct {
	V        int           `json:"v"`
	State    ApprovalState `json:"state"`
	EnrollID model.ID      `json:"enroll_id"`
	Approver model.ID      `json:"approver_device_id"`
	Account  model.ID      `json:"account_id"`
	AKV      uint32        `json:"akv"`
	SigFp    Hash          `json:"acct_sig_fp"`
	Commit   *EnrollCommit `json:"commit"`
	Chal     *EnrollChal   `json:"chal"`
	Open     *EnrollOpen   `json:"open"`
	Cert     *Cert         `json:"cert"`
	CertSig  []byte        `json:"cert_sig"`
	Unlock   *HPKEEnvelope `json:"unlock"`
	Delivery *HPKEEnvelope `json:"delivery"`
}

// Approval is A's side of §7. Every transition is persisted before the
// method returns the message it produces.
type Approval struct {
	p      Persister
	budget *ApprovalBudget
	rec    approvalRecord
}

// StartApproval reserves a budget attempt for enrollID (hop approve CODE)
// and persists the new attempt. pin is A's pinned account; approver is A's
// device ID.
func StartApproval(budget *ApprovalBudget, p Persister, enrollID model.ID, pin AccountPin, approver model.ID) (*Approval, error) {
	if pin.AccountID.IsZero() || approver.IsZero() {
		return nil, errors.New("crypto: approval needs the account and approver IDs")
	}
	if err := budget.Reserve(enrollID); err != nil {
		return nil, err
	}
	a := &Approval{p: p, budget: budget}
	rec := approvalRecord{V: Version, State: ApprovalReserved, EnrollID: enrollID, Approver: approver,
		Account: pin.AccountID, AKV: pin.AKV, SigFp: pin.FpSig}
	if err := a.save(rec); err != nil {
		// The slot stays spent; the attempt is over.
		_ = budget.finish(enrollID)
		return nil, err
	}
	return a, nil
}

// RestoreApproval loads A's persisted attempt after a restart.
func RestoreApproval(budget *ApprovalBudget, p Persister, state []byte) (*Approval, error) {
	var rec approvalRecord
	if err := canonjson.Unmarshal(state, &rec); err != nil {
		return nil, err
	}
	if rec.V != Version {
		return nil, ErrUnsupported
	}
	switch rec.State {
	case ApprovalReserved, ApprovalChallenged, ApprovalOpened, ApprovalConfirmed,
		ApprovalPrepared, ApprovalDelivered, ApprovalFailed:
	default:
		return nil, fmt.Errorf("crypto: unknown approval state %q", rec.State)
	}
	a := &Approval{p: p, budget: budget, rec: rec}
	if rec.State == ApprovalDelivered || rec.State == ApprovalFailed {
		// A crash can land between persisting the end of the attempt and
		// releasing the budget's outstanding mark.
		if err := budget.finish(rec.EnrollID); err != nil {
			return nil, err
		}
	}
	return a, nil
}

func (a *Approval) save(rec approvalRecord) error {
	j, err := canonjson.Marshal(rec)
	if err != nil {
		return err
	}
	if err := a.p.Persist(j); err != nil {
		return err
	}
	a.rec = rec
	return nil
}

// State returns A's current state.
func (a *Approval) State() ApprovalState { return a.rec.State }

// EnrollID returns the attempt's enroll_id.
func (a *Approval) EnrollID() model.ID { return a.rec.EnrollID }

// HandleCommit accepts exactly one commit for the attempt, persists it with
// a fresh nA and returns chal.
func (a *Approval) HandleCommit(c *EnrollCommit) (EnrollChal, error) {
	if a.rec.State != ApprovalReserved {
		return EnrollChal{}, ErrEnrollState
	}
	if err := c.Validate(); err != nil {
		return EnrollChal{}, err
	}
	nA := make([]byte, EnrollNonceSize)
	if _, err := rand.Read(nA); err != nil {
		return EnrollChal{}, err
	}
	ch := EnrollChal{V: Version, EnrollID: a.rec.EnrollID, NA: nA, AccountID: a.rec.Account,
		ApproverDeviceID: a.rec.Approver, AcctSigFp: a.rec.SigFp, AKV: a.rec.AKV}
	cm := *c
	rec := a.rec
	rec.State = ApprovalChallenged
	rec.Commit = &cm
	rec.Chal = &ch
	if err := a.save(rec); err != nil {
		return EnrollChal{}, err
	}
	return ch, nil
}

// Chal returns the persisted chal for re-sending.
func (a *Approval) Chal() (EnrollChal, error) {
	if a.rec.Chal == nil || a.rec.State != ApprovalChallenged {
		return EnrollChal{}, ErrEnrollState
	}
	return *a.rec.Chal, nil
}

// HandleOpen checks that open matches c, persists it and returns the SAS
// and device name for the user to compare. An open that does not match
// changes nothing. If the SAS derivation aborts, the attempt fails.
func (a *Approval) HandleOpen(o *EnrollOpen) (sas, name string, err error) {
	if a.rec.State != ApprovalChallenged {
		return "", "", ErrEnrollState
	}
	if err := o.Validate(); err != nil {
		return "", "", err
	}
	c := Commitment(o)
	if subtle.ConstantTimeCompare(c[:], a.rec.Commit.C[:]) != 1 {
		return "", "", ErrCommitMismatch
	}
	sas, err = SAS(Transcript(c, a.rec.Chal, o))
	if err != nil {
		if ferr := a.fail(); ferr != nil {
			return "", "", ferr
		}
		return "", "", err
	}
	om := *o
	rec := a.rec
	rec.State = ApprovalOpened
	rec.Open = &om
	if err := a.save(rec); err != nil {
		return "", "", err
	}
	return sas, o.Name, nil
}

// SAS returns the code again once OPENED, for showing after a restart.
func (a *Approval) SAS() (sas, name string, err error) {
	if a.rec.Open == nil {
		return "", "", ErrEnrollState
	}
	sas, err = SAS(a.transcript())
	return sas, a.rec.Open.Name, err
}

func (a *Approval) transcript() []byte {
	return Transcript(a.rec.Commit.C, a.rec.Chal, a.rec.Open)
}

// Confirm records the user's comparison. A mismatch ends the attempt as a
// failure, and its budget slot stays spent.
func (a *Approval) Confirm(match bool) error {
	if a.rec.State != ApprovalOpened {
		return ErrEnrollState
	}
	if !match {
		return a.fail()
	}
	rec := a.rec
	rec.State = ApprovalConfirmed
	return a.save(rec)
}

// PreparedDevice is the device_add material A puts in its normal entry.
type PreparedDevice struct {
	Cert    Cert
	CertSig []byte
	KEMPK   []byte
	SigPK   []byte
	Unlock  HPKEEnvelope
}

// Prepare builds the certificate (enroll_transcript = SHA-256(T)), signs
// it and seals the unlock blob to D's KEM key, then persists them. acct
// must be the pinned account the challenge named.
func (a *Approval) Prepare(acct *AccountKeys, deviceID model.ID, issuedAt model.Timestamp) (*PreparedDevice, error) {
	if a.rec.State != ApprovalConfirmed {
		return nil, ErrEnrollState
	}
	pin := acct.Pin()
	if pin.AccountID != a.rec.Account || pin.AKV != a.rec.AKV || !pin.FpSig.Equal(a.rec.SigFp) {
		return nil, ErrAccountMismatch
	}
	o := a.rec.Open
	th := TranscriptHash(a.transcript())
	cert := Cert{V: Version, AccountID: a.rec.Account, AKV: a.rec.AKV, DeviceID: deviceID, Name: o.Name,
		KEMFp: FpKEM(o.KEMPK), SigFp: FpSig(o.SigPK), EnrollTranscript: OptHash(th), IssuedAt: issuedAt}
	sig, err := SignCert(acct, &cert)
	if err != nil {
		return nil, err
	}
	unlock, err := SealUnlock(o.KEMPK, &cert, acct)
	if err != nil {
		return nil, err
	}
	rec := a.rec
	rec.State = ApprovalPrepared
	rec.Cert = &cert
	rec.CertSig = sig
	rec.Unlock = &unlock
	if err := a.save(rec); err != nil {
		return nil, err
	}
	return a.Prepared()
}

// Prepared returns the persisted device_add material.
func (a *Approval) Prepared() (*PreparedDevice, error) {
	if a.rec.Cert == nil {
		return nil, ErrEnrollState
	}
	return &PreparedDevice{Cert: *a.rec.Cert, CertSig: a.rec.CertSig, KEMPK: a.rec.Open.KEMPK,
		SigPK: a.rec.Open.SigPK, Unlock: *a.rec.Unlock}, nil
}

// Deliver seals the delivery to D and persists it, ending the attempt. Call
// it only after the normal entry carrying the device_add has committed.
// anchorSeq and anchorH identify the genesis or checkpoint entry for the
// current akv.
func (a *Approval) Deliver(anchorSeq uint64, anchorH Hash) (HPKEEnvelope, error) {
	switch a.rec.State {
	case ApprovalPrepared:
	case ApprovalDelivered:
		return *a.rec.Delivery, nil
	default:
		return HPKEEnvelope{}, ErrEnrollState
	}
	d := EnrollDelivery{V: Version, Cert: *a.rec.Cert, CertSig: a.rec.CertSig, Unlock: *a.rec.Unlock,
		AnchorSeq: anchorSeq, AnchorH: anchorH}
	env, err := SealDelivery(a.rec.Open.KEMPK, TranscriptHash(a.transcript()), &d)
	if err != nil {
		return HPKEEnvelope{}, err
	}
	rec := a.rec
	rec.State = ApprovalDelivered
	rec.Delivery = &env
	if err := a.save(rec); err != nil {
		return HPKEEnvelope{}, err
	}
	if err := a.budget.finish(a.rec.EnrollID); err != nil {
		return HPKEEnvelope{}, err
	}
	return env, nil
}

// Abort ends an unfinished attempt as a failure. The slot stays spent. If
// the device_add has already committed, the device exists in the log
// regardless; removing it takes a checkpoint.
func (a *Approval) Abort() error {
	switch a.rec.State {
	case ApprovalDelivered, ApprovalFailed:
		return a.budget.finish(a.rec.EnrollID)
	}
	return a.fail()
}

func (a *Approval) fail() error {
	rec := a.rec
	rec.State = ApprovalFailed
	if err := a.save(rec); err != nil {
		return err
	}
	return a.budget.finish(a.rec.EnrollID)
}
