package crypto

import (
	"bytes"
	"crypto/ed25519"
	"crypto/hpke"
	"crypto/rand"
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
	ErrEnrollExpired        = errors.New("crypto: the enrollment deadline passed and the attempt failed")
	ErrSASNotConfirmed      = errors.New("crypto: delivery discarded: the user has not confirmed the SAS on this device")
	ErrSASRejected          = errors.New("crypto: the user rejected the SAS; this enrollment is over")
)

// EnrollDeadline bounds an attempt (§7): 10 minutes from COMMITTED on D and
// from CHALLENGED on A. When it passes, the attempt is a failure, its budget
// slot stays spent, and A's outstanding-challenge slot is released.
const EnrollDeadline = 10 * time.Minute

// expired reports whether now is at or past deadline.
func expired(now time.Time, deadline model.Timestamp) bool { return !now.Before(deadline.Time()) }

func deadlineFrom(now time.Time) model.Timestamp { return model.TimestampOf(now.Add(EnrollDeadline)) }

// --- the approving device's budget ---

const (
	budgetAttempts = 3
	budgetWindow   = time.Hour
)

type budgetRecord struct {
	V            int               `json:"v"`
	Reservations []model.Timestamp `json:"reservations"`
	Outstanding  model.ID          `json:"outstanding"` // "" when none
	Deadline     model.Timestamp   `json:"deadline"`    // when Outstanding is released; 0 when none
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
// The outstanding challenge is released when its attempt ends or when its
// deadline passes (§7), whichever comes first, so a device that never
// answers blocks approvals for at most EnrollDeadline. The deadline starts
// at the reservation and moves to CHALLENGED + EnrollDeadline when A sends
// chal; the reservation itself is part of the attempt, so it is bounded the
// same way.
//
// Methods are not safe for concurrent use, and two processes must not load
// the same budget at once; the caller serializes approvals (for example
// with internal/filelock).
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

// outstanding reports whether a challenge is outstanding at now: one is
// recorded and its deadline has not passed.
func (b *ApprovalBudget) outstanding(now time.Time) bool {
	return !b.rec.Outstanding.IsZero() && !expired(now, b.rec.Deadline)
}

// Remaining reports how many attempts could be reserved now.
func (b *ApprovalBudget) Remaining() int {
	now := b.now()
	if b.outstanding(now) {
		return 0
	}
	return max(0, budgetAttempts-len(b.live(now)))
}

// Reserve atomically reserves an attempt for enrollID and persists it.
func (b *ApprovalBudget) Reserve(enrollID model.ID) error {
	if enrollID.IsZero() {
		return errors.New("crypto: zero enroll ID")
	}
	now := b.now()
	if b.outstanding(now) {
		return ErrChallengeOutstanding
	}
	live := b.live(now)
	if len(live) >= budgetAttempts {
		return ErrBudgetExhausted
	}
	next := budgetRecord{V: Version, Reservations: append(live, model.TimestampOf(now)), Outstanding: enrollID,
		Deadline: deadlineFrom(now)}
	if err := b.persist(next); err != nil {
		return err
	}
	b.rec = next
	return nil
}

// challenged moves the outstanding deadline of enrollID to deadline, the
// CHALLENGED time plus EnrollDeadline.
func (b *ApprovalBudget) challenged(enrollID model.ID, deadline model.Timestamp) error {
	if b.rec.Outstanding != enrollID {
		return nil
	}
	next := b.rec
	next.Reservations = slices.Clone(b.rec.Reservations)
	next.Deadline = deadline
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
	DeviceConfirmed DeviceEnrollState = "confirmed" // the user confirmed the SAS on D
	DeviceRejected  DeviceEnrollState = "rejected"  // the user rejected the SAS on D; terminal, keys wiped
	DeviceDone      DeviceEnrollState = "done"
	DeviceFailed    DeviceEnrollState = "failed" // the deadline passed; terminal, keys wiped
)

type deviceRecord struct {
	V        int               `json:"v"`
	State    DeviceEnrollState `json:"state"`
	KEMSK    []byte            `json:"kem_sk"`
	SigSeed  []byte            `json:"sig_seed"`
	ND       []byte            `json:"nD"`
	Name     string            `json:"name"`
	Deadline model.Timestamp   `json:"deadline"`  // COMMITTED + EnrollDeadline
	EnrollID model.ID          `json:"enroll_id"` // "" until the server assigns it
	Chal     *EnrollChal       `json:"chal"`
	Cert     *Cert             `json:"cert"`
	CertSig  []byte            `json:"cert_sig"`
	Delivery *HPKEEnvelope     `json:"delivery"` // the verified delivery, once DONE
}

// DeviceEnrollment is D's side of §7. Every transition is persisted before
// the method returns the message it produces. Messages that fail their
// checks are discarded with no change of state, so the real message can
// still arrive before the deadline.
//
// Once REVEALED, the user compares the SAS with A's and records the result
// with ConfirmSAS or RejectSAS. D accepts a delivery only in CONFIRMED.
// REJECTED is terminal: the enrollment keys are wiped and every later call
// fails with ErrSASRejected. FAILED (the deadline passed) is terminal the
// same way, with ErrEnrollExpired.
//
// Messages passed in and returned are copied; the caller may reuse or
// change its buffers.
type DeviceEnrollment struct {
	p    Persister
	now  Clock
	rec  deviceRecord
	kem  hpke.PrivateKey
	sig  ed25519.PrivateKey
	open EnrollOpen
}

// NewDeviceEnrollment is NewDeviceEnrollmentWithClock with the system clock.
func NewDeviceEnrollment(p Persister, name string) (*DeviceEnrollment, EnrollCommit, error) {
	return NewDeviceEnrollmentWithClock(p, time.Now, name)
}

// NewDeviceEnrollmentWithClock generates D's keys and nD, persists them
// (state COMMITTED, with the deadline now + EnrollDeadline) and returns the
// commit message to post.
func NewDeviceEnrollmentWithClock(p Persister, now Clock, name string) (*DeviceEnrollment, EnrollCommit, error) {
	if err := CheckStr("name", name, 64); err != nil {
		return nil, EnrollCommit{}, err
	}
	kem, err := GenerateKEMKey()
	if err != nil {
		return nil, EnrollCommit{}, err
	}
	kemSK, err := kemPrivateBytes(kem)
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
	rec := deviceRecord{V: Version, State: DeviceCommitted, KEMSK: kemSK, SigSeed: sig.Seed(), ND: nD, Name: name,
		Deadline: deadlineFrom(now())}
	d, err := newDevice(p, now, rec)
	if err != nil {
		return nil, EnrollCommit{}, err
	}
	if err := d.save(rec); err != nil {
		return nil, EnrollCommit{}, err
	}
	return d, d.Commit(), nil
}

// RestoreDeviceEnrollment is RestoreDeviceEnrollmentWithClock with the
// system clock.
func RestoreDeviceEnrollment(p Persister, state []byte) (*DeviceEnrollment, error) {
	return RestoreDeviceEnrollmentWithClock(p, time.Now, state)
}

// RestoreDeviceEnrollmentWithClock loads D's persisted state after a
// restart. An unfinished attempt whose deadline has passed is failed.
// A restored challenge and the reconstructed open must pass the same
// checks the live HandleChal and NewDeviceEnrollment apply: the chal's
// closed schema and its enroll_id equal to the session's, and open's
// schema.
func RestoreDeviceEnrollmentWithClock(p Persister, now Clock, state []byte) (*DeviceEnrollment, error) {
	var rec deviceRecord
	if err := canonjson.Unmarshal(state, &rec); err != nil {
		return nil, err
	}
	if rec.V != Version {
		return nil, ErrUnsupported
	}
	switch rec.State {
	case DeviceCommitted, DeviceRevealed, DeviceConfirmed, DeviceDone:
	case DeviceRejected, DeviceFailed:
		// The record holds only the terminal state.
		if !rec.onlyState() {
			return nil, errors.New("crypto: inconsistent enrollment state")
		}
		return &DeviceEnrollment{p: p, now: now, rec: rec}, nil
	default:
		return nil, fmt.Errorf("crypto: unknown enrollment state %q", rec.State)
	}
	inconsistent := (rec.State == DeviceDone) != (rec.Cert != nil) || (rec.State == DeviceDone) != (rec.Delivery != nil)
	if (rec.State != DeviceCommitted) != (rec.Chal != nil) {
		inconsistent = true
	}
	if inconsistent {
		return nil, errors.New("crypto: inconsistent enrollment state")
	}
	if rec.Chal != nil {
		// As HandleChal accepted it: a valid chal for this session.
		if err := rec.Chal.Validate(); err != nil {
			return nil, fmt.Errorf("crypto: restored challenge: %w", err)
		}
		if rec.Chal.EnrollID != rec.EnrollID {
			return nil, ErrWrongEnrollID
		}
	}
	d, err := newDevice(p, now, rec)
	if err != nil {
		return nil, err
	}
	if err := d.open.Validate(); err != nil {
		return nil, fmt.Errorf("crypto: restored open: %w", err)
	}
	if err := d.checkDeadline(); err != nil && !errors.Is(err, ErrEnrollExpired) {
		return nil, err
	}
	return d, nil
}

func newDevice(p Persister, now Clock, rec deviceRecord) (*DeviceEnrollment, error) {
	kem, err := ParseKEMPrivateKey(rec.KEMSK)
	if err != nil {
		return nil, err
	}
	if len(rec.SigSeed) != ed25519.SeedSize || len(rec.ND) != EnrollNonceSize {
		return nil, errors.New("crypto: corrupt enrollment state")
	}
	sig := ed25519.NewKeyFromSeed(rec.SigSeed)
	d := &DeviceEnrollment{p: p, now: now, rec: rec, kem: kem, sig: sig}
	d.open = EnrollOpen{V: Version, KEMPK: kem.PublicKey().Bytes(), SigPK: sig.Public().(ed25519.PublicKey),
		ND: bytes.Clone(rec.ND), Name: rec.Name}
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

// terminalRecord is the whole persisted record of a REJECTED or FAILED
// enrollment: the state and nothing else.
func terminalRecord(s DeviceEnrollState) deviceRecord { return deviceRecord{V: Version, State: s} }

// terminal reports whether s is REJECTED or FAILED.
func terminal(s DeviceEnrollState) bool { return s == DeviceRejected || s == DeviceFailed }

// onlyState reports whether r holds nothing but its state.
func (r *deviceRecord) onlyState() bool {
	return len(r.KEMSK) == 0 && len(r.SigSeed) == 0 && len(r.ND) == 0 &&
		r.Name == "" && r.Deadline == 0 && r.EnrollID.IsZero() && r.Chal == nil && r.Cert == nil &&
		len(r.CertSig) == 0 && r.Delivery == nil
}

// checkDeadline fails an unfinished attempt whose deadline has passed and
// returns ErrEnrollExpired for a failed one and ErrSASRejected for a
// rejected one.
func (d *DeviceEnrollment) checkDeadline() error {
	switch d.rec.State {
	case DeviceDone:
		return nil
	case DeviceFailed:
		return ErrEnrollExpired
	case DeviceRejected:
		return ErrSASRejected
	}
	if !expired(d.now(), d.rec.Deadline) {
		return nil
	}
	// FAILED is terminal: like REJECTED, the persisted record keeps only
	// the state and the enrollment keys are wiped from memory.
	if err := d.end(DeviceFailed); err != nil {
		return err
	}
	return ErrEnrollExpired
}

// end persists the terminal state s (REJECTED or FAILED) as a record that
// holds nothing else, then wipes D's enrollment keys from memory. If
// persisting fails, nothing changes.
func (d *DeviceEnrollment) end(s DeviceEnrollState) error {
	old := d.rec
	if err := d.save(terminalRecord(s)); err != nil {
		return err
	}
	clear(old.KEMSK)
	clear(old.SigSeed)
	clear(old.ND)
	d.wipe()
	return nil
}

// State returns D's current state.
func (d *DeviceEnrollment) State() DeviceEnrollState { return d.rec.State }

// Deadline returns the time at which an unfinished attempt fails. A
// REJECTED or FAILED enrollment keeps no deadline and returns the zero
// Timestamp's time.
func (d *DeviceEnrollment) Deadline() time.Time { return d.rec.Deadline.Time() }

// Commit returns the commit message. It is the same after a restart, so an
// uncertain post can be repeated. A REJECTED or FAILED enrollment has no
// commit and returns the zero value.
func (d *DeviceEnrollment) Commit() EnrollCommit {
	if terminal(d.rec.State) {
		return EnrollCommit{}
	}
	return EnrollCommit{V: Version, C: Commitment(&d.open)}
}

// SetEnrollID records the enroll_id the server returned for the commit.
// It can be set once.
func (d *DeviceEnrollment) SetEnrollID(id model.ID) error {
	if id.IsZero() {
		return errors.New("crypto: zero enroll ID")
	}
	if err := d.checkDeadline(); err != nil {
		return err
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
func (d *DeviceEnrollment) HandleChal(in *EnrollChal) (EnrollOpen, error) {
	if err := d.checkDeadline(); err != nil {
		return EnrollOpen{}, err
	}
	switch d.rec.State {
	case DeviceCommitted:
	case DeviceRevealed, DeviceConfirmed, DeviceDone:
		return EnrollOpen{}, ErrChalAfterReveal
	default:
		return EnrollOpen{}, ErrEnrollState
	}
	if d.rec.EnrollID.IsZero() {
		return EnrollOpen{}, ErrEnrollState
	}
	ch := in.clone()
	if err := ch.Validate(); err != nil {
		return EnrollOpen{}, err
	}
	if ch.EnrollID != d.rec.EnrollID {
		return EnrollOpen{}, ErrWrongEnrollID
	}
	rec := d.rec
	rec.State = DeviceRevealed
	rec.Chal = ch
	if err := d.save(rec); err != nil {
		return EnrollOpen{}, err
	}
	return *d.open.clone(), nil
}

// Open returns the open message once REVEALED (or CONFIRMED), for
// re-sending after a restart.
func (d *DeviceEnrollment) Open() (EnrollOpen, error) {
	if err := d.checkDeadline(); err != nil {
		return EnrollOpen{}, err
	}
	if d.rec.State != DeviceRevealed && d.rec.State != DeviceConfirmed {
		return EnrollOpen{}, ErrEnrollState
	}
	return *d.open.clone(), nil
}

func (d *DeviceEnrollment) transcript() []byte {
	return Transcript(Commitment(&d.open), d.rec.Chal, &d.open)
}

// SAS returns the 8-digit code D shows once REVEALED.
func (d *DeviceEnrollment) SAS() (string, error) {
	if err := d.checkDeadline(); err != nil {
		return "", err
	}
	if d.rec.Chal == nil {
		return "", ErrEnrollState
	}
	return SAS(d.transcript())
}

// ConfirmSAS records that the user saw the same 8 digits on A and D (§7
// step 4) and persists CONFIRMED. Only then does D accept a delivery. It
// needs state REVEALED and an SAS that D could show.
func (d *DeviceEnrollment) ConfirmSAS() error {
	if err := d.sasDecision(); err != nil {
		return err
	}
	rec := d.rec
	rec.State = DeviceConfirmed
	return d.save(rec)
}

// RejectSAS records that the codes on A and D differ (§7 step 4) and
// persists REJECTED, which is terminal: the persisted record keeps only the
// state, the enrollment keys are wiped from memory, and every later call
// fails with ErrSASRejected. It needs state REVEALED and an SAS that D
// could show. If persisting fails, nothing changes; D stays REVEALED and
// still accepts no delivery.
func (d *DeviceEnrollment) RejectSAS() error {
	if err := d.sasDecision(); err != nil {
		return err
	}
	return d.end(DeviceRejected)
}

// sasDecision checks that the user can confirm or reject now: REVEALED,
// before the deadline, with an SAS on screen.
func (d *DeviceEnrollment) sasDecision() error {
	if err := d.checkDeadline(); err != nil {
		return err
	}
	if d.rec.State != DeviceRevealed {
		return ErrEnrollState
	}
	_, err := SAS(d.transcript())
	return err
}

// wipe clears D's enrollment keys from memory after REJECTED or FAILED was
// persisted.
// The KEM key's internal copy cannot be overwritten from here; dropping the
// reference leaves it to the garbage collector.
func (d *DeviceEnrollment) wipe() {
	clear(d.sig)
	d.sig = nil
	d.kem = nil
	clear(d.open.ND)
	d.open = EnrollOpen{}
}

func (d *DeviceEnrollment) verify(e HPKEEnvelope) (*VerifiedDelivery, error) {
	return verifyDelivery(d.kem, d.open.SigPK, d.rec.Chal, d.open.Name, TranscriptHash(d.transcript()), e)
}

// HandleDelivery verifies A's delivery (§7 step 6, including Cert.name =
// open.name) and persists DONE together with the delivery itself, so the
// result can be recovered after a crash (Delivered). A delivery that fails
// verification changes nothing. Once DONE, handing in the same delivery
// again returns the same result; any other delivery is rejected.
//
// D accepts a delivery only in CONFIRMED (§7 step 6). One that arrives
// before the user confirmed the SAS on D is discarded unopened with
// ErrSASNotConfirmed and is not kept; A or the relay must send it again.
// After RejectSAS every delivery fails with ErrSASRejected. The deadline
// still applies in CONFIRMED.
//
// The caller then runs the anchor algorithm from AnchorSeq/AnchorH and the
// transitions, and requires the result to contain this device's
// device_add with the delivered certificate.
func (d *DeviceEnrollment) HandleDelivery(in HPKEEnvelope) (*VerifiedDelivery, error) {
	e := in.clone()
	if d.rec.State == DeviceDone {
		got, err1 := e.Digest()
		have, err2 := d.rec.Delivery.Digest()
		if err1 != nil || err2 != nil || !got.Equal(have) {
			return nil, ErrEnrollState
		}
		return d.Delivered()
	}
	if err := d.checkDeadline(); err != nil {
		return nil, err
	}
	if d.rec.State != DeviceConfirmed {
		return nil, ErrSASNotConfirmed
	}
	v, err := d.verify(e)
	if err != nil {
		return nil, err
	}
	rec := d.rec
	rec.State = DeviceDone
	cert := v.Cert
	rec.Cert = &cert
	rec.CertSig = bytes.Clone(v.CertSig)
	rec.Delivery = &e
	if err := d.save(rec); err != nil {
		v.Account.Zero()
		return nil, err
	}
	return v, nil
}

// Delivered returns the verified delivery once DONE, re-opening the
// persisted delivery. It gives the same certificate, account keys and
// anchor coordinates after a restart as HandleDelivery did.
func (d *DeviceEnrollment) Delivered() (*VerifiedDelivery, error) {
	switch d.rec.State {
	case DeviceRejected:
		return nil, ErrSASRejected
	case DeviceFailed:
		return nil, ErrEnrollExpired
	case DeviceDone:
	default:
		return nil, ErrEnrollState
	}
	v, err := d.verify(*d.rec.Delivery)
	if err != nil {
		return nil, fmt.Errorf("crypto: persisted delivery no longer verifies: %w", err)
	}
	return v, nil
}

// DeviceKeys returns D's new device keys. The signing key is a copy. A
// REJECTED or FAILED enrollment has no keys and returns nil for both.
func (d *DeviceEnrollment) DeviceKeys() (hpke.PrivateKey, ed25519.PrivateKey) {
	if terminal(d.rec.State) {
		return nil, nil
	}
	return d.kem, ed25519.PrivateKey(bytes.Clone(d.sig))
}

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
	V        int             `json:"v"`
	State    ApprovalState   `json:"state"`
	EnrollID model.ID        `json:"enroll_id"`
	Approver model.ID        `json:"approver_device_id"`
	Account  model.ID        `json:"account_id"`
	AKV      uint32          `json:"akv"`
	SigFp    Hash            `json:"acct_sig_fp"`
	Deadline model.Timestamp `json:"deadline"` // reservation, then CHALLENGED, + EnrollDeadline
	Commit   *EnrollCommit   `json:"commit"`
	Chal     *EnrollChal     `json:"chal"`
	Open     *EnrollOpen     `json:"open"`
	Cert     *Cert           `json:"cert"`
	CertSig  []byte          `json:"cert_sig"`
	Unlock   *HPKEEnvelope   `json:"unlock"`
	Delivery *HPKEEnvelope   `json:"delivery"`
}

// Approval is A's side of §7. Every transition is persisted before the
// method returns the message it produces. Messages that fail their checks
// are discarded with no change of state, so the real message can still
// arrive before the deadline. Once the deadline passes (EnrollDeadline from
// CHALLENGED), every method fails the attempt and returns
// ErrEnrollExpired; the slot stays spent and the outstanding challenge is
// released.
//
// Messages and material passed in and returned are copied; the caller may
// reuse or change its buffers.
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
		Account: pin.AccountID, AKV: pin.AKV, SigFp: pin.FpSig, Deadline: budget.rec.Deadline}
	if err := a.save(rec); err != nil {
		// The slot stays spent; the attempt is over.
		_ = budget.finish(enrollID)
		return nil, err
	}
	return a, nil
}

// RestoreApproval loads A's persisted attempt after a restart. An
// unfinished attempt whose deadline has passed is failed.
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
		return a, nil
	}
	if err := a.checkDeadline(); err != nil && !errors.Is(err, ErrEnrollExpired) {
		return nil, err
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

// checkDeadline fails an unfinished attempt whose deadline has passed.
func (a *Approval) checkDeadline() error {
	switch a.rec.State {
	case ApprovalDelivered:
		return nil
	case ApprovalFailed:
		return ErrEnrollState
	}
	if !expired(a.budget.now(), a.rec.Deadline) {
		return nil
	}
	if err := a.fail(); err != nil {
		return err
	}
	return ErrEnrollExpired
}

// State returns A's current state.
func (a *Approval) State() ApprovalState { return a.rec.State }

// EnrollID returns the attempt's enroll_id.
func (a *Approval) EnrollID() model.ID { return a.rec.EnrollID }

// Deadline returns the time at which an unfinished attempt fails.
func (a *Approval) Deadline() time.Time { return a.rec.Deadline.Time() }

// HandleCommit accepts exactly one commit for the attempt, persists it with
// a fresh nA and returns chal. The deadline restarts at CHALLENGED.
func (a *Approval) HandleCommit(c *EnrollCommit) (EnrollChal, error) {
	if err := a.checkDeadline(); err != nil {
		return EnrollChal{}, err
	}
	if a.rec.State != ApprovalReserved {
		return EnrollChal{}, ErrEnrollState
	}
	cm := *c // EnrollCommit holds no slices
	if err := cm.Validate(); err != nil {
		return EnrollChal{}, err
	}
	nA := make([]byte, EnrollNonceSize)
	if _, err := rand.Read(nA); err != nil {
		return EnrollChal{}, err
	}
	ch := &EnrollChal{V: Version, EnrollID: a.rec.EnrollID, NA: nA, AccountID: a.rec.Account,
		ApproverDeviceID: a.rec.Approver, AcctSigFp: a.rec.SigFp, AKV: a.rec.AKV}
	deadline := deadlineFrom(a.budget.now())
	// The budget's deadline moves first: a crash in between leaves the
	// outstanding mark held longer than the attempt, never shorter.
	if err := a.budget.challenged(a.rec.EnrollID, deadline); err != nil {
		return EnrollChal{}, err
	}
	rec := a.rec
	rec.State = ApprovalChallenged
	rec.Deadline = deadline
	rec.Commit = &cm
	rec.Chal = ch
	if err := a.save(rec); err != nil {
		return EnrollChal{}, err
	}
	return *ch.clone(), nil
}

// Chal returns the persisted chal for re-sending.
func (a *Approval) Chal() (EnrollChal, error) {
	if err := a.checkDeadline(); err != nil {
		return EnrollChal{}, err
	}
	if a.rec.Chal == nil || a.rec.State != ApprovalChallenged {
		return EnrollChal{}, ErrEnrollState
	}
	return *a.rec.Chal.clone(), nil
}

// HandleOpen checks that open matches c, persists it and returns the SAS
// and device name for the user to compare. An open that does not match
// changes nothing. If the SAS derivation aborts, the attempt fails.
func (a *Approval) HandleOpen(in *EnrollOpen) (sas, name string, err error) {
	if err := a.checkDeadline(); err != nil {
		return "", "", err
	}
	if a.rec.State != ApprovalChallenged {
		return "", "", ErrEnrollState
	}
	// Work on a copy, so a caller changing its buffers after the SAS is
	// shown cannot change what Prepare certifies.
	o := in.clone()
	if err := o.Validate(); err != nil {
		return "", "", err
	}
	c := Commitment(o)
	if !c.Equal(a.rec.Commit.C) {
		return "", "", ErrCommitMismatch
	}
	sas, err = SAS(Transcript(c, a.rec.Chal, o))
	if err != nil {
		if ferr := a.fail(); ferr != nil {
			return "", "", ferr
		}
		return "", "", err
	}
	rec := a.rec
	rec.State = ApprovalOpened
	rec.Open = o
	if err := a.save(rec); err != nil {
		return "", "", err
	}
	return sas, o.Name, nil
}

// SAS returns the code again once OPENED, for showing after a restart.
func (a *Approval) SAS() (sas, name string, err error) {
	if err := a.checkDeadline(); err != nil {
		return "", "", err
	}
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
	if err := a.checkDeadline(); err != nil {
		return err
	}
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
	if err := a.checkDeadline(); err != nil {
		return nil, err
	}
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
		KEMFp: FpKEM(o.KEMPK), SigFp: FpSig(o.SigPK), EnrollTranscript: SomeHash(th), IssuedAt: issuedAt}
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

// Prepared returns the persisted device_add material. Before delivery it
// fails once the deadline has passed, so a late device_add is not written.
func (a *Approval) Prepared() (*PreparedDevice, error) {
	if err := a.checkDeadline(); err != nil {
		return nil, err
	}
	if a.rec.Cert == nil {
		return nil, ErrEnrollState
	}
	return &PreparedDevice{Cert: *a.rec.Cert, CertSig: bytes.Clone(a.rec.CertSig), KEMPK: bytes.Clone(a.rec.Open.KEMPK),
		SigPK: bytes.Clone(a.rec.Open.SigPK), Unlock: a.rec.Unlock.clone()}, nil
}

// Deliver seals the delivery to D and persists it, ending the attempt. Call
// it only after the normal entry carrying the device_add has committed.
// anchorSeq and anchorH identify the genesis or checkpoint entry for the
// current akv. After delivery it returns the persisted envelope again.
func (a *Approval) Deliver(anchorSeq uint64, anchorH Hash) (HPKEEnvelope, error) {
	if err := a.checkDeadline(); err != nil {
		return HPKEEnvelope{}, err
	}
	switch a.rec.State {
	case ApprovalPrepared:
	case ApprovalDelivered:
		return a.rec.Delivery.clone(), nil
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
	return env.clone(), nil
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
