package store

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"

	"github.com/zalando/go-keyring"

	"github.com/dalyem/hopkey/internal/canonjson"
	"github.com/dalyem/hopkey/internal/crypto"
	"github.com/dalyem/hopkey/internal/model"
	"github.com/dalyem/hopkey/internal/vaultlog"
)

// Enrollment by approval, the new device D's side (§7), in a data directory
// with no vault. The §7 state machine is crypto.DeviceEnrollment; the store
// persists it, durably, before any message it produces is returned, so a
// crash at any step resumes (ResumeEnrollment) or is refused safely:
//
//	BeginEnrollment          new keys and nD, COMMITTED → the commit to post
//	SetEnrollID              the enroll_id the server assigned
//	HandleChal               REVEALED → open (exactly one chal is accepted)
//	SAS, ConfirmSAS/RejectSAS CONFIRMED, or REJECTED (terminal: keys wiped)
//	Install                  the delivery, staged in CONFIRMED, accepted (DONE)
//	                         once every step-6 check passed → the vault
//
// Files:
//
//	enroll.json   in the data directory, no secrets, written before the record (the intent):
//	              JCS({"v":1, "store":"keychain"|"file", "sealed":bool, "ref":id, "server":str, "email":str})
//	the record    in the device key store, as §11 stores device keys: the keychain entry
//	              "enroll:<ref>", or enroll.key
//	              record   = JCS({"v":1, "ref":id, "local_key":b64(32), "state":<crypto.DeviceEnrollment state>,
//	                             "staged":<the delivery being checked> | null})
//	              enroll.key = JCS({"v":1, "kdf_version":u32, "ref":id, "salt":b64,
//	                             "key":AEAD(pk, record, aad = lp("hopkey/v1/enroll-key-file") || lp(ref_bytes)) | record})
//
// with pk from crypto.DevicePassphraseKey when HOP_DEVICE_PASSPHRASE seals
// it (kdf_version 1), and the record itself otherwise (kdf_version 0, empty
// salt). ref is a local ID: the device ID is chosen by the approving device
// and arrives in the delivered certificate.
//
// Install is the sign-in's path (signin.go) with the delivery's anchor. The
// delivery is accepted only once every check of §7 step 6 has passed, its
// anchor and the log included, since input that fails them changes no
// state: crypto.DeviceEnrollment opens and checks it, but the DONE state it
// produces is held in memory, and the record keeps CONFIRMED with the
// delivery staged beside it (so a crash during the checks can retry it,
// and a delivery that fails them leaves the record as it was, the real one
// still accepted, DiscardEnrollment still allowed). The log is read with
// device authentication, anchored at the delivery's (anchor_seq,
// anchor_h), a trusted H, and verified by transitions as the new device;
// the result must contain its device_add with the delivered certificate.
// Then DONE is persisted (the delivery is accepted), device.json names the
// delivered device as pending and its record (the enrollment keys,
// "secret_key":"" (§11 addendum), and the enrollment's local_key) is made
// durable, and one durable commit installs the vault, server-backed. After
// a crash once DONE is durable, Install takes the steps again from the
// persisted delivery. A revocation met on the way is terminal for the data
// directory (the sign-in ledger, then a tombstone).

const (
	enrollRel          = "enroll.json"
	enrollKeyRel       = "enroll.key"
	labelEnrollKeyFile = "hopkey/v1/enroll-key-file"
	enrollVersion      = 1
)

var (
	// ErrNoEnrollment means no enrollment is in progress in the data
	// directory.
	ErrNoEnrollment = errors.New("store: no enrollment is in progress on this device; start one with hop auth login")
	// ErrEnrollmentPending means an enrollment is already in progress:
	// continue it, or discard it.
	ErrEnrollmentPending = errors.New("store: an enrollment by approval is in progress on this device; continue it or discard it")
	// ErrEnrollmentInstalling means the enrollment's delivery was accepted
	// and its device is being installed: only Install finishes it.
	ErrEnrollmentInstalling = errors.New("store: this device's enrollment was approved and is being installed; run hop auth login again to finish it")
)

// EnrollRemote is the server as a device enrolled by approval reads it
// before it has a vault: the log, read with the new device's own §9
// session (GET /v1/vaults/{id}/entries/{seq}, GET /v1/vaults/{id}/log).
// Slice E3 implements it over HTTP. Nothing it returns is trusted.
type EnrollRemote interface {
	EntryAt(ctx context.Context, auth DeviceAuth, seq uint64) (Committed, error)
	Since(ctx context.Context, auth DeviceAuth, after uint64) ([]Committed, vaultlog.Head, error)
}

// EnrollParams are a new device's choices for its enrollment.
type EnrollParams struct {
	// ServerURL is the server's origin, kept in vault/server.json.
	ServerURL string
	// Email is the account's sign-in email, normalized here, or "" when
	// the new device does not know it.
	Email string
	// DeviceName names the new device (open.name, §7). Empty means
	// Config.DeviceName, then the host name.
	DeviceName string
	// DeviceStore is DeviceStoreKeychain (the default) or DeviceStoreFile.
	DeviceStore string
}

type enrollConfig struct {
	V      int      `json:"v"`
	Store  string   `json:"store"`
	Sealed bool     `json:"sealed"`
	Ref    model.ID `json:"ref"`
	Server string   `json:"server"`
	Email  string   `json:"email"`
}

type enrollRecord struct {
	V        int                  `json:"v"`
	Ref      model.ID             `json:"ref"`
	LocalKey []byte               `json:"local_key"`
	State    canonjson.Raw        `json:"state"`
	Staged   *crypto.HPKEEnvelope `json:"staged"`
}

type enrollKeyFile struct {
	V          int           `json:"v"`
	KDFVersion uint32        `json:"kdf_version"`
	Ref        model.ID      `json:"ref"`
	Salt       []byte        `json:"salt"`
	Key        canonjson.Raw `json:"key"`
}

func (l layout) enrollFile() string    { return filepath.Join(l.data, enrollRel) }
func (l layout) enrollKeyFile() string { return filepath.Join(l.data, enrollKeyRel) }

func enrollSlot(ref model.ID) string { return "enroll:" + ref.String() }

func enrollKeyAAD(ref model.ID) []byte {
	return append(crypto.LP([]byte(labelEnrollKeyFile)), crypto.LP(ref[:])...)
}

// enrollPending reports whether enroll.json exists.
func (l layout) enrollPending() (bool, error) {
	_, err := os.Lstat(l.enrollFile())
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	return err == nil, err
}

// Enrollment is D's side of an enrollment in progress. It owns the data
// directory (vault/owner.lock) until Close, or until Install hands it to
// the Store it returns. It is not safe for concurrent use.
type Enrollment struct {
	s        *Store
	ec       enrollConfig
	localKey []byte
	d        *crypto.DeviceEnrollment
	// state is D's state as the record holds it, and staged the delivery
	// staged beside it, if any.
	state  []byte
	staged *crypto.HPKEEnvelope
	// hold makes Persist keep a DONE state in held instead of persisting
	// it: the delivery is not accepted until its checks are over.
	hold bool
	held []byte
}

// enrollPersister persists D's state into the enrollment record, durably,
// with no staged delivery; a DONE state is held while e.hold.
type enrollPersister struct{ e *Enrollment }

func (p enrollPersister) Persist(state []byte) error {
	e := p.e
	if e.hold && enrollDone(state) {
		e.held = bytes.Clone(state)
		return nil
	}
	if err := e.s.hook("enroll:persist"); err != nil {
		return err
	}
	if err := e.save(state, nil); err != nil {
		return err
	}
	e.setState(state)
	e.staged = nil
	return nil
}

// enrollDone reports whether the persisted D state is DONE. Only the state
// is read: crypto.DeviceEnrollment owns the record's schema.
func enrollDone(state []byte) bool {
	var rec struct {
		State crypto.DeviceEnrollState `json:"state"`
	}
	return json.Unmarshal(state, &rec) == nil && rec.State == crypto.DeviceDone
}

// save stores the enrollment record with D's state and the staged
// delivery, durably.
func (e *Enrollment) save(state []byte, staged *crypto.HPKEEnvelope) error {
	b, err := canonjson.Marshal(enrollRecord{V: enrollVersion, Ref: e.ec.Ref, LocalKey: e.localKey, State: canonjson.Raw(state), Staged: staged})
	if err != nil {
		return err
	}
	defer clear(b)
	return e.s.saveEnroll(e.ec, b)
}

func (e *Enrollment) setState(state []byte) {
	clear(e.state)
	e.state = bytes.Clone(state)
}

// BeginEnrollment starts enrolling this machine by approval (§7 step 1) in
// cfg.DataDir, which must hold no vault, no device and no other enrollment:
// it generates the device keys and nD, persists them (COMMITTED), and
// returns the commit to post. The caller then records the server's
// enroll_id with SetEnrollID.
func BeginEnrollment(cfg Config, p EnrollParams) (*Enrollment, crypto.EnrollCommit, error) {
	return beginEnrollment(cfg, p, nil)
}

func beginEnrollment(cfg Config, p EnrollParams, hook func(string) error) (_ *Enrollment, _ crypto.EnrollCommit, err error) {
	s := &Store{cfg: cfg, l: layout{data: cfg.DataDir}, testHook: hook}
	ec, name, err := p.check(s)
	if err != nil {
		return nil, crypto.EnrollCommit{}, err
	}
	if err := s.l.ensureDirs(); err != nil {
		return nil, crypto.EnrollCommit{}, err
	}
	if err := s.own(); err != nil {
		return nil, crypto.EnrollCommit{}, err
	}
	defer func() {
		if err != nil {
			s.Close()
		}
	}()
	unlock, err := s.lockFile()
	if err != nil {
		return nil, crypto.EnrollCommit{}, err
	}
	defer unlock()
	if err := s.replayWAL(); err != nil {
		return nil, crypto.EnrollCommit{}, err
	}
	if exists, err := s.l.exists(); err != nil {
		return nil, crypto.EnrollCommit{}, err
	} else if exists {
		return nil, crypto.EnrollCommit{}, ErrVaultExists
	}
	if _, err := os.Lstat(s.l.deviceConfig()); err == nil {
		return nil, crypto.EnrollCommit{}, fmt.Errorf("%w: %s names a device or a sign-in in progress", ErrVaultExists, s.l.deviceConfig())
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, crypto.EnrollCommit{}, err
	}
	if pending, err := s.l.enrollPending(); err != nil {
		return nil, crypto.EnrollCommit{}, err
	} else if pending {
		return nil, crypto.EnrollCommit{}, ErrEnrollmentPending
	}
	if err := s.deviceStore(deviceConfig{V: 1, Store: ec.Store, Sealed: ec.Sealed}).probe(); err != nil {
		if ec.Store == DeviceStoreKeychain {
			return nil, crypto.EnrollCommit{}, fmt.Errorf("%w (%v); pass --device-key-store=file to keep the device key in %s instead",
				ErrKeychainUnusable, err, s.l.deviceKeyFile())
		}
		return nil, crypto.EnrollCommit{}, err
	}
	if ec.Ref, err = vaultlog.NewID(); err != nil {
		return nil, crypto.EnrollCommit{}, err
	}
	local, err := newLocalKey()
	if err != nil {
		return nil, crypto.EnrollCommit{}, err
	}
	// The intent: enroll.json names the record before it exists, so the
	// device key store never holds one that nothing tracks.
	b, err := canonjson.Marshal(ec)
	if err != nil {
		return nil, crypto.EnrollCommit{}, err
	}
	if err := writeFileAtomic(s.l.enrollFile(), b); err != nil {
		return nil, crypto.EnrollCommit{}, err
	}
	if err := s.hook("enroll:intent"); err != nil {
		return nil, crypto.EnrollCommit{}, err
	}
	e := &Enrollment{s: s, ec: ec, localKey: local}
	d, commit, err := crypto.NewDeviceEnrollmentWithClock(enrollPersister{e}, s.clock, name)
	if err != nil {
		clear(local)
		return nil, crypto.EnrollCommit{}, err
	}
	e.d = d
	return e, commit, nil
}

// check validates p and returns enroll.json without its ref, and the
// device name.
func (p *EnrollParams) check(s *Store) (enrollConfig, string, error) {
	if p.ServerURL == "" || crypto.CheckStr("server", p.ServerURL, 256) != nil {
		return enrollConfig{}, "", errors.New("store: the server's origin must be 1 to 256 characters")
	}
	email := ""
	if p.Email != "" {
		var err error
		if email, err = NormalizeEmail(p.Email); err != nil {
			return enrollConfig{}, "", err
		}
	}
	name := p.DeviceName
	if name == "" {
		name = s.deviceName()
	} else if crypto.CheckStr("name", name, 64) != nil {
		return enrollConfig{}, "", errors.New("store: a device name is 1 to 64 characters")
	}
	ec := enrollConfig{V: enrollVersion, Store: p.DeviceStore, Server: p.ServerURL, Email: email}
	switch ec.Store {
	case "":
		ec.Store = DeviceStoreKeychain
	case DeviceStoreKeychain:
	case DeviceStoreFile:
		ec.Sealed = s.getenv()(PassphraseEnv) != ""
	default:
		return enrollConfig{}, "", fmt.Errorf("store: unknown device key store %q (keychain or file)", ec.Store)
	}
	return ec, name, nil
}

// ResumeEnrollment opens the enrollment in progress in cfg.DataDir after a
// restart, in whatever state it was persisted: a REJECTED or FAILED one is
// terminal, and every step then fails (crypto.ErrSASRejected,
// crypto.ErrEnrollExpired) until DiscardEnrollment. An enrollment whose
// record never became durable (a crash right after the intent) produced no
// message: it is forgotten, and the result is ErrNoEnrollment.
func ResumeEnrollment(cfg Config) (*Enrollment, error) {
	return resumeEnrollment(cfg, nil)
}

func resumeEnrollment(cfg Config, hook func(string) error) (_ *Enrollment, err error) {
	s := &Store{cfg: cfg, l: layout{data: cfg.DataDir}, testHook: hook}
	if err := s.l.ensureDirs(); err != nil {
		return nil, err
	}
	if err := s.own(); err != nil {
		return nil, err
	}
	defer func() {
		if err != nil {
			s.Close()
		}
	}()
	unlock, err := s.lockFile()
	if err != nil {
		return nil, err
	}
	defer unlock()
	if err := s.replayWAL(); err != nil {
		return nil, err
	}
	ec, err := s.readEnrollConfig()
	if err != nil {
		return nil, err
	}
	b, found, err := s.loadEnroll(ec)
	if err != nil {
		return nil, err
	}
	if !found {
		if err := s.removeEnrollConfig(); err != nil {
			return nil, err
		}
		return nil, fmt.Errorf("%w (an earlier one stopped before it started)", ErrNoEnrollment)
	}
	defer clear(b)
	var rec enrollRecord
	if err := canonjson.Unmarshal(b, &rec); err != nil || rec.V != enrollVersion || rec.Ref != ec.Ref || len(rec.LocalKey) != localKeySize {
		clear(rec.LocalKey)
		return nil, fmt.Errorf("%w: the enrollment record does not parse", ErrDeviceKey)
	}
	e := &Enrollment{s: s, ec: ec, localKey: rec.LocalKey, state: bytes.Clone(rec.State)}
	d, err := crypto.RestoreDeviceEnrollmentWithClock(enrollPersister{e}, s.clock, rec.State)
	if err != nil {
		clear(rec.LocalKey)
		clear(e.state)
		return nil, fmt.Errorf("%w: the enrollment state: %v", ErrDeviceKey, err)
	}
	e.d = d
	if d.State() == crypto.DeviceConfirmed {
		// A delivery staged before a crash: Install(nil) checks it again.
		e.staged = rec.Staged
	}
	return e, nil
}

// readEnrollConfig reads enroll.json: ErrNoEnrollment when there is none.
func (s *Store) readEnrollConfig() (enrollConfig, error) {
	var ec enrollConfig
	b, err := os.ReadFile(s.l.enrollFile())
	if errors.Is(err, os.ErrNotExist) {
		return ec, ErrNoEnrollment
	}
	if err != nil {
		return ec, err
	}
	if canonjson.Unmarshal(b, &ec) != nil || ec.V != enrollVersion || ec.Ref.IsZero() ||
		(ec.Store != DeviceStoreKeychain && ec.Store != DeviceStoreFile) || (ec.Sealed && ec.Store != DeviceStoreFile) {
		return ec, fmt.Errorf("%w: %s does not parse", ErrCorrupt, s.l.enrollFile())
	}
	return ec, nil
}

func (s *Store) removeEnrollConfig() error {
	if err := os.Remove(s.l.enrollFile()); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return syncDir(s.l.data)
}

// saveEnroll stores the enrollment record b in the device key store,
// durably, and reads it back byte for byte (§11).
func (s *Store) saveEnroll(ec enrollConfig, b []byte) error {
	switch ec.Store {
	case DeviceStoreKeychain:
		if err := s.ring().Set(keychainService, enrollSlot(ec.Ref), string(b)); err != nil {
			return fmt.Errorf("saving the enrollment keys in the keychain: %w", err)
		}
	case DeviceStoreFile:
		f := enrollKeyFile{V: enrollVersion, Ref: ec.Ref, Salt: []byte{}, Key: canonjson.Raw(b)}
		if ec.Sealed {
			pass := s.getenv()(PassphraseEnv)
			if pass == "" {
				return fmt.Errorf("the enrollment key file is sealed; set %s", PassphraseEnv)
			}
			f.KDFVersion = crypto.KDFv1.Version
			f.Salt = make([]byte, crypto.SaltSize)
			if _, err := rand.Read(f.Salt); err != nil {
				return err
			}
			key, err := crypto.DevicePassphraseKey([]byte(pass), f.Salt, ec.Ref)
			if err != nil {
				return fmt.Errorf("%s: %w", PassphraseEnv, err)
			}
			env, err := crypto.SealAEAD(key, b, enrollKeyAAD(ec.Ref))
			key.Zero()
			if err != nil {
				return err
			}
			if f.Key, err = env.JCS(); err != nil {
				return err
			}
		}
		out, err := canonjson.Marshal(f)
		if err != nil {
			return err
		}
		defer clear(out)
		if err := writeFileAtomic(s.l.enrollKeyFile(), out); err != nil {
			return err
		}
		if err := syncFile(s.l.enrollKeyFile()); err != nil {
			return err
		}
	default:
		return fmt.Errorf("unknown device key store %q", ec.Store)
	}
	got, found, err := s.loadEnroll(ec)
	if err != nil {
		return err
	}
	same := found && bytes.Equal(got, b)
	clear(got)
	if !same {
		return errors.New("the device key store gave back other enrollment keys than were saved")
	}
	return nil
}

// loadEnroll reads the enrollment record. found is false only for a
// confirmed absence; any other failure to read is ErrKeyStoreUnavailable,
// and content that does not open is ErrDeviceKey.
func (s *Store) loadEnroll(ec enrollConfig) ([]byte, bool, error) {
	switch ec.Store {
	case DeviceStoreKeychain:
		raw, err := s.ring().Get(keychainService, enrollSlot(ec.Ref))
		if errors.Is(err, keyring.ErrNotFound) {
			return nil, false, nil
		}
		if err != nil {
			return nil, false, fmt.Errorf("%w: the enrollment's keychain entry could not be read: %v", ErrKeyStoreUnavailable, err)
		}
		return []byte(raw), true, nil
	case DeviceStoreFile:
		b, err := readKeyFile(s.l.enrollKeyFile())
		if errors.Is(err, os.ErrNotExist) {
			return nil, false, nil
		}
		if err != nil {
			return nil, false, fmt.Errorf("%w: %v", ErrKeyStoreUnavailable, err)
		}
		var f enrollKeyFile
		if canonjson.Unmarshal(b, &f) != nil || f.V != enrollVersion || f.Ref != ec.Ref {
			return nil, false, fmt.Errorf("%w: %s does not parse", ErrDeviceKey, s.l.enrollKeyFile())
		}
		switch {
		case ec.Sealed && f.KDFVersion == crypto.KDFv1.Version && len(f.Salt) == crypto.SaltSize:
			pass := s.getenv()(PassphraseEnv)
			if pass == "" {
				return nil, false, fmt.Errorf("%w: %s is sealed; set %s", ErrDeviceKey, s.l.enrollKeyFile(), PassphraseEnv)
			}
			env, err := crypto.ParseAEADEnvelope(f.Key)
			if err != nil {
				return nil, false, fmt.Errorf("%w: %s: %v", ErrDeviceKey, s.l.enrollKeyFile(), err)
			}
			key, err := crypto.DevicePassphraseKey([]byte(pass), f.Salt, ec.Ref)
			if err != nil {
				return nil, false, fmt.Errorf("%w: %s: %v", ErrDeviceKey, PassphraseEnv, err)
			}
			pt, err := crypto.OpenAEAD(key, env, enrollKeyAAD(ec.Ref))
			key.Zero()
			if err != nil {
				return nil, false, fmt.Errorf("%w: %s does not open with %s", ErrDeviceKey, s.l.enrollKeyFile(), PassphraseEnv)
			}
			return pt, true, nil
		case !ec.Sealed && f.KDFVersion == 0 && len(f.Salt) == 0:
			return bytes.Clone(f.Key), true, nil
		}
		return nil, false, fmt.Errorf("%w: %s is not sealed as this enrollment expects", ErrDeviceKey, s.l.enrollKeyFile())
	}
	return nil, false, fmt.Errorf("unknown device key store %q", ec.Store)
}

// deleteEnroll deletes the enrollment record. One already gone is no
// error.
func (s *Store) deleteEnroll(ec enrollConfig) error {
	switch ec.Store {
	case DeviceStoreKeychain:
		if err := s.ring().Delete(keychainService, enrollSlot(ec.Ref)); err != nil && !errors.Is(err, keyring.ErrNotFound) {
			return err
		}
		return nil
	case DeviceStoreFile:
		if err := os.Remove(s.l.enrollKeyFile()); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
		return syncDir(s.l.data)
	}
	return fmt.Errorf("unknown device key store %q", ec.Store)
}

// DiscardEnrollment deletes the enrollment in progress in cfg.DataDir and
// its keys, so a new one can start: one that is REJECTED or FAILED, or one
// the user gives up. If the approving device already committed the device,
// it stays in the account until a checkpoint revokes it. Once a delivery
// was accepted and its install began (device.json names the device), it is
// refused with ErrEnrollmentInstalling: Install finishes it. Once installed,
// it only removes what the install left behind.
func DiscardEnrollment(cfg Config) error {
	s := &Store{cfg: cfg, l: layout{data: cfg.DataDir}}
	if err := s.l.ensureDirs(); err != nil {
		return err
	}
	if err := s.own(); err != nil {
		return err
	}
	defer s.Close()
	unlock, err := s.lockFile()
	if err != nil {
		return err
	}
	defer unlock()
	if err := s.replayWAL(); err != nil {
		return err
	}
	ec, err := s.readEnrollConfig()
	if err != nil {
		return err
	}
	exists, err := s.l.exists()
	if err != nil {
		return err
	}
	if _, err := os.Lstat(s.l.deviceConfig()); err == nil && !exists {
		return ErrEnrollmentInstalling
	} else if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if err := s.deleteEnroll(ec); err != nil {
		return err
	}
	return s.removeEnrollConfig()
}

// State returns D's §7 state.
func (e *Enrollment) State() crypto.DeviceEnrollState { return e.d.State() }

// Commit returns the commit message, the same after a restart.
func (e *Enrollment) Commit() crypto.EnrollCommit { return e.d.Commit() }

// SetEnrollID records the enroll_id the server assigned to the commit.
func (e *Enrollment) SetEnrollID(id model.ID) error { return e.d.SetEnrollID(id) }

// HandleChal accepts the approving device's chal, persists it (REVEALED)
// and returns open. Exactly one chal is accepted.
func (e *Enrollment) HandleChal(ch *crypto.EnrollChal) (crypto.EnrollOpen, error) {
	return e.d.HandleChal(ch)
}

// Open returns open again once REVEALED, for re-sending.
func (e *Enrollment) Open() (crypto.EnrollOpen, error) { return e.d.Open() }

// SAS returns the 8 digits D shows once REVEALED.
func (e *Enrollment) SAS() (string, error) { return e.d.SAS() }

// ConfirmSAS records that the user saw the same 8 digits on both devices
// (CONFIRMED). Only then is a delivery accepted.
func (e *Enrollment) ConfirmSAS() error { return e.d.ConfirmSAS() }

// RejectSAS records that the digits differ (REJECTED): terminal, the
// enrollment keys are wiped, and no delivery is accepted for this session.
func (e *Enrollment) RejectSAS() error { return e.d.RejectSAS() }

// Close gives up the data directory without changing the enrollment.
func (e *Enrollment) Close() error {
	clear(e.localKey)
	clear(e.state)
	clear(e.held)
	if e.s == nil {
		return nil
	}
	err := e.s.Close()
	e.s = nil
	return err
}

// Install accepts the approving device's delivery (§7 step 6) and installs
// the vault (see above). It returns the store, unlocked, server-backed and
// owning the vault; the Enrollment no longer owns the data directory. A
// delivery is accepted only in CONFIRMED, and only once every check of
// step 6 has passed, its anchor and the verified log included: one that
// arrives earlier, or after RejectSAS, or that fails a check (a
// substituted one, or one naming another anchor) is discarded with no
// change of state, and the real one can still be handed in. delivery nil
// uses the one an earlier Install accepted, or staged before a crash.
//
// Every failure after the delivery is accepted leaves a state the next
// Install finishes (InstallEnrolled after a restart).
func (e *Enrollment) Install(ctx context.Context, r EnrollRemote, delivery *crypto.HPKEEnvelope) (*Store, error) {
	if e.s == nil {
		return nil, ErrClosed
	}
	s := e.s
	accepted := e.d.State() == crypto.DeviceDone
	var v *crypto.VerifiedDelivery
	var err error
	switch {
	case accepted && delivery != nil:
		v, err = e.d.HandleDelivery(*delivery)
	case accepted:
		v, err = e.d.Delivered()
	default:
		v, err = e.stage(delivery)
	}
	if err != nil {
		return nil, err
	}
	o := &signInSecrets{acct: v.Account}
	defer o.zero()
	rec, err := e.deviceRecord(v)
	if err != nil {
		if !accepted {
			err = errors.Join(err, e.unstage())
		}
		return nil, err
	}
	o.rec = rec
	var dcfg deviceConfig
	if accepted {
		if err := s.hook("enroll:delivered"); err != nil {
			return nil, err
		}
		var installed bool
		if dcfg, installed, err = s.enrolledDevice(e.ec, rec); err != nil {
			return nil, err
		}
		if installed {
			return e.reopen(ctx)
		}
	}
	self, err := rec.device()
	if err != nil {
		return nil, err
	}
	o.dev = self
	auth := &sessionAuth{key: ed25519.PrivateKey(slices.Clone(self.Sig))}
	defer auth.close()
	rr := enrollReader{r: r, auth: auth.auth(rec.AccountID, rec.DeviceID)}
	err = enrolledDestination(ctx, rr, o, self, v, s.hook)
	rev := (*vaultlog.RevokedError)(nil)
	revoked := errors.As(err, &rev)
	if !accepted {
		if err != nil && !revoked {
			// The delivery failed a check: nothing changes (§7).
			return nil, errors.Join(err, e.unstage())
		}
		// Every check passed (a revocation is met in verified history):
		// the delivery is accepted, and the install owns the data
		// directory from here.
		if aerr := e.accept(); aerr != nil {
			return nil, aerr
		}
		if herr := s.hook("enroll:delivered"); herr != nil {
			return nil, herr
		}
		var installed bool
		if dcfg, installed, err = s.enrolledDevice(e.ec, rec); err != nil {
			return nil, err
		}
		if installed {
			return nil, fmt.Errorf("%w: a vault was installed while this delivery was checked", ErrVaultExists)
		}
		if revoked {
			err = rev
		}
	}
	if revoked {
		return nil, s.revokePending(dcfg, rec.DeviceID, err)
	}
	if err != nil {
		return nil, err
	}
	if err := s.installSignIn(o, dcfg, serverFile{Server: e.ec.Server, Email: e.ec.Email}); err != nil {
		return nil, err
	}
	e.s = nil
	e.cleanup(s)
	return s, nil
}

// stage runs D's own checks of §7 step 6 on delivery (nil: the staged one)
// without accepting it: crypto.DeviceEnrollment opens and verifies it, and
// its DONE state is held, not persisted; the record keeps CONFIRMED and
// gets the delivery staged beside it, durably, so a crash during the
// remaining checks can retry it. A delivery that fails here changes
// nothing (one past the deadline fails the enrollment, as it would
// anyway). Install then accepts it (accept) or unstages it (unstage).
func (e *Enrollment) stage(delivery *crypto.HPKEEnvelope) (*crypto.VerifiedDelivery, error) {
	if delivery == nil {
		if e.staged == nil || e.d.State() != crypto.DeviceConfirmed {
			// The state's own error: ErrEnrollState, ErrSASRejected, ...
			return e.d.Delivered()
		}
		delivery = e.staged
	}
	env := *delivery
	env.Enc, env.CT = bytes.Clone(env.Enc), bytes.Clone(env.CT)
	e.hold, e.held = true, nil
	v, err := e.d.HandleDelivery(env)
	e.hold = false
	if err != nil {
		return nil, err
	}
	fail := func(err error) (*crypto.VerifiedDelivery, error) {
		v.Account.Zero()
		return nil, errors.Join(err, e.restore())
	}
	if e.held == nil {
		return fail(fmt.Errorf("%w: the delivery was accepted without its state", crypto.ErrEnrollState))
	}
	if err := e.save(e.state, &env); err != nil {
		return fail(err)
	}
	e.staged = &env
	if err := e.s.hook("enroll:staged"); err != nil {
		return fail(err)
	}
	return v, nil
}

// accept persists the held DONE state, which drops the staged delivery:
// the delivery is accepted. If it fails, the enrollment is CONFIRMED again
// with the delivery staged, and Install(nil) checks it again.
func (e *Enrollment) accept() error {
	if err := e.s.hook("enroll:accept"); err != nil {
		return errors.Join(err, e.restore())
	}
	if err := e.save(e.held, nil); err != nil {
		return errors.Join(err, e.restore())
	}
	e.setState(e.held)
	clear(e.held)
	e.held, e.staged = nil, nil
	return nil
}

// unstage drops the staged delivery, durably, and returns D to the state
// the record holds (CONFIRMED): a delivery that failed a check changes no
// state.
func (e *Enrollment) unstage() error {
	var err error
	if e.staged != nil {
		if err = e.save(e.state, nil); err == nil {
			e.staged = nil
		}
	}
	return errors.Join(err, e.restore())
}

// restore reloads D from the state the record holds, dropping a held DONE.
func (e *Enrollment) restore() error {
	clear(e.held)
	e.held = nil
	d, err := crypto.RestoreDeviceEnrollmentWithClock(enrollPersister{e}, e.s.clock, e.state)
	if err != nil {
		return fmt.Errorf("%w: the enrollment state: %v", ErrDeviceKey, err)
	}
	e.d = d
	return nil
}

// InstallEnrolled is ResumeEnrollment and Install, for a restart.
func InstallEnrolled(ctx context.Context, cfg Config, r EnrollRemote, delivery *crypto.HPKEEnvelope) (*Store, error) {
	e, err := ResumeEnrollment(cfg)
	if err != nil {
		return nil, err
	}
	s, err := e.Install(ctx, r, delivery)
	if err != nil {
		e.Close()
		return nil, err
	}
	clear(e.localKey)
	return s, nil
}

// deviceRecord is the new device's record: the enrollment's keys under the
// delivered account and device ID, no Secret Key (§11 addendum), and the
// enrollment's local_key.
func (e *Enrollment) deviceRecord(v *crypto.VerifiedDelivery) (*deviceRecord, error) {
	kem, sig := e.d.DeviceKeys()
	if kem == nil || sig == nil {
		return nil, crypto.ErrEnrollState
	}
	defer clear(sig)
	kemSK, err := kem.Bytes()
	if err != nil {
		return nil, err
	}
	return &deviceRecord{
		V: 2, AccountID: v.Cert.AccountID, DeviceID: v.Cert.DeviceID,
		KEMSK: bytes.Clone(kemSK), SigSeed: bytes.Clone(sig.Seed()), SecretKey: "", LocalKey: bytes.Clone(e.localKey),
	}, nil
}

// reopen opens the vault an earlier Install committed, after removing what
// the enrollment left behind.
func (e *Enrollment) reopen(ctx context.Context) (*Store, error) {
	s := e.s
	cfg := s.cfg
	e.s = nil
	e.cleanup(s)
	s.Close()
	st, err := Open(ctx, cfg)
	if err != nil {
		return nil, err
	}
	if info := st.Info(); info.Locked {
		st.Close()
		if info.Revoked {
			return nil, fmt.Errorf("%w: an earlier install committed, but its device is revoked: %s", ErrDeviceRevoked, info.LockReason)
		}
		return nil, fmt.Errorf("store: an earlier install committed, but the vault does not unlock: %s", info.LockReason)
	}
	return st, nil
}

// cleanup deletes the enrollment record and enroll.json once the vault is
// installed. It is best effort: what it leaves is removed by the next
// Install or DiscardEnrollment, and is never used again.
func (e *Enrollment) cleanup(s *Store) {
	if s.hook("enroll:cleanup") != nil {
		return
	}
	if err := s.deleteEnroll(e.ec); err == nil {
		s.removeEnrollConfig()
	}
	clear(e.localKey)
}

// enrolledDevice makes the delivered device rec this data directory's
// pending device: device.json names it (the intent), then its record is
// durable in the device key store. An earlier Install's work is resumed:
// the same pending device, its record (which must be rec) or a confirmed
// absence of it. installed reports a vault an earlier Install committed. A
// revocation the sign-in ledger, or a tombstone, records is terminal. The
// caller holds no lock.
func (s *Store) enrolledDevice(ec enrollConfig, rec *deviceRecord) (deviceConfig, bool, error) {
	unlock, err := s.lockFile()
	if err != nil {
		return deviceConfig{}, false, err
	}
	defer unlock()
	if err := s.replayWAL(); err != nil {
		return deviceConfig{}, false, err
	}
	acct, id := rec.AccountID, rec.DeviceID
	ledger, err := s.l.readLedger()
	if err != nil {
		return deviceConfig{}, false, err
	}
	dcfg := deviceConfig{V: 1, Store: ec.Store, Sealed: ec.Sealed, AccountID: acct}
	if ledger.isRevoked(acct, id) {
		return deviceConfig{}, false, s.stillRevoked(s.deviceStore(dcfg), id,
			fmt.Errorf("%w: %w (device %v, recorded in %s)", ErrDeviceRevoked, ErrSignInRevoked, id, s.l.ledgerFile()))
	}
	exists, err := s.l.exists()
	if err != nil {
		return deviceConfig{}, false, err
	}
	if _, err := os.Lstat(s.l.deviceConfig()); err == nil {
		if dcfg, err = s.readDeviceConfig(); err != nil {
			return deviceConfig{}, false, err
		}
		mine := dcfg.AccountID == acct && dcfg.Store == ec.Store && dcfg.Next == nil &&
			(dcfg.DeviceID == id || (dcfg.DeviceID.IsZero() && dcfg.pendingID() == id))
		if !mine {
			return deviceConfig{}, false, fmt.Errorf("%w: %s belongs to another device or sign-in", ErrVaultExists, s.l.deviceConfig())
		}
		if exists {
			if server, err := s.l.serverBacked(); err == nil && server {
				return dcfg, true, nil
			}
			return deviceConfig{}, false, ErrVaultExists
		}
		if !dcfg.DeviceID.IsZero() {
			return deviceConfig{}, false, fmt.Errorf("%w: %s names the device, but there is no vault", ErrCorrupt, s.l.deviceConfig())
		}
		state, got, err := s.deviceStore(dcfg).probeSlot(id)
		if err != nil {
			return deviceConfig{}, false, fmt.Errorf("store: the enrolled device's record can't be resolved, so nothing was changed: %w", err)
		}
		switch state {
		case slotTombstone:
			return deviceConfig{}, false, fmt.Errorf("%w: %w (device %v; its record is a tombstone)", ErrDeviceRevoked, ErrSignInRevoked, id)
		case slotRecord:
			same := got.equal(rec)
			got.zero()
			if !same {
				return deviceConfig{}, false, fmt.Errorf("%w: the device key store holds other keys for device %v", ErrDeviceKey, id)
			}
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return deviceConfig{}, false, err
	} else {
		if exists {
			return deviceConfig{}, false, ErrVaultExists
		}
		dcfg.Pending = &pendingDevice{DeviceID: id}
		if err := s.writeDeviceConfig(dcfg); err != nil {
			return deviceConfig{}, false, err
		}
		if err := s.hook("enroll:intent-device"); err != nil {
			return deviceConfig{}, false, err
		}
	}
	if err := s.deviceStore(dcfg).storeDurably(rec); err != nil {
		return deviceConfig{}, false, fmt.Errorf("store: the device key was not saved durably: %w", err)
	}
	if err := s.hook("enroll:record"); err != nil {
		return deviceConfig{}, false, err
	}
	return dcfg, false, nil
}

// enrollReader reads the log with the new device's session, as the
// sign-in's destination does (SignInRemote). An enrollment posts nothing.
type enrollReader struct {
	r    EnrollRemote
	auth DeviceAuth
}

func (e enrollReader) EntryAt(ctx context.Context, seq uint64) (Committed, error) {
	return e.r.EntryAt(ctx, e.auth, seq)
}

func (e enrollReader) Since(ctx context.Context, after uint64) ([]Committed, vaultlog.Head, error) {
	return e.r.Since(ctx, e.auth, after)
}

func (enrollReader) Post(context.Context, *vaultlog.Wire) (vaultlog.Head, error) {
	return vaultlog.Head{}, errors.New("store: an enrollment by approval posts nothing")
}

// enrolledDestination reads the whole log and verifies it for a device
// enrolled by approval (§7 step 6, §5.5): the anchor is the delivery's
// (anchor_seq, anchor_h), a trusted H, checked with the account keys the
// delivery's unlock blob opened, and with self checked against its public
// state before anything is decrypted; then every later entry is verified
// by the transition algorithm, as self once self is active, so a checkpoint
// that revokes it is met in the public stage (*vaultlog.RevokedError). The
// log must hold self's device_add with the delivered certificate, and self
// must be active at the head. The destination goes to o as soon as it
// holds secrets.
func enrolledDestination(ctx context.Context, r SignInRemote, o *signInSecrets, self *vaultlog.LocalDevice, v *crypto.VerifiedDelivery, hook func(string) error) error {
	if err := hook("enroll:fetch"); err != nil {
		return err
	}
	c0, err := r.EntryAt(ctx, 0)
	if err != nil {
		return err
	}
	d := &destination{self: self, objs: vaultlog.ObjectMap{}, onState: o.onState}
	if err := d.add([]Committed{c0}); err != nil {
		return err
	}
	if err := d.fetchRest(ctx, r); err != nil {
		return err
	}
	if v.AnchorSeq >= uint64(len(d.wires)) {
		return fmt.Errorf("store: the server's log ends at seq %d, before the delivered anchor (seq %d)", len(d.wires)-1, v.AnchorSeq)
	}
	aw := d.wires[v.AnchorSeq]
	pin := o.acct.Pin()
	trusted := &vaultlog.Head{Seq: v.AnchorSeq, H: v.AnchorH}
	notAnchor := func(err error) error {
		return fmt.Errorf("store: the delivered anchor (seq %d) does not verify: %w", v.AnchorSeq, err)
	}
	c, err := vaultlog.CheckAnchorPublic(pin, aw, d.objs)
	if err != nil {
		return notAnchor(err)
	}
	if !c.H.Equal(v.AnchorH) {
		return notAnchor(errors.New("its H is not the delivered anchor_h"))
	}
	if err := d.checkSelf(c.Post); err != nil {
		return err
	}
	st, sec, _, err := vaultlog.Anchor(pin, o.acct, aw, d.objs, trusted)
	if err != nil {
		return notAnchor(err)
	}
	d.st, d.sec = st, sec
	o.d = d
	d.seen()
	found := false
	for _, w := range d.wires[v.AnchorSeq+1:] {
		if !found && w.Entry.Kind == vaultlog.KindNormal && addsCert(w, &v.Cert, v.CertSig) {
			found = true
		}
		if err := d.step(w); err != nil {
			return err
		}
	}
	if err := d.departed(); err != nil {
		return err
	}
	if !found {
		return errors.New("store: the server's log has no device_add with the delivered certificate")
	}
	if _, active := d.st.Devices[self.ID]; !active {
		return fmt.Errorf("%w: the enrolled device is not active in the verified log", ErrDeviceKey)
	}
	return nil
}

// addsCert reports whether w holds a device_add with exactly cert and sig.
func addsCert(w *vaultlog.Wire, cert *crypto.Cert, sig []byte) bool {
	want, err := canonjson.Marshal(cert)
	if err != nil {
		return false
	}
	for _, op := range w.Entry.Ops {
		d, ok := op.(*vaultlog.DeviceAddOp)
		if !ok || d.Cert.DeviceID != cert.DeviceID {
			continue
		}
		got, err := canonjson.Marshal(&d.Cert)
		if err == nil && bytes.Equal(got, want) && bytes.Equal(d.CertSig, sig) {
			return true
		}
	}
	return false
}
