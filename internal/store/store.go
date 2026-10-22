// Package store is HopKey's encrypted local vault: a model.Store over the
// signed vault log (crypto spec §5, §11; https://plan.23d.dev/p/xuu5z9q2).
// Phase 1 has no server, so what a server would hold (the account record,
// the log and its objects) lives on disk next to the verified state. Only
// ciphertext, public log data and digests are written; item plaintexts,
// hostnames and keys exist only in memory while the vault is unlocked.
//
// Layout, under the data directory ($XDG_DATA_HOME/hop, else
// ~/.local/share/hop), every directory 0700 and every file 0600:
//
//	device.json                which device key store is in use, this device's ID and
//	                           stale devices to revoke (no secrets)
//	device.key                 the device key, when the file store is used (§11)
//	vault/owner.lock           held by the one process that has the vault open
//	vault/lock                 the writer lock
//	vault/entries/<seq>.json   signed entries (the wire without its objects), append-only
//	vault/objects/<sha256>     envelopes, content-addressed and immutable
//	vault/state.json           the verified state (§5.5)
//	vault/account.json         account_id, salt, kdf_version, pw_blob, rk_blob, verifier hashes
//	vault/journal/<seq>.json   checkpoint candidates, sealed to the device key (§10.1)
//	vault/wal.json             the write-ahead journal of a multi-file commit (wal.go)
//	vault/server.json          present in a server-backed vault (§11.1)
//	vault/outbox/<n>.json      outbox records, sealed under local_key (outbox.go)
//	vault/outbox.json          the outbox counter
//	vault/revoked.json         present once a checkpoint revoked this device (§5.5)
//
// device.json names this device and, while a password unlock is enrolling
// one, its pending replacement; only those two are ever a source of the
// device key. A data directory that a phase 1 build left mid-replacement,
// with the replacement listed as stale and no pending member, is not
// supported: its key is never loaded, and hop unlock --password enrolls
// again. Phase 1 was never released, so no such directory needs migrating.
//
// One process owns the vault at a time: Open takes vault/owner.lock for the
// life of the Store, and a second Open fails with ErrVaultBusy. That process
// is the hop daemon; the CLI goes through it.
//
// A write stores its objects, then its entry, then state.json, each fsynced,
// under an exclusive lock. The entry file is the commit point: on unlock,
// every entry is verified again from the latest anchor (genesis or
// checkpoint), and an entry past state.json's head (a crash between the two)
// is applied only after it passes the transition algorithm. Otherwise
// state.json must be, byte for byte, the state the replay computes at its
// head (rev 12 makes that state the same on every client); any other
// state.json fails closed.
//
// A server-backed vault (§11.1, EnableServerMode) writes nothing to the log
// itself. Item writes become outbox records; Pull writes only entries
// verified from the server, each in one write-ahead-journaled commit with
// state.json and the outbox records it settles; PushHead posts the head
// record. Snapshot shows the overlay.
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
	"sync"
	"sync/atomic"
	"time"

	"github.com/dalyem/hopkey/internal/canonjson"
	"github.com/dalyem/hopkey/internal/crypto"
	"github.com/dalyem/hopkey/internal/filelock"
	"github.com/dalyem/hopkey/internal/model"
	"github.com/dalyem/hopkey/internal/vaultlog"
)

var (
	// ErrNoVault means the data directory holds no vault.
	ErrNoVault = errors.New("store: there is no vault on this device; run hop init")
	// ErrVaultExists means init found a vault (or the start of one).
	ErrVaultExists = errors.New("store: a vault already exists on this device")
	// ErrCorrupt means the files on disk fail verification. The store
	// refuses to use them.
	ErrCorrupt = errors.New("store: the vault failed verification")
	// ErrObjectDigest means an object file does not match its digest.
	ErrObjectDigest = errors.New("store: object does not match its digest")
	// ErrDeviceKey means the device key could not be read. The vault stays
	// locked; hop unlock --password restores the key.
	ErrDeviceKey = errors.New("store: the device key is unavailable")
	// ErrKeyStoreUnavailable means the device key store could not be read
	// conclusively: a backend or access error, not a missing entry. The
	// vault stays locked, nothing in the store or in device.json is changed,
	// and no password unlock replaces the key until the store reads again
	// (deviceStore.revokedSelf).
	ErrKeyStoreUnavailable = errors.New("store: the device key store could not be read")
	// ErrWrongPassword means the master password (with the Secret Key) did
	// not open the account.
	ErrWrongPassword = errors.New("store: wrong master password or Secret Key")
	// ErrNeedSecretKey means a password unlock needs the Secret Key, which
	// this device does not have stored.
	ErrNeedSecretKey = errors.New("store: the Secret Key is not stored on this device; enter it from your Emergency Kit")
	// ErrKitPending means a password change committed but its Emergency Kit
	// has not been confirmed yet.
	ErrKitPending = errors.New("store: a new Emergency Kit is waiting to be confirmed; run hop passwd to see it")
	// ErrVaultBusy means another Store (another process, normally the hop
	// daemon) has the vault open.
	ErrVaultBusy = errors.New("store: the vault is busy (another hop process owns it)")
	// ErrDeviceRevoked means an authenticated checkpoint revoked this device
	// (§5.5). Its vault can't be unlocked or used again, with the device key
	// or the password: sign in again as a new device.
	ErrDeviceRevoked = errors.New("store: this device was revoked from the account; its vault can't be used here again")
	// ErrAlreadyUnlocked means UnlockWithPasswordRemote was called on an
	// unlocked vault. It is for a lost device key, so it runs only locked.
	ErrAlreadyUnlocked = errors.New("store: the vault is already unlocked; hop lock first to replace the device key with the password")

	errClosed = errors.New("store: the vault store is closed")

	errLocked = fmt.Errorf("%w; run hop unlock", model.ErrLocked)
)

// Config says where the vault is and what it may use.
type Config struct {
	// DataDir holds the vault and the device key file. Use DefaultDataDir.
	DataDir string
	// Keyring is the OS keychain. Nil means OSKeyring.
	Keyring Keyring
	// Getenv reads HOP_DEVICE_PASSPHRASE. Nil means os.Getenv.
	Getenv func(string) string
	// Now is the clock for entry times. Nil means time.Now.
	Now func() time.Time
	// DeviceName names devices this store creates (init, password unlock).
	// Empty means the host name.
	DeviceName string
}

// Head is the verified head of the log: seq and H(E) in hex.
type Head struct {
	Seq uint64 `json:"seq,string"`
	H   string `json:"h"`
}

// Short is what hop status prints: seq and the first 8 bytes of H (§5.6).
func (h Head) Short() string {
	if len(h.H) < 16 {
		return fmt.Sprintf("%d", h.Seq)
	}
	return fmt.Sprintf("%d %s", h.Seq, h.H[:16])
}

// Info describes the vault for hop status. It holds no secrets.
type Info struct {
	Locked      bool   `json:"locked"`
	Revoked     bool   `json:"revoked,omitempty"`     // see ErrDeviceRevoked
	LockReason  string `json:"lock_reason,omitempty"` // why the last unlock failed
	DeviceStore string `json:"device_key_store"`
	DeviceID    string `json:"device_id,omitempty"`
	AccountID   string `json:"account_id,omitempty"`
	Head        *Head  `json:"head,omitempty"`
	KitPending  bool   `json:"kit_pending,omitempty"`
	// StaleDevices counts devices this machine enrolled and lost the key
	// of (password unlocks), still active in the log until hop passwd.
	StaleDevices int `json:"stale_devices,omitempty"`
	// Warnings are for the user, one sentence each.
	Warnings []string `json:"warnings,omitempty"`
}

// Store is the encrypted vault. It implements model.Store; Head, Lock,
// Unlock, UnlockWithPassword and ChangePassword are extra.
type Store struct {
	cfg Config
	l   layout

	mu      sync.Mutex
	state   *vaultlog.State   // verified; nil while locked
	sec     *vaultlog.Secrets // nil while locked
	dev     *vaultlog.LocalDevice
	rec     *deviceRecord
	devCfg  deviceConfig
	lockErr error
	kit     *Kit   // a committed password change whose kit is not confirmed
	kitSeq  uint64 // the seq of kit's journal
	// kitOrphaned means the current checkpoint's journal is sealed only to
	// a device key this device no longer has: its kit cannot be shown.
	kitOrphaned bool
	// skErr is why the pending kit's Secret Key is not in the device key
	// store yet. AckKit refuses until it is.
	skErr error
	// kitSKDurable means a save of the pending kit's Secret Key, or the
	// fsyncs that make a stored one durable, fully succeeded. Until then a
	// record that merely reads back is not trusted (see persistKitSK).
	kitSKDurable bool
	// repaired says what the last unlock finished after a crash.
	repaired string

	// server says the vault is server-backed (vault/server.json).
	server bool
	// syncMu serializes Pull and PushHead. Neither holds mu while it waits
	// on the server.
	syncMu sync.Mutex
	// gen is the generation (Generation): it counts unlocks, locks,
	// self-locks and revocations. A pull or push started in an earlier
	// generation discards its result (§11.2); cancels are its in-flight
	// requests. It is written under mu and read without it.
	gen      atomic.Uint64
	cancels  map[uint64]context.CancelFunc
	cancelID uint64
	// syncHalt is the error that stopped syncing (an equivocation or a
	// rule violation in a server entry).
	syncHalt error
	// revoked is set for good once a checkpoint revokes this device
	// (§5.5, revoke): it wraps ErrDeviceRevoked. revokedC is closed then
	// (Revoked), and isRevoked set (IsRevoked).
	revoked   error
	revokedC  chan struct{}
	isRevoked atomic.Bool

	owner *os.File // vault/owner.lock, held from Open (or Commit) to Close

	testHook func(stage string) error // simulates crashes in tests
}

var _ model.Store = (*Store)(nil)

func (s *Store) ring() Keyring {
	if s.cfg.Keyring != nil {
		return s.cfg.Keyring
	}
	return OSKeyring{}
}

func (s *Store) getenv() func(string) string {
	if s.cfg.Getenv != nil {
		return s.cfg.Getenv
	}
	return os.Getenv
}

func (s *Store) now() model.Timestamp {
	if s.cfg.Now != nil {
		return model.TimestampOf(s.cfg.Now())
	}
	return model.TimestampOf(time.Now())
}

func (s *Store) deviceName() string {
	name := s.cfg.DeviceName
	if name == "" {
		name, _ = os.Hostname()
	}
	if crypto.CheckStr("name", name, 64) != nil || name == "" {
		name = "hop device"
	}
	return name
}

// Open opens the vault in cfg.DataDir and unlocks it with the device key.
// If the device key cannot be read, the store is returned locked (Info says
// why) so that hop unlock --password can still reach it. So it is when the
// device key store cannot be read at all (ErrKeyStoreUnavailable), and
// then the password unlock refuses too. So is the vault of
// a revoked device, which never unlocks again. A vault that fails
// verification is an error.
//
// The returned Store owns the vault until Close: a second Open, in this
// process or another, fails with ErrVaultBusy.
func Open(ctx context.Context, cfg Config) (*Store, error) {
	s := &Store{cfg: cfg, l: layout{data: cfg.DataDir}}
	if ok, err := s.l.exists(); err != nil {
		return nil, err
	} else if !ok {
		return nil, ErrNoVault
	}
	if err := s.l.ensureDirs(); err != nil {
		return nil, err
	}
	if err := s.own(); err != nil {
		return nil, err
	}
	if err := s.Unlock(ctx); err != nil && !errors.Is(err, ErrDeviceKey) && !errors.Is(err, ErrDeviceRevoked) && !errors.Is(err, ErrKeyStoreUnavailable) {
		s.Close()
		return nil, err
	}
	return s, nil
}

// own takes vault/owner.lock without waiting.
func (s *Store) own() error {
	f, err := filelock.TryLock(s.l.ownerLock())
	if errors.Is(err, filelock.ErrLocked) {
		return ErrVaultBusy
	}
	if err != nil {
		return err
	}
	s.owner = f
	return nil
}

// Close drops every secret from memory and gives up the vault, so another
// Open can take it. The Store cannot be unlocked again.
func (s *Store) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.dropLocked(nil)
	if s.owner == nil {
		return nil
	}
	err := s.owner.Close()
	s.owner = nil
	return err
}

// lockFile takes the vault's writer lock. Every write, and every unlock
// (which may finish a crashed write), holds it throughout.
func (s *Store) lockFile() (func(), error) {
	f, err := filelock.Lock(s.l.lockFile())
	if err != nil {
		return nil, err
	}
	return func() { f.Close() }, nil
}

// Lock drops every secret from memory. Reads and writes fail with
// model.ErrLocked until Unlock.
func (s *Store) Lock() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.dropLocked(nil)
}

func (s *Store) dropLocked(reason error) {
	// The generation moves first, so the daemon's fence (Generation) admits
	// no new signature before anything else happens. A signature admitted
	// before it moved may still complete.
	s.gen.Add(1)
	if s.sec != nil {
		if s.sec.Account != nil {
			s.sec.Account.Zero()
		}
		s.sec.VK.Zero()
		for id := range s.sec.Items {
			p := s.sec.Items[id]
			p.IK.Zero()
			delete(s.sec.Items, id)
		}
	}
	if s.rec != nil {
		s.rec.zero()
	}
	s.state, s.sec, s.dev, s.rec, s.kit = nil, nil, nil, nil, nil
	s.kitOrphaned, s.skErr, s.kitSKDurable, s.repaired = false, nil, false, ""
	s.lockErr = reason
	// §11.2: locking stops pulls and pushes. In-flight requests are
	// cancelled, and their responses are discarded by generation.
	for id, cancel := range s.cancels {
		cancel()
		delete(s.cancels, id)
	}
}

// Generation is the store's generation: it moves on every unlock, every
// lock, every self-lock (an interrupted commit, a failed unlock) and every
// revocation, before anything slow is written. It reads without the
// store's mutex, which a lock or a revocation may hold for a while. The
// daemon admits a list or a signature only while the generation its keys
// were loaded in is current and IsRevoked is false (§5.5). That is an
// admission cutoff: a call admitted before the generation moved may still
// complete; every call that starts after is refused.
func (s *Store) Generation() uint64 { return s.gen.Load() }

// IsRevoked reports, without the store's mutex, whether this device is
// known to be revoked (ErrDeviceRevoked).
func (s *Store) IsRevoked() bool { return s.isRevoked.Load() }

// Unlock reads the device key, verifies the log on disk and loads the
// vault (§5.5). It finishes a write or a password change that a crash
// interrupted, after verifying it. It does nothing if the vault is already
// unlocked. A failure leaves the vault locked.
func (s *Store) Unlock(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.state != nil {
		return nil
	}
	err := s.unlockLocked()
	if rev := (*vaultlog.RevokedError)(nil); errors.As(err, &rev) {
		err = s.revoke(rev)
	}
	if err != nil {
		s.dropLocked(err)
	}
	return err
}

func (s *Store) unlockLocked() error {
	if s.owner == nil {
		return errClosed
	}
	if err := s.checkRevoked(); err != nil {
		// A revocation whose tombstone failed retries it.
		s.retryTombstone()
		return err
	}
	cfg, err := s.readDeviceConfig()
	if err != nil {
		return err
	}
	s.devCfg = cfg
	rec, err := s.deviceStore(cfg).load()
	if errors.Is(err, ErrDeviceRevoked) {
		// The tombstone of a revocation whose revoked.json was lost, of
		// this device or of its pending replacement.
		s.setRevoked(err)
	}
	if err != nil {
		return err
	}
	defer func() {
		if s.rec != rec {
			rec.zero()
		}
	}()
	dev, err := rec.device()
	if err != nil {
		return err
	}
	unlock, err := s.lockFile()
	if err != nil {
		return err
	}
	defer unlock()
	// A v1 record becomes v2 with a local_key, durably, before anything
	// uses it (§11, rev 16). If that fails, the vault stays locked.
	if err := s.deviceStore(cfg).upgradeRecord(rec); err != nil {
		return err
	}
	if err := s.replayWAL(); err != nil {
		return err
	}
	server, err := s.l.serverBacked()
	if err != nil {
		return err
	}

	stored, raw, err := s.readStoredState()
	if err != nil {
		return err
	}
	acct, err := deviceAccount(s.l, stored, dev)
	if err != nil {
		return err
	}
	st, sec, repaired, err := s.replay(stored, raw, acct, dev, nil)
	if err != nil {
		return err
	}
	s.state, s.sec, s.dev, s.rec, s.repaired, s.server = st, sec, dev, rec, repaired, server
	s.gen.Add(1)
	return s.finishUnlock()
}

// finishUnlock is what every unlock does once its verified state is
// installed: device.json, account.json, the outbox candidates that verified
// history decides, and the checkpoint journals. The caller holds the file
// lock, and locks the store again if it fails.
func (s *Store) finishUnlock() error {
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

// revokedFile is vault/revoked.json, the terminal revocation record (§5.5):
// the device and the checkpoint that revoked it.
type revokedFile struct {
	V        int         `json:"v"`
	DeviceID model.ID    `json:"device_id"`
	Seq      uint64      `json:"seq,string"`
	H        crypto.Hash `json:"h"`
}

func (l layout) revokedFile() string { return filepath.Join(l.vault(), "revoked.json") }

// revoke handles an authenticated checkpoint that revokes this device
// (§5.5, "Revoked here?"). It first marks the store revoked, which moves
// the generation and fences the daemon's agent at once (Generation,
// IsRevoked), and closes the Revoked channel. Then it records the
// revocation durably in vault/revoked.json and overwrites the device
// record with its tombstone, so the device key store keeps no key material
// and, if the marker was lost, still says the device is revoked. Then it
// wipes every decrypted secret and cancels in-flight requests. From then
// on every use and every unlock of this vault fails with ErrDeviceRevoked,
// after a restart too. The revoking entry is never decrypted or written.
// The caller holds s.mu and, when there is one, the file lock.
//
// rev.DeviceID is a device this data directory is: DeviceID, or the
// pending replacement of a password unlock (deviceConfig.self). Either
// one's revocation is terminal for the directory.
//
// The marker and a tombstone in every self record (DeviceID's and the
// pending replacement's keychain entries, or device.key) are each
// attempted, independently, and each failure is reported. Any one of them
// keeps the revocation terminal under a server that withholds the revoking
// checkpoint: Open, Unlock and both password unlocks refuse when they find
// it (checkRevoked, load). Only if none was written is every self record
// deleted, each independently, as a last resort, and the error says so: a
// password unlock against a server that withholds the checkpoint could
// then enroll this machine again (the total-failure limitation). A self
// record whose deletion failed is still readable, and its key unlocks the
// vault again after a restart unless the server shows the revocation; the
// error names it.
func (s *Store) revoke(rev *vaultlog.RevokedError) error {
	s.setRevoked(fmt.Errorf("%w (device %v, by the checkpoint at seq %d)", ErrDeviceRevoked, rev.DeviceID, rev.Head.Seq))
	var failed []string
	b, err := canonjson.Marshal(revokedFile{V: 1, DeviceID: rev.DeviceID, Seq: rev.Head.Seq, H: rev.Head.H})
	if err == nil {
		err = s.hook("revoke:marker")
	}
	if err == nil {
		err = writeFileAtomic(s.l.revokedFile(), b)
	}
	written := err == nil
	if !written {
		failed = append(failed, fmt.Sprintf("recording it on disk failed: %v", err))
	}
	tombs, errs := s.tombstoneRecord(rev.DeviceID)
	failed = append(failed, errs...)
	if !written && tombs == 0 {
		if errs := s.destroyDeviceRecord(rev.DeviceID); len(errs) > 0 {
			failed = append(failed, errs...)
			failed = append(failed, "a device key that could not be deleted is still readable on this machine")
		} else {
			failed = append(failed, "the device key was deleted instead, so a server that withholds the revocation could enroll this machine again")
		}
	}
	s.dropLocked(s.revoked)
	if len(failed) > 0 {
		return fmt.Errorf("%w; %s", s.revoked, strings.Join(failed, "; "))
	}
	return s.revoked
}

// selfRecords is the device records a revocation of id reaches: in the
// keychain, id's entry and the entry of every device this data directory
// is (deviceConfig.self), DeviceID's and the pending replacement's;
// device.key is one record, whichever self device it holds (ownsFile).
func selfRecords(cfg deviceConfig, id model.ID) []model.ID {
	if cfg.Store != DeviceStoreKeychain {
		return []model.ID{id}
	}
	ids := []model.ID{id}
	for _, other := range cfg.self() {
		if !slices.Contains(ids, other) {
			ids = append(ids, other)
		}
	}
	return ids
}

// tombstoneRecord overwrites every self record a revocation of id reaches
// with its tombstone (selfRecords, deviceStore.tombstone), each
// independently: one that fails does not stop the others. It returns how
// many were written and a description of each failure. The caller holds
// s.mu.
func (s *Store) tombstoneRecord(id model.ID) (int, []string) {
	cfg, err := s.readDeviceConfig()
	if err != nil {
		return 0, []string{fmt.Sprintf("replacing the device key with a tombstone failed: %v", err)}
	}
	if err := s.hook("revoke:tombstone"); err != nil {
		return 0, []string{fmt.Sprintf("replacing the device key with a tombstone failed: %v", err)}
	}
	ds := s.deviceStore(cfg)
	var n int
	var failed []string
	for _, rid := range selfRecords(cfg, id) {
		if err := ds.tombstone(rid); err != nil {
			failed = append(failed, fmt.Sprintf("replacing the device key of %v with a tombstone failed: %v", rid, err))
			continue
		}
		n++
	}
	return n, failed
}

// destroyDeviceRecord deletes every self record a revocation of id
// reaches (selfRecords, deviceStore.destroy), each independently, and
// returns a description of each failure. The caller holds s.mu.
func (s *Store) destroyDeviceRecord(id model.ID) []string {
	cfg, err := s.readDeviceConfig()
	if err != nil {
		return []string{fmt.Sprintf("deleting the device key failed: %v", err)}
	}
	if err := s.hook("revoke:destroy"); err != nil {
		return []string{fmt.Sprintf("deleting the device key failed: %v", err)}
	}
	ds := s.deviceStore(cfg)
	var failed []string
	for _, rid := range selfRecords(cfg, id) {
		if err := ds.destroy(rid); err != nil {
			failed = append(failed, fmt.Sprintf("deleting the device key of %v failed: %v", rid, err))
		}
	}
	return failed
}

// retryTombstone writes the tombstone of the device revoked.json names,
// for a revocation whose tombstone failed. It is best effort: the marker
// already makes the revocation terminal. The caller holds s.mu.
func (s *Store) retryTombstone() {
	b, err := os.ReadFile(s.l.revokedFile())
	var f revokedFile
	if err != nil || canonjson.Unmarshal(b, &f) != nil || f.V != 1 || f.DeviceID.IsZero() {
		return
	}
	s.tombstoneRecord(f.DeviceID)
}

// checkRevoked fails with ErrDeviceRevoked once this device is revoked: a
// file at vault/revoked.json (any file counts: only hop writes it), or the
// tombstone of a device this data directory is, DeviceID or the pending
// replacement, in the device key store (deviceStore.revokedSelf). A device
// key store it cannot read conclusively fails with ErrKeyStoreUnavailable,
// which is not a revocation: nothing is recorded, and the next check reads
// again. The caller holds s.mu.
func (s *Store) checkRevoked() error {
	if s.revoked != nil {
		return s.revoked
	}
	b, err := os.ReadFile(s.l.revokedFile())
	if errors.Is(err, os.ErrNotExist) {
		if cfg, err := s.readDeviceConfig(); err == nil {
			err := s.deviceStore(cfg).revokedSelf()
			if errors.Is(err, ErrDeviceRevoked) {
				s.setRevoked(err)
			}
			return err
		}
		return nil
	}
	var f revokedFile
	if err != nil || canonjson.Unmarshal(b, &f) != nil || f.V != 1 {
		s.setRevoked(fmt.Errorf("%w (%s)", ErrDeviceRevoked, s.l.revokedFile()))
	} else {
		s.setRevoked(fmt.Errorf("%w (device %v, by the checkpoint at seq %d)", ErrDeviceRevoked, f.DeviceID, f.Seq))
	}
	return s.revoked
}

// setRevoked records err, which wraps ErrDeviceRevoked, as this device's
// revocation and closes the Revoked channel. The caller holds s.mu.
func (s *Store) setRevoked(err error) {
	if s.revoked == nil {
		// The fence first (Generation, IsRevoked), then the signal.
		s.isRevoked.Store(true)
		s.gen.Add(1)
		close(s.revokedChan())
	}
	s.revoked = err
}

// revokedChan returns the Revoked channel, made on first use. The caller
// holds s.mu.
func (s *Store) revokedChan() chan struct{} {
	if s.revokedC == nil {
		s.revokedC = make(chan struct{})
	}
	return s.revokedC
}

// Revoked returns a channel that is closed once this device is revoked
// (ErrDeviceRevoked), by a pull or any other path that meets the revoking
// checkpoint. The daemon watches it to drop the keys it serves at once.
func (s *Store) Revoked() <-chan struct{} {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.checkRevoked()
	return s.revokedChan()
}

// lockedErr is the error for a use of the vault while it is locked:
// ErrDeviceRevoked for a revoked device. The caller holds s.mu.
func (s *Store) lockedErr() error {
	if s.revoked != nil {
		return s.revoked
	}
	return errLocked
}

// deviceAccount opens this device's unlock blob (§6.2) in the stored state
// and returns the account keys for its akv. stored is not verified yet: the
// replay that follows anchors with these keys and fails unless they are the
// account's.
func deviceAccount(l layout, stored *vaultlog.State, dev *vaultlog.LocalDevice) (*crypto.AccountKeys, error) {
	if stored == nil {
		// Only genesis was written before a crash: take this device's
		// unlock blob from it.
		w, err := l.readEntry(0)
		if err != nil {
			return nil, fmt.Errorf("%w: no state and no genesis entry: %v", ErrCorrupt, err)
		}
		for _, o := range w.Entry.Ops {
			if d, ok := o.(*vaultlog.DeviceAddOp); ok && d.Cert.DeviceID == dev.ID {
				return openUnlock(l, &d.Cert, d.UnlockSHA256, dev)
			}
		}
		return nil, fmt.Errorf("%w: this device is not in the genesis entry", ErrDeviceKey)
	}
	d, ok := stored.Devices[dev.ID]
	if !ok {
		return nil, fmt.Errorf("%w: device %v is not active in this vault", ErrDeviceKey, dev.ID)
	}
	acct, err := openUnlock(l, &d.Cert, d.UnlockSHA256, dev)
	if err != nil {
		return nil, err
	}
	if err := crypto.CheckUnlockPin(acct, stored.Pin()); err != nil {
		return nil, fmt.Errorf("%w: unlock blob: %v", ErrCorrupt, err)
	}
	return acct, nil
}

func openUnlock(l layout, cert *crypto.Cert, h crypto.Hash, dev *vaultlog.LocalDevice) (*crypto.AccountKeys, error) {
	b, err := objectDir(l.objects()).FetchObject(h)
	if err != nil {
		return nil, fmt.Errorf("%w: unlock blob: %w", ErrCorrupt, err)
	}
	env, err := crypto.ParseHPKEEnvelope(b)
	if err != nil {
		return nil, fmt.Errorf("%w: unlock blob: %v", ErrCorrupt, err)
	}
	acct, err := dev.OpenUnlock(cert, env)
	if err != nil {
		return nil, fmt.Errorf("%w: this device key does not open its unlock blob: %v", ErrDeviceKey, err)
	}
	return acct, nil
}

// readStoredState reads state.json, parsed and as the bytes on disk, or
// returns nil if it is missing and only the genesis entry exists (a crash
// during init).
func (s *Store) readStoredState() (*vaultlog.State, []byte, error) {
	b, err := os.ReadFile(s.l.stateFile())
	if errors.Is(err, os.ErrNotExist) {
		seqs, err := s.l.entrySeqs()
		if err != nil {
			return nil, nil, err
		}
		if len(seqs) == 1 && seqs[0] == 0 {
			return nil, nil, nil
		}
		if len(seqs) == 0 {
			return nil, nil, ErrNoVault
		}
		return nil, nil, fmt.Errorf("%w: state.json is missing", ErrCorrupt)
	}
	if err != nil {
		return nil, nil, err
	}
	st, err := vaultlog.ParseState(b)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: state.json: %v", ErrCorrupt, err)
	}
	return st, b, nil
}

// replay verifies the log on disk (§5.5): it anchors at the newest genesis
// or checkpoint entry at or before the stored head with acct, applies the
// transition algorithm to every later entry, and requires the stored head
// to be one it passes and state.json (raw) to be exactly the state it
// computes there. Entries past the stored head are the tail of a write that
// crashed before state.json was updated: each is verified by the transition
// algorithm before it is applied, and state.json is then rewritten; the
// returned note says so. dev crosses a checkpoint in that tail; with no dev
// (a password unlock) such a tail is an error, or a *vaultlog.RevokedError
// if it revokes a device in self (see transition).
func (s *Store) replay(stored *vaultlog.State, raw []byte, acct *crypto.AccountKeys, dev vaultlog.DeviceKey, self []model.ID) (*vaultlog.State, *vaultlog.Secrets, string, error) {
	seqs, err := s.l.entrySeqs()
	if err != nil {
		return nil, nil, "", err
	}
	for i, seq := range seqs {
		if seq != uint64(i) {
			return nil, nil, "", fmt.Errorf("%w: entry %d is missing", ErrCorrupt, i)
		}
	}
	var storedHead *vaultlog.Head
	if stored != nil {
		storedHead = &stored.Head
	}
	if storedHead != nil && storedHead.Seq >= uint64(len(seqs)) {
		return nil, nil, "", fmt.Errorf("%w: the state head (seq %d) is not among the entries (%d on disk)", ErrCorrupt, storedHead.Seq, len(seqs))
	}
	last := uint64(0)
	if storedHead != nil {
		last = storedHead.Seq
	}

	wires := make([]*vaultlog.Wire, len(seqs))
	anchor := -1
	for i := range seqs {
		w, err := s.l.readEntry(uint64(i))
		if err != nil {
			return nil, nil, "", err
		}
		wires[i] = w
		if k := w.Entry.Kind; uint64(i) <= last && (k == vaultlog.KindGenesis || k == vaultlog.KindCheckpoint) {
			anchor = i
		}
	}
	if anchor < 0 {
		return nil, nil, "", fmt.Errorf("%w: no genesis or checkpoint entry at or before seq %d", ErrCorrupt, last)
	}

	objs := objectDir(s.l.objects())
	st, sec, _, err := vaultlog.Anchor(acct.Pin(), acct, wires[anchor], objs, nil)
	if err != nil {
		return nil, nil, "", fmt.Errorf("%w: anchor entry %d: %w", ErrCorrupt, anchor, err)
	}
	for i := anchor + 1; i <= int(last); i++ {
		if st, sec, err = vaultlog.Transition(st, sec, dev, wires[i], objs); err != nil {
			return nil, nil, "", fmt.Errorf("%w: entry %d: %w", ErrCorrupt, i, err)
		}
	}
	if storedHead != nil && (st.Head.Seq != storedHead.Seq || !st.Head.H.Equal(storedHead.H)) {
		return nil, nil, "", fmt.Errorf("%w: the state head (seq %d) is not the entry on disk at that seq", ErrCorrupt, storedHead.Seq)
	}
	// Every client computes the same state at the same head (rev 12), so
	// state.json must be exactly that state. Anything else was changed
	// outside hop: fail closed rather than trust it or quietly repair it.
	if stored != nil {
		want, err := st.Marshal()
		if err != nil {
			return nil, nil, "", err
		}
		if !bytes.Equal(want, raw) {
			return nil, nil, "", fmt.Errorf("%w: state.json differs from the verified log at seq %d", ErrCorrupt, last)
		}
	}

	// Crash recovery: entries past the stored head. With no state.json at
	// all, only genesis exists (a crash during init).
	note := ""
	if stored != nil && len(wires)-1 > int(last) {
		note = fmt.Sprintf("finished a write that a crash interrupted: state.json moved from seq %d to %d", last, len(wires)-1)
	}
	for i := int(last) + 1; i < len(wires); i++ {
		if st, sec, err = transition(st, sec, dev, self, wires[i], objs); err != nil {
			return nil, nil, "", fmt.Errorf("%w: entry %d past the state head: %w", ErrCorrupt, i, err)
		}
	}
	if stored == nil || note != "" {
		if err := s.writeState(st); err != nil {
			return nil, nil, "", err
		}
	}
	return st, sec, note, nil
}

// Head returns the verified head. It fails with model.ErrLocked while the
// vault is locked. The daemon compares it with the head of its last reload
// to skip rebuilding from an unchanged vault.
func (s *Store) Head() (Head, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.state == nil {
		return Head{}, s.lockedErr()
	}
	return Head{Seq: s.state.Head.Seq, H: s.state.Head.H.String()}, nil
}

// Info describes the vault for hop status.
func (s *Store) Info() Info {
	s.mu.Lock()
	defer s.mu.Unlock()
	info := Info{Locked: s.state == nil, KitPending: s.kit != nil, Revoked: errors.Is(s.checkRevoked(), ErrDeviceRevoked)}
	if cfg, err := s.readDeviceConfig(); err == nil {
		info.DeviceStore = s.deviceStore(cfg).Describe()
		info.AccountID = cfg.AccountID.String()
		info.StaleDevices = len(cfg.StaleDevices)
		if s.state != nil {
			info.StaleDevices = len(s.staleActive(cfg))
		}
	}
	if s.lockErr != nil {
		info.LockReason = s.lockErr.Error()
	}
	if s.state != nil {
		info.Head = &Head{Seq: s.state.Head.Seq, H: s.state.Head.H.String()}
		info.DeviceID = s.dev.ID.String()
	}
	if s.kitOrphaned {
		info.Warnings = append(info.Warnings, "the Emergency Kit from the last hop passwd was never confirmed, "+
			"and this device can no longer read it: hop unlock --password replaced the device key it was sealed to. "+
			"Its Recovery Key cannot be recovered; run hop passwd to make a new Emergency Kit")
	}
	if s.skErr != nil {
		info.Warnings = append(info.Warnings, fmt.Sprintf("the new Secret Key from the last hop passwd is not saved on this device yet (%v); run hop passwd to retry", s.skErr))
	}
	if info.StaleDevices > 0 {
		info.Warnings = append(info.Warnings, fmt.Sprintf("%d stale device(s) from earlier password unlocks; run hop passwd to revoke", info.StaleDevices))
	}
	if s.repaired != "" {
		info.Warnings = append(info.Warnings, s.repaired)
	}
	if m, err := s.readOutboxMeta(); err == nil && m.Lost > 0 {
		info.Warnings = append(info.Warnings, fmt.Sprintf("%d queued change(s), pending or held, were lost when hop unlock --password "+
			"replaced an unreadable device key; make them again", m.Lost))
	}
	if s.syncHalt != nil {
		info.Warnings = append(info.Warnings, s.syncHalt.Error())
	}
	return info
}

// catchUp applies, after verifying them, entries past the in-memory head:
// a write whose entry committed but whose state.json write failed. The
// verified result goes to state.json before it replaces the state in
// memory, so memory never runs ahead of the disk. The caller holds the file
// lock.
func (s *Store) catchUp() error {
	objs := objectDir(s.l.objects())
	st, sec := s.state, s.sec
	for {
		w, err := s.l.readEntry(st.Head.Seq + 1)
		if errors.Is(err, os.ErrNotExist) {
			break
		}
		if err != nil {
			return err
		}
		if st, sec, err = vaultlog.Transition(st, sec, s.dev, w, objs); err != nil {
			if rev := (*vaultlog.RevokedError)(nil); errors.As(err, &rev) {
				return s.revoke(rev)
			}
			return fmt.Errorf("%w: entry %d: %w", ErrCorrupt, w.Entry.Seq, err)
		}
	}
	if st == s.state {
		return nil
	}
	if err := s.writeState(st); err != nil {
		return err
	}
	s.state, s.sec = st, sec
	return nil
}

// writeState writes state.json.
func (s *Store) writeState(st *vaultlog.State) error {
	if err := s.hook("state"); err != nil {
		return err
	}
	return s.l.writeState(st)
}

// commit writes a built entry: its objects, then the entry, then state.json.
// The caller holds the file lock.
func (s *Store) commit(w *vaultlog.Wire, st *vaultlog.State) error {
	if err := s.l.writeObjects(w); err != nil {
		return err
	}
	if err := s.l.writeEntry(w); err != nil {
		return err
	}
	return s.writeState(st)
}

// write builds a normal entry for ch against the current head and commits
// it. check, if set, runs against the current head before anything is
// built.
func (s *Store) write(ch vaultlog.Changes, check func() error) error {
	unlock, err := s.lockFile()
	if err != nil {
		return err
	}
	defer unlock()
	if err := s.catchUp(); err != nil {
		return err
	}
	if check != nil {
		if err := check(); err != nil {
			return err
		}
	}
	w, st, sec, err := vaultlog.BuildNormal(s.state, s.sec, s.dev, ch, s.now(), objectDir(s.l.objects()))
	if err != nil {
		return err
	}
	if err := s.commit(w, st); err != nil {
		return err
	}
	s.state, s.sec = st, sec
	return nil
}

// Snapshot returns every live item, decrypted. In a server-backed vault it
// is the overlay (§11.1): verified state with the queued records applied in
// order, and Marks naming the items they affect.
func (s *Store) Snapshot(context.Context) (model.Snapshot, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.sec == nil {
		return model.Snapshot{}, s.lockedErr()
	}
	if !s.server {
		return snapshotOf(s.sec), nil
	}
	unlock, err := s.lockFile()
	if err != nil {
		return model.Snapshot{}, err
	}
	defer unlock()
	ov, err := s.overlayLocked()
	if err != nil {
		return model.Snapshot{}, err
	}
	return ov.snapshot()
}

func snapshotOf(sec *vaultlog.Secrets) model.Snapshot {
	var snap model.Snapshot
	for _, p := range sec.Items {
		switch v := p.Item.(type) {
		case *model.Host:
			snap.Hosts = append(snap.Hosts, cloneHost(*v))
		case *model.Key:
			snap.Keys = append(snap.Keys, *v)
		case *model.Credential:
			snap.Credentials = append(snap.Credentials, *v)
		case *model.Snippet:
			c := *v
			c.Params = slices.Clone(v.Params)
			snap.Snippets = append(snap.Snippets, c)
		}
	}
	byName := func(a, b model.Header, an, bn string) int {
		if c := strings.Compare(an, bn); c != 0 {
			return c
		}
		return strings.Compare(a.ItemID.String(), b.ItemID.String())
	}
	slices.SortFunc(snap.Hosts, func(a, b model.Host) int { return byName(a.Header, b.Header, a.Name, b.Name) })
	slices.SortFunc(snap.Keys, func(a, b model.Key) int { return byName(a.Header, b.Header, a.Name, b.Name) })
	slices.SortFunc(snap.Credentials, func(a, b model.Credential) int { return byName(a.Header, b.Header, a.Name, b.Name) })
	slices.SortFunc(snap.Snippets, func(a, b model.Snippet) int { return byName(a.Header, b.Header, a.Name, b.Name) })
	return snap
}

func cloneHost(h model.Host) model.Host {
	h.Aliases = slices.Clone(h.Aliases)
	h.Addresses = slices.Clone(h.Addresses)
	h.Tags = slices.Clone(h.Tags)
	h.HostKeys = slices.Clone(h.HostKeys)
	if h.Tailscale != nil {
		t := *h.Tailscale
		h.Tailscale = &t
	}
	return h
}

func (s *Store) PutHost(_ context.Context, h model.Host) (model.Host, error) {
	h = cloneHost(h)
	for _, l := range []*[]string{&h.Aliases, &h.Addresses, &h.Tags, &h.HostKeys} {
		if *l == nil {
			*l = []string{}
		}
	}
	out, err := put(s, &h, model.TypeHost)
	if err != nil {
		return model.Host{}, err
	}
	return cloneHost(*out), nil
}

func (s *Store) PutKey(_ context.Context, k model.Key) (model.Key, error) {
	out, err := put(s, &k, model.TypeKey)
	if err != nil {
		return model.Key{}, err
	}
	return *out, nil
}

func (s *Store) PutCredential(_ context.Context, c model.Credential) (model.Credential, error) {
	out, err := put(s, &c, model.TypeCredential)
	if err != nil {
		return model.Credential{}, err
	}
	return *out, nil
}

func (s *Store) PutSnippet(_ context.Context, sn model.Snippet) (model.Snippet, error) {
	sn.Params = slices.Clone(sn.Params)
	if sn.Params == nil {
		sn.Params = []string{}
	}
	out, err := put(s, &sn, model.TypeSnippet)
	if err != nil {
		return model.Snippet{}, err
	}
	c := *out
	c.Params = slices.Clone(out.Params)
	return c, nil
}

// header returns the shared header of an item pointer.
func header(it crypto.Item) *model.Header {
	switch v := it.(type) {
	case *model.Host:
		return &v.Header
	case *model.Key:
		return &v.Header
	case *model.Credential:
		return &v.Header
	case *model.Snippet:
		return &v.Header
	}
	return nil
}

// put creates (zero ItemID) or replaces an item. A replacement names the
// live item's current version; the store writes version + 1. In a
// server-backed vault the write is queued in the outbox, and the result is
// the overlay item it shows.
func put[T any](s *Store, it *T, typ model.Type) (*T, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.sec == nil {
		return nil, s.lockedErr()
	}
	h := header(it)
	isNew := h.ItemID.IsZero()
	if isNew {
		id, err := vaultlog.NewID()
		if err != nil {
			return nil, err
		}
		h.ItemID, h.ItemVersion = id, 0
	}
	h.V, h.Type = crypto.Version, typ
	if s.server {
		if err := s.queuePut(it, isNew); err != nil {
			return nil, err
		}
		return it, nil
	}
	check := func() error { return s.checkPut(it, isNew) }
	if err := s.write(vaultlog.Changes{Put: []crypto.Item{it}}, check); err != nil {
		return nil, err
	}
	saved, ok := s.sec.Items[h.ItemID].Item.(*T)
	if !ok {
		return nil, fmt.Errorf("store: item %v was not saved", h.ItemID)
	}
	return saved, nil
}

// checkPut applies the model.Store rules for one Put before the log rules:
// a replacement names a live item of the same type at its current version,
// and a host's jump chain must not loop.
func (s *Store) checkPut(it crypto.Item, isNew bool) error {
	h := header(it)
	if !isNew {
		cur, ok := s.state.Items[h.ItemID]
		switch {
		case !ok:
			return model.ErrNotFound
		case cur.Type != h.Type:
			return fmt.Errorf("store: item %s is a %s, not a %s", h.ItemID, cur.Type, h.Type)
		case h.ItemVersion != cur.ItemVersion:
			return fmt.Errorf("store: item %s is at version %d, not %d", h.ItemID, cur.ItemVersion, h.ItemVersion)
		}
	}
	if host, ok := it.(*model.Host); ok {
		seen := map[model.ID]bool{host.ItemID: true}
		for next := host.JumpHostID; !next.IsZero(); {
			if seen[next] {
				return fmt.Errorf("store: host %q has a jump host loop", host.Name)
			}
			seen[next] = true
			j, ok := s.sec.Items[next].Item.(*model.Host)
			if !ok {
				break // the log rules report a missing jump host
			}
			next = j.JumpHostID
		}
	}
	return nil
}

// Delete deletes a live item. References to it must be gone first. In a
// server-backed vault the delete is queued in the outbox.
func (s *Store) Delete(_ context.Context, id model.ID) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.sec == nil {
		return s.lockedErr()
	}
	if s.server {
		return s.queueDelete(id)
	}
	if _, ok := s.state.Items[id]; !ok {
		return model.ErrNotFound
	}
	return s.write(vaultlog.Changes{Delete: []model.ID{id}}, func() error {
		if _, ok := s.state.Items[id]; !ok {
			return model.ErrNotFound
		}
		return nil
	})
}
