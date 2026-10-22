package store

import (
	"bytes"
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

// Device key stores (§11).
const (
	DeviceStoreKeychain = "keychain" // the OS keychain, through zalando/go-keyring
	DeviceStoreFile     = "file"     // $XDG_DATA_HOME/hop/device.key, optionally sealed
)

// PassphraseEnv seals the device key file when it is set at hop init.
const PassphraseEnv = "HOP_DEVICE_PASSPHRASE"

// keychainService is the keychain service name. Each device has its own
// entry under it (deviceStore.slot).
const keychainService = "hopkey-device"

// Keyring is the OS keychain. OSKeyring is the real one; tests use
// go-keyring's mock provider behind it, or their own.
type Keyring interface {
	Get(service, user string) (string, error)
	Set(service, user, secret string) error
	Delete(service, user string) error
}

// OSKeyring is the OS keychain through zalando/go-keyring: the Secret
// Service on Linux, the login keychain on macOS, the Credential Manager on
// Windows.
type OSKeyring struct{}

func (OSKeyring) Get(service, user string) (string, error) { return keyring.Get(service, user) }
func (OSKeyring) Set(service, user, secret string) error   { return keyring.Set(service, user, secret) }
func (OSKeyring) Delete(service, user string) error        { return keyring.Delete(service, user) }

// deviceConfig is device.json: which store holds the device key, and the
// local device bookkeeping. It holds no secrets.
//
// DeviceID is this data directory's device. Pending is at most one
// replacement that a password unlock is enrolling and has not installed
// yet: it is set durably before the bootstrap entry is built, and cleared
// in the same write that makes it DeviceID, or once the attempt is
// abandoned and its record deleted. Only these two are this machine (self):
// the device key is read from DeviceID's record, else from Pending's, and a
// revocation of either is terminal for this directory.
//
// StaleDevices are devices this machine enrolled and then lost the key of
// (a password unlock replaced them, or was abandoned): they are still
// active in the log, and the next hop passwd revokes them (§10.1). They are
// a cleanup list only: never a source of the device key, never self.
type deviceConfig struct {
	V            int            `json:"v"`
	Store        string         `json:"store"`
	Sealed       bool           `json:"sealed,omitempty"` // file store only
	AccountID    model.ID       `json:"account_id"`
	DeviceID     model.ID       `json:"device_id,omitzero"`
	Pending      *pendingDevice `json:"pending,omitempty"`
	StaleDevices []model.ID     `json:"stale_devices,omitempty"`
	// Next is the destination device of a login merge (mergefile.go), of
	// another account. It is written before its record is (the intent), so
	// the device key store never holds a record device.json does not name;
	// the record is durable in the device key store (its keychain entry, or
	// device.next.key) before its bootstrap is posted, and it replaces this
	// device once the destination vault is installed (promoteNext). It is
	// never self and never a source of this vault's device key.
	Next *nextDevice `json:"next,omitempty"`
}

// nextDevice is device.json's next member:
// {"account_id":id, "device_id":id, "stale":[id, ...]}.
//
// Stale are destination devices that an earlier attempt named here and
// whose record was then found, conclusively, to be gone: a bootstrap may
// have committed for any of them, so they become stale devices of the
// destination account when it is installed, and hop passwd revokes the
// ones that are active.
type nextDevice struct {
	AccountID model.ID   `json:"account_id"`
	DeviceID  model.ID   `json:"device_id"`
	Stale     []model.ID `json:"stale,omitempty"`
}

// pendingDevice is device.json's pending member: {"device_id":id}.
type pendingDevice struct {
	DeviceID model.ID `json:"device_id"`
}

// pendingID is the pending replacement, or the zero ID.
func (c deviceConfig) pendingID() model.ID {
	if c.Pending == nil {
		return model.ID{}
	}
	return c.Pending.DeviceID
}

// self is the devices this data directory is: DeviceID, then Pending.
func (c deviceConfig) self() []model.ID {
	var ids []model.ID
	for _, id := range []model.ID{c.DeviceID, c.pendingID()} {
		if !id.IsZero() && !slices.Contains(ids, id) {
			ids = append(ids, id)
		}
	}
	return ids
}

// withPending returns c with the pending replacement set to id, or cleared
// for the zero ID, and its own copy of the stale list.
func (c deviceConfig) withPending(id model.ID) deviceConfig {
	c.Pending = nil
	if !id.IsZero() {
		c.Pending = &pendingDevice{DeviceID: id}
	}
	c.StaleDevices = slices.Clone(c.StaleDevices)
	return c
}

// deviceRecord is what the device key store keeps: this device's private
// keys, the account Secret Key, so the SK never has to be typed again on
// this device (§11, rev 15), and the device-local key that seals the outbox
// (§11, rev 16). It is the keychain entry and the device key file's key
// (sealed, or raw when unsealed):
//
//	JCS({"v":2, "account_id":id, "device_id":id, "kem_sk":b64, "sig_seed":b64(32), "secret_key":str≤64, "local_key":b64(32)})
//
// and is read with parseDeviceRecord, which refuses anything else except a
// phase 1 record (v 1, no local_key). Unlock upgrades that one durably
// before the store is used (upgradeRecord). Only v 2 is ever written.
//
// local_key never leaves the machine. Every rewrite carries it unchanged,
// and a replacement record takes the old one's when that is readable.
type deviceRecord struct {
	V         int      `json:"v"`
	AccountID model.ID `json:"account_id"`
	DeviceID  model.ID `json:"device_id"`
	KEMSK     []byte   `json:"kem_sk"`
	SigSeed   []byte   `json:"sig_seed"`
	SecretKey string   `json:"secret_key"`
	LocalKey  []byte   `json:"local_key"`
}

// deviceRecordV1 is the phase 1 record, read only to upgrade it.
type deviceRecordV1 struct {
	V         int      `json:"v"`
	AccountID model.ID `json:"account_id"`
	DeviceID  model.ID `json:"device_id"`
	KEMSK     []byte   `json:"kem_sk"`
	SigSeed   []byte   `json:"sig_seed"`
	SecretKey string   `json:"secret_key"`
}

// readKeyFile reads device.key. Tests replace it to make a read fail.
var readKeyFile = os.ReadFile

// localKeySize is the length of local_key (§11).
const localKeySize = 32

// parseDeviceRecord strictly decodes a device record: unknown, missing,
// duplicate and wrongly typed members are refused, and so is a record with
// another version, an empty ID or kem_sk, a signing seed that is not 32
// bytes, or a secret_key that is not a str≤64 holding a valid Secret Key
// (§12). Its errors never quote the record: they could carry a character of
// the keys.
func parseDeviceRecord(b []byte) (*deviceRecord, error) {
	var rec deviceRecord
	err := canonjson.Unmarshal(b, &rec)
	if err == nil && rec.V != 2 {
		err = fmt.Errorf("device record version %d with a local_key", rec.V)
	}
	if err != nil {
		rec.zero()
		// A phase 1 record has no local_key; it is read only to upgrade it.
		var v1 deviceRecordV1
		if err1 := canonjson.Unmarshal(b, &v1); err1 != nil || v1.V != 1 {
			clear(v1.KEMSK)
			clear(v1.SigSeed)
			return nil, err
		}
		rec = deviceRecord{
			V: 1, AccountID: v1.AccountID, DeviceID: v1.DeviceID,
			KEMSK: v1.KEMSK, SigSeed: v1.SigSeed, SecretKey: v1.SecretKey,
		}
	}
	switch {
	case rec.V == 2 && len(rec.LocalKey) != localKeySize:
		err = errors.New("device record: local_key is not 32 bytes")
	case rec.V != 1 && rec.V != 2:
		err = fmt.Errorf("device record version %d", rec.V)
	case rec.AccountID.IsZero() || rec.DeviceID.IsZero():
		err = errors.New("device record: empty account_id or device_id")
	case len(rec.KEMSK) == 0:
		err = errors.New("device record: empty kem_sk")
	case len(rec.SigSeed) != ed25519.SeedSize:
		err = errors.New("device record: sig_seed is not 32 bytes")
	default:
		err = crypto.CheckStr("secret_key", rec.SecretKey, 64)
	}
	if err == nil {
		if _, perr := crypto.ParseSecretKey(rec.SecretKey); perr != nil {
			err = errors.New("device record: secret_key is not a valid Secret Key")
		}
	}
	if err != nil {
		rec.zero()
		return nil, err
	}
	return &rec, nil
}

func (r *deviceRecord) zero() {
	clear(r.KEMSK)
	clear(r.SigSeed)
	clear(r.LocalKey)
	r.SecretKey = ""
}

// jcs returns the record's canonical encoding. Only a v 2 record is ever
// written.
func (r *deviceRecord) jcs() ([]byte, error) {
	if r.V != 2 || len(r.LocalKey) != localKeySize {
		return nil, errors.New("store: only a v2 device record with a local_key is written")
	}
	return canonjson.Marshal(r)
}

// localKey returns local_key as an AEAD key.
func (r *deviceRecord) localKey() (*crypto.SymKey, error) {
	if r.V != 2 || len(r.LocalKey) != localKeySize {
		return nil, ErrLocalKey
	}
	var k crypto.SymKey
	copy(k[:], r.LocalKey)
	return &k, nil
}

// newLocalKey returns 32 bytes from the OS CSPRNG.
func newLocalKey() ([]byte, error) {
	k := make([]byte, localKeySize)
	if _, err := rand.Read(k); err != nil {
		return nil, err
	}
	return k, nil
}

// device returns the in-memory DeviceKey for the record.
func (r *deviceRecord) device() (*vaultlog.LocalDevice, error) {
	kem, err := crypto.ParseKEMPrivateKey(r.KEMSK)
	if err != nil {
		return nil, fmt.Errorf("%w: bad device KEM key: %v", ErrDeviceKey, err)
	}
	if len(r.SigSeed) != ed25519.SeedSize {
		return nil, fmt.Errorf("%w: bad device signing key", ErrDeviceKey)
	}
	return &vaultlog.LocalDevice{ID: r.DeviceID, KEM: kem, Sig: ed25519.NewKeyFromSeed(r.SigSeed)}, nil
}

func (r *deviceRecord) secretKey() (*crypto.SecretKey, error) {
	sk, err := crypto.ParseSecretKey(r.SecretKey)
	if err != nil {
		return nil, fmt.Errorf("%w: the stored Secret Key does not parse", ErrDeviceKey)
	}
	return &sk, nil
}

// newDeviceRecord generates a device: an X-Wing key and an Ed25519 key
// under a new device ID, and a new local_key.
func newDeviceRecord(accountID model.ID, sk string) (*deviceRecord, vaultlog.DeviceInfo, error) {
	id, err := vaultlog.NewID()
	if err != nil {
		return nil, vaultlog.DeviceInfo{}, err
	}
	kem, err := crypto.GenerateKEMKey()
	if err != nil {
		return nil, vaultlog.DeviceInfo{}, err
	}
	kemSK, err := kem.Bytes()
	if err != nil {
		return nil, vaultlog.DeviceInfo{}, err
	}
	seed := make([]byte, ed25519.SeedSize)
	if _, err := rand.Read(seed); err != nil {
		return nil, vaultlog.DeviceInfo{}, err
	}
	sig := ed25519.NewKeyFromSeed(seed)
	local, err := newLocalKey()
	if err != nil {
		return nil, vaultlog.DeviceInfo{}, err
	}
	rec := &deviceRecord{
		V: 2, AccountID: accountID, DeviceID: id,
		KEMSK: append([]byte(nil), kemSK...), SigSeed: seed, SecretKey: sk, LocalKey: local,
	}
	info := vaultlog.DeviceInfo{
		ID: id, KEMPK: kem.PublicKey().Bytes(), SigPK: append([]byte(nil), sig.Public().(ed25519.PublicKey)...),
	}
	return rec, info, nil
}

// deviceStore reads and writes the device record in the configured store.
// It never falls back from one store to the other (§11).
type deviceStore struct {
	cfg    deviceConfig
	l      layout
	ring   Keyring
	getenv func(string) string
}

func (s *Store) deviceStore(cfg deviceConfig) *deviceStore {
	return &deviceStore{cfg: cfg, l: s.l, ring: s.ring(), getenv: s.getenv()}
}

func (s *Store) readDeviceConfig() (deviceConfig, error) {
	var c deviceConfig
	b, err := os.ReadFile(s.l.deviceConfig())
	if err != nil {
		return c, fmt.Errorf("%w: %v", ErrDeviceKey, err)
	}
	if err := json.Unmarshal(b, &c); err != nil || c.V != 1 || (c.Store != DeviceStoreKeychain && c.Store != DeviceStoreFile) ||
		(c.Pending != nil && c.Pending.DeviceID.IsZero()) || (c.Next != nil && (c.Next.AccountID.IsZero() || c.Next.DeviceID.IsZero())) {
		return c, fmt.Errorf("%w: %s is not a device key configuration", ErrDeviceKey, s.l.deviceConfig())
	}
	return c, nil
}

func (s *Store) writeDeviceConfig(c deviceConfig) error {
	b, err := json.Marshal(c)
	if err != nil {
		return err
	}
	return writeFileAtomic(s.l.deviceConfig(), b)
}

// Describe says which store is in use, for hop status (§11).
func (d *deviceStore) Describe() string {
	switch {
	case d.cfg.Store == DeviceStoreKeychain:
		return "keychain"
	case d.cfg.Sealed:
		return "file (sealed)"
	default:
		return "file (unsealed: private keys on disk)"
	}
}

// Unsealed reports whether the device key file holds the device private
// keys and the Secret Key in plain form, protected only by its 0600 mode.
func (d *deviceStore) Unsealed() bool { return d.cfg.Store == DeviceStoreFile && !d.cfg.Sealed }

// slot is the keychain entry of one device: per account and per device, so
// two vaults of the same account on one machine (two data directories)
// never share an entry, and deleting or tombstoning one device's record
// leaves the others alone.
func (d *deviceStore) slot(id model.ID) string {
	return "device:" + d.cfg.AccountID.String() + ":" + id.String()
}

// probe checks that the store can hold a record before init commits to it.
func (d *deviceStore) probe() error {
	switch d.cfg.Store {
	case DeviceStoreKeychain:
		const probeUser = "probe"
		if err := d.ring.Set(keychainService, probeUser, "hopkey keychain probe"); err != nil {
			return err
		}
		got, err := d.ring.Get(keychainService, probeUser)
		d.ring.Delete(keychainService, probeUser)
		if err != nil {
			return err
		}
		if got != "hopkey keychain probe" {
			return errors.New("the keychain returned a different value than was stored")
		}
		return nil
	case DeviceStoreFile:
		if !d.cfg.Sealed {
			return nil
		}
		pw, err := crypto.NormalizePassword([]byte(d.getenv(PassphraseEnv)))
		if err != nil {
			return fmt.Errorf("%s: %w", PassphraseEnv, err)
		}
		clear(pw)
		return nil
	}
	return fmt.Errorf("unknown device key store %q", d.cfg.Store)
}

// deviceKeyFile is device.key (§11, rev 14):
//
//	{"v":1, "kdf_version":1, "device_id":id, "salt":b64(16),
//	 "key":AEAD(pk, device_private_keys, aad=lp("hopkey/v1/device-key-file") || lp(device_id_bytes))}
//
// with pk from crypto.DevicePassphraseKey. Unsealed, kdf_version is 0, the
// salt is empty and key is the device private keys' JCS itself. The device
// private keys are the record: this device's KEM and signing keys and the
// account Secret Key. The file is JCS and is read with the strict decoder.
type deviceKeyFile struct {
	V          int           `json:"v"`
	KDFVersion uint32        `json:"kdf_version"`
	DeviceID   model.ID      `json:"device_id"`
	Salt       []byte        `json:"salt"`
	Key        canonjson.Raw `json:"key"`
}

// load reads this data directory's device record: DeviceID's, or, if that
// cannot be read, Pending's (deviceConfig). No other record is ever a
// candidate: without either there is no device key, which a password
// unlock replaces. It fails with ErrDeviceRevoked instead, before it
// returns any record, when the store holds the tombstone of either device
// (revokedSelf); the caller checks vault/revoked.json (Store.checkRevoked).
func (d *deviceStore) load() (*deviceRecord, error) {
	if err := d.revokedSelf(); err != nil {
		return nil, err
	}
	ids := d.cfg.self()
	if len(ids) == 0 {
		return nil, fmt.Errorf("%w: %s names no device (hop unlock --password restores it)", ErrDeviceKey, d.l.deviceConfig())
	}
	switch d.cfg.Store {
	case DeviceStoreKeychain:
		var first error
		for _, id := range ids {
			rec, err := d.loadSlot(id)
			if err == nil {
				return rec, nil
			}
			if first == nil {
				first = err
			}
		}
		return nil, first
	case DeviceStoreFile:
		rec, err := d.loadFile()
		if err != nil {
			return nil, err
		}
		if !slices.Contains(ids, rec.DeviceID) {
			rec.zero()
			return nil, fmt.Errorf("%w: %s holds the key of device %v, which %s names neither as this device nor as its pending replacement (hop unlock --password restores it)",
				ErrDeviceKey, d.l.deviceKeyFile(), rec.DeviceID, d.l.deviceConfig())
		}
		return rec, nil
	}
	return nil, fmt.Errorf("%w: unknown store %q", ErrDeviceKey, d.cfg.Store)
}

// revokedSelf fails with ErrDeviceRevoked when the device key store holds
// the tombstone of a device this data directory is (DeviceID or Pending): a
// revocation whose revoked.json was lost (§5.5, Store.revoke). device.key
// is this directory's alone, so a tombstone of this account there counts
// whichever device it names. Only a confirmed absence (keyring.ErrNotFound,
// a missing device.key) or a record that is read and is no tombstone
// clears a self device. Any other read failure is inconclusive: it fails
// with ErrKeyStoreUnavailable, which leaves the vault locked and changes
// nothing, so a tombstone that cannot be read now is never deleted, nor
// passed over for the other device's key. A tombstone found in one slot
// wins over a failed read of the other.
func (d *deviceStore) revokedSelf() error {
	switch d.cfg.Store {
	case DeviceStoreKeychain:
		var unread error
		for _, id := range d.cfg.self() {
			raw, err := d.ring.Get(keychainService, d.slot(id))
			if errors.Is(err, keyring.ErrNotFound) {
				continue
			}
			if err != nil {
				if unread == nil {
					unread = fmt.Errorf("%w: the keychain entry of device %v could not be read: %v", ErrKeyStoreUnavailable, id, err)
				}
				continue
			}
			if t, ok := parseTombstone([]byte(raw)); ok && t.AccountID == d.cfg.AccountID && t.DeviceID == id {
				return t.err()
			}
		}
		return unread
	case DeviceStoreFile:
		b, err := readKeyFile(d.l.deviceKeyFile())
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		if err != nil {
			return fmt.Errorf("%w: %v", ErrKeyStoreUnavailable, err)
		}
		if t, ok := parseTombstone(b); ok && t.AccountID == d.cfg.AccountID {
			return t.err()
		}
	}
	return nil
}

// slotState is what the device key store holds for one device.
type slotState int

const (
	slotAbsent    slotState = iota // confirmed: keyring.ErrNotFound, or no file
	slotRecord                     // the device's record
	slotTombstone                  // its tombstone (§5.5): terminal
)

// probeSlot reads what the store holds for device id, a device that a
// sign-in named before creating its record (the intent): its record (which
// the caller then owns), its tombstone, or a confirmed absence. Nothing
// else is concluded: a read that fails for any other reason is
// ErrKeyStoreUnavailable, and content that is neither id's record nor a
// tombstone of this account is ErrDeviceKey. Neither changes anything.
// device.key or device.next.key holds one device's record, so for the file
// store a tombstone of this account there counts whichever device it names.
func (d *deviceStore) probeSlot(id model.ID) (slotState, *deviceRecord, error) {
	var raw []byte
	switch d.cfg.Store {
	case DeviceStoreKeychain:
		s, err := d.ring.Get(keychainService, d.slot(id))
		if errors.Is(err, keyring.ErrNotFound) {
			return slotAbsent, nil, nil
		}
		if err != nil {
			return 0, nil, fmt.Errorf("%w: the keychain entry of device %v could not be read: %v", ErrKeyStoreUnavailable, id, err)
		}
		raw = []byte(s)
		if t, ok := parseTombstone(raw); ok {
			if t.AccountID != d.cfg.AccountID || t.DeviceID != id {
				return 0, nil, fmt.Errorf("%w: the keychain entry of device %v holds another device's tombstone", ErrDeviceKey, id)
			}
			return slotTombstone, nil, nil
		}
	case DeviceStoreFile:
		b, err := readKeyFile(d.l.deviceKeyFile())
		if errors.Is(err, os.ErrNotExist) {
			return slotAbsent, nil, nil
		}
		if err != nil {
			return 0, nil, fmt.Errorf("%w: %v", ErrKeyStoreUnavailable, err)
		}
		if t, ok := parseTombstone(b); ok {
			if t.AccountID != d.cfg.AccountID {
				return 0, nil, fmt.Errorf("%w: %s holds another account's tombstone", ErrDeviceKey, d.l.deviceKeyFile())
			}
			return slotTombstone, nil, nil
		}
	default:
		return 0, nil, fmt.Errorf("%w: unknown store %q", ErrDeviceKey, d.cfg.Store)
	}
	rec, err := d.loadID(id)
	if err != nil {
		return 0, nil, err
	}
	return slotRecord, rec, nil
}

// loadID reads the record of device id, and fails unless that is what the
// store holds.
func (d *deviceStore) loadID(id model.ID) (*deviceRecord, error) {
	switch d.cfg.Store {
	case DeviceStoreKeychain:
		return d.loadSlot(id)
	case DeviceStoreFile:
		rec, err := d.loadFile()
		if err != nil {
			return nil, err
		}
		if rec.DeviceID != id {
			rec.zero()
			return nil, fmt.Errorf("%w: %s holds the key of device %v, not %v", ErrDeviceKey, d.l.deviceKeyFile(), rec.DeviceID, id)
		}
		return rec, nil
	}
	return nil, fmt.Errorf("%w: unknown store %q", ErrDeviceKey, d.cfg.Store)
}

// loadSlot reads the keychain entry of device id.
func (d *deviceStore) loadSlot(id model.ID) (*deviceRecord, error) {
	raw, err := d.ring.Get(keychainService, d.slot(id))
	if err != nil {
		return nil, fmt.Errorf("%w: keychain: %v (hop unlock --password restores it)", ErrDeviceKey, err)
	}
	if t, ok := parseTombstone([]byte(raw)); ok {
		if t.AccountID != d.cfg.AccountID || t.DeviceID != id {
			return nil, fmt.Errorf("%w: the keychain entry of device %v holds another device's tombstone", ErrDeviceKey, id)
		}
		return nil, t.err()
	}
	// The decoder's error is not quoted: it can carry a character of the
	// keys.
	rec, err := parseDeviceRecord([]byte(raw))
	if err != nil {
		return nil, fmt.Errorf("%w: the keychain entry is not a valid device record", ErrDeviceKey)
	}
	if rec.AccountID != d.cfg.AccountID {
		rec.zero()
		return nil, fmt.Errorf("%w: the stored device key does not belong to this vault", ErrDeviceKey)
	}
	if rec.DeviceID != id {
		rec.zero()
		return nil, fmt.Errorf("%w: the keychain entry of device %v holds the key of %v", ErrDeviceKey, id, rec.DeviceID)
	}
	return rec, nil
}

func (d *deviceStore) loadFile() (*deviceRecord, error) {
	path := d.l.deviceKeyFile()
	b, err := readKeyFile(path)
	if err != nil {
		return nil, fmt.Errorf("%w: %v (hop unlock --password restores it)", ErrDeviceKey, err)
	}
	if t, ok := parseTombstone(b); ok {
		if t.AccountID != d.cfg.AccountID {
			return nil, fmt.Errorf("%w: %s holds another account's tombstone", ErrDeviceKey, path)
		}
		return nil, t.err()
	}
	var f deviceKeyFile
	if err := canonjson.Unmarshal(b, &f); err != nil || f.V != 1 {
		return nil, fmt.Errorf("%w: %s does not parse", ErrDeviceKey, path)
	}
	pt := []byte(f.Key)
	switch {
	case d.cfg.Sealed && f.KDFVersion == crypto.KDFv1.Version && len(f.Salt) == crypto.SaltSize:
		pass := d.getenv(PassphraseEnv)
		if pass == "" {
			return nil, fmt.Errorf("%w: %s is sealed; set %s", ErrDeviceKey, path, PassphraseEnv)
		}
		env, err := crypto.ParseAEADEnvelope(f.Key)
		if err != nil {
			return nil, fmt.Errorf("%w: %s: %v", ErrDeviceKey, path, err)
		}
		key, err := crypto.DevicePassphraseKey([]byte(pass), f.Salt, f.DeviceID)
		if err != nil {
			return nil, fmt.Errorf("%w: %s: %v", ErrDeviceKey, PassphraseEnv, err)
		}
		pt, err = crypto.OpenAEAD(key, env, crypto.DeviceKeyFileAAD(f.DeviceID))
		key.Zero()
		if err != nil {
			return nil, fmt.Errorf("%w: %s does not open with %s (wrong passphrase, or the file was changed)", ErrDeviceKey, path, PassphraseEnv)
		}
		defer clear(pt)
	case !d.cfg.Sealed && f.KDFVersion == 0 && len(f.Salt) == 0:
	case d.cfg.Sealed:
		return nil, fmt.Errorf("%w: %s should be sealed but is not", ErrDeviceKey, path)
	default:
		return nil, fmt.Errorf("%w: %s is sealed, but this device is set up for an unsealed file", ErrDeviceKey, path)
	}
	rec, err := parseDeviceRecord(pt)
	if err != nil {
		return nil, fmt.Errorf("%w: %s does not hold a valid device record", ErrDeviceKey, path)
	}
	if rec.DeviceID != f.DeviceID {
		rec.zero()
		return nil, fmt.Errorf("%w: %s names device %v but holds the key of %v", ErrDeviceKey, path, f.DeviceID, rec.DeviceID)
	}
	if rec.AccountID != d.cfg.AccountID {
		rec.zero()
		return nil, fmt.Errorf("%w: the stored device key does not belong to this vault", ErrDeviceKey)
	}
	return rec, nil
}

func (d *deviceStore) save(rec *deviceRecord) error {
	switch d.cfg.Store {
	case DeviceStoreKeychain:
		b, err := rec.jcs()
		if err != nil {
			return err
		}
		defer clear(b)
		if err := d.ring.Set(keychainService, d.slot(rec.DeviceID), string(b)); err != nil {
			return fmt.Errorf("saving the device key in the keychain: %w", err)
		}
		return nil
	case DeviceStoreFile:
		pt, err := rec.jcs()
		if err != nil {
			return err
		}
		defer clear(pt)
		f := deviceKeyFile{V: 1, DeviceID: rec.DeviceID, Salt: []byte{}, Key: pt}
		if d.cfg.Sealed {
			pass := d.getenv(PassphraseEnv)
			if pass == "" {
				return fmt.Errorf("the device key file is sealed; set %s", PassphraseEnv)
			}
			f.KDFVersion = crypto.KDFv1.Version
			f.Salt = make([]byte, crypto.SaltSize)
			if _, err := rand.Read(f.Salt); err != nil {
				return err
			}
			key, err := crypto.DevicePassphraseKey([]byte(pass), f.Salt, rec.DeviceID)
			if err != nil {
				return fmt.Errorf("%s: %w", PassphraseEnv, err)
			}
			env, err := crypto.SealAEAD(key, pt, crypto.DeviceKeyFileAAD(rec.DeviceID))
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
		return writeFileAtomic(d.l.deviceKeyFile(), out)
	}
	return fmt.Errorf("unknown device key store %q", d.cfg.Store)
}

// sync makes a saved record durable. A file save can rename device.key
// into place and then fail to fsync the directory: the record then reads
// back but may not survive a crash. sync fsyncs the file and its directory
// again; the keychain has nothing to do.
func (d *deviceStore) sync() error {
	if d.cfg.Store != DeviceStoreFile {
		return nil
	}
	path := d.l.deviceKeyFile()
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	err = f.Sync()
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return err
	}
	return syncDir(filepath.Dir(path))
}

// storeDurably saves rec, makes it durable, rereads it and checks it byte
// for byte (§11, rev 16): the file store's save fsyncs device.key and its
// directory, and sync does both again; a keychain entry is read back. Any
// failed step is an error even if the reread succeeds, and the caller must
// then not use the record. The caller holds the file lock.
func (d *deviceStore) storeDurably(rec *deviceRecord) error {
	want, err := rec.jcs()
	if err != nil {
		return err
	}
	defer clear(want)
	if err := d.save(rec); err != nil {
		return err
	}
	if err := d.sync(); err != nil {
		return err
	}
	got, err := d.loadID(rec.DeviceID)
	if err != nil {
		return err
	}
	b, err := got.jcs()
	got.zero()
	if err != nil {
		return err
	}
	same := bytes.Equal(b, want)
	clear(b)
	if !same {
		return errors.New("the device key store gave back a different device key than was saved")
	}
	return nil
}

// deviceTombstone is what a revoked device's record is overwritten with
// (§5.5, Store.revoke), in its keychain entry or as device.key itself:
//
//	JCS({"v":2, "revoked":true, "account_id":id, "device_id":id})
//
// It holds no key material. Every unlock that meets one for this data
// directory's device fails with ErrDeviceRevoked, even when
// vault/revoked.json is missing.
type deviceTombstone struct {
	V         int      `json:"v"`
	Revoked   bool     `json:"revoked"`
	AccountID model.ID `json:"account_id"`
	DeviceID  model.ID `json:"device_id"`
}

// parseTombstone strictly decodes a tombstone; ok is false for anything
// else, a device record included.
func parseTombstone(b []byte) (deviceTombstone, bool) {
	var t deviceTombstone
	if canonjson.Unmarshal(b, &t) != nil || t.V != 2 || !t.Revoked || t.AccountID.IsZero() || t.DeviceID.IsZero() {
		return deviceTombstone{}, false
	}
	return t, true
}

func (t deviceTombstone) err() error {
	return fmt.Errorf("%w (device %v; the device key store holds its tombstone)", ErrDeviceRevoked, t.DeviceID)
}

// fileDevice is the device device.key belongs to, a record or a tombstone,
// from its public members. ok is false when there is no file.
func (d *deviceStore) fileDevice() (id model.ID, ok bool, err error) {
	b, err := readKeyFile(d.l.deviceKeyFile())
	if errors.Is(err, os.ErrNotExist) {
		return model.ID{}, false, nil
	}
	if err != nil {
		return model.ID{}, false, err
	}
	if t, isTomb := parseTombstone(b); isTomb {
		return t.DeviceID, true, nil
	}
	var f deviceKeyFile
	if err := canonjson.Unmarshal(b, &f); err != nil || f.V != 1 {
		return model.ID{}, false, fmt.Errorf("%s does not parse", d.l.deviceKeyFile())
	}
	return f.DeviceID, true, nil
}

// errOtherDevice means device.key belongs to a device that this data
// directory is not: it is left alone.
var errOtherDevice = errors.New("device.key holds another device's key, which is left alone")

// ownsFile reports whether device.key, holding device cur's record or
// tombstone, may be replaced on behalf of device id: it belongs to id, or
// to a device this data directory is (self). A revocation of either self
// device is terminal for the directory, whichever record device.key holds.
func (d *deviceStore) ownsFile(cur, id model.ID) bool {
	return cur == id || slices.Contains(d.cfg.self(), cur)
}

// tombstone overwrites device id's record with its tombstone, durably. The
// keychain entry is the device's own. device.key is shared by whatever
// device this data directory is, so it is overwritten only when it is
// missing or the directory owns it for id (ownsFile).
func (d *deviceStore) tombstone(id model.ID) error {
	b, err := canonjson.Marshal(deviceTombstone{V: 2, Revoked: true, AccountID: d.cfg.AccountID, DeviceID: id})
	if err != nil {
		return err
	}
	switch d.cfg.Store {
	case DeviceStoreKeychain:
		if got, err := d.ring.Get(keychainService, d.slot(id)); err == nil && got == string(b) {
			return nil
		}
		if err := d.ring.Set(keychainService, d.slot(id), string(b)); err != nil {
			return err
		}
		got, err := d.ring.Get(keychainService, d.slot(id))
		if err != nil {
			return err
		}
		if got != string(b) {
			return errors.New("the keychain gave back something other than the tombstone")
		}
		return nil
	case DeviceStoreFile:
		if cur, ok, err := d.fileDevice(); err != nil {
			return err
		} else if ok && !d.ownsFile(cur, id) {
			return errOtherDevice
		}
		if got, err := readKeyFile(d.l.deviceKeyFile()); err == nil && bytes.Equal(got, b) {
			return nil
		}
		return writeFileAtomic(d.l.deviceKeyFile(), b)
	}
	return fmt.Errorf("unknown device key store %q", d.cfg.Store)
}

// destroy deletes device id's record: its keychain entry, or device.key
// when the directory owns it for id (ownsFile), with its directory fsynced
// after. A record that is already gone is no error. A revocation does this
// only when neither revoked.json nor the tombstone could be written
// (Store.revoke).
func (d *deviceStore) destroy(id model.ID) error {
	switch d.cfg.Store {
	case DeviceStoreKeychain:
		return d.deleteSlot(id)
	case DeviceStoreFile:
		if cur, ok, err := d.fileDevice(); err != nil {
			return err
		} else if !ok {
			return nil
		} else if !d.ownsFile(cur, id) {
			return errOtherDevice
		}
		path := d.l.deviceKeyFile()
		if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
		return syncDir(filepath.Dir(path))
	}
	return fmt.Errorf("unknown device key store %q", d.cfg.Store)
}

// deleteSlot deletes device id's keychain entry. One that is already gone
// is no error. The file store has nothing to do: device.key is replaced in
// place.
func (d *deviceStore) deleteSlot(id model.ID) error {
	if d.cfg.Store != DeviceStoreKeychain {
		return nil
	}
	if err := d.ring.Delete(keychainService, d.slot(id)); err != nil && !errors.Is(err, keyring.ErrNotFound) {
		return err
	}
	return nil
}

// discard removes the record of id, an abandoned pending replacement, so
// that clearing it from device.json leaves no key of it behind: its
// keychain entry is deleted, and device.key, if it holds id, is replaced
// with keep (the record in use) or else deleted. A tombstone is never
// removed: if either self device has one, it fails with ErrDeviceRevoked
// (revokedSelf) and changes nothing. Nor is anything it could not read:
// an inconclusive read of a self device, or of id's own record, fails with
// ErrKeyStoreUnavailable and changes nothing.
func (d *deviceStore) discard(id model.ID, keep *deviceRecord) error {
	if err := d.revokedSelf(); err != nil {
		return err
	}
	if d.cfg.Store != DeviceStoreFile {
		raw, err := d.ring.Get(keychainService, d.slot(id))
		if errors.Is(err, keyring.ErrNotFound) {
			return nil
		}
		if err != nil {
			return fmt.Errorf("%w: the keychain entry of device %v could not be read: %v", ErrKeyStoreUnavailable, id, err)
		}
		if t, ok := parseTombstone([]byte(raw)); ok {
			return fmt.Errorf("%w: the keychain entry of device %v holds a tombstone (device %v), which is left alone", ErrDeviceKey, id, t.DeviceID)
		}
		return d.deleteSlot(id)
	}
	cur, ok, err := d.fileDevice()
	if err != nil {
		return fmt.Errorf("%w: %v", ErrKeyStoreUnavailable, err)
	}
	if !ok || cur != id {
		return nil
	}
	if keep != nil {
		return d.storeDurably(keep)
	}
	return d.destroy(id)
}

// equal reports whether r and o are the same record.
func (r *deviceRecord) equal(o *deviceRecord) bool {
	return r.V == o.V && r.AccountID == o.AccountID && r.DeviceID == o.DeviceID &&
		bytes.Equal(r.KEMSK, o.KEMSK) && bytes.Equal(r.SigSeed, o.SigSeed) && r.SecretKey == o.SecretKey &&
		bytes.Equal(r.LocalKey, o.LocalKey)
}

// clone returns a copy of the record that shares no memory with it.
func (r *deviceRecord) clone() *deviceRecord {
	c := *r
	c.KEMSK = append([]byte(nil), r.KEMSK...)
	c.SigSeed = append([]byte(nil), r.SigSeed...)
	c.LocalKey = append([]byte(nil), r.LocalKey...)
	return &c
}

// upgradeRecord turns a phase 1 (v 1) record into v 2 with a new local_key
// and stores it durably (§11, rev 16). Unlock runs it before anything uses
// the record; if any durability step fails, the record is not used and the
// vault stays locked. A v 2 record from the file store is made durable
// again instead: an earlier save may have renamed it into place and then
// failed to fsync, and its local_key is trusted only once it is durable.
// The caller holds the file lock.
func (d *deviceStore) upgradeRecord(rec *deviceRecord) error {
	if rec.V == 2 {
		if err := d.sync(); err != nil {
			return fmt.Errorf("%w: the device key is not durable: %v", ErrDeviceKey, err)
		}
		return nil
	}
	next := rec.clone()
	next.V = 2
	local, err := newLocalKey()
	if err != nil {
		next.zero()
		return err
	}
	next.LocalKey = local
	if err := d.storeDurably(next); err != nil {
		next.zero()
		return fmt.Errorf("%w: the device record could not be upgraded durably: %v", ErrDeviceKey, err)
	}
	rec.zero()
	*rec = *next
	return nil
}

// reconcileDevice brings device.json up to date with the device key in use
// and the verified state. The device in use is always one device.json
// names (load): DeviceID, or the pending replacement. If it is the pending
// one, this installs it: in one atomic write of device.json it becomes
// DeviceID, the device it replaces becomes stale, and Pending is cleared.
// If it is DeviceID, a pending replacement is an abandoned attempt: its
// record is discarded first, then it becomes stale and Pending is cleared.
// Stale devices that are no longer active in the log are dropped, and this
// device is never stale. The caller holds the file lock and the store is
// unlocked.
func (s *Store) reconcileDevice() error {
	cfg := s.devCfg.withPending(model.ID{})
	id, pending := s.rec.DeviceID, s.devCfg.pendingID()
	switch {
	case !pending.IsZero() && pending == id:
		if !cfg.DeviceID.IsZero() && cfg.DeviceID != id {
			cfg.StaleDevices = append(cfg.StaleDevices, cfg.DeviceID)
		}
		cfg.DeviceID = id
	case cfg.DeviceID != id:
		return fmt.Errorf("%w: %s names device %v, whose key is in use, neither as this device nor as its pending replacement", ErrDeviceKey, s.l.deviceConfig(), id)
	case !pending.IsZero():
		if err := s.deviceStore(s.devCfg).discard(pending, s.rec); err != nil {
			return fmt.Errorf("discarding the device key of an abandoned password unlock: %w", err)
		}
		cfg.StaleDevices = append(cfg.StaleDevices, pending)
	}
	cfg.StaleDevices = s.staleActive(cfg)
	if cfg.DeviceID == s.devCfg.DeviceID && pending.IsZero() && slices.Equal(cfg.StaleDevices, s.devCfg.StaleDevices) {
		return nil
	}
	if err := s.writeDeviceConfig(cfg); err != nil {
		return err
	}
	s.devCfg = cfg
	return nil
}

// reloadDeviceConfig reads device.json again and reconciles it with the
// device key in use and the verified state. The caller holds the file lock
// and the store is unlocked.
func (s *Store) reloadDeviceConfig() error {
	cfg, err := s.readDeviceConfig()
	if err != nil {
		return err
	}
	if cfg.AccountID != s.state.Account.AccountID {
		return fmt.Errorf("%w: %s belongs to another account", ErrDeviceKey, s.l.deviceConfig())
	}
	s.devCfg = cfg
	return s.reconcileDevice()
}

// staleActive returns cfg's stale devices that are active in the verified
// state, sorted, without duplicates and without this device.
func (s *Store) staleActive(cfg deviceConfig) []model.ID {
	var out []model.ID
	for _, id := range cfg.StaleDevices {
		if _, ok := s.state.Devices[id]; ok && id != s.dev.ID && !slices.Contains(out, id) {
			out = append(out, id)
		}
	}
	slices.SortFunc(out, func(a, b model.ID) int { return bytes.Compare(a[:], b[:]) })
	return out
}
