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

// keychainService is the keychain service name. The account is the user.
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
// DeviceID is the device whose key the store holds. StaleDevices are
// devices this machine enrolled and then lost the key of (a password unlock
// replaces the device key): they are still active in the log, and the next
// hop passwd revokes them (§10.1).
type deviceConfig struct {
	V            int        `json:"v"`
	Store        string     `json:"store"`
	Sealed       bool       `json:"sealed,omitempty"` // file store only
	AccountID    model.ID   `json:"account_id"`
	DeviceID     model.ID   `json:"device_id,omitzero"`
	StaleDevices []model.ID `json:"stale_devices,omitempty"`
}

// deviceRecord is what the device key store keeps: this device's private
// keys and the account Secret Key, so the SK never has to be typed again on
// this device (§11, rev 15). It is the keychain entry and the device key
// file's key (sealed, or raw when unsealed):
//
//	JCS({"v":1, "account_id":id, "device_id":id, "kem_sk":b64, "sig_seed":b64(32), "secret_key":str≤64})
//
// and is read with parseDeviceRecord, which refuses anything else.
type deviceRecord struct {
	V         int      `json:"v"`
	AccountID model.ID `json:"account_id"`
	DeviceID  model.ID `json:"device_id"`
	KEMSK     []byte   `json:"kem_sk"`
	SigSeed   []byte   `json:"sig_seed"`
	SecretKey string   `json:"secret_key"`
}

// parseDeviceRecord strictly decodes a device record: unknown, missing,
// duplicate and wrongly typed members are refused, and so is a record with
// another version, an empty ID or kem_sk, a signing seed that is not 32
// bytes, or a secret_key that is not a str≤64 holding a valid Secret Key
// (§12). Its errors never quote the record: they could carry a character of
// the keys.
func parseDeviceRecord(b []byte) (*deviceRecord, error) {
	var rec deviceRecord
	if err := canonjson.Unmarshal(b, &rec); err != nil {
		rec.zero()
		return nil, err
	}
	var err error
	switch {
	case rec.V != 1:
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
	r.SecretKey = ""
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
// under a new device ID.
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
	rec := &deviceRecord{
		V: 1, AccountID: accountID, DeviceID: id,
		KEMSK: append([]byte(nil), kemSK...), SigSeed: seed, SecretKey: sk,
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
	if err := json.Unmarshal(b, &c); err != nil || c.V != 1 || (c.Store != DeviceStoreKeychain && c.Store != DeviceStoreFile) {
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

func (d *deviceStore) user() string { return "device:" + d.cfg.AccountID.String() }

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

func (d *deviceStore) load() (*deviceRecord, error) {
	switch d.cfg.Store {
	case DeviceStoreKeychain:
		raw, err := d.ring.Get(keychainService, d.user())
		if err != nil {
			return nil, fmt.Errorf("%w: keychain: %v (hop unlock --password restores it)", ErrDeviceKey, err)
		}
		// The decoder's error is not quoted: it can carry a character of
		// the keys.
		rec, err := parseDeviceRecord([]byte(raw))
		if err != nil {
			return nil, fmt.Errorf("%w: the keychain entry is not a valid device record", ErrDeviceKey)
		}
		if rec.AccountID != d.cfg.AccountID {
			rec.zero()
			return nil, fmt.Errorf("%w: the stored device key does not belong to this vault", ErrDeviceKey)
		}
		return rec, nil
	case DeviceStoreFile:
		return d.loadFile()
	}
	return nil, fmt.Errorf("%w: unknown store %q", ErrDeviceKey, d.cfg.Store)
}

func (d *deviceStore) loadFile() (*deviceRecord, error) {
	path := d.l.deviceKeyFile()
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("%w: %v (hop unlock --password restores it)", ErrDeviceKey, err)
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
		b, err := canonjson.Marshal(rec)
		if err != nil {
			return err
		}
		defer clear(b)
		if err := d.ring.Set(keychainService, d.user(), string(b)); err != nil {
			return fmt.Errorf("saving the device key in the keychain: %w", err)
		}
		return nil
	case DeviceStoreFile:
		pt, err := canonjson.Marshal(rec)
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

// storeDurably saves rec and checks that the store gives it back: the
// file store has fsynced device.key and its directory once save returns,
// and a keychain entry is read back. The caller holds the file lock.
func (d *deviceStore) storeDurably(rec *deviceRecord) error {
	if err := d.save(rec); err != nil {
		return err
	}
	got, err := d.load()
	if err != nil {
		return err
	}
	same := got.equal(rec)
	got.zero()
	if !same {
		return errors.New("the device key store gave back a different device key than was saved")
	}
	return nil
}

// equal reports whether r and o are the same record.
func (r *deviceRecord) equal(o *deviceRecord) bool {
	return r.V == o.V && r.AccountID == o.AccountID && r.DeviceID == o.DeviceID &&
		bytes.Equal(r.KEMSK, o.KEMSK) && bytes.Equal(r.SigSeed, o.SigSeed) && r.SecretKey == o.SecretKey
}

// clone returns a copy of the record that shares no memory with it.
func (r *deviceRecord) clone() *deviceRecord {
	c := *r
	c.KEMSK = append([]byte(nil), r.KEMSK...)
	c.SigSeed = append([]byte(nil), r.SigSeed...)
	return &c
}

// reconcileDevice brings device.json up to date with the device key in use
// and the verified state. The record in the device key store decides which
// device this is: a device.json that names another one (a password unlock
// stopped between saving the new key and updating device.json, or an older
// device.json) has that device moved to the stale list. Stale devices that
// are no longer active in the log are dropped, and this device is never
// stale. The caller holds the file lock and the store is unlocked.
func (s *Store) reconcileDevice() error {
	cfg := s.devCfg
	if cfg.DeviceID != s.rec.DeviceID {
		if !cfg.DeviceID.IsZero() {
			cfg.StaleDevices = append(cfg.StaleDevices, cfg.DeviceID)
		}
		cfg.DeviceID = s.rec.DeviceID
	}
	cfg.StaleDevices = s.staleActive(cfg)
	if cfg.DeviceID == s.devCfg.DeviceID && slices.Equal(cfg.StaleDevices, s.devCfg.StaleDevices) {
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
