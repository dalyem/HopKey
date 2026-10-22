package store

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"os"

	"github.com/zalando/go-keyring"

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

// deviceConfig is device.json: which store holds the device key. It holds
// no secrets.
type deviceConfig struct {
	V         int      `json:"v"`
	Store     string   `json:"store"`
	Sealed    bool     `json:"sealed,omitempty"` // file store only
	AccountID model.ID `json:"account_id"`
}

// deviceRecord is what the device key store keeps: this device's private
// keys and the account Secret Key, so the SK never has to be typed again on
// this device (§11).
type deviceRecord struct {
	V         int      `json:"v"`
	AccountID model.ID `json:"account_id"`
	DeviceID  model.ID `json:"device_id"`
	KEMSK     []byte   `json:"kem_sk"`
	SigSeed   []byte   `json:"sig_seed"`
	SecretKey string   `json:"secret_key"`
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

// Describe says which store is in use, for hop status.
func (d *deviceStore) Describe() string {
	switch {
	case d.cfg.Store == DeviceStoreKeychain:
		return "keychain"
	case d.cfg.Sealed:
		return "file " + d.l.deviceKeyFile() + " (sealed with " + PassphraseEnv + ")"
	default:
		return "file " + d.l.deviceKeyFile()
	}
}

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
		if d.cfg.Sealed && d.getenv(PassphraseEnv) == "" {
			return fmt.Errorf("%s is empty", PassphraseEnv)
		}
		return nil
	}
	return fmt.Errorf("unknown device key store %q", d.cfg.Store)
}

// fileForm is device.key: the record in the clear (0600) or sealed with a
// key derived from HOP_DEVICE_PASSPHRASE.
type fileForm struct {
	V        int                  `json:"v"`
	Record   *deviceRecord        `json:"record,omitempty"`
	Salt     []byte               `json:"salt,omitempty"`
	Envelope *crypto.AEADEnvelope `json:"envelope,omitempty"`
}

// passphraseKey derives the file key from the passphrase with the §4.1
// Argon2id derivation (crypto.DeriveLoginKeys). internal/crypto has no
// stand-alone passphrase KDF, so this reuses that one, with an all-zero
// Secret Key and the account ID as its context, rather than invent another.
func passphraseKey(pass string, salt []byte, accountID model.ID) (*crypto.SymKey, error) {
	var zeroSK crypto.SecretKey
	lk, err := crypto.DeriveLoginKeys([]byte(pass), salt, &zeroSK, accountID, crypto.KDFv1)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", PassphraseEnv, err)
	}
	k := lk.EncKey
	lk.Zero()
	return &k, nil
}

const labelDeviceKeyFile = "hopkey/v1/local-device-key"

func fileAAD(accountID model.ID) []byte {
	return append(crypto.LP([]byte(labelDeviceKeyFile)), crypto.LP(accountID[:])...)
}

func (d *deviceStore) load() (*deviceRecord, error) {
	var raw string
	switch d.cfg.Store {
	case DeviceStoreKeychain:
		s, err := d.ring.Get(keychainService, d.user())
		if err != nil {
			return nil, fmt.Errorf("%w: keychain: %v (hop unlock --password restores it)", ErrDeviceKey, err)
		}
		raw = s
	case DeviceStoreFile:
		b, err := os.ReadFile(d.l.deviceKeyFile())
		if err != nil {
			return nil, fmt.Errorf("%w: %v (hop unlock --password restores it)", ErrDeviceKey, err)
		}
		var f fileForm
		if err := json.Unmarshal(b, &f); err != nil || f.V != 1 {
			return nil, fmt.Errorf("%w: %s does not parse", ErrDeviceKey, d.l.deviceKeyFile())
		}
		switch {
		case f.Envelope != nil:
			pass := d.getenv(PassphraseEnv)
			if pass == "" {
				return nil, fmt.Errorf("%w: %s is sealed; set %s", ErrDeviceKey, d.l.deviceKeyFile(), PassphraseEnv)
			}
			key, err := passphraseKey(pass, f.Salt, d.cfg.AccountID)
			if err != nil {
				return nil, fmt.Errorf("%w: %v", ErrDeviceKey, err)
			}
			pt, err := crypto.OpenAEAD(key, *f.Envelope, fileAAD(d.cfg.AccountID))
			key.Zero()
			if err != nil {
				return nil, fmt.Errorf("%w: %s does not open with %s", ErrDeviceKey, d.l.deviceKeyFile(), PassphraseEnv)
			}
			raw = string(pt)
			clear(pt)
		case f.Record != nil:
			if d.cfg.Sealed {
				return nil, fmt.Errorf("%w: %s should be sealed but is not", ErrDeviceKey, d.l.deviceKeyFile())
			}
			b, _ := json.Marshal(f.Record)
			raw = string(b)
		default:
			return nil, fmt.Errorf("%w: %s is empty", ErrDeviceKey, d.l.deviceKeyFile())
		}
	default:
		return nil, fmt.Errorf("%w: unknown store %q", ErrDeviceKey, d.cfg.Store)
	}
	var rec deviceRecord
	if err := json.Unmarshal([]byte(raw), &rec); err != nil || rec.V != 1 || rec.AccountID != d.cfg.AccountID {
		return nil, fmt.Errorf("%w: the stored device key does not belong to this vault", ErrDeviceKey)
	}
	return &rec, nil
}

func (d *deviceStore) save(rec *deviceRecord) error {
	b, err := json.Marshal(rec)
	if err != nil {
		return err
	}
	defer clear(b)
	switch d.cfg.Store {
	case DeviceStoreKeychain:
		if err := d.ring.Set(keychainService, d.user(), string(b)); err != nil {
			return fmt.Errorf("saving the device key in the keychain: %w", err)
		}
		return nil
	case DeviceStoreFile:
		f := fileForm{V: 1}
		if d.cfg.Sealed {
			pass := d.getenv(PassphraseEnv)
			if pass == "" {
				return fmt.Errorf("the device key file is sealed; set %s", PassphraseEnv)
			}
			f.Salt = make([]byte, crypto.SaltSize)
			if _, err := rand.Read(f.Salt); err != nil {
				return err
			}
			key, err := passphraseKey(pass, f.Salt, d.cfg.AccountID)
			if err != nil {
				return err
			}
			env, err := crypto.SealAEAD(key, b, fileAAD(d.cfg.AccountID))
			key.Zero()
			if err != nil {
				return err
			}
			f.Envelope = &env
		} else {
			f.Record = rec
		}
		out, err := json.Marshal(f)
		if err != nil {
			return err
		}
		return writeFileAtomic(d.l.deviceKeyFile(), out)
	}
	return fmt.Errorf("unknown device key store %q", d.cfg.Store)
}
