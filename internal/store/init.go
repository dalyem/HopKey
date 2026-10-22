package store

import (
	"crypto/rand"
	"errors"
	"fmt"

	"github.com/dalyem/hopkey/internal/crypto"
	"github.com/dalyem/hopkey/internal/vaultlog"
)

var randRead = rand.Read

// InitOptions are the choices of hop init.
type InitOptions struct {
	// Password is the master password.
	Password []byte
	// DeviceStore is DeviceStoreKeychain or DeviceStoreFile. Empty means
	// the keychain, which must then be usable: there is no silent fallback
	// to the file (§11).
	DeviceStore string
}

// PendingInit is a vault generated in memory but not yet written. hop init
// shows its Emergency Kit and has the user type it back before Commit.
type PendingInit struct {
	s       *Store
	devCfg  deviceConfig
	rec     *deviceRecord
	dev     *vaultlog.LocalDevice
	wire    *vaultlog.Wire
	state   *vaultlog.State
	sec     *vaultlog.Secrets
	kit     Kit
	created bool
}

// Exists reports whether dataDir holds a vault, or the start of one.
func Exists(dataDir string) (bool, error) { return layout{data: dataDir}.exists() }

// ErrKeychainUnusable means hop init could not use the OS keychain.
var ErrKeychainUnusable = errors.New("store: the OS keychain is not usable")

// PrepareInit generates a new account and vault (§4.3): account keys, the
// Secret Key, the Recovery Key, VK[1], this device's keys, and the genesis
// entry, verified with the anchor algorithm. Nothing is written yet.
func PrepareInit(cfg Config, opts InitOptions) (*PendingInit, error) {
	s := &Store{cfg: cfg, l: layout{data: cfg.DataDir}}
	if ok, err := s.l.exists(); err != nil {
		return nil, err
	} else if ok {
		return nil, ErrVaultExists
	}
	store := opts.DeviceStore
	if store == "" {
		store = DeviceStoreKeychain
	}
	accountID, err := vaultlog.NewID()
	if err != nil {
		return nil, err
	}
	devCfg := deviceConfig{V: 1, Store: store, AccountID: accountID}
	switch store {
	case DeviceStoreKeychain:
	case DeviceStoreFile:
		devCfg.Sealed = s.getenv()(PassphraseEnv) != ""
	default:
		return nil, fmt.Errorf("store: unknown device key store %q (keychain or file)", store)
	}
	if err := s.deviceStore(devCfg).probe(); err != nil {
		if store == DeviceStoreKeychain {
			return nil, fmt.Errorf("%w (%v); pass --device-key-store=file to keep the device key in %s instead",
				ErrKeychainUnusable, err, s.l.deviceKeyFile())
		}
		return nil, err
	}

	vaultID, err := vaultlog.NewID()
	if err != nil {
		return nil, err
	}
	sk, err := crypto.NewSecretKey()
	if err != nil {
		return nil, err
	}
	rk, err := crypto.NewRecoveryKey()
	if err != nil {
		return nil, err
	}
	defer rk.Zero()
	acct, err := crypto.GenerateAccountKeys(accountID, 1)
	if err != nil {
		return nil, err
	}
	creds, err := newCreds(opts.Password, &sk, &rk, acct)
	if err != nil {
		return nil, err
	}
	vk, err := crypto.NewSymKey()
	if err != nil {
		return nil, err
	}
	defer vk.Zero()
	rec, info, err := newDeviceRecord(accountID, sk.String())
	if err != nil {
		return nil, err
	}
	info.Name = s.deviceName()
	devCfg.DeviceID = rec.DeviceID
	dev, err := rec.device()
	if err != nil {
		return nil, err
	}
	now := s.now()
	w, st, sec, err := vaultlog.BuildGenesis(vaultlog.GenesisParams{
		VaultID: vaultID, Account: acct, VK: vk, Creds: creds, Device: info, Time: now,
	})
	if err != nil {
		return nil, err
	}
	return &PendingInit{
		s: s, devCfg: devCfg, rec: rec, dev: dev, wire: w, state: st, sec: sec,
		kit: Kit{AccountID: accountID.String(), SecretKey: sk.String(), RecoveryKey: rk.String(), Created: now.Time()},
	}, nil
}

// Discard drops the generated secrets without writing anything.
func (p *PendingInit) Discard() {
	p.rec.zero()
	p.sec.Account.Zero()
	p.sec.VK.Zero()
}

// Kit is the new account's Emergency Kit.
func (p *PendingInit) Kit() Kit { return p.kit }

// DeviceStore says where Commit will keep the device key.
func (p *PendingInit) DeviceStore() string { return p.s.deviceStore(p.devCfg).Describe() }

// Commit writes the vault: the device key first (so a vault never exists
// that this device cannot open), then device.json, the genesis objects and
// entry, state.json and account.json. It returns the unlocked store, which
// owns the vault (see Open) until Close.
func (p *PendingInit) Commit() (st *Store, err error) {
	if p.created {
		return nil, errors.New("store: init already committed")
	}
	s := p.s
	if err := s.l.ensureDirs(); err != nil {
		return nil, err
	}
	if s.owner == nil {
		if err := s.own(); err != nil {
			return nil, err
		}
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
	if ok, err := s.l.exists(); err != nil {
		return nil, err
	} else if ok {
		return nil, ErrVaultExists
	}
	if err := s.deviceStore(p.devCfg).save(p.rec); err != nil {
		return nil, err
	}
	if err := s.writeDeviceConfig(p.devCfg); err != nil {
		return nil, err
	}
	if err := s.commit(p.wire, p.state); err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.state, s.sec, s.dev, s.rec, s.devCfg = p.state, p.sec, p.dev, p.rec, p.devCfg
	if err := s.writeAccountFile(); err != nil {
		return nil, err
	}
	p.created = true
	return s, nil
}
