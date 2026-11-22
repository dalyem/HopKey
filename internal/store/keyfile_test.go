package store

import (
	"bytes"
	"context"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"sync"
	"syscall"
	"testing"
)

// failKeyFile makes every read of device.key under dataDir fail with err
// while on is set, as a permission or I/O error would, and leaves the file
// as it is.
type failKeyFile struct {
	mu   sync.Mutex
	on   bool
	path string
	err  error
}

func (f *failKeyFile) set(on bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.on = on
}

func installFailKeyFile(t *testing.T, cfg Config, err error) *failKeyFile {
	t.Helper()
	f := &failKeyFile{path: filepath.Join(cfg.DataDir, "device.key"), err: err}
	orig := readKeyFile
	readKeyFile = func(name string) ([]byte, error) {
		f.mu.Lock()
		on := f.on
		f.mu.Unlock()
		if on && filepath.Clean(name) == filepath.Clean(f.path) {
			return nil, &fs.PathError{Op: "open", Path: name, Err: f.err}
		}
		return orig(name)
	}
	t.Cleanup(func() { readKeyFile = orig })
	return f
}

func fileVault(t *testing.T) *fixture {
	t.Helper()
	cfg := testConfig(t)
	p, err := PrepareInit(cfg, InitOptions{Password: []byte(testPassword), DeviceStore: DeviceStoreFile})
	if err != nil {
		t.Fatal(err)
	}
	s, err := p.Commit()
	if err != nil {
		t.Fatal(err)
	}
	track(t, cfg, s)
	return &fixture{cfg: cfg, kit: p.Kit(), s: s}
}

// Review r6 of D1 (minor): the file store's device.key holds this
// device's tombstone, revoked.json is missing, and reading device.key
// fails with a permission or an I/O error. That read is inconclusive: the
// store stays locked and is not terminally revoked, both unlock paths
// refuse with ErrKeyStoreUnavailable, and neither the evidence (the
// tombstone in device.key) nor device.json changes. Once device.key reads
// again, the revocation is terminal.
func TestAnUnreadableKeyFileTombstoneIsKept(t *testing.T) {
	for _, errno := range []error{syscall.EACCES, syscall.EIO} {
		t.Run(errno.Error(), func(t *testing.T) {
			ctx := context.Background()
			f := fileVault(t)
			addHost(t, f.s, "web")
			acct, dev := accountOfKit(t, f), deviceOf(f.s)
			release(f.cfg)
			keyPath := filepath.Join(f.cfg.DataDir, "device.key")
			tomb := []byte(tombstoneOf(t, acct, dev))
			if err := os.WriteFile(keyPath, tomb, 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := os.Stat(filepath.Join(f.cfg.DataDir, "vault", "revoked.json")); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("revoked.json: %v", err)
			}
			cfgBefore, err := os.ReadFile(filepath.Join(f.cfg.DataDir, "device.json"))
			if err != nil {
				t.Fatal(err)
			}
			kept := func(when string) {
				t.Helper()
				if b, err := os.ReadFile(keyPath); err != nil || !bytes.Equal(b, tomb) {
					t.Errorf("%s: device.key is %q, %v; want the tombstone", when, b, err)
				}
				if b, err := os.ReadFile(filepath.Join(f.cfg.DataDir, "device.json")); err != nil || !bytes.Equal(b, cfgBefore) {
					t.Errorf("%s: device.json changed: %s", when, b)
				}
				if _, err := os.Stat(filepath.Join(f.cfg.DataDir, "vault", "revoked.json")); !errors.Is(err, os.ErrNotExist) {
					t.Errorf("%s: revoked.json appeared: %v", when, err)
				}
			}
			fail := installFailKeyFile(t, f.cfg, errno)
			fail.set(true)

			s, err := tryOpen(t, f.cfg)
			if err != nil {
				t.Fatal(err)
			}
			if info := s.Info(); !info.Locked || info.Revoked {
				t.Errorf("open with device.key unreadable: %+v; want locked, not revoked", info)
			}
			if s.IsRevoked() {
				t.Error("an unreadable device.key was taken for a revocation")
			}
			if err := s.Unlock(ctx); !errors.Is(err, ErrKeyStoreUnavailable) {
				t.Errorf("unlock: %v; want ErrKeyStoreUnavailable", err)
			}
			if err := s.UnlockWithPassword(ctx, []byte(testPassword), f.kit.SecretKey); !errors.Is(err, ErrKeyStoreUnavailable) {
				t.Errorf("password unlock: %v; want ErrKeyStoreUnavailable", err)
			}
			if s.IsRevoked() || s.Info().Revoked {
				t.Error("revoked after the unlocks")
			}
			kept("after the unlocks")

			fail.set(false)
			if err := s.Unlock(ctx); !errors.Is(err, ErrDeviceRevoked) {
				t.Errorf("unlock once device.key reads: %v; want ErrDeviceRevoked", err)
			}
			if !s.IsRevoked() {
				t.Error("not revoked once the tombstone reads")
			}
			s, err = tryOpen(t, f.cfg)
			if err != nil {
				t.Fatal(err)
			}
			if info := s.Info(); !info.Locked || !info.Revoked {
				t.Errorf("open once device.key reads: %+v; want locked and revoked", info)
			}
			if err := s.UnlockWithPassword(ctx, []byte(testPassword), f.kit.SecretKey); !errors.Is(err, ErrDeviceRevoked) {
				t.Errorf("password unlock once device.key reads: %v; want ErrDeviceRevoked", err)
			}
		})
	}
}

// The same inconclusive read of a valid, non-revoked device.key: locked,
// nothing changed, and the vault unlocks with its key once it reads again.
func TestAnUnreadableKeyFileRecovers(t *testing.T) {
	ctx := context.Background()
	f := fileVault(t)
	addHost(t, f.s, "web")
	release(f.cfg)
	keyPath := filepath.Join(f.cfg.DataDir, "device.key")
	before, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	cfgBefore, err := os.ReadFile(filepath.Join(f.cfg.DataDir, "device.json"))
	if err != nil {
		t.Fatal(err)
	}
	fail := installFailKeyFile(t, f.cfg, syscall.EIO)
	fail.set(true)
	s, err := tryOpen(t, f.cfg)
	if err != nil {
		t.Fatal(err)
	}
	if info := s.Info(); !info.Locked || info.Revoked {
		t.Errorf("open: %+v", info)
	}
	if err := s.Unlock(ctx); !errors.Is(err, ErrKeyStoreUnavailable) {
		t.Errorf("unlock: %v", err)
	}
	if err := s.UnlockWithPassword(ctx, []byte(testPassword), f.kit.SecretKey); !errors.Is(err, ErrKeyStoreUnavailable) {
		t.Errorf("password unlock: %v", err)
	}
	fail.set(false)
	if b, _ := os.ReadFile(keyPath); !bytes.Equal(b, before) {
		t.Error("device.key changed")
	}
	if b, _ := os.ReadFile(filepath.Join(f.cfg.DataDir, "device.json")); !bytes.Equal(b, cfgBefore) {
		t.Error("device.json changed")
	}
	if err := s.Unlock(ctx); err != nil {
		t.Fatalf("unlock once device.key reads: %v", err)
	}
	if names(snapshot(t, s))[0] != "web" || s.IsRevoked() {
		t.Error("the vault did not come back")
	}
}
