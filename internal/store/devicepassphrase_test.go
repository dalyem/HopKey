package store

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

const sealPass = "a device passphrase"

// sealedFixture is a vault whose device key is a file sealed with sealPass,
// opened by a process that has no HOP_DEVICE_PASSPHRASE: what the daemon is
// after a hand-off, which keeps no passphrase.
func sealedFixture(t *testing.T) (cfg Config, s *Store) {
	t.Helper()
	cfg = testConfig(t)
	withPass := cfg
	withPass.Getenv = func(k string) string {
		if k == PassphraseEnv {
			return sealPass
		}
		return ""
	}
	p, err := PrepareInit(withPass, InitOptions{Password: []byte(testPassword), DeviceStore: DeviceStoreFile})
	if err != nil {
		t.Fatal(err)
	}
	first, err := p.Commit()
	if err != nil {
		t.Fatal(err)
	}
	first.Close()
	s, err = Open(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	track(t, cfg, s)
	if err := s.UnlockWithPassphrase(context.Background(), []byte(sealPass)); err != nil {
		t.Fatalf("unlock with the passphrase: %v", err)
	}
	return cfg, s
}

// CheckDevicePassphrase tells a right passphrase from a wrong one without
// changing anything on disk.
func TestCheckDevicePassphraseOnlyReads(t *testing.T) {
	cfg, _ := sealedFixture(t)
	keyFile := DeviceKeyFile(cfg.DataDir)
	before, err := os.ReadFile(keyFile)
	if err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(keyFile)
	if err != nil {
		t.Fatal(err)
	}
	if err := CheckDevicePassphrase(cfg.DataDir, []byte(sealPass)); err != nil {
		t.Errorf("the right passphrase: %v", err)
	}
	for _, wrong := range []string{"not the passphrase", "short", ""} {
		if err := CheckDevicePassphrase(cfg.DataDir, []byte(wrong)); !errors.Is(err, ErrWrongDevicePassphrase) {
			t.Errorf("%q: %v, want ErrWrongDevicePassphrase", wrong, err)
		}
	}
	after, err := os.ReadFile(keyFile)
	if err != nil {
		t.Fatal(err)
	}
	after2, _ := os.Stat(keyFile)
	if !bytes.Equal(before, after) || !after2.ModTime().Equal(info.ModTime()) {
		t.Error("the check changed the key file")
	}
}

// A key file that is not sealed, or is not there, is another kind of
// failure than a wrong passphrase: asking again would not help.
func TestCheckDevicePassphraseOtherFailures(t *testing.T) {
	cfg := testConfig(t)
	p, err := PrepareInit(cfg, InitOptions{Password: []byte(testPassword), DeviceStore: DeviceStoreFile})
	if err != nil {
		t.Fatal(err)
	}
	s, err := p.Commit()
	if err != nil {
		t.Fatal(err)
	}
	s.Close()
	if err := CheckDevicePassphrase(cfg.DataDir, []byte(sealPass)); !errors.Is(err, ErrDeviceKey) || errors.Is(err, ErrWrongDevicePassphrase) {
		t.Errorf("an unsealed file: %v", err)
	}
	if err := os.Remove(filepath.Join(cfg.DataDir, "device.key")); err != nil {
		t.Fatal(err)
	}
	if err := CheckDevicePassphrase(cfg.DataDir, []byte(sealPass)); !errors.Is(err, ErrDeviceKey) || errors.Is(err, ErrWrongDevicePassphrase) {
		t.Errorf("no file: %v", err)
	}
}

// A revoked device's key file holds its tombstone, not a key a passphrase
// opens: the check says the device was revoked, as the store does, and not
// that the file is damaged.
func TestCheckDevicePassphraseOfARevokedDevicesFile(t *testing.T) {
	cfg, _ := sealedFixture(t)
	tomb := tombstoneOf(t, randomID(t), randomID(t))
	if err := os.WriteFile(filepath.Join(cfg.DataDir, "device.key"), []byte(tomb), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := CheckDevicePassphrase(cfg.DataDir, []byte(sealPass)); !errors.Is(err, ErrDeviceRevoked) || errors.Is(err, ErrDeviceKey) {
		t.Errorf("a tombstone: %v", err)
	}
}

// A process with no passphrase of its own changes the master password when
// it is given one for that call: the key file is saved again, sealed with
// the same passphrase, and the process keeps nothing.
func TestChangePasswordWithPassphraseSealsTheFileAgain(t *testing.T) {
	ctx := context.Background()
	cfg, s := sealedFixture(t)
	const next = "a much better password"
	keyFile := DeviceKeyFile(cfg.DataDir)
	before, err := os.ReadFile(keyFile)
	if err != nil {
		t.Fatal(err)
	}
	// Without it the save fails before anything is written to the log.
	if _, err := s.ChangePassword(ctx, []byte(testPassword), []byte(next)); err == nil {
		t.Fatal("ChangePassword without a passphrase saved a sealed file")
	}
	if s.PendingKit() != nil {
		t.Error("a failed change left a kit")
	}
	if after, _ := os.ReadFile(keyFile); !bytes.Equal(before, after) {
		t.Error("a failed change touched the key file")
	}

	// A passphrase that does not open the file is refused: sealing the file
	// with it would leave nobody the passphrase.
	if _, err := s.ChangePasswordWithPassphrase(ctx, []byte(testPassword), []byte(next), []byte("not the passphrase")); !errors.Is(err, ErrWrongDevicePassphrase) {
		t.Fatalf("a wrong passphrase: %v", err)
	}
	if after, _ := os.ReadFile(keyFile); !bytes.Equal(before, after) {
		t.Error("a refused passphrase touched the key file")
	}
	if _, err := s.ChangePasswordWithPassphrase(ctx, []byte(testPassword), []byte(next), []byte(sealPass)); err != nil {
		t.Fatalf("ChangePasswordWithPassphrase: %v", err)
	}
	if s.passphrase.Load() != nil {
		t.Error("the store kept the passphrase")
	}
	if err := s.AckKit(); err == nil {
		t.Error("AckKit without a passphrase saved the Secret Key into a sealed file")
	}
	if err := s.AckKitWithPassphrase([]byte(sealPass)); err != nil {
		t.Fatalf("AckKitWithPassphrase: %v", err)
	}
	if s.passphrase.Load() != nil {
		t.Error("the store kept the passphrase")
	}
	if s.PendingKit() != nil {
		t.Error("the kit is still pending")
	}
	// The file the daemon re-saved is sealed with the same passphrase, and
	// a fresh process opens the vault with it.
	if err := CheckDevicePassphrase(cfg.DataDir, []byte(sealPass)); err != nil {
		t.Fatalf("the passphrase no longer opens the key file: %v", err)
	}
	if after, _ := os.ReadFile(keyFile); bytes.Equal(before, after) {
		t.Error("the key file was not saved again")
	}
	release(cfg)
	s2, err := Open(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	track(t, cfg, s2)
	if err := s2.UnlockWithPassphrase(ctx, []byte(sealPass)); err != nil {
		t.Fatalf("a fresh process cannot unlock with the passphrase: %v", err)
	}
}
