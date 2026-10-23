package store

import (
	"context"
	"encoding/json"
	"errors"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/dalyem/hopkey/internal/canonjson"
	"github.com/dalyem/hopkey/internal/model"
)

const testDevicePassphrase = "device passphrase 1"

// sealedFileVault makes a vault whose device key is in a sealed device key
// file. Setting *pass to "" makes every read and write of that file fail,
// without touching it.
func sealedFileVault(t *testing.T) (Config, *Store, *string) {
	t.Helper()
	cfg := testConfig(t)
	pass := testDevicePassphrase
	cfg.Getenv = func(k string) string {
		if k == PassphraseEnv {
			return pass
		}
		return ""
	}
	p, err := PrepareInit(cfg, InitOptions{Password: []byte(testPassword), DeviceStore: DeviceStoreFile})
	if err != nil {
		t.Fatal(err)
	}
	s, err := p.Commit()
	if err != nil {
		t.Fatal(err)
	}
	track(t, cfg, s)
	addHost(t, s, "web-1")
	return cfg, s, &pass
}

// keyFileDevice is the device whose key device.key holds, from the file's
// outer device_id.
func keyFileDevice(t *testing.T, dataDir string) model.ID {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(dataDir, "device.key"))
	if err != nil {
		t.Fatal(err)
	}
	var f deviceKeyFile
	if err := canonjson.Unmarshal(b, &f); err != nil {
		t.Fatal(err)
	}
	return f.DeviceID
}

// failedFileUnlock runs a password unlock on the unlocked store s whose
// save of the new device key renames device.key into place and then fails
// to fsync the directory. It returns the device in memory (A) and the one
// whose key is now in device.key (B).
func failedFileUnlock(t *testing.T, s *Store) (a, b model.ID) {
	t.Helper()
	a = s.dev.ID
	dataDir := s.l.data
	errFsync := errors.New("injected directory fsync failure")
	syncDir = func(dir string) error {
		if dir == dataDir && keyFileDevice(t, dataDir) != a {
			return errFsync
		}
		return fsyncDir(dir)
	}
	defer func() { syncDir = fsyncDir }()
	if err := s.UnlockWithPassword(context.Background(), []byte(testPassword), ""); !errors.Is(err, errFsync) {
		t.Fatalf("setup: password unlock with the directory fsync failing: %v", err)
	}
	b = keyFileDevice(t, dataDir)
	if b == a || s.dev == nil || s.dev.ID != a {
		t.Fatalf("setup: device.key holds %v, memory %v; want B on disk and A in memory", b, a)
	}
	return a, b
}

// Round 3, finding 1: a password unlock left a stale device's key (B) in
// device.key while memory kept A. hop passwd revokes B and seals its
// journal to A alone; then the new Secret Key fails to save and the process
// stops before the kit is shown. After a restart the device key on disk
// still opens the vault, the kit is recoverable, and acking it finishes.
func TestPasswdKeepsTheSurvivingDeviceKeyOnDisk(t *testing.T) {
	cfg, s, pass := sealedFileVault(t)
	ctx := context.Background()
	a, b := failedFileUnlock(t, s)

	// The new Secret Key's save fails without writing anything: the
	// passphrase is gone from the moment the checkpoint entry is on disk.
	s.testHook = func(stage string) error {
		if stage == "entry" {
			*pass = ""
		}
		return nil
	}
	kit, err := s.ChangePassword(ctx, []byte(testPassword), []byte(newPassword))
	if err != nil {
		t.Fatalf("passwd: %v", err)
	}
	if s.skErr == nil {
		t.Fatal("setup: the new Secret Key was saved")
	}

	// The process stops before the kit is shown; it restarts with its
	// passphrase.
	*pass = testDevicePassphrase
	s, err = tryOpen(t, cfg)
	if err != nil {
		t.Fatalf("the vault does not open after the crash: %v", err)
	}
	info := s.Info()
	if info.Locked {
		t.Fatalf("the device key on disk does not unlock the vault: %s", info.LockReason)
	}
	if info.DeviceID != a.String() {
		t.Errorf("unlocked as %s, want the surviving device %v", info.DeviceID, a)
	}
	got := s.PendingKit()
	if got == nil || got.SecretKey != kit.SecretKey || got.RecoveryKey != kit.RecoveryKey {
		t.Fatal("the pending kit was lost")
	}
	if _, ok := s.state.Devices[b]; ok || !slices.Contains(s.state.Retired.DeviceIDs, b) {
		t.Error("the stale device was not revoked")
	}
	if err := s.AckKit(); err != nil {
		t.Fatalf("ack: %v", err)
	}
	if len(journalFiles(t, cfg)) != 0 || s.PendingKit() != nil || len(s.Info().Warnings) != 0 {
		t.Errorf("after the ack: journal %v, warnings %q", journalFiles(t, cfg), s.Info().Warnings)
	}
	if info := open(t, cfg).Info(); info.Locked || info.DeviceID != a.String() {
		t.Errorf("reopen after the ack: %+v", info)
	}
	if err := open(t, cfg).UnlockWithPassword(ctx, []byte(newPassword), ""); err != nil {
		t.Errorf("password unlock with the stored Secret Key: %v", err)
	}
}

// Round 3, finding 1: when this device's key cannot be saved durably before
// the checkpoint, hop passwd changes nothing: no entry, no journal, and the
// old password still works.
func TestPasswdAbortsWhenTheDeviceKeyCannotBeSaved(t *testing.T) {
	ctx := context.Background()
	for _, tc := range []struct {
		name  string
		setup func(t *testing.T) (Config, *Store, func(fail bool))
	}{
		{"keychain refuses the write", func(t *testing.T) (Config, *Store, func(bool)) {
			cfg := testConfig(t)
			ring := &failRing{memRing: newMemRing()}
			cfg.Keyring = ring
			f := newVault(t, cfg)
			addHost(t, f.s, "web-1")
			return cfg, f.s, func(fail bool) { ring.fail = fail }
		}},
		{"keychain stores but reports a failure", func(t *testing.T) (Config, *Store, func(bool)) {
			cfg := testConfig(t)
			ring := &failRing{memRing: newMemRing()}
			cfg.Keyring = ring
			f := newVault(t, cfg)
			addHost(t, f.s, "web-1")
			return cfg, f.s, func(fail bool) { ring.failAfter = fail }
		}},
		{"a stale device's key in device.key and no passphrase", func(t *testing.T) (Config, *Store, func(bool)) {
			cfg, s, pass := sealedFileVault(t)
			failedFileUnlock(t, s)
			return cfg, s, func(fail bool) {
				*pass = testDevicePassphrase
				if fail {
					*pass = ""
				}
			}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg, s, fail := tc.setup(t)
			seqs, err := s.l.entrySeqs()
			if err != nil {
				t.Fatal(err)
			}
			fail(true)
			_, err = s.ChangePassword(ctx, []byte(testPassword), []byte(newPassword))
			if err == nil || !strings.Contains(err.Error(), "the password was not changed") {
				t.Fatalf("passwd with the device key store failing: %v", err)
			}
			fail(false)
			if after, err := s.l.entrySeqs(); err != nil || !slices.Equal(after, seqs) {
				t.Errorf("the log moved: %v, was %v (%v)", after, seqs, err)
			}
			if len(journalFiles(t, cfg)) != 0 || s.PendingKit() != nil {
				t.Errorf("journal %v, pending %v", journalFiles(t, cfg), s.PendingKit() != nil)
			}
			s = open(t, cfg)
			if info := s.Info(); info.Locked {
				t.Fatalf("locked after the refused passwd: %s", info.LockReason)
			}
			if err := s.UnlockWithPassword(ctx, []byte(testPassword), ""); err != nil {
				t.Errorf("the old password no longer works: %v", err)
			}
			if _, err := s.ChangePassword(ctx, []byte(testPassword), []byte(newPassword)); err != nil {
				t.Errorf("passwd once the store works: %v", err)
			}
		})
	}
}

// Round 3, finding 2: a device record's secret_key must parse as a Secret
// Key. The refusal does not quote it.
func TestDeviceRecordRefusesABadSecretKey(t *testing.T) {
	cfg := testConfig(t)
	f := newVault(t, cfg)
	user := deviceSlot(t, cfg)
	raw, err := cfg.Keyring.Get(keychainService, user)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal([]byte(raw), &m); err != nil {
		t.Fatal(err)
	}
	sk := f.kit.SecretKey
	last := sk[len(sk)-1]
	swap := byte('0')
	if last == '0' {
		swap = '1'
	}
	with := func(v string) []byte {
		c := maps.Clone(m)
		c["secret_key"] = v
		b, err := json.Marshal(c)
		if err == nil {
			b, err = canonjson.Canonicalize(b)
		}
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	// Only secret_key changes: the record with the real one parses.
	if _, err := parseDeviceRecord(with(sk)); err != nil {
		t.Fatalf("control: %v", err)
	}
	// Slice E2: "" now parses (a device enrolled by approval stores no
	// Secret Key, §11 addendum), but a device that was not enrolled by
	// approval still never unlocks with it.
	t.Run("empty", func(t *testing.T) {
		b := with("")
		if _, err := parseDeviceRecord(b); err != nil {
			t.Fatalf("an enrolled device's record is refused: %v", err)
		}
		if err := cfg.Keyring.Set(keychainService, user, string(b)); err != nil {
			t.Fatal(err)
		}
		info := open(t, cfg).Info()
		if !info.Locked || !strings.Contains(info.LockReason, "not enrolled by approval") {
			t.Errorf("locked=%v reason %q", info.Locked, info.LockReason)
		}
	})
	for name, v := range map[string]string{
		"garbage":      "not-a-secret-key",
		"bad checksum": sk[:len(sk)-1] + string(swap),
	} {
		t.Run(name, func(t *testing.T) {
			b := with(v)
			_, err := parseDeviceRecord(b)
			if err == nil {
				t.Fatal("accepted")
			}
			if v != "" && strings.Contains(err.Error(), v) {
				t.Errorf("the error quotes the value: %v", err)
			}
			if err := cfg.Keyring.Set(keychainService, user, string(b)); err != nil {
				t.Fatal(err)
			}
			info := open(t, cfg).Info()
			if !info.Locked || !strings.Contains(info.LockReason, "not a valid device record") || (v != "" && strings.Contains(info.LockReason, v)) {
				t.Errorf("locked=%v reason %q", info.Locked, info.LockReason)
			}
		})
	}
	if _, err := parseDeviceRecord([]byte(raw)); err != nil {
		t.Errorf("the stored record does not parse: %v", err)
	}
}
