package store

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/dalyem/hopkey/internal/model"
	"github.com/dalyem/hopkey/internal/vaultlog"
)

// Round 3 (D1), finding 1, store side: a revocation moves the generation
// and sets IsRevoked before it writes anything, and both read without the
// store's mutex. Here revoke's first write blocks, holding the mutex, and
// the fence has already moved.
func TestRevocationMovesTheFenceFirst(t *testing.T) {
	ctx := context.Background()
	p := newPair(t)
	a := p.a.s
	revokeOn(t, p.b.s, p.r, deviceOf(a))
	before := a.Generation()
	entered, release := make(chan struct{}), make(chan struct{})
	a.testHook = func(stage string) error {
		if stage == "revoke:marker" {
			close(entered)
			<-release
		}
		return nil
	}
	pulled := make(chan error, 1)
	go func() { pulled <- a.Pull(ctx, p.r) }()
	select {
	case <-entered:
	case err := <-pulled:
		t.Fatalf("the pull finished without revoking: %v", err)
	case <-time.After(10 * time.Second):
		t.Fatal("the pull never reached the revocation")
	}
	fenced := make(chan bool, 1)
	go func() { fenced <- a.IsRevoked() && a.Generation() != before }()
	select {
	case ok := <-fenced:
		if !ok {
			t.Error("the fence had not moved when revoke started writing")
		}
	case <-time.After(5 * time.Second):
		t.Error("reading the fence blocked behind the revocation")
	}
	close(release)
	if err := <-pulled; !errors.Is(err, ErrDeviceRevoked) {
		t.Fatalf("pull: %v", err)
	}
}

// Round 3 (D1), finding 5, store side: the generation moves on lock,
// unlock and a commit that locks the store itself, whatever error that
// commit returns.
func TestGenerationMovesOnEveryLockChange(t *testing.T) {
	ctx := context.Background()
	f, _ := serverVault(t)
	s := f.s
	g := s.Generation()
	step := func(what string) {
		t.Helper()
		if now := s.Generation(); now == g {
			t.Errorf("%s: the generation stayed at %d", what, g)
		} else {
			g = now
		}
	}
	s.Lock()
	step("lock")
	if err := s.Unlock(ctx); err != nil {
		t.Fatal(err)
	}
	step("unlock")
	s.testHook = crashAt("wal:op:0")
	_, err := s.PutCredential(ctx, model.Credential{Name: "c", Username: "u", Password: "p"})
	if !errors.Is(err, errCrash) || errors.Is(err, model.ErrLocked) {
		t.Fatalf("put with the journal's first operation failing: %v", err)
	}
	step("interrupted commit")
	if _, err := s.Snapshot(ctx); !errors.Is(err, model.ErrLocked) {
		t.Errorf("the store is not locked: %v", err)
	}
	if s.IsRevoked() {
		t.Error("revoked")
	}
}

// sameRingVault enrolls a second device of f's account in its own data
// directory, on the same keychain as f: a second vault of the account on
// the same machine. Its device.json starts out naming a device that has
// no key, so it opens locked, and a password unlock through r enrolls it.
func sameRingVault(t *testing.T, f *fixture, r *fakeRemote) *fixture {
	t.Helper()
	ctx := context.Background()
	if err := f.s.Pull(ctx, r); err != nil {
		t.Fatal(err)
	}
	cfg := testConfig(t)
	cfg.Keyring = f.cfg.Keyring
	copyDir(t, f.cfg.DataDir, cfg.DataDir)
	path := filepath.Join(cfg.DataDir, "device.json")
	var dc deviceConfig
	if err := json.Unmarshal([]byte(readFile(t, path)), &dc); err != nil {
		t.Fatal(err)
	}
	id, err := vaultlog.NewID()
	if err != nil {
		t.Fatal(err)
	}
	dc.DeviceID, dc.StaleDevices = id, nil
	b, err := json.Marshal(dc)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, b, 0o600); err != nil {
		t.Fatal(err)
	}
	s, err := Open(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	track(t, cfg, s)
	if !s.Info().Locked {
		t.Fatal("setup: the second vault unlocked with the first one's key")
	}
	if err := s.UnlockWithPasswordRemote(ctx, r, []byte(testPassword), f.kit.SecretKey); err != nil {
		t.Fatal(err)
	}
	if err := f.s.Pull(ctx, r); err != nil {
		t.Fatal(err)
	}
	return &fixture{cfg: cfg, kit: f.kit, s: s}
}

// Round 3 (D1), finding 2: two vault directories of one account share the
// keychain, each device in its own entry. Revoking the device of one
// leaves the other's record, and its vault, as they were.
func TestRevocationLeavesAnotherVaultOfTheAccountAlone(t *testing.T) {
	ctx := context.Background()
	f, r := serverVaultIn(t, DeviceStoreKeychain)
	addHost(t, f.s, "web")
	pushAll(t, f.s, r)
	other := sameRingVault(t, f, r)
	a, b := deviceOf(f.s), deviceOf(other.s)
	if a == b {
		t.Fatal("setup: one device")
	}
	if got := storedRecord(t, f.cfg, f.kit.AccountID); got.DeviceID != a {
		t.Fatalf("setup: the first vault's record is %v, want %v", got.DeviceID, a)
	}

	revokeOn(t, other.s, r, a)
	if err := f.s.Pull(ctx, r); !errors.Is(err, ErrDeviceRevoked) {
		t.Fatalf("pull: %v", err)
	}
	if !tombstoned(t, f, DeviceStoreKeychain, a) {
		t.Error("the revoked device's entry is not its tombstone")
	}
	if got := storedRecord(t, other.cfg, f.kit.AccountID); got.DeviceID != b {
		t.Errorf("the other vault's record is %v, want %v", got.DeviceID, b)
	}
	s := open(t, other.cfg)
	if info := s.Info(); info.Locked || info.Revoked {
		t.Fatalf("the other vault after the revocation: %+v", info)
	}
	if err := s.Pull(ctx, r); err != nil {
		t.Errorf("the other vault's pull: %v", err)
	}
	if info := open(t, f.cfg).Info(); !info.Revoked {
		t.Errorf("the revoked vault after a restart: %+v", info)
	}
}

// Round 3 (D1), finding 3: a replacement that stopped after saving the new
// record (B) and before installing it leaves device.json naming the lost
// device (A), with B pending. Another device then revokes A and keeps B.
// The retried password unlock finds B's bootstrap in the verified log and
// its record readable, and installs B before it asks the server anything:
// the revocation of A, which B replaced, does not revoke it.
func TestAStaleConfigIDDoesNotRevokeTheReplacement(t *testing.T) {
	ctx := context.Background()
	f, r := serverVaultIn(t, DeviceStoreKeychain)
	addHost(t, f.s, "web")
	pushAll(t, f.s, r)
	other := secondDevice(t, f, r)
	acct, err := model.ParseID(f.kit.AccountID)
	if err != nil {
		t.Fatal(err)
	}
	a := deviceOf(f.s)

	// A's key is lost; the password unlock enrolls B.
	f.s.Lock()
	if err := f.cfg.Keyring.Delete(keychainService, slotOf(acct, a)); err != nil {
		t.Fatal(err)
	}
	if err := f.s.UnlockWithPasswordRemote(ctx, r, []byte(testPassword), f.kit.SecretKey); err != nil {
		t.Fatal(err)
	}
	b := deviceOf(f.s)
	f.s.Lock()
	// What a replacement that stopped between saving B's record and
	// installing it leaves on disk: device.json names A, with B pending.
	path := filepath.Join(f.cfg.DataDir, "device.json")
	var dc deviceConfig
	if err := json.Unmarshal([]byte(readFile(t, path)), &dc); err != nil {
		t.Fatal(err)
	}
	dc.DeviceID, dc.Pending, dc.StaleDevices = a, &pendingDevice{DeviceID: b}, nil
	raw, err := json.Marshal(dc)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}

	if err := other.s.Pull(ctx, r); err != nil {
		t.Fatal(err)
	}
	revokeOn(t, other.s, r, a)

	s := f.s
	if got := storedRecord(t, f.cfg, f.kit.AccountID); got.DeviceID != b {
		t.Fatalf("setup: the readable record is %v, want B (%v)", got.DeviceID, b)
	}
	posts := r.postCount()
	err = s.UnlockWithPasswordRemote(ctx, r, []byte(testPassword), f.kit.SecretKey)
	if errors.Is(err, ErrDeviceRevoked) || s.IsRevoked() || revokedFileExists(t, f.cfg) || s.Info().Revoked {
		t.Fatalf("the revocation of the replaced device A revoked this machine: %v", err)
	}
	if err != nil || deviceOf(s) != b || r.postCount() != posts {
		t.Fatalf("the retried password unlock: %v; want B (%v) installed with nothing posted", err, b)
	}
	if tombstoned(t, f, DeviceStoreKeychain, b) || tombstoned(t, f, DeviceStoreKeychain, a) {
		t.Error("a device record was tombstoned")
	}
	if got := storedRecord(t, f.cfg, f.kit.AccountID); got.DeviceID != b {
		t.Errorf("the readable record is %v, want B (%v)", got.DeviceID, b)
	}
	// B, recertified by the checkpoint, unlocks and crosses it.
	s = open(t, f.cfg)
	if info := s.Info(); info.Locked || info.DeviceID != b.String() {
		t.Fatalf("after a restart %+v, want unlocked as B (%v)", info, b)
	}
	if err := s.Pull(ctx, r); err != nil {
		t.Errorf("pull across the checkpoint that revoked A: %v", err)
	}
}

// Round 3 (D1), finding 4: the marker fails and the tombstone is written.
// After a restart, a password unlock against a server that withholds the
// revoking checkpoint is refused, from the tombstone alone, and nothing is
// posted. When both fail, the record is deleted as a last resort and the
// error says so.
func TestTheTombstoneKeepsTheRevocationTerminal(t *testing.T) {
	for _, deviceStore := range []string{DeviceStoreKeychain, DeviceStoreFile} {
		t.Run(deviceStore, func(t *testing.T) {
			ctx := context.Background()
			f, r := serverVaultIn(t, deviceStore)
			addHost(t, f.s, "web")
			pushAll(t, f.s, r)
			b := secondDevice(t, f, r)
			dev := deviceOf(f.s)
			revokeOn(t, b.s, r, dev)
			f.s.testHook = crashAt("revoke:marker")
			if err := f.s.Pull(ctx, r); !errors.Is(err, ErrDeviceRevoked) {
				t.Fatalf("pull: %v", err)
			}
			if revokedFileExists(t, f.cfg) {
				t.Fatal("setup: the marker was written")
			}
			if !tombstoned(t, f, deviceStore, dev) {
				t.Error("the device record was not replaced with its tombstone")
			}
			// This server never shows the revoking checkpoint.
			withholding := newFakeRemote(t, f.cfg.DataDir)
			if withholding.head().Seq >= r.head().Seq {
				t.Fatal("setup: the withholding server has the checkpoint")
			}

			s, err := tryOpen(t, f.cfg)
			if err != nil {
				t.Fatal(err)
			}
			if info := s.Info(); !info.Locked || !info.Revoked {
				t.Errorf("open: %+v", info)
			}
			if err := s.UnlockWithPasswordRemote(ctx, withholding, []byte(testPassword), f.kit.SecretKey); !errors.Is(err, ErrDeviceRevoked) {
				t.Errorf("password unlock against a server that withholds the revocation: %v", err)
			}
			if n := withholding.postCount(); n != 0 {
				t.Errorf("%d entries posted", n)
			}
			if err := s.Unlock(ctx); !errors.Is(err, ErrDeviceRevoked) {
				t.Errorf("unlock: %v", err)
			}
			if !tombstoned(t, f, deviceStore, dev) {
				t.Error("the tombstone is gone")
			}
		})
	}

	t.Run("both fail", func(t *testing.T) {
		ctx := context.Background()
		f, r := serverVaultIn(t, DeviceStoreKeychain)
		pushAll(t, f.s, r)
		b := secondDevice(t, f, r)
		dev := deviceOf(f.s)
		acct, err := model.ParseID(f.kit.AccountID)
		if err != nil {
			t.Fatal(err)
		}
		revokeOn(t, b.s, r, dev)
		f.s.testHook = func(stage string) error {
			if stage == "revoke:marker" || stage == "revoke:tombstone" {
				return errCrash
			}
			return nil
		}
		err = f.s.Pull(ctx, r)
		if !errors.Is(err, ErrDeviceRevoked) || !strings.Contains(err.Error(), "deleted instead") {
			t.Fatalf("pull: %v", err)
		}
		if _, err := f.cfg.Keyring.Get(keychainService, slotOf(acct, dev)); err == nil {
			t.Error("the device record survived both failures")
		}
	})
}
