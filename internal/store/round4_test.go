package store

import (
	"context"
	"errors"
	"slices"
	"sync"
	"testing"

	"github.com/dalyem/hopkey/internal/model"
	"github.com/dalyem/hopkey/internal/vaultlog"
)

// pickyRing is a memRing that refuses writes to chosen entries, storing
// nothing, and can ignore deletes.
type pickyRing struct {
	*memRing
	mu           sync.Mutex
	refused      map[string]bool // keychain users whose Set fails
	keepOnDelete bool            // Delete reports success and deletes nothing
}

func newPickyRing() *pickyRing {
	return &pickyRing{memRing: newMemRing(), refused: map[string]bool{}}
}

func (r *pickyRing) refuse(user string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.refused[user] = true
}

func (r *pickyRing) Set(service, user, secret string) error {
	r.mu.Lock()
	refused := r.refused[user]
	r.mu.Unlock()
	if refused {
		return errors.New("keychain write refused")
	}
	return r.memRing.Set(service, user, secret)
}

func (r *pickyRing) Delete(service, user string) error {
	if r.keepOnDelete {
		return nil
	}
	return r.memRing.Delete(service, user)
}

// serverVaultOn is serverVaultIn on the keyring ring.
func serverVaultOn(t *testing.T, ring Keyring, deviceStore string) (*fixture, *fakeRemote) {
	t.Helper()
	cfg := testConfig(t)
	cfg.Keyring = ring
	p, err := PrepareInit(cfg, InitOptions{Password: []byte(testPassword), DeviceStore: deviceStore})
	if err != nil {
		t.Fatal(err)
	}
	s, err := p.Commit()
	if err != nil {
		t.Fatal(err)
	}
	track(t, cfg, s)
	f := &fixture{cfg: cfg, kit: p.Kit(), s: s}
	r := newFakeRemote(t, cfg.DataDir)
	if err := s.EnableServerMode(); err != nil {
		t.Fatal(err)
	}
	return f, r
}

// diskDeviceConfig is device.json in cfg's data directory.
func diskDeviceConfig(t *testing.T, cfg Config) deviceConfig {
	t.Helper()
	dc, err := (&Store{cfg: cfg, l: layout{data: cfg.DataDir}}).readDeviceConfig()
	if err != nil {
		t.Fatal(err)
	}
	return dc
}

func accountOfKit(t *testing.T, f *fixture) model.ID {
	t.Helper()
	acct, err := model.ParseID(f.kit.AccountID)
	if err != nil {
		t.Fatal(err)
	}
	return acct
}

// Round 4 (D1), finding 1: A's record is still readable when a password
// unlock through the server enrolls B. Another device revokes B after B's
// bootstrap commits and before B is installed; revoked.json fails, and only
// B's tombstone is written (in the keychain, A's entry refuses writes). A
// revocation of the pending replacement is terminal for the directory:
// after a restart, nothing unlocks, against a server that withholds the
// revoking checkpoint too.
func TestARevokedPendingReplacementStaysRevoked(t *testing.T) {
	for _, deviceStore := range []string{DeviceStoreKeychain, DeviceStoreFile} {
		t.Run(deviceStore, func(t *testing.T) {
			ctx := context.Background()
			ring := newPickyRing()
			f, r := serverVaultOn(t, ring, deviceStore)
			addHost(t, f.s, "web")
			pushAll(t, f.s, r)
			other := secondDevice(t, f, r)
			acct, a := accountOfKit(t, f), deviceOf(f.s)
			f.s.Lock()

			posts := r.postCount()
			var b model.ID
			r.onSince = func(context.Context) {
				if !b.IsZero() || r.postCount() == posts {
					return
				}
				// B's bootstrap is posted; it is pending in device.json.
				b = diskDeviceConfig(t, f.cfg).pendingID()
				if b.IsZero() {
					t.Error("the bootstrap was posted before its device was recorded as pending")
					return
				}
				revokeOn(t, other.s, r, b)
				ring.refuse(slotOf(acct, a))
			}
			f.s.testHook = crashAt("revoke:marker")
			if err := f.s.UnlockWithPasswordRemote(ctx, r, []byte(testPassword), f.kit.SecretKey); !errors.Is(err, ErrDeviceRevoked) {
				t.Fatalf("password unlock across the revocation of its new device: %v", err)
			}
			r.onSince = nil
			if b.IsZero() {
				t.Fatal("setup: B was never revoked")
			}
			if revokedFileExists(t, f.cfg) {
				t.Fatal("setup: the marker was written")
			}
			if !tombstoned(t, f, deviceStore, b) {
				t.Fatal("B's record is not its tombstone")
			}
			if deviceStore == DeviceStoreKeychain {
				raw, err := ring.Get(keychainService, slotOf(acct, a))
				if err != nil {
					t.Fatal(err)
				}
				if _, err := parseDeviceRecord([]byte(raw)); err != nil {
					t.Fatalf("setup: A's record is not readable: %v", err)
				}
			}

			// A restart, and a server that never shows the revoking
			// checkpoint.
			withholding := newFakeRemote(t, f.cfg.DataDir)
			s, err := tryOpen(t, f.cfg)
			if err != nil {
				t.Fatal(err)
			}
			if info := s.Info(); !info.Locked || !info.Revoked {
				t.Errorf("open after the restart: %+v", info)
			}
			if err := s.Unlock(ctx); !errors.Is(err, ErrDeviceRevoked) {
				t.Errorf("unlock: %v", err)
			}
			if err := s.UnlockWithPasswordRemote(ctx, withholding, []byte(testPassword), f.kit.SecretKey); !errors.Is(err, ErrDeviceRevoked) {
				t.Errorf("password unlock against a server that withholds the revocation: %v", err)
			}
			if n := withholding.postCount(); n != 0 {
				t.Errorf("%d entries posted", n)
			}
			dc := diskDeviceConfig(t, f.cfg)
			if rec, err := s.deviceStore(dc).load(); !errors.Is(err, ErrDeviceRevoked) {
				t.Errorf("load returned %v, %v", rec != nil, err)
			}
		})
	}
}

// Round 4 (D1), finding 2: the stale list is never a source of the device
// key. Two password unlocks leave two stale devices whose records survive
// in the keychain; then the current device's key is lost. Nothing unlocks
// with a stale key, and a checkpoint that revokes the stale devices does
// not revoke this machine.
func TestStaleKeysAreNeverLoaded(t *testing.T) {
	ctx := context.Background()
	ring := newPickyRing()
	ring.keepOnDelete = true
	f, r := serverVaultOn(t, ring, DeviceStoreKeychain)
	addHost(t, f.s, "web")
	pushAll(t, f.s, r)
	other := secondDevice(t, f, r)
	acct := accountOfKit(t, f)
	var stale []model.ID
	for range 2 {
		stale = append(stale, deviceOf(f.s))
		f.s.Lock()
		if err := f.s.UnlockWithPasswordRemote(ctx, r, []byte(testPassword), f.kit.SecretKey); err != nil {
			t.Fatal(err)
		}
	}
	cur := deviceOf(f.s)
	f.s.Lock()
	dc := diskDeviceConfig(t, f.cfg)
	if dc.DeviceID != cur || !dc.pendingID().IsZero() || len(dc.StaleDevices) != 2 {
		t.Fatalf("setup: device.json %+v", dc)
	}
	for _, id := range stale {
		raw, err := ring.Get(keychainService, slotOf(acct, id))
		if err != nil {
			t.Fatalf("setup: stale device %v has no record: %v", id, err)
		}
		if _, err := parseDeviceRecord([]byte(raw)); err != nil {
			t.Fatalf("setup: stale device %v's record does not parse: %v", id, err)
		}
	}
	if err := ring.memRing.Delete(keychainService, slotOf(acct, cur)); err != nil {
		t.Fatal(err)
	}

	s, err := tryOpen(t, f.cfg)
	if err != nil {
		t.Fatal(err)
	}
	if info := s.Info(); !info.Locked {
		t.Fatalf("unlocked as %s with a stale device's key", info.DeviceID)
	}
	if rec, err := s.deviceStore(dc).load(); !errors.Is(err, ErrDeviceKey) {
		t.Errorf("load returned a record (%v): %v", rec != nil, err)
	}

	for _, id := range stale {
		revokeOn(t, other.s, r, id)
	}
	// Without the current device's key the password unlock cannot open the
	// checkpoints' new keys, so it may fail; it must not revoke.
	err = s.UnlockWithPasswordRemote(ctx, r, []byte(testPassword), f.kit.SecretKey)
	t.Logf("password unlock across the revocation of the stale devices: %v", err)
	if errors.Is(err, ErrDeviceRevoked) || s.IsRevoked() || revokedFileExists(t, f.cfg) || s.Info().Revoked {
		t.Fatalf("the revocation of a stale device revoked this machine: %v", err)
	}
	for _, id := range stale {
		if tombstoned(t, f, DeviceStoreKeychain, id) {
			t.Errorf("stale device %v was tombstoned", id)
		}
	}
}

// Round 4 (D1): a password unlock whose bootstrap committed and whose
// record was saved, but which stopped before installing it, is finished by
// the next attempt, or by the next unlock after a restart: the pending
// device is installed, and nothing new is enrolled.
func TestACompletedPendingReplacementIsInstalled(t *testing.T) {
	for _, restart := range []bool{false, true} {
		name := "retry"
		if restart {
			name = "restart"
		}
		t.Run(name, func(t *testing.T) {
			ctx := context.Background()
			f, r := serverVaultIn(t, DeviceStoreKeychain)
			addHost(t, f.s, "web")
			pushAll(t, f.s, r)
			acct, a := accountOfKit(t, f), deviceOf(f.s)
			f.s.Lock()
			if err := f.cfg.Keyring.Delete(keychainService, slotOf(acct, a)); err != nil {
				t.Fatal(err)
			}
			f.s.testHook = crashAt("passwd:install")
			if err := f.s.UnlockWithPasswordRemote(ctx, r, []byte(testPassword), f.kit.SecretKey); !errors.Is(err, errCrash) {
				t.Fatalf("password unlock stopped before the install: %v", err)
			}
			dc := diskDeviceConfig(t, f.cfg)
			b := dc.pendingID()
			if b.IsZero() || dc.DeviceID != a {
				t.Fatalf("setup: device.json %+v; want A named and B pending", dc)
			}
			if got := storedRecord(t, f.cfg, f.kit.AccountID); got.DeviceID != b {
				t.Fatalf("setup: the readable record is %v, want B (%v)", got.DeviceID, b)
			}
			posts := r.postCount()

			s := f.s
			if restart {
				s = open(t, f.cfg)
			} else if err := s.UnlockWithPasswordRemote(ctx, r, []byte(testPassword), f.kit.SecretKey); err != nil {
				t.Fatalf("the retried password unlock: %v", err)
			}
			if info := s.Info(); info.Locked || info.DeviceID != b.String() {
				t.Fatalf("%+v; want unlocked as B (%v)", info, b)
			}
			if n := r.postCount(); n != posts {
				t.Errorf("%d entries posted", n-posts)
			}
			dc = diskDeviceConfig(t, f.cfg)
			if dc.DeviceID != b || !dc.pendingID().IsZero() || !slices.Equal(dc.StaleDevices, []model.ID{a}) {
				t.Errorf("device.json %+v; want B named, nothing pending, A stale", dc)
			}
			pull(t, s, r)
			if info := open(t, f.cfg).Info(); info.Locked || info.DeviceID != b.String() {
				t.Errorf("after another restart: %+v", info)
			}
		})
	}
}

// errRefused is a post the server refuses without committing it.
var errRefused = errors.New("fake: the post was refused")

// Round 4 (D1): a password unlock whose bootstrap never committed leaves
// its device pending. The next password unlock, or the next unlock with the
// device key, clears it after deleting its record: the device is not stale
// (it is not in the log), and no key of it is left.
func TestANeverCommittedPendingReplacementIsCleared(t *testing.T) {
	for _, path := range []string{"password unlock", "unlock"} {
		t.Run(path, func(t *testing.T) {
			ctx := context.Background()
			f, r := serverVaultIn(t, DeviceStoreKeychain)
			addHost(t, f.s, "web")
			pushAll(t, f.s, r)
			acct, a := accountOfKit(t, f), deviceOf(f.s)
			// A's record stays readable, so it is the one each path reads,
			// and B's can go only by being discarded.
			f.s.Lock()
			r.onPost = func(*vaultlog.Wire) (bool, error) { return false, errRefused }
			if err := f.s.UnlockWithPasswordRemote(ctx, r, []byte(testPassword), f.kit.SecretKey); !errors.Is(err, errRefused) {
				t.Fatalf("password unlock with the post refused: %v", err)
			}
			r.onPost = nil
			dc := diskDeviceConfig(t, f.cfg)
			b := dc.pendingID()
			if b.IsZero() || dc.DeviceID != a {
				t.Fatalf("setup: device.json %+v; want A named and B pending", dc)
			}
			// A record of B where B's would be: what a store that saved it
			// anyway would hold.
			rec, _, err := newDeviceRecord(acct, f.kit.SecretKey)
			if err != nil {
				t.Fatal(err)
			}
			rec.DeviceID = b
			raw, err := rec.jcs()
			if err != nil {
				t.Fatal(err)
			}
			if err := f.cfg.Keyring.Set(keychainService, slotOf(acct, b), string(raw)); err != nil {
				t.Fatal(err)
			}

			s := f.s
			want := a
			if path == "unlock" {
				if err := s.Unlock(ctx); err != nil {
					t.Fatal(err)
				}
			} else {
				if err := s.UnlockWithPasswordRemote(ctx, r, []byte(testPassword), f.kit.SecretKey); err != nil {
					t.Fatalf("the retried password unlock: %v", err)
				}
				want = deviceOf(s)
				if want == a || want == b {
					t.Fatalf("unlocked as %v; want a new device", want)
				}
			}
			if deviceOf(s) != want {
				t.Errorf("unlocked as %v, want %v", deviceOf(s), want)
			}
			dc = diskDeviceConfig(t, f.cfg)
			if dc.DeviceID != want || !dc.pendingID().IsZero() || slices.Contains(dc.StaleDevices, b) {
				t.Errorf("device.json %+v; want %v named, nothing pending, B not stale", dc, want)
			}
			if _, err := f.cfg.Keyring.Get(keychainService, slotOf(acct, b)); err == nil {
				t.Error("B's record survived")
			}
			s.mu.Lock()
			_, active := s.state.Devices[b]
			s.mu.Unlock()
			if active {
				t.Error("B is in the log")
			}
			if info := open(t, f.cfg).Info(); info.Locked || info.DeviceID != want.String() {
				t.Errorf("after a restart: %+v", info)
			}
		})
	}
}
