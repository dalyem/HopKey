package store

import (
	"context"
	"crypto/rand"
	"errors"
	"strings"
	"sync"
	"testing"

	"github.com/dalyem/hopkey/internal/canonjson"
	"github.com/dalyem/hopkey/internal/model"
)

// errBackend is a keychain backend failure that is not a missing entry.
var errBackend = errors.New("keychain backend unavailable")

// brokenRing is a pickyRing whose reads of chosen entries fail with a
// backend error, and whose deletes of chosen entries fail and delete
// nothing.
type brokenRing struct {
	*pickyRing
	mu          sync.Mutex
	unreadable  map[string]bool
	undeletable map[string]bool
}

func newBrokenRing() *brokenRing {
	return &brokenRing{pickyRing: newPickyRing(), unreadable: map[string]bool{}, undeletable: map[string]bool{}}
}

func (r *brokenRing) setUnreadable(user string, on bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.unreadable[user] = on
}

func (r *brokenRing) setUndeletable(user string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.undeletable[user] = true
}

func (r *brokenRing) Get(service, user string) (string, error) {
	r.mu.Lock()
	broken := r.unreadable[user]
	r.mu.Unlock()
	if broken {
		return "", errBackend
	}
	return r.pickyRing.Get(service, user)
}

func (r *brokenRing) Delete(service, user string) error {
	r.mu.Lock()
	broken := r.undeletable[user]
	r.mu.Unlock()
	if broken {
		return errors.New("keychain delete refused")
	}
	return r.pickyRing.Delete(service, user)
}

func randomID(t *testing.T) model.ID {
	t.Helper()
	var id model.ID
	if _, err := rand.Read(id[:]); err != nil {
		t.Fatal(err)
	}
	return id
}

func tombstoneOf(t *testing.T, acct, dev model.ID) string {
	t.Helper()
	b, err := canonjson.Marshal(deviceTombstone{V: 2, Revoked: true, AccountID: acct, DeviceID: dev})
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// Round 5 (D1), finding 1: the pending replacement B holds its tombstone,
// and every read of B's entry fails with a backend error while a delete of
// it would succeed. An unlock must not take that for "no tombstone": the
// vault stays locked with ErrKeyStoreUnavailable, and B's entry and the
// pending device in device.json are left as they are. Once the keychain
// reads again, the vault is refused as revoked.
func TestAnUnreadablePendingTombstoneIsKept(t *testing.T) {
	ctx := context.Background()
	ring := newBrokenRing()
	cfg := testConfig(t)
	cfg.Keyring = ring
	f := newVault(t, cfg)
	addHost(t, f.s, "web")
	acct, a := accountOfKit(t, f), deviceOf(f.s)
	release(cfg)

	b := randomID(t)
	dc := diskDeviceConfig(t, cfg)
	dc.Pending = &pendingDevice{DeviceID: b}
	if err := (&Store{cfg: cfg, l: layout{data: cfg.DataDir}}).writeDeviceConfig(dc); err != nil {
		t.Fatal(err)
	}
	tomb := tombstoneOf(t, acct, b)
	if err := ring.memRing.Set(keychainService, slotOf(acct, b), tomb); err != nil {
		t.Fatal(err)
	}
	ring.setUnreadable(slotOf(acct, b), true)

	kept := func(when string) {
		t.Helper()
		if raw, err := ring.memRing.Get(keychainService, slotOf(acct, b)); err != nil || raw != tomb {
			t.Errorf("%s: B's entry is %q, %v; want its tombstone", when, raw, err)
		}
		if got := diskDeviceConfig(t, cfg); got.DeviceID != a || got.pendingID() != b {
			t.Errorf("%s: device.json %+v; want A named and B pending", when, got)
		}
	}

	s, err := tryOpen(t, cfg)
	if err != nil {
		t.Fatal(err)
	}
	if info := s.Info(); !info.Locked || info.Revoked {
		t.Errorf("open with B's entry unreadable: %+v; want locked, not revoked", info)
	}
	if s.IsRevoked() {
		t.Error("an unreadable entry was taken for a revocation")
	}
	kept("after open")
	if err := s.Unlock(ctx); !errors.Is(err, ErrKeyStoreUnavailable) {
		t.Errorf("unlock: %v; want ErrKeyStoreUnavailable", err)
	}
	if err := s.UnlockWithPassword(ctx, []byte(testPassword), f.kit.SecretKey); !errors.Is(err, ErrKeyStoreUnavailable) {
		t.Errorf("password unlock: %v; want ErrKeyStoreUnavailable", err)
	}
	kept("after the unlocks")

	ring.setUnreadable(slotOf(acct, b), false)
	if err := s.Unlock(ctx); !errors.Is(err, ErrDeviceRevoked) {
		t.Errorf("unlock once B's entry reads: %v; want ErrDeviceRevoked", err)
	}
	s, err = tryOpen(t, cfg)
	if err != nil {
		t.Fatal(err)
	}
	if info := s.Info(); !info.Locked || !info.Revoked {
		t.Errorf("open once B's entry reads: %+v; want locked and revoked", info)
	}
	if err := s.UnlockWithPassword(ctx, []byte(testPassword), f.kit.SecretKey); !errors.Is(err, ErrDeviceRevoked) {
		t.Errorf("password unlock once B's entry reads: %v; want ErrDeviceRevoked", err)
	}
	kept("at the end")
}

// Round 5 (D1), finding 1, the current slot: A, the device device.json
// names, holds its tombstone and its entry cannot be read; B, the pending
// replacement, has a readable record and its bootstrap is in the log. The
// unlock must not pass over A's entry to B's key: that would install B and
// make A stale, and A's revocation would be lost.
func TestAnUnreadableCurrentTombstoneIsNotPassedOver(t *testing.T) {
	ctx := context.Background()
	ring := newBrokenRing()
	f, r := serverVaultOn(t, ring, DeviceStoreKeychain)
	addHost(t, f.s, "web")
	pushAll(t, f.s, r)
	acct, a := accountOfKit(t, f), deviceOf(f.s)
	f.s.Lock()
	if err := ring.memRing.Delete(keychainService, slotOf(acct, a)); err != nil {
		t.Fatal(err)
	}
	f.s.testHook = crashAt("passwd:install")
	if err := f.s.UnlockWithPasswordRemote(ctx, r, []byte(testPassword), f.kit.SecretKey); !errors.Is(err, errCrash) {
		t.Fatalf("password unlock stopped before the install: %v", err)
	}
	b := diskDeviceConfig(t, f.cfg).pendingID()
	if b.IsZero() {
		t.Fatal("setup: no pending replacement")
	}
	if got := storedRecord(t, f.cfg, f.kit.AccountID); got.DeviceID != b {
		t.Fatalf("setup: the readable record is %v, want B (%v)", got.DeviceID, b)
	}
	tomb := tombstoneOf(t, acct, a)
	if err := ring.memRing.Set(keychainService, slotOf(acct, a), tomb); err != nil {
		t.Fatal(err)
	}
	ring.setUnreadable(slotOf(acct, a), true)
	posts := r.postCount()

	s, err := tryOpen(t, f.cfg)
	if err != nil {
		t.Fatal(err)
	}
	if info := s.Info(); !info.Locked || info.Revoked {
		t.Errorf("open with A's entry unreadable: %+v; want locked, not revoked", info)
	}
	if err := s.Unlock(ctx); !errors.Is(err, ErrKeyStoreUnavailable) {
		t.Errorf("unlock: %v; want ErrKeyStoreUnavailable", err)
	}
	if err := s.UnlockWithPasswordRemote(ctx, r, []byte(testPassword), f.kit.SecretKey); !errors.Is(err, ErrKeyStoreUnavailable) {
		t.Errorf("password unlock: %v; want ErrKeyStoreUnavailable", err)
	}
	if n := r.postCount(); n != posts {
		t.Errorf("%d entries posted", n-posts)
	}
	if dc := diskDeviceConfig(t, f.cfg); dc.DeviceID != a || dc.pendingID() != b {
		t.Errorf("device.json %+v; want A named and B pending", dc)
	}
	if raw, err := ring.memRing.Get(keychainService, slotOf(acct, a)); err != nil || raw != tomb {
		t.Errorf("A's entry is %q, %v; want its tombstone", raw, err)
	}

	ring.setUnreadable(slotOf(acct, a), false)
	if err := s.Unlock(ctx); !errors.Is(err, ErrDeviceRevoked) {
		t.Errorf("unlock once A's entry reads: %v; want ErrDeviceRevoked", err)
	}
}

// Round 5 (D1), finding 1: discard never deletes an entry it could not
// read, whatever device.json says about it.
func TestDiscardKeepsAnUnreadableEntry(t *testing.T) {
	ring := newBrokenRing()
	acct, a, b := randomID(t), randomID(t), randomID(t)
	ds := &deviceStore{cfg: deviceConfig{V: 1, Store: DeviceStoreKeychain, AccountID: acct, DeviceID: a}, ring: ring}
	tomb := tombstoneOf(t, acct, b)
	if err := ring.memRing.Set(keychainService, slotOf(acct, b), tomb); err != nil {
		t.Fatal(err)
	}
	ring.setUnreadable(slotOf(acct, b), true)
	if err := ds.discard(b, nil); !errors.Is(err, ErrKeyStoreUnavailable) {
		t.Errorf("discard of an unreadable entry: %v; want ErrKeyStoreUnavailable", err)
	}
	if raw, err := ring.memRing.Get(keychainService, slotOf(acct, b)); err != nil || raw != tomb {
		t.Errorf("the entry is %q, %v; want it kept", raw, err)
	}
}

// pendingRevocation sets up round 4's revocation of a pending replacement:
// A's record is readable when a password unlock through the server enrolls
// B, and another device revokes B after B's bootstrap commits and before B
// is installed, with revoked.json failing. During the revocation, before
// it is handled, prepare runs with B's ID. It returns A, B and the error of
// the password unlock.
func pendingRevocation(t *testing.T, ring *brokenRing, prepare func(f *fixture, acct, a, b model.ID)) (f *fixture, a, b model.ID, err error) {
	t.Helper()
	ctx := context.Background()
	f, r := serverVaultOn(t, ring, DeviceStoreKeychain)
	addHost(t, f.s, "web")
	pushAll(t, f.s, r)
	other := secondDevice(t, f, r)
	acct := accountOfKit(t, f)
	a = deviceOf(f.s)
	f.s.Lock()

	posts := r.postCount()
	r.onSince = func(context.Context) {
		if !b.IsZero() || r.postCount() == posts {
			return
		}
		b = diskDeviceConfig(t, f.cfg).pendingID()
		if b.IsZero() {
			t.Error("the bootstrap was posted before its device was recorded as pending")
			return
		}
		revokeOn(t, other.s, r, b)
		prepare(f, acct, a, b)
	}
	f.s.testHook = crashAt("revoke:marker")
	err = f.s.UnlockWithPasswordRemote(ctx, r, []byte(testPassword), f.kit.SecretKey)
	r.onSince = nil
	if b.IsZero() {
		t.Fatal("setup: B was never revoked")
	}
	if revokedFileExists(t, f.cfg) {
		t.Fatal("setup: the marker was written")
	}
	return f, a, b, err
}

// Round 5 (D1), finding 2: the revoked device is the pending replacement
// B, revoked.json fails and B's entry refuses writes, but A's entry takes
// its tombstone. One failed tombstone does not skip the other self slot:
// after a restart, Open and both password unlocks are refused as revoked,
// against a server that withholds the revoking checkpoint too.
func TestOneFailedTombstoneDoesNotSkipTheOtherSelfSlot(t *testing.T) {
	ctx := context.Background()
	ring := newBrokenRing()
	f, a, b, err := pendingRevocation(t, ring, func(_ *fixture, acct, _, b model.ID) {
		ring.refuse(slotOf(acct, b))
	})
	if !errors.Is(err, ErrDeviceRevoked) {
		t.Fatalf("password unlock across the revocation of its new device: %v", err)
	}
	if !strings.Contains(err.Error(), "replacing the device key of "+b.String()+" with a tombstone failed") {
		t.Errorf("the error does not report B's failed tombstone: %v", err)
	}
	if tombstoned(t, f, DeviceStoreKeychain, b) {
		t.Fatal("setup: B's entry took its tombstone")
	}
	if !tombstoned(t, f, DeviceStoreKeychain, a) {
		t.Fatal("A's entry was not replaced with its tombstone")
	}

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
	if err := s.UnlockWithPassword(ctx, []byte(testPassword), f.kit.SecretKey); !errors.Is(err, ErrDeviceRevoked) {
		t.Errorf("password unlock: %v", err)
	}
	if err := s.UnlockWithPasswordRemote(ctx, withholding, []byte(testPassword), f.kit.SecretKey); !errors.Is(err, ErrDeviceRevoked) {
		t.Errorf("password unlock against a server that withholds the revocation: %v", err)
	}
	if n := withholding.postCount(); n != 0 {
		t.Errorf("%d entries posted", n)
	}
}

// Round 5 (D1), finding 2, total failure: the marker and both tombstones
// fail, so every self record is deleted as a last resort, each on its
// own. A's deletion succeeds and B's fails. Every failure is reported, A's
// key is gone, and the record in B's entry, the only one left, is the one
// the error says is still readable. B's real keys were never saved (the
// revocation came before its record was stored), so that record is a
// stand-in that does not open this vault: after a restart nothing unlocks
// and nothing says revoked. A surviving record that did open it would
// unlock it again: the documented total-failure limitation, which this
// test does not cover.
func TestATotalRevocationFailureDeletesEverySelfRecord(t *testing.T) {
	ctx := context.Background()
	ring := newBrokenRing()
	var bRec string
	f, a, b, err := pendingRevocation(t, ring, func(f *fixture, acct, a, b model.ID) {
		// B's record where B's would be: a store that saved it anyway.
		rec, _, err := newDeviceRecord(acct, f.kit.SecretKey)
		if err != nil {
			t.Error(err)
			return
		}
		rec.DeviceID = b
		raw, err := rec.jcs()
		if err != nil {
			t.Error(err)
			return
		}
		bRec = string(raw)
		if err := ring.memRing.Set(keychainService, slotOf(acct, b), bRec); err != nil {
			t.Error(err)
		}
		ring.refuse(slotOf(acct, a))
		ring.refuse(slotOf(acct, b))
		ring.setUndeletable(slotOf(acct, b))
	})
	if !errors.Is(err, ErrDeviceRevoked) {
		t.Fatalf("password unlock across the revocation of its new device: %v", err)
	}
	for _, want := range []string{
		"recording it on disk failed",
		"replacing the device key of " + a.String() + " with a tombstone failed",
		"replacing the device key of " + b.String() + " with a tombstone failed",
		"deleting the device key of " + b.String() + " failed",
		"still readable",
	} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the error does not report %q: %v", want, err)
		}
	}
	if strings.Contains(err.Error(), "deleting the device key of "+a.String()) {
		t.Errorf("the error reports A's deletion, which succeeded: %v", err)
	}
	acct := accountOfKit(t, f)
	if _, err := ring.memRing.Get(keychainService, slotOf(acct, a)); err == nil {
		t.Error("A's record survived its deletion")
	}
	if raw, err := ring.memRing.Get(keychainService, slotOf(acct, b)); err != nil || raw != bRec {
		t.Errorf("B's entry is %q, %v; want B's record, whose deletion failed", raw, err)
	}

	s, err := tryOpen(t, f.cfg)
	if err != nil {
		t.Fatal(err)
	}
	if info := s.Info(); !info.Locked || info.Revoked {
		t.Errorf("open after the restart: %+v; want locked, not revoked", info)
	}
	if err := s.Unlock(ctx); !errors.Is(err, ErrDeviceKey) || errors.Is(err, ErrDeviceRevoked) {
		t.Errorf("unlock: %v; want ErrDeviceKey", err)
	}
}
