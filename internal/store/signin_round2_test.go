package store

import (
	"context"
	"errors"
	"slices"
	"testing"

	"github.com/dalyem/hopkey/internal/model"
	"github.com/dalyem/hopkey/internal/vaultlog"
)

// Tests for D2's review round 2. Finding 3's test is
// TestSignInRecoveryCheckpointDue, and finding 6 also extends
// capture.zeroed, which TestMergeSignInZeroesSecretsOnFailure uses.

// ledgerOf reads cfg's sign-in ledger.
func ledgerOf(t *testing.T, cfg Config) *signInLedger {
	t.Helper()
	g, err := layout{data: cfg.DataDir}.readLedger()
	if err != nil {
		t.Fatal(err)
	}
	return g
}

// keychainTombstone reports whether cfg's keychain holds the tombstone of
// device dev of account acct.
func keychainTombstone(t *testing.T, cfg Config, acct, dev model.ID) bool {
	t.Helper()
	raw, err := cfg.Keyring.Get(keychainService, slotOf(acct, dev))
	if err != nil {
		return false
	}
	tomb, ok := parseTombstone([]byte(raw))
	return ok && tomb.AccountID == acct && tomb.DeviceID == dev
}

// Finding 1: a retry whose newest anchor is the checkpoint that revoked
// its device stops at the anchor's public stage: it decrypts nothing (no
// verified state, no secrets) before the revocation is terminal.
func TestSignInRetryRevokedAtAnchorDecryptsNothing(t *testing.T) {
	ctx := context.Background()
	t.Run("merge", func(t *testing.T) {
		m := newMergeFix(t, testConfig(t))
		s := m.src.s
		if _, err := s.MergeStart(); err != nil {
			t.Fatal(err)
		}
		var newAcct = m.acct
		posted, done := false, false
		m.srv.onPost = func(*vaultlog.Wire) (bool, error) { posted = true; return true, nil }
		m.r.onSince = func(context.Context) {
			if posted && !done {
				done = true
				newAcct = checkpointOn(t, m.dst.s, m.r, []model.ID{nextOf(t, m.src.cfg).DeviceID})
			}
		}
		if _, err := s.MergeSignIn(ctx, m.srv.login(t), m.params(t)); !errors.Is(err, errTokenInvalid) {
			t.Fatalf("sign-in across the checkpoint: %v", err)
		}
		m.srv.onPost, m.r.onSince = nil, nil
		next := nextOf(t, m.src.cfg)
		c := &capture{}
		c.install(s, nil)
		p := m.params(t)
		p.Account = newAcct
		if _, err := s.MergeSignIn(ctx, m.srv.login(t), p); !errors.Is(err, ErrSignInRevoked) {
			t.Fatalf("retry with the device revoked: %v", err)
		}
		if len(c.states) != 0 || c.o.d != nil {
			t.Errorf("the retry decrypted %d verified states before it found the revocation", len(c.states))
		}
		if !nextTombstoned(t, m, next) {
			t.Error("the revoked destination device's record is not a tombstone")
		}
		m.sourceIntact(t, s)
	})
	t.Run("SignIn", func(t *testing.T) {
		d := newSignInFix(t)
		cfg := testConfig(t)
		newAcct := d.acct
		posted, done := false, false
		d.srv.onPost = func(*vaultlog.Wire) (bool, error) { posted = true; return true, nil }
		d.r.onSince = func(context.Context) {
			if posted && !done {
				done = true
				newAcct = checkpointOn(t, d.dst.s, d.r, []model.ID{diskDeviceConfig(t, cfg).Pending.DeviceID})
			}
		}
		if _, _, err := SignIn(ctx, cfg, d.srv.login(t), d.params(t)); !errors.Is(err, errTokenInvalid) {
			t.Fatalf("sign-in across the checkpoint: %v", err)
		}
		d.srv.onPost, d.r.onSince = nil, nil
		dev := diskDeviceConfig(t, cfg).Pending.DeviceID
		c := &capture{}
		p := d.params(t)
		p.Account = cloneAccountKeys(t, newAcct)
		if _, _, err := signInWith(ctx, cfg, d.srv.login(t), p, nil, c.watch); !errors.Is(err, ErrSignInRevoked) {
			t.Fatalf("retry with the device revoked: %v", err)
		}
		if len(c.states) != 0 || c.o.d != nil {
			t.Errorf("the retry decrypted %d verified states before it found the revocation", len(c.states))
		}
		if !keychainTombstone(t, cfg, d.acct.AccountID, dev) {
			t.Error("the revoked device's record is not a tombstone")
		}
		if !allZero(c.acct.Sig) || !allZero(c.dev.Sig) {
			t.Error("the refused retry left keys in memory")
		}
	})
}

// Finding 2: a revocation whose tombstone write fails is kept by the
// sign-in ledger. Every retry stops at it, while the keychain still
// refuses writes and once it works again, against a server that withholds
// the revoking checkpoint: the revoked device is never installed, and the
// tombstone is written once the keychain recovers.
func TestSignInRevocationSurvivesFailedTombstone(t *testing.T) {
	ctx := context.Background()
	t.Run("SignIn", func(t *testing.T) {
		d := newSignInFix(t)
		cfg := testConfig(t)
		ring := &readFailRing{memRing: newMemRing()}
		cfg.Keyring = ring
		withheld := 0
		var dev model.ID
		posted, done := false, false
		d.srv.onPost = func(*vaultlog.Wire) (bool, error) { posted = true; return true, nil }
		d.r.onSince = func(context.Context) {
			if posted && !done {
				done = true
				d.r.mu.Lock()
				withheld = len(d.r.entries)
				d.r.mu.Unlock()
				dev = diskDeviceConfig(t, cfg).Pending.DeviceID
				checkpointOn(t, d.dst.s, d.r, []model.ID{dev})
				ring.setFail(dev.String())
			}
		}
		_, _, err := SignIn(ctx, cfg, d.srv.login(t).lenient(), d.params(t))
		d.srv.onPost, d.r.onSince = nil, nil
		if !errors.Is(err, ErrSignInRevoked) || !errors.Is(err, ErrDeviceRevoked) {
			t.Fatalf("sign-in with the device revoked: %v", err)
		}
		if keychainTombstone(t, cfg, d.acct.AccountID, dev) {
			t.Fatal("the tombstone was written; the keychain was to refuse it")
		}
		if !ledgerOf(t, cfg).isRevoked(d.acct.AccountID, dev) {
			t.Fatal("the sign-in ledger does not record the revocation")
		}
		hidden := newFakeServer(t, d.r.prefix(withheld))
		posts := hidden.postCount()
		for _, recovered := range []bool{false, true} {
			if recovered {
				ring.setFail("")
			}
			if _, _, err := SignIn(ctx, cfg, hidden.login(t), d.params(t)); !errors.Is(err, ErrSignInRevoked) {
				t.Fatalf("retry (keychain recovered: %v) against a server that withholds the revocation: %v", recovered, err)
			}
			if _, err := tryOpen(t, cfg); !errors.Is(err, ErrNoVault) {
				t.Fatalf("open after the retry (keychain recovered: %v): %v", recovered, err)
			}
		}
		if hidden.postCount() != posts {
			t.Error("a bootstrap was posted")
		}
		if !keychainTombstone(t, cfg, d.acct.AccountID, dev) {
			t.Error("the tombstone was not written once the keychain recovered")
		}
		if got := diskDeviceConfig(t, cfg).pendingID(); got != dev {
			t.Errorf("device.json names pending device %v; want %v, the revoked one", got, dev)
		}
	})
	t.Run("merge", func(t *testing.T) {
		m, ring := mergeFixIn(t, DeviceStoreKeychain)
		s := m.src.s
		if _, err := s.MergeStart(); err != nil {
			t.Fatal(err)
		}
		withheld := 0
		var dev model.ID
		posted, done := false, false
		m.srv.onPost = func(*vaultlog.Wire) (bool, error) { posted = true; return true, nil }
		m.r.onSince = func(context.Context) {
			if posted && !done {
				done = true
				m.r.mu.Lock()
				withheld = len(m.r.entries)
				m.r.mu.Unlock()
				dev = nextOf(t, m.src.cfg).DeviceID
				checkpointOn(t, m.dst.s, m.r, []model.ID{dev})
				ring.setFail(dev.String())
			}
		}
		_, err := s.MergeSignIn(ctx, m.srv.login(t).lenient(), m.params(t))
		m.srv.onPost, m.r.onSince = nil, nil
		if !errors.Is(err, ErrSignInRevoked) {
			t.Fatalf("sign-in with the device revoked: %v", err)
		}
		next := nextOf(t, m.src.cfg)
		if nextTombstoned(t, m, next) {
			t.Fatal("the tombstone was written; the keychain was to refuse it")
		}
		if !ledgerOf(t, m.src.cfg).isRevoked(m.acct.AccountID, dev) {
			t.Fatal("the sign-in ledger does not record the revocation")
		}
		s = open(t, m.src.cfg)
		hidden := newFakeServer(t, m.r.prefix(withheld))
		posts := hidden.postCount()
		if _, err := s.MergeSignIn(ctx, hidden.login(t), m.params(t)); !errors.Is(err, ErrSignInRevoked) {
			t.Fatalf("retry against a server that withholds the revocation: %v", err)
		}
		// Cancel needs the tombstone, so no revoked record is left behind
		// untracked.
		if err := s.MergeCancel(MergeCancelOptions{}); !errors.Is(err, ErrKeyStoreUnavailable) {
			t.Fatalf("cancel while the tombstone can't be written: %v", err)
		}
		if got := nextOf(t, m.src.cfg); got.DeviceID != dev {
			t.Fatalf("device.json next %+v; want %v kept", got, dev)
		}
		ring.setFail("")
		if _, err := s.MergeSignIn(ctx, hidden.login(t), m.params(t)); !errors.Is(err, ErrSignInRevoked) {
			t.Fatalf("retry with the keychain recovered: %v", err)
		}
		if hidden.postCount() != posts {
			t.Error("a bootstrap was posted")
		}
		if !nextTombstoned(t, m, next) {
			t.Error("the tombstone was not written once the keychain recovered")
		}
		if s.ServerBacked() || s.IsRevoked() {
			t.Error("the revoked destination was installed, or the source marked revoked")
		}
		m.sourceIntact(t, s)
		if err := s.MergeCancel(MergeCancelOptions{}); err != nil {
			t.Fatalf("cancel: %v", err)
		}
		if !ledgerOf(t, m.src.cfg).isRevoked(m.acct.AccountID, dev) {
			t.Error("the revocation did not survive the cancel")
		}
		m.sourceIntact(t, s)
	})
}

// Finding 4: cancel refuses while a destination device may be enrolled
// (its record lost after its bootstrap, or a stale one), with a typed
// error that changes nothing. ForceOrphan cancels and keeps them, and the
// revoked device, in the sign-in ledger; the next merge into the same
// account carries the orphaned device forward as a stale device.
func TestMergeCancelUnresolvedDevices(t *testing.T) {
	ctx := context.Background()
	m, _ := mergeFixIn(t, DeviceStoreKeychain)
	s := m.src.s
	if _, err := s.MergeStart(); err != nil {
		t.Fatal(err)
	}
	// A bootstrap commits, its response is lost, and then its record.
	m.srv.onPost = func(*vaultlog.Wire) (bool, error) { return true, errLostResponse }
	if _, err := m.signIn(t, s); !errors.Is(err, errLostResponse) {
		t.Fatalf("sign-in: %v", err)
	}
	m.srv.onPost = nil
	lost := nextOf(t, m.src.cfg)
	if err := m.src.cfg.Keyring.Delete(keychainService, slotOf(lost.AccountID, lost.DeviceID)); err != nil {
		t.Fatal(err)
	}
	refused := func(want ...model.ID) {
		t.Helper()
		before := diskDeviceConfig(t, m.src.cfg)
		err := s.MergeCancel(MergeCancelOptions{})
		var ue *MergeUnresolvedError
		if !errors.As(err, &ue) || ue.AccountID != m.acct.AccountID || !slices.Equal(ue.Devices, want) {
			t.Fatalf("cancel with unresolved devices %v: %v", want, err)
		}
		if !errors.Is(err, ErrMergeState) {
			t.Error("a MergeUnresolvedError is not an ErrMergeState")
		}
		after := diskDeviceConfig(t, m.src.cfg)
		if !mergeFileExists(t, m.src.cfg) || after.Next == nil || after.Next.DeviceID != before.Next.DeviceID ||
			!slices.Equal(after.Next.Stale, before.Next.Stale) {
			t.Errorf("the refused cancel changed device.json (%+v, was %+v) or the merge file", after.Next, before.Next)
		}
		if _, err := s.PutSnippet(ctx, model.Snippet{Name: "x", Command: "true"}); !errors.Is(err, ErrMergeFrozen) {
			t.Errorf("a write after the refused cancel: %v", err)
		}
	}
	refused(lost.DeviceID)
	// A retry names a new device with the lost one stale, and the new one
	// is then revoked: it is resolved, the stale one is not.
	s.testHook = crashAt("signin:fetch")
	if _, err := m.signIn(t, s); !errors.Is(err, errCrash) {
		t.Fatalf("sign-in: %v", err)
	}
	s.testHook = nil
	revoked := nextOf(t, m.src.cfg)
	if !slices.Equal(revoked.Stale, []model.ID{lost.DeviceID}) {
		t.Fatalf("device.json next %+v; want %v stale", revoked, lost.DeviceID)
	}
	if err := s.nextStore(diskDeviceConfig(t, m.src.cfg)).tombstone(revoked.DeviceID); err != nil {
		t.Fatal(err)
	}
	refused(lost.DeviceID)
	if err := s.MergeCancel(MergeCancelOptions{ForceOrphan: true}); err != nil {
		t.Fatalf("cancel with ForceOrphan: %v", err)
	}
	g := ledgerOf(t, m.src.cfg)
	if !g.isRevoked(m.acct.AccountID, revoked.DeviceID) || !slices.Equal(g.orphaned(m.acct.AccountID), []model.ID{lost.DeviceID}) {
		t.Fatalf("ledger %+v; want %v revoked and %v orphaned", g.Accounts, revoked.DeviceID, lost.DeviceID)
	}
	if diskDeviceConfig(t, m.src.cfg).Next != nil || mergeFileExists(t, m.src.cfg) {
		t.Fatal("the cancel left the destination device or the merge file")
	}
	m.sourceIntact(t, s)
	// The next merge into the same account carries the orphaned device
	// forward: once installed, it is a stale device, active in the log.
	if _, err := s.MergeStart(); err != nil {
		t.Fatal(err)
	}
	if _, err := m.signIn(t, s); err != nil {
		t.Fatal(err)
	}
	dc := diskDeviceConfig(t, m.src.cfg)
	if !slices.Contains(dc.StaleDevices, lost.DeviceID) {
		t.Errorf("device.json stale %v; want %v, which a cancelled merge orphaned", dc.StaleDevices, lost.DeviceID)
	}
	if info := s.Info(); info.StaleDevices != 1 {
		t.Errorf("Info reports %d stale devices; want 1", info.StaleDevices)
	}
	if g := ledgerOf(t, m.src.cfg); len(g.orphaned(m.acct.AccountID)) != 0 || !g.isRevoked(m.acct.AccountID, revoked.DeviceID) {
		t.Errorf("ledger after the install %+v; want no orphan, the revocation kept", g.Accounts)
	}
	noUntrackedRecords(t, m.src.cfg, "after the second merge")
}

// Finding 5: a retry that reuses an earlier attempt's device stores its
// own Secret Key in the record: the account's credentials changed in
// between (SK₁ to SK₂), the retry with SK₂ succeeds, and a later password
// unlock with the stored Secret Key works.
func TestSignInRetryStoresNewSecretKey(t *testing.T) {
	ctx := context.Background()
	storedSK := func(t *testing.T, cfg Config, acct, dev model.ID) string {
		t.Helper()
		raw, err := cfg.Keyring.Get(keychainService, slotOf(acct, dev))
		if err != nil {
			t.Fatal(err)
		}
		rec, err := parseDeviceRecord([]byte(raw))
		if err != nil {
			t.Fatal(err)
		}
		defer rec.zero()
		return rec.SecretKey
	}
	t.Run("SignIn", func(t *testing.T) {
		d := newSignInFix(t)
		cfg := testConfig(t)
		if _, _, err := signIn(ctx, cfg, d.srv.login(t), d.params(t), crashAt("signin:post")); !errors.Is(err, errCrash) {
			t.Fatal(err)
		}
		dev := diskDeviceConfig(t, cfg).Pending.DeviceID
		if got := storedSK(t, cfg, d.acct.AccountID, dev); got != d.dst.kit.SecretKey {
			t.Fatal("the first attempt did not store SK₁")
		}
		acct2, sk2 := checkpointKit(t, d.dst.s, d.r, nil)
		p := d.params(t)
		p.Account, p.SecretKey = acct2, sk2
		s, _, err := SignIn(ctx, cfg, d.srv.login(t), p)
		if err != nil {
			t.Fatal(err)
		}
		track(t, cfg, s)
		if got := diskDeviceConfig(t, cfg).DeviceID; got != dev {
			t.Fatalf("installed device %v; want %v, the first attempt's", got, dev)
		}
		if got := storedSK(t, cfg, d.acct.AccountID, dev); got != sk2 {
			t.Error("the device record keeps the old Secret Key")
		}
		s.Lock()
		if err := s.UnlockWithPasswordRemote(ctx, d.r, []byte(testPassword), ""); err != nil {
			t.Fatalf("password unlock with the stored Secret Key: %v", err)
		}
	})
	t.Run("merge", func(t *testing.T) {
		m := newMergeFix(t, testConfig(t))
		s := m.src.s
		next := interruptedMerge(t, m, "signin:post")
		acct2, sk2 := checkpointKit(t, m.dst.s, m.r, nil)
		p := m.params(t)
		p.Account, p.SecretKey = acct2, sk2
		if _, err := s.MergeSignIn(ctx, m.srv.login(t), p); err != nil {
			t.Fatal(err)
		}
		if got := diskDeviceConfig(t, m.src.cfg).DeviceID; got != next.DeviceID {
			t.Fatalf("installed device %v; want %v, the first attempt's", got, next.DeviceID)
		}
		if got := storedSK(t, m.src.cfg, m.acct.AccountID, next.DeviceID); got != sk2 {
			t.Error("the device record keeps the old Secret Key")
		}
		s.Lock()
		if err := s.UnlockWithPasswordRemote(ctx, m.r, []byte(testPassword), ""); err != nil {
			t.Fatalf("password unlock with the stored Secret Key: %v", err)
		}
	})
}

// Finding 6: a sign-in that crosses a checkpoint verifies several states;
// each one a later state replaces is zeroed at once (its VK and item keys,
// and the login's account keys once the checkpoint replaces them), and
// the decoded device signing key is zeroed on failure and by a lock.
func TestMergeSignInZeroesSupersededSecrets(t *testing.T) {
	for _, crash := range []bool{true, false} {
		t.Run(map[bool]string{true: "failure", false: "installed"}[crash], func(t *testing.T) {
			m := newMergeFix(t, testConfig(t))
			s := m.src.s
			if _, err := s.MergeStart(); err != nil {
				t.Fatal(err)
			}
			posted, done := false, false
			m.srv.onPost = func(*vaultlog.Wire) (bool, error) { posted = true; return true, nil }
			m.r.onSince = func(context.Context) {
				if posted && !done {
					done = true
					checkpointOn(t, m.dst.s, m.r, nil)
				}
			}
			c := &capture{}
			var hook func(string) error
			if crash {
				hook = crashAt("signin:drop")
			}
			c.install(s, hook)
			_, err := s.MergeSignIn(context.Background(), m.srv.login(t).lenient(), m.params(t))
			m.srv.onPost, m.r.onSince = nil, nil
			if n := len(c.states); n < 3 {
				t.Fatalf("the sign-in verified %d states; want the anchor, the bootstrap and the checkpoint at least", n)
			}
			if crash {
				if !errors.Is(err, errCrash) {
					t.Fatalf("sign-in: %v", err)
				}
				c.zeroed(t, "a failure after the checkpoint")
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			n := len(c.states)
			c.supersededZeroed(t, "installed", n-1)
			last := c.states[n-1]
			if allZero(last.VK[:]) || last.Account == nil || allZero(last.Account.Sig) {
				t.Fatal("the installed state's secrets were zeroed")
			}
			if !allZero(c.acct.Sig) {
				t.Error("the login's account keys, which the checkpoint replaced, are still in memory")
			}
			s.mu.Lock()
			owned := s.sec == last && s.dev == c.dev
			s.mu.Unlock()
			if !owned || allZero(c.dev.Sig) {
				t.Fatal("the store does not hold the sign-in's device key and verified secrets")
			}
			s.Lock()
			if !allZero(c.dev.Sig) || !allZero(last.VK[:]) {
				t.Error("the lock left the device signing key or the vault key in memory")
			}
		})
	}
}
