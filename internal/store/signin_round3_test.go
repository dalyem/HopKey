package store

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/dalyem/hopkey/internal/crypto"
	"github.com/dalyem/hopkey/internal/model"
	"github.com/dalyem/hopkey/internal/vaultlog"
)

// Tests for D2's review round 3.

// revokeDuringSignIn arranges for a checkpoint that revokes the sign-in's
// device to commit right after its bootstrap, and returns a func that
// gives a server which withholds that checkpoint (the log as it was before
// it). dev names the device being enrolled.
func revokeDuringSignIn(t *testing.T, srv *fakeServer, r *fakeRemote, dst *Store, dev func() model.ID) func() *fakeServer {
	t.Helper()
	withheld := 0
	posted, done := false, false
	srv.onPost = func(*vaultlog.Wire) (bool, error) { posted = true; return true, nil }
	r.onSince = func(context.Context) {
		if posted && !done {
			done = true
			r.mu.Lock()
			withheld = len(r.entries)
			r.mu.Unlock()
			checkpointOn(t, dst, r, []model.ID{dev()})
		}
	}
	t.Cleanup(func() { srv.onPost, r.onSince = nil, nil })
	return func() *fakeServer {
		if withheld == 0 {
			t.Fatal("the revoking checkpoint was not posted yet")
		}
		return newFakeServer(t, r.prefix(withheld))
	}
}

// fileTombstone reports whether cfg's device.key holds a tombstone of
// account acct.
func fileTombstone(t *testing.T, cfg Config, acct model.ID) bool {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(cfg.DataDir, "device.key"))
	if err != nil {
		return false
	}
	tomb, ok := parseTombstone(raw)
	return ok && tomb.AccountID == acct
}

// selfTombstoned reports whether the record of device dev of account acct,
// this data directory's device, is a tombstone in cfg's device key store.
func selfTombstoned(t *testing.T, cfg Config, acct, dev model.ID) bool {
	t.Helper()
	if diskDeviceConfig(t, cfg).Store == DeviceStoreFile {
		return fileTombstone(t, cfg, acct)
	}
	return keychainTombstone(t, cfg, acct, dev)
}

// Finding 1a: a sign-in that meets the revocation of its destination
// device and is descheduled before it records it, while another goroutine
// closes the store. Close waits for the sign-in, so no other owner can
// open the vault meanwhile and finish the merge against a server that
// withholds the revocation; the revocation is recorded while this store
// still owns the vault.
func TestCloseWaitsForSignInRevocation(t *testing.T) {
	ctx := context.Background()
	m := newMergeFix(t, testConfig(t))
	s := m.src.s
	if _, err := s.MergeStart(); err != nil {
		t.Fatal(err)
	}
	hidden := revokeDuringSignIn(t, m.srv, m.r, m.dst.s, func() model.ID { return nextOf(t, m.src.cfg).DeviceID })
	draining, closed := make(chan struct{}), make(chan struct{})
	var other error
	s.testHook = func(stage string) error {
		switch stage {
		case "close:drain":
			close(draining)
		case "signin:revoking":
			go func() {
				s.Close()
				close(closed)
			}()
			select {
			case <-draining:
			case <-closed:
			}
			// A Close that does not wait gives the vault up now.
			select {
			case <-closed:
			case <-time.After(200 * time.Millisecond):
			}
			b, err := Open(ctx, m.src.cfg)
			if err == nil {
				_, serr := b.MergeSignIn(ctx, hidden().login(t), m.params(t))
				b.Close()
				other = fmt.Errorf("a second owner opened the vault during the revocation; its sign-in returned %v", serr)
			} else if !errors.Is(err, ErrVaultBusy) {
				other = fmt.Errorf("open during the revocation: %w", err)
			}
		}
		return nil
	}
	_, err := s.MergeSignIn(ctx, m.srv.login(t).lenient(), m.params(t))
	<-closed
	s.testHook = nil
	if other != nil {
		t.Fatal(other)
	}
	if !errors.Is(err, ErrSignInRevoked) {
		t.Fatalf("sign-in with the device revoked: %v", err)
	}
	next := nextOf(t, m.src.cfg)
	if !ledgerOf(t, m.src.cfg).isRevoked(m.acct.AccountID, next.DeviceID) || !nextTombstoned(t, m, next) {
		t.Fatal("the revocation was not recorded and tombstoned before the store gave the vault up")
	}
	s = open(t, m.src.cfg)
	if _, err := s.MergeSignIn(ctx, hidden().login(t), m.params(t)); !errors.Is(err, ErrSignInRevoked) {
		t.Fatalf("sign-in against a server that withholds the revocation: %v", err)
	}
	m.sourceIntact(t, s)
}

// Finding 1b: a revocation recorded after the destination was installed
// and promoted (the race above, or a crash) tombstones the record of the
// device that device.json now names as this one, and revokes the store.
func TestLateRevocationOfPromotedDestination(t *testing.T) {
	for _, store := range []string{DeviceStoreKeychain, DeviceStoreFile} {
		t.Run(store, func(t *testing.T) {
			m, _ := mergeFixIn(t, store)
			s := m.src.s
			if _, err := s.MergeStart(); err != nil {
				t.Fatal(err)
			}
			if _, err := m.signIn(t, s); err != nil {
				t.Fatal(err)
			}
			dc := diskDeviceConfig(t, m.src.cfg)
			if dc.Next != nil || dc.AccountID != m.acct.AccountID {
				t.Fatalf("device.json %+v; want the destination's, promoted", dc)
			}
			id := dc.DeviceID
			rev := &vaultlog.RevokedError{DeviceID: id, Head: vaultlog.Head{Seq: 9}}
			err := s.revokeNext(m.acct.AccountID, id, rev)
			if !errors.Is(err, ErrSignInRevoked) || !errors.Is(err, ErrDeviceRevoked) {
				t.Fatalf("late revocation: %v", err)
			}
			if !selfTombstoned(t, m.src.cfg, m.acct.AccountID, id) {
				t.Error("the promoted device's record is not a tombstone")
			}
			if !ledgerOf(t, m.src.cfg).isRevoked(m.acct.AccountID, id) {
				t.Error("the sign-in ledger does not record the revocation")
			}
			if !s.IsRevoked() || !s.Info().Locked {
				t.Error("the store is not revoked")
			}
			if s, err := tryOpen(t, m.src.cfg); err != nil || !s.Info().Revoked || !s.Info().Locked {
				t.Errorf("open after the late revocation: %v", err)
			}
		})
	}
}

// Finding 1c: a revocation that only the sign-in ledger records (its
// tombstone was never written) is enforced wherever a key is loaded or a
// destination installed: Open and the password unlock refuse the current
// or pending device, the install of SignIn and of a merge refuse, and a
// promotion revokes.
func TestLedgerRevocationIsEnforced(t *testing.T) {
	ctx := context.Background()
	revoked := func(t *testing.T, cfg Config) {
		t.Helper()
		s, err := tryOpen(t, cfg)
		if err != nil {
			t.Fatalf("open: %v", err)
		}
		if info := s.Info(); !info.Locked || !info.Revoked {
			t.Fatalf("open with the device revoked in the ledger: %+v", info)
		}
		if err := s.UnlockWithPassword(ctx, []byte(testPassword), ""); !errors.Is(err, ErrDeviceRevoked) {
			t.Errorf("password unlock: %v", err)
		}
	}
	signedIn := func(t *testing.T) (*signInFix, Config, deviceConfig) {
		t.Helper()
		d := newSignInFix(t)
		cfg := testConfig(t)
		s, _, err := SignIn(ctx, cfg, d.srv.login(t), d.params(t))
		if err != nil {
			t.Fatal(err)
		}
		track(t, cfg, s)
		release(cfg)
		return d, cfg, diskDeviceConfig(t, cfg)
	}
	t.Run("current device", func(t *testing.T) {
		d, cfg, dc := signedIn(t)
		if err := (layout{data: cfg.DataDir}).markRevoked(d.acct.AccountID, dc.DeviceID); err != nil {
			t.Fatal(err)
		}
		revoked(t, cfg)
		if !keychainTombstone(t, cfg, d.acct.AccountID, dc.DeviceID) {
			t.Error("the unlock did not write the missing tombstone")
		}
	})
	t.Run("pending device", func(t *testing.T) {
		d, cfg, dc := signedIn(t)
		pending, err := vaultlog.NewID()
		if err != nil {
			t.Fatal(err)
		}
		dc = dc.withPending(pending)
		if err := (&Store{cfg: cfg, l: layout{data: cfg.DataDir}}).writeDeviceConfig(dc); err != nil {
			t.Fatal(err)
		}
		if err := (layout{data: cfg.DataDir}).markRevoked(d.acct.AccountID, pending); err != nil {
			t.Fatal(err)
		}
		revoked(t, cfg)
	})
	t.Run("SignIn install", func(t *testing.T) {
		d := newSignInFix(t)
		cfg := testConfig(t)
		d.srv.onPost = func(*vaultlog.Wire) (bool, error) {
			return true, (layout{data: cfg.DataDir}).markRevoked(d.acct.AccountID, diskDeviceConfig(t, cfg).pendingID())
		}
		_, _, err := SignIn(ctx, cfg, d.srv.login(t), d.params(t))
		d.srv.onPost = nil
		if !errors.Is(err, ErrSignInRevoked) || !errors.Is(err, ErrDeviceRevoked) {
			t.Fatalf("sign-in with the device revoked in the ledger: %v", err)
		}
		if exists, err := Exists(cfg.DataDir); err != nil || exists {
			t.Errorf("a vault was installed (%v)", err)
		}
		if !keychainTombstone(t, cfg, d.acct.AccountID, diskDeviceConfig(t, cfg).pendingID()) {
			t.Error("the refused install did not write the tombstone")
		}
	})
	t.Run("merge install", func(t *testing.T) {
		m := newMergeFix(t, testConfig(t))
		s := m.src.s
		if _, err := s.MergeStart(); err != nil {
			t.Fatal(err)
		}
		m.srv.onPost = func(*vaultlog.Wire) (bool, error) {
			return true, (layout{data: m.src.cfg.DataDir}).markRevoked(m.acct.AccountID, nextOf(t, m.src.cfg).DeviceID)
		}
		_, err := m.signIn(t, s)
		m.srv.onPost = nil
		if !errors.Is(err, ErrSignInRevoked) {
			t.Fatalf("merge sign-in with the device revoked in the ledger: %v", err)
		}
		if !nextTombstoned(t, m, nextOf(t, m.src.cfg)) {
			t.Error("the refused install did not write the tombstone")
		}
		m.sourceIntact(t, s)
	})
	t.Run("promotion", func(t *testing.T) {
		for _, store := range []string{DeviceStoreKeychain, DeviceStoreFile} {
			t.Run(store, func(t *testing.T) {
				m, _ := mergeFixIn(t, store)
				s := m.src.s
				if _, err := s.MergeStart(); err != nil {
					t.Fatal(err)
				}
				s.testHook = crashAt("signin:promote")
				if _, err := m.signIn(t, s); !errors.Is(err, errCrash) {
					t.Fatalf("sign-in: %v", err)
				}
				s.testHook = nil
				next := nextOf(t, m.src.cfg)
				if err := (layout{data: m.src.cfg.DataDir}).markRevoked(next.AccountID, next.DeviceID); err != nil {
					t.Fatal(err)
				}
				s, err := tryOpen(t, m.src.cfg)
				if err != nil {
					t.Fatalf("open: %v", err)
				}
				if info := s.Info(); !info.Locked || !info.Revoked {
					t.Fatalf("open after a promotion of a revoked destination: %+v", info)
				}
				if !selfTombstoned(t, m.src.cfg, next.AccountID, next.DeviceID) {
					t.Error("the promoted device's record is not a tombstone")
				}
				revoked(t, m.src.cfg)
			})
		}
	})
}

// Finding 2: an ordinary SignIn, fresh or retried, carries the devices a
// cancelled merge into the account orphaned into its stale devices, so
// hop passwd revokes the active ones; the ledger forgets them only once
// device.json lists them.
func TestSignInAdoptsOrphanedDevices(t *testing.T) {
	ctx := context.Background()
	setup := func(t *testing.T) (*signInFix, Config, model.ID) {
		t.Helper()
		d := newSignInFix(t)
		// The orphan: a device enrolled in the account, active in its log.
		other := testConfig(t)
		so, _, err := SignIn(ctx, other, d.srv.login(t), d.params(t))
		if err != nil {
			t.Fatal(err)
		}
		track(t, other, so)
		return d, testConfig(t), diskDeviceConfig(t, other).DeviceID
	}
	orphan := func(t *testing.T, cfg Config, acct, id model.ID) {
		t.Helper()
		if err := os.MkdirAll(cfg.DataDir, 0o700); err != nil {
			t.Fatal(err)
		}
		l := layout{data: cfg.DataDir}
		g, err := l.readLedger()
		if err != nil {
			t.Fatal(err)
		}
		g.add(acct, nil, []model.ID{id})
		if err := l.writeLedger(g); err != nil {
			t.Fatal(err)
		}
	}
	adopted := func(t *testing.T, d *signInFix, cfg Config, s *Store, id model.ID) {
		t.Helper()
		if dc := diskDeviceConfig(t, cfg); !slices.Contains(dc.StaleDevices, id) {
			t.Errorf("device.json stale %v; want %v, which a cancelled merge orphaned", dc.StaleDevices, id)
		}
		if n := s.Info().StaleDevices; n != 1 {
			t.Errorf("Info reports %d stale devices; want 1", n)
		}
		if got := ledgerOf(t, cfg).orphaned(d.acct.AccountID); len(got) != 0 {
			t.Errorf("the ledger still holds orphans %v", got)
		}
	}
	t.Run("fresh", func(t *testing.T) {
		d, cfg, id := setup(t)
		orphan(t, cfg, d.acct.AccountID, id)
		if _, _, err := signIn(ctx, cfg, d.srv.login(t), d.params(t), crashAt("signin:record")); !errors.Is(err, errCrash) {
			t.Fatal(err)
		}
		if got := ledgerOf(t, cfg).orphaned(d.acct.AccountID); !slices.Equal(got, []model.ID{id}) {
			t.Fatalf("a sign-in that wrote no device.json cleared the orphans (%v)", got)
		}
		s, _, err := SignIn(ctx, cfg, d.srv.login(t), d.params(t))
		if err != nil {
			t.Fatal(err)
		}
		track(t, cfg, s)
		adopted(t, d, cfg, s, id)
	})
	t.Run("retry", func(t *testing.T) {
		d, cfg, id := setup(t)
		if _, _, err := signIn(ctx, cfg, d.srv.login(t), d.params(t), crashAt("signin:post")); !errors.Is(err, errCrash) {
			t.Fatal(err)
		}
		orphan(t, cfg, d.acct.AccountID, id)
		s, _, err := SignIn(ctx, cfg, d.srv.login(t), d.params(t))
		if err != nil {
			t.Fatal(err)
		}
		track(t, cfg, s)
		adopted(t, d, cfg, s, id)
	})
}

// Finding 3: a sign-in ledger that does not parse fails closed everywhere:
// a fresh sign-in, the retry of one an earlier attempt installed, the
// recovery of an interrupted merge, and Open and the unlocks.
func TestMalformedLedgerFailsClosed(t *testing.T) {
	ctx := context.Background()
	corrupt := func(t *testing.T, cfg Config) {
		t.Helper()
		if err := os.MkdirAll(cfg.DataDir, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(cfg.DataDir, ledgerRel), []byte(`{"v":1,"accounts":[`), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	t.Run("fresh sign-in", func(t *testing.T) {
		d := newSignInFix(t)
		cfg := testConfig(t)
		corrupt(t, cfg)
		posts := d.srv.postCount()
		if _, _, err := SignIn(ctx, cfg, d.srv.login(t), d.params(t)); !errors.Is(err, ErrCorrupt) {
			t.Fatalf("sign-in: %v", err)
		}
		if _, err := os.Stat(filepath.Join(cfg.DataDir, "device.json")); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("the refused sign-in wrote device.json (%v)", err)
		}
		if d.srv.postCount() != posts {
			t.Error("a bootstrap was posted")
		}
	})
	t.Run("installed retry", func(t *testing.T) {
		d := newSignInFix(t)
		cfg := testConfig(t)
		s, _, err := SignIn(ctx, cfg, d.srv.login(t), d.params(t))
		if err != nil {
			t.Fatal(err)
		}
		track(t, cfg, s)
		release(cfg)
		corrupt(t, cfg)
		if s, _, err := SignIn(ctx, cfg, d.srv.login(t), d.params(t)); !errors.Is(err, ErrCorrupt) {
			if err == nil {
				track(t, cfg, s)
			}
			t.Fatalf("sign-in again over the installed vault: %v", err)
		}
	})
	t.Run("interrupted merge", func(t *testing.T) {
		m := newMergeFix(t, testConfig(t))
		s := m.src.s
		if _, err := s.MergeStart(); err != nil {
			t.Fatal(err)
		}
		s.testHook = crashAt("signin:promote")
		if _, err := m.signIn(t, s); !errors.Is(err, errCrash) {
			t.Fatalf("sign-in: %v", err)
		}
		s.testHook = nil
		release(m.src.cfg)
		corrupt(t, m.src.cfg)
		if _, err := tryOpen(t, m.src.cfg); !errors.Is(err, ErrCorrupt) {
			t.Fatalf("open: %v", err)
		}
		if diskDeviceConfig(t, m.src.cfg).Next == nil {
			t.Error("the destination was promoted over a ledger that does not parse")
		}
	})
	t.Run("Open", func(t *testing.T) {
		f := newVault(t, testConfig(t))
		corrupt(t, f.cfg)
		f.s.Lock()
		if err := f.s.Unlock(ctx); !errors.Is(err, ErrCorrupt) {
			t.Errorf("unlock: %v", err)
		}
		if err := f.s.UnlockWithPassword(ctx, []byte(testPassword), f.kit.SecretKey); !errors.Is(err, ErrCorrupt) {
			t.Errorf("password unlock: %v", err)
		}
		if _, err := tryOpen(t, f.cfg); !errors.Is(err, ErrCorrupt) {
			t.Errorf("open: %v", err)
		}
	})
}

// A destination whose newest anchor lists the enrolling device as active
// with other keys than its record's is refused at the anchor's public
// stage, before anything is decrypted.
func TestSignInAnchorKeyMismatch(t *testing.T) {
	ctx := context.Background()
	d := newSignInFix(t)
	cfg := testConfig(t)
	if _, _, err := signIn(ctx, cfg, d.srv.login(t), d.params(t), crashAt("signin:post")); !errors.Is(err, errCrash) {
		t.Fatal(err)
	}
	id := diskDeviceConfig(t, cfg).Pending.DeviceID
	// Another device's keys, under the pending device's ID.
	impostor, info, err := newDeviceRecord(d.acct.AccountID, d.dst.kit.SecretKey)
	if err != nil {
		t.Fatal(err)
	}
	defer impostor.zero()
	info.ID, info.Name = id, "impostor"
	s := d.dst.s
	pull(t, s, d.r)
	s.mu.Lock()
	w, _, _, err := vaultlog.BuildBootstrap(s.state, s.sec, info, s.now())
	s.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := d.r.Post(ctx, w); err != nil {
		t.Fatal(err)
	}
	// A checkpoint makes the impostor part of the newest anchor.
	acct, sk := checkpointKit(t, s, d.r, nil)
	c := &capture{}
	p := d.params(t)
	p.Account, p.SecretKey = acct, sk
	if _, _, err := signInWith(ctx, cfg, d.srv.login(t), p, nil, c.watch); !errors.Is(err, ErrDeviceKey) {
		t.Fatalf("sign-in with the anchor listing other keys: %v", err)
	}
	if len(c.states) != 0 {
		t.Errorf("the sign-in decrypted %d verified states before it found the mismatch", len(c.states))
	}
}

// deviceInfo zeroes the device keys it decodes, and the public keys it
// returns survive that.
func TestDeviceInfoZeroesDecodedKeys(t *testing.T) {
	acct, err := vaultlog.NewID()
	if err != nil {
		t.Fatal(err)
	}
	sk, err := crypto.NewSecretKey()
	if err != nil {
		t.Fatal(err)
	}
	rec, _, err := newDeviceRecord(acct, sk.String())
	if err != nil {
		t.Fatal(err)
	}
	defer rec.zero()
	want, err := rec.device()
	if err != nil {
		t.Fatal(err)
	}
	defer zeroDevice(want)
	var seen *vaultlog.LocalDevice
	info, err := deviceInfoWith(rec, "laptop", func(d *vaultlog.LocalDevice) { seen = d })
	if err != nil {
		t.Fatal(err)
	}
	if seen == nil || !allZero(seen.Sig) {
		t.Error("the decoded signing key is still in memory")
	}
	if !bytes.Equal(info.SigPK, want.Sig.Public().(ed25519.PublicKey)) || !bytes.Equal(info.KEMPK, want.KEM.PublicKey().Bytes()) {
		t.Error("the public keys returned are not the device's")
	}
	if info.ID != rec.DeviceID || info.Name != "laptop" {
		t.Errorf("device info %v %q", info.ID, info.Name)
	}
}

// The diagnostic of a revocation a retry learns from the newest anchor's
// retired list names the anchor, not a revoking checkpoint it never saw.
func TestSignInRevokedAtAnchorDiagnostic(t *testing.T) {
	ctx := context.Background()
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
	head := d.r.head().Seq
	p := d.params(t)
	p.Account = cloneAccountKeys(t, newAcct)
	_, _, err := SignIn(ctx, cfg, d.srv.login(t), p)
	if !errors.Is(err, ErrSignInRevoked) {
		t.Fatalf("retry with the device revoked: %v", err)
	}
	if want := fmt.Sprintf("known retired at anchor seq %d", head); !strings.Contains(err.Error(), want) {
		t.Errorf("diagnostic %q; want it to say %q", err, want)
	}
}
