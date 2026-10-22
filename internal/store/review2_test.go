package store

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/zalando/go-keyring"

	"github.com/dalyem/hopkey/internal/model"
)

// serverVaultIn is serverVault with the device key in deviceStore (an
// unsealed file for DeviceStoreFile).
func serverVaultIn(t *testing.T, deviceStore string) (*fixture, *fakeRemote) {
	t.Helper()
	cfg := testConfig(t)
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

// recordGone reports whether the device key store of f holds no record.
func recordGone(t *testing.T, f *fixture, deviceStore string) bool {
	t.Helper()
	if deviceStore == DeviceStoreFile {
		_, err := os.Stat(filepath.Join(f.cfg.DataDir, "device.key"))
		return errors.Is(err, os.ErrNotExist)
	}
	_, err := f.cfg.Keyring.Get(keychainService, "device:"+f.kit.AccountID)
	return errors.Is(err, keyring.ErrNotFound)
}

func revokedFileExists(t *testing.T, cfg Config) bool {
	t.Helper()
	_, err := os.Stat(filepath.Join(cfg.DataDir, "vault", "revoked.json"))
	return err == nil
}

// Round 2, finding 1 (store side): the Revoked channel closes when a pull
// meets the revoking checkpoint, and is closed at once for a vault opened
// revoked.
func TestRevokedChannel(t *testing.T) {
	ctx := context.Background()
	p := newPair(t)
	a := p.a.s
	ch := a.Revoked()
	select {
	case <-ch:
		t.Fatal("closed before any revocation")
	default:
	}
	revokeOn(t, p.b.s, p.r, deviceOf(a))
	if err := a.Pull(ctx, p.r); !errors.Is(err, ErrDeviceRevoked) {
		t.Fatalf("pull: %v", err)
	}
	select {
	case <-ch:
	default:
		t.Error("the channel is open after the revocation")
	}
	s, err := tryOpen(t, p.a.cfg)
	if err != nil {
		t.Fatal(err)
	}
	select {
	case <-s.Revoked():
	default:
		t.Error("the channel of a vault opened revoked is open")
	}
}

// Round 2, finding 2: a password unlock through the server meets a
// checkpoint that revokes this device in the public stage. The device is
// revoked for good, as a pull would revoke it, and nothing is posted,
// decrypted or saved.
func TestPasswordUnlockMeetsTheRevocationOfThisDevice(t *testing.T) {
	for _, keyLost := range []bool{true, false} {
		name := "device key readable"
		if keyLost {
			name = "device key lost"
		}
		t.Run(name, func(t *testing.T) {
			ctx := context.Background()
			p := newPair(t)
			a := p.a.s
			before := stateHead(t, p.a.cfg)
			revokeOn(t, p.b.s, p.r, deviceOf(a))
			rseq := p.r.head().Seq
			a.Lock()
			if keyLost {
				p.a.cfg.Keyring.(*memRing).clear()
			}
			posts := p.r.postCount()

			if err := a.UnlockWithPasswordRemote(ctx, p.r, []byte(testPassword), p.a.kit.SecretKey); !errors.Is(err, ErrDeviceRevoked) {
				t.Fatalf("password unlock across a checkpoint that revokes this device: %v", err)
			}
			if n := p.r.postCount(); n != posts {
				t.Errorf("%d bootstrap entries posted", n-posts)
			}
			if info := a.Info(); !info.Locked || !info.Revoked {
				t.Errorf("info %+v", info)
			}
			if !revokedFileExists(t, p.a.cfg) {
				t.Error("the revocation was not recorded")
			}
			if got := stateHead(t, p.a.cfg); got.Seq != before.Seq {
				t.Errorf("the head moved from %d to %d (the checkpoint is %d)", before.Seq, got.Seq, rseq)
			}
			if _, err := os.Stat(a.l.entryFile(rseq)); !errors.Is(err, os.ErrNotExist) {
				t.Errorf("the revoking checkpoint was written: %v", err)
			}
			if !recordGone(t, p.a, DeviceStoreKeychain) {
				t.Error("the revoked device's record is still in the keychain")
			}
			s, err := tryOpen(t, p.a.cfg)
			if err != nil {
				t.Fatal(err)
			}
			if err := s.UnlockWithPasswordRemote(ctx, p.r, []byte(testPassword), p.a.kit.SecretKey); !errors.Is(err, ErrDeviceRevoked) {
				t.Errorf("password unlock after a restart: %v", err)
			}
		})
	}
}

// Round 2, finding 3: a password unlock through the server runs only on a
// locked vault. On an unlocked one it is refused before anything is read,
// written or posted.
func TestRemotePasswordUnlockNeedsALockedVault(t *testing.T) {
	ctx := context.Background()
	f, r := serverVault(t)
	s := f.s
	_, h := addHost(t, s, "web")
	pushAll(t, s, r)
	dev, head, posts := deviceOf(s), stateHead(t, f.cfg), r.postCount()
	devJSON := readFile(t, filepath.Join(f.cfg.DataDir, "device.json"))

	if err := s.UnlockWithPasswordRemote(ctx, r, []byte(testPassword), ""); !errors.Is(err, ErrAlreadyUnlocked) {
		t.Fatalf("on an unlocked vault: %v", err)
	}
	if deviceOf(s) != dev || r.postCount() != posts || stateHead(t, f.cfg) != head {
		t.Error("the refused password unlock changed the device, the server or the log")
	}
	if got := readFile(t, filepath.Join(f.cfg.DataDir, "device.json")); got != devJSON {
		t.Error("the refused password unlock rewrote device.json")
	}
	if _, ok := hostByID(t, s, h.ItemID); !ok {
		t.Error("the store is no longer usable")
	}

	s.Lock()
	if err := s.UnlockWithPasswordRemote(ctx, r, []byte(testPassword), ""); err != nil {
		t.Fatalf("on the locked vault: %v", err)
	}
	if deviceOf(s) == dev {
		t.Error("the password unlock kept the old device")
	}
}

// Round 2, finding 4: a revocation deletes the device record whether or not
// revoked.json could be written. Without the marker an Open stays locked,
// and the server path meets the revocation again and records it.
func TestRevocationDestroysTheDeviceRecord(t *testing.T) {
	for _, deviceStore := range []string{DeviceStoreKeychain, DeviceStoreFile} {
		for _, markerFails := range []bool{false, true} {
			name := deviceStore + "/marker written"
			if markerFails {
				name = deviceStore + "/marker failed"
			}
			t.Run(name, func(t *testing.T) {
				ctx := context.Background()
				f, r := serverVaultIn(t, deviceStore)
				addHost(t, f.s, "web")
				pushAll(t, f.s, r)
				b := secondDevice(t, f, r)
				revokeOn(t, b.s, r, deviceOf(f.s))
				if markerFails {
					f.s.testHook = crashAt("revoke:marker")
				}

				err := f.s.Pull(ctx, r)
				if !errors.Is(err, ErrDeviceRevoked) {
					t.Fatalf("pull: %v", err)
				}
				if markerFails != strings.Contains(err.Error(), "recording it on disk failed") {
					t.Errorf("the marker's failure is not reported right: %v", err)
				}
				if there := revokedFileExists(t, f.cfg); there == markerFails {
					t.Errorf("revoked.json there: %v", there)
				}
				if !recordGone(t, f, deviceStore) {
					t.Fatal("the device record survived the revocation")
				}

				s, err := tryOpen(t, f.cfg)
				if err != nil {
					t.Fatalf("open: %v", err)
				}
				if _, err := s.Snapshot(ctx); err == nil {
					t.Fatal("the vault of a revoked device unlocked after a restart")
				}
				if markerFails {
					if err := s.Unlock(ctx); !errors.Is(err, ErrDeviceKey) {
						t.Errorf("unlock without the marker: %v", err)
					}
					if err := s.UnlockWithPassword(ctx, []byte(testPassword), f.kit.SecretKey); !errors.Is(err, ErrServerBacked) {
						t.Errorf("local password unlock: %v", err)
					}
					if err := s.UnlockWithPasswordRemote(ctx, r, []byte(testPassword), f.kit.SecretKey); !errors.Is(err, ErrDeviceRevoked) {
						t.Errorf("password unlock through the server: %v", err)
					}
					if !revokedFileExists(t, f.cfg) {
						t.Error("meeting the revocation again did not record it")
					}
				} else if err := s.Unlock(ctx); !errors.Is(err, ErrDeviceRevoked) {
					t.Errorf("unlock: %v", err)
				}
				if info := s.Info(); !info.Locked {
					t.Errorf("info %+v", info)
				}
			})
		}
	}
}

// Round 2, finding 5: a password unlock through the server fails closed
// when settling the outbox fails, in the catch-up before the new record is
// saved and in the unlock that follows it.
func TestRemotePasswordUnlockFailsClosedOnASettlementError(t *testing.T) {
	for _, phase := range []string{"catch-up", "finish"} {
		t.Run(phase, func(t *testing.T) {
			ctx := context.Background()
			f, r := serverVault(t)
			s := f.s
			oldDev := deviceOf(s)
			s.Lock()
			corrupt := func() error {
				return os.WriteFile(filepath.Join(f.cfg.DataDir, "vault", "outbox", "1.json"), []byte("{}"), 0o600)
			}
			if phase == "catch-up" {
				if err := corrupt(); err != nil {
					t.Fatal(err)
				}
			} else {
				s.testHook = func(stage string) error {
					if stage == "passwd:save" {
						return corrupt()
					}
					return nil
				}
			}
			if err := s.UnlockWithPasswordRemote(ctx, r, []byte(testPassword), ""); !errors.Is(err, ErrCorrupt) {
				t.Errorf("password unlock: %v", err)
			}
			if _, err := s.Snapshot(ctx); !errors.Is(err, model.ErrLocked) {
				t.Errorf("a password unlock that could not settle the outbox left the store unlocked: %v", err)
			}
			if phase == "catch-up" {
				if stored := storedRecord(t, f.cfg, f.kit.AccountID); stored.DeviceID != oldDev {
					t.Error("the new device record was saved")
				}
			}
			if _, err := tryOpen(t, f.cfg); !errors.Is(err, ErrCorrupt) {
				t.Errorf("open: %v", err)
			}
		})
	}
}

// Round 2, finding 6: a replay makes the journal durable before it applies
// anything. Here the journal of the lost records is renamed into place but
// its directory fsync fails; the next unlock fails to make it durable and
// stays locked with nothing applied; the one after is interrupted halfway;
// the last one fsyncs the journal first, finishes it, and counts the loss
// once.
func TestWALReplayMakesTheJournalDurableFirst(t *testing.T) {
	ctx := context.Background()
	f, r := serverVault(t)
	addHost(t, f.s, "web") // two records
	f.cfg.Keyring.(*memRing).clear()
	s := open(t, f.cfg)
	unlock := func(stage string) error {
		t.Helper()
		s.testHook = crashAt(stage)
		return s.UnlockWithPasswordRemote(ctx, r, []byte(testPassword), f.kit.SecretKey)
	}
	stillLocked := func(when string, records int) {
		t.Helper()
		if _, err := s.Snapshot(ctx); !errors.Is(err, model.ErrLocked) {
			t.Errorf("%s: the store is unlocked: %v", when, err)
		}
		if !walExists(t, f.cfg) {
			t.Errorf("%s: the journal is gone", when)
		}
		if got := len(outboxFiles(t, f.cfg.DataDir)); got != records {
			t.Errorf("%s: %d records, want %d", when, got, records)
		}
	}

	if err := unlock("wal:install:sync"); !errors.Is(err, errCrash) {
		t.Fatalf("the journal's directory fsync failing: %v", err)
	}
	stillLocked("after the install", 2)
	if err := unlock("wal:replay:sync"); !errors.Is(err, errCrash) {
		t.Fatalf("the replay's fsync failing: %v", err)
	}
	stillLocked("after the failed fsync before the replay", 2)
	if err := unlock("wal:op:1"); !errors.Is(err, errCrash) {
		t.Fatalf("a crash during the replay: %v", err)
	}
	stillLocked("after the interrupted replay", 1)

	var mu sync.Mutex
	var events []string
	note := func(e string) {
		mu.Lock()
		events = append(events, e)
		mu.Unlock()
	}
	syncDir = func(dir string) error {
		note("dir " + dir)
		return fsyncDir(dir)
	}
	syncFile = func(p string) error {
		note("file " + p)
		return fsyncFile(p)
	}
	t.Cleanup(func() { syncDir, syncFile = fsyncDir, fsyncFile })
	s.testHook = func(stage string) error {
		note(stage)
		return nil
	}
	if err := s.UnlockWithPasswordRemote(ctx, r, []byte(testPassword), f.kit.SecretKey); err != nil {
		t.Fatal(err)
	}
	syncDir, syncFile = fsyncDir, fsyncFile
	journal, vault := slices.Index(events, "file "+s.l.walFile()), slices.Index(events, "dir "+s.l.vault())
	first := slices.Index(events, "wal:op:0")
	if journal < 0 || vault < 0 || first < 0 || journal > first || vault > first {
		t.Errorf("the journal and vault/ were not fsynced before the first operation: %q", events)
	}
	if walExists(t, f.cfg) || len(outboxFiles(t, f.cfg.DataDir)) != 0 {
		t.Error("the replay did not finish")
	}
	if lost, err := s.LostIntents(); err != nil || lost != 2 {
		t.Errorf("lost %d, %v; want 2", lost, err)
	}
}
