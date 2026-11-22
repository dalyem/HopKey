package store

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/dalyem/hopkey/internal/canonjson"
	"github.com/dalyem/hopkey/internal/crypto"
	"github.com/dalyem/hopkey/internal/model"
	"github.com/dalyem/hopkey/internal/vaultlog"
)

// retireFixture is a server-backed vault with a host, its outbox pushed,
// on a fake server where its device has a session.
func retireFixture(t *testing.T) (*fixture, *fakeServer) {
	t.Helper()
	f, r := serverVault(t)
	addHost(t, f.s, "web")
	if res := pushAll(t, f.s, r); res.Outcome != PushEmpty {
		t.Fatalf("push: %+v", res)
	}
	return f, newFakeServer(t, r)
}

type ids struct{ acct, dev model.ID }

func idsOf(t *testing.T, cfg Config) ids {
	t.Helper()
	dc := diskDeviceConfig(t, cfg)
	return ids{dc.AccountID, dc.DeviceID}
}

// loggedOut requires nothing of the vault to be left: no device record in
// the keychain, no device.json or device.key, only the locks in vault/, and
// Open finds no vault.
func loggedOut(t *testing.T, cfg Config, who ids) {
	t.Helper()
	if _, err := cfg.Keyring.Get(keychainService, slotOf(who.acct, who.dev)); err == nil {
		t.Error("the device record is still in the keychain")
	}
	for _, name := range []string{"device.json", "device.key"} {
		if _, err := os.Stat(filepath.Join(cfg.DataDir, name)); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("%s is still there: %v", name, err)
		}
	}
	ents, err := os.ReadDir(filepath.Join(cfg.DataDir, "vault"))
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range ents {
		if e.Name() != "lock" && e.Name() != "owner.lock" {
			t.Errorf("vault/%s is still there", e.Name())
		}
	}
	if _, err := tryOpen(t, cfg); !errors.Is(err, ErrNoVault) {
		t.Errorf("open after the logout: %v; want ErrNoVault", err)
	}
	// The ssh config is the caller's to empty, and stays owed until it
	// says it has.
	if pending, err := LogoutCleanupPending(cfg.DataDir); err != nil || !pending {
		t.Errorf("the cleanup outside the store is not marked as owed: %v %v", pending, err)
	}
	if err := ClearLogoutCleanup(cfg.DataDir); err != nil {
		t.Fatal(err)
	}
	if pending, err := LogoutCleanupPending(cfg.DataDir); err != nil || pending {
		t.Errorf("still owed after ClearLogoutCleanup: %v %v", pending, err)
	}
}

// retiredOnServer reports how the server says dev left, or "".
func retiredOnServer(t *testing.T, srv *fakeServer, dev model.ID) string {
	t.Helper()
	pub, _, receipts := srv.public(t)
	if pub.DeviceActive(dev) {
		return ""
	}
	return receipts[dev].How
}

func readRetire(t *testing.T, cfg Config) *retireJournal {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(cfg.DataDir, "vault", retireRel))
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		t.Fatal(err)
	}
	var j retireJournal
	if err := canonjson.Unmarshal(b, &j); err != nil {
		t.Fatal(err)
	}
	return &j
}

// §11.1: logout journals the exact device_retire wire, posts it, and once
// retire-status (the session has ended) or verified history shows it
// committed, records RETIRED and deletes the outbox, the cache and the
// device record.
func TestLogoutRetiresThisDevice(t *testing.T) {
	ctx := context.Background()
	f, srv := retireFixture(t)
	who := idsOf(t, f.cfg)
	res, err := f.s.Logout(ctx, retirer{srv}, LogoutOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if !res.Done || res.State != StateRetired || res.Outcome != OutcomeCommitted || res.RevokeElsewhere {
		t.Errorf("result %+v", res)
	}
	if how := retiredOnServer(t, srv, who.dev); how != "retired" {
		t.Errorf("the server says %q", how)
	}
	if srv.hasSession(who.dev) {
		t.Error("the device still has a session")
	}
	if srv.statusCalls == 0 {
		t.Error("the outcome did not come from retire-status once the session ended")
	}
	if !f.s.Info().Locked {
		t.Error("the store is unlocked after logout")
	}
	loggedOut(t, f.cfg, who)
}

// §13: a crash at each retirement-journal state. RETIRING never unlocks
// the vault and resumes its resolution; RETIRED resumes its cleanup at
// Open. The device record is deleted only after RETIRED.
func TestLogoutCrashAtEachState(t *testing.T) {
	type crash struct {
		name string
		hook func(string) error
	}
	var crashes []crash
	for _, st := range []string{"wal:before", "wal:install", "wal:install:sync", "wal:op:0", "wal:op:0:sync", "wal:removed",
		"retire:since", "retire:post", "retire:status", "retire:record", "retire:outbox", "retire:cache", "retire:device", "retire:journal"} {
		crashes = append(crashes, crash{st, crashAt(st)})
	}
	crashes = append(crashes,
		crash{"since after the post", crashAfter("retire:post", "retire:since")},
		crash{"RETIRED wal:install:sync", crashAfter("retire:record", "wal:install:sync")},
		crash{"RETIRED wal:op:0", crashAfter("retire:record", "wal:op:0")})
	for _, c := range crashes {
		t.Run(c.name, func(t *testing.T) {
			ctx := context.Background()
			f, srv := retireFixture(t)
			who := idsOf(t, f.cfg)
			f.s.testHook = c.hook
			if _, err := f.s.Logout(ctx, retirer{srv}, LogoutOptions{}); !errors.Is(err, errCrash) {
				t.Fatalf("logout: %v", err)
			}
			j := readRetire(t, f.cfg)
			if j == nil || j.State == StateRetiring {
				if _, err := f.cfg.Keyring.Get(keychainService, slotOf(who.acct, who.dev)); err != nil {
					t.Errorf("the device record is gone before RETIRED: %v", err)
				}
			}
			s, err := tryOpen(t, f.cfg)
			if errors.Is(err, ErrLoggedOut) {
				if j == nil {
					t.Error("Open finished a logout that was never journaled")
				}
				loggedOut(t, f.cfg, who)
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			state, err := s.Retirement()
			if err != nil {
				t.Fatal(err)
			}
			switch state {
			case "":
				// Nothing was journaled: the vault is as it was.
				if s.Info().Locked {
					t.Error("locked with no retirement journal")
				}
			case StateRetiring:
				if !s.Info().Locked {
					t.Error("RETIRING opened unlocked")
				}
				if err := s.Unlock(ctx); !errors.Is(err, ErrLoggingOut) {
					t.Errorf("unlock while RETIRING: %v", err)
				}
				if err := s.UnlockWithPassword(ctx, []byte(testPassword), f.kit.SecretKey); !errors.Is(err, ErrLoggingOut) {
					t.Errorf("password unlock while RETIRING: %v", err)
				}
				if _, err := s.Snapshot(ctx); err == nil {
					t.Error("a snapshot while RETIRING")
				}
			default:
				t.Fatalf("Open left %s", state)
			}
			res, err := s.Logout(ctx, retirer{srv}, LogoutOptions{})
			if err != nil {
				t.Fatal(err)
			}
			if !res.Done || res.Outcome != OutcomeCommitted {
				t.Errorf("result %+v", res)
			}
			if how := retiredOnServer(t, srv, who.dev); how != "retired" {
				t.Errorf("the server says %q", how)
			}
			loggedOut(t, f.cfg, who)
		})
	}
}

// checkpointBy builds a checkpoint on s's verified state with new
// credentials, revoking revoke, as another device's hop auth rotate would.
func checkpointBy(t *testing.T, s *Store, revoke []model.ID) *vaultlog.Wire {
	t.Helper()
	s.mu.Lock()
	defer s.mu.Unlock()
	sk, err := crypto.NewSecretKey()
	if err != nil {
		t.Fatal(err)
	}
	rk, err := crypto.NewRecoveryKey()
	if err != nil {
		t.Fatal(err)
	}
	acct, err := crypto.GenerateAccountKeys(s.state.Account.AccountID, s.state.Account.AKV+1)
	if err != nil {
		t.Fatal(err)
	}
	creds, err := newCreds([]byte(newPassword), &sk, &rk, acct)
	if err != nil {
		t.Fatal(err)
	}
	vk, err := crypto.NewSymKey()
	if err != nil {
		t.Fatal(err)
	}
	w, _, _, err := vaultlog.BuildCheckpoint(s.state, s.sec, s.dev, vaultlog.CheckpointParams{
		NewAccount: acct, NewVK: vk, Creds: creds, Time: s.now(), Revoke: revoke,
	})
	if err != nil {
		t.Fatal(err)
	}
	return w
}

// §13: retirement status for a long-retired device, and for a revoked one.
func TestRetireStatusLongRetiredAndRevoked(t *testing.T) {
	ctx := context.Background()
	t.Run("long retired", func(t *testing.T) {
		p := newPair(t)
		srv := newFakeServer(t, p.r)
		who := idsOf(t, p.a.cfg)
		// The retirement commits, and the device stops before it learns so.
		p.a.s.testHook = crashAfter("retire:post", "retire:since")
		if _, err := p.a.s.Logout(ctx, retirer{srv}, LogoutOptions{}); !errors.Is(err, errCrash) {
			t.Fatal(err)
		}
		if how := retiredOnServer(t, srv, who.dev); how != "retired" {
			t.Fatalf("the server says %q", how)
		}
		// Long after, the account has moved on.
		for i := range 3 {
			editHost(t, p.b.s, p.host.ItemID, func(h *model.Host) { h.Description = strings.Repeat("x", i+1) })
			if res := pushAll(t, p.b.s, p.r); res.Outcome != PushEmpty {
				t.Fatalf("B's push: %+v", res)
			}
		}
		s, err := tryOpen(t, p.a.cfg)
		if err != nil {
			t.Fatal(err)
		}
		res, err := s.Logout(ctx, retirer{srv}, LogoutOptions{})
		if err != nil {
			t.Fatal(err)
		}
		if res.Outcome != OutcomeCommitted || !res.Done || srv.statusCalls == 0 {
			t.Errorf("result %+v after %d status calls", res, srv.statusCalls)
		}
		loggedOut(t, p.a.cfg, who)
	})
	t.Run("revoked", func(t *testing.T) {
		p := newPair(t)
		srv := newFakeServer(t, p.r)
		who := idsOf(t, p.a.cfg)
		// RETIRING is journaled but never posted; meanwhile B's checkpoint
		// revokes A, which ends every session.
		p.a.s.testHook = crashAt("retire:post")
		if _, err := p.a.s.Logout(ctx, retirer{srv}, LogoutOptions{}); !errors.Is(err, errCrash) {
			t.Fatal(err)
		}
		pull(t, p.b.s, p.r)
		if _, err := srv.commitEnding(checkpointBy(t, p.b.s, []model.ID{who.dev})); err != nil {
			t.Fatal(err)
		}
		s, err := tryOpen(t, p.a.cfg)
		if err != nil {
			t.Fatal(err)
		}
		res, err := s.Logout(ctx, retirer{srv}, LogoutOptions{})
		if err != nil {
			t.Fatal(err)
		}
		if res.Outcome != OutcomeDeparted || !res.Done {
			t.Errorf("result %+v", res)
		}
		if how := retiredOnServer(t, srv, who.dev); how != "revoked" {
			t.Errorf("the server says %q", how)
		}
		loggedOut(t, p.a.cfg, who)
	})
}

// §13: a retry after a checkpoint ended every session. The candidate died
// when the checkpoint took its seq; the device is still active, so it
// reauthenticates, catches up across the checkpoint (opening its new unlock
// blob), journals a rebuilt candidate and retires.
func TestLogoutRetryAfterCheckpointEndedSessions(t *testing.T) {
	ctx := context.Background()
	p := newPair(t)
	srv := newFakeServer(t, p.r)
	who := idsOf(t, p.a.cfg)
	p.a.s.testHook = crashAt("retire:post")
	if _, err := p.a.s.Logout(ctx, retirer{srv}, LogoutOptions{}); !errors.Is(err, errCrash) {
		t.Fatal(err)
	}
	first := readRetire(t, p.a.cfg).live()
	pull(t, p.b.s, p.r)
	cp := checkpointBy(t, p.b.s, nil)
	if _, err := srv.commitEnding(cp); err != nil {
		t.Fatal(err)
	}
	if srv.hasSession(who.dev) {
		t.Fatal("the checkpoint did not end A's session")
	}
	s, err := tryOpen(t, p.a.cfg)
	if err != nil {
		t.Fatal(err)
	}
	s.testHook = crashAt("retire:rebuilt")
	if _, err := s.Logout(ctx, retirer{srv}, LogoutOptions{}); !errors.Is(err, errCrash) {
		t.Fatalf("logout: %v", err)
	}
	j := readRetire(t, p.a.cfg)
	if len(j.Candidates) != 2 || j.Candidates[0].Status != statusDead || j.Candidates[1].Status != statusLive ||
		j.Candidates[1].Seq != cp.Entry.Seq+1 {
		t.Fatalf("candidates %+v; want the first dead and a rebuilt one after the checkpoint", j.Candidates)
	}
	s, err = tryOpen(t, p.a.cfg)
	if err != nil {
		t.Fatal(err)
	}
	res, err := s.Logout(ctx, retirer{srv}, LogoutOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if res.Outcome != OutcomeCommitted || !res.Done {
		t.Errorf("result %+v", res)
	}
	if srv.committed(first.H) {
		t.Error("the dead candidate committed")
	}
	if how := retiredOnServer(t, srv, who.dev); how != "retired" {
		t.Errorf("the server says %q", how)
	}
	loggedOut(t, p.a.cfg, who)
}

// §13: --local-only skips the server: RETIRED with the outcome unknown,
// cleaned up, and the device is still listed until revoked elsewhere. It
// also finishes a RETIRING logout whose server is gone.
func TestLogoutLocalOnly(t *testing.T) {
	ctx := context.Background()
	f, srv := retireFixture(t)
	who := idsOf(t, f.cfg)
	posts := srv.postCount()
	res, err := f.s.Logout(ctx, nil, LogoutOptions{LocalOnly: true})
	if err != nil {
		t.Fatal(err)
	}
	if !res.Done || res.Outcome != OutcomeUnknown || !res.RevokeElsewhere {
		t.Errorf("result %+v", res)
	}
	if srv.postCount() != posts {
		t.Error("--local-only posted to the server")
	}
	if how := retiredOnServer(t, srv, who.dev); how != "" {
		t.Errorf("the server says %q; --local-only must not reach it", how)
	}
	loggedOut(t, f.cfg, who)

	g, srv2 := retireFixture(t)
	who = idsOf(t, g.cfg)
	srv2.down = errDown
	res, err = g.s.Logout(ctx, retirer{srv2}, LogoutOptions{})
	if !errors.Is(err, ErrLogoutPending) || res.State != StateRetiring {
		t.Fatalf("logout with the server down: %+v %v", res, err)
	}
	s, err := tryOpen(t, g.cfg)
	if err != nil || !s.Info().Locked {
		t.Fatalf("reopen while RETIRING: %v", err)
	}
	res, err = s.Logout(ctx, nil, LogoutOptions{LocalOnly: true})
	if err != nil || !res.Done || res.Outcome != OutcomeUnknown {
		t.Fatalf("--local-only from RETIRING: %+v %v", res, err)
	}
	loggedOut(t, g.cfg, who)
}

// Server unreachable: the logout stays pending, locked, and finishes on a
// later run.
func TestLogoutPendingWhileUnreachable(t *testing.T) {
	ctx := context.Background()
	f, srv := retireFixture(t)
	who := idsOf(t, f.cfg)
	srv.down = errDown
	if res, err := f.s.Logout(ctx, retirer{srv}, LogoutOptions{}); !errors.Is(err, ErrLogoutPending) || res.State != StateRetiring {
		t.Fatalf("logout: %+v %v", res, err)
	}
	if !f.s.Info().Locked {
		t.Error("unlocked while RETIRING")
	}
	if err := f.s.Unlock(ctx); !errors.Is(err, ErrLoggingOut) {
		t.Errorf("unlock: %v", err)
	}
	srv.down = nil
	if res, err := f.s.Logout(ctx, retirer{srv}, LogoutOptions{}); err != nil || !res.Done {
		t.Fatalf("logout once the server is back: %+v %v", res, err)
	}
	loggedOut(t, f.cfg, who)
}

// §13: logout refuses with a checkpoint journal or an unacknowledged kit,
// even with --discard-pending (and --local-only); a non-empty outbox
// refuses unless --discard-pending. A refusal changes nothing.
func TestLogoutRefusals(t *testing.T) {
	ctx := context.Background()
	f, srv := retireFixture(t)
	newCredential(t, f.s, "queued")
	if _, err := f.s.Logout(ctx, retirer{srv}, LogoutOptions{}); !errors.Is(err, ErrOutboxNotEmpty) {
		t.Errorf("with a queued change: %v", err)
	}
	if j := readRetire(t, f.cfg); j != nil || f.s.Info().Locked {
		t.Error("a refused logout journaled or locked the vault")
	}
	who := idsOf(t, f.cfg)
	if res, err := f.s.Logout(ctx, retirer{srv}, LogoutOptions{DiscardPending: true}); err != nil || !res.Done {
		t.Fatalf("--discard-pending: %+v %v", res, err)
	}
	loggedOut(t, f.cfg, who)

	// A pending kit: a password change on a vault that is then server-backed.
	g := newVault(t, testConfig(t))
	if _, err := g.s.ChangePassword(ctx, []byte(testPassword), []byte(newPassword)); err != nil {
		t.Fatal(err)
	}
	if err := g.s.EnableServerMode(); err != nil {
		t.Fatal(err)
	}
	for _, opts := range []LogoutOptions{{}, {DiscardPending: true}, {DiscardPending: true, LocalOnly: true}} {
		if _, err := g.s.Logout(ctx, nil, opts); !errors.Is(err, ErrCheckpointPending) {
			t.Errorf("%+v with a pending kit: %v", opts, err)
		}
	}
	// A checkpoint journal whose kit this device can't read: still refused.
	jfiles := journalFiles(t, g.cfg)
	if len(jfiles) != 1 {
		t.Fatalf("journals %v", jfiles)
	}
	b, err := os.ReadFile(filepath.Join(g.cfg.DataDir, "vault", "journal", jfiles[0]))
	if err != nil {
		t.Fatal(err)
	}
	h, srvH := retireFixture(t)
	if err := os.WriteFile(filepath.Join(h.cfg.DataDir, "vault", "journal", jfiles[0]), b, 0o600); err != nil {
		t.Fatal(err)
	}
	for _, opts := range []LogoutOptions{{DiscardPending: true}, {DiscardPending: true, LocalOnly: true}} {
		if _, err := h.s.Logout(ctx, retirer{srvH}, opts); !errors.Is(err, ErrCheckpointPending) {
			t.Errorf("%+v with a checkpoint journal: %v", opts, err)
		}
	}
	if readRetire(t, h.cfg) != nil {
		t.Error("a refused logout journaled")
	}
	// A local-only vault has no server to log out of.
	l := newVault(t, testConfig(t))
	if _, err := l.s.Logout(ctx, nil, LogoutOptions{LocalOnly: true}); !errors.Is(err, ErrNotServerBacked) {
		t.Errorf("a local-only vault: %v", err)
	}
}
