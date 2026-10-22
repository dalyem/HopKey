package store

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/dalyem/hopkey/internal/vaultlog"
)

// blockingRetirer is the fake server as a Retirer whose Since blocks until
// its context is cancelled, as a server that never answers would. Closing
// stop lets a failed test end.
type blockingRetirer struct {
	retirer
	once    *sync.Once
	entered chan struct{}
	stop    chan struct{}
}

func (b blockingRetirer) Since(ctx context.Context, auth DeviceAuth, after uint64) ([]Committed, vaultlog.Head, error) {
	b.once.Do(func() { close(b.entered) })
	select {
	case <-ctx.Done():
		return nil, vaultlog.Head{}, ctx.Err()
	case <-b.stop:
		return nil, vaultlog.Head{}, errDown
	}
}

// countingRetirer is the fake server as a Retirer that counts the calls
// that reach it.
type countingRetirer struct {
	retirer
	calls *atomic.Int32
}

func (c countingRetirer) Since(ctx context.Context, auth DeviceAuth, after uint64) ([]Committed, vaultlog.Head, error) {
	c.calls.Add(1)
	return c.retirer.Since(ctx, auth, after)
}

// Round 4 finding: Close cancels a logout waiting on the server, as it does
// a pull or a push, and returns promptly. The logout stays RETIRING,
// durably, and the next Logout finishes it. A Logout queued behind it, or
// started once Close has begun, refuses with ErrClosed and never reaches
// the server, and so does any other sync operation.
func TestCloseCancelsABlockedLogout(t *testing.T) {
	ctx := context.Background()
	f, srv := retireFixture(t)
	who := idsOf(t, f.cfg)
	blocked := blockingRetirer{retirer: retirer{srv}, once: &sync.Once{}, entered: make(chan struct{}), stop: make(chan struct{})}
	type result struct {
		res LogoutResult
		err error
	}
	first := make(chan result, 1)
	go func() {
		res, err := f.s.Logout(ctx, blocked, LogoutOptions{})
		first <- result{res, err}
	}()
	select {
	case <-blocked.entered:
	case r := <-first:
		t.Fatalf("logout returned before it reached the server: %+v %v", r.res, r.err)
	}

	var queuedCalls atomic.Int32
	queued := make(chan result, 1)
	go func() {
		res, err := f.s.Logout(ctx, countingRetirer{retirer{srv}, &queuedCalls}, LogoutOptions{})
		queued <- result{res, err}
	}()
	var drainCalls atomic.Int32
	var drainErr, drainPull error
	f.s.testHook = func(stage string) error {
		if stage == "close:drain" {
			_, drainErr = f.s.Logout(ctx, countingRetirer{retirer{srv}, &drainCalls}, LogoutOptions{})
			drainPull = f.s.Pull(ctx, srv.fakeRemote)
		}
		return nil
	}
	closed := make(chan error, 1)
	go func() { closed <- f.s.Close() }()
	select {
	case err := <-closed:
		if err != nil {
			t.Fatalf("close: %v", err)
		}
	case <-time.After(10 * time.Second):
		close(blocked.stop)
		<-closed
		t.Fatal("Close is waiting for a logout it did not cancel")
	}
	f.s.testHook = nil

	r := <-first
	if !errors.Is(r.err, ErrLogoutPending) || !errors.Is(r.err, ErrClosed) || r.res.State != StateRetiring || r.res.Done {
		t.Errorf("the cancelled logout: %+v %v", r.res, r.err)
	}
	if r := <-queued; !errors.Is(r.err, ErrClosed) {
		t.Errorf("a logout queued behind Close: %+v %v", r.res, r.err)
	}
	if !errors.Is(drainErr, ErrClosed) || !errors.Is(drainPull, ErrClosed) {
		t.Errorf("sync started once Close began: logout %v, pull %v", drainErr, drainPull)
	}
	if n := queuedCalls.Load() + drainCalls.Load(); n != 0 {
		t.Errorf("%d requests reached the server after Close began", n)
	}
	if _, err := f.s.Logout(ctx, retirer{srv}, LogoutOptions{}); !errors.Is(err, ErrClosed) {
		t.Errorf("logout after Close: %v", err)
	}
	if j := readRetire(t, f.cfg); j == nil || j.State != StateRetiring {
		t.Fatalf("the retirement journal after Close: %+v", j)
	}

	s := open(t, f.cfg)
	if err := s.Unlock(ctx); !errors.Is(err, ErrLoggingOut) {
		t.Errorf("unlock while RETIRING: %v", err)
	}
	if res, err := s.Logout(ctx, retirer{srv}, LogoutOptions{}); err != nil || !res.Done {
		t.Fatalf("the resumed logout: %+v %v", res, err)
	}
	if how := retiredOnServer(t, srv, who.dev); how != "retired" {
		t.Errorf("the server says %q", how)
	}
	loggedOut(t, f.cfg, who)
}

// A sign-in ledger revocation is scoped to its account: one that names this
// device's ID under another account does not revoke this vault.
func TestLedgerRevocationOfAnotherAccount(t *testing.T) {
	ctx := context.Background()
	d := newSignInFix(t)
	cfg := testConfig(t)
	s, _, err := SignIn(ctx, cfg, d.srv.login(t), d.params(t))
	if err != nil {
		t.Fatal(err)
	}
	track(t, cfg, s)
	release(cfg)
	dc := diskDeviceConfig(t, cfg)
	other, err := vaultlog.NewID()
	if err != nil {
		t.Fatal(err)
	}
	if other == d.acct.AccountID {
		t.Fatal("the other account has this account's ID")
	}
	if err := (layout{data: cfg.DataDir}).markRevoked(other, dc.DeviceID); err != nil {
		t.Fatal(err)
	}
	s, err = tryOpen(t, cfg)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if info := s.Info(); info.Revoked {
		t.Fatalf("open with this device ID revoked under another account: %+v", info)
	}
	if err := s.Unlock(ctx); err != nil {
		t.Fatalf("unlock: %v", err)
	}
	if s.IsRevoked() {
		t.Error("the store reports itself revoked")
	}
	if keychainTombstone(t, cfg, d.acct.AccountID, dc.DeviceID) {
		t.Error("this device's record was tombstoned")
	}
}
