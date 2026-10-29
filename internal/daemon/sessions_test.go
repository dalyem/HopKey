package daemon

import (
	"context"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/dalyem/hopkey/internal/model"
	"github.com/dalyem/hopkey/internal/vaultlog"
)

// watched is a session.watch subscription a test opened, as a hop process
// that runs ssh does, and what came of it.
type watched struct {
	w    *Watch
	done chan struct{}
	why  string
	err  error
}

// watchAt subscribes at sock for alias. It fails the test unless the
// daemon answers, at once, watching (atOnce "") or ended for atOnce.
func watchAt(t *testing.T, sock, alias, atOnce string) *watched {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	w, why, err := WatchSessions(ctx, sock, WatchParams{Alias: alias, PID: 4242})
	if err != nil {
		t.Fatalf("session.watch: %v", err)
	}
	if why != atOnce {
		t.Fatalf("session.watch answered ended %q at once, want %q", why, atOnce)
	}
	x := &watched{w: w, done: make(chan struct{})}
	if w == nil {
		x.why = why
		close(x.done)
		return x
	}
	t.Cleanup(func() { w.Close() })
	go func() {
		x.why, x.err = w.Wait()
		close(x.done)
	}()
	return x
}

// ended waits for the daemon to end x, and checks why.
func (x *watched) ended(t *testing.T, within time.Duration, why string) {
	t.Helper()
	select {
	case <-x.done:
	case <-time.After(within):
		t.Fatalf("the session was not ended within %v", within)
	}
	if x.err != nil || x.why != why {
		t.Fatalf("the session ended with %q (%v), want %q", x.why, x.err, why)
	}
}

// running checks that x is still watched, a while after something that
// must not end it.
func (x *watched) running(t *testing.T, what string) {
	t.Helper()
	select {
	case <-x.done:
		t.Fatalf("%s ended the session: %q (%v)", what, x.why, x.err)
	case <-time.After(500 * time.Millisecond):
	}
}

func endedStatus(t *testing.T, n *node) *EndedSessions {
	t.Helper()
	var st StatusResult
	n.must(OpStatus, nil, &st)
	return st.EndedSessions
}

// A device revoked while it is online tells every hop process watching
// its ssh to end it, at once. A subscription opened after that is told so
// in its first answer: a session that starts as the others end is ended
// too. Status counts both.
func TestRevocationEndsWatchedSessions(t *testing.T) {
	x := newSyncSetup(t)
	x.w.start(x.n1, x.n1.st, SyncOptions{})
	x.w.start(x.n2, x.n2.st, SyncOptions{})
	sock := x.n2.d.ControlSocket()
	a, b := watchAt(t, sock, "web1", ""), watchAt(t, sock, "web2", "")

	x.revokeLaptop(t)
	revoked := time.Now()
	a.ended(t, 20*time.Second, whyRevoked)
	b.ended(t, time.Second, whyRevoked)
	t.Logf("the sessions were told to end %v after the revoke", time.Since(revoked).Round(time.Millisecond))

	watchAt(t, sock, "web3", whyRevoked)
	e := endedStatus(t, x.n2)
	if e == nil || e.TerminationRequests != 3 || e.Why != whyRevoked || len(e.Sessions) != 3 {
		t.Fatalf("status: ended sessions %+v", e)
	}
	got := map[string]bool{}
	for _, s := range e.Sessions {
		got[s.Alias] = s.PID == 4242
	}
	if !got["web1"] || !got["web2"] || !got["web3"] {
		t.Errorf("status names %+v", e.Sessions)
	}
}

// The server refusing this device a session, without a report hop can
// use, locks the vault as unconfirmed, and ends the sessions as a
// revocation does, new ones too. Once the server accepts the device again
// and the vault unlocks, new sessions are watched again.
func TestRefusalEndsWatchedSessionsUntilTheVaultOpens(t *testing.T) {
	x := newSyncSetup(t)
	ender := &sessionEnder{Store: x.n2.st}
	x.w.start(x.n2, ender, SyncOptions{minBackoff: 10 * time.Millisecond, maxBackoff: 20 * time.Millisecond})
	x.n2.must(OpSyncNow, nil, nil)
	laptop, err := model.ParseID(x.n2.st.Info().DeviceID)
	if err != nil {
		t.Fatal(err)
	}
	stranger, err := vaultlog.NewID()
	if err != nil {
		t.Fatal(err)
	}
	var refuse atomic.Bool
	refuseSessions(x.w, laptop, &refuse, func(rw http.ResponseWriter, req *http.Request) {
		// A receipt for another device: no report to record.
		rw.Header().Set("Content-Type", "application/json")
		rw.Write(retireStatusBody(t, stranger, "revoked", 7))
	})
	sock := x.n2.d.ControlSocket()
	a := watchAt(t, sock, "web1", "")

	refuse.Store(true)
	ender.end.Store(true)
	x.n2.d.sync.wake()
	a.ended(t, 10*time.Second, whyRefused)
	if info := x.n2.st.Info(); !info.Locked || !info.ServerUnconfirmed {
		t.Fatalf("the vault is not locked as unconfirmed: %+v", info)
	}
	watchAt(t, sock, "web2", whyRefused)

	refuse.Store(false)
	ender.end.Store(false)
	x.n2.must(OpUnlock, UnlockParams{}, nil)
	if x.n2.agentKeys() != 1 {
		t.Fatal("the key is not back once the server accepts the device")
	}
	watchAt(t, sock, "web3", "").running(t, "nothing")
}

// The max-offline policy's lock ends the sessions too, new ones as well,
// until the device has reached the server and the vault is unlocked: the
// laptop's clock jumps two hours past its last contact, with a one-hour
// policy, then comes back.
func TestMaxOfflineLockEndsWatchedSessions(t *testing.T) {
	x := newSyncSetup(t)
	var skew atomic.Int64
	clock := func() time.Time { return time.Now().Add(time.Duration(skew.Load())) }
	x.w.start(x.n1, x.n1.st, SyncOptions{})
	x.w.startWith(x.n2, x.n2.st, Options{offlineEvery: 50 * time.Millisecond, now: clock})
	x.n1.must(OpPolicy, PolicyParams{MaxOffline: 3600}, nil)
	eventually(t, 10*time.Second, "the policy reaches the laptop", func() bool {
		x.n1.call(OpSyncNow, nil, nil)
		x.n2.call(OpSyncNow, nil, nil)
		return x.n2.policy() == 3600
	})
	sock := x.n2.d.ControlSocket()
	a := watchAt(t, sock, "web1", "")

	skew.Store(int64(2 * time.Hour))
	a.ended(t, 15*time.Second, whyOffline)
	if s := x.n2.status(); s.OfflineLocked == "" {
		t.Errorf("the vault did not lock for the policy: %+v", s)
	}
	watchAt(t, sock, "web2", whyOffline)
	if e := endedStatus(t, x.n2); e == nil || e.TerminationRequests != 2 || e.Why != whyOffline {
		t.Errorf("status: ended sessions %+v", e)
	}

	skew.Store(0)
	eventually(t, 10*time.Second, "the laptop unlocks once it reached the server", func() bool {
		x.n2.call(OpSyncNow, nil, nil)
		return x.n2.call(OpUnlock, UnlockParams{}, nil) == nil
	})
	watchAt(t, sock, "web3", "").running(t, "nothing")
}

// A plain hop lock ends no session. hop lock --end-sessions ends the
// sessions open then, and returns them; one opened later is watched as
// usual.
func TestLockEndsWatchedSessionsOnlyWhenAsked(t *testing.T) {
	x := newSyncSetup(t)
	x.w.start(x.n2, x.n2.st, SyncOptions{})
	sock := x.n2.d.ControlSocket()
	a := watchAt(t, sock, "web1", "")

	x.n2.must(OpLock, nil, nil)
	a.running(t, "a plain hop lock")
	if e := endedStatus(t, x.n2); e != nil {
		t.Errorf("status after a plain lock: ended sessions %+v", e)
	}

	var res LockResult
	x.n2.must(OpLock, LockParams{EndSessions: true}, &res)
	a.ended(t, 5*time.Second, whyLock)
	if len(res.EndedSessions) != 1 || res.EndedSessions[0] != (EndedSession{PID: 4242, Alias: "web1"}) {
		t.Errorf("hop lock --end-sessions returned %+v", res.EndedSessions)
	}
	if e := endedStatus(t, x.n2); e == nil || e.TerminationRequests != 1 || e.Why != whyLock {
		t.Errorf("status: ended sessions %+v", e)
	}
	watchAt(t, sock, "web2", "").running(t, "the earlier hop lock --end-sessions")
}

// A daemon that stops leaves its sessions alone: the subscription ends
// without a reason, and a hop process lets its ssh run.
func TestDaemonStopEndsNoSession(t *testing.T) {
	x := newSyncSetup(t)
	x.w.start(x.n2, x.n2.st, SyncOptions{})
	a := watchAt(t, x.n2.d.ControlSocket(), "web1", "")
	if err := x.n2.d.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-a.done:
	case <-time.After(5 * time.Second):
		t.Fatal("the subscription outlived the daemon")
	}
	if a.why != "" || a.err == nil {
		t.Errorf("the subscription ended with %q (%v), want no reason", a.why, a.err)
	}
}

// A subscription that sends a bad request is refused, and the daemon goes
// on answering others.
func TestWatchRefusesBadParams(t *testing.T) {
	x := newSyncSetup(t)
	x.w.start(x.n2, x.n2.st, SyncOptions{})
	c, err := Dial(context.Background(), x.n2.d.ControlSocket())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if err := c.Call(context.Background(), OpSessionWatch, []int{1}, nil); err == nil || !strings.Contains(err.Error(), "bad params") {
		t.Errorf("session.watch with bad params: %v", err)
	}
	watchAt(t, x.n2.d.ControlSocket(), "web1", "").running(t, "nothing")
}
