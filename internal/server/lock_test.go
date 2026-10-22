package server

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"sort"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/dalyem/hopkey/internal/canonjson"
	"github.com/dalyem/hopkey/internal/model"
	"github.com/dalyem/hopkey/internal/vaultlog"
)

// writersOf is how many writes wait for the account's admission lock.
func (l *accountLocks) writersOf(id model.ID) int {
	l.mu.Lock()
	defer l.mu.Unlock()
	if a := l.m[id]; a != nil {
		return a.writers
	}
	return 0
}

func (l *accountLocks) waitingTotal() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.waiting
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatal(what)
		}
		time.Sleep(time.Millisecond)
	}
}

// within runs f and fails the test when it takes longer than d. f keeps
// running after a failure, so the test's cleanup must unblock it.
func within(t *testing.T, d time.Duration, what string, f func() resp) resp {
	t.Helper()
	ch := make(chan resp, 1)
	go func() { ch <- f() }()
	select {
	case r := <-ch:
		return r
	case <-time.After(d):
		t.Fatalf("%s did not return within %v", what, d)
		return resp{}
	}
}

// admissionGate pauses every admitted log response while armed, holding
// its account's read lock, until release.
type admissionGate struct {
	armed   atomic.Bool
	entered chan struct{}
	open    chan struct{}
	release func()
}

func newAdmissionGate() *admissionGate {
	g := &admissionGate{entered: make(chan struct{}, 8), open: make(chan struct{})}
	g.release = sync.OnceFunc(func() { close(g.open) })
	return g
}

func (g *admissionGate) hook() {
	if g.armed.Load() {
		g.entered <- struct{}{}
		<-g.open
	}
}

// stall starts a read of v's log that is admitted and then held unsent.
func (g *admissionGate) stall(t *testing.T, e *env, v *tvault, tok string) <-chan resp {
	t.Helper()
	g.armed.Store(true)
	ch := make(chan resp, 1)
	go func() { ch <- e.do("GET", logPath(v), tok, nil) }()
	select {
	case <-g.entered:
	case <-time.After(15 * time.Second):
		t.Fatal("the read was never admitted")
	}
	g.armed.Store(false)
	return ch
}

// startWaiters posts w n times, each of which waits for the account's
// admission lock, and returns the channel of their responses.
func startWaiters(t *testing.T, e *env, v *tvault, tok string, w *vaultlog.Wire, n int) <-chan resp {
	t.Helper()
	acct := v.accountID()
	before := e.srv.accounts.writersOf(acct)
	ch := make(chan resp, n)
	for range n {
		go func() { ch <- e.post(v, tok, w) }()
	}
	waitFor(t, "the writes never waited for the account lock", func() bool {
		return e.srv.accounts.writersOf(acct) == before+n
	})
	return ch
}

func statuses(t *testing.T, ch <-chan resp, n int) []int {
	t.Helper()
	var got []int
	for range n {
		got = append(got, waitResp(t, ch).status)
	}
	sort.Ints(got)
	return got
}

func wantStatuses(t *testing.T, got []int, want ...int) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("statuses %v, want %v", got, want)
	}
	for i := range got {
		if got[i] != want[i] {
			t.Fatalf("statuses %v, want %v", got, want)
		}
	}
}

// R14, R2: writes waiting for an account's admission lock hold no
// validation slot. Account A's reader stalls with its response admitted;
// A's invalidating writes fill A's waiting places, and one more is refused
// at once. Account B's ordinary write still gets a slot and commits at
// once, and nothing is left behind.
func TestLockWaitersHoldNoValidationSlot(t *testing.T) {
	g := newAdmissionGate()
	e := newEnv(t,
		withLimits(func(l *Limits) {
			l.ValidationJobs, l.ValidationQueue = 4, 16
			l.LockWaitersPerAccount, l.LockWaiters = 4, 16
		}),
		withHooks(func(s *Server) { s.hooks.admitted = g.hook }))
	va, vb := newVault(t, "a@example.com"), newVault(t, "b@example.com")
	e.publish(va)
	e.publish(vb)
	A := va.dev(0)
	readerA, writerA, writerB := e.session(va, A), e.session(va, A), e.session(vb, vb.dev(0))
	// Released on every exit, so a failure leaves no handler paused.
	defer g.release()

	read := g.stall(t, e, va, readerA)
	ck := va.checkpoint(A)
	waiters := startWaiters(t, e, va, writerA, ck, 4)
	if n := len(e.srv.validate.slots); n != 0 {
		t.Errorf("%d validation slots held by writes waiting for the account lock", n)
	}
	r := within(t, 5*time.Second, "a fifth write for A", func() resp { return e.post(va, writerA, ck) })
	wantCode(t, r, 429, "busy", "a fifth write waiting for A's lock")

	// B is not held up by A's reader or A's waiting writes.
	nb := vb.normal(vb.dev(0), 1, 10)
	r = within(t, 5*time.Second, "B's write", func() resp { return e.post(vb, writerB, nb) })
	wantStatus(t, r, 200, "B's write while A's writes wait")
	if n := e.srv.accounts.writersOf(va.accountID()); n != 4 {
		t.Errorf("%d writes wait for A's lock after B's write, want 4", n)
	}

	g.release()
	wantStatus(t, waitResp(t, read), 200, "A's stalled read")
	// One checkpoint commits; it ends A's sessions, so the rest are 401.
	wantStatuses(t, statuses(t, waiters, 4), 200, 401, 401, 401)
	if n := e.srv.accounts.refsOf(va.accountID()); n != 0 {
		t.Errorf("%d references to A's lock left", n)
	}
	if n := e.srv.accounts.waitingTotal(); n != 0 {
		t.Errorf("%d waiting writes counted after all returned", n)
	}
}

// R14: the writes waiting for admission locks are bounded across all
// accounts as well. With room for two in all, two of A's fill it and C's
// first is refused at once, though C has room of its own.
func TestLockWaitersBoundedInTotal(t *testing.T) {
	g := newAdmissionGate()
	e := newEnv(t,
		withLimits(func(l *Limits) { l.LockWaitersPerAccount, l.LockWaiters = 4, 2 }),
		withHooks(func(s *Server) { s.hooks.admitted = g.hook }))
	va, vc := newVault(t, "a@example.com"), newVault(t, "c@example.com")
	e.publish(va)
	e.publish(vc)
	A, C := va.dev(0), vc.dev(0)
	writerA, writerC := e.session(va, A), e.session(vc, C)
	// Released on every exit, so a failure leaves no handler paused.
	defer g.release()

	readA := g.stall(t, e, va, e.session(va, A))
	readC := g.stall(t, e, vc, e.session(vc, C))
	waiters := startWaiters(t, e, va, writerA, va.checkpoint(A), 2)
	ckC := vc.checkpoint(C)
	r := within(t, 5*time.Second, "C's write", func() resp { return e.post(vc, writerC, ckC) })
	wantCode(t, r, 429, "busy", "C's write with every waiting place taken")

	g.release()
	wantStatus(t, waitResp(t, readA), 200, "A's stalled read")
	wantStatus(t, waitResp(t, readC), 200, "C's stalled read")
	wantStatuses(t, statuses(t, waiters, 2), 200, 401)
	// With the places free, C's write goes through.
	wantStatus(t, e.post(vc, writerC, ckC), 200, "C's write after the waiters left")
	if n := e.srv.accounts.waitingTotal(); n != 0 {
		t.Errorf("%d waiting writes counted after all returned", n)
	}
}

// A write waiting for its account's admission lock stops waiting when its
// request ends, and its place is free at once for another.
func TestLockWaiterCancelled(t *testing.T) {
	g := newAdmissionGate()
	e := newEnv(t,
		withLimits(func(l *Limits) { l.LockWaitersPerAccount, l.LockWaiters = 1, 1 }),
		withHooks(func(s *Server) { s.hooks.admitted = g.hook }))
	v := newVault(t, "a@example.com")
	e.publish(v)
	A := v.dev(0)
	writer := e.session(v, A)
	acct := v.accountID()
	// Released on every exit, so a failure leaves no handler paused.
	defer g.release()

	read := g.stall(t, e, v, e.session(v, A))
	ck := v.checkpoint(A)
	body, err := canonjson.Marshal(postBody(t, ck))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, "POST", e.ts.URL+logPath(v), bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+writer)
	done := make(chan struct{})
	go func() {
		defer close(done)
		if res, err := e.ts.Client().Do(req); err == nil {
			io.Copy(io.Discard, res.Body)
			res.Body.Close()
		}
	}()
	waitFor(t, "the write never waited for the account lock", func() bool { return e.srv.accounts.writersOf(acct) == 1 })

	cancel()
	<-done
	start := time.Now()
	for e.srv.accounts.writersOf(acct) != 0 || e.srv.accounts.refsOf(acct) != 1 {
		if time.Since(start) > 2*time.Second {
			t.Fatalf("the cancelled write still waits: %d waiting, %d references",
				e.srv.accounts.writersOf(acct), e.srv.accounts.refsOf(acct))
		}
		time.Sleep(time.Millisecond)
	}
	// Its place is free: another write waits instead of a 429.
	waiters := startWaiters(t, e, v, writer, ck, 1)
	g.release()
	wantStatus(t, waitResp(t, read), 200, "the stalled read")
	wantStatus(t, waitResp(t, waiters), 200, "the write that took the freed place")
	if n := e.srv.accounts.refsOf(acct); n != 0 {
		t.Errorf("%d references to the account lock left", n)
	}
}

// R2: an admitted response reaches the client before the handler releases
// the account's admission lock. The response, an empty page, is small
// enough to sit in the server's buffers until the handler returns, so only
// the flush under the lock sends it earlier; the hook after the flush,
// which still holds the lock, waits for the client to have read the whole
// body.
func TestAdmittedResponseSentUnderLock(t *testing.T) {
	var armed atomic.Bool
	received, hooked := make(chan struct{}), make(chan struct{})
	var heldAtReceipt atomic.Int64
	var sawReceipt atomic.Bool
	var e *env
	var acct model.ID
	e = newEnv(t, withHooks(func(s *Server) {
		s.hooks.sent = func() {
			if !armed.Load() {
				return
			}
			defer close(hooked)
			select {
			case <-received:
				sawReceipt.Store(true)
				heldAtReceipt.Store(int64(e.srv.accounts.refsOf(acct)))
			case <-time.After(5 * time.Second):
			}
		}
	}))
	v := newVault(t, "a@example.com")
	e.publish(v)
	acct = v.accountID()
	tok := e.session(v, v.dev(0))

	armed.Store(true)
	req, err := http.NewRequest("GET", e.ts.URL+logPath(v)+"?after="+itoa(v.head().Seq), nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+tok)
	var got []byte
	var status int
	done := make(chan error, 1)
	go func() {
		res, err := e.ts.Client().Do(req)
		if err != nil {
			done <- err
			return
		}
		defer res.Body.Close()
		status = res.StatusCode
		got, err = io.ReadAll(res.Body)
		close(received)
		done <- err
	}()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(15 * time.Second):
		t.Fatal("the read did not return")
	}
	if status != 200 {
		t.Fatalf("status %d: %s", status, got)
	}
	select {
	case <-hooked:
	case <-time.After(15 * time.Second):
		t.Fatal("the handler never reached the hook after the flush")
	}
	if !sawReceipt.Load() {
		t.Fatal("the response reached the client only after the handler released the account lock")
	}
	if n := heldAtReceipt.Load(); n != 1 {
		t.Errorf("%d references to the account lock when the client had the response, want the reader's 1", n)
	}
	if !bytes.HasPrefix(got, []byte(`{"entries":[],"head":`)) {
		t.Errorf("response %q", got)
	}
}

// A write that runs out of request time waiting for its account's lock
// gets a retryable 429 busy, not a 500.
func TestLockWaitDeadlineIsBusy(t *testing.T) {
	g := newAdmissionGate()
	e := newEnv(t,
		withLimits(func(l *Limits) { l.RequestDeadline = time.Second }),
		withHooks(func(s *Server) { s.hooks.admitted = g.hook }))
	v := newVault(t, "a@example.com")
	e.publish(v)
	A := v.dev(0)
	writer := e.session(v, A)
	// Released on every exit, so a failure leaves no handler paused.
	defer g.release()

	read := g.stall(t, e, v, e.session(v, A))
	ck := v.checkpoint(A)
	r := within(t, 5*time.Second, "the waiting write", func() resp { return e.post(v, writer, ck) })
	wantCode(t, r, 429, "busy", "a write whose deadline passed while it waited for the account lock")

	g.release()
	waitResp(t, read)
	if n := e.srv.accounts.refsOf(v.accountID()); n != 0 {
		t.Errorf("%d references to the account lock left", n)
	}
}
