package daemon

import (
	"context"
	"io"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// syncNowLimit is how long an explicit sync may take against a server
// that stopped answering: its 8 s budget, and a little for the test.
const syncNowLimit = 10 * time.Second

// blackholeAll makes the server stop answering, as when packets are
// dropped on an established connection: every request waits until the
// client gives up. Each request's arrival is sent on hits, if there is
// room.
func blackholeAll(t *testing.T, w *syncWorld) <-chan string {
	t.Helper()
	hits := make(chan string, 64)
	w.setIntercept(func(rw http.ResponseWriter, req *http.Request, next http.Handler) bool {
		// The body is read first: the server notices a client that gave up
		// only once it has.
		io.Copy(io.Discard, req.Body)
		select {
		case hits <- req.Method + " " + req.URL.Path:
		default:
		}
		<-req.Context().Done()
		return true
	})
	t.Cleanup(func() { w.intercept.Store(nil) })
	return hits
}

func waitHit(t *testing.T, hits <-chan string, what string) {
	t.Helper()
	select {
	case <-hits:
	case <-time.After(10 * time.Second):
		t.Fatalf("no request reached the server: %s", what)
	}
}

// syncNowFails runs sync.now on n and checks that it fails within
// syncNowLimit, saying the server did not answer.
func syncNowFails(t *testing.T, n *node) {
	t.Helper()
	start := time.Now()
	err := n.call(OpSyncNow, nil, nil)
	took := time.Since(start)
	if err == nil {
		t.Fatal("sync.now succeeded against a server that does not answer")
	}
	if !IsCode(err, CodeUnreachable) || !strings.Contains(err.Error(), "did not answer") {
		t.Errorf("sync.now error = %v, want an unreachable error that says the server did not answer", err)
	}
	if took > syncNowLimit {
		t.Errorf("sync.now took %s to fail, want under %s", took, syncNowLimit)
	}
}

// An explicit sync that arrives while the loop pushes a change to a server
// that has stopped answering does not wait out the push's own deadline
// (15 s) first: it has one budget from the moment the daemon receives it.
// The live suite measured 19.9 s: the push's 15 s, then the sync's own.
func TestExplicitSyncDoesNotWaitForABackgroundPush(t *testing.T) {
	x := newSyncSetup(t)
	x.w.start(x.n1, x.n1.st, SyncOptions{})
	x.n1.must(OpSyncNow, nil, nil)
	hits := blackholeAll(t, x.w)

	// The write wakes the loop, which pushes it into the blackhole.
	x.n1.putHost(webHost("web1", x.keyID, "203.0.113.10"))
	waitHit(t, hits, "the background push")
	time.Sleep(300 * time.Millisecond)

	syncNowFails(t, x.n1)
	if st := x.n1.status(); st.Pending != 1 {
		t.Errorf("the change is no longer queued: pending %d, held %d", st.Pending, st.Held)
	}
}

// Nor does it wait for the long-poll in flight to a server that has
// stopped answering.
func TestExplicitSyncDoesNotWaitForTheLongPoll(t *testing.T) {
	x := newSyncSetup(t)
	x.w.start(x.n1, x.n1.st, SyncOptions{})
	x.n1.must(OpSyncNow, nil, nil)
	eventually(t, 5*time.Second, "status says online", func() bool { return x.n1.status().State == SyncOnline })
	hits := blackholeAll(t, x.w)

	// The long-poll that was waiting at the server ends; the next one
	// goes into the blackhole.
	x.n1.d.sync.wake()
	waitHit(t, hits, "the long-poll")
	time.Sleep(300 * time.Millisecond)

	syncNowFails(t, x.n1)
}

// A background push the explicit sync ends is no failure: the explicit
// sync pushes the change itself, at once.
func TestExplicitSyncTakesOverASlowBackgroundPush(t *testing.T) {
	x := newSyncSetup(t)
	x.w.start(x.n1, x.n1.st, SyncOptions{})
	x.n1.must(OpSyncNow, nil, nil)
	// The first post of a change gets no answer until the client gives up;
	// every other request is answered.
	var swallowed atomic.Bool
	held := make(chan struct{})
	x.w.setIntercept(func(rw http.ResponseWriter, req *http.Request, next http.Handler) bool {
		if req.Method != http.MethodPost || !strings.HasPrefix(req.URL.Path, "/v1/vaults/") || !swallowed.CompareAndSwap(false, true) {
			return false
		}
		io.Copy(io.Discard, req.Body)
		close(held)
		<-req.Context().Done()
		return true
	})
	t.Cleanup(func() { x.w.intercept.Store(nil) })

	x.n1.putHost(webHost("web1", x.keyID, "203.0.113.10"))
	waitClosed(t, held, 10*time.Second, "the background push posts")

	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
	defer cancel()
	start := time.Now()
	err := x.n1.c.Call(ctx, OpSyncNow, nil, nil)
	took := time.Since(start)
	if err != nil {
		t.Fatalf("sync.now: %v", err)
	}
	if took > 5*time.Second {
		t.Errorf("sync.now took %s: it waited for the background push", took)
	}
	st := x.n1.status()
	if st.Pending != 0 || st.Held != 0 {
		t.Errorf("the change is still queued: pending %d, held %d", st.Pending, st.Held)
	}
}
