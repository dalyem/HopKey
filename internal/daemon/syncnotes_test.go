package daemon

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/dalyem/hopkey/internal/store"
	"github.com/dalyem/hopkey/internal/syncclient"
)

// Status says online once the server has answered, not only when the
// first long-poll returns (up to Wait, 50 s by default, later).
func TestSyncIsOnlineAsSoonAsTheServerAnswers(t *testing.T) {
	x := newSyncSetup(t)
	// The laptop signed in last: it is at the server's head, so its first
	// pull finds nothing new and waits.
	x.w.start(x.n2, x.n2.st, SyncOptions{})
	eventually(t, 5*time.Second, "status says online", func() bool { return x.n2.status().State == SyncOnline })
}

// A push does not wait behind a server that has stopped answering for as
// long as any request may take: it times out, and status stops saying
// online.
func TestPushToAServerThatStoppedAnsweringTimesOut(t *testing.T) {
	x := newSyncSetup(t)
	x.w.start(x.n1, x.n1.st, SyncOptions{pushTimeout: 300 * time.Millisecond})
	x.n1.must(OpSyncNow, nil, nil)
	if st := x.n1.status(); st.State != SyncOnline {
		t.Fatalf("not online after sync.now: %+v", st)
	}
	// Every request from here on is swallowed: no answer, no error, as
	// when the network drops packets.
	blackhole := interceptor(func(rw http.ResponseWriter, req *http.Request, next http.Handler) bool {
		<-req.Context().Done()
		return true
	})
	x.w.intercept.Store(&blackhole)
	t.Cleanup(func() { x.w.intercept.Store(nil) })

	x.n1.putHost(webHost("web1", x.keyID, "203.0.113.10"))
	eventually(t, 20*time.Second, "status stops saying online", func() bool {
		st := x.n1.status()
		return st.State == SyncBackingOff && st.LastError != "" && st.Pending == 1
	})
}

// An explicit sync against a server that has stopped answering (packets
// dropped on an established connection) fails within a few seconds and
// says the server is unreachable, rather than waiting out the request
// timeout or the HTTP/2 health check.
func TestExplicitSyncToAServerThatStoppedAnsweringFailsFast(t *testing.T) {
	x := newSyncSetup(t)
	x.w.start(x.n1, x.n1.st, SyncOptions{})
	x.n1.must(OpSyncNow, nil, nil)
	blackhole := interceptor(func(rw http.ResponseWriter, req *http.Request, next http.Handler) bool {
		<-req.Context().Done()
		return true
	})
	x.w.intercept.Store(&blackhole)
	t.Cleanup(func() { x.w.intercept.Store(nil) })

	x.n1.putHost(webHost("web1", x.keyID, "203.0.113.10"))
	start := time.Now()
	err := x.n1.call(OpSyncNow, nil, nil)
	took := time.Since(start)
	if err == nil {
		t.Fatal("sync.now succeeded against a server that does not answer")
	}
	if !IsCode(err, CodeUnreachable) || !strings.Contains(err.Error(), "unreachable") {
		t.Errorf("sync.now error = %v, want an unreachable error that says so", err)
	}
	if took > 8*time.Second {
		t.Errorf("sync.now took %s to fail, want about 5s", took)
	}
}

// hop auth devices shows when each device last talked to the server, not
// only when it last wrote: a device that only pulls is seen too.
func TestDevicesLastSeenFollowsPulls(t *testing.T) {
	x := newSyncSetup(t)
	time.Sleep(1100 * time.Millisecond) // the laptop's sign-in is a whole second before this
	since := time.Now().Truncate(time.Second)
	x.w.start(x.n1, x.n1.st, SyncOptions{})
	x.w.start(x.n2, x.n2.st, SyncOptions{})
	x.n2.must(OpSyncNow, nil, nil)

	// The server writes the time in the background, so it may take a
	// moment to show.
	var laptop *store.DeviceListing
	eventually(t, 5*time.Second, "the laptop's last seen is after its pull", func() bool {
		var devs DevicesResult
		x.n1.must(OpDevicesList, nil, &devs)
		for _, d := range devs.Devices {
			if d.Name == "laptop" {
				laptop = &d
			}
		}
		return laptop != nil && laptop.LastSeen != nil && !laptop.LastSeen.Before(since)
	})
}

// Two devices change the same host's description before either sees the
// other's change: the last to reach the server wins (§5.4, description is
// a free member, never held), and that device says what its edit
// replaced, in sync.status, naming the host and the field.
func TestConcurrentDescriptionEditsLeaveANote(t *testing.T) {
	x := newSyncSetup(t)
	x.w.start(x.n1, x.n1.st, SyncOptions{})
	x.w.start(x.n2, x.n2.st, SyncOptions{})
	h := webHost("web1", x.keyID, "203.0.113.10")
	h.Description = "base"
	x.n1.putHost(h)
	eventually(t, 10*time.Second, "web1 reaches the laptop", func() bool { return x.n2.host("web1") != nil })

	x.n2.pause(true)
	desk := *x.n1.host("web1")
	desk.Description = "from the desk"
	x.n1.putHost(desk)
	eventually(t, 10*time.Second, "the desk's edit is pushed", func() bool { return x.n1.status().Pending == 0 })
	laptop := *x.n2.host("web1")
	laptop.Description = "from the laptop"
	x.n2.putHost(laptop)
	x.n2.pause(false)

	eventually(t, 10*time.Second, "the laptop's edit reaches the desk", func() bool {
		h := x.n1.host("web1")
		return h != nil && h.Description == "from the laptop"
	})
	eventually(t, 5*time.Second, "the laptop notes what its edit replaced", func() bool {
		return hasWarning(x.n2.status().Warnings, "web1", "description", "another device")
	})
	for _, w := range x.n2.status().Warnings {
		if strings.Contains(w, "from the desk") || strings.Contains(w, "from the laptop") {
			t.Errorf("the note quotes a value: %q", w)
		}
	}
	// No note where nothing was replaced.
	if ws := x.n1.status().Warnings; hasWarning(ws, "description") {
		t.Errorf("the desk has a note: %q", ws)
	}
}

// hop sync pushes under the same deadline as the background loop: a post
// the server never answers fails the request in moments, not after as
// long as the caller is willing to wait.
func TestSyncNowPushToAServerThatStoppedAnsweringTimesOut(t *testing.T) {
	x := newSyncSetup(t)
	x.w.start(x.n1, x.n1.st, SyncOptions{pushTimeout: 300 * time.Millisecond})
	x.n1.must(OpSyncNow, nil, nil)
	// The loop leaves the push to hop sync.
	x.n1.pause(true)
	// Posts are swallowed; reads still work. The body is read first: the
	// server notices a client that gave up only once it has.
	released := make(chan struct{})
	blackhole := interceptor(func(rw http.ResponseWriter, req *http.Request, next http.Handler) bool {
		if req.Method != http.MethodPost {
			return false
		}
		io.Copy(io.Discard, req.Body)
		select {
		case <-req.Context().Done():
		case <-released:
		}
		return true
	})
	x.w.intercept.Store(&blackhole)
	t.Cleanup(func() {
		x.w.intercept.Store(nil)
		close(released)
	})

	x.n1.putHost(webHost("web1", x.keyID, "203.0.113.10"))
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	start := time.Now()
	err := x.n1.c.Call(ctx, OpSyncNow, nil, nil)
	took := time.Since(start)
	if err == nil {
		t.Fatal("hop sync succeeded with every post swallowed")
	}
	if took > 10*time.Second {
		t.Errorf("hop sync waited %v on a post the server never answered: %v", took, err)
	}
	if st := x.n1.status(); st.Pending != 1 {
		t.Errorf("the change is no longer queued: %+v", st)
	}
}

// The push of an edit that replaced another device's value has an
// uncertain outcome: the server's answer to the post is lost, after the
// post committed or before. The note still comes, once verified history
// shows the edit committed, whether the next push or a pull finds that
// out, and whether the queued candidate had to be posted again.
func TestReplacedNoteSurvivesAnUncertainPush(t *testing.T) {
	for _, tc := range []struct {
		name   string
		commit bool // whether the post the answer is lost for commits
	}{
		{"committed, answer lost", true},
		{"not committed, posted again", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			x := newSyncSetup(t)
			opts := SyncOptions{minBackoff: 20 * time.Millisecond, maxBackoff: 100 * time.Millisecond}
			x.w.start(x.n1, x.n1.st, opts)
			x.w.start(x.n2, x.n2.st, opts)
			h := webHost("web1", x.keyID, "203.0.113.10")
			h.Description = "base"
			x.n1.putHost(h)
			eventually(t, 10*time.Second, "web1 reaches the laptop", func() bool { return x.n2.host("web1") != nil })

			x.n2.pause(true)
			desk := *x.n1.host("web1")
			desk.Description = "from the desk"
			x.n1.putHost(desk)
			eventually(t, 10*time.Second, "the desk's edit is pushed", func() bool { return x.n1.status().Pending == 0 })
			x.n1.pause(true) // only the laptop talks to the server from here
			laptop := *x.n2.host("web1")
			laptop.Description = "from the laptop"
			x.n2.putHost(laptop)

			// The laptop's first post gets no answer it can trust.
			var lost atomic.Bool
			x.w.setIntercept(func(rw http.ResponseWriter, req *http.Request, next http.Handler) bool {
				if req.Method != http.MethodPost || !lost.CompareAndSwap(false, true) {
					return false
				}
				if tc.commit {
					rec := httptest.NewRecorder()
					next.ServeHTTP(rec, req)
					if rec.Code/100 != 2 {
						t.Errorf("the post did not commit: %d %s", rec.Code, rec.Body)
					}
				}
				http.Error(rw, "the answer was lost", http.StatusBadGateway)
				return true
			})
			t.Cleanup(func() { x.w.intercept.Store(nil) })
			x.n2.pause(false)

			eventually(t, 10*time.Second, "the laptop's edit is settled", func() bool {
				st := x.n2.status()
				return lost.Load() && st.Pending == 0
			})
			x.n1.pause(false)
			eventually(t, 10*time.Second, "the laptop's edit reaches the desk", func() bool {
				h := x.n1.host("web1")
				return h != nil && h.Description == "from the laptop"
			})
			eventually(t, 5*time.Second, "the laptop notes what its edit replaced", func() bool {
				return hasWarning(x.n2.status().Warnings, "web1", "description", "another device")
			})
			if n := countWarnings(x.n2.status().Warnings, "web1"); n != 1 {
				t.Errorf("the laptop notes the edit %d times: %q", n, x.n2.status().Warnings)
			}
		})
	}
}

// The push of an edit that replaced another device's value loses its
// answer, and before the daemon tries again an auth command stops it (hop
// auth rotate does): the command's own pull finds the edit committed and
// settles it. The note is not the command's to give; it waits in the
// vault, and the next daemon gives it.
func TestReplacedNoteSurvivesAnAuthFlowThatSettlesIt(t *testing.T) {
	x := newSyncSetup(t)
	ctx := context.Background()
	remote := func(n *node) store.Remote {
		dev, err := syncclient.StoreDevice(n.st.DeviceAuth)
		if err != nil {
			t.Fatal(err)
		}
		return x.w.client(t).Remote(x.pub.VaultID, dev)
	}
	r1, r2 := remote(x.n1), remote(x.n2)
	pushAll := func(s *store.Store, r store.Remote) {
		t.Helper()
		for range 10 {
			res, err := s.PushHead(ctx, r)
			if err != nil {
				t.Fatalf("push: %v", err)
			}
			if res.Outcome == store.PushEmpty {
				return
			}
		}
		t.Fatal("the outbox never drained")
	}
	edit := func(s *store.Store, desc string) {
		t.Helper()
		snap, err := s.Snapshot(ctx)
		if err != nil {
			t.Fatal(err)
		}
		for _, h := range snap.Hosts {
			if h.Name == "web1" {
				h.Description = desc
				if _, err := s.PutHost(ctx, h); err != nil {
					t.Fatal(err)
				}
				return
			}
		}
		t.Fatal("no web1")
	}
	h := webHost("web1", x.keyID, "203.0.113.10")
	h.Description = "base"
	if _, err := x.n1.st.PutHost(ctx, h); err != nil {
		t.Fatal(err)
	}
	pushAll(x.n1.st, r1)
	if err := x.n2.st.Pull(ctx, r2); err != nil {
		t.Fatal(err)
	}
	edit(x.n1.st, "from the desk")
	pushAll(x.n1.st, r1)
	edit(x.n2.st, "from the laptop")

	// The laptop's post commits, and its answer is lost.
	x.w.setIntercept(func(rw http.ResponseWriter, req *http.Request, next http.Handler) bool {
		if req.Method != http.MethodPost {
			return false
		}
		rec := httptest.NewRecorder()
		next.ServeHTTP(rec, req)
		if rec.Code/100 != 2 {
			t.Errorf("the post did not commit: %d %s", rec.Code, rec.Body)
		}
		http.Error(rw, "the answer was lost", http.StatusBadGateway)
		return true
	})
	if _, err := x.n2.st.PushHead(ctx, r2); err == nil {
		t.Fatal("a push whose answer was lost worked")
	}
	x.w.intercept.Store(nil)

	// The auth command's pull settles the edit, and the command ends.
	if err := x.n2.st.Pull(ctx, r2); err != nil {
		t.Fatal(err)
	}
	if st, err := x.n2.st.Status(); err != nil || st.Pending != 0 {
		t.Fatalf("the edit is not settled: %+v %v", st, err)
	}
	x.n2.st.Close()

	s2, err := store.Open(ctx, x.n2.cfg)
	if err != nil {
		t.Fatal(err)
	}
	x.n2.st = s2
	x.w.start(x.n2, s2, SyncOptions{})
	eventually(t, 10*time.Second, "the laptop's next daemon notes what its edit replaced", func() bool {
		return hasWarning(x.n2.status().Warnings, "web1", "description", "another device")
	})
}

func countWarnings(ws []string, sub string) int {
	n := 0
	for _, w := range ws {
		if strings.Contains(w, sub) {
			n++
		}
	}
	return n
}
