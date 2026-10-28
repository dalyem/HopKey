package daemon

import (
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/dalyem/hopkey/internal/store"
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
	x.w.start(x.n1, x.n1.st, SyncOptions{})
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
