package daemon

import (
	"bytes"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// outboxFiles reads every file of n's outbox: a journaled candidate
// rewrites its record.
func outboxFiles(t *testing.T, n *node) map[string][]byte {
	t.Helper()
	dir := filepath.Join(n.cfg.DataDir, "vault", "outbox")
	entries, err := os.ReadDir(dir)
	if err != nil && !os.IsNotExist(err) {
		t.Fatal(err)
	}
	out := map[string][]byte{}
	for _, e := range entries {
		b, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			t.Fatal(err)
		}
		out[e.Name()] = b
	}
	return out
}

// sync.pull pulls and verifies and never pushes: with a change queued, it
// journals no candidate and posts nothing, and the change stays queued
// (hop access check, crypto spec rev 17 §7.8). It still brings in what
// another device committed.
func TestSyncPullNeverPushes(t *testing.T) {
	x := newSyncSetup(t)
	x.w.start(x.n1, x.n1.st, SyncOptions{})
	x.w.start(x.n2, x.n2.st, SyncOptions{})
	x.n1.must(OpSyncNow, nil, nil)
	x.n2.must(OpSyncNow, nil, nil)

	var posts atomic.Int32
	x.w.setIntercept(func(rw http.ResponseWriter, req *http.Request, next http.Handler) bool {
		if req.Method == http.MethodPost && strings.HasSuffix(req.URL.Path, "/log") {
			posts.Add(1)
		}
		return false
	})
	t.Cleanup(func() { x.w.intercept.Store(nil) })

	// The desk's loop is paused, so only an op can push its change.
	x.n1.d.sync.pause.Store(true)
	x.n1.putHost(webHost("web1", x.keyID, "203.0.113.10"))
	if st := x.n1.status(); st.Pending != 1 {
		t.Fatalf("pending %d", st.Pending)
	}
	before := outboxFiles(t, x.n1)
	// The laptop commits a change the desk's pull brings in.
	x.n2.putHost(webHost("db1", x.keyID, "203.0.113.20"))
	eventually(t, 10*time.Second, "the laptop pushes", func() bool { return x.n2.status().Pending == 0 })
	posted := posts.Load()

	x.n1.must(OpSyncPull, nil, nil)
	if x.n1.host("db1") == nil {
		t.Error("sync.pull did not bring in the laptop's change")
	}
	if got := posts.Load(); got != posted {
		t.Errorf("sync.pull posted %d entries", got-posted)
	}
	if st := x.n1.status(); st.Pending != 1 || st.Held != 0 {
		t.Errorf("after sync.pull: pending %d, held %d", st.Pending, st.Held)
	}
	after := outboxFiles(t, x.n1)
	if len(after) != len(before) {
		t.Fatalf("outbox files %d -> %d", len(before), len(after))
	}
	for name, b := range before {
		if !bytes.Equal(after[name], b) {
			t.Errorf("outbox record %s was rewritten: a candidate was journaled", name)
		}
	}

	// sync.now, for comparison, pushes it.
	x.n1.must(OpSyncNow, nil, nil)
	if st := x.n1.status(); st.Pending != 0 || posts.Load() == posted {
		t.Errorf("sync.now: pending %d, posts %d", st.Pending, posts.Load()-posted)
	}
}
