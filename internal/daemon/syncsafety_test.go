package daemon

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/dalyem/hopkey/internal/crypto"
	"github.com/dalyem/hopkey/internal/merge"
	"github.com/dalyem/hopkey/internal/model"
	"github.com/dalyem/hopkey/internal/sshconfig"
	"github.com/dalyem/hopkey/internal/store"
	"github.com/dalyem/hopkey/internal/vaultlog"
)

func (w *syncWorld) setIntercept(f interceptor) { w.intercept.Store(&f) }

func waitClosed(t *testing.T, ch <-chan struct{}, within time.Duration, what string) {
	t.Helper()
	select {
	case <-ch:
	case <-time.After(within):
		t.Fatalf("not within %v: %s", within, what)
	}
}

// A pull that commits a key deletion and then fails on what comes after
// it (here the server's head contradicts the entries it served, an
// equivocation) still takes the deleted key out of the agent: the daemon
// follows what the store committed, not only pulls that worked.
func TestPartialPullFailureStillDropsADeletedKey(t *testing.T) {
	x := newSyncSetup(t)
	x.w.start(x.n1, x.n1.st, SyncOptions{})
	x.w.start(x.n2, x.n2.st, SyncOptions{})
	if got := x.n2.agentKeys(); got != 1 {
		t.Fatalf("the laptop's agent holds %d keys; want 1", got)
	}

	x.n2.pause(true)
	x.n1.must(OpDelete, DeleteParams{ID: x.keyID.String()}, nil)
	eventually(t, 5*time.Second, "the desk pushes the deletion", func() bool { return x.n1.status().Pending == 0 })
	// The desk's long-poll ends, so the next log read is the laptop's.
	x.n1.pause(true)

	tampered := tamperNextLogHead(t, x.w)
	x.n2.pause(false)

	// Read in process: a control read could reload on its own.
	eventually(t, 10*time.Second, "the laptop's sync halts", func() bool { return x.n2.d.sync.status().Halted != "" })
	if !tampered.Load() {
		t.Fatal("the log read was not tampered with")
	}
	snap, err := x.n2.st.Snapshot(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(snap.Keys) != 0 {
		t.Fatalf("the store did not commit the deletion before the failure: %d keys", len(snap.Keys))
	}
	if got := x.n2.agentKeys(); got != 0 {
		t.Errorf("the laptop's agent still holds %d keys the vault deleted", got)
	}
	if st := x.n2.d.sync.status(); st.State != SyncHalted || !st.Equivocation {
		t.Errorf("the failure is not kept: %+v", st)
	}
}

// tamperNextLogHead makes the server's next log read, which must serve
// entries, end on a head that contradicts them: an equivocation, found
// after the entries before it are committed. It reports whether it ran.
func tamperNextLogHead(t *testing.T, w *syncWorld) *atomic.Bool {
	t.Helper()
	var tampered atomic.Bool
	w.setIntercept(func(rw http.ResponseWriter, req *http.Request, next http.Handler) bool {
		if req.Method != http.MethodGet || !strings.HasSuffix(req.URL.Path, "/log") || !tampered.CompareAndSwap(false, true) {
			return false
		}
		rec := httptest.NewRecorder()
		next.ServeHTTP(rec, req)
		body := rec.Body.Bytes()
		var page map[string]json.RawMessage
		var head map[string]json.RawMessage
		if rec.Code != http.StatusOK || json.Unmarshal(body, &page) != nil || json.Unmarshal(page["head"], &head) != nil ||
			string(page["entries"]) == "[]" {
			t.Errorf("the log read: %d %s", rec.Code, body)
		} else {
			head["h"] = json.RawMessage(`"` + strings.Repeat("ab", 32) + `"`)
			page["head"], _ = json.Marshal(head)
			body, _ = json.Marshal(page)
		}
		rw.Header().Set("Content-Type", "application/json")
		rw.WriteHeader(rec.Code)
		rw.Write(body)
		return true
	})
	return &tampered
}

// The same partial pull with the ssh config impossible to write: the
// deleted key still leaves the agent, sync.status says the config is out
// of date, and once the config can be written again the daemon rewrites it
// on its own, though sync stays stopped.
func TestPartialPullFailureDropsADeletedKeyWhenTheConfigCannotBeWritten(t *testing.T) {
	x := newSyncSetup(t)
	var failWrites atomic.Bool
	x.w.start(x.n1, x.n1.st, SyncOptions{})
	x.w.startWith(x.n2, x.n2.st, Options{
		writeConfig: func(o sshconfig.Options, hosts []sshconfig.Host) error {
			if failWrites.Load() {
				return errors.New("the directory is read-only")
			}
			return sshconfig.Write(o, hosts)
		},
		configRetry: 50 * time.Millisecond,
	})
	web := x.n1.putHost(webHost("web1", x.keyID, "203.0.113.10"))
	eventually(t, 10*time.Second, "the laptop's ssh config has web1", func() bool { return strings.Contains(x.n2.config(), "Host web1\n") })
	if got := x.n2.agentKeys(); got != 1 {
		t.Fatalf("the laptop's agent holds %d keys; want 1", got)
	}

	x.n2.pause(true)
	failWrites.Store(true)
	x.n1.must(OpDelete, DeleteParams{ID: web.ItemID.String()}, nil)
	x.n1.must(OpDelete, DeleteParams{ID: x.keyID.String()}, nil)
	eventually(t, 5*time.Second, "the desk pushes the deletions", func() bool { return x.n1.status().Pending == 0 })
	x.n1.pause(true)
	tampered := tamperNextLogHead(t, x.w)
	x.n2.pause(false)

	eventually(t, 10*time.Second, "the laptop's sync halts", func() bool { return x.n2.d.sync.status().Halted != "" })
	if !tampered.Load() {
		t.Fatal("the log read was not tampered with")
	}
	snap, err := x.n2.st.Snapshot(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(snap.Keys) != 0 || len(snap.Hosts) != 0 {
		t.Fatalf("the store did not commit the deletions before the failure: %d keys, %d hosts", len(snap.Keys), len(snap.Hosts))
	}
	if got := x.n2.agentKeys(); got != 0 {
		t.Errorf("the laptop's agent still holds %d keys the vault deleted", got)
	}
	if !strings.Contains(x.n2.config(), "Host web1\n") {
		t.Error("the ssh config changed though it could not be written")
	}
	outOfDate := func(ws []string) bool {
		return slices.ContainsFunc(ws, func(w string) bool { return strings.Contains(w, "ssh config") && strings.Contains(w, "out of date") })
	}
	if st := x.n2.status(); !outOfDate(st.Warnings) || st.State != SyncHalted {
		t.Errorf("sync.status while the config can't be written: %s %q", st.State, st.Warnings)
	}
	// hop status works, and says so too.
	var status StatusResult
	x.n2.must(OpStatus, nil, &status)
	if !outOfDate(status.Warnings) || status.KeysInAgent != 0 {
		t.Errorf("status while the config can't be written: %d keys, %q", status.KeysInAgent, status.Warnings)
	}

	failWrites.Store(false)
	eventually(t, 5*time.Second, "the laptop's ssh config drops web1", func() bool { return !strings.Contains(x.n2.config(), "Host web1\n") })
	eventually(t, 5*time.Second, "the warning goes", func() bool { return !outOfDate(x.n2.status().Warnings) })
	if st := x.n2.status(); st.State != SyncHalted || !st.Equivocation {
		t.Errorf("sync restarted after the config was written: %+v", st)
	}
	if got := x.n2.agentKeys(); got != 0 {
		t.Errorf("the agent holds %d keys after the config was written", got)
	}
}

// A held credential's proposal leaves its password out, and its
// confirmation token is not the unkeyed digest of the full replacement,
// which would let anyone holding the redacted proposal test password
// guesses offline: it is keyed per daemon process. A password change on
// another device after the proposal makes the token stale, though the
// password is not shown.
func TestHeldCredentialConfirmTokenHidesAndCoversThePassword(t *testing.T) {
	ctx := context.Background()
	x := newSyncSetup(t)
	x.w.start(x.n1, x.n1.st, SyncOptions{})
	x.w.start(x.n2, x.n2.st, SyncOptions{noPoll: true})

	cred, err := x.n1.st.PutCredential(ctx, model.Credential{Name: "db", Username: "app", Password: "hunter2-original"})
	if err != nil {
		t.Fatal(err)
	}
	x.n1.must(OpSyncNow, nil, nil)
	x.n2.must(OpSyncNow, nil, nil)

	// The desk changes the password while the laptop changes the user name.
	x.n2.pause(true)
	theirs := cred
	theirs.Password = "hunter2-second"
	theirs, err = x.n1.st.PutCredential(ctx, theirs)
	if err != nil {
		t.Fatal(err)
	}
	x.n1.must(OpSyncNow, nil, nil)
	mine := cred
	mine.Username = "admin"
	if _, err := x.n2.st.PutCredential(ctx, mine); err != nil {
		t.Fatal(err)
	}
	x.n2.pause(false)
	x.n2.must(OpSyncNow, nil, nil)
	if st := x.n2.status(); st.Held != 1 {
		t.Fatalf("the laptop's change is not held: %+v", st)
	}

	var held SyncHeldResult
	x.n2.must(OpSyncHeld, nil, &held)
	if len(held.Held) != 1 || held.Held[0].KeepMine == nil {
		t.Fatalf("held %+v", held)
	}
	hc := held.Held[0]
	km := hc.KeepMine

	// (c) Nothing of the password crosses the socket.
	for name, raw := range map[string]json.RawMessage{
		"seen": hc.Seen, "want": hc.Want, "current": hc.Current, "keep-mine seen": km.Seen, "keep-mine want": km.Want,
	} {
		if s := string(raw); s == "null" || strings.Contains(s, "password") || strings.Contains(s, "hunter2") {
			t.Errorf("%s: %s", name, s)
		}
	}
	if !strings.Contains(string(km.Want), `"admin"`) {
		t.Errorf("keep-mine want %s", km.Want)
	}

	// (a) The token is not the store's digest, and another daemon
	// process, with its own key, gives another.
	sp, err := x.n2.st.Propose(store.Resolution{Choice: merge.ChoiceKeepMine})
	if err != nil {
		t.Fatal(err)
	}
	if km.Confirm == sp.Digest.String() {
		t.Error("the confirmation token is the unkeyed digest of the full replacement")
	}
	if got := x.n2.d.sync.confirmToken(sp).String(); got != km.Confirm {
		t.Fatalf("the token %s is not this daemon's token for the store's proposal %s", km.Confirm, got)
	}
	other := newSyncer(x.n2.d, x.n2.st, SyncOptions{})
	if other.confirmToken(sp).String() == km.Confirm {
		t.Error("two daemon processes give the same token")
	}

	// (b) The desk changes the password again; the user name, all the
	// laptop's proposal shows of the credential, stays.
	theirs.Password = "hunter2-third"
	if _, err := x.n1.st.PutCredential(ctx, theirs); err != nil {
		t.Fatal(err)
	}
	x.n1.must(OpSyncNow, nil, nil)
	x.n2.must(OpSyncNow, nil, nil)
	if st := x.n2.status(); st.Held != 1 {
		t.Fatalf("the laptop's change is no longer held: %+v", st)
	}
	err = x.n2.call(OpSyncResolve, SyncResolveParams{N: hc.N, Choice: ChoiceKeepMine, Confirm: km.Confirm, NewID: km.NewID}, nil)
	if !IsCode(err, CodeStaleConfirm) {
		t.Fatalf("keep mine confirmed with the token from before the password change: %v", err)
	}
	var held2 SyncHeldResult
	x.n2.must(OpSyncHeld, nil, &held2)
	km2 := held2.Held[0].KeepMine
	if km2 == nil || km2.Confirm == km.Confirm || strings.Contains(string(km2.Want), "hunter2") {
		t.Fatalf("the new proposal %+v", km2)
	}
	var res SyncResolveResult
	x.n2.must(OpSyncResolve, SyncResolveParams{N: hc.N, Choice: ChoiceKeepMine, Confirm: km2.Confirm, NewID: km2.NewID}, &res)
	x.n1.must(OpSyncNow, nil, nil)
	eventually(t, 5*time.Second, "keep mine reaches the desk", func() bool {
		x.n1.must(OpSyncNow, nil, nil)
		snap, err := x.n1.st.Snapshot(ctx)
		if err != nil {
			t.Fatal(err)
		}
		i := slices.IndexFunc(snap.Credentials, func(c model.Credential) bool { return c.ItemID == cred.ItemID })
		return i >= 0 && snap.Credentials[i].Username == "admin" && snap.Credentials[i].Password == "hunter2-third"
	})
}

// sessionEnder is a store whose pulls and pushes are refused a session
// while end is set, as for a device that left the account.
type sessionEnder struct {
	*store.Store
	end atomic.Bool
}

func (s *sessionEnder) Pull(ctx context.Context, r store.Remote) error {
	if s.end.Load() {
		return store.ErrSessionEnded
	}
	return s.Store.Pull(ctx, r)
}

func (s *sessionEnder) PushHead(ctx context.Context, r store.Remote) (store.PushResult, error) {
	if s.end.Load() {
		return store.PushResult{}, store.ErrSessionEnded
	}
	return s.Store.PushHead(ctx, r)
}

// retireStatusBody is a retire-status answer with a receipt for device.
func retireStatusBody(t *testing.T, device model.ID, how string, seq uint64) []byte {
	t.Helper()
	type receipt struct {
		DeviceID model.ID    `json:"device_id"`
		H        crypto.Hash `json:"h"`
		How      string      `json:"how"`
		Seq      uint64      `json:"seq,string"`
	}
	b, err := json.Marshal(map[string]any{
		"committed": false, "head": vaultlog.Head{Seq: seq}, "seq": nil,
		"receipt": receipt{DeviceID: device, How: how, Seq: seq},
	})
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// refuseSessions makes the server refuse device a session while on is
// set, as it does a device that left the account, and answers its
// retire-status with answer, when that is set (it may block). Everything
// else goes to the real server.
func refuseSessions(w *syncWorld, device model.ID, on *atomic.Bool, answer func(rw http.ResponseWriter, req *http.Request)) {
	w.setIntercept(func(rw http.ResponseWriter, req *http.Request, _ http.Handler) bool {
		if !on.Load() {
			return false
		}
		b, _ := io.ReadAll(req.Body)
		req.Body = io.NopCloser(bytes.NewReader(b))
		var body struct {
			DeviceID  model.ID `json:"device_id"`
			Operation string   `json:"operation"`
		}
		json.Unmarshal(b, &body)
		if body.DeviceID != device {
			return false
		}
		switch {
		case req.URL.Path == "/v1/auth/challenge" && body.Operation == "session":
			rw.Header().Set("Content-Type", "application/json")
			rw.WriteHeader(http.StatusUnauthorized)
			rw.Write([]byte(`{"error":{"code":"unauthorized","message":"unauthorized"}}`))
			return true
		case req.URL.Path == "/v1/retire-status" && answer != nil:
			answer(rw, req)
			return true
		}
		return false
	})
}

// A retire-status request in flight when the vault locks is cancelled, and
// its answer, arriving after an unlock, does nothing. One asked and
// answered in the same unlocked session records the report and locks the
// vault, but marks nothing revoked and deletes nothing.
func TestLateRetireStatusAnswerAfterLockAndUnlockDoesNothing(t *testing.T) {
	x := newSyncSetup(t)
	ender := &sessionEnder{Store: x.n2.st}
	x.w.start(x.n2, ender, SyncOptions{minBackoff: 10 * time.Millisecond, maxBackoff: 20 * time.Millisecond})
	x.n2.must(OpSyncNow, nil, nil)
	if got := x.n2.agentKeys(); got != 1 {
		t.Fatalf("the laptop's agent holds %d keys; want 1", got)
	}
	laptop, err := model.ParseID(x.n2.st.Info().DeviceID)
	if err != nil {
		t.Fatal(err)
	}

	arrived, cancelled, release := make(chan struct{}), make(chan struct{}), make(chan struct{})
	var releaseOnce sync.Once
	releaseAll := func() { releaseOnce.Do(func() { close(release) }) }
	// Before the server closes, which waits for a handler still blocked.
	t.Cleanup(releaseAll)
	var calls atomic.Int32
	var refuse atomic.Bool
	refuseSessions(x.w, laptop, &refuse, func(rw http.ResponseWriter, req *http.Request) {
		if calls.Add(1) == 1 {
			close(arrived)
			select {
			case <-req.Context().Done():
				close(cancelled)
			case <-release:
			}
			<-release
		}
		rw.Header().Set("Content-Type", "application/json")
		rw.Write(retireStatusBody(t, laptop, "revoked", 99))
	})

	refuse.Store(true)
	ender.end.Store(true)
	x.n2.d.sync.wake()
	waitClosed(t, arrived, 10*time.Second, "the laptop asks retire-status")
	x.n2.must(OpLock, nil, nil)
	select {
	case <-cancelled:
	case <-time.After(5 * time.Second):
		// Go on: the answer must still do nothing.
		t.Error("the lock did not cancel the retire-status request")
	}
	refuse.Store(false)
	ender.end.Store(false)
	x.n2.must(OpUnlock, UnlockParams{}, nil)
	releaseAll()

	time.Sleep(500 * time.Millisecond)
	if x.n2.st.Info().Locked {
		t.Error("the late answer locked the vault unlocked since")
	}
	if got := x.n2.agentKeys(); got != 1 {
		t.Errorf("the agent holds %d keys after the late answer; want 1", got)
	}
	if st := x.n2.status(); st.State == SyncRevoked || st.ServerRetirement != nil {
		t.Errorf("the late answer stopped sync: %+v", st)
	}
	var now SyncStatusResult
	x.n2.must(OpSyncNow, nil, &now)
	if now.State != SyncOnline {
		t.Errorf("sync.now after the late answer: %+v", now)
	}

	// Asked and answered in one session, the receipt counts.
	refuse.Store(true)
	ender.end.Store(true)
	x.n2.d.sync.wake()
	eventually(t, 10*time.Second, "the laptop stops on the receipt", func() bool { return x.n2.status().State == SyncRevoked })
	st := x.n2.status()
	if r := st.ServerRetirement; r == nil || r.How != "revoked" || r.Seq != 99 || !r.Unverified || r.Wiped {
		t.Errorf("server retirement %+v", r)
	}
	if !slices.ContainsFunc(st.Warnings, func(w string) bool { return strings.Contains(w, "the server reports that this device was revoked") }) {
		t.Errorf("warnings %q", st.Warnings)
	}
	if !x.n2.st.Info().Locked || x.n2.agentKeys() != 0 {
		t.Error("the receipt did not lock the vault and empty the agent")
	}
	if x.n2.st.IsRevoked() || x.n2.st.Info().Revoked {
		t.Error("the store was marked revoked on the server's word")
	}
	if rep, err := x.n2.st.Report(); err != nil || rep == nil || rep.Seq != 99 {
		t.Errorf("the report on disk: %+v, %v", rep, err)
	}
}

// A retire-status receipt is recorded only if it names this device and
// says retired or revoked. Any other is not recorded, but the session was
// refused, so the vault locks in memory until the server accepts the
// device again.
func TestServerRetirementChecksTheReceipt(t *testing.T) {
	x := newSyncSetup(t)
	x.w.start(x.n2, x.n2.st, SyncOptions{noPoll: true})
	e := x.n2.d.sync
	laptop, err := model.ParseID(x.n2.st.Info().DeviceID)
	if err != nil {
		t.Fatal(err)
	}
	stranger, err := vaultlog.NewID()
	if err != nil {
		t.Fatal(err)
	}
	var refuse atomic.Bool
	refuse.Store(true)
	var rc atomic.Pointer[[]byte]
	refuseSessions(x.w, laptop, &refuse, func(rw http.ResponseWriter, req *http.Request) {
		rw.Header().Set("Content-Type", "application/json")
		rw.Write(*rc.Load())
	})
	for name, body := range map[string][]byte{
		"another device": retireStatusBody(t, stranger, "revoked", 7),
		"an unknown how": retireStatusBody(t, laptop, "suspended", 7),
	} {
		rc.Store(&body)
		if !e.sessionEnded(context.Background(), e.st.Generation()) {
			t.Errorf("%s: sync went on after a refused session", name)
		}
		if info := x.n2.st.Info(); !info.Locked || !info.ServerUnconfirmed || x.n2.agentKeys() != 0 {
			t.Errorf("%s: the vault did not lock, or the agent kept its key", name)
		}
		if rep, _ := x.n2.st.Report(); rep != nil || e.status().ServerRetirement != nil {
			t.Fatalf("%s: a bad receipt was recorded: %+v", name, rep)
		}
		refuse.Store(false)
		x.n2.must(OpUnlock, nil, nil)
		refuse.Store(true)
		if x.n2.agentKeys() != 1 {
			t.Fatalf("%s: the key is not back once the server accepts the device", name)
		}
	}
	good := retireStatusBody(t, laptop, "revoked", 7)
	rc.Store(&good)
	if !e.sessionEnded(context.Background(), e.st.Generation()) {
		t.Fatal("did not act on a good receipt")
	}
	if !x.n2.st.Info().Locked || x.n2.agentKeys() != 0 {
		t.Error("a good receipt did not lock the vault and empty the agent")
	}
	if r := x.n2.status().ServerRetirement; r == nil || !r.Unverified {
		t.Errorf("server retirement %+v", r)
	}
}

// After the server's word that this device left the account, hop unlock
// refuses while the server still refuses the device, and works once the
// server authenticates it again: the report was wrong. Status never
// suggests hop unlock meanwhile.
func TestUnlockAfterAServerReportWaitsForTheServer(t *testing.T) {
	x := newSyncSetup(t)
	ender := &sessionEnder{Store: x.n2.st}
	x.w.start(x.n2, ender, SyncOptions{minBackoff: 10 * time.Millisecond, maxBackoff: 20 * time.Millisecond})
	x.n2.must(OpSyncNow, nil, nil)
	laptop, err := model.ParseID(x.n2.st.Info().DeviceID)
	if err != nil {
		t.Fatal(err)
	}
	var refuse atomic.Bool
	refuse.Store(true)
	refuseSessions(x.w, laptop, &refuse, func(rw http.ResponseWriter, req *http.Request) {
		rw.Header().Set("Content-Type", "application/json")
		rw.Write(retireStatusBody(t, laptop, "retired", 7))
	})
	ender.end.Store(true)
	x.n2.d.sync.wake()
	eventually(t, 10*time.Second, "the laptop stops on the receipt", func() bool { return x.n2.status().State == SyncRevoked })
	if !x.n2.st.Info().Locked || x.n2.agentKeys() != 0 {
		t.Fatal("the receipt did not lock the vault and empty the agent")
	}
	st := x.n2.status()
	i := slices.IndexFunc(st.Warnings, func(w string) bool { return strings.Contains(w, "the server reports that this device was retired") })
	if i < 0 {
		t.Fatalf("warnings %q", st.Warnings)
	}
	for _, want := range []string{"hop auth logout", "hop auth login"} {
		if !strings.Contains(st.Warnings[i], want) {
			t.Errorf("the warning %q does not say %q", st.Warnings[i], want)
		}
	}
	if strings.Contains(st.Warnings[i], "hop unlock") {
		t.Errorf("the warning %q suggests hop unlock", st.Warnings[i])
	}

	if err := x.n2.call(OpUnlock, UnlockParams{}, nil); !IsCode(err, CodeRevoked) {
		t.Fatalf("unlock while the server still refuses: %v", err)
	}
	if x.n2.agentKeys() != 0 {
		t.Fatal("the refused unlock loaded keys")
	}

	// The server serves this device again.
	refuse.Store(false)
	ender.end.Store(false)
	x.n2.must(OpUnlock, UnlockParams{}, nil)
	if x.n2.st.Info().Locked {
		t.Fatal("the vault is still locked")
	}
	if got := x.n2.agentKeys(); got != 1 {
		t.Errorf("the agent holds %d keys after the unlock; want 1", got)
	}
	if rep, _ := x.n2.st.Report(); rep != nil {
		t.Errorf("the report is still recorded: %+v", rep)
	}
	eventually(t, 10*time.Second, "sync resumes", func() bool { return x.n2.status().State == SyncOnline })
}
