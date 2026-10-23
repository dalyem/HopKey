package daemon

import (
	"context"
	"encoding/json"
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

	var tampered atomic.Bool
	x.w.setIntercept(func(rw http.ResponseWriter, req *http.Request, next http.Handler) bool {
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
			t.Errorf("the laptop's log read: %d %s", rec.Code, body)
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

// A retire-status request in flight when the vault locks is cancelled, and
// its answer, arriving after an unlock, does nothing. One asked and
// answered in the same unlocked session locks the vault in memory only,
// labelled server-reported and unverified.
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
	x.w.setIntercept(func(rw http.ResponseWriter, req *http.Request, _ http.Handler) bool {
		if req.URL.Path != "/v1/retire-status" {
			return false
		}
		// Read to the end, so the server notices the client going away.
		io.Copy(io.Discard, req.Body)
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
		return true
	})

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
	ender.end.Store(true)
	x.n2.d.sync.wake()
	eventually(t, 10*time.Second, "the laptop stops on the receipt", func() bool { return x.n2.status().State == SyncRevoked })
	st := x.n2.status()
	if r := st.ServerRetirement; r == nil || r.How != "revoked" || r.Seq != 99 || !r.Unverified {
		t.Errorf("server retirement %+v", r)
	}
	if !slices.ContainsFunc(st.Warnings, func(w string) bool { return strings.Contains(w, "server-reported, unverified") }) {
		t.Errorf("warnings %q", st.Warnings)
	}
	if !x.n2.st.Info().Locked || x.n2.agentKeys() != 0 {
		t.Error("the receipt did not lock the vault and empty the agent")
	}
	if x.n2.st.IsRevoked() || x.n2.st.Info().Revoked {
		t.Error("the store was marked revoked on the server's word")
	}
}

// A retire-status receipt acts only if it names this device in this
// device's account, says retired or revoked, and the store is still in the
// unlocked session the request was made in.
func TestServerRetirementChecksTheReceiptAndTheSession(t *testing.T) {
	x := newSyncSetup(t)
	x.w.start(x.n2, x.n2.st, SyncOptions{noPoll: true})
	e := x.n2.d.sync
	info, err := x.n2.st.ServerInfo()
	if err != nil {
		t.Fatal(err)
	}
	auth, err := x.n2.st.DeviceAuth()
	if err != nil {
		t.Fatal(err)
	}
	stranger, err := vaultlog.NewID()
	if err != nil {
		t.Fatal(err)
	}
	good := store.DeviceReceipt{DeviceID: auth.DeviceID, How: "revoked", Seq: 7}
	gen := x.n2.st.Generation()
	otherAccount := info
	otherAccount.AccountID = stranger

	for name, tc := range map[string]struct {
		info store.ServerInfo
		rc   store.DeviceReceipt
	}{
		"another device":  {info, store.DeviceReceipt{DeviceID: stranger, How: "revoked", Seq: 7}},
		"another account": {otherAccount, good},
		"an unknown how":  {info, store.DeviceReceipt{DeviceID: auth.DeviceID, How: "suspended", Seq: 7}},
	} {
		if e.serverRetired(gen, tc.info, auth, tc.rc) {
			t.Errorf("%s: acted on the receipt", name)
		}
	}

	// A lock and an unlock since the request: another session.
	x.n2.must(OpLock, nil, nil)
	x.n2.must(OpUnlock, UnlockParams{}, nil)
	if e.serverRetired(gen, info, auth, good) {
		t.Error("acted on a receipt asked for in an earlier session")
	}
	if x.n2.st.Info().Locked || x.n2.agentKeys() != 1 || e.status().ServerRetirement != nil {
		t.Fatal("a stale receipt had an effect")
	}

	if !e.serverRetired(x.n2.st.Generation(), info, auth, good) {
		t.Fatal("did not act on a good receipt")
	}
	if !x.n2.st.Info().Locked || x.n2.agentKeys() != 0 {
		t.Error("a good receipt did not lock the vault and empty the agent")
	}
	if r := x.n2.status().ServerRetirement; r == nil || !r.Unverified {
		t.Errorf("server retirement %+v", r)
	}
}
