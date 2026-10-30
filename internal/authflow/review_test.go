package authflow_test

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

	"github.com/dalyem/hopkey/internal/authflow"
	"github.com/dalyem/hopkey/internal/canonjson"
	"github.com/dalyem/hopkey/internal/crypto"
	"github.com/dalyem/hopkey/internal/model"
	"github.com/dalyem/hopkey/internal/store"
	"github.com/dalyem/hopkey/internal/syncclient"
)

// relayTap stands between the clients and the server (world.tap). It
// learns D's mailbox token, so it can tell D's relay reads from A's; it can
// edit a message body as one of them reads it, lose the first response of
// an enrollment transition after the server handled the request, and fail
// requests before the server sees them.
type relayTap struct {
	mu    sync.Mutex
	token string // D's mailbox token
	// edit returns a replacement for a body that D (toD) or A reads, or
	// nil to leave it.
	edit func(toD bool, typ string, body canonjson.Raw) canonjson.Raw
	// lose names the transitions whose next response is lost.
	lose map[string]bool
	// fail answers a request with 503 instead of the server.
	fail func(r *http.Request) bool
	// before runs before the server sees a request.
	before func(r *http.Request)

	lost   []string
	served map[string]int // transitions whose response was delivered
}

func (tp *relayTap) install(w *world) {
	f := tapFunc(tp.serve)
	w.tap.Store(&f)
}

func (tp *relayTap) count(key string) int {
	tp.mu.Lock()
	defer tp.mu.Unlock()
	return tp.served[key]
}

// transition names an enrollment request that changes the server's state.
func transition(r *http.Request) string {
	if r.Method != http.MethodPost {
		return ""
	}
	p := r.URL.Path
	switch {
	case p == "/v1/enroll":
		return "create mailbox"
	case p == "/v1/enroll/claim":
		return "claim"
	case strings.HasPrefix(p, "/v1/enroll/") && strings.HasSuffix(p, "/msg"):
		b, _ := io.ReadAll(r.Body)
		r.Body = io.NopCloser(bytes.NewReader(b))
		var m struct {
			Type string `json:"type"`
		}
		json.Unmarshal(b, &m)
		return "post " + m.Type
	case strings.HasPrefix(p, "/v1/vaults/") && strings.HasSuffix(p, "/log"):
		return "post entry"
	}
	return ""
}

func (tp *relayTap) serve(rw http.ResponseWriter, r *http.Request, next http.Handler) {
	if tp.before != nil {
		tp.before(r)
	}
	if tp.fail != nil && tp.fail(r) {
		rw.WriteHeader(http.StatusServiceUnavailable)
		return
	}
	key := transition(r)
	toD := false
	tp.mu.Lock()
	if tp.token != "" {
		toD = r.Header.Get("Authorization") == "Bearer "+tp.token
	}
	tp.mu.Unlock()
	rec := httptest.NewRecorder()
	next.ServeHTTP(rec, r)
	body := rec.Body.Bytes()
	ok := rec.Code == http.StatusOK

	tp.mu.Lock()
	if ok && key != "" && tp.lose[key] {
		delete(tp.lose, key)
		tp.lost = append(tp.lost, key)
		tp.mu.Unlock()
		rw.WriteHeader(http.StatusServiceUnavailable)
		return
	}
	if ok && key != "" {
		if tp.served == nil {
			tp.served = map[string]int{}
		}
		tp.served[key]++
	}
	if ok && key == "create mailbox" {
		var m struct {
			Token string `json:"mailbox_token"`
		}
		json.Unmarshal(body, &m)
		tp.token = m.Token
	}
	edit := tp.edit
	tp.mu.Unlock()
	if ok && edit != nil && r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/v1/enroll/") {
		body = editMessages(body, toD, edit)
	}
	for k, v := range rec.Header() {
		if k != "Content-Length" {
			rw.Header()[k] = v
		}
	}
	rw.WriteHeader(rec.Code)
	rw.Write(body)
}

type relayMsgs struct {
	Messages []relayMsg `json:"messages"`
}

type relayMsg struct {
	Body canonjson.Raw `json:"body"`
	N    uint64        `json:"n,string"`
	Type string        `json:"type"`
}

func editMessages(body []byte, toD bool, edit func(bool, string, canonjson.Raw) canonjson.Raw) []byte {
	var ms relayMsgs
	if canonjson.Unmarshal(body, &ms) != nil {
		return body
	}
	changed := false
	for i, m := range ms.Messages {
		if b := edit(toD, m.Type, m.Body); b != nil {
			ms.Messages[i].Body, changed = b, true
		}
	}
	if !changed {
		return body
	}
	out, err := canonjson.Marshal(ms)
	if err != nil {
		panic(err)
	}
	return out
}

// editOnce edits the first message of type typ that D (toD) or A reads,
// with f, and counts the edits.
func editOnce(toD bool, typ string, f func(canonjson.Raw) canonjson.Raw, edits *atomic.Int32) func(bool, string, canonjson.Raw) canonjson.Raw {
	return func(d bool, ty string, body canonjson.Raw) canonjson.Raw {
		if d != toD || ty != typ || !edits.CompareAndSwap(0, 1) {
			return nil
		}
		return f(body)
	}
}

func mustCanon(v any) canonjson.Raw {
	b, err := canonjson.Marshal(v)
	if err != nil {
		panic(err)
	}
	return b
}

func yes(string, string) bool { return true }

// The survivors are resolved once, against the list the user was shown:
// a name whose device left while the user typed the password never picks
// the device that joined under the same name, and an ID the list did not
// show is refused.
func TestSurvivorsResolvedFromTheList(t *testing.T) {
	ctx := context.Background()
	t.Run("a name whose device left", func(t *testing.T) {
		w := newWorld(t)
		env1, v1, kit := signedUp(t, w)
		env2, v2 := loggedIn(t, w, "laptop", password, kit.SecretKey)
		id1, id2 := deviceID(t, v1), deviceID(t, v2)
		ui1 := env1.UI.(*scriptUI)
		ui1.keep = func(authflow.SurvivorChoice) []string { return []string{"laptop"} }
		var newcomer model.ID
		ui1.onPassword = func() {
			// While the user types the password, the laptop logs out and
			// another device joins under its name.
			if _, err := authflow.Logout(ctx, env2, v2.Store, store.LogoutOptions{}); err != nil {
				t.Fatalf("the laptop's logout: %v", err)
			}
			_, v4 := loggedIn(t, w, "laptop", password, kit.SecretKey)
			newcomer = deviceID(t, v4)
		}
		if _, err := authflow.Rotate(ctx, env1, v1); !errors.Is(err, store.ErrUnknownDevice) {
			t.Fatalf("rotate keeping the departed laptop: %v; want ErrUnknownDevice", err)
		}
		if len(ui1.kits) != 0 || v1.Store.PendingKit() != nil {
			t.Fatal("a rotation committed: it kept the newcomer named laptop")
		}
		if st, err := v1.Store.PendingCheckpoint(); err != nil || st != nil {
			t.Errorf("pending checkpoint %+v %v; want none", st, err)
		}
		if got, want := deviceIDs(t, v1), sortedIDs(id1, newcomer); !slices.Equal(got, want) || slices.Contains(got, id2) {
			t.Errorf("devices %v; want %v", got, want)
		}
	})
	t.Run("an ID the list did not show", func(t *testing.T) {
		w := newWorld(t)
		env1, v1, kit := signedUp(t, w)
		ui1 := env1.UI.(*scriptUI)
		var late model.ID
		ui1.keep = func(c authflow.SurvivorChoice) []string {
			// A device that joins after the list was shown.
			_, v3 := loggedIn(t, w, "tablet", password, kit.SecretKey)
			late = deviceID(t, v3)
			return []string{late.String()}
		}
		if _, err := authflow.Rotate(ctx, env1, v1); !errors.Is(err, store.ErrUnknownDevice) {
			t.Fatalf("rotate keeping a device the list did not show: %v; want ErrUnknownDevice", err)
		}
		if len(ui1.kits) != 0 || v1.Store.PendingKit() != nil {
			t.Fatal("a rotation committed with a survivor the user was not shown")
		}
		if got := deviceIDs(t, v1); !slices.Contains(got, late) {
			t.Errorf("devices %v; want the late device still there", got)
		}
	})
}

// An open that fails the commitment is discarded on A, which keeps
// waiting and approves with the real one.
func TestApproveDiscardsInvalidOpen(t *testing.T) {
	w := newWorld(t)
	envA, vA, _ := signedUp(t, w)
	var edits atomic.Int32
	tp := &relayTap{edit: editOnce(false, syncclient.MsgOpen, func(b canonjson.Raw) canonjson.Raw {
		var o crypto.EnrollOpen
		if err := canonjson.Unmarshal(b, &o); err != nil {
			panic(err)
		}
		o.Name = "imposter"
		return mustCanon(o)
	}, &edits)}
	tp.install(w)
	_, res, err, ar, aerr := approval(t, w, envA, vA, yes, yes)
	if aerr != nil || err != nil {
		t.Fatalf("approval after a substituted open: A %v, D %v", aerr, err)
	}
	if edits.Load() != 1 {
		t.Fatal("A never read a substituted open")
	}
	if ar.DeviceName != "phone" {
		t.Errorf("A approved %q; want phone", ar.DeviceName)
	}
	if sas := envA.UI.(*scriptUI).sasShown; len(sas) != 1 {
		t.Errorf("A showed %d SAS codes; want 1, the real open's", len(sas))
	}
	wantSnippets(t, res.Vault.Store, "the approved device", "deploy")
}

// A chal that fails its schema and a delivery that fails the checks of
// step 6 are discarded on D, which keeps waiting and installs the real
// delivery.
func TestEnrollDiscardsInvalidMessages(t *testing.T) {
	for _, c := range []struct {
		typ  string
		edit func(canonjson.Raw) canonjson.Raw
	}{
		{syncclient.MsgChal, func(canonjson.Raw) canonjson.Raw { return canonjson.Raw(`{"v":1}`) }},
		// Well-formed, but for another enrollment: the store refuses it
		// (store.ErrChalInvalid).
		{syncclient.MsgChal, func(b canonjson.Raw) canonjson.Raw {
			var ch crypto.EnrollChal
			if err := canonjson.Unmarshal(b, &ch); err != nil {
				panic(err)
			}
			ch.EnrollID[0] ^= 1
			return mustCanon(ch)
		}},
		{syncclient.MsgDeliver, func(b canonjson.Raw) canonjson.Raw {
			var env crypto.HPKEEnvelope
			if err := canonjson.Unmarshal(b, &env); err != nil {
				panic(err)
			}
			env.CT[len(env.CT)/2] ^= 1
			return mustCanon(env)
		}},
	} {
		t.Run(c.typ, func(t *testing.T) {
			w := newWorld(t)
			envA, vA, _ := signedUp(t, w)
			var edits atomic.Int32
			tp := &relayTap{edit: editOnce(true, c.typ, c.edit, &edits)}
			tp.install(w)
			_, res, err, _, aerr := approval(t, w, envA, vA, yes, yes)
			if aerr != nil || err != nil {
				t.Fatalf("approval after an invalid %s: A %v, D %v", c.typ, aerr, err)
			}
			if edits.Load() != 1 {
				t.Fatalf("D never read an invalid %s", c.typ)
			}
			wantSnippets(t, res.Vault.Store, "the approved device", "deploy")
		})
	}
}

// D whose log reads keep failing after the delivery arrived is
// interrupted, not ended: the same process resumes it with the mailbox
// and installs the delivery.
func TestEnrollInterruptedInstallResumes(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	w := newWorld(t)
	envA, vA, _ := signedUp(t, w)
	var down atomic.Bool
	down.Store(true)
	tp := &relayTap{}
	tp.fail = func(r *http.Request) bool {
		return down.Load() && r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/v1/vaults/") && tp.count("post deliver") > 0
	}
	tp.install(w)
	setSAS(envA, yes)
	d := startEnroll(t, ctx, w, vA, yes)
	if _, err := authflow.Approve(ctx, envA, vA, d.code); err != nil {
		t.Fatalf("approve: %v", err)
	}
	_, err := d.wait(t)
	var ie *authflow.EnrollInterruptedError
	if !errors.As(err, &ie) || ie.Mailbox == nil {
		t.Fatalf("D with the server's log down: %v; want an *EnrollInterruptedError with the mailbox", err)
	}
	down.Store(false)
	d.resume(ctx, authflow.EnrollOptions{Email: email, DeviceName: "phone", VaultID: vA.VaultID, Mailbox: ie.Mailbox})
	res, err := d.wait(t)
	if err != nil {
		t.Fatalf("D resumed: %v", err)
	}
	wantSnippets(t, res.Vault.Store, "the approved device", "deploy")
	if got, want := deviceIDs(t, vA), sortedIDs(deviceID(t, vA), deviceID(t, res.Vault)); !slices.Equal(got, want) {
		t.Errorf("devices %v; want %v", got, want)
	}
}

// A mailbox that expires while A waits for the open ends A's attempt as a
// failure.
func TestApprovalMailboxExpires(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	w := newWorld(t)
	envA, vA, _ := signedUp(t, w)
	// A new device that posts its commit and then goes quiet.
	envD := w.env(t, "phone", &scriptUI{})
	e, commit, err := store.BeginEnrollment(envD.Config, store.EnrollParams{ServerURL: w.origin, DeviceName: "phone"})
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	mb, err := envD.Client.CreateMailbox(ctx, commit)
	if err != nil {
		t.Fatal(err)
	}
	// The server's clock passes the mailbox's lifetime once A waits for
	// the open.
	tp := &relayTap{before: func(r *http.Request) {
		if r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/v1/enroll/") {
			w.skew.Store(int64(crypto.EnrollDeadline + time.Minute))
		}
	}}
	tp.install(w)
	if _, err := authflow.Approve(ctx, envA, vA, mb.RoutingCode); !errors.Is(err, crypto.ErrEnrollExpired) {
		t.Fatalf("approve with the mailbox expiring: %v; want ErrEnrollExpired", err)
	}
	if tp.count("post chal") != 1 {
		t.Error("A did not send its chal before the mailbox expired")
	}
	info, err := vA.Store.Approval()
	if err != nil || info == nil || info.State != crypto.ApprovalFailed {
		t.Fatalf("approval %+v %v; want FAILED", info, err)
	}
}

var errNoTerminal = errors.New("no terminal to ask on")

// An approval interrupted at the SAS resumes: A with the same code, D in
// the same process with the mailbox.
func TestApprovalResumes(t *testing.T) {
	t.Run("A", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		defer cancel()
		w := newWorld(t)
		envA, vA, _ := signedUp(t, w)
		setSAS(envA, yes)
		envA.UI.(*scriptUI).failSAS = errNoTerminal
		d := startEnroll(t, ctx, w, vA, yes)
		if _, err := authflow.Approve(ctx, envA, vA, d.code); !errors.Is(err, errNoTerminal) {
			t.Fatalf("approve with no answer to the SAS: %v", err)
		}
		if info, err := vA.Store.Approval(); err != nil || info == nil || info.State != crypto.ApprovalOpened {
			t.Fatalf("approval %+v %v; want OPENED", info, err)
		}
		ar, err := authflow.Approve(ctx, envA, vA, d.code)
		if err != nil {
			t.Fatalf("approve again: %v", err)
		}
		res, err := d.wait(t)
		if err != nil || ar.DeviceName != "phone" {
			t.Fatalf("D: %v; A approved %q", err, ar.DeviceName)
		}
		wantSnippets(t, res.Vault.Store, "the approved device", "deploy")
	})
	t.Run("D", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		defer cancel()
		w := newWorld(t)
		envA, vA, _ := signedUp(t, w)
		setSAS(envA, yes)
		d := startEnroll(t, ctx, w, vA, yes)
		d.ui.mu.Lock()
		d.ui.failSAS = errNoTerminal
		d.ui.mu.Unlock()
		if _, err := authflow.Approve(ctx, envA, vA, d.code); err != nil {
			t.Fatalf("approve: %v", err)
		}
		_, err := d.wait(t)
		var ie *authflow.EnrollInterruptedError
		if !errors.As(err, &ie) || !errors.Is(err, errNoTerminal) || ie.Mailbox == nil {
			t.Fatalf("D with no answer to the SAS: %v; want an *EnrollInterruptedError", err)
		}
		d.resume(ctx, authflow.EnrollOptions{Email: email, DeviceName: "phone", VaultID: vA.VaultID, Mailbox: ie.Mailbox})
		res, err := d.wait(t)
		if err != nil {
			t.Fatalf("D resumed: %v", err)
		}
		wantSnippets(t, res.Vault.Store, "the approved device", "deploy")
	})
}

// A response lost after the server handled the request, at each
// transition of an enrollment, is retried, and the approval completes.
func TestApprovalLostResponses(t *testing.T) {
	w := newWorld(t)
	envA, vA, _ := signedUp(t, w)
	keys := []string{"create mailbox", "claim", "post chal", "post open", "post entry", "post deliver"}
	tp := &relayTap{lose: map[string]bool{}}
	for _, k := range keys {
		tp.lose[k] = true
	}
	tp.install(w)
	_, res, err, ar, aerr := approval(t, w, envA, vA, yes, yes)
	if aerr != nil || err != nil {
		t.Fatalf("approval with lost responses: A %v, D %v", aerr, err)
	}
	tp.mu.Lock()
	lost := slices.Clone(tp.lost)
	tp.mu.Unlock()
	slices.Sort(lost)
	slices.Sort(keys)
	if !slices.Equal(lost, keys) {
		t.Errorf("lost responses %v; want %v", lost, keys)
	}
	if ar.DeviceName != "phone" {
		t.Errorf("A approved %q", ar.DeviceName)
	}
	wantSnippets(t, res.Vault.Store, "the approved device", "deploy")
}

// A logout whose cleanup failed part way finishes on the same store.
func TestLogoutResumesCleanup(t *testing.T) {
	ctx := context.Background()
	w := newWorld(t)
	_, v1, kit := signedUp(t, w)
	env2, v2 := loggedIn(t, w, "laptop", password, kit.SecretKey)
	id1, id2 := deviceID(t, v1), deviceID(t, v2)
	env2.Config.Keyring.(*memRing).failDelete.Store(1)
	res, err := authflow.Logout(ctx, env2, v2.Store, store.LogoutOptions{})
	if err == nil || res.State != store.StateRetired || res.Done {
		t.Fatalf("logout with the keychain refusing: %+v %v; want RETIRED, not done", res, err)
	}
	res, err = authflow.Logout(ctx, env2, v2.Store, store.LogoutOptions{})
	if err != nil || !res.Done || res.Outcome != store.OutcomeCommitted {
		t.Fatalf("logout again: %+v %v; want done", res, err)
	}
	if ok, err := store.Exists(env2.Config.DataDir); err != nil || ok {
		t.Errorf("a vault is left after the logout: %v %v", ok, err)
	}
	if got := deviceIDs(t, v1); !slices.Equal(got, []model.ID{id1}) || slices.Contains(got, id2) {
		t.Errorf("devices %v; want only device 1", got)
	}
}
