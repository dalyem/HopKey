package server

import (
	"bytes"
	"errors"
	"math"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/dalyem/hopkey/internal/canonjson"
	"github.com/dalyem/hopkey/internal/crypto"
	"github.com/dalyem/hopkey/internal/model"
	"github.com/dalyem/hopkey/internal/vaultlog"
)

// Account A's credentials never reach vault B, and every refusal looks
// like an absent vault (R1).
func TestTenantIsolation(t *testing.T) {
	e := newEnv(t)
	a, b := newVault(t, "a@example.com"), newVault(t, "b@example.com")
	e.publish(a)
	e.publish(b)
	sessA, loginA := e.session(a, a.dev(0)), e.login(a)
	sessB := e.session(b, b.dev(0))
	bObj := b.log[0].Entry.ObjectDigests()[0]
	aObj := a.log[0].Entry.ObjectDigests()[0]
	absent := randID(t).String()

	notFound := e.do("GET", "/v1/vaults/"+absent+"/log", sessA, nil)
	wantCode(t, notFound, 404, "not_found", "absent vault")
	for _, tok := range []string{sessA, loginA} {
		for name, r := range map[string]resp{
			"log":          e.do("GET", logPath(b), tok, nil),
			"long-poll":    e.do("GET", logPath(b)+"?after=0&wait=1", tok, nil),
			"entry":        e.do("GET", "/v1/vaults/"+b.vaultID().String()+"/entries/0", tok, nil),
			"object":       e.do("GET", "/v1/vaults/"+b.vaultID().String()+"/objects/"+bObj.String(), tok, nil),
			"post":         e.post(b, tok, b.unrecorded(b.dev(0))),
			"absent entry": e.do("GET", "/v1/vaults/"+absent+"/entries/0", tok, nil),
			"malformed":    e.do("GET", "/v1/vaults/zz/log", tok, nil),
		} {
			if r.status != 404 || !bytes.Equal(r.body, notFound.body) {
				t.Errorf("%s of vault B with A's credential: %s, want the absent-vault response %s", name, r, notFound)
			}
		}
	}
	// A's object is not B's, even for B's own credential.
	r := e.do("GET", "/v1/vaults/"+b.vaultID().String()+"/objects/"+aObj.String(), sessB, nil)
	if r.status != 404 || !bytes.Equal(r.body, notFound.body) {
		t.Errorf("A's object through vault B: %s", r)
	}
	// B is unchanged, and its own reads work.
	rb, page := e.readLog(b, sessB, "")
	wantStatus(t, rb, 200, "B reads its log")
	if page.Head != b.head() || len(page.Entries) != 1 {
		t.Errorf("B's log changed: head %+v, %d entries", page.Head, len(page.Entries))
	}
	wantStatus(t, e.do("GET", "/v1/vaults/"+a.vaultID().String()+"/objects/"+aObj.String(), sessA, nil), 200, "A reads its object")
	// No credential, or a malformed one: 401 before anything else.
	wantCode(t, e.do("GET", logPath(b), "", nil), 401, "unauthorized", "no credential")
	wantCode(t, e.do("GET", logPath(b), "not-a-token", nil), 401, "unauthorized", "malformed credential")
}

// startPoll long-polls the log in the background and waits until the
// server holds the poll.
func (e *env) startPoll(v *tvault, tok string, after uint64) <-chan resp {
	e.t.Helper()
	before := e.polls()
	ch := make(chan resp, 1)
	go func() {
		ch <- e.do("GET", logPath(v)+"?after="+itoa(after)+"&wait=30", tok, nil)
	}()
	deadline := time.Now().Add(10 * time.Second)
	for e.polls() == before {
		if time.Now().After(deadline) {
			e.t.Fatal("the long-poll never started waiting")
		}
		time.Sleep(5 * time.Millisecond)
	}
	return ch
}

func (e *env) polls() int {
	e.srv.polls.mu.Lock()
	defer e.srv.polls.mu.Unlock()
	return e.srv.polls.total
}

func itoa(n uint64) string { return strconv.FormatUint(n, 10) }

func waitResp(t *testing.T, ch <-chan resp) resp {
	t.Helper()
	select {
	case r := <-ch:
		return r
	case <-time.After(15 * time.Second):
		t.Fatal("the long-poll did not return")
		return resp{}
	}
}

func TestLongPollWakesOnCommit(t *testing.T) {
	e := newEnv(t)
	v := newVault(t, "a@example.com")
	e.publish(v)
	tok := e.session(v, v.dev(0))
	ch := e.startPoll(v, tok, v.head().Seq)
	w := v.normal(v.dev(0), 1, 10)
	e.mustPost(v, tok, w)
	r := waitResp(t, ch)
	var p logPage
	e.must(r, 200, &p)
	if len(p.Entries) != 1 || p.Entries[0].Seq != w.Entry.Seq || p.Head != v.head() {
		t.Errorf("woken poll returned %s", r.body)
	}
}

// A checkpoint ends every session of the account, survivors included, and
// a long-poll waiting on one of them wakes with a 401 (R2). Revoked
// devices also lose their challenges and get a receipt.
func TestCheckpointInvalidatesEverySession(t *testing.T) {
	e := newEnv(t)
	v := newVault(t, "a@example.com")
	e.publish(v)
	A := v.dev(0)
	login := e.login(v)
	B, wb := v.bootstrap("dev-b")
	e.mustPost(v, login, wb)
	C, wc := v.bootstrap("dev-c")
	e.mustPost(v, e.login(v), wc)
	sessA, sessB, sessC := e.session(v, A), e.session(v, B), e.session(v, C)

	poll := e.startPoll(v, sessB, v.head().Seq)
	ck := v.checkpoint(A, C)
	e.mustPost(v, sessA, ck)

	r := waitResp(t, poll)
	wantCode(t, r, 401, "unauthorized", "B's long-poll across the checkpoint")
	if strings.Contains(string(r.body), "entries") {
		t.Errorf("the 401 carries data: %s", r.body)
	}
	for name, tok := range map[string]string{"A (author)": sessA, "B (survivor)": sessB, "C (revoked)": sessC} {
		r, _ := e.readLog(v, tok, "")
		wantCode(t, r, 401, "unauthorized", name+" session after the checkpoint")
	}
	// Survivors authenticate again; the revoked device cannot.
	for _, d := range []model.ID{A, B} {
		r, _ := e.readLog(v, e.session(v, d), "")
		wantStatus(t, r, 200, "a survivor's fresh session")
	}
	wantCode(t, e.challenge(v, C, "session"), 401, "unauthorized", "session challenge for the revoked device")
	wantStatus(t, e.challenge(v, C, "retire-status"), 200, "retire-status challenge for the revoked device")
	ckH, _ := ck.Entry.Hash()
	e.view(func(tx Tx) error {
		rc, err := tx.Receipt(v.accountID(), C)
		if err != nil {
			t.Fatalf("no receipt for the revoked device: %v", err)
		}
		if rc.How != vaultlog.DepartRevoked || rc.Seq != ck.Entry.Seq || rc.H != ckH {
			t.Errorf("receipt %+v", rc)
		}
		d, err := tx.Device(v.accountID(), C)
		if err != nil || d.Active {
			t.Errorf("revoked device row %+v, %v", d, err)
		}
		if _, err := tx.Receipt(v.accountID(), B); !errors.Is(err, ErrNotFound) {
			t.Errorf("a survivor has a receipt: %v", err)
		}
		a, err := tx.Account(v.accountID())
		if err != nil {
			return err
		}
		if a.CredGen != 2 || a.AuthSHA256 != crypto.SHA256(v.authKey) || a.RAuthSHA256 != crypto.SHA256(v.rAuth) ||
			!bytes.Equal(a.Salt, v.st.Creds.Salt) {
			t.Errorf("derived creds not updated: %+v", a)
		}
		return nil
	})
}

// A device_retire ends that device's sessions only and writes its receipt.
func TestRetireInvalidatesDeviceAndWritesReceipt(t *testing.T) {
	e := newEnv(t)
	v := newVault(t, "a@example.com")
	e.publish(v)
	A := v.dev(0)
	B, wb := v.bootstrap("dev-b")
	e.mustPost(v, e.login(v), wb)
	sessA, sessB := e.session(v, A), e.session(v, B)
	sessB2 := e.session(v, B)
	// A challenge issued before the removal must not yield a session after
	// it (R2).
	early := e.newChallenge(v, B, "session")

	ret := v.retire(B)
	e.mustPost(v, sessB, ret)
	wantCode(t, e.sessionResp(v, B, early, e.signAuth(v, B, "session", testOrigin, early)), 401, "unauthorized",
		"a challenge issued before the retirement")
	for _, tok := range []string{sessB, sessB2} {
		r, _ := e.readLog(v, tok, "")
		wantCode(t, r, 401, "unauthorized", "retired device's session")
	}
	r, _ := e.readLog(v, sessA, "")
	wantStatus(t, r, 200, "another device's session after the retirement")
	wantCode(t, e.challenge(v, B, "session"), 401, "unauthorized", "session challenge for the retired device")
	wantStatus(t, e.challenge(v, B, "retire-status"), 200, "retire-status challenge for the retired device")

	retH, _ := ret.Entry.Hash()
	e.view(func(tx Tx) error {
		rc, err := tx.Receipt(v.accountID(), B)
		if err != nil {
			t.Fatalf("no receipt: %v", err)
		}
		if rc.How != vaultlog.DepartRetired || rc.Seq != ret.Entry.Seq || rc.H != retH {
			t.Errorf("receipt %+v", rc)
		}
		d, err := tx.Device(v.accountID(), B)
		if err != nil || d.Active || len(d.SigPK) != 32 {
			t.Errorf("retired device row %+v, %v", d, err)
		}
		return nil
	})
}

// Login and recovery tokens carry the credential generation and die when it
// changes (R2, R6).
func TestLoginTokensDieOnCredentialChange(t *testing.T) {
	e := newEnv(t)
	v := newVault(t, "a@example.com")
	e.publish(v)
	oldAuth, oldRAuth := v.authKey, v.rAuth
	login, rec := e.login(v), e.recoverToken(v)
	for _, tok := range []string{login, rec} {
		r, _ := e.readLog(v, tok, "")
		wantStatus(t, r, 200, "token before the checkpoint")
	}
	e.mustPost(v, e.session(v, v.dev(0)), v.checkpoint(v.dev(0)))
	for name, tok := range map[string]string{"login": login, "recovery": rec} {
		r, _ := e.readLog(v, tok, "")
		wantCode(t, r, 401, "unauthorized", name+" token after the checkpoint")
	}
	wantCode(t, e.do("POST", "/v1/login", "", loginRequest{v.accountID(), oldAuth}), 401, "unauthorized", "the old auth key")
	wantCode(t, e.do("POST", "/v1/recover", "", recoverRequest{v.accountID(), oldRAuth}), 401, "unauthorized", "the old rAuth")
	r, _ := e.readLog(v, e.login(v), "")
	wantStatus(t, r, 200, "a token under the new credentials")
	r, _ = e.readLog(v, e.recoverToken(v), "")
	wantStatus(t, r, 200, "a recovery token under the new credentials")

	// Tokens also expire after 10 minutes.
	tok := e.login(v)
	e.clock.advance(LoginTokenTTL)
	r, _ = e.readLog(v, tok, "")
	wantCode(t, r, 401, "unauthorized", "an expired login token")
}

// A login or recovery token commits one bootstrap. Failures don't consume
// it, an identical retry returns the commit, and a second, different
// bootstrap is refused. It writes nothing but a bootstrap (R6).
func TestBootstrapConsumedOnce(t *testing.T) {
	for _, kind := range []string{"login", "recovery"} {
		t.Run(kind, func(t *testing.T) {
			e := newEnv(t)
			v := newVault(t, "a@example.com")
			e.publish(v)
			tok := e.login(v)
			if kind == "recovery" {
				tok = e.recoverToken(v)
			}
			wantCode(t, e.post(v, tok, v.unrecorded(v.dev(0))), 401, "unauthorized", "a normal entry by token")

			// A stale bootstrap: head conflict, nothing consumed.
			stale := *v
			stale.log = nil
			_, wStale := stale.bootstrap("stale")
			e.mustPost(v, e.session(v, v.dev(0)), v.normal(v.dev(0), 1, 1))
			wantCode(t, e.post(v, tok, wStale), 409, "head_conflict", "a stale bootstrap")

			// An invalid bootstrap: rejected, nothing consumed.
			B, wb := v.bootstrap("dev-b")
			bad := *wb
			bad.Sigs = []vaultlog.Sig{{Role: vaultlog.RoleAccount, Sig: bytes.Repeat([]byte{1}, 64)}}
			wantCode(t, e.post(v, tok, &bad), 400, "invalid_entry", "a badly signed bootstrap")

			e.mustPost(v, tok, wb)
			e.mustPost(v, tok, wb) // identical retry
			_, wc := v.bootstrap("dev-c")
			wantCode(t, e.post(v, tok, wc), 401, "unauthorized", "a second bootstrap")
			// The token still reads, and the bootstrapped device gets a session.
			r, _ := e.readLog(v, tok, "")
			wantStatus(t, r, 200, "reads after the bootstrap")
			r, _ = e.readLog(v, e.session(v, B), "")
			wantStatus(t, r, 200, "the new device's session")
		})
	}
}

// Session writes: the session's device must author the entry, and a
// session never posts a bootstrap (R1).
func TestSessionWritesNeedTheAuthorDevice(t *testing.T) {
	e := newEnv(t)
	v := newVault(t, "a@example.com")
	e.publish(v)
	A := v.dev(0)
	B, wb := v.bootstrap("dev-b")
	e.mustPost(v, e.login(v), wb)
	sessB := e.session(v, B)
	wantCode(t, e.post(v, sessB, v.unrecorded(A)), 401, "unauthorized", "B posting A's entry")
	_, wc := v.bootstrap("dev-c")
	wantCode(t, e.post(v, sessB, wc), 401, "unauthorized", "a bootstrap by session")
}

// The R11 head conflict: 409 with the error and the head.
func TestHeadConflictShape(t *testing.T) {
	e := newEnv(t)
	v := newVault(t, "a@example.com")
	e.publish(v)
	tok := e.session(v, v.dev(0))
	w1 := v.unrecorded(v.dev(0))
	e.mustPost(v, tok, v.normal(v.dev(0), 1, 1))
	r := e.post(v, tok, w1)
	want := `{"error":{"code":"head_conflict","message":"prev is not the head"},"head":{"h":"` +
		v.head().H.String() + `","seq":"` + itoa(v.head().Seq) + `"}}`
	if r.status != 409 || string(r.body) != want {
		t.Errorf("head conflict: %s\nwant 409 %s", r, want)
	}
	// An identical committed H is idempotent, not a conflict.
	last := v.log[len(v.log)-1]
	e.mustPost(v, tok, last)
}

// Only objects an entry names are stored and served; the stored wire
// carries only those (R11).
func TestOnlyReferencedObjectsAreStored(t *testing.T) {
	e := newEnv(t)
	v := newVault(t, "a@example.com")
	e.publish(v)
	tok := e.session(v, v.dev(0))
	w := v.normal(v.dev(0), 1, 10)
	key, err := crypto.NewSymKey()
	if err != nil {
		t.Fatal(err)
	}
	env, err := crypto.SealAEAD(&key, []byte("unreferenced"), nil)
	if err != nil {
		t.Fatal(err)
	}
	extraBody, err := canonjson.Marshal(env)
	if err != nil {
		t.Fatal(err)
	}
	extra := crypto.SHA256(extraBody)
	sent := *w
	sent.Objects = append(append([]vaultlog.Object{}, w.Objects...), vaultlog.Object{SHA256: extra, Body: extraBody})
	e.mustPost(v, tok, &sent)

	base := "/v1/vaults/" + v.vaultID().String()
	wantCode(t, e.do("GET", base+"/objects/"+extra.String(), tok, nil), 404, "not_found", "the unreferenced object")
	var got struct {
		Seq  uint64        `json:"seq,string"`
		H    crypto.Hash   `json:"h"`
		Wire canonjson.Raw `json:"wire"`
	}
	e.must(e.do("GET", base+"/entries/"+itoa(w.Entry.Seq), tok, nil), 200, &got)
	if !bytes.Equal(got.Wire, wireJSON(t, w)) {
		t.Errorf("stored wire differs from the wire without the extra object")
	}
	if bytes.Contains(got.Wire, []byte(extra.String())) {
		t.Error("the stored wire names the unreferenced object")
	}
	for _, d := range w.Entry.ObjectDigests() {
		r := e.do("GET", base+"/objects/"+d.String(), tok, nil)
		wantStatus(t, r, 200, "a referenced object")
		if crypto.SHA256(r.body) != d {
			t.Errorf("object %v: body digest %v", d, crypto.SHA256(r.body))
		}
	}
	wantCode(t, e.do("GET", base+"/entries/99", tok, nil), 404, "not_found", "an absent entry")
	e.view(func(tx Tx) error {
		if _, err := tx.Object(v.vaultID(), extra); !errors.Is(err, ErrNotFound) {
			t.Errorf("the unreferenced object is stored: %v", err)
		}
		return nil
	})
}

// Pages make progress and stay within the entry and byte caps; a wire
// whose singleton response is over the cap is refused (R9).
func TestPagingAndSingletonCap(t *testing.T) {
	const maxWire = 24 << 10
	e := newEnv(t, withLimits(func(l *Limits) {
		l.MaxPageEntries = 4
		l.MaxPageBytes = maxWire + 2000
		l.MaxWireResponse = maxWire
	}))
	v := newVault(t, "a@example.com")
	e.publish(v)
	tok := e.session(v, v.dev(0))
	for i := range 9 {
		e.mustPost(v, tok, v.normal(v.dev(0), 1, 500+800*i))
	}
	y := strings.Repeat("y", 8000)
	big, _, _, err := vaultlog.BuildNormal(v.st, v.sec, v.devs[v.dev(0)],
		vaultlog.Changes{Put: []crypto.Item{snippet(t, y), snippet(t, y), snippet(t, y)}}, v.now(), v.archive)
	if err != nil {
		t.Fatal(err)
	}
	wantCode(t, e.post(v, tok, big), 413, "too_large", "a wire over the singleton cap")

	var seqs []uint64
	query := ""
	for pages := 0; ; pages++ {
		if pages > 20 {
			t.Fatal("paging does not finish")
		}
		r, p := e.readLog(v, tok, query)
		wantStatus(t, r, 200, "page")
		if p.Head != v.head() {
			t.Errorf("page head %+v, want %+v", p.Head, v.head())
		}
		if len(p.Entries) > 4 {
			t.Errorf("page of %d entries", len(p.Entries))
		}
		if len(p.Entries) > 1 && len(r.body) > maxWire+2000 {
			t.Errorf("page of %d bytes with %d entries", len(r.body), len(p.Entries))
		}
		if len(p.Entries) == 0 {
			break
		}
		for _, en := range p.Entries {
			seqs = append(seqs, en.Seq)
		}
		query = "?after=" + itoa(p.Entries[len(p.Entries)-1].Seq)
	}
	for i, s := range seqs {
		if s != uint64(i) {
			t.Fatalf("paged seqs %v, want 0..%d", seqs, len(v.log)-1)
		}
	}
	if len(seqs) != len(v.log) {
		t.Errorf("paged %d entries, want %d", len(seqs), len(v.log))
	}
	r, p := e.readLog(v, tok, "?after="+itoa(v.head().Seq+5))
	if r.status != 200 || len(p.Entries) != 0 {
		t.Errorf("after beyond the head: %s", r)
	}
	wantCode(t, e.do("GET", logPath(v)+"?after=01", tok, nil), 400, "bad_request", "a non-canonical after")
	wantCode(t, e.do("GET", logPath(v)+"?wait=56", tok, nil), 400, "bad_request", "wait over 55")
}

// The manual page assembly is exactly the JCS encoding, and its length
// formulas match.
func TestPageEncodingIsJCS(t *testing.T) {
	e := newEnv(t)
	v := newVault(t, "a@example.com")
	e.publish(v)
	tok := e.session(v, v.dev(0))
	e.mustPost(v, tok, v.normal(v.dev(0), 2, 50))
	r, p := e.readLog(v, tok, "")
	j, err := canonjson.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(j, r.body) {
		t.Errorf("page is not JCS:\n got %s\nwant %s", r.body, j)
	}
	n := frameLen(digits(p.Head.Seq)) + len(p.Entries) - 1
	for _, en := range p.Entries {
		n += itemLen(en.Seq, len(en.Wire))
	}
	if n != len(r.body) {
		t.Errorf("computed length %d, actual %d", n, len(r.body))
	}
	// The singleton measure is the response with a 20-digit head seq.
	wj := wireJSON(t, v.log[0])
	b := append([]byte(nil), pageOpen...)
	b = appendItem(b, &LogEntry{Seq: 0, Wire: wj})
	b = append(b, pageMid...)
	b = appendHead(b, vaultlog.Head{Seq: math.MaxUint64})
	b = append(b, pageClose...)
	if len(b) != singletonLen(0, len(wj)) {
		t.Errorf("singletonLen %d, a singleton response with a 20-digit head is %d bytes", singletonLen(0, len(wj)), len(b))
	}
}

// R8: concurrent long-polls are limited per credential.
func TestLongPollLimitPerCredential(t *testing.T) {
	e := newEnv(t, withLimits(func(l *Limits) { l.PollsPerCredential = 1 }))
	v := newVault(t, "a@example.com")
	e.publish(v)
	tok := e.session(v, v.dev(0))
	ch := e.startPoll(v, tok, v.head().Seq)
	wantCode(t, e.do("GET", logPath(v)+"?after="+itoa(v.head().Seq)+"&wait=5", tok, nil), 429, "busy", "a second poll on one credential")
	r, _ := e.readLog(v, tok, "")
	wantStatus(t, r, 200, "a plain read on the same credential")
	other := e.startPoll(v, e.session(v, v.dev(0)), v.head().Seq)
	e.mustPost(v, tok, v.normal(v.dev(0), 1, 1))
	wantStatus(t, waitResp(t, ch), 200, "the first poll")
	wantStatus(t, waitResp(t, other), 200, "a poll on another credential")
}

// A page always makes progress, even when one entry is larger than the page
// byte cap (R9).
func TestPageAlwaysMakesProgress(t *testing.T) {
	e := newEnv(t, withLimits(func(l *Limits) { l.MaxPageBytes = 100 }))
	v := newVault(t, "a@example.com")
	e.publish(v)
	tok := e.session(v, v.dev(0))
	e.mustPost(v, tok, v.normal(v.dev(0), 1, 10))
	e.mustPost(v, tok, v.normal(v.dev(0), 1, 10))
	query := ""
	for want := uint64(0); want <= v.head().Seq; want++ {
		r, p := e.readLog(v, tok, query)
		if r.status != 200 || len(p.Entries) != 1 || p.Entries[0].Seq != want {
			t.Fatalf("page after %q: %s", query, r)
		}
		query = "?after=" + itoa(want)
	}
}

// pauser pauses the first request that reaches a hook after it is armed.
type pauser struct {
	armed   atomic.Bool
	once    sync.Once
	paused  chan struct{}
	resumed chan struct{}
}

func newPauser() *pauser {
	return &pauser{paused: make(chan struct{}), resumed: make(chan struct{})}
}

func (p *pauser) hook() {
	if p.armed.Load() {
		p.once.Do(func() {
			close(p.paused)
			<-p.resumed
		})
	}
}

func (p *pauser) waitPaused(t *testing.T) {
	t.Helper()
	select {
	case <-p.paused:
	case <-time.After(15 * time.Second):
		t.Fatal("no request reached the hook")
	}
}

// A log response is admitted by a fresh authentication immediately before
// it is written: a credential revoked or expired after the page was built
// gets a 401 with no data (R2), including on the shutdown path.
func TestLogResponseAdmissionRechecksAuth(t *testing.T) {
	for _, mode := range []string{"read", "long-poll"} {
		t.Run(mode+" revoked by a checkpoint", func(t *testing.T) {
			p := newPauser()
			e := newEnv(t, withHooks(func(s *Server) { s.hooks.beforeSend = p.hook }))
			v := newVault(t, "a@example.com")
			e.publish(v)
			A := v.dev(0)
			reader, writer := e.session(v, A), e.session(v, A)
			var got <-chan resp
			if mode == "read" {
				p.armed.Store(true)
				ch := make(chan resp, 1)
				go func() { ch <- e.do("GET", logPath(v), reader, nil) }()
				got = ch
			} else {
				got = e.startPoll(v, reader, v.head().Seq)
				p.armed.Store(true)
				// The commit wakes the poll, which builds a page holding it.
				e.mustPost(v, writer, v.normal(A, 1, 10))
			}
			p.waitPaused(t)
			e.mustPost(v, writer, v.checkpoint(A))
			close(p.resumed)
			r := waitResp(t, got)
			wantCode(t, r, 401, "unauthorized", "a page built before the checkpoint")
			if strings.Contains(string(r.body), "entries") {
				t.Errorf("the 401 carries data: %s", r.body)
			}
		})
	}
	t.Run("expired at shutdown", func(t *testing.T) {
		e := newEnv(t)
		v := newVault(t, "a@example.com")
		e.publish(v)
		poll := e.startPoll(v, e.session(v, v.dev(0)), v.head().Seq)
		e.clock.advance(SessionTTL)
		e.srv.Close()
		r := waitResp(t, poll)
		wantCode(t, r, 401, "unauthorized", "a poll woken by shutdown after its session expired")
		if strings.Contains(string(r.body), "entries") {
			t.Errorf("the 401 carries data: %s", r.body)
		}
	})
	t.Run("valid at shutdown", func(t *testing.T) {
		e := newEnv(t)
		v := newVault(t, "a@example.com")
		e.publish(v)
		poll := e.startPoll(v, e.session(v, v.dev(0)), v.head().Seq)
		e.srv.Close()
		var p logPage
		e.must(waitResp(t, poll), 200, &p)
		if len(p.Entries) != 0 || p.Head != v.head() {
			t.Errorf("shutdown answer %+v", p)
		}
	})
}

// R14: a write takes a validation slot before any of its body is decoded,
// so with every slot and queue position taken another write gets a 429
// and is never parsed.
func TestValidationSlotBeforeParsing(t *testing.T) {
	var prepares atomic.Int64
	entered, release := make(chan struct{}, 2), make(chan struct{})
	e := newEnv(t, withLimits(func(l *Limits) { l.ValidationJobs, l.ValidationQueue = 1, 1 }), withHooks(func(s *Server) {
		s.hooks.prepare = func() { prepares.Add(1) }
		s.hooks.validating = func() {
			entered <- struct{}{}
			<-release
		}
	}))
	v := newVault(t, "a@example.com")
	e.publish(v)
	tok := e.session(v, v.dev(0))
	w := v.normal(v.dev(0), 1, 10)
	base := prepares.Load()

	first, second := make(chan resp, 1), make(chan resp, 1)
	go func() { first <- e.post(v, tok, w) }()
	select {
	case <-entered:
	case <-time.After(15 * time.Second):
		t.Fatal("the first write never took the slot")
	}
	go func() { second <- e.post(v, tok, w) }()
	deadline := time.Now().Add(10 * time.Second)
	for {
		e.srv.validate.mu.Lock()
		n := e.srv.validate.waiting
		e.srv.validate.mu.Unlock()
		if n == 1 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the second write never queued")
		}
		time.Sleep(time.Millisecond)
	}
	wantCode(t, e.post(v, tok, w), 429, "busy", "a write with the slot and the queue full")
	if n := prepares.Load() - base; n != 0 {
		t.Errorf("%d wires prepared while every slot was held", n)
	}
	close(release)
	wantStatus(t, waitResp(t, first), 200, "the write holding the slot")
	wantStatus(t, waitResp(t, second), 200, "the queued write")
	if n := prepares.Load() - base; n != 2 {
		t.Errorf("%d wires prepared, want the 2 admitted ones", n)
	}
}

// R14 collection limits refuse a write from a scan of its bytes, before
// the strict decoder or prepare runs.
func TestCollectionLimitsBeforeParsing(t *testing.T) {
	var prepares atomic.Int64
	e := newEnv(t, withHooks(func(s *Server) { s.hooks.prepare = func() { prepares.Add(1) } }))
	v := newVault(t, "a@example.com")
	e.publish(v)
	tok := e.session(v, v.dev(0))
	base := prepares.Load()
	many := func(n int) string { return "[" + strings.Repeat(`{"a":[1,"]"]},`, n-1) + `{}]` }
	for name, body := range map[string]string{
		"8,193 ops":      `{"wire":{"entry":{"ops":` + many(8193) + `},"sigs":[],"objects":[]}}`,
		"16,385 objects": `{"wire":{"entry":{"ops":[]},"sigs":[],"objects":` + many(16385) + `}}`,
	} {
		wantCode(t, e.do("POST", logPath(v), tok, []byte(body)), 413, "too_large", name)
	}
	// At the limits the scan passes, and the decoder rejects the shape.
	wantCode(t, e.do("POST", logPath(v), tok, []byte(`{"wire":{"entry":{"ops":`+many(8192)+`},"sigs":[],"objects":`+many(16384)+`}}`)),
		400, "invalid_entry", "a malformed wire at the limits")
	if n := prepares.Load() - base; n != 0 {
		t.Errorf("%d wires prepared", n)
	}
	code := e.invite("b@example.com")
	wires := `{"email":"b@example.com","registration_code":"` + code + `","challenge":"","pop_sig":"","wires":[` +
		strings.Repeat(`{},`, 16384) + `{}]}`
	wantCode(t, e.do("POST", "/v1/signup", "", []byte(wires)), 413, "too_large", "16,385 signup wires")
	ops := `{"email":"b@example.com","registration_code":"` + code + `","challenge":"","pop_sig":"","wires":[{},` +
		`{"entry":{"ops":` + many(8193) + `}}]}`
	wantCode(t, e.do("POST", "/v1/signup", "", []byte(ops)), 413, "too_large", "a signup wire with 8,193 ops")
}

func TestArrayLens(t *testing.T) {
	type got struct {
		path string
		n    int
	}
	var out []got
	arrayLens([]byte(` {"a":[1, [2,3], {"b":[]}, "x]\\\",[" ], "c":{"d":[ {} ,{"e":[1]}]}}`), func(path []string, n int) bool {
		out = append(out, got{strings.Join(path, "."), n})
		return true
	})
	want := []got{{"a", 2}, {"a.b", 0}, {"a", 4}, {"c.d.e", 1}, {"c.d", 2}}
	if len(out) != len(want) {
		t.Fatalf("arrays %v, want %v", out, want)
	}
	for i := range want {
		if out[i] != want[i] {
			t.Errorf("arrays %v, want %v", out, want)
			break
		}
	}
}

// Cursors anywhere in the u64 range: a page after the head is empty, and an
// entry past 2^63-1 is absent, never a 500. wait is compared before it
// becomes a duration, so values that would overflow are refused.
func TestLargeCursorsAndWaits(t *testing.T) {
	e := newEnv(t)
	v := newVault(t, "a@example.com")
	e.publish(v)
	tok := e.session(v, v.dev(0))
	for _, after := range []string{"9223372036854775807", "9223372036854775808", "18446744073709551615"} {
		for _, wait := range []string{"", "&wait=55"} {
			r, p := e.readLog(v, tok, "?after="+after+wait)
			if r.status != 200 || len(p.Entries) != 0 || p.Head != v.head() {
				t.Errorf("after=%s%s: %s", after, wait, r)
			}
		}
		wantCode(t, e.do("GET", "/v1/vaults/"+v.vaultID().String()+"/entries/"+after, tok, nil), 404, "not_found", "entry "+after)
	}
	wantCode(t, e.do("GET", logPath(v)+"?after=18446744073709551616", tok, nil), 400, "bad_request", "after = 2^64")
	wantCode(t, e.do("GET", "/v1/vaults/"+v.vaultID().String()+"/entries/18446744073709551616", tok, nil), 404, "not_found", "entry 2^64")
	for _, wait := range []string{"56", "18446744074", "9223372036854775808", "18446744073709551615", "18446744073709551616"} {
		wantCode(t, e.do("GET", logPath(v)+"?wait="+wait, tok, nil), 400, "bad_request", "wait="+wait)
	}
	r, _ := e.readLog(v, tok, "?wait=0")
	wantStatus(t, r, 200, "wait=0")
}
