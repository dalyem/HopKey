package server

import (
	"bytes"
	"encoding/base64"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/dalyem/hopkey/internal/crypto"
	"github.com/dalyem/hopkey/internal/model"
)

func (e *env) sessionResp(v *tvault, dev model.ID, chal, sig []byte) resp {
	return e.do("POST", "/v1/auth/session", "", sessionRequest{v.accountID(), dev, chal, sig})
}

func (e *env) newChallenge(v *tvault, dev model.ID, op string) []byte {
	e.t.Helper()
	var cr challengeResponse
	e.must(e.challenge(v, dev, op), 200, &cr)
	if len(cr.Challenge) != 32 {
		e.t.Fatalf("challenge of %d bytes", len(cr.Challenge))
	}
	return cr.Challenge
}

// Challenges are single use and bound to the operation, the origin, the
// account, the device and an expiry (R5); signup challenges never
// authenticate a device (R3).
func TestChallengeBindings(t *testing.T) {
	e := newEnv(t)
	v := newVault(t, "a@example.com")
	e.publish(v)
	A := v.dev(0)
	B, wb := v.bootstrap("dev-b")
	e.mustPost(v, e.login(v), wb)

	t.Run("single use", func(t *testing.T) {
		ch := e.newChallenge(v, A, "session")
		sig := e.signAuth(v, A, "session", testOrigin, ch)
		wantStatus(t, e.sessionResp(v, A, ch, sig), 200, "first use")
		wantCode(t, e.sessionResp(v, A, ch, sig), 401, "unauthorized", "second use")
	})
	t.Run("operation", func(t *testing.T) {
		ch := e.newChallenge(v, A, "retire-status")
		for _, op := range []string{"retire-status", "session"} {
			wantCode(t, e.sessionResp(v, A, ch, e.signAuth(v, A, op, testOrigin, ch)), 401, "unauthorized",
				"a retire-status challenge signed as "+op)
		}
		wantCode(t, e.challenge(v, A, "sync"), 400, "bad_request", "an unknown operation")
	})
	t.Run("origin", func(t *testing.T) {
		ch := e.newChallenge(v, A, "session")
		for _, o := range []string{"https://evil.example.com", "https://hop.example.com:443", "http://hop.example.com"} {
			wantCode(t, e.sessionResp(v, A, ch, e.signAuth(v, A, "session", o, ch)), 401, "unauthorized", "signed for "+o)
		}
		// A failed attempt does not consume the challenge.
		wantStatus(t, e.sessionResp(v, A, ch, e.signAuth(v, A, "session", testOrigin, ch)), 200, "signed for the server's origin")
	})
	t.Run("device and account", func(t *testing.T) {
		ch := e.newChallenge(v, A, "session")
		wantCode(t, e.sessionResp(v, B, ch, e.signAuth(v, B, "session", testOrigin, ch)), 401, "unauthorized", "A's challenge used by B")
		wantCode(t, e.sessionResp(v, A, ch, e.signAuth(v, B, "session", testOrigin, ch)), 401, "unauthorized", "A's challenge signed by B")
		other := newVault(t, "o@example.com")
		e.publish(other)
		wantCode(t, e.challenge(other, A, "session"), 401, "unauthorized", "a device of another account")
		wantCode(t, e.challenge(v, randID(t), "session"), 401, "unauthorized", "an unknown device")
	})
	t.Run("expiry", func(t *testing.T) {
		ch := e.newChallenge(v, A, "session")
		e.clock.advance(ChallengeTTL)
		wantCode(t, e.sessionResp(v, A, ch, e.signAuth(v, A, "session", testOrigin, ch)), 401, "unauthorized", "an expired challenge")
	})
	t.Run("signup challenge", func(t *testing.T) {
		code2 := e.invite("c@example.com")
		ch := e.signupChallenge("c@example.com", code2)
		wantCode(t, e.sessionResp(v, A, ch, e.signAuth(v, A, "session", testOrigin, ch)), 401, "unauthorized", "a signup challenge")
	})
	t.Run("outstanding per device", func(t *testing.T) {
		for range 16 {
			e.newChallenge(v, B, "session")
		}
		wantCode(t, e.challenge(v, B, "session"), 429, "rate_limited", "a 17th outstanding challenge")
		e.clock.advance(ChallengeTTL)
		wantStatus(t, e.challenge(v, B, "session"), 200, "after the others expired")
	})
	t.Run("session expiry", func(t *testing.T) {
		tok := e.session(v, A)
		e.clock.advance(SessionTTL)
		r, _ := e.readLog(v, tok, "")
		wantCode(t, r, 401, "unauthorized", "an expired session")
	})
}

type preloginResult struct {
	status int
	body   string
	resp   preloginResponse
}

func (e *env) prelogin(email string, hdr ...string) preloginResult {
	e.t.Helper()
	r := e.do("POST", "/v1/prelogin", "", preloginRequest{email}, hdr...)
	res := preloginResult{status: r.status, body: string(r.body)}
	if r.status == 200 {
		e.must(r, 200, &res.resp)
	}
	return res
}

// Prelogin answers every email the same way: the real values for an
// account, and deterministic synthetic ones of the same shape otherwise
// (R4).
func TestPrelogin(t *testing.T) {
	path := filepath.Join(t.TempDir(), "hop.db")
	e := newEnvAt(t, path)
	v := newVault(t, "Alice@example.com")
	e.publish(v)

	known := e.prelogin("  Alice@EXAMPLE.COM\t")
	if known.status != 200 || known.resp.AccountID != v.accountID() || !bytes.Equal(known.resp.Salt, v.st.Creds.Salt) || known.resp.KDFVersion != 1 {
		t.Fatalf("known account: %+v", known)
	}
	u1, u2 := e.prelogin("bob@example.com"), e.prelogin("bob@example.com")
	if u1.status != 200 || u1.body != u2.body {
		t.Errorf("unknown email not deterministic: %s / %s", u1.body, u2.body)
	}
	if len(u1.resp.Salt) != 16 || u1.resp.AccountID.IsZero() || u1.resp.KDFVersion != 1 || len(u1.body) != len(known.body) {
		t.Errorf("synthetic response has another shape: %s vs %s", u1.body, known.body)
	}
	if u1.resp.AccountID == v.accountID() || bytes.Equal(u1.resp.Salt, u1.resp.AccountID[:]) {
		t.Errorf("synthetic values are not separately derived: %s", u1.body)
	}
	if c := e.prelogin("carol@example.com"); c.body == u1.body {
		t.Error("two unknown emails share a synthetic answer")
	}
	// Local parts are case-sensitive: this is another (unknown) account.
	if l := e.prelogin("alice@example.com"); l.resp.AccountID == v.accountID() {
		t.Error("the local part was case-folded")
	}
	wantCode(t, e.do("POST", "/v1/prelogin", "", preloginRequest{"no-at-sign"}), 400, "bad_request", "an invalid email")

	// The secret persists with the database and differs between servers.
	e.ts.Close()
	e.srv.Close()
	e.st.Close()
	again := newEnvAt(t, path)
	if r := again.prelogin("bob@example.com"); r.body != u1.body {
		t.Errorf("synthetic answer changed across a restart: %s vs %s", r.body, u1.body)
	}
	other := newEnv(t)
	if r := other.prelogin("bob@example.com"); r.body == u1.body {
		t.Error("two servers derive the same synthetic answer")
	}
}

// Unknown accounts and wrong secrets get the same status, schema and error
// for both login and recovery (R4).
func TestLoginFailuresAreUniform(t *testing.T) {
	e := newEnv(t)
	v := newVault(t, "a@example.com")
	e.publish(v)
	unknown := randID(t)
	wrong := bytes.Repeat([]byte{7}, 32)
	for _, ep := range []string{"/v1/login", "/v1/recover"} {
		var bodies []string
		for _, id := range []model.ID{unknown, v.accountID()} {
			var r resp
			if ep == "/v1/login" {
				r = e.do("POST", ep, "", loginRequest{id, wrong})
			} else {
				r = e.do("POST", ep, "", recoverRequest{id, wrong})
			}
			wantCode(t, r, 401, "unauthorized", ep)
			bodies = append(bodies, string(r.body))
		}
		if bodies[0] != bodies[1] {
			t.Errorf("%s: unknown account %s, wrong secret %s", ep, bodies[0], bodies[1])
		}
	}
	// Timing: both failures run the same lookup, hashing and comparison.
	// This is a coarse measurement, not a promise (R4): it only catches a
	// gross difference such as skipping the comparison for unknown accounts.
	median := func(id model.ID) time.Duration {
		var ds []time.Duration
		for range 41 {
			start := time.Now()
			e.do("POST", "/v1/login", "", loginRequest{id, wrong})
			ds = append(ds, time.Since(start))
		}
		slices.Sort(ds)
		return ds[len(ds)/2]
	}
	mu, mw := median(unknown), median(v.accountID())
	t.Logf("median login failure: unknown account %v, wrong secret %v", mu, mw)
	if mu > 5*mw+5*time.Millisecond || mw > 5*mu+5*time.Millisecond {
		t.Errorf("login failures differ grossly in time: unknown %v, wrong secret %v", mu, mw)
	}
	// The secrets are not interchangeable.
	wantCode(t, e.do("POST", "/v1/login", "", loginRequest{v.accountID(), v.rAuth}), 401, "unauthorized", "rAuth as an auth key")
	wantCode(t, e.do("POST", "/v1/recover", "", recoverRequest{v.accountID(), v.authKey}), 401, "unauthorized", "an auth key as rAuth")
	// A stored hash is not a credential.
	h := crypto.SHA256(v.authKey)
	wantCode(t, e.do("POST", "/v1/login", "", loginRequest{v.accountID(), h[:]}), 401, "unauthorized", "the stored hash")
	// A login token is not a session.
	tok := e.login(v)
	wantCode(t, e.post(v, tok, v.unrecorded(v.dev(0))), 401, "unauthorized", "a normal entry by login token")
}

// R14: prelogin, login and recovery have separate buckets, so anonymous
// prelogin traffic cannot starve recovery; identity buckets count
// nonexistent identities; forwarded addresses count only from trusted
// proxies.
func TestRateLimitBuckets(t *testing.T) {
	t.Run("per IP", func(t *testing.T) {
		e := newEnv(t, withRates(DefaultRates()))
		v := newVault(t, "a@example.com")
		e.publish(v)
		for i := range 10 {
			wantStatus(t, e.do("POST", "/v1/prelogin", "", preloginRequest{"x" + itoa(uint64(i)) + "@example.com"}), 200, "prelogin")
		}
		wantCode(t, e.do("POST", "/v1/prelogin", "", preloginRequest{"y@example.com"}), 429, "rate_limited", "the 11th prelogin")
		// A forwarded address from an untrusted peer changes nothing.
		wantCode(t, e.do("POST", "/v1/prelogin", "", preloginRequest{"y@example.com"}, "X-Forwarded-For", "203.0.113.9"), 429, "rate_limited", "a spoofed X-Forwarded-For")
		// Recovery and login still work from the same address.
		var lr loginResponse
		e.must(e.do("POST", "/v1/recover", "", recoverRequest{v.accountID(), v.rAuth}), 200, &lr)
		e.must(e.do("POST", "/v1/login", "", loginRequest{v.accountID(), v.authKey}), 200, &lr)
		for range 9 {
			e.do("POST", "/v1/login", "", loginRequest{randID(t), v.authKey})
		}
		wantCode(t, e.do("POST", "/v1/login", "", loginRequest{v.accountID(), v.authKey}), 429, "rate_limited", "the 11th login")
		wantStatus(t, e.do("POST", "/v1/recover", "", recoverRequest{v.accountID(), v.rAuth}), 200, "recovery after login is exhausted")
		wantStatus(t, e.do("GET", "/v1/healthz", "", nil), 200, "another endpoint")
	})
	t.Run("per identity", func(t *testing.T) {
		e := newEnv(t, withRates(DefaultRates()), withProxies("127.0.0.0/8", "::1/128"))
		ip := func(i int) []string { return []string{"X-Forwarded-For", "198.51.100." + itoa(uint64(i))} }
		for i := range 20 {
			wantStatus(t, e.do("POST", "/v1/prelogin", "", preloginRequest{"nobody@example.com"}, ip(i)...), 200, "prelogin")
		}
		wantCode(t, e.do("POST", "/v1/prelogin", "", preloginRequest{" nobody@EXAMPLE.com"}, ip(21)...), 429, "rate_limited",
			"the 21st prelogin for one email from many addresses")
		id := randID(t)
		for i := range 20 {
			wantCode(t, e.do("POST", "/v1/recover", "", recoverRequest{id, bytes.Repeat([]byte{1}, 32)}, ip(i)...), 401, "unauthorized", "recover")
		}
		wantCode(t, e.do("POST", "/v1/recover", "", recoverRequest{id, bytes.Repeat([]byte{1}, 32)}, ip(30)...), 429, "rate_limited",
			"the 21st recovery for one nonexistent account")
		wantCode(t, e.do("POST", "/v1/login", "", loginRequest{id, bytes.Repeat([]byte{1}, 32)}, ip(31)...), 401, "unauthorized",
			"login for that account has its own bucket")
	})
}

// Nothing secret reaches the log: no bodies, tokens, codes, emails or
// derived secrets.
func TestLogsHoldNoSecrets(t *testing.T) {
	e := newEnv(t)
	v := newVault(t, "secret-person@example.com")
	code := e.publish(v)
	sess, login, rec := e.session(v, v.dev(0)), e.login(v), e.recoverToken(v)
	e.mustPost(v, sess, v.normal(v.dev(0), 1, 10))
	e.do("POST", "/v1/login", "", loginRequest{v.accountID(), bytes.Repeat([]byte{9}, 32)})
	e.do("POST", "/v1/signup", "", []byte(`{"not":"json"`))
	logs := e.logs.String()
	if !strings.Contains(logs, "POST /v1/signup") {
		t.Fatalf("no access log: %q", logs)
	}
	for name, s := range map[string]string{
		"code": code, "session": sess, "login token": login, "recovery token": rec,
		"email": v.email, "auth key": b64(v.authKey), "rAuth": b64(v.rAuth),
		"account": v.accountID().String(), "vault": v.vaultID().String(),
	} {
		if strings.Contains(logs, s) {
			t.Errorf("the log contains the %s", name)
		}
	}
}

func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

func TestHealthz(t *testing.T) {
	e := newEnv(t)
	r := e.do("GET", "/v1/healthz", "", nil)
	if r.status != 200 || !strings.HasPrefix(string(r.body), `{"ok":true,"version":"`) {
		t.Errorf("healthz: %s", r)
	}
	wantCode(t, e.do("GET", "/v1/nothing", "", nil), 404, "not_found", "an unknown route")
}

// Request limits: body size, nesting depth, content encoding, strict
// schemas.
func TestRequestLimits(t *testing.T) {
	e := newEnv(t, withLimits(func(l *Limits) { l.MaxBody = 1024 }))
	big := []byte(`{"email":"` + strings.Repeat("a", 2000) + `@example.com"}`)
	wantCode(t, e.do("POST", "/v1/prelogin", "", big), 413, "too_large", "an oversized body")
	deep := []byte(strings.Repeat("[", 33) + strings.Repeat("]", 33))
	wantCode(t, e.do("POST", "/v1/prelogin", "", deep), 413, "too_large", "nesting deeper than 32")
	wantCode(t, e.do("POST", "/v1/prelogin", "", []byte(`{"email":"a@example.com"}`), "Content-Encoding", "gzip"), 400, "bad_request", "gzip")
	wantCode(t, e.do("POST", "/v1/prelogin", "", []byte(`{"email":"a@example.com","x":1}`)), 400, "bad_request", "an unknown member")
	wantCode(t, e.do("POST", "/v1/prelogin", "", []byte(`{"email":"a@example.com","email":"b@example.com"}`)), 400, "bad_request", "a duplicate member")
	wantStatus(t, e.do("POST", "/v1/prelogin", "", []byte(" {\n\"email\" : \"a@example.com\" } ")), 200, "non-canonical JSON")
}

func TestQueueRefusesWhenFull(t *testing.T) {
	q := newQueue(1, 1)
	rel, ok := q.acquire(t.Context())
	if !ok {
		t.Fatal("first acquire")
	}
	got := make(chan bool)
	go func() {
		r, ok := q.acquire(t.Context())
		if ok {
			r()
		}
		got <- ok
	}()
	deadline := time.Now().Add(5 * time.Second)
	for {
		q.mu.Lock()
		w := q.waiting
		q.mu.Unlock()
		if w == 1 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the second caller never queued")
		}
		time.Sleep(time.Millisecond)
	}
	if _, ok := q.acquire(t.Context()); ok {
		t.Error("a full queue admitted a third caller")
	}
	rel()
	if !<-got {
		t.Error("the queued caller was not admitted")
	}
}

// The limiter's key store is bounded, but churning keys never replenishes
// a bucket that is still refilling: while no stored bucket has refilled,
// new keys share one overflow bucket per scope (R14).
func TestRateLimiterBoundsKeys(t *testing.T) {
	c := &clock{t: time.Unix(0, 0)}
	l := newRateLimiter(c.now, 8)
	r := Rate{N: 1, Per: time.Hour}
	if !l.allow("s", "a", r) || l.allow("s", "a", r) {
		t.Error("a bucket of 1 per hour")
	}
	for i := range 100 {
		l.allow("s", "k"+itoa(uint64(i)), r)
	}
	if len(l.buckets) > 8 {
		t.Errorf("%d buckets kept, max 8", len(l.buckets))
	}
	if l.allow("s", "a", r) {
		t.Error("key churn replenished an exhausted bucket")
	}
	if l.allow("s", "new", r) {
		t.Error("a new key in a full store escaped the scope's overflow bucket")
	}
	if !l.allow("other", "new", r) {
		t.Error("another scope shares the overflow bucket")
	}
	c.advance(time.Hour)
	if !l.allow("s", "a", r) {
		t.Error("the bucket did not refill")
	}
	if !l.allow("s", "new", r) || l.allow("s", "new", r) {
		t.Error("after the buckets refilled, a new key did not get a bucket of its own")
	}
	if len(l.buckets) > 8 {
		t.Errorf("%d buckets kept, max 8", len(l.buckets))
	}
}

// A key without a bucket of its own stays on its scope's overflow bucket
// until that bucket has refilled completely: room appearing in the store
// does not hand it a fresh bucket and so reset its debt (R14).
func TestRateLimiterOverflowKeepsDebt(t *testing.T) {
	c := &clock{t: time.Unix(0, 0)}
	l := newRateLimiter(c.now, 1)
	r := Rate{N: 1, Per: time.Hour}
	if !l.allow("s", "A", r) {
		t.Fatal("A on its own bucket at minute 0")
	}
	c.advance(59 * time.Minute)
	if !l.allow("s", "B", r) {
		t.Fatal("B on the overflow bucket at minute 59")
	}
	c.advance(time.Minute)
	// A's bucket has refilled, so the store could take B now.
	if a := l.buckets["s|A"]; a != nil {
		a.refill(c.now())
		if a.tokens < 1 {
			t.Fatal("A's bucket has not refilled at minute 60")
		}
	}
	if l.allow("s", "B", r) {
		t.Error("B was admitted at minute 60, one minute after it emptied the overflow bucket")
	}
	c.advance(time.Hour)
	if !l.allow("s", "B", r) {
		t.Error("B was refused after the overflow bucket refilled")
	}
	if l.allow("s", "B", r) {
		t.Error("B's bucket allowed two requests in an hour")
	}
}

// A session request refused by the account bucket consumes nothing: the
// challenge stays valid and no session is stored (R14).
func TestSessionRateLimitChangesNothing(t *testing.T) {
	rates := *unlimitedRates()
	rates.Account = Rate{N: 1, Per: 30 * time.Second}
	e := newEnv(t, withRates(rates))
	v := newVault(t, "a@example.com")
	e.publish(v)
	A := v.dev(0)
	e.session(v, A)
	sessions := e.count(`SELECT COUNT(*) FROM sessions`)
	chal := e.newChallenge(v, A, "session")
	sig := e.signAuth(v, A, "session", testOrigin, chal)
	wantCode(t, e.sessionResp(v, A, chal, sig), 429, "rate_limited", "a session over the account bucket")
	if n := e.count(`SELECT COUNT(*) FROM sessions`); n != sessions {
		t.Errorf("%d sessions after the refusal, %d before", n, sessions)
	}
	h := crypto.SHA256(chal)
	if e.count(`SELECT COUNT(*) FROM challenges WHERE hash = ?`, h[:]) != 1 {
		t.Error("the refused request consumed the challenge")
	}
	// Once the bucket refills, the same challenge still issues a session.
	e.clock.advance(30 * time.Second)
	var sr sessionResponse
	e.must(e.sessionResp(v, A, chal, sig), 200, &sr)
	r, _ := e.readLog(v, sr.AccessToken, "")
	wantStatus(t, r, 200, "the session issued after the refusal")
}

// The session response names the vault the session is bound to, so a
// device that enrolled by approval, which has no vault ID, can learn it
// (R1). Another account's vault on the same server is not named.
func TestSessionResponseCarriesBoundVault(t *testing.T) {
	e := newEnv(t, withRates(*unlimitedRates()))
	v := newVault(t, "a@example.com")
	e.publish(v)
	other := newVault(t, "b@example.com")
	e.publish(other)
	if v.vaultID() == other.vaultID() {
		t.Fatal("the two test vaults share an ID")
	}
	B, wb := v.bootstrap("dev-b")
	e.mustPost(v, e.login(v), wb)

	for _, dev := range []model.ID{v.dev(0), B} {
		var cr challengeResponse
		e.must(e.challenge(v, dev, "session"), 200, &cr)
		r := e.do("POST", "/v1/auth/session", "", sessionRequest{v.accountID(), dev, cr.Challenge,
			e.signAuth(v, dev, "session", testOrigin, cr.Challenge)})
		var sr sessionResponse
		e.must(r, 200, &sr)
		if sr.VaultID != v.vaultID() {
			t.Errorf("device %v: session bound to vault %v; want %v", dev, sr.VaultID, v.vaultID())
		}
		if !bytes.Contains(r.body, []byte(`"vault_id":"`+v.vaultID().String()+`"`)) {
			t.Errorf("response %s has no vault_id member", r.body)
		}
		if got, _ := e.readLog(v, sr.AccessToken, ""); got.status != 200 {
			t.Errorf("the session cannot read the vault it names: %s", got)
		}
	}
}
