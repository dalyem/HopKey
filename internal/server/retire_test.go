package server

import (
	"context"
	"fmt"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/dalyem/hopkey/internal/crypto"
	"github.com/dalyem/hopkey/internal/model"
	"github.com/dalyem/hopkey/internal/vaultlog"
)

// retireStatus asks for dev's retirement status about h with a fresh
// retire-status challenge.
func (e *env) retireStatus(v *tvault, dev model.ID, h crypto.Hash) resp {
	e.t.Helper()
	chal := e.newChallenge(v, dev, crypto.OperationRetireStatus)
	return e.retireStatusWith(v, dev, chal, e.signAuth(v, dev, crypto.OperationRetireStatus, testOrigin, chal), h)
}

func (e *env) retireStatusWith(v *tvault, dev model.ID, chal, sig []byte, h crypto.Hash) resp {
	return e.do("POST", "/v1/retire-status", "", retireStatusRequest{v.accountID(), chal, dev, h, sig})
}

func (e *env) retirePost(v *tvault, dev model.ID, w *vaultlog.Wire) resp {
	e.t.Helper()
	chal := e.newChallenge(v, dev, crypto.OperationRetireStatus)
	return e.retirePostWith(v, dev, chal, e.signAuth(v, dev, crypto.OperationRetireStatus, testOrigin, chal), w)
}

func (e *env) retirePostWith(v *tvault, dev model.ID, chal, sig []byte, w *vaultlog.Wire) resp {
	e.t.Helper()
	return e.do("POST", "/v1/retire-status/post", "", retirePostRequest{v.accountID(), chal, dev, sig, wireJSON(e.t, w)})
}

func hashOf(t *testing.T, w *vaultlog.Wire) crypto.Hash {
	t.Helper()
	h, err := w.Entry.Hash()
	if err != nil {
		t.Fatal(err)
	}
	return h
}

func headJSON(h vaultlog.Head) string {
	return `{"h":"` + h.H.String() + `","seq":"` + itoa(h.Seq) + `"}`
}

func wantBody(t *testing.T, r resp, status int, body, what string) {
	t.Helper()
	if r.status != status || string(r.body) != body {
		t.Errorf("%s: %s\nwant %d %s", what, r, status, body)
	}
}

// twoDevices publishes a vault with A (genesis) and B (bootstrapped).
func twoDevices(t *testing.T, e *env) (*tvault, model.ID, model.ID) {
	t.Helper()
	v := newVault(t, "a@example.com")
	e.publish(v)
	B, wb := v.bootstrap("dev-b")
	e.mustPost(v, e.login(v), wb)
	return v, v.dev(0), B
}

// A retired device learns its receipt, that its entry committed and where,
// and the head (§9).
func TestRetireStatusRetiredDevice(t *testing.T) {
	e := newEnv(t)
	v, A, B := twoDevices(t, e)
	ret := v.retire(B)
	e.mustPost(v, e.session(v, B), ret)
	e.mustPost(v, e.session(v, A), v.normal(A, 1, 10))
	h := hashOf(t, ret)
	wantBody(t, e.retireStatus(v, B, h), 200,
		`{"committed":true,"head":`+headJSON(v.head())+`,"receipt":{"device_id":"`+B.String()+`","h":"`+h.String()+
			`","how":"retired","seq":"`+itoa(ret.Entry.Seq)+`"},"seq":"`+itoa(ret.Entry.Seq)+`"}`,
		"retired device")
}

// A revoked device gets its revocation receipt; an H that never committed
// is reported as such.
func TestRetireStatusRevokedDevice(t *testing.T) {
	e := newEnv(t)
	v, A, B := twoDevices(t, e)
	cp := v.checkpoint(A, B)
	e.mustPost(v, e.session(v, A), cp)
	var never crypto.Hash
	copy(never[:], randBytes(t, 32))
	wantBody(t, e.retireStatus(v, B, never), 200,
		`{"committed":false,"head":`+headJSON(v.head())+`,"receipt":{"device_id":"`+B.String()+`","h":"`+hashOf(t, cp).String()+
			`","how":"revoked","seq":"`+itoa(cp.Entry.Seq)+`"},"seq":null}`,
		"revoked device")
}

// A device that never left has no receipt, and never sees another
// device's (R5).
func TestRetireStatusNeverDeparted(t *testing.T) {
	e := newEnv(t)
	v, A, B := twoDevices(t, e)
	e.mustPost(v, e.session(v, B), v.retire(B))
	gen := v.log[0]
	wantBody(t, e.retireStatus(v, A, hashOf(t, gen)), 200,
		`{"committed":true,"head":`+headJSON(v.head())+`,"receipt":null,"seq":"`+itoa(gen.Entry.Seq)+`"}`,
		"active device")
	// Another account's entry is not this vault's.
	other := newVault(t, "b@example.com")
	e.publish(other)
	wantBody(t, e.retireStatus(v, A, hashOf(t, other.log[0])), 200,
		`{"committed":false,"head":`+headJSON(v.head())+`,"receipt":null,"seq":null}`,
		"another vault's entry")
}

// Only a retire-status challenge for this account, device and origin,
// signed by the device's key, authenticates; a refusal consumes nothing,
// and a challenge is used at most once across every endpoint (R5).
func TestRetireStatusChallenges(t *testing.T) {
	e := newEnv(t)
	v, A, B := twoDevices(t, e)
	h := hashOf(t, v.log[0])
	rs := crypto.OperationRetireStatus

	// A session challenge is refused here and still works for a session.
	sc := e.newChallenge(v, A, crypto.OperationSession)
	wantCode(t, e.retireStatusWith(v, A, sc, e.signAuth(v, A, crypto.OperationSession, testOrigin, sc), h), 401, "unauthorized", "session challenge, session signature")
	wantCode(t, e.retireStatusWith(v, A, sc, e.signAuth(v, A, rs, testOrigin, sc), h), 401, "unauthorized", "session challenge, retire-status signature")
	wantStatus(t, e.sessionResp(v, A, sc, e.signAuth(v, A, crypto.OperationSession, testOrigin, sc)), 200, "the session challenge at /auth/session")
	// Consumed by /auth/session, it is refused here too.
	wantCode(t, e.retireStatusWith(v, A, sc, e.signAuth(v, A, rs, testOrigin, sc), h), 401, "unauthorized", "a challenge /auth/session consumed")

	// A retire-status challenge is refused by /auth/session, and works here
	// once.
	rc := e.newChallenge(v, A, rs)
	sig := e.signAuth(v, A, rs, testOrigin, rc)
	wantCode(t, e.sessionResp(v, A, rc, sig), 401, "unauthorized", "retire-status challenge at /auth/session")
	wantCode(t, e.sessionResp(v, A, rc, e.signAuth(v, A, crypto.OperationSession, testOrigin, rc)), 401, "unauthorized", "retire-status challenge signed as a session")

	// Refusals that consume nothing.
	wantCode(t, e.retireStatusWith(v, A, rc, e.signAuth(v, A, rs, "https://evil.example.com", rc), h), 401, "unauthorized", "another origin")
	wantCode(t, e.retireStatusWith(v, A, rc, e.signAuth(v, B, rs, testOrigin, rc), h), 401, "unauthorized", "B's key for A")
	wantCode(t, e.retireStatusWith(v, B, rc, e.signAuth(v, B, rs, testOrigin, rc), h), 401, "unauthorized", "A's challenge for B")
	other := newVault(t, "b@example.com")
	e.publish(other)
	wrongAcct := retireStatusRequest{other.accountID(), rc, A, h, sig}
	wantCode(t, e.do("POST", "/v1/retire-status", "", wrongAcct), 401, "unauthorized", "another account")
	wantCode(t, e.retireStatusWith(v, A, rc[:31], sig, h), 401, "unauthorized", "a short challenge")

	wantStatus(t, e.retireStatusWith(v, A, rc, sig, h), 200, "the challenge, correctly used")
	wantCode(t, e.retireStatusWith(v, A, rc, sig, h), 401, "unauthorized", "the same challenge again")
	wantCode(t, e.retirePostWith(v, A, rc, sig, v.unrecordedRetire(A)), 401, "unauthorized", "the same challenge at /retire-status/post")

	// An expired challenge.
	late := e.newChallenge(v, A, rs)
	e.clock.advance(ChallengeTTL)
	wantCode(t, e.retireStatusWith(v, A, late, e.signAuth(v, A, rs, testOrigin, late), h), 401, "unauthorized", "an expired challenge")

	// A device the account never had gets no challenge.
	wantCode(t, e.challenge(v, randID(t), rs), 401, "unauthorized", "an unknown device")
}

// A challenge is bound to the origin the server had when it issued it: a
// server restarted with another --origin refuses it, whatever the
// signature covers (R5).
func TestRetireStatusOriginChange(t *testing.T) {
	path := filepath.Join(t.TempDir(), "hop.db")
	e := newEnvAt(t, path)
	v, A, _ := twoDevices(t, e)
	rs := crypto.OperationRetireStatus
	chal := e.newChallenge(v, A, rs)
	moved := newEnvAt(t, path, func(c *envConfig) { c.Origin = "https://moved.example.com" })
	h := hashOf(t, v.log[0])
	for _, origin := range []string{testOrigin, "https://moved.example.com"} {
		wantCode(t, moved.retireStatusWith(v, A, chal, moved.signAuth(v, A, rs, origin, chal), h), 401, "unauthorized", "signed for "+origin)
	}
	wantStatus(t, e.retireStatusWith(v, A, chal, e.signAuth(v, A, rs, testOrigin, chal), h), 200, "the old server still accepts it")
}

// unrecordedRetire builds dev's retirement on the current head without
// applying it.
func (v *tvault) unrecordedRetire(dev model.ID) *vaultlog.Wire {
	v.t.Helper()
	w, _, _, err := vaultlog.BuildRetire(v.st, v.sec, v.devs[dev], v.now())
	if err != nil {
		v.t.Fatal(err)
	}
	return w
}

// A device posts its own retirement through the retire-status operation:
// the normal commit path ends its sessions and writes its receipt, and its
// status then shows the commit.
func TestRetirePost(t *testing.T) {
	e := newEnv(t)
	v, A, B := twoDevices(t, e)
	sessB := e.session(v, B)
	poll := e.startPoll(v, e.session(v, A), v.head().Seq)
	ret := v.retire(B)
	h := hashOf(t, ret)
	wantBody(t, e.retirePost(v, B, ret), 200, headJSON(vaultlog.Head{Seq: ret.Entry.Seq, H: h}), "retire post")
	var p logPage
	e.must(waitResp(t, poll), 200, &p)
	if len(p.Entries) != 1 || p.Entries[0].H != h {
		t.Errorf("the long-poll got %+v", p)
	}
	r, _ := e.readLog(v, sessB, "")
	wantCode(t, r, 401, "unauthorized", "the retired device's session")
	wantBody(t, e.retireStatus(v, B, h), 200,
		`{"committed":true,"head":`+headJSON(v.head())+`,"receipt":{"device_id":"`+B.String()+`","h":"`+h.String()+
			`","how":"retired","seq":"`+itoa(ret.Entry.Seq)+`"},"seq":"`+itoa(ret.Entry.Seq)+`"}`,
		"status after the post")
}

// Only an active device may post, and only its own retirement as the
// wire's only op. Refusals of the wire or the challenge consume nothing;
// an inactive device's, which comes after its challenge authenticated,
// consumes it.
func TestRetirePostRefusals(t *testing.T) {
	e := newEnv(t)
	v, A, B := twoDevices(t, e)
	rs := crypto.OperationRetireStatus
	h := hashOf(t, v.log[0])

	// Not a retirement, another device's retirement, or a session
	// challenge.
	chal := e.newChallenge(v, B, rs)
	sig := e.signAuth(v, B, rs, testOrigin, chal)
	wantCode(t, e.retirePostWith(v, B, chal, sig, v.unrecorded(B)), 400, "bad_request", "a normal entry")
	wantCode(t, e.retirePostWith(v, B, chal, sig, v.unrecordedRetire(A)), 400, "bad_request", "A's retirement under B's challenge")
	// Authored and signed by B, but retiring A: refused here, before the
	// log rules would (which would spend the challenge).
	cross := v.unrecordedRetire(B)
	cross.Entry.Ops[0].(*vaultlog.DeviceRetireOp).DeviceID = A
	crossSig, err := v.devs[B].SignEntry(&cross.Entry)
	if err != nil {
		t.Fatal(err)
	}
	cross.Sigs = []vaultlog.Sig{{Role: vaultlog.RoleDevice, Sig: crossSig}}
	wantCode(t, e.retirePostWith(v, B, chal, sig, cross), 400, "bad_request", "B's entry retiring A")
	wantCode(t, e.retirePostWith(v, A, chal, e.signAuth(v, A, rs, testOrigin, chal), v.unrecordedRetire(A)), 401, "unauthorized", "B's challenge for A")
	sc := e.newChallenge(v, B, crypto.OperationSession)
	wantCode(t, e.retirePostWith(v, B, sc, e.signAuth(v, B, rs, testOrigin, sc), v.unrecordedRetire(B)), 401, "unauthorized", "a session challenge")
	wantStatus(t, e.retireStatusWith(v, B, chal, sig, h), 200, "the challenge after the refusals")

	// An inactive device: B's retirement is committed, and the identical
	// wire is refused through this operation.
	ret := v.retire(B)
	e.mustPost(v, e.session(v, B), ret)
	chal = e.newChallenge(v, B, rs)
	sig = e.signAuth(v, B, rs, testOrigin, chal)
	wantCode(t, e.retirePostWith(v, B, chal, sig, ret), 401, "unauthorized", "a retired device")
	wantCode(t, e.retireStatusWith(v, B, chal, sig, hashOf(t, ret)), 401, "unauthorized", "the challenge the inactive refusal consumed")
	wantStatus(t, e.retireStatus(v, B, hashOf(t, ret)), 200, "a fresh challenge")
}

// resign signs w again as dev, after a test changed its entry.
func resign(t *testing.T, v *tvault, dev model.ID, w *vaultlog.Wire) {
	t.Helper()
	sig, err := v.devs[dev].SignEntry(&w.Entry)
	if err != nil {
		t.Fatal(err)
	}
	w.Sigs = []vaultlog.Sig{{Role: vaultlog.RoleDevice, Sig: sig}}
}

// otherVaultRetire is dev's retirement on v's head, but for vault other.
func otherVaultRetire(t *testing.T, v, other *tvault, dev model.ID) *vaultlog.Wire {
	t.Helper()
	w := v.unrecordedRetire(dev)
	w.Entry.VaultID = other.vaultID()
	resign(t, v, dev, w)
	return w
}

// written summarizes what a retirement commit writes for v's account: the
// head and public state, the log, receipts, active devices and sessions,
// and the account's usage and reserve.
func (e *env) written(v *tvault) string {
	e.t.Helper()
	vid, aid := v.vaultID(), v.accountID()
	a := e.account(v)
	return fmt.Sprint(
		e.count(`SELECT head_seq FROM vaults WHERE vault_id = ?`, vid[:]),
		e.count(`SELECT length(public_state) FROM vaults WHERE vault_id = ?`, vid[:]),
		e.count(`SELECT COUNT(*) FROM log WHERE vault_id = ?`, vid[:]),
		e.count(`SELECT COUNT(*) FROM receipts WHERE account_id = ?`, aid[:]),
		e.count(`SELECT COUNT(*) FROM devices WHERE account_id = ? AND active = 1`, aid[:]),
		e.count(`SELECT COUNT(*) FROM sessions WHERE account_id = ?`, aid[:]),
		a.UsedBytes, a.Reserve,
	)
}

// Every refusal after the challenge and the signature verified consumes
// the challenge: a wire for another vault, an entry the log rules reject,
// and a commit past the quota. None writes anything else (R5, R13).
func TestRetirePostAuthenticatedRefusalsConsume(t *testing.T) {
	rs := crypto.OperationRetireStatus
	for _, c := range []struct {
		name, code string
		status     int
		wire       func(t *testing.T, e *env, v *tvault, B model.ID) *vaultlog.Wire
	}{
		{"another vault", "bad_request", 400, func(t *testing.T, e *env, v *tvault, B model.ID) *vaultlog.Wire {
			other := newVault(t, "b@example.com")
			e.publish(other)
			return otherVaultRetire(t, v, other, B)
		}},
		{"invalid entry", "invalid_entry", 400, func(t *testing.T, e *env, v *tvault, B model.ID) *vaultlog.Wire {
			w := v.unrecordedRetire(B)
			w.Sigs[0].Sig = append([]byte(nil), w.Sigs[0].Sig...)
			w.Sigs[0].Sig[0] ^= 1
			return w
		}},
		{"quota", "quota_exhausted", 507, func(t *testing.T, e *env, v *tvault, B model.ID) *vaultlog.Wire {
			e.setQuota(v, 1)
			return v.unrecordedRetire(B)
		}},
	} {
		t.Run(c.name, func(t *testing.T) {
			e := newEnv(t)
			v, _, B := twoDevices(t, e)
			e.session(v, B)
			w := c.wire(t, e, v, B)
			chal := e.newChallenge(v, B, rs)
			sig := e.signAuth(v, B, rs, testOrigin, chal)
			before := e.written(v)
			wantCode(t, e.retirePostWith(v, B, chal, sig, w), c.status, c.code, "the refused post")
			if after := e.written(v); after != before {
				t.Errorf("the refusal wrote: %s, before %s", after, before)
			}
			wantCode(t, e.retireStatusWith(v, B, chal, sig, hashOf(t, v.log[0])), 401, "unauthorized", "the consumed challenge")
			e.view(func(tx Tx) error {
				if _, err := tx.Challenge(crypto.SHA256(chal)); err == nil {
					t.Error("the challenge is still stored")
				}
				return nil
			})
		})
	}
}

// wantSpent checks that chal, which authenticated for dev, authenticates
// on neither retirement endpoint any more and is no longer stored.
func wantSpent(t *testing.T, e *env, v *tvault, dev model.ID, chal, sig []byte) {
	t.Helper()
	wantCode(t, e.retireStatusWith(v, dev, chal, sig, hashOf(t, v.log[0])), 401, "unauthorized", "the spent challenge at /retire-status")
	wantCode(t, e.retirePostWith(v, dev, chal, sig, v.unrecordedRetire(dev)), 401, "unauthorized", "the spent challenge at /retire-status/post")
	h := crypto.SHA256(chal)
	if e.count(`SELECT COUNT(*) FROM challenges WHERE hash = ?`, h[:]) != 0 {
		t.Error("the challenge is still stored")
	}
}

// A request refused by the account bucket after its challenge
// authenticated spends the challenge, on either endpoint: once the bucket
// refills, the challenge authenticates nowhere (R5, R14).
func TestRetireRateLimitConsumes(t *testing.T) {
	rs := crypto.OperationRetireStatus
	rates := *unlimitedRates()
	rates.Account = Rate{N: 1, Per: 30 * time.Second}
	for _, endpoint := range []string{"status", "post"} {
		t.Run(endpoint, func(t *testing.T) {
			e := newEnv(t, withRates(rates))
			v, _, B := twoDevices(t, e)
			other := newVault(t, "b@example.com")
			e.publish(other)
			h := hashOf(t, v.log[0])
			// Spend the endpoint's one token: a status, or a post refused
			// after the bucket (a wire for another vault).
			if endpoint == "status" {
				wantStatus(t, e.retireStatus(v, B, h), 200, "the first status")
			} else {
				chal := e.newChallenge(v, B, rs)
				wantCode(t, e.retirePostWith(v, B, chal, e.signAuth(v, B, rs, testOrigin, chal), otherVaultRetire(t, v, other, B)),
					400, "bad_request", "the first post")
			}
			chal := e.newChallenge(v, B, rs)
			sig := e.signAuth(v, B, rs, testOrigin, chal)
			var r resp
			if endpoint == "status" {
				r = e.retireStatusWith(v, B, chal, sig, h)
			} else {
				r = e.retirePostWith(v, B, chal, sig, v.unrecordedRetire(B))
			}
			wantCode(t, r, 429, "rate_limited", "a request over the account bucket")
			e.clock.advance(30 * time.Second)
			wantSpent(t, e, v, B, chal, sig)
			wantStatus(t, e.retireStatus(v, B, hashOf(t, v.log[0])), 200, "a fresh challenge after the refill")
		})
	}
}

// A post whose challenge authenticated, and that is then refused while it
// waits to commit, spends the challenge: when its account's lock has no
// waiting place, when the request runs out of time waiting for that lock,
// and when no validation slot is free once it holds the lock (R5, R14).
func TestRetirePostAdmissionRefusalsConsume(t *testing.T) {
	rs := crypto.OperationRetireStatus
	for _, c := range []struct {
		name string
		lim  func(*Limits)
		// slot is whether the test takes the post's validation slot while
		// the post waits for the account lock.
		slot bool
	}{
		{"lock waiters full", func(l *Limits) { l.LockWaitersPerAccount = 0 }, false},
		{"lock wait deadline", func(l *Limits) { l.RequestDeadline = time.Second }, false},
		{"validation slot", func(l *Limits) { l.ValidationJobs, l.ValidationQueue = 1, 0 }, true},
	} {
		t.Run(c.name, func(t *testing.T) {
			read := make(chan struct{})
			var once sync.Once
			e := newEnv(t, withLimits(c.lim), withHooks(func(s *Server) {
				s.hooks.retireRead = func() { once.Do(func() { close(read) }) }
			}))
			v, _, B := twoDevices(t, e)
			chal := e.newChallenge(v, B, rs)
			sig := e.signAuth(v, B, rs, testOrigin, chal)
			unlock, err := e.srv.accounts.lock(context.Background(), v.accountID())
			if err != nil {
				t.Fatal(err)
			}
			unlocked := false
			defer func() {
				if !unlocked {
					unlock()
				}
			}()
			post := make(chan resp, 1)
			go func() { post <- e.retirePostWith(v, B, chal, sig, v.unrecordedRetire(B)) }()
			select {
			case <-read:
			case <-time.After(15 * time.Second):
				t.Fatal("the post did not authenticate")
			}
			release := func() {}
			if c.slot {
				// The post holds the only slot until it goes to wait for
				// the lock; take the slot then, and let the post have the
				// lock.
				release = nil
				for deadline := time.Now().Add(15 * time.Second); release == nil; {
					if rel, ok := e.srv.validate.acquire(context.Background()); ok {
						release = rel
					} else if time.Now().After(deadline) {
						t.Fatal("the post kept its validation slot")
					} else {
						time.Sleep(time.Millisecond)
					}
				}
				unlocked = true
				unlock()
			}
			r := waitResp(t, post)
			release()
			if !unlocked {
				unlocked = true
				unlock()
			}
			wantCode(t, r, 429, "busy", "the refused post")
			wantSpent(t, e, v, B, chal, sig)
		})
	}
}

// Of requests on both retirement endpoints with one challenge, exactly one
// consumes it, whether the post commits or is refused after its challenge
// authenticated (R5).
func TestRetireChallengeConsumedOnce(t *testing.T) {
	rs := crypto.OperationRetireStatus
	// consumers counts the responses that consumed the challenge: a
	// status 200, and a post 200, or 400 for a wire of another vault. Every
	// other response must be the 401 of a spent challenge.
	consumers := func(t *testing.T, post resp, statuses []resp) int {
		t.Helper()
		n := 0
		if post.status == 200 || post.status == 400 {
			n++
		} else {
			wantCode(t, post, 401, "unauthorized", "a post that lost")
		}
		for _, r := range statuses {
			if r.status == 200 {
				n++
			} else {
				wantCode(t, r, 401, "unauthorized", "a status that lost")
			}
		}
		return n
	}
	for _, mode := range []string{"commit", "another vault"} {
		// The post reads the challenge first, and statuses consume it
		// before the post writes.
		t.Run(mode+", interleaved", func(t *testing.T) {
			p := newPauser()
			e := newEnv(t, withHooks(func(s *Server) { s.hooks.retireRead = p.hook }))
			v, _, B := twoDevices(t, e)
			other := newVault(t, "b@example.com")
			e.publish(other)
			w := v.unrecordedRetire(B)
			if mode == "another vault" {
				w = otherVaultRetire(t, v, other, B)
			}
			chal := e.newChallenge(v, B, rs)
			sig := e.signAuth(v, B, rs, testOrigin, chal)
			p.armed.Store(true)
			post := make(chan resp, 1)
			go func() { post <- e.retirePostWith(v, B, chal, sig, w) }()
			p.waitPaused(t)
			status := e.retireStatusWith(v, B, chal, sig, hashOf(t, v.log[0]))
			close(p.resumed)
			if n := consumers(t, waitResp(t, post), []resp{status}); n != 1 {
				t.Errorf("%d requests consumed the challenge", n)
			}
		})
		t.Run(mode+", simultaneous", func(t *testing.T) {
			e := newEnv(t)
			v, _, B := twoDevices(t, e)
			other := newVault(t, "b@example.com")
			e.publish(other)
			h := hashOf(t, v.log[0])
			for round := range 10 {
				w := v.unrecordedRetire(B)
				if mode == "another vault" {
					w = otherVaultRetire(t, v, other, B)
				}
				chal := e.newChallenge(v, B, rs)
				sig := e.signAuth(v, B, rs, testOrigin, chal)
				start := make(chan struct{})
				var post resp
				statuses := make([]resp, 4)
				var wg sync.WaitGroup
				wg.Add(1 + len(statuses))
				go func() {
					defer wg.Done()
					<-start
					post = e.retirePostWith(v, B, chal, sig, w)
				}()
				for i := range statuses {
					go func() {
						defer wg.Done()
						<-start
						statuses[i] = e.retireStatusWith(v, B, chal, sig, h)
					}()
				}
				close(start)
				wg.Wait()
				if n := consumers(t, post, statuses); n != 1 {
					t.Fatalf("round %d: %d requests consumed the challenge", round, n)
				}
				if post.status == 200 {
					break // B is retired; it has nothing more to post
				}
			}
		})
	}
}

// A retirement whose prev is no longer the head gets the standard
// head_conflict, and the authenticated challenge is spent (R5, R11).
func TestRetirePostHeadConflict(t *testing.T) {
	e := newEnv(t)
	v, A, B := twoDevices(t, e)
	ret := v.unrecordedRetire(B)
	e.mustPost(v, e.session(v, A), v.normal(A, 1, 10))
	chal := e.newChallenge(v, B, crypto.OperationRetireStatus)
	sig := e.signAuth(v, B, crypto.OperationRetireStatus, testOrigin, chal)
	wantBody(t, e.retirePostWith(v, B, chal, sig, ret), 409,
		`{"error":{"code":"head_conflict","message":"prev is not the head"},"head":`+headJSON(v.head())+`}`, "stale retirement")
	wantCode(t, e.retirePostWith(v, B, chal, sig, ret), 401, "unauthorized", "the spent challenge")
	e.view(func(tx Tx) error {
		d, err := tx.Device(v.accountID(), B)
		if err != nil || !d.Active {
			t.Errorf("B after the conflict: %+v, %v", d, err)
		}
		return nil
	})
	// Rebuilt on the head, it commits.
	ret = v.retire(B)
	wantStatus(t, e.retirePost(v, B, ret), 200, "the rebuilt retirement")
}

// The retire-status endpoints never issue a session.
func TestRetireStatusIssuesNoSession(t *testing.T) {
	e := newEnv(t)
	v, _, B := twoDevices(t, e)
	var before, after int
	count := func(n *int) {
		e.view(func(tx Tx) error {
			return tx.(*sqliteTx).row(`SELECT COUNT(*) FROM sessions`).Scan(n)
		})
	}
	count(&before)
	wantStatus(t, e.retireStatus(v, B, hashOf(t, v.log[0])), 200, "status")
	wantStatus(t, e.retirePost(v, B, v.retire(B)), 200, "post")
	count(&after)
	if after != before {
		t.Errorf("sessions went from %d to %d", before, after)
	}
}
