package server

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/dalyem/hopkey/internal/crypto"
	"github.com/dalyem/hopkey/internal/model"
)

// Tests for the operator's access controls: accounts disable and enable,
// devices block and unblock, sessions revoke (access.go).

// sessionAttempt runs a fresh challenge and signs it as dev, and returns
// the session endpoint's answer.
func (e *env) sessionAttempt(v *tvault, dev model.ID) resp {
	e.t.Helper()
	var cr challengeResponse
	e.must(e.challenge(v, dev, "session"), 200, &cr)
	return e.do("POST", "/v1/auth/session", "", sessionRequest{v.accountID(), dev, cr.Challenge,
		e.signAuth(v, dev, "session", testOrigin, cr.Challenge)})
}

// errorReason is the reason member of an error response, and whether it
// is there.
func errorReason(t *testing.T, r resp) (string, bool) {
	t.Helper()
	var body struct {
		Error map[string]string `json:"error"`
	}
	if err := json.Unmarshal(r.body, &body); err != nil {
		t.Fatalf("%s: %v", r.body, err)
	}
	reason, ok := body.Error["reason"]
	return reason, ok
}

func liveSessions(t *testing.T, e *env, acct model.ID) map[model.ID]int {
	t.Helper()
	var out map[model.ID]int
	e.view(func(tx Tx) (err error) {
		out, err = tx.LiveSessions(acct, e.clock.now())
		return err
	})
	return out
}

func loginTokens(t *testing.T, e *env, acct model.ID) int {
	t.Helper()
	var n int
	e.view(func(tx Tx) (err error) {
		n, err = tx.CountLoginTokens(acct, e.clock.now())
		return err
	})
	return n
}

func (e *env) op() Operator { return Operator{Actor: "tester (uid 1000)", Now: e.clock.now()} }

// A disable ends the account's sessions and login tokens, and refuses it
// sessions, logins and recovery with 403 account_disabled and the reason,
// but only to a caller that proved the device's key or the secret:
// challenges, wrong signatures, wrong secrets and unknown accounts get
// what they got before. Retire-status stays open. Enable undoes it, and
// every change writes its audit row.
func TestDisableAccount(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	v, A, B, C, _ := adminVault(e)
	acct := v.accountID()
	old := e.session(v, A)

	plan, err := PlanDisable(ctx, e.st, v.email, e.op())
	if err != nil {
		t.Fatal(err)
	}
	if plan.AccountID != acct || plan.Disabled != nil || plan.Sessions != 4 || plan.LoginTokens != 1 {
		t.Fatalf("plan %+v", plan)
	}
	reason, err := SanitizeReason(" billing\u202e overdue\x07 ")
	if err != nil || reason != "billing overdue" {
		t.Fatalf("SanitizeReason: %q, %v", reason, err)
	}
	got, entry, err := DisableAccount(ctx, e.st, e.op(), v.email, reason, plan)
	if err != nil {
		t.Fatal(err)
	}
	if got.Sessions != 4 || got.LoginTokens != 1 {
		t.Errorf("result %+v", got)
	}
	if entry == nil || entry.Action != ActionDisable || entry.Result != "ok" || entry.AccountID == nil || *entry.AccountID != acct ||
		!strings.Contains(string(entry.Params), `"reason":"billing overdue"`) || !strings.Contains(string(entry.Params), `"sessions":4`) ||
		!strings.Contains(string(entry.Params), `"login_tokens":1`) || strings.Contains(string(entry.Params), v.email) {
		t.Errorf("audit row %+v %s", entry, entry.Params)
	}
	if s := liveSessions(t, e, acct); len(s) != 0 {
		t.Errorf("sessions left: %v", s)
	}
	if n := loginTokens(t, e, acct); n != 0 {
		t.Errorf("%d login tokens left", n)
	}

	// The old session is gone, and a new one is refused with the reason.
	r, _ := e.readLog(v, old, "")
	wantCode(t, r, 401, "unauthorized", "a session from before the disable")
	for _, dev := range []model.ID{A, B} {
		r = e.sessionAttempt(v, dev)
		wantCode(t, r, 403, CodeAccountDisabled, "a session for a disabled account")
		if got, ok := errorReason(t, r); !ok || got != "billing overdue" {
			t.Errorf("reason %q (%v) in %s", got, ok, r.body)
		}
	}
	// Proving nothing still gets the uniform answers.
	var cr challengeResponse
	e.must(e.challenge(v, A, "session"), 200, &cr)
	r = e.do("POST", "/v1/auth/session", "", sessionRequest{acct, A, cr.Challenge, e.signAuth(v, B, "session", testOrigin, cr.Challenge)})
	wantCode(t, r, 401, "unauthorized", "a session signed by another device's key")
	r = e.do("POST", "/v1/login", "", loginRequest{acct, randBytes(t, 32)})
	wantCode(t, r, 401, "unauthorized", "a wrong password for a disabled account")
	r = e.do("POST", "/v1/login", "", loginRequest{randID(t), v.authKey})
	wantCode(t, r, 401, "unauthorized", "an unknown account")
	r = e.do("POST", "/v1/recover", "", recoverRequest{acct, randBytes(t, 32)})
	wantCode(t, r, 401, "unauthorized", "a wrong recovery key for a disabled account")
	// The right secrets are refused, after they matched.
	r = e.do("POST", "/v1/login", "", loginRequest{acct, v.authKey})
	wantCode(t, r, 403, CodeAccountDisabled, "a login to a disabled account")
	r = e.do("POST", "/v1/recover", "", recoverRequest{acct, v.rAuth})
	wantCode(t, r, 403, CodeAccountDisabled, "a recovery of a disabled account")
	if n := loginTokens(t, e, acct); n != 0 {
		t.Errorf("a refused login left %d login tokens", n)
	}
	// A device can still ask how it left, and a device of the account
	// that never left is told it is active.
	wantStatus(t, e.retireStatus(v, C, crypto.Hash{}), 200, "retire-status of a retired device of a disabled account")
	wantStatus(t, e.retireStatus(v, A, crypto.Hash{}), 200, "retire-status of an active device of a disabled account")

	d, err := ShowAccount(ctx, e.st, v.email, e.clock.now())
	if err != nil || d.Disabled == nil || d.Disabled.Reason != "billing overdue" || !d.Disabled.At.Equal(e.clock.now().Truncate(time.Second)) {
		t.Errorf("ShowAccount after the disable: %+v, %v", d, err)
	}

	// Disabling again replaces the reason and keeps the time.
	e.clock.advance(time.Hour)
	plan, err = PlanDisable(ctx, e.st, acct.String(), e.op())
	if err != nil || plan.Disabled == nil {
		t.Fatalf("plan of a disabled account: %+v, %v", plan, err)
	}
	if _, entry, err = DisableAccount(ctx, e.st, e.op(), acct.String(), "", plan); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(entry.Params), `"was_disabled":true`) {
		t.Errorf("audit params %s", entry.Params)
	}
	r = e.sessionAttempt(v, A)
	wantCode(t, r, 403, CodeAccountDisabled, "a session after the reason was cleared")
	if got, ok := errorReason(t, r); ok {
		t.Errorf("a disable without a reason sent the reason %q", got)
	}
	d, _ = ShowAccount(ctx, e.st, v.email, e.clock.now())
	if d.Disabled == nil || !d.Disabled.At.Equal(e.clock.now().Add(-time.Hour).Truncate(time.Second)) {
		t.Errorf("disabling again moved the time: %+v", d.Disabled)
	}

	// Enable: sessions and logins work again.
	plan, err = PlanEnable(ctx, e.st, v.email, e.op())
	if err != nil {
		t.Fatal(err)
	}
	if _, entry, err = EnableAccount(ctx, e.st, e.op(), v.email, plan); err != nil || entry.Action != ActionEnable {
		t.Fatalf("enable: %+v, %v", entry, err)
	}
	r, _ = e.readLog(v, e.session(v, A), "")
	wantStatus(t, r, 200, "reading the log after the enable")
	e.login(v)
	_, err = PlanEnable(ctx, e.st, v.email, e.op())
	wantAdminCode(t, err, "not_disabled", "enabling an enabled account")
	if rows := auditRows(t, e, AuditFilter{AccountID: &acct}); len(rows) != 3 {
		t.Errorf("%d audit rows for the account, want 3", len(rows))
	}
}

// A login token the disable did not delete (it can't happen, as the
// disable deletes them in its transaction) is refused all the same.
func TestDisabledAccountRefusesALoginToken(t *testing.T) {
	e := newEnv(t)
	v := newVault(t, "a@example.com")
	e.publish(v)
	tok := e.login(v)
	if err := e.st.Update(context.Background(), func(tx Tx) error {
		return tx.SetAccountDisabled(v.accountID(), &AdminBlock{At: e.clock.now()})
	}); err != nil {
		t.Fatal(err)
	}
	r, _ := e.readLog(v, tok, "")
	wantCode(t, r, 403, CodeAccountDisabled, "a login token of a disabled account")
}

// The refusal comes before the account's rate bucket: a 429 is
// "unreachable" to a client, which then loads its keys.
func TestDisabledAccountIsRefusedBeforeTheRateLimit(t *testing.T) {
	rates := *unlimitedRates()
	rates.Account = Rate{N: 1, Per: time.Hour}
	e := newEnv(t, withRates(rates))
	v := newVault(t, "a@example.com")
	e.publish(v)
	wantStatus(t, e.sessionAttempt(v, v.dev(0)), 200, "the first session")
	wantCode(t, e.sessionAttempt(v, v.dev(0)), 429, "rate_limited", "setup: the second session")
	plan, err := PlanDisable(context.Background(), e.st, v.email, e.op())
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := DisableAccount(context.Background(), e.st, e.op(), v.email, "", plan); err != nil {
		t.Fatal(err)
	}
	wantCode(t, e.sessionAttempt(v, v.dev(0)), 403, CodeAccountDisabled, "a session past the rate limit for a disabled account")
}

// A block ends that device's sessions and refuses it new ones with 403
// device_blocked; the account's other devices keep theirs. A departed
// device can't be blocked, a blocked one not twice; --all takes the
// active devices not blocked yet, and unblock --all the blocked ones. A
// disable wins over a block.
func TestBlockDevices(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	v, A, B, C, D := adminVault(e)
	acct := v.accountID()
	aTok := e.session(v, A)

	sel := DeviceSelection{IDs: []string{B.String()[:8]}}
	plan, err := PlanBlockDevices(ctx, e.st, v.email, sel, e.op())
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.Devices) != 1 || plan.Devices[0].ID != B || plan.Sessions != 1 {
		t.Fatalf("plan %+v", plan)
	}
	_, entry, err := BlockDevices(ctx, e.st, e.op(), v.email, sel, "lost on a train", plan)
	if err != nil {
		t.Fatal(err)
	}
	if entry.Action != ActionDeviceBlock || !strings.Contains(string(entry.Params), B.String()) ||
		!strings.Contains(string(entry.Params), `"reason":"lost on a train"`) {
		t.Errorf("audit row %+v %s", entry, entry.Params)
	}
	s := liveSessions(t, e, acct)
	if s[B] != 0 || s[A] != 3 {
		t.Errorf("sessions after the block: %v", s)
	}
	r := e.sessionAttempt(v, B)
	wantCode(t, r, 403, CodeDeviceBlocked, "a session for a blocked device")
	if got, _ := errorReason(t, r); got != "lost on a train" {
		t.Errorf("reason %q", got)
	}
	r, _ = e.readLog(v, aTok, "")
	wantStatus(t, r, 200, "another device's session after the block")
	wantStatus(t, e.sessionAttempt(v, A), 200, "another device's new session")
	e.login(v) // a block does not stop the password

	_, err = PlanBlockDevices(ctx, e.st, v.email, sel, e.op())
	wantAdminCode(t, err, "already_blocked", "blocking a blocked device")
	for dev, code := range map[model.ID]string{C: "not_active", D: "not_active"} {
		_, err = PlanBlockDevices(ctx, e.st, v.email, DeviceSelection{IDs: []string{dev.String()}}, e.op())
		wantAdminCode(t, err, code, "blocking a departed device")
	}
	for _, bad := range []string{"1234", "zzzzzzzz", strings.Repeat("a", 33)} {
		_, err = PlanBlockDevices(ctx, e.st, v.email, DeviceSelection{IDs: []string{bad}}, e.op())
		wantAdminCode(t, err, "invalid", "a device selector "+bad)
	}
	_, err = PlanBlockDevices(ctx, e.st, v.email, DeviceSelection{IDs: []string{randID(t).String()}}, e.op())
	wantAdminCode(t, err, "not_found", "another account's or an unknown device")
	_, err = PlanUnblockDevices(ctx, e.st, v.email, DeviceSelection{IDs: []string{A.String()}}, e.op())
	wantAdminCode(t, err, "not_blocked", "unblocking a device that is not blocked")

	all := DeviceSelection{All: true}
	plan, err = PlanBlockDevices(ctx, e.st, v.email, all, e.op())
	if err != nil || len(plan.Devices) != 1 || plan.Devices[0].ID != A {
		t.Fatalf("block --all plan %+v, %v", plan, err)
	}
	if _, _, err := BlockDevices(ctx, e.st, e.op(), v.email, all, "", plan); err != nil {
		t.Fatal(err)
	}
	r, _ = e.readLog(v, aTok, "")
	wantCode(t, r, 401, "unauthorized", "a blocked device's old session")
	_, err = PlanBlockDevices(ctx, e.st, v.email, all, e.op())
	wantAdminCode(t, err, "not_found", "block --all with every device blocked")
	d, _ := ShowAccount(ctx, e.st, v.email, e.clock.now())
	for _, dev := range d.Devices {
		if blocked := dev.Blocked != nil; blocked != (dev.ID == A || dev.ID == B) {
			t.Errorf("device %v blocked %v", dev.ID, blocked)
		}
	}

	// A disable wins over the block.
	dp, _ := PlanDisable(ctx, e.st, v.email, e.op())
	if _, _, err := DisableAccount(ctx, e.st, e.op(), v.email, "", dp); err != nil {
		t.Fatal(err)
	}
	wantCode(t, e.sessionAttempt(v, B), 403, CodeAccountDisabled, "a blocked device of a disabled account")
	ep, _ := PlanEnable(ctx, e.st, v.email, e.op())
	if _, _, err := EnableAccount(ctx, e.st, e.op(), v.email, ep); err != nil {
		t.Fatal(err)
	}
	wantCode(t, e.sessionAttempt(v, B), 403, CodeDeviceBlocked, "enable leaves the blocks")

	plan, err = PlanUnblockDevices(ctx, e.st, v.email, all, e.op())
	if err != nil || len(plan.Devices) != 2 {
		t.Fatalf("unblock --all plan %+v, %v", plan, err)
	}
	if _, entry, err = UnblockDevices(ctx, e.st, e.op(), v.email, all, plan); err != nil || entry.Action != ActionDeviceUnblock {
		t.Fatalf("unblock: %+v, %v", entry, err)
	}
	for _, dev := range []model.ID{A, B} {
		wantStatus(t, e.sessionAttempt(v, dev), 200, "a session after the unblock")
	}
}

// A change refuses with "changed", and changes nothing, when the account
// is not as it was shown; the refusal is audited.
func TestAccessChangedSincePlan(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	v, _, B, _, _ := adminVault(e)
	acct := v.accountID()

	stale, err := PlanDisable(ctx, e.st, v.email, e.op())
	if err != nil {
		t.Fatal(err)
	}
	fresh, _ := PlanDisable(ctx, e.st, v.email, e.op())
	if _, _, err := DisableAccount(ctx, e.st, e.op(), v.email, "first", fresh); err != nil {
		t.Fatal(err)
	}
	_, entry, err := DisableAccount(ctx, e.st, e.op(), v.email, "second", stale)
	wantAdminCode(t, err, "changed", "disabling with a plan from before another disable")
	if entry == nil || entry.Result != "changed" || entry.AccountID == nil || *entry.AccountID != acct {
		t.Errorf("the refusal's audit row %+v", entry)
	}
	d, _ := ShowAccount(ctx, e.st, v.email, e.clock.now())
	if d.Disabled == nil || d.Disabled.Reason != "first" {
		t.Errorf("the stale disable changed the reason: %+v", d.Disabled)
	}

	ep, _ := PlanEnable(ctx, e.st, v.email, e.op())
	if _, _, err := EnableAccount(ctx, e.st, e.op(), v.email, ep); err != nil {
		t.Fatal(err)
	}
	_, _, err = EnableAccount(ctx, e.st, e.op(), v.email, ep)
	wantAdminCode(t, err, "changed", "enabling twice with one plan")

	sel := DeviceSelection{IDs: []string{B.String()}}
	bp, _ := PlanBlockDevices(ctx, e.st, v.email, sel, e.op())
	bp2, _ := PlanBlockDevices(ctx, e.st, v.email, sel, e.op())
	if _, _, err := BlockDevices(ctx, e.st, e.op(), v.email, sel, "", bp2); err != nil {
		t.Fatal(err)
	}
	_, _, err = BlockDevices(ctx, e.st, e.op(), v.email, sel, "x", bp)
	wantAdminCode(t, err, "changed", "blocking a device blocked since the plan")

	_, _, err = DisableAccount(ctx, e.st, e.op(), v.email, "a\x1bb", fresh)
	wantAdminCode(t, err, "invalid", "an unsanitized reason")
}

// sessions revoke deletes sessions, and for the whole account its login
// tokens, and signs nobody out: the devices get new sessions.
func TestRevokeSessions(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	v, A, B, _, _ := adminVault(e)
	acct := v.accountID()

	plan, err := PlanRevokeSessions(ctx, e.st, v.email, B.String(), e.op())
	if err != nil || plan.Sessions != 1 || len(plan.Devices) != 1 {
		t.Fatalf("plan %+v, %v", plan, err)
	}
	if _, entry, err := RevokeSessions(ctx, e.st, e.op(), v.email, B.String(), plan); err != nil ||
		!strings.Contains(string(entry.Params), `"device":"`+B.String()+`"`) {
		t.Fatalf("revoke one device's: %+v, %v", entry, err)
	}
	if s := liveSessions(t, e, acct); s[B] != 0 || s[A] != 2 {
		t.Errorf("sessions: %v", s)
	}
	if n := loginTokens(t, e, acct); n != 1 {
		t.Errorf("a device's revoke ended login tokens: %d left", n)
	}

	plan, err = PlanRevokeSessions(ctx, e.st, v.email, "", e.op())
	if err != nil || plan.Sessions != 2 || plan.LoginTokens != 1 {
		t.Fatalf("plan %+v, %v", plan, err)
	}
	if _, entry, err := RevokeSessions(ctx, e.st, e.op(), v.email, "", plan); err != nil || entry.Action != ActionSessionsRevoke ||
		!strings.Contains(string(entry.Params), `"device":null`) {
		t.Fatalf("revoke the account's: %+v, %v", entry, err)
	}
	if s := liveSessions(t, e, acct); len(s) != 0 {
		t.Errorf("sessions: %v", s)
	}
	if n := loginTokens(t, e, acct); n != 0 {
		t.Errorf("%d login tokens left", n)
	}
	for _, dev := range []model.ID{A, B} {
		wantStatus(t, e.sessionAttempt(v, dev), 200, "a new session after sessions revoke")
	}
}

func TestSanitizeReason(t *testing.T) {
	for in, want := range map[string]string{
		"":                                  "",
		"   ":                               "",
		"overdue":                           "overdue",
		" two  spaces ":                     "two  spaces",
		"a\tb\nc\rd":                        "abcd",
		"esc\x1b[2Jape":                     "esc[2Jape",
		"del\x7f c1\u0085\u009b":            "del c1",
		"bidi \u202egnp\u202c\u2066x\u2069": "bidi gnpx",
		"marks \u200e\u200f\u061c":          "marks",
		"sep\u2028\u2029":                   "sep",
		"naïve café ✓":                      "naïve café ✓",
		strings.Repeat("é", 100):            strings.Repeat("é", 100), // 200 bytes
	} {
		got, err := SanitizeReason(in)
		if err != nil || got != want {
			t.Errorf("SanitizeReason(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	for _, bad := range []string{"\xff", "ok\xc3", strings.Repeat("a", 201), strings.Repeat("é", 100) + "a"} {
		if _, err := SanitizeReason(bad); err == nil {
			t.Errorf("SanitizeReason(%q) accepted", bad)
		} else {
			wantAdminCode(t, err, "invalid", "SanitizeReason")
		}
	}
	// Removing comes before measuring: a long run of controls is fine.
	if got, err := SanitizeReason("ok" + strings.Repeat("\x00", 300)); err != nil || got != "ok" {
		t.Errorf("controls past the limit: %q, %v", got, err)
	}
}
