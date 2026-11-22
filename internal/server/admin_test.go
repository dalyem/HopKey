package server

import (
	"context"
	"database/sql"
	"encoding/hex"
	"errors"
	"math"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/dalyem/hopkey/internal/crypto"
	"github.com/dalyem/hopkey/internal/model"
	"github.com/dalyem/hopkey/internal/vaultlog"
)

// hostileName is a device name the certificate schema accepts (no Cc
// character) that would still reorder a terminal line: a bidi override and
// a zero-width space.
const hostileName = "evil‮gnp.exe​"

func wantAdminCode(t *testing.T, err error, code, what string) {
	t.Helper()
	var ae *AdminError
	if !errors.As(err, &ae) || ae.Code != code {
		t.Errorf("%s: %v, want an AdminError %q", what, err, code)
	}
}

// adminVault is an account with every kind of device the operator view
// distinguishes: A (genesis) and B active, C retired, D revoked by a
// checkpoint. After it, the clock is past every login token made on the
// way, A has two live sessions, B one, and one login token is outstanding.
func adminVault(e *env) (v *tvault, A, B, C, D model.ID) {
	t := e.t
	t.Helper()
	v = newVault(t, "a@example.com")
	e.publish(v)
	A = v.dev(0)
	B, wb := v.bootstrap(hostileName) // seq 1
	e.mustPost(v, e.login(v), wb)
	C, wc := v.bootstrap("dev-c") // seq 2
	e.mustPost(v, e.login(v), wc)
	e.mustPost(v, e.session(v, C), v.retire(C)) // seq 3
	D, wd := v.bootstrap("dev-d")               // seq 4
	e.mustPost(v, e.login(v), wd)
	e.mustPost(v, e.session(v, A), v.checkpoint(A, D)) // seq 5
	e.clock.advance(LoginTokenTTL + time.Minute)
	e.session(v, A)
	e.session(v, A)
	e.session(v, B)
	e.login(v)
	return v, A, B, C, D
}

// accounts show: the devices with their names (from public state for an
// active device, from the log for a departed one), states, sessions and
// last seen, the credentials in flight, and the pending invites.
func TestAdminShowAccount(t *testing.T) {
	e := newEnv(t)
	v, A, B, C, D := adminVault(e)
	ctx := context.Background()
	seenA := e.clock.now().Add(time.Hour)
	if err := e.st.Update(ctx, func(tx Tx) error {
		if err := tx.SetDeviceSeen(v.accountID(), A, seenA); err != nil {
			return err
		}
		mid, aid, did := randID(t), v.accountID(), A
		return tx.InsertMailbox(&Mailbox{ID: mid, RoutingCode: "ABCDEFGHJK", Commit: []byte("{}"), IP: "192.0.2.1",
			AccountID: &aid, DeviceID: &did, ExpiresAt: e.clock.now().Add(MailboxTTL)})
	}); err != nil {
		t.Fatal(err)
	}
	pending := e.invite(v.email)

	for _, who := range []string{v.email, v.accountID().String(), "  " + v.email} {
		d, err := ShowAccount(ctx, e.st, who, e.clock.now())
		if err != nil {
			t.Fatalf("ShowAccount(%q): %v", who, err)
		}
		if d.ID != v.accountID() || d.Email != v.email || d.VaultID != v.vaultID() {
			t.Errorf("account %v %q vault %v", d.ID, d.Email, d.VaultID)
		}
		if d.HeadSeq != 5 || d.LastCheckpoint != 5 || d.LastBootstrap != 4 || d.ActiveDevices != 2 || d.AllDevices != 4 {
			t.Errorf("head %d checkpoint %d bootstrap %d devices %d/%d", d.HeadSeq, d.LastCheckpoint, d.LastBootstrap, d.ActiveDevices, d.AllDevices)
		}
		if !d.LastSeen.Equal(seenA.Truncate(time.Second)) {
			t.Errorf("last seen %v, want %v", d.LastSeen, seenA)
		}
		if d.Sessions != 3 || d.LoginTokens != 1 || d.Enrollments != 1 {
			t.Errorf("sessions %d login tokens %d enrollments %d, want 3, 1, 1", d.Sessions, d.LoginTokens, d.Enrollments)
		}
		if d.ReserveBytes != 2*reserveHalf(DefaultLimits()) || d.UsedBytes <= 0 || d.Reserve != ReserveIntact {
			t.Errorf("storage %+v", d.AccountSummary)
		}
		if len(d.Invites) != 1 || d.Invites[0].Email != v.email || d.Invites[0].State(e.clock.now()) != InvitePending {
			t.Errorf("pending invites %+v", d.Invites)
		} else if h, _ := secretHash(pending); d.Invites[0].CapHash != h {
			t.Error("the pending invite is not the one issued")
		}
		want := []DeviceDetail{
			{ID: A, Name: "dev-a", Active: true, AddedSeq: 0, LastSeen: seenA.Truncate(time.Second), Sessions: 2},
			{ID: B, Name: hostileName, Active: true, AddedSeq: 1, Sessions: 1},
			{ID: C, Name: "dev-c", AddedSeq: 2, DepartedHow: vaultlog.DepartRetired, DepartedSeq: 3},
			{ID: D, Name: "dev-d", AddedSeq: 4, DepartedHow: vaultlog.DepartRevoked, DepartedSeq: 5},
		}
		if len(d.Devices) != len(want) {
			t.Fatalf("%d devices, want %d", len(d.Devices), len(want))
		}
		for i, w := range want {
			got := *d.Devices[i]
			if w.ID == C {
				got.LastSeen = time.Time{} // C made a request; the background writer may have recorded it
			}
			if got != w {
				t.Errorf("device %d: %+v, want %+v", i, got, w)
			}
		}
	}

	_, err := ShowAccount(ctx, e.st, "nobody@example.com", e.clock.now())
	wantAdminCode(t, err, "not_found", "an unknown email")
	_, err = ShowAccount(ctx, e.st, "not an account", e.clock.now())
	wantAdminCode(t, err, "invalid", "neither an ID nor an email")
}

// accounts ls: every account, oldest first, with its counts.
func TestAdminListAccounts(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	if list, err := ListAccounts(ctx, e.st); err != nil || len(list) != 0 {
		t.Fatalf("an empty server: %v, %v", list, err)
	}
	v, _, _, _, _ := adminVault(e)
	e.clock.advance(time.Hour)
	w := newVault(t, "b@example.com")
	e.publish(w)
	list, err := ListAccounts(ctx, e.st)
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 2 || list[0].ID != v.accountID() || list[1].ID != w.accountID() {
		t.Fatalf("accounts %+v", list)
	}
	a, b := list[0], list[1]
	if a.ActiveDevices != 2 || a.AllDevices != 4 || a.HeadSeq != 5 || a.Email != v.email {
		t.Errorf("first account %+v", a)
	}
	if b.ActiveDevices != 1 || b.AllDevices != 1 || b.HeadSeq != 0 || b.LastBootstrap != -1 || b.LastCheckpoint != 0 || !b.LastSeen.IsZero() {
		t.Errorf("second account %+v", b)
	}
	if !a.CreatedAt.Before(b.CreatedAt) {
		t.Errorf("created %v and %v", a.CreatedAt, b.CreatedAt)
	}
}

func auditRows(t *testing.T, e *env, f AuditFilter) []*AuditEntry {
	t.Helper()
	rows, err := AuditLog(context.Background(), e.st, f)
	if err != nil {
		t.Fatal(err)
	}
	return rows
}

// insertReg stores an invite with a chosen capability hash, for prefix
// collisions.
func insertReg(t *testing.T, e *env, h crypto.Hash, email string, ttl time.Duration) {
	t.Helper()
	now := e.clock.now()
	if err := e.st.Update(context.Background(), func(tx Tx) error {
		return tx.InsertRegistration(&Registration{CapHash: h, Email: email, CreatedAt: now, ExpiresAt: now.Add(ttl)})
	}); err != nil {
		t.Fatal(err)
	}
}

// invites ls|revoke|reissue: what each selects, that a revoked code gets
// the uniform 401, that a used invite is never touched, and the audit rows.
func TestAdminInvites(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	used := newVault(t, "used@example.com")
	usedCode := e.publish(used)
	x1, x2 := e.invite("x@example.com"), e.invite("x@example.com")
	y := e.invite("y@example.com")
	if _, err := CreateInvite(ctx, e.st, "old@example.com", time.Minute, e.clock.now()); err != nil {
		t.Fatal(err)
	}
	e.clock.advance(2 * time.Minute)
	now := e.clock.now()
	op := Operator{Actor: "tester (uid 1000)", Now: now}

	pending, err := ListInvites(ctx, e.st, false, now)
	if err != nil {
		t.Fatal(err)
	}
	if len(pending) != 3 {
		t.Fatalf("%d pending invites, want 3: %+v", len(pending), pending)
	}
	all, err := ListInvites(ctx, e.st, true, now)
	if err != nil {
		t.Fatal(err)
	}
	states := map[string]InviteState{}
	for _, inv := range all {
		states[inv.Email] = inv.State(now)
		if inv.Email == used.email && (inv.AccountID == nil || *inv.AccountID != used.accountID() || inv.UsedAt.IsZero()) {
			t.Errorf("the used invite %+v", inv)
		}
	}
	if len(all) != 5 || states[used.email] != InviteUsed || states["old@example.com"] != InviteExpired || states["y@example.com"] != InvitePending {
		t.Errorf("all invites: %d, states %v", len(all), states)
	}

	idOf := func(code string) string {
		h, _ := secretHash(code)
		return InviteID(h)
	}
	// Selection. An ID prefix of 8 digits is enough; a used or expired
	// invite and an ambiguous prefix are refused.
	plan, err := PlanRevokeInvites(ctx, e.st, "X@example.com ", now)
	if err == nil {
		t.Errorf("an email that normalizes elsewhere (local part case) selected %d invites", len(plan))
	}
	plan, err = PlanRevokeInvites(ctx, e.st, "x@EXAMPLE.com", now)
	if err != nil || len(plan) != 2 || plan[0].ID != idOf(x1) && plan[1].ID != idOf(x1) {
		t.Errorf("by email: %+v, %v", plan, err)
	}
	if plan, err := PlanRevokeInvites(ctx, e.st, strings.ToUpper(idOf(y)[:8]), now); err != nil || len(plan) != 1 || plan[0].Email != "y@example.com" {
		t.Errorf("by ID prefix: %+v, %v", plan, err)
	}
	_, err = PlanRevokeInvites(ctx, e.st, idOf(usedCode), now)
	wantAdminCode(t, err, "used", "a used invite")
	_, err = PlanRevokeInvites(ctx, e.st, used.email, now)
	wantAdminCode(t, err, "not_found", "an email whose only invite is used")
	_, err = PlanRevokeInvites(ctx, e.st, idOf(y)[:7], now)
	wantAdminCode(t, err, "invalid", "a 7-digit prefix")
	_, err = PlanRevokeInvites(ctx, e.st, "zzzzzzzzzz", now)
	wantAdminCode(t, err, "invalid", "not hex")
	_, err = PlanRevokeInvites(ctx, e.st, "0000000000ff", now)
	wantAdminCode(t, err, "not_found", "an unknown ID")
	var h1, h2 crypto.Hash
	h1[0], h1[1], h1[6], h2[0], h2[1], h2[6] = 0xab, 0xcd, 1, 0xab, 0xcd, 2
	insertReg(t, e, h1, "p@example.com", time.Hour)
	insertReg(t, e, h2, "q@example.com", time.Hour)
	_, err = PlanRevokeInvites(ctx, e.st, "abcd0000", now)
	wantAdminCode(t, err, "ambiguous", "two invites share the prefix")
	if p, err := PlanRevokeInvites(ctx, e.st, "abcd0000000001", now); err != nil || len(p) != 1 || p[0].CapHash != h1 {
		t.Errorf("a longer prefix: %+v, %v", p, err)
	}
	var expired crypto.Hash
	expired[0] = 0xee
	insertReg(t, e, expired, "e@example.com", -time.Second)
	_, err = PlanRevokeInvites(ctx, e.st, "ee00000000", now)
	wantAdminCode(t, err, "expired", "an expired invite")
	if n := len(auditRows(t, e, AuditFilter{})); n != 0 {
		t.Errorf("planning wrote %d audit rows", n)
	}

	// A change between the plan and the revoke is refused, and recorded.
	stale := plan
	x3 := e.invite("x@example.com")
	entry, err := RevokeInvites(ctx, e.st, op, "x@example.com", stale)
	wantAdminCode(t, err, "changed", "revoking a stale plan")
	if entry == nil || entry.Result != "changed" || entry.ID == 0 {
		t.Errorf("the refused revoke's audit row %+v", entry)
	}
	if p, _ := PlanRevokeInvites(ctx, e.st, "x@example.com", now); len(p) != 3 {
		t.Errorf("a refused revoke changed the invites: %d pending", len(p))
	}

	// Revoke by email: every pending invite for it, and the codes stop
	// working with the same answer as a wrong code.
	plan, _ = PlanRevokeInvites(ctx, e.st, "x@example.com", now)
	entry, err = RevokeInvites(ctx, e.st, op, "x@example.com", plan)
	if err != nil {
		t.Fatal(err)
	}
	for _, code := range []string{x1, x2, x3} {
		wantCode(t, e.do("POST", "/v1/signup/challenge", "", signupChallengeRequest{"x@example.com", code}), 401, "unauthorized", "a revoked code")
	}
	wantStatus(t, e.do("POST", "/v1/signup/challenge", "", signupChallengeRequest{"y@example.com", y}), 200, "another email's invite")
	if entry.Action != ActionInviteRevoke || entry.Actor != op.Actor || entry.Result != "ok" || entry.AccountID != nil || !entry.At.Equal(now) {
		t.Errorf("audit row %+v", entry)
	}
	for _, code := range []string{x1, x2, x3} {
		if strings.Contains(string(entry.Params), code) {
			t.Error("the audit row holds an invite code")
		}
		if !strings.Contains(string(entry.Params), idOf(code)) {
			t.Errorf("the audit row %s does not name invite %s", entry.Params, idOf(code))
		}
	}
	if want := `{"by":"email","email":"x@example.com","invites":["` + strings.Join(inviteIDs(plan), `","`) + `"]}`; string(entry.Params) != want {
		t.Errorf("revoke audit params %s, want %s", entry.Params, want)
	}
	_, err = RevokeInvites(ctx, e.st, op, "x@example.com", nil)
	wantAdminCode(t, err, "not_found", "revoking again")

	// The used invite's row is untouched: its acknowledgment still serves
	// a signup retry (R3).
	e.view(func(tx Tx) error {
		h, _ := secretHash(usedCode)
		r, err := tx.Registration(h)
		if err != nil || r.Ack == nil || !r.ExpiresAt.After(now) {
			t.Errorf("the used invite %+v, %v", r, err)
		}
		return nil
	})

	// Reissue: ends y's pending invite and issues a working one.
	email, plan, err := PlanReissueInvite(ctx, e.st, "y@example.com", now)
	if err != nil || email != "y@example.com" || len(plan) != 1 {
		t.Fatalf("reissue plan %q %+v %v", email, plan, err)
	}
	inv, entry, err := ReissueInvite(ctx, e.st, op, email, 48*time.Hour, plan)
	if err != nil {
		t.Fatal(err)
	}
	wantCode(t, e.do("POST", "/v1/signup/challenge", "", signupChallengeRequest{"y@example.com", y}), 401, "unauthorized", "the reissued invite's old code")
	wantStatus(t, e.do("POST", "/v1/signup/challenge", "", signupChallengeRequest{"y@example.com", inv.Code}), 200, "the new code")
	if inv.Email != email || !inv.ExpiresAt.Equal(now.Add(48*time.Hour)) || inv.ID != idOf(inv.Code) {
		t.Errorf("new invite %+v", inv.Invite)
	}
	if entry.Action != ActionInviteReissue || strings.Contains(string(entry.Params), inv.Code) ||
		!strings.Contains(string(entry.Params), inv.ID) || !strings.Contains(string(entry.Params), idOf(y)) {
		t.Errorf("reissue audit row %+v %s", entry, entry.Params)
	}
	// Reissue for an email with nothing pending only issues.
	email, plan, err = PlanReissueInvite(ctx, e.st, "new@example.com", now)
	if err != nil || len(plan) != 0 {
		t.Fatalf("reissue plan for a new email: %+v, %v", plan, err)
	}
	if _, _, err := ReissueInvite(ctx, e.st, op, email, time.Hour, plan); err != nil {
		t.Fatal(err)
	}
	// A reissue whose plan went stale is refused and issues nothing.
	e.invite("new@example.com")
	_, entry, err = ReissueInvite(ctx, e.st, op, email, time.Hour, plan)
	wantAdminCode(t, err, "changed", "a stale reissue")
	if p, _ := PlanRevokeInvites(ctx, e.st, email, now); len(p) != 2 {
		t.Errorf("a refused reissue left %d pending invites, want 2", len(p))
	}

	rows := auditRows(t, e, AuditFilter{})
	var got []string
	for _, r := range rows {
		got = append(got, r.Action+":"+r.Result)
	}
	want := []string{"invites.revoke:changed", "invites.revoke:ok", "invites.revoke:not_found", "invites.reissue:ok", "invites.reissue:ok", "invites.reissue:changed"}
	if !slices.Equal(got, want) {
		t.Errorf("audit trail %v, want %v", got, want)
	}
	if !slices.IsSortedFunc(rows, func(a, b *AuditEntry) int { return int(a.ID - b.ID) }) {
		t.Error("audit rows out of order")
	}
	if entry == nil || entry.ID != rows[len(rows)-1].ID {
		t.Errorf("the stale reissue's row %+v", entry)
	}
}

// A selector longer than an invite ID, up to the whole capability hash,
// reaches neither the audit trail nor a message: a row names the selector
// by kind and the invites by their 12-digit IDs, on success and failure.
func TestAdminRevokeKeepsOnlyInviteIDs(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	now := e.clock.now()
	op := Operator{Actor: "tester (uid 1000)", Now: now}
	var full []string
	for _, addr := range []string{"a@example.com", "b@example.com"} {
		h, _ := secretHash(e.invite(addr))
		full = append(full, hex.EncodeToString(h[:]))
	}
	unknown := strings.Repeat("5a", len(crypto.Hash{}))
	secrets := []string{full[0][:inviteIDLen+1], full[1][:inviteIDLen+1], unknown[:inviteIDLen+1]}
	leaks := func(what, s string) {
		t.Helper()
		for _, x := range secrets {
			if strings.Contains(s, x) {
				t.Errorf("%s holds more than 12 digits of a selector: %s", what, s)
			}
		}
	}

	planA, err := PlanRevokeInvites(ctx, e.st, strings.ToUpper(full[0]), now)
	if err != nil || len(planA) != 1 {
		t.Fatalf("plan by the whole hash: %+v, %v", planA, err)
	}
	if _, err := RevokeInvites(ctx, e.st, op, strings.ToUpper(full[0]), planA); err != nil {
		t.Fatal(err)
	}
	planB, err := PlanRevokeInvites(ctx, e.st, full[1][:20], now)
	if err != nil || len(planB) != 1 {
		t.Fatalf("plan by a 20-digit prefix: %+v, %v", planB, err)
	}
	if _, err := RevokeInvites(ctx, e.st, op, full[1][:20], planB); err != nil {
		t.Fatal(err)
	}
	// Failures: a confirmed invite that expired since, and an unknown
	// hash, whole or in part.
	_, err = RevokeInvites(ctx, e.st, op, full[0], planA)
	wantAdminCode(t, err, "changed", "revoking an invite that expired since the plan")
	leaks("the error", err.Error())
	for _, sel := range []string{unknown, unknown[:30]} {
		_, err = RevokeInvites(ctx, e.st, op, sel, nil)
		wantAdminCode(t, err, "not_found", "an unknown hash")
		leaks("the error", err.Error())
		_, err = PlanRevokeInvites(ctx, e.st, sel, now)
		wantAdminCode(t, err, "not_found", "planning an unknown hash")
		leaks("the plan error", err.Error())
	}
	_, err = PlanRevokeInvites(ctx, e.st, full[0], now)
	wantAdminCode(t, err, "expired", "planning a revoked invite")
	leaks("the plan error", err.Error())

	rows := auditRows(t, e, AuditFilter{})
	idsA, idsB := `{"by":"id","invites":["`+planA[0].ID+`"]}`, `{"by":"id","invites":["`+planB[0].ID+`"]}`
	want := []string{"ok " + idsA, "ok " + idsB, "changed " + idsA, `not_found {"by":"id","invites":[]}`, `not_found {"by":"id","invites":[]}`}
	var got []string
	for _, r := range rows {
		got = append(got, r.Result+" "+string(r.Params))
		leaks("an audit row", string(r.Params))
	}
	if !slices.Equal(got, want) {
		t.Errorf("audit rows\n%v\nwant\n%v", got, want)
	}
}

// Once the operator confirmed a plan, any change in what the selector
// picks is refused as "changed", with the reason in the message: the
// invite was used or expired, the prefix became ambiguous, or the email
// has nothing pending any more. Nothing is revoked.
func TestAdminRevokeChangedSincePlan(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	now := e.clock.now()
	op := Operator{Actor: "tester (uid 1000)", Now: now}
	later := Operator{Actor: op.Actor, Now: now.Add(8 * 24 * time.Hour)} // past every 7-day invite
	idOf := func(code string) string {
		h, _ := secretHash(code)
		return InviteID(h)
	}
	plan := func(sel string) []*Invite {
		t.Helper()
		p, err := PlanRevokeInvites(ctx, e.st, sel, now)
		if err != nil || len(p) == 0 {
			t.Fatalf("plan %s: %+v, %v", sel, p, err)
		}
		return p
	}
	refused := func(what string, o Operator, sel string, want []*Invite, reason string) {
		t.Helper()
		entry, err := RevokeInvites(ctx, e.st, o, sel, want)
		wantAdminCode(t, err, "changed", what)
		if err != nil && !strings.Contains(err.Error(), reason) {
			t.Errorf("%s: %v does not give the reason %q", what, err, reason)
		}
		if entry == nil || entry.Result != "changed" || entry.ID == 0 {
			t.Errorf("%s: audit row %+v", what, entry)
		}
	}

	// Used: the invite signs an account up after the plan.
	v := newVault(t, "used@example.com")
	code := e.invite(v.email)
	planUsed := plan(idOf(code))
	chal := e.signupChallenge(v.email, code)
	e.must(e.do("POST", "/v1/signup", "", e.signupReq(v, code, chal, 0, nil, testOrigin)), 200, nil)
	refused("an invite used since the plan", op, idOf(code), planUsed, "was used")

	// Expired, by ID and by email (the email then has nothing pending).
	exp := e.invite("exp@example.com")
	refused("an invite expired since the plan", later, idOf(exp), plan(idOf(exp)), "has already expired")
	refused("an email with nothing pending since the plan", later, "exp@example.com", plan("exp@example.com"), "no pending invite")

	// Ambiguous: another invite now shares the prefix.
	var h1, h2 crypto.Hash
	h1[0], h1[1], h1[6], h2[0], h2[1], h2[6] = 0xab, 0xcd, 1, 0xab, 0xcd, 2
	insertReg(t, e, h1, "p@example.com", time.Hour)
	planAmb := plan("abcd0000")
	insertReg(t, e, h2, "q@example.com", time.Hour)
	refused("a prefix that became ambiguous", op, "abcd0000", planAmb, "2 invites start with abcd0000")

	if pending, err := ListInvites(ctx, e.st, false, now); err != nil || len(pending) != 3 {
		t.Errorf("after the refusals %d invites are pending, want exp, p and q: %+v, %v", len(pending), pending, err)
	}
}

// IssueInvite and SetQuota write their audit rows; a quota change is
// recorded against its account, and the filters select by account and
// time.
func TestAdminAuditTrail(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	v := newVault(t, "a@example.com")
	e.publish(v)
	op := Operator{Actor: "root (uid 0)", Now: e.clock.now()}
	inv, entry, err := IssueInvite(ctx, e.st, op, "B@Example.COM", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if entry.Action != ActionInviteCreate || strings.Contains(string(entry.Params), inv.Code) ||
		string(entry.Params) != `{"email":"B@example.com","expires_at":`+strconv.FormatInt(op.Now.Add(time.Hour).Unix(), 10)+`,"invite":"`+inv.ID+`","revoked":[]}` {
		t.Errorf("invite audit row %+v %s", entry, entry.Params)
	}
	if _, _, err := IssueInvite(ctx, e.st, Operator{Now: op.Now}, "c@example.com", time.Hour); err == nil {
		t.Error("an admin change without an actor")
	}

	e.clock.advance(time.Hour)
	op.Now = e.clock.now()
	if _, _, err := SetQuota(ctx, e.st, op, v.email, math.MaxInt64, e.srv.lim); err != nil {
		t.Errorf("a quota past the JSON safe integers: %v", err)
	}
	_, entry, err = SetQuota(ctx, e.st, op, v.email, 1<<30, e.srv.lim)
	if err != nil {
		t.Fatal(err)
	}
	if entry.AccountID == nil || *entry.AccountID != v.accountID() || entry.Action != ActionQuota ||
		!strings.Contains(string(entry.Params), `"quota_bytes":"1073741824"`) ||
		!strings.Contains(string(entry.Params), `"old_quota_bytes":"9223372036854775807"`) {
		t.Errorf("quota audit row %+v %s", entry, entry.Params)
	}
	_, entry, err = SetQuota(ctx, e.st, op, "nobody@example.com", 1<<30, e.srv.lim)
	wantAdminCode(t, err, "not_found", "quota for an unknown account")
	if entry == nil || entry.Result != "not_found" || entry.AccountID != nil {
		t.Errorf("the failed quota's audit row %+v", entry)
	}

	if rows := auditRows(t, e, AuditFilter{}); len(rows) != 4 {
		t.Errorf("%d audit rows, want 4", len(rows))
	}
	id := v.accountID()
	if rows := auditRows(t, e, AuditFilter{AccountID: &id}); len(rows) != 2 || rows[0].Action != ActionQuota {
		t.Errorf("rows for the account: %+v", rows)
	}
	if rows := auditRows(t, e, AuditFilter{Since: op.Now}); len(rows) != 3 {
		t.Errorf("rows since the quota change: %d, want 3", len(rows))
	}
}

// --- schema migration ---

// sqlObject is one row of sqlite_master.
type sqlObject struct{ Type, Name, Table, SQL string }

func schemaOf(t *testing.T, db *sql.DB) []sqlObject {
	t.Helper()
	rows, err := db.Query(`SELECT type, name, tbl_name, coalesce(sql, '') FROM sqlite_master ORDER BY type, name`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var out []sqlObject
	for rows.Next() {
		var o sqlObject
		if err := rows.Scan(&o.Type, &o.Name, &o.Table, &o.SQL); err != nil {
			t.Fatal(err)
		}
		out = append(out, o)
	}
	return out
}

func tableCounts(t *testing.T, db *sql.DB) map[string]int {
	t.Helper()
	out := map[string]int{}
	for _, o := range schemaOf(t, db) {
		if o.Type != "table" {
			continue
		}
		var n int
		if err := db.QueryRow(`SELECT COUNT(*) FROM "` + o.Name + `"`).Scan(&n); err != nil {
			t.Fatal(err)
		}
		out[o.Name] = n
	}
	return out
}

func openRaw(t *testing.T, path string) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite", "file:"+path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

func schemaVersionOf(t *testing.T, db *sql.DB) string {
	t.Helper()
	var v []byte
	if err := db.QueryRow(`SELECT v FROM meta WHERE k = 'schema_version'`).Scan(&v); err != nil {
		t.Fatal(err)
	}
	return string(v)
}

// dropV5 undoes what version 5 added.
var dropV5 = []string{
	`DROP TRIGGER accounts_insert_deleted`, `DROP TRIGGER accounts_update_deleted`,
	`DROP TRIGGER vaults_insert_deleted`, `DROP TRIGGER vaults_update_deleted`,
	`DROP TABLE deleted_ids`, `DROP TABLE delete_fences`,
}

// v2DB copies e's database and turns the copy into exactly what a version 2
// server would have written: the same rows, and a schema identical to the
// frozen version 2 schema.
func v2DB(t *testing.T, e *env) string {
	t.Helper()
	return oldDB(t, e, "2", append(slices.Clone(dropV5), `DROP TABLE account_admin`, `DROP TABLE device_blocks`,
		`DROP INDEX admin_audit_account`, `DROP TABLE admin_audit`)...)
}

// v3DB is v2DB for version 3.
func v3DB(t *testing.T, e *env) string {
	t.Helper()
	return oldDB(t, e, "3", append(slices.Clone(dropV5), `DROP TABLE account_admin`, `DROP TABLE device_blocks`)...)
}

// v4DB is v2DB for version 4.
func v4DB(t *testing.T, e *env) string {
	t.Helper()
	return oldDB(t, e, "4", dropV5...)
}

// oldDB copies e's database, runs drop on the copy and records version,
// and checks that its schema is the frozen one of that version.
func oldDB(t *testing.T, e *env, version string, drop ...string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "v"+version+".db")
	if err := e.st.Backup(context.Background(), path); err != nil {
		t.Fatal(err)
	}
	db := openRaw(t, path)
	for _, q := range append(drop, `UPDATE meta SET v = CAST('`+version+`' AS BLOB) WHERE k = 'schema_version'`) {
		if _, err := db.Exec(q); err != nil {
			t.Fatal(err)
		}
	}
	frozen, err := os.ReadFile(filepath.Join("testdata", "schema-v"+version+".sql"))
	if err != nil {
		t.Fatal(err)
	}
	ref := openRaw(t, filepath.Join(t.TempDir(), "ref.db"))
	if _, err := ref.Exec(string(frozen)); err != nil {
		t.Fatal(err)
	}
	if got, want := schemaOf(t, db), schemaOf(t, ref); !slices.Equal(got, want) {
		t.Fatalf("the downgraded schema is not version %s:\n%v\nwant\n%v", version, got, want)
	}
	db.Close()
	return path
}

// A populated version 2 database moves to version 5 on open: admin_audit,
// the access tables and the delete tables appear, every existing row is
// kept, and the server and the admin commands work on it.
func TestMigrateV2ToV5(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	v, A, _, _, _ := adminVault(e)
	e.invite("pending@example.com")
	path := v2DB(t, e)
	before := tableCounts(t, openRaw(t, path))
	if before["accounts"] != 1 || before["devices"] != 4 || before["sessions"] != 3 || before["log"] != 6 || before["registrations"] != 2 {
		t.Fatalf("the version 2 database is not populated: %v", before)
	}

	st, err := OpenSQLite(path)
	if err != nil {
		t.Fatal(err)
	}
	raw := openRaw(t, path)
	if v := schemaVersionOf(t, raw); v != "5" {
		t.Errorf("schema version %q after the migration", v)
	}
	after := tableCounts(t, raw)
	for _, tbl := range []string{"admin_audit", "account_admin", "device_blocks", "delete_fences", "deleted_ids"} {
		if n, ok := after[tbl]; !ok || n != 0 {
			t.Errorf("%s: %d rows (there: %v)", tbl, n, ok)
		}
		delete(after, tbl)
	}
	if !mapsEqual(before, after) {
		t.Errorf("rows changed: %v, then %v", before, after)
	}

	if _, _, err := IssueInvite(ctx, st, Operator{Actor: "t", Now: e.clock.now()}, "n@example.com", time.Hour); err != nil {
		t.Errorf("an audited change after the migration: %v", err)
	}
	if d, err := ShowAccount(ctx, st, v.email, e.clock.now()); err != nil || len(d.Devices) != 4 || d.HeadSeq != 5 {
		t.Errorf("ShowAccount after the migration: %+v, %v", d, err)
	}
	st.Close()

	// The migrated database serves: a device still signs in and reads.
	e2 := newEnvAt(t, path)
	r, _ := e2.readLog(v, e2.session(v, A), "")
	wantStatus(t, r, 200, "reading the log after the migration")

	// Opening again changes nothing; a database from a newer server is
	// refused, and the refusal creates nothing.
	if v := schemaVersionOf(t, raw); v != "5" {
		t.Errorf("schema version %q after reopening", v)
	}
	for _, q := range []string{`UPDATE meta SET v = CAST('6' AS BLOB) WHERE k = 'schema_version'`, `DROP TABLE device_seen`} {
		if _, err := raw.Exec(q); err != nil {
			t.Fatal(err)
		}
	}
	if st3, err := OpenSQLite(path); err == nil {
		st3.Close()
		t.Error("opened a version 6 database")
	}
	if slices.ContainsFunc(schemaOf(t, raw), func(o sqlObject) bool { return o.Name == "device_seen" }) {
		t.Error("refusing a newer database created a table")
	}
}

// A populated version 3 database, with audit rows, moves to version 5 on
// open: account_admin, device_blocks and the delete tables appear empty,
// every existing row is kept, and an access change and the server's
// refusal work on it.
func TestMigrateV3ToV5(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	v, A, _, _, _ := adminVault(e)
	if _, _, err := IssueInvite(ctx, e.st, e.op(), "pending@example.com", time.Hour); err != nil {
		t.Fatal(err)
	}
	path := v3DB(t, e)
	before := tableCounts(t, openRaw(t, path))
	if before["accounts"] != 1 || before["devices"] != 4 || before["admin_audit"] != 1 || before["log"] != 6 {
		t.Fatalf("the version 3 database is not populated: %v", before)
	}
	st, err := OpenSQLite(path)
	if err != nil {
		t.Fatal(err)
	}
	raw := openRaw(t, path)
	if v := schemaVersionOf(t, raw); v != "5" {
		t.Errorf("schema version %q after the migration", v)
	}
	after := tableCounts(t, raw)
	for _, tbl := range []string{"account_admin", "device_blocks", "delete_fences", "deleted_ids"} {
		if n, ok := after[tbl]; !ok || n != 0 {
			t.Errorf("%s: %d rows (there: %v)", tbl, n, ok)
		}
		delete(after, tbl)
	}
	if !mapsEqual(before, after) {
		t.Errorf("rows changed: %v, then %v", before, after)
	}
	plan, err := PlanDisable(ctx, st, v.email, e.op())
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := DisableAccount(ctx, st, e.op(), v.email, "migrated", plan); err != nil {
		t.Errorf("a disable after the migration: %v", err)
	}
	st.Close()
	e2 := newEnvAt(t, path)
	wantCode(t, e2.sessionAttempt(v, A), 403, CodeAccountDisabled, "a session after the migration and a disable")
}

// A populated version 4 database, disabled account and blocked device and
// all, moves to version 5 on open: delete_fences and deleted_ids appear
// empty with their triggers, every existing row is kept, and a delete
// runs on it, its IDs then refused as on a new database.
func TestMigrateV4ToV5(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	v, A, B, _, _ := adminVault(e)
	sel := DeviceSelection{IDs: []string{B.String()}}
	bp, err := PlanBlockDevices(ctx, e.st, v.email, sel, e.op())
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := BlockDevices(ctx, e.st, e.op(), v.email, sel, "lost", bp); err != nil {
		t.Fatal(err)
	}
	e.disable(v, "closing")
	path := v4DB(t, e)
	before := tableCounts(t, openRaw(t, path))
	if before["accounts"] != 1 || before["account_admin"] != 1 || before["device_blocks"] != 1 || before["admin_audit"] != 2 {
		t.Fatalf("the version 4 database is not populated: %v", before)
	}
	st, err := OpenSQLite(path)
	if err != nil {
		t.Fatal(err)
	}
	raw := openRaw(t, path)
	if v := schemaVersionOf(t, raw); v != "5" {
		t.Errorf("schema version %q after the migration", v)
	}
	after := tableCounts(t, raw)
	for _, tbl := range []string{"delete_fences", "deleted_ids"} {
		if n, ok := after[tbl]; !ok || n != 0 {
			t.Errorf("%s: %d rows (there: %v)", tbl, n, ok)
		}
		delete(after, tbl)
	}
	if !mapsEqual(before, after) {
		t.Errorf("rows changed: %v, then %v", before, after)
	}
	fresh := openRaw(t, e.path)
	if got, want := schemaOf(t, raw), schemaOf(t, fresh); !slices.Equal(got, want) {
		t.Errorf("the migrated schema is not a new database's:\n%v\nwant\n%v", got, want)
	}
	plan, err := PlanDelete(ctx, st, v.email, e.op(), 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := DeleteAccount(ctx, st, e.op(), plan, DeleteOptions{BackupDir: t.TempDir()}); err != nil {
		t.Fatalf("a delete after the migration: %v", err)
	}
	err = st.Update(ctx, func(tx Tx) error {
		return tx.InsertAccount(&Account{ID: v.accountID(), Email: "n@example.com", VaultID: randID(t), Salt: []byte{}, CreatedAt: e.clock.now()})
	})
	if !errors.Is(err, ErrDuplicate) {
		t.Errorf("the deleted ID inserted again after the migration: %v", err)
	}
	st.Close()
	e2 := newEnvAt(t, path)
	wantCode(t, e2.challenge(v, A, "session"), 401, "unauthorized", "a challenge after the migration and a delete")
}

// A version 2 database from before device_seen existed gains it too.
func TestMigrateV2WithoutDeviceSeen(t *testing.T) {
	e := newEnv(t)
	v := newVault(t, "a@example.com")
	e.publish(v)
	path := v2DB(t, e)
	raw := openRaw(t, path)
	if _, err := raw.Exec(`DROP TABLE device_seen`); err != nil {
		t.Fatal(err)
	}
	st, err := OpenSQLite(path)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if v := schemaVersionOf(t, raw); v != "5" {
		t.Errorf("schema version %q", v)
	}
	if _, err := ShowAccount(context.Background(), st, v.email, e.clock.now()); err != nil {
		t.Errorf("ShowAccount: %v", err)
	}
}

// An admin command opening a version 2 database while another connection
// (the running server) holds a write transaction fails without migrating
// anything, and the database opens and migrates once the writer is done.
// On a WAL database, as the server leaves it, the open first waits out
// the busy timeout. A rollback-journal file (VACUUM INTO writes one, so a
// restored backup is one until a server opens it) fails at once: the
// switch to WAL needs a lock the writer holds.
func TestOpenWhileAnotherWriterHoldsTheLock(t *testing.T) {
	for _, wal := range []bool{true, false} {
		t.Run(map[bool]string{true: "wal", false: "rollback journal"}[wal], func(t *testing.T) {
			e := newEnv(t)
			ctx := context.Background()
			e.invite("pending@example.com")
			path := v2DB(t, e)
			raw := openRaw(t, path)
			if wal {
				if _, err := raw.Exec(`PRAGMA journal_mode = WAL`); err != nil {
					t.Fatal(err)
				}
			}
			before := tableCounts(t, raw)
			conn, err := raw.Conn(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			if _, err := conn.ExecContext(ctx, `BEGIN IMMEDIATE`); err != nil {
				t.Fatal(err)
			}

			start := time.Now()
			st, err := OpenSQLite(path)
			waited := time.Since(start)
			if err == nil {
				st.Close()
				t.Fatal("opened a database another connection is writing")
			}
			t.Logf("failed after %v: %v", waited, err)
			if wal && waited < 9*time.Second {
				t.Errorf("gave up after %v, before the 10 s busy timeout: %v", waited, err)
			}
			if _, err := conn.ExecContext(ctx, `ROLLBACK`); err != nil {
				t.Fatal(err)
			}
			if v := schemaVersionOf(t, raw); v != "2" {
				t.Errorf("schema version %q after a failed open", v)
			}
			if slices.ContainsFunc(schemaOf(t, raw), func(o sqlObject) bool { return o.Name == "admin_audit" }) {
				t.Error("a failed open created admin_audit")
			}
			if after := tableCounts(t, raw); !mapsEqual(before, after) {
				t.Errorf("rows changed: %v, then %v", before, after)
			}

			st, err = OpenSQLite(path)
			if err != nil {
				t.Fatalf("opening once the writer is done: %v", err)
			}
			st.Close()
			if v := schemaVersionOf(t, raw); v != "5" {
				t.Errorf("schema version %q after the writer finished", v)
			}
		})
	}
}

func mapsEqual(a, b map[string]int) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if w, ok := b[k]; !ok || w != v {
			return false
		}
	}
	return true
}
