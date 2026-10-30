package server

import (
	"context"
	"database/sql"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/dalyem/hopkey/internal/crypto"
	"github.com/dalyem/hopkey/internal/model"
	"github.com/dalyem/hopkey/internal/vaultlog"
)

// Tests for account delete (delete.go): the fence, the verified backup,
// the delete of every row of the account and nothing else, the
// tombstones that keep its IDs from coming back, and what its devices see.

// disable disables v's account at the env's clock.
func (e *env) disable(v *tvault, reason string) {
	e.t.Helper()
	ctx := context.Background()
	p, err := PlanDisable(ctx, e.st, v.email, e.op())
	if err != nil {
		e.t.Fatal(err)
	}
	if _, _, err := DisableAccount(ctx, e.st, e.op(), v.email, reason, p); err != nil {
		e.t.Fatal(err)
	}
}

// deleteFixture is adminVault's account with a row in every table a
// delete removes, short of the fence: a last seen time, a claimed
// enrollment mailbox with a message, an outstanding challenge, a blocked
// device, and the disable. It also has a pending invite for its email,
// and a second account, other, that the delete must not touch. It
// returns the mailbox's ID.
func deleteFixture(e *env) (v, other *tvault, A, B, C, D, mbox model.ID) {
	t := e.t
	t.Helper()
	ctx := context.Background()
	v, A, B, C, D = adminVault(e)
	other = newVault(t, "other@example.com")
	e.publish(other)
	e.session(other, other.dev(0))
	mbox = randID(t)
	if err := e.st.Update(ctx, func(tx Tx) error {
		aid, did := v.accountID(), A
		if err := tx.SetDeviceSeen(aid, A, e.clock.now()); err != nil {
			return err
		}
		if err := tx.SetDeviceSeen(other.accountID(), other.dev(0), e.clock.now()); err != nil {
			return err
		}
		if err := tx.InsertMailbox(&Mailbox{ID: mbox, RoutingCode: "ABCDEFGHJK", Commit: []byte("{}"), IP: "192.0.2.1",
			AccountID: &aid, DeviceID: &did, ExpiresAt: e.clock.now().Add(MailboxTTL)}); err != nil {
			return err
		}
		return tx.InsertMailboxMessage(mbox, &MailboxMessage{N: 1, Type: "open", Body: []byte("{}")})
	}); err != nil {
		t.Fatal(err)
	}
	e.must(e.challenge(v, B, "session"), 200, nil)
	sel := DeviceSelection{IDs: []string{B.String()}}
	p, err := PlanBlockDevices(ctx, e.st, v.email, sel, e.op())
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := BlockDevices(ctx, e.st, e.op(), v.email, sel, "lost", p); err != nil {
		t.Fatal(err)
	}
	e.invite(v.email)
	e.disable(v, "closing")
	// The disable ended the account's sessions and login tokens; these
	// stand for ones that raced it.
	if err := e.st.Update(ctx, func(tx Tx) error {
		_, sh, err := newSecret()
		if err != nil {
			return err
		}
		_, lh, err := newSecret()
		if err != nil {
			return err
		}
		if err := tx.InsertSession(&Session{TokenHash: sh, AccountID: v.accountID(), VaultID: v.vaultID(), DeviceID: A,
			ExpiresAt: e.clock.now().Add(SessionTTL)}); err != nil {
			return err
		}
		return tx.InsertLoginToken(&LoginToken{TokenHash: lh, Kind: TokenLogin, AccountID: v.accountID(), VaultID: v.vaultID(),
			ExpiresAt: e.clock.now().Add(LoginTokenTTL)})
	}); err != nil {
		t.Fatal(err)
	}
	return v, other, A, B, C, D, mbox
}

// probeIDs counts, table by table and column by column, the rows that
// hold any of ids, in every table but those in skip. It needs no list of
// where an ID may be: a new table or column that keeps one is found.
func probeIDs(t *testing.T, db *sql.DB, skip []string, ids ...model.ID) map[string]int {
	t.Helper()
	out := map[string]int{}
	for _, o := range schemaOf(t, db) {
		if o.Type != "table" || slices.Contains(skip, o.Name) {
			continue
		}
		rows, err := db.Query(`SELECT name FROM pragma_table_info(?)`, o.Name)
		if err != nil {
			t.Fatal(err)
		}
		var cols []string
		for rows.Next() {
			var c string
			if err := rows.Scan(&c); err != nil {
				t.Fatal(err)
			}
			cols = append(cols, c)
		}
		rows.Close()
		for _, c := range cols {
			for _, id := range ids {
				var n int
				if err := db.QueryRow(`SELECT COUNT(*) FROM "`+o.Name+`" WHERE "`+c+`" = ?`, id[:]).Scan(&n); err != nil {
					t.Fatal(err)
				}
				if n > 0 {
					out[o.Name+"."+c] += n
				}
			}
		}
	}
	return out
}

// keptTables are the tables a delete keeps rows of the account in, on
// purpose, and meta, which holds no account's.
var keptTables = []string{"meta", "admin_audit", "deleted_ids"}

// Every table is either one a delete clears of the account's rows
// (accountRows) or one it keeps on purpose, and every table with a column
// that names an account, vault, device or enrollment mailbox is one it
// clears or keeps. A table added later fails here until it is placed.
func TestDeleteCoversEveryTable(t *testing.T) {
	e := newEnv(t)
	db := openRaw(t, e.path)
	var cleared []string
	for _, r := range accountRows {
		cleared = append(cleared, r.table)
	}
	for _, o := range schemaOf(t, db) {
		if o.Type != "table" {
			continue
		}
		if !slices.Contains(cleared, o.Name) && !slices.Contains(keptTables, o.Name) {
			t.Errorf("table %s is neither cleared by a delete (accountRows) nor kept on purpose (keptTables)", o.Name)
		}
		if slices.Contains(cleared, o.Name) && slices.Contains(keptTables, o.Name) {
			t.Errorf("table %s is both cleared and kept", o.Name)
		}
	}
	for _, name := range append(cleared, keptTables...) {
		if !slices.ContainsFunc(schemaOf(t, db), func(o sqlObject) bool { return o.Type == "table" && o.Name == name }) {
			t.Errorf("accountRows or keptTables names %s, which is no table", name)
		}
	}
}

// A delete of a disabled account fences it, writes and verifies a backup
// of mode 0600, and deletes every row of the account and only those:
// afterwards no column of any table but the audit trail and the
// tombstones holds its account, vault, device or mailbox IDs, and the
// other account is as it was. Each step writes its audit row, never with
// the email.
func TestDeleteAccount(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	v, other, A, B, C, D, mbox := deleteFixture(e)
	acct, vid := v.accountID(), v.vaultID()
	db := openRaw(t, e.path)
	devs := []model.ID{A, B, C, D}
	if got := probeIDs(t, db, keptTables, append([]model.ID{acct, vid, mbox}, devs...)...); len(got) == 0 {
		t.Fatal("setup: the account has no rows")
	}
	var otherBefore map[string]int
	e.view(func(tx Tx) (err error) {
		otherBefore, err = tx.AccountRows(other.accountID(), other.vaultID())
		return err
	})

	plan, err := PlanDelete(ctx, e.st, v.email, e.op(), 0)
	if err != nil {
		t.Fatal(err)
	}
	if plan.AccountID != acct || plan.VaultID != vid || plan.Head != v.head() || plan.Fence != nil || plan.Disabled == nil ||
		!slices.Equal(plan.Devices, []model.ID{A, B, C, D}) || len(plan.Invites) != 1 {
		t.Fatalf("plan %+v", plan)
	}
	// The fixture has a row of the account in every table a delete
	// clears, but the fence, which the delete sets itself.
	for _, r := range accountRows {
		if n, ok := plan.Rows[r.table]; !ok || (n == 0) != (r.table == "delete_fences") {
			t.Errorf("plan rows of %s: %d (%v)", r.table, n, ok)
		}
	}

	dir := filepath.Join(t.TempDir(), "backups")
	res, entries, err := DeleteAccount(ctx, e.st, e.op(), plan, DeleteOptions{BackupDir: dir})
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 2 || entries[0].Action != ActionDeleteFence || entries[1].Action != ActionDelete {
		t.Fatalf("audit rows %+v", entries)
	}
	for _, en := range entries {
		if en.Result != "ok" || en.AccountID == nil || *en.AccountID != acct || strings.Contains(string(en.Params), v.email) ||
			strings.Contains(string(en.Params), "example.com") {
			t.Errorf("audit row %+v %s", en, en.Params)
		}
	}
	if !strings.Contains(string(entries[1].Params), `"backup":"`+res.Backup+`"`) || !strings.Contains(string(entries[1].Params), `"log":6`) {
		t.Errorf("delete audit params %s", entries[1].Params)
	}
	if res.Head != v.head() || res.Rows["accounts"] != 1 || res.Rows["log"] != 6 || res.Rows["delete_fences"] != 1 ||
		res.Rows["enroll_messages"] != 1 || res.Rows["registrations"] != 1 || !slices.Equal(res.Devices, devs) {
		t.Errorf("result %+v", res)
	}

	// The backup: 0600, in a 0700 directory, verified, and a whole
	// database with the account in it as it was under the fence.
	if fi, err := os.Stat(res.Backup); err != nil || fi.Mode().Perm() != 0o600 || filepath.Dir(res.Backup) != dir {
		t.Errorf("backup %s: %v, %v", res.Backup, fi.Mode(), err)
	}
	if fi, err := os.Stat(dir); err != nil || fi.Mode().Perm() != 0o700 {
		t.Errorf("backup dir: %v, %v", fi.Mode(), err)
	}
	fence := &DeleteFence{AccountID: acct, VaultID: vid, At: res.FencedAt, Head: res.Head}
	if err := VerifyBackup(ctx, res.Backup, fence); err != nil {
		t.Errorf("the backup does not verify: %v", err)
	}
	bk, err := OpenSQLite(res.Backup)
	if err != nil {
		t.Fatal(err)
	}
	if d, err := ShowAccount(ctx, bk, acct.String(), e.clock.now()); err != nil || d.HeadSeq != v.head().Seq || d.Deleting.IsZero() {
		t.Errorf("the account in the backup: %+v, %v", d, err)
	}
	bk.Close()

	// Nothing of the account is left but the audit trail and its
	// tombstones; the other account is untouched.
	if got := probeIDs(t, db, keptTables, append([]model.ID{acct, vid, mbox}, devs...)...); len(got) != 0 {
		t.Errorf("rows of the deleted account left: %v", got)
	}
	var otherAfter map[string]int
	e.view(func(tx Tx) (err error) {
		otherAfter, err = tx.AccountRows(other.accountID(), other.vaultID())
		return err
	})
	if !mapsEqual(otherBefore, otherAfter) || otherAfter["accounts"] != 1 || otherAfter["sessions"] != 1 {
		t.Errorf("the other account changed: %v, then %v", otherBefore, otherAfter)
	}
	r, _ := e.readLog(other, e.session(other, other.dev(0)), "")
	wantStatus(t, r, 200, "the other account reads its log")
	var tomb int
	if err := db.QueryRow(`SELECT COUNT(*) FROM deleted_ids WHERE account_id = ?`, acct[:]).Scan(&tomb); err != nil || tomb != 6 {
		t.Errorf("%d tombstones (%v), want the account, the vault and 4 devices", tomb, err)
	}
	if _, err := ShowAccount(ctx, e.st, v.email, e.clock.now()); err == nil {
		t.Error("the deleted account is still shown")
	}
	rows, err := AuditLog(ctx, e.st, AuditFilter{AccountID: &acct})
	if err != nil || len(rows) < 3 || rows[len(rows)-1].Action != ActionDelete {
		t.Errorf("the audit trail of the deleted account: %d rows, %v", len(rows), err)
	}
	// The pending invite for the email stays.
	invs, err := ListInvites(ctx, e.st, false, e.clock.now())
	if err != nil || len(invs) != 1 || invs[0].Email != v.email {
		t.Errorf("pending invites after the delete: %+v, %v", invs, err)
	}
}

// After a delete, a device of the account is told account_deleted when
// it asks for a challenge, for a session or for retire-status, with no
// reason; an unknown device of the account, or the device under another
// account, still gets the uniform 401, as do its login, its recovery and
// its old sessions. Prelogin answers for the email as for any unknown one.
func TestDeletedAccountRefusals(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	v := newVault(t, "a@example.com")
	e.publish(v)
	A := v.dev(0)
	B, wb := v.bootstrap("laptop")
	e.mustPost(v, e.login(v), wb)
	old := e.session(v, A)
	var real preloginResponse
	e.must(e.do("POST", "/v1/prelogin", "", preloginRequest{v.email}), 200, &real)
	e.disable(v, "")
	plan, err := PlanDelete(ctx, e.st, v.email, e.op(), 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := DeleteAccount(ctx, e.st, e.op(), plan, DeleteOptions{NoBackup: true}); err != nil {
		t.Fatal(err)
	}

	for _, dev := range []model.ID{A, B} {
		for _, op := range []string{crypto.OperationSession, crypto.OperationRetireStatus} {
			r := e.challenge(v, dev, op)
			wantCode(t, r, 403, CodeAccountDeleted, "a challenge for a device of a deleted account")
			if reason, ok := errorReason(t, r); ok {
				t.Errorf("a reason %q with account_deleted", reason)
			}
		}
	}
	wantCode(t, e.do("POST", "/v1/auth/challenge", "", challengeRequest{v.accountID(), randID(t), "session"}), 401, "unauthorized",
		"an unknown device of a deleted account")
	wantCode(t, e.do("POST", "/v1/auth/challenge", "", challengeRequest{randID(t), A, "session"}), 401, "unauthorized",
		"a device of a deleted account under another account")
	r, _ := e.readLog(v, old, "")
	wantCode(t, r, 401, "unauthorized", "a session from before the delete")
	wantCode(t, e.do("POST", "/v1/login", "", loginRequest{v.accountID(), v.authKey}), 401, "unauthorized", "a login to a deleted account")
	wantCode(t, e.do("POST", "/v1/recover", "", recoverRequest{v.accountID(), v.rAuth}), 401, "unauthorized", "a recovery of a deleted account")
	var pl preloginResponse
	e.must(e.do("POST", "/v1/prelogin", "", preloginRequest{v.email}), 200, &pl)
	if pl.AccountID == real.AccountID || pl.AccountID != model.ID(e.srv.synthetic(labelSyntheticAccountID, v.email)) {
		t.Errorf("prelogin after the delete answers %v (the account was %v)", pl.AccountID, real.AccountID)
	}
}

// The deleted account's and vault's IDs never come back, on any path
// that writes an account or a vault: signup is refused with
// registration_conflict, and InsertAccount, InsertVault and an update to
// the ID are refused by the database's triggers. The email signs up again
// as a new account.
func TestDeletedIDsAreNeverReused(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	v := newVault(t, "a@example.com")
	e.publish(v)
	e.disable(v, "")
	plan, err := PlanDelete(ctx, e.st, v.email, e.op(), 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := DeleteAccount(ctx, e.st, e.op(), plan, DeleteOptions{NoBackup: true}); err != nil {
		t.Fatal(err)
	}

	code := e.invite(v.email)
	chal := e.signupChallenge(v.email, code)
	wantCode(t, e.do("POST", "/v1/signup", "", e.signupReq(v, code, chal, 0, nil, testOrigin)), 409, "registration_conflict",
		"a signup with the deleted account's IDs")
	e.view(func(tx Tx) error {
		if taken, err := tx.AccountTaken(v.accountID(), "new@example.com", randID(t)); err != nil || !taken {
			t.Errorf("AccountTaken of the deleted account ID: %v, %v", taken, err)
		}
		if taken, err := tx.AccountTaken(randID(t), "new@example.com", v.vaultID()); err != nil || !taken {
			t.Errorf("AccountTaken of the deleted vault ID: %v, %v", taken, err)
		}
		return nil
	})

	// Below AccountTaken, the database refuses the IDs itself.
	fresh := func(id, vault model.ID) *Account {
		return &Account{ID: id, Email: "x" + id.String()[:6] + "@example.com", VaultID: vault, Salt: []byte{}, CreatedAt: e.clock.now()}
	}
	other := newVault(t, "other@example.com")
	e.publish(other)
	for _, c := range []struct {
		what string
		fn   func(Tx) error
	}{
		{"an account with the deleted account ID", func(tx Tx) error { return tx.InsertAccount(fresh(v.accountID(), randID(t))) }},
		{"an account with the deleted vault ID as its vault", func(tx Tx) error { return tx.InsertAccount(fresh(randID(t), v.vaultID())) }},
		{"an account with the deleted vault ID as its ID", func(tx Tx) error { return tx.InsertAccount(fresh(v.vaultID(), randID(t))) }},
		{"a vault with the deleted vault ID", func(tx Tx) error {
			id := randID(t)
			if err := tx.InsertAccount(fresh(id, randID(t))); err != nil {
				return err
			}
			return tx.InsertVault(&Vault{ID: v.vaultID(), AccountID: id, PublicState: []byte{}, LastBootstrap: -1})
		}},
		{"a vault row moved to the deleted account ID", func(tx Tx) error {
			gone, vault := v.accountID(), other.vaultID()
			return tx.(*sqliteTx).exec(`UPDATE vaults SET account_id = ? WHERE vault_id = ?`, gone[:], vault[:])
		}},
		{"an account row moved to the deleted vault ID", func(tx Tx) error {
			gone, acct := v.vaultID(), other.accountID()
			return tx.(*sqliteTx).exec(`UPDATE accounts SET vault_id = ? WHERE account_id = ?`, gone[:], acct[:])
		}},
	} {
		err := e.st.Update(ctx, c.fn)
		if !errors.Is(err, ErrDuplicate) || !strings.Contains(err.Error(), "deleted account or vault") {
			t.Errorf("%s: %v", c.what, err)
		}
	}

	again := newVault(t, v.email)
	e.publish(again)
	if d, err := ShowAccount(ctx, e.st, v.email, e.clock.now()); err != nil || d.ID != again.accountID() || d.ID == v.accountID() {
		t.Errorf("the email signed up again: %+v, %v", d, err)
	}
}

// A last seen time the server queued before the delete, written after
// it, writes nothing: the write needs the device's row.
func TestLateLastSeenAfterDelete(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	v := newVault(t, "a@example.com")
	e.publish(v)
	A := v.dev(0)
	e.session(v, A)
	e.disable(v, "")
	plan, err := PlanDelete(ctx, e.st, v.email, e.op(), 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := DeleteAccount(ctx, e.st, e.op(), plan, DeleteOptions{NoBackup: true}); err != nil {
		t.Fatal(err)
	}
	e.srv.noteSeen(v.accountID(), A)
	e.srv.flushSeen()
	if err := e.st.Update(ctx, func(tx Tx) error { return tx.SetDeviceSeen(v.accountID(), A, e.clock.now()) }); err != nil {
		t.Fatal(err)
	}
	var seen map[model.ID]time.Time
	e.view(func(tx Tx) (err error) {
		seen, err = tx.DevicesSeen(v.accountID())
		return err
	})
	if len(seen) != 0 {
		t.Errorf("a late last seen write recreated rows: %v", seen)
	}
}

// A delete needs a prior disable, for at least --min-disabled when given;
// refusals change nothing. An account that changed between the plan and
// the delete (enabled meanwhile, or its head moved by a retirement, which
// stays open while it is only disabled) is refused with "changed", before
// the fence, with a failed audit row.
func TestDeletePreconditions(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	v := newVault(t, "a@example.com")
	e.publish(v)
	B, wb := v.bootstrap("laptop")
	e.mustPost(v, e.login(v), wb)

	_, err := PlanDelete(ctx, e.st, v.email, e.op(), 0)
	wantAdminCode(t, err, "not_disabled", "a delete of an enabled account")
	e.disable(v, "")
	_, err = PlanDelete(ctx, e.st, v.email, e.op(), 24*time.Hour)
	wantAdminCode(t, err, "disabled_too_recently", "a delete an hour short of --min-disabled")
	e.clock.advance(24 * time.Hour)
	plan, err := PlanDelete(ctx, e.st, v.email, e.op(), 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}

	// B retires while the account is disabled: the head moves.
	e.must(e.retirePost(v, B, v.retire(B)), 200, nil)
	_, entries, err := DeleteAccount(ctx, e.st, e.op(), plan, DeleteOptions{NoBackup: true, MinDisabled: 24 * time.Hour})
	wantAdminCode(t, err, "changed", "a delete after the head moved")
	if len(entries) != 1 || entries[0].Action != ActionDeleteFence || entries[0].Result != "changed" {
		t.Errorf("audit rows %+v", entries)
	}
	plan, err = PlanDelete(ctx, e.st, v.email, e.op(), 0)
	if err != nil {
		t.Fatal(err)
	}
	enable(t, e, v)
	_, _, err = DeleteAccount(ctx, e.st, e.op(), plan, DeleteOptions{NoBackup: true})
	wantAdminCode(t, err, "changed", "a delete after an enable")
	e.view(func(tx Tx) error {
		if f, err := tx.DeleteFence(v.accountID()); err != nil || f != nil {
			t.Errorf("a refused delete left a fence: %+v, %v", f, err)
		}
		if _, err := tx.Account(v.accountID()); err != nil {
			t.Errorf("a refused delete removed the account: %v", err)
		}
		return nil
	})
}

func enable(t *testing.T, e *env, v *tvault) {
	t.Helper()
	ctx := context.Background()
	p, err := PlanEnable(ctx, e.st, v.email, e.op())
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := EnableAccount(ctx, e.st, e.op(), v.email, p); err != nil {
		t.Fatal(err)
	}
}

// failBackup runs a delete of v whose backup can't be written, which
// leaves the account fenced. It returns the fence.
func failBackup(t *testing.T, e *env, v *tvault) *DeleteFence {
	t.Helper()
	ctx := context.Background()
	plan, err := PlanDelete(ctx, e.st, v.email, e.op(), 0)
	if err != nil {
		t.Fatal(err)
	}
	notDir := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(notDir, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	_, entries, err := DeleteAccount(ctx, e.st, e.op(), plan, DeleteOptions{BackupDir: notDir})
	wantAdminCode(t, err, "backup_failed", "a delete whose backup fails")
	if len(entries) != 2 || entries[0].Action != ActionDeleteFence || entries[0].Result != "ok" ||
		entries[1].Action != ActionDelete || entries[1].Result != "backup_failed" {
		t.Errorf("audit rows %+v", entries)
	}
	var f *DeleteFence
	e.view(func(tx Tx) (err error) {
		f, err = tx.DeleteFence(v.accountID())
		return err
	})
	if f == nil || f.Head != v.head() {
		t.Fatalf("the fence after a failed backup: %+v", f)
	}
	return f
}

// A backup that fails deletes nothing and leaves the account fenced: the
// server then refuses it every write and the retire endpoints, sessions,
// logins and enable, and accounts ls shows it deleting. Cancel lifts the
// fence, and the account is as it was, disabled; retirement works again.
func TestDeleteFenceAndCancel(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	v := newVault(t, "a@example.com")
	e.publish(v)
	A := v.dev(0)
	B, wb := v.bootstrap("laptop")
	e.mustPost(v, e.login(v), wb)
	e.disable(v, "closing")
	before := tableCounts(t, openRaw(t, e.path))
	f := failBackup(t, e, v)

	after := tableCounts(t, openRaw(t, e.path))
	before["delete_fences"]++
	before["admin_audit"] += 2
	if !mapsEqual(before, after) {
		t.Errorf("a failed backup changed rows: %v, then %v", before, after)
	}
	list, err := ListAccounts(ctx, e.st)
	if err != nil || len(list) != 1 || !list[0].Deleting.Equal(f.At) {
		t.Errorf("accounts ls of a fenced account: %+v, %v", list, err)
	}

	retire := v.retire(B)
	wantCode(t, e.retirePost(v, B, retire), 403, CodeAccountDisabled, "retire-post while fenced")
	wantCode(t, e.retireStatus(v, A, crypto.Hash{}), 403, CodeAccountDisabled, "retire-status while fenced")
	wantCode(t, e.retireProof(v, A, 0), 403, CodeAccountDisabled, "retire-status/proof while fenced")
	wantCode(t, e.sessionAttempt(v, A), 403, CodeAccountDisabled, "a session while fenced")
	wantCode(t, e.do("POST", "/v1/login", "", loginRequest{v.accountID(), v.authKey}), 403, CodeAccountDisabled, "a login while fenced")
	_, err = PlanEnable(ctx, e.st, v.email, e.op())
	wantAdminCode(t, err, "deleting", "an enable while fenced")
	var head vaultlog.Head
	e.view(func(tx Tx) error {
		vt, err := tx.Vault(v.vaultID())
		head = vt.Head
		return err
	})
	if head != f.Head {
		t.Errorf("the head moved under the fence: %+v", head)
	}

	plan, err := PlanCancelDelete(ctx, e.st, v.email, e.op())
	if err != nil || plan.Fence == nil {
		t.Fatalf("plan cancel: %+v, %v", plan, err)
	}
	got, entry, err := CancelDelete(ctx, e.st, e.op(), plan)
	if err != nil || got.Fence != nil || got.Disabled == nil || entry.Action != ActionDeleteCancel || entry.Result != "ok" {
		t.Fatalf("cancel: %+v, %+v, %v", got, entry, err)
	}
	_, err = PlanCancelDelete(ctx, e.st, v.email, e.op())
	wantAdminCode(t, err, "not_deleting", "a cancel with no delete in progress")
	e.must(e.retirePost(v, B, retire), 200, nil)
	enable(t, e, v)
	e.session(v, A)
}

// A delete whose backup failed goes on from its fence when run again: no
// new fence, a verified backup, and the delete.
func TestDeleteResumesFromItsFence(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	v := newVault(t, "a@example.com")
	e.publish(v)
	e.disable(v, "")
	f := failBackup(t, e, v)
	e.clock.advance(time.Minute)

	plan, err := PlanDelete(ctx, e.st, v.email, e.op(), 0)
	if err != nil || plan.Fence == nil || !plan.Fence.At.Equal(f.At) {
		t.Fatalf("plan of a fenced account: %+v, %v", plan, err)
	}
	res, entries, err := DeleteAccount(ctx, e.st, e.op(), plan, DeleteOptions{BackupDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Action != ActionDelete || entries[0].Result != "ok" || !res.FencedAt.Equal(f.At) {
		t.Errorf("resumed delete: %+v, %+v", res, entries)
	}
	if err := VerifyBackup(ctx, res.Backup, f); err != nil {
		t.Errorf("the backup does not verify: %v", err)
	}
}

// VerifyBackup refuses a copy taken before the fence, one whose fence or
// head is not this delete's, and a file that is not a sound database.
func TestVerifyBackupRefuses(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	v := newVault(t, "a@example.com")
	e.publish(v)
	e.disable(v, "")
	early := filepath.Join(t.TempDir(), "early.db")
	if err := e.st.Backup(ctx, early); err != nil {
		t.Fatal(err)
	}
	f := failBackup(t, e, v)
	good := filepath.Join(t.TempDir(), "good.db")
	if err := e.st.Backup(ctx, good); err != nil {
		t.Fatal(err)
	}
	if err := VerifyBackup(ctx, good, f); err != nil {
		t.Fatalf("a backup under the fence: %v", err)
	}
	moved := *f
	moved.Head.Seq++
	otherFence := *f
	otherFence.At = f.At.Add(time.Second)
	garbage := filepath.Join(t.TempDir(), "garbage.db")
	b, err := os.ReadFile(good)
	if err != nil {
		t.Fatal(err)
	}
	for i := 4096; i < len(b); i += 97 {
		b[i] ^= 0xff
	}
	if err := os.WriteFile(garbage, b, 0o600); err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		what, path string
		f          *DeleteFence
	}{
		{"a backup from before the fence", early, f},
		{"another head", good, &moved},
		{"another fence", good, &otherFence},
		{"a damaged file", garbage, f},
		{"no file", filepath.Join(t.TempDir(), "none.db"), f},
	} {
		if err := VerifyBackup(ctx, c.path, c.f); err == nil {
			t.Errorf("%s verified", c.what)
		}
	}
	// hop-server backup writes 0600 and never over a file.
	if fi, err := os.Stat(good); err != nil || fi.Mode().Perm() != 0o600 {
		t.Errorf("backup mode %v, %v", fi.Mode(), err)
	}
	if err := e.st.Backup(ctx, good); err == nil {
		t.Error("a backup overwrote a file")
	}
}
