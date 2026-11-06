package server

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/dalyem/hopkey/internal/model"
	"github.com/dalyem/hopkey/internal/vaultlog"
)

func (e *env) account(v *tvault) *Account {
	e.t.Helper()
	var a *Account
	e.view(func(tx Tx) (err error) {
		a, err = tx.Account(v.accountID())
		return err
	})
	return a
}

func (e *env) setQuota(v *tvault, quota int64) {
	e.t.Helper()
	err := e.st.Update(context.Background(), func(tx Tx) error {
		a, err := tx.Account(v.accountID())
		if err != nil {
			return err
		}
		a.QuotaBytes = quota
		return tx.UpdateAccount(a)
	})
	if err != nil {
		e.t.Fatal(err)
	}
}

// count runs a COUNT or SUM query on the store under test.
func (e *env) count(q string, args ...any) int64 {
	e.t.Helper()
	var n int64
	if err := e.st.r.QueryRow(q, args...).Scan(&n); err != nil {
		e.t.Fatal(err)
	}
	return n
}

func (e *env) stateLen(v *tvault) int64 {
	id := v.vaultID()
	return e.count(`SELECT length(public_state) FROM vaults WHERE vault_id = ?`, id[:])
}

// persisted is what R13 must charge for the commit at seq, computed from
// the rows that commit wrote: its wire, the objects first stored with it,
// the devices it added, the receipts it wrote, and the change in the
// public state from stateBefore.
func (e *env) persisted(v *tvault, seq uint64, stateBefore int64) int64 {
	e.t.Helper()
	vid, aid := v.vaultID(), v.accountID()
	wire := e.count(`SELECT length(wire) FROM log WHERE vault_id = ? AND seq = ?`, vid[:], seq)
	bodies := e.count(`SELECT COALESCE(SUM(length(body)), 0) FROM objects WHERE vault_id = ? AND seq = ?`, vid[:], seq)
	rows := e.count(`SELECT COUNT(*) FROM objects WHERE vault_id = ? AND seq = ?`, vid[:], seq) +
		e.count(`SELECT COUNT(*) FROM devices WHERE account_id = ? AND added_seq = ?`, aid[:], seq) +
		e.count(`SELECT COUNT(*) FROM receipts WHERE account_id = ? AND seq = ?`, aid[:], seq)
	return wire + entryRowOverhead + bodies + rows*rowOverhead + e.stateLen(v) - stateBefore
}

// signupPersisted is what R13 must charge for v's signup: every wire's
// rows, the final public state, and the rows kept for the life of the
// account: the account and vault rows and the registration row holding
// the acknowledgment, with their email and capability-hash bytes.
func (e *env) signupPersisted(v *tvault) int64 {
	e.t.Helper()
	sum := e.stateLen(v)
	for seq := range uint64(len(v.log)) {
		sum += e.persisted(v, seq, e.stateLen(v))
	}
	aid := v.accountID()
	email := e.count(`SELECT length(CAST(email AS BLOB)) FROM accounts WHERE account_id = ?`, aid[:])
	capHash := e.count(`SELECT length(cap_hash) FROM registrations WHERE ack_account_id = ?`, aid[:])
	if email == 0 || capHash != 32 {
		e.t.Fatalf("signup rows: email %d bytes, capability hash %d bytes", email, capHash)
	}
	return sum + signupRowOverhead + 3*email + 2*capHash
}

// postCharged posts w and checks that the account was charged exactly what
// the commit persisted. It returns the charge.
func (e *env) postCharged(v *tvault, tok string, w *vaultlog.Wire) int64 {
	e.t.Helper()
	used, state := e.account(v).UsedBytes, e.stateLen(v)
	e.mustPost(v, tok, w)
	got := e.account(v).UsedBytes - used
	if want := e.persisted(v, w.Entry.Seq, state); got != want {
		e.t.Errorf("%s entry %d charged %d bytes, but the commit persisted %d", w.Entry.Kind, w.Entry.Seq, got, want)
	}
	return got
}

// fork copies the database into a second server, for admitting the same
// wire against a different quota.
func (e *env) fork(opts ...envOpt) *env {
	e.t.Helper()
	path := filepath.Join(e.t.TempDir(), "fork.db")
	if err := e.st.Backup(context.Background(), path); err != nil {
		e.t.Fatal(err)
	}
	return newEnvAt(e.t, path, opts...)
}

// The reserve half documented in reserveHalf, for the default limits.
func TestReserveHalfFormula(t *testing.T) {
	if got := reserveHalf(DefaultLimits()); got != 18_612_736 {
		t.Errorf("reserve half %d, want 18,612,736 (3 × 4 MiB + 512 + 24,576 × 160 + 8,192 × 256)", got)
	}
}

// R13 charges what a commit persists: the stored wire, the object bodies
// new to the vault, device rows, receipts and the public state, and
// admission uses that charge, for large envelopes and for checkpoints
// with many departures.
func TestQuotaChargesPersistedBytes(t *testing.T) {
	e := newEnv(t)
	v := newVault(t, "a@example.com")
	e.publish(v)
	A := v.dev(0)
	tok := e.session(v, A)

	// The signup charge covers its rows, the public state and the rows it
	// keeps for the life of the account too.
	signup := e.signupPersisted(v)
	if e.account(v).UsedBytes != signup {
		t.Errorf("signup charged %d, persisted %d", e.account(v).UsedBytes, signup)
	}

	// Large envelopes: 100 maximum-size snippets, over 1 MB of objects that
	// are stored apart from the wire as well as in it.
	f := e.fork()
	big := v.normal(A, 100, 8192)
	wireLen := int64(len(wireJSON(t, big)))
	var bodies int64
	for _, o := range big.Objects {
		bodies += int64(len(o.Body))
	}
	charge := e.postCharged(v, tok, big)
	if bodies < 1_000_000 || charge < wireLen+bodies {
		t.Errorf("an entry with %d bytes of objects in a %d-byte wire was charged %d", bodies, wireLen, charge)
	}
	half := reserveHalf(f.srv.lim)
	used := f.account(v).UsedBytes
	f.setQuota(v, used+2*half+charge-1)
	wantCode(t, f.post(v, tok, big), 507, "quota_exhausted", "a large entry one byte over the quota")
	f.setQuota(v, used+2*half+charge)
	f.mustPost(v, tok, big)
	if f.account(v).UsedBytes != used+charge {
		t.Errorf("the fork charged %d, the original %d", f.account(v).UsedBytes-used, charge)
	}

	// Many devices: each bootstrap adds a device row.
	var devs []model.ID
	for i := range 4 {
		d, w := v.bootstrap("dev-" + itoa(uint64(i)))
		e.postCharged(v, e.login(v), w)
		devs = append(devs, d)
	}
	// Many departures: a checkpoint revoking three devices writes three
	// receipts; its device_add ops for the survivors add no rows. After
	// those bootstraps it may spend the whole reserve, so it is admitted
	// up to the quota itself.
	f = e.fork()
	ck := v.checkpoint(A, devs[:3]...)
	charge = e.postCharged(v, tok, ck)
	if n := e.count(`SELECT COUNT(*) FROM receipts WHERE seq = ?`, ck.Entry.Seq); n != 3 {
		t.Errorf("%d receipts for the checkpoint", n)
	}
	used = f.account(v).UsedBytes
	f.setQuota(v, used+charge-1)
	wantCode(t, f.post(v, tok, ck), 507, "quota_exhausted", "a checkpoint one byte over the quota")
	f.setQuota(v, used+charge)
	f.mustPost(v, tok, ck)
	if f.account(v).Reserve != ReserveExhausted {
		t.Errorf("a checkpoint spending the reserve left it %v", f.account(v).Reserve)
	}

	// A retirement writes a receipt and deactivates the device.
	tok = e.session(v, devs[3])
	e.postCharged(v, tok, v.retire(devs[3]))
}

// R13: a signup is admitted when its whole charge, the rows it keeps for
// the life of the account included, leaves the recovery reserve free, and
// refused one byte short.
func TestSignupQuotaBoundary(t *testing.T) {
	v := newVault(t, "a@example.com")
	e := newEnv(t)
	e.publish(v)
	charge := e.signupPersisted(v)
	if got := e.account(v).UsedBytes; got != charge {
		t.Fatalf("signup charged %d, persisted %d", got, charge)
	}
	half := reserveHalf(DefaultLimits())
	for _, c := range []struct {
		quota  int64
		status int
	}{{charge + 2*half - 1, 507}, {charge + 2*half, 200}} {
		f := newEnv(t, withLimits(func(l *Limits) { l.QuotaBytes = c.quota }))
		code := f.invite(v.email)
		r := f.do("POST", "/v1/signup", "", f.signupReq(v, code, f.signupChallenge(v.email, code), 0, nil, testOrigin))
		if c.status == 507 {
			wantCode(t, r, 507, "quota_exhausted", "a signup one byte over the quota")
			if n := f.count(`SELECT COUNT(*) FROM accounts`); n != 0 {
				t.Errorf("%d accounts after the refused signup", n)
			}
			continue
		}
		wantStatus(t, r, 200, "a signup exactly at the quota")
		if got := f.account(v).UsedBytes; got != charge {
			t.Errorf("signup at the boundary charged %d, want %d", got, charge)
		}
	}
}

// R13: ordinary writes leave the recovery reserve; one bootstrap and the
// checkpoint after it may spend it, after which the account is
// capacity-exhausted and no further recovery sequence may spend it until
// an operator raises the quota.
func TestQuotaAndRecoveryReserve(t *testing.T) {
	e := newEnv(t, withLimits(func(l *Limits) { l.MaxWireResponse = 64 << 10 }))
	v := newVault(t, "a@example.com")
	e.publish(v)
	A := v.dev(0)
	tok := e.session(v, A)
	half := reserveHalf(e.srv.lim)
	state := func(want ReserveState, what string) {
		t.Helper()
		if got := e.account(v).Reserve; got != want {
			t.Errorf("%s: reserve %v, want %v", what, got, want)
		}
	}

	small := e.postCharged(v, tok, v.normal(A, 1, 100))
	e.setQuota(v, e.account(v).UsedBytes+2*half+small/2)
	wantCode(t, e.post(v, tok, v.unrecorded(A)), 507, "quota_exhausted", "an ordinary write into the reserve")
	state(ReserveIntact, "after a refused ordinary write")

	_, wb := v.bootstrap("dev-b")
	e.mustPost(v, e.recoverToken(v), wb)
	state(ReserveBootstrapSpent, "after a bootstrap on the reserve")
	wantCode(t, e.post(v, tok, v.unrecorded(A)), 507, "quota_exhausted", "an ordinary write after the bootstrap")
	stale := *v
	stale.log = nil
	_, wb2 := stale.bootstrap("dev-b2")
	wantCode(t, e.post(v, e.login(v), wb2), 507, "quota_exhausted", "a second bootstrap on the reserve")

	e.mustPost(v, tok, v.checkpoint(A))
	state(ReserveExhausted, "after the checkpoint completing the recovery")
	tok = e.session(v, A)
	wantCode(t, e.post(v, tok, v.unrecorded(A)), 507, "quota_exhausted", "an ordinary write after the recovery")
	r, _ := e.readLog(v, tok, "")
	wantStatus(t, r, 200, "reads in the exhausted state")
	r, _ = e.readLog(v, e.login(v), "")
	wantStatus(t, r, 200, "login in the exhausted state")

	// A second recovery sequence cannot spend the reserve again.
	stale = *v
	stale.log = nil
	_, wb3 := stale.bootstrap("dev-c")
	wantCode(t, e.post(v, e.recoverToken(v), wb3), 507, "quota_exhausted", "a bootstrap in the exhausted state")
	stale = *v
	stale.log = nil
	wantCode(t, e.post(v, tok, stale.checkpoint(A)), 507, "quota_exhausted", "a checkpoint in the exhausted state")
	state(ReserveExhausted, "after the refused second sequence")

	// Raising the quota without freeing the whole reserve keeps the state.
	used := e.account(v).UsedBytes
	op := Operator{Actor: "test", Now: e.clock.now()}
	q, _, err := SetQuota(context.Background(), e.st, op, v.email, used+2*half-1, e.srv.lim)
	if err != nil {
		t.Fatal(err)
	}
	if q.Reserve != ReserveExhausted || q.QuotaBytes != used+2*half-1 || q.UsedBytes != used || q.ReserveBytes != 2*half {
		t.Errorf("SetQuota short of the reserve: %+v", q)
	}
	wantCode(t, e.post(v, e.recoverToken(v), wb3), 507, "quota_exhausted", "a bootstrap before the reserve is replenished")
	// Freeing it ends the exhausted state, by account ID as well as email.
	if q, _, err = SetQuota(context.Background(), e.st, op, v.accountID().String(), used+2*half, e.srv.lim); err != nil {
		t.Fatal(err)
	}
	if q.Reserve != ReserveIntact {
		t.Errorf("SetQuota with the reserve free: %+v", q)
	}
	state(ReserveIntact, "after the operator raised the quota")
	e.mustPost(v, e.recoverToken(v), wb3)
	state(ReserveBootstrapSpent, "after a bootstrap on the replenished reserve")

	if _, _, err := SetQuota(context.Background(), e.st, op, "nobody@example.com", 1<<30, e.srv.lim); err == nil {
		t.Error("SetQuota for an unknown account")
	}
	if _, _, err := SetQuota(context.Background(), e.st, op, v.email, 0, e.srv.lim); err == nil {
		t.Error("SetQuota with a zero quota")
	}
}
