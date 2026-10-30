package server

import (
	"context"
	"crypto/rand"
	"database/sql"
	"errors"
	"fmt"
	"io/fs"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"time"

	"github.com/dalyem/hopkey/internal/crypto"
	"github.com/dalyem/hopkey/internal/model"
	"github.com/dalyem/hopkey/internal/vaultlog"
)

// Account delete: hop-server accounts delete, the one irreversible admin
// command, and the only thing an operator can do for an owner who lost
// both the password and the Emergency Kit. It needs a prior disable, and
// it runs in three steps, each with its audit row:
//
//  1. Fence. One transaction checks that the account is as the operator
//     confirmed it, records its vault head in delete_fences under a new
//     random fence ID, and deletes its sessions and login tokens again.
//     From then on the server refuses the account every write
//     (retire-post included), session, login, recovery, enrollment claim
//     and retire-status, so its head stays at the fenced one.
//     CancelDelete lifts the fence.
//  2. Backup. VACUUM INTO a new file of mode 0600, in a directory created
//     durably if need be (mkdirDurable), verified: opened read-only,
//     PRAGMA integrity_check, the account and its fence there, its vault
//     head the fenced head. A failure stops here: the fence stays and
//     nothing is deleted.
//  3. Delete. One transaction checks that the fence still stands and the
//     head is still the fenced one, deletes every row of the account
//     (accountRows), tombstones its account and vault IDs (deleted_ids)
//     and writes the audit row, with the account ID and never the email.
//
// A fence is known by its ID alone: a cancel and a new fence in the same
// second, at the same head, is another fence, and a delete, resume or
// cancel shown the old one refuses with "changed".
//
// The email is not tombstoned: it can be invited again, and signs up as
// a new account with new IDs. A device of the deleted account gets the
// 401 any unknown device gets: the server tells a caller nothing before
// it proves something, and the device's key went with the account. Its
// client locks as for any answer that does not confirm the device, and
// nothing on it is deleted; its local copy stays, for the owner to
// salvage.
//
// The pre-delete backup holds the deleted account, and every other one:
// deleting it is the operator's job. A database restored from a file
// older than the delete brings the account back, without its tombstones;
// nothing here can prevent that.

// Audit actions of account delete.
const (
	ActionDeleteFence  = "accounts.delete.fence"
	ActionDelete       = "accounts.delete"
	ActionDeleteCancel = "accounts.delete.cancel"
)

// fenceRefusal refuses the account a request while a delete fences it, as
// a disabled account, which it is: a delete needs a prior disable, and
// enable refuses while the fence stands. Call it only once the caller
// proved it holds the device's key or the account's secret, or a session.
func fenceRefusal(tx Tx, accountID model.ID) error {
	f, err := tx.DeleteFence(accountID)
	if err != nil || f == nil {
		return err
	}
	b, err := tx.AccountDisabled(accountID)
	if err != nil {
		return err
	}
	if b == nil {
		b = &AdminBlock{}
	}
	return errAccountDisabled(b)
}

// DeletePlan is an account as a delete finds it: what the operator
// confirms, and what the delete removes.
type DeletePlan struct {
	AccountID model.ID
	VaultID   model.ID
	Email     string
	Disabled  *AdminBlock
	// Fence is a delete started earlier and not finished (its backup
	// failed, say); nil when none is. A delete of a fenced account goes on
	// from it.
	Fence     *DeleteFence
	Head      vaultlog.Head
	UsedBytes int64
	// Devices are every device the account has had, which the delete
	// removes.
	Devices []model.ID
	// Rows are the account's rows per table, every one of which the
	// delete removes.
	Rows map[string]int
	// Invites are the pending invites for the email, which the delete
	// keeps: the email may be invited again.
	Invites []*Invite
}

// readDeletePlan reads the account who names, an ID or an email.
func readDeletePlan(tx Tx, who string, now time.Time) (*DeletePlan, error) {
	a, err := findAccount(tx, who)
	if err != nil {
		return nil, err
	}
	p := &DeletePlan{AccountID: a.ID, VaultID: a.VaultID, Email: a.Email, UsedBytes: a.UsedBytes}
	if p.Disabled, err = tx.AccountDisabled(a.ID); err != nil {
		return nil, err
	}
	if p.Fence, err = tx.DeleteFence(a.ID); err != nil {
		return nil, err
	}
	v, err := tx.Vault(a.VaultID)
	if err != nil {
		return nil, err
	}
	p.Head = v.Head
	devs, err := tx.Devices(a.ID)
	if err != nil {
		return nil, err
	}
	for _, d := range devs {
		p.Devices = append(p.Devices, d.DeviceID)
	}
	if p.Rows, err = tx.AccountRows(a.ID, a.VaultID); err != nil {
		return nil, err
	}
	if p.Invites, err = pendingInvites(tx, a.Email, now); err != nil {
		return nil, err
	}
	return p, nil
}

// planDelete is readDeletePlan with a delete's preconditions: the account
// is disabled, for at least minDisabled.
func planDelete(tx Tx, who string, op Operator, minDisabled time.Duration) (*DeletePlan, error) {
	p, err := readDeletePlan(tx, who, op.Now)
	if err != nil {
		return nil, err
	}
	switch {
	case p.Disabled == nil:
		return nil, adminErr("not_disabled", "the account is not disabled: a delete needs a prior hop-server accounts disable")
	case op.Now.Sub(p.Disabled.At) < minDisabled:
		return nil, adminErr("disabled_too_recently", "the account was disabled %s ago, and the minimum asked for is %s",
			op.Now.Sub(p.Disabled.At).Round(time.Second), minDisabled)
	}
	return p, nil
}

// PlanDelete returns what DeleteAccount would do to the account who
// names, an ID or an email. It refuses an account that is not disabled,
// or was disabled less than minDisabled ago. It changes nothing.
func PlanDelete(ctx context.Context, st Store, who string, op Operator, minDisabled time.Duration) (*DeletePlan, error) {
	var out *DeletePlan
	err := st.View(ctx, func(tx Tx) (err error) {
		out, err = planDelete(tx, who, op, minDisabled)
		return err
	})
	return out, err
}

// sameDeletePlan reports whether got is still the account the operator
// confirmed in want: the same account and vault, at the same head, with
// the same devices, disabled since the same time, and the same fence (by
// its ID) or none. Row counts move on their own (challenges, last seen)
// and are not compared, nor is the disable's reason.
func sameDeletePlan(got, want *DeletePlan) bool {
	sameFence := (got.Fence == nil) == (want.Fence == nil) && (got.Fence == nil || got.Fence.ID == want.Fence.ID)
	return got.AccountID == want.AccountID && got.VaultID == want.VaultID && got.Head == want.Head &&
		slices.Equal(got.Devices, want.Devices) && sameFence &&
		got.Disabled != nil && want.Disabled != nil && got.Disabled.At.Equal(want.Disabled.At)
}

// recheckDelete plans again in tx, by the account's ID, and refuses with
// "changed" unless the plan is want.
func recheckDelete(tx Tx, op Operator, want *DeletePlan, minDisabled time.Duration) (*DeletePlan, error) {
	got, err := planDelete(tx, want.AccountID.String(), op, minDisabled)
	var ae *AdminError
	if errors.As(err, &ae) {
		return nil, adminErr("changed", "the account changed since it was shown (%s); nothing was deleted; run the command again", ae.Msg)
	}
	if err != nil {
		return nil, err
	}
	if !sameDeletePlan(got, want) {
		return nil, adminErr("changed", "the account changed since it was shown; nothing was deleted; run the command again")
	}
	return got, nil
}

// DeleteOptions are a delete's choices.
type DeleteOptions struct {
	// MinDisabled refuses an account disabled for less than this.
	MinDisabled time.Duration
	// BackupDir is where the pre-delete backup is written; it is created,
	// mode 0700, if needed.
	BackupDir string
	// NoBackup skips the backup. It is for tests.
	NoBackup bool
	// syncDir makes a new directory entry durable; nil is syncDir. Tests
	// set it.
	syncDir func(dir string) error
}

// DeleteResult is what a delete did.
type DeleteResult struct {
	AccountID model.ID
	VaultID   model.ID
	Head      vaultlog.Head // the vault's head when it was deleted: the fenced one
	FenceID   model.ID
	FencedAt  time.Time
	// Backup is the verified pre-delete backup; "" with NoBackup. It holds
	// the deleted account and every other one.
	Backup string
	// Rows are the rows deleted per table.
	Rows map[string]int
	// Devices are the IDs of the devices deleted with the account.
	Devices []model.ID
}

type fenceParams struct {
	FenceID    model.ID    `json:"fence_id"`
	VaultID    model.ID    `json:"vault_id"`
	HeadSeq    uint64      `json:"head_seq,string"`
	HeadH      crypto.Hash `json:"head_h"`
	DisabledAt int64       `json:"disabled_at"`
}

// deleteParams are the delete's audit params: never the email.
type deleteParams struct {
	FenceID  model.ID       `json:"fence_id"`
	VaultID  model.ID       `json:"vault_id"`
	HeadSeq  uint64         `json:"head_seq,string"`
	HeadH    crypto.Hash    `json:"head_h"`
	FencedAt int64          `json:"fenced_at"`
	Backup   *string        `json:"backup"` // null with NoBackup
	Rows     map[string]int `json:"rows"`
	Devices  []model.ID     `json:"devices"`
}

// DeleteAccount deletes the account PlanDelete showed as want, in the
// three steps described above, and returns the audit rows it wrote. It
// goes on from want's fence when there is one. It refuses with "changed"
// when the account is not as planned; a backup that fails or does not
// verify leaves the account fenced (backup_failed), with nothing
// deleted. The operator's confirmation is the caller's: this is the
// irreversible step.
func DeleteAccount(ctx context.Context, st Store, op Operator, want *DeletePlan, opts DeleteOptions) (*DeleteResult, []*AuditEntry, error) {
	var entries []*AuditEntry
	note := func(e *AuditEntry) {
		if e != nil {
			entries = append(entries, e)
		}
	}
	fence := want.Fence
	if fence == nil {
		var id model.ID
		if _, err := rand.Read(id[:]); err != nil {
			return nil, nil, err
		}
		params := &fenceParams{FenceID: id, VaultID: want.VaultID, HeadSeq: want.Head.Seq, HeadH: want.Head.H}
		if want.Disabled != nil {
			params.DisabledAt = want.Disabled.At.Unix()
		}
		entry, err := op.change(ctx, st, ActionDeleteFence, &want.AccountID, params, func(tx Tx) (*model.ID, error) {
			got, err := recheckDelete(tx, op, want, opts.MinDisabled)
			if err != nil {
				return nil, err
			}
			f := &DeleteFence{ID: id, AccountID: got.AccountID, VaultID: got.VaultID, At: op.Now.Truncate(time.Second), Head: got.Head}
			if err := tx.SetDeleteFence(got.AccountID, f); err != nil {
				return nil, err
			}
			// The disable ended them, and the server issues none while it
			// lasts; none outlives the fence all the same.
			if err := tx.DeleteSessions(got.AccountID, nil); err != nil {
				return nil, err
			}
			if err := tx.DeleteLoginTokens(got.AccountID); err != nil {
				return nil, err
			}
			fence = f
			return &got.AccountID, nil
		})
		note(entry)
		if err != nil {
			return nil, entries, err
		}
	} else if err := st.View(ctx, func(tx Tx) error {
		_, err := recheckDelete(tx, op, want, opts.MinDisabled)
		return err
	}); err != nil {
		return nil, entries, err
	}

	res := &DeleteResult{AccountID: want.AccountID, VaultID: want.VaultID, Head: fence.Head, FenceID: fence.ID, FencedAt: fence.At}
	params := &deleteParams{FenceID: fence.ID, VaultID: fence.VaultID, HeadSeq: fence.Head.Seq, HeadH: fence.Head.H, FencedAt: fence.At.Unix(),
		Rows: map[string]int{}, Devices: []model.ID{}}
	if !opts.NoBackup {
		sync := opts.syncDir
		if sync == nil {
			sync = syncDir
		}
		path, berr := writeBackup(ctx, st, opts.BackupDir, sync, fence, op.Now)
		if path != "" {
			params.Backup = &path
		}
		if berr != nil {
			entry, err := op.change(ctx, st, ActionDelete, &want.AccountID, params, func(Tx) (*model.ID, error) {
				return nil, adminErr("backup_failed", "the pre-delete backup failed (%v); nothing was deleted, and the account stays fenced: "+
					"run the command again, or lift the fence with hop-server accounts delete --cancel", berr)
			})
			note(entry)
			return nil, entries, err
		}
		res.Backup = path
	}

	entry, err := op.change(ctx, st, ActionDelete, &want.AccountID, params, func(tx Tx) (*model.ID, error) {
		a, err := tx.Account(want.AccountID)
		if errors.Is(err, ErrNotFound) {
			return nil, adminErr("changed", "the account is gone already")
		}
		if err != nil {
			return nil, err
		}
		f, err := tx.DeleteFence(a.ID)
		if err != nil {
			return nil, err
		}
		if f == nil || f.ID != fence.ID || f.VaultID != a.VaultID {
			return nil, adminErr("changed", "the delete's fence was lifted or set again since the backup; nothing was deleted")
		}
		v, err := tx.Vault(a.VaultID)
		if err != nil {
			return nil, err
		}
		if v.Head != f.Head {
			return nil, adminErr("changed", "the vault moved past the fenced head (seq %d, now %d); nothing was deleted", f.Head.Seq, v.Head.Seq)
		}
		if b, err := tx.AccountDisabled(a.ID); err != nil {
			return nil, err
		} else if b == nil {
			return nil, adminErr("changed", "the account is no longer disabled; nothing was deleted")
		}
		devs, err := tx.Devices(a.ID)
		if err != nil {
			return nil, err
		}
		for _, d := range devs {
			params.Devices = append(params.Devices, d.DeviceID)
		}
		rows, err := tx.DeleteAccountRows(a.ID, a.VaultID)
		if err != nil {
			return nil, err
		}
		if err := tx.InsertDeleted(DeletedAccount, a.ID, a.ID, op.Now); err != nil {
			return nil, err
		}
		if err := tx.InsertDeleted(DeletedVault, a.VaultID, a.ID, op.Now); err != nil {
			return nil, err
		}
		params.Rows, res.Rows, res.Devices = rows, rows, params.Devices
		return &a.ID, nil
	})
	note(entry)
	if err != nil {
		return nil, entries, err
	}
	return res, entries, nil
}

// BackupName is the file name of an account's pre-delete backup, taken
// at now.
func BackupName(accountID model.ID, now time.Time) string {
	return fmt.Sprintf("pre-delete-%s-%s.db", accountID, now.UTC().Format("20060102T150405Z"))
}

// writeBackup writes the pre-delete backup into dir, created durably
// with sync if need be (mkdirDurable), and verifies it against the fence.
// A backup that does not verify is removed: it is no backup, and it holds
// every account. The path is returned once one was chosen.
func writeBackup(ctx context.Context, st Store, dir string, sync func(string) error, f *DeleteFence, now time.Time) (string, error) {
	if dir == "" {
		return "", errors.New("no backup directory")
	}
	if err := mkdirDurable(dir, sync); err != nil {
		return "", fmt.Errorf("the backup directory %s: %w", dir, err)
	}
	path, err := filepath.Abs(filepath.Join(dir, BackupName(f.AccountID, now)))
	if err != nil {
		return "", err
	}
	if err := st.Backup(ctx, path); err != nil {
		return path, err
	}
	if err := VerifyBackup(ctx, path, f); err != nil {
		os.Remove(path)
		return path, fmt.Errorf("the backup %s did not verify, and was removed: %w", path, err)
	}
	return path, nil
}

// mkdirDurable creates dir and its missing parents, mode 0700, as
// os.MkdirAll does, and after each directory it creates, syncs its
// parent (with sync), from the top down: a backup synced in a directory
// whose own entry a power loss can still undo is not on disk. dir's
// parent is synced even when dir was there, in case a run that crashed
// created it without the sync.
func mkdirDurable(dir string, sync func(string) error) error {
	dir, err := filepath.Abs(dir)
	if err != nil {
		return err
	}
	var missing []string
	for d := dir; ; d = filepath.Dir(d) {
		fi, err := os.Stat(d)
		if err == nil {
			if !fi.IsDir() {
				return fmt.Errorf("%s is not a directory", d)
			}
			break
		}
		if !errors.Is(err, fs.ErrNotExist) || filepath.Dir(d) == d {
			return err
		}
		missing = append(missing, d)
	}
	if len(missing) == 0 {
		return sync(filepath.Dir(dir))
	}
	for i := len(missing) - 1; i >= 0; i-- {
		// One that appeared meanwhile is synced all the same.
		if err := os.Mkdir(missing[i], 0o700); err != nil && !errors.Is(err, fs.ErrExist) {
			return err
		}
		if err := sync(filepath.Dir(missing[i])); err != nil {
			return err
		}
	}
	return nil
}

// VerifyBackup checks that the database file at path is a sound copy
// taken under the fence f: it opens read-only, passes PRAGMA
// integrity_check, is of this schema version, and holds the account,
// disabled, with f as its fence (by its ID, time and head) and f's head
// as its vault's head.
func VerifyBackup(ctx context.Context, path string, f *DeleteFence) error {
	if _, err := os.Stat(path); err != nil {
		return err
	}
	db, err := sql.Open("sqlite", "file:"+(&url.URL{Path: path}).EscapedPath()+"?mode=ro")
	if err != nil {
		return err
	}
	defer db.Close()
	var check string
	if err := db.QueryRowContext(ctx, `PRAGMA integrity_check`).Scan(&check); err != nil {
		return err
	}
	if check != "ok" {
		return fmt.Errorf("integrity_check: %s", check)
	}
	var v []byte
	if err := db.QueryRowContext(ctx, `SELECT v FROM meta WHERE k = 'schema_version'`).Scan(&v); err != nil {
		return fmt.Errorf("its schema version: %w", err)
	}
	if string(v) != schemaVersion {
		return fmt.Errorf("its schema version is %q, not %q", v, schemaVersion)
	}
	var n int
	err = db.QueryRowContext(ctx, `SELECT COUNT(*) FROM accounts a JOIN account_admin x ON x.account_id = a.account_id
		WHERE a.account_id = ? AND a.vault_id = ? AND x.disabled_at IS NOT NULL`, f.AccountID[:], f.VaultID[:]).Scan(&n)
	if err != nil {
		return err
	}
	if n != 1 {
		return errors.New("it does not hold the account, disabled")
	}
	var at, seq, fseq int64
	var id, h, fh []byte
	err = db.QueryRowContext(ctx, `SELECT f.fence_id, f.fenced_at, f.head_seq, f.head_h, v.head_seq, v.head_h
		FROM delete_fences f JOIN vaults v ON v.vault_id = f.vault_id AND v.account_id = f.account_id
		WHERE f.account_id = ?`, f.AccountID[:]).Scan(&id, &at, &fseq, &fh, &seq, &h)
	if errors.Is(err, sql.ErrNoRows) {
		return errors.New("it does not hold the account's fence, or its vault")
	}
	if err != nil {
		return err
	}
	if !slices.Equal(id, f.ID[:]) || at != f.At.Unix() || fseq < 0 || uint64(fseq) != f.Head.Seq || !slices.Equal(fh, f.Head.H[:]) {
		return errors.New("its fence is not this delete's")
	}
	if seq < 0 || uint64(seq) != f.Head.Seq || !slices.Equal(h, f.Head.H[:]) {
		return fmt.Errorf("its vault head is seq %d, not the fenced seq %d", seq, f.Head.Seq)
	}
	return nil
}

// PlanCancelDelete returns the delete in progress that CancelDelete would
// lift. It refuses when there is none.
func PlanCancelDelete(ctx context.Context, st Store, who string, op Operator) (*DeletePlan, error) {
	var out *DeletePlan
	err := st.View(ctx, func(tx Tx) (err error) {
		out, err = planCancel(tx, who, op)
		return err
	})
	return out, err
}

func planCancel(tx Tx, who string, op Operator) (*DeletePlan, error) {
	p, err := readDeletePlan(tx, who, op.Now)
	if err == nil && p.Fence == nil {
		err = adminErr("not_deleting", "no delete of the account is in progress")
	}
	return p, err
}

type cancelParams struct {
	FenceID  model.ID `json:"fence_id"`
	FencedAt int64    `json:"fenced_at"`
	HeadSeq  uint64   `json:"head_seq,string"`
}

// CancelDelete lifts the fence of the delete PlanCancelDelete showed as
// want. The account stays disabled; hop-server accounts enable undoes
// that. It refuses with "changed" when the fence is not the one shown (by
// its ID).
func CancelDelete(ctx context.Context, st Store, op Operator, want *DeletePlan) (*DeletePlan, *AuditEntry, error) {
	if want.Fence == nil {
		return nil, nil, adminErr("not_deleting", "no delete of the account is in progress")
	}
	params := &cancelParams{FenceID: want.Fence.ID, FencedAt: want.Fence.At.Unix(), HeadSeq: want.Fence.Head.Seq}
	var out *DeletePlan
	entry, err := op.change(ctx, st, ActionDeleteCancel, &want.AccountID, params, func(tx Tx) (*model.ID, error) {
		got, err := planCancel(tx, want.AccountID.String(), op)
		var ae *AdminError
		if errors.As(err, &ae) {
			return nil, adminErr("changed", "the account changed since it was shown (%s); run the command again", ae.Msg)
		}
		if err != nil {
			return nil, err
		}
		if got.Fence.ID != want.Fence.ID {
			return nil, adminErr("changed", "the delete's fence changed since it was shown; run the command again")
		}
		if err := tx.SetDeleteFence(got.AccountID, nil); err != nil {
			return nil, err
		}
		if out, err = readDeletePlan(tx, got.AccountID.String(), op.Now); err != nil {
			return nil, err
		}
		return &got.AccountID, nil
	})
	return out, entry, err
}
