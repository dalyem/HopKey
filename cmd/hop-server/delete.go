package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/dalyem/hopkey/internal/email"
	"github.com/dalyem/hopkey/internal/model"
	"github.com/dalyem/hopkey/internal/server"
)

// hop-server accounts delete: the one irreversible admin command. It
// needs a prior accounts disable. It shows the account and everything it
// will delete, and asks twice: the account's email typed (or --confirm
// EMAIL), then [y/N] (or --yes). It fences the account, writes and
// verifies a backup, and only then deletes (server.DeleteAccount).
// --cancel lifts the fence of a delete that stopped before its last
// step.

const deleteUsage = "usage: hop-server accounts delete ACCOUNT_ID|EMAIL [--confirm EMAIL] [--backup-dir DIR | --no-backup] " +
	"[--min-disabled DURATION] [--dry-run] [--yes] [--json] --data DIR\n" +
	"       hop-server accounts delete --cancel ACCOUNT_ID|EMAIL [--dry-run] [--yes] [--json] --data DIR"

type deletePlanJSON struct {
	AccountID      model.ID       `json:"account_id"`
	Email          string         `json:"email"`
	VaultID        model.ID       `json:"vault_id"`
	Disabled       *blockJSON     `json:"disabled"`
	Deleting       *deletingJSON  `json:"deleting"`
	HeadSeq        uint64         `json:"head_seq"`
	UsedBytes      int64          `json:"used_bytes"`
	Devices        []model.ID     `json:"devices"`
	Rows           map[string]int `json:"rows"`
	PendingInvites []inviteJSON   `json:"pending_invites"`
}

// deletingJSON is a delete in progress: its fence's ID, when it was set,
// and the head it holds the vault at.
type deletingJSON struct {
	FenceID  model.ID  `json:"fence_id"`
	FencedAt time.Time `json:"fenced_at"`
	HeadSeq  uint64    `json:"head_seq"`
}

func deletePlanOf(p *server.DeletePlan, now time.Time) deletePlanJSON {
	out := deletePlanJSON{
		AccountID: p.AccountID, Email: p.Email, VaultID: p.VaultID, Disabled: blockOf(p.Disabled),
		HeadSeq: p.Head.Seq, UsedBytes: p.UsedBytes, Devices: []model.ID{}, Rows: p.Rows,
		PendingInvites: invitesJSON(p.Invites, now),
	}
	if p.Fence != nil {
		out.Deleting = &deletingJSON{FenceID: p.Fence.ID, FencedAt: p.Fence.At.UTC(), HeadSeq: p.Fence.Head.Seq}
	}
	out.Devices = append(out.Devices, p.Devices...)
	return out
}

// rowsText lists the tables with rows, in a fixed order, for people.
func rowsText(rows map[string]int) string {
	var names []string
	for t, n := range rows {
		if n > 0 {
			names = append(names, t)
		}
	}
	slices.Sort(names)
	var parts []string
	for _, t := range names {
		parts = append(parts, fmt.Sprintf("%s %d", t, rows[t]))
	}
	if len(parts) == 0 {
		return "none"
	}
	return strings.Join(parts, ", ")
}

func printDeletePlan(w io.Writer, p *server.DeletePlan) {
	fmt.Fprintf(w, "account %s (%s): %s\n", p.AccountID, esc(p.Email), disabledText(p.Disabled))
	fmt.Fprintf(w, "  vault %s at head seq %d, %s used, %s\n", p.VaultID, p.Head.Seq, size(p.UsedBytes),
		plural(len(p.Devices), "device", "devices"))
	fmt.Fprintf(w, "  rows: %s\n", rowsText(p.Rows))
	if len(p.Invites) > 0 {
		fmt.Fprintf(w, "  %s for the email stay\n", plural(len(p.Invites), "pending invite", "pending invites"))
	}
	if p.Fence != nil {
		fmt.Fprintf(w, "  a delete started %s is in progress: the account is fenced at head seq %d (fence %s)\n", when(p.Fence.At), p.Fence.Head.Seq, p.Fence.ID)
	}
}

const deleteHelp = "This cannot be undone. Every row above is deleted from this server; the account and vault IDs " +
	"are never used again, and the audit trail keeps the account ID. The email can be invited again, as a new account. " +
	"First the account is fenced (the server refuses it every write, session and logout), then a backup is written and verified, " +
	"and only then is it deleted; if the backup fails, nothing is deleted and the account stays fenced " +
	"(hop-server accounts delete --cancel lifts it). Its devices lock and keep their local copy: nothing on them is deleted."

func deleteBackupText(dir string, none bool) string {
	if none {
		return "WARNING: --no-backup: no backup is taken, so nothing can bring the account back."
	}
	return fmt.Sprintf("The backup goes to %s. It holds this account and every other one: delete it on your own retention policy.", esc(dir))
}

func accountsDelete(args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("accounts delete", flag.ContinueOnError)
	f := newChangeFlags(fs)
	cancel := fs.Bool("cancel", false, "lift the fence of a delete that stopped before deleting")
	confirmEmail := fs.String("confirm", "", "the account's email, typed to confirm the delete (needed without a terminal)")
	backupDir := fs.String("backup-dir", "", "where to write the pre-delete backup (default DATA/backups)")
	noBackup := fs.Bool("no-backup", false, "take no backup (for tests: nothing can bring the account back)")
	minText := fs.String("min-disabled", "", "refuse unless the account has been disabled at least this long: Nd, or a Go duration such as 24h")
	pos, err := parse(fs, args)
	if err != nil {
		return err
	}
	if len(pos) != 1 {
		return errors.New(deleteUsage)
	}
	if *cancel {
		if *confirmEmail != "" || *backupDir != "" || *noBackup || *minText != "" {
			return errors.New("--cancel takes no --confirm, --backup-dir, --no-backup or --min-disabled\n" + deleteUsage)
		}
		return accountsDeleteCancel(pos[0], f, stdout, stderr)
	}
	if *noBackup && *backupDir != "" {
		return errors.New("--no-backup and --backup-dir go separately")
	}
	var minDisabled time.Duration
	if *minText != "" {
		if minDisabled, err = parseTTL(*minText); err != nil {
			return fmt.Errorf("--min-disabled: %w", err)
		}
	}
	dir := *backupDir
	if dir == "" && !*noBackup {
		if *f.data == "" {
			return errors.New("--data is required")
		}
		dir = filepath.Join(*f.data, "backups")
	}
	if dir != "" {
		if dir, err = filepath.Abs(dir); err != nil {
			return err
		}
	}
	st, err := openStore(*f.data)
	if err != nil {
		return err
	}
	defer st.Close()
	ctx := context.Background()
	now := clock().UTC()
	plan, err := server.PlanDelete(ctx, st, pos[0], operator(), minDisabled)
	if err != nil {
		return err
	}
	if *f.asJSON && *f.dryRun {
		return writeJSON(stdout, struct {
			DryRun  bool           `json:"dry_run"`
			Account deletePlanJSON `json:"account"`
			Backup  *string        `json:"backup_dir"`
		}{true, deletePlanOf(plan, now), strOrNil(dir)})
	}
	if w := f.planOut(stdout, stderr); w != nil {
		printDeletePlan(w, plan)
		fmt.Fprintln(w, "would delete the account and everything above. "+deleteHelp)
		fmt.Fprintln(w, deleteBackupText(dir, *noBackup))
		if *f.dryRun {
			fmt.Fprintln(w, "dry run: nothing changed")
			return nil
		}
	}
	if err := confirmDelete(stderr, plan.Email, *confirmEmail); err != nil {
		return err
	}
	if err := confirm(stderr, *f.yes, fmt.Sprintf("Delete %s for good?", esc(plan.Email))); err != nil {
		return err
	}
	if *noBackup {
		fmt.Fprintln(stderr, "hop-server: warning: --no-backup: deleting without a backup")
	}
	res, entries, err := server.DeleteAccount(ctx, st, operator(), plan, server.DeleteOptions{
		MinDisabled: minDisabled, BackupDir: dir, NoBackup: *noBackup,
	})
	for _, e := range entries {
		printAudit(stderr, e)
	}
	if err != nil {
		return err
	}
	if *f.asJSON {
		ids := []int64{}
		for _, e := range entries {
			ids = append(ids, e.ID)
		}
		// The account no longer exists: what is left to report is what
		// went, and the backup that still holds it.
		return writeJSON(stdout, struct {
			Deleted deletedJSON `json:"deleted"`
			Exists  bool        `json:"exists"`
			Backup  *string     `json:"backup"`
			Audit   []int64     `json:"audit_ids"`
		}{deletedJSON{res.AccountID, res.VaultID, res.Head.Seq, res.FenceID, res.FencedAt.UTC(), append([]model.ID{}, res.Devices...), res.Rows},
			false, strOrNil(res.Backup), ids})
	}
	fmt.Fprintf(stdout, "deleted account %s at head seq %d: %s\n", res.AccountID, res.Head.Seq, rowsText(res.Rows))
	if res.Backup != "" {
		fmt.Fprintf(stdout, "the pre-delete backup is %s; it holds this account and every other one: delete it on your own retention policy\n", esc(res.Backup))
	}
	fmt.Fprintln(stdout, "its devices lock and keep their local copy; the email can be invited again, as a new account")
	return nil
}

type deletedJSON struct {
	AccountID model.ID       `json:"account_id"`
	VaultID   model.ID       `json:"vault_id"`
	HeadSeq   uint64         `json:"head_seq"`
	FenceID   model.ID       `json:"fence_id"`
	FencedAt  time.Time      `json:"fenced_at"`
	Devices   []model.ID     `json:"devices"`
	Rows      map[string]int `json:"rows"`
}

func strOrNil(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

// confirmDelete makes the operator name the account by its email: given
// as --confirm, or typed on a terminal. Either must normalize to the
// account's email. Without a terminal, --confirm is required, --yes or
// not.
func confirmDelete(stderr io.Writer, want, given string) error {
	if given == "" {
		if !stdinIsTTY() {
			return errors.New("not deleting without the account's email: give --confirm EMAIL (and --yes), or run it on a terminal")
		}
		fmt.Fprintf(stderr, "This deletes the account for good. Type its email to confirm: ")
		given = readLine(stdin)
	}
	got, err := email.Normalize(strings.TrimSpace(given))
	if err != nil || got != want {
		return errors.New("that is not the account's email; nothing changed")
	}
	return nil
}

// readLine reads one line from r, a byte at a time, so the [y/N] that
// follows on the same input is left for confirm.
func readLine(r io.Reader) string {
	var b []byte
	one := make([]byte, 1)
	for {
		n, err := r.Read(one)
		if n == 1 {
			if one[0] == '\n' {
				break
			}
			b = append(b, one[0])
		}
		if err != nil {
			break
		}
	}
	return string(b)
}

func accountsDeleteCancel(who string, f changeFlags, stdout, stderr io.Writer) error {
	st, err := openStore(*f.data)
	if err != nil {
		return err
	}
	defer st.Close()
	ctx := context.Background()
	now := clock().UTC()
	plan, err := server.PlanCancelDelete(ctx, st, who, operator())
	if err != nil {
		return err
	}
	const what = "would lift the delete's fence: nothing is deleted, the account stays disabled " +
		"(hop-server accounts enable undoes that), and a new delete starts over with a new backup."
	if *f.asJSON && *f.dryRun {
		return writeJSON(stdout, struct {
			DryRun  bool           `json:"dry_run"`
			Account deletePlanJSON `json:"account"`
			Change  string         `json:"change"`
		}{true, deletePlanOf(plan, now), what})
	}
	if w := f.planOut(stdout, stderr); w != nil {
		printDeletePlan(w, plan)
		fmt.Fprintln(w, what)
		if *f.dryRun {
			fmt.Fprintln(w, "dry run: nothing changed")
			return nil
		}
	}
	if err := confirm(stderr, *f.yes, fmt.Sprintf("Lift the delete fence of %s?", esc(plan.Email))); err != nil {
		return err
	}
	after, entry, err := server.CancelDelete(ctx, st, operator(), plan)
	printAudit(stderr, entry)
	if err != nil {
		return err
	}
	if *f.asJSON {
		return writeJSON(stdout, struct {
			Account deletePlanJSON `json:"account"`
			Audit   int64          `json:"audit_id"`
		}{deletePlanOf(after, now), entry.ID})
	}
	fmt.Fprintf(stdout, "lifted the delete fence of %s; it stays disabled. hop-server accounts enable %s undoes that.\n", esc(after.Email), after.AccountID)
	return nil
}
