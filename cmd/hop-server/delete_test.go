package main

import (
	"bytes"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/dalyem/hopkey/internal/model"
)

// accounts delete: refused for an enabled account; --dry-run changes
// nothing; without a terminal it needs both --confirm EMAIL and --yes; on
// a terminal the email must be typed, then [y/N]; a wrong email, a "no"
// or a wrong --confirm changes nothing. The delete writes a 0600 backup,
// prints both audit lines, and leaves the other account alone.
func TestAccountsDelete(t *testing.T) {
	dir := t.TempDir()
	stubTerminal(t, "")
	acct, dev := signup(t, dir, "alice@example.com", hostileDevice)
	bob, _ := signup(t, dir, "bob@example.com", "laptop")
	refuse := func(want string, args ...string) {
		t.Helper()
		var prompt bytes.Buffer
		err := run(append([]string{"accounts", "delete"}, append(args, "--data", dir)...), io.Discard, &prompt)
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("accounts delete %v: %v, want %q (prompt %q)", args, err, want, prompt.String())
		}
	}

	refuse("not disabled", "alice@example.com", "--confirm", "alice@example.com", "--yes")
	mustRun(t, "accounts", "disable", "alice@example.com", "--yes", "--data", dir)
	before := dump(t, dir)

	out, _ := mustRun(t, "accounts", "delete", "alice@example.com", "--dry-run", "--data", dir)
	assertTerminalSafe(t, "delete --dry-run", out)
	for _, want := range []string{"account " + acct.String() + " (alice@example.com): disabled since", "1 device",
		"rows: account_admin 1, accounts 1, devices 1, log 1", "cannot be undone", "never used again",
		"The backup goes to " + filepath.Join(dir, "backups"), "every other one", "dry run: nothing changed"} {
		if !strings.Contains(out, want) {
			t.Errorf("delete --dry-run lacks %q:\n%s", want, out)
		}
	}
	out, _ = mustRun(t, "accounts", "delete", acct.String(), "--dry-run", "--json", "--no-backup", "--data", dir)
	var dry struct {
		DryRun  bool `json:"dry_run"`
		Account struct {
			AccountID model.ID       `json:"account_id"`
			Email     string         `json:"email"`
			Devices   []model.ID     `json:"devices"`
			Rows      map[string]int `json:"rows"`
			Deleting  *struct{}      `json:"deleting"`
		} `json:"account"`
		BackupDir *string `json:"backup_dir"`
	}
	if err := json.Unmarshal([]byte(out), &dry); err != nil || !dry.DryRun || dry.Account.AccountID != acct ||
		dry.Account.Email != "alice@example.com" || len(dry.Account.Devices) != 1 || dry.Account.Devices[0] != dev ||
		dry.Account.Rows["accounts"] != 1 || dry.Account.Deleting != nil || dry.BackupDir != nil {
		t.Errorf("delete --dry-run --json: %s, %v", out, err)
	}

	refuse("--confirm EMAIL", "alice@example.com", "--yes")
	refuse("--yes", "alice@example.com", "--confirm", "alice@example.com")
	refuse("not the account's email", "alice@example.com", "--confirm", "bob@example.com", "--yes")
	refuse("go separately", "alice@example.com", "--no-backup", "--backup-dir", t.TempDir())
	refuse("usage", "alice@example.com", "bob@example.com")
	refuse("--cancel takes no", "--cancel", "alice@example.com", "--confirm", "alice@example.com")
	refuse("disabled", "alice@example.com", "--confirm", "alice@example.com", "--yes", "--min-disabled", "1d")
	stubTerminal(t, "bob@example.com\ny\n")
	refuse("not the account's email", "alice@example.com")
	stubTerminal(t, "alice@example.com\nn\n")
	var prompt bytes.Buffer
	err := run([]string{"accounts", "delete", "alice@example.com", "--data", dir}, io.Discard, &prompt)
	if err == nil || !strings.Contains(err.Error(), "cancelled") || !strings.Contains(prompt.String(), "Type its email to confirm: ") ||
		!strings.Contains(prompt.String(), "Delete alice@example.com for good? [y/N]") {
		t.Errorf("answering no: %v, prompt %q", err, prompt.String())
	}
	if after := dump(t, dir); after != before {
		t.Errorf("a dry run or a refusal changed the database:\n%s\nthen\n%s", before, after)
	}

	// Typed on a terminal, the email is normalized as the server does.
	stubTerminal(t, " alice@EXAMPLE.com \ny\n")
	out, stderr := mustRun(t, "accounts", "delete", "alice@example.com", "--data", dir)
	assertTerminalSafe(t, "delete", out)
	if !strings.Contains(out, "deleted account "+acct.String()+" at head seq 0") || !strings.Contains(out, "keep their local copy") {
		t.Errorf("delete:\n%s", out)
	}
	if !strings.Contains(stderr, `"action":"accounts.delete.fence"`) || !strings.Contains(stderr, `"action":"accounts.delete"`) ||
		strings.Contains(stderr[strings.Index(stderr, `{"admin_audit"`):], "alice@example.com") {
		t.Errorf("delete audit lines:\n%s", stderr)
	}
	backups, err := filepath.Glob(filepath.Join(dir, "backups", "pre-delete-"+acct.String()+"-*.db"))
	if err != nil || len(backups) != 1 || !strings.Contains(out, backups[0]) {
		t.Fatalf("backups %v, %v:\n%s", backups, err, out)
	}
	if fi, err := os.Stat(backups[0]); err != nil || fi.Mode().Perm() != 0o600 {
		t.Errorf("backup mode %v, %v", fi.Mode(), err)
	}
	out, _ = mustRun(t, "accounts", "ls", "--data", dir)
	if strings.Contains(out, acct.String()) || !strings.Contains(out, bob.String()) {
		t.Errorf("accounts ls after the delete:\n%s", out)
	}
	out, _ = mustRun(t, "audit", "--account", acct.String(), "--data", dir)
	for _, action := range []string{"accounts.disable", "accounts.delete.fence", "accounts.delete "} {
		if !strings.Contains(out, action) {
			t.Errorf("audit lacks %s:\n%s", action, out)
		}
	}
	if err := run([]string{"accounts", "show", "alice@example.com", "--data", dir}, io.Discard, io.Discard); err == nil {
		t.Error("accounts show of a deleted account")
	}
}

// A delete whose backup fails leaves the account fenced: ls says
// deleting, show says how to go on, enable is refused. --cancel lifts
// the fence; then --json reports a delete's result, with --no-backup
// warning on stderr.
func TestAccountsDeleteFenceCancelAndJSON(t *testing.T) {
	dir := t.TempDir()
	stubTerminal(t, "")
	acct, _ := signup(t, dir, "bob@example.com", "laptop")
	mustRun(t, "accounts", "disable", "bob@example.com", "--yes", "--data", dir)
	notDir := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(notDir, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	var stderr bytes.Buffer
	err := run([]string{"accounts", "delete", "bob@example.com", "--confirm", "bob@example.com", "--yes", "--backup-dir", notDir, "--data", dir},
		io.Discard, &stderr)
	if err == nil || !strings.Contains(err.Error(), "backup failed") || !strings.Contains(err.Error(), "--cancel") {
		t.Errorf("a delete whose backup fails: %v", err)
	}
	if a := parseAuditLine(t, stderr.String()); a.Audit.Action != "accounts.delete" || a.Audit.Result != "backup_failed" {
		t.Errorf("failed delete audit line %+v", a)
	}
	out, _ := mustRun(t, "accounts", "ls", "--data", dir)
	if !strings.Contains(out, acct.String()) || !strings.Contains(out, "deleting") {
		t.Errorf("accounts ls of a fenced account:\n%s", out)
	}
	out, _ = mustRun(t, "accounts", "show", acct.String(), "--data", dir)
	if !strings.Contains(out, "in progress since") || !strings.Contains(out, "--cancel lifts it") {
		t.Errorf("accounts show of a fenced account:\n%s", out)
	}
	if err := run([]string{"accounts", "enable", acct.String(), "--yes", "--data", dir}, io.Discard, io.Discard); err == nil ||
		!strings.Contains(err.Error(), "delete --cancel") {
		t.Errorf("enable while fenced: %v", err)
	}

	out, _ = mustRun(t, "accounts", "delete", "--cancel", acct.String(), "--dry-run", "--data", dir)
	if !strings.Contains(out, "would lift the delete's fence") || !strings.Contains(out, "dry run: nothing changed") ||
		!strings.Contains(out, "(fence ") {
		t.Errorf("cancel --dry-run:\n%s", out)
	}
	out, errOut := mustRun(t, "accounts", "delete", "--cancel", "bob@example.com", "--yes", "--json", "--data", dir)
	var cancelled struct {
		Account struct {
			Deleting *struct{} `json:"deleting"`
			Disabled *struct{} `json:"disabled"`
		} `json:"account"`
		Audit int64 `json:"audit_id"`
	}
	if err := json.Unmarshal([]byte(out), &cancelled); err != nil || cancelled.Account.Deleting != nil || cancelled.Account.Disabled == nil ||
		cancelled.Audit == 0 || parseAuditLine(t, errOut).Audit.Action != "accounts.delete.cancel" {
		t.Errorf("cancel --json: %s, %v", out, err)
	}
	if err := run([]string{"accounts", "delete", "--cancel", acct.String(), "--yes", "--data", dir}, io.Discard, io.Discard); err == nil ||
		!strings.Contains(err.Error(), "no delete") {
		t.Errorf("a second cancel: %v", err)
	}

	out, errOut = mustRun(t, "accounts", "delete", acct.String(), "--confirm", "bob@example.com", "--yes", "--json", "--no-backup", "--data", dir)
	var res struct {
		Deleted struct {
			AccountID model.ID       `json:"account_id"`
			FenceID   model.ID       `json:"fence_id"`
			Devices   []model.ID     `json:"devices"`
			Rows      map[string]int `json:"rows"`
		} `json:"deleted"`
		Exists *bool   `json:"exists"`
		Backup *string `json:"backup"`
		Audit  []int64 `json:"audit_ids"`
	}
	if err := json.Unmarshal([]byte(out), &res); err != nil || res.Deleted.AccountID != acct || res.Deleted.FenceID.IsZero() || len(res.Deleted.Devices) != 1 ||
		res.Deleted.Rows["accounts"] != 1 || res.Exists == nil || *res.Exists || res.Backup != nil || len(res.Audit) != 2 {
		t.Errorf("delete --json: %s, %v", out, err)
	}
	if !strings.Contains(errOut, "--no-backup") {
		t.Errorf("no warning for --no-backup: %q", errOut)
	}
}
