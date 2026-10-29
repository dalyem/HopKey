package main

import (
	"bytes"
	"encoding/json"
	"io"
	"strings"
	"testing"
	"time"
)

// accounts disable and enable, devices block and unblock, sessions
// revoke: --dry-run changes nothing, no terminal refuses without --yes, a
// "no" cancels, and each change prints its audit line and stores the
// operator's reason sanitized.
func TestAccessCommands(t *testing.T) {
	dir := t.TempDir()
	stubTerminal(t, "")
	acct, dev := signup(t, dir, "alice@example.com", hostileDevice)

	before := dump(t, dir)
	out, _ := mustRun(t, "accounts", "disable", "alice@example.com", "--reason", "overdue", "--dry-run", "--data", dir)
	if !strings.Contains(out, "would disable it (reason: \"overdue\")") || !strings.Contains(out, "dry run: nothing changed") ||
		!strings.Contains(out, "enabled") {
		t.Errorf("disable --dry-run:\n%s", out)
	}
	out, _ = mustRun(t, "accounts", "disable", "alice@example.com", "--dry-run", "--json", "--data", dir)
	var dry struct {
		DryRun  bool `json:"dry_run"`
		Account struct {
			Disabled *json.RawMessage `json:"disabled"`
		} `json:"account"`
	}
	if err := json.Unmarshal([]byte(out), &dry); err != nil || !dry.DryRun || dry.Account.Disabled != nil {
		t.Errorf("disable --dry-run --json: %s, %v", out, err)
	}
	err := run([]string{"accounts", "disable", "alice@example.com", "--data", dir}, io.Discard, io.Discard)
	if err == nil || !strings.Contains(err.Error(), "--yes") {
		t.Errorf("disable without a terminal or --yes: %v", err)
	}
	stubTerminal(t, "n\n")
	var prompt bytes.Buffer
	err = run([]string{"accounts", "disable", "alice@example.com", "--data", dir}, io.Discard, &prompt)
	if err == nil || !strings.Contains(err.Error(), "cancelled") || !strings.Contains(prompt.String(), "Disable alice@example.com? [y/N]") {
		t.Errorf("answering no: %v, prompt %q", err, prompt.String())
	}
	err = run([]string{"accounts", "disable", "alice@example.com", "--reason", strings.Repeat("x", 201), "--yes", "--data", dir}, io.Discard, io.Discard)
	if err == nil || !strings.Contains(err.Error(), "at most 200") {
		t.Errorf("a reason too long: %v", err)
	}
	if after := dump(t, dir); after != before {
		t.Errorf("a dry run, a refusal or a no changed the database:\n%s\nthen\n%s", before, after)
	}

	stubTerminal(t, "y\n")
	out, stderr := mustRun(t, "accounts", "disable", "alice@example.com", "--reason", "over\x1b[2Jdue \u202e!", "--data", dir)
	if !strings.Contains(out, "disabled alice@example.com") {
		t.Errorf("disable:\n%s", out)
	}
	a := parseAuditLine(t, stderr)
	if a.Audit.Action != "accounts.disable" || a.Audit.AccountID == nil || *a.Audit.AccountID != acct ||
		!strings.Contains(string(a.Audit.Params), `"reason":"over[2Jdue !"`) {
		t.Errorf("disable audit line %+v %s", a, a.Audit.Params)
	}
	out, _ = mustRun(t, "accounts", "ls", "--disabled", "--data", dir)
	if !strings.Contains(out, acct.String()) || !strings.Contains(out, "disabled") {
		t.Errorf("accounts ls --disabled:\n%s", out)
	}
	out, _ = mustRun(t, "accounts", "show", acct.String(), "--data", dir)
	assertTerminalSafe(t, "accounts show", out)
	if !strings.Contains(out, `access        disabled since`) || !strings.Contains(out, `(reason: "over[2Jdue !")`) {
		t.Errorf("accounts show of a disabled account:\n%s", out)
	}

	stubTerminal(t, "")
	// --json reports the account as the change left it, and what it ended.
	out, _ = mustRun(t, "accounts", "disable", acct.String(), "--reason", "still overdue", "--yes", "--json", "--data", dir)
	var dis accessResultJSON
	if err := json.Unmarshal([]byte(out), &dis); err != nil || dis.Audit == 0 || dis.Account.Disabled == nil ||
		dis.Account.Disabled.Reason != "still overdue" || dis.Account.Disabled.At.IsZero() ||
		dis.EndedSessions == nil || dis.EndedLoginTokens == nil || dis.Account.Sessions != 0 || dis.Account.LoginTokens != 0 {
		t.Errorf("disable --json: %s, %v", out, err)
	}
	out, stderr = mustRun(t, "accounts", "enable", acct.String(), "--yes", "--json", "--data", dir)
	var res accessResultJSON
	if err := json.Unmarshal([]byte(out), &res); err != nil || res.Audit == 0 || res.Account.Disabled != nil ||
		res.EndedSessions == nil || *res.EndedSessions != 0 || res.EndedLoginTokens == nil || *res.EndedLoginTokens != 0 {
		t.Errorf("enable --json: %s, %v", out, err)
	}
	if parseAuditLine(t, stderr).Audit.Action != "accounts.enable" {
		t.Errorf("enable audit line %q", stderr)
	}
	out, _ = mustRun(t, "accounts", "ls", "--disabled", "--data", dir)
	if strings.TrimSpace(out) != "no disabled accounts" {
		t.Errorf("accounts ls --disabled after enable: %q", out)
	}
	if err := run([]string{"accounts", "enable", acct.String(), "--yes", "--data", dir}, io.Discard, io.Discard); err == nil ||
		!strings.Contains(err.Error(), "not disabled") {
		t.Errorf("enabling an enabled account: %v", err)
	}

	// devices block by a prefix, with the hint for a stolen device; the
	// device's name is escaped.
	out, stderr = mustRun(t, "devices", "block", "alice@example.com", dev.String()[:10], "--reason", "lost", "--yes", "--data", dir)
	assertTerminalSafe(t, "devices block", out)
	if !strings.Contains(out, esc(hostileDevice)) || !strings.Contains(out, "blocked 1 device") || !strings.Contains(out, "hop key rotate --all") {
		t.Errorf("devices block:\n%s", out)
	}
	if parseAuditLine(t, stderr).Audit.Action != "devices.block" {
		t.Errorf("block audit line %q", stderr)
	}
	out, _ = mustRun(t, "accounts", "show", acct.String(), "--data", dir)
	if !strings.Contains(out, dev.String()+"  active, blocked") {
		t.Errorf("accounts show of a blocked device:\n%s", out)
	}
	for _, args := range [][]string{
		{"devices", "block", "alice@example.com", "--yes", "--data", dir},
		{"devices", "block", "alice@example.com", dev.String(), "--all", "--yes", "--data", dir},
		{"devices", "unblock", "alice@example.com", "--reason", "x", "--all", "--yes", "--data", dir},
	} {
		if err := run(args, io.Discard, io.Discard); err == nil {
			t.Errorf("%v: no error", args)
		}
	}
	out, _ = mustRun(t, "devices", "unblock", "alice@example.com", "--all", "--yes", "--json", "--data", dir)
	var unb accessResultJSON
	if err := json.Unmarshal([]byte(out), &unb); err != nil || len(unb.Account.Devices) != 1 ||
		unb.Account.Devices[0].DeviceID != dev.String() || unb.Account.Devices[0].Blocked != nil {
		t.Errorf("devices unblock --json: %s, %v", out, err)
	}
	out, _ = mustRun(t, "devices", "block", "alice@example.com", dev.String(), "--reason", "again", "--yes", "--json", "--data", dir)
	var blk accessResultJSON
	if err := json.Unmarshal([]byte(out), &blk); err != nil || len(blk.Account.Devices) != 1 || blk.Account.Devices[0].Blocked == nil ||
		blk.Account.Devices[0].Blocked.Reason != "again" || blk.Account.Devices[0].Sessions != 0 || blk.EndedSessions == nil {
		t.Errorf("devices block --json: %s, %v", out, err)
	}
	mustRun(t, "devices", "unblock", "alice@example.com", "--all", "--yes", "--data", dir)

	out, stderr = mustRun(t, "sessions", "revoke", "alice@example.com", "--yes", "--data", dir)
	if !strings.Contains(out, "ended 0 sessions and 0 login tokens") || parseAuditLine(t, stderr).Audit.Action != "sessions.revoke" {
		t.Errorf("sessions revoke: %q %q", out, stderr)
	}
	out, _ = mustRun(t, "sessions", "revoke", "alice@example.com", "--device", dev.String(), "--dry-run", "--data", dir)
	if !strings.Contains(out, "signs nobody out") {
		t.Errorf("sessions revoke --dry-run:\n%s", out)
	}

	out, _ = mustRun(t, "audit", "--account", acct.String(), "--data", dir)
	for _, action := range []string{"accounts.disable", "accounts.enable", "devices.block", "devices.unblock", "sessions.revoke"} {
		if !strings.Contains(out, action) {
			t.Errorf("audit lacks %s:\n%s", action, out)
		}
	}
	assertTerminalSafe(t, "audit", out)
}

// accessResultJSON is what an access command prints under --json.
type accessResultJSON struct {
	Account struct {
		Disabled *struct {
			At     time.Time `json:"at"`
			Reason string    `json:"reason"`
		} `json:"disabled"`
		Devices []struct {
			DeviceID string `json:"device_id"`
			Blocked  *struct {
				Reason string `json:"reason"`
			} `json:"blocked"`
			Sessions int `json:"sessions"`
		} `json:"devices"`
		Sessions    int `json:"sessions"`
		LoginTokens int `json:"login_tokens"`
	} `json:"account"`
	EndedSessions    *int  `json:"ended_sessions"`
	EndedLoginTokens *int  `json:"ended_login_tokens"`
	Audit            int64 `json:"audit_id"`
}
