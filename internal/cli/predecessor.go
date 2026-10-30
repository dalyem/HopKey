package cli

import (
	"context"
	"fmt"
	"slices"

	"github.com/dalyem/hopkey/internal/daemon"
	"github.com/dalyem/hopkey/internal/store"
)

// Getting a blocked device back in (A2b option E). When the server's
// operator blocks a device, or disables its account, the vault locks and
// stays locked. If the operator does not let the device in again, the
// owner signs out and signs in as a new device: hop auth logout, then hop
// auth login. The old identity is then retired by the logout, or, when the
// server would not take the retirement, left in the account until the new
// device revokes it. Queued changes on the old installation are lost, and
// nothing a copier took is taken back: a copied device key, the stored SSH
// keys and the passwords all need their own rotation. Nothing in this file
// changes the account by itself; it says what to run.

// daemonAdminLock asks the running daemon, without starting one, whether
// the server's operator is refusing this device: the lock the daemon
// holds in memory, which the store does not keep. It is nil when no
// daemon runs, or when the vault is not locked by a refusal. A logout
// asks before it stops the daemon, which forgets the refusal.
func daemonAdminLock(ctx context.Context, e *Env) *store.AdminRefusal {
	c, err := dialExisting(ctx, e)
	if err != nil || c == nil {
		return nil
	}
	defer c.Close()
	var st daemon.StatusResult
	if c.Call(ctx, daemon.OpStatus, nil, &st) != nil || st.Vault == nil || !st.Vault.Locked {
		return nil
	}
	return st.Vault.AdminLock
}

// adminLockWhy is the code a logout records for the lock: "" for none.
func adminLockWhy(a *store.AdminRefusal) string {
	if a == nil {
		return ""
	}
	return a.Code
}

// adminLockHelp is the way out of an operator's lock, for the lines
// under hop status's vault line: what to run, in order, and what it
// costs. The device ID is this device's own (the old identity once the
// new one is signed in).
func adminLockHelp(v *store.Info) []string {
	if v == nil || !v.Locked || v.Revoked || v.ServerReport != nil || v.AdminLock == nil {
		return nil
	}
	id := oneLine(v.DeviceID)
	if id == "" {
		id = "OLD-ID"
	}
	var out []string
	if v.AdminLock.Code == store.AdminAccountDisabled {
		out = append(out, "to leave this identity behind instead of waiting (the server refuses every sign-in while the account is disabled, so step 2 waits for the operator too):")
	} else {
		out = append(out, "to sign in again as a new device instead of waiting for the operator:")
	}
	out = append(out,
		"  1. hop auth logout --discard-pending   queued changes on this device are lost; the command lists how many before it asks.",
		"     If the server refuses to retire this device, it says so: then run hop auth logout --local-only --discard-pending",
		"  2. hop auth login                      needs the master password and the current Secret Key",
		"  3. if this device's files could have been copied while it was locked, from the new device:",
		fmt.Sprintf("       hop auth devices revoke %s   after a --local-only logout (this device is still in the account)", id),
		"       hop auth rotate                      after a logout the server accepted",
		"     and rotate the SSH keys and change the passwords stored in the vault; they stay as they were (hop key rotate)")
	return out
}

// printAdminLockHelp writes adminLockHelp under the vault line.
func printAdminLockHelp(e *Env, v *store.Info) {
	for _, l := range adminLockHelp(v) {
		e.printf("              %s\n", l)
	}
}

// pendingChangesText says how many changes a logout would discard.
func pendingChangesText(pc store.PendingChanges) string {
	s := fmt.Sprintf("%d queued change(s)", pc.Queued)
	if pc.Held > 0 {
		s += fmt.Sprintf(", %d of them held for your decision", pc.Held)
	}
	return s
}

// oldDeviceReport is one identity this machine had before it signed in
// again, as hop auth login --json reports it, and what to do about it.
type oldDeviceReport struct {
	DeviceID string `json:"device_id"`
	// Outcome is the old logout's: committed or departed (the device
	// left the account) or unknown (the server was not told).
	Outcome string `json:"outcome"`
	// Why is device_blocked or account_disabled when the operator had
	// the device locked out.
	Why string `json:"why,omitempty"`
	// StillInAccount is whether the old identity is still listed in the
	// account, as this device's verified log shows it.
	StillInAccount   bool   `json:"still_in_account"`
	DiscardedChanges int    `json:"discarded_changes,omitempty"`
	HeldChanges      int    `json:"held_changes,omitempty"`
	Command          string `json:"command,omitempty"`
}

// oldDevice is the report for one recorded identity, against the devices
// the verified log lists (active, when known). With no list, an identity
// whose logout did not tell the server is taken to be still in the
// account.
func oldDevice(p store.Predecessor, active []store.DeviceListing, known bool) oldDeviceReport {
	r := oldDeviceReport{DeviceID: p.DeviceID.String(), Outcome: p.Outcome, Why: p.Why, DiscardedChanges: p.Queued, HeldChanges: p.Held}
	r.StillInAccount = slices.ContainsFunc(active, func(d store.DeviceListing) bool { return d.ID == p.DeviceID })
	if !known {
		r.StillInAccount = p.Outcome == store.OutcomeUnknown
	}
	switch {
	case r.StillInAccount:
		r.Command = "hop auth devices revoke " + r.DeviceID
	case p.Why != "":
		// The identity is out of the account, however the logout ended
		// (a retirement the server committed but did not acknowledge
		// leaves an unknown outcome): the copy that the lock made
		// possible still warrants new keys.
		r.Command = "hop auth rotate"
	}
	return r
}

// oldDevices turns the predecessors recorded for accountID into reports.
// An entry for another account is left alone and not reported.
func oldDevices(entries []store.Predecessor, accountID string, active []store.DeviceListing, known bool) []oldDeviceReport {
	var out []oldDeviceReport
	for _, p := range entries {
		if p.AccountID.String() == accountID {
			out = append(out, oldDevice(p, active, known))
		}
	}
	return out
}

// printOldDevices tells the user, after a sign-in, what became of the
// identity this machine had before (Q15): it prints the exact command and
// runs nothing.
func printOldDevices(e *Env, rs []oldDeviceReport) {
	for _, r := range rs {
		id := oneLine(r.DeviceID)
		locked := "was logged out of"
		switch r.Why {
		case store.AdminDeviceBlocked:
			locked = "was blocked by the server's operator when you logged it out of"
		case store.AdminAccountDisabled:
			locked = "the operator's disabling of the account had locked when you logged it out of"
		}
		e.printf("\nBefore this sign-in, this machine was device %s, which %s the account.\n", id, locked)
		if r.DiscardedChanges > 0 {
			held := ""
			if r.HeldChanges > 0 {
				held = fmt.Sprintf(", %d of them held for your decision,", r.HeldChanges)
			}
			e.printf("The %d change(s) it had queued%s were discarded by that logout; make them again here if you still need them.\n", r.DiscardedChanges, held)
		}
		switch {
		case r.StillInAccount:
			e.printf("That logout did not tell the server (--local-only), so %s is still in the account. Nothing was changed for you.\n", id)
			e.printf("If its files could have been copied while it was locked, cut it off from this device:\n")
			e.printf("    %s\n", r.Command)
			e.printf("That replaces every key in the account and shows a new Emergency Kit. If you are sure nobody copied the files, you can leave it: a block can be lifted by the operator, a revocation can't.\n")
		default:
			if r.Outcome == store.OutcomeUnknown {
				e.printf("That logout did not tell the server, but %s is not in the account now", id)
				if r.Command == "" {
					e.printf(": nothing is left to cut off.\n")
				} else {
					e.printf(".\n")
				}
			} else {
				e.printf("That logout removed it from the account.\n")
			}
			if r.Command != "" {
				e.printf("If its files could have been copied while it was locked, replace every key in the account with:\n    %s\n", r.Command)
				e.printf("and keep only the devices you trust.\n")
			}
		}
		if r.Why != "" || r.StillInAccount {
			e.printf("The SSH keys and passwords stored in the vault are not changed by any of this. If the files may have been copied, rotate the SSH keys (hop key rotate) and change the passwords where they are used.\n")
		}
	}
}

// settleOldDevices is what a command does with the identities it has
// just reported: it forgets the ones that are not still in the account,
// and marks the others reported. active is the devices the verified log
// lists now, and ok whether it could be read; without it nothing is
// forgotten, only marked.
func settleOldDevices(dataDir string, entries []store.Predecessor, accountID string, active []store.DeviceListing, ok bool) error {
	for _, p := range entries {
		if p.AccountID.String() != accountID {
			continue
		}
		var err error
		if ok && !slices.ContainsFunc(active, func(d store.DeviceListing) bool { return d.ID == p.DeviceID }) {
			err = store.ForgetPredecessor(dataDir, p.DeviceID)
		} else {
			err = store.MarkPredecessorReported(dataDir, p.DeviceID)
		}
		if err != nil {
			return err
		}
	}
	return nil
}

// statusOldDevices is hop auth status's view of the identities this
// machine left behind. It shows the ones still listed in the account, and
// the ones that left it but whose advice (rotate) no command has shown
// yet: a sign-in that was cut short between installing the new identity
// and printing leaves them unreported. An identity with nothing more to
// say, or whose advice was shown before, is forgotten when the device
// list could be read. Nothing it returns is consumed here: the returned
// function marks the shown entries reported, and the caller runs it once
// they are printed.
func statusOldDevices(ctx context.Context, e *Env, c *daemon.Client, accountID string, unlocked bool) ([]oldDeviceReport, func()) {
	dataDir := e.storeConfig().DataDir
	entries, err := store.ReadPredecessors(dataDir)
	if err != nil || len(entries) == 0 {
		return nil, func() {}
	}
	var dl daemon.DevicesResult
	known := unlocked && c.Call(ctx, daemon.OpDevicesList, nil, &dl) == nil
	return reportOldDevices(dataDir, entries, accountID, dl.Devices, known)
}

// reportOldDevices is statusOldDevices over the entries and the device
// list it read.
func reportOldDevices(dataDir string, entries []store.Predecessor, accountID string, active []store.DeviceListing, known bool) ([]oldDeviceReport, func()) {
	var out []oldDeviceReport
	var shown []store.Predecessor
	for _, p := range entries {
		if p.AccountID.String() != accountID {
			continue
		}
		r := oldDevice(p, active, known)
		switch {
		case r.StillInAccount, r.Command != "" && !p.IsReported():
			out = append(out, r)
			shown = append(shown, p)
		case known:
			_ = store.ForgetPredecessor(dataDir, p.DeviceID)
		}
	}
	return out, func() {
		for _, p := range shown {
			_ = store.MarkPredecessorReported(dataDir, p.DeviceID)
		}
	}
}

// oldDeviceLines are hop auth status's lines about identities this
// machine left behind.
func oldDeviceLines(rs []oldDeviceReport) []string {
	var out []string
	for _, r := range rs {
		id := oneLine(r.DeviceID)
		if r.StillInAccount {
			out = append(out, fmt.Sprintf("old device:   %s, this machine's earlier identity, is still in the account (the logout did not tell the server); to cut it off: %s", id, r.Command))
			continue
		}
		out = append(out, fmt.Sprintf("old device:   %s, this machine's earlier identity, is out of the account, but it was locked out by the operator; if its files could have been copied, replace every key in the account: %s (shown once)", id, r.Command))
	}
	return out
}

// loginAdminHint is what hop auth login says when the machine is
// signed in and the operator is refusing it: the way out is a logout
// first.
func loginAdminHint(a *store.AdminRefusal) string {
	what := "blocked this device"
	if a.Code == store.AdminAccountDisabled {
		what = "disabled this account"
	}
	return fmt.Sprintf("this device is still signed in, and the server's operator %s. To sign in again as a new device: hop auth logout (--discard-pending drops queued changes; --local-only if the server won't retire this device), then hop auth login. "+
		"Or wait for the operator to let the device in", what)
}
