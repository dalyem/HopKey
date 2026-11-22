package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"time"

	"github.com/dalyem/hopkey/internal/model"
	"github.com/dalyem/hopkey/internal/server"
)

// The access controls: hop-server accounts disable and enable, devices
// block and unblock, and sessions revoke. Each shows the account as it
// stands and what will change, asks, and refuses with "changed" when the
// account moved in between. Their effects reach a running serve within
// about a minute: the admin process can't wake a long-poll, which notices
// at its next timeout.

// disabledText says whether an account is disabled, for people.
func disabledText(b *server.AdminBlock) string {
	if b == nil {
		return "enabled"
	}
	return "disabled since " + when(b.At) + reasonText(b.Reason)
}

func blockedText(b *server.AdminBlock) string {
	if b == nil {
		return ""
	}
	return "blocked since " + when(b.At) + reasonText(b.Reason)
}

func reasonText(r string) string {
	if r == "" {
		return ""
	}
	return fmt.Sprintf(" (reason: \"%s\")", esc(r))
}

type blockJSON struct {
	At     time.Time `json:"at"`
	Reason string    `json:"reason"`
}

func blockOf(b *server.AdminBlock) *blockJSON {
	if b == nil {
		return nil
	}
	return &blockJSON{At: b.At.UTC(), Reason: b.Reason}
}

type accessDeviceJSON struct {
	DeviceID model.ID   `json:"device_id"`
	Name     string     `json:"name"`
	Active   bool       `json:"active"`
	Blocked  *blockJSON `json:"blocked"`
	Sessions int        `json:"sessions"`
}

type accessJSON struct {
	AccountID   model.ID           `json:"account_id"`
	Email       string             `json:"email"`
	Disabled    *blockJSON         `json:"disabled"`
	Devices     []accessDeviceJSON `json:"devices"`
	Sessions    int                `json:"sessions"`
	LoginTokens int                `json:"login_tokens"`
}

func accessOf(p *server.AccessPlan) accessJSON {
	out := accessJSON{
		AccountID: p.AccountID, Email: p.Email, Disabled: blockOf(p.Disabled), Devices: []accessDeviceJSON{},
		Sessions: p.Sessions, LoginTokens: p.LoginTokens,
	}
	for _, d := range p.Devices {
		out.Devices = append(out.Devices, accessDeviceJSON{DeviceID: d.ID, Name: d.Name, Active: d.Active, Blocked: blockOf(d.Blocked), Sessions: d.Sessions})
	}
	return out
}

func printAccess(w io.Writer, p *server.AccessPlan) {
	fmt.Fprintf(w, "account %s (%s): %s\n", p.AccountID, esc(p.Email), disabledText(p.Disabled))
	for _, d := range p.Devices {
		name := esc(d.Name)
		if d.Name == "" {
			name = "(unknown)"
		}
		state := "active"
		if !d.Active {
			state = "departed"
		}
		if b := blockedText(d.Blocked); b != "" {
			state += ", " + b
		}
		fmt.Fprintf(w, "  device %s %s: %s, %s\n", d.ID, name, state, plural(d.Sessions, "live session", "live sessions"))
	}
}

// accessChange is the shape every access command shares: plan, show,
// confirm, change, report. what describes the change; done the result,
// the account as the change left it.
type accessChange struct {
	f      changeFlags
	plan   func(ctx context.Context, st *server.SQLite, op server.Operator) (*server.AccessPlan, error)
	what   func(p *server.AccessPlan) string // "would ..." lines, after the plan
	ask    func(p *server.AccessPlan) string
	change func(ctx context.Context, st *server.SQLite, op server.Operator, want *server.AccessPlan) (*server.AccessResult, *server.AuditEntry, error)
	done   func(w io.Writer, r *server.AccessResult)
}

func (a accessChange) run(stdout, stderr io.Writer) error {
	st, err := openStore(*a.f.data)
	if err != nil {
		return err
	}
	defer st.Close()
	ctx := context.Background()
	plan, err := a.plan(ctx, st, operator())
	if err != nil {
		return err
	}
	if *a.f.asJSON && *a.f.dryRun {
		return writeJSON(stdout, struct {
			DryRun  bool       `json:"dry_run"`
			Account accessJSON `json:"account"`
			Change  string     `json:"change"`
		}{true, accessOf(plan), a.what(plan)})
	}
	if w := a.f.planOut(stdout, stderr); w != nil {
		printAccess(w, plan)
		fmt.Fprintln(w, a.what(plan))
		if *a.f.dryRun {
			fmt.Fprintln(w, "dry run: nothing changed")
			return nil
		}
	}
	if err := confirm(stderr, *a.f.yes, a.ask(plan)); err != nil {
		return err
	}
	res, entry, err := a.change(ctx, st, operator(), plan)
	printAudit(stderr, entry)
	if err != nil {
		return err
	}
	if *a.f.asJSON {
		// account is the state after the change; the counts are what it
		// ended.
		return writeJSON(stdout, struct {
			Account          accessJSON `json:"account"`
			EndedSessions    int        `json:"ended_sessions"`
			EndedLoginTokens int        `json:"ended_login_tokens"`
			Audit            int64      `json:"audit_id"`
		}{accessOf(&res.AccessPlan), res.EndedSessions, res.EndedLoginTokens, entry.ID})
	}
	a.done(stdout, res)
	return nil
}

// reasonFlag reads --reason and sanitizes it as the server stores it.
func reasonFlag(fs *flag.FlagSet) func() (string, error) {
	r := fs.String("reason", "", fmt.Sprintf("a message for the account's devices, at most %d bytes; control characters are removed", server.MaxReasonBytes))
	return func() (string, error) { return server.SanitizeReason(*r) }
}

// --- accounts disable | enable ---

const disableHelp = "Its devices are refused sessions, logins and recovery: an online device with a current hop client " +
	"locks its vault and empties its agent within about a minute. Nothing is deleted, on the server or the devices. " +
	"A device that can't reach the server keeps working offline, within the account's max-offline policy. " +
	"hop-server accounts enable undoes it."

func accountsDisable(args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("accounts disable", flag.ContinueOnError)
	f := newChangeFlags(fs)
	reason := reasonFlag(fs)
	pos, err := parse(fs, args)
	if err != nil {
		return err
	}
	if len(pos) != 1 {
		return errors.New("usage: hop-server accounts disable ACCOUNT_ID|EMAIL [--reason TEXT] [--dry-run] [--yes] [--json] --data DIR")
	}
	r, err := reason()
	if err != nil {
		return err
	}
	who := pos[0]
	return accessChange{
		f: f,
		plan: func(ctx context.Context, st *server.SQLite, op server.Operator) (*server.AccessPlan, error) {
			return server.PlanDisable(ctx, st, who, op)
		},
		what: func(p *server.AccessPlan) string {
			s := fmt.Sprintf("would disable it%s, and end its %s and %s.", reasonText(r),
				plural(p.Sessions, "live session", "live sessions"), plural(p.LoginTokens, "login token", "login tokens"))
			if p.Disabled != nil {
				s = fmt.Sprintf("it is disabled already: would set its reason to \"%s\", and end its %s and %s.", esc(r),
					plural(p.Sessions, "live session", "live sessions"), plural(p.LoginTokens, "login token", "login tokens"))
			}
			return s + " " + disableHelp
		},
		ask: func(p *server.AccessPlan) string { return fmt.Sprintf("Disable %s?", esc(p.Email)) },
		change: func(ctx context.Context, st *server.SQLite, op server.Operator, want *server.AccessPlan) (*server.AccessResult, *server.AuditEntry, error) {
			return server.DisableAccount(ctx, st, op, who, r, want)
		},
		done: func(w io.Writer, r *server.AccessResult) {
			fmt.Fprintf(w, "disabled %s; ended %s and %s. hop-server accounts enable %s undoes it.\n",
				esc(r.Email), plural(r.EndedSessions, "session", "sessions"), plural(r.EndedLoginTokens, "login token", "login tokens"), r.AccountID)
		},
	}.run(stdout, stderr)
}

func accountsEnable(args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("accounts enable", flag.ContinueOnError)
	f := newChangeFlags(fs)
	pos, err := parse(fs, args)
	if err != nil {
		return err
	}
	if len(pos) != 1 {
		return errors.New("usage: hop-server accounts enable ACCOUNT_ID|EMAIL [--dry-run] [--yes] [--json] --data DIR")
	}
	who := pos[0]
	return accessChange{
		f: f,
		plan: func(ctx context.Context, st *server.SQLite, op server.Operator) (*server.AccessPlan, error) {
			return server.PlanEnable(ctx, st, who, op)
		},
		what: func(p *server.AccessPlan) string {
			return "would enable it: its devices get sessions again and unlock at their next retry; " +
				"a device whose key is sealed with a device passphrase needs hop unlock. Blocked devices stay blocked."
		},
		ask: func(p *server.AccessPlan) string { return fmt.Sprintf("Enable %s?", esc(p.Email)) },
		change: func(ctx context.Context, st *server.SQLite, op server.Operator, want *server.AccessPlan) (*server.AccessResult, *server.AuditEntry, error) {
			return server.EnableAccount(ctx, st, op, who, want)
		},
		done: func(w io.Writer, r *server.AccessResult) { fmt.Fprintf(w, "enabled %s\n", esc(r.Email)) },
	}.run(stdout, stderr)
}

// --- devices block | unblock ---

func devices(args []string, stdout, stderr io.Writer) error {
	if len(args) == 0 {
		return errors.New("usage: hop-server devices block|unblock")
	}
	switch args[0] {
	case "block":
		return devicesBlock(args[1:], stdout, stderr, true)
	case "unblock":
		return devicesBlock(args[1:], stdout, stderr, false)
	}
	return fmt.Errorf("unknown devices command %q", args[0])
}

const stolenHint = "A block is a reversible access control: it doesn't keep the password holder from signing in as a new device " +
	"(only accounts disable does). For a lost or stolen device, the owner runs hop auth devices revoke and hop key rotate --all."

func devicesBlock(args []string, stdout, stderr io.Writer, block bool) error {
	verb := map[bool]string{true: "block", false: "unblock"}[block]
	fs := flag.NewFlagSet("devices "+verb, flag.ContinueOnError)
	f := newChangeFlags(fs)
	all := fs.Bool("all", false, map[bool]string{true: "every active device of the account", false: "every blocked device of the account"}[block])
	reason := func() (string, error) { return "", nil }
	if block {
		reason = reasonFlag(fs)
	}
	pos, err := parse(fs, args)
	if err != nil {
		return err
	}
	usage := fmt.Errorf("usage: hop-server devices %s ACCOUNT_ID|EMAIL DEVICE_ID...|--all%s [--dry-run] [--yes] [--json] --data DIR",
		verb, map[bool]string{true: " [--reason TEXT]", false: ""}[block])
	if len(pos) < 1 || (*all && len(pos) != 1) || (!*all && len(pos) < 2) {
		return usage
	}
	r, err := reason()
	if err != nil {
		return err
	}
	who, sel := pos[0], server.DeviceSelection{IDs: pos[1:], All: *all}
	return accessChange{
		f: f,
		plan: func(ctx context.Context, st *server.SQLite, op server.Operator) (*server.AccessPlan, error) {
			if block {
				return server.PlanBlockDevices(ctx, st, who, sel, op)
			}
			return server.PlanUnblockDevices(ctx, st, who, sel, op)
		},
		what: func(p *server.AccessPlan) string {
			if !block {
				return fmt.Sprintf("would unblock %s: each gets sessions again and unlocks at its next retry.", plural(len(p.Devices), "device", "devices"))
			}
			return fmt.Sprintf("would block %s%s and end their %s: an online device with a current hop client locks its vault "+
				"and empties its agent within about a minute; the account's other devices keep working. Nothing is deleted. %s",
				plural(len(p.Devices), "device", "devices"), reasonText(r), plural(p.Sessions, "live session", "live sessions"), stolenHint)
		},
		ask: func(p *server.AccessPlan) string {
			return fmt.Sprintf("%s %s of %s?", map[bool]string{true: "Block", false: "Unblock"}[block],
				plural(len(p.Devices), "device", "devices"), esc(p.Email))
		},
		change: func(ctx context.Context, st *server.SQLite, op server.Operator, want *server.AccessPlan) (*server.AccessResult, *server.AuditEntry, error) {
			if block {
				return server.BlockDevices(ctx, st, op, who, sel, r, want)
			}
			return server.UnblockDevices(ctx, st, op, who, sel, want)
		},
		done: func(w io.Writer, r *server.AccessResult) {
			if block {
				fmt.Fprintf(w, "blocked %s; ended %s. %s\n", plural(len(r.Devices), "device", "devices"), plural(r.EndedSessions, "session", "sessions"), stolenHint)
				return
			}
			fmt.Fprintf(w, "unblocked %s\n", plural(len(r.Devices), "device", "devices"))
		},
	}.run(stdout, stderr)
}

// --- sessions revoke ---

func sessions(args []string, stdout, stderr io.Writer) error {
	if len(args) == 0 || args[0] != "revoke" {
		return errors.New("usage: hop-server sessions revoke")
	}
	fs := flag.NewFlagSet("sessions revoke", flag.ContinueOnError)
	f := newChangeFlags(fs)
	device := fs.String("device", "", "only this device's sessions (a device ID, or at least 8 of its hex digits)")
	pos, err := parse(fs, args[1:])
	if err != nil {
		return err
	}
	if len(pos) != 1 {
		return errors.New("usage: hop-server sessions revoke ACCOUNT_ID|EMAIL [--device DEVICE_ID] [--dry-run] [--yes] [--json] --data DIR")
	}
	who := pos[0]
	const signsNobodyOut = "This signs nobody out: each active device signs a new challenge and goes on. " +
		"It is for a session token that may have leaked; to stop devices, use hop-server accounts disable or devices block."
	return accessChange{
		f: f,
		plan: func(ctx context.Context, st *server.SQLite, op server.Operator) (*server.AccessPlan, error) {
			return server.PlanRevokeSessions(ctx, st, who, *device, op)
		},
		what: func(p *server.AccessPlan) string {
			if *device != "" {
				return fmt.Sprintf("would end the device's %s. %s", plural(p.Sessions, "live session", "live sessions"), signsNobodyOut)
			}
			return fmt.Sprintf("would end the account's %s and %s (a half-finished password login must start again). %s",
				plural(p.Sessions, "live session", "live sessions"), plural(p.LoginTokens, "login token", "login tokens"), signsNobodyOut)
		},
		ask: func(p *server.AccessPlan) string { return fmt.Sprintf("End these sessions of %s?", esc(p.Email)) },
		change: func(ctx context.Context, st *server.SQLite, op server.Operator, want *server.AccessPlan) (*server.AccessResult, *server.AuditEntry, error) {
			return server.RevokeSessions(ctx, st, op, who, *device, want)
		},
		done: func(w io.Writer, r *server.AccessResult) {
			fmt.Fprintf(w, "ended %s and %s\n", plural(r.EndedSessions, "session", "sessions"), plural(r.EndedLoginTokens, "login token", "login tokens"))
		},
	}.run(stdout, stderr)
}
