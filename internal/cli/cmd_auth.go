package cli

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/dalyem/hopkey/internal/authflow"
	"github.com/dalyem/hopkey/internal/crypto"
	"github.com/dalyem/hopkey/internal/daemon"
	"github.com/dalyem/hopkey/internal/sshconfig"
	"github.com/dalyem/hopkey/internal/store"
	"github.com/dalyem/hopkey/internal/syncclient"
)

// hop auth is everything about accounts, devices and access (design:
// "Signing in: hop auth"). hop login and hop logout are aliases. The flows
// are internal/authflow's; this file gives them flags and output, and
// authui.go is their terminal UI. A flow needs the vault, which the daemon
// owns while it runs, so each one stops the daemon and starts it again
// afterwards (authvault.go). To add a subcommand, give authCommands an
// entry: run gets the arguments after the subcommand.

type authCommand struct {
	run   func(ctx context.Context, e *Env, args []string) error
	usage string
}

var authCommands map[string]authCommand

func init() {
	authCommands = map[string]authCommand{
		"devices": {runAuthDevices, "hop auth devices [--json] | hop auth devices revoke <name|id>... [--keep D]... [--yes] [--kit-file PATH] [--password-stdin] [--json]"},
		"login":   {runAuthLogin, "hop auth login [--server URL] [--email E] [--method approve|password|recovery] [--name DEVICE] [--merge] [--device-key-store keychain|file] [--keep D]... [--yes] [--kit-file PATH] [--password-stdin] [--json] | hop auth login --discard [--yes] [--json]"},
		"signup":  {runAuthSignup, "hop auth signup [--server URL] [--email E] [--code CODE] [--device-key-store keychain|file] [--kit-file PATH] [--json]"},
		"approve": {runAuthApprove, "hop auth approve [CODE] [--sas DIGITS] | hop auth approve --abort [--json]"},
		"logout":  {runAuthLogout, "hop auth logout [--discard-pending] [--local-only] [--yes] [--json]"},
		"rotate":  {runAuthRotate, "hop auth rotate [--keep D]... [--yes] [--kit-file PATH] [--password-stdin] [--json]"},
		"passwd":  {runAuthPasswd, "hop auth passwd [--keep D]... [--exclude D]... [--kit-file PATH] [--password-stdin] [--json]"},
		"merge":   {runAuthMerge, "hop auth merge [--pause | --resume | --discard [--confirm TOKEN]] [--json]"},
		"status":  {runAuthStatus, "hop auth status [--json]"},
		"policy":  {runAuthPolicy, "hop auth policy [--max-offline DURATION|off] [--json]"},
		"resume":  {runAuthResume, "hop auth resume [--keep D]... [--yes] [--kit-file PATH] [--password-stdin] [--json]"},
	}
}

const authHelp = `On a terminal, hop auth asks for what it needs. With --json, or when stdin
or stdout is not a terminal, it never asks: each answer comes from a flag or
an environment variable, or the command fails and names it. Secrets are
never flags:
  HOP_PASSWORD        the current master password (or --password-stdin)
  HOP_NEW_PASSWORD    a new master password
  HOP_SECRET_KEY      the Secret Key from your Emergency Kit
  HOP_RECOVERY_KEY    the Recovery Key from your Emergency Kit
  HOP_KIT_CONFIRM     the last group of a new kit's Secret Key and of its
                      Recovery Key, for hop auth resume
--keep and --exclude choose devices, --yes confirms what deletes or revokes,
--code gives the registration code, and hop auth approve --sas gives the
check code the new device shows.
Two things need a person at a terminal, by design:
  hop auth login by approval, on the new device, which compares the check
                      code (without one: --method password or recovery)
  hop auth signup with no vault here, which creates an account whose new
                      Emergency Kit you must see and type back (publishing
                      a vault this device has works without one)
`

func authUsage() string {
	names := make([]string, 0, len(authCommands))
	for n := range authCommands {
		names = append(names, n)
	}
	slices.Sort(names)
	var sb strings.Builder
	sb.WriteString("usage:\n")
	for _, n := range names {
		fmt.Fprintf(&sb, "  %s\n", authCommands[n].usage)
	}
	return sb.String()
}

func runAuth(ctx context.Context, e *Env, args []string) error {
	if len(args) == 0 {
		fmt.Fprint(e.Stderr, authUsage())
		return failf("auth needs a subcommand")
	}
	switch args[0] {
	case "-h", "--help", "help":
		fmt.Fprint(e.Stdout, authUsage()+"\n"+authHelp)
		return nil
	}
	sub, ok := authCommands[args[0]]
	if !ok {
		fmt.Fprint(e.Stderr, authUsage())
		return failf("unknown auth subcommand %q", args[0])
	}
	return sub.run(ctx, e, args[1:])
}

// runLogin is hop login, the alias of hop auth login.
func runLogin(ctx context.Context, e *Env, args []string) error {
	return runAuth(ctx, e, append([]string{"login"}, args...))
}

// runLogout is hop logout, the alias of hop auth logout.
func runLogout(ctx context.Context, e *Env, args []string) error {
	return runAuth(ctx, e, append([]string{"logout"}, args...))
}

// authOpts are the flags that answer prompts, shared by the subcommands
// that take them.
type authOpts struct {
	asJSON        bool
	yes           bool
	passwordStdin bool
	kitFile       string
	keep, exclude stringList
}

func (o *authOpts) jsonFlag(fs *flag.FlagSet) {
	fs.BoolVar(&o.asJSON, "json", false, "print the result as JSON (prompts are never asked)")
}

// checkpointFlags are the flags of a command that may commit a checkpoint
// and show its new kit.
func (o *authOpts) checkpointFlags(fs *flag.FlagSet) {
	fs.Var(&o.keep, "keep", "a device to keep besides this one, by ID or unique name (repeatable, or comma-separated)")
	fs.BoolVar(&o.yes, "yes", false, "confirm revoking every device not kept, without a terminal")
	fs.StringVar(&o.kitFile, "kit-file", "", "also write the new Emergency Kit to this new file (mode 0600)")
	fs.BoolVar(&o.passwordStdin, "password-stdin", false, "read the current master password from the first line of stdin")
}

func (o *authOpts) ui(e *Env) *termUI {
	u := newTermUI(e, o.asJSON)
	u.yes, u.passwordStdin, u.kitFile = o.yes, o.passwordStdin, o.kitFile
	u.keep, u.keepSet, u.exclude = o.keep.vals, o.keep.set, o.exclude.vals
	if o.passwordStdin {
		// stdin holds the password, not answers.
		u.interactive = false
	}
	return u
}

// checkKitFile refuses a --kit-file that exists, before anything changes;
// writeKitFile is what guarantees nothing is replaced.
func (o *authOpts) checkKitFile() error {
	if o.kitFile == "" {
		return nil
	}
	if _, err := os.Lstat(o.kitFile); err == nil {
		return failf("%s already exists; give --kit-file a new file", o.kitFile)
	}
	return nil
}

// need returns a flag's value or, on a terminal, asks for it; without
// one it fails naming the flag.
func (u *termUI) need(val, flagName, prompt string) (string, error) {
	if val != "" {
		return val, nil
	}
	if !u.interactive {
		return "", failf("--%s is needed (there is no terminal to ask on)", flagName)
	}
	a, err := u.readAnswer(prompt)
	if err != nil {
		return "", failf("%v", err)
	}
	if a == "" {
		return "", failf("no %s given", strings.TrimSuffix(strings.TrimSpace(prompt), ":"))
	}
	return a, nil
}

func noArgs(fs *flag.FlagSet, pos []string) error {
	if len(pos) != 0 {
		fs.Usage()
		return failf("unexpected argument %q", pos[0])
	}
	return nil
}

// ---- signup ----

// signupReport is the --json shape of hop auth signup.
type signupReport struct {
	Server    string `json:"server"`
	Email     string `json:"email"`
	AccountID string `json:"account_id"`
	VaultID   string `json:"vault_id"`
	DeviceID  string `json:"device_id"`
	// Created means signup created the vault; otherwise it published the
	// one this device had, whose Emergency Kit stays valid.
	Created bool `json:"created"`
}

// errSignupNeedsTerminal is the one hop auth flow that has no answer
// without a terminal, by design: a new account's Emergency Kit must be
// shown to a person and typed back by them.
const errSignupNeedsTerminal = "creating a new account needs a person at a terminal: its new Emergency Kit must be shown to you and typed back by you, " +
	"which no flag or environment variable can do (this run has no terminal: --json, or stdin or stdout is not a terminal). " +
	"Run hop auth signup in a terminal (an SSH session has one). " +
	"Publishing a vault this device already has works without a terminal: hop init on a terminal once, then hop auth signup --server URL --email E --code CODE from anywhere"

func runAuthSignup(ctx context.Context, e *Env, args []string) error {
	fs := newFlags(e, "auth signup", authCommands["signup"].usage)
	helpNote(e, fs, "\nWith no vault on this device, signup creates a new account, and that needs a person at a terminal:\n"+
		"its Emergency Kit is shown to you and typed back by you. Publishing a vault this device already has\n"+
		"(made with hop init) works without a terminal.\n")
	var o authOpts
	o.jsonFlag(fs)
	server := fs.String("server", "", "the hop-server URL (https://...)")
	email := fs.String("email", "", "the account's sign-in email")
	code := fs.String("code", "", "the registration code from hop-server invite")
	devStore := fs.String("device-key-store", "", "for a new vault: where the device key lives, keychain (the default) or file")
	fs.StringVar(&o.kitFile, "kit-file", "", "for a new vault: also write its Emergency Kit to this new file (mode 0600)")
	pos, _, err := parseFlags(fs, args)
	if err != nil {
		return err
	}
	if err := noArgs(fs, pos); err != nil {
		return err
	}
	if err := o.checkKitFile(); err != nil {
		return err
	}
	u := o.ui(e)
	if !u.interactive {
		// Before the daemon stops: a new account can't be made here.
		if ok, err := store.Exists(e.storeConfig().DataDir); err == nil && !ok {
			return failf("%s", errSignupNeedsTerminal)
		}
	}
	h, err := holdVault(ctx, e, o.asJSON)
	if err != nil {
		return err
	}
	defer h.release(ctx)
	s, err := h.open(ctx)
	if err != nil {
		return err
	}
	var pending *store.Publication
	if s != nil {
		if pending, err = s.Publication(); err != nil {
			s.Close()
			return failf("%v", err)
		}
		if pending == nil && s.ServerBacked() {
			s.Close()
			return authFailure(authflow.ErrSignedIn)
		}
	} else if !u.interactive {
		return failf("%s", errSignupNeedsTerminal)
	}
	srv, addr, regCode := *server, *email, *code
	if pending != nil {
		// The pending publication says where and as whom; a code is
		// asked for only if the server refuses the journaled one.
		if srv == "" {
			srv = pending.Server
		}
		u.code = regCode
		if !o.asJSON {
			fmt.Fprintf(e.Stderr, "Finishing the publication to %s that was started earlier.\n", oneLine(pending.Server))
		}
	} else {
		if srv, err = u.need(srv, "server", "Server URL (https://...): "); err != nil {
			closeStores(s)
			return err
		}
		if addr, err = u.need(addr, "email", "Email: "); err != nil {
			closeStores(s)
			return err
		}
		if regCode, err = u.need(regCode, "code", "Registration code (from hop-server invite): "); err != nil {
			closeStores(s)
			return err
		}
	}
	c, err := e.serverClient(srv)
	if err != nil {
		closeStores(s)
		return err
	}
	defer c.CloseIdleConnections()
	res, err := authflow.Signup(ctx, h.flowEnv(c, u), authflow.SignupOptions{
		Email: addr, RegistrationCode: regCode, DeviceStore: *devStore, Local: s,
	})
	var rs *store.Store
	if res != nil {
		rs = res.Vault.Store
	}
	defer closeStores(s, rs)
	if err != nil {
		if s == nil && u.wroteKit != "" {
			if ok, xerr := store.Exists(h.cfg.DataDir); xerr == nil && !ok {
				os.Remove(u.wroteKit) // the kit of a vault that does not exist
			}
		}
		return authFailure(err)
	}
	return printSignup(e, o.asJSON, res)
}

func printSignup(e *Env, asJSON bool, res *authflow.SignupResult) error {
	p := res.Publication
	r := signupReport{
		Server: p.Server, Email: p.Email, AccountID: p.AccountID.String(), VaultID: p.VaultID.String(),
		DeviceID: res.Vault.Store.Info().DeviceID, Created: res.Created,
	}
	if asJSON {
		return printJSON(e, r)
	}
	e.printf("Signed up: this vault now syncs with %s as %s.\n", oneLine(r.Server), oneLine(r.Email))
	e.printf("Account ID: %s\n", oneLine(r.AccountID))
	if !r.Created {
		e.printf("Your Emergency Kit stays valid. Write the server URL and the email on it.\n")
	}
	e.printf("The hop daemon keeps it in sync from now on.\n")
	return nil
}

// ---- login ----

// loginReport is the --json shape of hop auth login.
type loginReport struct {
	Server     string             `json:"server"`
	Email      string             `json:"email,omitempty"`
	AccountID  string             `json:"account_id"`
	VaultID    string             `json:"vault_id"`
	DeviceID   string             `json:"device_id"`
	DeviceName string             `json:"device_name"`
	Method     string             `json:"method"`
	Merge      *store.MergeStatus `json:"merge,omitempty"`
	Recovery   *checkpointReport  `json:"recovery,omitempty"`
	// OldDevices are the identities this machine had before a logout that
	// left something to do about them (hop auth logout on a device the
	// operator locked out, or --local-only). Nothing has been run for them.
	OldDevices []oldDeviceReport `json:"old_devices,omitempty"`
}

// discardReport is the --json shape of hop auth login --discard.
type discardReport struct {
	Discarded bool `json:"discarded"`
}

const (
	methodApprove  = "approve"
	methodPassword = "password"
	methodRecovery = "recovery"
)

func runAuthLogin(ctx context.Context, e *Env, args []string) error {
	fs := newFlags(e, "auth login", authCommands["login"].usage)
	var o authOpts
	o.jsonFlag(fs)
	o.checkpointFlags(fs)
	server := fs.String("server", "", "the hop-server URL (https://...)")
	email := fs.String("email", "", "the account's sign-in email (needed for password and recovery)")
	method := fs.String("method", methodApprove, "approve (by another device), password (master password and Secret Key) or recovery (Recovery Key)")
	name := fs.String("name", "", "this device's name in the account (default: the host name)")
	mergeLocal := fs.Bool("merge", false, "merge this device's local-only vault into the account")
	devStore := fs.String("device-key-store", "", "where the device key lives: keychain (the default) or file")
	withToken := fs.Bool("with-token", false, "store a hop1_ token read from stdin (not available yet)")
	discard := fs.Bool("discard", false, "discard an enrollment by approval that is in progress on this device (--yes skips the question)")
	pos, _, err := parseFlags(fs, args)
	if err != nil {
		return err
	}
	if err := noArgs(fs, pos); err != nil {
		return err
	}
	if *discard {
		return runLoginDiscard(ctx, e, &o)
	}
	if *withToken {
		return failf("hop auth login --with-token is not available yet in this version of hop (tokens for cloud agents come in a later version)")
	}
	switch *method {
	case methodApprove:
		if *mergeLocal {
			return failf("--merge needs --method password or recovery: a device approved by another one can't merge a local vault")
		}
	case methodPassword, methodRecovery:
	default:
		return failf("--method is approve, password or recovery, not %q", *method)
	}
	if err := o.checkKitFile(); err != nil {
		return err
	}
	ctx, stopWatch := hangupContext(ctx, e)
	defer stopWatch()
	u := o.ui(e)
	u.role = roleLogin
	defer u.stopWaitHint()
	srv, err := u.need(*server, "server", "Server URL (https://...): ")
	if err != nil {
		return err
	}
	if *method == methodApprove && !u.interactive {
		// Before the daemon stops or the server hears of it.
		return failf("%s", errApproveNeedsTerminal)
	}
	addr := *email
	if *method != methodApprove {
		if addr, err = u.need(addr, "email", "Email: "); err != nil {
			return err
		}
	}
	c, err := e.serverClient(srv)
	if err != nil {
		return err
	}
	defer c.CloseIdleConnections()
	// Asked before the daemon stops: the operator's refusal lives in its
	// memory only.
	lock := daemonAdminLock(ctx, e)
	h, err := holdVault(ctx, e, o.asJSON)
	if err != nil {
		return err
	}
	defer h.release(ctx)
	env := h.flowEnv(c, u)

	var res *authflow.LoginResult
	var local *store.Store
	if *method == methodApprove {
		res, err = loginApprove(ctx, env, u, authflow.EnrollOptions{Email: addr, DeviceName: *name, DeviceStore: *devStore})
	} else {
		if local, err = h.open(ctx); err != nil {
			return err
		}
		opts := authflow.LoginOptions{Email: addr, DeviceName: *name, DeviceStore: *devStore, Merge: *mergeLocal, Local: local}
		if *method == methodPassword {
			res, err = authflow.LoginPassword(ctx, env, opts)
		} else {
			res, err = authflow.LoginRecovery(ctx, env, opts)
		}
	}
	var rs *store.Store
	if res != nil && res.Vault != nil {
		rs = res.Vault.Store
	}
	defer closeStores(local, rs)
	if errors.Is(err, authflow.ErrRecoveryIncomplete) && rs != nil {
		return failf("signed in with the Recovery Key, but the recovery is not finished (%v); run hop auth resume to finish it", err)
	}
	if err != nil {
		if errors.Is(context.Cause(ctx), errStdinClosed) {
			return failf("stdin closed, so the login was cancelled")
		}
		if lock != nil && errors.Is(err, authflow.ErrSignedIn) {
			return failf("%s", loginAdminHint(lock))
		}
		return authFailure(err)
	}
	return printLogin(e, o.asJSON, *method, res)
}

// runLoginDiscard is hop auth login --discard: it deletes the enrollment by
// approval in progress on this device, the one that otherwise makes every
// other login fail, and its keys.
func runLoginDiscard(ctx context.Context, e *Env, o *authOpts) error {
	if !o.yes {
		if !e.StdinTTY || o.asJSON {
			return failf("hop auth login --discard deletes this device's unfinished enrollment and its keys, and there is no terminal to confirm on: pass --yes")
		}
		ok, err := confirm(e, false, "Discard the enrollment in progress on this device? Its keys are deleted; a device the approver already added stays in the account until it is revoked.")
		if err != nil {
			return err
		}
		if !ok {
			return failf("not discarded")
		}
	}
	h, err := holdVault(ctx, e, o.asJSON)
	if err != nil {
		return err
	}
	defer h.release(ctx)
	switch err := store.DiscardEnrollment(h.cfg); {
	case errors.Is(err, store.ErrNoEnrollment):
		return failf("no enrollment is in progress on this device, so there is nothing to discard")
	case errors.Is(err, store.ErrEnrollmentInstalling):
		return failf("this device's enrollment was approved and is being installed, so it cannot be discarded: run hop auth login to finish it")
	case err != nil:
		return failf("%v", err)
	}
	if o.asJSON {
		return printJSON(e, discardReport{Discarded: true})
	}
	e.printf("The enrollment was discarded. hop auth login can start again.\n")
	return nil
}

// maxEnrollResumes bounds how often one hop auth login resumes an
// enrollment the network interrupted; the enrollment's own deadline
// bounds it too.
const maxEnrollResumes = 30

// loginApprove is the approve method: the enrollment, resumed in this
// process with its mailbox when the network interrupts it (the mailbox's
// token lives only in memory, so another run starts over).
func loginApprove(ctx context.Context, env *authflow.Env, u *termUI, opts authflow.EnrollOptions) (*authflow.LoginResult, error) {
	// An enrollment an earlier run left can't be resumed here: start a new
	// one. A delivery it accepted is still installed first.
	opts.Restart = true
	for resumes := 0; ; resumes++ {
		res, err := authflow.LoginApprove(ctx, env, opts)
		var ie *authflow.EnrollInterruptedError
		if err == nil || !errors.As(err, &ie) || ie.Mailbox == nil || isUIError(err) || ctx.Err() != nil || resumes >= maxEnrollResumes {
			return res, err
		}
		warn(u.e, u.asJSON, "the enrollment was interrupted ("+ie.Err.Error()+"); resuming")
		if err := sleepCtx(ctx, min(time.Second<<min(resumes, 4), 10*time.Second)); err != nil {
			return nil, err
		}
		opts.Mailbox, opts.Restart = ie.Mailbox, false
	}
}

func sleepCtx(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-t.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// thisDevice is this device's name and ID in the vault.
func thisDevice(s *store.Store) (name, id string) {
	id = s.Info().DeviceID
	if devices, err := s.Devices(); err == nil {
		for _, d := range devices {
			if d.This {
				return d.Name, d.ID.String()
			}
		}
	}
	return "", id
}

func printLogin(e *Env, asJSON bool, method string, res *authflow.LoginResult) error {
	s := res.Vault.Store
	name, id := thisDevice(s)
	r := loginReport{Method: method, DeviceID: id, DeviceName: name, VaultID: res.Vault.VaultID.String(), Merge: res.Merge}
	if si, err := s.ServerInfo(); err == nil {
		r.Server, r.Email, r.AccountID = si.Server, si.Email, si.AccountID.String()
	}
	if res.Recovery != nil {
		r.Recovery = newCheckpointReport(res.Recovery)
	}
	// What became of this machine's earlier identity (Q15): the commands
	// are printed, never run, and an entry that needs nothing more is
	// forgotten once it has been reported.
	dataDir := e.storeConfig().DataDir
	entries, _ := store.ReadPredecessors(dataDir)
	devs, devErr := s.Devices()
	r.OldDevices = oldDevices(entries, r.AccountID, devs, devErr == nil)
	// Settled once the report is out: a sign-in cut short before that
	// leaves the entries unreported for hop auth status to show.
	settle := func() { _ = settleOldDevices(dataDir, entries, r.AccountID, devs, devErr == nil) }
	if asJSON {
		if err := printJSON(e, r); err != nil {
			return err
		}
		settle()
		return nil
	}
	e.printf("Signed in to %s as %s.\n", oneLine(r.Server), fmtDevice(name, id))
	if m := res.Merge; m != nil {
		n := 0
		for _, it := range m.Items {
			if !it.Imported {
				n++
			}
		}
		e.printf("Your local vault is being merged into the account: %d item(s) are queued for upload (hop auth merge shows them).\n", n)
	}
	if res.Recovery != nil {
		e.printf("The recovery is finished: a new password, new keys and a new Emergency Kit.\n")
		printSurvivors(e, res.Recovery.Devices)
	}
	e.printf("The hop daemon keeps this device in sync from now on.\n")
	return reportLoginOldDevices(e.Stdout, r.OldDevices, settle)
}

// ---- approve ----

// approveReport is the --json shape of hop auth approve.
type approveReport struct {
	// Approved is the device just approved; Approval is the approval in
	// progress on this device, when no code was given.
	Approved *approvedDevice     `json:"approved,omitempty"`
	Approval *store.ApprovalInfo `json:"approval"`
	Aborted  bool                `json:"aborted,omitempty"`
}

type approvedDevice struct {
	EnrollID   string `json:"enroll_id"`
	DeviceName string `json:"device_name"`
}

// maxApproveRetries bounds the times one hop auth approve resumes an
// approval the network interrupted.
const maxApproveRetries = 5

func runAuthApprove(ctx context.Context, e *Env, args []string) error {
	fs := newFlags(e, "auth approve", authCommands["approve"].usage)
	var o authOpts
	o.jsonFlag(fs)
	sas := fs.String("sas", "", "the 8-digit check code the new device shows (to approve without a terminal)")
	abort := fs.Bool("abort", false, "end this device's unfinished approval")
	pos, _, err := parseFlags(fs, args)
	if err != nil {
		return err
	}
	if *abort && len(pos) != 0 {
		return failf("--abort takes no code")
	}
	ctx, stopWatch := hangupContext(ctx, e)
	defer stopWatch()
	u := o.ui(e)
	u.role, u.sas = roleApprove, *sas
	h, err := holdVault(ctx, e, o.asJSON)
	if err != nil {
		return err
	}
	defer h.release(ctx)
	s, v, err := h.signedIn(ctx)
	if err != nil {
		return err
	}
	defer s.Close()

	if *abort {
		if err := authflow.AbortApproval(v); err != nil {
			return authFailure(err)
		}
		if o.asJSON {
			return printJSON(e, approveReport{Aborted: true})
		}
		e.printf("The approval was ended. A device it added but never delivered to is listed as undelivered: revoke it with hop auth devices revoke.\n")
		return nil
	}
	if len(pos) == 0 {
		// Only this device's own approval can be listed: the server does
		// not list waiting devices, and the routing code is how one is
		// picked.
		info, err := s.Approval()
		if err != nil {
			return failf("%v", err)
		}
		if info != nil && (info.State == crypto.ApprovalDelivered || info.State == crypto.ApprovalFailed) {
			info = nil
		}
		if o.asJSON {
			return printJSON(e, approveReport{Approval: info})
		}
		if info == nil {
			e.printf("No approval is in progress on this device.\n")
			e.printf("To approve a new device, run hop auth approve CODE with the code it shows.\n")
			return nil
		}
		e.printf("An approval is in progress (%s, enrollment %s, until %s).\n", oneLine(string(info.State)), oneLine(info.EnrollID.String()), e.when(info.Deadline))
		e.printf("Resume it with hop auth approve CODE, using the code the new device shows, or end it with hop auth approve --abort.\n")
		return nil
	}
	code := strings.Join(pos, "")
	env := h.flowEnv(v.Client, u)
	var res *authflow.ApproveResult
	for attempt := 0; ; attempt++ {
		res, err = authflow.Approve(ctx, env, v, code)
		if err == nil || isUIError(err) || !syncclient.Retryable(err) || ctx.Err() != nil || attempt >= maxApproveRetries {
			break
		}
		warn(e, o.asJSON, "the server could not be reached ("+err.Error()+"); trying again")
		if err := sleepCtx(ctx, time.Second<<attempt); err != nil {
			return err
		}
	}
	if err != nil {
		if errors.Is(context.Cause(ctx), errStdinClosed) {
			return failf("stdin closed, so the approval was cancelled; hop auth approve --abort ends it")
		}
		if errors.Is(err, crypto.ErrBudgetExhausted) {
			return budgetFailure(err)
		}
		switch {
		case isUIError(err), errors.Is(err, authflow.ErrSASMismatch), errors.Is(err, authflow.ErrApprovalFailed),
			errors.Is(err, crypto.ErrEnrollExpired):
			return authFailure(err)
		}
		return failf("%v. Run hop auth approve with the same code to resume the approval, or hop auth approve --abort to end it", err)
	}
	if o.asJSON {
		return printJSON(e, approveReport{Approved: &approvedDevice{EnrollID: res.EnrollID.String(), DeviceName: res.DeviceName}})
	}
	name := oneLine(res.DeviceName)
	if name == "" {
		name = "the new device"
	}
	e.printf("Approved %s. It receives the vault now.\n", name)
	return nil
}

// budgetFailure is the approver's refusal when its hourly approvals are used
// up. The error says when one frees up; the new device is not told, so this
// names what it can do meanwhile. The new device's login is unfinished, which
// blocks every other method until it is discarded.
func budgetFailure(err error) error {
	return failf("%v; or the new device can cancel its login (Ctrl-C), run hop auth login --discard, then sign in with hop auth login --method password", err)
}

// ---- status ----

// AuthStatus is the --json shape of hop auth status.
type AuthStatus struct {
	// SignedIn means the vault syncs with a server. A revoked device is not
	// signed in: nothing syncs on it again.
	SignedIn bool `json:"signed_in"`
	// Revoked means the account revoked this device (SignedIn is false):
	// the server reports it (RevokedUnverified while that is not proven,
	// and the vault stays locked), or the log proved it and the vault was
	// wiped here (Wiped, and Revocation says when). WipePending means it is
	// proven, but the wipe has not finished.
	Revoked           bool                    `json:"revoked,omitempty"`
	RevokedUnverified bool                    `json:"revoked_unverified,omitempty"`
	Wiped             bool                    `json:"wiped,omitempty"`
	WipePending       bool                    `json:"wipe_pending,omitempty"`
	Revocation        *store.RevocationRecord `json:"revocation,omitempty"`
	// Vault is false when this device has no vault at all.
	Vault          bool                     `json:"vault"`
	Server         string                   `json:"server,omitempty"`
	Email          string                   `json:"email,omitempty"`
	AccountID      string                   `json:"account_id,omitempty"`
	VaultID        string                   `json:"vault_id,omitempty"`
	DeviceID       string                   `json:"device_id,omitempty"`
	DeviceName     string                   `json:"device_name,omitempty"`
	DeviceKeyStore string                   `json:"device_key_store,omitempty"`
	Locked         bool                     `json:"locked"`
	RecoveryDue    bool                     `json:"recovery_due,omitempty"`
	SecretKeyStale bool                     `json:"secret_key_stale,omitempty"`
	KitPending     bool                     `json:"kit_pending,omitempty"`
	Sync           *daemon.SyncStatusResult `json:"sync,omitempty"`
	// OldDevices are identities this machine left in the account when it
	// logged out without telling the server (hop auth logout --local-only):
	// still active, until a device in the account revokes them.
	OldDevices []oldDeviceReport `json:"old_devices,omitempty"`
	// EndedSessions is the ssh sessions the daemon told to end, on a
	// revocation say: termination requests sent, not ends confirmed.
	EndedSessions *daemon.EndedSessions `json:"ended_sessions,omitempty"`
	Warnings      []string              `json:"warnings,omitempty"`
}

func runAuthStatus(ctx context.Context, e *Env, args []string) error {
	var settle func()
	err := authStatus(ctx, e, args, &settle)
	if err == nil && settle != nil {
		settle() // the advice about earlier identities is consumed once it is out
	}
	return err
}

// authStatus is runAuthStatus; it sets *settle to what to run once the
// report is printed.
func authStatus(ctx context.Context, e *Env, args []string, settle *func()) error {
	fs := newFlags(e, "auth status", authCommands["status"].usage)
	var o authOpts
	o.jsonFlag(fs)
	pos, _, err := parseFlags(fs, args)
	if err != nil {
		return err
	}
	if err := noArgs(fs, pos); err != nil {
		return err
	}
	c, err := dialExisting(ctx, e)
	if err != nil {
		return err
	}
	if c == nil {
		// With no daemon running, a missing vault is not worth starting
		// one for.
		if ok, err := store.Exists(e.storeConfig().DataDir); err == nil && !ok {
			rev, _ := store.ReadRevocation(e.storeConfig().DataDir)
			pending := rev != nil && sshCleanupPending(e)
			if o.asJSON {
				return printJSON(e, AuthStatus{Revoked: rev != nil, Wiped: rev != nil && !pending, WipePending: pending, Revocation: rev})
			}
			switch {
			case pending:
				printWipePending(e, rev)
				return nil
			case rev != nil:
				printWipedRevocation(e, rev)
				return nil
			}
			e.printf("signed in:    no; this device has no vault (hop auth login signs in, hop auth signup creates an account)\n")
			return nil
		}
		if c, err = connect(ctx, e); err != nil {
			return err
		}
	}
	defer c.Close()
	var st daemon.StatusResult
	if err := c.Call(ctx, daemon.OpStatus, nil, &st); err != nil {
		return failf("%v", err)
	}
	a := AuthStatus{Vault: true, Sync: st.Sync, EndedSessions: st.EndedSessions}
	sshPending := false
	if v := st.Vault; v != nil {
		a.DeviceID, a.DeviceKeyStore, a.Locked, a.KitPending, a.AccountID = v.DeviceID, v.DeviceStore, v.Locked, v.KitPending, v.AccountID
		a.SecretKeyStale = v.SecretKeyStale
		a.Warnings = append(a.Warnings, v.Warnings...)
	}
	if s := st.Sync; s != nil && s.State != daemon.SyncOff {
		a.Revoked = s.State == daemon.SyncRevoked
		if r := s.ServerRetirement; a.Revoked && r != nil {
			// The daemon decides whether the ssh files are gone too
			// (daemon.CleanupLeft), so this and its sync block agree.
			a.Wiped, a.RevokedUnverified, a.WipePending = r.Wiped, r.Unverified, !r.Unverified && !r.Wiped
			sshPending = a.WipePending && r.SSHFilesLeft
		}
		if a.Wiped || sshPending {
			a.Vault = false
			a.Revocation, _ = store.ReadRevocation(e.storeConfig().DataDir)
		}
		a.SignedIn = !a.Revoked
		a.Server, a.Email, a.VaultID = s.Server, s.Email, s.VaultID
		if s.AccountID != "" {
			a.AccountID = s.AccountID
		}
		a.RecoveryDue = s.CheckpointDue
		a.SecretKeyStale = a.SecretKeyStale || s.SecretKeyStale
		if !a.Locked {
			var dl daemon.DevicesResult
			if err := c.Call(ctx, daemon.OpDevicesList, nil, &dl); err == nil {
				for _, d := range dl.Devices {
					if d.This {
						a.DeviceName = d.Name
					}
				}
			}
		}
	}
	// settleOld is handed to the caller only where the advice was written.
	settleOld := func() {}
	if a.AccountID != "" {
		a.OldDevices, settleOld = statusOldDevices(ctx, e, c, a.AccountID, !a.Locked)
	}
	if o.asJSON {
		if err := printJSON(e, a); err != nil {
			return err
		}
		*settle = settleOld
		return nil
	}
	ended := func() {
		if l := e.endedLine(a.EndedSessions); l != "" {
			e.printf("sessions:     %s\n", l)
		}
	}
	switch {
	case a.SignedIn:
		e.printf("signed in:    yes\n")
	case a.Wiped && a.Revocation != nil:
		printWipedRevocation(e, a.Revocation)
		ended()
		return nil
	case a.Wiped:
		e.printf("signed in:    no; this device was revoked from the account, the revocation verified, and this device's copy of the vault, " +
			"its device key and the ssh files hop wrote were wiped (hop auth login signs in again)\n")
		ended()
		return nil
	case sshPending:
		printWipePending(e, a.Revocation)
		ended()
		return nil
	case a.WipePending:
		r := a.Sync.ServerRetirement
		e.printf("signed in:    no; this device was %s from the account at seq %d, and the revocation verified, so the vault stays locked for good; "+
			"wiping this device's copy has not finished (%s)\n", oneLine(r.How), r.Seq, oneLine(r.WipeError))
	case a.RevokedUnverified && a.Sync.ServerRetirement.ReportCorrupt:
		e.printf("signed in:    no; the server reported that this device left the account, but the record of that report here is corrupt, " +
			"so the vault stays locked and nothing syncs (hop auth logout wipes this device, then hop auth login signs in again)\n")
	case a.RevokedUnverified:
		r := a.Sync.ServerRetirement
		e.printf("signed in:    no; the server reports that this device was %s from the account at seq %d, so the vault stays locked "+
			"and nothing syncs (hop auth logout wipes this device, then hop auth login signs in again)\n", oneLine(r.How), r.Seq)
	case a.Revoked:
		e.printf("signed in:    no; this device was revoked from the account, so nothing syncs here any more (hop auth logout --local-only wipes this device's copy, then hop auth login signs in again)\n")
	default:
		e.printf("signed in:    no; this vault is local-only (hop auth signup publishes it, hop auth login --merge merges it into an account)\n")
	}
	if a.DeviceID != "" {
		e.printf("this device:  %s\n", fmtDevice(a.DeviceName, a.DeviceID))
	}
	if a.DeviceKeyStore != "" {
		e.printf("device key:   %s\n", oneLine(a.DeviceKeyStore))
	}
	switch {
	case !a.Locked:
		e.printf("vault:        unlocked\n")
	case a.Revoked:
		e.printf("vault:        locked: hop unlock refuses on a revoked device\n")
	case st.Vault != nil:
		e.printf("vault:        %s\n", vaultState(st.Vault))
		printAdminLockHelp(e, st.Vault)
	default:
		e.printf("vault:        locked; run hop unlock\n")
	}
	ended()
	if s := a.Sync; s != nil && a.SignedIn {
		switch {
		case s.MaxOffline > 0 && s.LastContact != nil:
			e.printf("max offline:  %s (last server contact %s)\n", fmtSeconds(s.MaxOffline), e.when(*s.LastContact))
		case s.MaxOffline > 0:
			e.printf("max offline:  %s\n", fmtSeconds(s.MaxOffline))
		}
	}
	shown := map[string]bool{}
	if a.Sync != nil && (a.SignedIn || a.Revoked) {
		printSyncBlock(e, e.Stdout, a.Sync, syncBlockOpts{shown: shown})
		for _, w := range a.Sync.Warnings {
			shown[w] = true
		}
	}
	if a.KitPending {
		e.printf("warning:      a new Emergency Kit is waiting to be confirmed; run hop auth resume\n")
	}
	for _, w := range a.Warnings {
		if !shown[w] {
			e.printf("warning:      %s\n", oneLine(w))
		}
	}
	if err := printOldDeviceLines(e.Stdout, a.OldDevices); err != nil {
		return err
	}
	*settle = settleOld
	return nil
}

// ---- checkpoints: devices revoke, rotate, passwd, resume ----

// checkpointReport is the --json shape of a committed checkpoint.
type checkpointReport struct {
	Kind    string                `json:"kind"`
	Resumed bool                  `json:"resumed,omitempty"`
	Devices []store.DeviceListing `json:"devices"`
	// RotateCommand, after a revoke, replaces the SSH keys the revoked
	// device could decrypt (offerKeyRotation).
	RotateCommand string `json:"rotate_command,omitempty"`
}

func newCheckpointReport(r *authflow.CheckpointResult) *checkpointReport {
	devices := r.Devices
	if devices == nil {
		devices = []store.DeviceListing{}
	}
	out := &checkpointReport{Kind: r.Kind, Resumed: r.Resumed, Devices: devices}
	if r.Kind == store.CheckpointRevoke {
		out.RotateCommand = rotateAllCommand
	}
	return out
}

func printSurvivors(e *Env, devices []store.DeviceListing) {
	names := make([]string, len(devices))
	for i, d := range devices {
		names[i] = fmtDevice(d.Name, d.ID.String())
	}
	e.printf("Devices signed in now: %s.\n", strings.Join(names, ", "))
}

func printCheckpoint(e *Env, asJSON bool, res *authflow.CheckpointResult) error {
	if asJSON {
		return printJSON(e, newCheckpointReport(res))
	}
	switch res.Kind {
	case store.CheckpointPasswd:
		e.printf("Your master password has changed. Your Secret Key and Recovery Key changed with it; the old ones no longer work.\n")
	case store.CheckpointRecovery:
		e.printf("The recovery is finished: a new password, new keys and a new Emergency Kit.\n")
	default:
		e.printf("Every key was replaced, with a new Secret Key and Recovery Key; the old ones no longer work. Every device not kept was revoked.\n")
	}
	e.printf("Emergency Kit confirmed.\n")
	printSurvivors(e, res.Devices)
	if res.Resumed {
		e.printf("This finished a %s an earlier run left pending; run the command again if you wanted another.\n", oneLine(res.Kind))
	}
	return nil
}

// runCheckpoint is the shape of the checkpoint commands: the flags, the
// signed-in vault, the flow, and its kit and survivors.
func runCheckpoint(ctx context.Context, e *Env, name string, args []string, extra func(*flag.FlagSet, *authOpts),
	flow func(ctx context.Context, env *authflow.Env, v *authflow.Vault, pos []string) (*authflow.CheckpointResult, error)) error {
	fs := newFlags(e, "auth "+name, authCommands[strings.Fields(name)[0]].usage)
	var o authOpts
	o.jsonFlag(fs)
	o.checkpointFlags(fs)
	if extra != nil {
		extra(fs, &o)
	}
	pos, _, err := parseFlags(fs, args)
	if err != nil {
		return err
	}
	if err := o.checkKitFile(); err != nil {
		return err
	}
	u := o.ui(e)
	h, err := holdVault(ctx, e, o.asJSON)
	if err != nil {
		return err
	}
	defer h.release(ctx)
	s, v, err := h.signedIn(ctx)
	if err != nil {
		return err
	}
	defer s.Close()
	res, err := flow(ctx, h.flowEnv(v.Client, u), v, pos)
	if err != nil {
		if errors.Is(err, authflow.ErrKitNotConfirmed) || (u.kit != nil && isUIError(err)) {
			return failf("%v. The change is committed; its new Emergency Kit stays pending until you confirm it with hop auth resume", err)
		}
		return authFailure(err)
	}
	if res == nil {
		if o.asJSON {
			return printJSON(e, map[string]any{"resumed": nil})
		}
		e.printf("Nothing is pending.\n")
		return nil
	}
	return printCheckpoint(e, o.asJSON, res)
}

func runAuthRevoke(ctx context.Context, e *Env, args []string) error {
	revoked := false
	err := runCheckpoint(ctx, e, "devices revoke", args, nil, func(ctx context.Context, env *authflow.Env, v *authflow.Vault, pos []string) (*authflow.CheckpointResult, error) {
		if len(pos) == 0 {
			return nil, failf("name the device to revoke: hop auth devices revoke <name|id> (hop auth devices lists them)")
		}
		res, err := authflow.RevokeDevices(ctx, env, v, pos)
		revoked = err == nil && res != nil
		return res, err
	})
	if err != nil || !revoked {
		return err
	}
	// After runCheckpoint, so the daemon has the vault again.
	return offerKeyRotation(ctx, e, wantsJSON(args))
}

func runAuthRotate(ctx context.Context, e *Env, args []string) error {
	return runCheckpoint(ctx, e, "rotate", args, nil, func(ctx context.Context, env *authflow.Env, v *authflow.Vault, pos []string) (*authflow.CheckpointResult, error) {
		if len(pos) != 0 {
			return nil, failf("unexpected argument %q", pos[0])
		}
		return authflow.Rotate(ctx, env, v)
	})
}

// runAuthPasswd is hop auth passwd, and hop passwd for a vault on a
// server: a full checkpoint with a new master password that keeps every
// device. A recovery that is not finished finishes here.
func runAuthPasswd(ctx context.Context, e *Env, args []string) error {
	return runCheckpoint(ctx, e, "passwd", args, func(fs *flag.FlagSet, o *authOpts) {
		fs.Var(&o.exclude, "exclude", "a device that joined during the change to revoke, by ID or unique name (repeatable)")
	}, func(ctx context.Context, env *authflow.Env, v *authflow.Vault, pos []string) (*authflow.CheckpointResult, error) {
		if len(pos) != 0 {
			return nil, failf("unexpected argument %q", pos[0])
		}
		if si, err := v.Store.ServerInfo(); err == nil && si.CheckpointDue {
			env.UI.(*termUI).notice("This device signed in with the Recovery Key: the new password finishes the recovery.")
			res, err := authflow.Resume(ctx, env, v)
			if err != nil || res.Checkpoint == nil {
				return nil, err
			}
			return res.Checkpoint, nil
		}
		return authflow.ChangePassword(ctx, env, v)
	})
}

// runAuthResume is hop auth resume: what an earlier flow left pending, a
// publication, a recovery's checkpoint, a journaled checkpoint or a kit
// to confirm.
func runAuthResume(ctx context.Context, e *Env, args []string) error {
	fs := newFlags(e, "auth resume", authCommands["resume"].usage)
	var o authOpts
	o.jsonFlag(fs)
	o.checkpointFlags(fs)
	pos, _, err := parseFlags(fs, args)
	if err != nil {
		return err
	}
	if err := noArgs(fs, pos); err != nil {
		return err
	}
	if err := o.checkKitFile(); err != nil {
		return err
	}
	u := o.ui(e)
	h, err := holdVault(ctx, e, o.asJSON)
	if err != nil {
		return err
	}
	defer h.release(ctx)
	s, err := h.open(ctx)
	if err != nil {
		return err
	}
	if s == nil {
		return failf("there is no vault on this device, so nothing to resume (an interrupted hop auth login --method approve starts over: run it again)")
	}
	defer s.Close()
	if pending, err := s.Publication(); err != nil {
		return failf("%v", err)
	} else if pending != nil {
		c, err := e.serverClient(pending.Server)
		if err != nil {
			return err
		}
		res, err := authflow.Signup(ctx, h.flowEnv(c, u), authflow.SignupOptions{Local: s})
		if err != nil {
			return authFailure(err)
		}
		return printSignup(e, o.asJSON, res)
	}
	v, err := h.vaultOf(s)
	if err != nil {
		return err
	}
	res, err := authflow.Resume(ctx, h.flowEnv(v.Client, u), v)
	if err != nil {
		if errors.Is(err, authflow.ErrKitNotConfirmed) || (u.kit != nil && isUIError(err)) {
			return failf("%v. Its new Emergency Kit stays pending until you confirm it with hop auth resume", err)
		}
		return authFailure(err)
	}
	if res.Checkpoint == nil {
		if o.asJSON {
			return printJSON(e, map[string]any{"resumed": nil})
		}
		e.printf("Nothing is pending.\n")
		return nil
	}
	return printCheckpoint(e, o.asJSON, res.Checkpoint)
}

// ---- logout ----

// logoutReport is the --json shape of hop auth logout.
type logoutReport struct {
	store.LogoutResult
	DeviceID string `json:"device_id,omitempty"`
}

func runAuthLogout(ctx context.Context, e *Env, args []string) error {
	fs := newFlags(e, "auth logout", authCommands["logout"].usage)
	var o authOpts
	o.jsonFlag(fs)
	discard := fs.Bool("discard-pending", false, "log out even with queued changes, which are lost")
	localOnly := fs.Bool("local-only", false, "wipe this device without telling the server (then revoke it from another device)")
	fs.BoolVar(&o.yes, "yes", false, "log out without asking")
	pos, _, err := parseFlags(fs, args)
	if err != nil {
		return err
	}
	if err := noArgs(fs, pos); err != nil {
		return err
	}
	u := o.ui(e)
	if !o.yes && !u.interactive {
		return failf("hop auth logout deletes this device's keys and its copy of the vault, and there is no terminal to confirm on: pass --yes")
	}
	// Asked before the daemon stops: the operator's refusal lives in its
	// memory only.
	lock := daemonAdminLock(ctx, e)
	// A sealed device key opens with its passphrase, which a logout that
	// tells the server needs to sign the retirement.
	var pass []byte
	if !*localOnly && e.Getenv(store.PassphraseEnv) == "" && canAskPassphrase(e) {
		if pass, err = e.ReadPassword("Device passphrase: "); err != nil {
			return failf("reading the device passphrase: %v", err)
		}
		defer clear(pass)
	}
	h, err := holdVault(ctx, e, o.asJSON)
	if err != nil {
		return err
	}
	defer h.release(ctx)
	if len(pass) > 0 {
		getenv := h.cfg.Getenv
		h.cfg.Getenv = func(k string) string {
			if k == store.PassphraseEnv {
				return string(pass)
			}
			return getenv(k)
		}
	}
	s, err := h.open(ctx)
	if err != nil {
		return err
	}
	if s == nil {
		if h.loggedOut {
			// An earlier logout was recorded and cut short; opening the
			// vault finished it, and open emptied the ssh config.
			if o.asJSON {
				return printJSON(e, logoutReport{LogoutResult: store.LogoutResult{State: store.StateRetired, Done: true}})
			}
			e.printf("An interrupted logout is finished: this device's keys and vault are deleted.\n")
			return nil
		}
		// A logout that deleted the vault but could not empty the ssh
		// config said to run it again: this is that retry.
		wipeSSHConfig(e, o.asJSON)
		return failf("there is no vault on this device, so there is nothing to log out of")
	}
	defer s.Close()
	env := h.flowEnv(nil, u)
	si, err := s.ServerInfo()
	switch {
	case errors.Is(err, store.ErrNotServerBacked):
		return failf("this vault is local-only, so it is not signed in to an account")
	case err == nil && si.Server != "":
		if env.Client, err = e.serverClient(si.Server); err != nil {
			return err
		}
	case err != nil && !*localOnly:
		return failf("%v", err)
	}
	id := s.Info().DeviceID
	// What the logout throws away, said before anything is asked or
	// deleted. A logout already under way (RETIRING) counted it when it
	// began.
	var pc store.PendingChanges
	if state, err := s.Retirement(); err != nil {
		return failf("%v", err)
	} else if state == "" {
		if pc, err = s.PendingChanges(); err != nil {
			return failf("%v", err)
		}
		if pc.Queued > 0 && !*discard {
			return failf("this device has %s that the server has not received, and a logout throws them away: wait for the daemon to send them (hop sync shows them), "+
				"or log out with --discard-pending to drop them%s", pendingChangesText(pc), lockedLogoutHint(lock))
		}
	}
	if !o.yes {
		q := "Log out? This device leaves the account, and its keys and its copy of the vault are deleted."
		if *localOnly {
			q = "Wipe this device without telling the server? Its keys and its copy of the vault are deleted; the old device ID is still in the account until you revoke it from the new device."
		}
		if pc.Queued > 0 {
			fmt.Fprintf(e.Stderr, "This device has %s that the server has not received. They are lost: they are not kept for the next sign-in.\n", pendingChangesText(pc))
		}
		if lock != nil {
			fmt.Fprintf(e.Stderr, "The server's operator has locked this device out. After the logout, hop auth login signs this machine in again as a new device (master password and current Secret Key).\n")
		}
		ok, err := confirm(e, false, q)
		if err != nil {
			return err
		}
		if !ok {
			return failf("not logged out")
		}
	}
	res, err := authflow.Logout(ctx, env, s, store.LogoutOptions{DiscardPending: *discard, LocalOnly: *localOnly, Why: adminLockWhy(lock)})
	if errors.Is(err, store.ErrLogoutPending) {
		return failf("the server could not tell yet whether the logout went through, so it is not finished: the daemon finishes it once the server answers, or run hop logout again (%v)%s",
			err, localOnlyHint(lock))
	}
	if errors.Is(err, store.ErrDeviceKey) {
		return failf("%v. A logout that tells the server signs with the device key: if it is sealed, set %s to its passphrase (or run on a terminal to type it); "+
			"hop auth logout --local-only needs no key", err, store.PassphraseEnv)
	}
	if err != nil {
		return authFailure(err)
	}
	s.Close()
	if res.Done {
		finishLogoutCleanup(e, o.asJSON)
	}
	if o.asJSON {
		return printJSON(e, logoutReport{LogoutResult: res, DeviceID: id})
	}
	if !res.Done {
		e.printf("This device left the account, but deleting its keys and vault is not finished; run hop logout again to finish it.\n")
		return nil
	}
	if res.RevokeElsewhere {
		e.printf("This device was wiped: its keys and vault are deleted. The server was not told, so device %s is still in the account.\n", oneLine(id))
	} else {
		e.printf("Logged out: this device left the account, and its keys and vault are deleted.\n")
	}
	if res.Discarded > 0 {
		e.printf("%d queued change(s) were discarded.\n", res.Discarded)
	}
	printLogoutNext(e, res, id, lock != nil || res.Why != "")
	return nil
}

// lockedLogoutHint is the end of a refusal to log out with queued
// changes on a device the operator locked out.
func lockedLogoutHint(lock *store.AdminRefusal) string {
	if lock == nil {
		return ""
	}
	return ". The server's operator has locked this device out, so they will not be sent until it lets the device in again"
}

// localOnlyHint says what to do when the server won't take the logout of
// a device the operator locked out.
func localOnlyHint(lock *store.AdminRefusal) string {
	if lock == nil {
		return ""
	}
	return "; if the server keeps refusing, hop auth logout --local-only --discard-pending wipes this device without it"
}

// printLogoutNext says what follows a logout: how this machine signs in
// again, and what to do about the old identity. It runs nothing.
func printLogoutNext(e *Env, res store.LogoutResult, id string, locked bool) {
	if res.RevokeElsewhere {
		e.printf("To sign in again as a new device: hop auth login (master password and current Secret Key). "+
			"Then, from that device, take the old one out of the account: hop auth devices revoke %s\n", oneLine(id))
		e.printf("hop auth login reminds you of that command. If another device is signed in, it can run it now.\n")
		return
	}
	if locked {
		e.printf("To sign in again as a new device: hop auth login (master password and current Secret Key).\n")
		e.printf("If this device's files could have been copied while it was locked, then run hop auth rotate from the new device, " +
			"and rotate the SSH keys and passwords stored in the vault.\n")
	}
}

// wipeSSHConfig removes what the vault decrypted into the ssh config
// directory (§5.5), as the daemon does for a logout it finishes: the
// config is left with no hosts, and the key files and pins go
// (sshconfig.Wipe). Files hop did not write are left alone. It is for a
// device that has no vault: once config.lock is held, a vault that is
// there after all is a new sign-in's, whose config this is, and nothing
// is wiped. After a wipe that worked, and before the lock goes, the
// store's mark of a logout that still owes it is cleared. A failure is a
// warning: the mark stays, and the next hop command that finds no vault,
// or starts the daemon, tries again (finishLogoutCleanup), as does hop
// logout run again.
func wipeSSHConfig(e *Env, asJSON bool) {
	dataDir := e.storeConfig().DataDir
	err := sshconfig.WipeIf(sshconfig.Options{Dir: e.Paths.ConfigDir, AgentSocket: e.Paths.AgentSocket()},
		func() (bool, error) {
			exists, err := store.Exists(dataDir)
			return !exists, err
		},
		func() error { return store.ClearLogoutCleanup(dataDir) })
	if err != nil {
		warn(e, asJSON, fmt.Sprintf("the ssh config in %s could not be emptied (%v) and may still name the vault's hosts; hop tries again on its next start, or run hop logout again", e.Paths.ConfigDir, err))
	}
}

// testHookLogoutCleanup, if set, runs once finishLogoutCleanup has read
// the mark of a logout that owes the ssh config.
var testHookLogoutCleanup func()

// finishLogoutCleanup empties the ssh config, as wipeSSHConfig does, if a
// finished logout still owes it (store.LogoutCleanupPending): one a crash
// cut short after it was recorded, which store.Open has just finished, or
// one whose wipe failed. A device wiped after a verified revocation whose
// ssh config still holds what the vault decrypted owes it too, with no
// mark (store.OweSSHCleanup marks it then). The mark is read, the config
// emptied and the mark cleared in one hold of config.lock
// (sshconfig.WipeIf), the lock every config write takes: a new sign-in
// clears the mark this way before its daemon writes, so a mark read before
// that sign-in can't wipe its config.
func finishLogoutCleanup(e *Env, asJSON bool) {
	dataDir := e.storeConfig().DataDir
	o := sshconfig.Options{Dir: e.Paths.ConfigDir, AgentSocket: e.Paths.AgentSocket()}
	var readErr error
	err := sshconfig.WipeIf(o,
		func() (bool, error) {
			pending, err := store.OweSSHCleanup(dataDir, func() (bool, error) { return sshconfig.Generated(o) })
			if testHookLogoutCleanup != nil {
				testHookLogoutCleanup()
			}
			readErr = err
			return pending, err
		},
		func() error { return store.ClearLogoutCleanup(dataDir) })
	switch {
	case readErr != nil:
		warn(e, asJSON, fmt.Sprintf("could not tell whether a logout still has to empty the ssh config in %s: %v", e.Paths.ConfigDir, readErr))
	case err != nil:
		warn(e, asJSON, fmt.Sprintf("the ssh config in %s could not be emptied (%v) and may still name the vault's hosts; hop tries again on its next start, or run hop logout again", e.Paths.ConfigDir, err))
	}
}

// ---- merge ----

// mergeReport is the --json shape of hop auth merge.
type mergeReport struct {
	Merge   *store.MergeStatus     `json:"merge"`
	Discard *store.DiscardProposal `json:"discard,omitempty"`
	Done    string                 `json:"done,omitempty"` // paused, resumed or discarded
}

func runAuthMerge(ctx context.Context, e *Env, args []string) error {
	fs := newFlags(e, "auth merge", authCommands["merge"].usage)
	var o authOpts
	o.jsonFlag(fs)
	pause := fs.Bool("pause", false, "pause the merge's imports")
	resume := fs.Bool("resume", false, "resume a paused merge")
	discard := fs.Bool("discard", false, "delete a paused merge's items that were never imported (needs --confirm without a terminal)")
	token := fs.String("confirm", "", "the token hop auth merge --discard shows, which confirms what is deleted")
	pos, _, err := parseFlags(fs, args)
	if err != nil {
		return err
	}
	if err := noArgs(fs, pos); err != nil {
		return err
	}
	n := 0
	for _, b := range []bool{*pause, *resume, *discard} {
		if b {
			n++
		}
	}
	if n > 1 {
		return failf("choose one of --pause, --resume and --discard")
	}
	if *token != "" && !*discard {
		return failf("--confirm goes with --discard")
	}
	u := o.ui(e)
	h, err := holdVault(ctx, e, o.asJSON)
	if err != nil {
		return err
	}
	defer h.release(ctx)
	s, v, err := h.signedIn(ctx)
	if err != nil {
		return err
	}
	defer s.Close()
	report := func(st *store.MergeStatus, prop *store.DiscardProposal, done string) error {
		if o.asJSON {
			return printJSON(e, mergeReport{Merge: st, Discard: prop, Done: done})
		}
		if done != "" {
			e.printf("The merge was %s.\n", done)
		}
		printMerge(e, st)
		return nil
	}
	switch {
	case *pause:
		st, err := s.MergePause(ctx, v.Remote)
		if err != nil {
			return authFailure(err)
		}
		return report(&st, nil, "paused")
	case *resume:
		st, err := s.MergeResume()
		if err != nil {
			return authFailure(err)
		}
		return report(&st, nil, "resumed")
	case *discard:
		var c crypto.Hash
		if *token != "" {
			if err := c.UnmarshalText([]byte(strings.TrimSpace(*token))); err != nil || c == (crypto.Hash{}) {
				return failf("--confirm %q is not a token hop auth merge --discard showed", *token)
			}
		} else {
			prop, err := s.MergeDiscardProposal()
			if err != nil {
				return authFailure(err)
			}
			if !o.asJSON {
				printDiscard(e, &prop)
			}
			if !u.interactive {
				if o.asJSON {
					printJSON(e, mergeReport{Discard: &prop})
				}
				return failf("discarding needs --confirm %s (the token of what is deleted)", prop.Token.String())
			}
			ok, err := confirm(e, false, fmt.Sprintf("Delete these %d item(s) for good?", len(prop.Items)))
			if err != nil {
				return err
			}
			if !ok {
				return failf("nothing was discarded")
			}
			c = prop.Token
		}
		prop, err := s.MergeDiscard(c)
		if errors.Is(err, store.ErrStaleConfirm) {
			return failf("the merge changed since that token was shown: run hop auth merge --discard again to see what it deletes now")
		}
		if err != nil {
			return authFailure(err)
		}
		return report(nil, &prop, "discarded")
	}
	st, err := s.MergeStatus()
	if err != nil {
		return authFailure(err)
	}
	if st == nil && !o.asJSON {
		e.printf("No login merge is in progress.\n")
		return nil
	}
	return report(st, nil, "")
}

func printMerge(e *Env, st *store.MergeStatus) {
	if st == nil {
		return
	}
	e.printf("Login merge %s: %s.\n", oneLine(st.TxnID.String()), oneLine(st.State))
	tw := tabwriter.NewWriter(e.Stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "TYPE\tNAME\tID\tIMPORTED")
	for _, it := range st.Items {
		imp := "no"
		if it.Imported {
			imp = fmt.Sprintf("yes (seq %d)", it.Seq)
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n", oneLine(string(it.Type)), dash(oneLine(it.Name)), oneLine(it.ItemID.String()), imp)
	}
	tw.Flush()
}

func printDiscard(e *Env, p *store.DiscardProposal) {
	e.printf("Discarding deletes these %d item(s), which were never imported:\n", len(p.Items))
	for _, it := range p.Items {
		e.printf("  %s %s (%s)\n", oneLine(string(it.Type)), dash(oneLine(it.Name)), oneLine(it.ItemID.String()))
	}
	e.printf("To discard them: hop auth merge --discard --confirm %s\n", p.Token.String())
}

// ---- devices ----

func runAuthDevices(ctx context.Context, e *Env, args []string) error {
	if len(args) > 0 && args[0] == "revoke" {
		return runAuthRevoke(ctx, e, args[1:])
	}
	fs := newFlags(e, "auth devices", authCommands["devices"].usage)
	asJSON := fs.Bool("json", false, "print the devices as JSON")
	pos, _, err := parseFlags(fs, args)
	if err != nil {
		return err
	}
	if len(pos) != 0 {
		fs.Usage()
		return failf("unknown devices subcommand %q (revoke)", pos[0])
	}
	var res daemon.DevicesResult
	if err := call(ctx, e, daemon.OpDevicesList, nil, &res); err != nil {
		if daemon.IsCode(err, daemon.CodeLocalOnly) {
			return failf("this vault is local-only, so it has no devices to list")
		}
		if daemon.IsCode(err, daemon.CodeRevoked) {
			return failf("this device was revoked from the account, so it can't list the account's devices any more; " +
				"hop auth status says what happened, and hop auth login signs in again")
		}
		if daemon.IsCode(err, daemon.CodeOffline) {
			return failf("%v", cleanErr(err))
		}
		if daemon.IsCode(err, daemon.CodeLocked) {
			return failf("the vault is locked; run hop unlock first")
		}
		return err
	}
	if res.Devices == nil {
		res.Devices = []store.DeviceListing{}
	}
	if *asJSON {
		return printJSON(e, res)
	}
	if len(res.Devices) == 0 {
		fmt.Fprintln(e.Stderr, "no devices")
		return nil
	}
	// Device names come from other devices through the server: oneLine
	// keeps them from breaking the table.
	tw := tabwriter.NewWriter(e.Stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "NAME\tID\tADDED BY\tADDED\tLAST SEEN\tNOTES")
	for _, d := range res.Devices {
		seen := "-"
		if d.LastSeen != nil {
			seen = e.when(*d.LastSeen)
		}
		var notes []string
		if d.This {
			notes = append(notes, "this device")
		}
		if d.Stale {
			notes = append(notes, "stale: its key was replaced here; hop passwd revokes it")
		}
		if d.Undelivered {
			notes = append(notes, "undelivered: never received the vault; revoke it")
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\n", dash(oneLine(d.Name)), oneLine(d.ID.String()), dash(oneLine(d.How)), e.when(d.AddedAt), seen, dash(strings.Join(notes, "; ")))
	}
	return tw.Flush()
}

// printWipedRevocation is hop auth status on a device a verified
// revocation wiped.
func printWipedRevocation(e *Env, r *store.RevocationRecord) {
	e.printf("signed in:    no; this device was %s from the account", oneLine(r.How))
	if r.Email != "" {
		e.printf(" %s", oneLine(r.Email))
	}
	if r.Seq != 0 {
		e.printf(" by the entry at seq %d", r.Seq)
	}
	e.printf(", verified here on %s\n", e.when(r.At.Time()))
	e.printf("wiped:        this device's copy of the vault, its device key and the ssh files hop wrote\n")
	e.printf("kept:         SSH key files you imported yourself; the vault's SSH keys stay valid on your hosts until rotated (hop key rotate)\n")
	e.printf("next:         hop auth login signs in again as a new device\n")
}

// printWipePending is printWipedRevocation for a device whose copy of the
// vault is wiped, but whose ssh files may not be (sshCleanupPending). r may
// be nil.
func printWipePending(e *Env, r *store.RevocationRecord) {
	e.printf("signed in:    no; this device was ")
	if r == nil {
		e.printf("revoked from the account")
	} else {
		e.printf("%s from the account", oneLine(r.How))
		if r.Email != "" {
			e.printf(" %s", oneLine(r.Email))
		}
		if r.Seq != 0 {
			e.printf(" by the entry at seq %d", r.Seq)
		}
	}
	e.printf(", verified; wipe pending (ssh files remain under %s; the daemon retries, and so do hop sync and hop auth logout)\n", oneLine(homePath(e, e.Paths.ConfigDir)))
	e.printf("wiped so far: this device's copy of the vault and its device key\n")
	e.printf("next:         hop auth login signs in again as a new device, once the ssh files are gone\n")
}

// sshCleanupPending reports whether the ssh files hop wrote may still be
// there on a device whose vault was wiped, as the daemon's status decides
// it (daemon.CleanupLeft): for hop auth status with no daemon.
func sshCleanupPending(e *Env) bool {
	dataDir := e.storeConfig().DataDir
	return daemon.CleanupLeft(func() (bool, error) { return store.LogoutCleanupPending(dataDir) },
		sshconfig.Options{Dir: e.Paths.ConfigDir, AgentSocket: e.Paths.AgentSocket()}) != ""
}

// homePath writes p under the home directory as ~/....
func homePath(e *Env, p string) string {
	if e.Home == "" {
		return p
	}
	if rel, err := filepath.Rel(e.Home, p); err == nil && rel != "." && !strings.HasPrefix(rel, "..") {
		return "~/" + filepath.ToSlash(rel)
	}
	return p
}

// fmtSeconds writes a duration of n seconds in days, hours or minutes.
func fmtSeconds(n int64) string {
	d := time.Duration(n) * time.Second
	switch {
	case d%(24*time.Hour) == 0:
		return fmt.Sprintf("%dd", d/(24*time.Hour))
	case d%time.Hour == 0:
		return fmt.Sprintf("%dh", d/time.Hour)
	case d%time.Minute == 0:
		return fmt.Sprintf("%dm", d/time.Minute)
	}
	return d.String()
}

// parseMaxOffline reads --max-offline: "off", or a duration with an
// optional d (days) unit, from a minute to ten years.
func parseMaxOffline(s string) (int64, error) {
	if s == "off" || s == "0" {
		return 0, nil
	}
	var d time.Duration
	if days, ok := strings.CutSuffix(s, "d"); ok && days != "" && !strings.ContainsAny(days, "hmsuµn.") {
		n, err := strconv.ParseInt(days, 10, 64)
		if err != nil || n <= 0 || n > 3660 {
			return 0, fmt.Errorf("%q is not a number of days", s)
		}
		d = time.Duration(n) * 24 * time.Hour
	} else {
		var err error
		if d, err = time.ParseDuration(s); err != nil {
			return 0, fmt.Errorf("%q is not a duration (like 12h or 7d) or off", s)
		}
	}
	if d < time.Minute || d > 3660*24*time.Hour {
		return 0, fmt.Errorf("the max-offline time must be off, or between a minute and ten years")
	}
	return int64(d / time.Second), nil
}

// PolicyStatus is the --json shape of hop auth policy.
type PolicyStatus struct {
	MaxOffline  int64      `json:"max_offline"` // seconds; 0 is off
	Pending     bool       `json:"pending,omitempty"`
	LastContact *time.Time `json:"last_contact,omitempty"`
}

// runAuthPolicy is hop auth policy: the account's settings that every
// device follows. With --max-offline it sets, for every device of the
// account, how long one may go without reaching the server before it
// locks and refuses to unlock; off turns that off.
func runAuthPolicy(ctx context.Context, e *Env, args []string) error {
	fs := newFlags(e, "auth policy", authCommands["policy"].usage)
	var o authOpts
	o.jsonFlag(fs)
	maxOffline := fs.String("max-offline", "", "lock a device that has not reached the server for this long (like 12h or 7d), or off")
	pos, _, err := parseFlags(fs, args)
	if err != nil {
		return err
	}
	if err := noArgs(fs, pos); err != nil {
		return err
	}
	var params any
	if *maxOffline != "" {
		n, err := parseMaxOffline(*maxOffline)
		if err != nil {
			return failf("%v", err)
		}
		params = daemon.PolicyParams{MaxOffline: n}
	}
	var res daemon.PolicyResult
	if err := call(ctx, e, daemon.OpPolicy, params, &res); err != nil {
		switch {
		case daemon.IsCode(err, daemon.CodeLocalOnly):
			return failf("this vault is local-only: an account policy applies only to signed-in devices")
		case daemon.IsCode(err, daemon.CodeRevoked):
			return failf("this device was revoked from the account; hop auth status says more")
		case daemon.IsCode(err, daemon.CodeLocked):
			return failf("%v; run hop unlock first", err)
		}
		return err
	}
	if o.asJSON {
		return printJSON(e, PolicyStatus{MaxOffline: res.MaxOffline, Pending: res.Pending, LastContact: res.LastContact})
	}
	if res.MaxOffline == 0 {
		e.printf("max offline:  off (a device keeps working however long it can't reach the server)\n")
	} else {
		e.printf("max offline:  %s (a device that has not reached the server for longer locks, and refuses to unlock until it does)\n", fmtSeconds(res.MaxOffline))
	}
	if res.LastContact != nil {
		e.printf("this device:  last reached the server %s\n", e.when(*res.LastContact))
	}
	if res.Pending {
		e.printf("pending:      the change reaches the other devices once this one syncs\n")
	}
	return nil
}
