package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/user"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"
	"unicode"
	"unicode/utf16"
	"unicode/utf8"

	"golang.org/x/term"

	"github.com/dalyem/hopkey/internal/model"
	"github.com/dalyem/hopkey/internal/server"
)

// The admin commands: hop-server accounts, invites and audit. They open
// the database file the way invite and quota do, so whoever can write the
// data directory is an admin. A command that changes state shows the
// change, asks on a terminal (or takes --yes), changes nothing with
// --dry-run, and writes one admin_audit row in the transaction that makes
// the change. That row is also printed to stderr as one JSON line.

// What the commands read and how they ask; tests replace them.
var (
	stdin      io.Reader = os.Stdin
	stdinIsTTY           = func() bool { return term.IsTerminal(int(os.Stdin.Fd())) }
	clock                = time.Now
	actor                = currentActor
)

// currentActor names the OS user running hop-server, for the audit trail.
// It is only as honest as the people who can write the data directory.
func currentActor() string {
	s := fmt.Sprintf("uid %d", os.Getuid())
	if u, err := user.Current(); err == nil && u.Username != "" {
		s = u.Username + " (" + s + ")"
	}
	if su := os.Getenv("SUDO_USER"); su != "" {
		s += " via sudo from " + su
	}
	return s
}

func operator() server.Operator { return server.Operator{Actor: actor(), Now: clock().UTC()} }

// esc makes text from the database safe to print on a terminal. Invalid
// UTF-8, control characters (C0 including tab and newline, DEL, C1),
// Unicode format characters such as bidi overrides, and the line and
// paragraph separators become \xNN, \uNNNN or \UNNNNNNNN escapes, and a
// backslash is doubled, so an escape in the output always came from esc.
// Emails, device names and the audit actor all pass through it.
func esc(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); {
		c, n := utf8.DecodeRuneInString(s[i:])
		switch {
		case c == utf8.RuneError && n == 1:
			fmt.Fprintf(&b, `\x%02x`, s[i])
		case c == '\\':
			b.WriteString(`\\`)
		case unsafeRune(c):
			switch {
			case c < 0x100:
				fmt.Fprintf(&b, `\x%02x`, c)
			case c <= 0xffff:
				fmt.Fprintf(&b, `\u%04x`, c)
			default:
				fmt.Fprintf(&b, `\U%08x`, c)
			}
		default:
			b.WriteRune(c)
		}
		i += n
	}
	return b.String()
}

func unsafeRune(c rune) bool {
	return c < ' ' || c == 0x7f || (c >= 0x80 && c < 0xa0) || c == '\u2028' || c == '\u2029' || unicode.Is(unicode.Cf, c)
}

// writeJSON prints v as indented JSON. encoding/json escapes C0 controls
// and the line separators; format characters, DEL and C1 are escaped here
// as \uXXXX, so values reach a script intact and stay inert on a terminal.
func writeJSON(w io.Writer, v any) error {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	_, err = w.Write(append(escapeJSONControls(b), '\n'))
	return err
}

func escapeJSONControls(b []byte) []byte {
	unsafe := func(c rune) bool { return c >= ' ' && unsafeRune(c) }
	if !bytes.ContainsFunc(b, unsafe) {
		return b
	}
	var out bytes.Buffer
	for _, c := range string(b) {
		switch {
		case !unsafe(c):
			out.WriteRune(c)
		case c > 0xffff:
			hi, lo := utf16.EncodeRune(c)
			fmt.Fprintf(&out, `\u%04x\u%04x`, hi, lo)
		default:
			fmt.Fprintf(&out, `\u%04x`, c)
		}
	}
	return out.Bytes()
}

// confirm asks on a terminal whether to go ahead. Without a terminal it
// refuses unless yes is set.
func confirm(stderr io.Writer, yes bool, question string) error {
	if yes {
		return nil
	}
	if !stdinIsTTY() {
		return errors.New("not changing anything without a terminal to confirm on: give --yes, or --dry-run to only see the change")
	}
	fmt.Fprintf(stderr, "%s [y/N] ", question)
	line, _ := bufio.NewReader(stdin).ReadString('\n')
	if a := strings.ToLower(strings.TrimSpace(line)); a == "y" || a == "yes" {
		return nil
	}
	return errors.New("cancelled; nothing changed")
}

// auditJSON is an audit row as JSON, for audit --json and the stderr line.
type auditJSON struct {
	ID        int64           `json:"id"`
	At        time.Time       `json:"at"`
	Actor     string          `json:"actor"`
	Action    string          `json:"action"`
	AccountID *model.ID       `json:"account_id"`
	Params    json.RawMessage `json:"params"`
	Result    string          `json:"result"`
}

func auditOf(e *server.AuditEntry) auditJSON {
	params := json.RawMessage(e.Params)
	if !json.Valid(params) {
		params, _ = json.Marshal(string(e.Params))
	}
	return auditJSON{ID: e.ID, At: e.At, Actor: e.Actor, Action: e.Action, AccountID: e.AccountID, Params: params, Result: e.Result}
}

// printAudit writes the audit row a change wrote to stderr, as one line.
func printAudit(stderr io.Writer, e *server.AuditEntry) {
	if e == nil {
		return
	}
	b, err := json.Marshal(map[string]auditJSON{"admin_audit": auditOf(e)})
	if err != nil {
		return
	}
	fmt.Fprintf(stderr, "%s\n", escapeJSONControls(b))
}

// --- formatting ---

func when(t time.Time) string {
	if t.IsZero() {
		return "never"
	}
	return t.UTC().Format("2006-01-02 15:04Z")
}

func timeOrNil(t time.Time) *time.Time {
	if t.IsZero() {
		return nil
	}
	u := t.UTC()
	return &u
}

func seqOrNil(seq int64) *int64 {
	if seq < 0 {
		return nil
	}
	return &seq
}

func seqText(seq int64) string {
	if seq < 0 {
		return "none"
	}
	return strconv.FormatInt(seq, 10)
}

// size is n bytes in binary units, for people.
func size(n int64) string {
	if n < 1024 {
		return fmt.Sprintf("%d B", n)
	}
	v, unit := float64(n), ""
	for _, u := range []string{"KiB", "MiB", "GiB", "TiB"} {
		v, unit = v/1024, u
		if v < 1024 {
			break
		}
	}
	return fmt.Sprintf("%.1f %s", v, unit)
}

func quotaText(n int64) string {
	if n == 0 {
		return "default"
	}
	return size(n)
}

func plural(n int, one, many string) string {
	if n == 1 {
		return "1 " + one
	}
	return fmt.Sprintf("%d %s", n, many)
}

func table(w io.Writer) *tabwriter.Writer { return tabwriter.NewWriter(w, 0, 0, 2, ' ', 0) }

// --- accounts ---

func accounts(args []string, stdout io.Writer) error {
	if len(args) == 0 {
		return errors.New("usage: hop-server accounts ls|show")
	}
	switch args[0] {
	case "ls":
		return accountsLs(args[1:], stdout)
	case "show":
		return accountsShow(args[1:], stdout)
	}
	return fmt.Errorf("unknown accounts command %q", args[0])
}

type accountJSON struct {
	AccountID         model.ID   `json:"account_id"`
	Email             string     `json:"email"`
	VaultID           model.ID   `json:"vault_id"`
	CreatedAt         time.Time  `json:"created_at"`
	UsedBytes         int64      `json:"used_bytes"`
	QuotaBytes        int64      `json:"quota_bytes"` // 0: the server default
	Reserve           string     `json:"reserve"`
	ActiveDevices     int        `json:"active_devices"`
	Devices           int        `json:"devices"`
	LastSeen          *time.Time `json:"last_seen"`
	HeadSeq           uint64     `json:"head_seq"`
	LastBootstrapSeq  *int64     `json:"last_bootstrap_seq"`
	LastCheckpointSeq *int64     `json:"last_checkpoint_seq"`
}

func accountOf(a *server.AccountSummary) accountJSON {
	return accountJSON{
		AccountID: a.ID, Email: a.Email, VaultID: a.VaultID, CreatedAt: a.CreatedAt, UsedBytes: a.UsedBytes,
		QuotaBytes: a.QuotaBytes, Reserve: a.Reserve.String(), ActiveDevices: a.ActiveDevices, Devices: a.AllDevices,
		LastSeen: timeOrNil(a.LastSeen), HeadSeq: a.HeadSeq,
		LastBootstrapSeq: seqOrNil(a.LastBootstrap), LastCheckpointSeq: seqOrNil(a.LastCheckpoint),
	}
}

func accountsLs(args []string, stdout io.Writer) error {
	fs := flag.NewFlagSet("accounts ls", flag.ContinueOnError)
	data := fs.String("data", "", "data directory")
	asJSON := fs.Bool("json", false, "print JSON")
	pos, err := parse(fs, args)
	if err != nil {
		return err
	}
	if len(pos) != 0 {
		return errors.New("usage: hop-server accounts ls [--json] --data DIR")
	}
	st, err := openStore(*data)
	if err != nil {
		return err
	}
	defer st.Close()
	list, err := server.ListAccounts(context.Background(), st)
	if err != nil {
		return err
	}
	if *asJSON {
		out := struct {
			Accounts []accountJSON `json:"accounts"`
		}{[]accountJSON{}}
		for _, a := range list {
			out.Accounts = append(out.Accounts, accountOf(a))
		}
		return writeJSON(stdout, out)
	}
	if len(list) == 0 {
		fmt.Fprintln(stdout, "no accounts")
		return nil
	}
	tw := table(stdout)
	fmt.Fprintln(tw, "ACCOUNT\tEMAIL\tCREATED\tUSED\tQUOTA\tRESERVE\tDEVICES\tLAST SEEN\tHEAD\tCHECKPOINT")
	for _, a := range list {
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\t%d/%d\t%s\t%d\t%s\n", a.ID, esc(a.Email), when(a.CreatedAt),
			size(a.UsedBytes), quotaText(a.QuotaBytes), a.Reserve, a.ActiveDevices, a.AllDevices, when(a.LastSeen),
			a.HeadSeq, seqText(a.LastCheckpoint))
	}
	if err := tw.Flush(); err != nil {
		return err
	}
	fmt.Fprintln(stdout, "DEVICES is active/all. A quota of default is the server's --quota-mib.")
	return nil
}

type deviceJSON struct {
	DeviceID    model.ID   `json:"device_id"`
	Name        string     `json:"name"`
	Active      bool       `json:"active"`
	AddedSeq    uint64     `json:"added_seq"`
	DepartedHow string     `json:"departed_how,omitempty"` // retired or revoked
	DepartedSeq *uint64    `json:"departed_seq,omitempty"`
	LastSeen    *time.Time `json:"last_seen"`
	Sessions    int        `json:"sessions"`
}

type accountDetailJSON struct {
	accountJSON
	ReserveBytes int64        `json:"reserve_bytes"`
	Sessions     int          `json:"sessions"`
	LoginTokens  int          `json:"login_tokens"`
	Enrollments  int          `json:"enrollments"`
	DeviceList   []deviceJSON `json:"device_list"`
	Invites      []inviteJSON `json:"pending_invites"`
}

func deviceState(d *server.DeviceDetail) string {
	switch {
	case d.Active:
		return "active"
	case d.DepartedHow != "":
		return fmt.Sprintf("%s at seq %d", d.DepartedHow, d.DepartedSeq)
	}
	return "departed"
}

func accountsShow(args []string, stdout io.Writer) error {
	fs := flag.NewFlagSet("accounts show", flag.ContinueOnError)
	data := fs.String("data", "", "data directory")
	asJSON := fs.Bool("json", false, "print JSON")
	pos, err := parse(fs, args)
	if err != nil {
		return err
	}
	if len(pos) != 1 {
		return errors.New("usage: hop-server accounts show ACCOUNT_ID|EMAIL [--json] --data DIR")
	}
	st, err := openStore(*data)
	if err != nil {
		return err
	}
	defer st.Close()
	now := clock().UTC()
	d, err := server.ShowAccount(context.Background(), st, pos[0], now)
	if err != nil {
		return err
	}
	if *asJSON {
		out := accountDetailJSON{
			accountJSON: accountOf(&d.AccountSummary), ReserveBytes: d.ReserveBytes, Sessions: d.Sessions,
			LoginTokens: d.LoginTokens, Enrollments: d.Enrollments, DeviceList: []deviceJSON{}, Invites: []inviteJSON{},
		}
		for _, dev := range d.Devices {
			j := deviceJSON{
				DeviceID: dev.ID, Name: dev.Name, Active: dev.Active, AddedSeq: dev.AddedSeq,
				DepartedHow: string(dev.DepartedHow), LastSeen: timeOrNil(dev.LastSeen), Sessions: dev.Sessions,
			}
			if dev.DepartedHow != "" {
				j.DepartedSeq = &dev.DepartedSeq
			}
			out.DeviceList = append(out.DeviceList, j)
		}
		for _, inv := range d.Invites {
			out.Invites = append(out.Invites, inviteOf(inv, now))
		}
		return writeJSON(stdout, struct {
			Account accountDetailJSON `json:"account"`
		}{out})
	}
	tw := table(stdout)
	fmt.Fprintf(tw, "account\t%s\n", d.ID)
	fmt.Fprintf(tw, "email\t%s\n", esc(d.Email))
	fmt.Fprintf(tw, "vault\t%s\n", d.VaultID)
	fmt.Fprintf(tw, "created\t%s\n", when(d.CreatedAt))
	quota := quotaText(d.QuotaBytes)
	if d.QuotaBytes == 0 {
		quota = "the server default (--quota-mib)"
	}
	fmt.Fprintf(tw, "storage\t%s used, quota %s\n", size(d.UsedBytes), quota)
	fmt.Fprintf(tw, "reserve\t%s (recovery reserve %s)\n", d.Reserve, size(d.ReserveBytes))
	fmt.Fprintf(tw, "log\thead seq %d, last checkpoint seq %s, last bootstrap seq %s\n", d.HeadSeq, seqText(d.LastCheckpoint), seqText(d.LastBootstrap))
	fmt.Fprintf(tw, "last seen\t%s\n", when(d.LastSeen))
	fmt.Fprintf(tw, "sessions\t%d live\n", d.Sessions)
	fmt.Fprintf(tw, "login tokens\t%d outstanding\n", d.LoginTokens)
	fmt.Fprintf(tw, "enrollments\t%d open\n", d.Enrollments)
	if len(d.Invites) == 0 {
		fmt.Fprintf(tw, "invites\tnone pending\n")
	}
	for _, inv := range d.Invites {
		fmt.Fprintf(tw, "invites\t%s pending, expires %s\n", inv.ID, when(inv.ExpiresAt))
	}
	if err := tw.Flush(); err != nil {
		return err
	}
	fmt.Fprintf(stdout, "\ndevices: %d active, %d in all\n", d.ActiveDevices, d.AllDevices)
	tw = table(stdout)
	fmt.Fprintln(tw, "DEVICE\tSTATE\tADDED\tLAST SEEN\tSESSIONS\tNAME")
	for _, dev := range d.Devices {
		name := esc(dev.Name)
		if dev.Name == "" {
			name = "(unknown)"
		}
		fmt.Fprintf(tw, "%s\t%s\tseq %d\t%s\t%d\t%s\n", dev.ID, deviceState(dev), dev.AddedSeq, when(dev.LastSeen), dev.Sessions, name)
	}
	return tw.Flush()
}

// --- invites ---

func invites(args []string, stdout, stderr io.Writer) error {
	if len(args) == 0 {
		return errors.New("usage: hop-server invites ls|revoke|reissue")
	}
	switch args[0] {
	case "ls":
		return invitesLs(args[1:], stdout)
	case "revoke":
		return invitesRevoke(args[1:], stdout, stderr)
	case "reissue":
		return invitesReissue(args[1:], stdout, stderr)
	}
	return fmt.Errorf("unknown invites command %q", args[0])
}

type inviteJSON struct {
	Invite    string     `json:"invite"`
	Email     string     `json:"email"`
	State     string     `json:"state"`
	CreatedAt time.Time  `json:"created_at"`
	ExpiresAt time.Time  `json:"expires_at"`
	UsedAt    *time.Time `json:"used_at,omitempty"`
	AccountID *model.ID  `json:"account_id,omitempty"`
	Code      string     `json:"code,omitempty"` // only when just issued
}

func inviteOf(inv *server.Invite, now time.Time) inviteJSON {
	return inviteJSON{
		Invite: inv.ID, Email: inv.Email, State: string(inv.State(now)), CreatedAt: inv.CreatedAt.UTC(),
		ExpiresAt: inv.ExpiresAt.UTC(), UsedAt: timeOrNil(inv.UsedAt), AccountID: inv.AccountID,
	}
}

func invitesJSON(list []*server.Invite, now time.Time) []inviteJSON {
	out := []inviteJSON{}
	for _, inv := range list {
		out = append(out, inviteOf(inv, now))
	}
	return out
}

func printInvites(w io.Writer, list []*server.Invite, now time.Time) error {
	tw := table(w)
	fmt.Fprintln(tw, "INVITE\tEMAIL\tSTATE\tCREATED\tEXPIRES\tACCOUNT")
	for _, inv := range list {
		acct := "-"
		if inv.AccountID != nil {
			acct = inv.AccountID.String()
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\n", inv.ID, esc(inv.Email), inv.State(now), when(inv.CreatedAt), when(inv.ExpiresAt), acct)
	}
	return tw.Flush()
}

func invitesLs(args []string, stdout io.Writer) error {
	fs := flag.NewFlagSet("invites ls", flag.ContinueOnError)
	data := fs.String("data", "", "data directory")
	all := fs.Bool("all", false, "also list used and expired invites")
	asJSON := fs.Bool("json", false, "print JSON")
	pos, err := parse(fs, args)
	if err != nil {
		return err
	}
	if len(pos) != 0 {
		return errors.New("usage: hop-server invites ls [--all] [--json] --data DIR")
	}
	st, err := openStore(*data)
	if err != nil {
		return err
	}
	defer st.Close()
	now := clock().UTC()
	list, err := server.ListInvites(context.Background(), st, *all, now)
	if err != nil {
		return err
	}
	if *asJSON {
		return writeJSON(stdout, struct {
			Invites []inviteJSON `json:"invites"`
		}{invitesJSON(list, now)})
	}
	if len(list) == 0 {
		if *all {
			fmt.Fprintln(stdout, "no invites")
		} else {
			fmt.Fprintln(stdout, "no pending invites")
		}
		return nil
	}
	return printInvites(stdout, list, now)
}

// changeFlags are the flags of every command that changes state.
type changeFlags struct {
	data   *string
	asJSON *bool
	dryRun *bool
	yes    *bool
}

func newChangeFlags(fs *flag.FlagSet) changeFlags {
	return changeFlags{
		data:   fs.String("data", "", "data directory"),
		asJSON: fs.Bool("json", false, "print JSON"),
		dryRun: fs.Bool("dry-run", false, "show what would change and change nothing"),
		yes:    fs.Bool("yes", false, "go ahead without asking"),
	}
}

func invitesRevoke(args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("invites revoke", flag.ContinueOnError)
	f := newChangeFlags(fs)
	pos, err := parse(fs, args)
	if err != nil {
		return err
	}
	if len(pos) != 1 {
		return errors.New("usage: hop-server invites revoke INVITE|EMAIL [--dry-run] [--yes] [--json] --data DIR")
	}
	st, err := openStore(*f.data)
	if err != nil {
		return err
	}
	defer st.Close()
	ctx := context.Background()
	now := clock().UTC()
	plan, err := server.PlanRevokeInvites(ctx, st, pos[0], now)
	if err != nil {
		return err
	}
	if *f.asJSON && *f.dryRun {
		return writeJSON(stdout, struct {
			DryRun bool         `json:"dry_run"`
			Revoke []inviteJSON `json:"revoke"`
		}{true, invitesJSON(plan, now)})
	}
	if !*f.asJSON {
		fmt.Fprintf(stdout, "would revoke %s:\n", plural(len(plan), "invite", "invites"))
		if err := printInvites(stdout, plan, now); err != nil {
			return err
		}
		if *f.dryRun {
			fmt.Fprintln(stdout, "dry run: nothing changed")
			return nil
		}
	}
	if err := confirm(stderr, *f.yes, fmt.Sprintf("Revoke %s?", plural(len(plan), "invite", "invites"))); err != nil {
		return err
	}
	op := operator()
	entry, err := server.RevokeInvites(ctx, st, op, pos[0], plan)
	printAudit(stderr, entry)
	if err != nil {
		return err
	}
	for _, inv := range plan {
		inv.ExpiresAt = op.Now
	}
	if *f.asJSON {
		return writeJSON(stdout, struct {
			Revoked []inviteJSON `json:"revoked"`
			Audit   int64        `json:"audit_id"`
		}{invitesJSON(plan, op.Now), entry.ID})
	}
	fmt.Fprintf(stdout, "revoked %s; a revoked code gets the same answer as a wrong one\n", plural(len(plan), "invite", "invites"))
	return nil
}

func invitesReissue(args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("invites reissue", flag.ContinueOnError)
	f := newChangeFlags(fs)
	ttlText := fs.String("ttl", "7d", "how long the new code is valid: Nd, or a Go duration such as 36h")
	pos, err := parse(fs, args)
	if err != nil {
		return err
	}
	if len(pos) != 1 {
		return errors.New("usage: hop-server invites reissue EMAIL [--ttl 7d] [--dry-run] [--yes] [--json] --data DIR")
	}
	ttl, err := parseTTL(*ttlText)
	if err != nil {
		return err
	}
	st, err := openStore(*f.data)
	if err != nil {
		return err
	}
	defer st.Close()
	ctx := context.Background()
	now := clock().UTC()
	norm, plan, err := server.PlanReissueInvite(ctx, st, pos[0], now)
	if err != nil {
		return err
	}
	if *f.asJSON && *f.dryRun {
		return writeJSON(stdout, struct {
			DryRun    bool         `json:"dry_run"`
			Revoke    []inviteJSON `json:"revoke"`
			Email     string       `json:"email"`
			ExpiresAt time.Time    `json:"expires_at"`
		}{true, invitesJSON(plan, now), norm, now.Add(ttl)})
	}
	if !*f.asJSON {
		if len(plan) > 0 {
			fmt.Fprintf(stdout, "would revoke %s:\n", plural(len(plan), "pending invite", "pending invites"))
			if err := printInvites(stdout, plan, now); err != nil {
				return err
			}
		}
		fmt.Fprintf(stdout, "would issue a new invite for %s, valid until %s\n", esc(norm), when(now.Add(ttl)))
		if *f.dryRun {
			fmt.Fprintln(stdout, "dry run: nothing changed")
			return nil
		}
	}
	q := fmt.Sprintf("Issue a new invite for %s?", esc(norm))
	if len(plan) > 0 {
		q = fmt.Sprintf("Revoke %s and issue a new invite for %s?", plural(len(plan), "invite", "invites"), esc(norm))
	}
	if err := confirm(stderr, *f.yes, q); err != nil {
		return err
	}
	op := operator()
	inv, entry, err := server.ReissueInvite(ctx, st, op, norm, ttl, plan)
	printAudit(stderr, entry)
	if err != nil {
		return err
	}
	for _, inv := range plan {
		inv.ExpiresAt = op.Now
	}
	if *f.asJSON {
		j := inviteOf(&inv.Invite, op.Now)
		j.Code = inv.Code
		return writeJSON(stdout, struct {
			Revoked []inviteJSON `json:"revoked"`
			Invite  inviteJSON   `json:"invite"`
			Audit   int64        `json:"audit_id"`
		}{invitesJSON(plan, op.Now), j, entry.ID})
	}
	if len(plan) > 0 {
		fmt.Fprintf(stdout, "revoked %s\n", plural(len(plan), "invite", "invites"))
	}
	fmt.Fprintf(stdout, "new invite %s for %s, valid until %s. Its code, shown only now:\n%s\n",
		inv.ID, esc(inv.Email), when(inv.ExpiresAt), inv.Code)
	return nil
}

// --- audit ---

func audit(args []string, stdout io.Writer) error {
	fs := flag.NewFlagSet("audit", flag.ContinueOnError)
	data := fs.String("data", "", "data directory")
	account := fs.String("account", "", "only this account (ID, or the email of an existing account)")
	sinceText := fs.String("since", "", "only rows from this time on: Nd, a Go duration such as 36h, YYYY-MM-DD or RFC 3339")
	asJSON := fs.Bool("json", false, "print JSON")
	pos, err := parse(fs, args)
	if err != nil {
		return err
	}
	if len(pos) != 0 {
		return errors.New("usage: hop-server audit [--account ACCOUNT_ID|EMAIL] [--since T] [--json] --data DIR")
	}
	var f server.AuditFilter
	if *sinceText != "" {
		if f.Since, err = parseSince(*sinceText, clock()); err != nil {
			return err
		}
	}
	st, err := openStore(*data)
	if err != nil {
		return err
	}
	defer st.Close()
	ctx := context.Background()
	if *account != "" {
		var id model.ID
		if err := id.UnmarshalText([]byte(*account)); err == nil && len(*account) == 2*len(id) && !id.IsZero() {
			f.AccountID = &id // an ID filters even after its account is gone
		} else if id, err = server.ResolveAccount(ctx, st, *account); err != nil {
			return err
		} else {
			f.AccountID = &id
		}
	}
	rows, err := server.AuditLog(ctx, st, f)
	if err != nil {
		return err
	}
	if *asJSON {
		out := struct {
			Audit []auditJSON `json:"audit"`
		}{[]auditJSON{}}
		for _, e := range rows {
			out.Audit = append(out.Audit, auditOf(e))
		}
		return writeJSON(stdout, out)
	}
	if len(rows) == 0 {
		fmt.Fprintln(stdout, "no audit entries")
		return nil
	}
	tw := table(stdout)
	fmt.Fprintln(tw, "ID\tAT\tACTOR\tACTION\tACCOUNT\tRESULT\tPARAMS")
	for _, e := range rows {
		acct := "-"
		if e.AccountID != nil {
			acct = e.AccountID.String()
		}
		fmt.Fprintf(tw, "%d\t%s\t%s\t%s\t%s\t%s\t%s\n", e.ID, when(e.At), esc(e.Actor), esc(e.Action), acct, esc(e.Result), esc(string(e.Params)))
	}
	return tw.Flush()
}

// parseSince reads --since: a duration back from now, or a date or time.
func parseSince(s string, now time.Time) (time.Time, error) {
	if d, err := parseTTL(s); err == nil {
		return now.Add(-d), nil
	}
	if t, err := time.Parse(time.RFC3339, s); err == nil {
		return t, nil
	}
	if t, err := time.Parse(time.DateOnly, s); err == nil {
		return t, nil
	}
	return time.Time{}, fmt.Errorf("--since %q: want Nd, a duration such as 36h, YYYY-MM-DD or an RFC 3339 time", s)
}
