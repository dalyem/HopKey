package server

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/dalyem/hopkey/internal/canonjson"
	"github.com/dalyem/hopkey/internal/crypto"
	"github.com/dalyem/hopkey/internal/email"
	"github.com/dalyem/hopkey/internal/model"
	"github.com/dalyem/hopkey/internal/vaultlog"
)

// Server administration: what the hop-server accounts, invites and audit
// commands read and change. An admin is whoever can open the database file;
// these functions run in that process, not in serve, so nothing here
// reaches the running server's memory.

// Audit actions. Every admin change writes one admin_audit row with its
// action, in the transaction that makes the change.
const (
	ActionInviteCreate  = "invites.create"
	ActionInviteRevoke  = "invites.revoke"
	ActionInviteReissue = "invites.reissue"
	ActionQuota         = "accounts.quota"
)

// Operator is who runs an admin command, and when.
type Operator struct {
	Actor string // the OS user of the hop-server process
	Now   time.Time
}

// AuditEntry is one row of the admin audit trail. Params is the JCS of the
// command's arguments; it never holds a code or other secret. Result is
// "ok" or the AdminError code of a change that failed.
type AuditEntry struct {
	ID        int64
	At        time.Time
	Actor     string
	Action    string
	AccountID *model.ID
	Params    []byte
	Result    string
}

// AuditFilter selects audit rows: at or after Since, and only one account's
// when AccountID is set.
type AuditFilter struct {
	AccountID *model.ID
	Since     time.Time
}

// AdminError is an admin command refusing. Code is what the audit trail
// records for it.
type AdminError struct {
	Code string
	Msg  string
}

func (e *AdminError) Error() string { return "server: " + e.Msg }

func adminErr(code, format string, args ...any) error {
	return &AdminError{Code: code, Msg: fmt.Sprintf(format, args...)}
}

// auditResult is the result column for a failed change.
func auditResult(err error) string {
	var ae *AdminError
	if errors.As(err, &ae) {
		return ae.Code
	}
	return "error"
}

// change runs fn and writes its audit row in one write transaction. params
// is marshaled after fn returns, so fn may fill it in. When fn fails, the
// change rolls back and a row with the failure is written on its own. The
// returned entry is the row written, if any.
func (op Operator) change(ctx context.Context, st Store, action string, account *model.ID, params any, fn func(Tx) (*model.ID, error)) (*AuditEntry, error) {
	if op.Actor == "" {
		return nil, errors.New("server: an admin change needs an actor")
	}
	entry := &AuditEntry{At: op.Now, Actor: op.Actor, Action: action, AccountID: account, Result: "ok"}
	err := st.Update(ctx, func(tx Tx) error {
		acct, err := fn(tx)
		if err != nil {
			return err
		}
		if acct != nil {
			entry.AccountID = acct
		}
		if entry.Params, err = canonjson.Marshal(params); err != nil {
			return err
		}
		return tx.InsertAudit(entry)
	})
	if err == nil {
		return entry, nil
	}
	entry.ID, entry.Result = 0, auditResult(err)
	p, perr := canonjson.Marshal(params)
	if perr != nil {
		return nil, err
	}
	entry.Params = p
	if aerr := st.Update(ctx, func(tx Tx) error { return tx.InsertAudit(entry) }); aerr != nil {
		return nil, errors.Join(err, fmt.Errorf("server: recording the failure in the audit trail: %w", aerr))
	}
	return entry, err
}

// AuditLog returns the audit rows the filter selects, oldest first.
func AuditLog(ctx context.Context, st Store, f AuditFilter) ([]*AuditEntry, error) {
	var out []*AuditEntry
	err := st.View(ctx, func(tx Tx) error {
		var err error
		out, err = tx.AuditEntries(f)
		return err
	})
	return out, err
}

// ResolveAccount returns the ID of the account who names, an account ID or
// an email.
func ResolveAccount(ctx context.Context, st Store, who string) (model.ID, error) {
	var id model.ID
	err := st.View(ctx, func(tx Tx) error {
		a, err := findAccount(tx, who)
		if err == nil {
			id = a.ID
		}
		return err
	})
	return id, err
}

// --- accounts ---

// AccountSummary is one account as hop-server accounts ls shows it. It
// holds no verifier.
type AccountSummary struct {
	ID         model.ID
	Email      string
	VaultID    model.ID
	UsedBytes  int64
	QuotaBytes int64 // 0: the server default
	Reserve    ReserveState
	CreatedAt  time.Time
	// The vault head and the seqs of the latest bootstrap and checkpoint
	// (-1: none).
	HeadSeq        uint64
	LastBootstrap  int64
	LastCheckpoint int64
	ActiveDevices  int
	AllDevices     int       // every device the account has had
	LastSeen       time.Time // the latest of its devices; zero when none was seen
	Disabled       *AdminBlock
}

// ListAccounts returns every account, oldest first.
func ListAccounts(ctx context.Context, st Store) ([]*AccountSummary, error) {
	var out []*AccountSummary
	err := st.View(ctx, func(tx Tx) error {
		var err error
		out, err = tx.AccountSummaries(nil)
		return err
	})
	return out, err
}

// AccountDetail is one account as hop-server accounts show shows it.
type AccountDetail struct {
	AccountSummary
	ReserveBytes int64 // the whole recovery reserve under the default limits
	Devices      []*DeviceDetail
	Sessions     int // unexpired sessions, all devices
	LoginTokens  int // unexpired login and recovery tokens
	Enrollments  int // unexpired enrollment mailboxes the account claimed
	Invites      []*Invite
}

// DeviceDetail is one device of an account.
type DeviceDetail struct {
	ID       model.ID
	Name     string // from its certificate; "" when it cannot be read
	Active   bool
	AddedSeq uint64
	// How and when it left, for a departed device.
	DepartedHow vaultlog.DepartureKind
	DepartedSeq uint64
	LastSeen    time.Time // zero when never seen
	Sessions    int
	Blocked     *AdminBlock // the operator's block; nil when not blocked
}

// ShowAccount returns the account who names (an ID or an email), its
// devices, credentials in flight and pending invites.
func ShowAccount(ctx context.Context, st Store, who string, now time.Time) (*AccountDetail, error) {
	var out *AccountDetail
	err := st.View(ctx, func(tx Tx) error {
		a, err := findAccount(tx, who)
		if err != nil {
			return err
		}
		sums, err := tx.AccountSummaries(&a.ID)
		if err != nil {
			return err
		}
		if len(sums) != 1 {
			return adminErr("not_found", "no such account")
		}
		d := &AccountDetail{AccountSummary: *sums[0], ReserveBytes: 2 * reserveHalf(DefaultLimits())}
		if d.Devices, err = accountDevices(tx, a, now); err != nil {
			return err
		}
		for _, dev := range d.Devices {
			d.Sessions += dev.Sessions
		}
		if d.LoginTokens, err = tx.CountLoginTokens(a.ID, now); err != nil {
			return err
		}
		if d.Enrollments, err = tx.CountAccountMailboxes(a.ID, now); err != nil {
			return err
		}
		regs, err := tx.Registrations(a.Email)
		if err != nil {
			return err
		}
		for _, r := range regs {
			if inv := inviteOf(r); inv.State(now) == InvitePending {
				d.Invites = append(d.Invites, inv)
			}
		}
		out = d
		return nil
	})
	return out, err
}

func accountDevices(tx Tx, a *Account, now time.Time) ([]*DeviceDetail, error) {
	devs, err := tx.Devices(a.ID)
	if err != nil {
		return nil, err
	}
	seen, err := tx.DevicesSeen(a.ID)
	if err != nil {
		return nil, err
	}
	sessions, err := tx.LiveSessions(a.ID, now)
	if err != nil {
		return nil, err
	}
	blocks, err := tx.DeviceBlocks(a.ID)
	if err != nil {
		return nil, err
	}
	var ps *vaultlog.PublicState
	if v, err := tx.Vault(a.VaultID); err == nil {
		ps, _ = vaultlog.ParsePublicState(v.PublicState)
	} else if !errors.Is(err, ErrNotFound) {
		return nil, err
	}
	var out []*DeviceDetail
	for _, dev := range devs {
		d := &DeviceDetail{
			ID: dev.DeviceID, Active: dev.Active, AddedSeq: dev.AddedSeq,
			LastSeen: seen[dev.DeviceID], Sessions: sessions[dev.DeviceID], Blocked: blocks[dev.DeviceID],
		}
		if d.Name, err = deviceName(tx, a.VaultID, ps, dev); err != nil {
			return nil, err
		}
		if !dev.Active {
			r, err := tx.Receipt(a.ID, dev.DeviceID)
			switch {
			case err == nil:
				d.DepartedHow, d.DepartedSeq = r.How, r.Seq
			case !errors.Is(err, ErrNotFound):
				return nil, err
			}
		}
		out = append(out, d)
	}
	return out, nil
}

// deviceName is the name in a device's certificate: the current one for an
// active device, else the one in the device_add that first added it. It is
// "" when neither can be read; a damaged row does not hide the others.
func deviceName(tx Tx, vaultID model.ID, ps *vaultlog.PublicState, dev *Device) (string, error) {
	if op, ok := ps.Device(dev.DeviceID); ok {
		return op.Cert.Name, nil
	}
	e, err := tx.Entry(vaultID, dev.AddedSeq)
	if errors.Is(err, ErrNotFound) {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	w, err := vaultlog.ParseWire(e.Wire)
	if err != nil {
		return "", nil
	}
	for _, o := range w.Entry.Ops {
		if add, ok := o.(*vaultlog.DeviceAddOp); ok && add.Cert.DeviceID == dev.DeviceID {
			return add.Cert.Name, nil
		}
	}
	return "", nil
}

// --- invites ---

// InviteState is where an invite is in its life.
type InviteState string

const (
	InvitePending InviteState = "pending" // unused and unexpired
	InviteUsed    InviteState = "used"
	InviteExpired InviteState = "expired" // includes revoked
)

// Invite is a registration capability as the operator sees it. Its code is
// never stored, so it can never be shown again.
type Invite struct {
	ID        string // InviteID of the capability hash
	CapHash   crypto.Hash
	Email     string
	CreatedAt time.Time
	ExpiresAt time.Time
	UsedAt    time.Time // zero while unused
	AccountID *model.ID // the account it created, once used
}

// State reports the invite's state at now.
func (i *Invite) State(now time.Time) InviteState {
	switch {
	case i.AccountID != nil:
		return InviteUsed
	case !now.Before(i.ExpiresAt):
		return InviteExpired
	}
	return InvitePending
}

// inviteIDLen is how many hex digits of the capability hash name an
// invite. The hash is of a 256-bit random code, so it reveals nothing
// about the code.
const inviteIDLen = 12

// minInvitePrefix is the shortest invite ID prefix revoke accepts.
const minInvitePrefix = 8

// InviteID names an invite by the start of its capability hash.
func InviteID(h crypto.Hash) string { return hex.EncodeToString(h[:])[:inviteIDLen] }

func inviteOf(r *Registration) *Invite {
	inv := &Invite{ID: InviteID(r.CapHash), CapHash: r.CapHash, Email: r.Email, CreatedAt: r.CreatedAt, ExpiresAt: r.ExpiresAt}
	if r.Ack != nil {
		id := r.Ack.AccountID
		inv.UsedAt, inv.AccountID = r.ConsumedAt, &id
	}
	return inv
}

// ListInvites returns the pending invites, or every invite when all is set,
// oldest first.
func ListInvites(ctx context.Context, st Store, all bool, now time.Time) ([]*Invite, error) {
	var out []*Invite
	err := st.View(ctx, func(tx Tx) error {
		regs, err := tx.Registrations("")
		if err != nil {
			return err
		}
		for _, r := range regs {
			if inv := inviteOf(r); all || inv.State(now) == InvitePending {
				out = append(out, inv)
			}
		}
		return nil
	})
	return out, err
}

// pendingInvites returns the pending invites for a normalized email.
func pendingInvites(tx Tx, norm string, now time.Time) ([]*Invite, error) {
	regs, err := tx.Registrations(norm)
	if err != nil {
		return nil, err
	}
	var out []*Invite
	for _, r := range regs {
		if inv := inviteOf(r); inv.State(now) == InvitePending {
			out = append(out, inv)
		}
	}
	return out, nil
}

// inviteSelector is what invites revoke was given: an email, or the start
// of an invite ID.
type inviteSelector struct {
	email  string // normalized, when by email
	prefix string // lower-case hex, when by invite ID
}

// parseInviteSelector reads an email (it holds an @) or an invite ID or a
// prefix of one of at least 8 hex digits.
func parseInviteSelector(sel string) (inviteSelector, error) {
	if strings.Contains(sel, "@") {
		norm, err := email.Normalize(sel)
		if err != nil {
			return inviteSelector{}, adminErr("invalid", "not an email or an invite ID")
		}
		return inviteSelector{email: norm}, nil
	}
	prefix := strings.ToLower(sel)
	notHex := func(c rune) bool { return !strings.ContainsRune("0123456789abcdef", c) }
	if len(prefix) < minInvitePrefix || len(prefix) > 2*len(crypto.Hash{}) || strings.ContainsFunc(prefix, notHex) {
		return inviteSelector{}, adminErr("invalid", "not an email or an invite ID (at least %d hex digits)", minInvitePrefix)
	}
	return inviteSelector{prefix: prefix}, nil
}

// idText is an invite ID prefix as messages show it: at most the 12 digits
// of an invite ID, so a longer prefix of the capability hash is never
// printed.
func idText(prefix string) string {
	if len(prefix) > inviteIDLen {
		return prefix[:inviteIDLen] + "..."
	}
	return prefix
}

// selectInvites returns the pending invites s names: every pending invite
// for its email, or the one invite its prefix names. It refuses when s
// names nothing pending.
func selectInvites(tx Tx, s inviteSelector, now time.Time) ([]*Invite, error) {
	if s.email != "" {
		out, err := pendingInvites(tx, s.email, now)
		if err == nil && len(out) == 0 {
			err = adminErr("not_found", "no pending invite for %s", s.email)
		}
		return out, err
	}
	regs, err := tx.Registrations("")
	if err != nil {
		return nil, err
	}
	var match []*Invite
	for _, r := range regs {
		if strings.HasPrefix(hex.EncodeToString(r.CapHash[:]), s.prefix) {
			match = append(match, inviteOf(r))
		}
	}
	switch {
	case len(match) == 0:
		return nil, adminErr("not_found", "no invite %s", idText(s.prefix))
	case len(match) > 1:
		return nil, adminErr("ambiguous", "%d invites start with %s; give more digits", len(match), idText(s.prefix))
	}
	switch inv := match[0]; inv.State(now) {
	case InviteUsed:
		return nil, adminErr("used", "invite %s was used; a used invite stays for the signup acknowledgment", inv.ID)
	case InviteExpired:
		return nil, adminErr("expired", "invite %s has already expired", inv.ID)
	}
	return match, nil
}

// PlanRevokeInvites returns the invites RevokeInvites would end for sel: an
// email (every pending invite for it) or an invite ID or a prefix of one of
// at least 8 hex digits. It changes nothing.
func PlanRevokeInvites(ctx context.Context, st Store, sel string, now time.Time) ([]*Invite, error) {
	s, err := parseInviteSelector(sel)
	if err != nil {
		return nil, err
	}
	var out []*Invite
	err = st.View(ctx, func(tx Tx) error {
		var err error
		out, err = selectInvites(tx, s, now)
		return err
	})
	return out, err
}

// sameInvites reports whether got are the invites in want.
func sameInvites(got, want []*Invite) bool {
	return slices.EqualFunc(got, want, func(a, b *Invite) bool { return a.CapHash == b.CapHash })
}

// expireInvites ends the invites in got, once they are checked to be the
// ones the operator confirmed.
func expireInvites(tx Tx, got, want []*Invite, now time.Time) error {
	if !sameInvites(got, want) {
		return adminErr("changed", "the invites changed since they were listed; run the command again")
	}
	for _, inv := range got {
		if err := tx.ExpireRegistration(inv.CapHash, now); err != nil {
			return err
		}
	}
	return nil
}

// The audit params of invites revoke name the selector by kind and email,
// never by the digits given: a selector can be the whole capability hash,
// and the trail keeps no more of it than the 12-digit IDs of the invites
// it resolved to.
type revokeByEmail struct {
	By      string   `json:"by"` // "email"
	Email   string   `json:"email"`
	Invites []string `json:"invites"`
}

type revokeByID struct {
	By      string   `json:"by"` // "id"
	Invites []string `json:"invites"`
}

// RevokeInvites makes the invites PlanRevokeInvites listed as want expire
// now, and writes the audit row. It refuses with "changed" when sel no
// longer selects exactly those invites, also when it now selects none, a
// used or expired one, or several. A used invite is never touched: it
// serves the signup acknowledgment retry (R3). A selector that cannot be
// read is refused before anything is written, as planning refuses it.
func RevokeInvites(ctx context.Context, st Store, op Operator, sel string, want []*Invite) (*AuditEntry, error) {
	s, err := parseInviteSelector(sel)
	if err != nil {
		return nil, err
	}
	var params any = &revokeByID{By: "id", Invites: inviteIDs(want)}
	if s.email != "" {
		params = &revokeByEmail{By: "email", Email: s.email, Invites: inviteIDs(want)}
	}
	return op.change(ctx, st, ActionInviteRevoke, nil, params, func(tx Tx) (*model.ID, error) {
		got, err := selectInvites(tx, s, op.Now)
		var ae *AdminError
		if len(want) > 0 && errors.As(err, &ae) {
			return nil, adminErr("changed", "the invites changed since they were listed (%s); run the command again", ae.Msg)
		}
		if err != nil {
			return nil, err
		}
		return nil, expireInvites(tx, got, want, op.Now)
	})
}

func inviteIDs(invs []*Invite) []string {
	out := []string{}
	for _, inv := range invs {
		out = append(out, inv.ID)
	}
	return out
}

// PlanReissueInvite returns the normalized email and its pending invites,
// which ReissueInvite would end. It changes nothing.
func PlanReissueInvite(ctx context.Context, st Store, addr string, now time.Time) (string, []*Invite, error) {
	norm, err := email.Normalize(addr)
	if err != nil {
		return "", nil, err
	}
	var out []*Invite
	err = st.View(ctx, func(tx Tx) error {
		out, err = pendingInvites(tx, norm, now)
		return err
	})
	return norm, out, err
}

// IssuedInvite is a new invite and its code, which is shown once.
type IssuedInvite struct {
	Invite
	Code string
}

type issueParams struct {
	Email     string   `json:"email"`
	Invite    string   `json:"invite"`
	ExpiresAt int64    `json:"expires_at"`
	Revoked   []string `json:"revoked"`
}

// IssueInvite issues an invite like CreateInvite and writes the audit row
// in the same transaction.
func IssueInvite(ctx context.Context, st Store, op Operator, addr string, ttl time.Duration) (*IssuedInvite, *AuditEntry, error) {
	norm, err := email.Normalize(addr)
	if err != nil {
		return nil, nil, err
	}
	var out *IssuedInvite
	params := &issueParams{Email: norm, Revoked: []string{}}
	entry, err := op.change(ctx, st, ActionInviteCreate, nil, params, func(tx Tx) (*model.ID, error) {
		var err error
		out, err = insertInvite(tx, norm, ttl, op.Now)
		if err == nil {
			params.Invite, params.ExpiresAt = out.ID, out.ExpiresAt.Unix()
		}
		return nil, err
	})
	return out, entry, err
}

// ReissueInvite ends the pending invites PlanReissueInvite listed as want
// and issues a new one for the email, in one transaction with its audit
// row. It refuses when the pending invites changed in between.
func ReissueInvite(ctx context.Context, st Store, op Operator, addr string, ttl time.Duration, want []*Invite) (*IssuedInvite, *AuditEntry, error) {
	norm, err := email.Normalize(addr)
	if err != nil {
		return nil, nil, err
	}
	var out *IssuedInvite
	params := &issueParams{Email: norm, Revoked: inviteIDs(want)}
	entry, err := op.change(ctx, st, ActionInviteReissue, nil, params, func(tx Tx) (*model.ID, error) {
		got, err := pendingInvites(tx, norm, op.Now)
		if err != nil {
			return nil, err
		}
		if err := expireInvites(tx, got, want, op.Now); err != nil {
			return nil, err
		}
		out, err = insertInvite(tx, norm, ttl, op.Now)
		if err == nil {
			params.Invite, params.ExpiresAt = out.ID, out.ExpiresAt.Unix()
		}
		return nil, err
	})
	return out, entry, err
}

// insertInvite stores a new registration capability for a normalized
// email.
func insertInvite(tx Tx, norm string, ttl time.Duration, now time.Time) (*IssuedInvite, error) {
	if ttl <= 0 {
		return nil, errors.New("server: invite TTL must be positive")
	}
	code, h, err := newSecret()
	if err != nil {
		return nil, err
	}
	r := &Registration{CapHash: h, Email: norm, CreatedAt: now, ExpiresAt: now.Add(ttl)}
	if err := tx.InsertRegistration(r); err != nil {
		return nil, err
	}
	return &IssuedInvite{Invite: *inviteOf(r), Code: code}, nil
}
