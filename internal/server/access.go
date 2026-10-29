package server

import (
	"context"
	"errors"
	"net/http"
	"slices"
	"strings"
	"unicode/utf8"

	"github.com/dalyem/hopkey/internal/model"
)

// The operator's access controls: hop-server accounts disable and enable,
// devices block and unblock, and sessions revoke.
//
// Deleting a session forces nothing: an active device signs a new
// challenge and gets another. A disabled account and a blocked device are
// refused that new session, with 403 and a code only a holder of the
// device's key sees, since the signature is checked first. A disabled
// account is also refused login and recovery tokens, after the secret
// matched. Retire-status and retire-post stay open, so a device can finish
// its own logout. Nothing here changes vault data or devices.active, which
// mirrors the signed log: these are reversible access controls, not
// revocations, and the server can make no device wipe itself.

// Refusal codes (R11). The status is 403: never 429 or a 5xx, which a
// client takes for an unreachable server.
const (
	CodeAccountDisabled = "account_disabled"
	CodeDeviceBlocked   = "device_blocked"
)

// Audit actions of the access controls.
const (
	ActionDisable        = "accounts.disable"
	ActionEnable         = "accounts.enable"
	ActionSessionsRevoke = "sessions.revoke"
	ActionDeviceBlock    = "devices.block"
	ActionDeviceUnblock  = "devices.unblock"
)

// MaxReasonBytes bounds an operator's reason, in bytes of UTF-8.
const MaxReasonBytes = 200

// SanitizeReason checks and cleans an operator's reason before it is
// stored: invalid UTF-8 is refused; C0 and C1 control characters, DEL,
// the line and paragraph separators and the Unicode bidi controls
// (overrides, embeddings, isolates and marks) are removed; spaces at
// either end are trimmed; and what is left must be at most MaxReasonBytes.
// "" means no reason. Devices escape it again on display: they can't
// trust a server to have done this.
func SanitizeReason(s string) (string, error) {
	if !utf8.ValidString(s) {
		return "", adminErr("invalid", "the reason is not valid UTF-8")
	}
	s = strings.TrimSpace(strings.Map(func(c rune) rune {
		if reasonDropped(c) {
			return -1
		}
		return c
	}, s))
	if len(s) > MaxReasonBytes {
		return "", adminErr("invalid", "the reason is %d bytes; at most %d are allowed", len(s), MaxReasonBytes)
	}
	return s, nil
}

func reasonDropped(c rune) bool {
	switch {
	case c < ' ', c == 0x7f, c >= 0x80 && c < 0xa0:
		return true
	case c == '\u2028', c == '\u2029':
		return true
	case c == '\u061c', c == '\u200e', c == '\u200f': // ALM, LRM, RLM
		return true
	case c >= '\u202a' && c <= '\u202e': // embeddings and overrides
		return true
	case c >= '\u2066' && c <= '\u2069': // isolates
		return true
	}
	return false
}

// adminRefusalError is an admin refusal: its response, and the
// operator's reason that goes with it.
type adminRefusalError struct {
	api    *apiError
	reason string
}

func (e *adminRefusalError) Error() string { return e.api.Error() }
func (e *adminRefusalError) Unwrap() error { return e.api }

// errAccountDisabled and errDeviceBlocked are the admin refusals.
func errAccountDisabled(b *AdminBlock) error {
	return &adminRefusalError{&apiError{http.StatusForbidden, CodeAccountDisabled, "the server's operator disabled this account", nil}, b.Reason}
}

func errDeviceBlocked(b *AdminBlock) error {
	return &adminRefusalError{&apiError{http.StatusForbidden, CodeDeviceBlocked, "the server's operator blocked this device", nil}, b.Reason}
}

// adminRefusal returns the refusal for an account the operator disabled,
// or, when device is not nil, a device the operator blocked; nil when
// neither. Call it only once the caller proved it holds the device's key
// or the account's secret.
func adminRefusal(tx Tx, accountID model.ID, device *model.ID) error {
	b, err := tx.AccountDisabled(accountID)
	if err != nil {
		return err
	}
	if b != nil {
		return errAccountDisabled(b)
	}
	if device == nil {
		return nil
	}
	blocks, err := tx.DeviceBlocks(accountID)
	if err != nil {
		return err
	}
	if b := blocks[*device]; b != nil {
		return errDeviceBlocked(b)
	}
	return nil
}

// --- planning and changing ---

// AccessPlan is one account's access as an access change found it, and
// what the change will do: the plan the operator confirms, and the
// command's result.
type AccessPlan struct {
	AccountID model.ID
	Email     string
	Disabled  *AdminBlock // the account's disable as it stands
	// Devices are the devices the change acts on: those blocked or
	// unblocked, or the one device whose sessions end.
	Devices []*DeviceDetail
	// Sessions and LoginTokens are the unexpired ones the change deletes.
	Sessions    int
	LoginTokens int
}

// samePlan reports whether got still selects what the operator confirmed
// in want: the same account, its disable as it was, and the same devices
// in the same block state. Session and token counts move on their own and
// are not compared.
func samePlan(got, want *AccessPlan) bool {
	sameBlock := func(a, b *AdminBlock) bool {
		return (a == nil) == (b == nil) && (a == nil || a.At.Equal(b.At) && a.Reason == b.Reason)
	}
	return got.AccountID == want.AccountID && sameBlock(got.Disabled, want.Disabled) &&
		slices.EqualFunc(got.Devices, want.Devices, func(a, b *DeviceDetail) bool {
			return a.ID == b.ID && sameBlock(a.Blocked, b.Blocked)
		})
}

// accessPlan reads the account who names and its sessions and tokens.
func accessPlan(tx Tx, who string, op Operator) (*AccessPlan, *Account, error) {
	a, err := findAccount(tx, who)
	if err != nil {
		return nil, nil, err
	}
	p := &AccessPlan{AccountID: a.ID, Email: a.Email}
	if p.Disabled, err = tx.AccountDisabled(a.ID); err != nil {
		return nil, nil, err
	}
	sessions, err := tx.LiveSessions(a.ID, op.Now)
	if err != nil {
		return nil, nil, err
	}
	for _, n := range sessions {
		p.Sessions += n
	}
	if p.LoginTokens, err = tx.CountLoginTokens(a.ID, op.Now); err != nil {
		return nil, nil, err
	}
	return p, a, nil
}

// view plans in a read transaction.
func view(ctx context.Context, st Store, fn func(Tx) (*AccessPlan, error)) (*AccessPlan, error) {
	var out *AccessPlan
	err := st.View(ctx, func(tx Tx) error {
		var err error
		out, err = fn(tx)
		return err
	})
	return out, err
}

// apply runs an access change and its audit row in one write
// transaction: it plans again, refuses with "changed" when the plan is
// not the one the operator confirmed (want), and then runs fn on it.
func (op Operator) apply(ctx context.Context, st Store, action string, params any, want *AccessPlan,
	plan func(Tx) (*AccessPlan, error), fn func(Tx, *AccessPlan) error) (*AccessPlan, *AuditEntry, error) {
	var out *AccessPlan
	entry, err := op.change(ctx, st, action, &want.AccountID, params, func(tx Tx) (*model.ID, error) {
		got, err := plan(tx)
		var ae *AdminError
		if errors.As(err, &ae) && ae.Code != "invalid" {
			return nil, adminErr("changed", "the account changed since it was shown (%s); run the command again", ae.Msg)
		}
		if err != nil {
			return nil, err
		}
		if !samePlan(got, want) {
			return nil, adminErr("changed", "the account changed since it was shown; run the command again")
		}
		if err := fn(tx, got); err != nil {
			return nil, err
		}
		out = got
		return &got.AccountID, nil
	})
	return out, entry, err
}

// planDisable is what disabling who does: it ends every session and login
// token, and refuses nothing for an account already disabled (its reason
// is replaced, its time kept).
func planDisable(who string, op Operator) func(Tx) (*AccessPlan, error) {
	return func(tx Tx) (*AccessPlan, error) {
		p, _, err := accessPlan(tx, who, op)
		return p, err
	}
}

// PlanDisable returns what DisableAccount would do. It changes nothing.
func PlanDisable(ctx context.Context, st Store, who string, op Operator) (*AccessPlan, error) {
	return view(ctx, st, planDisable(who, op))
}

type disableParams struct {
	Reason      string `json:"reason"`
	WasDisabled bool   `json:"was_disabled"`
	Sessions    int    `json:"sessions"`
	LoginTokens int    `json:"login_tokens"`
}

// DisableAccount disables the account PlanDisable showed as want: its
// sessions and login tokens are deleted, and from then on it is refused
// sessions, login and recovery (account_disabled, with reason). reason
// must be sanitized (SanitizeReason). It refuses with "changed" when the
// account is not as planned.
func DisableAccount(ctx context.Context, st Store, op Operator, who, reason string, want *AccessPlan) (*AccessPlan, *AuditEntry, error) {
	if r, err := SanitizeReason(reason); err != nil || r != reason {
		return nil, nil, adminErr("invalid", "the reason is not sanitized")
	}
	params := &disableParams{Reason: reason, WasDisabled: want.Disabled != nil}
	return op.apply(ctx, st, ActionDisable, params, want, planDisable(who, op), func(tx Tx, p *AccessPlan) error {
		params.Sessions, params.LoginTokens = p.Sessions, p.LoginTokens
		b := &AdminBlock{At: op.Now, Reason: reason}
		if p.Disabled != nil {
			b.At = p.Disabled.At
		}
		if err := tx.SetAccountDisabled(p.AccountID, b); err != nil {
			return err
		}
		if err := tx.DeleteSessions(p.AccountID, nil); err != nil {
			return err
		}
		return tx.DeleteLoginTokens(p.AccountID)
	})
}

func planEnable(who string, op Operator) func(Tx) (*AccessPlan, error) {
	return func(tx Tx) (*AccessPlan, error) {
		p, _, err := accessPlan(tx, who, op)
		if err == nil && p.Disabled == nil {
			err = adminErr("not_disabled", "the account is not disabled")
		}
		return p, err
	}
}

// PlanEnable returns what EnableAccount would do. It refuses an account
// that is not disabled.
func PlanEnable(ctx context.Context, st Store, who string, op Operator) (*AccessPlan, error) {
	return view(ctx, st, planEnable(who, op))
}

type enableParams struct {
	DisabledAt int64 `json:"disabled_at"`
}

// EnableAccount ends the disable PlanEnable showed as want. Devices get
// sessions again; nothing else changes.
func EnableAccount(ctx context.Context, st Store, op Operator, who string, want *AccessPlan) (*AccessPlan, *AuditEntry, error) {
	params := &enableParams{}
	if want.Disabled != nil {
		params.DisabledAt = want.Disabled.At.Unix()
	}
	return op.apply(ctx, st, ActionEnable, params, want, planEnable(who, op), func(tx Tx, p *AccessPlan) error {
		return tx.SetAccountDisabled(p.AccountID, nil)
	})
}

// minDevicePrefix is the shortest device ID prefix the device commands
// accept.
const minDevicePrefix = 8

// selectDevices returns the account's devices that sel names: each a
// device ID or a prefix of one of at least minDevicePrefix hex digits.
func selectDevices(tx Tx, a *Account, op Operator, sel []string) ([]*DeviceDetail, error) {
	devs, err := accountDevices(tx, a, op.Now)
	if err != nil {
		return nil, err
	}
	var out []*DeviceDetail
	for _, s := range sel {
		prefix := strings.ToLower(s)
		notHex := func(c rune) bool { return !strings.ContainsRune("0123456789abcdef", c) }
		if len(prefix) < minDevicePrefix || len(prefix) > 2*len(model.ID{}) || strings.ContainsFunc(prefix, notHex) {
			return nil, adminErr("invalid", "not a device ID (at least %d hex digits)", minDevicePrefix)
		}
		var match []*DeviceDetail
		for _, d := range devs {
			if strings.HasPrefix(d.ID.String(), prefix) {
				match = append(match, d)
			}
		}
		switch {
		case len(match) == 0:
			return nil, adminErr("not_found", "the account has no device %s", prefix)
		case len(match) > 1:
			return nil, adminErr("ambiguous", "%d of the account's devices start with %s; give more digits", len(match), prefix)
		}
		if !slices.ContainsFunc(out, func(d *DeviceDetail) bool { return d.ID == match[0].ID }) {
			out = append(out, match[0])
		}
	}
	return out, nil
}

// DeviceSelection names the devices of a device command: some, by ID or
// prefix, or every active one (All).
type DeviceSelection struct {
	IDs []string
	All bool
}

func planDevices(who string, sel DeviceSelection, op Operator, block bool) func(Tx) (*AccessPlan, error) {
	return func(tx Tx) (*AccessPlan, error) {
		p, a, err := accessPlan(tx, who, op)
		if err != nil {
			return nil, err
		}
		var devs []*DeviceDetail
		if sel.All {
			all, err := accountDevices(tx, a, op.Now)
			if err != nil {
				return nil, err
			}
			for _, d := range all {
				// block --all: every active device not blocked yet;
				// unblock --all: every blocked device.
				if (block && d.Active && d.Blocked == nil) || (!block && d.Blocked != nil) {
					devs = append(devs, d)
				}
			}
		} else if devs, err = selectDevices(tx, a, op, sel.IDs); err != nil {
			return nil, err
		}
		for _, d := range devs {
			switch {
			case !sel.All && block && !d.Active:
				return nil, adminErr("not_active", "device %s left the account; the signed log keeps it out already", d.ID)
			case !sel.All && block && d.Blocked != nil:
				return nil, adminErr("already_blocked", "device %s is blocked already", d.ID)
			case !sel.All && !block && d.Blocked == nil:
				return nil, adminErr("not_blocked", "device %s is not blocked", d.ID)
			}
		}
		if len(devs) == 0 {
			if block {
				return nil, adminErr("not_found", "the account has no active device that is not blocked")
			}
			return nil, adminErr("not_found", "the account has no blocked device")
		}
		p.Devices, p.Sessions, p.LoginTokens = devs, 0, 0
		for _, d := range devs {
			if block {
				p.Sessions += d.Sessions
			}
		}
		return p, nil
	}
}

// PlanBlockDevices returns what BlockDevices would do. A device that left
// the account, or one blocked already, is refused when named.
func PlanBlockDevices(ctx context.Context, st Store, who string, sel DeviceSelection, op Operator) (*AccessPlan, error) {
	return view(ctx, st, planDevices(who, sel, op, true))
}

type deviceParams struct {
	Devices  []model.ID `json:"devices"`
	All      bool       `json:"all"`
	Reason   string     `json:"reason"`
	Sessions int        `json:"sessions"`
}

func deviceIDs(devs []*DeviceDetail) []model.ID {
	out := []model.ID{}
	for _, d := range devs {
		out = append(out, d.ID)
	}
	return out
}

// BlockDevices blocks the devices PlanBlockDevices showed as want and
// deletes their sessions: each is refused sessions from then on
// (device_blocked, with reason). devices.active does not change, and the
// account's other devices keep working. It does not keep the password
// holder from signing in as a new device; only disable does.
func BlockDevices(ctx context.Context, st Store, op Operator, who string, sel DeviceSelection, reason string, want *AccessPlan) (*AccessPlan, *AuditEntry, error) {
	if r, err := SanitizeReason(reason); err != nil || r != reason {
		return nil, nil, adminErr("invalid", "the reason is not sanitized")
	}
	params := &deviceParams{Devices: deviceIDs(want.Devices), All: sel.All, Reason: reason}
	return op.apply(ctx, st, ActionDeviceBlock, params, want, planDevices(who, sel, op, true), func(tx Tx, p *AccessPlan) error {
		params.Sessions = p.Sessions
		for _, d := range p.Devices {
			if err := tx.SetDeviceBlock(p.AccountID, d.ID, &AdminBlock{At: op.Now, Reason: reason}); err != nil {
				return err
			}
			if err := tx.DeleteSessions(p.AccountID, &d.ID); err != nil {
				return err
			}
		}
		return nil
	})
}

// PlanUnblockDevices returns what UnblockDevices would do.
func PlanUnblockDevices(ctx context.Context, st Store, who string, sel DeviceSelection, op Operator) (*AccessPlan, error) {
	return view(ctx, st, planDevices(who, sel, op, false))
}

// UnblockDevices ends the blocks PlanUnblockDevices showed as want.
func UnblockDevices(ctx context.Context, st Store, op Operator, who string, sel DeviceSelection, want *AccessPlan) (*AccessPlan, *AuditEntry, error) {
	params := &deviceParams{Devices: deviceIDs(want.Devices), All: sel.All}
	return op.apply(ctx, st, ActionDeviceUnblock, params, want, planDevices(who, sel, op, false), func(tx Tx, p *AccessPlan) error {
		for _, d := range p.Devices {
			if err := tx.SetDeviceBlock(p.AccountID, d.ID, nil); err != nil {
				return err
			}
		}
		return nil
	})
}

func planSessions(who, device string, op Operator) func(Tx) (*AccessPlan, error) {
	return func(tx Tx) (*AccessPlan, error) {
		p, a, err := accessPlan(tx, who, op)
		if err != nil || device == "" {
			return p, err
		}
		if p.Devices, err = selectDevices(tx, a, op, []string{device}); err != nil {
			return nil, err
		}
		p.Sessions, p.LoginTokens = p.Devices[0].Sessions, 0
		return p, nil
	}
}

// PlanRevokeSessions returns what RevokeSessions would do: device is ""
// for the whole account.
func PlanRevokeSessions(ctx context.Context, st Store, who, device string, op Operator) (*AccessPlan, error) {
	return view(ctx, st, planSessions(who, device, op))
}

type sessionsParams struct {
	Device      *model.ID `json:"device"`
	Sessions    int       `json:"sessions"`
	LoginTokens int       `json:"login_tokens"`
}

// RevokeSessions deletes the sessions PlanRevokeSessions showed, and for
// the whole account its login tokens too. It signs nobody out: each
// active device signs a new challenge and goes on. It is for a bearer
// token that may have leaked; a half-finished password login must start
// again.
func RevokeSessions(ctx context.Context, st Store, op Operator, who, device string, want *AccessPlan) (*AccessPlan, *AuditEntry, error) {
	params := &sessionsParams{}
	if device != "" && len(want.Devices) == 1 {
		params.Device = &want.Devices[0].ID
	}
	return op.apply(ctx, st, ActionSessionsRevoke, params, want, planSessions(who, device, op), func(tx Tx, p *AccessPlan) error {
		params.Sessions, params.LoginTokens = p.Sessions, p.LoginTokens
		if device != "" {
			return tx.DeleteSessions(p.AccountID, &p.Devices[0].ID)
		}
		if err := tx.DeleteSessions(p.AccountID, nil); err != nil {
			return err
		}
		return tx.DeleteLoginTokens(p.AccountID)
	})
}
