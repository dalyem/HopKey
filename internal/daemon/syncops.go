package daemon

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/dalyem/hopkey/internal/crypto"
	"github.com/dalyem/hopkey/internal/merge"
	"github.com/dalyem/hopkey/internal/model"
	"github.com/dalyem/hopkey/internal/store"
	"github.com/dalyem/hopkey/internal/syncclient"
)

// dispatchSync handles the sync ops. handled is false for any other op.
func (d *Daemon) dispatchSync(ctx context.Context, req Request) (result any, handled bool, err error) {
	switch req.Op {
	case OpSyncStatus, OpSyncNow, OpSyncHeld, OpSyncResolve, OpDevicesList:
	default:
		return nil, false, nil
	}
	if d.sync == nil {
		return nil, true, &Error{Code: CodeLocalOnly, Message: "this vault store does not sync"}
	}
	switch req.Op {
	case OpSyncStatus:
		if err := noParams(req); err != nil {
			return nil, true, err
		}
		return d.syncStatus(true), true, nil
	case OpSyncNow:
		if err := noParams(req); err != nil {
			return nil, true, err
		}
		if err := d.sync.request(ctx, reqSyncNow); err != nil {
			return nil, true, syncError(err)
		}
		return d.syncStatus(true), true, nil
	case OpSyncHeld:
		if err := noParams(req); err != nil {
			return nil, true, err
		}
		res, err := d.opSyncHeld()
		return res, true, err
	case OpSyncResolve:
		var p SyncResolveParams
		if err := decodeStrict(req, &p); err != nil {
			return nil, true, err
		}
		res, err := d.opSyncResolve(ctx, p)
		return res, true, err
	case OpDevicesList:
		if err := noParams(req); err != nil {
			return nil, true, err
		}
		devs, err := d.sync.st.Devices()
		if err != nil {
			return nil, true, syncError(err)
		}
		if devs == nil {
			devs = []store.DeviceListing{}
		}
		return &DevicesResult{Devices: devs}, true, nil
	}
	return nil, false, nil
}

// noParams refuses params on an op that takes none.
func noParams(req Request) error {
	if p := bytes.TrimSpace(req.Params); len(p) > 0 && !bytes.Equal(p, []byte("null")) && !bytes.Equal(p, []byte("{}")) {
		return invalidf("%s takes no params", req.Op)
	}
	return nil
}

// decodeStrict decodes params into v, refusing unknown members and
// trailing data.
func decodeStrict(req Request, v any) error {
	dec := json.NewDecoder(bytes.NewReader(req.Params))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return invalidf("bad params for %s: %v", req.Op, err)
	}
	if dec.More() {
		return invalidf("bad params for %s: trailing data", req.Op)
	}
	return nil
}

// syncError maps the errors of sync and resolution to control codes.
func syncError(err error) error {
	var e *Error
	if errors.As(err, &e) {
		return err
	}
	code := ""
	switch {
	case errors.Is(err, store.ErrDeviceRevoked), errors.Is(err, store.ErrSessionEnded):
		code = CodeRevoked
	case errors.Is(err, model.ErrLocked):
		code = CodeLocked
	case errors.Is(err, store.ErrNotServerBacked):
		code = CodeLocalOnly
	case errors.Is(err, store.ErrSyncHalted):
		code = CodeSyncHalted
	case errors.Is(err, store.ErrNotHeld):
		code = CodeNotHeld
	case errors.Is(err, store.ErrStillHeld):
		code = CodeStillHeld
	case errors.Is(err, store.ErrStaleConfirm):
		code = CodeStaleConfirm
	case syncclient.Retryable(err), errors.Is(err, context.DeadlineExceeded):
		code = CodeUnreachable
	case errors.Is(err, store.ErrNoLongerHeld), errors.Is(err, store.ErrImportRecord), errors.Is(err, store.ErrLiveCandidate),
		errors.Is(err, store.ErrReplacementRefused), errors.As(err, new(*merge.RefusalError)):
		code = CodeInvalid
	default:
		return err
	}
	return &Error{Code: code, Message: err.Error()}
}

// syncStatus builds SyncStatusResult from the engine and the store. The
// device scan (undelivered devices) reads the verified log, so OpStatus
// leaves it out.
func (d *Daemon) syncStatus(devices bool) *SyncStatusResult {
	e := d.sync
	out := e.status()
	warn := func(format string, args ...any) { out.Warnings = append(out.Warnings, fmt.Sprintf(format, args...)) }
	info := e.st.Info()
	out.Logout, out.Publishing, out.Merge, out.SecretKeyStale = info.Logout, info.Publishing, info.Merge, info.SecretKeyStale
	out.Head = info.Head
	if si, err := e.st.ServerInfo(); err == nil {
		out.Server, out.Email, out.CheckpointDue = si.Server, si.Email, si.CheckpointDue
		if !si.VaultID.IsZero() {
			out.VaultID = si.VaultID.String()
		}
		if !si.AccountID.IsZero() {
			out.AccountID = si.AccountID.String()
		}
	}
	if st, err := e.st.Status(); err == nil {
		out.Pending, out.Held = st.Pending, st.Held
		if st.Halted != "" && out.Halted == "" {
			out.Halted = st.Halted
		}
	}
	if out.Halted != "" && out.State != SyncRevoked {
		out.State = SyncHalted
	}
	if info.Locked && out.State != SyncRevoked && out.State != SyncLoggedOut && out.State != SyncLoggingOut {
		out.State = SyncLocked
	}
	if n, err := e.st.LostIntents(); err == nil && n > 0 {
		out.LostIntents = n
	}
	if lost, err := e.st.LostJournals(); err == nil && lost != (store.LostJournals{}) {
		out.LostJournals = &lost
	}
	if cp, err := e.st.PendingCheckpoint(); err == nil && cp != nil {
		out.Checkpoint = cp
	}
	if devices && !info.Locked {
		if devs, err := e.st.Devices(); err == nil {
			for _, dv := range devs {
				if dv.Undelivered {
					out.UndeliveredDevices++
				}
			}
		}
	}

	switch {
	case out.Equivocation:
		warn("the server showed two different histories of the vault (an equivocation): sync is stopped; compare hop status on your devices and contact the server's operator")
	case out.Halted != "":
		warn("sync is stopped: %s", out.Halted)
	}
	if out.Held > 0 {
		warn("%d queued change(s) are held, and nothing queued behind them is sent: resolve with hop sync resolve", out.Held)
	}
	if out.LostIntents > 0 {
		warn("%d queued change(s) were lost when a password unlock replaced this device's key", out.LostIntents)
	}
	if out.LostJournals != nil {
		if out.LostJournals.Checkpoint {
			warn("a password change or other checkpoint was interrupted and its journal lost: if it committed, run hop auth rotate to get a new Emergency Kit")
		}
		if out.LostJournals.Approval {
			warn("a device approval was interrupted and its journal lost: if the new device never finished signing in, revoke it")
		}
	}
	if out.CheckpointDue {
		warn("this device signed in with the Recovery Key: set a new password with hop passwd to finish the recovery")
	}
	if out.Checkpoint != nil && !out.Checkpoint.Committed {
		warn("a %s checkpoint is not finished: run the same command again", out.Checkpoint.Kind)
	}
	if out.SecretKeyStale {
		warn("the Secret Key stored on this device is out of date: enter the one from your newest Emergency Kit when asked")
	}
	if out.UndeliveredDevices > 0 {
		warn("%d device(s) added by an approval here never received the vault: revoke them with hop auth devices revoke", out.UndeliveredDevices)
	}
	if out.Logout != "" && out.State != SyncLoggedOut {
		warn("a logout is in progress (%s): the daemon is finishing it", out.Logout)
	}
	if out.Publishing {
		warn("the publication to the server is not finished: the daemon is finishing it")
	}
	if out.Merge != "" {
		warn("a login merge is in progress (%s): finish it with hop auth merge", out.Merge)
	}
	return &out
}

// opSyncHeld lists the held outbox head with its keep-mine proposal.
func (d *Daemon) opSyncHeld() (*SyncHeldResult, error) {
	st := d.sync.st
	h, err := st.HeldHead()
	if err != nil {
		return nil, syncError(err)
	}
	out := &SyncHeldResult{Held: []HeldChange{}}
	if h == nil {
		return out, nil
	}
	hc := HeldChange{
		N: h.N, Import: h.Import, Action: h.Action, ItemID: h.ItemID.String(), Type: h.Type, Hold: h.Hold,
		Seen: redacted(h.Type, h.Seen), Want: redacted(h.Type, h.Want), Current: redacted(h.Type, h.Current),
		Choices: []string{},
	}
	if !h.Import {
		if p, err := st.Propose(store.Resolution{Choice: merge.ChoiceKeepMine}); err == nil {
			hc.KeepMine = proposalOf(p)
		} else {
			hc.KeepMineRefused = err.Error()
		}
		if hc.KeepMine != nil {
			hc.Choices = append(hc.Choices, ChoiceKeepMine)
		}
		if h.Hold != nil && editable(h.Type) {
			hc.Choices = append(hc.Choices, ChoiceEdit)
		}
		hc.Choices = append(hc.Choices, ChoiceTakeTheirs, ChoiceRetry)
	}
	out.Held = append(out.Held, hc)
	return out, nil
}

// editable reports whether an item type can be edited over the control
// socket: keys and credentials hold secrets that never cross it.
func editable(t model.Type) bool { return t == model.TypeHost || t == model.TypeSnippet }

func proposalOf(p store.Proposal) *Proposal {
	out := &Proposal{
		N: p.N, Choice: choiceName(p.Choice), Action: p.Action, ItemID: p.ItemID.String(), Type: p.Type,
		Seen: redacted(p.Type, p.Seen), Want: redacted(p.Type, p.Want), Digest: p.Digest.String(),
	}
	if !p.NewID.IsZero() {
		out.NewID = p.NewID.String()
	}
	return out
}

func choiceName(c merge.Choice) string {
	switch c {
	case merge.ChoiceKeepMine:
		return ChoiceKeepMine
	case merge.ChoiceEdit:
		return ChoiceEdit
	case merge.ChoiceTakeTheirs:
		return ChoiceTakeTheirs
	case merge.ChoiceRetry:
		return ChoiceRetry
	}
	return string(c)
}

func parseChoice(s string) (merge.Choice, error) {
	switch s {
	case ChoiceKeepMine:
		return merge.ChoiceKeepMine, nil
	case ChoiceEdit:
		return merge.ChoiceEdit, nil
	case ChoiceTakeTheirs:
		return merge.ChoiceTakeTheirs, nil
	case ChoiceRetry:
		return merge.ChoiceRetry, nil
	}
	return "", invalidf("choice must be %s, %s, %s or %s, not %q", ChoiceKeepMine, ChoiceEdit, ChoiceTakeTheirs, ChoiceRetry, s)
}

// redacted is an item's plaintext JSON without its secret: a key's
// private_key or a credential's password. Absent is null.
func redacted(t model.Type, pt []byte) json.RawMessage {
	if pt == nil {
		return json.RawMessage("null")
	}
	secret := ""
	switch t {
	case model.TypeKey:
		secret = "private_key"
	case model.TypeCredential:
		secret = "password"
	}
	if secret == "" {
		return json.RawMessage(pt)
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal(pt, &m); err != nil {
		return json.RawMessage("null")
	}
	delete(m, secret)
	b, err := json.Marshal(m)
	if err != nil {
		return json.RawMessage("null")
	}
	return b
}

// editedItem decodes an edited host or snippet.
func editedItem(t model.Type, raw json.RawMessage) (crypto.Item, error) {
	var v any
	switch t {
	case model.TypeHost:
		v = new(model.Host)
	case model.TypeSnippet:
		v = new(model.Snippet)
	default:
		return nil, invalidf("a held %s can't be edited here: keep mine or take theirs, or change it after", t)
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return nil, invalidf("the edited %s does not parse: %v", t, err)
	}
	return v, nil
}

// opSyncResolve resolves the held outbox head, or proposes a resolution.
func (d *Daemon) opSyncResolve(ctx context.Context, p SyncResolveParams) (*SyncResolveResult, error) {
	st := d.sync.st
	choice, err := parseChoice(p.Choice)
	if err != nil {
		return nil, err
	}
	r := store.Resolution{Choice: choice}
	if p.NewID != "" {
		if r.NewID, err = model.ParseID(p.NewID); err != nil {
			return nil, invalidf("new_id: %v", err)
		}
	}
	if p.Confirm != "" {
		if err := r.Confirm.UnmarshalText([]byte(strings.TrimSpace(p.Confirm))); err != nil {
			return nil, invalidf("confirm: %v", err)
		}
	}
	needsConfirm := choice == merge.ChoiceKeepMine || choice == merge.ChoiceEdit
	if p.Propose && !needsConfirm {
		return nil, invalidf("only %s and %s have a proposal", ChoiceKeepMine, ChoiceEdit)
	}
	if !needsConfirm && (p.Confirm != "" || p.NewID != "") {
		return nil, invalidf("%s takes no confirm or new_id", p.Choice)
	}

	d.mu.Lock()
	defer d.mu.Unlock()
	h, err := st.HeldHead()
	if err != nil {
		return nil, syncError(err)
	}
	if h == nil || h.N != p.N {
		return nil, &Error{Code: CodeNotHeld, Message: fmt.Sprintf("queued change %d is not the held one; list it again with hop sync", p.N)}
	}
	if choice == merge.ChoiceEdit {
		if len(p.Edited) == 0 {
			return nil, invalidf("edit needs the edited item")
		}
		if r.Edited, err = editedItem(h.Type, p.Edited); err != nil {
			return nil, err
		}
	} else if len(p.Edited) > 0 {
		return nil, invalidf("only edit takes an edited item")
	}
	if p.Propose {
		prop, err := st.Propose(r)
		if err != nil {
			return nil, syncError(err)
		}
		return &SyncResolveResult{Proposal: proposalOf(prop)}, nil
	}
	if needsConfirm && p.Confirm == "" {
		return nil, &Error{Code: CodeConfirm, Message: fmt.Sprintf("%s needs the digest of its proposal as confirm", p.Choice)}
	}
	if err := st.Resolve(r); err != nil {
		return nil, syncError(err)
	}
	d.logf("sync: queued change %d resolved: %s", p.N, p.Choice)
	d.localWrite()
	if _, err := d.reloadLocked(ctx); err != nil {
		return nil, fmt.Errorf("resolved, but reloading failed: %w", err)
	}
	return &SyncResolveResult{Status: d.syncStatus(false)}, nil
}
