package daemon

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
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
	case OpSyncStatus, OpSyncNow, OpSyncPull, OpSyncHeld, OpSyncProposal, OpSyncResolve, OpDevicesList:
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
	case OpSyncPull:
		if err := noParams(req); err != nil {
			return nil, true, err
		}
		pctx, cancel := context.WithTimeout(ctx, syncNowTimeout)
		defer cancel()
		if err := d.sync.request(pctx, reqPull); err != nil {
			return nil, true, syncError(err)
		}
		return d.syncStatus(true), true, nil
	case OpSyncHeld:
		if err := noParams(req); err != nil {
			return nil, true, err
		}
		res, err := d.opSyncHeld()
		return res, true, err
	case OpSyncProposal:
		var p SyncProposalParams
		if err := decodeStrict(req, &p); err != nil {
			return nil, true, err
		}
		res, err := d.opSyncProposal(p)
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
		// The log knows when a device last wrote; the server, when it last
		// asked for anything. The later of the two is when it was seen.
		seen := d.sync.devicesSeen(ctx)
		for i := range devs {
			if t, ok := seen[devs[i].ID]; ok && (devs[i].LastSeen == nil || t.After(*devs[i].LastSeen)) {
				devs[i].LastSeen = &t
			}
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
	case errors.Is(err, store.ErrDeviceRevoked), errors.Is(err, store.ErrSessionEnded), errors.Is(err, store.ErrServerRevoked):
		code = CodeRevoked
	case errors.Is(err, store.ErrOfflineTooLong):
		code = CodeOffline
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
	if rep := info.ServerReport; rep != nil && out.ServerRetirement == nil {
		out.State = SyncRevoked
		out.ServerRetirement = &ServerRetirement{How: rep.How, Seq: rep.Seq, Unverified: true}
	}
	if r := out.ServerRetirement; r != nil && r.Unverified && info.ServerReportCorrupt {
		r.ReportCorrupt, r.How, r.Seq = true, "", 0
	}
	if r := out.ServerRetirement; r != nil && !r.Unverified {
		// Proven. Wiped once the store's wipe and the ssh files are done.
		if r.WipeError == "" {
			left := d.pendingClear()
			if left == "" {
				left = d.cleanupLeft()
			}
			if left != "" {
				r.WipeError, r.SSHFilesLeft = "the ssh files hop wrote are not removed yet: "+left, true
			}
		}
		r.Wiped = r.WipeError == ""
	}
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

	switch r := out.ServerRetirement; {
	case r == nil:
	case r.Wiped:
		warn("this device was %s from the account (at seq %d), and the entry that did it verified here: "+
			"this device's copy of the vault, its device key and the ssh files hop wrote were wiped. hop auth login signs in again as a new device", r.How, r.Seq)
	case !r.Unverified:
		warn("this device was %s from the account (at seq %d), and the entry that did it verified here, so the vault stays locked for good; "+
			"wiping this device's copy has not finished (%s). The daemon tries the ssh files again, and the next start finishes the rest", r.How, r.Seq, r.WipeError)
	case r.ReportCorrupt:
		warn("the server reported that this device left the account, but the record of that report here is corrupt (it does not parse, or its MAC does not verify), " +
			"so what it says is not shown. The vault stays locked, as for any report, until the server accepts this device again; " +
			"hop auth logout wipes this device, and hop auth login signs in again. Nothing was deleted")
	default:
		msg := fmt.Sprintf("the server reports that this device was %s from the account at seq %d: the vault stays locked and nothing syncs, after a restart too. "+
			"hop auth logout wipes this device, and hop auth login signs in again. Nothing was deleted, since the report is not proven", r.How, r.Seq)
		if r.ProofError != "" {
			msg += fmt.Sprintf(" (%s)", r.ProofError)
		}
		warn("%s. If the server is wrong, the vault unlocks again once the server accepts this device: the daemon asks it each time it starts", msg)
	}
	if out.CheckSkipped != "" && out.State != SyncRevoked {
		warn("the check with the server before the keys loaded was skipped, since the server did not answer (%s): "+
			"this device uses its keys without knowing whether it is still in the account", out.CheckSkipped)
	}
	if out.ServerUnconfirmed != "" && info.Locked && out.State != SyncRevoked {
		warn("the server did not confirm that this device is still in the account, so the vault stays locked (%s); "+
			"nothing was deleted, and hop unlock, or the next sync, asks again", out.ServerUnconfirmed)
	}
	if out.OfflineLocked != "" && info.Locked {
		warn("offline too long; connect to the server (%s), then run hop unlock", out.OfflineLocked)
	}
	if cur := d.state.Load(); cur != nil && cur.configErr != "" {
		warn("%s", d.configWarning(cur.configErr))
	}
	if why := d.pendingClear(); why != "" {
		warn("%s", d.clearWarning(why))
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

// heldTries is how many times opSyncHeld reads the held head again when
// the server's version moved between reading it and proposing keep-mine.
const heldTries = 3

// opSyncHeld lists the held outbox head with its keep-mine proposal. It
// names the --merge choices it offers but leaves their proposals to
// opSyncProposal: the response carries the item at most five times over
// (seen, want, current, and keep-mine's seen and want), which is what it
// always carried. The hold's conflicts name members only, so they add
// nothing of the item's size.
func (d *Daemon) opSyncHeld() (*SyncHeldResult, error) {
	st := d.sync.st
	var h *store.HeldRecord
	var km *store.Proposal
	kmErr := ""
	for try := 1; ; try++ {
		var err error
		if h, err = st.HeldHead(); err != nil {
			return nil, syncError(err)
		}
		if h == nil || h.Import {
			break
		}
		p, err := st.Propose(store.Resolution{Choice: merge.ChoiceKeepMine})
		if err != nil {
			km, kmErr = nil, err.Error()
			break
		}
		// The listing shows keep-mine beside its own Current and Hold, so
		// they must be the ones it was computed from.
		if p.N == h.N && bytes.Equal(p.Current, h.Current) && sameHold(p.Hold, h.Hold) {
			km, kmErr = &p, ""
			break
		}
		if try == heldTries {
			km, kmErr = nil, "the server's version kept changing while it was listed: list it again"
			break
		}
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
		if km != nil {
			hc.KeepMine = d.sync.proposalOf(*km)
			hc.KeepMine.Current, hc.KeepMine.Hold = nil, nil
		} else {
			hc.KeepMineRefused = kmErr
		}
		// The --merge proposals exist only for a hold on a unit, class or
		// coupling conflict; there is nothing to say otherwise.
		offered := func(c merge.Choice, refused *string) bool {
			if h.Hold == nil || len(h.Hold.Conflicts) == 0 {
				return false
			}
			if _, err := st.Propose(store.Resolution{Choice: c}); err != nil {
				*refused = err.Error()
				return false
			}
			return true
		}
		keepMerge := offered(merge.ChoiceKeepMineMerge, &hc.KeepMineMergeRefused)
		theirsMerge := offered(merge.ChoiceTakeTheirsMerge, &hc.TakeTheirsMergeRefused)
		if hc.KeepMine != nil {
			hc.Choices = append(hc.Choices, ChoiceKeepMine)
		}
		if keepMerge {
			hc.Choices = append(hc.Choices, ChoiceKeepMineMerge)
		}
		if h.Hold != nil && editable(h.Type) {
			hc.Choices = append(hc.Choices, ChoiceEdit)
		}
		if theirsMerge {
			hc.Choices = append(hc.Choices, ChoiceTakeTheirsMerge)
		}
		hc.Choices = append(hc.Choices, ChoiceTakeTheirs, ChoiceRetry)
	}
	out.Held = append(out.Held, hc)
	return out, nil
}

// opSyncProposal returns the proposal of one --merge choice for the held
// record p.N, with its token and the server's version and hold it was
// computed from: one item three times over, whatever its size.
func (d *Daemon) opSyncProposal(p SyncProposalParams) (*SyncProposalResult, error) {
	choice, err := parseChoice(p.Choice)
	if err != nil {
		return nil, err
	}
	if choice != merge.ChoiceKeepMineMerge && choice != merge.ChoiceTakeTheirsMerge {
		return nil, invalidf("only %s and %s are proposed here; keep-mine's proposal is in %s, and edit's comes from %s with propose",
			ChoiceKeepMineMerge, ChoiceTakeTheirsMerge, OpSyncHeld, OpSyncResolve)
	}
	st := d.sync.st
	h, err := st.HeldHead()
	if err != nil {
		return nil, syncError(err)
	}
	if h == nil || h.N != p.N {
		return nil, &Error{Code: CodeNotHeld, Message: fmt.Sprintf("queued change %d is not the held one; list it again with hop sync", p.N)}
	}
	prop, err := st.Propose(store.Resolution{Choice: choice})
	if err != nil {
		return nil, syncError(err)
	}
	if prop.N != p.N {
		return nil, &Error{Code: CodeNotHeld, Message: fmt.Sprintf("queued change %d is not the held one; list it again with hop sync", p.N)}
	}
	return &SyncProposalResult{Proposal: d.sync.proposalOf(prop)}, nil
}

// sameHold reports whether a and b hold for the same reason. Reason, an
// error's text, is left out.
func sameHold(a, b *store.HoldInfo) bool {
	return bytes.Equal(holdBytes(a), holdBytes(b))
}

// holdBytes encodes what a hold says, less its Reason: the cause, the
// members each side changed and the conflicts.
func holdBytes(h *store.HoldInfo) []byte {
	if h == nil {
		return nil
	}
	b, err := json.Marshal(store.HoldInfo{Cause: h.Cause, Local: h.Local, Remote: h.Remote, Conflicts: h.Conflicts})
	if err != nil {
		panic(err) // strings and lists of strings
	}
	return b
}

// editable reports whether an item type can be edited over the control
// socket: keys and credentials hold secrets that never cross it.
func editable(t model.Type) bool { return t == model.TypeHost || t == model.TypeSnippet }

// proposalOf is the control form of a store proposal: redacted, and with
// a confirmation token in place of the store's digest.
func (e *syncer) proposalOf(p store.Proposal) *Proposal {
	out := &Proposal{
		N: p.N, Choice: choiceName(p.Choice), Action: p.Action, ItemID: p.ItemID.String(), Type: p.Type,
		Seen: redacted(p.Type, p.Seen), Want: redacted(p.Type, p.Want), Confirm: e.confirmToken(p).String(),
		Current: redacted(p.Type, p.Current), Hold: p.Hold,
	}
	if !p.NewID.IsZero() {
		out.NewID = p.NewID.String()
	}
	return out
}

// confirmToken is the token that confirms p: HMAC-SHA256, keyed with
// this daemon's random confirmKey, of n, the store's digest c (§5.4), and
// the server's version and the hold the proposal was computed from. c
// hashes the full replacement, a credential's password and a key's
// private key included, so on its own it would let anyone holding the
// redacted proposal test guesses at them; the token is useless without
// the key, and it still changes whenever c does. With the server's version
// and the hold in it, it also stops confirming once what was shown beside
// the proposal is out of date, even if the replacement is not.
func (e *syncer) confirmToken(p store.Proposal) crypto.Hash {
	m := hmac.New(sha256.New, e.confirmKey[:])
	m.Write([]byte("hopkey/daemon/resolve-confirm\x01"))
	m.Write(binary.BigEndian.AppendUint64(nil, p.N))
	m.Write(p.Digest[:])
	for _, b := range [][]byte{p.Current, holdBytes(p.Hold)} {
		m.Write(binary.BigEndian.AppendUint64(nil, uint64(len(b))))
		m.Write(b)
	}
	var out crypto.Hash
	copy(out[:], m.Sum(nil))
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
	case merge.ChoiceKeepMineMerge:
		return ChoiceKeepMineMerge
	case merge.ChoiceTakeTheirsMerge:
		return ChoiceTakeTheirsMerge
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
	case ChoiceKeepMineMerge:
		return merge.ChoiceKeepMineMerge, nil
	case ChoiceTakeTheirsMerge:
		return merge.ChoiceTakeTheirsMerge, nil
	}
	return "", invalidf("choice must be %s, %s, %s, %s, %s or %s, not %q",
		ChoiceKeepMine, ChoiceKeepMineMerge, ChoiceEdit, ChoiceTakeTheirsMerge, ChoiceTakeTheirs, ChoiceRetry, s)
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
	var token crypto.Hash
	if p.Confirm != "" {
		if err := token.UnmarshalText([]byte(strings.TrimSpace(p.Confirm))); err != nil {
			return nil, invalidf("confirm: %v", err)
		}
	}
	needsConfirm := choice == merge.ChoiceKeepMine || choice == merge.ChoiceEdit ||
		choice == merge.ChoiceKeepMineMerge || choice == merge.ChoiceTakeTheirsMerge
	if p.Propose && !needsConfirm {
		return nil, invalidf("only %s, %s, %s and %s have a proposal", ChoiceKeepMine, ChoiceKeepMineMerge, ChoiceEdit, ChoiceTakeTheirsMerge)
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
		return &SyncResolveResult{Proposal: d.sync.proposalOf(prop)}, nil
	}
	if needsConfirm {
		if p.Confirm == "" {
			return nil, &Error{Code: CodeConfirm, Message: fmt.Sprintf("%s needs the confirmation token of its proposal as confirm", p.Choice)}
		}
		// The token is checked against the full proposal as it stands
		// now, never the redacted one the user saw: a change to a secret
		// since then makes it stale too. Resolve checks the digest again
		// under the store's lock.
		prop, err := st.Propose(r)
		if err != nil {
			return nil, syncError(err)
		}
		if want := d.sync.confirmToken(prop); prop.N != p.N || !hmac.Equal(want[:], token[:]) {
			return nil, syncError(store.ErrStaleConfirm)
		}
		r.Confirm = prop.Digest
	}
	if err := st.Resolve(r); err != nil {
		return nil, syncError(err)
	}
	d.logf("sync: queued change %d resolved: %s", p.N, p.Choice)
	d.localWrite()
	err = d.reloadAfter(ctx, "resolved")
	return &SyncResolveResult{Status: d.syncStatus(false)}, err
}
