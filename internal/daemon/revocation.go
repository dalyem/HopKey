package daemon

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/dalyem/hopkey/internal/model"
	"github.com/dalyem/hopkey/internal/store"
	"github.com/dalyem/hopkey/internal/syncclient"
)

// Revocation on a signed-in device (store/revocation.go).
//
// Before the daemon puts a key in the agent, at start and at each hop
// unlock, it asks the server whether this device is still in the account,
// for at most checkTimeout. A refusal records the server's report: the
// vault stays locked, the agent empty and the ssh config emptied, after a
// restart too, and the daemon asks the server for the proof (prove). A
// proof that verifies wipes this device's copy of the vault as a logout
// does. A server that does not answer in time is no reason to refuse: the
// keys load, and status says the check was skipped. A report clears only
// when the server authenticates this device again: at the next start, or
// the next hop unlock.
//
// Then the account's max-offline policy (model.Policy): a device that has
// not had an authenticated answer from the server for longer locks, and
// refuses to unlock, until it has one. The daemon looks again every
// offlineEvery while the vault is unlocked. A local-only vault has neither.

const (
	// checkTimeout bounds the question asked before keys load.
	checkTimeout = 3 * time.Second
	// sessionCheckTimeout bounds it after the server ended a session.
	sessionCheckTimeout = 15 * time.Second
	// proofTimeout bounds fetching and checking a revocation proof.
	proofTimeout = 2 * time.Minute
	// offlineEvery is how often an unlocked vault's max-offline policy is
	// checked.
	offlineEvery = time.Minute
	// clockSlack is how far in the future the last contact may be before
	// the clock counts as set back.
	clockSlack = 5 * time.Minute
)

// revocationStore is the revocation side of the encrypted store
// (*store.Store).
type revocationStore interface {
	CheckServer(ctx context.Context, r store.ServerChecker, passphrase []byte) (store.ServerCheck, error)
	ProveRevocation(ctx context.Context, r store.ServerChecker, passphrase []byte) error
	WipeRevoked() error
	LastContact() (time.Time, bool, error)
	LockFor(reason error)
}

var _ revocationStore = (*store.Store)(nil)

// revocations returns the store's revocation side and the syncer, or false
// for a store that has none (not the encrypted store, or local-only).
func (d *Daemon) revocations() (revocationStore, *syncer, bool) {
	rs, ok := d.store.(revocationStore)
	if !ok || d.sync == nil {
		return nil, nil, false
	}
	if _, err := d.sync.st.ServerInfo(); err != nil {
		return nil, nil, false
	}
	return rs, d.sync, true
}

// checker returns the server as CheckServer asks it.
func (e *syncer) checker() (store.ServerChecker, error) {
	info, err := e.st.ServerInfo()
	if err != nil {
		return nil, err
	}
	c, err := e.client(info.Server)
	if err != nil {
		return nil, err
	}
	return c.Retirer(info.VaultID), nil
}

// checkServer asks the server, within timeout, whether this device is
// still in the account (store.CheckServer), and records the answer for
// status. An unanswered question is returned as the error. It does not take
// d.mu, but a report found is acted on by the caller (reportedLocked).
func (d *Daemon) checkServer(ctx context.Context, timeout time.Duration, passphrase []byte) (store.ServerCheck, error) {
	rs, e, ok := d.revocations()
	if !ok {
		return store.ServerCheck{}, store.ErrNotServerBacked
	}
	r, err := e.checker()
	if err != nil {
		return store.ServerCheck{}, err
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	res, err := rs.CheckServer(ctx, r, passphrase)
	switch {
	case err != nil && (syncclient.Retryable(err) || errors.Is(err, context.DeadlineExceeded)):
		why := err.Error()
		e.set(func() { e.checkSkipped = why })
		d.logf("the server could not be asked whether this device is still in the account: %v", err)
	case err != nil:
		d.logf("asking the server whether this device is still in the account: %v", err)
	case res.Active:
		e.set(func() {
			e.checkSkipped = ""
			if e.retired != nil && !e.retired.Wiped {
				// The report was wrong.
				e.retired = nil
				if e.phase == SyncRevoked {
					e.phase = SyncStarting
				}
			}
		})
	}
	return res, err
}

// reportedLocked takes the daemon to the reported state: sync stopped, the
// agent empty, the ssh config emptied. The store has recorded the report
// and locked itself. It starts the proof. The caller holds d.mu.
func (d *Daemon) reportedLocked(rep *store.ServerReport, passphrase []byte) {
	e := d.sync
	why := fmt.Sprintf("the server reports this device %s from the account at seq %d (server-reported, not proven yet)", rep.How, rep.Seq)
	e.set(func() {
		e.phase, e.lastErr, e.lastErrAt = SyncRevoked, why, time.Now()
		if e.retired == nil || e.retired.Seq != rep.Seq || e.retired.How != rep.How {
			e.retired = &ServerRetirement{How: rep.How, Seq: rep.Seq, Unverified: true}
		}
	})
	d.dropKeysLocked(true)
	d.logf("sync stopped: %s", why)
	d.prove(passphrase)
}

// prove asks the server for the proof of the revocation it reported and,
// once it verifies, wipes this device (store.ProveRevocation), in the
// background. One runs at a time.
func (d *Daemon) prove(passphrase []byte) {
	rs, e, ok := d.revocations()
	if !ok || !d.proving.CompareAndSwap(false, true) {
		return
	}
	pass := append([]byte(nil), passphrase...)
	if passphrase == nil {
		pass = nil
	}
	d.wg.Add(1)
	go func() {
		defer d.wg.Done()
		defer d.proving.Store(false)
		defer clear(pass)
		r, err := e.checker()
		if err == nil {
			ctx, cancel := context.WithTimeout(d.ctx, proofTimeout)
			err = rs.ProveRevocation(ctx, r, pass)
			cancel()
		}
		if errors.Is(err, store.ErrDeviceRevoked) {
			d.wiped(err)
			return
		}
		if d.ctx.Err() != nil {
			return
		}
		why := err.Error()
		e.set(func() {
			if e.retired != nil {
				e.retired.ProofError = why
			}
		})
		d.logf("the revocation the server reported is not proven, so nothing was deleted: %v", err)
	}()
}

// wiped follows a wipe of this device's copy of the vault (why wraps
// store.ErrDeviceRevoked): sync stops for good, and the ssh config is
// emptied and its files removed, which clears the store's mark that it was
// owed.
func (d *Daemon) wiped(why error) {
	e := d.sync
	e.set(func() {
		e.phase, e.lastErr, e.lastErrAt = SyncRevoked, why.Error(), time.Now()
		r := &ServerRetirement{How: "revoked", Wiped: true}
		if e.retired != nil {
			r.How, r.Seq = e.retired.How, e.retired.Seq
		}
		e.retired = r
	})
	d.mu.Lock()
	d.dropKeysLocked(true)
	d.mu.Unlock()
	d.logf("this device was revoked from the account, verified: its copy of the vault, its device key and the ssh files hop wrote were wiped (%v)", why)
}

// wipeVerified wipes the store after a verified revocation (a pull met the
// checkpoint, or one was recorded before), and reports whether it did.
func (d *Daemon) wipeVerified() bool {
	rs, ok := d.store.(revocationStore)
	if !ok || d.sync == nil {
		return false
	}
	err := rs.WipeRevoked()
	if !errors.Is(err, store.ErrDeviceRevoked) {
		if err != nil {
			d.logf("wiping the revoked device: %v", err)
		}
		return false
	}
	d.wiped(err)
	return true
}

// preflight runs at start, before anything is loaded into the agent. A
// verified revocation wipes. A signed-in device asks the server; a report
// keeps the vault locked, and a device whose report the server now
// contradicts unlocks with its own device key. Then the max-offline
// policy.
func (d *Daemon) preflight(ctx context.Context) {
	_, e, ok := d.revocations()
	if !ok {
		return
	}
	v, _ := d.store.(Vault)
	info := e.st.Info()
	if info.Revoked {
		d.wipeVerified()
		return
	}
	if info.Locked && info.ServerReport == nil {
		// Nothing to protect; hop unlock asks.
		return
	}
	res, err := d.checkServer(ctx, checkTimeout, nil)
	d.mu.Lock()
	defer d.mu.Unlock()
	switch {
	case err == nil && res.Report != nil:
		d.reportedLocked(res.Report, nil)
		return
	case err == nil && res.Active && info.ServerReport != nil && v != nil:
		if uerr := v.Unlock(ctx); uerr != nil {
			d.logf("the server accepts this device again, but the vault did not unlock: %v", uerr)
		}
	case info.ServerReport != nil:
		e.set(func() {
			e.phase = SyncRevoked
			e.retired = &ServerRetirement{How: info.ServerReport.How, Seq: info.ServerReport.Seq, Unverified: true}
		})
		return
	}
	d.enforceOfflineLocked(ctx)
}

// enforceOfflineLocked applies the account's max-offline policy to an
// unlocked, signed-in vault: one whose last authenticated contact with the
// server is older than the policy allows, or in the future (the clock was
// set back), is locked, and the error says why. The caller holds d.mu.
func (d *Daemon) enforceOfflineLocked(ctx context.Context) error {
	rs, e, ok := d.revocations()
	if !ok {
		return nil
	}
	snap, err := d.store.Snapshot(ctx)
	if err != nil {
		return nil
	}
	max := time.Duration(model.EffectiveMaxOffline(snap.Policies)) * time.Second
	at, has, cerr := rs.LastContact()
	e.set(func() {
		e.maxOffline = max
		if has {
			e.lastContact = at
		}
	})
	if max == 0 {
		return nil
	}
	now := time.Now()
	var why string
	switch {
	case cerr != nil:
		why = fmt.Sprintf("the time of the last server contact can't be read (%v)", cerr)
	case !has:
		why = "this device has no record of reaching the server"
	case at.After(now.Add(clockSlack)):
		why = fmt.Sprintf("the last server contact, %s, is in the future: the clock was set back", at.UTC().Format(time.RFC3339))
	case now.Sub(at) > max:
		why = fmt.Sprintf("the last server contact was %s ago, and the account allows %s", now.Sub(at).Round(time.Second), max)
	default:
		return nil
	}
	err = fmt.Errorf("%w (%s)", store.ErrOfflineTooLong, why)
	rs.LockFor(err)
	d.dropKeysLocked(false)
	e.set(func() { e.offline = why })
	d.sync.wake()
	d.logf("the vault locked itself: %v", err)
	return err
}

// watchOffline checks the max-offline policy of an unlocked vault every
// offlineEvery.
func (d *Daemon) watchOffline() {
	if _, _, ok := d.revocations(); !ok {
		return
	}
	every := d.opts.offlineEvery
	if every <= 0 {
		every = offlineEvery
	}
	d.wg.Add(1)
	go func() {
		defer d.wg.Done()
		t := time.NewTicker(every)
		defer t.Stop()
		for {
			select {
			case <-d.ctx.Done():
				return
			case <-t.C:
			}
			d.mu.Lock()
			if v, ok := d.store.(Vault); ok && !v.Info().Locked && d.ctx.Err() == nil {
				d.enforceOfflineLocked(d.ctx)
			}
			d.mu.Unlock()
		}
	}()
}

// checkBeforeKeysLocked is what an unlock does once the store is unlocked
// and before the agent gets a key: the server is asked, and the
// max-offline policy applied. The caller holds d.mu.
func (d *Daemon) checkBeforeKeysLocked(ctx context.Context, passphrase []byte) error {
	if _, _, ok := d.revocations(); !ok {
		return nil
	}
	res, err := d.checkServer(ctx, checkTimeout, nil)
	if err == nil && res.Report != nil {
		d.reportedLocked(res.Report, passphrase)
		return store.ErrServerRevoked
	}
	return d.enforceOfflineLocked(ctx)
}

// recheckReportLocked runs before an unlock of a vault the server reported
// revoked: only the server's authentication of this device clears it. The
// caller holds d.mu.
func (d *Daemon) recheckReportLocked(ctx context.Context, passphrase []byte) error {
	res, err := d.checkServer(ctx, checkTimeout, passphrase)
	switch {
	case err != nil:
		return fmt.Errorf("%w (the server could not be asked again: %v)", store.ErrServerRevoked, err)
	case res.Report != nil:
		d.reportedLocked(res.Report, passphrase)
		return store.ErrServerRevoked
	}
	d.logf("the server accepts this device again: its report that the device left the account is cleared")
	return nil
}

// OpPolicy reads the account's policy, or with params sets it.
const OpPolicy = "policy"

// PolicyParams is the request for OpPolicy that sets the policy.
type PolicyParams struct {
	// MaxOffline is the max-offline policy in seconds; 0 turns it off.
	MaxOffline int64 `json:"max_offline"`
}

// PolicyResult answers OpPolicy.
type PolicyResult struct {
	MaxOffline int64 `json:"max_offline"` // seconds; 0: off
	// Pending means a change to it has not reached the server yet.
	Pending     bool       `json:"pending,omitempty"`
	LastContact *time.Time `json:"last_contact,omitempty"`
}

// policyStore is the store's policy writer (*store.Store).
type policyStore interface {
	PutPolicy(ctx context.Context, p model.Policy) (model.Policy, error)
}

// opPolicy answers OpPolicy. set, when not nil, replaces the policy: the
// first policy item is updated and any other deleted, so the account ends
// up with one.
func (d *Daemon) opPolicy(ctx context.Context, set *PolicyParams) (*PolicyResult, error) {
	rs, _, ok := d.revocations()
	ps, okP := d.store.(policyStore)
	if !ok || !okP {
		return nil, &Error{Code: CodeLocalOnly, Message: "this vault is local-only, so it has no account policy"}
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	snap, err := d.store.Snapshot(ctx)
	if err != nil {
		return nil, err
	}
	if set != nil {
		if set.MaxOffline < 0 || (set.MaxOffline != 0 && (set.MaxOffline < 60 || set.MaxOffline > int64(maxPolicyOffline))) {
			return nil, invalidf("the max-offline time must be off, or between a minute and ten years")
		}
		p := model.Policy{}
		if len(snap.Policies) > 0 {
			p = snap.Policies[0]
		}
		p.MaxOffline = uint64(set.MaxOffline)
		if _, err := ps.PutPolicy(ctx, p); err != nil {
			return nil, storeError(err)
		}
		for _, other := range snap.Policies[min(1, len(snap.Policies)):] {
			if err := d.store.Delete(ctx, other.ItemID); err != nil {
				return nil, storeError(err)
			}
		}
		d.localWrite()
		if snap, err = d.store.Snapshot(ctx); err != nil {
			return nil, err
		}
	}
	out := &PolicyResult{MaxOffline: int64(model.EffectiveMaxOffline(snap.Policies))}
	for _, p := range snap.Policies {
		if _, marked := snap.Marks[p.ItemID]; marked {
			out.Pending = true
		}
	}
	if at, has, err := rs.LastContact(); err == nil && has {
		out.LastContact = &at
	}
	return out, nil
}

// maxPolicyOffline is crypto.MaxPolicyOffline.
const maxPolicyOffline = 10 * 366 * 24 * 3600
