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
// for at most checkTimeout in all, waiting for a sync in progress included
// (a long-poll is cut short for it). A refusal with a report records it:
// the vault stays locked, the agent empty and the ssh config emptied, after
// a restart too, and the daemon asks the server for the proof (prove). A
// proof that verifies wipes this device's copy of the vault as a logout
// does. A report clears only when the server authenticates this device
// again: at the next start, or the next hop unlock.
//
// Only a server that can't be reached (unreachable: DNS, dial, a reset, a
// timeout, TLS, a 5xx or 429 from what stands in front of it) is no reason
// to refuse: the keys load, and status says the check was skipped. Any
// other answer that does not confirm the device, a session refused without
// a valid report or a response the client can't use, keeps the vault
// locked in memory (unconfirmedLocked), deletes and records nothing, and
// the next unlock or sync asks again.
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
	// the clock counts as set back: the clock skew the policy allows.
	clockSlack = 5 * time.Minute
)

// unreachable reports whether err means the server could not be asked:
// the request failed below HTTP (DNS, dial, a refused or reset
// connection, a TLS handshake), the certificate did not verify (a captive
// portal or a proxy in the way, which could block the traffic anyway), the
// deadline passed (waiting for a sync in progress included), or what
// answered is a proxy or server that is down or busy (5xx, 429). Only
// these let keys load without an answer.
func unreachable(err error) bool {
	return syncclient.Retryable(err) || errors.Is(err, syncclient.ErrTLS) || errors.Is(err, context.DeadlineExceeded)
}

// unlockCheck is the server check of one unlock (unlockVault): one
// deadline, checkTimeout from the first question, for every question it
// asks, and whether the server accepted the device already.
type unlockCheck struct {
	parent   context.Context
	ctx      context.Context
	cancel   context.CancelFunc
	accepted bool
}

func (c *unlockCheck) context() context.Context {
	if c.ctx == nil {
		c.ctx, c.cancel = context.WithTimeout(c.parent, checkTimeout)
	}
	return c.ctx
}

func (c *unlockCheck) done() {
	if c.cancel != nil {
		c.cancel()
	}
}

// revocationStore is the revocation side of the encrypted store
// (*store.Store).
type revocationStore interface {
	CheckServer(ctx context.Context, r store.ServerChecker, passphrase []byte, gen uint64) (store.ServerCheck, error)
	UnconfirmedLock() (uint64, bool)
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
// status. A long-poll in flight is ended first, and none starts until the
// answer is in, so the question does not wait for one. An unanswered
// question is returned as the error; unreachable says whether that lets
// keys load. gen is the store's generation the caller decided to ask in:
// the store locks for a refusal only while it is still in it. It does not
// take d.mu, but a report found, or an answer that does not confirm the
// device, is acted on by the caller (reportedLocked, unconfirmedLocked).
func (d *Daemon) checkServer(ctx context.Context, timeout time.Duration, passphrase []byte, gen uint64) (store.ServerCheck, error) {
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
	defer e.holdPolls()()
	if d.opts.beforeCheck != nil {
		d.opts.beforeCheck()
	}
	res, err := rs.CheckServer(ctx, r, passphrase, gen)
	switch {
	case err != nil && unreachable(err):
		why := err.Error()
		e.set(func() { e.checkSkipped = why })
		d.logf("the server could not be asked whether this device is still in the account: %v", err)
	case err != nil:
		d.logf("asking the server whether this device is still in the account: %v", err)
	case res.Active:
		e.set(func() {
			e.checkSkipped, e.unconfirmed = "", ""
			if e.retired != nil && e.retired.Unverified {
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

// unconfirmedLocked keeps the keys out after the server answered without
// confirming this device (err): the vault is locked in memory, nothing is
// recorded or deleted, and status says why. The next unlock asks again,
// and so does the sync loop (retryUnconfirmed). It returns the error,
// which matches store.ErrServerUnconfirmed. The caller holds d.mu.
func (d *Daemon) unconfirmedLocked(err error) error {
	rs, e, ok := d.revocations()
	if !ok {
		return err
	}
	refused := errors.Is(err, store.ErrSessionRefused)
	if !errors.Is(err, store.ErrServerUnconfirmed) {
		err = fmt.Errorf("%w (%v)", store.ErrServerUnconfirmed, err)
	}
	rs.LockFor(err)
	if refused {
		// The server's refusal is how a revoked device learns it.
		d.endSessions(whyRefused)
	}
	d.dropKeysLocked(false)
	why := err.Error()
	e.set(func() { e.unconfirmed, e.checkSkipped = why, "" })
	d.logf("the vault stays locked: %v", err)
	return err
}

// stillUnconfirmed reports whether err, the answer to a check that the
// sync loop started in generation gen, is still to be acted on by
// unconfirmedLocked: the store locked itself for it (CheckServer), and
// nothing locked or unlocked the vault since, or, for any other answer,
// nothing locked or unlocked the vault meanwhile (hop lock, say, whose
// cancellation is no answer). The caller holds d.mu.
func (d *Daemon) stillUnconfirmed(err error, gen uint64) bool {
	if errors.Is(err, store.ErrServerUnconfirmed) {
		rs, _, ok := d.revocations()
		if !ok {
			return false
		}
		_, ok = rs.UnconfirmedLock()
		return ok
	}
	return d.sync.st.Generation() == gen
}

// retryUnconfirmed asks the server again about a vault unconfirmedLocked
// locked, and once it accepts the device, unlocks the vault with the
// device key and loads the agent, as hop unlock would. Only that lock
// unlocks: the store's UnconfirmedLock names it by its generation, and it
// must still be the vault's lock, under d.mu, when the vault unlocks. Any
// other lock since (hop lock, the max-offline policy, a report) is a new
// generation and stays. It reports whether the vault unlocked.
func (d *Daemon) retryUnconfirmed(ctx context.Context) bool {
	v, ok := d.store.(Vault)
	rs, _, okR := d.revocations()
	if !ok || !okR {
		return false
	}
	gen, ok := rs.UnconfirmedLock()
	if !ok {
		return false
	}
	if d.opts.unconfirmedRead != nil {
		d.opts.unconfirmedRead()
	}
	res, err := d.checkServer(ctx, sessionCheckTimeout, nil, gen)
	d.mu.Lock()
	defer d.mu.Unlock()
	switch {
	case err == nil && res.Report != nil:
		d.reportedLocked(res.Report, nil)
		return false
	case err != nil && !unreachable(err) && d.stillUnconfirmed(err, gen):
		d.unconfirmedLocked(err)
		return false
	case err != nil:
		return false
	}
	if cur, ok := rs.UnconfirmedLock(); !ok || cur != gen {
		// Locked or unlocked meanwhile: not the lock the server left.
		return false
	}
	if err := v.Unlock(ctx); err != nil {
		d.logf("the server accepts this device again, but the vault did not unlock: %v", err)
		return false
	}
	if err := d.checkBeforeKeysLocked(&unlockCheck{parent: ctx, accepted: true}, nil); err != nil {
		return false
	}
	d.sync.set(func() { d.sync.offline, d.sync.unconfirmed = "", "" })
	d.logf("the server accepts this device again: the vault is unlocked")
	if _, err := d.reloadLocked(ctx); err != nil {
		d.logf("loading the agent: %v", err)
	}
	return true
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
	d.endSessions(whyRevoked)
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

// wiped follows a proven revocation (why wraps store.ErrDeviceRevoked) and
// the wipe of this device's copy of the vault it started, finished or not
// (store.ErrWipeIncomplete): sync stops for good, and the ssh config is
// emptied and its files removed, which clears the store's mark that it was
// owed. Status calls the device wiped only once both are done (syncStatus).
func (d *Daemon) wiped(why error) {
	e := d.sync
	wipeErr := ""
	if errors.Is(why, store.ErrWipeIncomplete) {
		wipeErr = why.Error()
	}
	e.set(func() {
		e.phase, e.lastErr, e.lastErrAt = SyncRevoked, why.Error(), time.Now()
		r := &ServerRetirement{How: "revoked", WipeError: wipeErr}
		if e.retired != nil {
			r.How, r.Seq = e.retired.How, e.retired.Seq
		}
		e.retired = r
	})
	d.mu.Lock()
	d.endSessions(whyRevoked)
	d.dropKeysLocked(true)
	pending := d.pendingClear()
	d.mu.Unlock()
	switch {
	case wipeErr != "":
		d.logf("this device was revoked from the account, verified; wiping its copy of the vault did not finish, and finishes at the next start: %v", why)
	case pending != "":
		d.logf("this device was revoked from the account, verified: its copy of the vault and its device key were wiped; the ssh files hop wrote are not removed yet (%s), and the daemon tries again (%v)", pending, why)
	default:
		d.logf("this device was revoked from the account, verified: its copy of the vault, its device key and the ssh files hop wrote were wiped (%v)", why)
	}
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
// contradicts unlocks with its own device key. An answer that does not
// confirm the device keeps it locked too; only a server that can't be
// reached lets the keys load unasked. Then the max-offline policy.
func (d *Daemon) preflight(ctx context.Context) {
	_, e, ok := d.revocations()
	if !ok {
		return
	}
	v, _ := d.store.(Vault)
	gen := e.st.Generation()
	info := e.st.Info()
	if info.Revoked {
		if !d.wipeVerified() {
			// Not wiped yet, but revoked all the same (wiped ends them
			// when it is).
			d.endSessions(whyRevoked)
		}
		return
	}
	if info.Locked && info.ServerReport == nil {
		// Nothing to protect; hop unlock asks.
		return
	}
	res, err := d.checkServer(ctx, checkTimeout, nil, gen)
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
		d.endSessions(whyRevoked)
		return
	case err != nil && !unreachable(err):
		d.unconfirmedLocked(err)
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
	now := d.now()
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
	d.endSessions(whyOffline)
	d.dropKeysLocked(false)
	e.set(func() { e.offline = why })
	d.sync.wake()
	d.logf("the vault locked itself: %v", err)
	return err
}

// now is the time the max-offline policy is checked at.
func (d *Daemon) now() time.Time {
	if d.opts.now != nil {
		return d.opts.now()
	}
	return time.Now()
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
// and before the agent gets a key: the server is asked, unless it accepted
// the device already in c, and the max-offline policy applied. A report,
// or an answer that does not confirm the device, locks the vault again;
// only an unreachable server lets it through unasked. The caller holds
// d.mu.
func (d *Daemon) checkBeforeKeysLocked(c *unlockCheck, passphrase []byte) error {
	_, e, ok := d.revocations()
	if !ok {
		return nil
	}
	if !c.accepted {
		res, err := d.checkServer(c.context(), checkTimeout, nil, e.st.Generation())
		switch {
		case err == nil && res.Report != nil:
			d.reportedLocked(res.Report, passphrase)
			return store.ErrServerRevoked
		case err != nil && !unreachable(err):
			return d.unconfirmedLocked(err)
		}
		c.accepted = err == nil
	}
	return d.enforceOfflineLocked(c.parent)
}

// recheckReportLocked runs before an unlock of a vault the server reported
// revoked: only the server's authentication of this device clears it. A
// device key this daemon can't open without the device passphrase is
// returned as is (store.ErrDeviceKey), so hop unlock asks for it and tries
// again. The caller holds d.mu.
func (d *Daemon) recheckReportLocked(c *unlockCheck, passphrase []byte) error {
	res, err := d.checkServer(c.context(), checkTimeout, passphrase, d.sync.st.Generation())
	switch {
	case errors.Is(err, store.ErrDeviceKey):
		return fmt.Errorf("the server must accept this device again before the vault unlocks, and asking it needs the device key: %w", err)
	case err != nil:
		return fmt.Errorf("%w (the server could not be asked again: %v)", store.ErrServerRevoked, err)
	case res.Report != nil:
		d.reportedLocked(res.Report, passphrase)
		return store.ErrServerRevoked
	}
	c.accepted = true
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
