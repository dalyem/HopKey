package daemon

import (
	"context"
	crand "crypto/rand"
	"errors"
	"fmt"
	"math/rand/v2"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/dalyem/hopkey/internal/model"
	"github.com/dalyem/hopkey/internal/store"
	"github.com/dalyem/hopkey/internal/syncclient"
	"github.com/dalyem/hopkey/internal/vaultlog"
)

// Automatic sync (design "Automatic sync", crypto spec §11.2). While the
// vault is server-backed and unlocked, one goroutine keeps it current: it
// pushes the outbox head while records are pending, and otherwise holds a
// long-poll open for the next entry. A local write, an unlock, sync.now
// and a catch-up pull all wake it, cutting the long-poll short, since the
// store runs one pull or push at a time. Failures back off exponentially,
// with jitter, up to a minute. A lock pauses it (the store discards
// whatever was in flight); an equivocation, a rule violation, a revocation
// and a finished logout stop it.

// SyncOptions configures automatic sync.
type SyncOptions struct {
	// Client configures the HTTP client of each server. DevInsecure is
	// also set by HOP_DEV_INSECURE=1.
	Client syncclient.Options
	// Wait is how long a pull waits for a new entry; zero means 50 s.
	Wait time.Duration

	// Test hooks. after replaces time.After for backoff and idle waits;
	// minBackoff and maxBackoff replace 1 s and 60 s; catchUpAge replaces
	// how old the last pull must be before a catch-up; pushTimeout
	// replaces 15 s; noPoll keeps the loop from pulling unless asked (it
	// still pushes).
	after                  func(time.Duration) <-chan time.Time
	minBackoff, maxBackoff time.Duration
	catchUpAge             time.Duration
	pushTimeout            time.Duration
	noPoll                 bool
}

const (
	defaultWait       = 50 * time.Second
	defaultMinBackoff = time.Second
	defaultMaxBackoff = 60 * time.Second
	defaultCatchUpAge = 3 * time.Second
	// catchUpTimeout bounds the pull a missed target waits for.
	catchUpTimeout = 2 * time.Second
	// defaultPushTimeout bounds one push, its pull included, so queued
	// changes do not wait on a server that stopped answering for as long
	// as a request may take, while status says online.
	defaultPushTimeout = 15 * time.Second
	// idleRecheck is how often an idle loop looks at the store again, in
	// case something changed that did not wake it (a publication, say).
	idleRecheck = 30 * time.Second
	// syncNowTimeout bounds an explicit hop sync from the moment the daemon
	// receives it: any wait for the loop, the pull and every push. One
	// against a server that has stopped answering fails in seconds and says
	// so, not after a background push's deadline, a request timeout or the
	// HTTP/2 health check. The background loop keeps its own deadlines and
	// backoff.
	syncNowTimeout = 8 * time.Second
	// maxSyncNowPushes bounds the records one sync.now pushes.
	maxSyncNowPushes = 64
	// maxReplacedNotes bounds the notes noteReplaced keeps.
	maxReplacedNotes = 10
	// devicesSeenTimeout bounds the question devices.list asks the server.
	devicesSeenTimeout = 5 * time.Second
)

// syncStore is the sync side of the encrypted store (*store.Store).
type syncStore interface {
	Generation() uint64
	Info() store.Info
	ServerInfo() (store.ServerInfo, error)
	DeviceAuth() (store.DeviceAuth, error)
	Status() (store.SyncStatus, error)
	RequestContext(ctx context.Context) (context.Context, uint64, func(), error)
	Pull(ctx context.Context, r store.Remote) error
	PushHead(ctx context.Context, r store.Remote) (store.PushResult, error)
	Replacements() (store.Replacements, error)
	AckReplacements(r store.Replacements) error
	Lock()

	Retirement() (string, error)
	Logout(ctx context.Context, r store.Retirer, opts store.LogoutOptions) (store.LogoutResult, error)
	Publication() (*store.Publication, error)
	ResumePublish(ctx context.Context, p store.Publisher) (store.Publication, error)
	PendingCheckpoint() (*store.CheckpointStatus, error)
	ResumeCheckpoint(ctx context.Context, r store.Remote) (store.Kit, error)

	HeldHead() (*store.HeldRecord, error)
	Propose(r store.Resolution) (store.Proposal, error)
	Resolve(r store.Resolution) error
	Devices() ([]store.DeviceListing, error)
	LostIntents() (uint64, error)
	LostJournals() (store.LostJournals, error)
}

var _ syncStore = (*store.Store)(nil)

// backoff is exponential backoff with jitter: the nth failure in a row
// waits a random time in the upper half of min·2^(n-1), capped at max.
type backoff struct {
	min, max time.Duration
	rand     func() float64 // in [0, 1)
}

func (b backoff) delay(attempt int) time.Duration {
	d := b.min
	for i := 1; i < attempt && d < b.max; i++ {
		d *= 2
	}
	if d > b.max {
		d = b.max
	}
	return d/2 + time.Duration(b.rand()*float64(d/2))
}

// step results: run again at once, wait to be woken, or stop.
const (
	stepNow  time.Duration = 0
	stepIdle time.Duration = -1
	stepStop time.Duration = -2
)

// request kinds.
const (
	reqPull    = iota // one pull, for a catch-up
	reqSyncNow        // pull, then push the outbox
)

type syncReq struct {
	// ctx is the request's own context, a sync.now's budget included, and
	// caller the context it was asked in: the caller giving up is not the
	// server failing to answer.
	ctx    context.Context
	caller context.Context
	kind   int
	done   chan error
	// answer is the error serve got from the server, sent before serve
	// acts on it: the check after a refusal may outlast the budget, and
	// the refusal is still the answer.
	answer chan error
}

// syncer is the sync engine.
type syncer struct {
	d    *Daemon
	st   syncStore
	opts SyncOptions
	bo   backoff

	wakeCh chan struct{}
	// pause stops the loop from pulling or pushing (tests).
	pause atomic.Bool
	// held counts the server checks in progress (holdPolls): while any
	// is, the loop starts no step, so no long-poll holds the store's sync
	// lock for them to wait on. parked says the loop waits for them.
	held   atomic.Int32
	parked atomic.Bool

	mu        sync.Mutex
	pollStop  context.CancelFunc // ends the long-poll in flight
	pushStop  context.CancelFunc // ends the background push in flight (sync.now)
	reqs      []*syncReq
	stopped   bool
	clients   map[string]*syncclient.Client
	remote    *syncclient.Remote
	remoteKey string
	remoteGen uint64
	resumed   uint64 // the generation whose startup work is done, if resumedOK
	resumedOK bool

	// Status.
	phase     string
	syncedAt  time.Time
	lastErr   string
	lastErrAt time.Time
	attempt   int
	retryAt   time.Time
	halted    string
	equivoc   bool
	notes     []string // from the startup work: things that need the user
	// replaced are the newest notes of pushed changes that replaced
	// another device's (noteReplaced), at most maxReplacedNotes.
	replaced []string
	// notesErr is the last error reading or acknowledging the store's
	// notes, logged once.
	notesErr string
	// noteMu makes each noteReplaced's read, record and acknowledgement
	// one step, so no note is recorded twice.
	noteMu sync.Mutex
	// retired is the server's word that this device left the account
	// (reportedLocked), and whether its proof wiped the device.
	retired *ServerRetirement
	// checkSkipped says why the last question to the server before keys
	// loaded went unanswered (checkServer); "" once one is answered.
	checkSkipped string
	// maxOffline is the account's max-offline policy (0: off), lastContact
	// the last authenticated contact as last read, and offline why the
	// policy locked the vault (enforceOfflineLocked).
	maxOffline  time.Duration
	lastContact time.Time
	offline     string
	// unconfirmed says why the server's answer kept the vault locked
	// (unconfirmedLocked); "" once it accepts the device.
	unconfirmed string

	// confirmKey keys the confirmation tokens of resolution proposals
	// (confirmToken). It is random per daemon process.
	confirmKey [32]byte
}

func newSyncer(d *Daemon, st syncStore, opts SyncOptions) *syncer {
	if opts.Wait <= 0 {
		opts.Wait = defaultWait
	}
	if opts.Wait > syncclient.MaxWait {
		opts.Wait = syncclient.MaxWait
	}
	if opts.after == nil {
		opts.after = time.After
	}
	if opts.minBackoff <= 0 {
		opts.minBackoff = defaultMinBackoff
	}
	if opts.maxBackoff <= 0 {
		opts.maxBackoff = defaultMaxBackoff
	}
	if opts.catchUpAge == 0 {
		opts.catchUpAge = defaultCatchUpAge
	}
	if opts.pushTimeout <= 0 {
		opts.pushTimeout = defaultPushTimeout
	}
	if syncclient.DevInsecureFromEnv(os.Getenv) {
		opts.Client.DevInsecure = true
	}
	e := &syncer{
		d: d, st: st, opts: opts,
		bo:     backoff{min: opts.minBackoff, max: opts.maxBackoff, rand: rand.Float64},
		wakeCh: make(chan struct{}, 1),
		phase:  SyncStarting, clients: map[string]*syncclient.Client{},
	}
	crand.Read(e.confirmKey[:])
	return e
}

// newSync makes the engine for a store that can sync, without starting
// it.
func (d *Daemon) newSync() {
	if st, ok := d.store.(syncStore); ok {
		d.sync = newSyncer(d, st, d.opts.Sync)
	}
}

// startSync starts the engine newSync made.
func (d *Daemon) startSync() {
	if d.sync == nil {
		return
	}
	d.wg.Add(1)
	go func() {
		defer d.wg.Done()
		d.sync.run(d.ctx)
	}()
}

// wake makes the loop look at the store again at once, ending a long-poll
// or a backoff wait.
func (e *syncer) wake() {
	if e == nil {
		return
	}
	// The token goes first: a long-poll that starts after it sees it
	// (step), and one already started is ended here.
	select {
	case e.wakeCh <- struct{}{}:
	default:
	}
	e.mu.Lock()
	stop := e.pollStop
	e.mu.Unlock()
	if stop != nil {
		stop()
	}
}

// holdPolls ends the long-poll in flight and keeps the loop from taking
// the store's sync lock again until the func it returns is called, so a
// server check (checkServer) gets it at once. A loop that waited for it
// resumes then. It does not wake the loop otherwise: the loop's own checks
// (sessionEnded, retryUnconfirmed) hold it too.
func (e *syncer) holdPolls() func() {
	e.held.Add(1)
	e.mu.Lock()
	stop := e.pollStop
	e.mu.Unlock()
	if stop != nil {
		stop()
	}
	return func() {
		if e.held.Add(-1) == 0 && e.parked.Swap(false) {
			e.wake()
		}
	}
}

// parkForCheck reports whether a server check holds the loop
// (holdPolls); the loop then waits for it to end.
func (e *syncer) parkForCheck() bool {
	if e.held.Load() == 0 {
		return false
	}
	e.parked.Store(true)
	// Released meanwhile: then nothing wakes the loop, so it goes on.
	return e.held.Load() > 0 || !e.parked.Swap(false)
}

func (e *syncer) run(ctx context.Context) {
	defer func() {
		e.mu.Lock()
		e.stopped = true
		reqs := e.reqs
		e.reqs = nil
		clients := e.clients
		e.mu.Unlock()
		for _, r := range reqs {
			r.done <- store.ErrClosed
		}
		for _, c := range clients {
			c.CloseIdleConnections()
		}
	}()
	for ctx.Err() == nil {
		e.serveRequests(ctx)
		switch wait := e.step(ctx); wait {
		case stepStop:
			e.idle(ctx, nil, true)
			return
		case stepNow:
		case stepIdle:
			e.idle(ctx, time.After(idleRecheck), false)
		default:
			e.idle(ctx, e.opts.after(wait), false)
		}
	}
}

// idle waits for a wake, ctx or timer. A stopped loop waits for ctx only,
// answering requests (with refusals) meanwhile.
func (e *syncer) idle(ctx context.Context, timer <-chan time.Time, stopped bool) {
	for {
		select {
		case <-ctx.Done():
			return
		case <-timer:
			return
		case <-e.wakeCh:
			if !stopped {
				return
			}
			e.serveRequests(ctx)
		}
	}
}

func (e *syncer) set(f func()) {
	e.mu.Lock()
	defer e.mu.Unlock()
	f()
}

func (e *syncer) setPhase(p string) { e.set(func() { e.phase = p }) }

// step does one round of syncing and says when to do the next.
func (e *syncer) step(ctx context.Context) time.Duration {
	if e.terminal() {
		return stepStop
	}
	if e.pause.Load() || e.parkForCheck() {
		return stepIdle
	}
	if e.status().Halted != "" {
		// Never retried past an equivocation or a rule violation; the
		// store stays halted until it is opened again.
		return stepIdle
	}
	gen := e.st.Generation()
	// A logout in progress resumes first. It needs no unlock.
	if state, err := e.st.Retirement(); err != nil {
		return e.fail(ctx, gen, err)
	} else if state != "" {
		return e.resumeLogout(ctx)
	}
	info := e.st.Info()
	switch {
	case info.Revoked:
		e.setPhase(SyncRevoked)
		return stepStop
	case info.ServerReport != nil:
		// Until the server authenticates this device again (an unlock or
		// a start asks it), nothing syncs.
		rep := info.ServerReport
		e.set(func() {
			e.phase = SyncRevoked
			if e.retired == nil {
				e.retired = &ServerRetirement{How: rep.How, Seq: rep.Seq, Unverified: true}
			}
		})
		return stepIdle
	case info.Locked && info.ServerUnconfirmed:
		// The server answered without confirming this device: ask again.
		e.setPhase(SyncLocked)
		if e.d.retryUnconfirmed(ctx) {
			return stepNow
		}
		return stepIdle
	case info.Locked:
		e.setPhase(SyncLocked)
		return stepIdle
	}
	e.set(func() {
		if e.phase == SyncLocked || e.phase == SyncOff || (e.phase == SyncRevoked && e.retired != nil && e.retired.Unverified) {
			e.phase, e.retired = SyncStarting, nil
		}
	})
	// The generation the requests below are made in: a refusal is acted
	// on only while the store is still in it (sessionEnded).
	gen = e.st.Generation()
	if d, done := e.resumeUnlocked(ctx, gen); !done {
		return d
	}
	r, err := e.remoteFor(gen)
	if err != nil {
		return e.fail(ctx, gen, err)
	}
	if r == nil {
		e.setPhase(SyncOff)
		return stepIdle
	}
	st, err := e.st.Status()
	if err != nil {
		return e.fail(ctx, gen, err)
	}
	if st.Halted != "" {
		e.noteHalt(st.Halted, false)
		return stepIdle
	}
	if st.Held == 0 && st.Pending > 0 {
		// A sync.now ends the push (request), so it does not wait out the
		// push's deadline behind a server that stopped answering. A request
		// already queued goes first instead: it may push this record itself.
		pctx, cancel := context.WithCancel(ctx)
		e.mu.Lock()
		queued := len(e.reqs) > 0
		if !queued {
			e.pushStop = cancel
		}
		e.mu.Unlock()
		if queued {
			cancel()
			return stepNow
		}
		res, err := e.pushHead(pctx, r)
		e.set(func() { e.pushStop = nil })
		cancel()
		if err != nil {
			e.reconcile(ctx, gen, &st)
			return e.fail(ctx, gen, err)
		}
		e.pushed(ctx, gen, res)
		if res.Outcome != store.PushEmpty {
			return stepNow
		}
		// Nothing PushHead could push after all: wait for news rather
		// than ask again.
	}
	if e.opts.noPoll {
		return stepIdle
	}
	pctx, cancel := context.WithCancel(ctx)
	e.set(func() { e.pollStop = cancel })
	select {
	case <-e.wakeCh:
		// Woken before the long-poll could be ended by it.
		cancel()
	default:
	}
	if e.held.Load() > 0 {
		// A server check began since the step did: it goes first.
		cancel()
	}
	// Only once the server has answered does a pull wait for news: until
	// then, at start and after a failure, status would say starting or
	// retrying for as long as the long-poll lasts.
	wait := e.opts.Wait
	if e.status().State != SyncOnline {
		wait = 0
	}
	err = e.st.Pull(pctx, r.WithWait(wait))
	woken := pctx.Err() != nil
	e.set(func() { e.pollStop = nil })
	cancel()
	if err != nil {
		e.reconcile(ctx, gen, &st)
	}
	if err != nil && woken && ctx.Err() == nil && e.st.Generation() == gen {
		// Cut short by a wake.
		return stepNow
	}
	if err != nil {
		return e.fail(ctx, gen, err)
	}
	e.pulled(ctx, gen)
	return stepNow
}

// terminal reports whether sync has stopped for good: a verified
// revocation, or a finished logout. A revocation only the server reports is
// not (reportedLocked).
func (e *syncer) terminal() bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	return (e.phase == SyncRevoked && (e.retired == nil || !e.retired.Unverified)) || e.phase == SyncLoggedOut
}

// pushHead pushes the outbox's head record under the per-push deadline,
// its pulls included, so queued changes do not wait on a server that
// stopped answering for as long as a request may take, whether the loop
// or hop sync pushes.
func (e *syncer) pushHead(ctx context.Context, r store.Remote) (store.PushResult, error) {
	ctx, cancel := context.WithTimeout(ctx, e.opts.pushTimeout)
	defer cancel()
	return e.st.PushHead(ctx, r)
}

// pulled records a pull that worked and reloads if it changed anything.
func (e *syncer) pulled(ctx context.Context, gen uint64) {
	e.noteReplaced()
	e.set(func() {
		e.syncedAt = time.Now()
		e.attempt, e.retryAt, e.lastErr, e.lastErrAt = 0, time.Time{}, "", time.Time{}
		e.phase = SyncOnline
	})
	if e.st.Generation() == gen {
		e.d.refreshAfterSync(ctx)
	}
}

// reconcile follows the store after a pull or push that failed or was
// cut short, keeping the failure for the caller to record. The store
// commits verified entries one at a time, so a pull that stopped on a bad
// entry may have committed a deletion before it, and a push may have
// changed the outbox before it failed: the agent and the ssh config are
// rebuilt if the verified head or the outbox moved. before is the outbox
// as it was, if it was read. Nothing is rebuilt once the store has left
// generation gen (a lock fences the old keyring off already) or the
// daemon is closing.
func (e *syncer) reconcile(ctx context.Context, gen uint64, before *store.SyncStatus) {
	e.noteReplaced()
	if ctx.Err() != nil || e.st.Generation() != gen {
		return
	}
	// A change to the outbox is seen only through its Pending and Held
	// counts, and one to the log through the verified head (current). A
	// failed push that changed the outbox without moving either count or
	// the head goes unnoticed until something moves one of them.
	if after, err := e.st.Status(); err == nil && before != nil && (after.Pending != before.Pending || after.Held != before.Held) {
		e.d.outboxGen.Add(1)
	}
	e.d.refreshAfterSync(ctx)
}

// pushed records a push that worked: PushHead pulled first, and the outbox
// changed unless it was empty.
func (e *syncer) pushed(ctx context.Context, gen uint64, res store.PushResult) {
	if res.Outcome != store.PushEmpty {
		e.d.outboxGen.Add(1)
	}
	if res.Outcome == store.PushHeld {
		e.d.logf("sync: queued change %d is held: %+v", res.N, res.Hold)
	}
	e.pulled(ctx, gen)
}

// fail records err and says what to do next: wait for a wake when the
// vault is locked or sync has halted, stop on a revocation, and otherwise
// back off. gen is the store's generation the failed request was made in
// (sessionEnded).
func (e *syncer) fail(ctx context.Context, gen uint64, err error) time.Duration {
	if ctx.Err() != nil || errors.Is(err, store.ErrClosed) {
		return stepStop
	}
	if errors.Is(err, context.Canceled) {
		// Not by the daemon: a lock or a close cancelled the request
		// (§11.2), and the next step sees which, or a sync.now ended a
		// background push to run first.
		return stepNow
	}
	var eq *vaultlog.EquivocationError
	switch {
	case errors.Is(err, store.ErrDeviceRevoked):
		e.revoked(err)
		return stepStop
	case errors.As(err, &eq), errors.Is(err, store.ErrSyncHalted):
		e.noteHalt(err.Error(), eq != nil)
		return stepIdle
	case errors.Is(err, model.ErrLocked):
		e.setPhase(SyncLocked)
		e.d.mu.Lock()
		e.d.followStore(err)
		e.d.mu.Unlock()
		return stepIdle
	case errors.Is(err, store.ErrNotServerBacked):
		e.setPhase(SyncOff)
		return stepIdle
	case errors.Is(err, store.ErrSessionEnded):
		if e.sessionEnded(ctx, gen) {
			return stepIdle
		}
	}
	var wait time.Duration
	e.set(func() {
		e.attempt++
		wait = e.bo.delay(e.attempt)
		e.phase, e.lastErr, e.lastErrAt, e.retryAt = SyncBackingOff, err.Error(), time.Now(), time.Now().Add(wait)
	})
	e.d.logf("sync: %v (retrying in %v)", err, wait.Round(time.Millisecond))
	return wait
}

// noteReplaced records the pushed changes that replaced another device's
// value of a free member (store.Replacement), as verified history settles
// them: the merge keeps the last change to reach the server there, and
// holds nothing (§5.4), so the other device's value is gone and this is
// where the user hears of it. It runs after every pull and push, worked or
// not, since the one that settles a change need not be the push that
// posted it (an answer lost, a post repeated), nor this daemon's (an auth
// command's pull, while the daemon was stopped). The store keeps each note
// until it is recorded here, in the log and in sync.status, and only then
// is it acknowledged. The note names the item and the members, never a
// value.
func (e *syncer) noteReplaced() {
	e.noteMu.Lock()
	defer e.noteMu.Unlock()
	rs, err := e.st.Replacements()
	if err == nil {
		if rs.Evicted > 0 {
			e.d.logf("sync: %d older notes of this device's edits that replaced another device's value were dropped before they were shown "+
				"(the vault keeps the newest ones until the daemon shows them)", rs.Evicted)
		}
		for _, r := range rs.Notes {
			what := fmt.Sprintf("%s %q", r.Type, r.Name)
			if r.Name == "" {
				what = fmt.Sprintf("%s %s", r.Type, r.ItemID)
			}
			msg := fmt.Sprintf("%s: this device's edit of its %s replaced a different value another device had saved first "+
				"(for this field the last change to reach the server wins)", what, strings.Join(r.Fields, ", "))
			e.d.logf("sync: %s", msg)
			e.set(func() {
				e.replaced = append(e.replaced, msg)
				if len(e.replaced) > maxReplacedNotes {
					e.replaced = e.replaced[len(e.replaced)-maxReplacedNotes:]
				}
			})
		}
		err = e.st.AckReplacements(rs)
	}
	// A locked store keeps its notes for after the next unlock.
	why := ""
	if err != nil && !errors.Is(err, model.ErrLocked) {
		why = err.Error()
	}
	e.mu.Lock()
	first := why != "" && why != e.notesErr
	e.notesErr = why
	e.mu.Unlock()
	if first {
		e.d.logf("sync: the notes of replaced edits: %s", why)
	}
}

func (e *syncer) noteHalt(why string, equivocation bool) {
	e.mu.Lock()
	first := e.halted == ""
	e.phase, e.halted = SyncHalted, why
	e.equivoc = e.equivoc || equivocation
	e.mu.Unlock()
	if first {
		e.d.logf("sync stopped: %s", why)
	}
}

// revoked stops sync for good and takes the daemon to the revoked state:
// an empty agent and an empty ssh config.
// A verified revocation then wipes this device's copy of the vault
// (wipeVerified).
func (e *syncer) revoked(err error) {
	e.setPhase(SyncRevoked)
	e.d.mu.Lock()
	e.d.followStore(store.ErrDeviceRevoked)
	e.d.mu.Unlock()
	e.d.logf("sync stopped: %v", err)
	e.d.wipeVerified()
}

// sessionEnded handles the server refusing this device a session: an
// active device always gets one, so it may have left the account. Its
// entries are not served to it any more, so the revocation can't be
// verified from the log; CheckServer asks again and, if the server says it
// left, records the report and locks the vault (reportedLocked), and the
// proof is asked for. Any other outcome but the server accepting the
// device, a server that can't be asked again included, locks the vault
// until it does (unconfirmedLocked): the refusal was the server's answer.
// gen is the store's generation the refused request was made in: a lock
// or an unlock since (hop lock, say, while the request was out) is not
// taken over, so a refusal only locks, or labels a lock unconfirmed, while
// the store is still in gen. It reports whether sync stopped.
func (e *syncer) sessionEnded(ctx context.Context, gen uint64) bool {
	if e.d.opts.sessionRefused != nil {
		e.d.opts.sessionRefused()
	}
	res, err := e.d.checkServer(ctx, sessionCheckTimeout, nil, gen)
	switch {
	case err == nil && res.Report != nil:
		e.d.mu.Lock()
		defer e.d.mu.Unlock()
		e.d.reportedLocked(res.Report, nil)
		return true
	case err == nil:
		return false
	case unreachable(err):
		err = fmt.Errorf("the server refused this device a session, and could not be asked again: %w", err)
	}
	e.d.mu.Lock()
	defer e.d.mu.Unlock()
	if !e.d.stillUnconfirmed(err, gen) {
		return false
	}
	e.d.unconfirmedLocked(err)
	return true
}

// resumeLogout finishes a logout in progress (§11.1): RETIRING resumes its
// resolution and RETIRED its cleanup.
func (e *syncer) resumeLogout(ctx context.Context) time.Duration {
	e.setPhase(SyncLoggingOut)
	gen := e.st.Generation()
	var r store.Retirer
	if info, err := e.st.ServerInfo(); err == nil && info.Server != "" && !info.VaultID.IsZero() {
		c, err := e.client(info.Server)
		if err != nil {
			return e.fail(ctx, gen, err)
		}
		r = c.Retirer(info.VaultID)
	}
	res, err := e.st.Logout(ctx, r, store.LogoutOptions{})
	if err != nil {
		if errors.Is(err, store.ErrDeviceRevoked) || errors.Is(err, store.ErrClosed) || ctx.Err() != nil {
			return e.fail(ctx, gen, err)
		}
		d := e.fail(ctx, gen, err)
		e.setPhase(SyncLoggingOut)
		return d
	}
	if !res.Done {
		return stepNow
	}
	e.set(func() {
		e.phase = SyncLoggedOut
		e.attempt, e.retryAt = 0, time.Time{}
		if res.RevokeElsewhere {
			e.notes = append(e.notes, "the logout did not reach the server: if this device is still listed, revoke it from another device")
		}
	})
	e.d.mu.Lock()
	e.d.dropKeysLocked(true)
	e.d.mu.Unlock()
	e.d.logf("the logout finished: nothing of the vault is left on this device")
	return stepStop
}

// resumeUnlocked runs, once per unlock, what an interrupted command left
// for the daemon to finish: a publication, then a server-backed
// checkpoint whose candidate may have committed. done is false while it
// still has to run; d then says when to try again.
//
// An interrupted device approval is not resumed here, though the store
// could (Approval, ApproveFinish): finishing one means comparing the SAS
// with the new device's user, so it is hop auth approve's job, through
// authflow. sync.status warns about an approval whose journal was lost.
func (e *syncer) resumeUnlocked(ctx context.Context, gen uint64) (d time.Duration, done bool) {
	e.mu.Lock()
	finished := e.resumedOK && e.resumed == gen
	e.mu.Unlock()
	if finished {
		return 0, true
	}
	// Only a failure worth retrying (the server unreachable or busy, a
	// lock) holds sync back; any other is left for the user, and sync goes
	// on without it.
	retry := func(err error) bool {
		return syncclient.Retryable(err) || errors.Is(err, model.ErrLocked) || errors.Is(err, store.ErrClosed) ||
			errors.Is(err, store.ErrDeviceRevoked) || ctx.Err() != nil
	}
	note := func(what string, err error) {
		e.d.logf("%s: %v", what, err)
		e.set(func() { e.notes = append(e.notes, fmt.Sprintf("%s: %v", what, err)) })
	}
	if p, err := e.st.Publication(); err != nil {
		if retry(err) {
			return e.fail(ctx, gen, err), false
		}
		note("the pending publication can't be read", err)
	} else if p != nil {
		c, err := e.client(p.Server)
		if err == nil {
			_, err = e.st.ResumePublish(ctx, c.Publisher(p.VaultID))
		}
		if err != nil {
			e.reconcile(ctx, gen, nil)
		}
		var eq *vaultlog.EquivocationError
		switch {
		case errors.As(err, &eq):
			// The publication stays pending with its alarm; it is never
			// retried past an equivocation.
			e.noteHalt(err.Error(), true)
			return stepIdle, false
		case err != nil && retry(err):
			return e.fail(ctx, gen, err), false
		case err != nil:
			note("the pending publication did not finish (run hop auth signup again)", err)
		default:
			e.d.logf("the pending publication to %s finished", p.Server)
			e.d.outboxGen.Add(1)
			e.d.refreshAfterSync(ctx)
		}
	}
	if cp, err := e.st.PendingCheckpoint(); err != nil {
		if retry(err) {
			return e.fail(ctx, gen, err), false
		}
		note("the pending checkpoint can't be read", err)
	} else if cp != nil && !cp.Committed {
		r, err := e.remoteFor(gen)
		if err != nil {
			return e.fail(ctx, gen, err), false
		}
		if r != nil {
			_, err := e.st.ResumeCheckpoint(ctx, r)
			if err != nil {
				e.reconcile(ctx, gen, nil)
			}
			switch {
			case errors.Is(err, store.ErrNoCheckpoint):
			case err != nil && retry(err):
				return e.fail(ctx, gen, err), false
			case err != nil:
				note("a "+cp.Kind+" checkpoint did not finish (run the same command again)", err)
			default:
				e.d.logf("the pending %s checkpoint committed; its Emergency Kit is waiting", cp.Kind)
				e.d.refreshAfterSync(ctx)
			}
		}
	}
	e.set(func() { e.resumed, e.resumedOK = gen, true })
	return 0, true
}

// client returns the HTTP client for server, made once.
func (e *syncer) client(server string) (*syncclient.Client, error) {
	if server == "" {
		return nil, errors.New("daemon: no server is recorded for this vault")
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if c, ok := e.clients[server]; ok {
		return c, nil
	}
	c, err := syncclient.New(server, e.opts.Client)
	if err != nil {
		return nil, err
	}
	e.clients[server] = c
	return c, nil
}

// remoteFor returns the vault's Remote for the unlocked store generation
// gen, or nil when the vault is local-only or names no server.
func (e *syncer) remoteFor(gen uint64) (*syncclient.Remote, error) {
	info, err := e.st.ServerInfo()
	if errors.Is(err, store.ErrNotServerBacked) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if info.Server == "" || info.VaultID.IsZero() {
		return nil, nil
	}
	key := info.Server + " " + info.VaultID.String()
	e.mu.Lock()
	if e.remote != nil && e.remoteKey == key && e.remoteGen == gen {
		r := e.remote
		e.mu.Unlock()
		return r, nil
	}
	e.mu.Unlock()
	c, err := e.client(info.Server)
	if err != nil {
		return nil, err
	}
	// Each authentication asks the store for a signer, so a lock ends the
	// client's ability to authenticate too.
	dev, err := syncclient.StoreDevice(e.st.DeviceAuth)
	if err != nil {
		return nil, err
	}
	r := c.Remote(info.VaultID, dev)
	e.set(func() { e.remote, e.remoteKey, e.remoteGen = r, key, gen })
	return r, nil
}

// devicesSeen asks the server when each of the account's devices last made
// a request, for devices.list. Nil when it can't say (the vault is
// local-only or locked, or the server does not answer in time): the
// listing then goes by the log alone.
func (e *syncer) devicesSeen(ctx context.Context) map[model.ID]time.Time {
	r, err := e.remoteFor(e.st.Generation())
	if err != nil || r == nil {
		return nil
	}
	ctx, cancel := context.WithTimeout(ctx, devicesSeenTimeout)
	defer cancel()
	rctx, _, done, err := e.st.RequestContext(ctx)
	if err != nil {
		return nil
	}
	defer done()
	seen, err := r.DevicesSeen(rctx)
	if err != nil {
		e.d.logf("asking the server when each device was last seen: %v", err)
		return nil
	}
	return seen
}

// request asks the loop to run kind and waits for it, or for ctx. A
// sync.now has syncNowTimeout from here, whatever the loop is doing, and
// ends the background push or long-poll in flight rather than wait for it.
func (e *syncer) request(ctx context.Context, kind int) error {
	r := &syncReq{ctx: ctx, caller: ctx, kind: kind, done: make(chan error, 1), answer: make(chan error, 1)}
	if kind == reqSyncNow {
		var cancel context.CancelFunc
		r.ctx, cancel = context.WithTimeout(ctx, syncNowTimeout)
		defer cancel()
	}
	e.mu.Lock()
	if e.stopped {
		e.mu.Unlock()
		return store.ErrClosed
	}
	e.reqs = append(e.reqs, r)
	var stopPush context.CancelFunc
	if kind == reqSyncNow {
		stopPush = e.pushStop
	}
	e.mu.Unlock()
	if stopPush != nil {
		stopPush()
	}
	e.wake()
	select {
	case err := <-r.done:
		return err
	case <-r.ctx.Done():
	}
	// The loop's answer, if it came at the same moment, goes first: it may
	// be the server's. So does one the loop still acts on.
	select {
	case err := <-r.done:
		return err
	default:
	}
	select {
	case err := <-r.answer:
		return err
	default:
	}
	if kind == reqSyncNow {
		return syncNowError(r.ctx.Err(), r.ctx, r.caller)
	}
	return r.ctx.Err()
}

func (e *syncer) serveRequests(ctx context.Context) {
	for {
		e.mu.Lock()
		if len(e.reqs) == 0 {
			e.mu.Unlock()
			return
		}
		r := e.reqs[0]
		e.reqs = e.reqs[1:]
		e.mu.Unlock()
		if err := r.ctx.Err(); err != nil {
			r.done <- err
			continue
		}
		r.done <- e.serve(ctx, r)
	}
}

// serve runs one request in the loop, so it never waits behind a
// long-poll. Its own failures don't change the backoff schedule.
func (e *syncer) serve(ctx context.Context, req *syncReq) error {
	rctx, cancel := context.WithCancel(req.ctx)
	defer cancel()
	stop := context.AfterFunc(ctx, cancel)
	defer stop()
	switch phase := e.status().State; phase {
	case SyncRevoked:
		return store.ErrDeviceRevoked
	case SyncLoggedOut, SyncLoggingOut:
		return store.ErrLoggingOut
	}
	if e.st.Info().Locked {
		return model.ErrLocked
	}
	gen := e.st.Generation()
	r, err := e.remoteFor(gen)
	if err != nil {
		return err
	}
	if r == nil {
		return store.ErrNotServerBacked
	}
	var before *store.SyncStatus
	if st, err := e.st.Status(); err == nil {
		before = &st
	}
	err = e.st.Pull(rctx, r)
	if err == nil && req.kind == reqSyncNow {
		for range maxSyncNowPushes {
			var res store.PushResult
			res, err = e.pushHead(rctx, r)
			if err != nil {
				break
			}
			if res.Outcome != store.PushEmpty {
				e.d.outboxGen.Add(1)
			}
			if res.Outcome == store.PushEmpty || res.Outcome == store.PushHeld {
				break
			}
		}
	}
	if req.kind == reqSyncNow {
		err = syncNowError(err, req.ctx, req.caller)
	}
	if err != nil {
		req.answer <- err
		e.reconcile(ctx, gen, before)
		var eq *vaultlog.EquivocationError
		switch {
		case errors.Is(err, store.ErrDeviceRevoked):
			e.revoked(err)
		case errors.As(err, &eq), errors.Is(err, store.ErrSyncHalted):
			e.noteHalt(err.Error(), eq != nil)
		case errors.Is(err, store.ErrSessionEnded):
			e.sessionEnded(ctx, gen)
		}
		if req.kind == reqSyncNow {
			e.set(func() { e.lastErr, e.lastErrAt = err.Error(), time.Now() })
		}
		return err
	}
	e.pulled(ctx, gen)
	return nil
}

// catchUp runs one bounded pull for a target that matched nothing, when
// the last pull is older than a few seconds. It reports whether one ran
// and worked.
func (e *syncer) catchUp(ctx context.Context) bool {
	if e == nil {
		return false
	}
	s := e.status()
	switch s.State {
	case SyncOff, SyncLocked, SyncHalted, SyncRevoked, SyncLoggingOut, SyncLoggedOut:
		return false
	}
	if s.SyncedAt != nil && time.Since(*s.SyncedAt) < e.opts.catchUpAge {
		return false
	}
	cctx, cancel := context.WithTimeout(ctx, catchUpTimeout)
	defer cancel()
	err := e.request(cctx, reqPull)
	if err != nil {
		e.d.logf("catch-up pull: %v", err)
	}
	return err == nil
}

// status is the engine's part of SyncStatusResult.
func (e *syncer) status() SyncStatusResult {
	e.mu.Lock()
	defer e.mu.Unlock()
	out := SyncStatusResult{State: e.phase, LastError: e.lastErr, Halted: e.halted, Equivocation: e.equivoc,
		CheckSkipped: e.checkSkipped, MaxOffline: int64(e.maxOffline / time.Second), OfflineLocked: e.offline,
		ServerUnconfirmed: e.unconfirmed}
	if e.retired != nil {
		r := *e.retired
		out.ServerRetirement = &r
	}
	if !e.lastContact.IsZero() {
		t := e.lastContact
		out.LastContact = &t
	}
	if !e.syncedAt.IsZero() {
		t := e.syncedAt
		out.SyncedAt = &t
	}
	if !e.lastErrAt.IsZero() {
		t := e.lastErrAt
		out.LastErrorAt = &t
	}
	if e.phase == SyncBackingOff {
		out.Backoff = &SyncBackoff{Attempt: e.attempt, RetryAt: e.retryAt}
	}
	out.Warnings = append(out.Warnings, e.notes...)
	out.Warnings = append(out.Warnings, e.replaced...)
	return out
}

// syncNowError is the error of an explicit sync whose budget (budget, the
// request's context) has run out while the caller still waits: one the
// deadline caused says the server did not answer. Any other error is the
// server's answer, a session refusal or a revocation say, and is kept as
// it is, or the refusal handling that follows would never see it.
func syncNowError(err error, budget, caller context.Context) error {
	if err == nil || budget.Err() != context.DeadlineExceeded || caller.Err() != nil {
		return err
	}
	if !errors.Is(err, context.DeadlineExceeded) && !errors.Is(err, syncclient.ErrUnreachable) {
		return err
	}
	return fmt.Errorf("%w: the server did not answer within %s", syncclient.ErrUnreachable, syncNowTimeout)
}
