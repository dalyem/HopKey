package cli

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/dalyem/hopkey/internal/authflow"
	"github.com/dalyem/hopkey/internal/crypto"
	"github.com/dalyem/hopkey/internal/daemon"
	"github.com/dalyem/hopkey/internal/safepath"
	"github.com/dalyem/hopkey/internal/store"
	"github.com/dalyem/hopkey/internal/syncclient"
)

// The daemon owns the vault while it runs: a second store.Open fails with
// store.ErrVaultBusy. A hop auth flow needs the store itself, so it stops
// the daemon, runs the flow on its own store, and starts the daemon again,
// which then syncs whatever the flow left (a signed-in vault, a published
// one, queued merge imports).

// shutdownDaemon asks a running daemon to exit and waits until its
// sockets are gone. It reports whether one was running. It prints
// nothing, so a --json command's stdout keeps its shape.
//
// Only a refusal from the daemon means it is still running. Any other
// failure leaves the outcome unknown: a signal that cancels ctx can cut
// the read short after the daemon accepted the request. So the wait for
// its sockets runs on its own bounded context, whatever became of ctx,
// and the caller learns from daemonGone whether the daemon stopped.
func shutdownDaemon(ctx context.Context, e *Env) (bool, error) {
	c, err := dialExisting(ctx, e)
	if err != nil || c == nil {
		return false, err
	}
	defer c.Close()
	callErr := c.Call(ctx, daemon.OpShutdown, nil, nil)
	var refused *daemon.Error
	if errors.As(callErr, &refused) {
		return true, cleanErr(callErr)
	}
	// The daemon answers before it finishes closing. Wait for its sockets to
	// go, so a command that follows does not find a daemon on its way out.
	wctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), shutdownWait)
	defer cancel()
	for !e.daemonGone() {
		select {
		case <-wctx.Done():
			if callErr != nil {
				return true, cleanErr(callErr)
			}
			return true, failf("asked the hop daemon to stop, but its sockets are still there after %s", shutdownWait)
		case <-time.After(25 * time.Millisecond):
		}
	}
	return true, cleanErr(callErr)
}

// shutdownWait bounds how long shutdownDaemon waits for the daemon's
// sockets to go.
const shutdownWait = 5 * time.Second

// daemonGone reports whether both of the daemon's sockets are gone.
func (e *Env) daemonGone() bool {
	_, ctlErr := os.Lstat(e.Paths.ControlSocket())
	_, agentErr := os.Lstat(e.Paths.AgentSocket())
	return os.IsNotExist(ctlErr) && os.IsNotExist(agentErr)
}

// vaultHold is one hop auth command's hold of the vault.
//
// While it lasts, a marker file in the run directory names this process
// (holdMarker). The CLI's autostart and hop daemon both refuse to start a
// daemon while the marker names a live process, so a hop command run
// meanwhile can't start one that takes the vault from under the flow.
// What remains: a daemon that a concurrent command launched just before
// the marker was written, and that opens the vault after this command
// stopped the old one, still wins; open then reports the vault busy, and
// the flow changes nothing.
//
// The daemon is started again however the command ends: release, deferred
// by every command, on a normal return or a cancelled context; abandon,
// from Run's signal watcher, when SIGINT or SIGTERM arrives while the flow
// is stuck where the context does not reach (a prompt reading the
// terminal), just before the process exits.
type vaultHold struct {
	e      *Env
	cfg    store.Config
	asJSON bool // the command's output mode, for the warnings of release and abandon
	marker string
	once   sync.Once // the daemon's restart, by release or abandon
	// loggedOut says open finished a logout that a crash had cut short.
	loggedOut bool

	// mu guards what follows: the flow sets it, and abandon reads it from
	// Run's signal watcher, once, when it takes over.
	mu sync.Mutex
	// handPass says the command succeeded (succeeded), so release opens
	// the vault in the daemon it starts with the device passphrase typed
	// for the command (handDevicePassphrase).
	handPass bool
	// keepOpen is for a command on a vault that already exists: release
	// opens the vault in the daemon it starts with the typed device
	// passphrase however the command ended, unless the daemon it stopped
	// had the vault locked (wasLocked), so an open vault stays open. It
	// ends once the vault is leaving (leaving), and comes back as keep
	// says if the vault turns out to stay (staying).
	keepOpen, keep bool
	// wasLocked says the daemon holdVault stopped had the vault locked,
	// which a command that fails does not undo: release locks it again,
	// even where the daemon it starts opens it by itself (a keychain, an
	// unsealed key file).
	wasLocked bool
	// closers free the vault where the flow holds it (track): its stores,
	// a prepared fork. abandon runs them when the command is interrupted.
	closers []func()
}

// succeeded records that the command did what it was run for.
func (h *vaultHold) succeeded() {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.handPass = true
}

// leaving records that the flow has begun to replace or delete the vault,
// so the vault it found is not opened again.
func (h *vaultHold) leaving() {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.keepOpen = false
}

// staying records that the replacement or deletion leaving began did not
// happen after all, so the vault the command found is there, and goes back
// as it was found.
func (h *vaultHold) staying() {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.keepOpen = h.keep
}

// restoreTo is the state the daemon gets the vault in when the command
// ends (restoreLockState).
type restoreTo int

const (
	restoreAsItOpens restoreTo = iota // whatever the daemon makes of it
	restoreLocked
	restoreOpen // with the device passphrase typed for the command
)

// target is the state the vault goes back to: open after a command that
// made it or signed in to it, and otherwise as the command found it.
func (h *vaultHold) target() restoreTo {
	h.mu.Lock()
	defer h.mu.Unlock()
	switch {
	case h.handPass:
		return restoreOpen
	case h.wasLocked:
		return restoreLocked
	case h.keepOpen:
		return restoreOpen
	}
	return restoreAsItOpens
}

// track registers close, which frees the vault where the flow holds it,
// for abandon, and returns it to run once, by whichever runs it first.
func (h *vaultHold) track(close func()) func() {
	var once sync.Once
	f := func() { once.Do(close) }
	h.mu.Lock()
	defer h.mu.Unlock()
	h.closers = append(h.closers, f)
	return f
}

// holdMarkerName is the marker's name in the run directory.
const holdMarkerName = "auth-hold"

// holdMarkerMaxAge bounds how long a marker counts, for a holder whose
// pid was reused by another process.
const holdMarkerMaxAge = time.Hour

func (e *Env) holdMarker() string { return filepath.Join(e.Paths.RunDir, holdMarkerName) }

// holdInfo is what the marker says: the pid of the hop auth command, and
// handback once that command launched the daemon that is to take the vault
// after it.
type holdInfo struct {
	pid      int
	handback bool
}

// readHold reads the marker. ok is false unless it names a live process
// other than this one.
func (e *Env) readHold() (holdInfo, bool) {
	path := e.holdMarker()
	fi, err := os.Lstat(path)
	if err != nil || !fi.Mode().IsRegular() || time.Since(fi.ModTime()) > holdMarkerMaxAge {
		return holdInfo{}, false
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return holdInfo{}, false
	}
	hi, ok := parseHold(string(b))
	if !ok || hi.pid == os.Getpid() || !processAlive(hi.pid) {
		return holdInfo{}, false
	}
	return hi, true
}

// parseHold reads a marker's text: "PID" or "PID handback".
func parseHold(text string) (holdInfo, bool) {
	f := strings.Fields(text)
	if len(f) == 0 || len(f) > 2 || (len(f) == 2 && f[1] != "handback") {
		return holdInfo{}, false
	}
	pid, err := strconv.Atoi(f[0])
	if err != nil || pid <= 0 {
		return holdInfo{}, false
	}
	return holdInfo{pid: pid, handback: len(f) == 2}, true
}

// authHolder returns the pid of a live process that holds the vault for a
// hop auth command, other than this one.
func (e *Env) authHolder() (int, bool) {
	hi, ok := e.readHold()
	return hi.pid, ok && !hi.handback
}

// handbackFrom says which hop auth command launched this daemon to take
// the vault after it.
func (e *Env) handbackFrom() (holdInfo, bool) {
	hi, ok := e.readHold()
	return hi, ok && hi.handback
}

// writeMarker replaces the marker with text, atomically.
func writeMarker(path, text string) error {
	tmp := fmt.Sprintf("%s.%d.tmp", path, os.Getpid())
	if err := os.WriteFile(tmp, []byte(text), 0o600); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		os.Remove(tmp)
		return err
	}
	return nil
}

// errHeld is the refusal while another hop auth command holds the vault.
func errHeld(pid int) error {
	return failf("a hop auth command (pid %d) has the vault while it runs, and the hop daemon starts again when it ends; try again then", pid)
}

// mark writes the marker. One that names a dead process is replaced; one
// that names a live one refuses.
func (h *vaultHold) mark() error {
	if pid, ok := h.e.authHolder(); ok {
		return errHeld(pid)
	}
	if _, err := safepath.EnsurePrivateDir(h.e.Paths.RunDir); err != nil {
		return failf("%v", err)
	}
	path := h.e.holdMarker()
	tmp := fmt.Sprintf("%s.%d.tmp", path, os.Getpid())
	if err := os.WriteFile(tmp, []byte(strconv.Itoa(os.Getpid())+"\n"), 0o600); err != nil {
		return failf("%v", err)
	}
	defer os.Remove(tmp)
	// A link fails if another command marked first; a stale marker is
	// replaced (the check above found its holder dead).
	if err := os.Link(tmp, path); err != nil {
		if hi, ok := h.e.readHold(); ok {
			if hi.handback {
				return failf("the hop daemon is starting again after an interrupted hop auth command (pid %d); try again in a moment", hi.pid)
			}
			return errHeld(hi.pid)
		}
		if err := os.Rename(tmp, path); err != nil {
			return failf("%v", err)
		}
	}
	h.marker = path
	return nil
}

// unmark removes the marker if it is still this process's, a handback
// included.
func (h *vaultHold) unmark() {
	if h.marker == "" {
		return
	}
	if b, err := os.ReadFile(h.marker); err == nil {
		if hi, ok := parseHold(string(b)); ok && hi.pid == os.Getpid() {
			os.Remove(h.marker)
		}
	}
	h.marker = ""
}

// handOver turns the marker into a handback for the daemon about to be
// started. It reports whether the marker says so.
func (h *vaultHold) handOver() bool {
	return h.marker != "" && writeMarker(h.marker, fmt.Sprintf("%d handback\n", os.Getpid())) == nil
}

// startLockedName is, in the run directory, the instruction a hop auth
// command leaves for the daemon that takes the vault after it: keep it
// locked (startLocked). It is apart from the marker, which counts only
// while its holder lives: away from a prompt the holder launches the daemon
// and exits, and the daemon may read the run directory after that.
const startLockedName = "start-locked"

// startLockedMaxAge bounds how long an instruction to start locked is
// followed: past the time the daemon it was left for takes to open the
// vault (handbackWait), and short, so that one left by a daemon that never
// started does not lock a vault made later in the same place.
const startLockedMaxAge = 2 * time.Minute

func (e *Env) startLockedFile() string { return filepath.Join(e.Paths.RunDir, startLockedName) }

// startLocked leaves the instruction to start locked for the vault in this
// data directory: the next daemon to open it locks it before it serves
// anything (pendingStartLocked), although its device key may open by itself.
func (e *Env) startLocked() error {
	dir, err := filepath.Abs(e.storeConfig().DataDir)
	if err != nil {
		return err
	}
	if _, err := safepath.EnsurePrivateDir(e.Paths.RunDir); err != nil {
		return err
	}
	return writeMarker(e.startLockedFile(), dir+"\n")
}

// pendingStartLocked reports whether the vault this daemon has opened is
// to be served locked, and returns the instruction's file, which
// dropStartLocked removes once the daemon serves: it is for one daemon, and
// one that does not get to serve leaves it for the next. One for another
// data directory is left for its own daemon; one older than
// startLockedMaxAge is removed and not followed.
func (e *Env) pendingStartLocked() (os.FileInfo, bool) {
	path := e.startLockedFile()
	fi, err := os.Lstat(path)
	if err != nil || !fi.Mode().IsRegular() {
		return nil, false
	}
	if time.Since(fi.ModTime()) > startLockedMaxAge {
		os.Remove(path)
		return nil, false
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, false
	}
	here, err := filepath.Abs(e.storeConfig().DataDir)
	if err != nil || !sameDir(strings.TrimSpace(string(b)), here) {
		return nil, false
	}
	return fi, true
}

// dropStartLocked removes the instruction to start locked that
// pendingStartLocked returned, once the daemon serves the vault locked. One
// that has replaced it since is left.
func (e *Env) dropStartLocked(followed os.FileInfo) {
	path := e.startLockedFile()
	if fi, err := os.Lstat(path); err == nil && os.SameFile(fi, followed) {
		os.Remove(path)
	}
}

// holdVault stops the daemon so this process can own the vault. asJSON
// is the command's output mode.
func holdVault(ctx context.Context, e *Env, asJSON bool) (*vaultHold, error) {
	return holdVaultKeeping(ctx, e, asJSON, false)
}

// holdVaultKeeping is holdVault for a command on a vault that exists, when
// keep is set: release opens the vault in the daemon it starts again with
// the device passphrase typed for the command, however the command ends,
// unless the vault was locked. Whether the daemon has the vault locked is
// noted before it is stopped, keep or not: a vault that was locked is
// locked again unless the command succeeded.
func holdVaultKeeping(ctx context.Context, e *Env, asJSON, keep bool) (*vaultHold, error) {
	// The policy is settled before the hold is published: Run's signal
	// watcher may read it from then on.
	h := &vaultHold{e: e, cfg: e.storeConfig(), asJSON: asJSON, keepOpen: keep, keep: keep}
	if err := h.mark(); err != nil {
		return nil, err
	}
	h.wasLocked = daemonVaultLocked(ctx, e)
	e.setHold(h)
	if _, err := shutdownDaemon(ctx, e); err != nil {
		if e.daemonGone() {
			// The daemon stopped although the request failed (a signal
			// cut its answer short): start it again.
			h.release(ctx)
		} else {
			// The daemon was not stopped, so nothing is handed back.
			h.once.Do(h.unmark)
			e.setHold(nil)
		}
		return nil, err
	}
	return h, nil
}

// holdVaultWithKey is holdVault for a command that opens the vault itself
// on a vault that exists, and so needs the passphrase of a sealed device
// key file (requireDevicePassphrase). The passphrase is settled first: a
// failure there leaves the daemon as it was. However the command ends, the
// vault is open in the daemon afterwards if it was open before.
func holdVaultWithKey(ctx context.Context, e *Env, asJSON bool) (*vaultHold, error) {
	if err := requireDevicePassphrase(e, asJSON); err != nil {
		e.clearDevicePass()
		return nil, err
	}
	h, err := holdVaultKeeping(ctx, e, asJSON, true)
	if err != nil {
		e.clearDevicePass()
		return nil, err
	}
	return h, nil
}

// openHere returns the status of the running daemon when it serves this
// vault and has it open, so that stopping it loses something release must
// put back; otherwise nil.
func openHere(ctx context.Context, e *Env) *daemon.StatusResult {
	c, err := dialExisting(ctx, e)
	if err != nil || c == nil {
		return nil
	}
	defer c.Close()
	st, err := servesThisVault(ctx, e, c)
	if err != nil || st.Vault == nil || st.Vault.Locked {
		return nil
	}
	return &st
}

// daemonVaultLocked reports whether a running daemon has the vault locked.
// A daemon that is not running, or does not answer, has nothing locked.
func daemonVaultLocked(ctx context.Context, e *Env) bool {
	c, err := dialExisting(ctx, e)
	if err != nil || c == nil {
		return false
	}
	defer c.Close()
	var st daemon.StatusResult
	return c.Call(ctx, daemon.OpStatus, nil, &st) == nil && st.Vault != nil && st.Vault.Locked
}

func (e *Env) setHold(h *vaultHold) {
	e.holdMu.Lock()
	defer e.holdMu.Unlock()
	e.hold = h
}

func (e *Env) currentHold() *vaultHold {
	e.holdMu.Lock()
	defer e.holdMu.Unlock()
	return e.hold
}

// busyWait bounds how long open waits for a daemon on its way out to let
// go of the vault.
const vaultBusyWait = 10 * time.Second

// open opens the data directory's vault, or returns nil when there is
// none. The daemon closes the vault after its sockets are gone, so a busy
// vault is tried again for a while. A logout that was recorded before a
// crash finishes as the vault opens (store.ErrLoggedOut), and open then
// returns nil with h.loggedOut set. Wherever there turns out to be no
// vault, the ssh config a finished logout still owes is emptied
// (finishLogoutCleanup).
func (h *vaultHold) open(ctx context.Context) (*store.Store, error) {
	exists, err := store.Exists(h.cfg.DataDir)
	if err != nil {
		return nil, failf("%v", err)
	}
	if !exists {
		finishLogoutCleanup(h.e, h.asJSON)
		return nil, nil
	}
	deadline := time.Now().Add(vaultBusyWait)
	for {
		s, err := store.Open(ctx, h.cfg)
		if errors.Is(err, store.ErrNoVault) {
			h.loggedOut = errors.Is(err, store.ErrLoggedOut)
			finishLogoutCleanup(h.e, h.asJSON)
			return nil, nil
		}
		if !errors.Is(err, store.ErrVaultBusy) || time.Now().After(deadline) {
			if errors.Is(err, store.ErrVaultBusy) {
				return nil, failf("the vault is busy: another hop process owns it (hop auth stops the daemon first; is another hop auth command running?)")
			}
			if err != nil {
				return nil, failf("opening the vault: %v", err)
			}
			h.track(func() { s.Close() })
			return s, nil
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(50 * time.Millisecond):
		}
	}
}

// release starts the daemon again when a vault is left, so it syncs. A
// daemon that does not come up is a warning: the command itself is done,
// and hop sync, or the next command that needs the daemon, starts it. The
// command has closed its stores by now (each is closed by a defer that
// runs first).
//
// The old daemon removes its sockets before it closes its store, so it
// can still own the vault here: when a signal cut its shutdown answer
// short, or when the command ended before it opened the vault. A daemon
// started then would find the vault busy and exit, so release first waits
// for the vault to be free, with the marker still keeping autostart out.
func (h *vaultHold) release(ctx context.Context) {
	h.once.Do(func() {
		exists, err := store.Exists(h.cfg.DataDir)
		if err != nil || !exists {
			h.unmark()
			return
		}
		if !waitVaultFree(h.cfg.DataDir) {
			h.unmark()
			warn(h.e, h.asJSON, fmt.Sprintf("the old hop daemon still had the vault after %s, so it was not started again, and nothing syncs until it is (hop sync starts it)", releaseBusyWait))
			return
		}
		h.restart(ctx, h.target())
	})
	h.e.clearDevicePass()
	h.e.setHold(nil)
}

// restart starts the daemon again on the vault, which is free, and leaves
// the vault in it as target says (restoreLockState). A vault that is to be
// locked is handed over locked: the instruction to start locked has the
// daemon lock it before it serves anything (runDaemon), so it is never
// open in between.
func (h *vaultHold) restart(ctx context.Context, target restoreTo) {
	if target == restoreLocked {
		h.e.startLocked() // lockAgain, below, is the check
	}
	h.unmark()
	err := startDaemon(context.WithoutCancel(ctx), h.e)
	if target == restoreLocked && err == nil && servedHere(ctx, h.e) {
		// Taken by the daemon that started, or by none: lockAgain makes
		// sure. One that does not come up in time keeps it, and so does a
		// daemon of another vault, which never reads it.
		os.Remove(h.e.startLockedFile())
	}
	if err != nil {
		warn(h.e, h.asJSON, "the hop daemon did not start again, so nothing syncs until it does (hop sync starts it): "+err.Error())
		return
	}
	h.restoreLockState(ctx, target)
}

// restoreLockState leaves the vault in the daemon as the command found it,
// once release or abandon has started the daemon again: one that was
// locked stays locked, even for a device key the daemon opens by itself,
// and one that was open is open, with the device passphrase typed for the
// command when the key file is sealed. A command that made the vault or
// signed in to it (handPass) hands the passphrase over whatever the state
// was. Each takes at most restoreWait.
func (h *vaultHold) restoreLockState(ctx context.Context, target restoreTo) {
	switch target {
	case restoreOpen:
		handDevicePassphrase(ctx, h.e, h.asJSON)
	case restoreLocked:
		lockAgain(ctx, h.e, h.asJSON)
	}
}

// servedHere reports whether the running daemon says it serves this vault.
func servedHere(ctx context.Context, e *Env) bool {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), restoreWait)
	defer cancel()
	c, err := dialExisting(ctx, e)
	if err != nil || c == nil {
		return false
	}
	defer c.Close()
	_, err = servesThisVault(ctx, e, c)
	return err == nil
}

// restoreWait bounds each request that puts the lock state back.
const restoreWait = 30 * time.Second

// lockAgain makes sure the vault is locked in the daemon, and warns where
// it can't. A daemon that is not running, or that serves another vault,
// does not have this vault open, and is left alone.
func lockAgain(ctx context.Context, e *Env, asJSON bool) {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), restoreWait)
	defer cancel()
	if err := lockThisVault(ctx, e); err != nil {
		warn(e, asJSON, "the vault was locked before this command and may be open now: run hop lock ("+err.Error()+")")
	}
}

// lockThisVault locks the vault in the running daemon, if it serves this
// vault and has it open. A daemon too old to say which vault it serves is
// left alone too, but whether this vault is locked is then not known: that
// is an error.
func lockThisVault(ctx context.Context, e *Env) error {
	c, err := dialExisting(ctx, e)
	if err != nil || c == nil {
		return err
	}
	defer c.Close()
	st, err := servesThisVault(ctx, e, c)
	var other *daemonElsewhere
	if errors.As(err, &other) && other.dir != "" {
		return nil
	}
	if err != nil {
		return err
	}
	if st.Vault == nil || st.Vault.Locked {
		return nil
	}
	return cleanErr(c.Call(ctx, daemon.OpLock, nil, nil))
}

// releaseBusyWait bounds how long release waits for a daemon on its way
// out to let go of the vault. It does not stop for a cancelled context: a
// signal is what leaves the old daemon draining.
const releaseBusyWait = 5 * time.Second

// waitVaultFree waits, for at most releaseBusyWait, until no process owns
// the vault in dataDir, and reports whether none does. A failure to probe
// counts as free: the daemon's own open reports it.
func waitVaultFree(dataDir string) bool {
	deadline := time.Now().Add(releaseBusyWait)
	for {
		busy, err := store.Busy(dataDir)
		if err != nil || !busy {
			return true
		}
		if time.Now().After(deadline) {
			return false
		}
		time.Sleep(25 * time.Millisecond)
	}
}

// closeWait bounds how long abandon waits for the flow's stores to close:
// a store's close waits for a sync request it is making.
const closeWait = 5 * time.Second

// abandon is release for a process about to exit on a signal while its
// flow still runs, stuck where the context does not reach. What the vault
// goes back to (target) is settled first, and nothing the flow does from
// then on changes it.
//
// Where the flow waits at a prompt, which no longer returns to it (Env.prompt),
// what it holds the vault with is closed (track), and the daemon then
// starts as release starts it and gets the vault as the command found it:
// after Ctrl-C at a prompt an open vault is open. Elsewhere the flow may be
// using what it holds, so it is left to the exit, and the marker turns into
// a handback: hop daemon, finding the vault busy, waits for this process to
// exit (runDaemon), and keeps the vault locked if it was (startLocked),
// whether or not this process is still there when it looks. So does a vault
// that is still busy when that is closed. A release already under way
// finishes first.
//
// It takes at most closeWait, releaseBusyWait, Env.DaemonWait and
// restoreWait, 50 s by default, after Run's watcher gave the command
// Env.InterruptGrace; most of it is spent only where something hangs. A
// second Ctrl-C ends the process at once.
func (h *vaultHold) abandon() {
	atPrompt := h.e.haltPrompts()
	defer h.e.resumePrompts()
	h.once.Do(func() {
		target := h.target()
		h.mu.Lock()
		closers := h.closers
		h.closers = nil
		h.mu.Unlock()
		if exists, err := store.Exists(h.cfg.DataDir); err != nil || !exists {
			h.unmark()
			return
		}
		if atPrompt && runAll(closers, closeWait) && waitVaultFree(h.cfg.DataDir) {
			h.restart(context.Background(), target)
			return
		}
		// The marker now tells the daemon to wait for this process, and
		// the instruction to start locked outlives it.
		if target == restoreLocked {
			if err := h.e.startLocked(); err != nil {
				warn(h.e, h.asJSON, "the vault was locked before this command and may be open in the hop daemon that takes it: run hop lock ("+err.Error()+")")
			}
		}
		if !h.handOver() {
			h.unmark()
		}
		launch := h.e.StartDaemon
		if launch == nil {
			launch = func() error { return launchDaemon(h.e) }
		}
		if err := launch(); err != nil {
			warn(h.e, h.asJSON, "the hop daemon did not start again (hop sync starts it): "+err.Error())
		} else if target == restoreOpen && h.e.hasTypedPass() {
			warn(h.e, h.asJSON, "the vault is locked: the hop daemon takes it after this process, without the device passphrase typed for it; run hop unlock")
		}
	})
}

// runAll runs each of fs in turn, and reports whether they all returned
// within d. The rest go on running.
func runAll(fs []func(), d time.Duration) bool {
	done := make(chan struct{})
	go func() {
		for _, f := range fs {
			f()
		}
		close(done)
	}()
	select {
	case <-done:
		return true
	case <-time.After(d):
		return false
	}
}

// serverClient is a client for the hop-server at url. HOP_DEV_INSECURE=1
// allows a loopback http:// URL, as the daemon does.
func (e *Env) serverClient(url string) (*syncclient.Client, error) {
	opts := e.SyncClient
	if syncclient.DevInsecureFromEnv(e.Getenv) {
		opts.DevInsecure = true
	}
	c, err := syncclient.New(url, opts)
	if err != nil {
		return nil, failf("the server URL %q: %v", url, err)
	}
	return c, nil
}

// flowEnv is the authflow environment for this machine's data directory.
func (h *vaultHold) flowEnv(c *syncclient.Client, ui *termUI) *authflow.Env {
	return &authflow.Env{Config: h.cfg, Client: c, UI: ui}
}

// signedIn opens the signed-in vault for a flow that needs one: the
// store, unlocked, with a client for its server.
func (h *vaultHold) signedIn(ctx context.Context) (*store.Store, *authflow.Vault, error) {
	s, err := h.open(ctx)
	if err != nil {
		return nil, nil, err
	}
	if s == nil {
		return nil, nil, failf("there is no vault on this device: sign in with hop auth login, or create an account with hop auth signup")
	}
	v, err := h.vaultOf(s)
	if err != nil {
		s.Close()
		return nil, nil, err
	}
	return s, v, nil
}

// errLocalOnlyVault is the refusal of a command that needs a signed-in
// vault, on a local-only one.
const errLocalOnlyVault = "this vault is local-only: hop auth signup publishes it to a server, or hop auth login --merge merges it into an account"

// refuseLocalOnly refuses a command that needs a signed-in vault on a
// local-only one, as signedIn does, but before anything is asked or the
// daemon stopped. It reads vault/server.json only, so it works while the
// daemon owns the vault. With no vault it lets the command go on: no
// secret is asked for one, and signedIn says so.
func refuseLocalOnly(e *Env) error {
	if localOnlyVault(e) {
		return failf("%s", errLocalOnlyVault)
	}
	return nil
}

// localOnlyVault reports whether this device has a vault that is not
// signed in to a server. It reads the vault's files only, so it works while
// the daemon owns the vault.
func localOnlyVault(e *Env) bool {
	dir := e.storeConfig().DataDir
	if ok, err := store.Exists(dir); err != nil || !ok {
		return false
	}
	server, err := store.ServerBackedDir(dir)
	return err == nil && !server
}

func (h *vaultHold) vaultOf(s *store.Store) (*authflow.Vault, error) {
	si, err := s.ServerInfo()
	if errors.Is(err, store.ErrNotServerBacked) {
		return nil, failf("%s", errLocalOnlyVault)
	}
	if err != nil {
		return nil, failf("%v", err)
	}
	if si.Server == "" {
		return nil, failf("this vault has no server recorded")
	}
	c, err := h.e.serverClient(si.Server)
	if err != nil {
		return nil, err
	}
	if s.Info().Locked {
		// The reason says what to do about it, where anything can be done.
		if why := s.Info().LockReason; why != "" {
			return nil, failf("the vault is locked (%s)", why)
		}
		return nil, failf("the vault is locked; run hop unlock first")
	}
	v, err := authflow.NewVault(h.cfg, s, c)
	if err != nil {
		return nil, authFailure(err)
	}
	return v, nil
}

// closeStores closes each distinct store once.
func closeStores(ss ...*store.Store) {
	var done []*store.Store
	for _, s := range ss {
		if s == nil {
			continue
		}
		seen := false
		for _, d := range done {
			seen = seen || d == s
		}
		if !seen {
			s.Close()
			done = append(done, s)
		}
	}
}

// interruptedText is all hop says of a command that Ctrl-C (or a cancelled
// context) ended, whatever it was doing: the same words wherever it was.
const interruptedText = "interrupted"

// authFailure is a flow's error as the user reads it.
func authFailure(err error) error {
	if err == nil {
		return nil
	}
	var ee *exitError
	if errors.As(err, &ee) {
		return err
	}
	var limit *authflow.MailboxLimitError
	var mismatch *authflow.ServerMismatchError
	switch {
	case errors.Is(err, context.Canceled):
		// What a cancelled flow wraps quotes URLs and paths, which the user
		// need not see; and it is one text for every command that Ctrl-C
		// ends (interruptedText).
		return failf("%s", interruptedText)
	case errors.Is(err, authflow.ErrLocalVault):
		return failf("this device has a local-only vault: hop auth login --merge (with --method password or recovery) merges it into the account, or hop auth signup publishes it")
	case errors.Is(err, authflow.ErrSignedIn):
		return failf("this device is already signed in to a server (hop auth status shows which); hop auth logout first to sign in again")
	case errors.Is(err, authflow.ErrLoginFailed):
		return failf("the server refused the login: a wrong master password or Secret Key, or no account has that email")
	case errors.Is(err, authflow.ErrRecoveryFailed):
		return failf("the server refused the recovery: a wrong Recovery Key, or no account has that email")
	case errors.Is(err, authflow.ErrSASMismatch):
		return failf("the codes did not match, so nothing was sent to the new device. Start again on the new device")
	case errors.Is(err, authflow.ErrUnknownCode):
		return failf("no new device is waiting with that code: it was mistyped, or its request expired or finished (a request lasts 10 minutes). " +
			"Check the code the new device shows; if it is gone, run hop auth login again on the new device")
	case errors.Is(err, crypto.ErrEnrollExpired):
		return failf("the approval request expired, so nothing was installed: a request lasts 10 minutes, and the other device did not finish it in time " +
			"(it may have answered no, or cancelled, or never run hop auth approve). Run hop auth login again on the new device")
	case errors.Is(err, crypto.ErrSASRejected):
		return failf("this device's check code was rejected, so nothing was installed. Run hop auth login again to start over")
	case errors.As(err, &limit):
		return failf("%s", mailboxLimitText(limit))
	case errors.As(err, &mismatch):
		return failf("%s", originMismatchText(mismatch))
	case errors.Is(err, store.ErrOutboxNotEmpty):
		return failf("queued changes have not reached the server yet: wait for the daemon to send them (hop sync shows them), or log out with --discard-pending to drop them")
	}
	return failf("%v", err)
}

// originMismatchText is the refusal of a server URL that is not the origin
// the vault has: signatures to the server cover its origin, so a vault only
// works with the one it recorded. It says both, and that the account is not
// the problem, which a refused login would suggest.
func originMismatchText(m *authflow.ServerMismatchError) string {
	what := "this vault is signed in to"
	if m.Publication {
		what = "the publication of this vault that was started went to"
	}
	return fmt.Sprintf("origin mismatch: %s %s, but the server URL given is %s. "+
		"Use the same origin, character for character (hop auth status shows the recorded one). "+
		"This is about the server's address, not about the account or the password", what, oneLine(m.Recorded), oneLine(m.Given))
}

// mailboxLimitText is the refusal of a new approval request while the
// server holds the most it allows from this address: 3 unfinished ones,
// each kept for 10 minutes, even after the device that made it was
// cancelled. The server does not say when one frees; the latest this
// device's own place frees is known when an earlier attempt left a record.
func mailboxLimitText(l *authflow.MailboxLimitError) string {
	msg := "too many pending device approvals from this address: the server keeps at most 3 at a time, and one that was cancelled before it finished " +
		"holds its place for 10 minutes. Wait up to 10 minutes and run hop auth login again"
	if !l.Until.IsZero() {
		msg += " (this device's own earlier attempt frees its place by " + l.Until.Local().Format("15:04") + " at the latest)"
	}
	return msg
}

// fmtDevice names a device for a message: its name and ID.
func fmtDevice(name, id string) string {
	if name == "" {
		return oneLine(id)
	}
	return fmt.Sprintf("%s (%s)", oneLine(name), oneLine(id))
}
