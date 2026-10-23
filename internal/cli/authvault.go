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
func shutdownDaemon(ctx context.Context, e *Env) (bool, error) {
	c, err := dialExisting(ctx, e)
	if err != nil || c == nil {
		return false, err
	}
	defer c.Close()
	if err := c.Call(ctx, daemon.OpShutdown, nil, nil); err != nil {
		return true, cleanErr(err)
	}
	// The daemon answers before it finishes closing. Wait for its sockets to
	// go, so a command that follows does not find a daemon on its way out.
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		_, ctlErr := os.Lstat(e.Paths.ControlSocket())
		_, agentErr := os.Lstat(e.Paths.AgentSocket())
		if os.IsNotExist(ctlErr) && os.IsNotExist(agentErr) {
			return true, nil
		}
		time.Sleep(25 * time.Millisecond)
	}
	return true, failf("asked the hop daemon to stop, but its sockets are still there after 5s")
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
	marker string
	once   sync.Once // the daemon's restart, by release or abandon
}

// holdMarkerName is the marker's name in the run directory.
const holdMarkerName = "auth-hold"

// holdMarkerMaxAge bounds how long a marker counts, for a holder whose
// pid was reused by another process.
const holdMarkerMaxAge = time.Hour

func (e *Env) holdMarker() string { return filepath.Join(e.Paths.RunDir, holdMarkerName) }

// holdInfo is what the marker says: the pid of the hop auth command, and
// handback once that command, exiting on a signal, launched the daemon
// that is to take the vault after it.
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
	f := strings.Fields(string(b))
	if len(f) == 0 || len(f) > 2 || (len(f) == 2 && f[1] != "handback") {
		return holdInfo{}, false
	}
	pid, err := strconv.Atoi(f[0])
	if err != nil || pid <= 0 || pid == os.Getpid() || !processAlive(pid) {
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

// handbackFrom returns the pid of a hop auth command that is exiting and
// launched this daemon to take the vault after it.
func (e *Env) handbackFrom() (int, bool) {
	hi, ok := e.readHold()
	return hi.pid, ok && hi.handback
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

// unmark removes the marker if it is still this process's.
func (h *vaultHold) unmark() {
	if h.marker == "" {
		return
	}
	if b, err := os.ReadFile(h.marker); err == nil && strings.TrimSpace(string(b)) == strconv.Itoa(os.Getpid()) {
		os.Remove(h.marker)
	}
	h.marker = ""
}

// holdVault stops the daemon so this process can own the vault.
func holdVault(ctx context.Context, e *Env) (*vaultHold, error) {
	h := &vaultHold{e: e, cfg: e.storeConfig()}
	if err := h.mark(); err != nil {
		return nil, err
	}
	e.setHold(h)
	if _, err := shutdownDaemon(ctx, e); err != nil {
		// The daemon was not stopped, so nothing is handed back.
		h.once.Do(h.unmark)
		e.setHold(nil)
		return nil, err
	}
	return h, nil
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
// vault is tried again for a while.
func (h *vaultHold) open(ctx context.Context) (*store.Store, error) {
	exists, err := store.Exists(h.cfg.DataDir)
	if err != nil {
		return nil, failf("%v", err)
	}
	if !exists {
		return nil, nil
	}
	deadline := time.Now().Add(vaultBusyWait)
	for {
		s, err := store.Open(ctx, h.cfg)
		if !errors.Is(err, store.ErrVaultBusy) || time.Now().After(deadline) {
			if errors.Is(err, store.ErrVaultBusy) {
				return nil, failf("the vault is busy: another hop process owns it (hop auth stops the daemon first; is another hop auth command running?)")
			}
			if err != nil {
				return nil, failf("opening the vault: %v", err)
			}
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
// and the next hop command starts it. The command has closed its stores
// by now (each is closed by a defer that runs first).
func (h *vaultHold) release(ctx context.Context, asJSON bool) {
	h.once.Do(func() {
		h.unmark()
		exists, err := store.Exists(h.cfg.DataDir)
		if err != nil || !exists {
			return
		}
		if err := startDaemon(context.WithoutCancel(ctx), h.e); err != nil {
			warn(h.e, asJSON, "the hop daemon did not start again, so nothing syncs until it does (any hop command starts it): "+err.Error())
		}
	})
	h.e.setHold(nil)
}

// abandon is release for a process about to exit on a signal while its
// flow still runs. The flow's store is still open, so the daemon is
// launched without waiting for it, and the marker turns into a handback:
// hop daemon, finding the vault busy, waits for this process to exit
// (runDaemon). A release already under way finishes first.
func (h *vaultHold) abandon() {
	h.once.Do(func() {
		if exists, err := store.Exists(h.cfg.DataDir); err != nil || !exists {
			h.unmark()
			return
		}
		// The marker now tells the daemon to wait for this process.
		if h.marker == "" || writeMarker(h.marker, fmt.Sprintf("%d handback\n", os.Getpid())) != nil {
			h.unmark()
		}
		launch := h.e.StartDaemon
		if launch == nil {
			launch = func() error { return launchDaemon(h.e) }
		}
		if err := launch(); err != nil {
			fmt.Fprintf(h.e.Stderr, "hop: the hop daemon did not start again (any hop command starts it): %s\n", oneLine(err.Error()))
		}
	})
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

func (h *vaultHold) vaultOf(s *store.Store) (*authflow.Vault, error) {
	si, err := s.ServerInfo()
	if errors.Is(err, store.ErrNotServerBacked) {
		return nil, failf("this vault is local-only: hop auth signup publishes it to a server, or hop auth login --merge merges it into an account")
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
		return nil, failf("the vault is locked (%s); run hop unlock first", s.Info().LockReason)
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

// authFailure is a flow's error as the user reads it.
func authFailure(err error) error {
	if err == nil {
		return nil
	}
	var ee *exitError
	if errors.As(err, &ee) {
		return err
	}
	switch {
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
	case errors.Is(err, store.ErrOutboxNotEmpty):
		return failf("queued changes have not reached the server yet: wait for the daemon to send them (hop sync shows them), or log out with --discard-pending to drop them")
	}
	return failf("%v", err)
}

// fmtDevice names a device for a message: its name and ID.
func fmtDevice(name, id string) string {
	if name == "" {
		return oneLine(id)
	}
	return fmt.Sprintf("%s (%s)", oneLine(name), oneLine(id))
}
