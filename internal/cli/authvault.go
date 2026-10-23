package cli

import (
	"context"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/dalyem/hopkey/internal/authflow"
	"github.com/dalyem/hopkey/internal/daemon"
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
type vaultHold struct {
	e   *Env
	cfg store.Config
}

// holdVault stops the daemon so this process can own the vault.
func holdVault(ctx context.Context, e *Env) (*vaultHold, error) {
	if _, err := shutdownDaemon(ctx, e); err != nil {
		return nil, err
	}
	return &vaultHold{e: e, cfg: e.storeConfig()}, nil
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
// and the next hop command starts it.
func (h *vaultHold) release(ctx context.Context, asJSON bool) {
	exists, err := store.Exists(h.cfg.DataDir)
	if err != nil || !exists {
		return
	}
	if err := startDaemon(context.WithoutCancel(ctx), h.e); err != nil {
		warn(h.e, asJSON, "the hop daemon did not start again, so nothing syncs until it does (any hop command starts it): "+err.Error())
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
