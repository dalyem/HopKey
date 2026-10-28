package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/dalyem/hopkey/internal/daemon"
	"github.com/dalyem/hopkey/internal/store"
	"github.com/dalyem/hopkey/internal/version"
)

// runDaemon is `hop daemon`: run the daemon in the foreground until it is
// signalled. The CLI starts it this way, detached, when the control socket is
// missing. `hop daemon stop` asks a running one to exit.
func runDaemon(ctx context.Context, e *Env, args []string) error {
	if len(args) >= 1 && args[0] == "stop" {
		return stopDaemon(ctx, e, args[1:])
	}
	if len(args) != 0 {
		return failf("usage: %s", commands["daemon"].usage)
	}
	if e.OpenStore == nil {
		return failf("this build has no vault store")
	}
	if pid, ok := e.authHolder(); ok {
		return errHeld(pid)
	}
	vault, err := e.OpenStore()
	if errors.Is(err, store.ErrVaultBusy) {
		if pid, ok := e.handbackFrom(); ok {
			// An interrupted hop auth command launched this daemon as it
			// exits: the vault is free once it is gone.
			waitGone(ctx, pid, handbackWait)
			vault, err = e.OpenStore()
		}
	}
	if err == nil {
		e.clearHandback()
	}
	if errors.Is(err, store.ErrVaultBusy) {
		// Another process owns the vault. Only a daemon that answers on the
		// control socket makes this one redundant; anything else (hop init,
		// a daemon stuck before it serves) is a failure to report.
		if daemonAnswers(ctx, e) {
			fmt.Fprintln(e.Stderr, "hop daemon is already running")
			return nil
		}
		return failf("the vault is busy (another hop process owns it)")
	}
	if err != nil {
		return failf("opening the vault: %v", err)
	}
	d, err := daemon.Start(daemon.Options{
		Paths: e.Paths, Store: vault, Version: version.Version,
		Logf: func(format string, args ...any) {
			fmt.Fprintf(e.Stderr, "%s %s\n", time.Now().Format(time.RFC3339), safef(format, args...))
		},
	})
	if err != nil {
		if c, ok := vault.(io.Closer); ok {
			c.Close()
		}
	}
	if errors.Is(err, daemon.ErrAlreadyRunning) {
		fmt.Fprintln(e.Stderr, "hop daemon is already running")
		return nil
	}
	if err != nil {
		return failf("%v", err)
	}
	sigCtx, stop := signal.NotifyContext(ctx, syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	select {
	case <-sigCtx.Done():
		return d.Close()
	case <-d.Done():
		return nil
	}
}

// handbackWait bounds how long a daemon waits for an interrupted hop auth
// command to exit and free the vault.
const handbackWait = 15 * time.Second

// waitGone waits until process pid has exited, for at most d.
func waitGone(ctx context.Context, pid int, d time.Duration) {
	deadline := time.Now().Add(d)
	for processAlive(pid) && time.Now().Before(deadline) {
		select {
		case <-ctx.Done():
			return
		case <-time.After(25 * time.Millisecond):
		}
	}
}

// clearHandback removes a handback marker once the daemon has the vault.
func (e *Env) clearHandback() {
	path := e.holdMarker()
	if b, err := os.ReadFile(path); err == nil && strings.HasSuffix(strings.TrimSpace(string(b)), " handback") {
		os.Remove(path)
	}
}

// busyWait is how long a daemon that finds the vault busy waits for the
// owner to answer on the control socket: a daemon that has just opened the
// vault listens on it a moment later.
var busyWait = 2 * time.Second

// daemonAnswers reports whether a daemon answers a status request on the
// control socket within busyWait. One deadline covers every dial and every
// status request: a daemon that answers later counts as not answering.
func daemonAnswers(ctx context.Context, e *Env) bool {
	ctx, cancel := context.WithTimeout(ctx, busyWait)
	defer cancel()
	for {
		if c, err := daemon.Dial(ctx, e.Paths.ControlSocket()); err == nil {
			err = c.Call(ctx, daemon.OpStatus, nil, nil)
			c.Close()
			if err == nil {
				return true
			}
		}
		select {
		case <-ctx.Done():
			return false
		case <-time.After(50 * time.Millisecond):
		}
	}
}

// dialExisting connects to a running daemon without starting one.
func dialExisting(ctx context.Context, e *Env) (*daemon.Client, error) {
	c, err := daemon.Dial(ctx, e.Paths.ControlSocket())
	if err != nil {
		if socketAbsent(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("cannot reach the hop daemon at %s: %w", oneLine(e.Paths.ControlSocket()), cleanErr(err))
	}
	return c, nil
}

// StopReport is the --json shape of hop daemon stop.
type StopReport struct {
	// WasRunning is false when there was no daemon to stop.
	WasRunning bool `json:"was_running"`
}

func stopDaemon(ctx context.Context, e *Env, args []string) error {
	fs := newFlags(e, "daemon stop", "hop daemon stop [--json]")
	asJSON := fs.Bool("json", false, "print the result as JSON")
	pos, _, err := parseFlags(fs, args)
	if err != nil {
		return err
	}
	if err := noArgs(fs, pos); err != nil {
		return err
	}
	running, err := shutdownDaemon(ctx, e)
	if err != nil {
		return err
	}
	if *asJSON {
		return printJSON(e, StopReport{WasRunning: running})
	}
	if !running {
		e.printf("hop daemon is not running\n")
		return nil
	}
	e.printf("hop daemon stopped\n")
	return nil
}

func runStatus(ctx context.Context, e *Env, args []string) error {
	fs := newFlags(e, "status", commands["status"].usage)
	asJSON := fs.Bool("json", false, "print the status as JSON")
	if _, _, err := parseFlags(fs, args); err != nil {
		return err
	}
	c, err := dialExisting(ctx, e)
	if err != nil {
		return err
	}
	if c == nil {
		if *asJSON {
			if err := printJSON(e, map[string]any{"running": false}); err != nil {
				return err
			}
		} else {
			e.printf("hop daemon is not running; hop sync starts it\n")
		}
		return silent(ExitFailure)
	}
	defer c.Close()
	var st daemon.StatusResult
	if err := c.Call(ctx, daemon.OpStatus, nil, &st); err != nil {
		return err
	}
	if *asJSON {
		return printJSON(e, struct {
			Running bool `json:"running"`
			daemon.StatusResult
		}{true, st})
	}
	e.printf("hop daemon %s, pid %d, up since %s\n", oneLine(st.Version), st.PID, st.StartedAt.Format(time.RFC3339))
	e.printf("hosts:        %d (%d usable with ssh)\n", st.Hosts, st.SSHHosts)
	e.printf("keys:         %d in the vault, %d in the agent\n", st.Keys, st.KeysInAgent)
	e.printf("agent socket: %s\n", oneLine(st.AgentSocket))
	e.printf("ssh config:   %s\n", oneLine(st.ConfigDir))
	printVaultStatus(e, st.Vault)
	if st.Sync != nil {
		o := syncBlockOpts{shown: map[string]bool{}}
		if st.Vault != nil {
			o.device = st.Vault.DeviceID
			o.skipHead = st.Vault.Head != nil
			for _, w := range st.Vault.Warnings {
				o.shown[w] = true
			}
		}
		for _, w := range st.Warnings {
			o.shown[w] = true
		}
		printSyncBlock(e, e.Stdout, st.Sync, o)
	}
	if st.Tailscale.Available {
		e.printf("tailscale:    available\n")
	} else {
		e.printf("tailscale:    %s\n", oneLine(st.Tailscale.Reason))
	}
	for _, w := range st.Warnings {
		e.printf("warning:      %s\n", oneLine(w))
	}
	if st.LastError != "" {
		e.printf("last error:   %s\n", oneLine(st.LastError))
	}
	return nil
}
