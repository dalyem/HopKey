package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
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
	if len(args) == 1 && args[0] == "stop" {
		return stopDaemon(ctx, e)
	}
	if len(args) != 0 {
		return failf("usage: %s", commands["daemon"].usage)
	}
	if e.OpenStore == nil {
		return failf("this build has no vault store")
	}
	vault, err := e.OpenStore()
	if errors.Is(err, store.ErrVaultBusy) {
		// Another daemon got there first and owns the vault.
		fmt.Fprintln(e.Stderr, "hop daemon is already running")
		return nil
	}
	if err != nil {
		return failf("opening the vault: %v", err)
	}
	d, err := daemon.Start(daemon.Options{
		Paths: e.Paths, Store: vault, Version: version.Version,
		Logf: func(format string, args ...any) {
			fmt.Fprintf(e.Stderr, "%s %s\n", time.Now().Format(time.RFC3339), fmt.Sprintf(format, args...))
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

// dialExisting connects to a running daemon without starting one.
func dialExisting(ctx context.Context, e *Env) (*daemon.Client, error) {
	c, err := daemon.Dial(ctx, e.Paths.ControlSocket())
	if err != nil {
		if socketAbsent(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("cannot reach the hop daemon at %s: %w", e.Paths.ControlSocket(), err)
	}
	return c, nil
}

func stopDaemon(ctx context.Context, e *Env) error {
	c, err := dialExisting(ctx, e)
	if err != nil {
		return err
	}
	if c == nil {
		e.printf("hop daemon is not running\n")
		return nil
	}
	defer c.Close()
	if err := c.Call(ctx, daemon.OpShutdown, nil, nil); err != nil {
		return err
	}
	// The daemon answers before it finishes closing. Wait for its sockets to
	// go, so a command that follows does not find a daemon on its way out.
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		_, ctlErr := os.Lstat(e.Paths.ControlSocket())
		_, agentErr := os.Lstat(e.Paths.AgentSocket())
		if os.IsNotExist(ctlErr) && os.IsNotExist(agentErr) {
			e.printf("hop daemon stopped\n")
			return nil
		}
		time.Sleep(25 * time.Millisecond)
	}
	return failf("asked the hop daemon to stop, but its sockets are still there after 5s")
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
			e.printf("hop daemon is not running; any hop command starts it\n")
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
	e.printf("hop daemon %s, pid %d, up since %s\n", st.Version, st.PID, st.StartedAt.Format(time.RFC3339))
	e.printf("hosts:        %d (%d usable with ssh)\n", st.Hosts, st.SSHHosts)
	e.printf("keys:         %d in the vault, %d in the agent\n", st.Keys, st.KeysInAgent)
	e.printf("agent socket: %s\n", st.AgentSocket)
	e.printf("ssh config:   %s\n", st.ConfigDir)
	printVaultStatus(e, st.Vault)
	if st.Tailscale.Available {
		e.printf("tailscale:    available\n")
	} else {
		e.printf("tailscale:    %s\n", st.Tailscale.Reason)
	}
	for _, w := range st.Warnings {
		e.printf("warning:      %s\n", w)
	}
	if st.LastError != "" {
		e.printf("last error:   %s\n", st.LastError)
	}
	return nil
}
