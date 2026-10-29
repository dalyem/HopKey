//go:build unix

package cli

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"
)

// runTerminalSSH runs hop <target>'s ssh as a child on this process's
// terminal, watched by the daemon (watchSession), and returns its exit
// status: its own, or 128 plus the signal that killed it.
//
// ssh gets this process's stdin, stdout and stderr and its process group,
// so the terminal treats the two as one job, as it treats a plain ssh:
// Ctrl-C, Ctrl-\ and window size changes reach ssh from the terminal
// itself (in raw mode, Ctrl-C is a byte that goes to the remote side).
// hop ignores SIGINT and SIGQUIT meanwhile, and passes SIGTERM and SIGHUP
// sent to it on to ssh. When ssh stops for job control (Ctrl-Z, ~^Z,
// reading the terminal in the background), hop stops with the same
// signal, so the shell sees the job stop; fg continues both.
//
// hop reaps ssh itself (child.reap), so it can see it stop, and signals
// it only while it is not reaped: no other process can have its PID.
func (e *Env) runTerminalSSH(ctx context.Context, path string, argv, environ []string, alias string) (code int, endedWhy string, err error) {
	in, okIn := e.Stdin.(*os.File)
	out, okOut := e.Stdout.(*os.File)
	errf, okErr := e.Stderr.(*os.File)
	if !okIn || !okOut || !okErr {
		return e.runPipedSSH(path, argv, environ, alias)
	}
	sigs := make(chan os.Signal, 16)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGQUIT, syscall.SIGTERM, syscall.SIGHUP, syscall.SIGCHLD)
	defer signal.Stop(sigs)
	sw := e.watchSession(alias)
	defer sw.close()
	if sw.atOnce != "" {
		return 255, sw.atOnce, nil
	}
	if ctx.Err() != nil {
		return 0, "", context.Cause(ctx)
	}
	p, err := os.StartProcess(path, argv, &os.ProcAttr{Env: environ, Files: []*os.File{in, out, errf}})
	if err != nil {
		return 0, "", err
	}
	defer p.Release()
	e.sshRan.Store(true)
	c := &child{p: p}
	// SIGCHLD wakes the loop; the tick is in case one was missed.
	tick := time.NewTicker(time.Second)
	defer tick.Stop()
	var term, kill <-chan time.Time
	for {
		ws, done, err := c.reap()
		if err != nil {
			return ExitFailure, endedWhy, fmt.Errorf("waiting for ssh: %w", err)
		}
		if done {
			if ws.Signaled() {
				return 128 + int(ws.Signal()), endedWhy, nil
			}
			return ws.ExitStatus(), endedWhy, nil
		}
		select {
		case sig := <-sigs:
			// SIGINT and SIGQUIT from the terminal reach ssh too; SIGCHLD
			// only wakes the loop.
			if sig == syscall.SIGTERM || sig == syscall.SIGHUP {
				c.signal(sig)
			}
		case <-tick.C:
		case endedWhy = <-sw.ended:
			if c.signal(syscall.SIGHUP) == nil {
				term = time.After(endTerm)
			}
		case <-term:
			term, kill = nil, time.After(endKill-endTerm)
			c.signal(syscall.SIGTERM)
		case <-kill:
			kill = nil
			c.signal(syscall.SIGKILL)
		}
	}
}

// child is a process this one started and reaps itself.
type child struct {
	p      *os.Process
	mu     sync.Mutex // held to reap, and to signal
	reaped bool
}

// signal sends sig to the child, unless it is reaped.
func (c *child) signal(sig os.Signal) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.reaped {
		return os.ErrProcessDone
	}
	return c.p.Signal(sig)
}

// reap collects what happened to the child without waiting: done once it
// has exited, and reaped. A stop for job control stops this process too.
func (c *child) reap() (ws syscall.WaitStatus, done bool, err error) {
	for {
		c.mu.Lock()
		pid, err := syscall.Wait4(c.p.Pid, &ws, syscall.WNOHANG|syscall.WUNTRACED, nil)
		if err == nil && pid == c.p.Pid && (ws.Exited() || ws.Signaled()) {
			c.reaped = true
		}
		c.mu.Unlock()
		switch {
		case err == syscall.EINTR:
			continue
		case err != nil:
			return ws, false, err
		case pid != c.p.Pid:
			return ws, false, nil // still running
		case c.reaped:
			return ws, true, nil
		case ws.Stopped():
			switch sig := ws.StopSignal(); sig {
			case syscall.SIGTSTP, syscall.SIGTTIN, syscall.SIGTTOU:
				// Its default action stops this process, so the shell sees
				// the job stop.
				syscall.Kill(os.Getpid(), sig)
			}
		}
	}
}
