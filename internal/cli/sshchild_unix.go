//go:build unix

package cli

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"sync"
	"syscall"
)

// hangupIgnored is SIGHUP ignored when hop started (under nohup, say).
// hop then leaves it so: it does not catch it, so it is not reset for
// ssh either, and ssh starts with it ignored too.
var hangupIgnored = signal.Ignored(syscall.SIGHUP)

// runTerminalSSH runs hop <target>'s ssh as a child on this process's
// terminal, watched by the daemon (watchSession), and returns its exit
// status: its own, or 128 plus the signal that killed it.
//
// ssh gets this process's stdin, stdout and stderr and its process group,
// so the terminal treats the two as one job, as it treats a plain ssh:
// Ctrl-C, Ctrl-\ and window size changes reach ssh from the terminal
// itself (in raw mode, Ctrl-C is a byte that goes to the remote side).
// hop ignores SIGINT and SIGQUIT meanwhile, and passes SIGTERM and SIGHUP
// sent to it on to ssh, unless SIGHUP was ignored (hangupIgnored). When
// ssh stops for job control (Ctrl-Z, ~^Z, reading the terminal in the
// background), hop stops with the same signal, so the shell sees the job
// stop; fg continues both. A session the daemon ends while the job is
// stopped ends when it is continued.
//
// hop reaps ssh itself (child), so it can see it stop, and signals it
// only while it is not reaped: no other process can have its PID.
func (e *Env) runTerminalSSH(ctx context.Context, path string, argv, environ []string, alias string) (code int, endedWhy string, err error) {
	in, okIn := e.Stdin.(*os.File)
	out, okOut := e.Stdout.(*os.File)
	errf, okErr := e.Stderr.(*os.File)
	if !okIn || !okOut || !okErr {
		return e.runPipedSSH(path, argv, environ, alias)
	}
	held := make(chan os.Signal, 1) // never read: hop just does not stop on them
	signal.Notify(held, syscall.SIGINT, syscall.SIGQUIT)
	defer signal.Stop(held)
	fwd := make(chan os.Signal, 16)
	if hangupIgnored {
		signal.Notify(fwd, syscall.SIGTERM)
	} else {
		signal.Notify(fwd, syscall.SIGTERM, syscall.SIGHUP)
	}
	defer signal.Stop(fwd)
	sw := e.watchSession(alias)
	defer sw.close()
	if sw.atOnce != "" {
		return 255, sw.atOnce, nil
	}
	if ctx.Err() != nil {
		return 0, "", context.Cause(ctx)
	}
	c, err := startChild(path, argv, environ, "", []*os.File{in, out, errf})
	if err != nil {
		return 0, "", err
	}
	defer c.release()
	e.sshRan.Store(true)
	// ctx is not watched: hop's own SIGINT goes to ssh from the terminal,
	// and SIGTERM and SIGHUP are passed on.
	st, endedWhy, err := c.supervise(context.Background(), sw.ended, fwd, true)
	switch {
	case err != nil:
		return ExitFailure, endedWhy, fmt.Errorf("waiting for ssh: %w", err)
	case st.signal != nil:
		return 128 + int(st.signal.(syscall.Signal)), endedWhy, nil
	}
	return st.code, endedWhy, nil
}

// child is a process this one started and reaps itself (runChild,
// runTerminalSSH). Reaping and signalling it happen under one lock, and no
// signal is sent once it is reaped: by then another process may have its
// PID.
type child struct {
	p      *os.Process
	wake   chan os.Signal // SIGCHLD
	mu     sync.Mutex     // held to reap, and to signal
	reaped bool
}

// startChild starts path with argv, env (nil: this process's), dir ("":
// this process's) and files as its stdin, stdout and stderr.
func startChild(path string, argv, env []string, dir string, files []*os.File) (*child, error) {
	c := &child{wake: make(chan os.Signal, 1)}
	signal.Notify(c.wake, syscall.SIGCHLD)
	p, err := os.StartProcess(path, argv, &os.ProcAttr{Dir: dir, Env: env, Files: files})
	if err != nil {
		signal.Stop(c.wake)
		return nil, err
	}
	c.p = p
	return c, nil
}

func (c *child) release() {
	signal.Stop(c.wake)
	c.p.Release()
}

// signal sends sig to the child, unless it is reaped.
func (c *child) signal(sig os.Signal) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.reaped {
		return os.ErrProcessDone
	}
	return sendSignal(c.p, sig)
}

// reap collects what happened to the child without waiting: done once it
// has exited, and reaped. With jobControl, a stop for job control stops
// this process too.
func (c *child) reap(jobControl bool) (st exitStatus, done bool, err error) {
	opts := syscall.WNOHANG
	if jobControl {
		opts |= syscall.WUNTRACED
	}
	for {
		var ws syscall.WaitStatus
		c.mu.Lock()
		pid, err := syscall.Wait4(c.p.Pid, &ws, opts, nil)
		if (err == nil && pid == c.p.Pid && (ws.Exited() || ws.Signaled())) || err == syscall.ECHILD {
			c.reaped = true // ECHILD: something else reaped it
		}
		c.mu.Unlock()
		switch {
		case err == syscall.EINTR:
			continue
		case err != nil:
			return st, false, err
		case pid != c.p.Pid:
			return st, false, nil // still running
		case ws.Signaled():
			return exitStatus{code: -1, signal: ws.Signal()}, true, nil
		case ws.Exited():
			return exitStatus{code: ws.ExitStatus()}, true, nil
		case jobControl && ws.Stopped():
			switch sig := ws.StopSignal(); sig {
			case syscall.SIGTSTP, syscall.SIGTTIN, syscall.SIGTTOU:
				// Its default action stops this process, so the shell sees
				// the job stop.
				syscall.Kill(os.Getpid(), sig)
			}
		}
	}
}
