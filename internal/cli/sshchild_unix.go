//go:build unix

package cli

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"golang.org/x/term"

	"github.com/dalyem/hopkey/internal/daemon"
	"github.com/dalyem/hopkey/internal/termpanel"
)

// hangupIgnored is SIGHUP ignored when hop started (under nohup, say).
// hop then leaves it so: it does not catch it, so it is not reset for
// ssh either, and ssh starts with it ignored too.
var hangupIgnored = signal.Ignored(syscall.SIGHUP)

// runTerminalSSH runs hop <target>'s ssh as a child on this process's
// terminal, watched by the daemon (watchSession), and returns its exit
// status: its own, or 128 plus the signal that killed it. When the
// session has a shortcuts panel (sessionPanel), ssh runs behind it
// instead (runPanelSSH).
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
func (e *Env) runTerminalSSH(ctx context.Context, path string, argv, environ []string, alias string, rr *daemon.ResolveResult) (code int, endedWhy string, err error) {
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
	panel := e.sessionPanel(ctx, in, out, rr)
	if ctx.Err() != nil {
		return 0, "", context.Cause(ctx)
	}
	if panel != nil {
		code, endedWhy, started, err := e.runPanelSSH(*panel, path, argv, environ, errf, sw, fwd)
		if started {
			return code, endedWhy, err
		}
		if !errors.Is(err, termpanel.ErrNotTerminal) && !errors.Is(err, termpanel.ErrUnsupported) {
			fmt.Fprintf(e.Stderr, "hop: connecting without the shortcuts panel: %v\n", cleanErr(err))
		}
	}
	c, err := startChild(path, argv, environ, "", []*os.File{in, out, errf}, nil)
	if err != nil {
		return 0, "", err
	}
	defer c.release()
	e.sshRan.Store(true)
	// ctx is not watched: hop's own SIGINT goes to ssh from the terminal,
	// and SIGTERM and SIGHUP are passed on.
	return sshExit(c.supervise(context.Background(), sw.ended, fwd, true))
}

// sshExit is runTerminalSSH's result for how ssh ended.
func sshExit(st exitStatus, endedWhy string, err error) (code int, _ string, _ error) {
	switch {
	case err != nil:
		return ExitFailure, endedWhy, fmt.Errorf("waiting for ssh: %w", err)
	case st.signal != nil:
		return 128 + int(st.signal.(syscall.Signal)), endedWhy, nil
	}
	return st.code, endedWhy, nil
}

// panelLookupTimeout bounds asking the daemon for a session's shortcuts.
const panelLookupTimeout = 5 * time.Second

// sessionPanel is the shortcuts panel of the session rr resolved, or nil
// when ssh runs without one, as it did before there were shortcuts: when
// stdin or stdout is not a terminal, HOP_SHORTCUT_KEY is off, or the
// host's panel is empty. The panel's pty has costs a session with no
// shortcuts would pay for nothing: ssh's ~^Z does nothing behind it, and
// a lone Esc waits a moment for the rest of a sequence. A setting or a
// lookup that fails says so on one line, and ssh runs without the panel.
func (e *Env) sessionPanel(ctx context.Context, in, out *os.File, rr *daemon.ResolveResult) *termpanel.Options {
	if !term.IsTerminal(int(in.Fd())) || !term.IsTerminal(int(out.Fd())) {
		return nil
	}
	key, on, err := e.shortcutHotkey()
	if err != nil {
		fmt.Fprintf(e.Stderr, "hop: connecting without the shortcuts panel: %v\n", cleanErr(err))
		return nil
	}
	if !on {
		return nil
	}
	lctx, cancel := context.WithTimeout(ctx, panelLookupTimeout)
	defer cancel()
	sc, err := e.sessionShortcuts(lctx, rr)
	if err != nil {
		if ctx.Err() == nil {
			fmt.Fprintf(e.Stderr, "hop: connecting without the shortcuts panel: %v\n", cleanErr(err))
		}
		return nil
	}
	if len(sc) == 0 {
		return nil
	}
	return &termpanel.Options{In: in, Out: out, Shortcuts: sc, Hotkey: key}
}

// runPanelSSH runs ssh as runTerminalSSH does, but on a pty of its own
// behind the shortcuts panel (termpanel.Run), and says whether ssh
// started: when it did not, the caller runs it directly.
//
// ssh is then the leader of a session of its own, out of the terminal's
// job, so nothing the terminal sends a job reaches it: hop passes SIGTERM
// and SIGHUP on (fwd), and Ctrl-Z in the panel, or SIGTSTP, stops hop,
// which stops ssh (SIGSTOP) first and continues it (SIGCONT) once hop is
// continued. ssh's own ~^Z does nothing, since its process group has no
// shell to stop it for. stderr goes to the pty too when it is a terminal;
// a file stays a file.
func (e *Env) runPanelSSH(opts termpanel.Options, path string, argv, environ []string, errf *os.File, sw *sessionWatch, fwd <-chan os.Signal) (code int, endedWhy string, started bool, err error) {
	var c atomic.Pointer[child]
	send := func(sig os.Signal) func() {
		return func() {
			if ch := c.Load(); ch != nil {
				ch.signal(sig)
			}
		}
	}
	opts.OnSuspend, opts.OnResume = send(syscall.SIGSTOP), send(syscall.SIGCONT)
	var st exitStatus
	var waitErr error
	err = termpanel.Run(context.Background(), opts, func(tty *os.File, sys *syscall.SysProcAttr) (func() error, error) {
		stderr := errf
		if term.IsTerminal(int(errf.Fd())) {
			stderr = tty
		}
		ch, err := startChild(path, argv, environ, "", []*os.File{tty, tty, stderr}, sys)
		if err != nil {
			return nil, err
		}
		c.Store(ch)
		e.sshRan.Store(true)
		return func() error {
			// termpanel owns the job control here: no jobControl.
			st, endedWhy, waitErr = ch.supervise(context.Background(), sw.ended, fwd, false)
			return waitErr
		}, nil
	})
	ch := c.Load()
	if ch == nil {
		return 0, "", false, err
	}
	defer ch.release()
	code, endedWhy, err = sshExit(st, endedWhy, waitErr)
	return code, endedWhy, true, err
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
// this process's), files as its stdin, stdout and stderr, and sys as its
// os.ProcAttr.Sys.
func startChild(path string, argv, env []string, dir string, files []*os.File, sys *syscall.SysProcAttr) (*child, error) {
	c := &child{wake: make(chan os.Signal, 1)}
	signal.Notify(c.wake, syscall.SIGCHLD)
	p, err := os.StartProcess(path, argv, &os.ProcAttr{Dir: dir, Env: env, Files: files, Sys: sys})
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
