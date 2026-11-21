//go:build !unix

package cli

import (
	"context"
	"os"
	"syscall"

	"github.com/dalyem/hopkey/internal/daemon"
)

// runTerminalSSH runs hop <target>'s ssh as a child on this process's
// streams, watched by the daemon (watchSession), and returns its exit
// status. There is no shortcuts panel here (termpanel.ErrUnsupported).
func (e *Env) runTerminalSSH(_ context.Context, path string, argv, environ []string, alias string, _ *daemon.ResolveResult) (code int, endedWhy string, err error) {
	return e.runPipedSSH(path, argv, environ, alias)
}

// child is a process this one started (runChild). os.Process holds a
// handle to it here, so a signal can only reach it, never a process that
// took its ID.
type child struct {
	p     *os.Process
	wake  chan struct{} // closed once it has exited
	state *os.ProcessState
	err   error
}

// startChild starts path with argv, env (nil: this process's), dir ("":
// this process's), files as its stdin, stdout and stderr, and sys as its
// os.ProcAttr.Sys.
func startChild(path string, argv, env []string, dir string, files []*os.File, sys *syscall.SysProcAttr) (*child, error) {
	p, err := os.StartProcess(path, argv, &os.ProcAttr{Dir: dir, Env: env, Files: files, Sys: sys})
	if err != nil {
		return nil, err
	}
	c := &child{p: p, wake: make(chan struct{})}
	go func() {
		c.state, c.err = p.Wait()
		close(c.wake)
	}()
	return c, nil
}

func (c *child) release() {}

func (c *child) signal(sig os.Signal) error { return sendSignal(c.p, sig) }

// reap says whether the child has exited, and how.
func (c *child) reap(bool) (st exitStatus, done bool, err error) {
	select {
	case <-c.wake:
	default:
		return st, false, nil
	}
	if c.err != nil {
		return st, true, c.err
	}
	return exitStatus{code: c.state.ExitCode()}, true, nil
}
