package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"sync"
	"syscall"
	"time"
)

// sshCmd is an ssh for runSSH to run: what exec.Cmd would be given.
type sshCmd struct {
	path string   // looked up as exec.Command does
	args []string // args[0] is argv[0]
	env  []string
	dir  string
	// stdin, stdout and stderr are /dev/null when nil. An *os.File is
	// the child's own; anything else is copied through a pipe.
	stdin          io.Reader
	stdout, stderr io.Writer
	// waitDelay bounds the copying of stdin, stdout and stderr once ssh
	// has exited, as exec.Cmd.WaitDelay does; 0 waits for it to end.
	waitDelay time.Duration
}

// sendSignal sends sig to p. Tests replace it.
var sendSignal = func(p *os.Process, sig os.Signal) error { return p.Signal(sig) }

// exitStatus is how a child ended: its exit status, or the signal that
// killed it.
type exitStatus struct {
	code   int
	signal os.Signal // nil when it exited
}

// sshExitError is runChild's error for an ssh that did not exit 0, as
// exec.ExitError is for exec.Cmd.
type sshExitError struct{ exitStatus }

func (e *sshExitError) Error() string {
	if e.signal != nil {
		return "signal: " + e.signal.String()
	}
	return fmt.Sprintf("exit status %d", e.code)
}

// exited is ee's exit status, and whether it exited on its own; one killed
// by a signal has none: ExitFailure, and false.
func (e *sshExitError) exited() (code int, exited bool) {
	if e.signal != nil {
		return ExitFailure, false
	}
	return e.code, true
}

// runChild runs sc until it exits. When ended says why it is to end, it
// gets SIGHUP, then SIGTERM at endTerm and SIGKILL at endKill if it still
// runs; when ctx is done, SIGKILL. The error is an *sshExitError when it
// did not exit 0, exec.ErrWaitDelay when it did but its streams were still
// open after sc.waitDelay.
//
// It does not use exec.Cmd: its Wait reaps the child while anything else
// may still signal it (os/wait_unimp.go), and on macOS such a signal can
// reach a process that has taken the PID. child reaps and signals under
// one lock instead, and the streams are copied here.
func runChild(ctx context.Context, sc *sshCmd, ended <-chan string) (endedWhy string, err error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	path, err := exec.LookPath(sc.path)
	if err != nil {
		return "", err
	}
	s := &childIO{}
	files, err := s.open(sc)
	if err != nil {
		s.closeAll()
		return "", err
	}
	c, err := startChild(path, sc.args, sc.env, sc.dir, files)
	for _, f := range s.childEnds {
		f.Close()
	}
	if err != nil {
		s.closeAll()
		return "", err
	}
	defer c.release()
	s.start()
	st, endedWhy, err := c.supervise(ctx, ended, nil, false)
	if err != nil {
		s.abandon()
		return endedWhy, fmt.Errorf("waiting for ssh: %w", err)
	}
	ioErr := s.wait(sc.waitDelay)
	if st.signal != nil || st.code != 0 {
		return endedWhy, &sshExitError{st}
	}
	return endedWhy, ioErr
}

// supervise waits for c to exit, and returns how it did. It is the only
// thing that signals c meanwhile: it forwards what comes on fwd; when
// ended says why c is to end, it sends SIGHUP, then SIGTERM at endTerm and
// SIGKILL at endKill if c still runs; when ctx is done, SIGKILL. With
// jobControl, a stop of c for job control stops this process too (reap).
func (c *child) supervise(ctx context.Context, ended <-chan string, fwd <-chan os.Signal, jobControl bool) (st exitStatus, endedWhy string, err error) {
	// c.wake comes when c may have changed; the tick is in case it was
	// missed.
	tick := time.NewTicker(time.Second)
	defer tick.Stop()
	var term, kill <-chan time.Time
	cancelled := ctx.Done()
	for {
		st, done, err := c.reap(jobControl)
		if err != nil || done {
			return st, endedWhy, err
		}
		select {
		case <-c.wake:
		case <-tick.C:
		case sig := <-fwd:
			c.signal(sig)
		case endedWhy = <-ended:
			ended = nil
			switch err := c.signal(syscall.SIGHUP); {
			case err == nil:
				term = time.After(endTerm)
			case !errors.Is(err, os.ErrProcessDone):
				c.signal(os.Kill) // a system without SIGHUP
			}
		case <-term:
			term, kill = nil, time.After(endKill-endTerm)
			c.signal(syscall.SIGTERM)
		case <-kill:
			kill = nil
			c.signal(os.Kill)
		case <-cancelled:
			cancelled = nil
			c.signal(os.Kill)
		}
	}
}

// childIO is the streams of a child runChild starts, as exec.Cmd sets
// them up: a file is the child's own; anything else is copied through a
// pipe, by a goroutine.
type childIO struct {
	childEnds  []*os.File // closed once the child has them
	parentEnds []*os.File // closed once the copying is done
	copies     []func() error
	outputs    sync.WaitGroup // the copies from the child's stdout and stderr
	errc       chan error
}

// open returns the child's stdin, stdout and stderr for sc.
func (s *childIO) open(sc *sshCmd) ([]*os.File, error) {
	in, err := s.input(sc.stdin)
	if err != nil {
		return nil, err
	}
	out, err := s.output(sc.stdout)
	if err != nil {
		return nil, err
	}
	errf := out
	if !sameWriter(sc.stdout, sc.stderr) {
		if errf, err = s.output(sc.stderr); err != nil {
			return nil, err
		}
	}
	return []*os.File{in, out, errf}, nil
}

func (s *childIO) input(r io.Reader) (*os.File, error) {
	switch r := r.(type) {
	case nil:
		f, err := os.Open(os.DevNull)
		if err == nil {
			s.childEnds = append(s.childEnds, f)
		}
		return f, err
	case *os.File:
		return r, nil
	}
	pr, pw, err := os.Pipe()
	if err != nil {
		return nil, err
	}
	s.childEnds, s.parentEnds = append(s.childEnds, pr), append(s.parentEnds, pw)
	s.copies = append(s.copies, func() error {
		_, err := io.Copy(pw, r)
		if errors.Is(err, syscall.EPIPE) || errors.Is(err, os.ErrClosed) {
			err = nil // the child did not read it all, or exited
		}
		if cerr := pw.Close(); err == nil && !errors.Is(cerr, os.ErrClosed) {
			err = cerr
		}
		return err
	})
	return pr, nil
}

func (s *childIO) output(w io.Writer) (*os.File, error) {
	switch w := w.(type) {
	case nil:
		f, err := os.OpenFile(os.DevNull, os.O_WRONLY, 0)
		if err == nil {
			s.childEnds = append(s.childEnds, f)
		}
		return f, err
	case *os.File:
		return w, nil
	}
	pr, pw, err := os.Pipe()
	if err != nil {
		return nil, err
	}
	s.childEnds, s.parentEnds = append(s.childEnds, pw), append(s.parentEnds, pr)
	s.outputs.Add(1)
	s.copies = append(s.copies, func() error {
		defer s.outputs.Done()
		_, err := io.Copy(w, pr)
		pr.Close()
		return err
	})
	return pw, nil
}

// sameWriter is exec.Cmd's test for one pipe for stdout and stderr.
func sameWriter(a, b io.Writer) (same bool) {
	defer func() { recover() }() // an uncomparable type
	return a == b
}

func (s *childIO) start() {
	s.errc = make(chan error, len(s.copies))
	for _, fn := range s.copies {
		go func() { s.errc <- fn() }()
	}
}

// wait waits for the copying, once the child has exited, for up to delay
// (0: as long as it takes). After delay it closes the pipes, waits for the
// copies from stdout and stderr, so nothing writes to them after
// runChild returns, and returns exec.ErrWaitDelay. A copy to stdin blocked
// on its reader is left to end on its own, as exec.Cmd does.
func (s *childIO) wait(delay time.Duration) error {
	defer s.closeAll()
	var timeout <-chan time.Time
	if delay > 0 {
		t := time.NewTimer(delay)
		defer t.Stop()
		timeout = t.C
	}
	var first error
	for range s.copies {
		select {
		case err := <-s.errc:
			if first == nil {
				first = err
			}
		case <-timeout:
			s.abandon()
			return exec.ErrWaitDelay
		}
	}
	return first
}

// abandon closes the pipes and waits for the copies from stdout and
// stderr, which end with them.
func (s *childIO) abandon() {
	s.closeAll()
	s.outputs.Wait()
}

func (s *childIO) closeAll() {
	for _, f := range s.childEnds {
		f.Close()
	}
	for _, f := range s.parentEnds {
		f.Close()
	}
}
