//go:build unix

package cli

import (
	"context"
	"errors"
	"fmt"
	"os"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

// slowWriter takes a while over each write, as a full terminal or a slow
// reader would: whatever waits for it after the child exits waits longer.
type slowWriter struct{}

func (slowWriter) Write(b []byte) (int, error) {
	time.Sleep(3 * time.Millisecond)
	return len(b), nil
}

// No signal reaches a child after it is reaped: once it is, its PID can be
// another process's. Many short children are told to end as they exit on
// their own, while their output is still being copied, and each signal is
// checked against the reap as it is sent: a zombie still answers
// kill(pid, 0), a reaped PID does not (unless it was taken again since,
// which can only hide a late signal, never invent one).
func TestNoSignalAfterTheReap(t *testing.T) {
	var sent, late atomic.Int64
	real := sendSignal
	sendSignal = func(p *os.Process, sig os.Signal) error {
		sent.Add(1)
		if err := syscall.Kill(p.Pid, 0); errors.Is(err, syscall.ESRCH) {
			late.Add(1)
			return os.ErrProcessDone
		}
		return real(p, sig)
	}
	t.Cleanup(func() { sendSignal = real })

	const runs, parallel = 300, 8
	var wg sync.WaitGroup
	sem := make(chan struct{}, parallel)
	errs := make(chan error, runs)
	for i := range runs {
		wg.Add(1)
		sem <- struct{}{}
		go func() {
			defer func() { <-sem; wg.Done() }()
			ended := make(chan string, 1)
			go func() {
				time.Sleep(time.Duration(i%10) * time.Millisecond)
				ended <- "a test ended it"
			}()
			script := fmt.Sprintf("sleep 0.00%d; echo out; echo err >&2", i%8)
			sc := &sshCmd{path: "sh", args: []string{"sh", "-c", script}, stdout: slowWriter{}, stderr: slowWriter{}}
			_, err := runChild(context.Background(), sc, ended)
			var ee *sshExitError
			if err != nil && !errors.As(err, &ee) {
				errs <- err
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Errorf("runChild: %v", err)
	}
	if sent.Load() == 0 {
		t.Fatal("no child was signalled: the test checked nothing")
	}
	if n := late.Load(); n != 0 {
		t.Errorf("%d of %d signals were sent after the child was reaped", n, sent.Load())
	}
	t.Logf("%d signals sent over %d children", sent.Load(), runs)
}

// A done context kills the child, and runChild returns once it is reaped.
func TestRunChildKillsOnCancel(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	start := time.Now()
	_, err := runChild(ctx, &sshCmd{path: "sleep", args: []string{"sleep", "30"}}, nil)
	var ee *sshExitError
	if !errors.As(err, &ee) || ee.signal != syscall.SIGKILL {
		t.Fatalf("runChild after the context ended: %v, want killed", err)
	}
	if d := time.Since(start); d > 5*time.Second {
		t.Errorf("runChild returned %v after the context ended", d)
	}
}
