package cli

import (
	"strings"
	"testing"
	"time"
)

// stuckWriter is a stderr nobody drains: a full pipe. Write returns only
// once release is closed.
type stuckWriter struct{ release chan struct{} }

func (w stuckWriter) Write(p []byte) (int, error) {
	<-w.release
	return len(p), nil
}

// A second Ctrl-C ends hop promptly although a warning is stuck writing to
// a stderr nobody reads, holding warnMu: the notice is best-effort.
func TestForceQuitExitsWhileStderrIsStuck(t *testing.T) {
	release := make(chan struct{})
	defer close(release)
	exits := make(chan int, 1)
	e := &Env{Stdout: &strings.Builder{}, Stderr: stuckWriter{release}, Exit: func(code int) { exits <- code }}
	e.setHold(&vaultHold{e: e}) // the vault's lock state is still to be put back
	go warn(e, false, "a warning on a full pipe")
	for e.warnMu.TryLock() { // until the warning holds warnMu
		e.warnMu.Unlock()
		time.Sleep(time.Millisecond)
	}
	go e.ForceQuit()
	select {
	case code := <-exits:
		if code != ExitInterrupted {
			t.Errorf("exit %d, want %d", code, ExitInterrupted)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("no exit while stderr is stuck")
	}
}
