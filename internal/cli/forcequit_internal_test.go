package cli

import (
	"strings"
	"testing"
	"time"
)

// The first Ctrl-C while the vault is still to be put back says so, and
// that a second one quits at once; a second one that comes before that is
// done says what to run.
func TestSecondInterruptSaysWhatToRun(t *testing.T) {
	x := newInterruptEnv(t)
	ctx, cancel := interrupted()
	h, err := holdVault(ctx, x.e, false)
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go x.e.watchInterrupt(ctx, done, false, false)
	cancel(ErrInterrupted)
	select {
	case <-x.exits:
	case <-time.After(5 * time.Second):
		t.Fatal("no exit after the interrupt")
	}
	stderr := x.e.Stderr.(*syncBuffer)
	first := stderr.String()
	if !strings.Contains(first, "hop: "+restoringText+"\n") {
		t.Errorf("stderr after the first Ctrl-C: %q", first)
	}
	x.e.setHold(h) // as if the second came while abandon still ran
	x.e.ForceQuit()
	if code := <-x.exits; code != ExitInterrupted {
		t.Errorf("exit %d, want %d", code, ExitInterrupted)
	}
	if got := strings.TrimPrefix(stderr.String(), first); got != "hop: "+quitText+"\n" {
		t.Errorf("stderr after the second Ctrl-C: %q", got)
	}
	x.e.setHold(nil)
}

// With nothing to put back, Ctrl-C says nothing of it, and neither does a
// second one.
func TestInterruptWithNothingToRestoreSaysNothingOfIt(t *testing.T) {
	x := newInterruptEnv(t)
	ctx, cancel := interrupted()
	go x.e.watchInterrupt(ctx, make(chan struct{}), false, false)
	cancel(ErrInterrupted)
	select {
	case <-x.exits:
	case <-time.After(5 * time.Second):
		t.Fatal("no exit after the interrupt")
	}
	x.e.ForceQuit()
	<-x.exits
	if got := x.e.Stderr.(*syncBuffer).String(); strings.Contains(got, "lock state") {
		t.Errorf("stderr: %q", got)
	}
}
