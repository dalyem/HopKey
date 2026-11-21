package cli

import (
	"context"
	"runtime"
	"testing"
)

// Run's signal watcher reads the hold's policy as soon as the hold is
// published: it is set by then (go test -race finds a hold published
// first and filled in after).
func TestHoldIsPublishedWithItsPolicy(t *testing.T) {
	x := newInterruptEnv(t)
	read := make(chan restoreTo, 1)
	go func() {
		for {
			if h := x.e.currentHold(); h != nil {
				read <- h.target()
				return
			}
			runtime.Gosched()
		}
	}()
	h, err := holdVaultKeeping(context.Background(), x.e, false, true)
	if err != nil {
		t.Fatal(err)
	}
	if got := <-read; got != restoreOpen {
		t.Errorf("the watcher read %v; want restoreOpen", got)
	}
	h.release(context.Background())
}
