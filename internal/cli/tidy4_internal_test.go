package cli

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/dalyem/hopkey/internal/store"
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

// Ctrl-C while a command on an open vault with a sealed key file is stuck
// away from a prompt, after the hold and before the vault begins to leave
// (hop auth logout --local-only --yes, no passphrase in the environment):
// the daemon that takes the vault after this process can't open it, and
// abandon says so, although no passphrase was typed.
func TestHandbackOfAnOpenSealedVaultWarnsWithNothingTyped(t *testing.T) {
	const pass = "handback test device passphrase"
	x := newInterruptEnvWith(t, func(k string) string {
		if k == store.PassphraseEnv {
			return pass
		}
		return ""
	})
	if st, _, stop := startServing(t, x); st.Vault == nil || st.Vault.Locked {
		stop()
		t.Fatalf("the daemon with the passphrase serves the vault locked: %+v", st.Vault)
	} else {
		t.Cleanup(stop)
	}
	x.e.Getenv = func(string) string { return "" }
	ctx := context.Background()
	h, err := holdVaultKeeping(ctx, x.e, false, true)
	if err != nil {
		t.Fatal(err)
	}
	s, err := h.open(ctx) // what the stuck flow holds the vault with
	if err != nil || s == nil {
		t.Fatalf("open: %v", err)
	}
	defer s.Close()
	h.abandon()
	if starts := x.started(); len(starts) != 1 || !strings.HasSuffix(starts[0], "handback") {
		t.Fatalf("daemon starts %q, want one handback", starts)
	}
	if out := x.e.Stderr.(*syncBuffer).String(); !strings.Contains(out, "locked") || !strings.Contains(out, "hop unlock") {
		t.Errorf("no warning that the vault comes back locked: %q", out)
	}
}
