package cli

import (
	"context"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/dalyem/hopkey/internal/daemon"
	"github.com/dalyem/hopkey/internal/model"
)

// A hop auth command abandoned away from a prompt, on a vault the daemon
// had locked, hands the vault back with that said in the marker: the
// daemon that takes it is to keep it locked.
func TestAbandonAwayFromAPromptHandsALockedVaultBackLocked(t *testing.T) {
	x := newInterruptEnv(t)
	ctx, cancel := interrupted()
	h, err := holdVault(ctx, x.e, false)
	if err != nil {
		t.Fatal(err)
	}
	h.mu.Lock()
	h.keepOpen, h.wasLocked = true, true // what holdVaultKeeping finds
	h.mu.Unlock()
	go x.e.watchInterrupt(ctx, make(chan struct{}), false, false)
	cancel(ErrInterrupted)
	select {
	case <-x.exits:
	case <-time.After(5 * time.Second):
		t.Fatal("no exit after the interrupt")
	}
	want := strconv.Itoa(os.Getpid()) + " handback locked"
	if got := x.started(); len(got) != 1 || got[0] != want {
		t.Fatalf("daemon starts %q; want one, with the marker %q", got, want)
	}
}

// hop daemon, started on a handback that says the vault was locked, serves
// it locked, although its device key opens by itself.
func TestHandbackOfALockedVaultStartsTheDaemonLocked(t *testing.T) {
	x := newInterruptEnv(t)
	if err := os.MkdirAll(x.e.Paths.RunDir, 0o700); err != nil {
		t.Fatal(err)
	}
	other := os.Getppid() // alive, and not this process
	if err := os.WriteFile(x.e.holdMarker(), []byte(strconv.Itoa(other)+" handback locked\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	d := &Env{
		Stdout: &strings.Builder{}, Stderr: &strings.Builder{}, Getenv: x.e.Getenv,
		DataDir: x.e.DataDir, Paths: x.e.Paths,
	}
	d.OpenStore = func() (model.Store, error) { return openReal(d) }
	dctx, dcancel := context.WithCancel(context.Background())
	ran := make(chan error, 1)
	go func() { ran <- runDaemon(dctx, d, nil) }()
	defer func() {
		dcancel()
		if err := <-ran; err != nil {
			t.Errorf("runDaemon: %v; stderr %q", err, d.Stderr)
		}
	}()
	var st daemon.StatusResult
	deadline := time.Now().Add(10 * time.Second)
	for {
		c, err := daemon.Dial(context.Background(), x.e.Paths.ControlSocket())
		if err == nil {
			err = c.Call(context.Background(), daemon.OpStatus, nil, &st)
			c.Close()
			if err == nil {
				break
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("the daemon does not answer: %v; stderr %q", err, d.Stderr)
		}
		time.Sleep(25 * time.Millisecond)
	}
	if st.Vault == nil || !st.Vault.Locked {
		t.Errorf("the daemon serves the vault open: %+v", st.Vault)
	}
	if _, err := os.Lstat(x.e.holdMarker()); !os.IsNotExist(err) {
		t.Errorf("the handback marker is left: %v", err)
	}
}
