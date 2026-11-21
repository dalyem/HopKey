package cli

import (
	"os"
	"strconv"
	"strings"
	"testing"
	"time"
)

// A hop auth command abandoned away from a prompt, on a vault the daemon
// had locked, hands the vault back with the instruction to start locked:
// the daemon that takes it is to keep it locked.
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
	want := strconv.Itoa(os.Getpid()) + " handback"
	if got := x.started(); len(got) != 1 || got[0] != want {
		t.Fatalf("daemon starts %q; want one, with the marker %q", got, want)
	}
	if b, err := os.ReadFile(x.e.startLockedFile()); err != nil || !sameDir(strings.TrimSpace(string(b)), x.e.DataDir) {
		t.Errorf("the instruction to start locked: %q, %v; want %s", b, err, x.e.DataDir)
	}
}

// hop daemon, started where a hop auth command left the instruction to
// start locked, serves the vault locked, although its device key opens by
// itself, and takes the instruction and the handback marker away.
func TestHandbackOfALockedVaultStartsTheDaemonLocked(t *testing.T) {
	x := newInterruptEnv(t)
	writeStartLocked(t, x, x.e.storeConfig().DataDir, time.Now())
	other := os.Getppid() // alive, and not this process
	if err := os.WriteFile(x.e.holdMarker(), []byte(strconv.Itoa(other)+" handback\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if st := serveDaemon(t, x); st.Vault == nil || !st.Vault.Locked {
		t.Errorf("the daemon serves the vault open: %+v", st.Vault)
	}
	if _, err := os.Lstat(x.e.holdMarker()); !os.IsNotExist(err) {
		t.Errorf("the handback marker is left: %v", err)
	}
	if err := goneSoon(x.e.startLockedFile()); !os.IsNotExist(err) {
		t.Errorf("the instruction to start locked is left: %v", err)
	}
}
