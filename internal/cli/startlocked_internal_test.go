package cli

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/dalyem/hopkey/internal/model"
)

// otherVault is a second vault whose daemon uses x's run directory, as a
// daemon of another data directory does when both share XDG_RUNTIME_DIR.
func otherVault(t *testing.T, x *interruptEnv) *interruptEnv {
	t.Helper()
	y := newInterruptEnv(t)
	y.e.Paths.RunDir = x.e.Paths.RunDir
	return y
}

// runDaemonOnce runs hop daemon on x's vault where it can't serve, and
// returns once it has given up.
func runDaemonOnce(t *testing.T, x *interruptEnv) string {
	t.Helper()
	stderr := &syncBuffer{}
	d := &Env{Stdout: &strings.Builder{}, Stderr: stderr, Getenv: x.e.Getenv, DataDir: x.e.DataDir, Paths: x.e.Paths}
	d.OpenStore = func() (model.Store, error) { return openReal(d) }
	if err := runDaemon(context.Background(), d, nil); err != nil {
		t.Fatalf("runDaemon: %v; stderr %q", err, stderr)
	}
	return stderr.String()
}

// A daemon that takes the instruction to start locked and then can't
// serve (another vault's daemon has the sockets) leaves it: the vault's
// next daemon still starts locked.
func TestStartLockedOutlivesADaemonThatDidNotStart(t *testing.T) {
	x := newInterruptEnv(t)
	_, _, stopOther := startServing(t, otherVault(t, x))
	defer stopOther()
	writeStartLocked(t, x, x.e.storeConfig().DataDir, time.Now())
	if out := runDaemonOnce(t, x); !strings.Contains(out, "already running") {
		t.Fatalf("the daemon did not find the sockets taken: %q", out)
	}
	if _, err := os.Lstat(x.e.startLockedFile()); err != nil {
		t.Fatalf("a daemon that never served took the instruction: %v", err)
	}
	stopOther()
	if st := serveDaemon(t, x); st.Vault == nil || !st.Vault.Locked {
		t.Errorf("the retry serves the vault open: %+v", st.Vault)
	}
	if err := goneSoon(x.e.startLockedFile()); !os.IsNotExist(err) {
		t.Errorf("the instruction is left after the daemon served the vault locked: %v", err)
	}
}

// restart drops its instruction once a daemon answers only when that
// daemon serves this vault: the daemon of another vault never read it.
func TestRestartKeepsStartLockedWhenAnotherVaultAnswers(t *testing.T) {
	x := newInterruptEnv(t)
	serveDaemon(t, otherVault(t, x))
	h := &vaultHold{e: x.e, cfg: x.e.storeConfig()}
	h.restart(context.Background(), restoreLocked)
	if b, err := os.ReadFile(x.e.startLockedFile()); err != nil || !sameDir(strings.TrimSpace(string(b)), x.e.DataDir) {
		t.Errorf("the instruction to start locked: %q, %v; want it kept for %s", b, err, x.e.DataDir)
	}
}
