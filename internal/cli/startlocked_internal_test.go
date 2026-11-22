package cli

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/dalyem/hopkey/internal/model"
	"github.com/dalyem/hopkey/internal/store"
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

// An instruction to start locked is followed only from a file this user
// alone can have written: not through a symlink, not one that others can
// write, not one in a run directory that others can write, and not one
// dated in the future. Each is ignored with a warning in the daemon's log.
// (A file owned by another user can't be made without privileges, so that
// case is left to trustedMarker's owner check.)
func TestStartLockedFromAnUntrustedFileIsIgnored(t *testing.T) {
	cases := []struct {
		name  string
		plant func(t *testing.T, x *interruptEnv)
		gone  bool // the file is removed
	}{
		{"symlink", func(t *testing.T, x *interruptEnv) {
			target := filepath.Join(t.TempDir(), "planted")
			if err := os.WriteFile(target, []byte(x.e.storeConfig().DataDir+"\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.MkdirAll(x.e.Paths.RunDir, 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(target, x.e.startLockedFile()); err != nil {
				t.Fatal(err)
			}
		}, false},
		{"writable by others", func(t *testing.T, x *interruptEnv) {
			writeStartLocked(t, x, x.e.storeConfig().DataDir, time.Now())
			if err := os.Chmod(x.e.startLockedFile(), 0o666); err != nil {
				t.Fatal(err)
			}
		}, false},
		{"run directory writable by others", func(t *testing.T, x *interruptEnv) {
			writeStartLocked(t, x, x.e.storeConfig().DataDir, time.Now())
			if err := os.Chmod(x.e.Paths.RunDir, 0o777); err != nil {
				t.Fatal(err)
			}
		}, false},
		{"dated in the future", func(t *testing.T, x *interruptEnv) {
			writeStartLocked(t, x, x.e.storeConfig().DataDir, time.Now().Add(time.Hour))
		}, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			x := newInterruptEnv(t)
			c.plant(t, x)
			st, stderr, stop := startServing(t, x)
			defer stop()
			if st.Vault == nil || st.Vault.Locked {
				t.Errorf("an untrusted instruction locked the vault: %+v", st.Vault)
			}
			if out := stderr.String(); !strings.Contains(out, "instruction to start the vault locked") {
				t.Errorf("no warning that the instruction was ignored: %q", out)
			}
			_, err := os.Lstat(x.e.startLockedFile())
			if c.gone != os.IsNotExist(err) {
				t.Errorf("the file after the daemon started: %v; want it removed: %v", err, c.gone)
			}
		})
	}
}

// A vault that was open in the daemon, with a sealed key file whose
// passphrase the command did not ask for, comes back locked: the daemon
// started again has no passphrase. release says so, and what to run.
func TestReleaseSaysWhenAnOpenVaultComesBackLocked(t *testing.T) {
	const pass = "release test device passphrase"
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
	// The command has no passphrase, and the daemon it starts again none.
	x.e.Getenv = func(string) string { return "" }
	x.e.DaemonWait = 10 * time.Second
	x.e.StartDaemon = func() error {
		_, _, stop := startServing(t, x)
		t.Cleanup(stop)
		return nil
	}
	ctx := context.Background()
	h, err := holdVaultKeeping(ctx, x.e, false, true)
	if err != nil {
		t.Fatal(err)
	}
	h.release(ctx)
	if out := x.e.Stderr.(*syncBuffer).String(); !strings.Contains(out, "was open before this command") || !strings.Contains(out, "hop unlock") {
		t.Errorf("no warning that the vault came back locked: %q", out)
	}
}
