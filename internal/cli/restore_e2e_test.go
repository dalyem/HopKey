package cli_test

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/dalyem/hopkey/internal/cli"
	"github.com/dalyem/hopkey/internal/daemon"
)

// Ctrl-C at the confirmation of hop vault fork --local, which holds the old
// vault through a prepared fork rather than an opened store: the vault comes
// back as the fork found it. An open one is open, with the device passphrase
// typed for the command; a locked one is locked, even where the device key
// opens by itself.
func TestInterruptedForkRestoresTheLockState(t *testing.T) {
	t.Run("open, sealed device key", func(t *testing.T) {
		_, m := sealedAccount(t)
		interruptAtPrompt(t, m, &session{secrets: map[string]string{askOldPass: devPass}}, "vault", "fork", "--local")
		vaultOpen(t, m)
	})
	t.Run("locked, unsealed device key file", func(t *testing.T) {
		w := newAuthWorld(t)
		m := noKeychain(t)
		m.w = w
		localVault(t, m, "n")
		signedInAccount(t, w, m)
		m.must(t, nil, "lock")
		interruptAtPrompt(t, m, &session{}, "vault", "fork", "--local")
		if a := m.authStatus(t); !a.Locked {
			t.Error("the vault was locked before the interrupted fork and is open after it")
		}
	})
}

// Ctrl-C at the confirmation of hop auth logout, then "yes" typed while the
// process is giving the vault up: the logout does not go on, and what the
// vault goes back to is what was settled when the process took over. The
// vault is still there, signed in and open (its key file is sealed, so it
// is open again only with the device passphrase typed for the command).
// Where the daemon has the vault open, the question comes before it is
// stopped; with no daemon running, it comes while the vault is held.
func TestAnswerDuringAbandonmentDoesNotGoOn(t *testing.T) {
	_, m := sealedAccount(t)
	m.must(t, nil, "daemon", "stop")
	ictx, interrupt := context.WithCancelCause(context.Background())
	exited := make(chan int, 1)
	answer := make(chan string)
	s := &session{tty: true, ctx: ictx, grace: 50 * time.Millisecond, secrets: map[string]string{askOldPass: devPass}}
	s.exit = func(code int) { exited <- code }
	s.answer = func(string) string {
		interrupt(cli.ErrInterrupted) // Ctrl-C, while the prompt waits
		return <-answer
	}
	env := m.env(t, s)
	start := env.StartDaemon
	var released atomic.Bool
	env.StartDaemon = func() error {
		if released.CompareAndSwap(false, true) {
			answer <- "y" // typed while the vault is being given up
			time.Sleep(300 * time.Millisecond)
		}
		return start()
	}
	done := make(chan int, 1)
	go func() {
		ctx, cancel := context.WithTimeout(ictx, 90*time.Second)
		defer cancel()
		done <- cli.Run(ctx, []string{"auth", "logout"}, env)
	}()
	select {
	case code := <-exited:
		if code != cli.ExitInterrupted {
			t.Errorf("exit %d, want %d", code, cli.ExitInterrupted)
		}
	case <-time.After(60 * time.Second):
		t.Fatal("the interrupted command did not give the vault up")
	}
	if !released.Load() {
		t.Fatal("the daemon was not started again while the process gave the vault up")
	}
	select {
	case <-done:
	case <-time.After(30 * time.Second):
		t.Fatal("the command did not return once the prompt was answered")
	}
	t.Logf("stderr: %s", s.stderr.String())
	if a := m.authStatus(t); !a.SignedIn {
		t.Errorf("after the interrupted logout: %+v", a)
	}
	vaultOpen(t, m)
}

// Putting the lock back is for this vault's daemon only: one of another
// vault on the same socket is left as it is.
func TestLockAgainLeavesAnotherVaultsDaemonAlone(t *testing.T) {
	_, a := sealedAccount(t)
	b := noKeychain(t)
	b.paths, b.home = a.paths, a.home // the same sockets, a data directory of its own
	s := &session{}
	cli.LockAgain(context.Background(), b.env(t, s))
	vaultOpen(t, a)
}

// Where it can't make sure the vault is locked again, hop says so.
func TestLockAgainWarnsWhenItCannotLock(t *testing.T) {
	f := newFakeDaemon(t)
	f.ops[daemon.OpStatus] = func(json.RawMessage) (any, error) {
		return nil, errors.New("the status is broken")
	}
	var stderr strings.Builder
	cli.LockAgain(context.Background(), f.env(t, strings.NewReader(""), &strings.Builder{}, &stderr))
	if !strings.Contains(stderr.String(), "hop: warning:") || !strings.Contains(stderr.String(), "hop lock") {
		t.Errorf("stderr: %q", stderr.String())
	}
}

// A signup that fails leaves a locked vault locked, even where the device
// key opens by itself: the command opened the vault for itself only.
func TestFailedSignupLeavesALockedVaultLocked(t *testing.T) {
	w := newAuthWorld(t)
	m := newMachine(t, w, "kc")
	if code := m.hop(t, &session{secrets: initSecrets()}, "init"); code != 0 {
		t.Fatal("init")
	}
	m.must(t, nil, "lock")
	s := &session{}
	if code := m.hop(t, s, "auth", "signup", "--server", w.origin, "--email", authEmail, "--code", "not-an-invite"); code == 0 {
		t.Fatal("signup with a made-up code succeeded")
	}
	if a := m.authStatus(t); !a.Locked {
		t.Error("the vault was locked before the failed signup and is open after it")
	}
}
