package cli_test

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/dalyem/hopkey/internal/cli"
)

// Every command that Ctrl-C ends says the same: hop: interrupted. Not "the
// sign-in was cancelled" for one, the store's account of a publication that
// "did not commit" for another, and nothing for a third.
func TestInterruptedCommandsAllSayTheSame(t *testing.T) {
	cut := func(path string, interrupt context.CancelCauseFunc) func(http.ResponseWriter, *http.Request) bool {
		return func(rw http.ResponseWriter, r *http.Request) bool {
			if r.URL.Path != path {
				return false
			}
			io.Copy(io.Discard, r.Body)
			interrupt(cli.ErrInterrupted) // the signal, while the request waits
			<-r.Context().Done()
			return true
		}
	}
	t.Run("a publication", func(t *testing.T) {
		w := newAuthWorld(t)
		m := newMachine(t, w, "kc")
		if code := m.hop(t, &session{secrets: initSecrets()}, "init"); code != 0 {
			t.Fatal("init")
		}
		ctx, interrupt := context.WithCancelCause(context.Background())
		hook := cut("/v1/signup", interrupt)
		w.hook.Store(&hook)
		s := &session{ctx: ctx}
		code := m.hop(t, s, "auth", "signup", "--server", w.origin, "--email", authEmail, "--code", w.invite(t))
		w.hook.Store(nil)
		if code != cli.ExitInterrupted || s.stderr.String() != "hop: interrupted\n" {
			t.Errorf("exit %d, stderr %q", code, s.stderr.String())
		}
	})
	t.Run("an approval", func(t *testing.T) {
		w := newAuthWorld(t)
		m := signedInMachine(t, w, "kc")
		ctx, interrupt := context.WithCancelCause(context.Background())
		hook := cut("/v1/enroll/claim", interrupt)
		w.hook.Store(&hook)
		s := &session{ctx: ctx}
		code := m.hop(t, s, "auth", "approve", "ABCD-EFGH", "--sas", "12345678")
		w.hook.Store(nil)
		if code != cli.ExitInterrupted || s.stderr.String() != "hop: interrupted\n" {
			t.Errorf("exit %d, stderr %q", code, s.stderr.String())
		}
	})
	t.Run("a sign-in", func(t *testing.T) {
		w := newAuthWorld(t)
		signedInMachine(t, w, "m1")
		m2 := newMachine(t, w, "m2")
		ctx, interrupt := context.WithCancelCause(context.Background())
		s := &session{tty: true, ctx: ctx}
		_, exit := startLogin(t, m2, s)
		interrupt(cli.ErrInterrupted)
		code := exit()
		if code != cli.ExitInterrupted || !strings.HasSuffix(s.stderr.String(), "hop: interrupted\n") || strings.Contains(s.stderr.String(), "cancelled") {
			t.Errorf("exit %d, stderr %q", code, s.stderr.String())
		}
	})
}
