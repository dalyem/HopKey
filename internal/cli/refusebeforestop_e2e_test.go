package cli_test

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

// untouched fails the test unless the daemon that was running at before
// still runs, with the vault open: the command neither stopped it nor
// locked the vault.
func untouched(t *testing.T, m *machine, before time.Time) {
	t.Helper()
	if after := daemonStarted(t, m); !after.Equal(before) {
		t.Errorf("the daemon was stopped and started again (%s, then %s)", before, after)
	}
	if a := m.authStatus(t); a.Locked {
		t.Errorf("the vault is locked: %+v", a)
	}
}

// A command with nothing to do, or that refuses or is declined, says so
// before it stops the daemon: an open vault whose sealed key file has no
// passphrase in the environment would come back locked.
func TestNothingToDoLeavesTheDaemonAlone(t *testing.T) {
	t.Run("fork --abandon with no fork", func(t *testing.T) {
		_, m := sealedAccount(t)
		before := daemonStarted(t, m)
		s := &session{}
		if code := m.hop(t, s, "vault", "fork", "--local", "--abandon", "--yes"); code != 0 {
			t.Fatalf("exit %d: %s", code, s.stderr.String())
		}
		if !strings.Contains(s.stdout.String(), "There is no interrupted fork to give up.") {
			t.Errorf("stdout: %s", s.stdout.String())
		}
		untouched(t, m, before)
	})
	t.Run("fork --abandon with no fork, in JSON", func(t *testing.T) {
		_, m := sealedAccount(t)
		before := daemonStarted(t, m)
		s := &session{}
		if code := m.hop(t, s, "vault", "fork", "--local", "--abandon", "--yes", "--json"); code != 0 {
			t.Fatalf("exit %d: %s", code, s.stderr.String())
		}
		var r struct {
			Abandoned *bool `json:"abandoned"`
		}
		if err := json.Unmarshal([]byte(s.stdout.String()), &r); err != nil || r.Abandoned == nil || *r.Abandoned {
			t.Errorf("stdout: %s (%v)", s.stdout.String(), err)
		}
		untouched(t, m, before)
	})
	t.Run("login --discard with no enrollment", func(t *testing.T) {
		_, m := sealedAccount(t)
		before := daemonStarted(t, m)
		s := &session{}
		if code := m.hop(t, s, "auth", "login", "--discard", "--yes"); code == 0 || !strings.Contains(s.stderr.String(), "no enrollment is in progress") {
			t.Fatalf("exit %d: %s", code, s.stderr.String())
		}
		untouched(t, m, before)
	})
	t.Run("logout --local-only, declined", func(t *testing.T) {
		_, m := sealedAccount(t)
		before := daemonStarted(t, m)
		s := &session{tty: true, answer: func(string) string { return "n" }}
		if code := m.hop(t, s, "auth", "logout", "--local-only"); code == 0 || !strings.Contains(s.stderr.String(), "not logged out") {
			t.Fatalf("exit %d: %s", code, s.stderr.String())
		}
		if n := devicePassphrasePrompts(s); n != 0 {
			t.Errorf("asked for the device passphrase %d times", n)
		}
		untouched(t, m, before)
	})
	t.Run("logout of a local-only vault", func(t *testing.T) {
		m := sealedLocal(t)
		before := daemonStarted(t, m)
		s := &session{tty: true, secrets: map[string]string{askOldPass: devPass}}
		if code := m.hop(t, s, "auth", "logout", "--yes"); code == 0 || !strings.Contains(s.stderr.String(), "local-only") {
			t.Fatalf("exit %d: %s", code, s.stderr.String())
		}
		if n := devicePassphrasePrompts(s); n != 0 {
			t.Errorf("asked for the device passphrase %d times", n)
		}
		untouched(t, m, before)
	})
}

// A command whose arguments are wrong, or that can't run on this vault,
// says so before it asks for the device passphrase or stops the daemon.
func TestBadArgumentsRefuseBeforeAnySecret(t *testing.T) {
	cases := []struct {
		name  string
		local bool // on a local-only vault
		args  []string
		want  string
	}{
		{"revoke with no device", false, []string{"auth", "devices", "revoke"}, "name the device to revoke"},
		{"rotate with an argument", false, []string{"auth", "rotate", "extra"}, `unexpected argument "extra"`},
		{"passwd with an argument", false, []string{"auth", "passwd", "extra"}, `unexpected argument "extra"`},
		{"merge with a token that is not one", false, []string{"auth", "merge", "--discard", "--confirm", "nonsense"}, "is not a token"},
		{"rotate on a local-only vault", true, []string{"auth", "rotate"}, "local-only"},
		{"approve on a local-only vault", true, []string{"auth", "approve", "1234-5678"}, "local-only"},
		{"resume on a local-only vault", true, []string{"auth", "resume"}, "local-only"},
		{"merge on a local-only vault", true, []string{"auth", "merge"}, "local-only"},
		{"login without --merge on a local-only vault", true, []string{"auth", "login", "--method", "password", "--server", "https://127.0.0.1:9", "--email", "me@example.com"}, "local-only vault"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var m *machine
			if c.local {
				m = sealedLocal(t)
			} else {
				_, m = sealedAccount(t)
			}
			before := daemonStarted(t, m)
			s := &session{tty: true, env: map[string]string{"HOP_PASSWORD": resolvePassword}, secrets: map[string]string{askOldPass: devPass}}
			if code := m.hop(t, s, c.args...); code == 0 || !strings.Contains(s.stderr.String(), c.want) {
				t.Fatalf("exit %d; want a failure saying %q: %s", code, c.want, s.stderr.String())
			}
			if n := devicePassphrasePrompts(s); n != 0 {
				t.Errorf("asked for the device passphrase %d times before refusing", n)
			}
			untouched(t, m, before)
		})
	}
}
