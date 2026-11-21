package cli_test

import (
	"strings"
	"testing"
)

// A logout that the store is sure to refuse (a pending Emergency Kit) is
// refused from what the daemon says, before any secret is asked or the
// daemon stopped, so an open vault with a sealed key file stays open: with
// --local-only, which never asks for the device passphrase, as without.
func TestLogoutRefusedByAPendingKitAsksNothingAndKeepsTheVaultOpen(t *testing.T) {
	for _, flags := range [][]string{{"--yes"}, {"--local-only", "--yes"}} {
		t.Run(strings.Join(flags, " "), func(t *testing.T) {
			_, m := sealedAccount(t)
			keepOnlyThis := func(p string) string {
				if strings.HasSuffix(p, "[y/N] ") {
					return "y"
				}
				return "" // only this device
			}
			s := &session{tty: true, env: map[string]string{"HOP_PASSWORD": resolvePassword},
				secrets: map[string]string{askOldPass: devPass}, answer: keepOnlyThis, wrongTypeBack: true}
			if code := m.hop(t, s, "auth", "rotate"); code == 0 || !strings.Contains(s.stderr.String(), "stays pending") {
				t.Fatalf("rotate with a wrong type-back: exit %d: %s", code, s.stderr.String())
			}
			vaultOpen(t, m)
			before := daemonStarted(t, m)
			// The passphrase is there to be typed: asking for it is the
			// failure, not a missing answer.
			s = &session{tty: true, secrets: map[string]string{askOldPass: devPass}}
			if code := m.hop(t, s, append([]string{"auth", "logout"}, flags...)...); code == 0 || !strings.Contains(s.stderr.String(), "Emergency Kit is not confirmed") {
				t.Fatalf("logout with a pending kit: exit %d: %s", code, s.stderr.String())
			}
			if len(s.order) != 0 {
				t.Errorf("asked before the refusal: %q", s.order)
			}
			vaultOpen(t, m)
			if after := daemonStarted(t, m); !after.Equal(before) {
				t.Errorf("the daemon was stopped for a refusal: started %v, now %v", before, after)
			}
		})
	}
}

// Where no daemon has the vault open (it is locked, or no daemon runs),
// the refusal of a pending Emergency Kit comes from the vault's files, and
// still before the device passphrase is asked: plain hop auth logout.
func TestLogoutRefusedByAPendingKitAsksNothingWithTheVaultLockedOrNoDaemon(t *testing.T) {
	for _, how := range [][]string{{"lock"}, {"daemon", "stop"}} {
		t.Run(strings.Join(how, " "), func(t *testing.T) {
			_, m := sealedAccount(t)
			keepOnlyThis := func(p string) string {
				if strings.HasSuffix(p, "[y/N] ") {
					return "y"
				}
				return "" // only this device
			}
			s := &session{tty: true, env: map[string]string{"HOP_PASSWORD": resolvePassword},
				secrets: map[string]string{askOldPass: devPass}, answer: keepOnlyThis, wrongTypeBack: true}
			if code := m.hop(t, s, "auth", "rotate"); code == 0 || !strings.Contains(s.stderr.String(), "stays pending") {
				t.Fatalf("rotate with a wrong type-back: exit %d: %s", code, s.stderr.String())
			}
			m.must(t, nil, how...)
			s = &session{tty: true, secrets: map[string]string{askOldPass: devPass}}
			if code := m.hop(t, s, "auth", "logout", "--yes"); code == 0 || !strings.Contains(s.stderr.String(), "Emergency Kit is not confirmed") {
				t.Fatalf("logout with a pending kit: exit %d: %s", code, s.stderr.String())
			}
			if len(s.order) != 0 {
				t.Errorf("asked before the refusal: %q", s.order)
			}
		})
	}
}
