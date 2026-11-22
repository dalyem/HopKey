package cli_test

import (
	"os"
	"strings"
	"testing"
)

// What the vault goes back to follows what the command did, not what it
// set out to do: a fork whose new vault was given up, or a logout refused
// before it began, leaves the vault it found, which stays open.
func TestUnfinishedReplacementLeavesTheVaultOpen(t *testing.T) {
	t.Run("fork given up in its commit", func(t *testing.T) {
		_, m := sealedAccount(t)
		s := forkSession()
		s.secrets[askOldPass] = devPass
		s.onSecret = func(p string) (string, bool) {
			if strings.HasPrefix(p, "Type the last group of your Recovery Key") {
				// Where the commit builds the new vault: it can't, and
				// gives the new vault up.
				if err := os.WriteFile(m.data+".fork-new", nil, 0o600); err != nil {
					t.Error(err)
				}
			}
			return "", false
		}
		if code := m.hop(t, s, "vault", "fork", "--local", "--yes"); code == 0 {
			t.Fatal("the fork succeeded where it can't build its new vault")
		}
		if a := m.authStatus(t); !a.SignedIn {
			t.Fatalf("the old vault is not there: %+v", a)
		}
		vaultOpen(t, m)
	})
	t.Run("logout refused by a pending kit", func(t *testing.T) {
		_, m := sealedAccount(t)
		env := map[string]string{"HOP_PASSWORD": resolvePassword}
		keepOnlyThis := func(p string) string {
			if strings.HasSuffix(p, "[y/N] ") {
				return "y"
			}
			return "" // only this device
		}
		s := &session{tty: true, env: env, secrets: map[string]string{askOldPass: devPass}, answer: keepOnlyThis, wrongTypeBack: true}
		if code := m.hop(t, s, "auth", "rotate"); code == 0 || !strings.Contains(s.stderr.String(), "stays pending") {
			t.Fatalf("rotate with a wrong type-back: exit %d: %s", code, s.stderr.String())
		}
		vaultOpen(t, m)
		s = &session{tty: true, secrets: map[string]string{askOldPass: devPass}}
		if code := m.hop(t, s, "auth", "logout", "--yes"); code == 0 {
			t.Fatal("logout with a pending kit succeeded")
		}
		vaultOpen(t, m)
	})
}
