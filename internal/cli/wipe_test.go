package cli_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"

	"github.com/dalyem/hopkey/internal/sshconfig"
)

// plantHopSSH writes into configDir what a daemon writes there from the
// vault (a config with a host, its key file and its pins), and the user's
// own ssh files beside it under home/.ssh. The returned check, run after
// a logout, fails the test if anything the vault decrypted is left in
// configDir, if the config itself is gone (the user's Include names it),
// or if any of the user's files changed.
func plantHopSSH(t *testing.T, configDir, home string) (check func()) {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	k, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	err = sshconfig.Write(sshconfig.Options{Dir: configDir, AgentSocket: filepath.Join(configDir, "agent.sock")},
		[]sshconfig.Host{{Alias: "planted-web", HostName: "203.0.113.50", User: "deploy", PublicKey: k, HostKeys: []ssh.PublicKey{k}}})
	if err != nil {
		t.Fatal(err)
	}
	userSSH := filepath.Join(home, ".ssh")
	user := map[string]string{
		filepath.Join(userSSH, "config"):         "Include hop/config\nHost mine\n  HostName 198.51.100.1\n",
		filepath.Join(userSSH, "known_hosts"):    "mine " + strings.TrimSpace(string(ssh.MarshalAuthorizedKey(k))) + "\n",
		filepath.Join(userSSH, "id_ed25519.pub"): string(ssh.MarshalAuthorizedKey(k)),
	}
	for p, body := range user {
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if pins, _ := filepath.Glob(filepath.Join(configDir, "known_hosts-*")); len(pins) == 0 {
		t.Fatal("no pins file was planted")
	}
	return func() {
		t.Helper()
		cfg, err := os.ReadFile(filepath.Join(configDir, "config"))
		if err != nil {
			t.Errorf("the hop ssh config is gone, so the user's Include breaks: %v", err)
		}
		if strings.Contains(string(cfg), "Host ") || strings.Contains(string(cfg), "203.0.113.") {
			t.Errorf("the hop ssh config still names hosts after the logout:\n%s", cfg)
		}
		for _, pattern := range []string{"known_hosts*", filepath.Join("keys", "*.pub")} {
			left, _ := filepath.Glob(filepath.Join(configDir, pattern))
			if len(left) != 0 {
				t.Errorf("left behind after the logout: %q", left)
			}
		}
		for p, body := range user {
			if b, err := os.ReadFile(p); err != nil || string(b) != body {
				t.Errorf("the user's %s changed: %v %q", p, err, b)
			}
		}
	}
}
