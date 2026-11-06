package cli_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"

	"golang.org/x/crypto/ssh"

	"github.com/dalyem/hopkey/internal/cli"
)

// A signal while hop auth devices revoke runs the rotation it offers: the
// rotation finishes the host it is on, skips the rest, and keeps the keys
// the hosts need; the process is not ended under it. This goes through the
// whole command, from the revoke to the rotation, with Env.Exit recorded.
func TestKeyRotateFromRevokeSurvivesAnInterrupt(t *testing.T) {
	requireSSH(t)
	w := newAuthWorld(t)
	m1, m2 := newMachine(t, w, "m1"), newMachine(t, w, "m2")
	initS := &session{secrets: map[string]string{"Master password: ": resolvePassword, "Repeat it: ": resolvePassword}}
	if code := m1.hop(t, initS, "init"); code != 0 {
		t.Fatalf("init: exit %d: %s", code, initS.stderr.String())
	}
	sk, _ := kitKeys(t, initS.stdout.String())
	m1.must(t, nil, "auth", "signup", "--server", w.origin, "--email", authEmail, "--code", w.invite(t), "--json")
	m2.must(t, map[string]string{"HOP_PASSWORD": resolvePassword, "HOP_SECRET_KEY": sk},
		"login", "--method", "password", "--server", w.origin, "--email", authEmail, "--name", "m2", "--json")

	// The key, and two hosts that use it.
	base := shortTemp(t)
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	oldKey, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	block, err := ssh.MarshalPrivateKey(priv, "")
	if err != nil {
		t.Fatal(err)
	}
	keyFile := filepath.Join(base, "deploy")
	if err := os.WriteFile(keyFile, pem.EncodeToMemory(block), 0o600); err != nil {
		t.Fatal(err)
	}
	m1.must(t, nil, "key", "add", keyFile, "--name", "deploy-key")
	os.Remove(keyFile)
	var srv []*akServer
	var orig []string
	for i := range 2 {
		home := filepath.Join(base, "remote"+strconv.Itoa(i+1))
		if err := os.MkdirAll(filepath.Join(home, ".ssh"), 0o700); err != nil {
			t.Fatal(err)
		}
		content := "restrict " + authorizedKeysLine(oldKey.PublicKey()) + " deploy@old\n"
		if err := os.WriteFile(filepath.Join(home, ".ssh", "authorized_keys"), []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		s := startAKServer(t, home)
		srv, orig = append(srv, s), append(orig, content)
		m1.must(t, nil, "add", "web-"+strconv.Itoa(i+1), "--address", "127.0.0.1", "--port", strconv.Itoa(s.port),
			"--user", "deploy", "--key", "deploy-key", "--host-key", authorizedKeysLine(s.hostKey))
	}

	// The signal comes as web-1's first authorized_keys edit starts.
	ctx, interrupt := context.WithCancelCause(context.Background())
	var once sync.Once
	srv[0].setOnExec(func(cmd string) bool {
		if isAKWrite(cmd) {
			once.Do(func() { interrupt(cli.ErrInterrupted) })
		}
		return false
	})
	var mu sync.Mutex
	var exits []int
	s := &session{
		tty: true, ctx: ctx,
		secrets: map[string]string{"Current master password: ": resolvePassword},
		answer: func(prompt string) string {
			if strings.HasSuffix(prompt, "[y/N] ") {
				return "y"
			}
			return "" // keep only this device
		},
		exit: func(code int) {
			mu.Lock()
			defer mu.Unlock()
			exits = append(exits, code)
		},
	}
	code := m1.hop(t, s, "auth", "devices", "revoke", "m2")
	mu.Lock()
	if len(exits) > 0 {
		t.Errorf("hop ended the process (exit %v) while the rotation was changing web-1", exits)
	}
	mu.Unlock()
	if code != cli.ExitInterrupted {
		t.Errorf("exit %d, want %d", code, cli.ExitInterrupted)
	}
	out := s.stdout.String()
	if !strings.Contains(out, "Rotate them now?") && !strings.Contains(s.stderr.String(), "Rotate them now?") {
		t.Fatalf("no rotation was offered:\n%s\n%s", out, s.stderr.String())
	}

	// web-1 was finished: it accepts the new key only, and the vault points
	// it there. web-2 was never started.
	var keys []cli.KeyView
	decodeJSON(t, m1.must(t, nil, "key", "ls", "--json"), &keys)
	var newName string
	for _, k := range keys {
		if strings.HasPrefix(k.Name, "deploy-key-rotated-") {
			newName = k.Name
		}
	}
	hosts := m1.hosts(t)
	if newName == "" || hosts["web-1"].Key == nil || hosts["web-1"].Key.Name != newName {
		t.Errorf("web-1 is not on a new key: keys %+v, web-1 %+v", keys, hosts["web-1"].Key)
	}
	if hosts["web-2"].Key == nil || hosts["web-2"].Key.Name != "deploy-key" {
		t.Errorf("web-2 moved: %+v", hosts["web-2"].Key)
	}
	b, _ := os.ReadFile(filepath.Join(srv[0].home, ".ssh", "authorized_keys"))
	if strings.Contains(string(b), authorizedKeysLine(oldKey.PublicKey())) || !strings.Contains(string(b), "restrict ") {
		t.Errorf("web-1 authorized_keys:\n%s", b)
	}
	if b, _ := os.ReadFile(filepath.Join(srv[1].home, ".ssh", "authorized_keys")); string(b) != orig[1] {
		t.Errorf("web-2 authorized_keys changed:\n%s", b)
	}
	if !strings.Contains(out, "interrupted") {
		t.Errorf("web-2 is not reported as interrupted:\n%s", out)
	}
}
