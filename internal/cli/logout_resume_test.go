package cli_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/dalyem/hopkey/internal/cli"
	"github.com/dalyem/hopkey/internal/model"
	"github.com/dalyem/hopkey/internal/store"
	"github.com/dalyem/hopkey/internal/syncclient"
	"golang.org/x/crypto/ssh"
)

// signedUp is a machine with a vault that holds a host and is signed in
// to the test server.
func signedUp(t *testing.T) *machine {
	t.Helper()
	m, _ := signedUpWithKey(t)
	return m
}

// signedUpWithKey is signedUp, and the account's Secret Key.
func signedUpWithKey(t *testing.T) (*machine, string) {
	t.Helper()
	w := newAuthWorld(t)
	m := newMachine(t, w, "solo")
	initS := &session{secrets: map[string]string{"Master password: ": resolvePassword, "Repeat it: ": resolvePassword}}
	if code := m.hop(t, initS, "init"); code != 0 {
		t.Fatalf("init: exit %d: %s", code, initS.stderr.String())
	}
	sk, _ := kitKeys(t, initS.stdout.String())
	m.must(t, nil, "add", "web", "--address", "203.0.113.10", "--user", "deploy")
	m.must(t, nil, "auth", "signup", "--server", w.origin, "--email", authEmail, "--code", w.invite(t), "--json")
	return m, sk
}

// interruptedLogout runs hop logout while the keychain refuses to delete
// the device record: the logout is recorded as RETIRED, and its cleanup
// stops there, as a crash at that point leaves it. The keychain works
// again afterwards.
func interruptedLogout(t *testing.T, m *machine) {
	t.Helper()
	m.ring.failDelete.Store(true)
	s := &session{}
	if code := m.hop(t, s, "logout", "--yes"); code == 0 {
		t.Fatalf("logout with a keychain that refuses deletes: exit 0: %s", s.stdout.String())
	}
	m.ring.failDelete.Store(false)
	if ok, err := store.Exists(m.data); err != nil || !ok {
		t.Fatalf("setup: the logout's cleanup finished after all: %v", err)
	}
}

// A logout interrupted after RETIRED finishes at the next open, and that
// open is where ~/.ssh/hop gets emptied: hop logout run again finishes
// both.
func TestLogoutAfterAnInterruptedCleanupEmptiesTheSSHConfig(t *testing.T) {
	m := signedUp(t)
	checkWiped := plantHopSSH(t, m.paths.ConfigDir, m.home)
	interruptedLogout(t, m)

	s := &session{}
	if code := m.hop(t, s, "logout", "--yes"); code != 0 {
		t.Fatalf("logout again: exit %d: %s", code, s.stderr.String())
	}
	checkWiped()
	if ok, _ := store.Exists(m.data); ok {
		t.Error("the vault is still there")
	}
}

// hopDaemon runs hop daemon on m to its end, which with no vault is a
// failure, and returns its stderr.
func hopDaemon(m *machine) (int, string) {
	var so, se syncBuffer
	env := &cli.Env{
		Stdin: nil, Stdout: &so, Stderr: &se,
		Getenv: func(string) string { return "" },
		Home:   m.home, Paths: m.paths, DataDir: m.data, Keyring: m.ring,
		OpenStore: func() (model.Store, error) {
			return store.Open(context.Background(), store.Config{DataDir: m.data, Keyring: m.ring, Getenv: func(string) string { return "" }})
		},
		SyncClient: syncclient.Options{RootCAs: m.w.pool},
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	code := cli.Run(ctx, []string{"daemon"}, env)
	return code, se.String()
}

// A cleanup that decided to wipe from a stale read of the logout's mark
// does not wipe what a new sign-in wrote meanwhile: the daemon that finds
// the interrupted logout reads the mark and stalls, a password login
// installs a new vault and its daemon writes the ssh config, and then the
// stalled cleanup goes on. The new config is still there.
func TestStaleLogoutCleanupLeavesANewSignInsConfig(t *testing.T) {
	m, sk := signedUpWithKey(t)
	// web gets a key, so that a config written from the vault names it.
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	block, err := ssh.MarshalPrivateKey(priv, "")
	if err != nil {
		t.Fatal(err)
	}
	keyFile := filepath.Join(m.home, "id_ed25519")
	if err := os.WriteFile(keyFile, pem.EncodeToMemory(block), 0o600); err != nil {
		t.Fatal(err)
	}
	m.must(t, nil, "key", "add", keyFile, "--name", "k")
	m.must(t, nil, "edit", "web", "--key", "k")
	m.must(t, nil, "sync")
	plantHopSSH(t, m.paths.ConfigDir, m.home)
	interruptedLogout(t, m)

	paused, resume := make(chan struct{}), make(chan struct{})
	var once sync.Once
	defer cli.SetLogoutCleanupHook(func() {
		first := false
		once.Do(func() { first = true })
		if first {
			close(paused)
			<-resume
		}
	})()

	// A: the daemon start that finishes the logout, stalled after it read
	// the mark.
	aDone := make(chan struct{})
	go func() {
		defer close(aDone)
		if code, stderr := hopDaemon(m); code == 0 {
			t.Errorf("a daemon started with no vault: %s", stderr)
		}
	}()
	select {
	case <-paused:
	case <-time.After(30 * time.Second):
		t.Fatal("the daemon start never read the logout's mark")
	}
	if ok, _ := store.Exists(m.data); ok {
		t.Fatal("setup: the stalled daemon start did not finish the logout")
	}

	// B: a new password login, and its daemon's ssh config.
	config := filepath.Join(m.paths.ConfigDir, "config")
	hasWeb := func() bool {
		b, _ := os.ReadFile(config)
		return strings.Contains(string(b), "Host web\n")
	}
	bDone := make(chan struct{})
	go func() {
		defer close(bDone)
		s := &session{env: map[string]string{"HOP_PASSWORD": resolvePassword, "HOP_SECRET_KEY": sk}}
		if code := m.hop(t, s, "login", "--method", "password", "--server", m.w.origin, "--email", authEmail, "--name", "solo-again"); code != 0 {
			t.Errorf("login: exit %d: %s", code, s.stderr.String())
			return
		}
		deadline := time.Now().Add(20 * time.Second)
		for !hasWeb() {
			if time.Now().After(deadline) {
				b, _ := os.ReadFile(config)
				t.Errorf("the new sign-in's daemon never wrote the ssh config:\n%s", b)
				return
			}
			time.Sleep(20 * time.Millisecond)
		}
	}()
	// Without the fix B finishes while A is stalled. With it, B waits for
	// A's cleanup to let go of the config: A is resumed after a while.
	select {
	case <-bDone:
	case <-time.After(5 * time.Second):
	}
	close(resume)
	<-aDone
	<-bDone
	if t.Failed() {
		return
	}
	if !hasWeb() {
		b, _ := os.ReadFile(config)
		t.Fatalf("the stalled cleanup wiped the new sign-in's ssh config:\n%s", b)
	}
	if pending, err := store.LogoutCleanupPending(m.data); err != nil || pending {
		t.Errorf("the logout still owes a cleanup: %v %v", pending, err)
	}
	b, _ := os.ReadFile(config)
	if strings.Contains(string(b), "planted-web") {
		t.Errorf("the old vault's host is still in the config:\n%s", b)
	}
}

// The daemon that finishes such a logout as it starts (any hop command
// starts one) empties ~/.ssh/hop too, and a wipe that fails is tried
// again at the next start, though the vault is gone by then.
func TestDaemonStartAfterAnInterruptedLogoutEmptiesTheSSHConfig(t *testing.T) {
	m := signedUp(t)
	checkWiped := plantHopSSH(t, m.paths.ConfigDir, m.home)
	interruptedLogout(t, m)

	daemonRun := func() {
		t.Helper()
		code, stderr := hopDaemon(m)
		t.Logf("hop daemon: exit %d: %s", code, stderr)
		if code == 0 {
			t.Fatalf("a daemon started with no vault")
		}
	}

	// The first wipe fails: keys/ is a symlink, which hop refuses to
	// follow.
	keys := filepath.Join(m.paths.ConfigDir, "keys")
	aside := keys + ".aside"
	if err := os.Rename(keys, aside); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(aside, keys); err != nil {
		t.Fatal(err)
	}
	daemonRun()
	if ok, _ := store.Exists(m.data); ok {
		t.Fatal("the daemon start did not finish the logout")
	}
	if err := os.Remove(keys); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(aside, keys); err != nil {
		t.Fatal(err)
	}
	daemonRun()
	checkWiped()
}
