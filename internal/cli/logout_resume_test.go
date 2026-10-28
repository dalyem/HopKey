package cli_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/dalyem/hopkey/internal/cli"
	"github.com/dalyem/hopkey/internal/model"
	"github.com/dalyem/hopkey/internal/store"
	"github.com/dalyem/hopkey/internal/syncclient"
)

// signedUp is a machine with a vault that holds a host and is signed in
// to the test server.
func signedUp(t *testing.T) *machine {
	t.Helper()
	w := newAuthWorld(t)
	m := newMachine(t, w, "solo")
	initS := &session{secrets: map[string]string{"Master password: ": resolvePassword, "Repeat it: ": resolvePassword}}
	if code := m.hop(t, initS, "init"); code != 0 {
		t.Fatalf("init: exit %d: %s", code, initS.stderr.String())
	}
	m.must(t, nil, "add", "web", "--address", "203.0.113.10", "--user", "deploy")
	m.must(t, nil, "auth", "signup", "--server", w.origin, "--email", authEmail, "--code", w.invite(t), "--json")
	return m
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

// The daemon that finishes such a logout as it starts (any hop command
// starts one) empties ~/.ssh/hop too, and a wipe that fails is tried
// again at the next start, though the vault is gone by then.
func TestDaemonStartAfterAnInterruptedLogoutEmptiesTheSSHConfig(t *testing.T) {
	m := signedUp(t)
	checkWiped := plantHopSSH(t, m.paths.ConfigDir, m.home)
	interruptedLogout(t, m)

	daemonRun := func() {
		t.Helper()
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
		t.Logf("hop daemon: exit %d: %s", code, se.String())
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
