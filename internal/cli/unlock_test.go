package cli_test

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/dalyem/hopkey/internal/cli"
	"github.com/dalyem/hopkey/internal/daemon"
	"github.com/dalyem/hopkey/internal/store"
)

const unlockPassphrase = "the device passphrase"

// sealedDaemon is a vault whose device key is a sealed file, and a daemon
// in this process that opened it without HOP_DEVICE_PASSPHRASE, as hop mcp
// and the login service start one: it serves, locked.
type sealedDaemon struct {
	dataDir string
	paths   daemon.Paths
	prompts []string
}

func newSealedDaemon(t *testing.T) *sealedDaemon {
	t.Helper()
	base := shortTemp(t)
	x := &sealedDaemon{
		dataDir: filepath.Join(base, "data"),
		paths:   daemon.Paths{RunDir: filepath.Join(base, "run"), ConfigDir: filepath.Join(base, "cfg"), StateDir: filepath.Join(base, "state")},
	}
	withPass := func(k string) string {
		if k == store.PassphraseEnv {
			return unlockPassphrase
		}
		return ""
	}
	p, err := store.PrepareInit(store.Config{DataDir: x.dataDir, Getenv: withPass},
		store.InitOptions{Password: []byte("unlock test password"), DeviceStore: store.DeviceStoreFile})
	if err != nil {
		t.Fatal(err)
	}
	s, err := p.Commit()
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	st, err := store.Open(context.Background(), store.Config{DataDir: x.dataDir, Getenv: func(string) string { return "" }})
	if err != nil {
		t.Fatal(err)
	}
	d, err := daemon.Start(daemon.Options{Paths: x.paths, Store: st, Version: "test", Tailscale: noTailscale{}, Logf: t.Logf})
	if err != nil {
		st.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() { d.Close() })
	return x
}

// hop runs a command with env as its environment. A prompt is answered
// with the passphrase when tty is set.
func (x *sealedDaemon) hop(t *testing.T, env map[string]string, tty bool, args ...string) (int, string, string) {
	t.Helper()
	var so, se bytes.Buffer
	e := &cli.Env{
		Stdin: strings.NewReader(""), Stdout: &so, Stderr: &se,
		Getenv: func(k string) string { return env[k] },
		Home:   filepath.Dir(x.dataDir), Paths: x.paths, DataDir: x.dataDir, StdinTTY: tty,
		StartDaemon: func() error { return errors.New("no daemon start in this test") },
	}
	if tty {
		e.ReadPassword = func(p string) ([]byte, error) {
			x.prompts = append(x.prompts, p)
			return []byte(unlockPassphrase), nil
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	code := cli.Run(ctx, args, e)
	return code, so.String(), se.String()
}

func (x *sealedDaemon) locked(t *testing.T) bool {
	t.Helper()
	code, out, errOut := x.hop(t, nil, false, "status", "--json")
	if code != 0 {
		t.Fatalf("status: exit %d: %s", code, errOut)
	}
	var st struct {
		Vault *struct {
			Locked bool `json:"locked"`
		} `json:"vault"`
	}
	decodeJSON(t, out, &st)
	if st.Vault == nil {
		t.Fatalf("status has no vault: %s", out)
	}
	return st.Vault.Locked
}

// hop unlock passes the caller's HOP_DEVICE_PASSPHRASE to a daemon that
// was started without one; the daemon uses it for that unlock only.
func TestUnlockSendsTheDevicePassphrase(t *testing.T) {
	x := newSealedDaemon(t)
	if !x.locked(t) {
		t.Fatal("the daemon started unlocked without the passphrase")
	}
	// Without the passphrase anywhere, it stays locked and says why.
	code, _, errOut := x.hop(t, nil, false, "unlock")
	if code == 0 || !strings.Contains(errOut, store.PassphraseEnv) {
		t.Errorf("unlock with no passphrase: exit %d, %q", code, errOut)
	}
	if !x.locked(t) {
		t.Fatal("unlocked with no passphrase")
	}
	// A wrong one is refused.
	if code, _, errOut := x.hop(t, map[string]string{store.PassphraseEnv: "not the device passphrase"}, false, "unlock"); code == 0 || !strings.Contains(errOut, "wrong passphrase") {
		t.Errorf("unlock with a wrong passphrase: exit %d, %q", code, errOut)
	}
	code, out, errOut := x.hop(t, map[string]string{store.PassphraseEnv: unlockPassphrase}, false, "unlock")
	if code != 0 || !strings.Contains(out, "vault unlocked") {
		t.Fatalf("unlock with the passphrase: exit %d, %q %q", code, out, errOut)
	}
	if x.locked(t) {
		t.Fatal("still locked after hop unlock with the passphrase")
	}
	// The daemon did not keep it: after a lock, an unlock without it fails.
	if code, _, errOut := x.hop(t, nil, false, "lock"); code != 0 {
		t.Fatalf("lock: exit %d: %s", code, errOut)
	}
	if code, _, _ := x.hop(t, nil, false, "unlock"); code == 0 || !x.locked(t) {
		t.Errorf("the daemon kept the passphrase: unlock without it gave exit %d", code)
	}
}

// With no passphrase in the environment and a terminal, hop unlock asks
// for it when the device key is a sealed file.
func TestUnlockAsksForTheDevicePassphrase(t *testing.T) {
	x := newSealedDaemon(t)
	code, out, errOut := x.hop(t, nil, true, "unlock")
	if code != 0 || !strings.Contains(out, "vault unlocked") {
		t.Fatalf("unlock on a terminal: exit %d, %q %q", code, out, errOut)
	}
	if len(x.prompts) != 1 || x.prompts[0] != "Device passphrase: " {
		t.Errorf("prompts %q", x.prompts)
	}
	if x.locked(t) {
		t.Error("still locked")
	}
}

// hop lock and hop unlock take --json, as every command does.
func TestLockAndUnlockJSON(t *testing.T) {
	x := newSealedDaemon(t)
	env := map[string]string{store.PassphraseEnv: unlockPassphrase}
	var res struct {
		Locked *bool `json:"locked"`
	}
	code, out, errOut := x.hop(t, env, false, "unlock", "--json")
	if code != 0 {
		t.Fatalf("unlock --json: exit %d: %s", code, errOut)
	}
	decodeJSON(t, out, &res)
	if res.Locked == nil || *res.Locked {
		t.Errorf("unlock --json: %s", out)
	}
	res.Locked = nil
	code, out, errOut = x.hop(t, env, false, "lock", "--json")
	if code != 0 {
		t.Fatalf("lock --json: exit %d: %s", code, errOut)
	}
	decodeJSON(t, out, &res)
	if res.Locked == nil || !*res.Locked {
		t.Errorf("lock --json: %s", out)
	}
	if code, _, errOut := x.hop(t, env, false, "lock", "extra"); code == 0 || !strings.Contains(errOut, "usage") {
		t.Errorf("lock with an argument: exit %d, %q", code, errOut)
	}
}

// hop setup --service on a device whose key is a sealed file warns that
// the service's daemon starts locked, and how to open it.
func TestSetupServiceWarnsAboutASealedDeviceKey(t *testing.T) {
	s := newServiceEnv(t, "linux")
	dataDir := filepath.Join(s.home, ".local", "share", "hop")
	p, err := store.PrepareInit(store.Config{DataDir: dataDir, Getenv: func(k string) string {
		if k == store.PassphraseEnv {
			return unlockPassphrase
		}
		return ""
	}}, store.InitOptions{Password: []byte("service test password"), DeviceStore: store.DeviceStoreFile})
	if err != nil {
		t.Fatal(err)
	}
	st, err := p.Commit()
	if err != nil {
		t.Fatal(err)
	}
	st.Close()
	s.vars[store.PassphraseEnv] = unlockPassphrase

	code, _, errOut := s.hop(t, "setup", "--service", "--yes")
	if code != 0 {
		t.Fatalf("exit %d: %s", code, errOut)
	}
	for _, want := range []string{"sealed", "starts locked", "hop unlock", "keychain"} {
		if !strings.Contains(errOut, want) {
			t.Errorf("setup --service does not warn %q:\n%s", want, errOut)
		}
	}
	b, err := os.ReadFile(s.servicePath())
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), unlockPassphrase) || strings.Contains(string(b), store.PassphraseEnv) {
		t.Errorf("the unit carries the passphrase:\n%s", b)
	}

	// --json carries the warning in its notes.
	code, out, errOut := s.hop(t, "setup", "--service", "--yes", "--json")
	if code != 0 {
		t.Fatalf("--json: exit %d: %s", code, errOut)
	}
	var res cli.ServiceResult
	decodeJSON(t, out, &res)
	if !strings.Contains(strings.Join(res.Notes, "\n"), "starts locked") {
		t.Errorf("--json notes: %q", res.Notes)
	}

	// A keychain device gets no such warning.
	k := newServiceEnv(t, "linux")
	if code, _, errOut := k.hop(t, "setup", "--service", "--yes"); code != 0 || strings.Contains(errOut, "starts locked") {
		t.Errorf("no vault: exit %d, %q", code, errOut)
	}
}
