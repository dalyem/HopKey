package cli_test

import (
	"encoding/json"
	"maps"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/dalyem/hopkey/internal/canonjson"
	"github.com/dalyem/hopkey/internal/daemon"
	"github.com/dalyem/hopkey/internal/store"
)

// A secret goes only to the daemon of the vault it is for. The checks below
// run hop through cli.Run against a daemon that serves another vault, and
// against fake daemons that answer the status in the ways a real one does
// not, and look at what the daemon received and what it changed.

// ringState is a copy of what m's keychain holds.
func ringState(m *machine) map[string]string {
	m.ring.mu.Lock()
	defer m.ring.mu.Unlock()
	return maps.Clone(m.ring.m)
}

// keyState is m's device.json and device.key as they are now.
func keyState(t *testing.T, m *machine) map[string]string {
	t.Helper()
	out := map[string]string{}
	for _, name := range []string{"device.json", "device.key"} {
		b, err := os.ReadFile(filepath.Join(m.data, name))
		if err != nil && !os.IsNotExist(err) {
			t.Fatal(err)
		}
		out[name] = string(b)
	}
	return out
}

// vaultFiles is every file in m's vault directory and its device files.
func vaultFiles(t *testing.T, m *machine) map[string]string {
	t.Helper()
	out := map[string]string{}
	err := filepath.WalkDir(m.data, func(path string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() || filepath.Base(path) == "owner.lock" {
			return err
		}
		b, rerr := os.ReadFile(path)
		if rerr != nil {
			return rerr
		}
		out[path] = string(b)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// localVault makes m a local-only vault and returns its Secret Key. answer
// is how the seal question is answered, if there is one.
func localVault(t *testing.T, m *machine, answer string) string {
	t.Helper()
	i := &session{tty: true, secrets: initSecrets(), onSecret: typedTwice(devPass), answer: func(string) string { return answer }}
	if code := m.hop(t, i, "init"); code != 0 {
		t.Fatalf("init: exit %d: %s", code, i.stderr.String())
	}
	sk, _ := kitKeys(t, i.stdout.String())
	return sk
}

// hop unlock --password asks for the master password and the Secret Key,
// and sends them to the daemon. It must be the daemon of this vault, for a
// device key in the keychain, in an unsealed file and in a sealed one alike:
// otherwise the other vault's device key is replaced, and this one's is not.
func TestUnlockPasswordNeverReachesADaemonOfAnotherVault(t *testing.T) {
	a := newMachine(t, &authWorld{}, "a")
	localVault(t, a, "y")
	a.must(t, nil, "add", "web", "--address", "203.0.113.10", "--user", "deploy")
	aStarted := daemonStarted(t, a)
	aKeys, aRing := keyState(t, a), ringState(a)

	kinds := map[string]func(t *testing.T) (*machine, string){
		"keychain": func(t *testing.T) (*machine, string) {
			b := newMachine(t, &authWorld{}, "b-keychain")
			return b, localVault(t, b, "y")
		},
		"unsealed file": func(t *testing.T) (*machine, string) {
			b := noKeychain(t)
			sk := localVault(t, b, "n")
			if sealed(t, b) {
				t.Fatal("the key file is sealed")
			}
			return b, sk
		},
		"sealed file": func(t *testing.T) (*machine, string) {
			b := noKeychain(t)
			sk := localVault(t, b, "y")
			if !sealed(t, b) {
				t.Fatal("the key file is not sealed")
			}
			return b, sk
		},
	}
	for name, build := range kinds {
		t.Run(name, func(t *testing.T) {
			b, sk := build(t)
			bKeys, bRing := keyState(t, b), ringState(b)
			b.must(t, nil, "daemon", "stop")
			b.paths, b.home = a.paths, a.home // the sockets of the other vault's daemon
			// The same master password on both: the case in which the
			// other vault's key used to be replaced without a word.
			s := &session{tty: true, secrets: map[string]string{masterPrmpt: resolvePassword, "Secret Key (": sk}}
			if code := b.hop(t, s, "unlock", "--password"); code != 255 {
				t.Fatalf("exit %d: %s", code, s.stderr.String())
			}
			if len(s.order) != 0 {
				t.Errorf("asked before refusing: %v", s.order)
			}
			for _, want := range []string{a.data, b.data, "hop daemon stop", "locks the vault it serves"} {
				if !strings.Contains(s.stderr.String(), want) {
					t.Errorf("stderr does not say %q:\n%s", want, s.stderr.String())
				}
			}
			if out := s.stdout.String() + s.stderr.String(); strings.Contains(out, "wrong master password") || strings.Contains(out, "vault unlocked") {
				t.Errorf("a wrong-password or success message:\n%s", out)
			}
			if got := daemonStarted(t, a); !got.Equal(aStarted) {
				t.Error("the other vault's daemon was stopped")
			}
			if a.authStatus(t).Locked {
				t.Error("the other vault was locked")
			}
			if !maps.Equal(keyState(t, a), aKeys) || !maps.Equal(ringState(a), aRing) {
				t.Error("the other vault's device key changed")
			}
			if !maps.Equal(keyState(t, b), bKeys) || !maps.Equal(ringState(b), bRing) {
				t.Error("this vault's device key changed")
			}
		})
	}
}

// A daemon that does not say which vault it serves, one that serves
// another, and one that does not answer the status are all refused by a
// command that would send a password: the daemon receives only the status
// request, and nothing is asked.
func TestPasswordsNeverReachADaemonThatIsNotConfirmed(t *testing.T) {
	statuses := map[string]func(f *fakeDaemon){
		"another vault": func(f *fakeDaemon) {
			f.reply(daemon.OpStatus, map[string]any{"version": "test", "data_dir": "/somewhere/else/hop"})
		},
		"no data directory": func(f *fakeDaemon) { f.reply(daemon.OpStatus, map[string]any{"version": "test"}) },
		"status fails":      func(f *fakeDaemon) { f.fail(daemon.OpStatus, daemon.CodeInternal, "no status today") },
	}
	commands := map[string][]string{"unlock --password": {"unlock", "--password"}, "passwd": {"passwd"}}
	secrets := map[string]string{masterPrmpt: resolvePassword, "Secret Key (": "A3-XXXXXX-XXXXXX-XXXXX-XXXXX-XXXXX-XXXXX",
		"Current master password: ": resolvePassword, "New master password: ": newPassword, "Repeat it: ": newPassword}
	for sname, setup := range statuses {
		for cname, args := range commands {
			t.Run(sname+"/"+cname, func(t *testing.T) {
				f := newFakeDaemon(t)
				setup(f)
				f.reply(daemon.OpUnlock, nil)
				f.reply(daemon.OpPasswd, daemon.KitResult{})
				f.reply(daemon.OpKit, daemon.KitResult{})
				f.reply(daemon.OpKitDone, nil)
				m := newMachine(t, &authWorld{}, "keychain")
				m.paths = f.paths
				s := &session{tty: true, secrets: secrets}
				if code := m.hop(t, s, args...); code != 255 {
					t.Fatalf("exit %d, want 255: %s", code, s.stderr.String())
				}
				if len(s.order) != 0 {
					t.Errorf("asked before refusing: %v", s.order)
				}
				for _, op := range []string{daemon.OpUnlock, daemon.OpPasswd, daemon.OpKit, daemon.OpKitDone} {
					if n := len(f.called(op)); n != 0 {
						t.Errorf("the daemon received %s %d times: %s", op, n, f.called(op))
					}
				}
				if !strings.Contains(s.stderr.String(), "locks the vault it serves") {
					t.Errorf("the refusal does not say what stopping the daemon does:\n%s", s.stderr.String())
				}
				if strings.Contains(s.stderr.String(), "no device passphrase was sent") {
					t.Errorf("says a device passphrase was not sent, though this device has none:\n%s", s.stderr.String())
				}
			})
		}
	}
}

// A daemon whose HOP_DEVICE_PASSPHRASE the sealing rules refuse is no better
// than one with none: hop unlock --password refuses before it asks, and
// changes nothing. At daemon start the same value locks the vault, and
// hop status says why.
func TestUnlockPasswordRefusesAnUnusableDaemonPassphrase(t *testing.T) {
	m := noKeychain(t)
	sk := localVault(t, m, "y")
	m.must(t, nil, "lock")
	m.must(t, nil, "daemon", "stop")
	bad := "x"
	m.daemonPass.Store(&bad)

	// The daemon starts with it: the vault stays locked, and says why.
	m.hop(t, &session{}, "ls") // starts the daemon, which finds the vault locked
	status := &session{}
	m.hop(t, status, "status")
	out := status.stdout.String()
	if !strings.Contains(out, "locked") || !strings.Contains(out, "unlock error:") || !strings.Contains(out, store.PassphraseEnv) {
		t.Errorf("hop status does not say why the vault is locked:\n%s", out)
	}
	var st map[string]any
	if err := json.Unmarshal([]byte(m.must(t, nil, "status", "--json")), &st); err != nil {
		t.Fatal(err)
	}
	if st["has_device_passphrase"] == true {
		t.Error("the daemon says it has a device passphrase")
	}
	started := daemonStarted(t, m)
	before := vaultFiles(t, m)

	for name, env := range map[string]map[string]string{
		"no variable":       nil,
		"variable set here": {store.PassphraseEnv: otherPass},
	} {
		t.Run(name, func(t *testing.T) {
			s := &session{tty: true, env: env, secrets: map[string]string{masterPrmpt: resolvePassword, "Secret Key (": sk}}
			if code := m.hop(t, s, "unlock", "--password"); code != 255 {
				t.Fatalf("exit %d: %s", code, s.stderr.String())
			}
			if len(s.order) != 0 {
				t.Errorf("asked before refusing: %v", s.order)
			}
			for _, want := range []string{"has no usable one", "under 8 characters", "Nothing was changed", "hop daemon stop", "unset " + store.PassphraseEnv, "later unlocks ask for the passphrase"} {
				if !strings.Contains(s.stderr.String(), want) {
					t.Errorf("stderr does not say %q:\n%s", want, s.stderr.String())
				}
			}
			if strings.Contains(s.stderr.String(), "store:") {
				t.Errorf("the store's own refusal:\n%s", s.stderr.String())
			}
			if got := daemonStarted(t, m); !got.Equal(started) {
				t.Error("the daemon was stopped")
			}
			if !maps.Equal(vaultFiles(t, m), before) {
				t.Error("the data directory changed")
			}
		})
	}
}

// The sentence the refusal ends with is true: after the steps, a later
// hop lock and hop unlock open the vault without a prompt, because the
// daemon keeps the passphrase, until hop daemon stop; after that, with the
// variable unset, hop unlock asks for the passphrase.
func TestPasswordUnlockStepsEndWithTheDaemonStoppedAndTheVariableUnset(t *testing.T) {
	m := noKeychain(t)
	sk := localVault(t, m, "y")
	m.must(t, nil, "lock")
	m.must(t, nil, "daemon", "stop")
	np := otherPass
	m.daemonPass.Store(&np)
	steps := &session{tty: true, env: map[string]string{store.PassphraseEnv: np}, secrets: map[string]string{masterPrmpt: resolvePassword, "Secret Key (": sk}}
	if code := m.hop(t, steps, "unlock", "--password"); code != 0 {
		t.Fatalf("unlock --password: exit %d: %s", code, steps.stderr.String())
	}

	// Still in the daemon's environment: no prompt, in the shell without it.
	m.must(t, nil, "lock")
	s := &session{tty: true}
	if code := m.hop(t, s, "unlock"); code != 0 || len(s.order) != 0 {
		t.Errorf("unlock while the daemon holds the passphrase: exit %d, asked %v: %s", code, s.order, s.stderr.String())
	}

	m.must(t, nil, "daemon", "stop")
	m.daemonPass.Store(nil)
	m.must(t, nil, "lock")
	s = &session{tty: true, onSecret: typesDevicePassphrase(np)}
	if code := m.hop(t, s, "unlock"); code != 0 {
		t.Fatalf("unlock after the stop: exit %d: %s", code, s.stderr.String())
	}
	asksOnce(t, s)
}

// hop auth logout checks the key file before it stops the daemon whenever
// the logout would need the key: with the passphrase in the environment, at a
// terminal or not, and whatever the answer to the question. A vault that is
// open stays open, and the daemon is not stopped.
func TestLogoutChecksTheKeyBeforeStoppingTheDaemon(t *testing.T) {
	_, m := sealedAccount(t)
	good, err := os.ReadFile(keyFileOf(m))
	if err != nil {
		t.Fatal(err)
	}
	started := daemonStarted(t, m)
	declined := func(string) string { return "n" }
	for _, tc := range []struct {
		name    string
		missing bool
		s       func() *session
		args    []string
		want    string
	}{
		{"variable, terminal, declined", true, func() *session {
			return &session{tty: true, env: map[string]string{store.PassphraseEnv: devPass}, answer: declined}
		}, []string{"auth", "logout"}, "hop auth logout --local-only"},
		{"variable, no terminal", true, func() *session {
			return &session{env: map[string]string{store.PassphraseEnv: devPass}}
		}, []string{"auth", "logout", "--yes"}, "hop auth logout --local-only"},
		{"no variable, no terminal", true, func() *session { return &session{} }, []string{"auth", "logout", "--yes"}, "hop auth logout --local-only"},
		{"no variable, terminal, declined", true, func() *session { return &session{tty: true, answer: declined} }, []string{"auth", "logout"}, "hop auth logout --local-only"},
		{"wrong variable, terminal, declined", false, func() *session {
			return &session{tty: true, env: map[string]string{store.PassphraseEnv: otherPass}, answer: declined}
		}, []string{"auth", "logout"}, "does not open"},
		{"wrong variable, no terminal", false, func() *session {
			return &session{env: map[string]string{store.PassphraseEnv: otherPass}}
		}, []string{"auth", "logout", "--yes"}, "does not open"},
		{"no variable, no terminal, key file there", false, func() *session { return &session{} },
			[]string{"auth", "logout", "--yes"}, "hop auth logout --local-only"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if tc.missing {
				if err := os.Remove(keyFileOf(m)); err != nil {
					t.Fatal(err)
				}
				defer func() {
					if err := os.WriteFile(keyFileOf(m), good, 0o600); err != nil {
						t.Fatal(err)
					}
				}()
			}
			s := tc.s()
			if code := m.hop(t, s, tc.args...); code != 255 {
				t.Fatalf("exit %d: %s", code, s.stderr.String())
			}
			if !strings.Contains(s.stderr.String(), tc.want) {
				t.Errorf("stderr does not say %q:\n%s", tc.want, s.stderr.String())
			}
			if strings.Contains(s.stderr.String(), "Log out?") || strings.Contains(s.stderr.String(), "not logged out") {
				t.Errorf("got as far as the question:\n%s", s.stderr.String())
			}
			if len(s.order) != 0 {
				t.Errorf("asked: %v", s.order)
			}
			if got := daemonStarted(t, m); !got.Equal(started) {
				t.Error("the daemon was stopped and started again")
			}
			vaultOpen(t, m)
		})
	}
}

// hop vault fork --local decrypts this device's copy with the device key,
// so a key file that is gone or damaged fails before the daemon is
// stopped. A fork that is declined leaves an open vault open, and one on a
// device key that is not sealed asks nothing it did not.
func TestForkChecksTheKeyBeforeStoppingTheDaemon(t *testing.T) {
	_, m := sealedAccount(t)
	good, err := os.ReadFile(keyFileOf(m))
	if err != nil {
		t.Fatal(err)
	}
	started := daemonStarted(t, m)
	for name, damage := range map[string]func() error{
		"missing": func() error { return os.Remove(keyFileOf(m)) },
		"damaged": func() error { return os.WriteFile(keyFileOf(m), []byte("not a key file"), 0o600) },
	} {
		t.Run(name, func(t *testing.T) {
			if err := damage(); err != nil {
				t.Fatal(err)
			}
			defer func() {
				if err := os.WriteFile(keyFileOf(m), good, 0o600); err != nil {
					t.Fatal(err)
				}
			}()
			for _, s := range []*session{
				{tty: true, env: map[string]string{store.PassphraseEnv: devPass}},
				{tty: true},
				{},
			} {
				if code := m.hop(t, s, "vault", "fork", "--local", "--yes"); code != 255 {
					t.Fatalf("exit %d: %s", code, s.stderr.String())
				}
				if !strings.Contains(s.stderr.String(), "the device key can't be read") {
					t.Errorf("stderr does not say the key can't be read:\n%s", s.stderr.String())
				}
				if len(s.order) != 0 {
					t.Errorf("asked: %v", s.order)
				}
				if got := daemonStarted(t, m); !got.Equal(started) {
					t.Error("the daemon was stopped and started again")
				}
				vaultOpen(t, m)
			}
		})
	}
}

func TestDeclinedForkLeavesTheVaultOpen(t *testing.T) {
	_, sealedM := sealedAccount(t)
	type kind struct {
		m       *machine
		secrets map[string]string
	}
	kinds := map[string]kind{"sealed file": {sealedM, map[string]string{askOldPass: devPass}}}
	for name, answer := range map[string]string{"keychain": "y", "unsealed file": "n"} {
		w := newAuthWorld(t)
		var m *machine
		if name == "keychain" {
			m = newMachine(t, w, "kc")
		} else {
			m = noKeychain(t)
			m.w = w
		}
		localVault(t, m, answer)
		m.must(t, nil, "add", "web", "--address", "203.0.113.10", "--user", "deploy")
		m.must(t, nil, "auth", "signup", "--server", w.origin, "--email", authEmail, "--code", w.invite(t))
		kinds[name] = kind{m, nil}
	}
	for name, k := range kinds {
		t.Run(name, func(t *testing.T) {
			s := &session{tty: true, secrets: k.secrets, answer: func(string) string { return "n" }}
			if code := k.m.hop(t, s, "vault", "fork", "--local"); code != 255 {
				t.Fatalf("exit %d: %s", code, s.stderr.String())
			}
			if !strings.Contains(s.stderr.String(), "not forked; nothing changed") {
				t.Errorf("stderr does not say nothing changed:\n%s", s.stderr.String())
			}
			if name != "sealed file" && devicePassphrasePrompts(s) != 0 {
				t.Errorf("a vault whose key is not sealed was asked for a device passphrase: %v", s.order)
			}
			for _, p := range s.order {
				if name != "sealed file" && !strings.HasPrefix(p, "Fork this vault") {
					t.Errorf("a vault whose key is not sealed gained a prompt: %q", p)
				}
			}
			if name == "sealed file" {
				asksOnce(t, s)
			}
			vaultOpen(t, k.m)
			if rec, err := store.ForkRecord(k.m.data); err != nil || rec != nil {
				t.Errorf("a fork record exists after a declined fork: %v %v", rec, err)
			}
		})
	}
}

// A logout recorded as RETIRED and cut short before its cleanup is finished
// by running it again, and that needs no key: the check of the key file
// before a logout must not stand in its way, with no passphrase at hand and
// no terminal to ask on. While the logout is only RETIRING it still needs
// the key, and the check stays.
func TestRetiredLogoutFinishesWithoutTheDevicePassphrase(t *testing.T) {
	for _, tc := range []struct {
		state    string
		wantCode int
		want     string
	}{
		{store.StateRetired, 0, "An interrupted logout is finished"},
		{store.StateRetiring, 255, "hop auth logout --local-only"},
	} {
		t.Run(tc.state, func(t *testing.T) {
			_, m := sealedAccount(t)
			id := m.authStatus(t).DeviceID
			m.must(t, nil, "daemon", "stop")
			b, err := canonjson.Marshal(map[string]any{
				"v": 1, "state": tc.state, "account_id": id, "vault_id": id, "device_id": id,
				"outcome": store.OutcomeCommitted, "candidates": []any{}, "wires": []any{},
				"key_store": store.DeviceStoreFile, "records": []any{},
			})
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(m.data, "vault", "retire.json"), b, 0o600); err != nil {
				t.Fatal(err)
			}
			if got := store.RetiredDir(m.data); got != (tc.state == store.StateRetired) {
				t.Fatalf("RetiredDir = %v", got)
			}
			s := &session{}
			if code := m.hop(t, s, "auth", "logout", "--yes"); code != tc.wantCode {
				t.Fatalf("logout: exit %d, want %d: %s %s", code, tc.wantCode, s.stdout.String(), s.stderr.String())
			}
			if out := s.stdout.String() + s.stderr.String(); !strings.Contains(out, tc.want) {
				t.Errorf("logout said %q, want %q", out, tc.want)
			}
			if tc.state == store.StateRetired {
				if ok, _ := store.Exists(m.data); ok {
					t.Error("the vault is still there")
				}
			} else if _, err := os.Stat(keyFileOf(m)); err != nil {
				t.Errorf("the refused logout changed the key file: %v", err)
			}
		})
	}
}
