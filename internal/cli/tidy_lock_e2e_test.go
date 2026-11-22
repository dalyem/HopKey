package cli_test

import (
	"context"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/dalyem/hopkey/internal/cli"
	"github.com/dalyem/hopkey/internal/daemon"
)

// signedInAccount publishes m's vault, with a host, to w.
func signedInAccount(t *testing.T, w *authWorld, m *machine) {
	t.Helper()
	m.must(t, nil, "add", "web", "--address", "203.0.113.10", "--user", "deploy")
	m.must(t, nil, "auth", "signup", "--server", w.origin, "--email", authEmail, "--code", w.invite(t))
}

// A fork needs the device key to read this device's copy. Where the key
// is a keychain entry or an unsealed file that is gone, it fails before the
// daemon is stopped: stopped, the daemon would come back unable to open the
// vault, and an open vault would be locked.
func TestForkWithAnUnreadableDeviceKeyLeavesTheVaultOpen(t *testing.T) {
	for _, kind := range []string{"keychain", "unsealed file"} {
		t.Run(kind, func(t *testing.T) {
			w := newAuthWorld(t)
			var m *machine
			if kind == "keychain" {
				m = newMachine(t, w, "kc")
				if code := m.hop(t, &session{secrets: initSecrets()}, "init"); code != 0 {
					t.Fatal("init")
				}
			} else {
				m = noKeychain(t)
				m.w = w
				localVault(t, m, "n")
			}
			signedInAccount(t, w, m)
			started := daemonStarted(t, m)
			if kind == "keychain" {
				m.ring.mu.Lock()
				clear(m.ring.m)
				m.ring.mu.Unlock()
			} else if err := os.Remove(keyFileOf(m)); err != nil {
				t.Fatal(err)
			}
			s := &session{tty: true}
			if code := m.hop(t, s, "vault", "fork", "--local", "--yes"); code != 255 {
				t.Fatalf("exit %d: %s", code, s.stderr.String())
			}
			if !strings.Contains(s.stderr.String(), "the device key can't be read") {
				t.Errorf("stderr: %s", s.stderr.String())
			}
			if got := daemonStarted(t, m); !got.Equal(started) {
				t.Error("the daemon was stopped and started again")
			}
			vaultOpen(t, m)
		})
	}
}

// A wrong passphrase typed at the fork's own prompt is asked for again, up
// to three times, before the daemon is stopped, as every command that opens
// the vault itself does; failing, it leaves the open vault open.
func TestForkWithAWrongDevicePassphraseLeavesTheVaultOpen(t *testing.T) {
	_, m := sealedAccount(t)
	started := daemonStarted(t, m)
	s := &session{tty: true, secrets: map[string]string{askOldPass: "not the device passphrase"}}
	if code := m.hop(t, s, "vault", "fork", "--local", "--yes"); code != 255 {
		t.Fatalf("exit %d: %s", code, s.stderr.String())
	}
	if n := devicePassphrasePrompts(s); n != 3 || len(s.order) != 3 {
		t.Errorf("prompts: %v", s.order)
	}
	if got := daemonStarted(t, m); !got.Equal(started) {
		t.Error("the daemon was stopped and started again")
	}
	vaultOpen(t, m)
}

// hop passwd on a locked vault that nothing here can open says so before it
// asks for the three passwords, not after.
func TestPasswdOnALockedVaultWithNoPassphraseRefusesBeforeAsking(t *testing.T) {
	m := newMachine(t, &authWorld{}, "kc")
	if code := m.hop(t, &session{secrets: initSecrets()}, "init"); code != 0 {
		t.Fatal("init")
	}
	m.must(t, nil, "lock")
	s := &session{tty: true, secrets: map[string]string{
		"Current master password: ": resolvePassword, "New master password: ": newPassword, "Repeat it: ": newPassword}}
	if code := m.hop(t, s, "passwd"); code != 255 {
		t.Fatalf("exit %d: %s", code, s.stderr.String())
	}
	if len(s.order) != 0 {
		t.Errorf("asked before refusing: %v", s.order)
	}
	if !strings.Contains(s.stderr.String(), "the vault is locked") || !strings.Contains(s.stderr.String(), "hop unlock") {
		t.Errorf("stderr: %s", s.stderr.String())
	}
}

// Against the daemon of another vault, hop passwd refuses before it asks
// for the device passphrase, not after.
func TestPasswdAgainstAnotherVaultsDaemonRefusesBeforeAsking(t *testing.T) {
	_, a := sealedAccount(t)
	b := noKeychain(t)
	b.paths, b.home = a.paths, a.home // the same sockets, a data directory of its own
	i := &session{tty: true, secrets: initSecrets(), onSecret: typedTwice(otherPass), answer: func(string) string { return "y" }}
	if code := b.hop(t, i, "init"); code != 0 {
		t.Fatalf("init: exit %d: %s", code, i.stderr.String())
	}
	s := &session{tty: true, secrets: map[string]string{askOldPass: otherPass}}
	if code := b.hop(t, s, "passwd"); code != 255 {
		t.Fatalf("exit %d: %s", code, s.stderr.String())
	}
	if len(s.order) != 0 {
		t.Errorf("asked before refusing: %v", s.order)
	}
	for _, want := range []string{a.data, b.data, "hop daemon stop"} {
		if !strings.Contains(s.stderr.String(), want) {
			t.Errorf("stderr lacks %q:\n%s", want, s.stderr.String())
		}
	}
	vaultOpen(t, a)
}

// hop passwd leaves the vault locked or open as it found it, for a local
// vault and a signed-in one, whether or not the device key opens by itself.
func TestPasswdKeepsTheLockStateItFound(t *testing.T) {
	t.Run("local, sealed, locked", func(t *testing.T) {
		m := sealedLocal(t)
		m.must(t, nil, "lock")
		s := &session{tty: true, secrets: map[string]string{
			askOldPass: devPass, "Current master password: ": resolvePassword, "New master password: ": newPassword, "Repeat it: ": newPassword}}
		if code := m.hop(t, s, "passwd"); code != 0 {
			t.Fatalf("exit %d: %s", code, s.stderr.String())
		}
		if a := m.authStatus(t); !a.Locked {
			t.Error("the vault was locked before hop passwd and is open after it")
		}
	})
	t.Run("signed in, keychain, locked", func(t *testing.T) {
		w := newAuthWorld(t)
		m := signedInMachine(t, w, "kc")
		m.must(t, nil, "lock")
		s := &session{tty: true, env: map[string]string{"HOP_PASSWORD": resolvePassword, "HOP_NEW_PASSWORD": newPassword}}
		if code := m.hop(t, s, "passwd"); code != 0 {
			t.Fatalf("exit %d: %s", code, s.stderr.String())
		}
		if a := m.authStatus(t); !a.Locked {
			t.Error("the vault was locked before hop passwd and is open after it")
		}
	})
	t.Run("signed in, keychain, open", func(t *testing.T) {
		w := newAuthWorld(t)
		m := signedInMachine(t, w, "kc")
		s := &session{tty: true, env: map[string]string{"HOP_PASSWORD": resolvePassword, "HOP_NEW_PASSWORD": newPassword}}
		if code := m.hop(t, s, "passwd"); code != 0 {
			t.Fatalf("exit %d: %s", code, s.stderr.String())
		}
		if a := m.authStatus(t); a.Locked {
			t.Error("the vault was open before hop passwd and is locked after it")
		}
	})
}

// A device whose revocation is proven and wiped has nothing left for hop
// auth logout to wipe: hop unlock says what is true, not that.
func TestUnlockOfAWipedRevokedDeviceDoesNotSuggestWiping(t *testing.T) {
	f := newFakeDaemon(t)
	f.fail(daemon.OpUnlock, daemon.CodeRevoked, "this device was revoked from the account")
	f.reply(daemon.OpStatus, daemon.StatusResult{
		Version: "test", PID: 1, StartedAt: f.now,
		Sync: &daemon.SyncStatusResult{State: daemon.SyncRevoked, ServerRetirement: &daemon.ServerRetirement{How: "revoked", Seq: 9, Wiped: true}},
	})
	code, _, errOut := f.hop(t, "unlock")
	if code == 0 {
		t.Fatal("unlock of a revoked device exited 0")
	}
	if strings.Contains(errOut, "logout wipes this device") || !strings.Contains(errOut, "already wiped") || !strings.Contains(errOut, "hop auth login") {
		t.Errorf("stderr: %s", errOut)
	}
}

// hop unlock --password on an unlocked vault would re-key it and leave the
// old key as a stale device, each time. It asks nothing and changes nothing.
func TestUnlockPasswordOnAnUnlockedVaultRefuses(t *testing.T) {
	m := newMachine(t, &authWorld{}, "kc")
	i := &session{secrets: initSecrets()}
	if code := m.hop(t, i, "init"); code != 0 {
		t.Fatal("init")
	}
	sk, _ := kitKeys(t, i.stdout.String())
	s := &session{tty: true, secrets: map[string]string{masterPrmpt: resolvePassword, "Secret Key (": sk}}
	if code := m.hop(t, s, "unlock", "--password"); code != 255 {
		t.Fatalf("exit %d: %s", code, s.stderr.String())
	}
	if len(s.order) != 0 {
		t.Errorf("asked: %v", s.order)
	}
	if !strings.Contains(s.stderr.String(), "already unlocked") || strings.Contains(s.stdout.String(), "new device key") {
		t.Errorf("stdout %q, stderr %q", s.stdout.String(), s.stderr.String())
	}
	if m.authStatus(t).Locked {
		t.Error("the vault was locked")
	}
}

// The steps hop unlock --password names for a sealed key file start a daemon
// that is not the login service's, which stays inactive: when hop installed
// a service, the refusal says to run hop setup --service afterwards.
func TestUnlockPasswordStepsMentionTheLoginService(t *testing.T) {
	m := noKeychain(t)
	m.exe, m.goos = "/usr/local/bin/hop", "linux"
	i := &session{tty: true, secrets: initSecrets(), onSecret: typedTwice(devPass), answer: func(string) string { return "y" }}
	if code := m.hop(t, i, "init"); code != 0 {
		t.Fatalf("init: exit %d: %s", code, i.stderr.String())
	}
	sk, _ := kitKeys(t, i.stdout.String())
	m.must(t, nil, "lock")
	secrets := map[string]string{masterPrmpt: resolvePassword, "Secret Key (": sk}
	ask := func() string {
		s := &session{tty: true, secrets: secrets}
		if code := m.hop(t, s, "unlock", "--password"); code != 255 {
			t.Fatalf("exit %d: %s", code, s.stderr.String())
		}
		return s.stderr.String()
	}
	if out := ask(); strings.Contains(out, "hop setup --service") {
		t.Errorf("a hint about a service that was never installed:\n%s", out)
	}
	unit := filepath.Join(m.home, ".config", "systemd", "user", "hopkey.service")
	if err := os.MkdirAll(filepath.Dir(unit), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(unit, []byte("# Written by hop setup --service: it runs the hop daemon from login\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if out := ask(); !strings.Contains(out, "hop daemon stop and then hop setup --service") {
		t.Errorf("no hint to run hop setup --service again:\n%s", out)
	}
}

// hop unlock gives three tries at the device passphrase, as the commands that
// open the vault themselves do.
func TestUnlockGivesThreeTriesAtTheDevicePassphrase(t *testing.T) {
	x := newSealedDaemon(t)
	x.typed = []string{"wrong one", "wrong two"}
	code, out, errOut := x.hop(t, nil, true, "unlock")
	if code != 0 || !strings.Contains(out, "vault unlocked") {
		t.Fatalf("unlock after two wrong tries: exit %d, %q %q", code, out, errOut)
	}
	if len(x.prompts) != 3 {
		t.Errorf("prompts: %q", x.prompts)
	}
	if x.locked(t) {
		t.Error("still locked")
	}

	x = newSealedDaemon(t)
	x.typed = []string{"wrong one", "wrong two", "wrong three", unlockPassphrase}
	code, out, errOut = x.hop(t, nil, true, "unlock")
	if code == 0 || strings.Contains(out, "vault unlocked") {
		t.Fatalf("unlock after three wrong tries: exit %d, %q %q", code, out, errOut)
	}
	if len(x.prompts) != 3 {
		t.Errorf("prompts: %q", x.prompts)
	}
	if !x.locked(t) {
		t.Error("unlocked with a wrong passphrase")
	}
}

// A device that was logged out of locally has no vault: hop ls says so in
// plain words, not with the daemon's own failure.
func TestLsAfterALocalOnlyLogoutSaysThereIsNoVault(t *testing.T) {
	w := newAuthWorld(t)
	m := signedInMachine(t, w, "kc")
	m.must(t, nil, "auth", "logout", "--local-only", "--yes")
	s := &session{}
	if code := m.hop(t, s, "ls"); code == 0 {
		t.Fatal("hop ls with no vault exited 0")
	}
	msg := s.stderr.String()
	if !strings.Contains(msg, "there is no vault on this device") || !strings.Contains(msg, "hop init") || strings.Contains(msg, "starting the hop daemon") {
		t.Errorf("hop ls says: %s", msg)
	}
}

// A server URL that is not the origin a publication started with is named
// as an origin mismatch with both values, not as a problem of the account.
func TestSignupToAnotherOriginNamesTheMismatch(t *testing.T) {
	w1, w2 := newAuthWorld(t), newAuthWorld(t)
	m := newMachine(t, w1, "kc")
	if code := m.hop(t, &session{secrets: initSecrets()}, "init"); code != 0 {
		t.Fatal("init")
	}
	refuse := func(rw http.ResponseWriter, r *http.Request) bool {
		if r.URL.Path != "/v1/signup" {
			return false
		}
		http.Error(rw, "down", http.StatusInternalServerError)
		return true
	}
	w1.hook.Store(&refuse)
	if code := m.hop(t, &session{}, "auth", "signup", "--server", w1.origin, "--email", authEmail, "--code", w1.invite(t)); code == 0 {
		t.Fatal("signup succeeded against a server that refuses it")
	}
	w1.hook.Store(nil)
	m.w = w2
	s := &session{}
	if code := m.hop(t, s, "auth", "signup", "--server", w2.origin, "--email", authEmail, "--code", w2.invite(t)); code == 0 {
		t.Fatal("signup to another origin succeeded")
	}
	msg := s.stderr.String()
	for _, want := range []string{"origin mismatch", w1.origin, w2.origin, "not about the account"} {
		if !strings.Contains(msg, want) {
			t.Errorf("stderr lacks %q:\n%s", want, msg)
		}
	}
}

// hop init refuses a data directory that safepath will refuse before it asks
// for any secret or shows a kit that no vault will ever hold; under WSL it
// says to use the Linux home directory.
func TestInitOnAnUnsafePathRefusesBeforeAnySecret(t *testing.T) {
	for _, tc := range []struct {
		name string
		env  map[string]string
		want string
	}{
		{"plain", nil, "writable by group or others"},
		{"WSL", map[string]string{"WSL_DISTRO_NAME": "Ubuntu"}, "Linux home directory"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := newMachine(t, &authWorld{}, "kc")
			bad := shortTemp(t)
			if err := os.Chmod(bad, 0o777); err != nil {
				t.Fatal(err)
			}
			m.data = filepath.Join(bad, "data")
			s := &session{tty: true, env: tc.env, secrets: initSecrets()}
			if code := m.hop(t, s, "init"); code != 255 {
				t.Fatalf("exit %d: %s", code, s.stderr.String())
			}
			if len(s.order) != 0 {
				t.Errorf("asked before refusing: %v", s.order)
			}
			if strings.Contains(s.stdout.String(), "Secret Key") || strings.Contains(s.stderr.String(), "Generating keys") {
				t.Errorf("a kit or key generation before the refusal:\n%s\n%s", s.stdout.String(), s.stderr.String())
			}
			if !strings.Contains(s.stderr.String(), tc.want) {
				t.Errorf("stderr lacks %q:\n%s", tc.want, s.stderr.String())
			}
			if _, err := os.Lstat(m.data); !errors.Is(err, os.ErrNotExist) {
				t.Errorf("the refusal left a data directory behind: %v", err)
			}
		})
	}
}

// Ctrl-C at a prompt of a command that holds the vault leaves the vault as
// it found it: an open one open, with the device passphrase typed for the
// command, and a locked one locked, even where the device key opens by
// itself. The command cannot return from the prompt, so the process is
// abandoned and the vault freed for the daemon.
func TestInterruptAtAPromptRestoresTheLockState(t *testing.T) {
	interrupted := interruptAtPrompt
	t.Run("open, sealed device key", func(t *testing.T) {
		_, m := sealedAccount(t)
		interrupted(t, m, &session{env: map[string]string{"HOP_PASSWORD": resolvePassword}, secrets: map[string]string{askOldPass: devPass}}, "auth", "rotate")
		vaultOpen(t, m)
	})
	t.Run("locked, keychain device key", func(t *testing.T) {
		w := newAuthWorld(t)
		m := signedInMachine(t, w, "kc")
		m.must(t, nil, "lock")
		interrupted(t, m, &session{env: map[string]string{"HOP_PASSWORD": resolvePassword}}, "auth", "rotate")
		if a := m.authStatus(t); !a.Locked {
			t.Error("the vault was locked before the interrupted command and is open after it")
		}
	})
}

// interruptAtPrompt runs hop args on m in session s, on a terminal, and
// sends it Ctrl-C at its first line prompt, which then never returns while
// the test runs: the process is abandoned, and the test waits for its exit.
func interruptAtPrompt(t *testing.T, m *machine, s *session, args ...string) {
	t.Helper()
	ictx, interrupt := context.WithCancelCause(context.Background())
	exited := make(chan int, 1)
	release := make(chan struct{})
	s.tty, s.ctx, s.grace = true, ictx, 50*time.Millisecond
	s.exit = func(code int) { exited <- code }
	s.answer = func(string) string {
		interrupt(cli.ErrInterrupted) // Ctrl-C, while the prompt waits
		<-release
		return ""
	}
	done := make(chan int, 1)
	go func() { done <- m.hop(t, s, args...) }()
	select {
	case code := <-exited:
		if code != cli.ExitInterrupted {
			t.Errorf("exit %d, want %d", code, cli.ExitInterrupted)
		}
	case <-time.After(60 * time.Second):
		t.Fatal("the interrupted command did not give the vault up")
	}
	t.Cleanup(func() { close(release); <-done })
}
