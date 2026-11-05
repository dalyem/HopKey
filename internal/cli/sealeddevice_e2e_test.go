package cli_test

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/dalyem/hopkey/internal/daemon"
	"github.com/dalyem/hopkey/internal/store"
)

// A machine whose device key is a sealed file, with no HOP_DEVICE_PASSPHRASE
// exported, is the normal state on WSL and on a headless server. These run
// hop through cli.Run on such a machine: every ordinary command works at a
// terminal by typing the device passphrase when asked, and the passphrase
// only goes to the daemon of this vault.

const (
	otherPass   = "an-other-device-pass-4"
	newPassword = "a brand new master password"
)

// sealedAccount is a signed-in machine with no keychain whose device key
// file is sealed with devPass, with a host, and the vault open in its
// daemon: what hop init and hop auth signup leave there.
func sealedAccount(t *testing.T) (*authWorld, *machine) {
	t.Helper()
	w := newAuthWorld(t)
	m := noKeychain(t)
	m.w = w
	i := &session{tty: true, secrets: initSecrets(), onSecret: typedTwice(devPass), answer: func(string) string { return "y" }}
	if code := m.hop(t, i, "init"); code != 0 {
		t.Fatalf("init: exit %d: %s", code, i.stderr.String())
	}
	m.must(t, nil, "add", "web", "--address", "203.0.113.10", "--user", "deploy")
	s := &session{tty: true, secrets: map[string]string{askOldPass: devPass}}
	if code := m.hop(t, s, "auth", "signup", "--server", w.origin, "--email", authEmail, "--code", w.invite(t)); code != 0 {
		t.Fatalf("signup: exit %d: %s", code, s.stderr.String())
	}
	if a := m.authStatus(t); !a.SignedIn || a.Locked {
		t.Fatalf("after signup: %+v", a)
	}
	return w, m
}

// sealedLocal is a machine with no keychain and a local-only vault whose
// key file is sealed with devPass.
func sealedLocal(t *testing.T) *machine {
	t.Helper()
	m := noKeychain(t)
	i := &session{tty: true, secrets: initSecrets(), onSecret: typedTwice(devPass), answer: func(string) string { return "y" }}
	if code := m.hop(t, i, "init"); code != 0 {
		t.Fatalf("init: exit %d: %s", code, i.stderr.String())
	}
	return m
}

// vaultOpen fails the test unless the vault is open in the daemon and
// still has its host.
func vaultOpen(t *testing.T, m *machine) {
	t.Helper()
	if a := m.authStatus(t); a.Locked {
		t.Errorf("the vault is locked: %+v", a)
		return
	}
	if _, ok := m.hosts(t)["web"]; !ok {
		t.Error("the open vault has no host web")
	}
}

// daemonStarted is when the running daemon started.
func daemonStarted(t *testing.T, m *machine) time.Time {
	t.Helper()
	var st struct {
		StartedAt time.Time `json:"started_at"`
	}
	decodeJSON(t, m.must(t, nil, "status", "--json"), &st)
	return st.StartedAt
}

// devicePassphrasePrompts is how often s asked for the device passphrase.
func devicePassphrasePrompts(s *session) int {
	s.orderMu.Lock()
	defer s.orderMu.Unlock()
	n := 0
	for _, p := range s.order {
		if strings.HasPrefix(p, askOldPass) {
			n++
		}
	}
	return n
}

// asksOnce checks that s asked for the device passphrase exactly once, and
// before anything else.
func asksOnce(t *testing.T, s *session) {
	t.Helper()
	s.orderMu.Lock()
	first := ""
	if len(s.order) > 0 {
		first = s.order[0]
	}
	s.orderMu.Unlock()
	if n := devicePassphrasePrompts(s); n != 1 || !strings.HasPrefix(first, askOldPass) {
		t.Errorf("want the device passphrase asked once and first, got %d times in %v", n, s.order)
	}
}

// typesDevicePassphrase answers the device passphrase prompt with pass.
func typesDevicePassphrase(pass string) func(string) (string, bool) {
	return func(p string) (string, bool) {
		if strings.HasPrefix(p, askOldPass) {
			return pass, true
		}
		return "", false
	}
}

// noSealedComplaint checks that nothing said the key file is sealed, or
// told the user to set the variable.
func noSealedComplaint(t *testing.T, s *session) {
	t.Helper()
	for _, out := range []string{s.stderr.String(), s.stdout.String()} {
		if strings.Contains(out, store.PassphraseEnv) || strings.Contains(out, "sealed") {
			t.Errorf("asked a terminal user for the variable: %q", out)
		}
	}
}

// Each command that opens the vault itself asks for the device passphrase
// once, before anything else, works with no variable exported, and leaves
// the vault open in the daemon.
func TestSealedDeviceCommandsAskOnceAtATerminal(t *testing.T) {
	_, m := sealedAccount(t)
	env := map[string]string{"HOP_PASSWORD": resolvePassword}
	cases := []struct {
		name   string
		args   []string
		env    map[string]string
		code   int
		stdout string
	}{
		{"auth resume", []string{"auth", "resume"}, nil, 0, "Nothing is pending"},
		{"auth merge", []string{"auth", "merge"}, nil, 0, "No login merge is in progress"},
		{"auth approve", []string{"auth", "approve"}, nil, 0, "No approval is in progress"},
		{"auth rotate", []string{"auth", "rotate"}, env, 0, "Your new Emergency Kit"},
		{"auth devices revoke", []string{"auth", "devices", "revoke", "no-such-device"}, env, 255, ""},
		{"auth passwd", []string{"auth", "passwd"}, map[string]string{"HOP_PASSWORD": resolvePassword, "HOP_NEW_PASSWORD": newPassword}, 0, "Your new Emergency Kit"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := &session{tty: true, env: tc.env, secrets: map[string]string{askOldPass: devPass}, answer: func(p string) string {
				if strings.HasSuffix(p, "[y/N] ") {
					return "y"
				}
				return ""
			}}
			if code := m.hop(t, s, tc.args...); code != tc.code {
				t.Fatalf("exit %d, want %d: %s", code, tc.code, s.stderr.String())
			}
			asksOnce(t, s)
			noSealedComplaint(t, s)
			if !strings.Contains(s.stdout.String(), tc.stdout) {
				t.Errorf("stdout does not say %q:\n%s", tc.stdout, s.stdout.String())
			}
			notInEnvironment(t, s)
			vaultOpen(t, m)
		})
	}
	// The key changes left a file the same passphrase still opens: lock,
	// and unlock with it.
	m.must(t, nil, "lock")
	u := &session{tty: true, secrets: map[string]string{askOldPass: devPass}}
	if code := m.hop(t, u, "unlock"); code != 0 {
		t.Fatalf("unlock with the passphrase after the changes: exit %d: %s", code, u.stderr.String())
	}
	vaultOpen(t, m)
}

// A wrong passphrase is asked for again, three times in all, before
// anything changes: the daemon is not stopped, an open vault stays open,
// and no other secret is asked for. A right one on the third try goes on.
func TestSealedDeviceWrongPassphraseChangesNothing(t *testing.T) {
	_, m := sealedAccount(t)
	started := daemonStarted(t, m)
	s := &session{tty: true, env: map[string]string{"HOP_PASSWORD": resolvePassword}, onSecret: typesDevicePassphrase("a wrong passphrase")}
	if code := m.hop(t, s, "auth", "rotate"); code != 255 {
		t.Fatalf("rotate with a wrong passphrase: exit %d", code)
	}
	if n := devicePassphrasePrompts(s); n != 3 || len(s.order) != 3 {
		t.Errorf("want three device passphrase prompts and nothing else, got %v", s.order)
	}
	if n := strings.Count(s.stderr.String(), "Try again."); n != 2 {
		t.Errorf("asked again %d times, want 2:\n%s", n, s.stderr.String())
	}
	if !strings.Contains(s.stderr.String(), "nothing was changed") {
		t.Errorf("the failure does not say nothing changed:\n%s", s.stderr.String())
	}
	if got := daemonStarted(t, m); !got.Equal(started) {
		t.Error("the daemon was stopped and started again")
	}
	vaultOpen(t, m)

	var tries int
	s = &session{tty: true, onSecret: func(p string) (string, bool) {
		if !strings.HasPrefix(p, askOldPass) {
			return "", false
		}
		tries++
		if tries < 3 {
			return "still the wrong passphrase", true
		}
		return devPass, true
	}}
	if code := m.hop(t, s, "auth", "resume"); code != 0 {
		t.Fatalf("resume, right on the third try: exit %d: %s", code, s.stderr.String())
	}
	vaultOpen(t, m)
}

// A command that fails after the prompt still leaves an open vault open:
// the daemon it stopped comes back with the vault unlocked.
func TestSealedDeviceFailingCommandLeavesTheVaultOpen(t *testing.T) {
	_, m := sealedAccount(t)
	started := daemonStarted(t, m)
	s := &session{tty: true, env: map[string]string{"HOP_PASSWORD": resolvePassword}, secrets: map[string]string{askOldPass: devPass}}
	if code := m.hop(t, s, "auth", "devices", "revoke", "no-such-device"); code != 255 {
		t.Fatalf("revoking a device that is not there: exit %d", code)
	}
	if got := daemonStarted(t, m); got.Equal(started) {
		t.Error("the daemon was never stopped, so this does not test the failure path")
	}
	vaultOpen(t, m)

	// A vault that was locked before stays locked.
	m.must(t, nil, "lock")
	s = &session{tty: true, env: map[string]string{"HOP_PASSWORD": resolvePassword}, secrets: map[string]string{askOldPass: devPass}}
	if code := m.hop(t, s, "auth", "devices", "revoke", "no-such-device"); code != 255 {
		t.Fatalf("revoking a device that is not there, locked: exit %d", code)
	}
	if a := m.authStatus(t); !a.Locked {
		t.Errorf("a command opened a vault that hop lock had locked: %+v", a)
	}
}

// With --json, with no terminal, or with a variable that does not open the
// key file, nothing is asked: the command fails before the daemon stops,
// in one sentence that names the variable, and the vault stays open.
func TestSealedDeviceNeverAsksWithoutATerminal(t *testing.T) {
	_, m := sealedAccount(t)
	started := daemonStarted(t, m)
	cases := []struct {
		name string
		s    *session
		args []string
		want string
	}{
		{"json at a terminal", &session{tty: true, secrets: map[string]string{askOldPass: devPass}}, []string{"auth", "rotate", "--json"}, store.PassphraseEnv},
		{"no terminal", &session{}, []string{"auth", "devices", "revoke", "x"}, store.PassphraseEnv},
		{"no terminal, approve", &session{}, []string{"auth", "approve"}, store.PassphraseEnv},
		{"a variable that does not open it", &session{env: map[string]string{store.PassphraseEnv: "not the device passphrase"}},
			[]string{"auth", "resume"}, "does not open"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if code := m.hop(t, tc.s, tc.args...); code != 255 {
				t.Fatalf("exit %d: %s", code, tc.s.stderr.String())
			}
			if len(tc.s.order) != 0 {
				t.Errorf("asked: %v", tc.s.order)
			}
			if !strings.Contains(tc.s.stderr.String(), tc.want) {
				t.Errorf("stderr does not say %q:\n%s", tc.want, tc.s.stderr.String())
			}
			if strings.Contains(tc.s.stderr.String(), "run hop unlock") {
				t.Errorf("sends a person without a terminal to hop unlock, which cannot help here:\n%s", tc.s.stderr.String())
			}
			if got := daemonStarted(t, m); !got.Equal(started) {
				t.Error("the daemon was stopped")
			}
			vaultOpen(t, m)
		})
	}
	// The sentence is one line, and says what to do.
	s := &session{}
	m.hop(t, s, "auth", "resume")
	if msg := strings.TrimSpace(s.stderr.String()); strings.Count(msg, "\n") != 0 || strings.Count(msg, store.PassphraseEnv) != 1 {
		t.Errorf("want one sentence naming %s once, got %q", store.PassphraseEnv, msg)
	}
}

// hop passwd on a local vault goes through the daemon, which has no device
// passphrase: the one typed rides on the request, saves the key file
// sealed again, and is not kept.
func TestPasswdOnASealedDeviceNeedsNoVariable(t *testing.T) {
	m := sealedLocal(t)
	secrets := map[string]string{
		askOldPass: devPass, "Current master password: ": resolvePassword,
		"New master password: ": newPassword, "Repeat it: ": newPassword,
	}
	s := &session{tty: true, secrets: secrets, wrongTypeBack: true}
	if code := m.hop(t, s, "passwd"); code != 255 {
		t.Fatalf("passwd with a wrong type-back: exit %d: %s", code, s.stderr.String())
	}
	asksOnce(t, s)
	if !strings.Contains(s.stderr.String(), "run hop passwd again to see the kit") {
		t.Errorf("stderr: %s", s.stderr.String())
	}
	// The change is committed and its kit pending. Confirming it saves the
	// kit's Secret Key in the key file, which needs the passphrase too.
	s = &session{tty: true, secrets: secrets}
	if code := m.hop(t, s, "passwd"); code != 0 {
		t.Fatalf("passwd, confirming the pending kit: exit %d: %s", code, s.stderr.String())
	}
	asksOnce(t, s)
	if !strings.Contains(s.stdout.String(), "Emergency Kit confirmed") {
		t.Errorf("stdout: %s", s.stdout.String())
	}
	notInEnvironment(t, s)
	// And a second change in one go.
	secrets["Current master password: "], secrets["New master password: "], secrets["Repeat it: "] = newPassword, resolvePassword, resolvePassword
	s = &session{tty: true, secrets: secrets}
	if code := m.hop(t, s, "passwd"); code != 0 {
		t.Fatalf("passwd: exit %d: %s", code, s.stderr.String())
	}
	asksOnce(t, s)
	noSealedComplaint(t, s)
	if a := m.authStatus(t); a.Locked || !strings.Contains(a.DeviceKeyStore, "sealed") {
		t.Errorf("after passwd: %+v", a)
	}
	// The file is still sealed with the same passphrase, and opens.
	m.must(t, nil, "lock")
	u := &session{tty: true, secrets: map[string]string{askOldPass: devPass}}
	if code := m.hop(t, u, "unlock"); code != 0 {
		t.Fatalf("unlock with the passphrase after passwd: exit %d: %s", code, u.stderr.String())
	}
	if m.authStatus(t).Locked {
		t.Error("still locked")
	}
}

// hop passwd with a wrong passphrase asks again, then fails before any
// password is asked and before the daemon is touched.
func TestPasswdOnASealedDeviceWrongPassphrase(t *testing.T) {
	m := sealedLocal(t)
	s := &session{tty: true, onSecret: typesDevicePassphrase("a wrong passphrase")}
	if code := m.hop(t, s, "passwd"); code != 255 {
		t.Fatalf("exit %d", code)
	}
	if n := devicePassphrasePrompts(s); n != 3 || len(s.order) != 3 {
		t.Errorf("prompts: %v", s.order)
	}
	if m.authStatus(t).Locked {
		t.Error("the vault was locked")
	}
}

// The device passphrase of a hand-off goes only to a daemon that says it
// serves this data directory. The control socket does not depend on the
// data directory, so another vault's daemon, even an unlocked one, is
// what a command can reach: it gets nothing, and the command says so.
func TestHandOffGoesOnlyToTheDaemonOfThisVault(t *testing.T) {
	_, a := sealedAccount(t)
	b := newMachine(t, &authWorld{}, "other")
	b.paths, b.home = a.paths, a.home // the same sockets, a data directory of its own
	b.ring.broken.Store(true)
	s := &session{tty: true, secrets: initSecrets(), onSecret: typedTwice(otherPass), answer: func(string) string { return "y" }}
	if code := b.hop(t, s, "init"); code != 0 {
		t.Fatalf("init: exit %d: %s", code, s.stderr.String())
	}
	if !sealed(t, b) {
		t.Fatal("the new vault is not sealed")
	}
	for _, want := range []string{"device passphrase was not sent", a.data, "hop daemon stop"} {
		if !strings.Contains(s.stderr.String(), want) {
			t.Errorf("the warning does not say %q:\n%s", want, s.stderr.String())
		}
	}
	// The other vault's daemon is as it was.
	vaultOpen(t, a)
	// Stopping it, the new vault opens with its own passphrase.
	a.must(t, nil, "daemon", "stop")
	u := &session{tty: true, secrets: map[string]string{askOldPass: otherPass}}
	if code := b.hop(t, u, "unlock"); code != 0 {
		t.Fatalf("unlock of the new vault: exit %d: %s", code, u.stderr.String())
	}
	if b.authStatus(t).Locked {
		t.Error("the new vault is locked")
	}
}

// What a daemon of another vault, or one too old to say which vault it
// serves, is sent: nothing. It is checked on what the daemon received.
func TestNoSecretReachesADaemonOfAnotherVault(t *testing.T) {
	statuses := map[string]map[string]any{
		"another vault":  {"version": "test", "data_dir": "/somewhere/else/hop", "vault": map[string]any{"locked": true}},
		"too old to say": {"version": "test", "vault": map[string]any{"locked": true}},
	}
	for name, st := range statuses {
		t.Run(name, func(t *testing.T) {
			f := newFakeDaemon(t)
			f.reply(daemon.OpStatus, st)
			f.fail(daemon.OpUnlock, daemon.CodeInternal, "the key file is sealed and this daemon has no passphrase")
			f.reply(daemon.OpPasswd, daemon.KitResult{})
			f.reply(daemon.OpKit, daemon.KitResult{})
			f.reply(daemon.OpKitDone, nil)
			m := noKeychain(t)
			m.paths = f.paths

			// The hand-off after hop init.
			s := &session{tty: true, secrets: initSecrets(), onSecret: typedTwice(devPass), answer: func(string) string { return "y" }}
			if code := m.hop(t, s, "init"); code != 0 {
				t.Fatalf("init: exit %d: %s", code, s.stderr.String())
			}
			if !strings.Contains(s.stderr.String(), "device passphrase was not sent") {
				t.Errorf("no warning that nothing was sent:\n%s", s.stderr.String())
			}
			// hop unlock with a passphrase from the environment.
			u := &session{env: map[string]string{store.PassphraseEnv: devPass}}
			if code := m.hop(t, u, "unlock"); code != 255 || !strings.Contains(u.stderr.String(), "no device passphrase was sent") {
				t.Errorf("unlock: exit %d: %s", code, u.stderr.String())
			}
			// hop unlock asking for it on a terminal.
			u = &session{tty: true, secrets: map[string]string{askOldPass: devPass}}
			if code := m.hop(t, u, "unlock"); code != 255 || !strings.Contains(u.stderr.String(), "no device passphrase was sent") {
				t.Errorf("unlock on a terminal: exit %d: %s", code, u.stderr.String())
			}
			// hop passwd, which sends it with its request.
			p := &session{tty: true, secrets: map[string]string{
				askOldPass: devPass, "Current master password: ": resolvePassword, "New master password: ": newPassword, "Repeat it: ": newPassword}}
			if code := m.hop(t, p, "passwd"); code != 255 || !strings.Contains(p.stderr.String(), "no device passphrase was sent") {
				t.Errorf("passwd: exit %d: %s", code, p.stderr.String())
			}
			for _, op := range []string{daemon.OpUnlock, daemon.OpPasswd, daemon.OpKitDone} {
				for _, params := range f.called(op) {
					if strings.Contains(string(params), devPass) || strings.Contains(string(params), resolvePassword) || strings.Contains(string(params), "device_passphrase") {
						t.Errorf("the daemon received a secret with %s: %s", op, params)
					}
				}
			}
			if n := len(f.called(daemon.OpPasswd)); n != 0 {
				t.Errorf("hop passwd sent its request to the wrong daemon %d times", n)
			}
		})
	}
}

// The wording of the sealed-file failure, the unsealed warning and the
// rule for a device passphrase.
func TestDevicePassphraseWording(t *testing.T) {
	// A person who just said no is not told to run it on a terminal and say yes.
	m := noKeychain(t)
	s := &session{tty: true, secrets: initSecrets(), answer: func(string) string { return "n" }}
	if code := m.hop(t, s, "init"); code != 0 {
		t.Fatalf("init: exit %d: %s", code, s.stderr.String())
	}
	if !strings.Contains(s.stderr.String(), "unencrypted on disk") || strings.Contains(s.stderr.String(), "say yes") {
		t.Errorf("warning after no:\n%s", s.stderr.String())
	}
	// The rule is said in characters, not bytes.
	m = noKeychain(t)
	tries := 0
	s = &session{tty: true, secrets: initSecrets(), answer: func(string) string { return "y" }, onSecret: func(p string) (string, bool) {
		switch {
		case strings.HasPrefix(p, askNewPass), strings.HasPrefix(p, askRepeat):
			if tries++; tries <= 2 {
				return "short", true
			}
			return devPass, true
		}
		return "", false
	}}
	if code := m.hop(t, s, "init"); code != 0 {
		t.Fatalf("init: exit %d: %s", code, s.stderr.String())
	}
	if !strings.Contains(s.stderr.String(), "at least 8 characters") || strings.Contains(s.stderr.String(), "1024") {
		t.Errorf("the rule:\n%s", s.stderr.String())
	}
}

// hop auth policy on a locked vault says once what to run.
func TestLockedMessagesSayHopUnlockOnce(t *testing.T) {
	_, m := sealedAccount(t)
	m.must(t, nil, "lock")
	for _, args := range [][]string{{"auth", "policy"}, {"auth", "devices"}} {
		s := &session{}
		if code := m.hop(t, s, args...); code != 255 {
			t.Fatalf("%v: exit %d", args, code)
		}
		if n := strings.Count(s.stderr.String(), "run hop unlock"); n != 1 {
			t.Errorf("%v says \"run hop unlock\" %d times: %q", args, n, s.stderr.String())
		}
	}
}

// hop unlock --password on a signed-in vault says what to do instead
// before it asks for anything, and does not promise what it can't do.
func TestUnlockPasswordOnASignedInVaultRefusesBeforeAnySecret(t *testing.T) {
	_, m := sealedAccount(t)
	m.must(t, nil, "lock")
	s := &session{tty: true}
	if code := m.hop(t, s, "unlock", "--password"); code != 255 {
		t.Fatalf("exit %d", code)
	}
	if len(s.order) != 0 {
		t.Errorf("asked: %v", s.order)
	}
	for _, want := range []string{"hop auth logout --local-only", "hop auth login", "hop auth devices revoke"} {
		if !strings.Contains(s.stderr.String(), want) {
			t.Errorf("stderr does not say %q:\n%s", want, s.stderr.String())
		}
	}
	if strings.Contains(s.stderr.String(), "This opens the vault") || strings.Contains(s.stderr.String(), "store:") {
		t.Errorf("the intro line, or the store's own refusal:\n%s", s.stderr.String())
	}
	// A local vault still gets it. (One with a sealed key file is refused
	// earlier still: TestUnlockPasswordOnASealedLocalVault.)
	l := newMachine(t, &authWorld{}, "local")
	if code := l.hop(t, &session{secrets: initSecrets()}, "init"); code != 0 {
		t.Fatalf("init: exit %d", code)
	}
	l.must(t, nil, "lock")
	s = &session{tty: true, failAt: masterPrmpt} // Ctrl-C at the first question
	l.hop(t, s, "unlock", "--password")
	if !strings.Contains(s.stderr.String(), "This opens the vault with your master password and Secret Key") {
		t.Errorf("a local vault lost the intro line:\n%s", s.stderr.String())
	}
}

// hop auth login on a signed-in device says so before it asks for a server
// URL, an email or the device passphrase.
func TestLoginWhileSignedInAsksNothing(t *testing.T) {
	_, m := sealedAccount(t)
	for _, args := range [][]string{
		{"auth", "login", "--method", "password"},
		{"auth", "login"},
	} {
		s := &session{tty: true, secrets: map[string]string{askOldPass: devPass}}
		if code := m.hop(t, s, args...); code != 255 {
			t.Fatalf("%v: exit %d", args, code)
		}
		if len(s.order) != 0 {
			t.Errorf("%v asked: %v", args, s.order)
		}
		if !strings.Contains(s.stderr.String(), "already signed in") {
			t.Errorf("%v: %s", args, s.stderr.String())
		}
	}
	vaultOpen(t, m)
}

// The JSON of hop daemon status tells which vault the daemon serves.
func TestStatusNamesTheDataDirectory(t *testing.T) {
	m := sealedLocal(t)
	var st map[string]any
	if err := json.Unmarshal([]byte(m.must(t, nil, "status", "--json")), &st); err != nil {
		t.Fatal(err)
	}
	got, _ := st["data_dir"].(string)
	if got == "" {
		t.Fatalf("no data_dir in %v", st)
	}
	if a, err := os.Stat(got); err != nil {
		t.Errorf("data_dir %q: %v", got, err)
	} else if b, err := os.Stat(m.data); err != nil || !os.SameFile(a, b) {
		t.Errorf("data_dir %q is not %q", got, m.data)
	}
}

// A key file that is missing or damaged fails every command that opens the
// vault itself before the daemon stops, whatever the passphrase: the vault
// open in the daemon is the one working copy, and a daemon that starts
// again can't open the file.
func TestBrokenKeyFileFailsBeforeTheDaemonStops(t *testing.T) {
	_, m := sealedAccount(t)
	good, err := os.ReadFile(keyFileOf(m))
	if err != nil {
		t.Fatal(err)
	}
	started := daemonStarted(t, m)
	damages := []struct {
		name string
		do   func() error
	}{
		{"missing", func() error { return os.Remove(keyFileOf(m)) }},
		{"damaged", func() error { return os.WriteFile(keyFileOf(m), []byte("not a key file"), 0o600) }},
	}
	passwords := map[string]string{"HOP_PASSWORD": resolvePassword, store.PassphraseEnv: devPass}
	cases := []struct {
		name string
		args []string
	}{
		{"auth rotate", []string{"auth", "rotate"}},
		{"auth passwd", []string{"auth", "passwd"}},
		{"auth devices revoke", []string{"auth", "devices", "revoke", "no-such-device"}},
		{"auth resume", []string{"auth", "resume"}},
		{"auth approve", []string{"auth", "approve"}},
		{"auth merge", []string{"auth", "merge"}},
		{"passwd", []string{"passwd"}},
	}
	for _, d := range damages {
		for _, tc := range cases {
			t.Run(d.name+"/"+tc.name, func(t *testing.T) {
				if err := d.do(); err != nil {
					t.Fatal(err)
				}
				defer func() {
					if err := os.WriteFile(keyFileOf(m), good, 0o600); err != nil {
						t.Fatal(err)
					}
				}()
				// With a terminal, so that hop passwd gets as far as the key.
				s := &session{tty: true, env: passwords}
				if code := m.hop(t, s, tc.args...); code != 255 {
					t.Fatalf("exit %d: %s", code, s.stderr.String())
				}
				if !strings.Contains(s.stderr.String(), "the device key is unavailable") {
					t.Errorf("stderr does not say the key is unavailable:\n%s", s.stderr.String())
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
}

// hop passwd on a local vault checks the key file too, before it connects.
func TestPasswdOnABrokenKeyFileChangesNothing(t *testing.T) {
	m := sealedLocal(t)
	started := daemonStarted(t, m)
	if err := os.Remove(keyFileOf(m)); err != nil {
		t.Fatal(err)
	}
	s := &session{tty: true, env: map[string]string{store.PassphraseEnv: devPass}}
	if code := m.hop(t, s, "passwd"); code != 255 || !strings.Contains(s.stderr.String(), "the device key is unavailable") {
		t.Fatalf("exit %d: %s", code, s.stderr.String())
	}
	if len(s.order) != 0 {
		t.Errorf("asked: %v", s.order)
	}
	if got := daemonStarted(t, m); !got.Equal(started) {
		t.Error("the daemon was stopped and started again")
	}
}

// hop auth logout is the way out of a device whose key file is gone, and it
// says so wherever it stops: hop auth logout --local-only needs no key.
func TestLogoutOnABrokenKeyFileNamesLocalOnly(t *testing.T) {
	_, m := sealedAccount(t)
	started := daemonStarted(t, m)
	if err := os.Remove(keyFileOf(m)); err != nil {
		t.Fatal(err)
	}
	// At a terminal: no passphrase is asked for a file that can't be read.
	s := &session{tty: true, secrets: map[string]string{askOldPass: devPass}}
	if code := m.hop(t, s, "auth", "logout", "--yes"); code != 255 {
		t.Fatalf("logout at a terminal: exit %d: %s", code, s.stderr.String())
	}
	if !strings.Contains(s.stderr.String(), "hop auth logout --local-only") {
		t.Errorf("the failure does not name --local-only:\n%s", s.stderr.String())
	}
	if len(s.order) != 0 {
		t.Errorf("asked: %v", s.order)
	}
	if got := daemonStarted(t, m); !got.Equal(started) {
		t.Error("the daemon was stopped")
	}
	vaultOpen(t, m)
	// With the passphrase in the environment.
	s = &session{env: map[string]string{store.PassphraseEnv: devPass}}
	if code := m.hop(t, s, "auth", "logout", "--yes"); code != 255 {
		t.Fatalf("logout with the variable: exit %d: %s", code, s.stderr.String())
	}
	if !strings.Contains(s.stderr.String(), "hop auth logout --local-only") {
		t.Errorf("the failure does not name --local-only:\n%s", s.stderr.String())
	}
	// And --local-only works.
	s = &session{}
	if code := m.hop(t, s, "auth", "logout", "--local-only", "--yes"); code != 0 {
		t.Fatalf("logout --local-only: exit %d: %s", code, s.stderr.String())
	}
	if ok, err := store.Exists(m.data); err != nil || ok {
		t.Errorf("the vault is still there after --local-only (%v)", err)
	}
}

// hop unlock says "vault unlocked" only of the vault in its own data
// directory. A daemon that serves another vault is reported as such even
// when no passphrase would be sent; one that names no data directory (a
// store that has none, or an older daemon) is taken as it is.
func TestUnlockOfAnotherVaultsDaemonIsNotSuccess(t *testing.T) {
	a := sealedLocal(t)
	b := newMachine(t, &authWorld{}, "other")
	b.paths, b.home = a.paths, a.home // the same sockets, a data directory of its own
	s := &session{}
	code := b.hop(t, s, "unlock")
	if code != 255 {
		t.Fatalf("exit %d, want 255: %s", code, s.stderr.String())
	}
	if strings.Contains(s.stdout.String(), "vault unlocked") {
		t.Errorf("said the vault was unlocked: %q", s.stdout.String())
	}
	for _, want := range []string{a.data, b.data, "hop daemon stop"} {
		if !strings.Contains(s.stderr.String(), want) {
			t.Errorf("stderr does not say %q:\n%s", want, s.stderr.String())
		}
	}
	if a.authStatus(t).Locked {
		t.Error("the other vault's daemon was locked")
	}

	// The same vault, and a daemon that says nothing about its directory.
	if s := (&session{}); a.hop(t, s, "unlock") != 0 || !strings.Contains(s.stdout.String(), "vault unlocked") {
		t.Errorf("unlock of its own vault: %s %s", s.stdout.String(), s.stderr.String())
	}
	f := newFakeDaemon(t)
	f.reply(daemon.OpStatus, map[string]any{"version": "test", "vault": map[string]any{"locked": true}})
	f.reply(daemon.OpUnlock, nil)
	f.reply(daemon.OpKit, daemon.KitResult{})
	n := noKeychain(t)
	n.paths = f.paths
	s = &session{}
	if code := n.hop(t, s, "unlock"); code != 0 || !strings.Contains(s.stdout.String(), "vault unlocked") {
		t.Errorf("unlock by a daemon with no data directory: exit %d: %s %s", code, s.stdout.String(), s.stderr.String())
	}
}

// hop passwd on a locked vault that was never signed in asks for the
// passwords, as it does on an open one. A locked vault's sync state reads
// "paused", which is not a sign-in. A signed-in vault, open or locked, still
// goes through the server.
func TestPasswdOnALockedLocalVault(t *testing.T) {
	m := sealedLocal(t)
	m.must(t, nil, "lock")
	s := &session{tty: true, secrets: map[string]string{
		askOldPass: devPass, "Current master password: ": resolvePassword, "New master password: ": newPassword, "Repeat it: ": newPassword}}
	if code := m.hop(t, s, "passwd"); code != 0 {
		t.Fatalf("passwd on a locked local vault: exit %d: %s", code, s.stderr.String())
	}
	if strings.Contains(s.stderr.String(), "local-only") || !strings.Contains(s.stdout.String(), "Emergency Kit confirmed") {
		t.Errorf("stdout: %s\nstderr: %s", s.stdout.String(), s.stderr.String())
	}
	asksOnce(t, s)

	_, a := sealedAccount(t)
	for _, locked := range []bool{false, true} {
		cur, next := resolvePassword, newPassword
		if locked {
			cur, next = newPassword, resolvePassword
			a.must(t, nil, "lock")
		}
		s := &session{tty: true, env: map[string]string{"HOP_PASSWORD": cur, "HOP_NEW_PASSWORD": next}, secrets: map[string]string{askOldPass: devPass}}
		if code := a.hop(t, s, "passwd"); code != 0 {
			t.Fatalf("passwd on a signed-in vault (locked: %v): exit %d: %s", locked, code, s.stderr.String())
		}
		if !strings.Contains(s.stdout.String(), "Your new Emergency Kit") {
			t.Errorf("passwd on a signed-in vault (locked: %v) did not go through the server:\n%s", locked, s.stdout.String())
		}
	}
}

// hop unlock --password on a sealed key file can't save the new key through
// a daemon that has no device passphrase of its own, and the variable on
// this command does not reach it. It says so before it asks for a secret,
// and the steps it names work.
func TestUnlockPasswordOnASealedLocalVault(t *testing.T) {
	m := noKeychain(t)
	i := &session{tty: true, secrets: initSecrets(), onSecret: typedTwice(devPass), answer: func(string) string { return "y" }}
	if code := m.hop(t, i, "init"); code != 0 {
		t.Fatalf("init: exit %d: %s", code, i.stderr.String())
	}
	sk, _ := kitKeys(t, i.stdout.String())
	m.must(t, nil, "lock")
	secrets := map[string]string{masterPrmpt: resolvePassword, "Secret Key (": sk}
	started := daemonStarted(t, m)

	for _, tc := range []struct {
		name string
		env  map[string]string
		want []string
	}{
		{"no variable", nil, []string{"hop daemon stop", "read -rs " + store.PassphraseEnv, "export " + store.PassphraseEnv, "hop unlock --password again", "Nothing was changed"}},
		{"variable set here", map[string]string{store.PassphraseEnv: otherPass}, []string{"hop daemon stop", "does not reach the daemon", "set here"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := &session{tty: true, env: tc.env, secrets: secrets}
			if code := m.hop(t, s, "unlock", "--password"); code != 255 {
				t.Fatalf("exit %d: %s", code, s.stderr.String())
			}
			if len(s.order) != 0 {
				t.Errorf("asked before refusing: %v", s.order)
			}
			for _, want := range tc.want {
				if !strings.Contains(s.stderr.String(), want) {
					t.Errorf("stderr does not say %q:\n%s", want, s.stderr.String())
				}
			}
			if strings.Contains(s.stderr.String(), "store:") || strings.Contains(s.stderr.String(), "This opens the vault") {
				t.Errorf("the store's own refusal, or the intro line:\n%s", s.stderr.String())
			}
			if got := daemonStarted(t, m); !got.Equal(started) {
				t.Error("the daemon was stopped")
			}
		})
	}
	before, err := os.ReadFile(keyFileOf(m))
	if err != nil {
		t.Fatal(err)
	}

	// The steps: stop the daemon, start one with a new device passphrase
	// (the variable is what the daemon the command starts inherits), and
	// run the command again.
	m.must(t, nil, "daemon", "stop")
	np := otherPass
	m.daemonPass.Store(&np)
	s := &session{tty: true, env: map[string]string{store.PassphraseEnv: np}, secrets: secrets}
	if code := m.hop(t, s, "unlock", "--password"); code != 0 {
		t.Fatalf("unlock --password after the steps: exit %d: %s", code, s.stderr.String())
	}
	if !strings.Contains(s.stdout.String(), "vault unlocked with the master password") {
		t.Errorf("stdout: %s", s.stdout.String())
	}
	if a := m.authStatus(t); a.Locked {
		t.Error("still locked")
	}
	after, err := os.ReadFile(keyFileOf(m))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(before, after) {
		t.Error("the key file was not replaced")
	}
	if err := store.CheckDevicePassphrase(m.data, []byte(np)); err != nil {
		t.Errorf("the new device passphrase does not open the new key file: %v", err)
	}
	if err := store.CheckDevicePassphrase(m.data, []byte(devPass)); !errors.Is(err, store.ErrWrongDevicePassphrase) {
		t.Errorf("the old device passphrase still opens it: %v", err)
	}
	if strings.Contains(s.stdout.String()+s.stderr.String(), np) {
		t.Error("the device passphrase was printed")
	}
}

// hop auth signup on a device that is signed in says so before it asks for
// the device passphrase.
func TestSignupWhileSignedInAsksNothing(t *testing.T) {
	w, m := sealedAccount(t)
	started := daemonStarted(t, m)
	s := &session{tty: true, secrets: map[string]string{askOldPass: devPass}}
	if code := m.hop(t, s, "auth", "signup", "--server", w.origin, "--email", authEmail, "--code", w.invite(t)); code != 255 {
		t.Fatalf("exit %d: %s", code, s.stderr.String())
	}
	if len(s.order) != 0 {
		t.Errorf("asked: %v", s.order)
	}
	if !strings.Contains(s.stderr.String(), "already signed in") {
		t.Errorf("stderr: %s", s.stderr.String())
	}
	if got := daemonStarted(t, m); !got.Equal(started) {
		t.Error("the daemon was stopped")
	}
	vaultOpen(t, m)
}
