package cli_test

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/dalyem/hopkey/internal/store"
)

// A machine with no OS keychain (WSL, a headless server) is settled by one
// question asked before any secret, not by a failure after two were typed.
// These run hop through cli.Run, as a user does, with a keychain that fails
// the way the Secret Service does when no service is running.

const (
	devPass     = "tr1cky-unique-secret-9"
	askProtect  = "Protect it with a device passphrase? (recommended) [Y/n] "
	askNewPass  = "New device passphrase: "
	askRepeat   = "Repeat the device passphrase: "
	askOldPass  = "Device passphrase ("
	masterPrmpt = "Master password: "
)

// noKeychain is a machine whose keychain fails, and that never contacted a
// server.
func noKeychain(t *testing.T) *machine {
	t.Helper()
	m := newMachine(t, &authWorld{}, "nokeychain")
	m.ring.broken.Store(true)
	return m
}

// typedTwice answers the new device passphrase prompts with pass.
func typedTwice(pass string) func(string) (string, bool) {
	return func(p string) (string, bool) {
		if strings.HasPrefix(p, askNewPass) || strings.HasPrefix(p, askRepeat) {
			return pass, true
		}
		return "", false
	}
}

func initSecrets() map[string]string {
	return map[string]string{masterPrmpt: resolvePassword, "Repeat it: ": resolvePassword}
}

func keyFileOf(m *machine) string { return filepath.Join(m.data, "device.key") }

func sealed(t *testing.T, m *machine) bool {
	t.Helper()
	ok, err := store.SealedDeviceFile(m.data)
	if err != nil {
		t.Fatal(err)
	}
	return ok
}

// nothingWritten fails the test if the machine holds any vault state.
func nothingWritten(t *testing.T, m *machine) {
	t.Helper()
	for _, name := range []string{"device.key", "device.json"} {
		if _, err := os.Lstat(filepath.Join(m.data, name)); err == nil {
			t.Errorf("%s was written", name)
		}
	}
	if ok, err := store.Exists(m.data); err != nil || ok {
		t.Errorf("a vault exists (%v)", err)
	}
	if n := len(m.ring.m); n != 0 {
		t.Errorf("the keychain holds %d entries", n)
	}
}

func notInEnvironment(t *testing.T, s *session) {
	t.Helper()
	if v, ok := os.LookupEnv(store.PassphraseEnv); ok {
		t.Errorf("%s reached the process environment: %q", store.PassphraseEnv, v)
	}
	if _, ok := s.env[store.PassphraseEnv]; ok {
		t.Errorf("%s was put in the command's environment", store.PassphraseEnv)
	}
	for _, out := range []string{s.stdout.String(), s.stderr.String()} {
		if strings.Contains(out, devPass) {
			t.Errorf("the device passphrase was printed: %q", out)
		}
	}
}

// Yes: the question comes before the master password, the file is sealed,
// the passphrase never reaches the environment, and the vault is open in
// the daemon afterwards with no second prompt.
func TestInitWithNoKeychainAsksFirstAndSeals(t *testing.T) {
	m := noKeychain(t)
	s := &session{tty: true, secrets: initSecrets(), onSecret: typedTwice(devPass), answer: func(string) string { return "y" }}
	if code := m.hop(t, s, "init"); code != 0 {
		t.Fatalf("init: exit %d: %s", code, s.stderr.String())
	}
	q, pw := s.askedIndex(strings.TrimSuffix(askProtect, " [Y/n] ")), s.askedIndex(masterPrmpt)
	if q < 0 || pw < 0 || q > pw || s.askedIndex(askNewPass) > pw || s.askedIndex(askRepeat) > pw {
		t.Errorf("the question must come before the master password: %v", s.order)
	}
	out := s.stderr.String()
	for _, want := range []string{"no usable OS keychain", "org.freedesktop.secrets", keyFileOf(m)} {
		if !strings.Contains(out, want) {
			t.Errorf("stderr does not say %q:\n%s", want, out)
		}
	}
	if !sealed(t, m) {
		t.Error("the device key file is not sealed")
	}
	if b, _ := os.ReadFile(keyFileOf(m)); strings.Contains(string(b), "kem_sk") {
		t.Error("the sealed file holds the private keys in plain form")
	}
	if len(m.ring.m) != 0 {
		t.Errorf("the keychain holds %v", m.ring.m)
	}
	if a := m.authStatus(t); a.Locked || !strings.Contains(a.DeviceKeyStore, "sealed") {
		t.Errorf("the vault is locked right after init: %+v", a)
	}
	if strings.Count(s.stdout.String(), "Secret Key") == 0 {
		t.Error("no Emergency Kit was shown")
	}
	notInEnvironment(t, s)
}

// No: the file is unsealed, nothing is asked for a passphrase, and the
// warning says what that means.
func TestInitWithNoKeychainAnswerNoMakesAnUnsealedFile(t *testing.T) {
	m := noKeychain(t)
	s := &session{tty: true, secrets: initSecrets(), answer: func(string) string { return "n" }}
	if code := m.hop(t, s, "init"); code != 0 {
		t.Fatalf("init: exit %d: %s", code, s.stderr.String())
	}
	if sealed(t, m) {
		t.Error("the file is sealed")
	}
	if s.askedIndex(askNewPass) >= 0 {
		t.Errorf("a passphrase was asked for after no: %v", s.order)
	}
	if !strings.Contains(s.stderr.String(), "unencrypted on disk") {
		t.Errorf("no warning about the unsealed file:\n%s", s.stderr.String())
	}
	if a := m.authStatus(t); a.Locked || !strings.Contains(a.DeviceKeyStore, "unsealed") {
		t.Errorf("status after init: %+v", a)
	}
}

// A mismatch and a too-short or empty passphrase are each refused by asking
// again; the third try matches. Three tries that fail end the command with
// nothing written.
func TestInitDevicePassphraseIsAskedAgainUntilItMatches(t *testing.T) {
	typed := func(tries [][2]string) func(string) (string, bool) {
		var n atomic.Int32
		return func(p string) (string, bool) {
			switch {
			case strings.HasPrefix(p, askNewPass):
				return tries[min(int(n.Add(1))-1, len(tries)-1)][0], true
			case strings.HasPrefix(p, askRepeat):
				return tries[min(int(n.Load())-1, len(tries)-1)][1], true
			}
			return "", false
		}
	}
	m := noKeychain(t)
	s := &session{tty: true, secrets: initSecrets(), answer: func(string) string { return "y" },
		onSecret: typed([][2]string{{"first one 123", "other one 456"}, {"", ""}, {devPass, devPass}})}
	if code := m.hop(t, s, "init"); code != 0 {
		t.Fatalf("init: exit %d: %s", code, s.stderr.String())
	}
	if n := strings.Count(s.stderr.String(), "Try again."); n != 2 {
		t.Errorf("asked again %d times, want 2:\n%s", n, s.stderr.String())
	}
	if !sealed(t, m) {
		t.Error("the file is not sealed")
	}
	// What matched opens it: hop lock, then hop unlock with it.
	m.must(t, nil, "lock")
	u := &session{tty: true, secrets: map[string]string{askOldPass: devPass}}
	if code := m.hop(t, u, "unlock"); code != 0 {
		t.Fatalf("unlock with the typed passphrase: exit %d: %s", code, u.stderr.String())
	}
	if m.authStatus(t).Locked {
		t.Error("still locked")
	}

	m2 := noKeychain(t)
	s2 := &session{tty: true, secrets: initSecrets(), answer: func(string) string { return "y" },
		onSecret: typed([][2]string{{"first one 123", "other one 456"}, {"", ""}, {"short", "short"}})}
	if code := m2.hop(t, s2, "init"); code != 255 {
		t.Fatalf("init with three bad tries: exit %d", code)
	}
	if s2.askedIndex(masterPrmpt) >= 0 {
		t.Errorf("the master password was asked for: %v", s2.order)
	}
	nothingWritten(t, m2)
	// Too short and mismatched entries end the same way, in words true of both.
	for name, tries := range map[string][][2]string{
		"short":      {{"short", "short"}},
		"mismatched": {{"first one 123", "other one 456"}},
	} {
		m3 := noKeychain(t)
		s3 := &session{tty: true, secrets: initSecrets(), answer: func(string) string { return "y" }, onSecret: typed(tries)}
		if code := m3.hop(t, s3, "init"); code != 255 {
			t.Fatalf("init, %s: exit %d", name, code)
		}
		if !strings.Contains(s3.stderr.String(), "no usable device passphrase after 3 tries; nothing was created") {
			t.Errorf("%s: stderr: %s", name, s3.stderr.String())
		}
	}
}

// An explicit --device-key-store keychain is binding: the keychain is
// tried before any secret is asked, there is no fallback and no question,
// and the failure names both ways forward.
func TestInitExplicitKeychainStillFailsBeforeAnySecret(t *testing.T) {
	m := noKeychain(t)
	s := &session{tty: true, secrets: initSecrets(), answer: func(string) string { return "y" }}
	if code := m.hop(t, s, "init", "--device-key-store", "keychain"); code != 255 {
		t.Fatalf("init: exit %d", code)
	}
	for _, want := range []string{"--device-key-store=file", store.PassphraseEnv, "keychain is not usable"} {
		if !strings.Contains(s.stderr.String(), want) {
			t.Errorf("stderr does not say %q:\n%s", want, s.stderr.String())
		}
	}
	if len(s.order) != 0 {
		t.Errorf("something was asked before the failure: %v", s.order)
	}
	nothingWritten(t, m)
}

// With no terminal, nothing is asked: the failure is the same as ever, with
// both ways forward in it, and it comes before the master password.
func TestInitJSONNeverAsks(t *testing.T) {
	m := noKeychain(t)
	s := &session{tty: true, secrets: initSecrets(), answer: func(string) string { return "y" }}
	if code := m.hop(t, s, "init", "--json"); code != 255 {
		t.Fatalf("init --json: exit %d", code)
	}
	for _, want := range []string{"--device-key-store=file", store.PassphraseEnv} {
		if !strings.Contains(s.stderr.String(), want) {
			t.Errorf("stderr does not say %q:\n%s", want, s.stderr.String())
		}
	}
	if len(s.order) != 0 || s.stdout.String() != "" {
		t.Errorf("asked or printed something: %v, %q", s.order, s.stdout.String())
	}
	nothingWritten(t, m)
}

// Ctrl-C (the terminal reports an error, or stdin ends) at the question or
// at either passphrase prompt leaves nothing behind: no key file, no vault
// state, no keychain entry.
func TestInitInterruptedAtTheNewPromptsWritesNothing(t *testing.T) {
	for _, at := range []string{"the question", askNewPass, askRepeat} {
		t.Run(at, func(t *testing.T) {
			m := noKeychain(t)
			s := &session{tty: true, secrets: initSecrets(), onSecret: typedTwice(devPass), answer: func(string) string { return "y" }}
			if at == "the question" {
				s.answer = nil // stdin ends
			} else {
				s.failAt = at
			}
			if code := m.hop(t, s, "init"); code != 255 {
				t.Fatalf("exit %d: %s", code, s.stderr.String())
			}
			if s.askedIndex(masterPrmpt) >= 0 {
				t.Errorf("the master password was asked for: %v", s.order)
			}
			nothingWritten(t, m)
		})
	}
}

// --device-key-store file on a terminal with no HOP_DEVICE_PASSPHRASE asks
// the same question rather than going unsealed in silence, even where the
// keychain works.
func TestInitExplicitFileAsksTheSameQuestion(t *testing.T) {
	m := newMachine(t, &authWorld{}, "file")
	s := &session{tty: true, secrets: initSecrets(), onSecret: typedTwice(devPass), answer: func(string) string { return "" }}
	if code := m.hop(t, s, "init", "--device-key-store", "file"); code != 0 {
		t.Fatalf("init: exit %d: %s", code, s.stderr.String())
	}
	if s.askedIndex(strings.TrimSuffix(askProtect, " [Y/n] ")) < 0 || !sealed(t, m) {
		t.Errorf("no question, or not sealed (an empty answer means yes): %v", s.order)
	}
	if strings.Contains(s.stderr.String(), "no usable OS keychain") {
		t.Errorf("claims the keychain is unusable:\n%s", s.stderr.String())
	}
}

// HOP_DEVICE_PASSPHRASE set: it seals the file with no question and no
// prompt, as before.
func TestInitWithTheEnvironmentPassphraseAsksNothing(t *testing.T) {
	m := newMachine(t, &authWorld{}, "env")
	env := map[string]string{store.PassphraseEnv: devPass}
	s := &session{tty: true, env: env, secrets: initSecrets(), answer: func(string) string { return "y" }}
	if code := m.hop(t, s, "init", "--device-key-store", "file"); code != 0 {
		t.Fatalf("init: exit %d: %s", code, s.stderr.String())
	}
	if s.askedIndex("Protect") >= 0 || s.askedIndex(askNewPass) >= 0 || !sealed(t, m) {
		t.Errorf("asked, or not sealed: %v", s.order)
	}
}

// A usable keychain: exactly as before, no question, nothing left behind
// by the probe.
func TestInitWithAUsableKeychainAsksNothing(t *testing.T) {
	m := newMachine(t, &authWorld{}, "keychain")
	s := &session{tty: true, secrets: initSecrets(), answer: func(string) string { return "y" }}
	if code := m.hop(t, s, "init"); code != 0 {
		t.Fatalf("init: exit %d: %s", code, s.stderr.String())
	}
	if s.askedIndex("Protect") >= 0 {
		t.Errorf("asked: %v", s.order)
	}
	if _, err := os.Lstat(keyFileOf(m)); err == nil {
		t.Error("a key file was written")
	}
	for k := range m.ring.m {
		if strings.HasSuffix(k, "/probe") {
			t.Errorf("the probe left %s in the keychain", k)
		}
	}
	if len(m.ring.m) != 1 {
		t.Errorf("the keychain holds %v, want the device key alone", m.ring.m)
	}
}

// With HOP_DEVICE_PASSPHRASE set but no --device-key-store, a broken
// keychain is still the user's choice to make: they confirm the file, and
// the environment's passphrase seals it, with no passphrase prompt.
func TestInitNoKeychainWithTheEnvironmentPassphraseConfirmsTheFile(t *testing.T) {
	m := noKeychain(t)
	env := map[string]string{store.PassphraseEnv: devPass}
	s := &session{tty: true, env: env, secrets: initSecrets(), answer: func(string) string { return "y" }}
	if code := m.hop(t, s, "init"); code != 0 {
		t.Fatalf("init: exit %d: %s", code, s.stderr.String())
	}
	if s.askedIndex("Seal it with the device passphrase from HOP_DEVICE_PASSPHRASE?") < 0 || s.askedIndex(askNewPass) >= 0 || !sealed(t, m) {
		t.Errorf("order %v, sealed %v", s.order, sealed(t, m))
	}
	// Declining is a failure that changes nothing.
	m2 := noKeychain(t)
	s2 := &session{tty: true, env: env, secrets: initSecrets(), answer: func(string) string { return "n" }}
	if code := m2.hop(t, s2, "init"); code != 255 {
		t.Fatalf("init declining the file: exit %d", code)
	}
	// It says what to unset to get an unsealed file, not what the keychain
	// error says to set.
	for _, want := range []string{"unset " + store.PassphraseEnv, "unsealed file"} {
		if !strings.Contains(s2.stderr.String(), want) {
			t.Errorf("declining the file does not say %q:\n%s", want, s2.stderr.String())
		}
	}
	if strings.Contains(s2.stderr.String(), "--device-key-store=file") {
		t.Errorf("declining the file sends the user to the flag they just declined:\n%s", s2.stderr.String())
	}
	nothingWritten(t, m2)
}

// The sign-in from the report: password login on a machine with no keychain
// asks first, signs in with the typed device passphrase, and leaves the
// vault open in the daemon.
func TestLoginWithNoKeychainAsksBeforeTheSecrets(t *testing.T) {
	w := newAuthWorld(t)
	m1 := newMachine(t, w, "m1")
	initS := &session{secrets: initSecrets()}
	if code := m1.hop(t, initS, "init"); code != 0 {
		t.Fatalf("init: exit %d: %s", code, initS.stderr.String())
	}
	sk, _ := kitKeys(t, initS.stdout.String())
	m1.must(t, nil, "add", "web", "--address", "203.0.113.10", "--user", "deploy")
	m1.must(t, nil, "auth", "signup", "--server", w.origin, "--email", authEmail, "--code", w.invite(t))

	login := []string{"auth", "login", "--method", "password", "--server", w.origin, "--email", authEmail, "--name", "wsl"}
	secrets := map[string]string{masterPrmpt: resolvePassword, "Secret Key (from your Emergency Kit): ": sk}

	// Without a terminal nothing is asked: the old failure, naming both
	// ways forward.
	m2 := newMachine(t, w, "m2")
	m2.ring.broken.Store(true)
	plain := &session{env: map[string]string{"HOP_PASSWORD": resolvePassword, "HOP_SECRET_KEY": sk}}
	if code := m2.hop(t, plain, append(login, "--json")...); code != 255 {
		t.Fatalf("login without a terminal: exit %d", code)
	}
	for _, want := range []string{"--device-key-store=file", store.PassphraseEnv} {
		if !strings.Contains(plain.stderr.String(), want) {
			t.Errorf("stderr does not say %q:\n%s", want, plain.stderr.String())
		}
	}
	if len(plain.order) != 0 {
		t.Errorf("asked: %v", plain.order)
	}
	nothingWritten(t, m2)

	// On a terminal it asks first, then signs in.
	s := &session{tty: true, secrets: secrets, onSecret: typedTwice(devPass), answer: func(string) string { return "yes" }}
	if code := m2.hop(t, s, login...); code != 0 {
		t.Fatalf("login: exit %d: %s", code, s.stderr.String())
	}
	q := s.askedIndex(strings.TrimSuffix(askProtect, " [Y/n] "))
	if q < 0 || q > s.askedIndex(masterPrmpt) || q > s.askedIndex("Secret Key (from") || s.askedIndex(askRepeat) > s.askedIndex(masterPrmpt) {
		t.Errorf("the question must come before the secrets: %v", s.order)
	}
	if !sealed(t, m2) {
		t.Error("the file is not sealed")
	}
	if a := m2.authStatus(t); !a.SignedIn || a.Locked {
		t.Errorf("after login: %+v", a)
	}
	// The vault is open in the daemon, with no hop unlock: hosts list.
	var hosts []string
	for range 100 {
		for name := range m2.hosts(t) {
			hosts = append(hosts, name)
		}
		if slices.Contains(hosts, "web") {
			break
		}
		hosts = nil
		time.Sleep(100 * time.Millisecond)
	}
	if !slices.Contains(hosts, "web") {
		t.Error("the vault is not open in the daemon: no host web")
	}
	notInEnvironment(t, s)
}

// Publishing a vault that already exists follows the key file it has: a
// sealed one asks for its device passphrase, never the question, and the
// vault is open in the daemon afterwards.
func TestSignupOfASealedLocalVaultAsksNoQuestion(t *testing.T) {
	w := newAuthWorld(t)
	m := noKeychain(t)
	m.w = w
	i := &session{tty: true, secrets: initSecrets(), onSecret: typedTwice(devPass), answer: func(string) string { return "y" }}
	if code := m.hop(t, i, "init"); code != 0 {
		t.Fatalf("init: exit %d: %s", code, i.stderr.String())
	}
	s := &session{tty: true, secrets: map[string]string{askOldPass: devPass}, answer: func(string) string { return "y" }}
	if code := m.hop(t, s, "auth", "signup", "--server", w.origin, "--email", authEmail, "--code", w.invite(t)); code != 0 {
		t.Fatalf("signup: exit %d: %s", code, s.stderr.String())
	}
	if s.askedIndex("Protect") >= 0 || s.askedIndex(askNewPass) >= 0 || s.askedIndex(askOldPass) < 0 {
		t.Errorf("asked: %v", s.order)
	}
	if a := m.authStatus(t); !a.SignedIn || a.Locked {
		t.Errorf("after signup: %+v", a)
	}
	// With a vault whose key lives in a file, a login that merges nothing
	// is refused after only the passphrase: no question was asked.
	l := &session{tty: true, secrets: map[string]string{askOldPass: devPass}}
	m.hop(t, l, "auth", "login", "--method", "password", "--server", w.origin, "--email", authEmail)
	if l.askedIndex("Protect") >= 0 {
		t.Errorf("a question whose answer changes nothing was asked: %v", l.order)
	}
}

// approved runs hop login on the new machine and hop auth approve on the
// first, until both finish, comparing the check codes as a person does.
func approved(t *testing.T, m1, m2 *machine, w *authWorld, newcomer *session) (loginCode int) {
	t.Helper()
	approver := &session{tty: true}
	matching := func(mine, theirs *session) func(string) string {
		return func(prompt string) string {
			deadline := time.Now().Add(30 * time.Second)
			for sasOf(theirs) == "" && time.Now().Before(deadline) {
				time.Sleep(10 * time.Millisecond)
			}
			if a, b := sasOf(mine), sasOf(theirs); a == "" || a != b {
				t.Errorf("the check codes differ: %q and %q", a, b)
				return "no"
			}
			return "yes"
		}
	}
	approver.answer, newcomer.answer = matching(approver, newcomer), matching(newcomer, approver)
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		loginCode = m2.hop(t, newcomer, "login", "--server", w.origin, "--name", "m2")
	}()
	waitFor(t, 30*time.Second, "the routing code", func() bool { return routingLine.MatchString(newcomer.stderr.String()) })
	code := routingLine.FindStringSubmatch(newcomer.stderr.String())[1]
	if c := m1.hop(t, approver, "auth", "approve", code); c != 0 {
		t.Errorf("approve: exit %d", c)
	}
	wg.Wait()
	return loginCode
}

// Signing in by approval on a machine with no keychain: the question comes
// first, a login cut short (Ctrl-C while it waits for the approval) leaves
// an enrollment that records its choice, and signing in again follows that
// record: only the device passphrase is asked, not the question, and the
// restarted enrollment does not fall back to the keychain.
func TestLoginByApprovalWithNoKeychainFollowsItsRecord(t *testing.T) {
	w := newAuthWorld(t)
	m1 := newMachine(t, w, "m1")
	initS := &session{secrets: initSecrets()}
	if code := m1.hop(t, initS, "init"); code != 0 {
		t.Fatalf("init: exit %d: %s", code, initS.stderr.String())
	}
	m1.must(t, nil, "add", "web", "--address", "203.0.113.10", "--user", "deploy")
	m1.must(t, nil, "auth", "signup", "--server", w.origin, "--email", authEmail, "--code", w.invite(t))
	m2 := newMachine(t, w, "m2")
	m2.ring.broken.Store(true)

	// First try: the question, then Ctrl-C while waiting for the approval.
	ctx, cancel := context.WithCancel(context.Background())
	first := &session{tty: true, ctx: ctx, onSecret: typedTwice(devPass)}
	first.answer = func(prompt string) string {
		if strings.HasSuffix(prompt, "[Y/n] ") {
			return "y"
		}
		return "no"
	}
	done := make(chan int, 1)
	go func() { done <- m2.hop(t, first, "login", "--server", w.origin, "--name", "m2") }()
	waitFor(t, 30*time.Second, "the routing code", func() bool { return routingLine.MatchString(first.stderr.String()) })
	cancel()
	if code := <-done; code == 0 {
		t.Fatal("the cancelled login succeeded")
	}
	// The user is told it was cancelled, not shown the enrollment's URL.
	if out := first.stderr.String(); !strings.Contains(out, "the sign-in was cancelled") || strings.Contains(out, "/v1/enroll") || strings.Contains(out, "context canceled") {
		t.Errorf("the cancelled login says:\n%s", out)
	}
	if q, rc := strings.Index(first.stderr.String(), "Protect it"), strings.Index(first.stderr.String(), "hop auth approve "); q < 0 || q > rc {
		t.Errorf("the question must come before the routing code:\n%s", first.stderr.String())
	}
	plan, err := store.PlannedDeviceKey(m2.data)
	if err != nil || plan != (store.DeviceKeyPlan{Store: store.DeviceStoreFile, Sealed: true}) {
		t.Fatalf("the enrollment's record: %+v, %v", plan, err)
	}
	if _, err := os.Lstat(keyFileOf(m2)); err == nil {
		t.Error("a device key file was written by an enrollment that never finished")
	}

	// Second try: no question, the device passphrase of the record, done.
	second := &session{tty: true, onSecret: func(p string) (string, bool) {
		if strings.HasPrefix(p, askOldPass) {
			return devPass, true
		}
		return "", false
	}}
	if code := approved(t, m1, m2, w, second); code != 0 {
		t.Fatalf("the second login: exit %d: %s", code, second.stderr.String())
	}
	if second.askedIndex("Protect") >= 0 || second.askedIndex(askNewPass) >= 0 || second.askedIndex(askOldPass) < 0 {
		t.Errorf("the second login asked: %v", second.order)
	}
	if !sealed(t, m2) {
		t.Error("the file is not sealed")
	}
	if a := m2.authStatus(t); !a.SignedIn || a.Locked {
		t.Errorf("after the login: %+v", a)
	}
	waitFor(t, 20*time.Second, "web on m2", func() bool { _, ok := m2.hosts(t)["web"]; return ok })
	notInEnvironment(t, second)
}
