package cli_test

import (
	"context"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/dalyem/hopkey/internal/daemon"
	"github.com/dalyem/hopkey/internal/server"
	"github.com/dalyem/hopkey/internal/store"
)

// A2b option E, through the CLI against a real hop-server: a device the
// operator locked out signs out and signs in again as a new device. The
// vault locks when the operator's refusal arrives; hop status says how to
// get back in; hop auth logout counts what it will throw away and asks
// before it deletes anything; the next hop auth login names the old
// identity and prints the command that cuts it off, and runs nothing.

func opNow() server.Operator { return server.Operator{Actor: "test", Now: time.Now().UTC()} }

func blockOnServer(t *testing.T, w *authWorld, dev string) {
	t.Helper()
	ctx := context.Background()
	sel := server.DeviceSelection{IDs: []string{dev}}
	p, err := server.PlanBlockDevices(ctx, w.st, authEmail, sel, opNow())
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := server.BlockDevices(ctx, w.st, opNow(), authEmail, sel, "lost on a train", p); err != nil {
		t.Fatal(err)
	}
}

func disableOnServer(t *testing.T, w *authWorld, reason string) {
	t.Helper()
	ctx := context.Background()
	p, err := server.PlanDisable(ctx, w.st, authEmail, opNow())
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := server.DisableAccount(ctx, w.st, opNow(), authEmail, reason, p); err != nil {
		t.Fatal(err)
	}
}

func enableOnServer(t *testing.T, w *authWorld) {
	t.Helper()
	ctx := context.Background()
	p, err := server.PlanEnable(ctx, w.st, authEmail, opNow())
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := server.EnableAccount(ctx, w.st, opNow(), authEmail, p); err != nil {
		t.Fatal(err)
	}
}

// waitOperatorLock makes the daemon meet the operator's refusal (hop sync
// fails, and the vault locks) and returns hop status once it says want.
func waitOperatorLock(t *testing.T, m *machine, want string, env ...map[string]string) string {
	t.Helper()
	var out string
	waitFor(t, 30*time.Second, "the operator's lock on "+m.name, func() bool {
		for _, e := range env {
			// A daemon that restarted over a sealed device key meets the
			// refusal when it is unlocked.
			m.hop(t, &session{env: e}, "unlock")
		}
		m.hop(t, &session{}, "sync")
		s := &session{}
		m.hop(t, s, "status")
		out = s.stdout.String()
		return strings.Contains(out, want)
	})
	return out
}

func mustContain(t *testing.T, what, got string, wants ...string) {
	t.Helper()
	for _, w := range wants {
		if !strings.Contains(got, w) {
			t.Errorf("%s lacks %q:\n%s", what, w, got)
		}
	}
}

func mustNotContain(t *testing.T, what, got string, nots ...string) {
	t.Helper()
	for _, n := range nots {
		if strings.Contains(got, n) {
			t.Errorf("%s has %q:\n%s", what, n, got)
		}
	}
}

func hasVault(t *testing.T, m *machine) bool {
	t.Helper()
	ok, err := store.Exists(m.data)
	if err != nil {
		t.Fatal(err)
	}
	return ok
}

func predecessors(t *testing.T, m *machine) []store.Predecessor {
	t.Helper()
	got, err := store.ReadPredecessors(m.data)
	if err != nil {
		t.Fatal(err)
	}
	return got
}

// passwordLogin is a fresh sign-in on m with the master password and the
// Secret Key: the session, and the command to run in it.
func passwordLogin(m *machine, sk string, name string, extra ...string) (*session, func(*testing.T) int) {
	s := &session{env: map[string]string{"HOP_PASSWORD": resolvePassword, "HOP_SECRET_KEY": sk}}
	args := append([]string{"login", "--method", "password", "--server", m.w.origin, "--email", authEmail, "--name", name}, extra...)
	return s, func(t *testing.T) int { return m.hop(t, s, args...) }
}

func deviceIDs(t *testing.T, m *machine) map[string]bool {
	t.Helper()
	var dl daemon.DevicesResult
	waitFor(t, 20*time.Second, m.name+" lists its devices", func() bool {
		s := &session{}
		if m.hop(t, s, "auth", "devices", "--json") != 0 {
			return false
		}
		dl = daemon.DevicesResult{}
		decodeJSON(t, s.stdout.String(), &dl)
		return len(dl.Devices) > 0
	})
	out := map[string]bool{}
	for _, d := range dl.Devices {
		out[d.ID.String()] = true
	}
	return out
}

// The operator blocks a device that has a change queued. Status tells the
// way out. A logout refuses while changes are queued, then asks, saying
// how many are lost; a refusal changes nothing. The retirement goes
// through (a blocked device's own retirement is open to it), and the
// fresh sign-in names the old identity, says it is gone from the account,
// points to hop auth rotate, and runs nothing.
func TestBlockedDeviceSignsOutAndInAgain(t *testing.T) {
	m, sk := signedUpWithKey(t)
	w := m.w
	old := m.authStatus(t).DeviceID

	// A change queued while the server is away; the operator blocks the
	// device before the server is back, so the change never goes up.
	w.stop()
	m.must(t, nil, "edit", "web", "--address", "203.0.113.12")
	blockOnServer(t, w, old)
	w.start()
	out := waitOperatorLock(t, m, "blocked this device")
	mustContain(t, "hop status", out, "hop auth logout --discard-pending", "hop auth logout --local-only", "hop auth login",
		"master password and the current Secret Key", "hop auth devices revoke "+old, "hop auth rotate", "hop key rotate")
	s := &session{}
	m.hop(t, s, "auth", "status")
	mustContain(t, "hop auth status", s.stdout.String(), "hop auth logout --discard-pending", "hop auth devices revoke "+old)

	// A signed-in login points at the logout.
	s = &session{env: map[string]string{"HOP_PASSWORD": resolvePassword, "HOP_SECRET_KEY": sk}}
	if code := m.hop(t, s, "login", "--method", "password", "--server", w.origin, "--email", authEmail); code != 255 {
		t.Errorf("login on a signed-in machine: exit %d", code)
	}
	mustContain(t, "login on a blocked machine", s.stderr.String(), "operator blocked this device", "hop auth logout", "--local-only", "hop auth login")

	// Queued changes refuse a logout, and say how many.
	s = &session{}
	if code := m.hop(t, s, "logout", "--yes"); code != 255 {
		t.Errorf("logout with a queued change: exit %d", code)
	}
	mustContain(t, "the refusal", s.stderr.String(), "1 queued change(s)", "--discard-pending")
	if !hasVault(t, m) || len(predecessors(t, m)) != 0 {
		t.Fatal("a refused logout changed something")
	}

	// Declining the question changes nothing either; the question says
	// what is lost.
	waitOperatorLock(t, m, "blocked this device")
	s = &session{tty: true, answer: func(string) string { return "n" }}
	if code := m.hop(t, s, "logout", "--discard-pending"); code != 255 {
		t.Errorf("declined logout: exit %d", code)
	}
	mustContain(t, "the question", s.stderr.String(), "1 queued change(s)", "They are lost", "locked this device out", "not logged out")
	if !hasVault(t, m) || len(predecessors(t, m)) != 0 {
		t.Fatal("a declined logout changed something")
	}
	if a := m.authStatus(t); !a.SignedIn || a.DeviceID != old {
		t.Fatalf("after a declined logout: %+v", a)
	}

	// Accepted.
	waitOperatorLock(t, m, "blocked this device")
	s = &session{tty: true, answer: func(string) string { return "y" }}
	if code := m.hop(t, s, "logout", "--discard-pending"); code != 0 {
		t.Fatalf("logout: exit %d: %s", code, s.stderr.String())
	}
	mustContain(t, "the logout", s.stdout.String(), "Logged out", "1 queued change(s) were discarded", "hop auth login", "hop auth rotate")
	mustNotContain(t, "the logout", s.stdout.String(), "still in the account")
	if hasVault(t, m) {
		t.Fatal("the vault is still there")
	}
	ps := predecessors(t, m)
	if len(ps) != 1 || ps[0].DeviceID.String() != old || ps[0].Outcome != store.OutcomeCommitted || ps[0].Why != store.AdminDeviceBlocked || ps[0].Queued != 1 {
		t.Fatalf("predecessors %+v", ps)
	}

	// The fresh sign-in.
	login, run := passwordLogin(m, sk, "fresh")
	if code := run(t); code != 0 {
		t.Fatalf("login: exit %d: %s", code, login.stderr.String())
	}
	mustContain(t, "the login", login.stdout.String(), "Before this sign-in, this machine was device "+old, "blocked by the server's operator",
		"1 change(s) it had queued", "That logout removed it from the account", "hop auth rotate", "hop key rotate")
	mustNotContain(t, "the login", login.stdout.String(), "hop auth devices revoke")
	if a := m.authStatus(t); !a.SignedIn || a.DeviceID == old || a.DeviceID == "" {
		t.Errorf("after the login: %+v", a)
	}
	if ids := deviceIDs(t, m); ids[old] || len(ids) != 1 {
		t.Errorf("devices after the retirement and the login: %v", ids)
	}
	if ps := predecessors(t, m); len(ps) != 0 {
		t.Errorf("the note was not consumed: %+v", ps)
	}
	waitFor(t, 20*time.Second, "the queued edit is gone", func() bool {
		h := m.hosts(t)["web"]
		return len(h.Addresses) == 1 && h.Addresses[0] == "203.0.113.10"
	})
}

var revokeLine = regexp.MustCompile(`(?m)^ +(hop auth devices revoke [0-9a-f]+)$`)

// The server will not take the retirement (the device's head is behind
// the server's, and a blocked device cannot catch up): the logout stays
// pending and says what to do, --local-only wipes the device, and the
// next sign-in prints the exact command that cuts the old identity off.
// It runs nothing: the old identity is still listed until the user runs
// the command, and the command works.
func TestRefusedRetirementThenLocalOnlyThenRevokeFromTheNewDevice(t *testing.T) {
	m, sk := signedUpWithKey(t)
	w := m.w
	m2 := newMachine(t, w, "m2")
	if code := (func() int {
		s := &session{env: map[string]string{"HOP_PASSWORD": resolvePassword, "HOP_SECRET_KEY": sk}}
		return m2.hop(t, s, "login", "--method", "password", "--server", w.origin, "--email", authEmail, "--name", "m2")
	})(); code != 0 {
		t.Fatalf("m2 login: exit %d", code)
	}
	waitFor(t, 20*time.Second, "web on m2", func() bool { _, ok := m2.hosts(t)["web"]; return ok })
	old := m.authStatus(t).DeviceID
	blockOnServer(t, w, old)
	// The server's head moves past what the blocked device has verified.
	m2.must(t, nil, "edit", "web", "--address", "203.0.113.20")
	waitFor(t, 20*time.Second, "m2's queue drains", func() bool { return m2.syncState(t).Pending == 0 })
	waitOperatorLock(t, m, "blocked this device")

	s := &session{}
	if code := m.hop(t, s, "logout", "--yes"); code != 255 {
		t.Fatalf("logout: exit %d: %s", code, s.stderr.String())
	}
	mustContain(t, "the pending logout", s.stderr.String(), "not finished", "operator refused this device a session", "hop auth logout --local-only --discard-pending")
	if !hasVault(t, m) {
		t.Fatal("the vault was deleted by a logout that is still pending")
	}

	s = &session{}
	if code := m.hop(t, s, "logout", "--local-only", "--discard-pending", "--yes"); code != 0 {
		t.Fatalf("logout --local-only: exit %d: %s", code, s.stderr.String())
	}
	mustContain(t, "the local-only logout", s.stdout.String(), "The server was not told", "device "+old+" is still in the account",
		"hop auth login", "hop auth devices revoke "+old)
	if hasVault(t, m) {
		t.Fatal("the vault is still there")
	}
	ps := predecessors(t, m)
	if len(ps) != 1 || ps[0].DeviceID.String() != old || ps[0].Outcome != store.OutcomeUnknown || ps[0].Why != store.AdminDeviceBlocked {
		t.Fatalf("predecessors %+v", ps)
	}

	login, run := passwordLogin(m, sk, "fresh")
	if code := run(t); code != 0 {
		t.Fatalf("login: exit %d: %s", code, login.stderr.String())
	}
	out := login.stdout.String()
	mustContain(t, "the login", out, "Before this sign-in, this machine was device "+old, "blocked by the server's operator",
		"is still in the account", "(--local-only)", "Nothing was changed for you", "hop key rotate")
	mustNotContain(t, "the login", out, "That logout removed it")
	cmd := revokeLine.FindStringSubmatch(out)
	if cmd == nil || cmd[1] != "hop auth devices revoke "+old {
		t.Fatalf("the login did not print the exact command for %s:\n%s", old, out)
	}

	// Nothing ran: the old identity is still in the account, still noted.
	if ids := deviceIDs(t, m); !ids[old] {
		t.Errorf("the old device is gone before anyone revoked it: %v", ids)
	}
	if len(predecessors(t, m)) != 1 {
		t.Errorf("the note was consumed while the old device is still in the account: %+v", predecessors(t, m))
	}
	st := &session{}
	m.hop(t, st, "auth", "status")
	mustContain(t, "hop auth status", st.stdout.String(), "old device:", old, cmd[1])

	// The command works, and settles the note.
	rs := &session{
		tty: true, secrets: map[string]string{"Current master password: ": resolvePassword},
		answer: func(prompt string) string {
			if strings.HasSuffix(prompt, "[y/N] ") && !strings.Contains(prompt, "Rotate") {
				return "y"
			}
			if strings.HasSuffix(prompt, "[y/N] ") {
				return "n"
			}
			return ""
		},
	}
	if code := m.hop(t, rs, strings.Fields(cmd[1])[1:]...); code != 0 {
		t.Fatalf("%s: exit %d: %s", cmd[1], code, rs.stderr.String())
	}
	waitFor(t, 20*time.Second, "the old device leaves the list", func() bool { return !deviceIDs(t, m)[old] })
	waitFor(t, 20*time.Second, "hop auth status settles the note", func() bool {
		return len(m.authStatus(t).OldDevices) == 0 && len(predecessors(t, m)) == 0
	})
}

// An account the operator disabled: the logout still retires the device
// (the retirement does not need a session), the sign-in is refused while
// the account is disabled and keeps the note, and once it is enabled the
// sign-in reports the old identity, in JSON too.
func TestDisabledAccountLogoutThenLoginAfterEnable(t *testing.T) {
	m, sk := signedUpWithKey(t)
	w := m.w
	old := m.authStatus(t).DeviceID
	disableOnServer(t, w, "billing")
	out := waitOperatorLock(t, m, "disabled this account")
	mustContain(t, "hop status", out, "hop auth logout --discard-pending", "hop auth login", "the account is disabled")

	s := &session{}
	if code := m.hop(t, s, "logout", "--yes"); code != 0 {
		t.Fatalf("logout: exit %d: %s", code, s.stderr.String())
	}
	mustContain(t, "the logout", s.stdout.String(), "Logged out", "hop auth rotate")
	ps := predecessors(t, m)
	if len(ps) != 1 || ps[0].DeviceID.String() != old || ps[0].Why != store.AdminAccountDisabled || ps[0].Outcome != store.OutcomeCommitted {
		t.Fatalf("predecessors %+v", ps)
	}

	login, run := passwordLogin(m, sk, "fresh")
	if code := run(t); code == 0 {
		t.Fatal("a sign-in on a disabled account succeeded")
	}
	mustContain(t, "the refused login", login.stderr.String(), "disabled")
	if len(predecessors(t, m)) != 1 {
		t.Fatalf("a refused login consumed the note: %+v", predecessors(t, m))
	}

	enableOnServer(t, w)
	login, run = passwordLogin(m, sk, "fresh", "--json")
	if code := run(t); code != 0 {
		t.Fatalf("login after the enable: exit %d: %s", code, login.stderr.String())
	}
	var rep struct {
		DeviceID   string `json:"device_id"`
		OldDevices []struct {
			DeviceID string `json:"device_id"`
			Outcome  string `json:"outcome"`
			Why      string `json:"why"`
			Still    bool   `json:"still_in_account"`
			Command  string `json:"command"`
		} `json:"old_devices"`
	}
	decodeJSON(t, login.stdout.String(), &rep)
	if len(rep.OldDevices) != 1 || rep.OldDevices[0].DeviceID != old || rep.OldDevices[0].Why != store.AdminAccountDisabled ||
		rep.OldDevices[0].Outcome != store.OutcomeCommitted || rep.OldDevices[0].Still || rep.OldDevices[0].Command != "hop auth rotate" || rep.DeviceID == old {
		t.Errorf("login report %+v", rep)
	}
	if len(predecessors(t, m)) != 0 {
		t.Errorf("the note was not consumed: %+v", predecessors(t, m))
	}
}

// A device key sealed with a passphrase: a logout that tells the server
// has to sign with it. Without the passphrase it fails at once, names
// the variable and --local-only, and changes nothing. On a terminal it
// asks for the passphrase and goes through.
func TestSealedDeviceKeyLogoutOfABlockedDevice(t *testing.T) {
	w := newAuthWorld(t)
	m := newMachine(t, w, "sealed")
	env := map[string]string{store.PassphraseEnv: unlockPassphrase}
	initS := &session{env: env, secrets: map[string]string{"Master password: ": resolvePassword, "Repeat it: ": resolvePassword}}
	if code := m.hop(t, initS, "init", "--device-key-store", "file"); code != 0 {
		t.Fatalf("init: exit %d: %s", code, initS.stderr.String())
	}
	m.must(t, env, "auth", "signup", "--server", w.origin, "--email", authEmail, "--code", w.invite(t))
	m.must(t, env, "unlock")
	old := m.authStatus(t).DeviceID
	blockOnServer(t, w, old)
	waitOperatorLock(t, m, "blocked this device")

	s := &session{}
	if code := m.hop(t, s, "logout", "--yes"); code != 255 {
		t.Fatalf("logout without the passphrase: exit %d", code)
	}
	mustContain(t, "the refusal", s.stderr.String(), store.PassphraseEnv, "--local-only")
	if !hasVault(t, m) || len(predecessors(t, m)) != 0 {
		t.Fatal("a logout that could not sign changed something")
	}

	waitOperatorLock(t, m, "blocked this device", env)
	s = &session{tty: true, secrets: map[string]string{"Device passphrase: ": unlockPassphrase}, answer: func(string) string { return "y" }}
	if code := m.hop(t, s, "logout"); code != 0 {
		t.Fatalf("logout on a terminal: exit %d: %s", code, s.stderr.String())
	}
	mustContain(t, "the logout", s.stdout.String(), "Logged out")
	ps := predecessors(t, m)
	if hasVault(t, m) || len(ps) != 1 || ps[0].DeviceID.String() != old || ps[0].Outcome != store.OutcomeCommitted || ps[0].Why != store.AdminDeviceBlocked {
		t.Fatalf("after the logout: vault %v, predecessors %+v", hasVault(t, m), ps)
	}
}
