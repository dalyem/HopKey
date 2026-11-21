package cli_test

import (
	"context"
	"strings"
	"sync"
	"testing"
	"time"
)

// signedInMachine is a machine with a vault of its own, published as an
// account (a second machine of the same world signs in by approval).
func signedInMachine(t *testing.T, w *authWorld, name string) *machine {
	t.Helper()
	m := newMachine(t, w, name)
	initS := &session{secrets: map[string]string{"Master password: ": resolvePassword, "Repeat it: ": resolvePassword}}
	if code := m.hop(t, initS, "init"); code != 0 {
		t.Fatalf("init: exit %d: %s", code, initS.stderr.String())
	}
	m.must(t, nil, "auth", "signup", "--server", w.origin, "--email", authEmail, "--code", w.invite(t), "--json")
	return m
}

// login starts hop login on m in s, and returns the routing code it shows
// and a function that waits for the command's exit status.
func startLogin(t *testing.T, m *machine, s *session) (code string, exit func() int) {
	t.Helper()
	var wg sync.WaitGroup
	var status int
	wg.Add(1)
	go func() {
		defer wg.Done()
		status = m.hop(t, s, "login", "--server", m.w.origin, "--name", m.name)
	}()
	waitFor(t, 30*time.Second, "the routing code", func() bool { return routingLine.MatchString(s.stderr.String()) })
	return routingLine.FindStringSubmatch(s.stderr.String())[1], func() int { wg.Wait(); return status }
}

// A mistyped routing code is not an approval to resume: the new device it
// names does not exist, and the error says so.
func TestApproveWithAMistypedCodeSaysNoDeviceIsWaiting(t *testing.T) {
	w := newAuthWorld(t)
	m1 := signedInMachine(t, w, "m1")
	for _, code := range []string{"ZZZZZ-ZZZZZ", "AB"} {
		s := &session{}
		if got := m1.hop(t, s, "auth", "approve", code); got == 0 {
			t.Fatalf("approve %q: exit 0", code)
		}
		msg := s.stderr.String()
		if !strings.Contains(msg, "no new device is waiting with that code") || !strings.Contains(msg, "mistyped") {
			t.Errorf("approve %q: %q", code, msg)
		}
		if strings.Contains(msg, "resume") || strings.Contains(msg, "--abort") {
			t.Errorf("approve %q suggests resuming an approval that never started: %q", code, msg)
		}
	}
}

// The approver cannot tell that the new device cancelled: it says what it
// did, not that the device has the vault. A new device that confirmed the
// check code says what it waits for.
func TestApproveDoesNotClaimTheNewDeviceHasTheVault(t *testing.T) {
	w := newAuthWorld(t)
	m1 := signedInMachine(t, w, "m1")
	m2 := newMachine(t, w, "m2")
	approver := &session{tty: true, answer: func(string) string { return "yes" }}
	newcomer := &session{tty: true, answer: func(string) string { return "no" }}
	code, loginExit := startLogin(t, m2, newcomer)
	if got := m1.hop(t, approver, "auth", "approve", code); got != 0 {
		t.Fatalf("approve: exit %d: %s", got, approver.stderr.String())
	}
	if got := loginExit(); got == 0 {
		t.Fatal("the new device answered no, and login exited 0")
	}
	out := approver.stdout.String()
	if strings.Contains(out, "receives the vault now") || !strings.Contains(out, "once it has confirmed the check code") || !strings.Contains(out, "undelivered") {
		t.Errorf("approve output: %q", out)
	}
	if !strings.Contains(newcomer.stderr.String(), "check code was rejected") {
		t.Errorf("the new device's error: %q", newcomer.stderr.String())
	}
}

// After the approver answers no, the new device, which the relay cannot
// tell, says it waits for the approver, and what a no looks like from here.
func TestNewDeviceSaysItWaitsAfterTheApproverAnswersNo(t *testing.T) {
	w := newAuthWorld(t)
	m1 := signedInMachine(t, w, "m1")
	m2 := newMachine(t, w, "m2")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	approver := &session{tty: true, answer: func(string) string { return "no" }}
	newcomer := &session{tty: true, ctx: ctx, answer: func(string) string { return "yes" }}
	code, loginExit := startLogin(t, m2, newcomer)
	approveExit := m1.hop(t, approver, "auth", "approve", code)
	if approveExit == 0 || !strings.Contains(approver.stderr.String(), "codes did not match") {
		t.Fatalf("approve: exit %d: %s", approveExit, approver.stderr.String())
	}
	waitFor(t, 30*time.Second, "the new device to say it waits", func() bool {
		return strings.Contains(newcomer.stderr.String(), "Confirmed. Waiting for the approving device")
	})
	cancel()
	if got := loginExit(); got == 0 {
		t.Error("the cancelled login exited 0")
	}
}

// Three approvals that were cancelled before they finished hold the
// address's three places on the server for 10 minutes; the fourth says so
// instead of showing a bare 429.
func TestLoginWithAllApprovalPlacesTakenExplainsTheLimit(t *testing.T) {
	w := newAuthWorld(t)
	signedInMachine(t, w, "m1")
	m2 := newMachine(t, w, "m2")
	for i := range 3 {
		ctx, cancel := context.WithCancel(context.Background())
		s := &session{tty: true, ctx: ctx}
		_, exit := startLogin(t, m2, s)
		cancel()
		if got := exit(); got == 0 {
			t.Fatalf("cancelled login %d exited 0", i)
		}
	}
	s := &session{tty: true}
	if got := m2.hop(t, s, "login", "--server", w.origin, "--name", "m2"); got == 0 {
		t.Fatal("the fourth login exited 0")
	}
	msg := s.stderr.String()
	for _, want := range []string{"too many pending device approvals from this address", "10 minutes", "at the latest"} {
		if !strings.Contains(msg, want) {
			t.Errorf("stderr lacks %q:\n%s", want, msg)
		}
	}
	if strings.Contains(msg, "429") || strings.Contains(msg, "rate_limited") {
		t.Errorf("a bare status shows:\n%s", msg)
	}
}
