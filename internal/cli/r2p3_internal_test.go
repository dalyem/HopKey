package cli

import (
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/dalyem/hopkey/internal/crypto"
)

// The new device cannot see that the approver refused because its hourly
// approvals are used up, so after a while it says what else can be done.
func TestWaitingForAnApprovalHintsAtThePasswordMethod(t *testing.T) {
	f := newUIFixture(t, true, "", nil)
	f.u.waitHintAfter = 20 * time.Millisecond
	if err := f.u.ShowRoutingCode(t.Context(), "ABCDEFGHJK"); err != nil {
		t.Fatal(err)
	}
	time.Sleep(300 * time.Millisecond)
	f.u.stopWaitHint() // also orders the timer's write before this read
	out := f.stderr.String()
	if !strings.Contains(out, "Waiting for the approval") || !strings.Contains(out, "--method password") || !strings.Contains(out, "approval attempts of the hour") {
		t.Errorf("no hint after the wait:\n%s", out)
	}
	wantDiscardThenPassword(t, out)
}

// An approval that arrives in time prints no hint.
func TestNoHintOnceTheCheckCodeIsShown(t *testing.T) {
	f := newUIFixture(t, true, "yes\n", nil)
	f.u.waitHintAfter = 100 * time.Millisecond
	if err := f.u.ShowRoutingCode(t.Context(), "ABCDEFGHJK"); err != nil {
		t.Fatal(err)
	}
	if _, err := f.u.ConfirmSAS(t.Context(), testSAS, "laptop"); err != nil {
		t.Fatal(err)
	}
	time.Sleep(300 * time.Millisecond)
	f.u.stopWaitHint()
	if strings.Contains(f.stderr.String(), "--method password") {
		t.Errorf("a hint after the approval arrived:\n%s", f.stderr.String())
	}
}

// The password method refuses to start while the approval login is
// unfinished, so a hint that sends the user straight to it sends them into a
// refusal: it says to cancel, discard, then sign in.
func wantDiscardThenPassword(t *testing.T, text string) {
	t.Helper()
	cancel := strings.Index(text, "Ctrl-C")
	discard := strings.Index(text, "hop auth login --discard")
	password := strings.Index(text, "hop auth login --method password")
	if cancel < 0 || discard < 0 || password < 0 || !(cancel < discard && discard < password) {
		t.Errorf("want Ctrl-C, then hop auth login --discard, then hop auth login --method password, in that order:\n%s", text)
	}
}

func TestApproverBudgetFailureSaysWhenToTryAgain(t *testing.T) {
	err := budgetFailure(fmt.Errorf("approving: %w", &crypto.BudgetExhaustedError{RetryAfter: 23*time.Minute + 30*time.Second}))
	var ee *exitError
	if !errors.As(err, &ee) {
		t.Fatalf("not an exit error: %v", err)
	}
	for _, want := range []string{"3 attempts per rolling hour", "about 24 minute", "--method password"} {
		if !strings.Contains(ee.msg, want) {
			t.Errorf("%q does not say %q", ee.msg, want)
		}
	}
	wantDiscardThenPassword(t, ee.msg)
}

func TestClosestCommand(t *testing.T) {
	for word, want := range map[string]string{
		"lst": "ls", "stauts": "status", "sync": "sync", "stat": "status", "ssh-command": "", "t2inner": "",
	} {
		if got := closestCommand(word); got != want {
			t.Errorf("closestCommand(%q) = %q, want %q", word, got, want)
		}
	}
}
