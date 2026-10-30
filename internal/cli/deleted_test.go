package cli_test

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/dalyem/hopkey/internal/server"
	"github.com/dalyem/hopkey/internal/store"
)

// deleteAccount deletes m's account on its server as hop-server accounts
// delete does, after the disable it needs, without a backup.
func deleteAccount(t *testing.T, m *machine) {
	t.Helper()
	ctx := context.Background()
	op := server.Operator{Actor: "test", Now: time.Now().UTC()}
	dis, err := server.PlanDisable(ctx, m.w.st, authEmail, op)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := server.DisableAccount(ctx, m.w.st, op, authEmail, "", dis); err != nil {
		t.Fatal(err)
	}
	del, err := server.PlanDelete(ctx, m.w.st, authEmail, op, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := server.DeleteAccount(ctx, m.w.st, op, del, server.DeleteOptions{NoBackup: true}); err != nil {
		t.Fatal(err)
	}
}

// hop logout on a device whose account the operator deleted can't be
// recorded by the server: it says so and how to give up on it, and
// deletes nothing; hop logout --local-only then wipes the device.
func TestLogoutOfADeletedAccount(t *testing.T) {
	m := signedUp(t)
	deleteAccount(t, m)
	s := &session{}
	if code := m.hop(t, s, "logout", "--yes"); code == 0 || !strings.Contains(s.stderr.String(), "operator deleted this account") ||
		!strings.Contains(s.stderr.String(), "hop auth logout --local-only") {
		t.Fatalf("logout of a deleted account: exit %d: %s", code, s.stderr.String())
	}
	if ok, err := store.Exists(m.data); err != nil || !ok {
		t.Fatalf("the pending logout deleted the vault: %v, %v", ok, err)
	}
	s = &session{}
	if code := m.hop(t, s, "logout", "--local-only", "--yes"); code != 0 {
		t.Fatalf("logout --local-only: exit %d: %s", code, s.stderr.String())
	}
	if ok, _ := store.Exists(m.data); ok {
		t.Error("logout --local-only left the vault")
	}
}
