package cli

import (
	"strings"
	"testing"

	"github.com/dalyem/hopkey/internal/store"
)

// hop status and hop auth status say the operator locked the vault, with
// the operator's message escaped and marked as the server's word, and
// that nothing was deleted.
func TestVaultStateOfAnAdminLock(t *testing.T) {
	for _, c := range []struct {
		lock *store.AdminRefusal
		want []string
	}{
		{&store.AdminRefusal{Code: store.AdminAccountDisabled, Reason: "billing\x1b[2J \u202eoverdue"},
			[]string{"locked: the server says its operator disabled this account", `The operator's message: "billing\x1b[2J \u202eoverdue"`,
				"the server's word, not your vault's", "Nothing was deleted", "enables the account", "hop unlock"}},
		{&store.AdminRefusal{Code: store.AdminAccountDisabled},
			[]string{"locked: the server's operator disabled this account. Nothing was deleted. Ask the server's operator"}},
		{&store.AdminRefusal{Code: store.AdminDeviceBlocked},
			[]string{"locked: the server's operator blocked this device", "unblocks this device"}},
	} {
		got := vaultState(&store.Info{Locked: true, ServerUnconfirmed: true, AdminLock: c.lock})
		for _, w := range c.want {
			if !strings.Contains(got, w) {
				t.Errorf("vaultState for %+v: %q lacks %q", c.lock, got, w)
			}
		}
		for _, r := range got {
			if r < ' ' || r == 0x7f || (r >= 0x80 && r < 0xa0) || r == '\u202e' {
				t.Errorf("raw %U in %q", r, got)
			}
		}
	}
	// A plain unconfirmed lock (a 401: a device the server doesn't know,
	// a deleted account's included) claims no operator's act, and says
	// whom to ask.
	got := vaultState(&store.Info{Locked: true, ServerUnconfirmed: true})
	for _, w := range []string{"locked: the server no longer confirms this device is in the account", "Nothing on this device was deleted",
		"hop unlock asks the server again", "check with the server's operator"} {
		if !strings.Contains(got, w) {
			t.Errorf("a plain unconfirmed lock: %q lacks %q", got, w)
		}
	}
	for _, w := range []string{"disabled", "blocked", "deleted this account", "revoked"} {
		if strings.Contains(got, w) {
			t.Errorf("a plain unconfirmed lock: %q says %q", got, w)
		}
	}
	// The daemon still holds the operator's refusal after another lock
	// replaced the reason (hop lock, an unlock that failed): status says
	// so, and that hop unlock opens it.
	lock := &store.AdminRefusal{Code: store.AdminDeviceBlocked, Reason: "lost"}
	got = vaultState(&store.Info{Locked: true, AdminLock: lock})
	if !strings.Contains(got, "operator blocked this device") || !strings.Contains(got, "(with hop unlock)") || strings.Contains(got, "by itself") {
		t.Errorf("an admin lock under hop lock: %q", got)
	}
	if got := vaultState(&store.Info{Locked: true, ServerUnconfirmed: true, AdminLock: lock}); !strings.Contains(got, "by itself") {
		t.Errorf("an admin lock the daemon retries: %q", got)
	}
}
