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
	if got := vaultState(&store.Info{Locked: true, ServerUnconfirmed: true}); strings.Contains(got, "operator") {
		t.Errorf("a plain unconfirmed lock: %q", got)
	}
}
