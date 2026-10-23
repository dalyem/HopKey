package store

import (
	"context"
	"errors"
	"testing"
)

// ServerInfo names the vault and its account whether or not the vault is
// unlocked, so the daemon can address the server before an unlock.
func TestServerInfoNamesTheVaultWhileLocked(t *testing.T) {
	f, _ := serverVault(t)
	want := f.s.state
	vaultID, accountID := want.VaultID, want.Account.AccountID

	si, err := f.s.ServerInfo()
	if err != nil || si.VaultID != vaultID || si.AccountID != accountID {
		t.Fatalf("unlocked: %+v %v; want vault %v account %v", si, err, vaultID, accountID)
	}
	f.s.Lock()
	si, err = f.s.ServerInfo()
	if err != nil || si.VaultID != vaultID || si.AccountID != accountID {
		t.Fatalf("locked: %+v %v; want vault %v account %v", si, err, vaultID, accountID)
	}
	if err := f.s.Unlock(context.Background()); err != nil {
		t.Fatal(err)
	}

	local := newVault(t, testConfig(t))
	if _, err := local.s.ServerInfo(); !errors.Is(err, ErrNotServerBacked) {
		t.Errorf("a local-only vault: %v", err)
	}
}
