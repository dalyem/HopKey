package store

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// LogoutPreflight refuses as the store's logout guards do, from the files
// alone: a merge file, and a pending kit's journal, with the vault locked
// and with no store open at all. A logout already under way meets no
// guard, and neither does a vault with none of them.
func TestLogoutPreflightMatchesTheGuards(t *testing.T) {
	ctx := context.Background()

	f, _ := retireFixture(t)
	if err := LogoutPreflight(f.cfg.DataDir); err != nil {
		t.Errorf("a vault with nothing pending: %v", err)
	}

	m, _ := heldMerge(t)
	m.src.s.Lock()
	if err := LogoutPreflight(m.src.cfg.DataDir); !errors.Is(err, ErrMergeInProgress) {
		t.Errorf("a merge file, vault locked: %v", err)
	}

	g := newVault(t, testConfig(t))
	if _, err := g.s.ChangePassword(ctx, []byte(testPassword), []byte(newPassword)); err != nil {
		t.Fatal(err)
	}
	if err := g.s.EnableServerMode(); err != nil {
		t.Fatal(err)
	}
	g.s.Close()
	if err := LogoutPreflight(g.cfg.DataDir); !errors.Is(err, ErrCheckpointPending) {
		t.Errorf("a pending kit, no store open: %v", err)
	}
	// The store agrees, opened again and locked.
	s, err := Open(ctx, g.cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	s.Lock()
	if _, err := s.Logout(ctx, nil, LogoutOptions{DiscardPending: true, LocalOnly: true}); !errors.Is(err, ErrCheckpointPending) {
		t.Errorf("the store's logout with a pending kit, locked: %v", err)
	}

	// A server-backed checkpoint's journal refuses by its name too.
	h, _ := retireFixture(t)
	if err := os.WriteFile(filepath.Join(h.cfg.DataDir, "vault", checkpointRel), []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := LogoutPreflight(h.cfg.DataDir); !errors.Is(err, ErrCheckpointPending) {
		t.Errorf("a checkpoint journal: %v", err)
	}

	// A logout under way is resumed, not guarded.
	if err := os.WriteFile(filepath.Join(h.cfg.DataDir, "vault", retireRel), []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := LogoutPreflight(h.cfg.DataDir); err != nil {
		t.Errorf("a logout under way: %v", err)
	}
}
