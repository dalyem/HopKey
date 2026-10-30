//go:build !hopdev

package main

import (
	"context"
	"os"

	"github.com/dalyem/hopkey/internal/model"
	"github.com/dalyem/hopkey/internal/store"
)

// openStore opens the encrypted vault in $XDG_DATA_HOME/hop (or
// ~/.local/share/hop) and unlocks it with the device key. If the device key
// cannot be read the store comes back locked, so hop unlock --password can
// still reach it.
func openStore() (model.Store, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil, err
	}
	return store.Open(context.Background(), store.Config{DataDir: store.DefaultDataDir(home, os.Getenv)})
}
