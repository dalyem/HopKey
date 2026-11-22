//go:build hopdev

package main

import (
	"os"
	"path/filepath"

	"github.com/dalyem/hopkey/internal/model"
	"github.com/dalyem/hopkey/internal/model/devstore"
)

// openStore opens the development store: a plaintext JSON file. It exists only
// in builds made with -tags hopdev. HOPKEY_DEVSTORE overrides the path.
func openStore() (model.Store, error) {
	path := os.Getenv("HOPKEY_DEVSTORE")
	if path == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return nil, err
		}
		path = filepath.Join(home, ".local", "state", "hop", "devstore.json")
	}
	return devstore.Open(path)
}
