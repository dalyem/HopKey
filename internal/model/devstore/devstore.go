//go:build hopdev

package devstore

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/dalyem/hopkey/internal/model"
	"github.com/dalyem/hopkey/internal/model/modeltest"
	"github.com/dalyem/hopkey/internal/safepath"
)

// Marker prefixes every error this package returns, so it appears in a binary
// only when the package is compiled in. A test looks for it in a normal build
// to prove the tag keeps the dev store out.
const Marker = "hopkey devstore (plaintext, development only)"

// Open loads the vault at path (creating an empty one) and returns a store
// that writes every change back to it. The file is mode 0600 and holds
// private keys in the clear.
func Open(path string) (model.Store, error) {
	if _, err := safepath.EnsurePrivateDir(filepath.Dir(path)); err != nil {
		return nil, fmt.Errorf("%s: %s: %w", Marker, path, err)
	}
	var snap model.Snapshot
	data, err := os.ReadFile(path)
	switch {
	case err == nil:
		if err := json.Unmarshal(data, &snap); err != nil {
			return nil, fmt.Errorf("%s: %s: %w", Marker, path, err)
		}
	case !errors.Is(err, os.ErrNotExist):
		return nil, err
	}
	s := modeltest.NewFrom(snap)
	s.Persist = func(snap model.Snapshot) error { return write(path, snap) }
	return s, nil
}

func write(path string, snap model.Snapshot) error {
	data, err := json.MarshalIndent(snap, "", "  ")
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".devstore.tmp*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}
