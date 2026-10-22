//go:build !hopdev

package main

import (
	"errors"

	"github.com/dalyem/hopkey/internal/model"
)

// openStore is where the encrypted store plugs in. Until it lands, a normal
// build has no vault to open.
func openStore() (model.Store, error) {
	return nil, errors.New("this build has no vault store yet (the encrypted store is not wired in); development builds use -tags hopdev")
}
