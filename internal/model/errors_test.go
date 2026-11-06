package model

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

// These errors reach the user as typed (hop: vault is locked; run hop
// unlock), so they carry no package prefix. Callers match them with
// errors.Is, never by text.
func TestSentinelErrorsHaveNoPackagePrefix(t *testing.T) {
	for _, err := range []error{ErrLocked, ErrNotFound} {
		if strings.HasPrefix(err.Error(), "model:") {
			t.Errorf("%q has an internal package prefix", err)
		}
		wrapped := fmt.Errorf("%w; run hop unlock", err)
		if !errors.Is(wrapped, err) {
			t.Errorf("errors.Is no longer matches %q once wrapped", err)
		}
	}
}
