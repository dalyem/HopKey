package cli

import (
	"context"
	"testing"
	"time"
)

// OfferKeyRotation is the end of hop auth devices revoke, for the tests.
func OfferKeyRotation(ctx context.Context, e *Env, asJSON bool) error {
	return offerKeyRotation(ctx, e, asJSON)
}

// SetRotateStepTimeout bounds each ssh run of hop key rotate by d until
// the test ends.
func SetRotateStepTimeout(t testing.TB, d time.Duration) {
	old := rotateStepTimeout
	rotateStepTimeout = d
	t.Cleanup(func() { rotateStepTimeout = old })
}
