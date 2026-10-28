package cli

import "context"

// OfferKeyRotation is the end of hop auth devices revoke, for the tests.
func OfferKeyRotation(ctx context.Context, e *Env, asJSON bool) error {
	return offerKeyRotation(ctx, e, asJSON)
}
