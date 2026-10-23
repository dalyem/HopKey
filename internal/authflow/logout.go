package authflow

import (
	"context"
	"errors"

	"github.com/dalyem/hopkey/internal/store"
)

// Logout is hop auth logout (§11.1): it retires this device from the
// account with a signed device_retire through the server, then deletes its
// keys and the local vault. opts.DiscardPending drops queued edits;
// opts.LocalOnly wipes the device without the server (the result's
// RevokeElsewhere then says to revoke it from another device). It also
// resumes a logout in progress, which keeps the vault locked: s need not be
// unlocked, and env.Client may be nil for LocalOnly.
//
// A logout whose outcome the server can't tell yet is retried while the
// failure is retryable; after that the error matches
// store.ErrLogoutPending, and Logout again finishes it.
//
// There is no token-machine logout: the store has no token mode yet
// (phase 4).
func Logout(ctx context.Context, env *Env, s *store.Store, opts store.LogoutOptions) (store.LogoutResult, error) {
	var r store.Retirer
	if env.Client != nil {
		id, err := vaultIDOf(env.Config.DataDir)
		if err != nil && !opts.LocalOnly {
			return store.LogoutResult{}, err
		}
		if err == nil {
			if si, err := s.ServerInfo(); err == nil && si.Server != "" && si.Server != env.Client.Origin() {
				return store.LogoutResult{}, ErrServerMismatch
			}
			r = env.Client.Retirer(id)
		}
	} else if !opts.LocalOnly {
		return store.LogoutResult{}, errors.New("authflow: a logout needs the server unless it is local-only")
	}
	var res store.LogoutResult
	err := env.retry(ctx, func() (err error) {
		res, err = s.Logout(ctx, r, opts)
		return err
	})
	return res, err
}
