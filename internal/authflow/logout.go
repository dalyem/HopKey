package authflow

import (
	"context"
	"errors"
	"fmt"

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
// store.ErrLogoutPending, and Logout again finishes it. A retired device
// whose cleanup failed part way (a keychain that refused a deletion, say)
// finishes it with Logout again, on the same store or after a restart.
//
// There is no token-machine logout: the store has no token mode yet
// (phase 4).
func Logout(ctx context.Context, env *Env, s *store.Store, opts store.LogoutOptions) (store.LogoutResult, error) {
	state, err := s.Retirement()
	if err != nil {
		return store.LogoutResult{}, err
	}
	if state == store.StateRetired {
		// Only the local cleanup is left, which resumes where it stopped.
		// It needs no server, and it may already have deleted the entries
		// the vault ID is read from.
		return s.Logout(ctx, nil, opts)
	}
	var r store.Retirer
	if env.Client != nil {
		// The vault to retire from: the verified state's while the vault is
		// unlocked; once RETIRING has locked it, the stored state's
		// (state.json), which only addresses the server: the resolution
		// checks the retirement journal's vault, taken from verified state,
		// against its own verified copy.
		si, err := s.ServerInfo()
		if err == nil && si.VaultID.IsZero() {
			err = fmt.Errorf("%w: the vault has no vault ID", store.ErrCorrupt)
		}
		if err != nil && !opts.LocalOnly {
			return store.LogoutResult{}, err
		}
		if err == nil {
			if si.Server != "" && si.Server != env.Client.Origin() {
				return store.LogoutResult{}, ErrServerMismatch
			}
			r = env.Client.Retirer(si.VaultID)
		}
	} else if !opts.LocalOnly {
		return store.LogoutResult{}, errors.New("authflow: a logout needs the server unless it is local-only")
	}
	var res store.LogoutResult
	err = env.retry(ctx, func() (err error) {
		res, err = s.Logout(ctx, r, opts)
		return err
	})
	return res, err
}
