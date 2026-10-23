package authflow

import (
	"context"
	"fmt"

	"github.com/dalyem/hopkey/internal/model"
	"github.com/dalyem/hopkey/internal/store"
	"github.com/dalyem/hopkey/internal/syncclient"
)

// SignupOptions are hop auth signup's inputs.
type SignupOptions struct {
	Email            string
	RegistrationCode string
	// DeviceStore is where a new vault keeps this device's key
	// (store.DeviceStoreKeychain, the default, or store.DeviceStoreFile).
	// Publishing an existing vault ignores it.
	DeviceStore string
	// Local is the open local-only vault to publish, when the caller has
	// it open. Nil opens the data directory's vault, or creates one when
	// there is none.
	Local *store.Store
}

// SignupResult is a published vault.
type SignupResult struct {
	Vault       *Vault
	Publication store.Publication
	// Created means signup created the vault (and the user confirmed its
	// Emergency Kit) rather than publishing an existing one. When it did
	// not, the existing kit stays valid: the user adds the server URL and
	// the email (Publication) to it.
	Created bool
}

// Signup creates the account on the server (§4.3). If the data directory
// holds a local-only vault, it publishes that vault as it is; otherwise it
// creates one first, as hop init does, with a new master password and an
// Emergency Kit the user must type back. A publication left pending (a
// crash, a lost response, an unreachable server) is resumed, whatever
// opts says.
//
// The result's store is the caller's to close; so is opts.Local in every
// case.
func Signup(ctx context.Context, env *Env, opts SignupOptions) (_ *SignupResult, err error) {
	cfg, c := env.Config, env.Client
	s, created := opts.Local, false
	if s == nil {
		var exists bool
		if exists, err = store.Exists(cfg.DataDir); err != nil {
			return nil, err
		}
		if exists {
			if s, err = store.Open(ctx, cfg); err != nil {
				return nil, err
			}
		} else {
			if s, err = initVault(ctx, env, opts.DeviceStore); err != nil {
				return nil, err
			}
			created = true
		}
		defer func() {
			if err != nil {
				s.Close()
			}
		}()
	}
	pending, err := s.Publication()
	if err != nil {
		return nil, err
	}
	var pub store.Publication
	switch {
	case pending != nil:
		if pending.Server != c.Origin() {
			return nil, fmt.Errorf("%w: a publication to %s is pending", ErrServerMismatch, pending.Server)
		}
		err = env.retry(ctx, func() (err error) {
			pub, err = s.ResumePublish(ctx, c.Publisher(pending.VaultID))
			return err
		})
	case s.ServerBacked():
		return nil, ErrSignedIn
	default:
		pub, err = s.Publish(ctx, c.Publisher(model.ID{}), store.PublishOptions{
			Server: c.Origin(), Email: opts.Email, RegistrationCode: opts.RegistrationCode,
		})
		if err != nil && syncclient.Retryable(err) {
			// The publication may be journaled: resolve it.
			postErr := err
			err = env.retry(ctx, func() error {
				p, err := s.Publication()
				if err != nil {
					return err
				}
				if p == nil {
					return postErr
				}
				pub, err = s.ResumePublish(ctx, c.Publisher(p.VaultID))
				return err
			})
		}
	}
	if err != nil {
		return nil, err
	}
	v, err := newVault(s, c, pub.VaultID)
	if err != nil {
		return nil, err
	}
	return &SignupResult{Vault: v, Publication: pub, Created: created}, nil
}

// initVault creates a local vault, as hop init does: a new master
// password, and the Emergency Kit typed back before anything is written.
func initVault(ctx context.Context, env *Env, deviceStore string) (*store.Store, error) {
	pw, err := env.UI.NewPassword(ctx, ReasonSignup)
	if err != nil {
		return nil, err
	}
	defer clear(pw)
	p, err := store.PrepareInit(env.Config, store.InitOptions{Password: pw, DeviceStore: deviceStore})
	if err != nil {
		return nil, err
	}
	if err := confirmKit(ctx, env.UI, p.Kit(), func() error { return nil }); err != nil {
		p.Discard()
		return nil, err
	}
	return p.Commit()
}
