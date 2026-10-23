package authflow

import (
	"context"
	"errors"
	"fmt"

	"github.com/dalyem/hopkey/internal/crypto"
	"github.com/dalyem/hopkey/internal/store"
	"github.com/dalyem/hopkey/internal/syncclient"
	"github.com/dalyem/hopkey/internal/vaultlog"
)

// LoginOptions are hop auth login's inputs for the password and recovery
// methods.
type LoginOptions struct {
	Email string
	// DeviceName names this device in the account; empty means
	// Config.DeviceName, then the host name.
	DeviceName string
	// DeviceStore is where this device's key goes (store.DeviceStoreKeychain,
	// the default, or store.DeviceStoreFile). A merge keeps the local
	// vault's.
	DeviceStore string
	// Merge merges the local-only vault in the data directory into the
	// account (§4.4, hop auth login --merge). Without it, a login on a
	// machine with a local-only vault fails with ErrLocalVault.
	Merge bool
	// Local is the open local-only vault to merge, when the caller has it
	// open. Nil opens the data directory's.
	Local *store.Store
}

// LoginResult is a signed-in device.
type LoginResult struct {
	Vault *Vault
	// Merge is the login merge's status, when the login merged a local
	// vault. Its imports are queued in the outbox; the sync engine uploads
	// them.
	Merge *store.MergeStatus
	// Recovery is the recovery's checkpoint (§4.5), for a recovery login.
	Recovery *CheckpointResult
}

// LoginPassword signs this machine in with the master password and the
// Secret Key (§4.4): prelogin, the §4.1 keys, login, the latest creds'
// pw_blob, and the sign-in, which verifies the log and bootstraps this
// device. The result's store is the caller's to close.
func LoginPassword(ctx context.Context, env *Env, opts LoginOptions) (*LoginResult, error) {
	return login(ctx, env, opts, store.SignInPassword)
}

// LoginRecovery signs this machine in with the Recovery Key (§4.5), then
// runs the checkpoint a recovery must: new credentials under a new
// password, keeping only the survivors the user chooses (only this device
// by default), and a new Emergency Kit the user types back. It returns
// with no error only once that checkpoint committed and its kit is
// acknowledged. Until then the error matches ErrRecoveryIncomplete, the
// result still holds the signed-in vault, and the store allows no other
// checkpoint (store.ErrRecoveryDue); Resume, or LoginRecovery again,
// finishes it.
func LoginRecovery(ctx context.Context, env *Env, opts LoginOptions) (*LoginResult, error) {
	return login(ctx, env, opts, store.SignInRecovery)
}

func login(ctx context.Context, env *Env, opts LoginOptions, method store.SignInMethod) (_ *LoginResult, err error) {
	cfg, c := env.Config, env.Client
	res := &LoginResult{}
	local := opts.Local
	if local == nil {
		var exists bool
		if exists, err = store.Exists(cfg.DataDir); err != nil {
			return nil, err
		}
		if exists {
			if local, err = store.Open(ctx, cfg); err != nil {
				return nil, err
			}
			defer func() {
				if err != nil && res.Vault == nil {
					local.Close()
				}
			}()
		}
	}
	if local != nil && local.ServerBacked() {
		// A recovery whose checkpoint did not finish signs in no further:
		// it finishes the checkpoint.
		if si, err := local.ServerInfo(); err == nil && si.CheckpointDue && method == store.SignInRecovery {
			if res.Vault, err = NewVault(cfg, local, c); err != nil {
				return nil, err
			}
			if res.Recovery, err = recoveryCheckpoint(ctx, env, res.Vault); err != nil {
				return res, fmt.Errorf("%w: %w", ErrRecoveryIncomplete, err)
			}
			return res, nil
		}
		return nil, ErrSignedIn
	}
	if local != nil && !opts.Merge {
		return nil, ErrLocalVault
	}

	pre, err := c.Prelogin(ctx, opts.Email)
	if err != nil {
		return nil, err
	}
	var tr *syncclient.TokenRemote
	var acct *crypto.AccountKeys
	var sk string
	if method == store.SignInRecovery {
		tr, acct, err = openRecovery(ctx, env, pre)
		if err == nil {
			// The device record keeps a Secret Key (§11); the recovery's
			// checkpoint replaces it.
			sk, err = env.UI.SecretKey(ctx, ReasonLogin, false)
		}
	} else {
		tr, acct, sk, err = openPassword(ctx, env, pre)
	}
	if err != nil {
		if acct != nil {
			acct.Zero()
		}
		return nil, err
	}
	p := store.SignInParams{
		ServerURL: c.Origin(), Email: opts.Email, Account: acct, SecretKey: sk,
		DeviceName: opts.DeviceName, Method: method, DeviceStore: opts.DeviceStore,
	}
	var s *store.Store
	due := false
	if local != nil {
		if st, err := local.MergeStatus(); err != nil {
			acct.Zero()
			return nil, err
		} else if st == nil {
			if _, err := local.MergeStart(); err != nil {
				acct.Zero()
				return nil, err
			}
		}
		st, err := local.MergeSignIn(ctx, tr, p)
		if err != nil {
			return nil, err
		}
		res.Merge, s, due = &st, local, st.CheckpointDue
	} else {
		var sr store.SignInResult
		if s, sr, err = store.SignIn(ctx, cfg, tr, p); err != nil {
			return nil, err
		}
		due = sr.CheckpointDue
		defer func() {
			if err != nil && res.Vault == nil {
				s.Close()
			}
		}()
	}
	if res.Vault, err = newVault(s, c, tr.VaultID); err != nil {
		return nil, err
	}
	if due {
		if res.Recovery, err = recoveryCheckpoint(ctx, env, res.Vault); err != nil {
			return res, fmt.Errorf("%w: %w", ErrRecoveryIncomplete, err)
		}
	}
	return res, nil
}

// openPassword is the API part of the password method (§4.4): the §4.1
// keys from the password and the Secret Key, the login token, and the
// account keys from the latest creds' pw_blob. It returns the Secret Key
// for the device record.
func openPassword(ctx context.Context, env *Env, pre syncclient.Prelogin) (*syncclient.TokenRemote, *crypto.AccountKeys, string, error) {
	if pre.KDFVersion != crypto.KDFv1.Version {
		return nil, nil, "", fmt.Errorf("authflow: the account uses kdf_version %d, which this client does not support", pre.KDFVersion)
	}
	pw, err := env.UI.Password(ctx, ReasonLogin)
	if err != nil {
		return nil, nil, "", err
	}
	defer clear(pw)
	skText, err := env.UI.SecretKey(ctx, ReasonLogin, false)
	if err != nil {
		return nil, nil, "", err
	}
	sk, err := crypto.ParseSecretKey(skText)
	if err != nil {
		return nil, nil, "", fmt.Errorf("authflow: that is not a Secret Key: %w", err)
	}
	keys, err := crypto.DeriveLoginKeys(pw, pre.Salt, &sk, pre.AccountID, crypto.KDFv1)
	sk.Zero()
	if err != nil {
		return nil, nil, "", err
	}
	defer keys.Zero()
	var tr *syncclient.TokenRemote
	err = env.retry(ctx, func() (err error) {
		tr, err = env.Client.Login(ctx, pre.AccountID, keys.AuthKey[:])
		return err
	})
	if errors.Is(err, syncclient.ErrUnauthorized) {
		return nil, nil, "", ErrLoginFailed
	}
	if err != nil {
		return nil, nil, "", err
	}
	creds, akv, err := latestCreds(ctx, env, tr)
	if err != nil {
		return nil, nil, "", err
	}
	env2, err := object(ctx, env, tr, creds.PwBlobSHA256)
	if err != nil {
		return nil, nil, "", err
	}
	acct, err := crypto.OpenPwBlob(&keys.EncKey, env2, pre.AccountID, akv)
	if err != nil {
		return nil, nil, "", fmt.Errorf("authflow: the server's pw_blob does not open with the login keys: %w", err)
	}
	return tr, acct, skText, nil
}

// openRecovery is the API part of the recovery method (§4.5): r_auth from
// the Recovery Key, the recovery token, and the account keys from the
// latest creds' rk_blob.
func openRecovery(ctx context.Context, env *Env, pre syncclient.Prelogin) (*syncclient.TokenRemote, *crypto.AccountKeys, error) {
	text, err := env.UI.RecoveryKey(ctx)
	if err != nil {
		return nil, nil, err
	}
	rk, err := crypto.ParseRecoveryKey(text)
	if err != nil {
		return nil, nil, fmt.Errorf("authflow: that is not a Recovery Key: %w", err)
	}
	rkKey, rAuth, err := crypto.RecoveryKeys(rk[:], pre.AccountID)
	clear(rk[:])
	if err != nil {
		return nil, nil, err
	}
	defer clear(rkKey[:])
	defer clear(rAuth)
	var tr *syncclient.TokenRemote
	err = env.retry(ctx, func() (err error) {
		tr, err = env.Client.Recover(ctx, pre.AccountID, rAuth)
		return err
	})
	if errors.Is(err, syncclient.ErrUnauthorized) {
		return nil, nil, ErrRecoveryFailed
	}
	if err != nil {
		return nil, nil, err
	}
	creds, akv, err := latestCreds(ctx, env, tr)
	if err != nil {
		return nil, nil, err
	}
	blob, err := object(ctx, env, tr, creds.RkBlobSHA256)
	if err != nil {
		return nil, nil, err
	}
	acct, err := crypto.OpenRkBlob(&rkKey, blob, pre.AccountID, akv)
	if err != nil {
		return nil, nil, fmt.Errorf("authflow: the server's rk_blob does not open with the Recovery Key: %w", err)
	}
	return tr, acct, nil
}

// latestCreds is the creds op in effect at the head, and the account's
// akv, from the public state of the log read with the token. Nothing here
// is trusted: the blob it names must open, and the sign-in then verifies
// the log from the anchor of the keys it opened.
func latestCreds(ctx context.Context, env *Env, tr *syncclient.TokenRemote) (vaultlog.CredsOp, uint32, error) {
	var c0 store.Committed
	if err := env.retry(ctx, func() (err error) { c0, err = tr.EntryAt(ctx, 0); return err }); err != nil {
		return vaultlog.CredsOp{}, 0, err
	}
	objs := vaultlog.ObjectMap{}
	var pub *vaultlog.PublicState
	apply := func(w *vaultlog.Wire) error {
		for _, o := range w.Objects {
			objs[o.SHA256] = o.Body
		}
		var err error
		pub, err = vaultlog.ApplyPublic(pub, w, objs)
		return err
	}
	if err := apply(c0.Wire); err != nil {
		return vaultlog.CredsOp{}, 0, fmt.Errorf("authflow: the server's genesis entry: %w", err)
	}
	after := uint64(0)
	for {
		var entries []store.Committed
		var head vaultlog.Head
		err := env.retry(ctx, func() (err error) { entries, head, err = tr.Since(ctx, after); return err })
		if err != nil {
			return vaultlog.CredsOp{}, 0, err
		}
		for _, e := range entries {
			if e.Seq != after+1 {
				return vaultlog.CredsOp{}, 0, fmt.Errorf("authflow: the server sent seq %d after %d", e.Seq, after)
			}
			if err := apply(e.Wire); err != nil {
				return vaultlog.CredsOp{}, 0, fmt.Errorf("authflow: the server's entry %d: %w", e.Seq, err)
			}
			after = e.Seq
		}
		if after >= head.Seq {
			break
		}
		if len(entries) == 0 {
			return vaultlog.CredsOp{}, 0, fmt.Errorf("authflow: the server sent no entries past %d before its head %d", after, head.Seq)
		}
	}
	creds, ok := pub.Creds()
	acct, ok2 := pub.Account()
	if !ok || !ok2 {
		return vaultlog.CredsOp{}, 0, errors.New("authflow: the server's log has no credentials")
	}
	return creds, acct.AKV, nil
}

// object fetches an AEAD envelope from the object endpoint.
func object(ctx context.Context, env *Env, tr *syncclient.TokenRemote, h crypto.Hash) (crypto.AEADEnvelope, error) {
	var b []byte
	if err := env.retry(ctx, func() (err error) { b, err = tr.Object(ctx, h); return err }); err != nil {
		return crypto.AEADEnvelope{}, err
	}
	return crypto.ParseAEADEnvelope(b)
}
