package authflow

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/dalyem/hopkey/internal/model"
	"github.com/dalyem/hopkey/internal/store"
	"github.com/dalyem/hopkey/internal/syncclient"
)

// CheckpointResult is a committed checkpoint (§10.1) whose new Emergency
// Kit the user confirmed.
type CheckpointResult struct {
	// Kind is store.CheckpointPasswd, CheckpointRotate, CheckpointRevoke
	// or CheckpointRecovery.
	Kind string
	// Resumed means the flow finished a checkpoint an earlier run left
	// pending (its kit, or its journal) instead of starting the one asked
	// for: run the command again for a new one.
	Resumed bool
	// Devices are the active devices afterwards: the survivors.
	Devices []store.DeviceListing
}

// maxSecretKeyPrompts is how often a checkpoint asks for the Secret Key.
const maxSecretKeyPrompts = 2

// maxRounds bounds a checkpoint's answers to the store: Secret Key
// prompts, new-device questions and retries together.
const maxRounds = 8

// ckpt is one checkpoint the user asked for.
type ckpt struct {
	kind    string
	keep    []string // survivors besides this device, by ID
	targets []string // a revocation's, by ID once chosen
	current []byte   // the current master password
	next    []byte   // the new one, for passwd and recovery
	opts    store.CheckpointOptions
}

func (k *ckpt) zero() {
	clear(k.current)
	clear(k.next)
}

func reasonOf(kind string) Reason {
	switch kind {
	case store.CheckpointRotate:
		return ReasonRotate
	case store.CheckpointRevoke:
		return ReasonRevoke
	case store.CheckpointRecovery:
		return ReasonRecovery
	}
	return ReasonPasswd
}

// call runs k once through the store.
func (k *ckpt) call(ctx context.Context, v *Vault) (store.Kit, error) {
	s, r := v.Store, v.Remote
	opts := k.opts
	switch k.kind {
	case store.CheckpointPasswd:
		return s.ChangePasswordRemote(ctx, r, k.current, k.next, opts)
	case store.CheckpointRotate:
		opts.Keep = k.keep
		return s.Rotate(ctx, r, k.current, opts)
	case store.CheckpointRevoke:
		opts.Keep = k.keep
		return s.RevokeDevices(ctx, r, k.current, k.targets, opts)
	case store.CheckpointRecovery:
		opts.Keep = k.keep
		return s.RecoveryCheckpoint(ctx, r, k.next, opts)
	}
	return store.Kit{}, errors.New("authflow: unknown checkpoint kind " + k.kind)
}

// ChangePassword is hop auth passwd for a server-backed vault: a full
// checkpoint with a new master password that keeps every device (§10.1).
// It shows the device list, and asks about any device that appears while
// it runs.
func ChangePassword(ctx context.Context, env *Env, v *Vault) (*CheckpointResult, error) {
	return checkpoint(ctx, env, v, store.CheckpointPasswd, nil)
}

// Rotate is hop auth rotate: a full checkpoint that rotates every
// credential and keeps only this device and the survivors the user
// chooses (§10.1).
func Rotate(ctx context.Context, env *Env, v *Vault) (*CheckpointResult, error) {
	return checkpoint(ctx, env, v, store.CheckpointRotate, nil)
}

// RevokeDevices is hop auth devices revoke: a full checkpoint that revokes
// the devices targets names (each an ID or a unique name) and, as a
// response to compromise, every device the user does not keep (§10.1).
func RevokeDevices(ctx context.Context, env *Env, v *Vault, targets []string) (*CheckpointResult, error) {
	if len(targets) == 0 {
		return nil, errors.New("authflow: name at least one device to revoke")
	}
	return checkpoint(ctx, env, v, store.CheckpointRevoke, targets)
}

// recoveryCheckpoint is the checkpoint a recovery sign-in owes (§4.5).
func recoveryCheckpoint(ctx context.Context, env *Env, v *Vault) (*CheckpointResult, error) {
	return checkpoint(ctx, env, v, store.CheckpointRecovery, nil)
}

// checkpoint runs a checkpoint of kind end to end: a pending kit or a
// journaled checkpoint of the same kind is finished first; otherwise the
// survivors are chosen, the passwords asked for, the checkpoint committed
// through the server (asking about new devices and a missing or stale
// Secret Key on the way), and its kit shown, typed back and acknowledged.
func checkpoint(ctx context.Context, env *Env, v *Vault, kind string, targets []string) (*CheckpointResult, error) {
	s := v.Store
	self := s.Info().DeviceID
	// A committed checkpoint's kit comes first: nothing else may run while
	// it is pending.
	if kit := s.PendingKit(); kit != nil {
		return finishKit(ctx, env, v, *kit, kindOfPending(s, kind), true)
	}
	k := &ckpt{kind: kind, targets: targets}
	defer k.zero()
	resumed := false
	st, err := s.PendingCheckpoint()
	if err != nil {
		return nil, err
	}
	if st != nil {
		if st.Kind != kind {
			return nil, &store.CheckpointPendingError{Kind: st.Kind}
		}
		resumed = true
		// A candidate that committed, or can still commit as it is, needs
		// no password.
		if kit, err := resumeCheckpoint(ctx, env, v); err == nil {
			return finishKit(ctx, env, v, kit, kind, true)
		} else if !errors.Is(err, store.ErrCheckpointRebuild) {
			return nil, err
		}
		// The rebuild reuses the journaled choices.
		if kind != store.CheckpointPasswd {
			k.keep = others(idStrings(st.Survivors), self)
		}
		if kind == store.CheckpointRevoke {
			k.targets = idStrings(st.Targets)
		}
	} else if err := choose(ctx, env, v, k, self); err != nil {
		return nil, err
	}

	r := reasonOf(kind)
	if kind != store.CheckpointRecovery {
		if k.current, err = env.UI.Password(ctx, r); err != nil {
			return nil, err
		}
	}
	if kind == store.CheckpointPasswd || kind == store.CheckpointRecovery {
		if k.next, err = env.UI.NewPassword(ctx, r); err != nil {
			return nil, err
		}
	}

	var kit store.Kit
	skPrompts, retries := 0, 0
	for round := 0; ; round++ {
		if round == maxRounds {
			return nil, err
		}
		kit, err = k.call(ctx, v)
		var nd *store.NewDevicesError
		switch {
		case err == nil:
			return finishKit(ctx, env, v, kit, kind, resumed)
		case errors.As(err, &nd):
			if err := answerNewDevices(ctx, env, v, k, nd.Devices); err != nil {
				return nil, err
			}
		case errors.Is(err, store.ErrNeedSecretKey) && skPrompts < maxSecretKeyPrompts:
			skPrompts++
			sk, uerr := env.UI.SecretKey(ctx, r, errors.Is(err, store.ErrSecretKeyStale))
			if uerr != nil {
				return nil, uerr
			}
			k.opts.SecretKey = sk
		case syncclient.Retryable(err) && retries < env.retries():
			// The candidate is journaled: the next call posts it again.
			if err := sleep(ctx, env.backoff(retries)); err != nil {
				return nil, err
			}
			retries++
		default:
			return nil, err
		}
	}
}

// choose asks for the survivors (§10.1): a password change keeps every
// device and shows them; the others keep only this device and the ones
// the user chooses. Every reference, a revocation's targets included, is
// resolved here, once, against the list the user was shown, and only
// device IDs go to the store: a name resolved again after a later pull
// could pick a device that joined meanwhile under the same name.
func choose(ctx context.Context, env *Env, v *Vault, k *ckpt, self string) error {
	// The list is the verified state's: bring it up to date first.
	if err := env.retry(ctx, func() error { return v.Store.Pull(ctx, v.Remote) }); err != nil {
		return err
	}
	devices, err := v.Store.Devices()
	if err != nil {
		return err
	}
	if k.kind == store.CheckpointPasswd {
		return env.UI.ShowDevices(ctx, devices)
	}
	var targets []model.ID
	if k.kind == store.CheckpointRevoke {
		if targets, err = resolveListed(devices, k.targets); err != nil {
			return err
		}
		k.targets = idStrings(targets)
	}
	refs, err := env.UI.ChooseSurvivors(ctx, SurvivorChoice{Kind: k.kind, Devices: devices, Targets: targets})
	if err != nil {
		return err
	}
	keep, err := resolveListed(devices, refs)
	if err != nil {
		return err
	}
	k.keep = others(idStrings(keep), self)
	return nil
}

// resolveListed resolves device references against listed, the devices
// the user was shown: each a listed device's ID, or a name exactly one
// listed device has. The errors are the store's (store.ErrUnknownDevice,
// store.ErrAmbiguousDevice).
func resolveListed(listed []store.DeviceListing, refs []string) ([]model.ID, error) {
	var out []model.ID
	for _, ref := range refs {
		ref = strings.TrimSpace(ref)
		if ref == "" {
			continue
		}
		var found []model.ID
		if id, err := model.ParseID(ref); err == nil {
			if slices.ContainsFunc(listed, func(d store.DeviceListing) bool { return d.ID == id }) {
				found = append(found, id)
			}
		} else {
			for _, d := range listed {
				if d.Name == ref {
					found = append(found, d.ID)
				}
			}
		}
		switch len(found) {
		case 0:
			return nil, fmt.Errorf("%w: %q is not among the devices listed", store.ErrUnknownDevice, ref)
		case 1:
		default:
			return nil, fmt.Errorf("%w: %q names %d devices", store.ErrAmbiguousDevice, ref, len(found))
		}
		if !slices.Contains(out, found[0]) {
			out = append(out, found[0])
		}
	}
	return out, nil
}

// answerNewDevices asks which devices that appeared during a password
// change to keep; the rest are revoked (§10.1). The answers add to the
// earlier ones, which the journal holds. The user answers about the
// devices listed, by ID; any other ID is refused.
func answerNewDevices(ctx context.Context, env *Env, v *Vault, k *ckpt, ids []model.ID) error {
	all, err := v.Store.Devices()
	if err != nil {
		return err
	}
	var listed []store.DeviceListing
	for _, d := range all {
		if slices.Contains(ids, d.ID) {
			listed = append(listed, d)
		}
	}
	keep, err := env.UI.ConfirmNewDevices(ctx, listed)
	if err != nil {
		return err
	}
	for _, id := range keep {
		if !slices.ContainsFunc(listed, func(d store.DeviceListing) bool { return d.ID == id }) {
			return fmt.Errorf("%w: %v is not among the new devices listed", store.ErrUnknownDevice, id)
		}
	}
	for _, id := range ids {
		ref := id.String()
		if slices.Contains(keep, id) {
			k.opts.Keep = append(k.opts.Keep, ref)
		} else {
			k.opts.Exclude = append(k.opts.Exclude, ref)
		}
	}
	return nil
}

// resumeCheckpoint finishes a journaled checkpoint without a password,
// retrying a request that failed in a retryable way.
func resumeCheckpoint(ctx context.Context, env *Env, v *Vault) (store.Kit, error) {
	var kit store.Kit
	err := env.retry(ctx, func() (err error) {
		kit, err = v.Store.ResumeCheckpoint(ctx, v.Remote)
		return err
	})
	return kit, err
}

// finishKit shows a committed checkpoint's kit, has it typed back and
// acknowledges it.
func finishKit(ctx context.Context, env *Env, v *Vault, kit store.Kit, kind string, resumed bool) (*CheckpointResult, error) {
	if err := confirmKit(ctx, env.UI, kit, v.Store.AckKit); err != nil {
		return nil, err
	}
	devices, err := v.Store.Devices()
	if err != nil {
		return nil, err
	}
	return &CheckpointResult{Kind: kind, Resumed: resumed, Devices: devices}, nil
}

// kindOfPending is the kind of the checkpoint whose kit is pending, as far
// as the store tells; def otherwise.
func kindOfPending(s *store.Store, def string) string {
	if st, err := s.PendingCheckpoint(); err == nil && st != nil {
		return st.Kind
	}
	return def
}

// ResumeResult says what Resume finished.
type ResumeResult struct {
	// Publication is a publication that was pending (§4.3).
	Publication *store.Publication
	// Checkpoint is a checkpoint that was pending: its kit, its journal,
	// or a recovery's mandatory checkpoint.
	Checkpoint *CheckpointResult
}

// Resume finishes what an earlier flow left pending on a signed-in vault
// (hop auth resume): a recovery's checkpoint, a journaled checkpoint
// (reposted as it is, or rebuilt with the passwords and the journaled
// survivors), or a kit waiting to be confirmed. A pending publication is
// Signup's to resume. With nothing pending it returns a zero result.
func Resume(ctx context.Context, env *Env, v *Vault) (*ResumeResult, error) {
	s := v.Store
	res := &ResumeResult{}
	si, err := s.ServerInfo()
	if err != nil {
		return nil, err
	}
	st, err := s.PendingCheckpoint()
	if err != nil {
		return nil, err
	}
	kind := ""
	switch {
	case st != nil:
		kind = st.Kind
	case si.CheckpointDue:
		kind = store.CheckpointRecovery
	case s.PendingKit() != nil:
		kind = store.CheckpointPasswd
	default:
		return res, nil
	}
	var targets []string
	if st != nil {
		targets = idStrings(st.Targets)
	}
	if res.Checkpoint, err = checkpoint(ctx, env, v, kind, targets); err != nil {
		return nil, err
	}
	res.Checkpoint.Resumed = true
	return res, nil
}

func (env *Env) retries() int {
	if env.Retries <= 0 {
		return 3
	}
	return env.Retries
}

// backoff is the delay before retry n (from 0).
func (env *Env) backoff(n int) time.Duration {
	d := env.Backoff
	if d <= 0 {
		d = 500 * time.Millisecond
	}
	return d << n
}
