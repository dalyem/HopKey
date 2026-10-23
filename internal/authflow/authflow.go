// Package authflow runs hop auth's account and device flows end to end
// (crypto spec rev 16 §4.3–4.5, §7, §10.1, §11; design "Signing in: hop
// auth") on top of the store and the sync client: signup, password and
// recovery login, enrollment by approval on both devices, logout, and the
// server-backed checkpoints.
//
// The package has no UI of its own. Every secret and every decision comes
// from the caller's UI, and every flow returns typed results and errors.
// It prints nothing, touches no TTY and reads no environment variable.
//
// The checks that matter for safety stay here, not in the UI: the
// Emergency Kit is acknowledged only once the user typed back the final
// group of both keys, a rejected SAS ends the attempt before anything is
// installed or delivered, and a recovery login is reported done only once
// its checkpoint committed and its kit was acknowledged.
package authflow

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/dalyem/hopkey/internal/model"
	"github.com/dalyem/hopkey/internal/store"
	"github.com/dalyem/hopkey/internal/syncclient"
	"github.com/dalyem/hopkey/internal/vaultlog"
)

// Reason says why a flow asks for a secret, so the UI can word the prompt.
type Reason string

const (
	ReasonSignup   Reason = "signup"   // a new account's master password
	ReasonLogin    Reason = "login"    // a password or recovery login (§4.4, §4.5)
	ReasonRecovery Reason = "recovery" // the recovery's checkpoint (§4.5)
	ReasonPasswd   Reason = "passwd"   // hop auth passwd
	ReasonRotate   Reason = "rotate"   // hop auth rotate
	ReasonRevoke   Reason = "revoke"   // hop auth devices revoke
)

// SurvivorChoice is what the user chooses survivors from (§10.1): every
// active device, with its ID, because names are not unique.
type SurvivorChoice struct {
	// Kind is store.CheckpointRotate, store.CheckpointRevoke or
	// store.CheckpointRecovery.
	Kind string
	// Devices are the active devices, oldest first; This marks this
	// device, which always survives.
	Devices []store.DeviceListing
	// Targets are the devices a revocation names; they never survive.
	Targets []model.ID
}

// KitTypeBack is what the user typed back from a new Emergency Kit: the
// final group of each key (§4.3, §12).
type KitTypeBack struct {
	SecretKey   string
	RecoveryKey string
}

// UI is every point where a flow needs the user. A method that cannot get
// an answer (no TTY and no flag, say) returns an error, which the flow
// returns as it is, or wrapped, to its caller, which may print or log it.
// An implementation must therefore never put a secret (a password, a
// Secret Key, a Recovery Key, a kit) into an error it returns. Secrets are
// returned as fresh slices the flow may clear.
type UI interface {
	// Password asks for the current master password.
	Password(ctx context.Context, r Reason) ([]byte, error)
	// NewPassword asks for a new master password (the UI has it entered
	// twice).
	NewPassword(ctx context.Context, r Reason) ([]byte, error)
	// SecretKey asks for the account's Secret Key from the Emergency Kit.
	// stale means the one this device stores was replaced by a checkpoint:
	// the user needs the newest kit's.
	SecretKey(ctx context.Context, r Reason, stale bool) (string, error)
	// RecoveryKey asks for the Recovery Key from the Emergency Kit.
	RecoveryKey(ctx context.Context) (string, error)

	// ShowRoutingCode shows the code the user carries to the approving
	// device (hop auth approve CODE).
	ShowRoutingCode(ctx context.Context, code string) error
	// ConfirmSAS shows the 8-digit code and the device name and asks
	// whether the other device shows the same digits (§7 step 4).
	ConfirmSAS(ctx context.Context, sas, deviceName string) (bool, error)

	// ShowDevices lists the active devices before a password change,
	// which keeps them all (§10.1).
	ShowDevices(ctx context.Context, devices []store.DeviceListing) error
	// ChooseSurvivors returns the devices to keep besides this one, by ID
	// (or a name exactly one device has), from c.Devices: the flow resolves
	// them against that list at once and refuses any other. Nil keeps
	// only this device.
	ChooseSurvivors(ctx context.Context, c SurvivorChoice) ([]string, error)
	// ConfirmNewDevices asks which of the devices that appeared during a
	// password change to keep (§10.1), by ID from devices. Every one it
	// does not return is revoked.
	ConfirmNewDevices(ctx context.Context, devices []store.DeviceListing) ([]model.ID, error)

	// ShowKit shows a new Emergency Kit.
	ShowKit(ctx context.Context, kit store.Kit) error
	// ConfirmKit asks the user to type back the final group of each key
	// of the kit just shown. attempt counts from 1.
	ConfirmKit(ctx context.Context, attempt int) (KitTypeBack, error)
}

// Env is what every flow runs with.
type Env struct {
	// Config is the store configuration of this machine's data directory.
	Config store.Config
	// Client talks to the server; its origin is the server URL the flows
	// record.
	Client *syncclient.Client
	UI     UI
	// Retries is how often a flow retries a request that failed in a
	// retryable way (syncclient.Retryable). Zero means 3.
	Retries int
	// Backoff is the first retry's delay, doubled each time. Zero means
	// 500ms.
	Backoff time.Duration
}

// Errors of the flows.
var (
	// ErrLocalVault means this machine holds a local-only vault: a login
	// refuses unless it merges (LoginOptions.Merge, §4.4), and enrollment
	// by approval can't merge (use the password method).
	ErrLocalVault = errors.New("authflow: this device has a local-only vault; sign in with --merge to merge it into the account")
	// ErrSignedIn means this machine is already signed in to a server.
	ErrSignedIn = errors.New("authflow: this device is already signed in")
	// ErrNotSignedIn means the vault is local-only.
	ErrNotSignedIn = errors.New("authflow: this device is not signed in to a server")
	// ErrServerMismatch means the vault syncs with another server than
	// the client's.
	ErrServerMismatch = errors.New("authflow: the vault is signed in to another server")
	// ErrLoginFailed means the server refused the login: a wrong password
	// or Secret Key, or an unknown email (the server does not say which,
	// R4). It matches store.ErrWrongPassword.
	ErrLoginFailed = fmt.Errorf("%w (or no account has that email)", store.ErrWrongPassword)
	// ErrRecoveryFailed means the server refused the Recovery Key, or no
	// account has that email.
	ErrRecoveryFailed = errors.New("authflow: wrong Recovery Key (or no account has that email)")
	// ErrKitNotConfirmed means the user did not type back the kit's final
	// groups. The kit stays pending; Resume shows it again.
	ErrKitNotConfirmed = errors.New("authflow: the Emergency Kit was not confirmed; it stays pending until you confirm it")
	// ErrRecoveryIncomplete means a recovery login signed in but its
	// mandatory checkpoint (§4.5) has not finished. The device is signed
	// in, and only that checkpoint is allowed; Resume finishes it.
	ErrRecoveryIncomplete = errors.New("authflow: the recovery is not finished: set a new password to finish it")
	// ErrSASMismatch means the user said the two devices show different
	// codes. The attempt is over and nothing was delivered.
	ErrSASMismatch = errors.New("authflow: the codes did not match; the approval was cancelled")
	// ErrApprovalFailed means this device's approval for that routing code
	// already failed (a mismatch, an abort, the deadline): the new device
	// must start a new enrollment.
	ErrApprovalFailed = errors.New("authflow: the approval for that code already failed; start again on the new device")
	// ErrEnrollmentInterrupted means an enrollment in progress can't be
	// continued: its mailbox credential exists only in memory (store gap
	// G2), and this process does not have it. Start again with
	// EnrollOptions.Restart.
	ErrEnrollmentInterrupted = errors.New("authflow: an enrollment by approval was interrupted and can't be continued; start it again")
	// ErrNeedVaultID means enrollment by approval was started without the
	// account's vault ID, which the new device can't learn from the API
	// (gap G1).
	ErrNeedVaultID = errors.New("authflow: enrollment by approval needs the account's vault ID")
)

// EnrollInterruptedError means an enrollment stopped before it finished,
// in a state the same process can resume: pass Mailbox in
// EnrollOptions.Mailbox within the mailbox's lifetime.
type EnrollInterruptedError struct {
	Mailbox *syncclient.Mailbox
	Err     error
}

func (e *EnrollInterruptedError) Error() string {
	return "authflow: the enrollment was interrupted: " + e.Err.Error()
}

func (e *EnrollInterruptedError) Unwrap() error { return e.Err }

// Vault is a signed-in store with its server.
type Vault struct {
	Store   *store.Store
	Client  *syncclient.Client
	VaultID model.ID
	// Remote is the vault under this device's sessions, which the
	// checkpoints and approvals post through. NewVault sets it; a caller
	// may wrap it.
	Remote store.Remote

	dev syncclient.Device
}

// NewVault is the signed-in, unlocked store s in cfg's data directory,
// with the server c talks to.
func NewVault(cfg store.Config, s *store.Store, c *syncclient.Client) (*Vault, error) {
	si, err := s.ServerInfo()
	if errors.Is(err, store.ErrNotServerBacked) {
		return nil, ErrNotSignedIn
	}
	if err != nil {
		return nil, err
	}
	if si.Server != "" && si.Server != c.Origin() {
		return nil, fmt.Errorf("%w: %s, not %s", ErrServerMismatch, si.Server, c.Origin())
	}
	id, err := vaultIDOf(cfg.DataDir)
	if err != nil {
		return nil, err
	}
	return newVault(s, c, id)
}

func newVault(s *store.Store, c *syncclient.Client, vaultID model.ID) (*Vault, error) {
	dev, err := syncclient.StoreDevice(s.DeviceAuth)
	if err != nil {
		return nil, err
	}
	return &Vault{Store: s, Client: c, VaultID: vaultID, Remote: c.Remote(vaultID, dev), dev: dev}, nil
}

// vaultIDOf reads the vault ID from an entry the store keeps on disk.
//
// Gap G3: the store exports no vault ID accessor. Every entry names its
// vault, and the store keeps only verified entries, so the ID read here is
// the one the store verified; it is only ever used to address the server,
// which can do no more with a wrong one than refuse.
func vaultIDOf(dataDir string) (model.ID, error) {
	dir := filepath.Join(dataDir, "vault", "entries")
	names, err := os.ReadDir(dir)
	if err != nil {
		return model.ID{}, fmt.Errorf("authflow: reading the vault's entries: %w", err)
	}
	for _, n := range names {
		if !strings.HasSuffix(n.Name(), ".json") {
			continue
		}
		b, err := os.ReadFile(filepath.Join(dir, n.Name()))
		if err != nil {
			return model.ID{}, err
		}
		w, err := vaultlog.ParseWire(b)
		if err != nil {
			return model.ID{}, fmt.Errorf("%w: %s: %v", store.ErrCorrupt, n.Name(), err)
		}
		if w.Entry.VaultID.IsZero() {
			break
		}
		return w.Entry.VaultID, nil
	}
	return model.ID{}, fmt.Errorf("%w: no entry names the vault", store.ErrCorrupt)
}

// errDiscarded marks an enrollment message that failed its schema or its
// checks: it is discarded with no change of state (§7, invalid input).
var errDiscarded = errors.New("authflow: an invalid enrollment message was discarded")

// maxDiscardPause bounds the pause before a mailbox is read again after an
// invalid message.
const maxDiscardPause = 15 * time.Second

// discardPause is the pause before reading a mailbox again after the
// n-th (from 0) invalid message in a row: like a retry's backoff, capped.
func (env *Env) discardPause(n int) time.Duration {
	return min(env.backoff(min(n, 8)), maxDiscardPause)
}

// retry runs f until it succeeds, fails in a way that is not retryable,
// or has been retried env.Retries times, with exponential backoff.
func (env *Env) retry(ctx context.Context, f func() error) error {
	for attempt := 0; ; attempt++ {
		err := f()
		if err == nil || attempt >= env.retries() || !syncclient.Retryable(err) {
			return err
		}
		if err := sleep(ctx, env.backoff(attempt)); err != nil {
			return err
		}
	}
}

func sleep(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-t.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// maxKitAttempts is how often the user may type a kit's groups back.
const maxKitAttempts = 3

// confirmKit shows kit and has the user type back the final group of each
// key; then ack records it (s.AckKit, or nothing for a vault not yet
// written).
func confirmKit(ctx context.Context, ui UI, kit store.Kit, ack func() error) error {
	if err := ui.ShowKit(ctx, kit); err != nil {
		return err
	}
	for attempt := 1; attempt <= maxKitAttempts; attempt++ {
		tb, err := ui.ConfirmKit(ctx, attempt)
		if err != nil {
			return err
		}
		if store.SameGroup(tb.SecretKey, store.LastGroup(kit.SecretKey)) &&
			store.SameGroup(tb.RecoveryKey, store.LastGroup(kit.RecoveryKey)) {
			return ack()
		}
	}
	return ErrKitNotConfirmed
}

// others is refs without this device's ID and without duplicates.
func others(refs []string, self string) []string {
	var out []string
	for _, r := range refs {
		r = strings.TrimSpace(r)
		if r == "" || r == self || slices.Contains(out, r) {
			continue
		}
		out = append(out, r)
	}
	return out
}

func idStrings(ids []model.ID) []string {
	out := make([]string, len(ids))
	for i, id := range ids {
		out[i] = id.String()
	}
	return out
}
