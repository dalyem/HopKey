package daemon

import (
	"context"
	"errors"
	"fmt"

	"github.com/dalyem/hopkey/internal/model"
	"github.com/dalyem/hopkey/internal/sshagent"
	"github.com/dalyem/hopkey/internal/store"
)

// Vault ops. They need a store that implements Vault (internal/store); with
// any other store they are refused.
const (
	OpLock    = "lock"
	OpUnlock  = "unlock"
	OpPasswd  = "passwd"
	OpKit     = "kit"     // the pending Emergency Kit, if any
	OpKitDone = "kit_ack" // the user has the pending kit
)

// More error codes.
const (
	CodeWrongPassword = "wrong_password"
	CodeNeedSecretKey = "need_secret_key"
	CodeKitPending    = "kit_pending"
)

// Vault is the locking side of the encrypted store.
type Vault interface {
	Head() (store.Head, error)
	Info() store.Info
	Lock()
	Unlock(ctx context.Context) error
	UnlockWithPassphrase(ctx context.Context, passphrase []byte) error
	UnlockWithPassword(ctx context.Context, password []byte, secretKey string) error
	ChangePassword(ctx context.Context, current, next []byte) (store.Kit, error)
	PendingKit() *store.Kit
	AckKit() error
}

// UnlockParams is the request for OpUnlock. With no password, the device
// key unlocks; with one, pw_blob does (hop unlock --password), using
// SecretKey when the device has none stored. DevicePassphrase opens a
// sealed device key file in place of the daemon's own
// HOP_DEVICE_PASSPHRASE, which a daemon started by hop mcp or the login
// service does not have; it is used for this unlock and not kept.
type UnlockParams struct {
	Password         string `json:"password,omitempty"`
	SecretKey        string `json:"secret_key,omitempty"`
	DevicePassphrase string `json:"device_passphrase,omitempty"`
}

// PasswdParams is the request for OpPasswd.
type PasswdParams struct {
	Current string `json:"current"`
	New     string `json:"new"`
}

// KitResult answers OpPasswd and OpKit. Kit is nil when none is pending.
// It is the one response that carries secrets (the new Secret Key and
// Recovery Key), over the same-uid control socket, so the CLI can print
// them once.
type KitResult struct {
	Kit *store.Kit `json:"kit"`
}

// canUnlock reports whether the store is a Vault: a locked one is worth
// serving, since hop unlock can open it.
func (d *Daemon) canUnlock() bool {
	_, ok := d.store.(Vault)
	return ok
}

func (d *Daemon) vault() (Vault, error) {
	v, ok := d.store.(Vault)
	if !ok {
		return nil, invalidf("this vault store cannot lock or change passwords")
	}
	return v, nil
}

// dispatchVault handles the vault ops. handled is false for any other op.
func (d *Daemon) dispatchVault(ctx context.Context, req Request, decode func(any) error) (result any, handled bool, err error) {
	switch req.Op {
	case OpLock, OpUnlock, OpPasswd, OpKit, OpKitDone:
	default:
		return nil, false, nil
	}
	v, err := d.vault()
	if err != nil {
		return nil, true, err
	}
	switch req.Op {
	case OpLock:
		d.lockVault(v)
		return nil, true, nil
	case OpUnlock:
		var p UnlockParams
		if len(req.Params) > 0 {
			if err := decode(&p); err != nil {
				return nil, true, err
			}
		}
		return nil, true, d.unlockVault(ctx, v, p)
	case OpPasswd:
		var p PasswdParams
		if err := decode(&p); err != nil {
			return nil, true, err
		}
		d.mu.Lock()
		defer d.mu.Unlock()
		kit, err := v.ChangePassword(ctx, []byte(p.Current), []byte(p.New))
		if err != nil {
			return nil, true, err
		}
		if _, err := d.reloadLocked(ctx); err != nil {
			d.logf("reload after the password change: %v", err)
		}
		return &KitResult{Kit: &kit}, true, nil
	case OpKit:
		return &KitResult{Kit: v.PendingKit()}, true, nil
	case OpKitDone:
		return nil, true, v.AckKit()
	}
	return nil, false, nil
}

// lockVault drops the store's secrets, empties the agent and forgets the
// last snapshot.
func (d *Daemon) lockVault(v Vault) {
	d.mu.Lock()
	defer d.mu.Unlock()
	v.Lock()
	d.dropKeysLocked(false)
	d.sync.wake() // so sync.status says locked at once
	d.logf("vault locked")
}

// dropKeysLocked empties the agent and forgets the last snapshot, as a lock
// does. For a revoked device it also writes an ssh config with no hosts, so
// nothing the vault decrypted stays behind (§5.5), and keeps trying until
// that works (clearConfigLocked). The caller holds d.mu.
func (d *Daemon) dropKeysLocked(revoked bool) {
	old := d.live.swap(sshagent.NewKeyring(), d.live.generation())
	old.RemoveAll()
	st := lockedState()
	st.revoked = revoked
	d.state.Store(st)
	if revoked {
		d.clearConfigLocked()
	}
}

// followStore takes the daemon to the locked state when err, from any use
// of the store, says the vault is locked or this device is revoked, or when
// the store has left the generation the keyring was loaded in (an
// interrupted commit locks the store whatever error it returns): the agent
// stops serving keys the vault no longer has unlocked, as after hop lock.
// The store's own state decides, so a vault unlocked again since err is
// left alone; its keys stay fenced off until the next reload. The caller
// holds d.mu.
func (d *Daemon) followStore(err error) {
	if !errors.Is(err, model.ErrLocked) && !errors.Is(err, store.ErrDeviceRevoked) && !d.live.stale() {
		return
	}
	v, ok := d.store.(Vault)
	if !ok {
		return
	}
	_, herr := v.Head()
	if herr == nil {
		return
	}
	revoked := errors.Is(herr, store.ErrDeviceRevoked)
	if cur := d.state.Load(); cur != nil && cur.locked && (cur.revoked || !revoked) {
		return
	}
	d.dropKeysLocked(revoked)
	if revoked {
		d.logf("this device was revoked: the agent is empty and the vault can't be unlocked here again (%v)", herr)
	} else {
		d.logf("the vault locked itself: %v", herr)
	}
}

// watchRevoked drops the keys at once when the store reports that this
// device was revoked, by a pull or any other path, rather than at the next
// request.
func (d *Daemon) watchRevoked() {
	rv, ok := d.store.(interface{ Revoked() <-chan struct{} })
	if !ok {
		return
	}
	ch := rv.Revoked()
	d.wg.Add(1)
	go func() {
		defer d.wg.Done()
		select {
		case <-ch:
			d.mu.Lock()
			d.followStore(store.ErrDeviceRevoked)
			d.mu.Unlock()
		case <-d.ctx.Done():
		}
	}()
}

func (d *Daemon) unlockVault(ctx context.Context, v Vault, p UnlockParams) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	var err error
	switch {
	case p.Password != "":
		err = v.UnlockWithPassword(ctx, []byte(p.Password), p.SecretKey)
	case p.DevicePassphrase != "":
		pass := []byte(p.DevicePassphrase)
		err = v.UnlockWithPassphrase(ctx, pass)
		clear(pass)
	default:
		err = v.Unlock(ctx)
	}
	if err != nil {
		return err
	}
	_, err = d.reloadLocked(ctx)
	// Sync resumes from the last verified head (§11.2).
	d.sync.wake()
	if cw := (*configWriteError)(nil); errors.As(err, &cw) {
		// The keys are loaded all the same: a partial success.
		return &Error{Code: CodeConfigNotWritten, Message: fmt.Sprintf(
			"vault unlocked and keys loaded; the ssh config could not be updated (%v), the daemon tries again every %v", cw.cause, d.configRetry())}
	}
	return err
}

// lockedState is the daemon state while the vault is locked: nothing in
// the agent and no hosts.
func lockedState() *state {
	return &state{locked: true, ssh: map[string]HostSSH{}}
}

// vaultError maps the store's errors to control error codes.
func vaultError(err error) *Error {
	switch {
	case errors.Is(err, store.ErrWrongPassword):
		return &Error{Code: CodeWrongPassword, Message: err.Error()}
	case errors.Is(err, store.ErrNeedSecretKey):
		return &Error{Code: CodeNeedSecretKey, Message: err.Error()}
	case errors.Is(err, store.ErrKitPending):
		return &Error{Code: CodeKitPending, Message: err.Error()}
	case errors.Is(err, model.ErrLocked):
		return &Error{Code: CodeLocked, Message: err.Error()}
	}
	return nil
}

// vaultStatus describes the vault for OpStatus, or nil for a store that is
// not a Vault.
func (d *Daemon) vaultStatus() *store.Info {
	v, ok := d.store.(Vault)
	if !ok {
		return nil
	}
	info := v.Info()
	return &info
}

// storeHead returns the store's head when it can say, so fresh can skip
// rebuilding from an unchanged vault.
func (d *Daemon) storeHead() (store.Head, bool) {
	v, ok := d.store.(interface{ Head() (store.Head, error) })
	if !ok {
		return store.Head{}, false
	}
	h, err := v.Head()
	return h, err == nil
}
