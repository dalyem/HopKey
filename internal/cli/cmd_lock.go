package cli

import (
	"context"
	"fmt"

	"github.com/dalyem/hopkey/internal/daemon"
	"github.com/dalyem/hopkey/internal/store"
)

// LockResult is the --json shape of hop lock and hop unlock.
type LockResult struct {
	Locked bool `json:"locked"`
	// Password says hop unlock --password replaced the device key.
	Password bool `json:"password,omitempty"`
}

// runLock is `hop lock`: the daemon drops every secret and the agent holds
// no keys until hop unlock.
func runLock(ctx context.Context, e *Env, args []string) error {
	fs := newFlags(e, "lock", commands["lock"].usage)
	asJSON := fs.Bool("json", false, "print the result as JSON")
	pos, _, err := parseFlags(fs, args)
	if err != nil {
		return err
	}
	if len(pos) != 0 {
		return failf("usage: %s", commands["lock"].usage)
	}
	if err := call(ctx, e, daemon.OpLock, nil, nil); err != nil {
		return err
	}
	if *asJSON {
		return printJSON(e, LockResult{Locked: true})
	}
	e.printf("vault locked; the agent holds no keys\n")
	return nil
}

// runUnlock is `hop unlock`: reload the vault with the device key, or with
// --password, open it with the master password and the Secret Key and
// replace the device key (the path for a lost or broken keychain entry).
//
// A sealed device key file opens with the device passphrase. hop unlock
// sends the daemon its own HOP_DEVICE_PASSPHRASE; without one, on a
// terminal, it asks for it once the daemon's own (if any) did not open
// the file. A daemon that hop mcp or the login service started has none,
// and uses the one it is sent for this unlock only.
func runUnlock(ctx context.Context, e *Env, args []string) error {
	fs := newFlags(e, "unlock", commands["unlock"].usage)
	usePassword := fs.Bool("password", false, "unlock with the master password and set up a new device key")
	asJSON := fs.Bool("json", false, "print the result as JSON")
	pos, _, err := parseFlags(fs, args)
	if err != nil {
		return err
	}
	if len(pos) != 0 {
		return failf("usage: %s", commands["unlock"].usage)
	}
	c, err := connect(ctx, e)
	if err != nil {
		return err
	}
	defer c.Close()
	done := func(password bool) error {
		switch {
		case *asJSON:
			if err := printJSON(e, LockResult{Password: password}); err != nil {
				return err
			}
		case password:
			e.printf("vault unlocked with the master password; this device has a new device key\n")
		default:
			e.printf("vault unlocked\n")
		}
		vaultWarnings(ctx, e, c)
		return kitReminder(ctx, e, c)
	}
	if !*usePassword {
		unlock := func(pass []byte) (*daemon.Error, error) {
			var p any
			if len(pass) > 0 {
				p = daemon.UnlockParams{DevicePassphrase: string(pass)}
			}
			return c.CallWarn(ctx, daemon.OpUnlock, p, nil)
		}
		pass := []byte(e.Getenv(store.PassphraseEnv))
		w, err := unlock(pass)
		if err != nil && len(pass) == 0 && canAskPassphrase(e) {
			// The daemon has no passphrase of its own, or the wrong one.
			if pass, err = e.ReadPassword("Device passphrase: "); err != nil {
				return failf("reading the device passphrase: %v", err)
			}
			defer clear(pass)
			w, err = unlock(pass)
		}
		if err := changeWarning(e, *asJSON, w, err); err != nil {
			return failf("%v", err)
		}
		return done(false)
	}
	if e.ReadPassword == nil {
		return failf("hop unlock --password needs a terminal to ask for the master password")
	}
	pw, err := e.ReadPassword("Master password: ")
	if err != nil {
		return failf("reading the password: %v", err)
	}
	defer clear(pw)
	p := daemon.UnlockParams{Password: string(pw)}
	w, err := c.CallWarn(ctx, daemon.OpUnlock, p, nil)
	if daemon.IsCode(err, daemon.CodeNeedSecretKey) {
		sk, rerr := e.ReadPassword("Secret Key (from your Emergency Kit): ")
		if rerr != nil {
			return failf("reading the Secret Key: %v", rerr)
		}
		p.SecretKey = string(sk)
		clear(sk)
		w, err = c.CallWarn(ctx, daemon.OpUnlock, p, nil)
	}
	if daemon.IsCode(err, daemon.CodeWrongPassword) {
		return failf("wrong master password or Secret Key; the vault was not unlocked")
	}
	if err := changeWarning(e, *asJSON, w, err); err != nil {
		return failf("%v", err)
	}
	return done(true)
}

// canAskPassphrase reports whether hop unlock may ask for the device
// passphrase: there is a terminal, and the device key is a sealed file.
func canAskPassphrase(e *Env) bool {
	if !e.StdinTTY || e.ReadPassword == nil {
		return false
	}
	sealed, err := store.SealedDeviceFile(e.storeConfig().DataDir)
	return err == nil && sealed
}

// vaultWarnings prints the vault's warnings (a lost Emergency Kit, stale
// devices to revoke) to stderr.
func vaultWarnings(ctx context.Context, e *Env, c *daemon.Client) {
	var st daemon.StatusResult
	if err := c.Call(ctx, daemon.OpStatus, nil, &st); err != nil || st.Vault == nil {
		return
	}
	printWarnings(e, st.Vault.Warnings)
}

// printWarnings writes each warning as one line. They come from the vault's
// own errors, which can quote a path.
func printWarnings(e *Env, warnings []string) {
	for _, w := range warnings {
		fmt.Fprintf(e.Stderr, "hop: warning: %s\n", oneLine(w))
	}
}

// kitReminder mentions a password change whose kit is still unconfirmed.
func kitReminder(ctx context.Context, e *Env, c *daemon.Client) error {
	var kr daemon.KitResult
	if err := c.Call(ctx, daemon.OpKit, nil, &kr); err == nil && kr.Kit != nil {
		fmt.Fprintln(e.Stderr, "hop: a password change finished but its new Emergency Kit is not confirmed; run hop passwd to see it")
	}
	return nil
}

// printVaultStatus is the vault part of hop status: locked or not, where
// the device key is, and the log head (seq and the first 8 bytes of H, for
// comparing devices by eye, spec §5.6).
func printVaultStatus(e *Env, v *store.Info) {
	if v == nil {
		return
	}
	if v.Locked {
		e.printf("vault:        locked; run hop unlock\n")
	} else {
		e.printf("vault:        unlocked\n")
	}
	e.printf("device key:   %s\n", oneLine(v.DeviceStore))
	if v.Head != nil {
		e.printf("log head:     seq %s\n", v.Head.Short())
	}
	if v.LockReason != "" {
		e.printf("unlock error: %s\n", oneLine(v.LockReason))
	}
	if v.KitPending {
		e.printf("warning:      a new Emergency Kit is waiting to be confirmed; run hop passwd\n")
	}
	for _, w := range v.Warnings {
		e.printf("warning:      %s\n", oneLine(w))
	}
}
