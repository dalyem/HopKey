package cli

import (
	"context"
	"fmt"

	"github.com/dalyem/hopkey/internal/daemon"
	"github.com/dalyem/hopkey/internal/store"
)

// runLock is `hop lock`: the daemon drops every secret and the agent holds
// no keys until hop unlock.
func runLock(ctx context.Context, e *Env, args []string) error {
	if len(args) != 0 {
		return failf("usage: %s", commands["lock"].usage)
	}
	if err := call(ctx, e, daemon.OpLock, nil, nil); err != nil {
		return err
	}
	e.printf("vault locked; the agent holds no keys\n")
	return nil
}

// runUnlock is `hop unlock`: reload the vault with the device key, or with
// --password, open it with the master password and the Secret Key and
// replace the device key (the path for a lost or broken keychain entry).
func runUnlock(ctx context.Context, e *Env, args []string) error {
	fs := newFlags(e, "unlock", commands["unlock"].usage)
	usePassword := fs.Bool("password", false, "unlock with the master password and set up a new device key")
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
	if !*usePassword {
		if err := c.Call(ctx, daemon.OpUnlock, nil, nil); err != nil {
			return failf("%v", err)
		}
		e.printf("vault unlocked\n")
		vaultWarnings(ctx, e, c)
		return kitReminder(ctx, e, c)
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
	err = c.Call(ctx, daemon.OpUnlock, p, nil)
	if daemon.IsCode(err, daemon.CodeNeedSecretKey) {
		sk, rerr := e.ReadPassword("Secret Key (from your Emergency Kit): ")
		if rerr != nil {
			return failf("reading the Secret Key: %v", rerr)
		}
		p.SecretKey = string(sk)
		clear(sk)
		err = c.Call(ctx, daemon.OpUnlock, p, nil)
	}
	if daemon.IsCode(err, daemon.CodeWrongPassword) {
		return failf("wrong master password or Secret Key; the vault was not unlocked")
	}
	if err != nil {
		return failf("%v", err)
	}
	e.printf("vault unlocked with the master password; this device has a new device key\n")
	vaultWarnings(ctx, e, c)
	return kitReminder(ctx, e, c)
}

// vaultWarnings prints the vault's warnings (a lost Emergency Kit, stale
// devices to revoke) to stderr.
func vaultWarnings(ctx context.Context, e *Env, c *daemon.Client) {
	var st daemon.StatusResult
	if err := c.Call(ctx, daemon.OpStatus, nil, &st); err != nil || st.Vault == nil {
		return
	}
	for _, w := range st.Vault.Warnings {
		fmt.Fprintf(e.Stderr, "hop: warning: %s\n", w)
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
	e.printf("device key:   %s\n", v.DeviceStore)
	if v.Head != nil {
		e.printf("log head:     seq %s\n", v.Head.Short())
	}
	if v.LockReason != "" {
		e.printf("unlock error: %s\n", v.LockReason)
	}
	if v.KitPending {
		e.printf("warning:      a new Emergency Kit is waiting to be confirmed; run hop passwd\n")
	}
	for _, w := range v.Warnings {
		e.printf("warning:      %s\n", w)
	}
}
