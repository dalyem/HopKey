package cli

import (
	"context"
	"fmt"
	"os"

	"github.com/dalyem/hopkey/internal/daemon"
	"github.com/dalyem/hopkey/internal/store"
)

// runPasswd is `hop passwd`: change the master password. Per spec §10.1
// this is a full checkpoint, so the Secret Key and the Recovery Key change
// too, every item is re-keyed and every token is revoked. The new kit is
// printed only once the change is committed, and stays pending until it is
// typed back. If one is already pending, hop passwd shows that one instead.
func runPasswd(ctx context.Context, e *Env, args []string) error {
	fs := newFlags(e, "passwd", commands["passwd"].usage)
	kitFile := fs.String("kit-file", "", "also write the new Emergency Kit to this new file (mode 0600)")
	pos, _, err := parseFlags(fs, args)
	if err != nil {
		return err
	}
	if len(pos) != 0 {
		return failf("usage: %s", commands["passwd"].usage)
	}
	if e.ReadPassword == nil {
		return failf("hop passwd needs a terminal to ask for passwords")
	}
	if *kitFile != "" {
		if _, err := os.Lstat(*kitFile); err == nil {
			return failf("%s already exists; give --kit-file a new file", *kitFile)
		}
	}
	c, err := connect(ctx, e)
	if err != nil {
		return err
	}
	defer c.Close()

	var pending daemon.KitResult
	if err := c.Call(ctx, daemon.OpKit, nil, &pending); err != nil {
		return failf("%v", err)
	}
	if pending.Kit != nil {
		fmt.Fprintln(e.Stderr, "hop: an earlier password change is done, but its new Emergency Kit was never confirmed. Here it is.")
		return confirmKit(ctx, e, c, *pending.Kit, *kitFile)
	}

	cur, err := e.ReadPassword("Current master password: ")
	if err != nil {
		return failf("reading the password: %v", err)
	}
	defer clear(cur)
	next, err := readNewPassword(e, "New master password: ")
	if err != nil {
		return err
	}
	defer clear(next)
	fmt.Fprintln(e.Stderr, "Re-keying the vault...")
	var res daemon.KitResult
	err = c.Call(ctx, daemon.OpPasswd, daemon.PasswdParams{Current: string(cur), New: string(next)}, &res)
	if daemon.IsCode(err, daemon.CodeWrongPassword) {
		return failf("the current master password is wrong; nothing changed")
	}
	if err != nil {
		return failf("%v", err)
	}
	if res.Kit == nil {
		return failf("the daemon returned no Emergency Kit")
	}
	e.printf("Your master password has changed. Your Secret Key and Recovery Key have\n")
	e.printf("changed with it; the old ones no longer work. Every token was revoked.\n")
	return confirmKit(ctx, e, c, *res.Kit, *kitFile)
}

// confirmKit prints a committed change's kit, has it typed back and then
// tells the daemon the user has it.
func confirmKit(ctx context.Context, e *Env, c *daemon.Client, kit store.Kit, kitFile string) error {
	if err := showKit(e, kit, kitFile); err != nil {
		return err
	}
	if err := typeBack(e, kit); err != nil {
		return failf("%v. The password change is done; run hop passwd again to see the kit", err)
	}
	if err := c.Call(ctx, daemon.OpKitDone, nil, nil); err != nil {
		return failf("%v", err)
	}
	e.printf("Emergency Kit confirmed.\n")
	return nil
}
