package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/dalyem/hopkey/internal/store"
)

const vaultForkUsage = "hop vault fork --local [--keep-old|--discard-old|--abandon] [--device-key-store keychain|file] [--kit-file PATH] [--yes] [--json]"

// runVault is `hop vault <subcommand>`.
func runVault(ctx context.Context, e *Env, args []string) error {
	if len(args) == 0 || args[0] != "fork" {
		return failf("usage: %s", vaultForkUsage)
	}
	return runVaultFork(ctx, e, args[1:])
}

// ForkReport is the --json shape of hop vault fork. It holds no secret
// and no item: the Emergency Kit is shown on the terminal only.
type ForkReport struct {
	store.ForkResult
	DeviceKeyStore string `json:"device_key_store,omitempty"`
	KitFile        string `json:"kit_file,omitempty"`
}

// runVaultFork is `hop vault fork --local` (admin plan A3c): this
// device's copy of a server-backed vault becomes a new local-only vault,
// a new account with new IDs and keys, for a device whose account was
// deleted or whose server is gone. The old vault directory is kept as a
// backup unless --discard-old. A fork that was interrupted is finished
// (or, if its new vault was never verified, started again) first; until
// then the vault is fenced (store.ErrForkPending). --abandon gives up an
// interrupted fork whose new vault is not in place yet, and leaves the
// old vault as it was.
func runVaultFork(ctx context.Context, e *Env, args []string) error {
	fs := newFlags(e, "vault fork", vaultForkUsage)
	local := fs.Bool("local", false, "make the new vault local-only (the only kind of fork there is)")
	keepOld := fs.Bool("keep-old", false, "keep the old vault directory as a backup (the default)")
	discardOld := fs.Bool("discard-old", false, "delete the old vault directory and its device key once the new vault is verified")
	devStore := fs.String("device-key-store", "", "where the new device key lives: keychain or file (default: where the old one is)")
	kitFile := fs.String("kit-file", "", "also write the new Emergency Kit to this new file (mode 0600)")
	abandon := fs.Bool("abandon", false, "give up an interrupted fork whose new vault is not in place yet; the old vault stays as it was")
	yes := fs.Bool("yes", false, "fork without asking")
	asJSON := fs.Bool("json", false, "print the result as JSON (the plan, the Emergency Kit and the prompts go to the terminal on stderr)")
	pos, _, err := parseFlags(fs, args)
	if err != nil {
		return err
	}
	if err := noArgs(fs, pos); err != nil {
		return err
	}
	if !*local {
		return failf("hop vault fork needs --local: the fork is a new local-only vault (publish it later with hop auth signup)")
	}
	if *keepOld && *discardOld {
		return failf("--keep-old and --discard-old exclude each other")
	}
	if *abandon && (*keepOld || *discardOld || *devStore != "" || *kitFile != "") {
		return failf("--abandon takes no other flag but --json: it only gives up an interrupted fork")
	}
	if *kitFile != "" {
		if _, err := os.Lstat(*kitFile); err == nil {
			return failf("%s already exists; give --kit-file a new file", *kitFile)
		}
	}
	if !*yes && !e.StdinTTY {
		return failf("hop vault fork makes a new account from this vault, and there is no terminal to confirm on: pass --yes")
	}
	var out io.Writer = e.Stdout
	if *asJSON {
		out = e.Stderr
	}
	h, err := holdVault(ctx, e, *asJSON)
	if err != nil {
		return err
	}
	defer h.release(ctx)
	cfg := e.storeConfig()

	if *abandon {
		if !*yes {
			ok, err := confirm(e, false, "Give up the interrupted fork? Its new vault is deleted; the old vault stays as it is.")
			if err != nil {
				return err
			}
			if !ok {
				return failf("not given up; nothing changed")
			}
		}
		var gaveUp bool
		err := retryBusy(ctx, func() (err error) {
			gaveUp, err = store.AbandonFork(ctx, cfg)
			return err
		})
		if err != nil {
			return forkFailure(err)
		}
		if *asJSON {
			return printJSON(e, struct {
				Abandoned bool `json:"abandoned"`
			}{gaveUp})
		}
		if !gaveUp {
			fmt.Fprintln(out, "There is no interrupted fork to give up.")
		} else {
			fmt.Fprintln(out, "The interrupted fork was given up: its new vault and device key are deleted, and the Emergency Kit it showed belongs to no vault.")
			fmt.Fprintf(out, "The vault in %s is as it was before the fork.\n", oneLine(cfg.DataDir))
		}
		return nil
	}

	// The device passphrase opens a sealed device key file: the old
	// vault's, and an interrupted fork's new one, which finishing it opens.
	pending, err := store.ForkInProgress(cfg.DataDir)
	if err != nil {
		return failf("%v", err)
	}
	sealed, err := store.SealedDeviceFile(cfg.DataDir)
	if err != nil && !pending {
		return failf("%v", err)
	}
	if pending {
		if s, err := store.ForkSealed(cfg.DataDir); err != nil {
			return failf("%v", err)
		} else if s {
			sealed = true
		}
	}
	var pass []byte
	if sealed && e.Getenv(store.PassphraseEnv) == "" {
		if e.ReadPassword == nil {
			return failf("the device key file is sealed and stdin is not a terminal to ask for its passphrase; set %s or run hop vault fork in an interactive terminal", store.PassphraseEnv)
		}
		if pass, err = e.ReadPassword("Device passphrase: "); err != nil {
			return failf("reading the device passphrase: %v", err)
		}
		defer clear(pass)
	}

	var res *store.ForkResult
	var abandoned bool
	err = retryBusy(ctx, func() (err error) {
		res, abandoned, err = store.ResumeFork(ctx, cfg, store.ForkOptions{Passphrase: pass})
		return err
	})
	if err != nil {
		return forkFailure(err)
	}
	if res != nil {
		if *asJSON {
			return printJSON(e, ForkReport{ForkResult: *res})
		}
		fmt.Fprintln(out, "An interrupted fork is finished.")
		printForkDone(out, res)
		return nil
	}
	if abandoned {
		warn(e, *asJSON, "an earlier fork stopped before its new vault was verified: it was deleted, and the Emergency Kit it showed belongs to no vault; the fork starts again")
	}

	if e.ReadPassword == nil {
		return failf("hop vault fork needs a terminal to ask for the new master password, and stdin is not one; run it in an interactive terminal")
	}
	if ok, err := store.Exists(cfg.DataDir); err != nil {
		return failf("%v", err)
	} else if !ok {
		return failf("there is no vault on this device to fork")
	}
	var p *store.PendingFork
	err = retryBusy(ctx, func() (err error) {
		p, err = store.PrepareFork(ctx, cfg, store.ForkOptions{Passphrase: pass})
		return err
	})
	if err != nil {
		return forkFailure(err)
	}
	defer p.Close()
	if *kitFile != "" {
		if in, err := p.Touches(*kitFile); err != nil {
			return failf("%v", err)
		} else if in {
			return failf("--kit-file %s is inside the vault's data directory, which the fork moves into the backup (and --discard-old deletes); give it a path outside %s; nothing was changed",
				oneLine(*kitFile), oneLine(cfg.DataDir))
		}
	}
	plan := p.Plan()
	printForkPlan(out, plan, *discardOld)
	if !*yes {
		if !e.StdinTTY {
			return failf("hop vault fork makes a new account from this vault, and there is no terminal to confirm on: pass --yes")
		}
		ok, err := confirm(e, false, "Fork this vault into a new local-only vault?")
		if err != nil {
			return err
		}
		if !ok {
			return failf("not forked; nothing changed")
		}
	}

	pw, err := readNewPassword(e, "Master password for the new vault: ")
	if err != nil {
		return err
	}
	defer clear(pw)
	fmt.Fprintln(e.Stderr, "Generating keys...")
	kit, err := p.Generate(pw, *devStore)
	if errors.Is(err, store.ErrKeychainUnusable) {
		return failf("%v", err)
	}
	if err != nil {
		return forkFailure(err)
	}
	if path, unsealed := p.UnsealedFile(); unsealed {
		fmt.Fprint(e.Stderr, unsealedWarning(path))
	}
	fmt.Fprintln(out, "\nThe new vault is a new account. This is its Emergency Kit; the old account's kit does not open it.")
	if err := showKitTo(e, out, kit, *kitFile); err != nil {
		return failf("%v; nothing was changed", err)
	}
	if err := typeBack(e, kit); err != nil {
		if *kitFile != "" {
			os.Remove(*kitFile) // it belongs to a vault that will not exist
		}
		return failf("%v; nothing was changed", err)
	}
	res, err = p.Commit(ctx, *discardOld)
	if err != nil {
		if pending, _ := store.ForkInProgress(cfg.DataDir); pending {
			return failf("the new vault is built and verified, but the fork did not finish (%v); run hop vault fork --local again to finish it "+
				"(until then the vault can't be used), or hop vault fork --local --abandon to give it up", err)
		}
		if *kitFile != "" {
			os.Remove(*kitFile) // it belongs to a vault that does not exist
		}
		return forkFailure(err)
	}
	if *asJSON {
		return printJSON(e, ForkReport{ForkResult: *res, DeviceKeyStore: p.DeviceStore(), KitFile: *kitFile})
	}
	printForkDone(out, res)
	return nil
}

// retryBusy runs f again while it fails with store.ErrVaultBusy, for at
// most vaultBusyWait: the daemon that holdVault stopped closes the vault
// only after its sockets are gone.
func retryBusy(ctx context.Context, f func() error) error {
	deadline := time.Now().Add(vaultBusyWait)
	for {
		err := f()
		if !errors.Is(err, store.ErrVaultBusy) || time.Now().After(deadline) {
			return err
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(50 * time.Millisecond):
		}
	}
}

// forkFailure is a fork's error as the user reads it.
func forkFailure(err error) error {
	switch {
	case errors.Is(err, store.ErrForkRevoked):
		return failf("%v. A device its account removed is not salvaged: its copy belongs to that account", err)
	case errors.Is(err, store.ErrNotServerBacked):
		return failf("this vault is local-only already, so there is nothing to fork it from")
	case errors.Is(err, store.ErrVaultBusy):
		return failf("the vault is busy: another hop process owns it (is another hop command running?)")
	case errors.Is(err, store.ErrDeviceKey):
		return failf("the device key can't be read (%v): a fork decrypts this device's copy with it, so it can't run without it", err)
	case errors.Is(err, store.ErrForkPending):
		return failf("%v", err)
	case errors.Is(err, store.ErrForkStale):
		return failf("the fork can't finish: %v", err)
	case errors.Is(err, store.ErrForkDamaged):
		return failf("the fork can't go on by itself: %v. Look at the directories it names; hop vault fork --local --abandon gives the fork up while the old vault is still there", err)
	}
	return failf("forking the vault: %v", err)
}

// printForkPlan says what the fork will do, before the confirmation.
func printForkPlan(out io.Writer, p store.ForkPlan, discardOld bool) {
	fmt.Fprintln(out, "hop vault fork --local makes a new local-only vault from this device's copy of the vault:")
	if p.Server != "" {
		fmt.Fprintf(out, "  from: account %s on %s (vault %s, this device %s)\n", p.Old.AccountID, oneLine(p.Server), p.Old.VaultID, p.Old.DeviceID)
	}
	fmt.Fprintf(out, "  items: %d hosts, %d keys, %d credentials, %d snippets, %d policies, each with a new item ID\n",
		p.Hosts, p.Keys, p.Credentials, p.Snippets, p.Policies)
	if p.Pending > 0 || p.Held > 0 {
		fmt.Fprintf(out, "  changes that never reached the server: %d pending, %d held; the new vault keeps them as this device shows them\n", p.Pending, p.Held)
	}
	if p.Logout == store.StateRetiring {
		fmt.Fprintln(out, "  this device's logout never finished; the fork keeps what that logout would have deleted")
	}
	if p.Policies > 0 {
		fmt.Fprintln(out, "  a local-only vault never locks for the max-offline policy; it applies again only if you publish the vault")
	}
	for _, w := range p.Warnings {
		fmt.Fprintf(out, "  note: %s\n", oneLine(w))
	}
	fmt.Fprintln(out, "  The new vault is a new account: new account, vault and device IDs, new keys, a new master password and Emergency Kit.")
	fmt.Fprintln(out, "  It never syncs with the old account.")
	if discardOld {
		fmt.Fprintf(out, "  The old vault is deleted from this device once the new one is verified.\n")
	} else {
		fmt.Fprintf(out, "  The old vault is kept, as it is, in %s.\n", oneLine(p.Backup))
	}
	if n := len(p.OtherDevices); n > 0 {
		names := make([]string, 0, n)
		for _, d := range p.OtherDevices {
			names = append(names, fmtDevice(d.Name, d.DeviceID.String()))
		}
		fmt.Fprintf(out, "  The old account's other devices keep their copies: %s.\n", strings.Join(names, ", "))
	}
}

// printForkDone reports a finished fork.
func printForkDone(out io.Writer, r *store.ForkResult) {
	fmt.Fprintf(out, "\nForked: %s now holds a new local-only vault (account %s, vault %s, device %s).\n",
		oneLine(r.DataDir), r.New.AccountID, r.New.VaultID, r.New.DeviceID)
	if r.Discarded {
		fmt.Fprintln(out, "The old vault was deleted from this device.")
	} else {
		fmt.Fprintf(out, "The old vault is kept in %s; nothing opens or syncs it there. Delete it when you no longer need it.\n", oneLine(r.Backup))
	}
	if len(r.OtherDevices) > 0 || len(r.Departed) > 0 {
		fmt.Fprintf(out, "The old account had %d other active device(s) and %d that left it; they may still hold copies of its keys. "+
			"Rotate SSH keys you no longer trust them with (hop key rotate).\n", len(r.OtherDevices), len(r.Departed))
	}
	fmt.Fprintln(out, "hop auth signup publishes the new vault to a server when you want it to sync again.")
}
