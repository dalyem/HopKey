package cli

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"

	"github.com/dalyem/hopkey/internal/store"
)

func (e *Env) storeConfig() store.Config {
	dir := e.DataDir
	if dir == "" {
		dir = store.DefaultDataDir(e.Home, e.Getenv)
	}
	return store.Config{DataDir: dir, Keyring: e.Keyring, Getenv: e.Getenv}
}

// runInit is `hop init`: create the account and the vault on this device
// (spec §4.3). It asks for the master password twice, prints the Emergency
// Kit, has the user type back the last group of the Secret Key and of the
// Recovery Key, and only then writes the vault.
func runInit(ctx context.Context, e *Env, args []string) error {
	fs := newFlags(e, "init", commands["init"].usage)
	kitFile := fs.String("kit-file", "", "also write the Emergency Kit to this new file (mode 0600)")
	devStore := fs.String("device-key-store", "", "where the device key lives: keychain (the default) or file")
	pos, _, err := parseFlags(fs, args)
	if err != nil {
		return err
	}
	if len(pos) != 0 {
		return failf("usage: %s", commands["init"].usage)
	}
	if e.ReadPassword == nil {
		return failf("hop init needs a terminal to ask for the master password")
	}
	cfg := e.storeConfig()
	if ok, err := store.Exists(cfg.DataDir); err != nil {
		return failf("%v", err)
	} else if ok {
		return failf("a vault already exists in %s; hop init will not replace it", cfg.DataDir)
	}
	if *kitFile != "" {
		if _, err := os.Lstat(*kitFile); err == nil {
			return failf("%s already exists; give --kit-file a new file", *kitFile)
		}
	}

	pw, err := readNewPassword(e, "Master password: ")
	if err != nil {
		return err
	}
	defer clear(pw)
	fmt.Fprintln(e.Stderr, "Generating keys...")
	p, err := store.PrepareInit(cfg, store.InitOptions{Password: pw, DeviceStore: *devStore})
	if errors.Is(err, store.ErrVaultExists) {
		return failf("a vault already exists in %s; hop init will not replace it", cfg.DataDir)
	}
	if err != nil {
		return failf("%v", err)
	}
	committed := false
	defer func() {
		if !committed {
			p.Discard()
		}
	}()
	kit := p.Kit()
	if err := showKit(e, kit, *kitFile); err != nil {
		return err
	}
	if err := typeBack(e, kit); err != nil {
		if *kitFile != "" {
			os.Remove(*kitFile) // it belongs to a vault that will not exist
		}
		return failf("%v; nothing was created", err)
	}
	if _, err := p.Commit(); err != nil {
		return failf("creating the vault: %v", err)
	}
	committed = true
	e.printf("\nVault created in %s.\nDevice key: %s.\n", cfg.DataDir, p.DeviceStore())
	return nil
}

// readNewPassword asks for a new master password twice.
func readNewPassword(e *Env, prompt string) ([]byte, error) {
	pw, err := e.ReadPassword(prompt)
	if err != nil {
		return nil, failf("reading the password: %v", err)
	}
	again, err := e.ReadPassword("Repeat it: ")
	if err != nil {
		clear(pw)
		return nil, failf("reading the password: %v", err)
	}
	defer clear(again)
	if !bytes.Equal(pw, again) {
		clear(pw)
		return nil, failf("the two passwords differ")
	}
	if len(pw) == 0 {
		return nil, failf("the master password cannot be empty")
	}
	return pw, nil
}

// showKit prints the Emergency Kit and writes it to kitFile, if one is
// given, as a new 0600 file.
func showKit(e *Env, kit store.Kit, kitFile string) error {
	e.printf("\n%s\n", kit.Text())
	if kitFile == "" {
		return nil
	}
	f, err := os.OpenFile(kitFile, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return failf("writing the kit: %v", err)
	}
	if _, err := f.WriteString(kit.Text()); err != nil {
		f.Close()
		return failf("writing the kit: %v", err)
	}
	if err := f.Close(); err != nil {
		return failf("writing the kit: %v", err)
	}
	e.printf("The kit was also written to %s.\n", kitFile)
	return nil
}

// typeBack makes the user type the last group of the Secret Key and of the
// Recovery Key (§4.3), three tries each.
func typeBack(e *Env, kit store.Kit) error {
	for _, k := range []struct{ name, key string }{
		{"Secret Key", kit.SecretKey}, {"Recovery Key", kit.RecoveryKey},
	} {
		ok := false
		for try := 0; try < 3 && !ok; try++ {
			got, err := e.ReadPassword(fmt.Sprintf("Type the last group of your %s: ", k.name))
			if err != nil {
				return fmt.Errorf("reading the answer: %v", err)
			}
			ok = store.SameGroup(string(got), store.LastGroup(k.key))
			if !ok {
				fmt.Fprintf(e.Stderr, "That is not the last group of the %s.\n", k.name)
			}
		}
		if !ok {
			return fmt.Errorf("the %s was not typed back", k.name)
		}
	}
	return nil
}
