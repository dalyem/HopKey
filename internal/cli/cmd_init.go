package cli

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"

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
		// An early, friendly check; writeKitFile is what guarantees that
		// nothing is replaced.
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
	if path, unsealed := p.UnsealedFile(); unsealed {
		fmt.Fprint(e.Stderr, unsealedWarning(path))
	}
	kit := p.Kit()
	if err := showKit(e, kit, *kitFile); err != nil {
		return failf("%v; nothing was created", err)
	}
	if err := typeBack(e, kit); err != nil {
		if *kitFile != "" {
			os.Remove(*kitFile) // it belongs to a vault that will not exist
		}
		return failf("%v; nothing was created", err)
	}
	s, err := p.Commit()
	if err != nil {
		return failf("creating the vault: %v", err)
	}
	committed = true
	// The daemon opens the vault on its own; this process lets go of it.
	if err := s.Close(); err != nil {
		return failf("closing the vault: %v", err)
	}
	e.printf("\nVault created in %s.\nDevice key: %s.\n", oneLine(cfg.DataDir), p.DeviceStore())
	return nil
}

// unsealedWarning is what hop init says before it keeps the device key in
// an unsealed file (§11, rev 15).
func unsealedWarning(path string) string {
	return safef("warning: %s is not set, so this device's private keys and the Secret Key will be stored "+
		"unencrypted on disk in %s, protected only by its file permissions (0600). "+
		"Anyone who can read that file as you can use them. Set %s before hop init to seal the file with a passphrase.\n",
		store.PassphraseEnv, path, store.PassphraseEnv)
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
// given, as a new 0600 file. The file is on disk, fsynced, before it is
// reported saved and before the kit can be typed back.
func showKit(e *Env, kit store.Kit, kitFile string) error {
	e.printf("\n%s\n", kit.Text())
	if kitFile == "" {
		return nil
	}
	if err := writeKitFile(kitFile, []byte(kit.Text())); err != nil {
		return failf("writing the kit: %v", err)
	}
	e.printf("The kit was also written to %s.\n", oneLine(kitFile))
	return nil
}

// kitSync fsyncs an open file or directory. Tests replace it.
var kitSync = func(f *os.File) error { return f.Sync() }

// kitRename and kitLink move the finished temp file into place without
// replacing anything. Tests replace them.
var (
	kitRename = renameNoReplace
	kitLink   = os.Link
)

// writeKitFile creates path holding data, mode 0600, atomically and without
// ever replacing an existing file: a temp file in the same directory is
// written and fsynced, then moved into place with an atomic no-replace
// rename (renameat2 RENAME_NOREPLACE on Linux, renamex_np RENAME_EXCL on
// macOS) or, where the system or filesystem has none, a hard link, and the
// directory is fsynced. Either fails if path exists. If neither is
// supported, no file is written.
func writeKitFile(path string, data []byte) error {
	dir := filepath.Dir(path)
	f, err := os.CreateTemp(dir, ".hop-kit-*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	moved := false
	defer func() {
		if !moved {
			os.Remove(tmp)
		}
	}()
	err = f.Chmod(0o600)
	if err == nil {
		_, err = f.Write(data)
	}
	if err == nil {
		err = kitSync(f)
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return err
	}
	err = kitRename(tmp, path)
	moved = err == nil
	if errors.Is(err, errNoReplaceUnsupported) {
		// The link leaves tmp in place; the deferred Remove takes it.
		err = kitLink(tmp, path)
		if err != nil && linkUnsupported(err) {
			return fmt.Errorf("no kit file was written: the filesystem of %s cannot create a file without the risk of replacing an existing one; "+
				"choose a --kit-file path on a filesystem that supports it, or leave out --kit-file and copy the kit from the screen", path)
		}
	}
	if errors.Is(err, os.ErrExist) {
		return fmt.Errorf("%s already exists", path)
	}
	if err != nil {
		return err
	}
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	return kitSync(d)
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
