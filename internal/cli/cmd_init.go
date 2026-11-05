package cli

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/dalyem/hopkey/internal/store"
)

func (e *Env) storeConfig() store.Config {
	dir := e.DataDir
	if dir == "" {
		dir = store.DefaultDataDir(e.Home, e.Getenv)
	}
	return store.Config{DataDir: dir, Keyring: e.Keyring, Getenv: e.storeGetenv()}
}

// runInit is `hop init`: create the account and the vault on this device
// (spec §4.3). On a machine with no usable keychain it first asks how to
// keep the device key (settleDeviceKey). It asks for the master password
// twice, prints the Emergency Kit, has the user type back the last group of
// the Secret Key and of the Recovery Key, and only then writes the vault.
func runInit(ctx context.Context, e *Env, args []string) error {
	fs := newFlags(e, "init", commands["init"].usage)
	kitFile := fs.String("kit-file", "", "also write the Emergency Kit to this new file (mode 0600)")
	devStore := fs.String("device-key-store", "", "where the device key lives: keychain (the default) or file, which a terminal asks to seal with a device passphrase, or HOP_DEVICE_PASSPHRASE seals")
	asJSON := fs.Bool("json", false, "print the result as JSON (the Emergency Kit and the prompts go to the terminal on stderr)")
	pos, _, err := parseFlags(fs, args)
	if err != nil {
		return err
	}
	if len(pos) != 0 {
		return failf("usage: %s", commands["init"].usage)
	}
	if e.ReadPassword == nil {
		return failf("hop init needs a terminal to ask for the master password, and stdin is not one; run it in an interactive terminal")
	}
	cfg := e.storeConfig()
	if pending, err := store.ForkInProgress(cfg.DataDir); err != nil {
		return failf("%v", err)
	} else if pending {
		return failf("a fork of the vault in %s was interrupted; run hop vault fork --local to finish it", cfg.DataDir)
	}
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

	// Before any secret: a machine with no keychain is found out now.
	defer e.clearDevicePass()
	choice, err := settleDeviceKey(e, *devStore, e.canAsk(*asJSON), true)
	if err != nil {
		return err
	}
	fmt.Fprintln(e.Stderr, "Your master password is the one thing you need to remember. Choose one you use nowhere else.")
	pw, err := readNewPassword(e, "Master password: ")
	if err != nil {
		return err
	}
	defer clear(pw)
	fmt.Fprintln(e.Stderr, "Generating keys...")
	p, err := store.PrepareInit(cfg, store.InitOptions{Password: pw, DeviceStore: choice.store})
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
		fmt.Fprint(e.Stderr, unsealedWarning(path, e.canAsk(*asJSON)))
	}
	kit := p.Kit()
	// The kit is for the person at the terminal. With --json, stdout holds
	// the JSON result alone.
	var kitOut io.Writer = e.Stdout
	if *asJSON {
		kitOut = e.Stderr
	}
	if err := showKitTo(e, kitOut, kit, *kitFile); err != nil {
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
	// A device passphrase typed here opens the vault in the daemon now, so
	// the user is not asked for it again straight away.
	handDevicePassphrase(ctx, e, *asJSON)
	if *asJSON {
		return printJSON(e, InitReport{DataDir: cfg.DataDir, DeviceKeyStore: p.DeviceStore(), KitFile: *kitFile})
	}
	e.printf("\nVault created in %s.\nDevice key: %s.\n", oneLine(cfg.DataDir), oneLine(deviceKeyWords(p.DeviceStore())))
	return nil
}

// InitReport is the --json shape of hop init. It holds no secret: the
// Emergency Kit is shown on the terminal only.
type InitReport struct {
	DataDir        string `json:"data_dir"`
	DeviceKeyStore string `json:"device_key_store"`
	// KitFile is the file --kit-file wrote the kit to, if any.
	KitFile string `json:"kit_file,omitempty"`
}

// unsealedWarning is what hop init says before it keeps the device key in
// an unsealed file (§11, rev 15). asked says a person at a terminal was
// asked about sealing it and said no, so the way to a sealed file is only
// the variable; without a terminal nobody was asked, and a terminal is
// the other way.
func unsealedWarning(path string, asked bool) string {
	way := "set " + store.PassphraseEnv + " to one and start again, or run this on a terminal and say yes when it asks"
	if asked {
		way = "set " + store.PassphraseEnv + " to one and start again"
	}
	return safef("warning: %s is not set, so this device's private keys and the Secret Key will be stored "+
		"unencrypted on disk in %s, protected only by its file permissions (0600). "+
		"Anyone who can read that file as you can use them. To seal the file with a device passphrase, %s.\n",
		store.PassphraseEnv, path, way)
}

// deviceKeyWords says where the device key is, in the words of this
// program's text, from store.Info.DeviceStore (which --json keeps as it is).
func deviceKeyWords(s string) string {
	switch s {
	case "file (sealed)":
		return "file, sealed with the device passphrase"
	case "file (unsealed: private keys on disk)":
		return "file, not sealed (private keys unencrypted on disk)"
	}
	return s
}

// readNewPassword asks for a new master password twice.
func readNewPassword(e *Env, prompt string) ([]byte, error) {
	pw, err := e.ReadPassword(prompt)
	if err != nil {
		return nil, failf("reading the master password: %v", err)
	}
	again, err := e.ReadPassword("Repeat it: ")
	if err != nil {
		clear(pw)
		return nil, failf("reading the master password: %v", err)
	}
	defer clear(again)
	if !bytes.Equal(pw, again) {
		clear(pw)
		return nil, failf("the two master passwords differ; type the same one twice")
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
	return showKitTo(e, e.Stdout, kit, kitFile)
}

// showKitTo is showKit with the kit shown on out.
func showKitTo(e *Env, out io.Writer, kit store.Kit, kitFile string) error {
	fmt.Fprintf(out, "\n%s\n", kit.Text())
	if kitFile == "" {
		return nil
	}
	if err := writeKitFile(kitFile, []byte(kit.Text())); err != nil {
		return failf("writing the kit: %v", err)
	}
	fmt.Fprintf(out, "The kit was also written to %s.\n", oneLine(kitFile))
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
			// EPERM can also be a real permission problem, so the
			// error itself is kept in the message.
			return fmt.Errorf("no kit file was written (%s): the filesystem of %s cannot create a file without the risk of replacing an existing one; "+
				"choose a --kit-file path on a filesystem that supports it, or leave out --kit-file and copy the kit from the screen",
				oneLine(err.Error()), oneLine(path))
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
