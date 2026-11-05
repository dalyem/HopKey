package cli

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/dalyem/hopkey/internal/crypto"
	"github.com/dalyem/hopkey/internal/daemon"
	"github.com/dalyem/hopkey/internal/store"
)

// A command that creates a device key settles where it goes before it asks
// for any secret, so nobody types a master password and a Secret Key and
// only then learns that this machine has no keychain.
//
// Only a person at a terminal who gave no --device-key-store is offered a
// way out of an unusable keychain, and the way out is a question they
// answer. An explicit choice stays binding: --device-key-store keychain
// fails when the keychain does not work, and hop never falls back from
// one store to the other on its own. Without a terminal nothing is asked,
// and the failure names both ways forward: --device-key-store=file, and
// HOP_DEVICE_PASSPHRASE to seal the file.
//
// A device passphrase typed here is kept in this process only (Env.devPass)
// and reaches the store through storeConfig's Getenv, never through the
// environment, which child processes would inherit.

// devicePassphrasePrompt asks for the passphrase of a sealed device key
// file that already exists. It says whose it is, because a terminal asking
// for "a passphrase" is easily taken for the master password.
const devicePassphrasePrompt = "Device passphrase (this machine's key file, not your master password): "

// maxAsks bounds how often a question or a passphrase is asked again.
const maxAsks = 3

// deviceKeyChoice is what settleDeviceKey decided.
type deviceKeyChoice struct {
	// store is the value the flows get as the device key store: the flag
	// as given, or "file" after the question.
	store string
	// unsealed means the user answered no to sealing the file, so the
	// device private keys and the Secret Key go to it unencrypted.
	unsealed bool
}

// setDevicePass keeps a copy of a device passphrase typed for this command.
func (e *Env) setDevicePass(p []byte) {
	e.devPassMu.Lock()
	defer e.devPassMu.Unlock()
	clear(e.devPass)
	e.devPass = bytes.Clone(p)
}

// typedPass returns a copy of the device passphrase typed for this
// command, or nil.
func (e *Env) typedPass() []byte {
	e.devPassMu.Lock()
	defer e.devPassMu.Unlock()
	return bytes.Clone(e.devPass)
}

// clearDevicePass drops the typed device passphrase.
func (e *Env) clearDevicePass() {
	e.devPassMu.Lock()
	defer e.devPassMu.Unlock()
	clear(e.devPass)
	e.devPass = nil
}

// storeGetenv is the Getenv the stores get: the caller's, except that the
// device passphrase typed for this command answers HOP_DEVICE_PASSPHRASE.
func (e *Env) storeGetenv() func(string) string {
	get := e.Getenv
	if get == nil {
		get = os.Getenv
	}
	return func(k string) string {
		if k == store.PassphraseEnv {
			if p := e.typedPass(); len(p) > 0 {
				defer clear(p)
				return string(p)
			}
		}
		return get(k)
	}
}

// hasDevicePassphrase reports whether a device passphrase is already at
// hand: the caller's environment has one, or one was typed.
func (e *Env) hasDevicePassphrase() bool {
	if e.Getenv != nil && e.Getenv(store.PassphraseEnv) != "" {
		return true
	}
	p := e.typedPass()
	defer clear(p)
	return len(p) > 0
}

// settleDeviceKey decides, before any secret is asked, where the device
// key goes. flagStore is --device-key-store. interactive says a person is at
// a terminal and may be asked (not --json, stdin and stdout terminals).
// early makes a keychain that cannot work, with no --device-key-store and
// nobody to ask, fail here instead of after the secrets were typed: for
// hop init, which types them itself.
//
// A sign-in or an enrollment that has begun here already recorded its
// store (store.PlannedDeviceKey), so there is nothing left to choose; if
// that store is a sealed file, its device passphrase is what is asked for.
func settleDeviceKey(e *Env, flagStore string, interactive, early bool) (deviceKeyChoice, error) {
	choice := deviceKeyChoice{store: flagStore}
	cfg := e.storeConfig()
	if plan, err := store.PlannedDeviceKey(cfg.DataDir); err == nil && plan.Store != "" {
		if flagStore == "" {
			// The record is the choice: a restarted enrollment follows it
			// too, instead of defaulting to the keychain.
			choice.store = plan.Store
		}
		if plan.Store == store.DeviceStoreFile && plan.Sealed && interactive && !e.hasDevicePassphrase() {
			pass, err := e.ReadPassword(devicePassphrasePrompt)
			if err != nil {
				return choice, failf("reading the device passphrase: %v", err)
			}
			e.setDevicePass(pass)
			clear(pass)
		}
		return choice, nil
	}
	envPass := e.Getenv != nil && e.Getenv(store.PassphraseEnv) != ""
	keyFile := store.DeviceKeyFile(cfg.DataDir)
	switch flagStore {
	case "":
		cause := store.KeychainProblem(cfg)
		if cause == nil {
			return choice, nil
		}
		if !interactive {
			if early {
				return choice, failf("%v", store.KeychainUnusable(cfg, cause))
			}
			return choice, nil
		}
		e.say("This machine has no usable OS keychain (%s), so hop will keep this device's key in a file:\n  %s\n", cause, keyFile)
		choice.store = store.DeviceStoreFile
		if envPass {
			ok, err := askYesNo(e, fmt.Sprintf("Seal it with the device passphrase from %s?", store.PassphraseEnv))
			if err != nil {
				return choice, err
			}
			if !ok {
				return choice, failf("%v", store.KeychainUnusable(cfg, cause))
			}
			return choice, nil
		}
	case store.DeviceStoreKeychain:
		// Binding: no fallback and no question. Only found out now, not
		// after the secrets are typed.
		if interactive || early {
			if cause := store.KeychainProblem(cfg); cause != nil {
				return choice, failf("%v", store.KeychainUnusable(cfg, cause))
			}
		}
		return choice, nil
	case store.DeviceStoreFile:
		if envPass || !interactive {
			return choice, nil
		}
		e.say("hop will keep this device's key in a file:\n  %s\n", keyFile)
	default:
		return choice, nil
	}
	sealed, err := askSeal(e)
	if err != nil {
		return choice, err
	}
	choice.unsealed = !sealed
	return choice, nil
}

// canAsk reports whether a person at a terminal may be asked a question:
// stdin and stdout are terminals, and the command is not --json.
func (e *Env) canAsk(asJSON bool) bool {
	return e.StdinTTY && e.StdoutTTY && !asJSON && e.ReadPassword != nil
}

// say writes a line for the user to stderr.
func (e *Env) say(format string, args ...any) {
	fmt.Fprint(e.Stderr, safef(format, args...))
}

// askSeal asks whether the device key file gets a device passphrase and,
// if so, asks for it twice. It reports whether the file will be sealed.
func askSeal(e *Env) (bool, error) {
	e.say("A device passphrase encrypts that file. It is separate from your master password, " +
		"and you type it to unlock hop after a lock or a restart.\n")
	ok, err := askYesNo(e, "Protect it with a device passphrase? (recommended)")
	if err != nil || !ok {
		return false, err
	}
	for range maxAsks {
		pass, err := e.ReadPassword("New device passphrase: ")
		if err != nil {
			return false, failf("reading the device passphrase: %v", err)
		}
		again, err := e.ReadPassword("Repeat the device passphrase: ")
		if err != nil {
			clear(pass)
			return false, failf("reading the device passphrase: %v", err)
		}
		same := bytes.Equal(pass, again)
		clear(again)
		switch {
		case !same:
			e.say("The two device passphrases differ. Try again.\n")
		case !validPassphrase(pass):
			e.say("A device passphrase is %d to %d characters of valid text. Try again.\n", crypto.MinPasswordBytes, crypto.MaxPasswordBytes)
		default:
			e.setDevicePass(pass)
			clear(pass)
			return true, nil
		}
		clear(pass)
	}
	return false, failf("no matching device passphrase after %d tries; nothing was created", maxAsks)
}

// validPassphrase reports whether pass can seal a device key file: the
// store applies the master password's rules to it (crypto.NormalizePassword).
func validPassphrase(pass []byte) bool {
	n, err := crypto.NormalizePassword(pass)
	clear(n)
	return err == nil
}

// askYesNo asks a question that defaults to yes, on stderr, and reads one
// line from stdin. Anything but yes or no asks again.
func askYesNo(e *Env, question string) (bool, error) {
	for range maxAsks {
		fmt.Fprintf(e.Stderr, "%s [Y/n] ", question)
		line, err := readLine(e.Stdin)
		if err != nil && line == "" {
			if errors.Is(err, io.EOF) {
				return false, failf("no answer: stdin ended; nothing was created")
			}
			return false, failf("reading the answer: %v; nothing was created", err)
		}
		switch strings.ToLower(strings.TrimSpace(line)) {
		case "", "y", "yes":
			return true, nil
		case "n", "no":
			return false, nil
		}
		e.say("Type yes or no.\n")
	}
	return false, failf("no yes or no answer; nothing was created")
}

// handDevicePassphrase opens the vault in the daemon with the device
// passphrase typed for this command, so the user can use the vault they
// just made or signed in to without typing it again. The daemon takes it
// for this unlock only and keeps nothing; a daemon that was not running is
// started. Where that fails the vault is fine and stays locked, and the
// warning says what to run.
func handDevicePassphrase(ctx context.Context, e *Env, asJSON bool) {
	pass := e.typedPass()
	if len(pass) == 0 {
		return
	}
	defer clear(pass)
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
	defer cancel()
	c, err := dialExisting(ctx, e)
	if err == nil && c == nil {
		if err = startDaemon(ctx, e); err == nil {
			c, err = dialExisting(ctx, e)
		}
	}
	if err == nil && c != nil {
		defer c.Close()
		var w *daemon.Error
		w, err = c.CallWarn(ctx, daemon.OpUnlock, daemon.UnlockParams{DevicePassphrase: string(pass)}, nil)
		err = changeWarning(e, asJSON, w, err)
	}
	if err != nil {
		warn(e, asJSON, "the vault is locked: the hop daemon did not open it ("+err.Error()+"); run hop unlock, which asks for the device passphrase")
	}
}
