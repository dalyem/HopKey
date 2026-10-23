package store

import (
	"context"
	"errors"
	"fmt"
	"os"
	"slices"

	"github.com/dalyem/hopkey/internal/model"
	"github.com/dalyem/hopkey/internal/vaultlog"
)

// Signing in on a machine with no vault (§4.4 password login, §4.5
// recovery). It is the login merge's sign-in (mergefile.go) without a
// source vault, on the same path:
//
//  1. device.json names the new device as pending (the intent), and then
//     its record is made durable in the chosen device key store; or the
//     pending device an earlier attempt left is resolved: first from the
//     sign-in ledger (ledger.go), where a revocation ends the sign-in
//     (ErrSignInRevoked) whatever the device key store holds, and then
//     from what the store holds for it (deviceStore.probeSlot): its record
//     is used again, with this sign-in's Secret Key, its tombstone ends the
//     sign-in, an inconclusive read changes nothing, and a confirmed
//     absence makes it stale, since its bootstrap may have committed. The
//     devices a cancelled merge into the account orphaned (ledger.go)
//     become stale devices too, in device.json before the ledger forgets
//     them;
//  2. signInDestination: the log is read from genesis and verified from
//     the anchor of the account keys, every head the server reports is
//     checked against it, the bootstrap is posted unless an earlier
//     attempt's committed, and the log is caught up as the new device, so
//     a checkpoint that revokes it is met before anything is decrypted and
//     made terminal (the ledger records it, then its record becomes a
//     tombstone);
//  3. one durable commit installs the verified log, account.json and
//     vault/server.json (the server, the email, and a recovery's due
//     checkpoint); then device.json names the device as this one
//     (reconcileDevice), as an unlock with a pending device would.
//
// A crash anywhere is finished by calling SignIn again with a new login,
// or by Open once step 3 committed (SignIn then opens it itself).

// SignInResult is what a sign-in leaves to its caller.
type SignInResult struct {
	// CheckpointDue means the sign-in was a recovery (§4.5), which MUST be
	// followed by a checkpoint with new credentials (§10.1), committed
	// through the server, before the recovery is reported done (plan R6).
	// SignIn does not run it: the caller must. The obligation is durable
	// (ServerInfo.CheckpointDue), and only the commit of that checkpoint,
	// authored by this device, clears it (recoveryCheckpointDone): a
	// checkpoint another device commits does not.
	CheckpointDue bool
}

// SignIn signs this machine in to the account of p.Account as a new device
// (§4.4, or §4.5 with SignInRecovery), in cfg.DataDir, which must hold no
// vault. It returns the store, unlocked, server-backed and owning the vault
// (see Open). r is the destination server with the login's token.
//
// Every failure leaves either nothing of the sign-in, or a pending device
// that the next call resolves; the account keys are zeroed on every path
// that does not install them. If an earlier call's install committed, the
// vault is opened with its device key instead. A revocation of the new
// device, now or seen by an earlier attempt, fails with ErrDeviceRevoked
// and ErrSignInRevoked: this data directory can't sign in to the account
// again.
func SignIn(ctx context.Context, cfg Config, r SignInRemote, p SignInParams) (*Store, SignInResult, error) {
	return signIn(ctx, cfg, r, p, nil)
}

// signIn is SignIn with a test hook.
func signIn(ctx context.Context, cfg Config, r SignInRemote, p SignInParams, hook func(string) error) (*Store, SignInResult, error) {
	return signInWith(ctx, cfg, r, p, hook, nil)
}

// signInWith is signIn with a second test hook, which sees the sign-in's
// secrets once its device keys are decoded.
func signInWith(ctx context.Context, cfg Config, r SignInRemote, p SignInParams, hook func(string) error, watch func(*signInSecrets)) (_ *Store, _ SignInResult, err error) {
	o := &signInSecrets{acct: p.Account}
	defer o.zero()
	sf, err := p.check()
	if err != nil {
		return nil, SignInResult{}, err
	}
	s := &Store{cfg: cfg, l: layout{data: cfg.DataDir}, testHook: hook}
	if err := s.l.ensureDirs(); err != nil {
		return nil, SignInResult{}, err
	}
	if err := s.own(); err != nil {
		return nil, SignInResult{}, err
	}
	defer func() {
		if err != nil {
			s.Close()
		}
	}()
	rec, dcfg, installed, err := s.signInDevice(p)
	if err != nil {
		return nil, SignInResult{}, err
	}
	if installed {
		// An earlier attempt committed: the vault is there, and its device
		// key opens it.
		s.Close()
		st, err := Open(ctx, cfg)
		if err != nil {
			return nil, SignInResult{}, err
		}
		if info := st.Info(); info.Locked {
			st.Close()
			if info.Revoked {
				return nil, SignInResult{}, fmt.Errorf("%w: an earlier sign-in installed the vault, but its device is revoked: %s", ErrDeviceRevoked, info.LockReason)
			}
			return nil, SignInResult{}, fmt.Errorf("store: an earlier sign-in installed the vault, but it does not unlock: %s", info.LockReason)
		}
		info, err := st.ServerInfo()
		if err != nil {
			st.Close()
			return nil, SignInResult{}, err
		}
		return st, SignInResult{CheckpointDue: info.CheckpointDue}, nil
	}
	o.rec = rec
	self, err := rec.device()
	if err != nil {
		return nil, SignInResult{}, err
	}
	o.dev = self
	if watch != nil {
		watch(o)
	}
	info, err := deviceInfo(rec, p.deviceName(s))
	if err != nil {
		return nil, SignInResult{}, err
	}
	err = signInDestination(ctx, r, o, self, info, s.now, s.hook)
	if rev := (*vaultlog.RevokedError)(nil); errors.As(err, &rev) {
		return nil, SignInResult{}, s.revokePending(dcfg, rec.DeviceID, err)
	}
	if err != nil {
		return nil, SignInResult{}, err
	}
	sf = p.serverFor(sf, o.d.st)
	dcfg.SecretKeyGen = p.secretKeyGen(rec.DeviceID, o.d.st)
	if err := s.installSignIn(o, dcfg, sf); err != nil {
		return nil, SignInResult{}, err
	}
	return s, SignInResult{CheckpointDue: s.serverInfoOf(&sf).CheckpointDue}, nil
}

// signInDevice returns the new device's record, durable and named as
// pending in device.json, and that configuration; or installed, when an
// earlier attempt's install committed for this account. Under the file
// lock, it finishes an interrupted commit first, then refuses a data
// directory that holds a vault, or a device configuration that is not an
// earlier sign-in to this account.
func (s *Store) signInDevice(p SignInParams) (*deviceRecord, deviceConfig, bool, error) {
	unlock, err := s.lockFile()
	if err != nil {
		return nil, deviceConfig{}, false, err
	}
	defer unlock()
	if err := s.replayWAL(); err != nil {
		return nil, deviceConfig{}, false, err
	}
	acctID := p.Account.AccountID
	// The sign-in ledger must parse before any device is chosen, the one
	// an earlier attempt installed included.
	ledger, err := s.l.readLedger()
	if err != nil {
		return nil, deviceConfig{}, false, err
	}
	orphans := ledger.orphaned(acctID)
	var dcfg deviceConfig
	present := false
	if _, err := os.Lstat(s.l.deviceConfig()); err == nil {
		if dcfg, err = s.readDeviceConfig(); err != nil {
			return nil, deviceConfig{}, false, err
		}
		present = true
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, deviceConfig{}, false, err
	}
	if exists, err := s.l.exists(); err != nil {
		return nil, deviceConfig{}, false, err
	} else if exists {
		if present && dcfg.AccountID == acctID {
			if server, err := s.l.serverBacked(); err == nil && server {
				return nil, dcfg, true, nil
			}
		}
		return nil, deviceConfig{}, false, ErrVaultExists
	}
	// An enrollment by approval in progress here owns the data directory's
	// next device (enroll.go).
	if pending, err := s.l.enrollPending(); err != nil {
		return nil, deviceConfig{}, false, err
	} else if pending {
		return nil, deviceConfig{}, false, fmt.Errorf("%w: %w", ErrVaultExists, ErrEnrollmentPending)
	}
	if present {
		if dcfg.AccountID != acctID || !dcfg.DeviceID.IsZero() || dcfg.Next != nil {
			return nil, deviceConfig{}, false, fmt.Errorf("%w: %s belongs to another device or sign-in", ErrVaultExists, s.l.deviceConfig())
		}
		if p.DeviceStore != "" && p.DeviceStore != dcfg.Store {
			return nil, deviceConfig{}, false, fmt.Errorf("store: an earlier sign-in here keeps its device key in the %s store, not %s", dcfg.Store, p.DeviceStore)
		}
		if id := dcfg.pendingID(); !id.IsZero() {
			// The ledger first: a revocation whose tombstone could not be
			// written leaves the record readable.
			if ledger.isRevoked(acctID, id) {
				return nil, deviceConfig{}, false, s.stillRevoked(s.deviceStore(dcfg), id,
					fmt.Errorf("%w: %w (device %v, recorded in %s)", ErrDeviceRevoked, ErrSignInRevoked, id, s.l.ledgerFile()))
			}
			state, rec, err := s.deviceStore(dcfg).probeSlot(id)
			if err != nil {
				return nil, deviceConfig{}, false, fmt.Errorf("store: the device of an earlier sign-in can't be resolved, so nothing was changed: %w", err)
			}
			switch state {
			case slotTombstone:
				return nil, deviceConfig{}, false, fmt.Errorf("%w: %w (device %v; its record is a tombstone)", ErrDeviceRevoked, ErrSignInRevoked, id)
			case slotRecord:
				// A record found on disk is made durable again before it is
				// used, with this sign-in's Secret Key.
				if err := s.deviceStore(dcfg).upgradeRecord(rec); err != nil {
					rec.zero()
					return nil, deviceConfig{}, false, err
				}
				if err := s.deviceStore(dcfg).refreshSecretKey(rec, p.SecretKey); err != nil {
					rec.zero()
					return nil, deviceConfig{}, false, err
				}
				if dcfg, err = s.adoptOrphans(dcfg, ledger, orphans); err != nil {
					rec.zero()
					return nil, deviceConfig{}, false, err
				}
				return rec, dcfg, false, nil
			}
			// Confirmed gone: its bootstrap may have committed, so it is
			// stale from the same write that names the next device.
			dcfg = dcfg.withPending(model.ID{})
			dcfg.StaleDevices = append(dcfg.StaleDevices, id)
		}
	} else {
		store := p.DeviceStore
		if store == "" {
			store = DeviceStoreKeychain
		}
		dcfg = deviceConfig{V: 1, Store: store, AccountID: acctID}
		switch store {
		case DeviceStoreKeychain:
		case DeviceStoreFile:
			dcfg.Sealed = s.getenv()(PassphraseEnv) != ""
		default:
			return nil, deviceConfig{}, false, fmt.Errorf("store: unknown device key store %q (keychain or file)", store)
		}
		if err := s.deviceStore(dcfg).probe(); err != nil {
			if store == DeviceStoreKeychain {
				return nil, deviceConfig{}, false, fmt.Errorf("%w (%v); pass --device-key-store=file to keep the device key in %s instead",
					ErrKeychainUnusable, err, s.l.deviceKeyFile())
			}
			return nil, deviceConfig{}, false, err
		}
	}
	if err := s.hook("signin:record"); err != nil {
		return nil, deviceConfig{}, false, err
	}
	rec, _, err := newDeviceRecord(acctID, p.SecretKey)
	if err != nil {
		return nil, deviceConfig{}, false, err
	}
	// The intent: device.json names the device before its record exists,
	// so the store never holds a record that device.json does not track.
	// The devices a cancelled merge into this account orphaned become
	// stale in the same write.
	dcfg.Pending = &pendingDevice{DeviceID: rec.DeviceID}
	dcfg.StaleDevices = uniqueIDs(append(dcfg.StaleDevices, orphans...))
	if err := s.writeDeviceConfig(dcfg); err != nil {
		rec.zero()
		return nil, deviceConfig{}, false, err
	}
	s.forgetOrphans(ledger, acctID)
	if err := s.hook("signin:intent"); err != nil {
		rec.zero()
		return nil, deviceConfig{}, false, err
	}
	if err := s.deviceStore(dcfg).storeDurably(rec); err != nil {
		rec.zero()
		return nil, deviceConfig{}, false, fmt.Errorf("store: the device key was not saved durably: %w", err)
	}
	if err := s.hook("signin:next"); err != nil {
		rec.zero()
		return nil, deviceConfig{}, false, err
	}
	return rec, dcfg, false, nil
}

// adoptOrphans makes orphans, the devices a cancelled merge into dcfg's
// account orphaned (MergeCancel with ForceOrphan), stale devices of dcfg,
// durably in device.json, so hop passwd revokes the active ones once the
// sign-in installs; then the ledger forgets them. It returns the
// configuration written. The caller holds the file lock.
func (s *Store) adoptOrphans(dcfg deviceConfig, ledger *signInLedger, orphans []model.ID) (deviceConfig, error) {
	stale := uniqueIDs(append(slices.Clone(dcfg.StaleDevices), orphans...))
	if len(stale) != len(dcfg.StaleDevices) {
		dcfg.StaleDevices = stale
		if err := s.writeDeviceConfig(dcfg); err != nil {
			return deviceConfig{}, err
		}
	}
	s.forgetOrphans(ledger, dcfg.AccountID)
	return dcfg, nil
}

// forgetOrphans clears account acct's orphaned devices from the ledger,
// once device.json lists them as stale. It is best effort: keeping them is
// harmless, since the next sign-in into acct adopts them again without
// duplicates. The caller holds the file lock.
func (s *Store) forgetOrphans(ledger *signInLedger, acct model.ID) {
	if ledger.clearOrphaned(acct) {
		s.l.writeLedger(ledger)
	}
}

// revokePending makes the revocation of id, the pending device of dcfg,
// terminal for this data directory (§5.5): the sign-in ledger records it
// durably, and then its record is replaced by its tombstone. Every later
// attempt stops at either (signInDevice), whatever history the server
// shows then, and tries a tombstone that could not be written again. rev
// wraps the *vaultlog.RevokedError.
func (s *Store) revokePending(dcfg deviceConfig, id model.ID, rev error) error {
	revoked := fmt.Errorf("%w: %w (device %v, %s)", ErrDeviceRevoked, ErrSignInRevoked, id, revokedAt(rev))
	unlock, err := s.lockFile()
	if err != nil {
		return fmt.Errorf("%w; it could not be recorded: %v", revoked, err)
	}
	defer unlock()
	return s.recordRevoked(dcfg.AccountID, id, revoked, func() error { return s.deviceStore(dcfg).tombstone(id) })
}

// installSignIn installs o's verified destination in one durable commit,
// with sf as vault/server.json, and unlocks the store with it: the store
// takes o's secrets over, and finishUnlock names the pending device as
// this one in device.json. A failure leaves the store locked; a crash
// after the commit is finished by Open.
func (s *Store) installSignIn(o *signInSecrets, dcfg deviceConfig, sf serverFile) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	unlock, err := s.lockFile()
	if err != nil {
		return err
	}
	defer unlock()
	if exists, err := s.l.exists(); err != nil {
		return err
	} else if exists {
		return ErrVaultExists
	}
	// A revocation the ledger recorded meanwhile is never installed.
	id := o.rec.DeviceID
	if g, err := s.l.readLedger(); err != nil {
		return err
	} else if g.isRevoked(dcfg.AccountID, id) {
		return s.stillRevoked(s.deviceStore(dcfg), id,
			fmt.Errorf("%w: %w (device %v, recorded in %s)", ErrDeviceRevoked, ErrSignInRevoked, id, s.l.ledgerFile()))
	}
	// The record, durable, holds the Secret Key of dcfg.SecretKeyGen:
	// device.json records it before the install commits, so the unlock
	// that finishes an install a crash interrupted keeps it.
	if g := dcfg.SecretKeyGen; !g.DeviceID.IsZero() {
		if err := s.noteSecretKeyGen(g.DeviceID, g.Gen); err != nil {
			return err
		}
	}
	t := &txn{}
	if err := s.putDestination(t, o.d, sf); err != nil {
		return err
	}
	if err := s.hook("signin:install"); err != nil {
		return err
	}
	if err := s.commitTxn(t); err != nil {
		return err
	}
	rec, self, d := o.take()
	s.state, s.sec, s.dev, s.rec, s.devCfg, s.server = d.st, d.sec, self, rec, dcfg, true
	s.gen.Add(1)
	if err := s.finishUnlock(); err != nil {
		s.dropLocked(err)
		return err
	}
	return nil
}

// signInPending reports whether device.json names a sign-in's pending
// device in a data directory with no vault: hop init must not replace it,
// or its record would be left untracked.
func (s *Store) signInPending() (bool, error) {
	if _, err := os.Lstat(s.l.deviceConfig()); errors.Is(err, os.ErrNotExist) {
		return false, nil
	} else if err != nil {
		return false, err
	}
	cfg, err := s.readDeviceConfig()
	if err != nil {
		return false, err
	}
	return cfg.Pending != nil && cfg.DeviceID.IsZero(), nil
}
