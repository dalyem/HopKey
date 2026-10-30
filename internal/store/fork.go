package store

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"time"

	"github.com/dalyem/hopkey/internal/crypto"
	"github.com/dalyem/hopkey/internal/filelock"
	"github.com/dalyem/hopkey/internal/merge"
	"github.com/dalyem/hopkey/internal/model"
	"github.com/dalyem/hopkey/internal/safepath"
	"github.com/dalyem/hopkey/internal/vaultlog"
)

// Forking a server-backed vault into a new local-only one (hop vault fork
// --local, admin plan A3c): the salvage of a device whose account was
// deleted, whose server is gone, or that the server refuses for good.
//
// The new vault is a new account, made as hop init makes one: new account,
// vault and device IDs, a new Secret Key, Recovery Key and Emergency Kit,
// new local keys, under a master password the user chooses. Its items are
// the old vault's as this device shows them (the overlay): every item
// gets a new item ID, and references between items follow. Nothing of the
// old account's identity, keys or log is reused.
//
// Layout, beside the data directory D (resolved through symlinks, the
// last one included when what it names is gone):
//
//	D.lock                         the data directory's gate (below); it is never deleted
//	D.fork-new/                    the new vault while it is built: a whole data directory
//	D.fork-new/fork.json           the fork's journal (no secrets), which moves with it to D
//	D.forked-<date>-<vault8>/      the old data directory, kept as it was (unless --discard-old)
//
//	fork.json = {"v":1, "state":"staging"|"verified"|"swapped"|"done", "txn_id":id, "data_dir":str,
//	             "backup":str, "discard_old":bool, "discarding":bool, "discarded":bool, "old":{ids}, "new":{ids},
//	             "new_store":str, "source":digest, "new_head":head, "new_items":n, ...counts}
//
// The gate: everything that opens or makes a vault in D (Open, hop init,
// a sign-in, an enrollment) takes D.lock shared while it checks the fence
// and takes vault/owner.lock. A fork holds it exclusive from PrepareFork
// (or ResumeFork, AbandonFork) to its end. The owner lock can't do this
// alone: it moves with the old vault when the swap renames D. The fence
// (forkFence) refuses with ErrForkPending once a fork's new vault has
// verified and until the fork is done. The backup is fenced as well while
// the fork is unfinished (backupFence): opening a directory named as a
// fork's backup takes D.lock shared too, and is refused while a journal
// that is not done names it.
//
// Steps, each durable before the next:
//
//   - staging: D.fork-new and its journal, which names the new identity
//     and where its device key goes before the key is written; hop init's
//     commit into it; the verified items, in batches of entries, then one
//     entry per item a pending or held change touched, then the deletes
//     those changes made. Every entry passes the server's admission. The
//     old vault is only read; source records a digest of it as read.
//   - verified: the new vault is opened from disk as hop opens any vault
//     (the log verified from genesis with the new device key) and its
//     items must equal what was imported. Its head and item count are
//     recorded with verified.
//   - the swap: the new vault in D.fork-new is opened and checked against
//     the journal again; D (checked to be the old vault, taken from any
//     owner, and still matching source) is renamed to the backup, then
//     D.fork-new to D.
//   - swapped is recorded once the new vault in D checks out. With
//     --discard-old, the backup is checked (the old vault, unowned, still
//     matching source; otherwise ErrForkStale, and it is kept), discarding
//     is recorded with the backup's files, and then the backup's device
//     records and its directory are deleted. A resumed deletion goes on
//     only with what a deletion cut short leaves (recorded files,
//     unchanged); a backup missing before discarding is refused, and one
//     missing after is reported missing, never deleted. done is recorded,
//     and the journal stays as the record of the fork. A crash after the
//     old vault moved checks the backup the same way before the new vault
//     goes into D. The backup's owner lock is held from the move (or that
//     check) to the fork's end.
//
// A crash before verified leaves the old vault as it was: the next run
// deletes the staging directory (and its keychain entry), and the fork
// starts again with a new Emergency Kit. A crash from verified on is
// finished by ResumeFork, or given up by AbandonFork while the new vault
// is not in D yet. Recovery derives every path from the data directory
// it is given and checks the journal against it: a journal that names
// other paths or identities, or a vault that does not match it, is
// refused (ErrForkDamaged), and nothing is deleted.

var (
	// ErrForkRevoked refuses to fork the vault of a device that left its
	// account by a revocation: proven (revoked.json) or reported by the
	// server (server-revoked.json). The account removed it on purpose.
	ErrForkRevoked = errors.New("store: this device was removed from its account, so its copy of the vault can't be forked")
	// ErrForkRefused means the vault holds something a fork can't carry,
	// or is in a state that does not allow one.
	ErrForkRefused = errors.New("store: this vault can't be forked")
	// ErrForkPending means an interrupted fork is waiting to finish, and
	// the vault is fenced until it does: hop vault fork --local finishes
	// it, and hop vault fork --local --abandon gives it up.
	ErrForkPending = errors.New("store: a fork of this vault was interrupted, and the vault can't be used until it ends; " +
		"run hop vault fork --local to finish it, or hop vault fork --local --abandon to give it up")
	// ErrForkStale means the old vault changed after the fork copied it,
	// so the copy can't replace it.
	ErrForkStale = errors.New("store: the vault changed after the fork copied it")
	// ErrForkDamaged means an interrupted fork's journal or vaults are not
	// what it recorded: nothing more is done with them automatically.
	ErrForkDamaged = errors.New("store: the interrupted fork's files are not as it left them")
)

// errForkReported refuses a device the server reported as departed
// (server-revoked.json): only the account's own checkpoint or this
// device's retirement makes that report.
var errForkReported = fmt.Errorf("%w: the server reported that it left the account (hop auth status shows how); "+
	"hop auth logout wipes it, and hop auth login signs in again", ErrForkRevoked)

const (
	forkRel        = "fork.json"
	forkVersion    = 1
	forkNewSuffix  = ".fork-new"
	forkBackupStem = ".forked-"
	forkGateSuffix = ".lock"
	forkBatch      = 32

	forkStaging  = "staging"
	forkVerified = "verified"
	forkSwapped  = "swapped"
	forkDone     = "done"
)

// forkHook simulates crashes in tests: a stage that returns an error stops
// the fork there, as a crash would.
var forkHook func(stage string) error

func forkStage(stage string) error {
	if forkHook != nil {
		return forkHook(stage)
	}
	return nil
}

// ForkIDs names an account, its vault and one device.
type ForkIDs struct {
	AccountID model.ID `json:"account_id"`
	VaultID   model.ID `json:"vault_id"`
	DeviceID  model.ID `json:"device_id"`
}

// ForkDevice is a device of the old account, from its verified log.
type ForkDevice struct {
	DeviceID model.ID `json:"device_id"`
	Name     string   `json:"name"`
}

// ForkPlan is what a fork would do, for the confirmation. It holds no item
// plaintext; Warnings name items, and are shown, never written.
type ForkPlan struct {
	DataDir string  `json:"data_dir"`
	Backup  string  `json:"backup"`
	Server  string  `json:"server,omitempty"`
	Old     ForkIDs `json:"old"`
	// Logout is StateRetiring when a logout of this device was journaled
	// and never finished.
	Logout      string `json:"logout,omitempty"`
	Hosts       int    `json:"hosts"`
	Keys        int    `json:"keys"`
	Credentials int    `json:"credentials"`
	Snippets    int    `json:"snippets"`
	Policies    int    `json:"policies"`
	// Pending and Held count the queued changes (outbox records) that
	// never reached the server; the fork keeps what they show.
	Pending int `json:"pending"`
	Held    int `json:"held"`
	// HeldDeletes counts held deletes: their items are kept, as this
	// device showed them.
	HeldDeletes int `json:"held_deletes,omitempty"`
	// OtherDevices are the old account's other active devices. Departed
	// counts the devices that left it (revoked or retired): the
	// revocation history, kept in the journal and in the backup's log.
	OtherDevices []ForkDevice `json:"other_devices"`
	Departed     []model.ID   `json:"departed"`
	Warnings     []string     `json:"warnings,omitempty"`
}

// ForkResult is a finished fork.
type ForkResult struct {
	ForkPlan
	New ForkIDs `json:"new"`
	// Discarded means the old data directory was deleted (--discard-old);
	// Backup then names where it was.
	Discarded bool `json:"discarded,omitempty"`
	// BackupMissing means the backup was not found when the fork ended,
	// and nothing showed that the fork deleted it: it may have been moved
	// away. It is not reported deleted.
	BackupMissing bool `json:"backup_missing,omitempty"`
	// Resumed means an interrupted fork was finished.
	Resumed bool `json:"resumed,omitempty"`
}

type forkJournal struct {
	V          int      `json:"v"`
	State      string   `json:"state"`
	TxnID      model.ID `json:"txn_id"`
	DataDir    string   `json:"data_dir"`
	Backup     string   `json:"backup"`
	DiscardOld bool     `json:"discard_old"`
	// Discarding is recorded, after the backup was checked to be the old
	// vault as the fork read it, before anything of it is deleted: only
	// then may a resumed deletion find its identity files gone.
	Discarding bool `json:"discarding,omitempty"`
	// DiscardManifest is the backup as its deletion began, recorded with
	// Discarding: every path in it, with its kind and, for a file, a
	// SHA-256 of its content (forkSourceScan). A resumed deletion goes on
	// only with a backup whose paths are all listed, unchanged: what a
	// deletion cut short leaves. A journal of an earlier build, with
	// Discarding and no manifest (its discard_files left out the entries'
	// contents and the objects), never deletes a backup still there: the
	// resume refuses until the backup is moved away, then finishes.
	DiscardManifest map[string]string `json:"discard_manifest,omitempty"`
	Discarded       bool              `json:"discarded"`
	// BackupMissing is ForkResult's.
	BackupMissing bool            `json:"backup_missing,omitempty"`
	At            model.Timestamp `json:"at"`
	Plan          forkPlanRecord  `json:"plan"`
	New           ForkIDs         `json:"new"`
	// NewStore is where the new device key goes (keychain or file). It is
	// journaled with New before the key is written, so the cleanup of an
	// abandoned fork finds the key whatever device.json says.
	NewStore string `json:"new_store"`
	// Source commits to the old vault as the fork read it
	// (forkSourceDigest): the swap moves it only while it still matches.
	Source string `json:"source"`
	// NewHead and NewItems commit to the new vault as it verified. Every
	// step after verified opens the new vault and checks them first.
	NewHead  vaultlog.Head `json:"new_head"`
	NewItems int           `json:"new_items"`
}

// forkPlanRecord is ForkPlan as the journal keeps it: no warnings, which
// name items.
type forkPlanRecord struct {
	Server       string       `json:"server"`
	Old          ForkIDs      `json:"old"`
	Logout       string       `json:"logout"`
	Hosts        int          `json:"hosts"`
	Keys         int          `json:"keys"`
	Credentials  int          `json:"credentials"`
	Snippets     int          `json:"snippets"`
	Policies     int          `json:"policies"`
	Pending      int          `json:"pending"`
	Held         int          `json:"held"`
	HeldDeletes  int          `json:"held_deletes"`
	OtherDevices []ForkDevice `json:"other_devices"`
	Departed     []model.ID   `json:"departed"`
}

func (j *forkJournal) result() *ForkResult {
	p := j.Plan
	return &ForkResult{
		ForkPlan: ForkPlan{
			DataDir: j.DataDir, Backup: j.Backup, Server: p.Server, Old: p.Old, Logout: p.Logout,
			Hosts: p.Hosts, Keys: p.Keys, Credentials: p.Credentials, Snippets: p.Snippets, Policies: p.Policies,
			Pending: p.Pending, Held: p.Held, HeldDeletes: p.HeldDeletes, OtherDevices: p.OtherDevices, Departed: p.Departed,
		},
		New: j.New, Discarded: j.Discarded, BackupMissing: j.BackupMissing,
	}
}

func forkJournalFile(dir string) string { return filepath.Join(dir, forkRel) }

func readForkJournal(dir string) (*forkJournal, error) {
	b, err := os.ReadFile(forkJournalFile(dir))
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var j forkJournal
	if err := json.Unmarshal(b, &j); err != nil || j.V != forkVersion {
		return nil, fmt.Errorf("%w: %s is not a fork journal", ErrCorrupt, forkJournalFile(dir))
	}
	return &j, nil
}

func writeForkJournal(dir string, j *forkJournal) error {
	b, err := json.Marshal(j)
	if err != nil {
		return err
	}
	return writeFileAtomic(forkJournalFile(dir), b)
}

// check validates j, a journal found for the fork of data. Recovery uses
// the paths it derives from data, never the journal's own: one that names
// another data directory (copied from there), a backup that is not beside
// it, or identities that are missing, reused or of no known device key
// store, is refused, as is a journal past staging with no record of what
// it verified.
func (j *forkJournal) check(data string) error {
	bad := func(why string) error {
		return fmt.Errorf("%w: the fork journal for %s %s; nothing was changed", ErrForkDamaged, data, why)
	}
	switch j.State {
	case forkStaging, forkVerified, forkSwapped, forkDone:
	default:
		return bad(fmt.Sprintf("has an unknown state %q", j.State))
	}
	if j.DataDir != data {
		return bad(fmt.Sprintf("names another data directory, %s (was it copied from there?)", j.DataDir))
	}
	if !isForkBackup(data, j.Plan.Old.VaultID, j.Backup) {
		return bad(fmt.Sprintf("names %s as the backup, which is not one beside it", j.Backup))
	}
	ids := []model.ID{j.TxnID, j.Plan.Old.AccountID, j.Plan.Old.VaultID, j.Plan.Old.DeviceID, j.New.AccountID, j.New.VaultID, j.New.DeviceID}
	for i, id := range ids {
		if id.IsZero() || slices.Contains(ids[:i], id) {
			return bad("has a missing or repeated ID")
		}
	}
	if j.NewStore != DeviceStoreKeychain && j.NewStore != DeviceStoreFile {
		return bad(fmt.Sprintf("names no known device key store (%q)", j.NewStore))
	}
	if j.State != forkStaging && (j.Source == "" || j.NewHead.Seq == 0 || j.NewItems < 0) {
		return bad("has no record of the vaults it verified")
	}
	if j.Discarding && (!j.DiscardOld || (j.State != forkSwapped && j.State != forkDone)) {
		return bad("says it was deleting the backup before the new vault was in place")
	}
	return nil
}

// isForkBackup reports whether backup is the name a fork of vault in data
// gives its backup: D.forked-<yyyymmdd>-<vault8>, beside D.
func isForkBackup(data string, vault model.ID, backup string) bool {
	if vault.IsZero() || filepath.Dir(backup) != filepath.Dir(data) {
		return false
	}
	rest, ok := strings.CutPrefix(filepath.Base(backup), filepath.Base(data)+forkBackupStem)
	if !ok || len(rest) != 8+1+8 || rest[8] != '-' || rest[9:] != vault.String()[:8] {
		return false
	}
	_, err := time.Parse("20060102", rest[:8])
	return err == nil
}

// backupSource returns D when dir is named as a fork of D names its
// backup (D.forked-<yyyymmdd>-<8 hex digits>), and "" otherwise.
func backupSource(dir string) string {
	base := filepath.Base(dir)
	i := strings.LastIndex(base, forkBackupStem)
	if i <= 0 {
		return ""
	}
	rest := base[i+len(forkBackupStem):]
	if len(rest) != 8+1+8 || rest[8] != '-' || strings.Trim(rest[9:], "0123456789abcdef") != "" {
		return ""
	}
	if _, err := time.Parse("20060102", rest[:8]); err != nil {
		return ""
	}
	return filepath.Join(filepath.Dir(dir), base[:i])
}

// backupFence refuses with ErrForkPending while dir is the backup of a
// fork that has not finished: the fork moved the old vault there, and
// checks it against what it copied before it deletes it (--discard-old)
// or puts it back (--abandon). A journal that can't be read fences it too.
// The journal is in D's staging directory until the swap, then in D.
func backupFence(dir string) error {
	src := backupSource(dir)
	if src == "" {
		return nil
	}
	for _, jd := range []string{src + forkNewSuffix, src} {
		j, err := readForkJournal(jd)
		if err != nil {
			return fmt.Errorf("%w (%v)", ErrForkPending, err)
		}
		if j != nil {
			if j.Backup == dir && j.State != forkDone {
				return ErrForkPending
			}
			return nil
		}
	}
	return nil
}

// resolveLoose resolves p through symlinks as far as it exists: every
// existing ancestor, and the last component too when it is a symlink,
// even one whose target is gone. What does not exist is joined on as
// given. A crash between the swap's renames leaves a symlinked data
// directory dangling, and its fork is still beside the link's target.
func resolveLoose(p string) (string, error) { return resolveLooseN(p, 0) }

func resolveLooseN(p string, depth int) (string, error) {
	if depth > 255 {
		return "", fmt.Errorf("store: %s: too many levels of symbolic links", p)
	}
	abs, err := filepath.Abs(p)
	if err != nil {
		return "", err
	}
	dir := filepath.Dir(abs)
	if dir == abs {
		return abs, nil
	}
	parent, err := resolveLooseN(dir, depth+1)
	if err != nil {
		return "", err
	}
	full := filepath.Join(parent, filepath.Base(abs))
	fi, err := os.Lstat(full)
	if errors.Is(err, os.ErrNotExist) {
		return full, nil
	}
	if err != nil {
		return "", err
	}
	if fi.Mode()&os.ModeSymlink == 0 {
		return full, nil
	}
	t, err := os.Readlink(full)
	if err != nil {
		return "", err
	}
	if !filepath.IsAbs(t) {
		t = filepath.Join(parent, t)
	}
	return resolveLooseN(t, depth+1)
}

// forkPaths resolves the data directory through symlinks (the swap renames
// the directory itself) and names the staging directory.
func forkPaths(dataDir string) (data, staging string, err error) {
	data, err = resolveLoose(dataDir)
	if err != nil {
		return "", "", err
	}
	return data, data + forkNewSuffix, nil
}

// within reports whether p is dir or inside it. Both are resolved.
func within(p, dir string) bool {
	rel, err := filepath.Rel(dir, p)
	return err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}

func pathExists(p string) (bool, error) {
	_, err := os.Lstat(p)
	if err == nil {
		return true, nil
	}
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	return false, err
}

// gateOptional reports whether err, from taking the gate, means the data
// directory's parent does not exist or can't be written. No fork can be
// there (its staging directory would be beside the gate), so there is
// nothing to fence or exclude.
func gateOptional(err error) bool {
	return errors.Is(err, os.ErrNotExist) || errors.Is(err, os.ErrPermission) || errors.Is(err, syscall.EROFS)
}

// enterGate takes the gate of dataDir (see the file comment) shared and
// checks the fence. The caller calls the returned func once it owns the
// vault or has given up. A fork running there makes it ErrVaultBusy. A
// directory named as a fork's backup is behind the gate of the data
// directory it would be the backup of as well (taken first): a fork there
// holds that gate, not the backup's, while it moves the old vault in.
func enterGate(dataDir string) (func(), error) {
	data, staging, err := forkPaths(dataDir)
	if err != nil {
		return nil, err
	}
	var gates []*os.File
	leave := func() {
		for _, f := range gates {
			f.Close()
		}
	}
	paths := []string{data + forkGateSuffix}
	if src := backupSource(data); src != "" {
		paths = []string{src + forkGateSuffix, data + forkGateSuffix}
	}
	for _, p := range paths {
		f, err := filelock.TryLockShared(p)
		if errors.Is(err, filelock.ErrLocked) {
			leave()
			return nil, ErrVaultBusy
		}
		if err != nil && !gateOptional(err) {
			leave()
			return nil, err
		}
		if f != nil {
			gates = append(gates, f)
		}
	}
	if err := forkFence(data, staging); err != nil {
		leave()
		return nil, err
	}
	return leave, nil
}

// takeForkGate takes the gate of data exclusive, for a fork. The caller
// closes the file to give it up. Where the gate can't be made (gateOptional)
// there is no vault to fork either: it returns a nil file, which closes
// harmlessly, and the fork fails on what it does not find.
func takeForkGate(data string) (*os.File, error) {
	f, err := filelock.TryLock(data + forkGateSuffix)
	if errors.Is(err, filelock.ErrLocked) {
		return nil, ErrVaultBusy
	}
	if err != nil && gateOptional(err) {
		return nil, nil
	}
	return f, err
}

// forkFence refuses with ErrForkPending while a fork of data has a new
// vault that verified and is not done: from then on the old vault must not
// change (the swap would put the change away in the backup, or delete it
// with --discard-old), nor the new one before the fork checks it. So it is
// for any state recovery would not act on by itself. A fork that never
// verified fences nothing while the old vault is in data: it is still the
// vault, and the fork's next run deletes the staging directory. data is
// fenced too while it is an unfinished fork's backup (backupFence).
func forkFence(data, staging string) error {
	if err := backupFence(data); err != nil {
		return err
	}
	hasStaging, err := pathExists(staging)
	if err != nil {
		return err
	}
	if hasStaging {
		j, jerr := readForkJournal(staging)
		if jerr == nil && (j == nil || j.State == forkStaging) {
			if ok, err := (layout{data: data}).exists(); err != nil {
				return err
			} else if ok {
				return nil
			}
		}
		return ErrForkPending
	}
	j, err := readForkJournal(data)
	if err != nil {
		return fmt.Errorf("%w (%v)", ErrForkPending, err)
	}
	if j != nil && j.State != forkDone {
		return ErrForkPending
	}
	return nil
}

// checkForkFence is forkFence for dataDir, outside the gate: an early
// refusal, before the gate is taken to check it again.
func checkForkFence(dataDir string) error {
	data, staging, err := forkPaths(dataDir)
	if err != nil {
		return err
	}
	return forkFence(data, staging)
}

// ForkInProgress reports whether a fork of the vault in dataDir has
// started and not finished: hop init and hop vault fork must not begin
// anything else there until ResumeFork or AbandonFork has run.
func ForkInProgress(dataDir string) (bool, error) {
	data, staging, err := forkPaths(dataDir)
	if err != nil {
		return false, err
	}
	if ok, err := pathExists(staging); err != nil || ok {
		return ok, err
	}
	j, err := readForkJournal(data)
	if err != nil {
		return true, err
	}
	return j != nil && j.State != forkDone, nil
}

// ForkSealed reports whether the new vault of an interrupted fork keeps
// its device key in a sealed file: finishing the fork opens that vault,
// so it needs the device passphrase.
func ForkSealed(dataDir string) (bool, error) {
	data, staging, err := forkPaths(dataDir)
	if err != nil {
		return false, err
	}
	if ok, err := pathExists(staging); err != nil {
		return false, err
	} else if ok {
		return SealedDeviceFile(staging)
	}
	if j, err := readForkJournal(data); err != nil || j == nil || j.State == forkDone {
		return false, err
	}
	return SealedDeviceFile(data)
}

// ForkRecord returns the journal a finished fork left in dataDir, or nil
// when the vault there was not made by a fork.
func ForkRecord(dataDir string) (*ForkResult, error) {
	data, _, err := forkPaths(dataDir)
	if err != nil {
		return nil, err
	}
	j, err := readForkJournal(data)
	if err != nil || j == nil {
		return nil, err
	}
	return j.result(), nil
}

// withPassphrase is cfg with pass, when there is one, as the device
// passphrase.
func withPassphrase(cfg Config, pass []byte) Config {
	if len(pass) == 0 {
		return cfg
	}
	get := cfg.Getenv
	if get == nil {
		get = os.Getenv
	}
	p := string(pass)
	cfg.Getenv = func(k string) string {
		if k == PassphraseEnv {
			return p
		}
		return get(k)
	}
	return cfg
}

// ResumeFork finishes a fork that a crash interrupted. One that had not
// verified its new vault is abandoned: its staging directory and device
// record are deleted, the old vault is left as it was, and abandoned is
// true (the Emergency Kit it showed belongs to no vault). One that had is
// finished: the swap, the discard if asked for, and done, each only after
// the vaults check out against the journal (finishFork). It returns nil
// and false when there is nothing to resume. opts.Passphrase opens a new
// vault whose device key file is sealed.
func ResumeFork(ctx context.Context, cfg Config, opts ForkOptions) (res *ForkResult, abandoned bool, err error) {
	data, staging, err := forkPaths(cfg.DataDir)
	if err != nil {
		return nil, false, err
	}
	gate, err := takeForkGate(data)
	if err != nil {
		return nil, false, err
	}
	defer gate.Close()
	cfg = withPassphrase(cfg, opts.Passphrase)
	cfg.DataDir = data
	var j *forkJournal
	if ok, err := pathExists(staging); err != nil {
		return nil, false, err
	} else if ok {
		var jerr error
		j, jerr = readForkJournal(staging)
		if jerr != nil {
			return nil, false, fmt.Errorf("%w: %w; hop vault fork --local --abandon gives the fork up", ErrForkDamaged, jerr)
		}
		if j != nil {
			if err := j.check(data); err != nil {
				return nil, false, err
			}
		}
		if j == nil || j.State == forkStaging {
			// It never verified: the old vault is still the vault.
			if ok, err := (layout{data: data}).exists(); err != nil {
				return nil, false, err
			} else if !ok {
				return nil, false, fmt.Errorf("%w: %s holds no vault, and the fork in %s never verified its new one; nothing was deleted",
					ErrForkDamaged, data, staging)
			}
			return nil, true, abandonStaging(cfg, staging, j)
		}
		if j.State != forkVerified {
			return nil, false, fmt.Errorf("%w: the staging directory %s says %q", ErrForkDamaged, staging, j.State)
		}
	} else {
		if j, err = readForkJournal(data); err != nil || j == nil || j.State == forkDone {
			return nil, false, err
		}
		if err := j.check(data); err != nil {
			return nil, false, err
		}
		if j.State != forkVerified && j.State != forkSwapped {
			return nil, false, fmt.Errorf("%w: the fork journal in %s is %q, with no staging directory", ErrForkDamaged, data, j.State)
		}
	}
	if opts.KeepOld {
		if j.Discarding {
			// Never a silent deletion of what was asked kept, nor a backup
			// kept as whole that may have lost its device key already.
			return nil, false, fmt.Errorf("%w: the fork had begun to delete the old vault in %s when it stopped (its device key may be gone already), "+
				"so --keep-old can't keep it; nothing was changed. Run hop vault fork --local without --keep-old to finish the deletion, "+
				"or first move %s elsewhere to keep what is left of it", ErrForkRefused, j.Backup, j.Backup)
		}
		j.DiscardOld = false
	}
	if err := finishFork(ctx, cfg, data, j); err != nil {
		return nil, false, err
	}
	r := j.result()
	r.Resumed = true
	return r, false, nil
}

// AbandonFork gives up an interrupted fork whose new vault is not in the
// data directory yet: the old vault is put back from the backup if the
// swap had moved it there, then the staging directory and its device key
// are deleted. The old vault is never changed. A fork whose new vault is
// in place is not abandoned (ResumeFork finishes it; the old vault is in
// its backup). It returns false when there is no fork to give up.
func AbandonFork(ctx context.Context, cfg Config) (bool, error) {
	data, staging, err := forkPaths(cfg.DataDir)
	if err != nil {
		return false, err
	}
	gate, err := takeForkGate(data)
	if err != nil {
		return false, err
	}
	defer gate.Close()
	cfg.DataDir = data
	if ok, err := pathExists(staging); err != nil {
		return false, err
	} else if !ok {
		j, err := readForkJournal(data)
		if err != nil {
			return false, err
		}
		if j != nil && j.State != forkDone {
			return false, fmt.Errorf("%w: the fork's new vault is in %s already, so it can't be given up; hop vault fork --local finishes it (the old vault is in %s)",
				ErrForkRefused, data, j.Backup)
		}
		return false, nil
	}
	j, jerr := readForkJournal(staging)
	if jerr == nil && j != nil {
		if err := j.check(data); err != nil {
			return false, err
		}
	}
	hasVault, err := (layout{data: data}).exists()
	if err != nil {
		return false, err
	}
	switch {
	case !hasVault:
		// The swap had moved the old vault aside: it goes back first.
		if jerr != nil || j == nil {
			return false, fmt.Errorf("%w: %s holds no vault, and no journal says where it went; nothing was changed", ErrForkDamaged, data)
		}
		if ok, err := pathExists(data); err != nil {
			return false, err
		} else if ok {
			return false, fmt.Errorf("%w: %s holds something that is not the vault; nothing was changed", ErrForkDamaged, data)
		}
		if err := isOldVault(cfg, j.Backup, j); err != nil {
			return false, err
		}
		owner, err := lockBackup(j.Backup)
		if err != nil {
			return false, err
		}
		err = os.Rename(j.Backup, data)
		owner.Close()
		if err != nil {
			return false, err
		}
		if err := syncDir(filepath.Dir(data)); err != nil {
			return false, err
		}
	case j != nil:
		if err := isOldVault(cfg, data, j); err != nil {
			return false, err
		}
	}
	return true, abandonStaging(cfg, staging, j)
}

// abandonStaging deletes a staging directory whose new vault is not in
// use: the keychain entries of the device the journal j (if any) names and
// of those its device.json names first, then the directory. An entry the
// data directory's own device.json names (the old vault's) is never
// deleted, whatever the staging directory claims.
func abandonStaging(cfg Config, staging string, j *forkJournal) error {
	s := &Store{cfg: cfg, l: layout{data: staging}}
	keep := map[retireRecord]bool{}
	old := &Store{cfg: cfg, l: layout{data: strings.TrimSuffix(staging, forkNewSuffix)}}
	if dc, err := old.readDeviceConfig(); err == nil {
		for _, r := range retireRecords(dc) {
			keep[r] = true
		}
	}
	del := func(store string, r retireRecord) error {
		if keep[r] {
			return nil
		}
		ds := s.deviceStore(deviceConfig{V: 1, Store: store, AccountID: r.AccountID})
		if err := ds.deleteSlot(r.DeviceID); err != nil {
			return fmt.Errorf("store: deleting the device key of an abandoned fork: %w", err)
		}
		return nil
	}
	if j != nil {
		if err := del(j.NewStore, retireRecord{AccountID: j.New.AccountID, DeviceID: j.New.DeviceID}); err != nil {
			return err
		}
	}
	if dc, err := s.readDeviceConfig(); err == nil {
		for _, r := range retireRecords(dc) {
			if err := del(dc.Store, r); err != nil {
				return err
			}
		}
	}
	if err := os.RemoveAll(staging); err != nil {
		return err
	}
	return syncDir(filepath.Dir(staging))
}

// isOldVault requires dir to hold the old vault of the fork j, by its
// device.json.
func isOldVault(cfg Config, dir string, j *forkJournal) error {
	s := &Store{cfg: cfg, l: layout{data: dir}}
	dc, err := s.readDeviceConfig()
	if err != nil || dc.AccountID != j.Plan.Old.AccountID || dc.DeviceID != j.Plan.Old.DeviceID {
		return fmt.Errorf("%w: %s does not hold the vault that was forked; nothing was changed", ErrForkDamaged, dir)
	}
	return nil
}

// ForkOptions are hop vault fork's inputs about the old vault.
type ForkOptions struct {
	// Passphrase opens a sealed device key file in place of
	// HOP_DEVICE_PASSPHRASE. The new vault's sealed file gets it too.
	Passphrase []byte
	// KeepOld, for ResumeFork, keeps the backup of a fork that was to
	// delete it (--discard-old): the way to finish a fork whose backup
	// changed after the swap. Once its deletion had begun, the resume is
	// refused (ErrForkRefused) and nothing is deleted.
	KeepOld bool
}

// PendingFork is a fork prepared and not committed: it owns the old
// vault, and holds its items in memory.
type PendingFork struct {
	cfg     Config
	src     *Store
	data    string
	staging string
	oldCfg  deviceConfig
	plan    ForkPlan
	pass    []byte
	// gate is the data directory's gate, held exclusive until Close.
	gate *os.File
	// source is forkSourceDigest of the old vault as read.
	source string

	// verified and final are the old vault's items by old ID: verified
	// state, and the overlay (what this device showed), sanitized.
	verified map[model.ID]crypto.Item
	final    map[model.ID]crypto.Item
	ids      map[model.ID]model.ID // old item ID to new

	init *PendingInit
	ncfg Config
	done bool
	// abandoned is set when Commit failed and left no new vault.
	abandoned bool
}

// PrepareFork opens the vault in cfg.DataDir, checks that it may be
// forked, and reads its items. It writes nothing but what opening a vault
// may finish (a crashed commit). The caller must Close the result.
//
// Refused: a device revoked from its account, by proof or by the
// server's report (ErrForkRevoked); a vault that is local-only already
// (ErrNotServerBacked); one with a login merge or a publication in
// progress, with grants or deploy operations, or a key dedicated to a
// grant, or with an item of a type this build does not carry
// (ErrForkRefused); a fork in progress (ErrForkPending). A logout that is
// pending (RETIRING) is no obstacle: the fork reads the vault in memory,
// as the logout's own resolution does.
//
// The fork holds the data directory's gate from here until Close, so
// nothing else opens or makes a vault there meanwhile.
func PrepareFork(ctx context.Context, cfg Config, opts ForkOptions) (*PendingFork, error) {
	data, staging, err := forkPaths(cfg.DataDir)
	if err != nil {
		return nil, err
	}
	gate, err := takeForkGate(data)
	if err != nil {
		return nil, err
	}
	if pending, err := ForkInProgress(data); err != nil || pending {
		gate.Close()
		if err == nil {
			err = ErrForkPending
		}
		return nil, err
	}
	if err := backupFence(data); err != nil {
		gate.Close()
		return nil, err
	}
	ocfg := cfg
	ocfg.DataDir = data
	src, err := openStore(ctx, ocfg, false)
	if err != nil {
		gate.Close()
		return nil, err
	}
	p := &PendingFork{cfg: ocfg, src: src, data: data, staging: staging, pass: slices.Clone(opts.Passphrase), gate: gate}
	if err := p.read(); err != nil {
		p.Close()
		return nil, err
	}
	return p, nil
}

// Plan says what Commit will do.
func (p *PendingFork) Plan() ForkPlan { return p.plan }

// Close gives up the old vault and drops what was read. A generated new
// account that was not committed is discarded.
func (p *PendingFork) Close() {
	if p.init != nil && !p.done {
		p.init.Discard()
	}
	if p.src != nil {
		p.src.Close()
		p.src = nil
	}
	if p.gate != nil {
		p.gate.Close()
		p.gate = nil
	}
	clear(p.verified)
	clear(p.final)
	clear(p.pass)
}

// Touches reports whether path, resolved through symlinks, is in a
// directory the fork moves or deletes: the data directory (moved into the
// backup, which --discard-old deletes), the staging directory and the
// backup. hop vault fork refuses an Emergency Kit file there.
func (p *PendingFork) Touches(path string) (bool, error) {
	r, err := resolveLoose(path)
	if err != nil {
		return false, err
	}
	for _, d := range []string{p.data, p.staging, p.plan.Backup} {
		if within(r, d) {
			return true, nil
		}
	}
	return false, nil
}

// read loads the old vault in memory, refuses what can't be forked, and
// computes the plan.
func (p *PendingFork) read() error {
	s := p.src
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.checkRevoked(); err != nil {
		if errors.Is(err, ErrDeviceRevoked) {
			return fmt.Errorf("%w: %w", ErrForkRevoked, err)
		}
		return err
	}
	if err := s.refuseReported(); err != nil {
		return errForkReported
	}
	if len(p.pass) > 0 {
		pass := p.pass
		s.passphrase.Store(&pass)
		defer s.passphrase.Store(nil)
	}
	// The vault as a logout's resolution loads it: verified in memory,
	// whatever the logout journal says, never installed for use.
	v, unlock, err := s.loadVault(true, false)
	if err != nil {
		return err
	}
	defer unlock()
	defer v.zero()
	// What a crash left journaled is replayed now: read the vault's state
	// files only from here.
	if err := s.refuseReported(); err != nil {
		return errForkReported
	}
	sf, err := s.l.readServerFile()
	if err != nil {
		return err
	}
	if sf == nil {
		return fmt.Errorf("%w: it has no server to salvage it from", ErrNotServerBacked)
	}
	if ok, err := s.l.mergeExists(); err != nil {
		return err
	} else if ok {
		return fmt.Errorf("%w: a login merge is in progress (hop auth merge)", ErrForkRefused)
	}
	if ok, err := s.l.publicationPending(); err != nil {
		return err
	} else if ok {
		return fmt.Errorf("%w: a publication is in progress (hop auth signup)", ErrForkRefused)
	}
	logout := ""
	if j, err := s.readRetireFile(); err != nil {
		return err
	} else if j != nil {
		if j.State != StateRetiring {
			return fmt.Errorf("%w: its logout finished", ErrForkRefused)
		}
		logout = StateRetiring
	}
	p.oldCfg = s.devCfg
	// The overlay is computed from fields of the store; this store is the
	// fork's own, and they are put back before anything else can use it.
	saved := [4]any{s.state, s.sec, s.dev, s.rec}
	s.state, s.sec, s.dev, s.rec = v.st, v.sec, v.dev, v.rec
	defer func() {
		s.state, s.sec = saved[0].(*vaultlog.State), saved[1].(*vaultlog.Secrets)
		s.dev, s.rec = saved[2].(*vaultlog.LocalDevice), saved[3].(*deviceRecord)
	}()
	if err := p.readLoaded(v, sf, logout); err != nil {
		return err
	}
	// What the fork read, under the file lock: the swap moves the old vault
	// only while it is still this.
	p.source, err = forkSourceDigest(p.data)
	return err
}

// forkCarries reports whether a fork imports items of type t. Any other
// type (a grant, or one a later revision adds, such as rev 17's access) is
// refused rather than dropped or carried without its rules.
func forkCarries(t model.Type) bool {
	switch t {
	case model.TypeHost, model.TypeKey, model.TypeCredential, model.TypeSnippet, model.TypePolicy:
		return true
	}
	return false
}

// forkSourceDigest commits to the old vault in data: every file of the
// data directory that says what the vault holds or is, by path and
// content (device.json and the key file, state.json and the entries'
// names, the outbox and its held records, the server, revocation, logout,
// merge and publication files, and the rest), and every directory. Left
// out are the locks, the objects (the head names them), and the files an
// open or close rewrites with no change to the vault: contact.json,
// account.json and sync-notes.json. A data directory with anything but
// directories and regular files in it, anywhere (a symbolic link), is
// refused: hop makes none there, and the fork neither follows nor deletes
// one.
func forkSourceDigest(data string) (string, error) {
	d, _, err := forkSourceScan(data, false)
	return d, err
}

// forkSourceScan is forkSourceDigest and, with manifest, the manifest of
// data that its deletion checks: every path under it, the ones the digest
// leaves out too, as "d" for a directory or "f <SHA-256 of the content>"
// for a file.
func forkSourceScan(data string, manifest bool) (string, map[string]string, error) {
	var files map[string]string
	if manifest {
		files = map[string]string{}
	}
	skip := map[string]bool{
		"vault/owner.lock": true, "vault/lock": true, "vault/objects": true, predecessorLock: true,
		"vault/" + contactRel: true, "vault/account.json": true, "vault/" + syncNotesRel: true,
	}
	skipped := func(rel string) bool {
		for r := rel; r != "."; r = path.Dir(r) {
			if skip[r] {
				return true
			}
		}
		return false
	}
	h := sha256.New()
	err := filepath.WalkDir(data, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(data, p)
		if err != nil {
			return err
		}
		rel = filepath.ToSlash(rel)
		digested := !skipped(rel)
		switch {
		case d.IsDir():
			if digested {
				fmt.Fprintf(h, "d %q\n", rel)
			}
			if manifest {
				files[rel] = "d"
			}
			return nil
		case !d.Type().IsRegular():
			return fmt.Errorf("%w: %s in %s is not a regular file or a directory (%v); a vault's data directory holds none",
				ErrForkRefused, rel, data, d.Type())
		}
		entry := strings.HasPrefix(rel, "vault/entries/")
		if digested && entry {
			fmt.Fprintf(h, "e %q\n", rel)
		}
		if !manifest && (!digested || entry) {
			return nil
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		if manifest {
			sum := sha256.Sum256(b)
			files[rel] = "f " + hex.EncodeToString(sum[:])
		}
		if digested && !entry {
			fmt.Fprintf(h, "f %q %d\n", rel, len(b))
			h.Write(b)
		}
		return nil
	})
	if err != nil {
		return "", nil, err
	}
	return hex.EncodeToString(h.Sum(nil)), files, nil
}

// readLoaded is read once the vault is loaded and installed in s for the
// overlay. The caller holds s.mu and the file lock.
func (p *PendingFork) readLoaded(v *loaded, sf *serverFile, logout string) error {
	s := p.src
	st := v.st
	if len(st.Grants) > 0 || len(st.DeployOps) > 0 {
		return fmt.Errorf("%w: it holds token grants or deploy operations, which belong to the old account's keys", ErrForkRefused)
	}
	p.verified = map[model.ID]crypto.Item{}
	for id := range v.sec.Items {
		it, err := s.verifiedItem(id)
		if err != nil {
			return err
		}
		if it == nil {
			return fmt.Errorf("%w: it holds a grant record", ErrForkRefused)
		}
		pt, err := plainOf(it)
		if err != nil {
			return err
		}
		p.verified[id] = pt
	}
	ov, err := s.overlayLocked()
	if err != nil {
		return err
	}
	recs, err := s.readOutbox()
	if err != nil {
		return err
	}
	p.final = map[model.ID]crypto.Item{}
	for id, it := range ov.items {
		pt, err := plainOf(it)
		if err != nil {
			return err
		}
		p.final[id] = pt
	}
	for _, m := range []map[model.ID]crypto.Item{p.verified, p.final} {
		for _, it := range m {
			if t := header(it).Type; !forkCarries(t) {
				return fmt.Errorf("%w: it holds an item of type %q, which this version of hop can't carry into a fork", ErrForkRefused, t)
			}
		}
	}
	plan := ForkPlan{
		DataDir: p.data, Server: sf.Server, Logout: logout,
		Old: ForkIDs{AccountID: st.Account.AccountID, VaultID: st.VaultID, DeviceID: v.dev.ID},
	}
	for _, r := range recs {
		if r.Held {
			plan.Held++
			if r.Intent.Action == merge.ActionDelete && p.final[r.Intent.ItemID] != nil {
				plan.HeldDeletes++
				plan.Warnings = append(plan.Warnings, fmt.Sprintf("a held delete of %s is not applied: the item is kept as this device showed it; delete it again if you still want it gone",
					itemLabel(p.final[r.Intent.ItemID])))
			}
		} else {
			plan.Pending++
		}
	}
	for _, it := range p.final {
		if k, ok := it.(*model.Key); ok && !k.DedicatedGrant.IsZero() {
			return fmt.Errorf("%w: key %q is dedicated to a token grant", ErrForkRefused, k.Name)
		}
	}
	plan.Warnings = append(plan.Warnings, sanitizeRefs(p.final)...)
	for _, it := range p.final {
		switch it.(type) {
		case *model.Host:
			plan.Hosts++
		case *model.Key:
			plan.Keys++
		case *model.Credential:
			plan.Credentials++
		case *model.Snippet:
			plan.Snippets++
		case *model.Policy:
			plan.Policies++
		}
	}
	for id, d := range st.Devices {
		if id != v.dev.ID {
			plan.OtherDevices = append(plan.OtherDevices, ForkDevice{DeviceID: id, Name: d.Cert.Name})
		}
	}
	slices.SortFunc(plan.OtherDevices, func(a, b ForkDevice) int { return strings.Compare(a.DeviceID.String(), b.DeviceID.String()) })
	plan.Departed = slices.Clone(st.Retired.DeviceIDs)
	if plan.Departed == nil {
		plan.Departed = []model.ID{}
	}
	if plan.OtherDevices == nil {
		plan.OtherDevices = []ForkDevice{}
	}
	plan.Backup = p.data + forkBackupStem + time.Unix(int64(s.now()), 0).UTC().Format("20060102") + "-" + st.VaultID.String()[:8]
	if ok, err := pathExists(plan.Backup); err != nil {
		return err
	} else if ok {
		return fmt.Errorf("%w: %s already exists (an earlier fork's backup?); move it away first", ErrForkRefused, plan.Backup)
	}
	p.plan = plan
	p.ids = map[model.ID]model.ID{}
	for _, m := range []map[model.ID]crypto.Item{p.verified, p.final} {
		for id := range m {
			if _, ok := p.ids[id]; ok {
				continue
			}
			nid, err := vaultlog.NewID()
			if err != nil {
				return err
			}
			p.ids[id] = nid
		}
	}
	return nil
}

// itemLabel names an item for a warning.
func itemLabel(it crypto.Item) string {
	switch v := it.(type) {
	case *model.Host:
		return fmt.Sprintf("host %q", v.Name)
	case *model.Key:
		return fmt.Sprintf("key %q", v.Name)
	case *model.Credential:
		return fmt.Sprintf("credential %q", v.Name)
	case *model.Snippet:
		return fmt.Sprintf("snippet %q", v.Name)
	case *model.Policy:
		return "the account policy"
	}
	return "an item"
}

// sanitizeRefs makes items, the overlay, satisfy the log's reference
// rules, which verified state already does but the queued changes applied
// to a newer verified state need not: a host reference to an item that is
// gone or of another type, and a jump host loop, are cleared, each with a
// warning.
func sanitizeRefs(items map[model.ID]crypto.Item) []string {
	var warns []string
	ids := make([]model.ID, 0, len(items))
	for id := range items {
		ids = append(ids, id)
	}
	slices.SortFunc(ids, func(a, b model.ID) int { return strings.Compare(a.String(), b.String()) })
	is := func(id model.ID, t model.Type) bool {
		it, ok := items[id]
		return ok && header(it).Type == t
	}
	for _, id := range ids {
		h, ok := items[id].(*model.Host)
		if !ok {
			continue
		}
		if !h.KeyID.IsZero() && !is(h.KeyID, model.TypeKey) {
			h.KeyID = model.ID{}
			warns = append(warns, fmt.Sprintf("host %q named a key the vault no longer has; it now has none", h.Name))
		}
		if !h.CredentialID.IsZero() && !is(h.CredentialID, model.TypeCredential) {
			h.CredentialID = model.ID{}
			warns = append(warns, fmt.Sprintf("host %q named a credential the vault no longer has; it now has none", h.Name))
		}
		if !h.JumpHostID.IsZero() && !is(h.JumpHostID, model.TypeHost) {
			h.JumpHostID = model.ID{}
			warns = append(warns, fmt.Sprintf("host %q named a jump host the vault no longer has; it is now reached directly", h.Name))
		}
	}
	for _, id := range ids {
		h, ok := items[id].(*model.Host)
		if !ok {
			continue
		}
		seen := map[model.ID]bool{id: true}
		for next := h.JumpHostID; !next.IsZero(); {
			if seen[next] {
				warns = append(warns, fmt.Sprintf("host %q was in a jump host loop; it is now reached directly", h.Name))
				h.JumpHostID = model.ID{}
				break
			}
			seen[next] = true
			next = items[next].(*model.Host).JumpHostID
		}
	}
	return warns
}

// UnsealedFile is PendingInit.UnsealedFile for the new vault, once
// Generate has run.
func (p *PendingFork) UnsealedFile() (string, bool) {
	if p.init == nil {
		return "", false
	}
	_, unsealed := p.init.UnsealedFile()
	return filepath.Join(p.data, "device.key"), unsealed
}

// DeviceStore says where the new vault's device key will be.
func (p *PendingFork) DeviceStore() string {
	if p.init == nil {
		return ""
	}
	return p.init.DeviceStore()
}

// Generate makes the new account in memory, as hop init does, under
// password, with its device key in deviceStore ("" keeps the old vault's
// kind of store), and returns its Emergency Kit. Nothing is written.
func (p *PendingFork) Generate(password []byte, deviceStore string) (Kit, error) {
	if p.init != nil {
		return Kit{}, errors.New("store: the fork's account was generated already")
	}
	if ok, err := pathExists(p.staging); err != nil {
		return Kit{}, err
	} else if ok {
		return Kit{}, fmt.Errorf("%w: %s exists", ErrForkPending, p.staging)
	}
	if deviceStore == "" {
		deviceStore = p.oldCfg.Store
	}
	p.ncfg = withPassphrase(p.cfg, p.pass)
	p.ncfg.DataDir = p.staging
	init, err := PrepareInit(p.ncfg, InitOptions{Password: password, DeviceStore: deviceStore})
	if err != nil {
		return Kit{}, err
	}
	// The fork holds the gate of the data directory the staging directory
	// becomes.
	init.s.ungated = true
	p.init = init
	return init.Kit(), nil
}

// Commit builds the new vault, verifies it, swaps it in for the old one
// and, with discardOld, deletes the old one. See the file comment for the
// steps and what a crash leaves.
func (p *PendingFork) Commit(ctx context.Context, discardOld bool) (*ForkResult, error) {
	if p.init == nil || p.done {
		return nil, errors.New("store: the fork has no generated account, or was committed")
	}
	j := &forkJournal{
		V: forkVersion, State: forkStaging, DataDir: p.data, Backup: p.plan.Backup, DiscardOld: discardOld,
		At: p.src.now(), Plan: p.planRecord(),
		New:      ForkIDs{AccountID: p.init.state.Account.AccountID, VaultID: p.init.state.VaultID, DeviceID: p.init.rec.DeviceID},
		NewStore: p.init.devCfg.Store, Source: p.source,
	}
	var err error
	if j.TxnID, err = vaultlog.NewID(); err != nil {
		p.abandoned = true
		return nil, err
	}
	if err := j.check(p.data); err != nil {
		p.abandoned = true
		return nil, err
	}
	if err := p.stage(ctx, j); err != nil {
		if aerr := abandonStaging(p.ncfg, p.staging, j); aerr != nil {
			err = fmt.Errorf("%w (and its staging directory %s could not be deleted: %v)", err, p.staging, aerr)
		} else {
			p.abandoned = true
		}
		return nil, err
	}
	p.done = true
	// The old vault's store lets go before the swap: its paths name the
	// data directory, which is about to hold the new vault. finishFork
	// takes the vault's owner lock again before it moves it, and the gate,
	// still held, keeps every other opener out meanwhile.
	p.src.Close()
	p.src = nil
	if err := finishFork(ctx, withPassphrase(p.cfg, p.pass), p.data, j); err != nil {
		return nil, err
	}
	r := j.result()
	r.Warnings = p.plan.Warnings
	return r, nil
}

// Abandoned reports whether a Commit that failed is known to have left no
// new vault: it failed before it began, or its staging directory was
// deleted. Only then does the Emergency Kit Generate returned belong to
// no vault. Any other failure may have left the new vault in place (or a
// fork that ResumeFork finishes), so its kit must be kept.
func (p *PendingFork) Abandoned() bool { return p.abandoned }

func (p *PendingFork) planRecord() forkPlanRecord {
	pl := p.plan
	return forkPlanRecord{
		Server: pl.Server, Old: pl.Old, Logout: pl.Logout, Hosts: pl.Hosts, Keys: pl.Keys, Credentials: pl.Credentials,
		Snippets: pl.Snippets, Policies: pl.Policies, Pending: pl.Pending, Held: pl.Held, HeldDeletes: pl.HeldDeletes,
		OtherDevices: pl.OtherDevices, Departed: pl.Departed,
	}
}

// stage builds and verifies the new vault in the staging directory, and
// records verified.
func (p *PendingFork) stage(ctx context.Context, j *forkJournal) error {
	if _, err := safepath.EnsurePrivateDir(p.staging); err != nil {
		return err
	}
	if err := writeForkJournal(p.staging, j); err != nil {
		return err
	}
	if err := forkStage("fork:staging"); err != nil {
		return err
	}
	ns, err := p.init.Commit()
	if err != nil {
		return err
	}
	err = p.importInto(ns)
	if cerr := ns.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return err
	}
	if err := forkStage("fork:imported"); err != nil {
		return err
	}
	if err := p.verify(ctx, j); err != nil {
		return err
	}
	j.State = forkVerified
	if err := writeForkJournal(p.staging, j); err != nil {
		return err
	}
	return forkStage("fork:verified")
}

// remap returns a copy of it under its new item ID, with its references
// renamed, and the version left for the build to fill in.
func (p *PendingFork) remap(old model.ID, it crypto.Item) (crypto.Item, error) {
	mi, err := merge.ItemOf(it)
	if err != nil {
		return nil, err
	}
	c, err := plainOf(mi)
	if err != nil {
		return nil, err
	}
	h := header(c)
	h.ItemID, h.ItemVersion = p.ids[old], 0
	if host, ok := c.(*model.Host); ok {
		for _, ref := range []*model.ID{&host.KeyID, &host.CredentialID, &host.JumpHostID} {
			if !ref.IsZero() {
				nid, ok := p.ids[*ref]
				if !ok {
					return nil, fmt.Errorf("store: host %q refers to an item the fork did not read", host.Name)
				}
				*ref = nid
			}
		}
	}
	return c, nil
}

// depOrder lists the IDs of items so that every item comes after what it
// refers to: keys, credentials, policies and snippets first, then hosts,
// each after its jump host.
func depOrder(items map[model.ID]crypto.Item) []model.ID {
	rank := map[model.Type]int{model.TypeKey: 0, model.TypeCredential: 1, model.TypePolicy: 2, model.TypeSnippet: 3}
	var flat, hosts []model.ID
	for id, it := range items {
		if _, ok := it.(*model.Host); ok {
			hosts = append(hosts, id)
		} else {
			flat = append(flat, id)
		}
	}
	byID := func(a, b model.ID) int { return strings.Compare(a.String(), b.String()) }
	slices.SortFunc(flat, func(a, b model.ID) int {
		if d := rank[header(items[a]).Type] - rank[header(items[b]).Type]; d != 0 {
			return d
		}
		return byID(a, b)
	})
	slices.SortFunc(hosts, byID)
	placed := map[model.ID]bool{}
	var visit func(id model.ID)
	visit = func(id model.ID) {
		if placed[id] {
			return
		}
		placed[id] = true // set first: a loop (sanitized away) can't recurse forever
		if j := items[id].(*model.Host).JumpHostID; !j.IsZero() {
			if _, ok := items[j].(*model.Host); ok {
				visit(j)
			}
		}
		flat = append(flat, id)
	}
	for _, id := range hosts {
		visit(id)
	}
	return flat
}

// importInto writes the items into ns, the new vault: verified state in
// batches, then one entry per item that a queued change created or
// changed, then the deletes those changes made, in one entry.
func (p *PendingFork) importInto(ns *Store) error {
	ns.mu.Lock()
	defer ns.mu.Unlock()
	var batch []crypto.Item
	flush := func() error {
		if len(batch) == 0 {
			return nil
		}
		err := ns.forkWrite(vaultlog.Changes{Put: batch})
		batch = nil
		return err
	}
	for _, id := range depOrder(p.verified) {
		it, err := p.remap(id, p.verified[id])
		if err != nil {
			return err
		}
		batch = append(batch, it)
		if len(batch) == forkBatch {
			if err := flush(); err != nil {
				return err
			}
		}
	}
	if err := flush(); err != nil {
		return err
	}
	for _, id := range depOrder(p.final) {
		want := p.final[id]
		if cur, ok := p.verified[id]; ok && sameItem(cur, want) {
			continue
		}
		it, err := p.remap(id, want)
		if err != nil {
			return err
		}
		if err := ns.forkWrite(vaultlog.Changes{Put: []crypto.Item{it}}); err != nil {
			return err
		}
	}
	var del []model.ID
	for id := range p.verified {
		if _, ok := p.final[id]; !ok {
			del = append(del, p.ids[id])
		}
	}
	if len(del) > 0 {
		slices.SortFunc(del, func(a, b model.ID) int { return strings.Compare(a.String(), b.String()) })
		if err := ns.forkWrite(vaultlog.Changes{Delete: del}); err != nil {
			return err
		}
	}
	return nil
}

// sameItem reports whether a and b agree on every member but the header.
func sameItem(a, b crypto.Item) bool {
	ma, err := merge.ItemOf(a)
	if err != nil {
		return false
	}
	mb, err := merge.ItemOf(b)
	if err != nil {
		return false
	}
	return ma.Type() == mb.Type() && ma.Equal(mb)
}

// forkWrite commits ch as one entry if the server would admit it (so a
// later publish can upload it), or else split: puts and deletes in
// halves, until each entry fits. An item that fits no entry by itself is
// refused by name, before anything of it is committed: an entry is
// immutable, and one the server refuses would keep the new vault from
// ever being published. The caller holds s.mu.
func (s *Store) forkWrite(ch vaultlog.Changes) error {
	unlock, err := s.lockFile()
	if err != nil {
		return err
	}
	w, st, sec, err := vaultlog.BuildNormal(s.state, s.sec, s.dev, ch, s.now(), objectDir(s.l.objects()))
	if err == nil {
		if aerr := admitWire(w); aerr != nil {
			unlock()
			return s.forkSplit(ch, aerr)
		}
	}
	defer unlock()
	if err != nil {
		return err
	}
	if err := s.commit(w, st); err != nil {
		return err
	}
	s.state, s.sec = st, sec
	return nil
}

// forkSplit is forkWrite of ch, which admission refused with aerr, in two
// halves.
func (s *Store) forkSplit(ch vaultlog.Changes, aerr error) error {
	switch {
	case !errors.Is(aerr, ErrTooLarge):
		return aerr
	case len(ch.Put) > 1:
		half := len(ch.Put) / 2
		if err := s.forkWrite(vaultlog.Changes{Put: ch.Put[:half]}); err != nil {
			return err
		}
		return s.forkWrite(vaultlog.Changes{Put: ch.Put[half:]})
	case len(ch.Delete) > 1:
		half := len(ch.Delete) / 2
		if err := s.forkWrite(vaultlog.Changes{Delete: ch.Delete[:half]}); err != nil {
			return err
		}
		return s.forkWrite(vaultlog.Changes{Delete: ch.Delete[half:]})
	case len(ch.Put) == 1:
		return fmt.Errorf("%w: %s is larger than a server accepts as one change (%w), so a vault holding it could never be published; "+
			"make it smaller or delete it in this vault, then fork again", ErrForkRefused, itemLabel(ch.Put[0]), aerr)
	}
	return aerr
}

// forkedVault is what a fork checks of its new vault, opened from disk.
type forkedVault struct {
	ids   ForkIDs
	head  vaultlog.Head
	items map[model.ID]crypto.Item
}

// readNewVault opens the vault in cfg.DataDir as hop opens any vault (the
// log verified from genesis with its device key), outside the gate, which
// the fork holds, and reads what the fork checks of it: it must unlock and
// be local-only.
func readNewVault(ctx context.Context, cfg Config) (*forkedVault, error) {
	ns, err := openStore(ctx, cfg, false)
	if err != nil {
		return nil, fmt.Errorf("the new vault does not open: %w", err)
	}
	defer ns.Close()
	if info := ns.Info(); info.Locked {
		return nil, fmt.Errorf("the new vault does not unlock: %s", info.LockReason)
	}
	if _, err := ns.ServerInfo(); !errors.Is(err, ErrNotServerBacked) {
		return nil, fmt.Errorf("the new vault is not local-only (%v)", err)
	}
	ns.mu.Lock()
	nv := &forkedVault{
		ids:  ForkIDs{AccountID: ns.state.Account.AccountID, VaultID: ns.state.VaultID, DeviceID: ns.dev.ID},
		head: ns.state.Head, items: map[model.ID]crypto.Item{},
	}
	ns.mu.Unlock()
	snap, err := ns.Snapshot(ctx)
	if err != nil {
		return nil, err
	}
	for i := range snap.Hosts {
		nv.items[snap.Hosts[i].ItemID] = &snap.Hosts[i]
	}
	for i := range snap.Keys {
		nv.items[snap.Keys[i].ItemID] = &snap.Keys[i]
	}
	for i := range snap.Credentials {
		nv.items[snap.Credentials[i].ItemID] = &snap.Credentials[i]
	}
	for i := range snap.Snippets {
		nv.items[snap.Snippets[i].ItemID] = &snap.Snippets[i]
	}
	for i := range snap.Policies {
		nv.items[snap.Policies[i].ItemID] = &snap.Policies[i]
	}
	return nv, nil
}

// verify opens the staged vault as hop opens any vault, checks that it is
// the new account's, local-only, and holds exactly the items imported,
// and records its head and item count in j.
func (p *PendingFork) verify(ctx context.Context, j *forkJournal) error {
	nv, err := readNewVault(ctx, p.ncfg)
	if err != nil {
		return fmt.Errorf("store: %w", err)
	}
	if nv.ids != j.New {
		return errors.New("store: the new vault's identity is not the one generated")
	}
	if nv.ids.VaultID == j.Plan.Old.VaultID || nv.ids.AccountID == j.Plan.Old.AccountID || j.New.DeviceID == j.Plan.Old.DeviceID {
		return errors.New("store: the new vault reuses an old identity")
	}
	got := nv.items
	if len(got) != len(p.final) {
		return fmt.Errorf("store: the new vault holds %d items, not the %d imported", len(got), len(p.final))
	}
	for old, it := range p.final {
		want, err := p.remap(old, it)
		if err != nil {
			return err
		}
		if _, reused := got[old]; reused {
			return errors.New("store: the new vault reuses an old item ID")
		}
		g, ok := got[p.ids[old]]
		if !ok || !sameItem(g, want) {
			return fmt.Errorf("store: %s did not arrive in the new vault as it was", itemLabel(it))
		}
	}
	j.NewHead, j.NewItems = nv.head, len(got)
	return nil
}

// checkNewVault opens the new vault in dir and requires it to be the one
// j recorded at verified: its identity, its head and its item count. A
// fork does nothing past verified (the swap, recording it, deleting the
// backup) without it.
func checkNewVault(ctx context.Context, cfg Config, dir string, j *forkJournal) error {
	ncfg := cfg
	ncfg.DataDir = dir
	nv, err := readNewVault(ctx, ncfg)
	if err == nil && (nv.ids != j.New || nv.head != j.NewHead || len(nv.items) != j.NewItems) {
		err = fmt.Errorf("it is not the vault the fork verified (head %d, %d items; the fork recorded head %d, %d items)",
			nv.head.Seq, len(nv.items), j.NewHead.Seq, j.NewItems)
	}
	if err != nil {
		return fmt.Errorf("%w: %s: %w; nothing more was changed", ErrForkDamaged, dir, err)
	}
	return nil
}

// finishFork carries a verified fork of data (the resolved data directory,
// which j was checked against) through the swap, the discard if asked
// for, and done. Each step checks what is on disk first, so it resumes
// from wherever a crash stopped it, and the new vault is opened and checked
// against j before each step that relies on it. The caller holds the gate.
// The backup's owner lock, once taken (moving the old vault there, or
// checking it there), is held until finishFork returns, on every path.
func finishFork(ctx context.Context, cfg Config, data string, j *forkJournal) error {
	var owner backupOwner
	defer owner.release()
	staging := data + forkNewSuffix
	parent := filepath.Dir(data)
	hasStaging, err := pathExists(staging)
	if err != nil {
		return err
	}
	if hasStaging {
		if j.State != forkVerified {
			return fmt.Errorf("%w: the fork journal is %q with the staging directory still there", ErrForkDamaged, j.State)
		}
		if err := checkNewVault(ctx, cfg, staging, j); err != nil {
			return err
		}
		hasData, err := pathExists(data)
		if err != nil {
			return err
		}
		if hasData {
			if err := moveOld(cfg, data, j, &owner); err != nil {
				return err
			}
			if err := forkStage("fork:moved-old"); err != nil {
				return err
			}
		} else if _, err := holdBackup(cfg, j, &owner); err != nil {
			// Not in data, and not in the backup as the fork read it: the
			// old vault is missing or changed, so nothing takes its place.
			return err
		}
		if err := os.Rename(staging, data); err != nil {
			return err
		}
		if err := syncDir(parent); err != nil {
			return err
		}
		if err := forkStage("fork:moved-new"); err != nil {
			return err
		}
	}
	// The new vault in data must be the one verified before the swap is
	// recorded or the backup deleted.
	if err := checkNewVault(ctx, cfg, data, j); err != nil {
		return err
	}
	if j.State == forkVerified {
		j.State = forkSwapped
		if err := writeForkJournal(data, j); err != nil {
			return err
		}
	}
	switch {
	case j.DiscardOld && !j.Discarded:
		deleted, err := discardBackup(cfg, data, j, &owner)
		if err != nil {
			return fmt.Errorf("the new vault is in place, but the old one in %s could not be deleted: %w", j.Backup, err)
		}
		if err := forkStage("fork:discarded"); err != nil {
			return err
		}
		j.Discarded, j.BackupMissing = deleted, !deleted
	case !j.DiscardOld:
		ok, err := pathExists(j.Backup)
		if err != nil {
			return err
		}
		j.BackupMissing = !ok
	}
	j.State = forkDone
	return writeForkJournal(data, j)
}

// backupOwner is the owner lock of the vault in a fork's backup. finishFork
// holds it from when it moves the old vault there or checks it there until
// it returns: through the swap and the deletion, so that no process opens
// the backup in between. It is taken once: a second lock of the same file
// conflicts with the first, even in one process.
type backupOwner struct{ f *os.File }

// take locks the owner lock of the vault in the backup dir (lockBackup),
// unless o holds it already.
func (o *backupOwner) take(dir string) error {
	if o.f != nil {
		return nil
	}
	f, err := lockBackup(dir)
	if err != nil {
		return err
	}
	o.f = f
	return nil
}

func (o *backupOwner) release() {
	if o.f != nil {
		o.f.Close()
		o.f = nil
	}
}

// moveOld renames the data directory, which must still be the old vault's,
// to the backup, while no process owns that vault, and only while it is as
// the fork read it (j.Source): a change since (a write, a sync, a
// revocation recorded) would be put away in the backup, so the fork is
// refused instead. owner takes the vault's owner lock, which moves with it
// into the backup and stays held.
func moveOld(cfg Config, data string, j *forkJournal, owner *backupOwner) error {
	if err := isOldVault(cfg, data, j); err != nil {
		return err
	}
	if ok, err := pathExists(j.Backup); err != nil {
		return err
	} else if ok {
		return fmt.Errorf("%w: %s already exists", ErrForkRefused, j.Backup)
	}
	f, err := filelock.TryLock(layout{data: data}.ownerLock())
	if errors.Is(err, filelock.ErrLocked) {
		return ErrVaultBusy
	}
	if err != nil {
		return err
	}
	owner.f = f
	if d, err := forkSourceDigest(data); err != nil {
		return err
	} else if d != j.Source {
		return fmt.Errorf("%w: %s is not as the fork read it (a change, a sync or a revocation since?); nothing was moved. "+
			"hop vault fork --local --abandon gives this fork up, and hop vault fork --local then forks the vault as it is now", ErrForkStale, data)
	}
	if err := os.Rename(data, j.Backup); err != nil {
		return err
	}
	return syncDir(filepath.Dir(data))
}

// lockBackup takes the owner lock of the vault in the backup dir, without
// waiting: a process that has it open (one that does not know the fence)
// makes it ErrVaultBusy. A backup whose vault directory is gone (a
// deletion that was cut short) has no owner to exclude, and gives a nil
// file, which closes harmlessly.
func lockBackup(dir string) (*os.File, error) {
	f, err := filelock.TryLock(layout{data: dir}.ownerLock())
	switch {
	case errors.Is(err, filelock.ErrLocked):
		return nil, fmt.Errorf("%w: a process has the old vault in %s open", ErrVaultBusy, dir)
	case errors.Is(err, os.ErrNotExist):
		return nil, nil
	}
	return f, err
}

// holdBackup requires the backup to hold the old vault, unowned, and as
// the fork read it (j.Source): a change made there since (by a hop that
// does not know the fence) is not put out of use by the swap, nor
// deleted. owner takes the backup's owner lock unless it holds it already,
// and keeps it. It returns the backup's manifest (forkSourceScan).
func holdBackup(cfg Config, j *forkJournal, owner *backupOwner) (map[string]string, error) {
	if err := isOldVault(cfg, j.Backup, j); err != nil {
		return nil, err
	}
	if err := owner.take(j.Backup); err != nil {
		return nil, err
	}
	d, files, err := forkSourceScan(j.Backup, true)
	if err != nil {
		return nil, err
	}
	if d != j.Source {
		return nil, fmt.Errorf("%w: the old vault in %s is not as the fork read it (it was opened and changed since?); it was kept as it is. "+
			"While the new vault is not in place, hop vault fork --local --abandon puts the old one back; once it is, "+
			"hop vault fork --local --keep-old finishes the fork and keeps the old vault", ErrForkStale, j.Backup)
	}
	return files, nil
}

// leftOfBackup requires the backup, whose deletion j records as begun, to
// be what that deletion leaves of the old vault: paths that its manifest
// (j.DiscardManifest) lists, each as it was, a directory still a directory
// and a file with the same content. A path changed or added means the
// backup was opened and changed since: ErrForkStale, and nothing more is
// deleted. A journal with no manifest (an earlier build) never deletes a
// backup that is still there: the source digest leaves out entry contents
// and objects, so it can't show the backup is unchanged.
func leftOfBackup(j *forkJournal) error {
	if j.DiscardManifest == nil {
		return fmt.Errorf("%w: this fork, begun by an earlier hop, did not record what the old vault in %s held when it began to delete it, so hop can't tell whether it changed since; "+
			"nothing more of it was deleted, and its device key may be gone already. To keep what is left of it, move %s elsewhere; "+
			"hop vault fork --local then finishes the fork without it", ErrForkStale, j.Backup, j.Backup)
	}
	_, files, err := forkSourceScan(j.Backup, true)
	if err != nil {
		return err
	}
	rels := make([]string, 0, len(files))
	for rel := range files {
		rels = append(rels, rel)
	}
	slices.Sort(rels)
	for _, rel := range rels {
		if want, ok := j.DiscardManifest[rel]; !ok || want != files[rel] {
			return fmt.Errorf("%w: the old vault in %s changed after the fork began to delete it (%s is not as the fork recorded it; was it opened and changed since?); "+
				"nothing more of it was deleted, and its device key may be gone already. To keep what is left of it, move %s elsewhere; "+
				"hop vault fork --local then finishes the fork without it", ErrForkStale, j.Backup, rel, j.Backup)
		}
	}
	return nil
}

// discardBackup deletes the backup of the fork j of data, under its owner
// lock (owner): the device records its device.json names (keychain
// entries; device key files go with the directory), then the directory.
// It reports whether it deleted it.
//
// First the backup must be the old vault, unowned and as the fork read it
// (holdBackup), and that is recorded (j.Discarding, with j.DiscardManifest)
// before anything is deleted. A deletion resumed after that goes on only
// with what it may have left (leftOfBackup).
//
// A backup that is missing before its deletion was recorded was not
// deleted by the fork, and is refused (ErrForkDamaged). One missing after
// can't be told from one moved away (the fork may have deleted all of it
// before it stopped): discardBackup returns false, and the fork reports it
// missing, not deleted.
func discardBackup(cfg Config, data string, j *forkJournal, owner *backupOwner) (bool, error) {
	backup := j.Backup
	if ok, err := pathExists(backup); err != nil {
		return false, err
	} else if !ok {
		if !j.Discarding {
			return false, fmt.Errorf("%w: the old vault's backup %s is missing (was it moved away?), and the fork deleted none of it; "+
				"put it back and run hop vault fork --local again to delete it, or run hop vault fork --local --keep-old to finish the fork without deleting it",
				ErrForkDamaged, backup)
		}
		return false, nil
	}
	if !j.Discarding {
		files, err := holdBackup(cfg, j, owner)
		if err != nil {
			return false, err
		}
		j.Discarding, j.DiscardManifest = true, files
		if err := writeForkJournal(data, j); err != nil {
			return false, err
		}
	} else {
		if err := owner.take(backup); err != nil {
			return false, err
		}
		if err := leftOfBackup(j); err != nil {
			return false, err
		}
	}
	s := &Store{cfg: cfg, l: layout{data: backup}}
	if dc, err := s.readDeviceConfig(); err == nil {
		if err := isOldVault(cfg, backup, j); err != nil {
			return false, err
		}
		for _, r := range retireRecords(dc) {
			ds := s.deviceStore(deviceConfig{V: 1, Store: dc.Store, AccountID: r.AccountID})
			if err := ds.deleteSlot(r.DeviceID); err != nil {
				return false, err
			}
		}
	} else if ok, _ := pathExists(s.l.deviceConfig()); ok {
		return false, err
	}
	if err := forkStage("fork:discarding"); err != nil {
		return false, err
	}
	if err := os.RemoveAll(backup); err != nil {
		return false, err
	}
	return true, syncDir(filepath.Dir(backup))
}
