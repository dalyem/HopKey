package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
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
// Layout, beside the data directory D (resolved through symlinks):
//
//	D.fork-new/                    the new vault while it is built: a whole data directory
//	D.fork-new/fork.json           the fork's journal (no secrets), which moves with it to D
//	D.forked-<date>-<vault8>/      the old data directory, kept as it was (unless --discard-old)
//
//	fork.json = {"v":1, "state":"staging"|"verified"|"swapped"|"done", "txn_id":id, "data_dir":str,
//	             "backup":str, "discard_old":bool, "discarded":bool, "old":{ids}, "new":{ids}, ...counts}
//
// Steps, each durable before the next:
//
//   - staging: D.fork-new and its journal; hop init's commit into it; the
//     verified items, in batches of entries, then one entry per item a
//     pending or held change touched, then one entry of the deletes those
//     changes made. The old vault is only read.
//   - verified: the new vault is opened from disk as hop opens any vault
//     (the log verified from genesis with the new device key) and its
//     items must equal what was imported. Only then is the journal set to
//     verified.
//   - the swap: D (checked to be the old vault, and taken from any owner)
//     is renamed to the backup, then D.fork-new to D. swapped is recorded.
//   - with --discard-old, the backup's device records and then its
//     directory are deleted. done is recorded, and the journal stays as
//     the record of the fork.
//
// A crash before verified leaves the old vault as it was: the staging
// directory (and its keychain entry) is deleted, and the fork starts again
// with a new Emergency Kit. A crash from verified on is finished by
// ResumeFork.

var (
	// ErrForkRevoked refuses to fork the vault of a device that left its
	// account by a revocation: proven (revoked.json) or reported by the
	// server (server-revoked.json). The account removed it on purpose.
	ErrForkRevoked = errors.New("store: this device was removed from its account, so its copy of the vault can't be forked")
	// ErrForkRefused means the vault holds something a fork can't carry,
	// or is in a state that does not allow one.
	ErrForkRefused = errors.New("store: this vault can't be forked")
	// ErrForkPending means an interrupted fork is waiting to finish:
	// hop vault fork --local finishes it.
	ErrForkPending = errors.New("store: a fork of this vault was interrupted; run hop vault fork --local again to finish it")
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
	// Resumed means an interrupted fork was finished.
	Resumed bool `json:"resumed,omitempty"`
}

type forkJournal struct {
	V          int             `json:"v"`
	State      string          `json:"state"`
	TxnID      model.ID        `json:"txn_id"`
	DataDir    string          `json:"data_dir"`
	Backup     string          `json:"backup"`
	DiscardOld bool            `json:"discard_old"`
	Discarded  bool            `json:"discarded"`
	At         model.Timestamp `json:"at"`
	Plan       forkPlanRecord  `json:"plan"`
	New        ForkIDs         `json:"new"`
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
		New: j.New, Discarded: j.Discarded,
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

// forkPaths resolves the data directory through symlinks (the swap renames
// the directory itself) and names the staging directory. A data directory
// that is gone (a crash between the two renames) resolves through its
// parent.
func forkPaths(dataDir string) (data, staging string, err error) {
	abs, err := filepath.Abs(dataDir)
	if err != nil {
		return "", "", err
	}
	if r, err := filepath.EvalSymlinks(abs); err == nil {
		abs = r
	} else if errors.Is(err, os.ErrNotExist) {
		if p, err := filepath.EvalSymlinks(filepath.Dir(abs)); err == nil {
			abs = filepath.Join(p, filepath.Base(abs))
		}
	} else {
		return "", "", err
	}
	return abs, abs + forkNewSuffix, nil
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

// ForkInProgress reports whether a fork of the vault in dataDir has
// started and not finished: hop init and hop vault fork must not begin
// anything else there until ResumeFork has run.
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

// ResumeFork finishes a fork that a crash interrupted. One that had not
// verified its new vault is abandoned: its staging directory and device
// record are deleted, the old vault is left as it was, and abandoned is
// true (the Emergency Kit it showed belongs to no vault). One that had is
// finished: the swap, the discard if asked for, and done. It returns nil
// and false when there is nothing to resume.
func ResumeFork(ctx context.Context, cfg Config) (res *ForkResult, abandoned bool, err error) {
	data, staging, err := forkPaths(cfg.DataDir)
	if err != nil {
		return nil, false, err
	}
	if ok, err := pathExists(staging); err != nil {
		return nil, false, err
	} else if ok {
		j, jerr := readForkJournal(staging)
		if jerr != nil || j == nil || j.State != forkVerified {
			return nil, true, abandonStaging(cfg, staging)
		}
		if err := finishFork(cfg, j); err != nil {
			return nil, false, err
		}
		r := j.result()
		r.Resumed = true
		return r, false, nil
	}
	j, err := readForkJournal(data)
	if err != nil || j == nil || j.State == forkDone {
		return nil, false, err
	}
	if j.State != forkVerified && j.State != forkSwapped {
		return nil, false, fmt.Errorf("%w: the fork journal in %s is %q, with no staging directory", ErrCorrupt, data, j.State)
	}
	if err := finishFork(cfg, j); err != nil {
		return nil, false, err
	}
	r := j.result()
	r.Resumed = true
	return r, false, nil
}

// abandonStaging deletes an unverified staging directory: the keychain
// entry of the device its device.json names first, then the directory.
func abandonStaging(cfg Config, staging string) error {
	s := &Store{cfg: cfg, l: layout{data: staging}}
	if dc, err := s.readDeviceConfig(); err == nil {
		for _, r := range retireRecords(dc) {
			ds := s.deviceStore(deviceConfig{V: 1, Store: dc.Store, AccountID: r.AccountID})
			if err := ds.deleteSlot(r.DeviceID); err != nil {
				return fmt.Errorf("store: deleting the device key of an abandoned fork: %w", err)
			}
		}
	}
	if err := os.RemoveAll(staging); err != nil {
		return err
	}
	return syncDir(filepath.Dir(staging))
}

// ForkOptions are hop vault fork's inputs about the old vault.
type ForkOptions struct {
	// Passphrase opens a sealed device key file in place of
	// HOP_DEVICE_PASSPHRASE. The new vault's sealed file gets it too.
	Passphrase []byte
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

	// verified and final are the old vault's items by old ID: verified
	// state, and the overlay (what this device showed), sanitized.
	verified map[model.ID]crypto.Item
	final    map[model.ID]crypto.Item
	ids      map[model.ID]model.ID // old item ID to new

	init *PendingInit
	ncfg Config
	done bool
}

// PrepareFork opens the vault in cfg.DataDir, checks that it may be
// forked, and reads its items. It writes nothing but what opening a vault
// may finish (a crashed commit). The caller must Close the result.
//
// Refused: a device revoked from its account, by proof or by the
// server's report (ErrForkRevoked); a vault that is local-only already
// (ErrNotServerBacked); one with a login merge or a publication in
// progress, with grants or deploy operations, or a key dedicated to a
// grant (ErrForkRefused); a fork in progress (ErrForkPending). A logout
// that is pending (RETIRING) is no obstacle: the fork reads the vault in
// memory, as the logout's own resolution does.
func PrepareFork(ctx context.Context, cfg Config, opts ForkOptions) (*PendingFork, error) {
	data, staging, err := forkPaths(cfg.DataDir)
	if err != nil {
		return nil, err
	}
	if pending, err := ForkInProgress(data); err != nil {
		return nil, err
	} else if pending {
		return nil, ErrForkPending
	}
	ocfg := cfg
	ocfg.DataDir = data
	src, err := Open(ctx, ocfg)
	if err != nil {
		return nil, err
	}
	p := &PendingFork{cfg: ocfg, src: src, data: data, staging: staging, pass: slices.Clone(opts.Passphrase)}
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
	clear(p.verified)
	clear(p.final)
	clear(p.pass)
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
	return p.readLoaded(v, sf, logout)
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
	get := p.cfg.Getenv
	if get == nil {
		get = os.Getenv
	}
	if len(p.pass) > 0 {
		pass := string(p.pass)
		inner := get
		get = func(k string) string {
			if k == PassphraseEnv {
				return pass
			}
			return inner(k)
		}
	}
	p.ncfg = p.cfg
	p.ncfg.DataDir = p.staging
	p.ncfg.Getenv = get
	init, err := PrepareInit(p.ncfg, InitOptions{Password: password, DeviceStore: deviceStore})
	if err != nil {
		return Kit{}, err
	}
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
		New: ForkIDs{AccountID: p.init.state.Account.AccountID, VaultID: p.init.state.VaultID, DeviceID: p.init.rec.DeviceID},
	}
	var err error
	if j.TxnID, err = vaultlog.NewID(); err != nil {
		return nil, err
	}
	if err := p.stage(ctx, j); err != nil {
		if aerr := abandonStaging(p.ncfg, p.staging); aerr != nil {
			err = fmt.Errorf("%w (and its staging directory %s could not be deleted: %v)", err, p.staging, aerr)
		}
		return nil, err
	}
	p.done = true
	// The old vault's store lets go before the swap: its paths name the
	// data directory, which is about to hold the new vault. finishFork
	// takes the vault from any other owner again before it moves it.
	p.src.Close()
	p.src = nil
	if err := finishFork(p.cfg, j); err != nil {
		return nil, err
	}
	r := j.result()
	r.Warnings = p.plan.Warnings
	return r, nil
}

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

// forkWrite commits ch as one entry, or, when the server would refuse it
// as too large (so a later publish could not upload it), as two halves.
// The caller holds s.mu.
func (s *Store) forkWrite(ch vaultlog.Changes) error {
	unlock, err := s.lockFile()
	if err != nil {
		return err
	}
	w, st, sec, err := vaultlog.BuildNormal(s.state, s.sec, s.dev, ch, s.now(), objectDir(s.l.objects()))
	if err == nil && len(ch.Put) > 1 && errors.Is(admitWire(w), ErrTooLarge) {
		unlock()
		half := len(ch.Put) / 2
		if err := s.forkWrite(vaultlog.Changes{Put: ch.Put[:half]}); err != nil {
			return err
		}
		return s.forkWrite(vaultlog.Changes{Put: ch.Put[half:]})
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

// verify opens the staged vault as hop opens any vault, and checks that
// it is the new account's, local-only, and holds exactly the items
// imported.
func (p *PendingFork) verify(ctx context.Context, j *forkJournal) error {
	ns, err := Open(ctx, p.ncfg)
	if err != nil {
		return fmt.Errorf("store: the new vault does not open: %w", err)
	}
	defer ns.Close()
	info := ns.Info()
	if info.Locked {
		return fmt.Errorf("store: the new vault does not unlock: %s", info.LockReason)
	}
	if _, err := ns.ServerInfo(); !errors.Is(err, ErrNotServerBacked) {
		return fmt.Errorf("store: the new vault is not local-only (%v)", err)
	}
	ns.mu.Lock()
	vid, aid := ns.state.VaultID, ns.state.Account.AccountID
	ns.mu.Unlock()
	if vid != j.New.VaultID || aid != j.New.AccountID || info.DeviceID != j.New.DeviceID.String() {
		return errors.New("store: the new vault's identity is not the one generated")
	}
	if vid == j.Plan.Old.VaultID || aid == j.Plan.Old.AccountID || j.New.DeviceID == j.Plan.Old.DeviceID {
		return errors.New("store: the new vault reuses an old identity")
	}
	snap, err := ns.Snapshot(ctx)
	if err != nil {
		return err
	}
	got := map[model.ID]crypto.Item{}
	for i := range snap.Hosts {
		got[snap.Hosts[i].ItemID] = &snap.Hosts[i]
	}
	for i := range snap.Keys {
		got[snap.Keys[i].ItemID] = &snap.Keys[i]
	}
	for i := range snap.Credentials {
		got[snap.Credentials[i].ItemID] = &snap.Credentials[i]
	}
	for i := range snap.Snippets {
		got[snap.Snippets[i].ItemID] = &snap.Snippets[i]
	}
	for i := range snap.Policies {
		got[snap.Policies[i].ItemID] = &snap.Policies[i]
	}
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
	return nil
}

// finishFork carries a verified fork through the swap, the discard if
// asked for, and done. Each step checks what is on disk first, so it
// resumes from wherever a crash stopped it.
func finishFork(cfg Config, j *forkJournal) error {
	data, staging := j.DataDir, j.DataDir+forkNewSuffix
	parent := filepath.Dir(data)
	hasStaging, err := pathExists(staging)
	if err != nil {
		return err
	}
	if hasStaging {
		hasData, err := pathExists(data)
		if err != nil {
			return err
		}
		if hasData {
			if err := moveOld(cfg, j); err != nil {
				return err
			}
			if err := forkStage("fork:moved-old"); err != nil {
				return err
			}
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
	if j.State == forkVerified {
		j.State = forkSwapped
		if err := writeForkJournal(data, j); err != nil {
			return err
		}
	}
	if j.DiscardOld && !j.Discarded {
		if err := discardBackup(cfg, j.Backup); err != nil {
			return fmt.Errorf("the new vault is in place, but the old one in %s could not be deleted: %w", j.Backup, err)
		}
		if err := forkStage("fork:discarded"); err != nil {
			return err
		}
		j.Discarded = true
	}
	j.State = forkDone
	return writeForkJournal(data, j)
}

// moveOld renames the data directory, which must still be the old vault's,
// to the backup, while no process owns that vault.
func moveOld(cfg Config, j *forkJournal) error {
	data := j.DataDir
	s := &Store{cfg: cfg, l: layout{data: data}}
	dc, err := s.readDeviceConfig()
	if err != nil || dc.AccountID != j.Plan.Old.AccountID || dc.DeviceID != j.Plan.Old.DeviceID {
		return fmt.Errorf("%w: %s no longer holds the vault being forked; the new one waits in %s", ErrForkRefused, data, data+forkNewSuffix)
	}
	if ok, err := pathExists(j.Backup); err != nil {
		return err
	} else if ok {
		return fmt.Errorf("%w: %s already exists", ErrForkRefused, j.Backup)
	}
	f, err := filelock.TryLock(s.l.ownerLock())
	if errors.Is(err, filelock.ErrLocked) {
		return ErrVaultBusy
	}
	if err != nil {
		return err
	}
	defer f.Close()
	if err := os.Rename(data, j.Backup); err != nil {
		return err
	}
	return syncDir(filepath.Dir(data))
}

// discardBackup deletes the old data directory: the device records its
// device.json names (keychain entries; device key files go with the
// directory), then the directory.
func discardBackup(cfg Config, backup string) error {
	if ok, err := pathExists(backup); err != nil || !ok {
		return err
	}
	s := &Store{cfg: cfg, l: layout{data: backup}}
	dc, err := s.readDeviceConfig()
	if err == nil {
		for _, r := range retireRecords(dc) {
			ds := s.deviceStore(deviceConfig{V: 1, Store: dc.Store, AccountID: r.AccountID})
			if err := ds.deleteSlot(r.DeviceID); err != nil {
				return err
			}
		}
	} else if ok, _ := pathExists(s.l.deviceConfig()); ok {
		return err
	}
	if err := os.RemoveAll(backup); err != nil {
		return err
	}
	return syncDir(filepath.Dir(backup))
}
