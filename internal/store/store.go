// Package store is HopKey's encrypted local vault: a model.Store over the
// signed vault log (crypto spec §5, §11; https://plan.23d.dev/p/xuu5z9q2).
// Phase 1 has no server, so what a server would hold (the account record,
// the log and its objects) lives on disk next to the verified state. Only
// ciphertext, public log data and digests are written; item plaintexts,
// hostnames and keys exist only in memory while the vault is unlocked.
//
// Layout, under the data directory ($XDG_DATA_HOME/hop, else
// ~/.local/share/hop), every directory 0700 and every file 0600:
//
//	device.json                which device key store is in use (no secrets)
//	device.key                 the device key, when the file store is used
//	vault/lock                 the writer lock
//	vault/entries/<seq>.json   signed entries (the wire without its objects), append-only
//	vault/objects/<sha256>     envelopes, content-addressed and immutable
//	vault/state.json           the verified state (§5.5)
//	vault/account.json         account_id, salt, kdf_version, pw_blob, rk_blob, verifier hashes
//	vault/journal/<seq>.json   checkpoint candidates, sealed to the device key (§10.1)
//
// A write stores its objects, then its entry, then state.json, each fsynced,
// under an exclusive lock. The entry file is the commit point: on unlock,
// every entry is verified again from the latest anchor (genesis or
// checkpoint), and an entry past state.json's head (a crash between the two)
// is applied only after it passes the transition algorithm.
package store

import (
	"context"
	"errors"
	"fmt"
	"os"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/dalyem/hopkey/internal/crypto"
	"github.com/dalyem/hopkey/internal/filelock"
	"github.com/dalyem/hopkey/internal/model"
	"github.com/dalyem/hopkey/internal/vaultlog"
)

var (
	// ErrNoVault means the data directory holds no vault.
	ErrNoVault = errors.New("store: there is no vault on this device; run hop init")
	// ErrVaultExists means init found a vault (or the start of one).
	ErrVaultExists = errors.New("store: a vault already exists on this device")
	// ErrCorrupt means the files on disk fail verification. The store
	// refuses to use them.
	ErrCorrupt = errors.New("store: the vault failed verification")
	// ErrObjectDigest means an object file does not match its digest.
	ErrObjectDigest = errors.New("store: object does not match its digest")
	// ErrDeviceKey means the device key could not be read. The vault stays
	// locked; hop unlock --password restores the key.
	ErrDeviceKey = errors.New("store: the device key is unavailable")
	// ErrWrongPassword means the master password (with the Secret Key) did
	// not open the account.
	ErrWrongPassword = errors.New("store: wrong master password or Secret Key")
	// ErrNeedSecretKey means a password unlock needs the Secret Key, which
	// this device does not have stored.
	ErrNeedSecretKey = errors.New("store: the Secret Key is not stored on this device; enter it from your Emergency Kit")
	// ErrKitPending means a password change committed but its Emergency Kit
	// has not been confirmed yet.
	ErrKitPending = errors.New("store: a new Emergency Kit is waiting to be confirmed; run hop passwd to see it")

	errLocked = fmt.Errorf("%w; run hop unlock", model.ErrLocked)
)

// Config says where the vault is and what it may use.
type Config struct {
	// DataDir holds the vault and the device key file. Use DefaultDataDir.
	DataDir string
	// Keyring is the OS keychain. Nil means OSKeyring.
	Keyring Keyring
	// Getenv reads HOP_DEVICE_PASSPHRASE. Nil means os.Getenv.
	Getenv func(string) string
	// Now is the clock for entry times. Nil means time.Now.
	Now func() time.Time
	// DeviceName names devices this store creates (init, password unlock).
	// Empty means the host name.
	DeviceName string
}

// Head is the verified head of the log: seq and H(E) in hex.
type Head struct {
	Seq uint64 `json:"seq,string"`
	H   string `json:"h"`
}

// Short is what hop status prints: seq and the first 8 bytes of H (§5.6).
func (h Head) Short() string {
	if len(h.H) < 16 {
		return fmt.Sprintf("%d", h.Seq)
	}
	return fmt.Sprintf("%d %s", h.Seq, h.H[:16])
}

// Info describes the vault for hop status. It holds no secrets.
type Info struct {
	Locked      bool   `json:"locked"`
	LockReason  string `json:"lock_reason,omitempty"` // why the last unlock failed
	DeviceStore string `json:"device_key_store"`
	DeviceID    string `json:"device_id,omitempty"`
	AccountID   string `json:"account_id,omitempty"`
	Head        *Head  `json:"head,omitempty"`
	KitPending  bool   `json:"kit_pending,omitempty"`
}

// Store is the encrypted vault. It implements model.Store; Head, Lock,
// Unlock, UnlockWithPassword and ChangePassword are extra.
type Store struct {
	cfg Config
	l   layout

	mu      sync.Mutex
	state   *vaultlog.State   // verified; nil while locked
	sec     *vaultlog.Secrets // nil while locked
	dev     *vaultlog.LocalDevice
	rec     *deviceRecord
	devCfg  deviceConfig
	lockErr error
	kit     *Kit // a committed password change whose kit is not confirmed

	testHook func(stage string) error // simulates crashes in tests
}

var _ model.Store = (*Store)(nil)

func (s *Store) ring() Keyring {
	if s.cfg.Keyring != nil {
		return s.cfg.Keyring
	}
	return OSKeyring{}
}

func (s *Store) getenv() func(string) string {
	if s.cfg.Getenv != nil {
		return s.cfg.Getenv
	}
	return os.Getenv
}

func (s *Store) now() model.Timestamp {
	if s.cfg.Now != nil {
		return model.TimestampOf(s.cfg.Now())
	}
	return model.TimestampOf(time.Now())
}

func (s *Store) deviceName() string {
	name := s.cfg.DeviceName
	if name == "" {
		name, _ = os.Hostname()
	}
	if crypto.CheckStr("name", name, 64) != nil || name == "" {
		name = "hop device"
	}
	return name
}

// Open opens the vault in cfg.DataDir and unlocks it with the device key.
// If the device key cannot be read, the store is returned locked (Info says
// why) so that hop unlock --password can still reach it. A vault that fails
// verification is an error.
func Open(ctx context.Context, cfg Config) (*Store, error) {
	s := &Store{cfg: cfg, l: layout{data: cfg.DataDir}}
	if ok, err := s.l.exists(); err != nil {
		return nil, err
	} else if !ok {
		return nil, ErrNoVault
	}
	if err := s.l.ensureDirs(); err != nil {
		return nil, err
	}
	if err := s.Unlock(ctx); err != nil && !errors.Is(err, ErrDeviceKey) {
		return nil, err
	}
	return s, nil
}

// lockFile takes the vault's writer lock. Every write, and every unlock
// (which may finish a crashed write), holds it throughout.
func (s *Store) lockFile() (func(), error) {
	f, err := filelock.Lock(s.l.lockFile())
	if err != nil {
		return nil, err
	}
	return func() { f.Close() }, nil
}

// Lock drops every secret from memory. Reads and writes fail with
// model.ErrLocked until Unlock.
func (s *Store) Lock() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.dropLocked(nil)
}

func (s *Store) dropLocked(reason error) {
	if s.sec != nil {
		if s.sec.Account != nil {
			s.sec.Account.Zero()
		}
		s.sec.VK.Zero()
		for id := range s.sec.Items {
			p := s.sec.Items[id]
			p.IK.Zero()
			delete(s.sec.Items, id)
		}
	}
	if s.rec != nil {
		s.rec.zero()
	}
	s.state, s.sec, s.dev, s.rec, s.kit = nil, nil, nil, nil, nil
	s.lockErr = reason
}

// Unlock reads the device key, verifies the log on disk and loads the
// vault (§5.5). It finishes a write or a password change that a crash
// interrupted, after verifying it. It does nothing if the vault is already
// unlocked. A failure leaves the vault locked.
func (s *Store) Unlock(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.state != nil {
		return nil
	}
	err := s.unlockLocked()
	if err != nil {
		s.dropLocked(err)
	}
	return err
}

func (s *Store) unlockLocked() error {
	cfg, err := s.readDeviceConfig()
	if err != nil {
		return err
	}
	s.devCfg = cfg
	rec, err := s.deviceStore(cfg).load()
	if err != nil {
		return err
	}
	dev, err := rec.device()
	if err != nil {
		return err
	}
	unlock, err := s.lockFile()
	if err != nil {
		return err
	}
	defer unlock()

	stored, err := s.readStoredState()
	if err != nil {
		return err
	}
	acct, err := deviceAccount(s.l, stored, dev)
	if err != nil {
		return err
	}
	st, sec, err := s.replay(stored, acct, dev)
	if err != nil {
		return err
	}
	s.state, s.sec, s.dev, s.rec = st, sec, dev, rec
	if err := s.writeAccountFile(); err != nil {
		return err
	}
	return s.recoverJournal()
}

// deviceAccount opens this device's unlock blob (§6.2) in the stored state
// and returns the account keys for its akv. stored is not verified yet: the
// replay that follows anchors with these keys and fails unless they are the
// account's.
func deviceAccount(l layout, stored *vaultlog.State, dev *vaultlog.LocalDevice) (*crypto.AccountKeys, error) {
	if stored == nil {
		// Only genesis was written before a crash: take this device's
		// unlock blob from it.
		w, err := l.readEntry(0)
		if err != nil {
			return nil, fmt.Errorf("%w: no state and no genesis entry: %v", ErrCorrupt, err)
		}
		for _, o := range w.Entry.Ops {
			if d, ok := o.(*vaultlog.DeviceAddOp); ok && d.Cert.DeviceID == dev.ID {
				return openUnlock(l, &d.Cert, d.UnlockSHA256, dev)
			}
		}
		return nil, fmt.Errorf("%w: this device is not in the genesis entry", ErrDeviceKey)
	}
	d, ok := stored.Devices[dev.ID]
	if !ok {
		return nil, fmt.Errorf("%w: device %v is not active in this vault", ErrDeviceKey, dev.ID)
	}
	acct, err := openUnlock(l, &d.Cert, d.UnlockSHA256, dev)
	if err != nil {
		return nil, err
	}
	if err := crypto.CheckUnlockPin(acct, stored.Pin()); err != nil {
		return nil, fmt.Errorf("%w: unlock blob: %v", ErrCorrupt, err)
	}
	return acct, nil
}

func openUnlock(l layout, cert *crypto.Cert, h crypto.Hash, dev *vaultlog.LocalDevice) (*crypto.AccountKeys, error) {
	b, err := objectDir(l.objects()).FetchObject(h)
	if err != nil {
		return nil, fmt.Errorf("%w: unlock blob: %w", ErrCorrupt, err)
	}
	env, err := crypto.ParseHPKEEnvelope(b)
	if err != nil {
		return nil, fmt.Errorf("%w: unlock blob: %v", ErrCorrupt, err)
	}
	acct, err := dev.OpenUnlock(cert, env)
	if err != nil {
		return nil, fmt.Errorf("%w: this device key does not open its unlock blob: %v", ErrDeviceKey, err)
	}
	return acct, nil
}

// readStoredState reads state.json, or returns nil if it is missing and
// only the genesis entry exists (a crash during init).
func (s *Store) readStoredState() (*vaultlog.State, error) {
	b, err := os.ReadFile(s.l.stateFile())
	if errors.Is(err, os.ErrNotExist) {
		seqs, err := s.l.entrySeqs()
		if err != nil {
			return nil, err
		}
		if len(seqs) == 1 && seqs[0] == 0 {
			return nil, nil
		}
		if len(seqs) == 0 {
			return nil, ErrNoVault
		}
		return nil, fmt.Errorf("%w: state.json is missing", ErrCorrupt)
	}
	if err != nil {
		return nil, err
	}
	st, err := vaultlog.ParseState(b)
	if err != nil {
		return nil, fmt.Errorf("%w: state.json: %v", ErrCorrupt, err)
	}
	return st, nil
}

// replay verifies the log on disk (§5.5): it anchors at the newest genesis
// or checkpoint entry at or before the stored head with acct, applies the
// transition algorithm to every later entry, and requires the stored head
// to be one it passes. Entries past the stored head are the tail of a write
// that crashed before state.json was updated: each is verified by the
// transition algorithm before it is applied, and state.json is then
// rewritten. dev crosses a checkpoint in that tail; with no dev (a password
// unlock) such a tail is an error.
func (s *Store) replay(stored *vaultlog.State, acct *crypto.AccountKeys, dev vaultlog.DeviceKey) (*vaultlog.State, *vaultlog.Secrets, error) {
	seqs, err := s.l.entrySeqs()
	if err != nil {
		return nil, nil, err
	}
	for i, seq := range seqs {
		if seq != uint64(i) {
			return nil, nil, fmt.Errorf("%w: entry %d is missing", ErrCorrupt, i)
		}
	}
	var storedHead *vaultlog.Head
	if stored != nil {
		storedHead = &stored.Head
	}
	if storedHead != nil && storedHead.Seq >= uint64(len(seqs)) {
		return nil, nil, fmt.Errorf("%w: the state head (seq %d) is not among the entries (%d on disk)", ErrCorrupt, storedHead.Seq, len(seqs))
	}
	last := uint64(0)
	if storedHead != nil {
		last = storedHead.Seq
	}

	wires := make([]*vaultlog.Wire, len(seqs))
	anchor := -1
	for i := range seqs {
		w, err := s.l.readEntry(uint64(i))
		if err != nil {
			return nil, nil, err
		}
		wires[i] = w
		if k := w.Entry.Kind; uint64(i) <= last && (k == vaultlog.KindGenesis || k == vaultlog.KindCheckpoint) {
			anchor = i
		}
	}
	if anchor < 0 {
		return nil, nil, fmt.Errorf("%w: no genesis or checkpoint entry at or before seq %d", ErrCorrupt, last)
	}

	objs := objectDir(s.l.objects())
	st, sec, _, err := vaultlog.Anchor(acct.Pin(), acct, wires[anchor], objs, nil)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: anchor entry %d: %w", ErrCorrupt, anchor, err)
	}
	for i := anchor + 1; i <= int(last); i++ {
		if st, sec, err = vaultlog.Transition(st, sec, dev, wires[i], objs); err != nil {
			return nil, nil, fmt.Errorf("%w: entry %d: %w", ErrCorrupt, i, err)
		}
	}
	if storedHead != nil && (st.Head.Seq != storedHead.Seq || !st.Head.H.Equal(storedHead.H)) {
		return nil, nil, fmt.Errorf("%w: the state head (seq %d) is not the entry on disk at that seq", ErrCorrupt, storedHead.Seq)
	}
	// state.json is a cache of what was just verified. A copy that differs
	// at the same head is not trusted; it is rewritten below.
	rewrite := stored == nil || !sameState(st, stored)

	// Crash recovery: entries past the stored head.
	for i := int(last) + 1; i < len(wires); i++ {
		if st, sec, err = vaultlog.Transition(st, sec, dev, wires[i], objs); err != nil {
			return nil, nil, fmt.Errorf("%w: entry %d past the state head: %w", ErrCorrupt, i, err)
		}
		rewrite = true
	}
	if rewrite {
		if err := s.l.writeState(st); err != nil {
			return nil, nil, err
		}
	}
	return st, sec, nil
}

func sameState(a, b *vaultlog.State) bool {
	x, err1 := a.Marshal()
	y, err2 := b.Marshal()
	return err1 == nil && err2 == nil && string(x) == string(y)
}

// Head returns the verified head. It fails with model.ErrLocked while the
// vault is locked. The daemon compares it with the head of its last reload
// to skip rebuilding from an unchanged vault.
func (s *Store) Head() (Head, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.state == nil {
		return Head{}, errLocked
	}
	return Head{Seq: s.state.Head.Seq, H: s.state.Head.H.String()}, nil
}

// Info describes the vault for hop status.
func (s *Store) Info() Info {
	s.mu.Lock()
	defer s.mu.Unlock()
	info := Info{Locked: s.state == nil, KitPending: s.kit != nil}
	if cfg, err := s.readDeviceConfig(); err == nil {
		info.DeviceStore = s.deviceStore(cfg).Describe()
		info.AccountID = cfg.AccountID.String()
	}
	if s.lockErr != nil {
		info.LockReason = s.lockErr.Error()
	}
	if s.state != nil {
		info.Head = &Head{Seq: s.state.Head.Seq, H: s.state.Head.H.String()}
		info.DeviceID = s.dev.ID.String()
	}
	return info
}

// catchUp applies, after verifying them, entries another writer appended
// since this store last looked. The caller holds the file lock.
func (s *Store) catchUp() error {
	objs := objectDir(s.l.objects())
	for {
		w, err := s.l.readEntry(s.state.Head.Seq + 1)
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		if err != nil {
			return err
		}
		st, sec, err := vaultlog.Transition(s.state, s.sec, s.dev, w, objs)
		if err != nil {
			return fmt.Errorf("%w: entry %d: %w", ErrCorrupt, w.Entry.Seq, err)
		}
		s.state, s.sec = st, sec
	}
}

// commit writes a built entry: its objects, then the entry, then state.json.
// The caller holds the file lock.
func (s *Store) commit(w *vaultlog.Wire, st *vaultlog.State) error {
	if err := s.l.writeObjects(w); err != nil {
		return err
	}
	if err := s.l.writeEntry(w); err != nil {
		return err
	}
	return s.l.writeState(st)
}

// write builds a normal entry for ch against the current head and commits
// it. check, if set, runs against the current head before anything is
// built.
func (s *Store) write(ch vaultlog.Changes, check func() error) error {
	unlock, err := s.lockFile()
	if err != nil {
		return err
	}
	defer unlock()
	if err := s.catchUp(); err != nil {
		return err
	}
	if check != nil {
		if err := check(); err != nil {
			return err
		}
	}
	w, st, sec, err := vaultlog.BuildNormal(s.state, s.sec, s.dev, ch, s.now(), objectDir(s.l.objects()))
	if err != nil {
		return err
	}
	if err := s.commit(w, st); err != nil {
		return err
	}
	s.state, s.sec = st, sec
	return nil
}

// Snapshot returns every live item, decrypted.
func (s *Store) Snapshot(context.Context) (model.Snapshot, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.sec == nil {
		return model.Snapshot{}, errLocked
	}
	return snapshotOf(s.sec), nil
}

func snapshotOf(sec *vaultlog.Secrets) model.Snapshot {
	var snap model.Snapshot
	for _, p := range sec.Items {
		switch v := p.Item.(type) {
		case *model.Host:
			snap.Hosts = append(snap.Hosts, cloneHost(*v))
		case *model.Key:
			snap.Keys = append(snap.Keys, *v)
		case *model.Credential:
			snap.Credentials = append(snap.Credentials, *v)
		case *model.Snippet:
			c := *v
			c.Params = slices.Clone(v.Params)
			snap.Snippets = append(snap.Snippets, c)
		}
	}
	byName := func(a, b model.Header, an, bn string) int {
		if c := strings.Compare(an, bn); c != 0 {
			return c
		}
		return strings.Compare(a.ItemID.String(), b.ItemID.String())
	}
	slices.SortFunc(snap.Hosts, func(a, b model.Host) int { return byName(a.Header, b.Header, a.Name, b.Name) })
	slices.SortFunc(snap.Keys, func(a, b model.Key) int { return byName(a.Header, b.Header, a.Name, b.Name) })
	slices.SortFunc(snap.Credentials, func(a, b model.Credential) int { return byName(a.Header, b.Header, a.Name, b.Name) })
	slices.SortFunc(snap.Snippets, func(a, b model.Snippet) int { return byName(a.Header, b.Header, a.Name, b.Name) })
	return snap
}

func cloneHost(h model.Host) model.Host {
	h.Aliases = slices.Clone(h.Aliases)
	h.Addresses = slices.Clone(h.Addresses)
	h.Tags = slices.Clone(h.Tags)
	h.HostKeys = slices.Clone(h.HostKeys)
	if h.Tailscale != nil {
		t := *h.Tailscale
		h.Tailscale = &t
	}
	return h
}

func (s *Store) PutHost(_ context.Context, h model.Host) (model.Host, error) {
	h = cloneHost(h)
	for _, l := range []*[]string{&h.Aliases, &h.Addresses, &h.Tags, &h.HostKeys} {
		if *l == nil {
			*l = []string{}
		}
	}
	out, err := put(s, &h, model.TypeHost)
	if err != nil {
		return model.Host{}, err
	}
	return cloneHost(*out), nil
}

func (s *Store) PutKey(_ context.Context, k model.Key) (model.Key, error) {
	out, err := put(s, &k, model.TypeKey)
	if err != nil {
		return model.Key{}, err
	}
	return *out, nil
}

func (s *Store) PutCredential(_ context.Context, c model.Credential) (model.Credential, error) {
	out, err := put(s, &c, model.TypeCredential)
	if err != nil {
		return model.Credential{}, err
	}
	return *out, nil
}

func (s *Store) PutSnippet(_ context.Context, sn model.Snippet) (model.Snippet, error) {
	sn.Params = slices.Clone(sn.Params)
	if sn.Params == nil {
		sn.Params = []string{}
	}
	out, err := put(s, &sn, model.TypeSnippet)
	if err != nil {
		return model.Snippet{}, err
	}
	c := *out
	c.Params = slices.Clone(out.Params)
	return c, nil
}

// header returns the shared header of an item pointer.
func header(it crypto.Item) *model.Header {
	switch v := it.(type) {
	case *model.Host:
		return &v.Header
	case *model.Key:
		return &v.Header
	case *model.Credential:
		return &v.Header
	case *model.Snippet:
		return &v.Header
	}
	return nil
}

// put creates (zero ItemID) or replaces an item. A replacement names the
// live item's current version; the store writes version + 1.
func put[T any](s *Store, it *T, typ model.Type) (*T, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.sec == nil {
		return nil, errLocked
	}
	h := header(it)
	isNew := h.ItemID.IsZero()
	if isNew {
		id, err := vaultlog.NewID()
		if err != nil {
			return nil, err
		}
		h.ItemID, h.ItemVersion = id, 0
	}
	h.V, h.Type = crypto.Version, typ
	check := func() error { return s.checkPut(it, isNew) }
	if err := s.write(vaultlog.Changes{Put: []crypto.Item{it}}, check); err != nil {
		return nil, err
	}
	saved, ok := s.sec.Items[h.ItemID].Item.(*T)
	if !ok {
		return nil, fmt.Errorf("store: item %v was not saved", h.ItemID)
	}
	return saved, nil
}

// checkPut applies the model.Store rules for one Put before the log rules:
// a replacement names a live item of the same type at its current version,
// and a host's jump chain must not loop.
func (s *Store) checkPut(it crypto.Item, isNew bool) error {
	h := header(it)
	if !isNew {
		cur, ok := s.state.Items[h.ItemID]
		switch {
		case !ok:
			return model.ErrNotFound
		case cur.Type != h.Type:
			return fmt.Errorf("store: item %s is a %s, not a %s", h.ItemID, cur.Type, h.Type)
		case h.ItemVersion != cur.ItemVersion:
			return fmt.Errorf("store: item %s is at version %d, not %d", h.ItemID, cur.ItemVersion, h.ItemVersion)
		}
	}
	if host, ok := it.(*model.Host); ok {
		seen := map[model.ID]bool{host.ItemID: true}
		for next := host.JumpHostID; !next.IsZero(); {
			if seen[next] {
				return fmt.Errorf("store: host %q has a jump host loop", host.Name)
			}
			seen[next] = true
			j, ok := s.sec.Items[next].Item.(*model.Host)
			if !ok {
				break // the log rules report a missing jump host
			}
			next = j.JumpHostID
		}
	}
	return nil
}

// Delete deletes a live item. References to it must be gone first.
func (s *Store) Delete(_ context.Context, id model.ID) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.sec == nil {
		return errLocked
	}
	if _, ok := s.state.Items[id]; !ok {
		return model.ErrNotFound
	}
	return s.write(vaultlog.Changes{Delete: []model.ID{id}}, func() error {
		if _, ok := s.state.Items[id]; !ok {
			return model.ErrNotFound
		}
		return nil
	})
}
