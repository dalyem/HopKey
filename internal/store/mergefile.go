package store

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/dalyem/hopkey/internal/canonjson"
	"github.com/dalyem/hopkey/internal/crypto"
	"github.com/dalyem/hopkey/internal/merge"
	"github.com/dalyem/hopkey/internal/model"
	"github.com/dalyem/hopkey/internal/vaultlog"
)

// Login with a local-only vault: the login merge (§4.4, rev 16). The source
// vault's items move into one sealed import bundle before sign-in, so two
// vaults never exist together:
//
//	vault/merge.json = JCS({"v":1, "txn_id":id,
//	    "journal":AEAD(local_key, merge,  aad = lp("hopkey/v1/merge-journal") || lp(txn_id_bytes)),
//	    "bundle": AEAD(local_key, bundle, aad = lp("hopkey/v1/merge-bundle")  || lp(txn_id_bytes))})
//	merge  = JCS({"v":1, "txn_id":id, "state":"sealed"|"signed_in"|"importing"|"paused", "vault_id":id|"",
//	              "manifest":[{"item_id":id, "type":type, "digest":h}], "receipts":[{"item_id":id, "seq":u64s, "h":h}]})
//	bundle = JCS({"v":1, "txn_id":id, "items":[item, ...]})
//
// Each digest is merge.MergeItemDigest (item_version "1"). The journal is
// sealed again, under a fresh nonce, whenever it changes; the bundle never
// changes. Both are sealed under local_key, which the destination device
// record carries over, so the destination opens them.
//
//   - MergeStart (sealed): the preflight (only host, key, credential and
//     snippet items; no grant, no deploy_op, no checkpoint journal, no
//     pending kit; a local-only vault, never published), then the file,
//     durably. The source is frozen: every local append is refused.
//     MergeCancel deletes the file while no destination record exists and
//     every destination device is resolved (or ForceOrphan keeps the
//     unresolved ones in the sign-in ledger).
//   - MergeSignIn: the destination device is named in device.json's next
//     member, and then its record, with the source's local_key, is made
//     durable (the keychain entry, or device.next.key); then the
//     destination log is read, verified from the anchor of the login's
//     account keys as that device, and the bootstrap that adds the device
//     is posted and verified. Then one
//     durable commit records signed_in with the vault_id, deletes the
//     source vault and installs the destination's verified log in its
//     place. The source device record goes next, and device.json names the
//     destination (promoteNext, which a restart finishes too).
//   - Enqueue (importing): one commit appends an import record per
//     manifest item to the outbox, in dependency order: keys and
//     credentials, then hosts in jump-host order, then snippets.
//   - Receipts: the commit that verifies an import's candidate and removes
//     its record writes its receipt (settle); the commit that writes the
//     last receipt deletes the file.
//   - Ordinary item writes are refused while signed_in or importing.
//   - MergePause, MergeResume and MergeDiscard follow §4.4 exactly.

var (
	// ErrMergeFrozen means a login merge has sealed this vault's items
	// into its import bundle: the source vault takes no more writes.
	ErrMergeFrozen = errors.New("store: this vault is being merged into an account (hop auth login --merge); finish or cancel the merge first")
	// ErrMergeImporting means ordinary item writes wait while a login
	// merge imports: wait for it, or pause it (hop auth merge --pause).
	ErrMergeImporting = errors.New("store: a login merge is importing items; wait for it to finish, or pause it with hop auth merge --pause")
	// ErrNoMerge means there is no login merge.
	ErrNoMerge = errors.New("store: no login merge is in progress")
	// ErrMergeState means the merge is not in the state the operation
	// needs (a second resume included).
	ErrMergeState = errors.New("store: the login merge is not in a state that allows this")
	// ErrMergeRefused means the source vault holds something a merge does
	// not move: grants or deploy operations (§4.4 preflight).
	ErrMergeRefused = errors.New("store: this vault can't be merged")
	// ErrConfirmRequired means the operation needs the user's confirmation
	// digest (§5.4); nothing was changed.
	ErrConfirmRequired = errors.New("store: confirmation required")
)

// Merge states (§4.4).
const (
	MergeSealed    = "sealed"
	MergeSignedIn  = "signed_in"
	MergeImporting = "importing"
	MergePaused    = "paused"
)

const (
	mergeRel           = "merge.json"
	mergeVersion       = 1
	labelMergeJournal  = "hopkey/v1/merge-journal"
	labelMergeBundle   = "hopkey/v1/merge-bundle"
	nextKeyName        = "device.next.key"
	maxSignInBootstrap = maxPushAttempts
)

func (l layout) mergeFile() string { return filepath.Join(l.vault(), mergeRel) }

// mergeExists reports whether vault/merge.json exists, from its name only.
func (l layout) mergeExists() (bool, error) {
	_, err := os.Lstat(l.mergeFile())
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	return err == nil, err
}

type mergeReceipt struct {
	ItemID model.ID    `json:"item_id"`
	Seq    uint64      `json:"seq,string"`
	H      crypto.Hash `json:"h"`
}

type mergeJournal struct {
	V        int                 `json:"v"`
	TxnID    model.ID            `json:"txn_id"`
	State    string              `json:"state"`
	VaultID  model.ID            `json:"vault_id"`
	Manifest []merge.ManifestRow `json:"manifest"`
	Receipts []mergeReceipt      `json:"receipts"`
}

type mergeBundle struct {
	V     int             `json:"v"`
	TxnID model.ID        `json:"txn_id"`
	Items []canonjson.Raw `json:"items"`
}

type mergeFileJSON struct {
	V       int                 `json:"v"`
	TxnID   model.ID            `json:"txn_id"`
	Journal crypto.AEADEnvelope `json:"journal"`
	Bundle  crypto.AEADEnvelope `json:"bundle"`
}

func mergeAAD(label string, txnID model.ID) []byte {
	return append(crypto.LP([]byte(label)), crypto.LP(txnID[:])...)
}

// receipt returns the receipt of item id, if any.
func (j *mergeJournal) receipt(id model.ID) *mergeReceipt {
	for i := range j.Receipts {
		if j.Receipts[i].ItemID == id {
			return &j.Receipts[i]
		}
	}
	return nil
}

// unreceipted is the manifest rows with no receipt, in manifest order.
func (j *mergeJournal) unreceipted() []merge.ManifestRow {
	var out []merge.ManifestRow
	for _, r := range j.Manifest {
		if j.receipt(r.ItemID) == nil {
			out = append(out, r)
		}
	}
	return out
}

// openedMerge is merge.json opened.
type openedMerge struct {
	j    *mergeJournal
	file mergeFileJSON
}

// readMerge opens vault/merge.json with rec's local_key, or returns nil if
// there is none. Anything that does not open is ErrCorrupt. The caller
// holds the file lock.
func (s *Store) readMerge(rec *deviceRecord) (*openedMerge, error) {
	b, err := os.ReadFile(s.l.mergeFile())
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if rec == nil {
		return nil, s.lockedErr()
	}
	bad := func(what string) error { return fmt.Errorf("%w: %s: %s", ErrCorrupt, s.l.mergeFile(), what) }
	var f mergeFileJSON
	if canonjson.Unmarshal(b, &f) != nil || f.V != mergeVersion || f.TxnID.IsZero() {
		return nil, bad("does not parse")
	}
	key, err := rec.localKey()
	if err != nil {
		return nil, err
	}
	defer key.Zero()
	pt, err := crypto.OpenAEAD(key, f.Journal, mergeAAD(labelMergeJournal, f.TxnID))
	if err != nil {
		return nil, bad("the journal does not open")
	}
	var j mergeJournal
	err = canonjson.Unmarshal(pt, &j)
	clear(pt)
	if err != nil || j.V != mergeVersion || j.TxnID != f.TxnID {
		return nil, bad("the journal does not parse")
	}
	switch j.State {
	case MergeSealed:
		if !j.VaultID.IsZero() {
			return nil, bad("a sealed merge names a vault")
		}
	case MergeSignedIn, MergeImporting, MergePaused:
		if j.VaultID.IsZero() {
			return nil, bad("the merge names no destination vault")
		}
	default:
		return nil, bad("unknown state")
	}
	ids := map[model.ID]bool{}
	for _, r := range j.Manifest {
		if ids[r.ItemID] || r.ItemID.IsZero() {
			return nil, bad("the manifest repeats an item")
		}
		ids[r.ItemID] = true
	}
	for _, r := range j.Receipts {
		if !ids[r.ItemID] {
			return nil, bad("a receipt names no manifest item")
		}
	}
	return &openedMerge{j: &j, file: f}, nil
}

// bundleItems opens the bundle and returns its items by ID, checked
// against the manifest digests.
func (m *openedMerge) bundleItems(rec *deviceRecord) (map[model.ID]*merge.Item, error) {
	key, err := rec.localKey()
	if err != nil {
		return nil, err
	}
	defer key.Zero()
	pt, err := crypto.OpenAEAD(key, m.file.Bundle, mergeAAD(labelMergeBundle, m.j.TxnID))
	if err != nil {
		return nil, fmt.Errorf("%w: the merge bundle does not open", ErrCorrupt)
	}
	defer clear(pt)
	var b mergeBundle
	if canonjson.Unmarshal(pt, &b) != nil || b.V != mergeVersion || b.TxnID != m.j.TxnID {
		return nil, fmt.Errorf("%w: the merge bundle does not parse", ErrCorrupt)
	}
	items := map[model.ID]*merge.Item{}
	for _, raw := range b.Items {
		it, err := merge.ParseItem(raw)
		if err != nil {
			return nil, fmt.Errorf("%w: a merge bundle item: %v", ErrCorrupt, err)
		}
		items[it.ID()] = it
	}
	if len(items) != len(m.j.Manifest) {
		return nil, fmt.Errorf("%w: the merge bundle does not match its manifest", ErrCorrupt)
	}
	for _, r := range m.j.Manifest {
		it, ok := items[r.ItemID]
		if !ok || it.Type() != r.Type {
			return nil, fmt.Errorf("%w: the merge bundle does not match its manifest", ErrCorrupt)
		}
		if d, err := merge.MergeItemDigest(it); err != nil || !d.Equal(r.Digest) {
			return nil, fmt.Errorf("%w: a merge bundle item does not match its digest", ErrCorrupt)
		}
	}
	return items, nil
}

// putMerge adds merge.json with journal j (sealed again, under a fresh
// nonce) and m's bundle to t.
func putMerge(t *txn, rec *deviceRecord, m *openedMerge) error {
	key, err := rec.localKey()
	if err != nil {
		return err
	}
	defer key.Zero()
	if m.j.Receipts == nil {
		m.j.Receipts = []mergeReceipt{}
	}
	if m.j.Manifest == nil {
		m.j.Manifest = []merge.ManifestRow{}
	}
	pt, err := canonjson.Marshal(m.j)
	if err != nil {
		return err
	}
	env, err := crypto.SealAEAD(key, pt, mergeAAD(labelMergeJournal, m.j.TxnID))
	clear(pt)
	if err != nil {
		return err
	}
	m.file.Journal = env
	b, err := canonjson.Marshal(m.file)
	if err != nil {
		return err
	}
	t.put(mergeRel, b)
	return nil
}

// MergeItem is one manifest item, for status and reports.
type MergeItem struct {
	ItemID   model.ID   `json:"item_id"`
	Type     model.Type `json:"type"`
	Name     string     `json:"name"`
	Imported bool       `json:"imported"`
	Seq      uint64     `json:"seq,omitempty"` // the entry that imported it
}

// MergeStatus describes a login merge.
type MergeStatus struct {
	TxnID   model.ID    `json:"txn_id"`
	State   string      `json:"state"`
	VaultID model.ID    `json:"vault_id,omitzero"`
	Items   []MergeItem `json:"items"`
	// Done means the merge finished: every item has its receipt and the
	// file is gone.
	Done bool `json:"done,omitempty"`
	// CheckpointDue, from MergeSignIn, means its sign-in was a recovery
	// (§4.5): see SignInResult.CheckpointDue.
	CheckpointDue bool `json:"checkpoint_due,omitempty"`
}

// status builds the merge's status from its journal and bundle.
func (m *openedMerge) status(rec *deviceRecord) (MergeStatus, error) {
	items, err := m.bundleItems(rec)
	if err != nil {
		return MergeStatus{}, err
	}
	st := MergeStatus{TxnID: m.j.TxnID, State: m.j.State, VaultID: m.j.VaultID}
	for _, r := range m.j.Manifest {
		mi := MergeItem{ItemID: r.ItemID, Type: r.Type, Name: itemName(items[r.ItemID])}
		if rc := m.j.receipt(r.ItemID); rc != nil {
			mi.Imported, mi.Seq = true, rc.Seq
		}
		st.Items = append(st.Items, mi)
	}
	return st, nil
}

func itemName(it *merge.Item) string {
	if it == nil {
		return ""
	}
	raw, ok := it.Member("name")
	if !ok {
		return ""
	}
	var name string
	if json.Unmarshal(raw, &name) != nil {
		return ""
	}
	return name
}

// MergeStatus returns the login merge in progress, or nil.
func (s *Store) MergeStatus() (*MergeStatus, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if exists, err := s.l.mergeExists(); err != nil || !exists {
		return nil, err
	}
	if s.state == nil {
		return nil, s.lockedErr()
	}
	unlock, err := s.lockFile()
	if err != nil {
		return nil, err
	}
	defer unlock()
	m, err := s.readMerge(s.rec)
	if err != nil || m == nil {
		return nil, err
	}
	st, err := m.status(s.rec)
	return &st, err
}

// HasMergeFile reports whether a login merge file exists (§4.4). It reads
// only the name, so it works while the vault is locked. Logout always
// refuses while one does (§11.1).
func (s *Store) HasMergeFile() (bool, error) { return s.l.mergeExists() }

// MergeStart seals this local-only vault's items into a login merge's
// import bundle and freezes the vault (§4.4, state sealed). It refuses a
// vault that holds grants or deploy operations, a checkpoint journal or a
// pending kit, a published vault, and a publication in progress.
func (s *Store) MergeStart() (MergeStatus, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.state == nil {
		return MergeStatus{}, s.lockedErr()
	}
	if s.server {
		return MergeStatus{}, fmt.Errorf("%w: it is server-backed; only a local-only vault is merged", ErrMergeRefused)
	}
	unlock, err := s.lockFile()
	if err != nil {
		return MergeStatus{}, err
	}
	defer unlock()
	if err := s.catchUp(); err != nil {
		return MergeStatus{}, err
	}
	if exists, err := s.l.mergeExists(); err != nil {
		return MergeStatus{}, err
	} else if exists {
		return MergeStatus{}, fmt.Errorf("%w: a login merge is already in progress", ErrMergeState)
	}
	if err := s.refuseLocalAppend(); err != nil {
		return MergeStatus{}, err
	}
	if err := s.refuseCheckpoint(); err != nil {
		return MergeStatus{}, err
	}
	if ns, err := s.l.outboxNumbers(); err != nil || len(ns) > 0 {
		return MergeStatus{}, errors.Join(err, errors.New("store: a local-only vault holds outbox records"))
	}
	if len(s.state.Grants) > 0 {
		return MergeStatus{}, fmt.Errorf("%w: it holds grants, which a merge does not move; revoke them first", ErrMergeRefused)
	}
	if len(s.state.DeployOps) > 0 {
		return MergeStatus{}, fmt.Errorf("%w: it holds key deployment operations, which a merge does not move", ErrMergeRefused)
	}
	txnID, err := vaultlog.NewID()
	if err != nil {
		return MergeStatus{}, err
	}
	j := &mergeJournal{V: mergeVersion, TxnID: txnID, State: MergeSealed, Manifest: []merge.ManifestRow{}, Receipts: []mergeReceipt{}}
	bundle := mergeBundle{V: mergeVersion, TxnID: txnID, Items: []canonjson.Raw{}}
	for id, st := range s.state.Items {
		switch st.Type {
		case model.TypeHost, model.TypeKey, model.TypeCredential, model.TypeSnippet:
		default:
			return MergeStatus{}, fmt.Errorf("%w: it holds a %s item, which a merge does not move", ErrMergeRefused, st.Type)
		}
		it, err := s.verifiedItem(id)
		if err != nil {
			return MergeStatus{}, err
		}
		if it == nil {
			return MergeStatus{}, fmt.Errorf("%w: item %v has no plaintext", ErrCorrupt, id)
		}
		d, err := merge.MergeItemDigest(it)
		if err != nil {
			return MergeStatus{}, err
		}
		j.Manifest = append(j.Manifest, merge.ManifestRow{ItemID: id, Type: st.Type, Digest: d})
		bundle.Items = append(bundle.Items, it.Plaintext())
	}
	slices.SortFunc(j.Manifest, func(a, b merge.ManifestRow) int { return bytes.Compare(a.ItemID[:], b.ItemID[:]) })
	slices.SortFunc(bundle.Items, func(a, b canonjson.Raw) int { return bytes.Compare(a, b) })
	key, err := s.outboxKey()
	if err != nil {
		return MergeStatus{}, err
	}
	pt, err := canonjson.Marshal(bundle)
	if err != nil {
		key.Zero()
		return MergeStatus{}, err
	}
	benv, err := crypto.SealAEAD(key, pt, mergeAAD(labelMergeBundle, txnID))
	clear(pt)
	key.Zero()
	if err != nil {
		return MergeStatus{}, err
	}
	m := &openedMerge{j: j, file: mergeFileJSON{V: mergeVersion, TxnID: txnID, Bundle: benv}}
	t := &txn{}
	if err := putMerge(t, s.rec, m); err != nil {
		return MergeStatus{}, err
	}
	if err := s.commitTxn(t); err != nil {
		return MergeStatus{}, err
	}
	return m.status(s.rec)
}

// MergeCancelOptions are MergeCancel's choices.
type MergeCancelOptions struct {
	// ForceOrphan cancels even while destination devices are unresolved
	// (MergeUnresolvedError): the user accepts that a bootstrap may have
	// committed for them. They are kept in the sign-in ledger (ledger.go),
	// and the next merge into the same account carries them forward as
	// stale devices, for hop passwd to revoke. It does not override a
	// destination device record: that sign-in must finish.
	ForceOrphan bool
}

// MergeUnresolvedError is MergeCancel's refusal while destination devices
// are unresolved: device.json names them (next, or its stale list), and a
// bootstrap may have committed for any of them, so dropping them could
// leave a device active in the account that nothing here tracks. Finish
// the sign-in, or cancel with ForceOrphan.
type MergeUnresolvedError struct {
	AccountID model.ID
	Devices   []model.ID
}

func (e *MergeUnresolvedError) Error() string {
	return fmt.Sprintf("store: the merge's destination devices %v in account %v may be enrolled; finish the sign-in, or cancel with --force-orphan to keep them as stale devices of that account", e.Devices, e.AccountID)
}

// Is makes a MergeUnresolvedError an ErrMergeState.
func (e *MergeUnresolvedError) Is(target error) bool { return target == ErrMergeState }

// MergeCancel deletes a sealed merge's file and unfreezes the source
// vault (§4.4, "Recovery"). It is refused once a destination device record
// exists: the sign-in may have committed, and only MergeSignIn finishes
// it. Every other destination device device.json names must be resolved
// first:
//
//   - one revoked, by its tombstone or in the sign-in ledger, is resolved:
//     the ledger keeps the revocation (written first, if only the
//     tombstone had it) and a missing tombstone is written, or cancel
//     fails, so no revoked record is left untracked;
//   - one whose record is confirmed gone, and every stale one, may have
//     been enrolled: cancel refuses with a *MergeUnresolvedError unless
//     opts.ForceOrphan, which records them in the ledger as orphaned
//     before device.json drops them.
//
// Anything the device key store can't answer conclusively refuses. It
// needs no key, so it works while the vault is locked.
func (s *Store) MergeCancel(opts MergeCancelOptions) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	unlock, err := s.lockFile()
	if err != nil {
		return err
	}
	defer unlock()
	if err := s.replayWAL(); err != nil {
		return err
	}
	if exists, err := s.l.mergeExists(); err != nil {
		return err
	} else if !exists {
		return ErrNoMerge
	}
	if server, err := s.l.serverBacked(); err != nil {
		return err
	} else if server {
		return fmt.Errorf("%w: the source vault is already dropped", ErrMergeState)
	}
	if s.rec != nil {
		m, err := s.readMerge(s.rec)
		if err != nil {
			return err
		}
		if m != nil && m.j.State != MergeSealed {
			return fmt.Errorf("%w: only a sealed merge can be cancelled", ErrMergeState)
		}
	}
	cfg, err := s.readDeviceConfig()
	if err != nil {
		return err
	}
	if cfg.Next != nil {
		if err := s.releaseNext(cfg, opts); err != nil {
			return err
		}
		cfg.Next = nil
		if err := s.writeDeviceConfig(cfg); err != nil {
			return err
		}
		s.devCfg = cfg
	}
	t := &txn{}
	t.remove(mergeRel)
	return s.commitTxn(t)
}

// releaseNext resolves cfg's destination devices for MergeCancel, and
// records in the sign-in ledger, durably, what device.json is about to
// drop: the revoked device, and with opts.ForceOrphan the unresolved ones.
// It changes nothing when it refuses. The caller holds the file lock.
func (s *Store) releaseNext(cfg deviceConfig, opts MergeCancelOptions) error {
	next := cfg.Next
	ns := s.nextStore(cfg)
	ledger, err := s.l.readLedger()
	if err != nil {
		return err
	}
	revoked := ledger.isRevoked(next.AccountID, next.DeviceID)
	if !revoked {
		state, rec, err := ns.probeSlot(next.DeviceID)
		if rec != nil {
			rec.zero()
		}
		if err != nil {
			return err
		}
		switch state {
		case slotRecord:
			return fmt.Errorf("%w: a destination device is already enrolled; finish the sign-in", ErrMergeState)
		case slotTombstone:
			revoked = true
		}
	}
	var unresolved []model.ID
	if !revoked {
		unresolved = append(unresolved, next.DeviceID)
	}
	unresolved = uniqueIDs(append(unresolved, next.Stale...))
	if len(unresolved) > 0 && !opts.ForceOrphan {
		return &MergeUnresolvedError{AccountID: next.AccountID, Devices: unresolved}
	}
	var gone []model.ID
	if revoked {
		gone = []model.ID{next.DeviceID}
	}
	if ledger.add(next.AccountID, gone, unresolved) {
		if err := s.l.writeLedger(ledger); err != nil {
			return err
		}
	}
	if revoked {
		// A record a failed tombstone write left behind must not outlive
		// device.json's name for it.
		if err := ns.tombstone(next.DeviceID); err != nil {
			return fmt.Errorf("%w: the revoked destination device's tombstone could not be written, so the merge was not cancelled: %v", ErrKeyStoreUnavailable, err)
		}
	}
	return nil
}

// SignInRemote is the destination server as a sign-in reads and writes it,
// with a login or recovery token (plan /v1/login, /v1/recover, R6: the
// three vault reads and one bootstrap). Slice E implements it over HTTP.
// Nothing it returns is trusted: the log is verified from the anchor of
// the sign-in's account keys, and the heads it reports are checked against
// the entries verified (fetchRest).
type SignInRemote interface {
	EntryAt(ctx context.Context, seq uint64) (Committed, error)
	Since(ctx context.Context, after uint64) ([]Committed, vaultlog.Head, error)
	Post(ctx context.Context, w *vaultlog.Wire) (vaultlog.Head, error)
}

// SignInMethod is how a sign-in opened the account keys.
type SignInMethod string

const (
	// SignInPassword: pw_blob, with the master password and the Secret Key
	// (§4.4).
	SignInPassword SignInMethod = "password"
	// SignInRecovery: rk_blob, with the Recovery Key (§4.5). The account's
	// credentials must then be replaced by a checkpoint (§10.1) before the
	// recovery is reported done: see SignInResult.CheckpointDue.
	SignInRecovery SignInMethod = "recovery"
)

// ErrSignInRevoked means the device a sign-in enrolled was revoked from the
// account (§5.5) before the sign-in installed it. That is terminal for the
// sign-in: its device record is replaced by a tombstone, so no later
// attempt uses it, whatever history the server shows then.
var ErrSignInRevoked = errors.New("store: the device this sign-in enrolled was revoked from the account")

// SignInParams is what a sign-in has learnt and chosen (§4.4, §4.5). The
// store takes Account over in every case: on success it is part of the
// verified secrets, zeroed when the vault locks; on failure it is zeroed
// before the call returns.
type SignInParams struct {
	// ServerURL is the server's origin and Email the sign-in email, which
	// is normalized here (plan R4). Both are kept in vault/server.json so
	// the sync engine can reconnect and sign in again.
	ServerURL string
	Email     string
	// Account is the account keys the sign-in opened: from pw_blob with
	// the password (SignInPassword) or from rk_blob with the Recovery Key
	// (SignInRecovery).
	Account *crypto.AccountKeys
	// SecretKey is the account's Secret Key, which the device record keeps.
	SecretKey string
	// DeviceName names the new device in the log. Empty means
	// Config.DeviceName, then the host name.
	DeviceName string
	// Method is how Account was opened. Empty means SignInPassword.
	Method SignInMethod
	// DeviceStore is where SignIn keeps the new device's key:
	// DeviceStoreKeychain (the default) or DeviceStoreFile. A merge keeps
	// the source's store and ignores it.
	DeviceStore string
}

// check validates p and returns its normalized server file.
func (p *SignInParams) check() (serverFile, error) {
	if p.Account == nil {
		return serverFile{}, errors.New("store: a sign-in needs the account keys")
	}
	if _, err := crypto.ParseSecretKey(p.SecretKey); err != nil {
		return serverFile{}, fmt.Errorf("store: that is not a Secret Key: %w", err)
	}
	if p.ServerURL == "" || crypto.CheckStr("server", p.ServerURL, 256) != nil {
		return serverFile{}, errors.New("store: the server's origin must be 1 to 256 characters")
	}
	email, err := NormalizeEmail(p.Email)
	if err != nil {
		return serverFile{}, err
	}
	switch p.Method {
	case "", SignInPassword, SignInRecovery:
	default:
		return serverFile{}, fmt.Errorf("store: unknown sign-in method %q", p.Method)
	}
	if p.DeviceName != "" && crypto.CheckStr("name", p.DeviceName, 64) != nil {
		return serverFile{}, errors.New("store: a device name is 1 to 64 characters")
	}
	return serverFile{Server: p.ServerURL, Email: email}, nil
}

// deviceName is the name of the device p enrolls.
func (p *SignInParams) deviceName(s *Store) string {
	if p.DeviceName != "" {
		return p.DeviceName
	}
	return s.deviceName()
}

// serverFor completes f for the verified destination st: a recovery
// records the creds gen it found, so its checkpoint stays due until this
// device's own checkpoint moves past it (recoveryCheckpointDone).
func (p *SignInParams) serverFor(f serverFile, st *vaultlog.State) serverFile {
	if p.Method == SignInRecovery {
		f.RecoveryGen = st.Creds.Gen
	}
	return f
}

// signInSecrets are the secrets a sign-in holds until it installs them:
// the account keys, the new device record, the device keys decoded from it
// and the verified destination. Exactly one owner zeroes them: the sign-in
// (zero, on every path that does not install), or the store, which takes
// them over (take) under s.mu in the same step that installs them. The
// destination's secrets of every state it verified before its current one
// are dropped as soon as the next one replaces them (supersede).
type signInSecrets struct {
	acct *crypto.AccountKeys
	rec  *deviceRecord
	dev  *vaultlog.LocalDevice
	d    *destination
	// onState, for tests, sees the secrets of every state the destination
	// verifies, in order.
	onState func(*vaultlog.Secrets)
}

// zero drops whatever o still owns.
func (o *signInSecrets) zero() {
	if o.d != nil {
		zeroSecrets(o.d.sec)
		o.d = nil
	}
	if o.acct != nil {
		o.acct.Zero()
		o.acct = nil
	}
	if o.rec != nil {
		o.rec.zero()
		o.rec = nil
	}
	if o.dev != nil {
		zeroDevice(o.dev)
		o.dev = nil
	}
}

// take hands the record, its device keys and the destination to the
// store, which installs them: o no longer zeroes them, nor the account
// keys if they are the destination's. The caller holds s.mu.
func (o *signInSecrets) take() (*deviceRecord, *vaultlog.LocalDevice, *destination) {
	rec, dev, d := o.rec, o.dev, o.d
	o.rec, o.dev, o.d = nil, nil, nil
	if d != nil && d.sec != nil && d.sec.Account == o.acct {
		o.acct = nil
	}
	return rec, dev, d
}

// zeroSecrets drops verified secrets.
func zeroSecrets(sec *vaultlog.Secrets) {
	if sec == nil {
		return
	}
	if sec.Account != nil {
		sec.Account.Zero()
	}
	sec.VK.Zero()
	for id := range sec.Items {
		p := sec.Items[id]
		p.IK.Zero()
		delete(sec.Items, id)
	}
}

// supersede drops prev, the secrets of a verified state that next, its
// successor, replaced, except what next still references. A transition
// copies VK and every item key into next and clones the item map, so those
// are prev's alone; the account keys are shared until a checkpoint
// replaces them, and are zeroed only then.
func supersede(prev, next *vaultlog.Secrets) {
	if prev == nil || prev == next {
		return
	}
	if next != nil && prev.Account == next.Account {
		prev.Account = nil
	}
	zeroSecrets(prev)
}

// zeroDevice drops a decoded device's Ed25519 signing key. Its X-Wing key
// is an opaque value the crypto package holds, which the record's zeroing
// covers at the source.
func zeroDevice(d *vaultlog.LocalDevice) {
	if d != nil {
		clear(d.Sig)
	}
}

// destination is a destination log as a sign-in fetched and verified it.
// self is the device the sign-in enrolls: every transition is run as that
// device once it is active, so a checkpoint that keeps it opens its new
// unlock blob, and one that revokes it is met in the public stage, before
// anything is decrypted (*vaultlog.RevokedError).
type destination struct {
	self    *vaultlog.LocalDevice
	wires   []*vaultlog.Wire // 0..head, each with its objects
	objs    vaultlog.ObjectMap
	st      *vaultlog.State
	sec     *vaultlog.Secrets
	onState func(*vaultlog.Secrets)
}

// fetchDestination reads the whole destination log from genesis and
// verifies it from the newest anchor (genesis or checkpoint) with o's
// account keys (§4.4, §5.5), as self. The anchor's public stage comes
// first, and self is checked against it before anything is decrypted: a
// device the anchor lists as retired was revoked (*vaultlog.RevokedError),
// and one it lists as active must have self's keys. It returns d as soon
// as it holds secrets, with an error too, so its owner can zero them.
func fetchDestination(ctx context.Context, r SignInRemote, o *signInSecrets, self *vaultlog.LocalDevice) (*destination, error) {
	c0, err := r.EntryAt(ctx, 0)
	if err != nil {
		return nil, err
	}
	d := &destination{self: self, objs: vaultlog.ObjectMap{}, onState: o.onState}
	if err := d.add([]Committed{c0}); err != nil {
		return nil, err
	}
	if err := d.fetchRest(ctx, r); err != nil {
		return nil, err
	}
	anchor := -1
	for i, w := range d.wires {
		if k := w.Entry.Kind; k == vaultlog.KindGenesis || k == vaultlog.KindCheckpoint {
			anchor = i
		}
	}
	if anchor < 0 {
		return nil, fmt.Errorf("%w: the destination log has no anchor", ErrCorrupt)
	}
	acct := o.acct
	notAnchor := func(err error) error {
		return fmt.Errorf("store: the destination's newest anchor (seq %d) does not verify with these account keys: %w", anchor, err)
	}
	c, err := vaultlog.CheckAnchorPublic(acct.Pin(), d.wires[anchor], d.objs)
	if err != nil {
		return nil, notAnchor(err)
	}
	if err := d.checkSelf(c.Post); err != nil {
		return nil, err
	}
	st, sec, _, err := vaultlog.Anchor(acct.Pin(), acct, d.wires[anchor], d.objs, nil)
	if err != nil {
		return nil, notAnchor(err)
	}
	d.st, d.sec = st, sec
	d.seen()
	for _, w := range d.wires[anchor+1:] {
		if err := d.step(w); err != nil {
			return d, err
		}
	}
	return d, d.departed()
}

// checkSelf checks self against a verified public state, before anything
// of it is decrypted: a device the account removed (retired, which is
// cumulative, includes every revoked device) is a revocation, and a device
// the state lists as active must be self, with self's keys.
func (d *destination) checkSelf(st *vaultlog.State) error {
	if slices.Contains(st.Retired.DeviceIDs, d.self.ID) {
		return &retiredError{RevokedError: &vaultlog.RevokedError{DeviceID: d.self.ID, Head: st.Head}, anchor: true}
	}
	if da, ok := st.Devices[d.self.ID]; ok {
		sigPK := d.self.Sig.Public().(ed25519.PublicKey)
		if err := crypto.CheckCertKeys(&da.Cert, d.self.KEM.PublicKey().Bytes(), sigPK); err != nil {
			return fmt.Errorf("%w: the destination lists device %v with other keys than its record's: %v", ErrDeviceKey, d.self.ID, err)
		}
	}
	return nil
}

// seen reports d's current secrets to the test hook.
func (d *destination) seen() {
	if d.onState != nil {
		d.onState(d.sec)
	}
}

// step verifies w on top of d's verified head, as self once self is
// active, and drops the secrets the new state replaces.
func (d *destination) step(w *vaultlog.Wire) error {
	var dev vaultlog.DeviceKey
	if _, active := d.st.Devices[d.self.ID]; active {
		dev = d.self
	}
	st, sec, err := transition(d.st, d.sec, dev, []model.ID{d.self.ID}, w, d.objs)
	if err != nil {
		var rev *vaultlog.RevokedError
		if errors.As(err, &rev) {
			return err
		}
		return fmt.Errorf("store: the destination's entry %d: %w", w.Entry.Seq, err)
	}
	prev := d.sec
	d.st, d.sec = st, sec
	supersede(prev, sec)
	d.seen()
	return nil
}

// departed fails with a *vaultlog.RevokedError when the verified state
// lists self among the devices removed from the account: an anchor taken
// after the checkpoint that revoked it.
func (d *destination) departed() error {
	if slices.Contains(d.st.Retired.DeviceIDs, d.self.ID) {
		return &retiredError{RevokedError: &vaultlog.RevokedError{DeviceID: d.self.ID, Head: d.st.Head}}
	}
	return nil
}

// retiredError is a revocation a sign-in knows from a verified state's
// list of retired devices, not one it met in the checkpoint that made it:
// Head is that state's (the anchor's, if anchor), and the revoking
// checkpoint may be older. It unwraps to the *vaultlog.RevokedError.
type retiredError struct {
	*vaultlog.RevokedError
	anchor bool
}

func (e *retiredError) Error() string {
	return fmt.Sprintf("store: device %v is %s", e.DeviceID, revokedAt(e))
}

func (e *retiredError) Unwrap() error { return e.RevokedError }

// revokedAt says how a sign-in learnt of the revocation err wraps (a
// *vaultlog.RevokedError): from the anchor's or a later state's retired
// list (retiredError), or by meeting the revoking checkpoint.
func revokedAt(err error) string {
	if r := (*retiredError)(nil); errors.As(err, &r) {
		if r.anchor {
			return fmt.Sprintf("known retired at anchor seq %d", r.Head.Seq)
		}
		return fmt.Sprintf("known retired at seq %d", r.Head.Seq)
	}
	if rev := (*vaultlog.RevokedError)(nil); errors.As(err, &rev) {
		return fmt.Sprintf("revoked by the checkpoint at seq %d", rev.Head.Seq)
	}
	return "revoked"
}

// add appends fetched entries, which must continue the log. An entry at a
// seq already held must be the one held: another is an equivocation (§5.6).
func (d *destination) add(cs []Committed) error {
	for _, c := range cs {
		if c.Wire == nil {
			return errors.New("store: the server returned an entry without its wire")
		}
		h, err := c.Wire.Entry.Hash()
		if err != nil {
			return err
		}
		if c.Wire.Entry.Seq != c.Seq || !h.Equal(c.H) {
			return fmt.Errorf("store: the server's entry %d does not match its seq and H", c.Seq)
		}
		if c.Seq < uint64(len(d.wires)) {
			have, err := d.wires[c.Seq].Entry.Hash()
			if err != nil {
				return err
			}
			if !have.Equal(h) {
				return &vaultlog.EquivocationError{Seq: c.Seq, Have: have, Got: h}
			}
			continue
		}
		if c.Seq != uint64(len(d.wires)) {
			return fmt.Errorf("store: the server's entry %d does not continue the log", c.Seq)
		}
		if len(d.wires) > 0 {
			prev, _ := d.wires[len(d.wires)-1].Entry.Hash()
			if !c.Wire.Entry.Prev.Equal(prev) {
				return fmt.Errorf("store: the server's entry %d does not chain to %d", c.Seq, c.Seq-1)
			}
		}
		objs, err := vaultlog.WireObjects(c.Wire)
		if err != nil {
			return err
		}
		for h, b := range objs {
			d.objs[h] = b
		}
		d.wires = append(d.wires, c.Wire)
	}
	return nil
}

// fetchRest reads every entry past the ones held, up to the server's head,
// and checks each head the server reports against the log held: a head
// behind it is a regression (ErrServerBehind), and one at the same seq
// with another H an equivocation (§5.6), as Pull and the publication's
// resolution treat them.
func (d *destination) fetchRest(ctx context.Context, r SignInRemote) error {
	for {
		after := uint64(len(d.wires) - 1)
		cs, head, err := r.Since(ctx, after)
		if err != nil {
			return err
		}
		if err := d.add(cs); err != nil {
			return err
		}
		ours := uint64(len(d.wires) - 1)
		have, err := d.wires[ours].Entry.Hash()
		if err != nil {
			return err
		}
		switch {
		case head.Seq < ours:
			return fmt.Errorf("%w: the server reports head %d, but this sign-in holds its log to seq %d", ErrServerBehind, head.Seq, ours)
		case head.Seq == ours:
			if !head.H.Equal(have) {
				return &vaultlog.EquivocationError{Seq: ours, Have: have, Got: head.H}
			}
			return nil
		case ours == after:
			return fmt.Errorf("store: the server reports head %d but returned no entry past %d", head.Seq, after)
		}
	}
}

// extend fetches and verifies the entries past the verified head.
func (d *destination) extend(ctx context.Context, r SignInRemote) error {
	n := len(d.wires)
	if err := d.fetchRest(ctx, r); err != nil {
		return err
	}
	for _, w := range d.wires[n:] {
		if err := d.step(w); err != nil {
			return err
		}
	}
	return d.departed()
}

// deviceInfo is rec's public device, for its bootstrap. The device keys
// it decodes for it are zeroed before it returns.
func deviceInfo(rec *deviceRecord, name string) (vaultlog.DeviceInfo, error) {
	return deviceInfoWith(rec, name, nil)
}

// deviceInfoWith is deviceInfo with a test hook, which sees the decoded
// device keys.
func deviceInfoWith(rec *deviceRecord, name string, watch func(*vaultlog.LocalDevice)) (vaultlog.DeviceInfo, error) {
	dev, err := rec.device()
	if err != nil {
		return vaultlog.DeviceInfo{}, err
	}
	defer zeroDevice(dev)
	if watch != nil {
		watch(dev)
	}
	return vaultlog.DeviceInfo{
		ID: rec.DeviceID, Name: name, KEMPK: dev.KEM.PublicKey().Bytes(),
		SigPK: append([]byte(nil), dev.Sig.Public().(ed25519.PublicKey)...),
	}, nil
}

// bootstrapDestination makes info's device active in d (§4.4): if it
// already is (an earlier attempt's bootstrap committed), its keys must be
// info's; otherwise a bootstrap is built against the verified head, posted,
// and accepted only once the server's log shows it, verified.
func bootstrapDestination(ctx context.Context, r SignInRemote, d *destination, info vaultlog.DeviceInfo, now func() model.Timestamp, hook func(string) error) error {
	for attempt := 0; attempt < maxSignInBootstrap; attempt++ {
		if da, ok := d.st.Devices[info.ID]; ok {
			return crypto.CheckCertKeys(&da.Cert, info.KEMPK, info.SigPK)
		}
		w, _, _, err := vaultlog.BuildBootstrap(d.st, d.sec, info, now())
		if err != nil {
			return err
		}
		if err := hook("signin:post"); err != nil {
			return err
		}
		if _, err := r.Post(ctx, w); err != nil && !errors.Is(err, ErrHeadConflict) {
			return err
		}
		if err := d.extend(ctx, r); err != nil {
			return err
		}
	}
	return errors.New("store: the bootstrap entry did not commit; another device keeps writing first")
}

// signInDestination is what every sign-in does on the server (§4.4, §4.5),
// with the new device's record durable and named in device.json: it reads
// the destination log, verifies it from the anchor of o's account keys as
// self, posts the bootstrap that adds self unless an earlier attempt's
// did, and catches up to the server's head. The verified destination goes
// to o, which owns it, as soon as it holds secrets. A *vaultlog.RevokedError
// means self was revoked: the caller makes that terminal.
func signInDestination(ctx context.Context, r SignInRemote, o *signInSecrets, self *vaultlog.LocalDevice, info vaultlog.DeviceInfo, now func() model.Timestamp, hook func(string) error) error {
	if err := hook("signin:fetch"); err != nil {
		return err
	}
	d, err := fetchDestination(ctx, r, o, self)
	if d != nil {
		o.d = d
	}
	if err != nil {
		return err
	}
	return bootstrapDestination(ctx, r, d, info, now, hook)
}

// nextStore is the device store of device.json's next member: the
// destination account's keychain entries, or device.next.key.
func (s *Store) nextStore(cfg deviceConfig) *deviceStore {
	next := deviceConfig{V: 1, Store: cfg.Store, Sealed: cfg.Sealed, AccountID: cfg.Next.AccountID, DeviceID: cfg.Next.DeviceID}
	l := s.l
	l.keyName = nextKeyName
	return &deviceStore{cfg: next, l: l, ring: s.ring(), getenv: s.getenv()}
}

// MergeSignIn is the sign-in of a login merge (§4.4), the hook slice E's
// hop auth login --merge calls once it has opened the destination
// account's keys. From state sealed (fresh, or resumed after a crash), it:
//
//  1. names the destination device in device.json (next), then makes its
//     record durable, with the source's local_key; or uses the record an
//     earlier attempt left (resolveNext);
//  2. reads the destination log through r, verifies it from the anchor of
//     p.Account as the destination device, and posts the bootstrap that
//     adds it, accepted once verified from the server's log
//     (signInDestination);
//  3. in one durable commit, records signed_in with the vault_id, deletes
//     the source vault and installs the destination's verified log, with
//     vault/server.json naming p's server and email;
//  4. deletes the source device record and names the destination in
//     device.json;
//  5. enqueues the imports (state importing).
//
// The store is then the destination's, unlocked and server-backed. Source
// deletion happens only once the bundle and the destination record are
// both durable. A failure before step 3 leaves the source as it was,
// frozen; a crash after it is finished by the next unlock. A revocation of
// the destination device is terminal for this destination
// (ErrSignInRevoked): the sign-in ledger records it and its record becomes
// a tombstone, and MergeCancel can then unfreeze the source. A recovery
// sign-in returns CheckpointDue.
func (s *Store) MergeSignIn(ctx context.Context, r SignInRemote, p SignInParams) (MergeStatus, error) {
	o := &signInSecrets{acct: p.Account}
	defer o.zero()
	sf, err := p.check()
	if err != nil {
		return MergeStatus{}, err
	}
	if err := s.lockSync(); err != nil {
		return MergeStatus{}, err
	}
	defer s.syncMu.Unlock()
	next, gen, err := s.mergeNextDevice(p)
	if err != nil {
		return MergeStatus{}, err
	}
	o.rec = next
	self, err := next.device()
	if err != nil {
		return MergeStatus{}, err
	}
	o.dev = self
	if s.testSignIn != nil {
		s.testSignIn(o)
	}
	info, err := deviceInfo(next, p.deviceName(s))
	if err != nil {
		return MergeStatus{}, err
	}
	err = s.signInCall(ctx, gen, func(ctx context.Context) error {
		return signInDestination(ctx, r, o, self, info, s.now, s.hook)
	})
	if rev := (*vaultlog.RevokedError)(nil); errors.As(err, &rev) {
		s.hook("signin:revoking")
		return MergeStatus{}, s.revokeNext(next.AccountID, next.DeviceID, err)
	}
	if err != nil {
		return MergeStatus{}, err
	}
	return s.dropSource(gen, o, p.serverFor(sf, o.d.st))
}

// mergeNextDevice checks that a sealed merge is waiting for its sign-in and
// returns the destination device record, durable and named in device.json:
// the one an earlier attempt left there, or a new one with the source's
// local_key. The caller owns the record.
//
// device.json names the destination device before its record is created
// (the intent), so the device key store never holds a destination record
// that device.json does not track. An earlier attempt's device is resolved
// first: the sign-in ledger (ledger.go) is read before the device key
// store, and a device it records as revoked ends the sign-in to this
// destination (ErrSignInRevoked), whatever the store holds, after its
// tombstone is tried again. Otherwise it is resolved from what the store
// holds for it (deviceStore.probeSlot):
//
//   - its record: it is used again, made durable again first, with this
//     sign-in's Secret Key (refreshSecretKey);
//   - its tombstone: the device was revoked, and the sign-in to this
//     destination is over (ErrSignInRevoked); the tombstone is never
//     overwritten;
//   - a read that is not conclusive: nothing is changed, and it fails;
//   - a confirmed absence: its bootstrap may still have committed (a record
//     lost after it was posted), so it is recorded as stale, in the same
//     write that names the new device, and hop passwd revokes it once the
//     destination is installed.
//
// A new destination device also carries the devices an earlier merge into
// the same account orphaned (MergeCancel with ForceOrphan) into its stale
// list.
func (s *Store) mergeNextDevice(p SignInParams) (*deviceRecord, uint64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.state == nil {
		return nil, 0, s.lockedErr()
	}
	unlock, err := s.lockFile()
	if err != nil {
		return nil, 0, err
	}
	defer unlock()
	m, err := s.readMerge(s.rec)
	if err != nil {
		return nil, 0, err
	}
	if m == nil {
		return nil, 0, ErrNoMerge
	}
	if m.j.State != MergeSealed || s.server {
		return nil, 0, fmt.Errorf("%w: the sign-in is already done (state %s)", ErrMergeState, m.j.State)
	}
	if p.Account.AccountID == s.state.Account.AccountID {
		return nil, 0, fmt.Errorf("%w: the destination is this vault's own account", ErrMergeRefused)
	}
	cfg, err := s.readDeviceConfig()
	if err != nil {
		return nil, 0, err
	}
	ledger, err := s.l.readLedger()
	if err != nil {
		return nil, 0, err
	}
	stale := ledger.orphaned(p.Account.AccountID)
	if cfg.Next != nil {
		if cfg.Next.AccountID != p.Account.AccountID {
			return nil, 0, fmt.Errorf("%w: a sign-in to account %v is already in progress", ErrMergeState, cfg.Next.AccountID)
		}
		if ledger.isRevoked(cfg.Next.AccountID, cfg.Next.DeviceID) {
			revoked := fmt.Errorf("%w (device %v, recorded in %s): this destination can't be signed in to from here again; cancel the merge with hop auth merge --cancel",
				ErrSignInRevoked, cfg.Next.DeviceID, s.l.ledgerFile())
			return nil, 0, s.stillRevoked(s.nextStore(cfg), cfg.Next.DeviceID, revoked)
		}
		state, rec, err := s.nextStore(cfg).probeSlot(cfg.Next.DeviceID)
		if err != nil {
			return nil, 0, fmt.Errorf("store: the destination device of an earlier attempt can't be resolved, so nothing was changed: %w", err)
		}
		switch state {
		case slotTombstone:
			return nil, 0, fmt.Errorf("%w (device %v; its record is a tombstone): this destination can't be signed in to from here again; cancel the merge with hop auth merge --cancel",
				ErrSignInRevoked, cfg.Next.DeviceID)
		case slotRecord:
			if !bytes.Equal(rec.LocalKey, s.rec.LocalKey) || rec.AccountID != p.Account.AccountID {
				rec.zero()
				return nil, 0, fmt.Errorf("%w: the destination device record does not carry this vault's local key", ErrCorrupt)
			}
			// A record found on disk is made durable again before it is
			// used, with this sign-in's Secret Key.
			if err := s.nextStore(cfg).upgradeRecord(rec); err != nil {
				rec.zero()
				return nil, 0, err
			}
			if err := s.nextStore(cfg).refreshSecretKey(rec, p.SecretKey); err != nil {
				rec.zero()
				return nil, 0, err
			}
			return rec, s.gen.Load(), nil
		}
		stale = append(stale, cfg.Next.Stale...)
		stale = append(stale, cfg.Next.DeviceID)
	}
	stale = uniqueIDs(stale)
	if err := s.hook("signin:record"); err != nil {
		return nil, 0, err
	}
	rec, _, err := newDeviceRecord(p.Account.AccountID, p.SecretKey)
	if err != nil {
		return nil, 0, err
	}
	copy(rec.LocalKey, s.rec.LocalKey)
	cfg.Next = &nextDevice{AccountID: p.Account.AccountID, DeviceID: rec.DeviceID, Stale: stale}
	if err := s.writeDeviceConfig(cfg); err != nil {
		rec.zero()
		return nil, 0, err
	}
	s.devCfg = cfg
	if err := s.hook("signin:intent"); err != nil {
		rec.zero()
		return nil, 0, err
	}
	if err := s.nextStore(cfg).storeDurably(rec); err != nil {
		rec.zero()
		return nil, 0, fmt.Errorf("store: the destination device key was not saved durably: %w", err)
	}
	if err := s.hook("signin:next"); err != nil {
		rec.zero()
		return nil, 0, err
	}
	return rec, s.gen.Load(), nil
}

// revokeNext makes the revocation of the destination device id of account
// acct terminal for this destination (§5.5): the sign-in ledger records it
// durably first, and then its record is replaced by its tombstone, so every
// later attempt stops at it (mergeNextDevice) without asking the server,
// which may withhold the revoking checkpoint then. Either one is enough;
// a tombstone that could not be written is tried again by every later
// attempt and by MergeCancel. The source vault is not revoked: it stays
// frozen until MergeCancel. It needs no unlocked store: a lock meanwhile
// does not lose the revocation. rev wraps the *vaultlog.RevokedError.
//
// device.json may name id as this directory's own device by now: a crash
// or another owner installed the destination and promoted it before the
// revocation was recorded. Its record is then the one tombstoned, and the
// revocation is this store's (ErrDeviceRevoked). Open and every unlock
// refuse it from the ledger alone too (checkRevoked).
func (s *Store) revokeNext(acct, id model.ID, rev error) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	revoked := fmt.Errorf("%w (device %v, %s)", ErrSignInRevoked, id, revokedAt(rev))
	unlock, err := s.lockFile()
	if err != nil {
		return fmt.Errorf("%w; it could not be recorded: %v", revoked, err)
	}
	defer unlock()
	cfg, cerr := s.readDeviceConfig()
	var ds *deviceStore
	promoted := false
	switch {
	case cerr != nil:
	case cfg.Next != nil && cfg.Next.AccountID == acct && cfg.Next.DeviceID == id:
		ds = s.nextStore(cfg)
	case cfg.AccountID == acct && slices.Contains(cfg.self(), id):
		ds, promoted = s.deviceStore(cfg), true
		revoked = fmt.Errorf("%w: %w", ErrDeviceRevoked, revoked)
	default:
		cerr = errors.New("device.json no longer names it")
	}
	err = s.recordRevoked(acct, id, revoked, func() error {
		if cerr != nil {
			return cerr
		}
		return ds.tombstone(id)
	})
	if promoted {
		s.setRevoked(revoked)
		s.dropLocked(revoked)
	}
	return err
}

// recordRevoked makes a sign-in's revocation of device id of account acct
// terminal: the sign-in ledger records it durably, then tombstone replaces
// its record. It returns revoked, annotated with whichever step failed.
// The caller holds the file lock.
func (s *Store) recordRevoked(acct, id model.ID, revoked error, tombstone func() error) error {
	if err := s.hook("signin:revoked"); err != nil {
		return errors.Join(revoked, err)
	}
	merr := s.l.markRevoked(acct, id)
	terr := tombstone()
	switch {
	case merr != nil && terr != nil:
		return fmt.Errorf("%w; neither the sign-in ledger (%v) nor its tombstone (%v) could be written", revoked, merr, terr)
	case merr != nil:
		return fmt.Errorf("%w; the sign-in ledger could not be written (%v), but its tombstone was", revoked, merr)
	case terr != nil:
		return fmt.Errorf("%w; the sign-in ledger records it, but its tombstone could not be written yet: %v", revoked, terr)
	}
	return revoked
}

// stillRevoked is the refusal of a sign-in whose device the sign-in ledger
// records as revoked: it tries the device's tombstone again (in ds), so a
// record a failed write left is replaced once the store works, and returns
// revoked. The caller holds the file lock.
func (s *Store) stillRevoked(ds *deviceStore, id model.ID, revoked error) error {
	if err := ds.tombstone(id); err != nil {
		return fmt.Errorf("%w; its tombstone could not be written yet: %v", revoked, err)
	}
	return revoked
}

// uniqueIDs returns ids without duplicates, in their first order.
func uniqueIDs(ids []model.ID) []model.ID {
	var out []model.ID
	for _, id := range ids {
		if !slices.Contains(out, id) {
			out = append(out, id)
		}
	}
	return out
}

// signInCall runs f, the sign-in's requests to the server, without s.mu, in
// a context that Lock cancels. A lock meanwhile discards the result, except
// a revocation of the device being enrolled, which is never lost.
func (s *Store) signInCall(ctx context.Context, gen uint64, f func(ctx context.Context) error) error {
	s.mu.Lock()
	if s.gen.Load() != gen || s.state == nil {
		s.mu.Unlock()
		return ErrSyncInterrupted
	}
	ctx, _, untrack := s.trackRequest(ctx)
	s.mu.Unlock()
	err := f(ctx)
	s.mu.Lock()
	defer s.mu.Unlock()
	untrack()
	if rev := (*vaultlog.RevokedError)(nil); errors.As(err, &rev) {
		return err
	}
	if s.gen.Load() != gen || s.state == nil {
		return ErrSyncInterrupted
	}
	return err
}

// dropSource is §4.4 "Drop the source": one durable commit records
// signed_in, deletes the source vault and installs the destination's
// verified log, with sf as vault/server.json; then the source device record
// goes and device.json names the destination (promoteNext); then the store
// takes o's secrets over and is the destination's, unlocked, and the
// imports are enqueued. Until it takes them, o owns them.
func (s *Store) dropSource(gen uint64, o *signInSecrets, sf serverFile) (MergeStatus, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.gen.Load() != gen || s.state == nil {
		return MergeStatus{}, ErrSyncInterrupted
	}
	next, d := o.rec, o.d
	unlock, err := s.lockFile()
	if err != nil {
		return MergeStatus{}, err
	}
	defer unlock()
	m, err := s.readMerge(s.rec)
	if err != nil {
		return MergeStatus{}, err
	}
	if m == nil || m.j.State != MergeSealed {
		return MergeStatus{}, fmt.Errorf("%w: the merge left state sealed during the sign-in", ErrMergeState)
	}
	cfg, err := s.readDeviceConfig()
	if err != nil {
		return MergeStatus{}, err
	}
	if cfg.Next == nil || cfg.Next.DeviceID != next.DeviceID {
		return MergeStatus{}, fmt.Errorf("%w: device.json no longer names the destination device", ErrDeviceKey)
	}
	// A revocation the ledger recorded meanwhile is never installed.
	if g, err := s.l.readLedger(); err != nil {
		return MergeStatus{}, err
	} else if g.isRevoked(cfg.Next.AccountID, next.DeviceID) {
		return MergeStatus{}, s.stillRevoked(s.nextStore(cfg), next.DeviceID,
			fmt.Errorf("%w (device %v, recorded in %s)", ErrSignInRevoked, next.DeviceID, s.l.ledgerFile()))
	}
	// The source's files, listed before the destination's objects are
	// written next to them.
	srcSeqs, err := s.l.entrySeqs()
	if err != nil {
		return MergeStatus{}, err
	}
	srcObjs, err := os.ReadDir(s.l.objects())
	if err != nil {
		return MergeStatus{}, err
	}
	srcJournals, err := s.journalSeqs()
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return MergeStatus{}, err
	}
	t := &txn{}
	m.j.State, m.j.VaultID = MergeSignedIn, d.st.VaultID
	if err := putMerge(t, next, m); err != nil {
		return MergeStatus{}, err
	}
	for _, seq := range srcSeqs {
		if seq >= uint64(len(d.wires)) {
			t.remove(entryRel(seq))
		}
	}
	keep := map[string]bool{}
	for h := range d.objs {
		keep[h.String()] = true
	}
	for _, e := range srcObjs {
		if !strings.HasPrefix(e.Name(), ".tmp") && !keep[e.Name()] {
			t.remove("objects/" + e.Name())
		}
	}
	for _, seq := range srcJournals {
		t.remove("journal/" + fmt.Sprint(seq) + ".json")
	}
	if err := s.putDestination(t, d, sf); err != nil {
		return MergeStatus{}, err
	}
	if _, err := os.Lstat(s.l.outboxMeta()); err == nil {
		t.remove(outboxMetaRel)
	}
	if err := s.hook("signin:drop"); err != nil {
		return MergeStatus{}, err
	}
	if err := s.commitTxn(t); err != nil {
		return MergeStatus{}, err
	}
	// Committed: from here there is one vault state, the destination's.
	// The source's secrets go now, whatever follows.
	s.dropLocked(nil)
	cfg, err = s.promoteNextLocked(cfg)
	if err != nil {
		s.lockErr = err
		return MergeStatus{}, err
	}
	rec, self, d := o.take()
	s.state, s.sec, s.dev, s.rec, s.devCfg, s.server = d.st, d.sec, self, rec, cfg, true
	s.gen.Add(1)
	if err := s.finishUnlock(); err != nil {
		s.dropLocked(err)
		return MergeStatus{}, err
	}
	st, err := s.mergeStatusLocked()
	st.CheckpointDue = s.serverInfoOf(&sf).CheckpointDue
	return st, err
}

// putDestination writes d's objects, and adds to t the destination's
// verified log (its entries, state.json and account.json) and sf as
// vault/server.json: a sign-in's install, in one durable commit with
// whatever else t holds. Objects are content-addressed, so one a crash
// leaves unreferenced is harmless. The caller holds the file lock.
func (s *Store) putDestination(t *txn, d *destination, sf serverFile) error {
	for _, w := range d.wires {
		if err := s.l.writeObjects(w); err != nil {
			return err
		}
	}
	acct, err := accountOf(d.st, d.objs)
	if err != nil {
		return err
	}
	ab, err := json.Marshal(acct)
	if err != nil {
		return err
	}
	sb, err := d.st.Marshal()
	if err != nil {
		return err
	}
	for _, w := range d.wires {
		bare := *w
		bare.Objects = []vaultlog.Object{}
		b, err := bare.Marshal()
		if err != nil {
			return err
		}
		t.put(entryRel(w.Entry.Seq), b)
	}
	t.put(stateRel, sb)
	t.put("account.json", ab)
	return serverModeOps(t, sf)
}

// mergeStatusLocked is MergeStatus for a caller that holds s.mu and the
// file lock. A merge that has finished reports Done.
func (s *Store) mergeStatusLocked() (MergeStatus, error) {
	m, err := s.readMerge(s.rec)
	if err != nil {
		return MergeStatus{}, err
	}
	if m == nil {
		return MergeStatus{Done: true}, nil
	}
	return m.status(s.rec)
}

// promoteNext finishes a login merge's switch of device.json to the
// destination device, when the destination vault is installed (its
// state.json is the next member's account): a crash between the drop
// commit and the switch. It returns the configuration to use. The caller
// holds s.mu, and not the file lock.
func (s *Store) promoteNext(cfg deviceConfig) (deviceConfig, error) {
	if cfg.Next == nil {
		return cfg, nil
	}
	unlock, err := s.lockFile()
	if err != nil {
		return cfg, err
	}
	defer unlock()
	if err := s.replayWAL(); err != nil {
		return cfg, err
	}
	b, err := os.ReadFile(s.l.stateFile())
	if errors.Is(err, os.ErrNotExist) {
		return cfg, nil
	}
	if err != nil {
		return cfg, err
	}
	st, err := vaultlog.ParseState(b)
	if err != nil || st.Account.AccountID != cfg.Next.AccountID {
		return cfg, nil // the source's state, or one the replay will refuse
	}
	return s.promoteNextLocked(cfg)
}

// promoteNextLocked deletes the source device record and names the next
// device in device.json: for the file store, device.next.key is renamed
// over device.key, which deletes the source record in the same step; for
// the keychain, the source's entries are deleted first. The caller holds
// the file lock.
func (s *Store) promoteNextLocked(cfg deviceConfig) (deviceConfig, error) {
	if err := s.hook("signin:promote"); err != nil {
		return cfg, err
	}
	// The ledger must parse before anything changes. A destination device
	// it records as revoked is promoted as one: its record becomes a
	// tombstone first (at best effort: the ledger alone keeps it terminal,
	// checkRevoked), and the store is revoked.
	g, err := s.l.readLedger()
	if err != nil {
		return cfg, err
	}
	var revoked error
	if g.isRevoked(cfg.Next.AccountID, cfg.Next.DeviceID) {
		revoked = fmt.Errorf("%w: %w (device %v, recorded in %s)", ErrDeviceRevoked, ErrSignInRevoked, cfg.Next.DeviceID, s.l.ledgerFile())
		s.nextStore(cfg).tombstone(cfg.Next.DeviceID)
	}
	ns := s.nextStore(cfg)
	switch cfg.Store {
	case DeviceStoreFile:
		if _, err := os.Lstat(ns.l.deviceKeyFile()); err == nil {
			if err := os.Rename(ns.l.deviceKeyFile(), s.l.deviceKeyFile()); err != nil {
				return cfg, err
			}
			if err := syncDir(s.l.data); err != nil {
				return cfg, err
			}
		} else if !errors.Is(err, os.ErrNotExist) {
			return cfg, err
		}
	case DeviceStoreKeychain:
		ds := s.deviceStore(cfg)
		for _, id := range cfg.self() {
			if err := ds.deleteSlot(id); err != nil {
				return cfg, fmt.Errorf("deleting the source vault's device key: %w", err)
			}
		}
		for _, id := range cfg.StaleDevices {
			ds.deleteSlot(id) // best effort: a key of the source account, which is gone
		}
	}
	// Devices an earlier attempt may have enrolled, and whose records are
	// gone, become stale devices of the destination: reconcileDevice keeps
	// the active ones, and hop passwd revokes them.
	next := deviceConfig{V: 1, Store: cfg.Store, Sealed: cfg.Sealed, AccountID: cfg.Next.AccountID, DeviceID: cfg.Next.DeviceID,
		StaleDevices: slices.Clone(cfg.Next.Stale)}
	if err := s.writeDeviceConfig(next); err != nil {
		return cfg, err
	}
	// The devices an earlier, cancelled merge into this account orphaned
	// are stale devices of it now (mergeNextDevice carried them into
	// next.stale): the ledger forgets them, at best effort, since keeping
	// them is harmless.
	if g.clearOrphaned(next.AccountID) {
		s.l.writeLedger(g)
	}
	if revoked != nil {
		s.setRevoked(revoked)
		return next, revoked
	}
	return next, nil
}

// resumeMerge continues a login merge at unlock: signed_in enqueues the
// imports. The caller holds the file lock and the store is unlocked.
func (s *Store) resumeMerge() error {
	m, err := s.readMerge(s.rec)
	if err != nil || m == nil {
		return err
	}
	if m.j.State == MergeSealed {
		if s.server {
			return fmt.Errorf("%w: a sealed merge in a server-backed vault", ErrCorrupt)
		}
		return nil
	}
	if !s.server || m.j.VaultID != s.state.VaultID {
		return fmt.Errorf("%w: the merge names another vault", ErrCorrupt)
	}
	if m.j.State != MergeSignedIn {
		return nil
	}
	return s.enqueueImports(m, MergeSignedIn)
}

// enqueueImports appends, in one commit, one import record for each
// manifest item with no receipt, in dependency order, and sets importing
// (§4.4 "Enqueue", and resume from paused). from is the state it leaves.
// The caller holds the file lock and the store is unlocked.
func (s *Store) enqueueImports(m *openedMerge, from string) error {
	if m.j.State != from {
		return fmt.Errorf("%w: the merge is %s", ErrMergeState, m.j.State)
	}
	items, err := m.bundleItems(s.rec)
	if err != nil {
		return err
	}
	recs, err := s.readOutbox()
	if err != nil {
		return err
	}
	for _, r := range recs {
		if r.Import == m.j.TxnID {
			return fmt.Errorf("%w: import records of this merge are still queued", ErrCorrupt)
		}
	}
	meta, err := s.readOutboxMeta()
	if err != nil {
		return err
	}
	n := meta.Next
	if ns, err := s.l.outboxNumbers(); err != nil {
		return err
	} else if len(ns) > 0 && ns[len(ns)-1] >= n {
		n = ns[len(ns)-1] + 1
	}
	t := &txn{}
	todo := m.j.unreceipted()
	for _, row := range importOrder(todo, items) {
		want, err := withVersion(items[row.ItemID], 1)
		if err != nil {
			return err
		}
		in := merge.Intent{Action: merge.ActionCreate, ItemID: row.ItemID, Type: row.Type, Want: want}
		if err := in.Validate(); err != nil {
			return fmt.Errorf("%w: import of %v: %v", ErrCorrupt, row.ItemID, err)
		}
		rec := &record{N: n, Intent: in, Import: m.j.TxnID, Cands: []candidate{}, Wires: map[crypto.Hash]*vaultlog.Wire{}}
		if err := s.putRecord(t, rec); err != nil {
			return err
		}
		n++
	}
	meta.Next = n
	if err := putOutboxMeta(t, meta); err != nil {
		return err
	}
	if len(todo) == 0 {
		// Nothing to import: every item has its receipt, so the merge is
		// done (§4.4 "Finish").
		t.remove(mergeRel)
	} else {
		m.j.State = MergeImporting
		if err := putMerge(t, s.rec, m); err != nil {
			return err
		}
	}
	if err := s.hook("merge:enqueue"); err != nil {
		return err
	}
	return s.commitTxn(t)
}

// importOrder sorts rows in dependency order (§4.4): keys and credentials,
// then hosts, each after its jump host, then snippets; by item_id within
// each group.
func importOrder(rows []merge.ManifestRow, items map[model.ID]*merge.Item) []merge.ManifestRow {
	sorted := slices.Clone(rows)
	slices.SortFunc(sorted, func(a, b merge.ManifestRow) int { return bytes.Compare(a.ItemID[:], b.ItemID[:]) })
	var out, hosts, snippets []merge.ManifestRow
	byID := map[model.ID]merge.ManifestRow{}
	for _, r := range sorted {
		switch r.Type {
		case model.TypeKey, model.TypeCredential:
			out = append(out, r)
		case model.TypeHost:
			hosts = append(hosts, r)
			byID[r.ItemID] = r
		default:
			snippets = append(snippets, r)
		}
	}
	placed := map[model.ID]bool{}
	var place func(r merge.ManifestRow)
	place = func(r merge.ManifestRow) {
		if placed[r.ItemID] {
			return
		}
		placed[r.ItemID] = true
		if p, err := plainOf(items[r.ItemID]); err == nil {
			if h, ok := p.(*model.Host); ok {
				if j, ok := byID[h.JumpHostID]; ok {
					place(j)
				}
			}
		}
		out = append(out, r)
	}
	for _, r := range hosts {
		place(r)
	}
	return append(out, snippets...)
}

// addReceipts adds the receipts of committed import records to the merge
// journal in t, the commit that removes those records (§4.4 "Receipts"),
// and deletes the file once every manifest item has one ("Finish"). rec's
// local_key opens it. Records of another transaction, or with no merge
// file, add nothing. The caller holds the file lock.
func (s *Store) addReceipts(t *txn, rec *deviceRecord, txnID model.ID, receipts []mergeReceipt) error {
	m, err := s.readMerge(rec)
	if err != nil || m == nil || m.j.TxnID != txnID {
		return err
	}
	for _, r := range receipts {
		if m.j.receipt(r.ItemID) == nil {
			m.j.Receipts = append(m.j.Receipts, r)
		}
	}
	if len(m.j.unreceipted()) == 0 {
		t.remove(mergeRel)
		return nil
	}
	return putMerge(t, rec, m)
}

// refuseImportingWrite refuses an ordinary item write while a login merge
// is signed_in or importing (§4.4). The caller holds the file lock.
func (s *Store) refuseImportingWrite() error {
	if exists, err := s.l.mergeExists(); err != nil || !exists {
		return err
	}
	m, err := s.readMerge(s.rec)
	if err != nil || m == nil {
		return err
	}
	switch m.j.State {
	case MergeSignedIn, MergeImporting:
		return ErrMergeImporting
	case MergeSealed:
		return ErrMergeFrozen
	}
	return nil
}

// MergePause pauses an importing merge (§4.4): it first waits until no
// import record has a live candidate (pulling through r, and re-posting
// the identical wire of one still live, so verified history settles it;
// nothing else is pushed meanwhile), then in one durable commit deletes
// this merge's import records and sets paused. With r nil it refuses if a
// candidate is live. It returns which items were imported.
func (s *Store) MergePause(ctx context.Context, r Remote) (MergeStatus, error) {
	if err := s.lockSync(); err != nil {
		return MergeStatus{}, err
	}
	defer s.syncMu.Unlock()
	for attempt := 0; attempt < maxPushAttempts; attempt++ {
		// A pull that fails (the server is unreachable) matters only if an
		// import is in flight: with none, the pause needs no server.
		var pullErr error
		if r != nil {
			pullErr = s.pullLocked(ctx, r)
		}
		st, w, err := s.pauseLocked()
		if err != nil || w == nil {
			return st, err
		}
		if r == nil || pullErr != nil {
			return MergeStatus{}, fmt.Errorf("%w: an import is in flight; pause again once the server is reachable", errors.Join(ErrLiveCandidate, pullErr))
		}
		ctx2, _, done, err := s.syncContext(ctx)
		if err != nil {
			return MergeStatus{}, err
		}
		_, err = r.Post(ctx2, w)
		done()
		if err != nil && !errors.Is(err, ErrHeadConflict) {
			return MergeStatus{}, err
		}
	}
	return MergeStatus{}, fmt.Errorf("%w: an import is still in flight", ErrLiveCandidate)
}

// pauseLocked commits the pause, or returns the live import wire to settle
// first.
func (s *Store) pauseLocked() (MergeStatus, *vaultlog.Wire, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.needServer(); err != nil {
		return MergeStatus{}, nil, err
	}
	unlock, err := s.lockFile()
	if err != nil {
		return MergeStatus{}, nil, err
	}
	defer unlock()
	m, err := s.readMerge(s.rec)
	if err != nil {
		return MergeStatus{}, nil, err
	}
	if m == nil {
		return MergeStatus{}, nil, ErrNoMerge
	}
	if m.j.State != MergeImporting {
		return MergeStatus{}, nil, fmt.Errorf("%w: only an importing merge can be paused (it is %s)", ErrMergeState, m.j.State)
	}
	recs, err := s.readOutbox()
	if err != nil {
		return MergeStatus{}, nil, err
	}
	t := &txn{}
	for _, r := range recs {
		if r.Import != m.j.TxnID {
			continue
		}
		if c := r.live(); c != nil {
			w, ok := r.Wires[c.H]
			if !ok {
				return MergeStatus{}, nil, fmt.Errorf("%w: outbox record %d has lost the wire of its live candidate", ErrCorrupt, r.N)
			}
			return MergeStatus{}, w, nil
		}
		t.remove(outboxRel(r.N))
	}
	m.j.State = MergePaused
	if err := putMerge(t, s.rec, m); err != nil {
		return MergeStatus{}, nil, err
	}
	if err := s.commitTxn(t); err != nil {
		return MergeStatus{}, nil, err
	}
	st, err := m.status(s.rec)
	return st, nil, err
}

// MergeResume resumes a paused merge (§4.4): valid only in paused, so a
// second resume is rejected. In one durable commit it sets importing and
// appends one import record, in dependency order, for each manifest item
// with no receipt.
func (s *Store) MergeResume() (MergeStatus, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.needServer(); err != nil {
		return MergeStatus{}, err
	}
	unlock, err := s.lockFile()
	if err != nil {
		return MergeStatus{}, err
	}
	defer unlock()
	m, err := s.readMerge(s.rec)
	if err != nil {
		return MergeStatus{}, err
	}
	if m == nil {
		return MergeStatus{}, ErrNoMerge
	}
	if m.j.State != MergePaused {
		return MergeStatus{}, fmt.Errorf("%w: only a paused merge can be resumed (it is %s)", ErrMergeState, m.j.State)
	}
	if err := s.enqueueImports(m, MergePaused); err != nil {
		return MergeStatus{}, err
	}
	return s.mergeStatusLocked()
}

// DiscardProposal is what hop auth merge --discard asks the user to
// confirm: the items never imported and the digest c (§5.4).
type DiscardProposal struct {
	VaultID model.ID    `json:"vault_id"`
	TxnID   model.ID    `json:"txn_id"`
	Items   []MergeItem `json:"items"` // the manifest rows with no receipt, sorted by item_id
	Digest  crypto.Hash `json:"digest"`
}

// discardCheck checks the §4.4 discard preconditions and returns the
// proposal: paused, no record of this merge left in the outbox and no live
// candidate. The caller holds s.mu and the file lock.
func (s *Store) discardCheck() (*openedMerge, DiscardProposal, error) {
	if err := s.needServer(); err != nil {
		return nil, DiscardProposal{}, err
	}
	m, err := s.readMerge(s.rec)
	if err != nil {
		return nil, DiscardProposal{}, err
	}
	if m == nil {
		return nil, DiscardProposal{}, ErrNoMerge
	}
	if m.j.State != MergePaused {
		return nil, DiscardProposal{}, fmt.Errorf("%w: only a paused merge can be discarded (it is %s)", ErrMergeState, m.j.State)
	}
	recs, err := s.readOutbox()
	if err != nil {
		return nil, DiscardProposal{}, err
	}
	for _, r := range recs {
		if r.Import == m.j.TxnID {
			return nil, DiscardProposal{}, fmt.Errorf("%w: import records of this merge are still queued", ErrMergeState)
		}
		if r.live() != nil {
			return nil, DiscardProposal{}, fmt.Errorf("%w: wait until the queued change in flight settles", ErrLiveCandidate)
		}
	}
	items, err := m.bundleItems(s.rec)
	if err != nil {
		return nil, DiscardProposal{}, err
	}
	rows := m.j.unreceipted()
	slices.SortFunc(rows, func(a, b merge.ManifestRow) int { return bytes.Compare(a.ItemID[:], b.ItemID[:]) })
	d, err := merge.MergeDiscardDigest(m.j.VaultID, m.j.TxnID, rows)
	if err != nil {
		return nil, DiscardProposal{}, err
	}
	p := DiscardProposal{VaultID: m.j.VaultID, TxnID: m.j.TxnID, Items: []MergeItem{}, Digest: d}
	for _, r := range rows {
		p.Items = append(p.Items, MergeItem{ItemID: r.ItemID, Type: r.Type, Name: itemName(items[r.ItemID])})
	}
	return m, p, nil
}

// MergeDiscardProposal returns what a discard would delete and its digest
// c, without changing anything.
func (s *Store) MergeDiscardProposal() (DiscardProposal, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	unlock, err := s.lockFile()
	if err != nil {
		return DiscardProposal{}, err
	}
	defer unlock()
	_, p, err := s.discardCheck()
	return p, err
}

// MergeDiscard discards a paused merge (§4.4): it deletes the file, and
// with it the items that were never imported. confirm must be the digest c
// of DiscardProposal, recomputed here, with the preconditions, immediately
// before anything is deleted. A zero confirm changes nothing and returns
// the proposal with ErrConfirmRequired (the non-interactive case); a
// different one returns ErrStaleConfirm.
func (s *Store) MergeDiscard(confirm crypto.Hash) (DiscardProposal, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	unlock, err := s.lockFile()
	if err != nil {
		return DiscardProposal{}, err
	}
	defer unlock()
	_, p, err := s.discardCheck()
	if err != nil {
		return DiscardProposal{}, err
	}
	if confirm == (crypto.Hash{}) {
		return p, ErrConfirmRequired
	}
	if !confirm.Equal(p.Digest) {
		return p, ErrStaleConfirm
	}
	t := &txn{}
	t.remove(mergeRel)
	return p, s.commitTxn(t)
}

// MergeRetry retries a held import at the head of the outbox (§4.4: "The
// user can retry, or pause the merge"): the unchanged import is evaluated
// again against verified state, and held is cleared only if every rule
// passes; otherwise it returns ErrStillHeld. Take theirs and edit are never
// offered for an import (Resolve refuses import records).
func (s *Store) MergeRetry() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.needServer(); err != nil {
		return err
	}
	unlock, err := s.lockFile()
	if err != nil {
		return err
	}
	defer unlock()
	recs, err := s.readOutbox()
	if err != nil {
		return err
	}
	if len(recs) == 0 || !recs[0].Held || recs[0].Import.IsZero() {
		return fmt.Errorf("%w: the outbox head is not a held import", ErrNotHeld)
	}
	rec := recs[0]
	if rec.live() != nil {
		return ErrLiveCandidate
	}
	ev, err := s.evaluate(rec.Intent)
	if err != nil {
		return err
	}
	if ev.res.Kind == merge.KindHold {
		return fmt.Errorf("%w: %s", ErrStillHeld, ev.res.Cause)
	}
	rec.Held = false
	t := &txn{}
	if err := s.putRecord(t, rec); err != nil {
		return err
	}
	return s.commitTxn(t)
}
