package store

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strconv"

	"github.com/dalyem/hopkey/internal/canonjson"
	"github.com/dalyem/hopkey/internal/crypto"
	"github.com/dalyem/hopkey/internal/merge"
	"github.com/dalyem/hopkey/internal/model"
)

// The sync notes of a server-backed vault (crypto spec rev 17 amendment,
// §3.2), one file:
//
//	vault/sync-notes.json  JCS({"v":1, "vault_id":id, "lk":b64(16), "sealed":AEAD(local_key, notes, aad)})
//
// with
//
//	lk    = HKDF-Expand(local_key, lp("hopkey/v1/local-key-id"), 16)
//	aad   = lp("hopkey/v1/sync-notes") || lp(vault_id_bytes) || lp(lk)
//	notes = JCS({"v":1, "next":u64s, "evicted":{kind: u64s},
//	             "pending":[{"seq":u64s, "h":h, "n":u64s, "note":Note}],
//	             "ready":  [{"id":u64s, "note":Note}]})
//	Note  = {"kind":str≤32, "body":object}
//
// A pending note is journaled with the candidate it describes, keyed by the
// candidate's (seq, h), and every commit that advances verified state, and
// every unlock, settles it: ready when the verified entry at seq has hash
// h, dropped otherwise. That does not depend on the outbox, so a note whose
// record an older build settled still arrives. Ready notes stay until a
// reader acknowledges exactly the ones it was given (SyncNotes,
// AckSyncNotes). A kind this build doesn't know is kept byte for byte,
// settled, and never shown, evicted or acknowledged.
//
// Builds before rev 17 never open the file, and replaced.json and the
// outbox keep their formats. A file sealed under an earlier local_key (an
// older build replaced it) is not corrupt but obsolete: its lk says so, and
// it is discarded with one notice. A newer version is left alone.

const (
	labelSyncNotes   = "hopkey/v1/sync-notes"
	syncNotesRel     = "sync-notes.json"
	syncNotesVersion = 1
	// maxSyncNotesPerKind bounds the ready notes of each kind this build
	// knows.
	maxSyncNotesPerKind = 50
	// maxSyncNotesFile bounds the whole file.
	maxSyncNotesFile = 1 << 20
	maxNoteKind      = 32

	// NoteCombined is the kind of a note of a write that combined changes
	// rev 16 would have held.
	NoteCombined = "combined"
)

// knownNoteKind reports whether this build reads notes of kind k.
func knownNoteKind(k string) bool { return k == NoteCombined }

func (l layout) syncNotesFile() string { return filepath.Join(l.vault(), syncNotesRel) }

func syncNotesAAD(vaultID model.ID, lk []byte) []byte {
	aad := crypto.LP([]byte(labelSyncNotes))
	aad = append(aad, crypto.LP(vaultID[:])...)
	return append(aad, crypto.LP(lk)...)
}

// u64s is a u64 written as a decimal string, as a map value.
type u64s uint64

func (n u64s) MarshalText() ([]byte, error) { return strconv.AppendUint(nil, uint64(n), 10), nil }

func (n *u64s) UnmarshalText(b []byte) error {
	v, err := strconv.ParseUint(string(b), 10, 64)
	if err != nil || strconv.FormatUint(v, 10) != string(b) {
		return fmt.Errorf("store: %q is not a u64s", b)
	}
	*n = u64s(v)
	return nil
}

type syncNotesFileJSON struct {
	V       int                 `json:"v"`
	VaultID model.ID            `json:"vault_id"`
	LK      []byte              `json:"lk"`
	Sealed  crypto.AEADEnvelope `json:"sealed"`
}

type syncNoteJSON struct {
	Kind string        `json:"kind"`
	Body canonjson.Raw `json:"body"`
}

type pendingNoteJSON struct {
	Seq  uint64       `json:"seq,string"`
	H    crypto.Hash  `json:"h"`
	N    uint64       `json:"n,string"`
	Note syncNoteJSON `json:"note"`
}

type readyNoteJSON struct {
	ID   uint64       `json:"id,string"`
	Note syncNoteJSON `json:"note"`
}

type syncNotesJSON struct {
	V       int               `json:"v"`
	Next    uint64            `json:"next,string"`
	Evicted map[string]u64s   `json:"evicted"`
	Pending []pendingNoteJSON `json:"pending"`
	Ready   []readyNoteJSON   `json:"ready"`
}

// combinedBody is a combined note's body.
type combinedBody struct {
	ItemID model.ID   `json:"item_id"`
	Type   model.Type `json:"type"`
	Name   string     `json:"name"`
	Local  []string   `json:"local"`
	Remote []string   `json:"remote"`
}

func emptySyncNotes() syncNotesJSON {
	return syncNotesJSON{V: syncNotesVersion, Next: 1, Evicted: map[string]u64s{}, Pending: []pendingNoteJSON{}, Ready: []readyNoteJSON{}}
}

// syncNotesFile is what readSyncNotes found.
type syncNotesFile struct {
	notes syncNotesJSON
	// exists: the file is there.
	exists bool
	// newer: its version is newer than this build's. It is never
	// rewritten, and notes are not added to it.
	newer bool
	// obsolete: it was sealed under an earlier local_key. Its notes are
	// lost; the next write replaces it.
	obsolete bool
}

// readSyncNotes opens sync-notes.json with rec's local_key. A missing file
// is no notes. A newer version, or a file sealed under another local_key,
// is reported, not an error. Anything else that fails is ErrCorrupt: only
// hop writes this file. The caller holds the file lock.
func (s *Store) readSyncNotes(rec *deviceRecord, vaultID model.ID) (syncNotesFile, error) {
	out := syncNotesFile{notes: emptySyncNotes()}
	b, err := os.ReadFile(s.l.syncNotesFile())
	if errors.Is(err, os.ErrNotExist) {
		return out, nil
	}
	if err != nil {
		return out, err
	}
	out.exists = true
	bad := fmt.Errorf("%w: %s does not open", ErrCorrupt, s.l.syncNotesFile())
	if v, ok := versionOf(b); !ok {
		return out, bad
	} else if v > syncNotesVersion {
		out.newer = true
		return out, nil
	}
	var f syncNotesFileJSON
	if err := canonjson.Unmarshal(b, &f); err != nil || f.V != syncNotesVersion || f.VaultID != vaultID || len(f.LK) != crypto.LocalKeyIDSize {
		return out, bad
	}
	key, err := rec.localKey()
	if err != nil {
		return out, err
	}
	defer key.Zero()
	lk, err := crypto.LocalKeyID(key)
	if err != nil {
		return out, err
	}
	if !bytes.Equal(lk, f.LK) {
		out.obsolete = true
		return out, nil
	}
	pt, err := crypto.OpenAEAD(key, f.Sealed, syncNotesAAD(vaultID, lk))
	if err != nil {
		return out, bad
	}
	defer clear(pt)
	if v, ok := versionOf(pt); !ok {
		return out, bad
	} else if v > syncNotesVersion {
		out.newer = true
		return out, nil
	}
	var n syncNotesJSON
	if err := canonjson.Unmarshal(pt, &n); err != nil || !validSyncNotes(n) {
		return out, bad
	}
	if n.Evicted == nil {
		n.Evicted = map[string]u64s{}
	}
	out.notes = n
	return out, nil
}

// versionOf reads the v member of a JSON object, whatever else it holds.
func versionOf(b []byte) (int, bool) {
	var x struct {
		V *int `json:"v"`
	}
	if json.Unmarshal(b, &x) != nil || x.V == nil || *x.V < 1 {
		return 0, false
	}
	return *x.V, true
}

func validSyncNotes(n syncNotesJSON) bool {
	if n.V != syncNotesVersion || n.Next == 0 {
		return false
	}
	notes := make([]syncNoteJSON, 0, len(n.Pending)+len(n.Ready))
	ids := map[uint64]bool{}
	for _, r := range n.Ready {
		if r.ID == 0 || r.ID >= n.Next || ids[r.ID] {
			return false
		}
		ids[r.ID] = true
		notes = append(notes, r.Note)
	}
	for _, p := range n.Pending {
		notes = append(notes, p.Note)
	}
	for _, x := range notes {
		if x.Kind == "" || len(x.Kind) > maxNoteKind || len(x.Body) == 0 || x.Body[0] != '{' {
			return false
		}
		if x.Kind == NoteCombined {
			if _, ok := parseCombined(x.Body); !ok {
				return false
			}
		}
	}
	return true
}

func parseCombined(body canonjson.Raw) (combinedBody, bool) {
	var c combinedBody
	if canonjson.Unmarshal(body, &c) != nil || c.ItemID.IsZero() || len(c.Local) == 0 || len(c.Remote) == 0 ||
		!slices.IsSorted(c.Local) || !slices.IsSorted(c.Remote) || len([]rune(c.Name)) > 64 {
		return c, false
	}
	return c, true
}

// putSyncNotes adds sync-notes.json, holding n, to t. It refuses a file
// over maxSyncNotesFile.
func putSyncNotes(t *txn, rec *deviceRecord, vaultID model.ID, n syncNotesJSON) error {
	b, err := sealSyncNotes(rec, vaultID, n)
	if err != nil {
		return err
	}
	if len(b) > maxSyncNotesFile {
		return errSyncNotesFull
	}
	t.put(syncNotesRel, b)
	return nil
}

var errSyncNotesFull = errors.New("store: sync-notes.json would exceed its size limit")

func sealSyncNotes(rec *deviceRecord, vaultID model.ID, n syncNotesJSON) ([]byte, error) {
	pt, err := canonjson.Marshal(n)
	if err != nil {
		return nil, err
	}
	defer clear(pt)
	key, err := rec.localKey()
	if err != nil {
		return nil, err
	}
	defer key.Zero()
	lk, err := crypto.LocalKeyID(key)
	if err != nil {
		return nil, err
	}
	env, err := crypto.SealAEAD(key, pt, syncNotesAAD(vaultID, lk))
	if err != nil {
		return nil, err
	}
	return canonjson.Marshal(syncNotesFileJSON{V: syncNotesVersion, VaultID: vaultID, LK: lk, Sealed: env})
}

// updateSyncNotes reads the notes, lets change edit them, and adds the
// result to t when change reports a change. A newer file is left alone and
// change is not called. An obsolete one is replaced by change's result on
// an empty file, or removed if change has nothing to add; either way the
// notice that it was discarded is raised. A result over the size limit
// evicts the oldest ready notes of known kinds, and if that is not enough,
// nothing is added. what names what is being recorded, for the reason a
// note was dropped; "" records nothing new. The caller holds s.mu and the
// file lock.
func (s *Store) updateSyncNotes(t *txn, rec *deviceRecord, vaultID model.ID, what string, change func(n *syncNotesJSON) bool) error {
	f, err := s.readSyncNotes(rec, vaultID)
	if err != nil {
		return err
	}
	if f.newer {
		if what != "" {
			s.dropSyncNotes(fmt.Sprintf("sync-notes.json was written by a newer hop, so %s was not recorded", what))
		}
		return nil
	}
	changed := change(&f.notes)
	if f.obsolete {
		s.syncNotesDiscarded = true
		if !changed {
			t.remove(syncNotesRel)
			return nil
		}
	}
	if !changed {
		return nil
	}
	for {
		err := putSyncNotes(t, rec, vaultID, f.notes)
		if !errors.Is(err, errSyncNotesFull) {
			return err
		}
		if !evictOldest(&f.notes) {
			if what == "" {
				what = "a settled note"
			}
			s.dropSyncNotes(fmt.Sprintf("sync-notes.json is full, so %s was not recorded", what))
			return nil
		}
	}
}

func (s *Store) dropSyncNotes(why string) {
	s.syncNotesDropped = append(s.syncNotesDropped, why)
	if len(s.syncNotesDropped) > maxSyncNotesPerKind {
		s.syncNotesDropped = s.syncNotesDropped[1:]
	}
}

// evictOldest removes the oldest ready note of a known kind and counts it.
func evictOldest(n *syncNotesJSON) bool {
	for i, r := range n.Ready {
		if knownNoteKind(r.Note.Kind) {
			n.Ready = slices.Delete(n.Ready, i, i+1)
			n.Evicted[r.Note.Kind]++
			return true
		}
	}
	return false
}

// combinedNote is the note for a write res that rev 16 would have held, or
// nil.
func combinedNote(in merge.Intent, res merge.Result) (*syncNoteJSON, error) {
	if res.Kind != merge.KindWrite || res.Combined == nil {
		return nil, nil
	}
	body := combinedBody{
		ItemID: in.ItemID, Type: in.Type, Name: itemNameOf(res.Plaintext),
		Local: slices.Clone(res.Combined.Local), Remote: slices.Clone(res.Combined.Remote),
	}
	b, err := canonjson.Marshal(body)
	if err != nil {
		return nil, err
	}
	return &syncNoteJSON{Kind: NoteCombined, Body: b}, nil
}

func itemNameOf(it *merge.Item) string {
	if it == nil {
		return ""
	}
	raw, ok := it.Member("name")
	var name string
	if !ok || json.Unmarshal(raw, &name) != nil {
		return ""
	}
	return name
}

// journalSyncNote adds a pending note for the candidate (seq, h) of record
// n to t, the commit that journals the candidate.
func (s *Store) journalSyncNote(t *txn, rec *deviceRecord, vaultID model.ID, seq uint64, h crypto.Hash, n uint64, note syncNoteJSON) error {
	return s.updateSyncNotes(t, rec, vaultID, "a note of a combined change", func(x *syncNotesJSON) bool {
		x.Pending = append(x.Pending, pendingNoteJSON{Seq: seq, H: h, N: n, Note: note})
		return true
	})
}

// settleSyncNotes adds to t what verified history up to head decides for
// the pending notes: a note whose candidate is the verified entry at its
// seq is ready, any other at a seq ≤ head is dropped. It runs whether or
// not the outbox is empty. The caller holds s.mu and the file lock.
func (s *Store) settleSyncNotes(t *txn, head uint64, hashAt func(uint64) (crypto.Hash, error), rec *deviceRecord, vaultID model.ID) error {
	if _, err := os.Lstat(s.l.syncNotesFile()); errors.Is(err, os.ErrNotExist) {
		return nil
	} else if err != nil {
		return err
	}
	var herr error
	err := s.updateSyncNotes(t, rec, vaultID, "", func(n *syncNotesJSON) bool {
		changed := false
		kept := n.Pending[:0:0]
		for _, p := range n.Pending {
			if p.Seq > head {
				kept = append(kept, p)
				continue
			}
			changed = true
			h, err := hashAt(p.Seq)
			if err != nil {
				herr = err
				return false
			}
			if h.Equal(p.H) {
				addReady(n, p.Note)
			}
		}
		n.Pending = kept
		return changed
	})
	if herr != nil {
		return herr
	}
	return err
}

// addReady adds a ready note, evicting the oldest of its kind past the
// per-kind bound. Only kinds this build knows are bounded.
func addReady(n *syncNotesJSON, note syncNoteJSON) {
	n.Ready = append(n.Ready, readyNoteJSON{ID: n.Next, Note: note})
	n.Next++
	if !knownNoteKind(note.Kind) {
		return
	}
	count := 0
	for _, r := range n.Ready {
		if r.Note.Kind == note.Kind {
			count++
		}
	}
	for i := 0; count > maxSyncNotesPerKind && i < len(n.Ready); {
		if n.Ready[i].Note.Kind == note.Kind {
			n.Ready = slices.Delete(n.Ready, i, i+1)
			n.Evicted[note.Kind]++
			count--
			continue
		}
		i++
	}
}

// CombinedNote is a write that combined this device's change with another
// device's change to the same item, which rev 16 would have held for hop
// sync resolve: each member kept the change made to it. It names the item
// and the members, never a value.
type CombinedNote struct {
	ID     uint64
	ItemID model.ID
	Type   model.Type
	Name   string
	Local  []string // the members this device changed
	Remote []string // the members the other device changed
}

// SyncNotes are the ready sync notes, as one delivery to acknowledge.
type SyncNotes struct {
	Combined []CombinedNote
	// Evicted counts, per kind, the older notes dropped undelivered.
	Evicted map[string]uint64
	// Discarded: notes sealed under an earlier local_key of this device
	// were discarded.
	Discarded bool
	// Dropped says why notes could not be recorded (a newer file, the size
	// limit), once each.
	Dropped []string
}

// Empty reports whether n holds nothing to show.
func (n SyncNotes) Empty() bool {
	return len(n.Combined) == 0 && len(n.Evicted) == 0 && !n.Discarded && len(n.Dropped) == 0
}

// SyncNotes returns the ready notes of the kinds this build knows, with
// each known kind's eviction count. They stay until AckSyncNotes. The store
// must be unlocked.
func (s *Store) SyncNotes() (SyncNotes, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.state == nil || s.rec == nil {
		return SyncNotes{}, s.lockedErr()
	}
	unlock, err := s.lockFile()
	if err != nil {
		return SyncNotes{}, err
	}
	defer unlock()
	f, err := s.readSyncNotes(s.rec, s.state.VaultID)
	if err != nil {
		return SyncNotes{}, err
	}
	out := SyncNotes{Discarded: s.syncNotesDiscarded || f.obsolete, Dropped: slices.Clone(s.syncNotesDropped)}
	for k, c := range f.notes.Evicted {
		if knownNoteKind(k) && c > 0 {
			if out.Evicted == nil {
				out.Evicted = map[string]uint64{}
			}
			out.Evicted[k] = uint64(c)
		}
	}
	for _, r := range f.notes.Ready {
		if r.Note.Kind != NoteCombined {
			continue
		}
		c, _ := parseCombined(r.Note.Body)
		out.Combined = append(out.Combined, CombinedNote{ID: r.ID, ItemID: c.ItemID, Type: c.Type, Name: c.Name, Local: c.Local, Remote: c.Remote})
	}
	return out, nil
}

// AckSyncNotes records that d, which SyncNotes returned, was delivered: the
// notes whose IDs it holds go, and its eviction counts are taken off. A
// note it doesn't hold stays, whatever its ID, and so does every note of a
// kind this build doesn't know. An obsolete file goes.
func (s *Store) AckSyncNotes(d SyncNotes) error {
	if d.Empty() {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.state == nil || s.rec == nil {
		return s.lockedErr()
	}
	unlock, err := s.lockFile()
	if err != nil {
		return err
	}
	defer unlock()
	if d.Discarded {
		s.syncNotesDiscarded = false
	}
	if len(d.Dropped) > 0 {
		s.syncNotesDropped = slices.Delete(s.syncNotesDropped, 0, min(len(d.Dropped), len(s.syncNotesDropped)))
	}
	f, err := s.readSyncNotes(s.rec, s.state.VaultID)
	if err != nil || f.newer || !f.exists {
		return err
	}
	t := &txn{}
	if f.obsolete {
		t.remove(syncNotesRel)
		return s.commitTxn(t)
	}
	ids := map[uint64]bool{}
	for _, c := range d.Combined {
		ids[c.ID] = true
	}
	n := f.notes
	before := len(n.Ready)
	n.Ready = slices.DeleteFunc(n.Ready, func(r readyNoteJSON) bool { return ids[r.ID] && knownNoteKind(r.Note.Kind) })
	changed := len(n.Ready) != before
	for k, c := range d.Evicted {
		if have := uint64(n.Evicted[k]); have > 0 && c > 0 {
			n.Evicted[k] = u64s(have - min(have, c))
			if n.Evicted[k] == 0 {
				delete(n.Evicted, k)
			}
			changed = true
		}
	}
	if !changed {
		return nil
	}
	if err := putSyncNotes(t, s.rec, s.state.VaultID, n); err != nil {
		return err
	}
	return s.commitTxn(t)
}
