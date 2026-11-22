package store

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"

	"github.com/dalyem/hopkey/internal/canonjson"
	"github.com/dalyem/hopkey/internal/crypto"
	"github.com/dalyem/hopkey/internal/model"
)

// The notes of replaced edits (Replacement) of a server-backed vault, one
// file:
//
//	vault/replaced.json  JCS({"v":1, "vault_id":id, "sealed":AEAD(local_key, notes, aad)})
//
// with
//
//	notes = JCS({"v":1, "next":u64s, "evicted":u64s,
//	             "notes":[{"n":u64s, "item_id":id, "type":type, "name":string, "fields":[member, ...]}]})
//	aad   = lp("hopkey/v1/replaced") || lp(vault_id)
//
// A note is written in the commit that deletes the outbox record of the
// candidate it describes (settle), so a crash keeps both or neither, and
// it stays until the daemon has delivered it: Replacements reads the notes
// and AckReplacements removes the ones read. Nothing else removes one, so
// a command that settles a candidate (an auth command's pull, say) leaves
// its note for the daemon. A note names the item and the members, never a
// value, and all of it is sealed. At most maxReplaced are kept: one more
// drops the oldest, and evicted counts what was dropped that way until
// it is acknowledged too. next numbers the notes, so an acknowledgement
// never removes one added after the read it answers.
//
// local_key is the outbox's, so whatever drops the outbox for an
// unreadable device record drops this file too (dropLostRecords).

const (
	labelReplaced   = "hopkey/v1/replaced"
	replacedRel     = "replaced.json"
	replacedVersion = 1
	// maxReplaced bounds the notes kept for the daemon.
	maxReplaced = 50
)

func (l layout) replacedFile() string { return filepath.Join(l.vault(), replacedRel) }

// replacedAAD is lp("hopkey/v1/replaced") || lp(vault_id_bytes).
func replacedAAD(vaultID model.ID) []byte {
	return append(crypto.LP([]byte(labelReplaced)), crypto.LP(vaultID[:])...)
}

// replacedFileJSON is vault/replaced.json.
type replacedFileJSON struct {
	V       int                 `json:"v"`
	VaultID model.ID            `json:"vault_id"`
	Sealed  crypto.AEADEnvelope `json:"sealed"`
}

// noteJSON is one sealed note.
type noteJSON struct {
	N      uint64     `json:"n,string"`
	ItemID model.ID   `json:"item_id"`
	Type   model.Type `json:"type"`
	Name   string     `json:"name"`
	Fields []string   `json:"fields"`
}

// notesJSON is the plaintext of replaced.json's sealed member.
type notesJSON struct {
	V       int        `json:"v"`
	Next    uint64     `json:"next,string"`
	Evicted uint64     `json:"evicted,string"`
	Notes   []noteJSON `json:"notes"`
}

// Replacements are the notes of replaced edits waiting for the daemon.
type Replacements struct {
	// Notes are the notes, oldest first. Each one's N is its number.
	Notes []Replacement
	// Evicted is how many older notes were dropped, undelivered, to keep
	// at most maxReplaced.
	Evicted uint64
}

// readNotes opens replaced.json with rec's local_key, for vault vaultID.
// A missing file is no notes. Anything else that fails is ErrCorrupt: only
// hop writes this file. The caller holds the file lock.
func (s *Store) readNotes(rec *deviceRecord, vaultID model.ID) (notesJSON, error) {
	n := notesJSON{V: replacedVersion, Next: 1, Notes: []noteJSON{}}
	b, err := os.ReadFile(s.l.replacedFile())
	if errors.Is(err, os.ErrNotExist) {
		return n, nil
	}
	if err != nil {
		return n, err
	}
	bad := fmt.Errorf("%w: %s does not open", ErrCorrupt, s.l.replacedFile())
	var f replacedFileJSON
	if err := canonjson.Unmarshal(b, &f); err != nil || f.V != replacedVersion || f.VaultID != vaultID {
		return n, bad
	}
	key, err := rec.localKey()
	if err != nil {
		return n, err
	}
	defer key.Zero()
	pt, err := crypto.OpenAEAD(key, f.Sealed, replacedAAD(vaultID))
	if err != nil {
		return n, bad
	}
	err = canonjson.Unmarshal(pt, &n)
	clear(pt)
	if err != nil || n.V != replacedVersion || n.Next == 0 {
		return n, bad
	}
	for _, x := range n.Notes {
		if x.N == 0 || x.N >= n.Next || len(x.Fields) == 0 {
			return n, bad
		}
	}
	return n, nil
}

// putNotes adds replaced.json, holding n, to t.
func putNotes(t *txn, rec *deviceRecord, vaultID model.ID, n notesJSON) error {
	pt, err := canonjson.Marshal(n)
	if err != nil {
		return err
	}
	key, err := rec.localKey()
	if err != nil {
		return err
	}
	defer key.Zero()
	env, err := crypto.SealAEAD(key, pt, replacedAAD(vaultID))
	clear(pt)
	if err != nil {
		return err
	}
	b, err := canonjson.Marshal(replacedFileJSON{V: replacedVersion, VaultID: vaultID, Sealed: env})
	if err != nil {
		return err
	}
	t.put(replacedRel, b)
	return nil
}

// addNotes adds to t the notes of rs, after the ones already kept, the
// newest maxReplaced of them. The caller holds the file lock.
func (s *Store) addNotes(t *txn, rec *deviceRecord, vaultID model.ID, rs []Replacement) error {
	if len(rs) == 0 {
		return nil
	}
	n, err := s.readNotes(rec, vaultID)
	if err != nil {
		return err
	}
	for _, r := range rs {
		n.Notes = append(n.Notes, noteJSON{N: n.Next, ItemID: r.ItemID, Type: r.Type, Name: r.Name, Fields: slices.Clone(r.Fields)})
		n.Next++
	}
	if over := len(n.Notes) - maxReplaced; over > 0 {
		n.Notes = slices.Clone(n.Notes[over:])
		n.Evicted += uint64(over)
	}
	return putNotes(t, rec, vaultID, n)
}

// Replacements returns the notes of what this device's committed changes
// replaced of other devices' values (Replacement), as verified history
// settled them: whichever pull or push found the candidate committed, in
// this process or another, and whether its post's answer was lost or the
// candidate was posted again after a restart. They stay until
// AckReplacements. The store must be unlocked.
func (s *Store) Replacements() (Replacements, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.state == nil || s.rec == nil {
		return Replacements{}, s.lockedErr()
	}
	unlock, err := s.lockFile()
	if err != nil {
		return Replacements{}, err
	}
	defer unlock()
	n, err := s.readNotes(s.rec, s.state.VaultID)
	if err != nil {
		return Replacements{}, err
	}
	out := Replacements{Evicted: n.Evicted}
	for _, x := range n.Notes {
		out.Notes = append(out.Notes, Replacement{N: x.N, ItemID: x.ItemID, Type: x.Type, Name: x.Name, Fields: x.Fields})
	}
	return out, nil
}

// AckReplacements records that r, which Replacements returned, has been
// delivered: its notes go, and its Evicted is taken off the count. A note
// added since stays.
func (s *Store) AckReplacements(r Replacements) error {
	if len(r.Notes) == 0 && r.Evicted == 0 {
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
	n, err := s.readNotes(s.rec, s.state.VaultID)
	if err != nil {
		return err
	}
	var upTo uint64
	for _, x := range r.Notes {
		upTo = max(upTo, x.N)
	}
	before, evicted := len(n.Notes), n.Evicted
	n.Notes = slices.DeleteFunc(n.Notes, func(x noteJSON) bool { return x.N <= upTo })
	n.Evicted -= min(n.Evicted, r.Evicted)
	if len(n.Notes) == before && n.Evicted == evicted {
		return nil
	}
	t := &txn{}
	if err := putNotes(t, s.rec, s.state.VaultID, n); err != nil {
		return err
	}
	return s.commitTxn(t)
}
