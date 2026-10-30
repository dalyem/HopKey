package store

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"

	"github.com/dalyem/hopkey/internal/canonjson"
	"github.com/dalyem/hopkey/internal/model"
)

// Predecessors: what a logout leaves in the data directory so that the
// next sign-in can say what became of the identity it replaced (A2b
// option E, Q15). A device the server's operator blocked gets back in by
// logging out and signing in as a new device; the old identity may still
// be in the account (a --local-only logout never told the server), and
// the queued changes it held are gone. Nothing here runs by itself: the
// next sign-in only prints the commands.
//
//	vault/retire-note.json = JCS({"v":1, "server":s, "email":s, "queued":n, "held":n, "why":""|"device_blocked"|"account_disabled"})
//	predecessor.json       = JCS({"v":1, "entries":[{"account_id":id, "device_id":id, "server":s, "email":s,
//	                              "outcome":"committed"|"departed"|"unknown", "queued":n, "held":n, "why":..., "at":ts}]})
//
// The note is written in the same commit as the retirement journal, so
// the journal never exists without it. The cleanup of a RETIRED logout
// moves it into predecessor.json, in the data directory beside
// device.json, before it deletes anything, so a crash anywhere in the
// cleanup still leaves the record. A logout records an entry when the
// server was not told (--local-only) or when the device was locked by the
// operator's refusal (LogoutOptions.Why); an ordinary logout leaves none.
// Both files are plain: they hold what device.json and server.json
// already hold, and counts.

const (
	retireNoteRel      = "retire-note.json"
	predecessorName    = "predecessor.json"
	predecessorVersion = 1
	retireNoteVersion  = 1
	// maxPredecessors bounds the entries kept: the newest win.
	maxPredecessors = 8
)

// retireNote is vault/retire-note.json.
type retireNote struct {
	V      int    `json:"v"`
	Server string `json:"server"`
	Email  string `json:"email"`
	Queued int    `json:"queued"`
	Held   int    `json:"held"`
	Why    string `json:"why,optional"`
}

// Predecessor is a device identity that a logout on this machine left
// behind. Outcome is the logout's: OutcomeCommitted or OutcomeDeparted
// (the device left the account) or OutcomeUnknown (the server was not
// told: the device may still be in the account). Queued and Held are the
// changes the logout discarded, the held ones among them. Why is
// AdminDeviceBlocked or AdminAccountDisabled when the operator's refusal
// had locked the device, and "" otherwise.
type Predecessor struct {
	AccountID model.ID        `json:"account_id"`
	DeviceID  model.ID        `json:"device_id"`
	Server    string          `json:"server"`
	Email     string          `json:"email"`
	Outcome   string          `json:"outcome"`
	Queued    int             `json:"queued"`
	Held      int             `json:"held"`
	Why       string          `json:"why,optional"`
	At        model.Timestamp `json:"at"`
}

type predecessorFile struct {
	V       int           `json:"v"`
	Entries []Predecessor `json:"entries"`
}

func predecessorPath(dataDir string) string { return filepath.Join(dataDir, predecessorName) }

// ReadPredecessors reads the predecessor record in dataDir, oldest entry
// first. No record is no entries. One that does not parse fails with
// ErrCorrupt.
func ReadPredecessors(dataDir string) ([]Predecessor, error) {
	b, err := os.ReadFile(predecessorPath(dataDir))
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var f predecessorFile
	if err := canonjson.Unmarshal(b, &f); err != nil || f.V != predecessorVersion {
		return nil, fmt.Errorf("%w: %s does not parse", ErrCorrupt, predecessorPath(dataDir))
	}
	return f.Entries, nil
}

func writePredecessors(dataDir string, entries []Predecessor) error {
	if len(entries) == 0 {
		if err := os.Remove(predecessorPath(dataDir)); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
		return syncDir(dataDir)
	}
	if len(entries) > maxPredecessors {
		entries = entries[len(entries)-maxPredecessors:]
	}
	b, err := canonjson.Marshal(predecessorFile{V: predecessorVersion, Entries: entries})
	if err != nil {
		return err
	}
	return writeFileAtomic(predecessorPath(dataDir), b)
}

// recordPredecessor adds p, replacing an entry for the same device. A
// record that does not parse is replaced: it must not keep a logout from
// finishing.
func recordPredecessor(dataDir string, p Predecessor) error {
	entries, err := ReadPredecessors(dataDir)
	if err != nil && !errors.Is(err, ErrCorrupt) {
		return err
	}
	entries = slices.DeleteFunc(entries, func(e Predecessor) bool { return e.AccountID == p.AccountID && e.DeviceID == p.DeviceID })
	return writePredecessors(dataDir, append(entries, p))
}

// ForgetPredecessor removes the entry for device id, once the old
// identity is settled (it is revoked, or no longer in the account). An
// entry that is not there is no error.
func ForgetPredecessor(dataDir string, id model.ID) error {
	entries, err := ReadPredecessors(dataDir)
	if errors.Is(err, ErrCorrupt) {
		return writePredecessors(dataDir, nil)
	}
	if err != nil {
		return err
	}
	kept := slices.DeleteFunc(slices.Clone(entries), func(e Predecessor) bool { return e.DeviceID == id })
	if len(kept) == len(entries) {
		return nil
	}
	return writePredecessors(dataDir, kept)
}

func knownWhy(why string) string {
	if why == AdminDeviceBlocked || why == AdminAccountDisabled {
		return why
	}
	return ""
}

// putRetireNote adds the note to t, the commit that journals the logout.
func putRetireNote(t *txn, n retireNote) error {
	n.V = retireNoteVersion
	b, err := canonjson.Marshal(n)
	if err != nil {
		return err
	}
	t.put(retireNoteRel, b)
	return nil
}

// newRetireNote describes the logout for the record: the server and the
// account's email from server.json, and what the logout discards. The
// caller holds the file lock.
func (s *Store) newRetireNote(why string, pc PendingChanges) retireNote {
	n := retireNote{Queued: pc.Queued, Held: pc.Held, Why: knownWhy(why)}
	if f, err := s.l.readServerFile(); err == nil && f != nil {
		n.Server, n.Email = f.Server, f.Email
	}
	return n
}

// readRetireNote reads vault/retire-note.json, or nil when there is none
// or it does not parse: a note that can't be read must not keep a logout
// from finishing. The caller holds the file lock.
func (s *Store) readRetireNote() *retireNote {
	b, err := os.ReadFile(filepath.Join(s.l.vault(), retireNoteRel))
	if err != nil {
		return nil
	}
	var n retireNote
	if canonjson.Unmarshal(b, &n) != nil || n.V != retireNoteVersion {
		return nil
	}
	n.Why = knownWhy(n.Why)
	return &n
}

// recordLogoutPredecessor moves the note of RETIRED logout j into
// predecessor.json, if the logout earns one: the server was not told, or
// the operator's refusal had locked the device. It is idempotent, and
// does nothing once the note is gone (an earlier attempt of the cleanup
// got past it). The caller holds the file lock.
func (s *Store) recordLogoutPredecessor(j *retireJournal) error {
	n := s.readRetireNote()
	if n == nil || (j.Outcome != OutcomeUnknown && n.Why == "") {
		return nil
	}
	return recordPredecessor(s.l.data, Predecessor{
		AccountID: j.AccountID, DeviceID: j.DeviceID, Server: n.Server, Email: n.Email,
		Outcome: j.Outcome, Queued: n.Queued, Held: n.Held, Why: n.Why, At: s.now(),
	})
}

// PendingChanges counts what a logout would discard: the changes queued
// in the outbox, and among them the held ones (§5.4: a conflict waiting
// for the user).
type PendingChanges struct {
	Queued int `json:"queued"`
	Held   int `json:"held,omitempty"`
	// HeldKnown is false while the vault is locked: the files give the
	// count of the queue, but only the unlocked store can tell which of
	// them are held.
	HeldKnown bool `json:"-"`
}

// PendingChanges counts the changes queued here that have not reached the
// server. It works while the vault is locked.
func (s *Store) PendingChanges() (PendingChanges, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.owner == nil {
		return PendingChanges{}, ErrClosed
	}
	unlock, err := s.lockFile()
	if err != nil {
		return PendingChanges{}, err
	}
	defer unlock()
	return s.pendingLocked()
}

// pendingLocked is PendingChanges. The caller holds s.mu and the file
// lock.
func (s *Store) pendingLocked() (PendingChanges, error) {
	ns, err := s.l.outboxNumbers()
	if err != nil {
		return PendingChanges{}, err
	}
	pc := PendingChanges{Queued: len(ns)}
	if len(ns) == 0 {
		pc.HeldKnown = true
		return pc, nil
	}
	if s.state == nil || s.rec == nil {
		return pc, nil
	}
	recs, err := s.readOutbox()
	if err != nil {
		return pc, nil // the count of the queue stands; which are held is unknown
	}
	pc.HeldKnown = true
	for _, r := range recs {
		if r.Held {
			pc.Held++
		}
	}
	return pc, nil
}
