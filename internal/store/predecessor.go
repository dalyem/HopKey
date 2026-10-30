package store

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"

	"github.com/dalyem/hopkey/internal/canonjson"
	"github.com/dalyem/hopkey/internal/filelock"
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
//	                              "outcome":"committed"|"departed"|"unknown", "queued":n, "held":n, "why":..., "reported":""|"revoke"|"rotate", "at":ts}]})
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
//
// The operator's refusal can also come to light after the logout began
// (no daemon was running to ask, or the first attempt went to a server
// that was not refusing): the retirement then records it in the note
// before the logout can finish. Every read-modify-write of
// predecessor.json runs under predecessor.lock in the data directory, so
// that a sign-in, a status and a logout in different processes never lose
// each other's entries. An entry carries "reported", the advice
// (revoke or rotate) a command has told the user about it; the commands
// that consume an entry (hop auth status) show the advice first when the
// one that applies now was never shown.

const (
	retireNoteRel      = "retire-note.json"
	predecessorName    = "predecessor.json"
	predecessorLock    = "predecessor.lock"
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
// had locked the device, and "" otherwise. Reported is the advice
// a command has shown the user about the identity (AdviceRevoke or
// AdviceRotate), and "" before any.
type Predecessor struct {
	AccountID model.ID        `json:"account_id"`
	DeviceID  model.ID        `json:"device_id"`
	Server    string          `json:"server"`
	Email     string          `json:"email"`
	Outcome   string          `json:"outcome"`
	Queued    int             `json:"queued"`
	Held      int             `json:"held"`
	Why       string          `json:"why,optional"`
	Reported  string          `json:"reported,optional"`
	At        model.Timestamp `json:"at"`
}

// The advice a command can have shown for a predecessor, the values of
// Predecessor.Reported: AdviceRevoke while the identity is still in the
// account (revoke it from a trusted device), AdviceRotate when it is out
// of the account but the lock it was under warrants new keys. An entry
// written by a build that recorded "yes" matches neither, so the advice
// is shown once more.
const (
	AdviceRevoke = "revoke"
	AdviceRotate = "rotate"
)

// predecessorRMWHook is a test seam: it runs between the read and the
// write of a read-modify-write of predecessor.json, with the lock held.
var predecessorRMWHook func()

// lockPredecessors takes the lock that serializes every read-modify-write
// of predecessor.json, across processes. It does not nest: a caller must
// not hold it already.
func lockPredecessors(dataDir string) (func(), error) {
	f, err := filelock.Lock(filepath.Join(dataDir, predecessorLock))
	if err != nil {
		return nil, err
	}
	return func() { f.Close() }, nil
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
	unlock, err := lockPredecessors(dataDir)
	if err != nil {
		return err
	}
	defer unlock()
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
	unlock, err := lockPredecessors(dataDir)
	if err != nil {
		return err
	}
	defer unlock()
	entries, err := ReadPredecessors(dataDir)
	if errors.Is(err, ErrCorrupt) {
		return writePredecessors(dataDir, nil)
	}
	if err != nil {
		return err
	}
	if predecessorRMWHook != nil {
		predecessorRMWHook()
	}
	kept := slices.DeleteFunc(slices.Clone(entries), func(e Predecessor) bool { return e.DeviceID == id })
	if len(kept) == len(entries) {
		return nil
	}
	return writePredecessors(dataDir, kept)
}

// MarkPredecessorReported records that the user has been shown advice
// (AdviceRevoke or AdviceRotate) about the entry for device id, in place
// of whatever was shown before. No advice, or an entry that is not
// there, is no error and no change.
func MarkPredecessorReported(dataDir string, id model.ID, advice string) error {
	if advice == "" {
		return nil
	}
	unlock, err := lockPredecessors(dataDir)
	if err != nil {
		return err
	}
	defer unlock()
	entries, err := ReadPredecessors(dataDir)
	if errors.Is(err, ErrCorrupt) {
		return writePredecessors(dataDir, nil)
	}
	if err != nil {
		return err
	}
	if predecessorRMWHook != nil {
		predecessorRMWHook()
	}
	changed := false
	for i := range entries {
		if entries[i].DeviceID == id && entries[i].Reported != advice {
			entries[i].Reported = advice
			changed = true
		}
	}
	if !changed {
		return nil
	}
	return writePredecessors(dataDir, entries)
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

// noteAdminRefusal records, in the note of the logout under way, that the
// server's operator refused this device (err matches ErrAdminRefused),
// when the note does not say so already. The refusal may be found after
// the logout began: with no daemon running, nothing could say it at the
// start. A note that is gone or unreadable is left alone. It is its own
// commit, durable before the retirement goes on, so that the cleanup moves
// it into predecessor.json whatever happens next. The caller holds s.mu.
func (s *Store) noteAdminRefusal(err error) error {
	var a *AdminRefusal
	if !errors.As(err, &a) || knownWhy(a.Code) == "" {
		return nil
	}
	unlock, err := s.lockFile()
	if err != nil {
		return err
	}
	defer unlock()
	n := s.readRetireNote()
	if n == nil || n.Why != "" {
		return nil
	}
	n.Why = a.Code
	if err := s.hook("retire:note"); err != nil {
		return err
	}
	t := &txn{}
	if err := putRetireNote(t, *n); err != nil {
		return err
	}
	return s.commitTxn(t)
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
	if err := s.hook("retire:predecessor"); err != nil {
		return err
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
