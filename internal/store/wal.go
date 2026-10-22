package store

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"strings"

	"github.com/dalyem/hopkey/internal/canonjson"
)

// The write-ahead journal (§11.1, "Transactions"). A commit that touches
// more than one file (advancing verified state together with deleting an
// outbox record, appending a record together with the outbox counter, and
// in D2 the publication and merge states) is written as one transaction:
//
//  1. vault/wal.json is written whole: a temporary file, fsynced, renamed
//     into place, the directory fsynced. That rename is the commit point.
//  2. Each operation is applied in order, each one durably.
//  3. vault/wal.json is removed and the directory fsynced.
//
// Every operation is idempotent, so a crash at any point after step 1 is
// finished by replaying the journal, which Unlock (and every other path
// that reads the vault's files) does before it reads anything. A crash
// before step 1 leaves the files as they were. There is one journal per
// vault and at most one transaction in it: the writer lock serializes
// commits, and a commit does not return until its journal is gone.
//
// Phase 1's commit order (objects, then the entry as the commit point,
// then state.json, repaired by the replay on unlock) is unchanged for
// local-only vaults, and the checkpoint journal keeps its own files.

// walVersion is the journal format.
const walVersion = 1

// Journal operations.
const (
	walPut    = "put"    // replace the file with data
	walCreate = "create" // create the file with data; an existing file must hold exactly data
	walDelete = "delete" // remove the file if it exists
)

// walOp is one operation. Path is relative to vault/ and slash-separated.
type walOp struct {
	Op   string `json:"op"`
	Path string `json:"path"`
	Data []byte `json:"data"`
}

type walFile struct {
	V   int     `json:"v"`
	Ops []walOp `json:"ops"`
}

// txn collects the operations of one atomic commit.
type txn struct {
	ops []walOp
}

func (t *txn) put(rel string, data []byte) {
	t.ops = append(t.ops, walOp{Op: walPut, Path: rel, Data: data})
}

func (t *txn) create(rel string, data []byte) {
	t.ops = append(t.ops, walOp{Op: walCreate, Path: rel, Data: data})
}

func (t *txn) remove(rel string) {
	t.ops = append(t.ops, walOp{Op: walDelete, Path: rel, Data: []byte{}})
}

func (t *txn) empty() bool { return len(t.ops) == 0 }

func (l layout) walFile() string { return filepath.Join(l.vault(), "wal.json") }

// walPath checks a journal path and returns it under vault/. Only plain
// files below vault/ that the store owns may be named: never the journal
// itself, the lock files or a temporary file.
func (l layout) walPath(rel string) (string, error) {
	clean := path.Clean(rel)
	if clean != rel || !filepath.IsLocal(filepath.FromSlash(rel)) || strings.Contains(rel, "\\") {
		return "", fmt.Errorf("%w: journal path %q", ErrCorrupt, rel)
	}
	switch base := path.Base(rel); {
	case rel == "wal.json", rel == "lock", rel == "owner.lock", strings.HasPrefix(base, ".tmp"):
		return "", fmt.Errorf("%w: journal path %q", ErrCorrupt, rel)
	}
	return filepath.Join(l.vault(), filepath.FromSlash(rel)), nil
}

// commitTxn writes t atomically (see above). The caller holds the file
// lock. If the journal is written but applying it fails, the store is
// locked: memory may no longer match the files, and the next unlock
// replays the journal.
func (s *Store) commitTxn(t *txn) error {
	if t.empty() {
		return nil
	}
	for _, op := range t.ops {
		if _, err := s.l.walPath(op.Path); err != nil {
			return err
		}
	}
	b, err := canonjson.Marshal(walFile{V: walVersion, Ops: t.ops})
	if err != nil {
		return err
	}
	if err := s.hook("wal:before"); err != nil {
		return err
	}
	if err := writeFileAtomic(s.l.walFile(), b); err != nil {
		return err
	}
	if err := s.applyWAL(t.ops); err != nil {
		s.dropLocked(fmt.Errorf("store: a commit was interrupted (%w); unlock to finish it", err))
		return err
	}
	return nil
}

// applyWAL applies the journaled operations and then removes the journal.
func (s *Store) applyWAL(ops []walOp) error {
	if err := s.hook("wal:written"); err != nil {
		return err
	}
	for i, op := range ops {
		if err := s.hook(fmt.Sprintf("wal:op:%d", i)); err != nil {
			return err
		}
		if err := s.l.applyOp(op); err != nil {
			return err
		}
	}
	if err := s.hook("wal:applied"); err != nil {
		return err
	}
	if err := os.Remove(s.l.walFile()); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return syncDir(s.l.vault())
}

func (l layout) applyOp(op walOp) error {
	p, err := l.walPath(op.Path)
	if err != nil {
		return err
	}
	switch op.Op {
	case walPut:
		return writeFileAtomic(p, op.Data)
	case walCreate:
		err := createExclusive(p, op.Data)
		if errors.Is(err, os.ErrExist) {
			// Written before a crash, or by an earlier replay. It must be
			// exactly this file: an entry is never replaced.
			old, rerr := os.ReadFile(p)
			if rerr != nil {
				return rerr
			}
			if !bytes.Equal(old, op.Data) {
				return fmt.Errorf("%w: %s differs from the journaled file", ErrCorrupt, op.Path)
			}
			return nil
		}
		return err
	case walDelete:
		if err := os.Remove(p); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
		return syncDir(filepath.Dir(p))
	}
	return fmt.Errorf("%w: journal operation %q", ErrCorrupt, op.Op)
}

// replayWAL finishes a transaction that a crash interrupted. It runs, under
// the file lock, before anything reads the vault's files. A journal that
// does not parse was not written by hop (it appears whole or not at all)
// and fails closed.
func (s *Store) replayWAL() error {
	b, err := os.ReadFile(s.l.walFile())
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	var w walFile
	if err := canonjson.Unmarshal(b, &w); err != nil || w.V != walVersion || len(w.Ops) == 0 {
		return fmt.Errorf("%w: %s does not parse", ErrCorrupt, s.l.walFile())
	}
	for _, op := range w.Ops {
		if _, err := s.l.walPath(op.Path); err != nil {
			return err
		}
	}
	return s.applyWAL(w.Ops)
}
