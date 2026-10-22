package store

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/dalyem/hopkey/internal/canonjson"
	"github.com/dalyem/hopkey/internal/crypto"
	"github.com/dalyem/hopkey/internal/safepath"
	"github.com/dalyem/hopkey/internal/vaultlog"
)

// DefaultDataDir is $XDG_DATA_HOME/hop when XDG_DATA_HOME is absolute, and
// ~/.local/share/hop otherwise.
func DefaultDataDir(home string, getenv func(string) string) string {
	if x := getenv("XDG_DATA_HOME"); filepath.IsAbs(x) {
		return filepath.Join(x, "hop")
	}
	return filepath.Join(home, ".local", "share", "hop")
}

// layout names the files under one data directory. Every directory is made
// with safepath (0700, safe ancestors) before use, and every file is 0600.
type layout struct {
	data string
}

func (l layout) deviceConfig() string  { return filepath.Join(l.data, "device.json") }
func (l layout) deviceKeyFile() string { return filepath.Join(l.data, "device.key") }
func (l layout) vault() string         { return filepath.Join(l.data, "vault") }
func (l layout) lockFile() string      { return filepath.Join(l.vault(), "lock") }
func (l layout) ownerLock() string     { return filepath.Join(l.vault(), "owner.lock") }
func (l layout) entries() string       { return filepath.Join(l.vault(), "entries") }
func (l layout) objects() string       { return filepath.Join(l.vault(), "objects") }
func (l layout) journal() string       { return filepath.Join(l.vault(), "journal") }
func (l layout) stateFile() string     { return filepath.Join(l.vault(), "state.json") }
func (l layout) accountFile() string   { return filepath.Join(l.vault(), "account.json") }

func (l layout) entryFile(seq uint64) string {
	return filepath.Join(l.entries(), strconv.FormatUint(seq, 10)+".json")
}

func (l layout) journalFile(seq uint64) string {
	return filepath.Join(l.journal(), strconv.FormatUint(seq, 10)+".json")
}

// ensureDirs makes the data directory and the vault's directories private,
// and replaces l.data with its resolved path.
func (l *layout) ensureDirs() error {
	data, err := safepath.EnsurePrivateDir(l.data)
	if err != nil {
		return err
	}
	l.data = data
	for _, d := range []string{l.vault(), l.entries(), l.objects(), l.journal(), l.outbox()} {
		if _, err := safepath.EnsurePrivateDir(d); err != nil {
			return err
		}
	}
	return nil
}

// exists reports whether a vault is here: any entry or a state file. An
// init that stopped before writing its genesis entry left nothing a vault
// needs, so init may run again over it.
func (l layout) exists() (bool, error) {
	for _, p := range []string{l.stateFile()} {
		if _, err := os.Lstat(p); err == nil {
			return true, nil
		} else if !errors.Is(err, os.ErrNotExist) {
			return false, err
		}
	}
	seqs, err := l.entrySeqs()
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return false, err
	}
	return len(seqs) > 0, nil
}

// entrySeqs lists the entries on disk in ascending seq order. A name that is
// not <decimal seq>.json is an error: nothing else belongs there.
func (l layout) entrySeqs() ([]uint64, error) {
	ents, err := os.ReadDir(l.entries())
	if err != nil {
		return nil, err
	}
	var seqs []uint64
	for _, e := range ents {
		name := e.Name()
		if strings.HasPrefix(name, ".tmp") {
			continue // an interrupted write; never linked into place
		}
		num, ok := strings.CutSuffix(name, ".json")
		seq, err := strconv.ParseUint(num, 10, 64)
		if !ok || err != nil || strconv.FormatUint(seq, 10) != num {
			return nil, fmt.Errorf("%w: unexpected file %s in %s", ErrCorrupt, name, l.entries())
		}
		seqs = append(seqs, seq)
	}
	sort.Slice(seqs, func(i, j int) bool { return seqs[i] < seqs[j] })
	return seqs, nil
}

// readEntry reads and strictly decodes entries/<seq>.json. The file holds
// the signed wire without its objects, which live in objects/.
func (l layout) readEntry(seq uint64) (*vaultlog.Wire, error) {
	b, err := os.ReadFile(l.entryFile(seq))
	if err != nil {
		return nil, err
	}
	w, err := vaultlog.ParseWire(b)
	if err != nil {
		return nil, fmt.Errorf("%w: entry %d: %v", ErrCorrupt, seq, err)
	}
	if w.Entry.Seq != seq {
		return nil, fmt.Errorf("%w: %s holds seq %d", ErrCorrupt, l.entryFile(seq), w.Entry.Seq)
	}
	return w, nil
}

// writeObjects stores every object of w under its digest. Objects are
// immutable: one that is already there is left alone, but only if its
// content still matches its name.
func (l layout) writeObjects(w *vaultlog.Wire) error {
	for _, o := range w.Objects {
		body, err := canonjson.Canonicalize(o.Body)
		if err != nil {
			return err
		}
		if d := crypto.SHA256(body); !d.Equal(o.SHA256) {
			return fmt.Errorf("store: object %v has digest %v", o.SHA256, d)
		}
		path := filepath.Join(l.objects(), o.SHA256.String())
		err = createExclusive(path, body)
		if errors.Is(err, os.ErrExist) {
			if _, err := (objectDir(l.objects())).FetchObject(o.SHA256); err != nil {
				return err
			}
			continue
		}
		if err != nil {
			return err
		}
	}
	return nil
}

// writeEntry writes the wire, without its objects, as entries/<seq>.json. It
// never replaces an entry: a second writer at the same seq gets os.ErrExist.
// The objects must already be on disk; the entry file is the commit point.
func (l layout) writeEntry(w *vaultlog.Wire) error {
	bare := *w
	bare.Objects = []vaultlog.Object{}
	b, err := bare.Marshal()
	if err != nil {
		return err
	}
	return createExclusive(l.entryFile(w.Entry.Seq), b)
}

func (l layout) writeState(s *vaultlog.State) error {
	b, err := s.Marshal()
	if err != nil {
		return err
	}
	return writeFileAtomic(l.stateFile(), b)
}

// objectDir is an ObjectFetcher over objects/. It checks every object it
// returns against its name, so a corrupt or swapped file fails closed here
// with ErrObjectDigest, before anything decrypts it.
type objectDir string

func (d objectDir) FetchObject(h crypto.Hash) ([]byte, error) {
	path := filepath.Join(string(d), h.String())
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	c, err := canonjson.Canonicalize(b)
	if err != nil {
		return nil, fmt.Errorf("%w: %s: %v", ErrObjectDigest, path, err)
	}
	if got := crypto.SHA256(c); !got.Equal(h) {
		return nil, fmt.Errorf("%w: %s has digest %v", ErrObjectDigest, path, got)
	}
	return b, nil
}

// writeFileAtomic replaces path with data: a temp file in the same
// directory, fsynced, renamed over path, then the directory fsynced.
func writeFileAtomic(path string, data []byte) error {
	tmp, err := writeTemp(path, data)
	if err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		os.Remove(tmp)
		return err
	}
	return syncDir(filepath.Dir(path))
}

// createExclusive writes data to path only if path does not exist yet, and
// returns an error wrapping os.ErrExist otherwise. The file appears whole or
// not at all (a hard link of a synced temp file).
func createExclusive(path string, data []byte) error {
	tmp, err := writeTemp(path, data)
	if err != nil {
		return err
	}
	defer os.Remove(tmp)
	if err := os.Link(tmp, path); err != nil {
		return err
	}
	return syncDir(filepath.Dir(path))
}

func writeTemp(path string, data []byte) (string, error) {
	f, err := os.CreateTemp(filepath.Dir(path), ".tmp*")
	if err != nil {
		return "", err
	}
	name := f.Name()
	fail := func(err error) (string, error) {
		f.Close()
		os.Remove(name)
		return "", err
	}
	if err := f.Chmod(0o600); err != nil {
		return fail(err)
	}
	if _, err := f.Write(data); err != nil {
		return fail(err)
	}
	if err := f.Sync(); err != nil {
		return fail(err)
	}
	if err := f.Close(); err != nil {
		os.Remove(name)
		return "", err
	}
	return name, nil
}

// syncDir fsyncs a directory. It is a variable so tests can make it fail.
var syncDir = fsyncDir

func fsyncDir(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	if err := d.Sync(); err != nil && !errors.Is(err, os.ErrInvalid) {
		return err
	}
	return nil
}
