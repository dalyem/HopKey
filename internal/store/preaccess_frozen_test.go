package store

import (
	"context"
	"errors"
	"fmt"
	"os"
	"slices"
	"strings"
	"testing"

	"github.com/dalyem/hopkey/internal/model"
	"github.com/dalyem/hopkey/internal/vaultlog"
)

// The build before access, frozen, unlocking a cache: copies of its §5.2
// allowlist and its item_put check (bc30d59, internal/vaultlog/ops.go:
// 339-358), and of how its replay reads an entry from the cache
// (internal/store/files.go, readEntry). That build's replay reads every
// entry on disk with readEntry before it anchors (internal/store/store.go,
// replay), so an entry its decoder refuses stops the unlock there,
// whatever the rest of it would do.
//
// What this still shares with the current code, and why that holds:
// the cache is written by today's store; the decoder is today's
// vaultlog.ParseWire with the frozen check after it (between the two
// builds the public stage changed only in the allowlist); the rest of
// the unlock, once every entry decodes, is today's Unlock (store.go and
// files.go changed between them only for access items, which a cache the
// frozen build decodes doesn't hold). Do not change the copies to follow
// the current code: they stand for a build that is already out there
// (crypto spec rev 17, §5.3, §8.4 Compatibility). The narrower schema
// regression is internal/vaultlog/preaccess_frozen_test.go.

func preAccessIsItemType(t model.Type) bool {
	switch t {
	case model.TypeHost, model.TypeKey, model.TypeCredential, model.TypeSnippet, model.TypeGrant, model.TypePolicy:
		return true
	}
	return false
}

// preAccessParseWire is that build's decoder: today's, which differs only
// in the allowlist, then its item_put type check.
func preAccessParseWire(b []byte) (*vaultlog.Wire, error) {
	w, err := vaultlog.ParseWire(b)
	if err != nil {
		return nil, err
	}
	for _, o := range w.Entry.Ops {
		if p, ok := o.(*vaultlog.ItemPutOp); ok && !preAccessIsItemType(p.Type) {
			return nil, &vaultlog.RuleError{Rule: vaultlog.RuleSchema,
				Msg: fmt.Sprintf("%s: type %q: this vault uses an item type from a newer hop (%s); upgrade hop on this device", p.Op, p.Type, p.Type)}
		}
	}
	return w, nil
}

// preAccessReadEntry is that build's readEntry.
func preAccessReadEntry(l layout, seq uint64) (*vaultlog.Wire, error) {
	b, err := os.ReadFile(l.entryFile(seq))
	if err != nil {
		return nil, err
	}
	w, err := preAccessParseWire(b)
	if err != nil {
		return nil, fmt.Errorf("%w: entry %d: %v", ErrCorrupt, seq, err)
	}
	if w.Entry.Seq != seq {
		return nil, fmt.Errorf("%w: %s holds seq %d", ErrCorrupt, l.entryFile(seq), w.Entry.Seq)
	}
	return w, nil
}

// preAccessUnlock unlocks s, locked, as that build would: every entry of
// the cache through its readEntry, as its replay starts, then today's
// unlock.
func preAccessUnlock(s *Store) error {
	s.mu.Lock()
	seqs, err := s.l.entrySeqs()
	if err == nil {
		for _, seq := range seqs {
			if _, err = preAccessReadEntry(s.l, seq); err != nil {
				break
			}
		}
	}
	s.mu.Unlock()
	if err != nil {
		return err
	}
	return s.Unlock(context.Background())
}

// A vault cache with an access entry in it: the build before access
// can't unlock it, and says to upgrade; the same cache without the access
// entry unlocks.
func TestFrozenPreAccessBuildCantUnlockACacheWithAccess(t *testing.T) {
	// The only type the two builds disagree on is access.
	frozen := slices.DeleteFunc(vaultlog.ItemTypes(), func(x model.Type) bool { return !preAccessIsItemType(x) })
	if want := slices.DeleteFunc(vaultlog.ItemTypes(), func(x model.Type) bool { return x == model.TypeAccess }); !slices.Equal(frozen, want) {
		t.Fatalf("the frozen allowlist %v, today's without access %v", frozen, want)
	}
	t.Run("control: no access entry", func(t *testing.T) {
		f := newVault(t, testConfig(t))
		_, host := addHost(t, f.s, "web")
		s := open(t, f.cfg)
		s.Lock()
		if err := preAccessUnlock(s); err != nil {
			t.Fatalf("the frozen build can't unlock a cache with no access entry: %v", err)
		}
		if snap := snapshot(t, s); !slices.ContainsFunc(snap.Hosts, func(h model.Host) bool { return h.ItemID == host.ItemID }) {
			t.Fatalf("unlocked without the host: %+v", snap.Hosts)
		}
	})
	t.Run("an access entry", func(t *testing.T) {
		f := newVault(t, testConfig(t))
		_, host := addHost(t, f.s, "web")
		newAccess(t, f.s, host.ItemID, model.AccessPending)
		s := open(t, f.cfg)
		// Today's build unlocks it.
		if snap := snapshot(t, s); len(snap.Access) != 1 {
			t.Fatalf("today's build: %d access records", len(snap.Access))
		}
		s.Lock()
		err := preAccessUnlock(s)
		if !errors.Is(err, ErrCorrupt) || !strings.Contains(err.Error(), "schema") || !strings.Contains(err.Error(), `"access"`) ||
			!strings.Contains(err.Error(), "upgrade hop on this device") {
			t.Fatalf("the frozen build's unlock: %v", err)
		}
		if _, err := s.Snapshot(context.Background()); !errors.Is(err, model.ErrLocked) {
			t.Fatalf("the vault after the refused unlock: %v", err)
		}
	})
}
