package vaultlog

import (
	"slices"
	"strings"
	"testing"

	"github.com/dalyem/hopkey/internal/crypto"
	"github.com/dalyem/hopkey/internal/model"
)

// The build before access, frozen: its §5.2 allowlist and its item_put
// check, copied from bc30d59 (internal/vaultlog/ops.go:339-358). Between
// that build and this one, the public stage changed only in the
// allowlist, so today's decoder with these copies is that build's public
// stage. This is the narrower schema regression; the unlock of a cache
// with an access entry in it, through that build's readEntry, is
// internal/store/preaccess_frozen_test.go. Do not change them to follow the current code: they stand for a build that
// is already out there (crypto spec rev 17, §5.3, §8.4 Compatibility).

func frozenPreAccessIsItemType(t model.Type) bool {
	switch t {
	case model.TypeHost, model.TypeKey, model.TypeCredential, model.TypeSnippet, model.TypeGrant, model.TypePolicy:
		return true
	}
	return false
}

func frozenPreAccessValidateItemPut(o *ItemPutOp) error {
	if err := checkOpName(o, o.Op); err != nil {
		return err
	}
	if err := checkID(o.Op, "item_id", o.ItemID); err != nil {
		return err
	}
	if !frozenPreAccessIsItemType(o.Type) {
		return schemaFail(o.Op, "type %q: this vault uses an item type from a newer hop (%s); upgrade hop on this device", o.Type, o.Type)
	}
	return nil
}

// frozenPreAccessCheck is the frozen build's schema check of the ops of a
// wire it received or cached.
func frozenPreAccessCheck(w *Wire) error {
	for _, o := range w.Entry.Ops {
		if p, ok := o.(*ItemPutOp); ok {
			if err := frozenPreAccessValidateItemPut(p); err != nil {
				return err
			}
		}
	}
	return nil
}

// An entry that puts an access item, as this build writes it: this build
// accepts it, and the build before access stops on it with a schema
// violation that says to upgrade. Entries without one pass both.
func TestFrozenPreAccessBuildRefusesAccessEntries(t *testing.T) {
	// The only type the two builds disagree on is access.
	var frozen []model.Type
	for _, typ := range ItemTypes() {
		if frozenPreAccessIsItemType(typ) {
			frozen = append(frozen, typ)
		}
	}
	if want := slices.DeleteFunc(slices.Clone(ItemTypes()), func(x model.Type) bool { return x == model.TypeAccess }); !slices.Equal(frozen, want) {
		t.Fatalf("the frozen allowlist %v, today's without access %v", frozen, want)
	}

	w := newWorld(t).withItems()
	reparse := func(t *testing.T, wire *Wire) *Wire {
		t.Helper()
		b, err := wire.Marshal()
		if err != nil {
			t.Fatal(err)
		}
		got, err := ParseWire(b)
		if err != nil {
			t.Fatalf("this build refuses the entry: %v", err)
		}
		return got
	}
	t.Run("an access put", func(t *testing.T) {
		got := reparse(t, w.unverified(Changes{Put: []crypto.Item{accessItem(t)}}))
		if !slices.ContainsFunc(got.Entry.Ops, func(o Op) bool { p, ok := o.(*ItemPutOp); return ok && p.Type == model.TypeAccess }) {
			t.Fatal("the entry has no access put")
		}
		mustAccept(t, w.transition(got))
		err := frozenPreAccessCheck(got)
		if err == nil || RuleOf(err) != RuleSchema || !strings.Contains(err.Error(), `"access"`) || !strings.Contains(err.Error(), "upgrade hop on this device") {
			t.Fatalf("the frozen build: %v (rule %q)", err, RuleOf(err))
		}
	})
	t.Run("no access put", func(t *testing.T) {
		got := reparse(t, w.unverified(Changes{Put: []crypto.Item{newSnippet(fixedID(0x64))}}))
		if err := frozenPreAccessCheck(got); err != nil {
			t.Fatalf("the frozen build refuses an entry with no access put: %v", err)
		}
	})
}
