package vaultlog

import (
	"slices"
	"strings"
	"testing"

	"github.com/dalyem/hopkey/internal/canonjson"
	"github.com/dalyem/hopkey/internal/crypto"
	"github.com/dalyem/hopkey/internal/model"
)

// The build before shortcuts, frozen: v0.1.0-rc.4, the client on devices
// today. Its §5.2 allowlist and item_put check are copied from
// v0.1.0-rc.4:internal/vaultlog/ops.go:339-358, and its snippet plaintext
// from v0.1.0-rc.4:internal/model/model.go:161-167. Between that build and
// this one, the public stage changed only in the allowlist. Do not change
// the copies to follow the current code: they stand for a build that is
// already out there.
//
// They are the evidence for storing a shortcut as an item type of its own
// rather than as a snippet with more members. Either way rc.4 stops
// syncing on the first shortcut, and nothing is lost or rewritten: a
// rule violation halts sync (store.haltOn). The difference is what it
// says, and whether a server can refuse it first.

func frozenRC4IsItemType(t model.Type) bool {
	switch t {
	case model.TypeHost, model.TypeKey, model.TypeCredential, model.TypeSnippet, model.TypeGrant, model.TypePolicy, model.TypeAccess:
		return true
	}
	return false
}

func frozenRC4ValidateItemPut(o *ItemPutOp) error {
	if err := checkOpName(o, o.Op); err != nil {
		return err
	}
	if err := checkID(o.Op, "item_id", o.ItemID); err != nil {
		return err
	}
	if !frozenRC4IsItemType(o.Type) {
		return schemaFail(o.Op, "type %q: this vault uses an item type from a newer hop (%s); upgrade hop on this device", o.Type, o.Type)
	}
	return nil
}

type frozenRC4Snippet struct {
	model.Header
	Name        string   `json:"name"`
	Command     string   `json:"command"`
	Params      []string `json:"params"`
	Description string   `json:"description"`
}

// An entry that puts a shortcut: this build accepts it, and rc.4 stops on
// it in its public stage with a schema violation that names the type and
// says to upgrade, before it decrypts anything.
func TestFrozenRC4RefusesShortcutEntries(t *testing.T) {
	var frozen []model.Type
	for _, typ := range ItemTypes() {
		if frozenRC4IsItemType(typ) {
			frozen = append(frozen, typ)
		}
	}
	if want := slices.DeleteFunc(slices.Clone(ItemTypes()), func(x model.Type) bool { return x == model.TypeShortcut }); !slices.Equal(frozen, want) {
		t.Fatalf("the frozen allowlist %v, today's without shortcut %v", frozen, want)
	}
	w := newWorld(t).withItems()
	sc := &model.Shortcut{Header: model.Header{ItemID: fixedID(0x65), Type: model.TypeShortcut}, Keys: "u", Command: "uptime", Enter: true, HostID: idH1}
	b, err := w.unverified(Changes{Put: []crypto.Item{sc}}).Marshal()
	if err != nil {
		t.Fatal(err)
	}
	got, err := ParseWire(b)
	if err != nil {
		t.Fatalf("this build refuses the entry: %v", err)
	}
	mustAccept(t, w.transition(got))
	var refusal error
	for _, o := range got.Entry.Ops {
		if p, ok := o.(*ItemPutOp); ok {
			if err := frozenRC4ValidateItemPut(p); err != nil {
				refusal = err
			}
		}
	}
	if refusal == nil || RuleOf(refusal) != RuleSchema || !strings.Contains(refusal.Error(), `"shortcut"`) || !strings.Contains(refusal.Error(), "upgrade hop on this device") {
		t.Fatalf("rc.4: %v (rule %q)", refusal, RuleOf(refusal))
	}
}

// The alternative, a snippet with more members, is no better for rc.4:
// its closed schema refuses an unknown member, which reaches rc.4 as an
// item it cannot read (object.decrypt, "unknown member") rather than as a
// newer type, and the server, which sees only "snippet", cannot refuse it
// first. An absent optional member could not carry the binding either:
// rc.4's decoder still needs every member it knows, and nothing else.
func TestFrozenRC4RefusesUnknownSnippetMembers(t *testing.T) {
	plain, err := canonjson.Marshal(&frozenRC4Snippet{Header: model.Header{V: 1, ItemID: fixedID(0x66), Type: model.TypeSnippet, ItemVersion: 1},
		Name: "up", Command: "uptime", Params: []string{}})
	if err != nil {
		t.Fatal(err)
	}
	var plainOK frozenRC4Snippet
	if err := canonjson.Unmarshal(plain, &plainOK); err != nil {
		t.Fatalf("rc.4 refuses its own snippet: %v", err)
	}
	extended := strings.Replace(string(plain), `"command":`, `"keys":"u","command":`, 1)
	var sn frozenRC4Snippet
	err = canonjson.Unmarshal([]byte(extended), &sn)
	if err == nil || !strings.Contains(err.Error(), `unknown member "keys"`) {
		t.Fatalf("rc.4 read a snippet with a keys member: %v", err)
	}
}
