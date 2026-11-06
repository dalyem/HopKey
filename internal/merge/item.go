// Package merge implements the rebase rule of crypto spec §5.4
// (https://plan.23d.dev/p/xuu5z9q2) as pure functions: Rebuild merges an
// intended change against the current verified state, the resolution
// functions turn a held change into its replacement, and the digests bind a
// user's confirmation to exactly what will be written.
//
// Nothing here reads a file, a clock or the network. The caller supplies the
// verified state S, whether the item is live or retired in it, and the §5.3
// validation of the candidate post-state (see CheckCandidate).
package merge

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strconv"

	"github.com/dalyem/hopkey/internal/canonjson"
	"github.com/dalyem/hopkey/internal/model"
)

// ErrGrant is returned for an item of type grant. Grants are never merged:
// an edit made directly to a grant is a grant command and never queues
// (§11.1).
var ErrGrant = errors.New("merge: grant items are not merged")

// The four header members of every item plaintext (§6.5). They are ignored
// by every comparison and always come from the candidate state.
var headerMembers = [...]string{"v", "item_id", "type", "item_version"}

func isHeader(member string) bool {
	return slices.Contains(headerMembers[:], member)
}

// IsFree reports whether member of an item of type t merges on its own
// (§5.4): description for a host or snippet, nothing for a key or
// credential. Every other member, including a header member, is not free.
func IsFree(t model.Type, member string) bool {
	switch t {
	case model.TypeHost, model.TypeSnippet:
		return member == "description"
	}
	return false
}

// IsGuarded reports whether member belongs to the item's single guarded
// group: any non-header member that is neither free nor a system member.
func IsGuarded(t model.Type, member string) bool {
	return !isHeader(member) && !IsFree(t, member) && !IsSystem(t, member)
}

func validType(t model.Type) error {
	switch t {
	case model.TypeHost, model.TypeKey, model.TypeCredential, model.TypeSnippet, model.TypePolicy, model.TypeAccess:
		return nil
	case model.TypeGrant:
		return ErrGrant
	}
	return fmt.Errorf("merge: unknown item type %q", string(t))
}

// Item is one item plaintext (host, key, credential or snippet) kept as the
// canonical JSON of each member. Members are compared as canonical JSON,
// so a list is compared whole and formatting never matters. An Item is
// immutable; every method that changes something returns a new Item.
type Item struct {
	typ     model.Type
	id      model.ID
	members map[string]canonjson.Raw // every member, header included
	plain   canonjson.Raw            // the whole object in canonical form
}

// ParseItem reads an item plaintext. It checks the header (v is 1, item_id
// is a non-zero ID, type is host, key, credential or snippet, item_version
// is a u64s) but not the per-type schema, which is §5.3's job.
func ParseItem(plaintext []byte) (*Item, error) {
	canon, err := canonjson.Canonicalize(plaintext)
	if err != nil {
		return nil, fmt.Errorf("merge: item plaintext: %w", err)
	}
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(canon, &raw); err != nil || raw == nil {
		return nil, errors.New("merge: item plaintext is not a JSON object")
	}
	members := make(map[string]canonjson.Raw, len(raw))
	for k, v := range raw {
		members[k] = canonjson.Raw(slices.Clone([]byte(v)))
	}
	return newItem(members)
}

// ItemOf encodes a model.Host, Key, Credential or Snippet (or a pointer to
// one). Any other value, including a model.Grant, is refused.
func ItemOf(v any) (*Item, error) {
	switch x := v.(type) {
	case model.Host, *model.Host, model.Key, *model.Key,
		model.Credential, *model.Credential, model.Snippet, *model.Snippet, model.Policy, *model.Policy,
		model.Access, *model.Access:
		j, err := canonjson.Marshal(x)
		if err != nil {
			return nil, fmt.Errorf("merge: %w", err)
		}
		return ParseItem(j)
	case model.Grant, *model.Grant:
		return nil, ErrGrant
	}
	return nil, fmt.Errorf("merge: %T is not an item type", v)
}

// newItem checks the header of members and builds the Item. It takes
// ownership of members.
func newItem(members map[string]canonjson.Raw) (*Item, error) {
	var (
		v       int
		typ     model.Type
		idText  string
		version string
	)
	for _, h := range []struct {
		name string
		into any
	}{{"v", &v}, {"item_id", &idText}, {"type", &typ}, {"item_version", &version}} {
		m, ok := members[h.name]
		if !ok {
			return nil, fmt.Errorf("merge: item has no %s member", h.name)
		}
		if err := json.Unmarshal(m, h.into); err != nil {
			return nil, fmt.Errorf("merge: item %s member is the wrong type", h.name)
		}
	}
	if v != 1 {
		return nil, fmt.Errorf("merge: item v is %d, want 1", v)
	}
	if err := validType(typ); err != nil {
		return nil, err
	}
	id, err := model.ParseID(idText)
	if err != nil {
		return nil, fmt.Errorf("merge: item_id: %w", err)
	}
	if id.IsZero() {
		return nil, errors.New("merge: item_id is the zero ID")
	}
	if n, err := strconv.ParseUint(version, 10, 64); err != nil || strconv.FormatUint(n, 10) != version {
		return nil, errors.New("merge: item_version is not a u64s")
	}
	plain, err := canonjson.Marshal(members)
	if err != nil {
		return nil, fmt.Errorf("merge: %w", err)
	}
	return &Item{typ: typ, id: id, members: members, plain: plain}, nil
}

// Type returns the item's type.
func (it *Item) Type() model.Type { return it.typ }

// ID returns the item's ID.
func (it *Item) ID() model.ID { return it.id }

// Plaintext returns the item as canonical JSON.
func (it *Item) Plaintext() []byte { return slices.Clone(it.plain) }

// Member returns the canonical JSON of one member.
func (it *Item) Member(name string) (canonjson.Raw, bool) {
	m, ok := it.members[name]
	return slices.Clone(m), ok
}

// Decode reads the item into a model.Host, Key, Credential or Snippet.
func (it *Item) Decode(v any) error { return canonjson.Unmarshal(it.plain, v) }

// Equal reports whether it and o agree on every non-header member. Both
// must be non-nil.
func (it *Item) Equal(o *Item) bool { return len(diff(it, o)) == 0 }

// with returns a copy with the given members replaced. A nil value removes
// the member.
func (it *Item) with(set map[string]canonjson.Raw) (*Item, error) {
	members := cloneMembers(it.members)
	for k, v := range set {
		if v == nil {
			delete(members, k)
		} else {
			members[k] = v
		}
	}
	return newItem(members)
}

// withHeaderOf returns a copy of it whose header members come from base.
func (it *Item) withHeaderOf(base *Item) (*Item, error) {
	set := make(map[string]canonjson.Raw, len(headerMembers))
	for _, h := range headerMembers {
		set[h] = base.members[h]
	}
	return it.with(set)
}

func cloneMembers(m map[string]canonjson.Raw) map[string]canonjson.Raw {
	out := make(map[string]canonjson.Raw, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}

// rawString encodes s, which must be valid UTF-8 (every caller passes a
// constant or an ID).
func rawString(s string) canonjson.Raw {
	j, err := canonjson.Marshal(s)
	if err != nil {
		panic(err)
	}
	return j
}

// names returns the sorted non-header member names of the given items.
func names(items ...*Item) []string {
	seen := map[string]bool{}
	for _, it := range items {
		if it == nil {
			continue
		}
		for k := range it.members {
			if !isHeader(k) {
				seen[k] = true
			}
		}
	}
	out := make([]string, 0, len(seen))
	for k := range seen {
		out = append(out, k)
	}
	slices.Sort(out)
	return out
}

// memberEqual compares one member of a and b as canonical JSON. A member
// that is absent differs from every present one.
func memberEqual(a, b *Item, name string) bool {
	x, okx := a.members[name]
	y, oky := b.members[name]
	return okx == oky && bytes.Equal(x, y)
}

// diff returns the sorted non-header members where a and b differ.
func diff(a, b *Item) []string {
	var out []string
	for _, n := range names(a, b) {
		if !memberEqual(a, b, n) {
			out = append(out, n)
		}
	}
	return out
}
