package merge

import (
	"encoding/json"
	"errors"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/dalyem/hopkey/internal/canonjson"
	"github.com/dalyem/hopkey/internal/model"
)

// The vectors of crypto spec rev 17 amendment §8.1. Host members a vector
// doesn't mention are equal in all three versions. The base host has name
// "web", aliases [], tags ["prod","old"], addresses ["old.example"], port
// 22, user "deploy", agent_access "deny", and no agent_output.

func base17(h *model.Host) {
	h.Name, h.Aliases, h.Tags = "web", []string{}, []string{"prod", "old"}
	h.Addresses, h.Port, h.User = []string{"old.example"}, 22, "deploy"
	h.AgentAccess, h.AgentOutput = "deny", ""
	h.CredentialID = model.ID{}
	h.Description = ""
}

func aliases(a ...string) hostMod  { return func(h *model.Host) { h.Aliases = a } }
func port(p uint32) hostMod        { return func(h *model.Host) { h.Port = p } }
func hostKeys(a ...string) hostMod { return func(h *model.Host) { h.HostKeys = a } }
func access(s string) hostMod      { return func(h *model.Host) { h.AgentAccess = s } }
func output(s string) hostMod      { return func(h *model.Host) { h.AgentOutput = s } }

// h17 is the §8.1 base host at version ver with mods applied.
func h17(t testing.TB, ver uint64, mods ...hostMod) *Item {
	t.Helper()
	return host(t, ver, append([]hostMod{base17}, mods...)...)
}

// conflictIDs names each conflict as kind:name, in order.
func conflictIDs(cs []Conflict) []string {
	var out []string
	for _, c := range cs {
		out = append(out, string(c.Kind)+":"+c.Name)
	}
	return out
}

func TestRev17Vectors(t *testing.T) {
	type mods []hostMod
	const (
		k1 = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIKey1"
		k2 = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIKey2"
	)
	tests := []struct {
		id         string
		seen, want mods // on the base
		s          mods
		// A hold: the conflicts, as kind:name, in order.
		conflicts []string
		// A write: the result's mods on seen, and the combined note.
		result         mods
		combinedLocal  []string
		combinedRemote []string
	}{
		{id: "U1", want: mods{hostKeys(k2)}, s: mods{addrs("new.example")}, conflicts: []string{"unit:connection"}},
		{id: "U2", want: mods{port(2222)}, s: mods{user("root")}, conflicts: []string{"unit:connection"}},
		{
			id: "U3", want: mods{tags("prod")}, s: mods{addrs("new.example")},
			result: mods{tags("prod"), addrs("new.example")}, combinedLocal: []string{"tags"}, combinedRemote: []string{"addresses"},
		},
		{
			id: "U4", want: mods{name("web-1")}, s: mods{tags("prod", "old", "db")},
			result: mods{name("web-1"), tags("prod", "old", "db")}, combinedLocal: []string{"name"}, combinedRemote: []string{"tags"},
		},
		{
			id: "K1", want: mods{tags("prod")}, s: mods{tags("prod", "old", "db")},
			result: mods{tags("db", "prod")}, combinedLocal: []string{"tags"}, combinedRemote: []string{"tags"},
		},
		{id: "K2", want: mods{tags("old")}, s: mods{tags("Prod", "old")}, conflicts: []string{"class:tags"}},
		{id: "K3", seen: mods{aliases("db.")}, want: mods{aliases("DB")}, s: mods{aliases(" db")}, conflicts: []string{"class:aliases"}},
		{id: "K4", want: mods{tags("old", "prod")}, s: mods{tags("old", "prod")}, result: mods{tags("old", "prod")}},
		{id: "K5", seen: mods{tags("s")}, want: mods{tags()}, s: mods{tags("ſ")}, conflicts: []string{"class:tags"}},
		{
			id: "K6", want: mods{tags("prod", "old", "x")}, s: mods{tags("prod", "old", "K")},
			result: mods{tags("K", "old", "prod", "x")}, combinedLocal: []string{"tags"}, combinedRemote: []string{"tags"},
		},
		{id: "C1", want: mods{aliases("test-db")}, s: mods{addrs("new.example")}, conflicts: []string{"coupling:selector-added"}},
		{
			id: "C2", want: mods{tags("prod")}, s: mods{port(2200)},
			result: mods{tags("prod"), port(2200)}, combinedLocal: []string{"tags"}, combinedRemote: []string{"port"},
		},
		{
			id: "C3", want: mods{name("Web")}, s: mods{port(2200)},
			result: mods{name("Web"), port(2200)}, combinedLocal: []string{"name"}, combinedRemote: []string{"port"},
		},
		{id: "C4", want: mods{access("allow")}, s: mods{user("root")}, conflicts: []string{"coupling:agent-widening"}},
		{
			// Both made the same address change, and S also has a new
			// description: rev 16 writes, and so must rev 17 (the L*/R* fix).
			id: "C5", want: mods{aliases("a"), addrs("new.example")}, s: mods{aliases("a"), addrs("new.example"), hostDesc("x")},
			result: mods{aliases("a"), addrs("new.example"), hostDesc("x")},
		},
		{id: "C6", want: mods{output("full")}, s: mods{addrs("new.example")}, conflicts: []string{"coupling:agent-widening"}},
		{
			id: "C7", want: mods{output("none")}, s: mods{addrs("new.example")},
			result: mods{output("none"), addrs("new.example")}, combinedLocal: []string{"agent_output"}, combinedRemote: []string{"addresses"},
		},
		{
			id: "C8", want: mods{access("allow")}, s: mods{tags("prod", "old", "db")},
			result: mods{access("allow"), tags("prod", "old", "db")}, combinedLocal: []string{"agent_access"}, combinedRemote: []string{"tags"},
		},
		{id: "C9", seen: mods{output("none")}, want: mods{access("allow")}, s: mods{output("full")}, conflicts: []string{"unit:agent"}},
		{
			id: "C10", seen: mods{output("full")}, want: mods{access("allow"), output("none")}, s: mods{addrs("new.example")},
			conflicts: []string{"coupling:agent-widening"},
		},
		{
			// R1's hold: the unit conflict, and S's new tag class db, added
			// while this device changed host_keys.
			id: "R1", want: mods{hostKeys(k2), tags("prod")}, s: mods{addrs("new.example"), tags("prod", "old", "db")},
			conflicts: []string{"unit:connection", "coupling:selector-added"},
		},
		{id: "R5", want: mods{tags("old", "db")}, s: mods{tags("Prod", "old", "ci")}, conflicts: []string{"class:tags"}},
		{id: "host_keys", seen: mods{hostKeys(k1)}, want: mods{hostKeys(k2)}, s: mods{hostKeys(k1), tags("prod")},
			result: mods{hostKeys(k2), tags("prod")}, combinedLocal: []string{"host_keys"}, combinedRemote: []string{"tags"}},
	}
	for _, tc := range tests {
		t.Run(tc.id, func(t *testing.T) {
			seen := h17(t, verSeen, tc.seen...)
			want := h17(t, verWant, append(slices.Clone(tc.seen), tc.want...)...)
			s := h17(t, verS, append(slices.Clone(tc.seen), tc.s...)...)
			res := Rebuild(put(seen, want), s, true, false)
			old := frozenRev16Put(put(seen, want), s)
			if tc.conflicts != nil {
				if res.Kind != KindHold || res.Cause != CauseGuardedConflict {
					t.Fatalf("got %s/%s %v, want a guarded hold", res.Kind, res.Cause, res.Err)
				}
				if got := conflictIDs(res.Conflicts); !slices.Equal(got, tc.conflicts) {
					t.Errorf("conflicts %v, want %v", got, tc.conflicts)
				}
				if old.Kind != KindHold {
					t.Errorf("rev 17 holds where rev 16 writes")
				}
				return
			}
			if res.Kind != KindWrite || res.Action != ActionPut {
				t.Fatalf("got %s/%s %v %v, want a put write", res.Kind, res.Cause, conflictIDs(res.Conflicts), res.Err)
			}
			samePlain(t, res.Plaintext, h17(t, verS, append(slices.Clone(tc.seen), tc.result...)...))
			if tc.combinedLocal == nil {
				if res.Combined != nil {
					t.Errorf("combined note %+v, want none", res.Combined)
				}
				if old.Kind != KindWrite {
					t.Fatal("rev 16 holds but no combined note")
				}
				samePlain(t, res.Plaintext, old.Plaintext)
				return
			}
			if old.Kind != KindHold {
				t.Errorf("a combined note for a change rev 16 writes")
			}
			if res.Combined == nil || !slices.Equal(res.Combined.Local, tc.combinedLocal) || !slices.Equal(res.Combined.Remote, tc.combinedRemote) {
				t.Errorf("combined %+v, want local %v remote %v", res.Combined, tc.combinedLocal, tc.combinedRemote)
			}
		})
	}
}

// K4 also pins S's bytes: both sides made the same reorder, and the result
// is S's list as it is, not re-sorted.
func TestRev17IdenticalReorderKeepsBytes(t *testing.T) {
	seen := h17(t, 1)
	want := h17(t, 2, tags("old", "prod"))
	s := h17(t, 3, tags("old", "prod"))
	res := Rebuild(put(seen, want), s, true, false)
	if res.Kind != KindWrite {
		t.Fatalf("got %s/%s", res.Kind, res.Cause)
	}
	if got, _ := res.Plaintext.Member("tags"); string(got) != `["old","prod"]` {
		t.Errorf("tags %s", got)
	}
}

func TestRev17HostDeleteAndOtherTypes(t *testing.T) {
	// D1: a delete holds on any remote change, a description included.
	if res := Rebuild(del(h17(t, 1)), h17(t, 2, hostDesc("changed")), true, false); res.Kind != KindHold || res.Cause != CauseDeleteChanged {
		t.Errorf("D1: got %s/%s", res.Kind, res.Cause)
	}
	// P1: a snippet's name and command are one unit.
	sseen := snippet(t, 1, nil)
	swant := snippet(t, 2, func(s *model.Snippet) { s.Name = "status" })
	ss := snippet(t, 3, func(s *model.Snippet) { s.Command = "systemctl status {{unit}}" })
	if res := Rebuild(put(sseen, swant), ss, true, false); res.Kind != KindHold || !slices.Equal(conflictIDs(res.Conflicts), []string{"unit:executable"}) {
		t.Errorf("P1: got %s/%s %v", res.Kind, res.Cause, conflictIDs(res.Conflicts))
	}
	// P2: policy holds as in rev 16.
	pol := func(ver, max uint64) *Item {
		it, err := ItemOf(model.Policy{Header: model.Header{V: 1, ItemID: mustID(t, idHost2), Type: model.TypePolicy, ItemVersion: ver}, MaxOffline: max})
		if err != nil {
			t.Fatal(err)
		}
		return it
	}
	if res := Rebuild(put(pol(1, 0), pol(2, 3600)), pol(3, 7200), true, false); res.Kind != KindHold || !slices.Equal(conflictIDs(res.Conflicts), []string{"unit:policy"}) {
		t.Errorf("P2: got %s/%s %v", res.Kind, res.Cause, conflictIDs(res.Conflicts))
	}
}

// withMember returns it with member m set to the JSON v (nil removes it).
func withMember(t testing.TB, it *Item, m string, v any) *Item {
	t.Helper()
	var raw canonjson.Raw
	if v != nil {
		var err error
		if raw, err = canonjson.Marshal(v); err != nil {
			t.Fatal(err)
		}
	}
	out, err := it.with(map[string]canonjson.Raw{m: raw})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// F1: a change to a member the tables don't list decides the item by the
// rev 16 rule, for every pairing, and offers no proposal.
func TestRev17UnclassifiedFallsBack(t *testing.T) {
	pairs := []struct {
		name       string
		want, s    []hostMod
		wantFuture string // the injected member's value in want and/or S
		sFuture    string
	}{
		{"local unclassified, remote tags", nil, []hostMod{tags("prod", "old", "db")}, "x", ""},
		{"local tags, remote unclassified", []hostMod{tags("prod")}, nil, "", "y"},
		{"local unclassified, remote connection", nil, []hostMod{addrs("new.example")}, "x", ""},
		{"both unclassified, equal", nil, nil, "x", "x"},
		{"both unclassified, different", nil, nil, "x", "y"},
		{"local unclassified, remote description", nil, []hostMod{hostDesc("r")}, "x", ""},
	}
	for _, p := range pairs {
		t.Run(p.name, func(t *testing.T) {
			seen := withMember(t, h17(t, 1), "future", "base")
			want := h17(t, 2, p.want...)
			s := h17(t, 3, p.s...)
			for _, x := range []struct {
				it  **Item
				val string
			}{{&want, p.wantFuture}, {&s, p.sFuture}} {
				v := x.val
				if v == "" {
					v = "base"
				}
				*x.it = withMember(t, *x.it, "future", v)
			}
			in := put(seen, want)
			got, old := Rebuild(in, s, true, false), frozenRev16Put(in, s)
			if got.Kind != old.Kind || got.Cause != old.Cause || !slices.Equal(got.Local, old.Local) || !slices.Equal(got.Remote, old.Remote) ||
				!slices.Equal(got.Replaced, old.Replaced) || got.Combined != nil || len(got.Conflicts) != 0 {
				t.Fatalf("rev 17 %+v, rev 16 %+v", got, old)
			}
			if got.Kind == KindWrite {
				samePlain(t, got.Plaintext, old.Plaintext)
				return
			}
			if _, err := KeepMineMerge(in, got.Cause, s); !isRefusal(err) {
				t.Errorf("keep mine --merge: %v, want a refusal", err)
			}
			if _, err := TakeTheirsMerge(in, got.Cause, s); !isRefusal(err) {
				t.Errorf("take theirs --merge: %v, want a refusal", err)
			}
		})
	}
}

func isRefusal(err error) bool {
	var r *RefusalError
	return err != nil && errors.As(err, &r)
}

// jsonMembers lists the JSON member names of a model struct, the header's
// left out.
func jsonMembers(t reflect.Type) []string {
	var out []string
	for i := range t.NumField() {
		f := t.Field(i)
		if f.Anonymous {
			continue
		}
		name, _, _ := strings.Cut(f.Tag.Get("json"), ",")
		out = append(out, name)
	}
	return out
}

// The classification tables must give every member of every item type
// exactly one kind, and every atomic member exactly one unit.
func TestClassificationIsComplete(t *testing.T) {
	for typ, v := range map[model.Type]any{
		model.TypeHost: model.Host{}, model.TypeSnippet: model.Snippet{}, model.TypeKey: model.Key{},
		model.TypeCredential: model.Credential{}, model.TypePolicy: model.Policy{},
	} {
		cl := classifications[typ]
		if cl == nil {
			t.Errorf("%s has no classification", typ)
			continue
		}
		members := jsonMembers(reflect.TypeOf(v))
		for _, m := range members {
			kinds := 0
			if slices.Contains(cl.free, m) {
				kinds++
				if !IsFree(typ, m) {
					t.Errorf("%s.%s is free here but not in rev 16", typ, m)
				}
			} else if IsFree(typ, m) {
				t.Errorf("%s.%s is free in rev 16 but not here", typ, m)
			}
			if cl.sets[m] != nil {
				kinds++
			}
			units := 0
			for _, u := range cl.units {
				if slices.Contains(u.members, m) {
					units++
				}
			}
			if units > 1 {
				t.Errorf("%s.%s is in %d units", typ, m, units)
			}
			if units > 0 {
				kinds++
			}
			if kinds != 1 {
				t.Errorf("%s.%s has %d kinds", typ, m, kinds)
			}
		}
		// Nothing the tables list is missing from the type.
		listed := slices.Clone(cl.free)
		for m := range cl.sets {
			listed = append(listed, m)
		}
		for _, u := range cl.units {
			listed = append(listed, u.members...)
		}
		for _, m := range listed {
			if !slices.Contains(members, m) {
				t.Errorf("%s classifies %s, which it doesn't have", typ, m)
			}
		}
	}
	if len(jsonMembers(reflect.TypeOf(model.Host{}))) != 15 {
		t.Error("host has a member count the spec doesn't know")
	}
	if _, ok := classifications[model.TypeGrant]; ok {
		t.Error("grants are never merged")
	}
}

// K_tag is EqualFold, and K_alias is host lookup's normalisation.
func TestSelectorKeys(t *testing.T) {
	words := []string{"s", "S", "ſ", "k", "K", "K", "prod", "Prod", "PROD", "ǅ", "ǆ", "Ǆ", "ß", "ẞ", "σ", "ς", "Σ", "db", "db.", " db", "ﬀ", "ff", "İ", "i", "ı", "I"}
	for _, a := range words {
		for _, b := range words {
			if (model.TagKey(a) == model.TagKey(b)) != strings.EqualFold(a, b) {
				t.Errorf("TagKey(%q)=%q, TagKey(%q)=%q, EqualFold %v", a, model.TagKey(a), b, model.TagKey(b), strings.EqualFold(a, b))
			}
		}
	}
	if model.TagKey("ſ") != model.TagKey("s") || strings.ToLower("ſ") == strings.ToLower("s") {
		t.Error("ſ and s are the same tag, and ToLower doesn't say so")
	}
	for _, c := range []struct{ in, out string }{{"DB.", "db"}, {" db ", "db"}, {"db..", "db."}, {"Web", "web"}} {
		if got := model.NameKey(c.in); got != c.out {
			t.Errorf("NameKey(%q) = %q, want %q", c.in, got, c.out)
		}
	}
}

func TestClassMerge(t *testing.T) {
	for _, tc := range []struct {
		name               string
		base, mine, theirs []string
		result, raced      []string
	}{
		{"each side's class", []string{"a"}, []string{"a", "b"}, []string{"a", "c"}, []string{"a", "b", "c"}, nil},
		{"removal and addition", []string{"a", "b"}, []string{"a"}, []string{"a", "b", "c"}, []string{"a", "c"}, nil},
		{"same respelling", []string{"prod"}, []string{"Prod"}, []string{"Prod"}, []string{"Prod"}, nil},
		{"removal races a respelling", []string{"prod"}, []string{}, []string{"Prod"}, nil, []string{"PROD"}},
		{"two respellings race", []string{"prod"}, []string{"PROD"}, []string{"Prod"}, nil, []string{"PROD"}},
		{"duplicates collapse", []string{}, []string{"x", "x"}, []string{"y"}, []string{"x", "y"}, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			res, raced := classMerge(model.TagKey, tc.base, tc.mine, tc.theirs)
			if !slices.Equal(res, tc.result) || !slices.Equal(raced, tc.raced) {
				t.Errorf("got %q raced %q, want %q raced %q", res, raced, tc.result, tc.raced)
			}
		})
	}
}

// A conflict carries no values; ConflictSpellings derives the strings a
// class conflict or a selector-added coupling is about from the three
// versions, whichever side fired it.
func TestConflictSpellings(t *testing.T) {
	const k2 = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIKey2"
	type mods []hostMod
	for _, tc := range []struct {
		id            string
		seen, want, s mods
		// conflict kind:name -> its spellings
		spellings map[string][]string
	}{
		{id: "class", want: mods{tags("PROD", "old")}, s: mods{tags("Prod", "old")},
			spellings: map[string][]string{"class:tags": {"PROD", "Prod", "prod"}}},
		{id: "local selector-added", want: mods{aliases("test-db")}, s: mods{addrs("new.example")},
			spellings: map[string][]string{"coupling:selector-added": {"test-db"}}},
		{id: "remote selector-added", want: mods{hostKeys(k2), tags("prod")}, s: mods{addrs("new.example"), tags("prod", "old", "DB", "db")},
			spellings: map[string][]string{"coupling:selector-added": {"DB", "db"}, "unit:connection": nil}},
		{id: "unit", want: mods{port(2222)}, s: mods{user("root")},
			spellings: map[string][]string{"unit:connection": nil}},
		{id: "agent widening", want: mods{port(2222)}, s: mods{output("full")},
			spellings: map[string][]string{"coupling:agent-widening": nil}},
	} {
		t.Run(tc.id, func(t *testing.T) {
			seen, want, s := h17(t, 3, tc.seen...), h17(t, 3, append(tc.seen, tc.want...)...), h17(t, 4, append(tc.seen, tc.s...)...)
			res := Rebuild(put(seen, want), s, true, false)
			if res.Kind != KindHold || len(res.Conflicts) != len(tc.spellings) {
				t.Fatalf("got %s/%s %v", res.Kind, res.Cause, conflictIDs(res.Conflicts))
			}
			for _, c := range res.Conflicts {
				exp, ok := tc.spellings[string(c.Kind)+":"+c.Name]
				if !ok {
					t.Fatalf("unexpected conflict %s:%s", c.Kind, c.Name)
				}
				if got := ConflictSpellings(model.TypeHost, seen, want, s, c); !slices.Equal(got, exp) {
					t.Errorf("%s:%s spellings %q, want %q", c.Kind, c.Name, got, exp)
				}
			}
		})
	}
	// Once the versions no longer show the conflict, there is nothing to
	// spell, and a missing version is not an error.
	seen, s := h17(t, 3), h17(t, 4, tags("Prod", "old"))
	c := Conflict{Kind: ConflictClass, Name: "tags", Local: []string{"tags"}, Remote: []string{"tags"}}
	if got := ConflictSpellings(model.TypeHost, seen, seen, s, c); got != nil {
		t.Errorf("no race: %q", got)
	}
	if got := ConflictSpellings(model.TypeHost, seen, nil, s, c); got != nil {
		t.Errorf("no want: %q", got)
	}
}

func memberJSON(t testing.TB, it *Item, m string) string {
	t.Helper()
	raw, ok := it.Member(m)
	if !ok {
		return "absent"
	}
	return string(raw)
}

// The proposals' member bytes (R1-R5, C9) and their digests, the existing
// Edit digest over the computed edit.
func TestRev17Proposals(t *testing.T) {
	const k2 = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIKey2"
	type mods []hostMod
	tests := []struct {
		id            string
		seen, want, s mods
		// member -> JCS bytes in P_mine and P_theirs
		mine, theirs map[string]string
		// "" or the refusal expected of keep mine --merge / take theirs --merge
		mineRefused, theirsRefused string
	}{
		{
			// The spec's R1 lists P_mine tags [db,prod]. S's db is a new tag
			// class added while this device changed host_keys, which fires
			// selector-added, so db is a conflict class and P_mine takes
			// mine's spellings of it: none (§2.5, §2.11).
			id: "R1", want: mods{hostKeys(k2), tags("prod")}, s: mods{addrs("new.example"), tags("prod", "old", "db")},
			mine:   map[string]string{"host_keys": `["` + k2 + `"]`, "addresses": `["old.example"]`, "tags": `["prod"]`},
			theirs: map[string]string{"host_keys": `[]`, "addresses": `["new.example"]`, "tags": `["db","prod"]`},
		},
		{
			id: "R2", want: mods{aliases("test-db")}, s: mods{addrs("new.example")},
			mine:   map[string]string{"aliases": `["test-db"]`, "addresses": `["old.example"]`},
			theirs: map[string]string{"aliases": `[]`, "addresses": `["new.example"]`},
			// Plain keep mine writes aliases [test-db] on new.example; P_mine
			// keeps old.example, so it differs. P_theirs is S.
			theirsRefused: "nothing to merge",
		},
		{
			id: "R3", seen: mods{aliases("z", "a")}, want: mods{aliases("z", "a", "x")}, s: mods{addrs("new.example")},
			mine:          map[string]string{"addresses": `["old.example"]`, "aliases": `["z","a","x"]`},
			theirs:        map[string]string{"addresses": `["new.example"]`, "aliases": `["z","a"]`},
			theirsRefused: "nothing to merge",
		},
		{
			id: "R4", seen: mods{aliases("z", "a")}, want: mods{aliases("x", "z", "a")}, s: mods{addrs("new.example")},
			mine:          map[string]string{"aliases": `["x","z","a"]`},
			theirs:        map[string]string{"aliases": `["z","a"]`},
			theirsRefused: "nothing to merge",
		},
		{
			id: "R5", want: mods{tags("old", "db")}, s: mods{tags("Prod", "old", "ci")},
			mine:   map[string]string{"tags": `["ci","db","old"]`},
			theirs: map[string]string{"tags": `["ci","db","old","Prod"]`},
		},
		{
			// Plain keep mine replaces only agent_access, so on S it writes
			// allow/full, the combination the unit exists to stop; P_mine is
			// the whole unit as mine.
			id: "C9", seen: mods{output("none")}, want: mods{access("allow")}, s: mods{output("full")},
			mine:          map[string]string{"agent_access": `"allow"`, "agent_output": `"none"`},
			theirs:        map[string]string{"agent_access": `"deny"`, "agent_output": `"full"`},
			theirsRefused: "nothing to merge",
		},
	}
	for _, tc := range tests {
		t.Run(tc.id, func(t *testing.T) {
			seen := h17(t, 1, tc.seen...)
			want := h17(t, 2, append(slices.Clone(tc.seen), tc.want...)...)
			s := h17(t, 5, append(slices.Clone(tc.seen), tc.s...)...)
			in := put(seen, want)
			res := Rebuild(in, s, true, false)
			if res.Kind != KindHold || res.Cause != CauseGuardedConflict {
				t.Fatalf("got %s/%s", res.Kind, res.Cause)
			}
			pm, pt, ok, err := proposals(in, s)
			if err != nil || !ok {
				t.Fatalf("proposals: %v %v", ok, err)
			}
			for m, w := range tc.mine {
				if got := memberJSON(t, pm, m); got != w {
					t.Errorf("P_mine %s = %s, want %s", m, got, w)
				}
			}
			for m, w := range tc.theirs {
				if got := memberJSON(t, pt, m); got != w {
					t.Errorf("P_theirs %s = %s, want %s", m, got, w)
				}
			}
			// Both keep S's header.
			for _, p := range []*Item{pm, pt} {
				for _, h := range headerMembers {
					if !memberEqual(p, s, h) {
						t.Errorf("proposal %s is not S's", h)
					}
				}
			}
			for _, c := range []struct {
				name    string
				f       func(Intent, Cause, *Item) (Intent, error)
				p       *Item
				refused string
			}{{"keep mine --merge", KeepMineMerge, pm, tc.mineRefused}, {"take theirs --merge", TakeTheirsMerge, pt, tc.theirsRefused}} {
				repl, err := c.f(in, res.Cause, s)
				if c.refused != "" {
					if !isRefusal(err) || !strings.Contains(err.Error(), c.refused) {
						t.Errorf("%s: %v, want a refusal %q", c.name, err, c.refused)
					}
					continue
				}
				if err != nil {
					t.Fatalf("%s: %v", c.name, err)
				}
				sameIntent(t, repl, Intent{Action: ActionPut, ItemID: in.ItemID, Type: in.Type, Seen: s, Want: c.p})
				// The digest is the existing Edit digest of the computed edit,
				// computed here by hand.
				got, err := ResolveDigest(9, repl)
				if err != nil {
					t.Fatal(err)
				}
				msg := `{"action":"put","n":"9","seen":` + string(s.Plaintext()) + `,"want":` + string(c.p.Plaintext()) + `}`
				if w := d(LabelResolve, msg); got.String() != w {
					t.Errorf("%s digest %s, want %s", c.name, got, w)
				}
			}
		})
	}
}

// A proposal exists only for a put held on a unit, class or coupling
// conflict, and only while S is live.
func TestRev17ProposalRefusals(t *testing.T) {
	seen, want := h17(t, 1), h17(t, 2, aliases("test-db"))
	s := h17(t, 3, addrs("new.example"))
	in := put(seen, want)
	if _, err := KeepMineMerge(in, CauseGuardedConflict, nil); !isRefusal(err) {
		t.Errorf("S not live: %v", err)
	}
	if _, err := KeepMineMerge(in, CauseRuleFailure, s); !isRefusal(err) {
		t.Errorf("rule failure: %v", err)
	}
	if _, err := TakeTheirsMerge(del(seen), CauseDeleteChanged, s); !isRefusal(err) {
		t.Errorf("delete: %v", err)
	}
	// A hold that would apply now has no conflict, so no proposal.
	if _, err := KeepMineMerge(put(seen, want), CauseGuardedConflict, h17(t, 3, tags("prod"))); !isRefusal(err) {
		t.Errorf("no conflict: %v", err)
	}
	// The member bytes don't parse as JSON here only if something is very
	// wrong; keep the encoder honest anyway.
	var list []string
	if err := json.Unmarshal(encodeList(nil), &list); err != nil || list == nil {
		t.Errorf("encodeList(nil) = %s", encodeList(nil))
	}
}
