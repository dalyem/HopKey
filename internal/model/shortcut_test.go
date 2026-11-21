package model

import (
	"slices"
	"testing"
)

func sc(id byte, keys string, host ID) Shortcut {
	return Shortcut{Header: Header{ItemID: ID{id}}, Keys: keys, Command: "c" + keys, HostID: host}
}

func panelKeys(p []ShortcutInPanel) []string {
	var out []string
	for _, e := range p {
		k := e.Shortcut.Keys
		if !e.Shortcut.HostID.IsZero() {
			k = "h:" + k
		}
		out = append(out, k)
	}
	return out
}

// A host's panel is its own shortcuts, then the global ones that clash
// with none of them; the others' hosts' shortcuts are not in it.
func TestEffectiveShortcuts(t *testing.T) {
	web, db := ID{0xaa}, ID{0xbb}
	all := []Shortcut{
		sc(1, "u", ID{}), sc(2, "gl", ID{}), sc(3, "gs", ID{}), sc(4, "x", ID{}),
		sc(5, "g", web), sc(6, "u", web), sc(7, "d", db),
	}
	cases := []struct {
		host ID
		want []string
	}{
		{web, []string{"h:g", "h:u", "x"}},
		{db, []string{"h:d", "gl", "gs", "u", "x"}},
		{ID{}, []string{"gl", "gs", "u", "x"}},
	}
	for _, c := range cases {
		p := EffectiveShortcuts(all, c.host)
		if got := panelKeys(p); !slices.Equal(got, c.want) {
			t.Errorf("panel of %v: %v, want %v", c.host, got, c.want)
		}
	}
	p := EffectiveShortcuts(all, web)
	var hidden []string
	for _, h := range p[0].Hides {
		hidden = append(hidden, h.Keys)
	}
	if !slices.Equal(hidden, []string{"gl", "gs"}) {
		t.Errorf("web's g hides %v", hidden)
	}
}

// Two devices can each add a clashing shortcut of one scope; every device
// keeps the same one, by item ID, whatever order it reads them in.
func TestEffectiveShortcutsSameScopeClash(t *testing.T) {
	a, b, c := sc(2, "g", ID{}), sc(1, "gu", ID{}), sc(3, "gu", ID{})
	for _, order := range [][]Shortcut{{a, b, c}, {c, a, b}, {b, c, a}} {
		p := EffectiveShortcuts(order, ID{})
		if len(p) != 1 || p[0].Shortcut.ItemID != b.ItemID || len(p[0].Hides) != 2 {
			t.Fatalf("order %v: %+v", panelKeys(p), p)
		}
	}
}

func TestShortcutKeysClash(t *testing.T) {
	for _, c := range []struct {
		a, b  string
		clash bool
	}{{"g", "g", true}, {"g", "gu", true}, {"gu", "g", true}, {"gu", "gx", false}, {"g", "u", false}, {"ug", "g", false}} {
		if got := ShortcutKeysClash(c.a, c.b); got != c.clash {
			t.Errorf("%q %q: %v", c.a, c.b, got)
		}
	}
	for _, ok := range []string{"a", "Z", "!", "~", "gu", "1/"} {
		if err := CheckShortcutKeys(ok); err != nil {
			t.Errorf("%q: %v", ok, err)
		}
	}
	for _, bad := range []string{"", "abc", " ", "a ", "\t", "\x1b", "é"} {
		if CheckShortcutKeys(bad) == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}
