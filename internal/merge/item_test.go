package merge

import (
	"errors"
	"strings"
	"testing"

	"github.com/dalyem/hopkey/internal/canonjson"
	"github.com/dalyem/hopkey/internal/model"
)

const hostJSON = `{"v":1,"item_id":"` + idHost + `","type":"host","item_version":"3","name":"web",` +
	`"aliases":[],"addresses":["10.0.0.1"],"port":22,"user":"root","key_id":"","credential_id":"",` +
	`"jump_host_id":"","tags":[],"description":"","tailscale":null,"route":"auto","host_keys":[],"agent_access":"allow"}`

func TestParseItemCanonicalizes(t *testing.T) {
	a, err := ParseItem([]byte(hostJSON))
	if err != nil {
		t.Fatal(err)
	}
	// The same item with other member order, whitespace and escapes.
	reordered := `{ "type":"host", "v":1, "name":"web", "item_id":"` + idHost + `", "item_version":"3",
	  "route":"auto","agent_access":"allow","port":22,"user":"root","key_id":"","credential_id":"",
	  "jump_host_id":"","tags":[],"description":"","tailscale":null,"host_keys":[],"aliases":[],
	  "addresses":["10.0.0.1"] }`
	b, err := ParseItem([]byte(reordered))
	if err != nil {
		t.Fatal(err)
	}
	if string(a.Plaintext()) != string(b.Plaintext()) {
		t.Errorf("plaintexts differ\n %s\n %s", a.Plaintext(), b.Plaintext())
	}
	if !a.Equal(b) {
		t.Error("equal items compare unequal")
	}
	if a.Type() != model.TypeHost || a.ID() != mustID(t, idHost) {
		t.Errorf("header: %s %s", a.Type(), a.ID())
	}
	if !strings.HasPrefix(string(a.Plaintext()), `{"addresses":["10.0.0.1"],"agent_access":"allow",`) {
		t.Errorf("plaintext is not in JCS order: %s", a.Plaintext())
	}
}

func TestParseItemRejects(t *testing.T) {
	good := hostJSON
	repl := func(from, to string) string { return strings.Replace(good, from, to, 1) }
	for name, in := range map[string]string{
		"array":               `[]`,
		"null":                `null`,
		"string":              `"x"`,
		"empty":               ``,
		"trailing data":       good + ` {}`,
		"duplicate member":    repl(`"port":22`, `"port":22,"port":23`),
		"float":               repl(`"port":22`, `"port":22.5`),
		"no v":                repl(`"v":1,`, ``),
		"v is 2":              repl(`"v":1`, `"v":2`),
		"v is a string":       repl(`"v":1`, `"v":"1"`),
		"no item_id":          repl(`"item_id":"`+idHost+`",`, ``),
		"short item_id":       repl(idHost, `1111`),
		"upper-case item_id":  repl(idHost, strings.Repeat("A", 32)),
		"zero item_id":        repl(idHost, strings.Repeat("0", 32)),
		"empty item_id":       repl(idHost, ``),
		"no type":             repl(`"type":"host",`, ``),
		"unknown type":        repl(`"host"`, `"widget"`),
		"no item_version":     repl(`"item_version":"3",`, ``),
		"numeric version":     repl(`"item_version":"3"`, `"item_version":3`),
		"leading zero":        repl(`"item_version":"3"`, `"item_version":"03"`),
		"signed version":      repl(`"item_version":"3"`, `"item_version":"+3"`),
		"overflowing version": repl(`"item_version":"3"`, `"item_version":"18446744073709551616"`),
	} {
		if _, err := ParseItem([]byte(in)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if _, err := ParseItem([]byte(good)); err != nil {
		t.Fatal(err)
	}

	// The largest u64 is fine.
	if _, err := ParseItem([]byte(repl(`"item_version":"3"`, `"item_version":"18446744073709551615"`))); err != nil {
		t.Errorf("largest u64: %v", err)
	}

	// Grants are never merged.
	grant := repl(`"host"`, `"grant"`)
	if _, err := ParseItem([]byte(grant)); !errors.Is(err, ErrGrant) {
		t.Errorf("grant plaintext: %v, want ErrGrant", err)
	}
}

func TestItemOf(t *testing.T) {
	h := model.Host{Header: model.Header{V: 1, ItemID: mustID(t, idHost), Type: model.TypeHost, ItemVersion: 3}, Name: "web", Port: 22}
	k := model.Key{Header: model.Header{V: 1, ItemID: mustID(t, idKey), Type: model.TypeKey, ItemVersion: 1}}
	c := model.Credential{Header: model.Header{V: 1, ItemID: mustID(t, idCred), Type: model.TypeCredential, ItemVersion: 1}}
	s := model.Snippet{Header: model.Header{V: 1, ItemID: mustID(t, idSnip), Type: model.TypeSnippet, ItemVersion: 1}}
	for _, tc := range []struct {
		v    any
		want model.Type
	}{
		{h, model.TypeHost}, {&h, model.TypeHost},
		{k, model.TypeKey}, {&k, model.TypeKey},
		{c, model.TypeCredential}, {&c, model.TypeCredential},
		{s, model.TypeSnippet}, {&s, model.TypeSnippet},
	} {
		it, err := ItemOf(tc.v)
		if err != nil {
			t.Errorf("%T: %v", tc.v, err)
			continue
		}
		if it.Type() != tc.want {
			t.Errorf("%T: type %s, want %s", tc.v, it.Type(), tc.want)
		}
	}

	// A typed round trip.
	it, err := ItemOf(h)
	if err != nil {
		t.Fatal(err)
	}
	var back model.Host
	if err := it.Decode(&back); err != nil {
		t.Fatal(err)
	}
	if back.Name != "web" || back.Port != 22 || back.ItemVersion != 3 || back.ItemID != h.ItemID {
		t.Errorf("round trip: %+v", back)
	}

	// Grants and everything else are refused.
	g := model.Grant{Header: model.Header{V: 1, ItemID: mustID(t, idHost2), Type: model.TypeGrant, ItemVersion: 1}}
	for _, v := range []any{g, &g} {
		if _, err := ItemOf(v); !errors.Is(err, ErrGrant) {
			t.Errorf("%T: %v, want ErrGrant", v, err)
		}
	}
	for _, v := range []any{nil, 3, "host", struct{}{}} {
		if _, err := ItemOf(v); err == nil {
			t.Errorf("%T: accepted", v)
		}
	}
	// A header that says grant is refused even on another struct.
	bad := h
	bad.Type = model.TypeGrant
	if _, err := ItemOf(bad); !errors.Is(err, ErrGrant) {
		t.Errorf("host struct typed grant: %v, want ErrGrant", err)
	}
	// A zero ID is refused: it would be written as "".
	bad = h
	bad.ItemID = model.ID{}
	if _, err := ItemOf(bad); err == nil {
		t.Error("accepted a zero item_id")
	}
}

func TestItemIsImmutable(t *testing.T) {
	a := host(t, 1)
	before := string(a.Plaintext())

	b, err := a.with(map[string]canonjson.Raw{"name": rawString("other")})
	if err != nil {
		t.Fatal(err)
	}
	if string(a.Plaintext()) != before {
		t.Error("with changed the receiver")
	}
	if a.Equal(b) {
		t.Error("changed item compares equal")
	}
	// What the accessors return can be modified without effect.
	p := a.Plaintext()
	p[1] = 'X'
	m, _ := a.Member("name")
	m[1] = 'X'
	if string(a.Plaintext()) != before {
		t.Error("Plaintext or Member returned shared storage")
	}
	// Removing a member makes it differ from every present value.
	c, err := a.with(map[string]canonjson.Raw{"description": nil})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := c.Member("description"); ok {
		t.Error("member was not removed")
	}
	if c.Equal(a) || a.Equal(c) {
		t.Error("a missing member equals a present one")
	}
}

func TestEqualIgnoresHeaderMembers(t *testing.T) {
	a, b := host(t, 1), host(t, 99)
	if !a.Equal(b) {
		t.Error("items differing only in item_version compare unequal")
	}
	if a.Equal(host(t, 1, name("x"))) {
		t.Error("items differing in name compare equal")
	}
	// Lists are compared whole and in order.
	if host(t, 1, tags("a", "b")).Equal(host(t, 1, tags("b", "a"))) {
		t.Error("reordered tags compare equal")
	}
}
