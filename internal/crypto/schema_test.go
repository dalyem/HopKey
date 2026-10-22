package crypto

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"encoding/pem"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"

	"github.com/dalyem/hopkey/internal/canonjson"
	"github.com/dalyem/hopkey/internal/model"
)

func hdr(t model.Type, id byte) model.Header {
	return model.Header{V: 1, ItemID: fixedID(id), Type: t, ItemVersion: 1}
}

func testKey(id byte, grant model.ID) *model.Key {
	return &model.Key{Header: hdr(model.TypeKey, id), Name: "k", KeyType: "ed25519",
		PrivateKey: "PRIVATE", PublicKey: "ssh-ed25519 AAAA", DedicatedGrant: grant}
}

func TestItemSchemasValid(t *testing.T) {
	items := []Item{
		testHost(fixedID(1), 1),
		testKey(2, model.ID{}),
		&model.Credential{Header: hdr(model.TypeCredential, 3), Name: "c", Username: "u", Password: "p"},
		&model.Snippet{Header: hdr(model.TypeSnippet, 4), Name: "s", Command: "uptime", Params: []string{}, Description: ""},
		&model.Grant{Header: hdr(model.TypeGrant, 5), GrantID: fixedID(6), Name: "g", ExpiresAt: 1 << 31,
			TokenKEMPK: []byte{1}, Items: []model.ID{fixedID(1), fixedID(2)}, HostKeyMap: map[model.ID]model.ID{fixedID(1): fixedID(2)},
			KeyPolicy: "shared"},
	}
	for _, it := range items {
		b, err := MarshalItem(it)
		if err != nil {
			t.Fatalf("%T: %v", it, err)
		}
		h, _ := ItemHeader(it)
		back, err := ParseItem(h.Type, b)
		if err != nil {
			t.Fatalf("%T: parse: %v", it, err)
		}
		again, _ := canonjson.Marshal(back)
		if string(again) != string(b) {
			t.Fatalf("%T: round trip changed %s to %s", it, b, again)
		}
	}
	// A host with tailscale set and null both pass.
	h := testHost(fixedID(1), 1)
	h.Tailscale = &model.Tailscale{StableNodeID: "n", DNSName: "web.ts.net", SSH: "unknown"}
	if err := ValidateHost(h); err != nil {
		t.Fatal(err)
	}
}

func TestHostSchemaRejects(t *testing.T) {
	for name, mutate := range map[string]func(*model.Host){
		"v=2":                func(h *model.Host) { h.V = 2 },
		"zero item_id":       func(h *model.Host) { h.ItemID = model.ID{} },
		"wrong type":         func(h *model.Host) { h.Type = model.TypeKey },
		"name 65 bytes":      func(h *model.Host) { h.Name = strings.Repeat("a", 65) },
		"control in name":    func(h *model.Host) { h.Name = "a\tb" },
		"DEL in name":        func(h *model.Host) { h.Name = "a\x7fb" },
		"C1 in name":         func(h *model.Host) { h.Name = "a\u0085b" },
		"alias too long":     func(h *model.Host) { h.Aliases = []string{strings.Repeat("a", 65)} },
		"address too long":   func(h *model.Host) { h.Addresses = []string{strings.Repeat("a", 256)} },
		"port 0":             func(h *model.Host) { h.Port = 0 },
		"port 65536":         func(h *model.Host) { h.Port = 65536 },
		"tag too long":       func(h *model.Host) { h.Tags = []string{strings.Repeat("a", 33)} },
		"description 1025":   func(h *model.Host) { h.Description = strings.Repeat("a", 1025) },
		"route":              func(h *model.Host) { h.Route = "magic" },
		"agent_access":       func(h *model.Host) { h.AgentAccess = "maybe" },
		"tailscale ssh":      func(h *model.Host) { h.Tailscale = &model.Tailscale{SSH: "sometimes"} },
		"tailscale dns_name": func(h *model.Host) { h.Tailscale = &model.Tailscale{DNSName: strings.Repeat("a", 256), SSH: "no"} },
		"host key too long":  func(h *model.Host) { h.HostKeys = []string{strings.Repeat("a", 8193)} },
		"invalid UTF-8":      func(h *model.Host) { h.User = "\xff" },
	} {
		h := testHost(fixedID(1), 1)
		mutate(h)
		if err := ValidateHost(h); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	// Multi-byte characters count by bytes.
	h := testHost(fixedID(1), 1)
	h.Name = strings.Repeat("é", 32) // 64 bytes
	if err := ValidateHost(h); err != nil {
		t.Errorf("64-byte name rejected: %v", err)
	}
	h.Name += "a"
	if err := ValidateHost(h); err == nil {
		t.Error("65-byte name accepted")
	}
}

func TestOtherSchemasReject(t *testing.T) {
	k := testKey(2, model.ID{})
	k.KeyType = "dsa"
	if ValidateKey(k) == nil {
		t.Error("key_type dsa accepted")
	}
	k = testKey(2, model.ID{})
	k.PrivateKey = strings.Repeat("a", 16385)
	if ValidateKey(k) == nil {
		t.Error("private_key over 16384 bytes accepted")
	}
	c := &model.Credential{Header: hdr(model.TypeCredential, 3), Name: "c", Username: strings.Repeat("u", 65)}
	if ValidateCredential(c) == nil {
		t.Error("username over 64 bytes accepted")
	}
	s := &model.Snippet{Header: hdr(model.TypeSnippet, 4), Name: "s", Params: []string{strings.Repeat("p", 33)}}
	if ValidateSnippet(s) == nil {
		t.Error("param over 32 bytes accepted")
	}
	grant := func() *model.Grant {
		return &model.Grant{Header: hdr(model.TypeGrant, 5), GrantID: fixedID(6), Name: "g", Items: []model.ID{fixedID(1), fixedID(2)}, KeyPolicy: "shared"}
	}
	for name, mutate := range map[string]func(*model.Grant){
		"zero grant_id":    func(g *model.Grant) { g.GrantID = model.ID{} },
		"unsorted items":   func(g *model.Grant) { g.Items = []model.ID{fixedID(2), fixedID(1)} },
		"duplicate items":  func(g *model.Grant) { g.Items = []model.ID{fixedID(1), fixedID(1)} },
		"empty item ID":    func(g *model.Grant) { g.Items = []model.ID{{}} },
		"key_policy":       func(g *model.Grant) { g.KeyPolicy = "none" },
		"empty map key":    func(g *model.Grant) { g.HostKeyMap = map[model.ID]model.ID{{}: fixedID(2)} },
		"expires_at range": func(g *model.Grant) { g.ExpiresAt = 1 << 40 },
	} {
		g := grant()
		mutate(g)
		if ValidateGrant(g) == nil {
			t.Errorf("grant %s: accepted", name)
		}
	}
}

// key.private_key is text≤16384 (§6.5), so a real multi-line OpenSSH PEM,
// generated here, passes. A CRLF copy passes after CRLFToLF.
func TestPrivateKeyPEMAccepted(t *testing.T) {
	_, edKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	rsaKey, err := rsa.GenerateKey(rand.Reader, 3072)
	if err != nil {
		t.Fatal(err)
	}
	for name, key := range map[string]any{"ed25519": edKey, "rsa-3072": rsaKey} {
		blk, err := ssh.MarshalPrivateKey(key, "")
		if err != nil {
			t.Fatal(err)
		}
		pemText := string(pem.EncodeToMemory(blk))
		if !strings.HasPrefix(pemText, "-----BEGIN OPENSSH PRIVATE KEY-----\n") || strings.Count(pemText, "\n") < 3 {
			t.Fatalf("%s: not a multi-line OpenSSH PEM: %q", name, pemText)
		}
		k := testKey(2, model.ID{})
		k.PrivateKey = pemText
		if err := ValidateKey(k); err != nil {
			t.Errorf("%s PEM rejected: %v", name, err)
		}
		// Round trip through the item plaintext encoding.
		b, err := MarshalItem(k)
		if err != nil {
			t.Fatal(err)
		}
		back, err := ParseItem(model.TypeKey, b)
		if err != nil || back.(*model.Key).PrivateKey != pemText {
			t.Errorf("%s PEM did not round-trip: %v", name, err)
		}
		crlf := strings.ReplaceAll(pemText, "\n", "\r\n")
		k.PrivateKey = crlf
		if ValidateKey(k) == nil {
			t.Errorf("%s PEM with CRLF accepted", name)
		}
		k.PrivateKey = CRLFToLF(crlf)
		if err := ValidateKey(k); err != nil || k.PrivateKey != pemText {
			t.Errorf("%s PEM after CRLFToLF: %v", name, err)
		}
	}
}

// text≤n allows LF and TAB and rejects CR and every other Cc character
// (§3). It applies to host.description, key.private_key, snippet.command
// and snippet.description; str≤n fields still reject LF.
func TestTextFields(t *testing.T) {
	for name, tc := range map[string]struct {
		s  string
		ok bool
	}{
		"plain":       {"uptime", true},
		"LF":          {"line 1\nline 2\n", true},
		"TAB":         {"a\tb", true},
		"CR":          {"a\rb", false},
		"CRLF":        {"a\r\nb", false},
		"NUL":         {"a\x00b", false},
		"ESC":         {"a\x1bb", false},
		"DEL":         {"a\x7fb", false},
		"C1 NEL":      {"a\u0085b", false},
		"VT":          {"a\vb", false},
		"FF":          {"a\fb", false},
		"invalid":     {"a\xffb", false},
		"non-control": {"caf\u00e9 \u2028", true}, // U+2028 is Zl, not Cc
	} {
		if got := CheckText("f", tc.s, 64) == nil; got != tc.ok {
			t.Errorf("CheckText %s: ok=%v, want %v", name, got, tc.ok)
		}
	}
	if CheckText("f", strings.Repeat("a", 65), 64) == nil || CheckText("f", strings.Repeat("\n", 64), 64) != nil {
		t.Error("text≤n length bound wrong")
	}
	if CheckStr("f", "a\nb", 64) == nil || CheckStr("f", "a\tb", 64) == nil {
		t.Error("str≤n accepted LF or TAB")
	}
	if got := CRLFToLF("a\r\nb\rc\n\r\n"); got != "a\nb\rc\n\n" {
		t.Errorf("CRLFToLF = %q", got)
	}

	multi := "line 1\n\tline 2\n"
	h := testHost(fixedID(1), 1)
	h.Description = multi
	if err := ValidateHost(h); err != nil {
		t.Errorf("multi-line host.description: %v", err)
	}
	h.Name = "a\nb"
	if ValidateHost(h) == nil {
		t.Error("LF in host.name (str≤64) accepted")
	}
	s := &model.Snippet{Header: hdr(model.TypeSnippet, 4), Name: "s", Command: "for h in a b; do\n\techo $h\ndone\n",
		Params: []string{}, Description: multi}
	if err := ValidateSnippet(s); err != nil {
		t.Errorf("multi-line snippet: %v", err)
	}
	s.Command = "echo\r\n"
	if ValidateSnippet(s) == nil {
		t.Error("CR in snippet.command accepted")
	}
	s.Command = "ok"
	s.Description = "x\r"
	if ValidateSnippet(s) == nil {
		t.Error("CR in snippet.description accepted")
	}
	k := testKey(2, model.ID{})
	k.PublicKey = "ssh-ed25519 AAAA\n"
	if ValidateKey(k) == nil {
		t.Error("LF in key.public_key (str≤8192) accepted")
	}
}

func TestParseItemClosedSchema(t *testing.T) {
	c := &model.Credential{Header: hdr(model.TypeCredential, 3), Name: "c", Username: "u", Password: "p"}
	b, _ := MarshalItem(c)
	good := string(b)
	for name, in := range map[string]string{
		"unknown member":   strings.Replace(good, `"v":1`, `"v":1,"notes":"x"`, 1),
		"duplicate member": strings.Replace(good, `"name":"c"`, `"name":"c","name":"d"`, 1),
		"missing member":   strings.Replace(good, `"password":"p",`, ``, 1),
		"version number":   strings.Replace(good, `"item_version":"1"`, `"item_version":1`, 1),
	} {
		if _, err := ParseItem(model.TypeCredential, []byte(in)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if _, err := ParseItem(model.TypeHost, b); err == nil {
		t.Error("credential parsed as a host")
	}
	if _, err := ParseItem("note", b); err == nil {
		t.Error("unknown type accepted")
	}
}
