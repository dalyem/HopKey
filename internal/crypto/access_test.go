package crypto

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"

	"github.com/dalyem/hopkey/internal/canonjson"
	"github.com/dalyem/hopkey/internal/model"
)

func accessKeyLine(t testing.TB, pk ssh.PublicKey) (line, fp string) {
	t.Helper()
	return pk.Type() + " " + base64.StdEncoding.EncodeToString(pk.Marshal()), ssh.FingerprintSHA256(pk)
}

func edKey(t testing.TB, seed byte) ssh.PublicKey {
	t.Helper()
	s := make([]byte, 32)
	s[0] = seed
	pk, err := ssh.NewPublicKey(ed25519.NewKeyFromSeed(s).Public())
	if err != nil {
		t.Fatal(err)
	}
	return pk
}

func id(b byte) model.ID {
	var x model.ID
	for i := range x {
		x[i] = b
	}
	return x
}

func validAccess(t testing.TB) *model.Access {
	t.Helper()
	line, fp := accessKeyLine(t, edKey(t, 1))
	_, hfp := accessKeyLine(t, edKey(t, 2))
	return &model.Access{
		Header: model.Header{V: Version, ItemID: id(1), Type: model.TypeAccess},
		Label:  "alice", RecordID: id(2), PublicKey: line, Fingerprint: fp,
		Options: model.AccessOptions{From: []string{}}, By: id(3),
		Targets: []model.AccessTarget{{HostItemID: id(4), User: "root", ServerKeyFP: hfp, Gen: 1, State: model.AccessPending}},
	}
}

func TestValidateAccess(t *testing.T) {
	if err := ValidateAccess(validAccess(t)); err != nil {
		t.Fatalf("valid: %v", err)
	}
	rsaLine := func(bits int) string {
		k, err := rsa.GenerateKey(rand.Reader, bits)
		if err != nil {
			t.Fatal(err)
		}
		pk, err := ssh.NewPublicKey(&k.PublicKey)
		if err != nil {
			t.Fatal(err)
		}
		l, _ := accessKeyLine(t, pk)
		return l
	}
	rsa3072, rsa2048 := rsaLine(3072), rsaLine(2048)
	skLine := func() string {
		var b []byte
		str := func(s []byte) { b = binary.BigEndian.AppendUint32(b, uint32(len(s))); b = append(b, s...) }
		str([]byte(ssh.KeyAlgoSKED25519))
		str(make([]byte, 32))
		str([]byte("ssh:"))
		return ssh.KeyAlgoSKED25519 + " " + base64.StdEncoding.EncodeToString(b)
	}()
	_, hfp := accessKeyLine(t, edKey(t, 2))
	_, hfp2 := accessKeyLine(t, edKey(t, 5))
	from16 := make([]string, 16)
	for i := range from16 {
		from16[i] = fmt.Sprintf("10.0.%d.0/24", i)
	}
	target := func(host byte, fp string, state string, gen uint64) model.AccessTarget {
		return model.AccessTarget{HostItemID: id(host), User: "root", ServerKeyFP: fp, Gen: gen, State: state}
	}
	sm := func(gen uint64, ids ...model.ID) *model.SameMachine {
		return &model.SameMachine{Gen: gen, ServerKeyFP: hfp, HostItemIDs: ids}
	}
	ids := func(n int) []model.ID {
		out := make([]model.ID, n)
		for i := range out {
			out[i] = id(byte(0x10 + i))
		}
		return out
	}
	many := func(n int) []model.AccessTarget {
		out := make([]model.AccessTarget, n)
		for i := range out {
			var h model.ID
			binary.BigEndian.PutUint16(h[14:], uint16(i+1))
			out[i] = model.AccessTarget{HostItemID: h, User: "u", ServerKeyFP: hfp, Gen: 1, State: model.AccessPending}
		}
		return out
	}
	cases := []struct {
		name string
		ok   bool
		f    func(a *model.Access)
	}{
		{"label at 64", true, func(a *model.Access) { a.Label = strings.Repeat("l", 64) }},
		{"label at 65", false, func(a *model.Access) { a.Label = strings.Repeat("l", 65) }},
		{"empty label", false, func(a *model.Access) { a.Label = "" }},
		{"no record_id", false, func(a *model.Access) { a.RecordID = model.ID{} }},
		{"no by", false, func(a *model.Access) { a.By = model.ID{} }},
		{"fingerprint mismatch", false, func(a *model.Access) { a.Fingerprint = hfp }},
		{"fingerprint padded", false, func(a *model.Access) { a.Fingerprint += "=" }},
		{"rsa-3072", true, func(a *model.Access) { a.PublicKey = rsa3072; a.Fingerprint, _ = SSHFingerprint(rsa3072) }},
		{"rsa-2048", false, func(a *model.Access) { a.PublicKey = rsa2048; a.Fingerprint, _ = SSHFingerprint(rsa2048) }},
		{"sk-ssh-ed25519", false, func(a *model.Access) { a.PublicKey = skLine; a.Fingerprint, _ = SSHFingerprint(skLine) }},
		{"a comment", false, func(a *model.Access) { a.PublicKey += " me@laptop" }},
		{"from at 16", true, func(a *model.Access) { a.Options.From = from16 }},
		{"from at 17", false, func(a *model.Access) { a.Options.From = append(from16, "10.1.0.0/16") }},
		{"from ipv6", true, func(a *model.Access) { a.Options.From = []string{"2001:db8::/32"} }},
		{"from not masked", false, func(a *model.Access) { a.Options.From = []string{"10.0.0.1/8"} }},
		{"from bare address", false, func(a *model.Access) { a.Options.From = []string{"10.0.0.1"} }},
		{"from twice", false, func(a *model.Access) { a.Options.From = []string{"10.0.0.0/8", "10.0.0.0/8"} }},
		{"restrict and no_forwarding", false, func(a *model.Access) { a.Options.Restrict, a.Options.NoForwarding = true, true }},
		{"no targets", false, func(a *model.Access) { a.Targets = nil }},
		{"256 targets", true, func(a *model.Access) { a.Targets = many(256) }},
		{"257 targets", false, func(a *model.Access) { a.Targets = many(257) }},
		{"targets unsorted", false, func(a *model.Access) {
			a.Targets = []model.AccessTarget{target(5, hfp, model.AccessPending, 1), target(4, hfp, model.AccessPending, 1)}
		}},
		{"targets sorted by fp", true, func(a *model.Access) {
			x, y := hfp, hfp2
			if x > y {
				x, y = y, x
			}
			a.Targets = []model.AccessTarget{target(4, x, model.AccessRemoved, 2), target(4, y, model.AccessPending, 1)}
		}},
		{"duplicate pair", false, func(a *model.Access) {
			a.Targets = []model.AccessTarget{target(4, hfp, model.AccessRemoved, 2), target(4, hfp, model.AccessRemoved, 2)}
		}},
		{"two live targets on one host", false, func(a *model.Access) {
			x, y := hfp, hfp2
			if x > y {
				x, y = y, x
			}
			a.Targets = []model.AccessTarget{target(4, x, model.AccessInstalled, 2), target(4, y, model.AccessPending, 1)}
		}},
		{"empty server_key_fp", false, func(a *model.Access) { a.Targets[0].ServerKeyFP = "" }},
		{"gen 0", false, func(a *model.Access) { a.Targets[0].Gen = 0 }},
		{"empty user", false, func(a *model.Access) { a.Targets[0].User = "" }},
		{"unknown state", false, func(a *model.Access) { a.Targets[0].State = "gone" }},
		{"error on installed", false, func(a *model.Access) { a.Targets[0].State, a.Targets[0].Error = model.AccessInstalled, "x" }},
		{"error on failed", true, func(a *model.Access) { a.Targets[0].State, a.Targets[0].Error = model.AccessFailed, "x" }},
		{"error at 257", false, func(a *model.Access) {
			a.Targets[0].State, a.Targets[0].Error = model.AccessFailed, strings.Repeat("e", 257)
		}},
		{"same_machine on removing", true, func(a *model.Access) {
			a.Targets[0].State, a.Targets[0].Gen, a.Targets[0].SameMachine = model.AccessRemoving, 2, sm(2, id(9))
		}},
		{"same_machine on pending", false, func(a *model.Access) { a.Targets[0].SameMachine = sm(1, id(9)) }},
		{"same_machine other fp", false, func(a *model.Access) {
			a.Targets[0].State, a.Targets[0].SameMachine = model.AccessRemoving, &model.SameMachine{Gen: 1, ServerKeyFP: hfp2, HostItemIDs: []model.ID{id(9)}}
		}},
		{"same_machine names its own host", false, func(a *model.Access) {
			a.Targets[0].State, a.Targets[0].SameMachine = model.AccessRemoving, sm(1, id(4))
		}},
		{"same_machine unsorted", false, func(a *model.Access) {
			a.Targets[0].State, a.Targets[0].SameMachine = model.AccessRemoving, sm(1, id(9), id(8))
		}},
		{"same_machine duplicate", false, func(a *model.Access) {
			a.Targets[0].State, a.Targets[0].SameMachine = model.AccessRemoving, sm(1, id(9), id(9))
		}},
		{"same_machine empty", false, func(a *model.Access) { a.Targets[0].State, a.Targets[0].SameMachine = model.AccessRemoving, sm(1) }},
		{"same_machine at 16", true, func(a *model.Access) {
			a.Targets[0].State, a.Targets[0].SameMachine = model.AccessRemoving, sm(1, ids(16)...)
		}},
		{"same_machine at 17", false, func(a *model.Access) {
			a.Targets[0].State, a.Targets[0].SameMachine = model.AccessRemoving, sm(1, ids(17)...)
		}},
		{"same_machine gen above the target's", false, func(a *model.Access) {
			a.Targets[0].State, a.Targets[0].SameMachine = model.AccessRemoving, sm(2, id(9))
		}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			a := validAccess(t)
			c.f(a)
			if err := ValidateAccess(a); (err == nil) != c.ok {
				t.Fatalf("ok %v, err %v", c.ok, err)
			}
		})
	}
}

// same_machine is a required member: null round-trips, and a target
// without it is rejected.
func TestAccessSameMachineEncoding(t *testing.T) {
	a := validAccess(t)
	b, err := MarshalItem(a)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), `"same_machine":null`) {
		t.Fatalf("encoding omits same_machine: %s", b)
	}
	back, err := ParseItem(model.TypeAccess, b)
	if err != nil {
		t.Fatal(err)
	}
	if back.(*model.Access).Targets[0].SameMachine != nil {
		t.Fatal("null did not round-trip")
	}
	missing := strings.Replace(string(b), `,"same_machine":null`, "", 1)
	if _, err := ParseItem(model.TypeAccess, []byte(missing)); err == nil {
		t.Fatal("a target without same_machine was accepted")
	}
	if _, err := canonjson.Canonicalize([]byte(missing)); err != nil {
		t.Fatal(err)
	}
}

func TestCanonicalFrom(t *testing.T) {
	for in, want := range map[string]string{
		"10.0.0.1":        "10.0.0.1/32",
		"10.1.2.3/8":      "10.0.0.0/8",
		"2001:db8::1":     "2001:db8::1/128",
		"2001:db8::1/32":  "2001:db8::/32",
		"192.168.10.0/24": "192.168.10.0/24",
	} {
		if got, err := CanonicalFrom(in); err != nil || got != want {
			t.Errorf("CanonicalFrom(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	for _, bad := range []string{"", "10.0.0.0/33", "host.example", "fe80::1%eth0"} {
		if _, err := CanonicalFrom(bad); err == nil {
			t.Errorf("CanonicalFrom(%q) accepted", bad)
		}
	}
}
