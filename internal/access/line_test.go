package access

import (
	"fmt"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"

	"github.com/dalyem/hopkey/internal/model"
)

func lineRecord(t testing.TB, o model.AccessOptions) *model.Access {
	t.Helper()
	a := record(t, model.AccessPending, 1, model.AccessPending, 1)
	a.Options = o
	return a
}

// §8.4 rendering vectors.
func TestRenderAndLineBody(t *testing.T) {
	got := Render(model.AccessOptions{From: []string{"10.0.0.0/8", "2001:db8::/32"}, NoForwarding: true})
	if want := `from="10.0.0.0/8,2001:db8::/32",no-agent-forwarding,no-port-forwarding,no-X11-forwarding`; got != want {
		t.Fatalf("render %q", got)
	}
	if Render(model.AccessOptions{From: []string{}}) != "" || Render(model.AccessOptions{Restrict: true}) != "restrict" {
		t.Fatal("render of empty or restrict")
	}
	for _, o := range []model.AccessOptions{
		{From: []string{}}, {Restrict: true}, {From: []string{"10.0.0.0/8"}, NoForwarding: true},
	} {
		a := lineRecord(t, o)
		body, err := LineBody(a)
		if err != nil {
			t.Fatal(err)
		}
		if !printable(body) || !strings.HasSuffix(body, " hop-access:"+a.RecordID.String()) {
			t.Fatalf("body %q", body)
		}
		k, ok := ParseKeyLine(body)
		if !ok || !ManagedBy(k, a) || !Matches(k, a) {
			t.Fatalf("%q does not parse back", body)
		}
		d := DecideAdd(nil, a, false)
		if d.Outcome != OutWrite || string(d.New) != body+"\n" {
			t.Fatalf("written %q", d.New)
		}
	}
}

// §8.4 comment grammar.
func TestCommentGrammar(t *testing.T) {
	a := lineRecord(t, model.AccessOptions{From: []string{}})
	key := a.PublicKey
	rid := a.RecordID.String()
	tabbed := strings.Replace(key, " ", "\t", 1)
	for _, c := range []struct {
		line           string
		managed, carry bool
	}{
		{key + " hop-access:" + rid, true, true},
		{tabbed + "\thop-access:" + rid, true, true},
		{key + " hop-access:" + rid + " \t ", true, true},
		{key + " hop-access:" + rid + "\r", true, true},
		{`from="10.0.0.0/8 x",no-pty ` + key + " hop-access:" + rid, true, true},
		{"  \t" + key + "  hop-access:" + rid, true, true},
		{key + " hop-access:" + rid + " extra", false, true},
		{key + " HOP-ACCESS:" + rid, false, true},
		{"cert-authority " + key + " hop-access:" + rid, false, true},
		{"#" + key + " hop-access:" + rid, false, false},
		{key + " colleague@laptop", false, false},
	} {
		k, ok := ParseKeyLine(c.line)
		managed := ok && ManagedBy(k, a)
		if managed != c.managed || (ok && k.Marked) != c.carry {
			t.Errorf("%q: managed %v carries %v; want %v %v", c.line, managed, ok && k.Marked, c.managed, c.carry)
		}
	}
}

func TestParseTombstone(t *testing.T) {
	rid := strings.Repeat("ab", 16)
	for _, c := range []struct {
		line string
		like bool
		gen  uint64
	}{
		{"# hop-access-removed " + rid + " 3", true, 3},
		{"#hop-access-removed " + rid + " 3", true, 3},
		{" \t# \thop-access-removed\t" + rid + "  18446744073709551615 \t\r", true, 18446744073709551615},
		{"# HOP-ACCESS-REMOVED " + rid + " 3", true, 0},
		{"# hop-access-removed " + rid[:30] + " 3", true, 0},
		{"# hop-access-removed " + strings.ToUpper(rid) + " 3", true, 0},
		{"# hop-access-removed " + rid + " 0", true, 0},
		{"# hop-access-removed " + rid + " 03", true, 0},
		{"# hop-access-removed " + rid + " 18446744073709551616", true, 0},
		{"# hop-access-removed " + rid + " 3 x", true, 0},
		{"# hop-access-removed", true, 0},
		{"# a comment", false, 0},
		{"hop-access-removed " + rid + " 3", false, 0},
	} {
		like, r, g := ParseTombstone(c.line)
		if like != c.like || g != c.gen || (c.gen != 0) != (r == rid) {
			t.Errorf("%q: like %v rid %q gen %d", c.line, like, r, g)
		}
	}
	a := lineRecord(t, model.AccessOptions{From: []string{}})
	tomb := Tombstone(a.RecordID, 7)
	if like, r, g := ParseTombstone(tomb); !like || r != a.RecordID.String() || g != 7 || !printable(tomb) {
		t.Fatalf("Tombstone %q", tomb)
	}
}

// §8.4 add planner, over fixture files.
func TestDecideAdd(t *testing.T) {
	a := lineRecord(t, model.AccessOptions{From: []string{}})
	body, _ := LineBody(a)
	other := keyLine(edPub(t, 7)) + " me@laptop"
	same := a.PublicKey + " colleague@laptop"
	tomb := Tombstone(a.RecordID, 2)
	rid := a.RecordID.String()
	cases := []struct {
		name      string
		file      string
		alongside bool
		out       Outcome
		new       string
	}{
		{"empty", "", false, OutWrite, body + "\n"},
		{"no trailing LF", other, false, OutWrite, other + "\n" + body + "\n"},
		{"present and matching", other + "\n" + body + "\n", false, OutInstalled, ""},
		{"other options", "restrict " + body + "\n", false, OutRefused, ""},
		{"two managed lines", body + "\n" + body + "\n", false, OutRefused, ""},
		{"the same key unmanaged", same + "\n", false, OutRefused, ""},
		{"the same key unmanaged, alongside", same + "\n", true, OutWrite, same + "\n" + body + "\n"},
		{"a CA line with the key", "cert-authority " + same + "\n", false, OutWrite, "cert-authority " + same + "\n" + body + "\n"},
		{"marker inside a longer comment", a.PublicKey + " hop-access:" + rid + " x\n", false, OutRefused, ""},
		{"a tombstone with a matching line", body + "\n" + tomb + "\n", false, OutRefused, ""},
		{"a malformed tombstone", "# HOP-ACCESS-REMOVED x\n", false, OutRefused, ""},
		{"another record's tombstone", "# hop-access-removed " + strings.Repeat("0", 31) + "1 4\n", false, OutWrite, "# hop-access-removed " + strings.Repeat("0", 31) + "1 4\n" + body + "\n"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			d := DecideAdd([]byte(c.file), a, c.alongside)
			if d.Outcome != c.out || (c.out == OutWrite && string(d.New) != c.new) {
				t.Fatalf("outcome %v new %q err %q", d.Outcome, d.New, d.Err)
			}
			if c.out == OutRefused && (d.Err == "" || len(d.Err) > 256) {
				t.Fatalf("error %q", d.Err)
			}
		})
	}
	if d := DecideAdd([]byte(body+"\n"+tomb+"\n"), a, false); !strings.Contains(d.Err, "was removed here (gen 2)") {
		t.Fatalf("tombstone error %q", d.Err)
	}
}

// §8.4 remove planner, and the tombstone bound.
func TestDecideRemove(t *testing.T) {
	a := lineRecord(t, model.AccessOptions{From: []string{}})
	body, _ := LineBody(a)
	tomb := Tombstone(a.RecordID, 5)
	same := a.PublicKey + " colleague@laptop"
	cases := []struct {
		name string
		file string
		out  Outcome
		new  string
	}{
		{"one match", "a\n" + body + "\nb", OutWrite, "a\nb\n" + tomb + "\n"},
		{"one match, last line without LF", "a\n" + body, OutWrite, "a\n" + tomb + "\n"},
		{"the same key without the marker", same + "\n", OutWrite, same + "\n" + tomb + "\n"},
		{"no line, no tombstone", "a\n", OutWrite, "a\n" + tomb + "\n"},
		{"no line, a tombstone", "a\n" + Tombstone(a.RecordID, 4) + "\n", OutRemoved, ""},
		{"a line and its tombstone", body + "\n" + Tombstone(a.RecordID, 4) + "\n", OutWrite, Tombstone(a.RecordID, 4) + "\n"},
		{"a line that doesn't match", "restrict " + body + "\n", OutRefused, ""},
		{"a malformed tombstone doesn't stop it", "# HOP-ACCESS-REMOVED\n" + body + "\n", OutWrite, "# HOP-ACCESS-REMOVED\n" + tomb + "\n"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			d := DecideRemove([]byte(c.file), a, 5, "web")
			if d.Outcome != c.out || (c.out == OutWrite && string(d.New) != c.new) {
				t.Fatalf("outcome %v new %q err %q", d.Outcome, d.New, d.Err)
			}
		})
	}
	tombs := func(n int) string {
		var b strings.Builder
		for i := range n {
			fmt.Fprintf(&b, "# hop-access-removed %032x %d\n", i+1, 1)
		}
		return b.String()
	}
	if d := DecideRemove([]byte(tombs(128)+body+"\n"), a, 5, "web"); d.Outcome != OutRefused || !strings.Contains(d.Err, "128 hop access tombstones") {
		t.Fatalf("129th tombstone: %+v", d)
	}
	withOwn := tombs(127) + Tombstone(a.RecordID, 4) + "\n" + body + "\n"
	if d := DecideRemove([]byte(withOwn), a, 5, "web"); d.Outcome != OutWrite || string(d.New) != tombs(127)+Tombstone(a.RecordID, 4)+"\n" || d.Warn == "" {
		t.Fatalf("128 with its own: %+v", d)
	}
	if d := DecideRemove([]byte(tombs(98)+body+"\n"), a, 5, "web"); d.Warn != "" {
		t.Fatalf("warned at 99: %q", d.Warn)
	}
	if d := DecideRemove([]byte(tombs(99)+body+"\n"), a, 5, "web"); !strings.Contains(d.Warn, "holds 100 hop access tombstones") {
		t.Fatalf("no warning at 100: %q", d.Warn)
	}
}

func TestBoundKey(t *testing.T) {
	pin, other := edPub(t, 1), edPub(t, 2)
	line := func(k ssh.PublicKey) string {
		return "debug1: Server host key: " + k.Type() + " " + ssh.FingerprintSHA256(k)
	}
	pins := []ssh.PublicKey{pin}
	head := "OpenSSH_9.2p1 Debian-2+deb12u3, OpenSSL 3.0.15 3 Sep 2024\r\ndebug1: Reading configuration data /tmp/x.config\r\n"
	for _, c := range []struct {
		name string
		log  string
		ok0  bool
		want bool
	}{
		{"one line", head + line(pin) + "\r\ndebug1: Authentication succeeded (publickey).\r\n", true, true},
		{"a rekey", head + line(pin) + "\r\n" + line(pin) + "\r\n", true, true},
		{"two that disagree", head + line(pin) + "\r\n" + line(other) + "\r\n", true, false},
		{"none", head, true, false},
		{"not a pin", head + line(other) + "\r\n", true, false},
		{"cut short", head + line(pin), true, false},
		{"ssh failed", head + line(pin) + "\r\n", false, false},
		{"a Remote: imitation", head + line(pin) + "\r\ndebug1: Remote: " + line(other)[8:] + "\r\n", true, false},
		{"an embedded newline naming another key", head + line(pin) + "\r\n" + line(other) + "\r\n", true, false},
		{"an embedded newline naming the genuine key", head + line(pin) + "\r\n" + line(pin) + "\r\n", true, true},
		{"trailing text", head + line(pin) + " x\r\n", true, false},
		{"wrong length", head + line(pin)[:len(line(pin))-1] + "\r\n", true, false},
		{"debug2 prefix", head + "debug2: Server host key: " + pin.Type() + " " + ssh.FingerprintSHA256(pin) + "\r\n", true, false},
		{"a host certificate", head + "debug1: Server host key: ssh-ed25519-cert-v01@openssh.com " + ssh.FingerprintSHA256(pin) + "\r\n", true, false},
	} {
		k, err := BoundKey(c.log, c.ok0, pins)
		if (err == nil) != c.want || (c.want && ssh.FingerprintSHA256(k) != ssh.FingerprintSHA256(pin)) {
			t.Errorf("%s: %v", c.name, err)
		}
	}
}
