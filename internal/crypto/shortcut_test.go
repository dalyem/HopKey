package crypto

import (
	"strings"
	"testing"

	"github.com/dalyem/hopkey/internal/canonjson"
	"github.com/dalyem/hopkey/internal/model"
)

func testShortcut() *model.Shortcut {
	return &model.Shortcut{Header: hdr(model.TypeShortcut, 7), Name: "logs", Keys: "gl", Command: "journalctl -fu app # follow", Enter: true}
}

// A shortcut round-trips under its closed schema, global (host_id "") or
// for a host.
func TestShortcutSchemaValid(t *testing.T) {
	for _, sc := range []*model.Shortcut{
		testShortcut(),
		{Header: hdr(model.TypeShortcut, 8), Keys: "~", Command: "x", HostID: fixedID(1)},
		// A Go template is not a parameter.
		{Header: hdr(model.TypeShortcut, 9), Keys: "d", Command: "docker ps --format '{{.Names}}'"},
	} {
		b, err := MarshalItem(sc)
		if err != nil {
			t.Fatal(err)
		}
		back, err := ParseItem(model.TypeShortcut, b)
		if err != nil {
			t.Fatalf("parse %s: %v", b, err)
		}
		if got := *back.(*model.Shortcut); got != *sc {
			t.Errorf("round trip: %+v, want %+v", got, *sc)
		}
	}
	b, _ := MarshalItem(testShortcut())
	if want := `"host_id":""`; !strings.Contains(string(b), want) {
		t.Errorf("a global shortcut %s lacks %s", b, want)
	}
}

// The panel types command into a remote shell as it is: one line, no
// control character (a TAB would be the completion key), no
// {{parameter}}, and keys of one or two printable characters, none of
// them the panel's own.
func TestShortcutSchemaRejects(t *testing.T) {
	for name, mutate := range map[string]func(*model.Shortcut){
		"wrong type":     func(s *model.Shortcut) { s.Type = model.TypeSnippet },
		"no keys":        func(s *model.Shortcut) { s.Keys = "" },
		"three keys":     func(s *model.Shortcut) { s.Keys = "abc" },
		"space key":      func(s *model.Shortcut) { s.Keys = " " },
		"control key":    func(s *model.Shortcut) { s.Keys = "\x1d" },
		"non-ASCII key":  func(s *model.Shortcut) { s.Keys = "é" },
		"DEL key":        func(s *model.Shortcut) { s.Keys = "\x7f" },
		"reserved key":   func(s *model.Shortcut) { s.Keys = "?" },
		"reserved 2nd":   func(s *model.Shortcut) { s.Keys = "a?" },
		"empty command":  func(s *model.Shortcut) { s.Command = "" },
		"LF in command":  func(s *model.Shortcut) { s.Command = "ls\nrm -rf /" },
		"CR in command":  func(s *model.Shortcut) { s.Command = "ls\r" },
		"ESC in command": func(s *model.Shortcut) { s.Command = "printf \x1b[2J" },
		"NUL in command": func(s *model.Shortcut) { s.Command = "a\x00b" },
		"DEL in command": func(s *model.Shortcut) { s.Command = "ab\x7f" },
		"C1 in command":  func(s *model.Shortcut) { s.Command = "a\u009bb" },
		"TAB in command": func(s *model.Shortcut) { s.Command = "echo\thello" },
		"parameter":      func(s *model.Shortcut) { s.Command = "ssh {{ host }}" },
		"long command":   func(s *model.Shortcut) { s.Command = strings.Repeat("a", model.MaxShortcutCommand+1) },
		"bad UTF-8":      func(s *model.Shortcut) { s.Command = "a\xffb" },
		"control name":   func(s *model.Shortcut) { s.Name = "a\x1b]0;x\x07" },
		"long name":      func(s *model.Shortcut) { s.Name = strings.Repeat("n", 65) },
		"CR description": func(s *model.Shortcut) { s.Description = "a\rb" },
	} {
		sc := testShortcut()
		mutate(sc)
		if err := ValidateShortcut(sc); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	sc := testShortcut()
	sc.Command = strings.Repeat("a", model.MaxShortcutCommand)
	if err := ValidateShortcut(sc); err != nil {
		t.Errorf("a command of the longest length: %v", err)
	}
}

// A shortcut another device wrote is opened under the same rules as one
// written here: one the panel could not use is refused, not synced.
func TestShortcutFromAnotherDeviceChecked(t *testing.T) {
	ik := SymKey(fixedBytes("IK", 32))
	c := ItemContext{AccountID: fixedID(0x10), VaultID: fixedID(0x50), ItemID: fixedID(7),
		Type: model.TypeShortcut, ItemVersion: 1, IV: 1, KV: 1}
	for name, mutate := range map[string]func(*model.Shortcut){
		"reserved key": func(s *model.Shortcut) { s.Keys = "a?" },
		"parameter":    func(s *model.Shortcut) { s.Command = "echo {{name}}" },
		"TAB":          func(s *model.Shortcut) { s.Command = "echo\thello" },
	} {
		sc := testShortcut()
		mutate(sc)
		// Sealed as a device without these rules would: past SealItem's
		// own check.
		pt, err := canonjson.Marshal(sc)
		if err != nil {
			t.Fatal(err)
		}
		e, err := SealAEAD(&ik, pt, c.bodyAAD())
		if err != nil {
			t.Fatal(err)
		}
		if _, err := OpenItem(&ik, c, e); err == nil {
			t.Errorf("%s: opened %s", name, pt)
		}
	}
	e, err := SealItem(&ik, c, testShortcut())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := OpenItem(&ik, c, e); err != nil {
		t.Fatalf("a valid shortcut: %v", err)
	}
}

// A shortcut never goes into a grant's bundle: it is for a person at the
// session panel, not for a token holder.
func TestShortcutIsNotABundleType(t *testing.T) {
	if isBundleType(model.TypeShortcut) {
		t.Error("shortcuts are bundled")
	}
}

// Every member is required, as in every item type.
func TestShortcutSchemaIsClosed(t *testing.T) {
	b, _ := MarshalItem(testShortcut())
	for _, bad := range []string{
		strings.Replace(string(b), `"enter":true,`, ``, 1),
		strings.Replace(string(b), `"enter":true,`, `"enter":true,"extra":1,`, 1),
	} {
		if _, err := ParseItem(model.TypeShortcut, []byte(bad)); err == nil {
			t.Errorf("accepted %s", bad)
		}
	}
	if _, err := canonjson.Canonicalize(b); err != nil {
		t.Fatal(err)
	}
}
