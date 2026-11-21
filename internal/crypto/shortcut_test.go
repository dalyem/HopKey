package crypto

import (
	"strings"
	"testing"

	"github.com/dalyem/hopkey/internal/canonjson"
	"github.com/dalyem/hopkey/internal/model"
)

func testShortcut() *model.Shortcut {
	return &model.Shortcut{Header: hdr(model.TypeShortcut, 7), Name: "logs", Keys: "gl", Command: "journalctl -fu app\t# follow", Enter: true}
}

// A shortcut round-trips under its closed schema, global (host_id "") or
// for a host.
func TestShortcutSchemaValid(t *testing.T) {
	for _, sc := range []*model.Shortcut{testShortcut(), {Header: hdr(model.TypeShortcut, 8), Keys: "~", Command: "x", HostID: fixedID(1)}} {
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

// The panel types command into a remote shell: one line, no control
// character but TAB, and keys of one or two printable characters.
func TestShortcutSchemaRejects(t *testing.T) {
	for name, mutate := range map[string]func(*model.Shortcut){
		"wrong type":     func(s *model.Shortcut) { s.Type = model.TypeSnippet },
		"no keys":        func(s *model.Shortcut) { s.Keys = "" },
		"three keys":     func(s *model.Shortcut) { s.Keys = "abc" },
		"space key":      func(s *model.Shortcut) { s.Keys = " " },
		"control key":    func(s *model.Shortcut) { s.Keys = "\x1d" },
		"non-ASCII key":  func(s *model.Shortcut) { s.Keys = "é" },
		"DEL key":        func(s *model.Shortcut) { s.Keys = "\x7f" },
		"empty command":  func(s *model.Shortcut) { s.Command = "" },
		"LF in command":  func(s *model.Shortcut) { s.Command = "ls\nrm -rf /" },
		"CR in command":  func(s *model.Shortcut) { s.Command = "ls\r" },
		"ESC in command": func(s *model.Shortcut) { s.Command = "printf \x1b[2J" },
		"NUL in command": func(s *model.Shortcut) { s.Command = "a\x00b" },
		"DEL in command": func(s *model.Shortcut) { s.Command = "ab\x7f" },
		"C1 in command":  func(s *model.Shortcut) { s.Command = "a\u009bb" },
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
