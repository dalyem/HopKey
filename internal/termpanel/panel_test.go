package termpanel

import (
	"strings"
	"testing"
)

func (v view) texts() []string {
	var out []string
	for _, l := range v.lines {
		var b strings.Builder
		for _, s := range l {
			b.WriteString(s.text)
		}
		out = append(out, b.String())
	}
	return out
}

var sample = []Shortcut{
	{Keys: "u", Name: "Update", Command: "sudo apt update && sudo apt upgrade -y", Enter: true},
	{Keys: "gs", Name: "Git status", Command: "git status", Host: true},
	{Keys: "gl", Name: "Git log", Command: "git log --oneline -20", Host: true},
	{Keys: "d", Name: "Disk", Command: "df -h"},
}

func TestLayoutBox(t *testing.T) {
	look := panelLook{hotkey: 0x1d, unicode: true, canSuspend: true}
	v := layout(80, 24, entries(sample), "", look)
	if v.top != 0 || v.left+v.width != 80 || v.width != minWidth {
		t.Fatalf("placement: %+v", v)
	}
	lines := v.texts()
	for i, l := range lines {
		if w := strWidth(l); w != v.width {
			t.Errorf("line %d is %d wide, want %d: %q", i, w, v.width, l)
		}
	}
	all := strings.Join(lines, "\n")
	t.Log("\n" + all)
	for _, want := range []string{"Shortcuts", "^] close", "Host shortcuts", "Global shortcuts", "Esc close", "^]^] sends ^]", "^Z suspends hop"} {
		if !strings.Contains(all, want) {
			t.Errorf("no %q", want)
		}
	}
	host, global := strings.Index(all, "Host shortcuts"), strings.Index(all, "Global shortcuts")
	if !(host < strings.Index(all, "Git status") && strings.Index(all, "Git log") < global && global < strings.Index(all, "Update")) {
		t.Error("host shortcuts are not listed first, under their header")
	}
	for _, l := range lines {
		if strings.Contains(l, "Update") && (!strings.Contains(l, "sudo apt update &&") || !strings.Contains(l, "…") || strings.Contains(l, "-y")) {
			t.Errorf("a long command is not cut with an ellipsis: %q", l)
		}
	}
	// The headers differ in colour, not only in text.
	var hs, gs style
	for _, l := range v.lines {
		for _, s := range l {
			switch s.text {
			case "Host shortcuts":
				hs = s.st
			case "Global shortcuts":
				gs = s.st
			}
		}
	}
	if hs == gs || hs.sgr() == styleNormal.sgr() {
		t.Errorf("header styles %v and %v", hs, gs)
	}
}

func TestLayoutPrefixAndEmpty(t *testing.T) {
	look := panelLook{hotkey: 0x1d, unicode: false}
	all := strings.Join(layout(80, 24, entries(sample), "g", look).texts(), "\n")
	if !strings.Contains(all, "Shortcuts: g") || !strings.Contains(all, "Git log") || strings.Contains(all, "Update") || strings.Contains(all, "Global") {
		t.Errorf("after g, only what g starts:\n%s", all)
	}
	if strings.ContainsAny(all, "─│┌…") {
		t.Errorf("ASCII look draws Unicode:\n%s", all)
	}
	empty := strings.Join(layout(80, 24, nil, "", look).texts(), "\n")
	if !strings.Contains(empty, "No shortcuts.") || !strings.Contains(empty, "hop shortcut add") {
		t.Errorf("no shortcuts:\n%s", empty)
	}
}

func TestLayoutSmall(t *testing.T) {
	look := panelLook{hotkey: 0x1d, unicode: true}
	v := layout(25, 24, entries(sample), "", look)
	if len(v.lines) != 1 || v.left+v.width != 25 || v.lines[0][0].st != styleBar {
		t.Fatalf("narrow: %+v", v)
	}
	if got := v.texts()[0]; !strings.Contains(got, "gs gl u d") {
		t.Errorf("bar: %q", got)
	}
	if v := layout(80, 4, entries(sample), "", look); len(v.lines) != 1 {
		t.Errorf("short: %d lines", len(v.lines))
	}
	// A screen with room for some of the list shows how many it left out.
	many := []Shortcut{}
	for _, k := range "abcdefghijklmnopqrstuvwxyz" {
		many = append(many, Shortcut{Keys: string(k), Name: "n", Command: "c"})
	}
	v = layout(80, 12, entries(many), "", look)
	if v.height() > 11 {
		t.Errorf("%d lines on a 12-line screen", v.height())
	}
	if all := strings.Join(v.texts(), "\n"); !strings.Contains(all, "… 20 more") {
		t.Errorf("cut list:\n%s", all)
	}
}

func TestEntriesNeutralizeAndOrder(t *testing.T) {
	es := entries([]Shortcut{
		{Keys: "x", Name: "\x1b[31mred\x1b[2J", Command: "rm\x1b[2J -rf\x00 /tmp/x\x07‮", Enter: true},
		{Keys: "x", Name: "host x", Command: "h", Host: true},
		{Keys: "", Name: "no keys"},
		{Keys: "abc", Name: "too long"},
		{Keys: "\x01", Name: "control"},
		{Keys: "y", Name: "\x9bC1", Command: "ok"},
	})
	if len(es) != 2 || es[0].name != "host x" || es[1].keys != "y" {
		t.Fatalf("entries: %+v", es)
	}
	e := entries([]Shortcut{{Keys: "x", Name: "\x1b[31mred\x1b[2J", Command: "rm\x1b[2J -rf\x00 /tmp/x\x07‮"}})[0]
	if e.name != "^[[31mred^[[2J" || e.command != "rm^[[2J -rf^@ /tmp/x^G�" {
		t.Errorf("drawn as %q, %q", e.name, e.command)
	}
	if e.typed != "rm[2J -rf /tmp/x‮" {
		t.Errorf("typed as %q", e.typed)
	}
	if es[1].name != "�C1" {
		t.Errorf("C1 drawn as %q", es[1].name)
	}
}
