package termpanel

import (
	"fmt"
	"strings"
	"testing"
)

func kinds(ts []token) string {
	names := map[tokKind]string{tokText: "text", tokControl: "ctl", tokSeq: "seq", tokEsc: "esc",
		tokHotkey: "HOT", tokHotkeyUp: "up", tokPaste: "paste"}
	var out []string
	for _, t := range ts {
		out = append(out, fmt.Sprintf("%s:%q", names[t.kind], t.raw))
	}
	return strings.Join(out, " ")
}

func TestInputTokens(t *testing.T) {
	for _, c := range []struct {
		name string
		in   []string // separate reads
		want string
	}{
		{"keys", []string{"a\x1d\r"}, `text:"a" HOT:"\x1d" ctl:"\r"`},
		{"arrow", []string{"\x1b[A\x1bOP"}, `seq:"\x1b[A" seq:"\x1bOP"`},
		{"alt", []string{"\x1bx\x1b\x1d"}, `seq:"\x1bx" seq:"\x1b\x1d"`},
		{"esc esc", []string{"\x1b\x1b[B"}, `esc:"\x1b" seq:"\x1b[B"`},
		{"utf-8", []string{"é日"}, `text:"é" text:"日"`},
		{"utf-8 split", []string{"\xe6\x97", "\xa5x"}, `text:"日" text:"x"`},
		{"csi split", []string{"\x1b[", "1;5A"}, `seq:"\x1b[1;5A"`},
		{"osc reply", []string{"\x1b]11;rgb:0/0/0\x1b\\a"}, `seq:"\x1b]11;rgb:0/0/0\x1b\\" text:"a"`},
		{"paste", []string{"\x1b[200~a\x1db\x1b[201~\x1d"}, `paste:"\x1b[200~" paste:"a\x1db\x1b[201~" HOT:"\x1d"`},
		{"paste end split", []string{"\x1b[200~x\x1b[2", "01~\x1d"}, `paste:"\x1b[200~" paste:"x\x1b[2" paste:"01~" HOT:"\x1d"`},
		{"kitty", []string{"\x1b[93;5u\x1b[93;5:3u\x1b[93;69u\x1b[97;5u"}, `HOT:"\x1b[93;5u" up:"\x1b[93;5:3u" HOT:"\x1b[93;69u" seq:"\x1b[97;5u"`},
		{"modifyOtherKeys", []string{"\x1b[27;5;93~\x1b[27;5;94~"}, `HOT:"\x1b[27;5;93~" seq:"\x1b[27;5;94~"`},
		{"stray continuation", []string{"\x80a"}, `text:"\x80" text:"a"`},
	} {
		p := newInputParser(0x1d)
		var ts []token
		for _, in := range c.in {
			for _, tk := range p.feed([]byte(in)) {
				ts = append(ts, token{tk.kind, append([]byte(nil), tk.raw...)})
			}
		}
		if got := kinds(ts); got != c.want {
			t.Errorf("%s:\n got %s\nwant %s", c.name, got, c.want)
		}
		if p.held() {
			t.Errorf("%s: still holds %q", c.name, p.pending)
		}
	}
}

func TestInputFlush(t *testing.T) {
	p := newInputParser(0x1d)
	if ts := p.feed([]byte("a\x1b")); kinds(ts) != `text:"a"` || !p.held() {
		t.Fatalf("ESC at the end is held: %s", kinds(ts))
	}
	if ts := p.flush(); kinds(ts) != `esc:"\x1b"` {
		t.Fatalf("flushed ESC is the Esc key: %s", kinds(ts))
	}
	p.feed([]byte("\x1b[1"))
	if ts := p.flush(); kinds(ts) != `seq:"\x1b[1"` {
		t.Fatalf("an unfinished sequence goes as it is: %s", kinds(ts))
	}
}

func TestInputOtherHotkey(t *testing.T) {
	p := newInputParser(0x01) // Ctrl-A
	if got := kinds(p.feed([]byte("\x01\x1b[97;5u\x1d"))); got != `HOT:"\x01" HOT:"\x1b[97;5u" ctl:"\x1d"` {
		t.Fatal(got)
	}
}

// Every hotkey from Ctrl-A to Ctrl-Z, Ctrl-\ and Ctrl-] is the hotkey in
// the kitty keyboard protocol and in modifyOtherKeys too, with Caps Lock
// on or not; the same key with Shift is not.
func TestInputHotkeyForms(t *testing.T) {
	var hotkeys []byte
	for k := byte(0x01); k <= 0x1a; k++ {
		hotkeys = append(hotkeys, k)
	}
	hotkeys = append(hotkeys, 0x1c, 0x1d)
	for _, k := range hotkeys {
		code := int('a' + k - 1)
		if k >= 0x1c {
			code = int(k + 0x40)
		}
		in := fmt.Sprintf("%c\x1b[%d;5u\x1b[%d;69u\x1b[27;5;%d~\x1b[%d;6u", k, code, code, code, code)
		want := fmt.Sprintf(`HOT:%q HOT:"\x1b[%d;5u" HOT:"\x1b[%d;69u" HOT:"\x1b[27;5;%d~" seq:"\x1b[%d;6u"`, string(rune(k)), code, code, code, code)
		if got := kinds(newInputParser(k).feed([]byte(in))); got != want {
			t.Errorf("hotkey %#x:\n got %s\nwant %s", k, got, want)
		}
	}
}

// Ctrl-^ and Ctrl-_ are Shift with 6 and minus on many layouts. The kitty
// protocol reports the key without Shift, with Shift among the
// modifiers (and, when asked, the shifted key after a colon), and
// modifyOtherKeys the character Shift gives: Ctrl with ^ or 6, and with
// _ or -, with or without Shift, is the hotkey. Ctrl with Alt is not,
// nor is the other one's key.
func TestInputHotkeyShiftedForms(t *testing.T) {
	for _, c := range []struct {
		hotkey      byte
		base, shift int
		other       int
	}{{0x1e, '6', '^', '_'}, {0x1f, '-', '_', '^'}} {
		var in, want []string
		hot := func(s string) {
			in = append(in, s)
			want = append(want, fmt.Sprintf("HOT:%q", s))
		}
		hot(string(rune(c.hotkey)))
		for _, code := range []int{c.base, c.shift} {
			hot(fmt.Sprintf("\x1b[%d;5u", code))
			hot(fmt.Sprintf("\x1b[%d;6u", code))
			hot(fmt.Sprintf("\x1b[%d;70u", code))
			hot(fmt.Sprintf("\x1b[27;5;%d~", code))
			hot(fmt.Sprintf("\x1b[27;6;%d~", code))
		}
		hot(fmt.Sprintf("\x1b[%d:%d;6u", c.base, c.shift))
		for _, s := range []string{fmt.Sprintf("\x1b[%d;7u", c.shift), fmt.Sprintf("\x1b[%d;5u", c.other), fmt.Sprintf("\x1b[27;5;%d~", c.other)} {
			in = append(in, s)
			want = append(want, fmt.Sprintf("seq:%q", s))
		}
		if got := kinds(newInputParser(c.hotkey).feed([]byte(strings.Join(in, "")))); got != strings.Join(want, " ") {
			t.Errorf("hotkey %#x:\n got %s\nwant %s", c.hotkey, got, strings.Join(want, " "))
		}
	}
}
