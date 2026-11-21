package termpanel

import (
	"fmt"
	"strings"
	"testing"
)

// text returns row r of the current screen as a string, a blank as a
// space and a wide character once.
func (s *screen) text(r int) string {
	var b strings.Builder
	for _, c := range s.grid()[r] {
		switch {
		case c.tail:
		case c.s == "":
			b.WriteByte(' ')
		default:
			b.WriteString(c.s)
		}
	}
	return b.String()
}

func feed(s *screen, parts ...string) {
	for _, p := range parts {
		s.Write([]byte(p))
	}
}

func TestScreenPrintWrapScroll(t *testing.T) {
	s := newScreen(5, 3)
	feed(s, "abcdefg")
	if got := s.text(0) + "|" + s.text(1); got != "abcde|fg   " {
		t.Fatalf("wrap: %q", got)
	}
	feed(s, "\r\n1\r\n2")
	if got := s.text(0) + "|" + s.text(2); got != "fg   |2    " {
		t.Fatalf("scroll: %q", got)
	}
	// A pending wrap: the cursor stays on the last column until the
	// next character.
	s = newScreen(5, 3)
	feed(s, "abcde")
	if s.cur.col != 4 || !s.cur.wrap || s.cur.row != 0 {
		t.Fatalf("pending wrap: %+v", s.cur)
	}
	feed(s, "\r")
	if s.cur.wrap || s.cur.col != 0 {
		t.Fatalf("CR clears the wrap: %+v", s.cur)
	}
}

func TestScreenScrollRegionAndLines(t *testing.T) {
	s := newScreen(4, 5)
	feed(s, "a\r\nb\r\nc\r\nd\r\ne")
	feed(s, "\x1b[2;4r") // rows 2-4
	if s.cur.row != 0 || s.cur.col != 0 {
		t.Fatalf("DECSTBM homes: %+v", s.cur)
	}
	feed(s, "\x1b[4H\n") // at the bottom margin: scrolls rows 2-4
	got := []string{s.text(0), s.text(1), s.text(2), s.text(3), s.text(4)}
	if want := []string{"a   ", "c   ", "d   ", "    ", "e   "}; fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("region scroll: %q", got)
	}
	feed(s, "\x1b[2H\x1b[L") // insert a line at row 2
	if s.text(1) != "    " || s.text(2) != "c   " || s.text(3) != "d   " {
		t.Fatalf("IL: %q %q %q", s.text(1), s.text(2), s.text(3))
	}
	feed(s, "\x1b[M")
	if s.text(1) != "c   " || s.text(4) != "e   " {
		t.Fatalf("DL: %q %q", s.text(1), s.text(4))
	}
	feed(s, "\x1b[H\x1bM") // RI at the top of the screen, outside the region
	if s.text(0) != "a   " || s.cur.row != 0 {
		t.Fatalf("RI outside the region: %q %+v", s.text(0), s.cur)
	}
}

func TestScreenErase(t *testing.T) {
	s := newScreen(6, 2)
	feed(s, "abcdef\r\nghijkl\x1b[1;3H")
	feed(s, "\x1b[41m\x1b[K")
	if s.text(0) != "ab    " || s.grid()[0][3].pen.bg != (color{colorBasic, 1}) {
		t.Fatalf("EL keeps the background: %q %+v", s.text(0), s.grid()[0][3])
	}
	feed(s, "\x1b[0m\x1b[2;3H\x1b[1K")
	if s.text(1) != "   jkl" {
		t.Fatalf("EL 1: %q", s.text(1))
	}
	feed(s, "\x1b[2;2H\x1b[2P")
	if s.text(1) != " jkl  " {
		t.Fatalf("DCH: %q", s.text(1))
	}
	feed(s, "\x1b[2@")
	if s.text(1) != "   jkl" {
		t.Fatalf("ICH: %q", s.text(1))
	}
	feed(s, "\x1b[2J")
	if s.text(0) != "      " || s.text(1) != "      " {
		t.Fatal("ED 2")
	}
}

func TestScreenWideAndCombining(t *testing.T) {
	s := newScreen(6, 2)
	feed(s, "a日b")
	g := s.grid()[0]
	if !g[1].wide || !g[2].tail || g[3].s != "b" || s.cur.col != 4 {
		t.Fatalf("wide: %+v cur %+v", g[:4], s.cur)
	}
	feed(s, "\x1b[1;3Hx") // over the tail: the head goes too
	if g[1].s != "" || g[1].wide || g[2].s != "x" {
		t.Fatalf("split wide: %+v", g[:4])
	}
	feed(s, "\x1b[2;1Hé")
	if s.grid()[1][0].s != "é" || s.cur.col != 1 {
		t.Fatalf("combining: %+v", s.grid()[1][0])
	}
	// A wide character that does not fit at the end of a line wraps.
	s = newScreen(3, 2)
	feed(s, "ab日")
	if s.text(0) != "ab " || !s.grid()[1][0].wide {
		t.Fatalf("wide wrap: %q %+v", s.text(0), s.grid()[1][:2])
	}
}

func TestScreenAlternateAndSavedCursor(t *testing.T) {
	s := newScreen(10, 3)
	feed(s, "main\x1b[2;3H\x1b7") // DECSC on the normal screen
	if !s.main.live {
		t.Fatal("DECSC makes the slot live")
	}
	feed(s, "\x1b[3;6H\x1b[?1049h")
	if !s.altActive || s.text(0) != "          " || s.main.live || s.main.saved.row != 2 || s.main.saved.col != 5 {
		t.Fatalf("1049h: alt %v %q live %v saved %+v", s.altActive, s.text(0), s.main.live, s.main.saved)
	}
	feed(s, "alt\x1b[3;5H\x1b7\x1b[H")
	if !s.alt.live || s.alt.saved.row != 2 {
		t.Fatal("DECSC on the alternate screen has its own slot")
	}
	feed(s, "\x1b[?1049l")
	if s.altActive || s.text(0) != "main      " || s.cur.row != 2 || s.cur.col != 5 {
		t.Fatalf("1049l: %q %+v", s.text(0), s.cur)
	}
	feed(s, "\x1b[?47h")
	if s.text(2) != "     alt  " { // 1049h left the cursor where it was
		t.Fatalf("47 does not clear: %q", s.text(2))
	}
	feed(s, "\x1b[?1047l\x1b[?47h")
	if s.text(2) != "          " {
		t.Fatalf("1047l clears the alternate screen: %q", s.text(2))
	}
}

func TestScreenModes(t *testing.T) {
	s := newScreen(10, 5)
	feed(s, "\x1b[?2004h\x1b[?1000h\x1b[?25l\x1b[4h\x1b=\x1b(0")
	if !s.bracketed || !s.modes[1000] || s.visible || !s.insert || !s.keypad || s.cur.g[0] != '0' {
		t.Fatalf("modes: %+v", s)
	}
	feed(s, "q")
	if c := s.grid()[0][0]; !c.dec || c.s != "q" {
		t.Fatalf("DEC graphics: %+v", c)
	}
	feed(s, "\x1b[?2004l\x1b[?1000l\x1b[?25h\x1b[4l\x1b>\x1b(B")
	if s.bracketed || s.modes[1000] || !s.visible || s.insert || s.keypad || s.cur.g[0] != 'B' {
		t.Fatalf("modes off: %+v", s)
	}
	feed(s, "\x1b[2;4r\x1b[?6h\x1b[1;1Hx")
	if s.grid()[1][0].s != "x" {
		t.Fatal("origin mode addresses from the region's top")
	}
}

func TestScreenGround(t *testing.T) {
	s := newScreen(10, 2)
	for _, part := range []string{"\x1b", "\x1b[3", "\x1b]0;title", "\xe6\x97"} {
		s = newScreen(10, 2)
		feed(s, part)
		if s.ground() {
			t.Errorf("%q: ground, want in a sequence", part)
		}
	}
	feed(s, "\xa5")
	if !s.ground() || s.grid()[0][0].s != "日" {
		t.Fatalf("UTF-8 across writes: %+v", s.grid()[0][0])
	}
	feed(s, "\x1b]0;t\x07")
	if !s.ground() {
		t.Fatal("OSC ended by BEL")
	}
	feed(s, "\x1bP1$r0m\x1b\\")
	if !s.ground() || s.text(1) != "          " {
		t.Fatal("DCS ended by ST is not printed")
	}
}

func TestPenRoundTrip(t *testing.T) {
	for _, sgr := range []string{
		"\x1b[1;3;4;31;42m", "\x1b[2;5;7;8;9;53m", "\x1b[38;5;200;48;2;1;2;3m",
		"\x1b[4:3;58:2::10:20:30m", "\x1b[21;95;104m", "\x1b[38:2:7:8:9m",
	} {
		s := newScreen(4, 1)
		feed(s, sgr)
		p := s.cur.pen
		s2 := newScreen(4, 1)
		s2.Write(p.sgr(nil))
		if s2.cur.pen != p {
			t.Errorf("%q: %+v sent as %q reads back as %+v", sgr, p, p.sgr(nil), s2.cur.pen)
		}
	}
	s := newScreen(4, 1)
	feed(s, "\x1b[4:3;38;2;1;2;3;48:5:7;58:2::10:20:30m")
	want := pen{underline: 3, fg: color{colorRGB, 0x010203}, bg: color{colorIndexed, 7}, ul: color{colorRGB, 0x0a141e}}
	if s.cur.pen != want {
		t.Fatalf("colours: %+v, want %+v", s.cur.pen, want)
	}
	feed(s, "\x1b[1;31m\x1b[22;39m\x1b[49;59;24m")
	if s.cur.pen != (pen{}) {
		t.Fatalf("22 and 39 reset: %+v", s.cur.pen)
	}
}

// TestPaintReproduces checks the painter against the model: a screen
// painted onto a blank one gives the same cells.
func TestPaintReproduces(t *testing.T) {
	src := newScreen(20, 6)
	feed(src, "\x1b[31mred\x1b[0m plain \x1b[1;44mbold\x1b[0m\r\n",
		"日本語 wide\r\n",
		"\x1b(0lqqk\x1b(B box\r\n",
		"\x1b[42m\x1b[K\x1b[0mgreen line erased\r\n",
		"é \x1b[4:3mcurly\x1b[0m",
		"\x1b[6;18Hend")
	dst := newScreen(20, 6)
	feed(dst, "garbage everywhere garbage everywhere garbage")
	w := &painter{}
	w.screen(src.grid())
	dst.Write(w.b)
	for r := range src.rows {
		for c := range src.cols {
			if a, b := src.grid()[r][c], dst.grid()[r][c]; a != b {
				t.Errorf("cell %d,%d: painted %+v, want %+v", r, c, b, a)
			}
		}
	}
	// A row painted from a column inside a wide character starts at its
	// head.
	w = &painter{}
	w.row(src.grid()[1], 1, 1, false)
	if !strings.HasPrefix(string(w.b), "\x1b[2;1H") {
		t.Errorf("row from a tail: %q", w.b)
	}
}

func TestScreenResize(t *testing.T) {
	s := newScreen(6, 4)
	feed(s, "a\r\nb\r\nc\r\nd日")
	s.Resize(4, 2)
	if s.text(0) != "c   " || s.text(1) != "d日 " || s.cur.row != 1 {
		t.Fatalf("shrink keeps the cursor's line: %q %q %+v", s.text(0), s.text(1), s.cur)
	}
	s.Resize(2, 3)
	if s.text(1) != "d " || s.text(2) != "  " {
		t.Fatalf("a cut wide character is blanked: %q %q", s.text(1), s.text(2))
	}
	if s.top != 0 || s.bot != 2 {
		t.Fatal("the region is the whole screen")
	}
}
