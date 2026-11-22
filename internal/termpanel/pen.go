package termpanel

import "strconv"

type colorKind uint8

const (
	colorDefault colorKind = iota
	colorBasic             // SGR 30-37 and 90-97 (40-47, 100-107): 0-15
	colorIndexed           // SGR 38;5;n: 0-255
	colorRGB               // SGR 38;2;r;g;b
)

type color struct {
	kind colorKind
	v    uint32 // the index, or 0xrrggbb
}

type attr uint16

const (
	attrBold attr = 1 << iota
	attrFaint
	attrItalic
	attrBlink
	attrRapidBlink
	attrReverse
	attrInvisible
	attrStrike
	attrOverline
)

// pen is the SGR state that a cell is drawn with.
type pen struct {
	attrs      attr
	underline  uint8 // 0 none, 1 single, 2 double, 3 curly, 4 dotted, 5 dashed
	fg, bg, ul color
}

// apply runs an SGR sequence's parameters. Each parameter is a group of
// its colon-separated sub-parameters; -1 is one left out.
func (p *pen) apply(params [][]int) {
	if len(params) == 0 {
		*p = pen{}
		return
	}
	for i := 0; i < len(params); i++ {
		g := params[i]
		n := max(g[0], 0)
		switch {
		case n == 0:
			*p = pen{}
		case n == 1:
			p.attrs |= attrBold
		case n == 2:
			p.attrs |= attrFaint
		case n == 3:
			p.attrs |= attrItalic
		case n == 4:
			p.underline = 1
			if len(g) > 1 {
				p.underline = uint8(min(max(g[1], 0), 5))
			}
		case n == 5:
			p.attrs |= attrBlink
		case n == 6:
			p.attrs |= attrRapidBlink
		case n == 7:
			p.attrs |= attrReverse
		case n == 8:
			p.attrs |= attrInvisible
		case n == 9:
			p.attrs |= attrStrike
		case n == 21:
			p.underline = 2
		case n == 22:
			p.attrs &^= attrBold | attrFaint
		case n == 23:
			p.attrs &^= attrItalic
		case n == 24:
			p.underline = 0
		case n == 25:
			p.attrs &^= attrBlink | attrRapidBlink
		case n == 27:
			p.attrs &^= attrReverse
		case n == 28:
			p.attrs &^= attrInvisible
		case n == 29:
			p.attrs &^= attrStrike
		case n >= 30 && n <= 37:
			p.fg = color{colorBasic, uint32(n - 30)}
		case n == 38, n == 48, n == 58:
			c, ok, used := extColor(g, params[i+1:])
			i += used
			if ok {
				switch n {
				case 38:
					p.fg = c
				case 48:
					p.bg = c
				default:
					p.ul = c
				}
			}
		case n == 39:
			p.fg = color{}
		case n >= 40 && n <= 47:
			p.bg = color{colorBasic, uint32(n - 40)}
		case n == 49:
			p.bg = color{}
		case n == 53:
			p.attrs |= attrOverline
		case n == 55:
			p.attrs &^= attrOverline
		case n == 59:
			p.ul = color{}
		case n >= 90 && n <= 97:
			p.fg = color{colorBasic, uint32(n - 90 + 8)}
		case n >= 100 && n <= 107:
			p.bg = color{colorBasic, uint32(n - 100 + 8)}
		}
	}
}

// extColor reads the colour after 38, 48 or 58: from g's sub-parameters
// (38:5:n, 38:2::r:g:b, 38:2:r:g:b) when it has them, else from the
// parameters after it (38;5;n, 38;2;r;g;b). used is how many of those it
// took.
func extColor(g []int, rest [][]int) (c color, ok bool, used int) {
	v := func(x int) uint32 { return uint32(min(max(x, 0), 255)) }
	if len(g) > 1 {
		switch {
		case g[1] == 5 && len(g) >= 3:
			return color{colorIndexed, v(g[2])}, true, 0
		case g[1] == 2 && len(g) >= 6:
			return color{colorRGB, v(g[3])<<16 | v(g[4])<<8 | v(g[5])}, true, 0
		case g[1] == 2 && len(g) == 5:
			return color{colorRGB, v(g[2])<<16 | v(g[3])<<8 | v(g[4])}, true, 0
		}
		return c, false, 0
	}
	if len(rest) == 0 {
		return c, false, 0
	}
	switch rest[0][0] {
	case 5:
		if len(rest) >= 2 {
			return color{colorIndexed, v(rest[1][0])}, true, 2
		}
		return c, false, len(rest)
	case 2:
		if len(rest) >= 4 {
			return color{colorRGB, v(rest[1][0])<<16 | v(rest[2][0])<<8 | v(rest[3][0])}, true, 4
		}
		return c, false, len(rest)
	}
	return c, false, 1
}

// sgr appends the SGR sequence that sets exactly p, from a reset.
func (p pen) sgr(b []byte) []byte {
	b = append(b, "\x1b[0"...)
	for _, a := range []struct {
		bit  attr
		code string
	}{
		{attrBold, "1"}, {attrFaint, "2"}, {attrItalic, "3"}, {attrBlink, "5"},
		{attrRapidBlink, "6"}, {attrReverse, "7"}, {attrInvisible, "8"},
		{attrStrike, "9"}, {attrOverline, "53"},
	} {
		if p.attrs&a.bit != 0 {
			b = append(b, ';')
			b = append(b, a.code...)
		}
	}
	switch p.underline {
	case 0:
	case 1:
		b = append(b, ";4"...)
	case 2:
		b = append(b, ";21"...)
	default:
		b = append(b, ";4:"...)
		b = strconv.AppendInt(b, int64(p.underline), 10)
	}
	b = p.fg.sgr(b, 30, 90, 38)
	b = p.bg.sgr(b, 40, 100, 48)
	b = p.ul.sgr(b, -1, -1, 58)
	return append(b, 'm')
}

func (c color) sgr(b []byte, base, bright, ext int) []byte {
	switch {
	case c.kind == colorDefault:
		return b
	case c.kind == colorBasic && base >= 0 && c.v < 8:
		b = append(b, ';')
		return strconv.AppendInt(b, int64(base)+int64(c.v), 10)
	case c.kind == colorBasic && base >= 0:
		b = append(b, ';')
		return strconv.AppendInt(b, int64(bright)+int64(c.v)-8, 10)
	case c.kind == colorRGB:
		b = append(b, ';')
		b = strconv.AppendInt(b, int64(ext), 10)
		b = append(b, ";2;"...)
		b = strconv.AppendInt(b, int64(c.v>>16), 10)
		b = append(b, ';')
		b = strconv.AppendInt(b, int64(c.v>>8&0xff), 10)
		b = append(b, ';')
		return strconv.AppendInt(b, int64(c.v&0xff), 10)
	}
	b = append(b, ';')
	b = strconv.AppendInt(b, int64(ext), 10)
	b = append(b, ";5;"...)
	return strconv.AppendInt(b, int64(c.v), 10)
}

// painter writes model cells to the terminal, sending an SGR or a
// character set change only when the cell needs a different one. It
// leaves G0 as ASCII.
type painter struct {
	b   []byte
	pen pen
	dec bool
	set bool // pen is what the terminal has
}

func (w *painter) cup(row, col int) {
	w.b = append(w.b, "\x1b["...)
	w.b = strconv.AppendInt(w.b, int64(row+1), 10)
	w.b = append(w.b, ';')
	w.b = strconv.AppendInt(w.b, int64(col+1), 10)
	w.b = append(w.b, 'H')
}

func (w *painter) setPen(p pen) {
	if !w.set || p != w.pen {
		w.b = p.sgr(w.b)
		w.pen, w.set = p, true
	}
}

func (w *painter) setDEC(on bool) {
	if on != w.dec {
		if on {
			w.b = append(w.b, "\x1b(0"...)
		} else {
			w.b = append(w.b, "\x1b(B"...)
		}
		w.dec = on
	}
}

// cell writes c, with a space for a blank.
func (w *painter) cell(c cell) {
	w.setPen(c.pen)
	w.setDEC(c.dec)
	if c.s == "" {
		w.b = append(w.b, ' ')
	} else {
		w.b = append(w.b, c.s...)
	}
}

// row writes line from column from to its end, and leaves the cursor
// somewhere on it. An erased run is erased again (ECH, or EL at the end
// of the line), with its background colour, so that it is blank as it
// was rather than spaces; clear says the screen was just cleared, so a
// run with no colour at the end of the line can be left as it is.
func (w *painter) row(line []cell, r, from int, clear bool) {
	if from > 0 && line[from].tail {
		from--
	}
	w.cup(r, from)
	for c := from; c < len(line); {
		cl := line[c]
		if cl.tail {
			c++
			continue
		}
		if cl.s != "" {
			w.cell(cl)
			c++
			continue
		}
		n := 1
		for c+n < len(line) && line[c+n] == cl {
			n++
		}
		switch {
		case c+n == len(line) && clear && cl == (cell{}):
		case c+n == len(line):
			w.setPen(cl.pen)
			w.b = append(w.b, "\x1b[K"...)
		default:
			w.setPen(cl.pen)
			w.b = append(w.b, "\x1b["...)
			w.b = strconv.AppendInt(w.b, int64(n), 10)
			w.b = append(w.b, "X\x1b["...)
			w.b = strconv.AppendInt(w.b, int64(n), 10)
			w.b = append(w.b, 'C')
		}
		c += n
	}
}

// screen clears the screen and paints g on it.
func (w *painter) screen(g [][]cell) {
	w.b = append(w.b, "\x1b[0m\x1b[H\x1b[2J"...)
	w.pen, w.set = pen{}, true
	for r, line := range g {
		w.row(line, r, 0, true)
	}
	w.finish()
}

func (w *painter) finish() {
	w.setDEC(false)
}
