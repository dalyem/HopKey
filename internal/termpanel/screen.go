package termpanel

import (
	"unicode/utf8"
)

// screen is a model of what the remote side's output has put on the
// user's terminal: the cells of the normal and alternate screens, the
// cursor, and the modes that drawing over the screen has to respect or
// put back. Every byte of output still goes to the terminal as it came;
// the model is only read to draw over the screen and to repaint it, so a
// sequence it does not know costs at most a wrong cell under the panel.
//
// It follows xterm where terminals differ: erasing uses the current
// background colour, the saved cursor (DECSC) is kept per screen, and
// 1049 saves the cursor in the normal screen's slot. It keeps no
// scrollback, and a resize clips lines rather than rewrapping them.
type screen struct {
	cols, rows int
	main, alt  buffer
	altActive  bool
	cur        cursor
	top, bot   int // scroll region, inclusive rows
	autowrap   bool
	insert     bool // IRM
	visible    bool // DECTCEM
	keypad     bool // DECKPAM
	bracketed  bool // 2004, bracketed paste
	modes      map[int]bool
	tabs       []bool
	last       rune // last printed character, for REP

	p parser
}

// cell is one column of the screen. A two-column character is a wide
// head followed by a tail; s is "" for a blank.
type cell struct {
	s    string
	pen  pen
	wide bool
	tail bool
	dec  bool // drawn from the DEC special graphics set
}

// cursor is the cursor's position and the state DECSC saves with it.
type cursor struct {
	row, col int
	wrap     bool // pending wrap: the last column has just been written
	pen      pen
	g        [4]byte // designated sets: 'B' ASCII, '0' DEC special graphics
	gl       int     // the set in GL: 0 (SI) or 1 (SO)
	origin   bool    // DECOM
}

type buffer struct {
	cells [][]cell
	saved cursor
	// live is that the remote side saved the cursor itself (DECSC,
	// SCOSC or 1048) and may restore it: the slot is not free to use.
	live bool
}

// trackedModes are the DEC private modes that change what the terminal
// sends or how it scrolls. They are turned off while hop is suspended,
// so the local shell gets a plain terminal, and on again after.
var trackedModes = []int{1, 9, 1000, 1001, 1002, 1003, 1004, 1005, 1006, 1007, 1015, 1016, 2004}

func newScreen(cols, rows int) *screen {
	s := &screen{modes: map[int]bool{}}
	s.cols, s.rows = max(cols, 1), max(rows, 1)
	s.reset()
	return s
}

// reset is RIS: everything as at power-on, both screens blank.
func (s *screen) reset() {
	s.main = buffer{cells: blankGrid(s.cols, s.rows)}
	s.alt = buffer{cells: blankGrid(s.cols, s.rows)}
	s.altActive = false
	s.cur = cursor{g: [4]byte{'B', 'B', 'B', 'B'}}
	s.main.saved, s.alt.saved = s.cur, s.cur
	s.top, s.bot = 0, s.rows-1
	s.autowrap, s.insert, s.visible, s.keypad, s.bracketed = true, false, true, false, false
	clear(s.modes)
	s.tabs = make([]bool, s.cols)
	for i := 8; i < s.cols; i += 8 {
		s.tabs[i] = true
	}
	s.last = 0
}

func blankGrid(cols, rows int) [][]cell {
	g := make([][]cell, rows)
	for i := range g {
		g[i] = make([]cell, cols)
	}
	return g
}

func (s *screen) buf() *buffer {
	if s.altActive {
		return &s.alt
	}
	return &s.main
}

func (s *screen) grid() [][]cell { return s.buf().cells }

// blank is an erased cell: xterm keeps the current background colour.
func (s *screen) blank() cell { return cell{pen: pen{bg: s.cur.pen.bg}} }

// Write feeds output from the remote side through the model.
func (s *screen) Write(b []byte) (int, error) {
	for _, c := range b {
		s.p.feed(s, c)
	}
	return len(b), nil
}

// ground says whether the output so far ends between sequences and
// characters, so that something else can be written to the terminal
// without landing inside one.
func (s *screen) ground() bool { return s.p.state == stGround && s.p.need == 0 }

// abort drops a sequence the output left unfinished, as the terminal
// does on CAN.
func (s *screen) abort() { s.p.state, s.p.need = stGround, 0 }

// Resize changes the screen size: lines are cut or padded, not rewrapped,
// and the scroll region becomes the whole screen.
func (s *screen) Resize(cols, rows int) {
	cols, rows = max(cols, 1), max(rows, 1)
	if cols == s.cols && rows == s.rows {
		return
	}
	for _, b := range []*buffer{&s.main, &s.alt} {
		cur := &b.saved
		if b == s.buf() {
			cur = &s.cur
		}
		g := b.cells
		// Keep the cursor's line on the screen, as terminals do, by
		// dropping lines from the top.
		if drop := cur.row - (rows - 1); drop > 0 {
			g = g[drop:]
			cur.row -= drop
		}
		for len(g) < rows {
			g = append(g, nil)
		}
		g = g[:rows]
		for i, line := range g {
			n := make([]cell, cols)
			copy(n, line)
			if cols < len(line) && n[cols-1].wide {
				n[cols-1] = blankOf(n[cols-1])
			}
			g[i] = n
		}
		b.cells = g
	}
	for _, c := range []*cursor{&s.cur, &s.main.saved, &s.alt.saved} {
		c.row, c.col = min(c.row, rows-1), min(c.col, cols-1)
		c.wrap = false
	}
	tabs := make([]bool, cols)
	copy(tabs, s.tabs)
	for i := (len(s.tabs) + 7) / 8 * 8; i < cols; i += 8 {
		tabs[i] = true
	}
	s.tabs = tabs
	s.cols, s.rows = cols, rows
	s.top, s.bot = 0, rows-1
}

// print puts r at the cursor and moves the cursor on.
func (s *screen) print(r rune) {
	dec := false
	if s.cur.g[s.cur.gl] == '0' && r >= 0x5f && r <= 0x7e {
		dec = true
	}
	w := runeWidth(r)
	if w == 0 {
		s.combine(r)
		return
	}
	s.last = r
	if s.cur.wrap && s.autowrap {
		s.cur.col = 0
		s.index()
	}
	s.cur.wrap = false
	if w == 2 && s.cur.col == s.cols-1 {
		if !s.autowrap || s.cols < 2 {
			return
		}
		s.grid()[s.cur.row][s.cur.col] = s.blank()
		s.cur.col = 0
		s.index()
	}
	line := s.grid()[s.cur.row]
	if s.insert {
		s.insertBlanks(w)
	}
	s.unsplit(line, s.cur.col)
	if w == 2 {
		s.unsplit(line, s.cur.col+1)
	}
	line[s.cur.col] = cell{s: string(r), pen: s.cur.pen, wide: w == 2, dec: dec}
	if w == 2 {
		line[s.cur.col+1] = cell{pen: s.cur.pen, tail: true}
	}
	if s.cur.col+w >= s.cols {
		s.cur.col = s.cols - 1
		s.cur.wrap = s.autowrap
	} else {
		s.cur.col += w
	}
}

// combine adds a zero-width character to the one before the cursor.
func (s *screen) combine(r rune) {
	col := s.cur.col - 1
	if s.cur.wrap {
		col = s.cur.col
	}
	if col < 0 {
		return
	}
	line := s.grid()[s.cur.row]
	if line[col].tail && col > 0 {
		col--
	}
	if line[col].s != "" && len(line[col].s) < 32 {
		line[col].s += string(r)
	}
}

// unsplit blanks the other half of a wide character at col, which is
// about to be overwritten.
func (s *screen) unsplit(line []cell, col int) {
	switch {
	case line[col].wide && col+1 < len(line):
		line[col+1] = blankOf(line[col+1])
	case line[col].tail && col > 0:
		line[col-1] = blankOf(line[col-1])
	}
}

// blankOf is c erased: a blank keeps only its background colour.
func blankOf(c cell) cell { return cell{pen: pen{bg: c.pen.bg}} }

// index is IND (and LF): down a line, scrolling at the bottom margin.
func (s *screen) index() {
	switch {
	case s.cur.row == s.bot:
		s.scrollUp(s.top, s.bot, 1)
	case s.cur.row < s.rows-1:
		s.cur.row++
	}
}

// reverseIndex is RI: up a line, scrolling at the top margin.
func (s *screen) reverseIndex() {
	switch {
	case s.cur.row == s.top:
		s.scrollDown(s.top, s.bot, 1)
	case s.cur.row > 0:
		s.cur.row--
	}
}

func (s *screen) scrollUp(top, bot, n int) {
	g := s.grid()
	n = min(n, bot-top+1)
	copy(g[top:bot+1], g[top+n:bot+1])
	for i := bot - n + 1; i <= bot; i++ {
		g[i] = s.blankLine()
	}
}

func (s *screen) scrollDown(top, bot, n int) {
	g := s.grid()
	n = min(n, bot-top+1)
	copy(g[top+n:bot+1], g[top:bot+1-n])
	for i := top; i < top+n; i++ {
		g[i] = s.blankLine()
	}
}

func (s *screen) blankLine() []cell {
	line := make([]cell, s.cols)
	b := s.blank()
	for i := range line {
		line[i] = b
	}
	return line
}

// erase blanks columns [from, to) of row.
func (s *screen) erase(row, from, to int) {
	line := s.grid()[row]
	from, to = max(from, 0), min(to, s.cols)
	if from >= to {
		return
	}
	s.unsplit(line, from)
	s.unsplit(line, to-1)
	b := s.blank()
	for i := from; i < to; i++ {
		line[i] = b
	}
}

func (s *screen) insertBlanks(n int) {
	line := s.grid()[s.cur.row]
	col := s.cur.col
	n = min(n, s.cols-col)
	if line[col].tail {
		s.unsplit(line, col)
		line[col] = blankOf(line[col])
	}
	copy(line[col+n:], line[col:s.cols-n])
	b := s.blank()
	for i := col; i < col+n; i++ {
		line[i] = b
	}
	if line[s.cols-1].wide {
		line[s.cols-1] = b
	}
}

func (s *screen) deleteChars(n int) {
	line := s.grid()[s.cur.row]
	col := s.cur.col
	n = min(n, s.cols-col)
	s.unsplit(line, col)
	if col+n < s.cols && line[col+n].tail {
		line[col+n] = blankOf(line[col+n])
	}
	copy(line[col:], line[col+n:])
	b := s.blank()
	for i := s.cols - n; i < s.cols; i++ {
		line[i] = b
	}
}

// moveTo puts the cursor at row and col of the screen (0-based), kept in
// the scroll region in origin mode.
func (s *screen) moveTo(row, col int) {
	top, bot := 0, s.rows-1
	if s.cur.origin {
		top, bot = s.top, s.bot
	}
	s.cur.row = min(max(row, top), bot)
	s.cur.col = min(max(col, 0), s.cols-1)
	s.cur.wrap = false
}

// moveRel moves the cursor up or down, stopping at the scroll margins
// when it starts inside them.
func (s *screen) moveRows(n int) {
	row := s.cur.row + n
	top, bot := 0, s.rows-1
	if s.cur.row >= s.top && s.cur.row <= s.bot {
		top, bot = s.top, s.bot
	}
	s.cur.row = min(max(row, top), bot)
	s.cur.wrap = false
}

// home puts the cursor at the top left, of the scroll region in origin
// mode.
func (s *screen) home() {
	if s.cur.origin {
		s.moveTo(s.top, 0)
	} else {
		s.moveTo(0, 0)
	}
}

func (s *screen) tab(n int) {
	for ; n > 0 && s.cur.col < s.cols-1; n-- {
		s.cur.col++
		for s.cur.col < s.cols-1 && !s.tabs[s.cur.col] {
			s.cur.col++
		}
	}
	s.cur.wrap = false
}

func (s *screen) backTab(n int) {
	for ; n > 0 && s.cur.col > 0; n-- {
		s.cur.col--
		for s.cur.col > 0 && !s.tabs[s.cur.col] {
			s.cur.col--
		}
	}
	s.cur.wrap = false
}

func (s *screen) saveCursor() {
	b := s.buf()
	b.saved, b.live = s.cur, true
}

func (s *screen) restoreCursor() {
	b := s.buf()
	s.cur = b.saved
	s.cur.row, s.cur.col = min(s.cur.row, s.rows-1), min(s.cur.col, s.cols-1)
}

// switchScreen moves to the alternate screen (alt) or back to the normal
// one, clearing the alternate screen when clear says to.
func (s *screen) switchScreen(alt, clear bool) {
	if alt && clear {
		s.alt.cells = blankGrid(s.cols, s.rows)
	}
	if !alt && clear && s.altActive {
		s.alt.cells = blankGrid(s.cols, s.rows)
	}
	s.altActive = alt
}

func (s *screen) control(c byte) {
	switch c {
	case 0x08: // BS
		if s.cur.col > 0 {
			s.cur.col--
		}
		s.cur.wrap = false
	case 0x09: // HT
		s.tab(1)
	case 0x0a, 0x0b, 0x0c: // LF, VT, FF
		s.index()
		s.cur.wrap = false
	case 0x0d: // CR
		s.cur.col, s.cur.wrap = 0, false
	case 0x0e: // SO
		s.cur.gl = 1
	case 0x0f: // SI
		s.cur.gl = 0
	}
}

func (s *screen) escDispatch(inter []byte, final byte) {
	if len(inter) == 1 {
		switch inter[0] {
		case '(', ')', '*', '+':
			s.cur.g[inter[0]-'('] = final
		case '#':
			if final == '8' { // DECALN
				for _, line := range s.grid() {
					for i := range line {
						line[i] = cell{s: "E"}
					}
				}
				s.top, s.bot = 0, s.rows-1
				s.moveTo(0, 0)
			}
		}
		return
	}
	if len(inter) > 1 {
		return
	}
	switch final {
	case '7':
		s.saveCursor()
	case '8':
		s.restoreCursor()
	case 'D':
		s.index()
		s.cur.wrap = false
	case 'E':
		s.cur.col = 0
		s.index()
		s.cur.wrap = false
	case 'M':
		s.reverseIndex()
		s.cur.wrap = false
	case 'H':
		s.tabs[s.cur.col] = true
	case 'c':
		s.reset()
	case '=':
		s.keypad = true
	case '>':
		s.keypad = false
	}
}

func (s *screen) csiDispatch(prefix byte, inter []byte, final byte, params [][]int) {
	arg := func(i, def int) int {
		if i < len(params) && params[i][0] > 0 {
			return params[i][0]
		}
		return def
	}
	if len(inter) == 1 && inter[0] == '!' && final == 'p' && prefix == 0 {
		s.softReset()
		return
	}
	if len(inter) > 0 {
		return
	}
	if prefix == '?' {
		if final == 'h' || final == 'l' {
			for _, p := range params {
				s.decMode(p[0], final == 'h')
			}
		}
		return
	}
	if prefix != 0 {
		return
	}
	switch final {
	case '@':
		s.insertBlanks(arg(0, 1))
		s.cur.wrap = false
	case 'A':
		s.moveRows(-arg(0, 1))
	case 'B', 'e':
		s.moveRows(arg(0, 1))
	case 'C', 'a':
		s.cur.col = min(s.cur.col+arg(0, 1), s.cols-1)
		s.cur.wrap = false
	case 'D':
		s.cur.col = max(s.cur.col-arg(0, 1), 0)
		s.cur.wrap = false
	case 'E':
		s.moveRows(arg(0, 1))
		s.cur.col = 0
	case 'F':
		s.moveRows(-arg(0, 1))
		s.cur.col = 0
	case 'G', '`':
		s.cur.col = min(arg(0, 1)-1, s.cols-1)
		s.cur.wrap = false
	case 'H', 'f':
		row := arg(0, 1) - 1
		if s.cur.origin {
			row += s.top
		}
		s.moveTo(row, arg(1, 1)-1)
	case 'I':
		s.tab(arg(0, 1))
	case 'J':
		switch arg(0, 0) {
		case 0:
			s.erase(s.cur.row, s.cur.col, s.cols)
			for r := s.cur.row + 1; r < s.rows; r++ {
				s.erase(r, 0, s.cols)
			}
		case 1:
			for r := 0; r < s.cur.row; r++ {
				s.erase(r, 0, s.cols)
			}
			s.erase(s.cur.row, 0, s.cur.col+1)
		case 2:
			for r := 0; r < s.rows; r++ {
				s.erase(r, 0, s.cols)
			}
		}
	case 'K':
		switch arg(0, 0) {
		case 0:
			s.erase(s.cur.row, s.cur.col, s.cols)
		case 1:
			s.erase(s.cur.row, 0, s.cur.col+1)
		case 2:
			s.erase(s.cur.row, 0, s.cols)
		}
	case 'L', 'M':
		if s.cur.row < s.top || s.cur.row > s.bot {
			return
		}
		if final == 'L' {
			s.scrollDown(s.cur.row, s.bot, arg(0, 1))
		} else {
			s.scrollUp(s.cur.row, s.bot, arg(0, 1))
		}
		s.cur.col, s.cur.wrap = 0, false
	case 'P':
		s.deleteChars(arg(0, 1))
		s.cur.wrap = false
	case 'S':
		s.scrollUp(s.top, s.bot, arg(0, 1))
	case 'T':
		if len(params) <= 1 {
			s.scrollDown(s.top, s.bot, arg(0, 1))
		}
	case 'X':
		s.erase(s.cur.row, s.cur.col, s.cur.col+arg(0, 1))
		s.cur.wrap = false
	case 'Z':
		s.backTab(arg(0, 1))
	case 'b':
		if s.last != 0 {
			for n := min(arg(0, 1), s.cols*s.rows); n > 0; n-- {
				s.print(s.last)
			}
		}
	case 'd':
		row := arg(0, 1) - 1
		if s.cur.origin {
			row += s.top
		}
		s.moveTo(row, s.cur.col)
	case 'g':
		switch arg(0, 0) {
		case 0:
			s.tabs[s.cur.col] = false
		case 3:
			clear(s.tabs)
		}
	case 'h', 'l':
		for _, p := range params {
			if p[0] == 4 {
				s.insert = final == 'h'
			}
		}
	case 'm':
		s.cur.pen.apply(params)
	case 'r':
		top, bot := arg(0, 1)-1, arg(1, s.rows)-1
		bot = min(bot, s.rows-1)
		if top < bot {
			s.top, s.bot = top, bot
			s.home()
		}
	case 's':
		if len(params) == 0 {
			s.saveCursor()
		}
	case 'u':
		if len(params) == 0 {
			s.restoreCursor()
		}
	}
}

func (s *screen) softReset() {
	s.insert, s.cur.origin, s.autowrap, s.visible, s.keypad = false, false, true, true, false
	s.cur.pen = pen{}
	s.cur.g, s.cur.gl = [4]byte{'B', 'B', 'B', 'B'}, 0
	s.top, s.bot = 0, s.rows-1
	b := s.buf()
	b.saved, b.live = cursor{g: s.cur.g}, false
}

func (s *screen) decMode(m int, on bool) {
	switch m {
	case 6:
		s.cur.origin = on
		s.home()
	case 7:
		s.autowrap = on
		if !on {
			s.cur.wrap = false
		}
	case 25:
		s.visible = on
	case 47:
		s.switchScreen(on, false)
	case 1047:
		s.switchScreen(on, !on)
	case 1048:
		if on {
			s.saveCursor()
		} else {
			s.restoreCursor()
		}
	case 1049:
		if on {
			if !s.altActive {
				s.main.saved, s.main.live = s.cur, false
			}
			s.switchScreen(true, true)
		} else {
			s.switchScreen(false, false)
			s.cur = s.main.saved
			s.cur.row, s.cur.col = min(s.cur.row, s.rows-1), min(s.cur.col, s.cols-1)
		}
	case 2004:
		s.bracketed = on
		s.modes[m] = on
	default:
		for _, t := range trackedModes {
			if t == m {
				s.modes[m] = on
			}
		}
	}
}

// Parser states, after the DEC/ANSI parser of vt100.net, with the
// sequences that only carry data (OSC, DCS, SOS, PM, APC) merged into
// one state that skips to their end.
const (
	stGround = iota
	stEscape
	stCSI
	stCSIIgnore
	stString
)

type parser struct {
	state  int
	inter  []byte
	prefix byte
	params [][]int
	sub    bool // the next digit belongs to a sub-parameter
	// UTF-8 decoding in the ground state
	u    [utf8.UTFMax]byte
	n    int
	need int
}

const maxParams = 32

func (p *parser) feed(s *screen, c byte) {
	if p.need > 0 {
		if c&0xc0 == 0x80 {
			p.u[p.n] = c
			p.n++
			if p.n == p.need {
				r, _ := utf8.DecodeRune(p.u[:p.n])
				p.need = 0
				s.print(r)
			}
			return
		}
		p.need = 0
		s.print(utf8.RuneError)
	}
	// Controls act in every state but a string's, which only ESC, CAN,
	// SUB and BEL end.
	switch {
	case c == 0x1b:
		p.state, p.inter = stEscape, p.inter[:0]
		return
	case c == 0x18 || c == 0x1a:
		p.state = stGround
		return
	case p.state == stString:
		if c == 0x07 {
			p.state = stGround
		}
		return
	case c < 0x20:
		s.control(c)
		return
	case c == 0x7f:
		return
	}
	switch p.state {
	case stGround:
		switch {
		case c < 0x80:
			s.print(rune(c))
		case c&0xe0 == 0xc0:
			p.u[0], p.n, p.need = c, 1, 2
		case c&0xf0 == 0xe0:
			p.u[0], p.n, p.need = c, 1, 3
		case c&0xf8 == 0xf0:
			p.u[0], p.n, p.need = c, 1, 4
		default:
			s.print(utf8.RuneError)
		}
	case stEscape:
		switch {
		case c >= 0x20 && c <= 0x2f:
			if len(p.inter) < 2 {
				p.inter = append(p.inter, c)
			}
		case len(p.inter) == 0 && c == '[':
			p.state, p.prefix, p.params, p.sub = stCSI, 0, p.params[:0], false
		case len(p.inter) == 0 && (c == ']' || c == 'P' || c == 'X' || c == '^' || c == '_'):
			p.state = stString
		case c >= 0x30 && c <= 0x7e:
			p.state = stGround
			s.escDispatch(p.inter, c)
		default:
			p.state = stGround
		}
	case stCSI:
		switch {
		case c >= '0' && c <= '9':
			if len(p.params) == 0 {
				p.params = append(p.params, []int{-1})
			}
			g := p.params[len(p.params)-1]
			v := &g[len(g)-1]
			if *v < 0 {
				*v = 0
			}
			*v = min(*v*10+int(c-'0'), 65535)
		case c == ';' || c == ':':
			if len(p.params) == 0 {
				p.params = append(p.params, []int{-1})
			}
			if c == ';' {
				if len(p.params) >= maxParams {
					p.state = stCSIIgnore
					return
				}
				p.params = append(p.params, []int{-1})
			} else {
				g := &p.params[len(p.params)-1]
				if len(*g) < 8 {
					*g = append(*g, -1)
				}
			}
		case c >= 0x3c && c <= 0x3f:
			if len(p.params) == 0 && p.prefix == 0 && len(p.inter) == 0 {
				p.prefix = c
			} else {
				p.state = stCSIIgnore
			}
		case c >= 0x20 && c <= 0x2f:
			if len(p.inter) < 2 {
				p.inter = append(p.inter, c)
			} else {
				p.state = stCSIIgnore
			}
		case c >= 0x40 && c <= 0x7e:
			p.state = stGround
			s.csiDispatch(p.prefix, p.inter, c, p.params)
		default:
			p.state = stCSIIgnore
		}
	case stCSIIgnore:
		if c >= 0x40 && c <= 0x7e {
			p.state = stGround
		}
	}
}
