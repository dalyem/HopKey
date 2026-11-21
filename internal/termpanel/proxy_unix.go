//go:build linux || darwin

package termpanel

import (
	"context"
	"math"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
	"golang.org/x/term"
)

const (
	// escWait is how long a lone ESC, or the start of a sequence, waits
	// for the rest before it is taken as it is: terminals send a
	// sequence in one write, so the rest is seldom later.
	escWait = 20 * time.Millisecond
	// openWait bounds how long opening the panel waits for the output to
	// finish a sequence it is in the middle of.
	openWait = 250 * time.Millisecond
	// drainQuiet and drainMax bound the reading of the child's last
	// output once it has exited.
	drainQuiet = 50 * time.Millisecond
	drainMax   = time.Second
)

// Run starts a child on a pty of its own and copies between it and the
// user's terminal (opts.In and opts.Out) until the child exits, with the
// shortcuts panel on the hotkey. It returns start's error or wait's.
//
// start starts the child with tty as its stdin, and as its stdout and
// stderr unless those go elsewhere, and with sys as its
// os.ProcAttr.Sys: the child is then the leader of a new session with
// tty as its controlling terminal (sys.Ctty is 0, the child's stdin).
// start returns wait, which waits for the child to exit; Run calls it
// on this goroutine. tty stays open until Run returns.
//
// Run puts the terminal in raw mode and restores it before it returns,
// also when start or wait panics or the child exits while the panel is
// open, and leaves it as the shell had it however the session ends: on
// the normal screen, with the modes the remote side turned on that change
// what keys and the mouse send turned off (plainTerminal). It handles
// SIGWINCH (the child's pty takes the terminal's size), SIGTSTP (hop
// stops, with the terminal restored for the shell) and SIGCONT, and
// nothing else: the caller still holds or passes on SIGINT, SIGTERM and
// the rest. The child is never signalled from here: on a suspend,
// opts.OnSuspend and opts.OnResume are the caller's. When ctx is
// done, or the terminal hangs up, the pty is closed, which hangs up the
// child's session; wait still decides when Run returns.
//
// Run returns ErrNotTerminal when In or Out is not a terminal, before
// calling start.
func Run(ctx context.Context, opts Options, start func(tty *os.File, sys *syscall.SysProcAttr) (wait func() error, err error)) error {
	p, err := newProxy(opts)
	if err != nil {
		return err
	}
	defer p.restore()
	// Once ctx is done, the loop's writes stop waiting on a terminal that
	// takes no output, as they do once the child has exited.
	ended := make(chan struct{})
	stopEnd := context.AfterFunc(ctx, func() {
		defer close(ended)
		p.o.end()
	})
	defer func() {
		if !stopEnd() {
			<-ended
		}
	}()
	childDone := make(chan struct{})
	abort := make(chan struct{})
	loopDone := make(chan struct{})
	go func() {
		defer close(loopDone)
		defer p.onPanic()
		p.loop(ctx, childDone, abort)
	}()
	// When start or wait panics, the loop stops before restore, which
	// runs next, takes the terminal and the pty from under it, even while
	// it waits for a terminal that takes no output. (A panic in the loop
	// restores from there, in onPanic.)
	joined := false
	defer func() {
		if !joined {
			p.o.abort()
			close(abort)
			<-loopDone
		}
	}()
	wait, err := start(p.pts, &syscall.SysProcAttr{Setsid: true, Setctty: true, Ctty: 0})
	if err == nil {
		err = wait()
	}
	p.o.end()
	close(childDone)
	<-loopDone
	joined = true
	return err
}

type proxy struct {
	in, out    *os.File
	inFd       int
	o          *termOut    // out's descriptor
	orig       *term.State // the terminal's mode before Run
	ptm        int         // -1 once closed
	pts        *os.File
	scr        *screen
	es         []entry
	look       panelLook
	tap        time.Duration
	ip         *inputParser
	inR, outR  *reader
	w          *writer
	sig, cont  chan os.Signal
	onSuspend  func()
	onResume   func()
	size       unix.Winsize
	panel      panelState
	held       []token // input for the child that the queue had no room for, and the keys after it
	needResume bool    // continued in the background: resume once in front
	gone       bool    // the terminal hung up, or ctx is done: the pty is closed
	outGone    bool    // a write to the terminal failed
	outStalled bool    // a write gave up on the terminal as the session ended
	outCut     bool    // a write stopped partway, maybe in a sequence
	outDone    bool    // the pty's output ended
	restored   sync.Once
	emergency  sync.Mutex // the panel state onPanic reads
}

type panelState struct {
	open bool
	// pending is that the hotkey came while the output was in the middle
	// of a sequence: the panel opens once it is through, and the keys
	// queued meanwhile are the panel's.
	pending   bool
	pendingAt time.Time
	queued    []token
	altBuf    bool // drawn on the alternate screen, over a copy of the normal one
	slot      bool // the terminal's saved cursor (DECSC) holds the cursor to put back
	view      view
	prefix    string
	note      string // why the last key did nothing
	openedAt  time.Time
}

func newProxy(opts Options) (_ *proxy, err error) {
	hk, err := opts.hotkey()
	if err != nil {
		return nil, err
	}
	if opts.In == nil || opts.Out == nil || !term.IsTerminal(int(opts.In.Fd())) || !term.IsTerminal(int(opts.Out.Fd())) {
		return nil, ErrNotTerminal
	}
	p := &proxy{in: opts.In, out: opts.Out, inFd: int(opts.In.Fd()), ptm: -1, es: entries(opts.Shortcuts), tap: opts.DoubleTap,
		onSuspend: opts.OnSuspend, onResume: opts.OnResume}
	if p.tap <= 0 {
		p.tap = DefaultDoubleTap
	}
	p.look = panelLook{hotkey: hk, unicode: utf8Locale(), canSuspend: !signal.Ignored(syscall.SIGTSTP)}
	p.ip = newInputParser(hk)
	defer func() {
		if err != nil {
			p.closeFds()
		}
	}()
	tio, err := unix.IoctlGetTermios(p.inFd, ioctlGetTermios)
	if err != nil {
		return nil, err
	}
	if p.ptm, p.pts, err = openPTY(); err != nil {
		return nil, err
	}
	// The child's terminal starts as the user's was, so ssh passes the
	// same modes (the erase character, say) to the remote side's pty.
	if err := unix.IoctlSetTermios(int(p.pts.Fd()), ioctlSetTermios, tio); err != nil {
		return nil, err
	}
	p.size = winsize(p.out)
	unix.IoctlSetWinsize(p.ptm, unix.TIOCSWINSZ, &p.size)
	p.scr = newScreen(int(p.size.Col), int(p.size.Row))
	if p.inR, err = newReader(p.inFd, 4096); err != nil {
		return nil, err
	}
	if p.outR, err = newReader(p.ptm, 32<<10); err != nil {
		return nil, err
	}
	if p.w, err = newWriter(p.ptm); err != nil {
		return nil, err
	}
	if p.o, err = newTermOut(int(p.out.Fd())); err != nil {
		return nil, err
	}
	// Every descriptor select is to wait on, before any goroutine waits:
	// the caller then runs the child directly.
	for _, fd := range []int{p.inFd, p.o.fd, p.ptm, p.inR.wake.r, p.outR.wake.r, p.w.wake.r, p.o.wake.r} {
		if fd >= maxFd {
			return nil, ErrUnsupported
		}
	}
	p.inR.start()
	p.outR.start()
	p.w.start()
	if p.orig, err = term.MakeRaw(p.inFd); err != nil {
		return nil, err
	}
	p.sig = make(chan os.Signal, 4)
	p.cont = make(chan os.Signal, 1)
	signal.Notify(p.sig, syscall.SIGWINCH)
	if p.look.canSuspend {
		signal.Notify(p.sig, syscall.SIGTSTP)
	}
	signal.Notify(p.cont, syscall.SIGCONT)
	return p, nil
}

// winsize is f's terminal size, or 80x24 when it has none.
func winsize(f *os.File) unix.Winsize {
	ws, err := unix.IoctlGetWinsize(int(f.Fd()), unix.TIOCGWINSZ)
	if err != nil || ws.Col == 0 || ws.Row == 0 {
		return unix.Winsize{Col: 80, Row: 24}
	}
	return *ws
}

func utf8Locale() bool {
	for _, k := range []string{"LC_ALL", "LC_CTYPE", "LANG"} {
		if v := strings.ToLower(os.Getenv(k)); v != "" {
			return strings.Contains(v, "utf-8") || strings.Contains(v, "utf8")
		}
	}
	return false
}

func (p *proxy) closeFds() {
	if p.inR != nil {
		p.inR.stop()
	}
	if p.outR != nil {
		p.outR.stop()
	}
	if p.w != nil {
		p.w.stop()
	}
	if p.o != nil {
		p.o.wake.close()
	}
	if p.ptm >= 0 {
		unix.Close(p.ptm)
		p.ptm = -1
	}
	if p.pts != nil {
		p.pts.Close()
	}
}

// restore puts the terminal back as Run found it and releases the pty.
func (p *proxy) restore() {
	p.restored.Do(func() {
		signal.Stop(p.sig)
		signal.Stop(p.cont)
		var b []byte
		p.emergency.Lock()
		if p.panel.open {
			b = p.emergencyClose()
		}
		p.emergency.Unlock()
		// The session is over, whatever the remote side left on. The
		// loop is not running (or it is the loop, in onPanic). A terminal
		// that takes no output gets outGrace, even when a write gave up
		// on it before; its mode is put back however much it took.
		p.outStalled = false
		p.writeWithin(append(b, p.plainTerminal()...), outGrace)
		term.Restore(p.inFd, p.orig)
		p.closeFds()
	})
}

// onPanic restores the terminal before a panic in the loop ends the
// process.
func (p *proxy) onPanic() {
	if r := recover(); r != nil {
		p.restore()
		panic(r)
	}
}

// emergencyClose is what takes the panel off the screen when it cannot
// be closed properly.
func (p *proxy) emergencyClose() []byte {
	if p.panel.altBuf {
		return []byte("\x1b[?1049l\x1b[?25h")
	}
	if p.panel.slot {
		return []byte("\x1b8\x1b[?25h")
	}
	return []byte("\x1b[?25h")
}

// loop copies between the terminal and the child until childDone, then
// shows the child's last output (finish), or until abort, at once.
func (p *proxy) loop(ctx context.Context, childDone, abort <-chan struct{}) {
	esc := time.NewTimer(time.Hour)
	esc.Stop()
	escArmed := false
	for {
		inC, spaceC := p.inR.out, (<-chan struct{})(nil)
		if !p.readsInput() {
			inC = nil
			spaceC = p.w.space
		}
		var outC <-chan []byte
		if !p.panel.open && !p.needResume && !p.outDone && p.ptm >= 0 {
			outC = p.outR.out
		}
		var pendC <-chan time.Time
		if p.panel.pending {
			pendC = time.After(max(openWait-time.Since(p.panel.pendingAt), 0))
		}
		if p.ip.held() && !escArmed {
			esc.Reset(escWait)
			escArmed = true
		}
		select {
		case b, ok := <-inC:
			if !ok {
				p.hangup()
				continue
			}
			p.handle(p.ip.feed(b))
			p.inR.release(b)
		case <-spaceC:
			p.handle(nil) // what is held, as far as there is room
		case b, ok := <-outC:
			if !ok {
				p.outDone = true
				continue
			}
			p.output(b)
			p.outR.release(b)
		case <-esc.C:
			escArmed = false
			p.handle(p.ip.flush())
		case <-pendC:
			p.write([]byte{0x18}) // CAN: the terminal drops the sequence too
			p.scr.abort()
			p.openPanel()
		case s := <-p.sig:
			switch s {
			case syscall.SIGWINCH:
				p.resize()
			case syscall.SIGTSTP:
				p.suspend()
			}
		case <-p.cont:
			p.resume()
		case <-ctx.Done():
			ctx = context.Background()
			p.hangup()
		case <-childDone:
			p.finish()
			return
		case <-abort:
			return
		}
		if escArmed && !p.ip.held() {
			esc.Stop()
			escArmed = false
		}
	}
}

// finish shows the child's last output, with the panel closed.
func (p *proxy) finish() {
	p.panel.pending, p.panel.queued = false, nil
	if p.panel.open {
		p.closePanel()
	}
	if p.ptm < 0 || p.outDone {
		return
	}
	limit := time.After(drainMax)
	for {
		quiet := time.After(drainQuiet)
		select {
		case b, ok := <-p.outR.out:
			if !ok {
				return
			}
			p.output(b)
			p.outR.release(b)
		case <-quiet:
			return
		case <-limit:
			return
		}
	}
}

// hangup closes the pty, which hangs up the child's session, when the
// terminal is gone or ctx is done.
func (p *proxy) hangup() {
	p.gone = true
	if p.ptm < 0 {
		return
	}
	p.outR.stop()
	p.w.stop()
	unix.Close(p.ptm)
	p.ptm = -1
}

func (p *proxy) write(b []byte) { p.writeWithin(b, 0) }

// writeWithin writes b to the terminal, waiting for it at most limit when
// that is not 0 (termOut.write). Once a write without a limit has given up
// on the terminal, as the session ends, the rest of the session's output
// is dropped.
func (p *proxy) writeWithin(b []byte, limit time.Duration) {
	if p.outGone || p.outStalled || len(b) == 0 {
		return
	}
	if p.outCut {
		// CAN ends the sequence the last write may have left unfinished.
		b = append([]byte{0x18}, b...)
	}
	n, err := p.o.write(b, limit)
	p.outCut = err != nil && (n > 0 || p.outCut)
	switch {
	case err == errStalled:
		p.outStalled = limit == 0
	case err != nil:
		p.outGone = true
		p.hangup()
	}
}

func (p *proxy) beep() { p.write([]byte{0x07}) }

func (p *proxy) send(b []byte) {
	if p.ptm >= 0 {
		p.w.send(b)
	}
}

// output passes the child's output to the terminal and the model.
func (p *proxy) output(b []byte) {
	p.write(b)
	p.scr.Write(b)
	if p.panel.pending && p.scr.ground() {
		p.openPanel()
	}
}

// readsInput says whether the loop reads the terminal. Input for the
// child that the queue has no room for stops it, and so does a full
// queue, but not while the panel is open: its keys are the panel's, and
// the child's output waits for the panel, so a child held up writing it
// would never take the input that frees the queue, and Esc would never be
// read. The panel adds to the queue only what it has room for.
func (p *proxy) readsInput() bool {
	return !p.gone && len(p.held) == 0 && (p.panel.open || !p.w.full())
}

// room is how much more input the queue for the child takes. Once the pty
// is closed, what is sent is dropped, so there is room for anything.
func (p *proxy) room() int {
	if p.ptm < 0 {
		return math.MaxInt
	}
	return p.w.room()
}

// handle acts on the user's keys, after any held: passes them to the
// child, or to the panel when it is open. Input for the child that the
// queue has no room for is held, with the keys after it, until there is
// room (readsInput).
func (p *proxy) handle(ts []token) {
	if len(p.held) > 0 {
		ts = append(p.held, ts...)
		p.held = nil
	}
	var pass []byte
	flush := func() {
		p.send(pass)
		pass = nil
	}
	for i, t := range ts {
		switch {
		case p.panel.pending && t.kind != tokHotkey:
			p.panel.queued = append(p.panel.queued, copyTokens(ts[i:i+1])...)
			continue
		case p.panel.pending:
			// The hotkey twice: the hotkey itself, for the child, held as
			// that if need be.
			p.panel.pending, p.panel.queued = false, nil
			ts[i].kind = tokLiteral
		case p.panel.open:
			flush()
			p.panelKey(t)
			continue
		case t.kind == tokHotkey:
			flush()
			if p.scr.ground() {
				p.openPanel()
			} else {
				p.panel.pending, p.panel.pendingAt = true, time.Now()
			}
			continue
		case t.kind == tokHotkeyUp:
			continue
		}
		if len(pass)+len(t.raw) > p.room() {
			flush()
			if len(t.raw) > p.room() {
				p.held = copyTokens(ts[i:])
				return
			}
		}
		pass = append(pass, t.raw...)
	}
	flush()
}

// copyTokens copies ts, whose bytes may be a read buffer's.
func copyTokens(ts []token) []token {
	out := make([]token, len(ts))
	for i, t := range ts {
		out[i] = token{t.kind, append([]byte(nil), t.raw...)}
	}
	return out
}

func (p *proxy) panelKey(t token) {
	switch t.kind {
	case tokHotkey:
		quick := time.Since(p.panel.openedAt) < p.tap
		if quick && !p.fits(t.raw) {
			return
		}
		p.closePanel()
		if quick {
			p.send(append([]byte(nil), t.raw...))
		}
	case tokEsc:
		p.closePanel()
	case tokControl:
		switch t.raw[0] {
		case 0x03: // Ctrl-C
			p.closePanel()
		case 0x1a: // Ctrl-Z
			if !p.look.canSuspend {
				p.beep()
				return
			}
			p.closePanel()
			p.suspend()
		case '\r':
			if e := p.find(p.panel.prefix); e != nil && p.panel.prefix != "" {
				p.fire(*e)
				return
			}
			p.beep()
		case 0x7f, 0x08:
			if p.panel.prefix == "" {
				p.beep()
				return
			}
			p.panel.prefix = ""
			p.drawPanel()
		default:
			p.beep()
		}
	case tokText:
		if len(t.raw) != 1 || t.raw[0] < 0x20 || t.raw[0] > 0x7e {
			p.beep()
			return
		}
		p.key(t.raw[0])
	case tokSeq:
		// The kitty keyboard protocol and modifyOtherKeys send the
		// panel's keys as sequences when the remote side turned them on.
		if k, release, ok := decodeKey(t.raw); ok {
			if !release {
				p.panelKey(k)
			}
		}
	}
	// Other escape sequences (other keys, mouse and focus reports) and
	// pastes are dropped.
}

func (p *proxy) find(keys string) *entry {
	for i := range p.es {
		if p.es[i].keys == keys {
			return &p.es[i]
		}
	}
	return nil
}

func (p *proxy) key(c byte) {
	k := p.panel.prefix + string(c)
	exact := p.find(k)
	longer := false
	for _, e := range p.es {
		longer = longer || (len(e.keys) > len(k) && strings.HasPrefix(e.keys, k))
	}
	switch {
	case exact != nil && !longer:
		p.fire(*exact)
	case longer:
		p.panel.prefix = k
		p.drawPanel()
	default:
		p.beep()
	}
}

// fits says whether the queue for the child has room for what the panel
// would type, b. When it has not, the panel stays open and says why,
// with a beep; what is queued already stays.
func (p *proxy) fits(b []byte) bool {
	if len(b) <= p.room() {
		return true
	}
	p.beep()
	if p.panel.note == "" {
		p.panel.note = noteNotReading
		p.drawPanel()
	}
	return false
}

// noteNotReading is the panel's note when the queue for the child has no
// room for a shortcut's command or the hotkey.
const noteNotReading = "Session isn't reading input"

// fire closes the panel and types e's command, as if the user had: in a
// bracketed paste when the remote side asked for those, so that a shell
// or an editor takes it as text whatever its key bindings, then Enter
// as a key of its own.
func (p *proxy) fire(e entry) {
	var b []byte
	if e.typed != "" {
		if p.scr.bracketed {
			b = append(b, pasteStart...)
			b = append(b, e.typed...)
			b = append(b, pasteEnd...)
		} else {
			b = append(b, e.typed...)
		}
	}
	if e.enter {
		b = append(b, '\r')
	}
	if !p.fits(b) {
		return
	}
	p.closePanel()
	p.send(b)
}

func (p *proxy) layout() view {
	look := p.look
	look.note = p.panel.note
	return layout(p.scr.cols, p.scr.rows, p.es, p.panel.prefix, look)
}

// openPanel draws the panel. On the normal screen it switches the
// terminal to the alternate screen and draws it over a copy of the
// normal one, unless the remote side has a cursor saved there (1049
// saves the cursor in the same slot): then, as on the alternate
// screen, it draws over the screen itself. The terminal's saved cursor
// keeps the cursor to go back to, when the slot is free.
func (p *proxy) openPanel() {
	q := p.panel.queued
	s := p.scr
	p.emergency.Lock()
	p.panel = panelState{open: true, openedAt: time.Now()}
	p.panel.altBuf = !s.altActive && !s.main.live
	p.panel.slot = p.panel.altBuf || (s.altActive && !s.alt.live)
	p.emergency.Unlock()
	w := &painter{}
	w.b = append(w.b, "\x1b[?2026h"...)
	switch {
	case p.panel.altBuf:
		w.b = append(w.b, "\x1b[?1049h"...)
	case p.panel.slot:
		w.b = append(w.b, "\x1b7"...)
	}
	w.b = append(w.b, drawModes...)
	if p.panel.altBuf {
		w.screen(s.main.cells)
	}
	p.panel.view = p.layout()
	drawView(w, p.panel.view)
	w.b = append(w.b, "\x1b[?2026l"...)
	p.write(w.b)
	p.handle(q)
}

// drawModes are the modes the panel is drawn in: cursor hidden, absolute
// positions (DECOM off), replace mode (IRM off), ASCII in GL.
const drawModes = "\x1b[?25l\x1b[?6l\x1b[4l\x1b(B\x0f"

// drawPanel redraws the panel, after the first key of a two-key
// shortcut or a backspace: what is under it first, as the new one may
// be smaller.
func (p *proxy) drawPanel() {
	w := &painter{}
	w.b = append(w.b, "\x1b[?2026h"...)
	p.paintUnder(w, p.panel.view)
	p.panel.view = p.layout()
	drawView(w, p.panel.view)
	w.b = append(w.b, "\x1b[?2026l"...)
	p.write(w.b)
}

// paintUnder repaints from the model what v covers.
func (p *proxy) paintUnder(w *painter, v view) {
	g := p.scr.grid()
	if p.panel.altBuf {
		g = p.scr.main.cells
	}
	for r := v.top; r < v.top+v.height() && r < len(g); r++ {
		w.row(g[r], r, max(v.left, 0), false)
	}
	w.finish()
}

func (p *proxy) closePanel() { p.write(p.closingPanel()) }

// closingPanel closes the panel and returns what takes it off the screen.
func (p *proxy) closingPanel() []byte {
	if !p.panel.open {
		return nil
	}
	pn := p.panel
	p.emergency.Lock()
	p.panel = panelState{}
	p.emergency.Unlock()
	w := &painter{}
	w.b = append(w.b, "\x1b[?2026h"...)
	switch {
	case pn.altBuf:
		// The terminal puts back the normal screen and, as DECRC does,
		// the cursor, its attributes, the character sets and origin mode.
		w.b = append(w.b, "\x1b[?1049l"...)
	default:
		p.paintUnder(w, pn.view)
		if pn.slot {
			w.b = append(w.b, "\x1b8"...)
		}
	}
	if !pn.slot {
		p.putCursor(w, p.scr.cur)
	}
	p.putModes(w)
	return append(w.b, "\x1b[?2026l"...)
}

// putCursor puts the cursor, its attributes, the character sets and
// origin mode as c has them, from the model.
func (p *proxy) putCursor(w *painter, c cursor) {
	s := p.scr
	row := c.row
	w.b = append(w.b, "\x1b[?6l"...)
	if c.origin {
		w.b = append(w.b, "\x1b[?6h"...)
		row -= s.top
	}
	if c.wrap && s.autowrap && c.col == s.cols-1 {
		// A pending wrap is had by writing the last column again.
		line := s.grid()[c.row]
		col := c.col
		if line[col].tail && col > 0 {
			col--
		}
		w.cup(row, col)
		w.set = false
		w.cell(line[col])
		w.finish()
	} else {
		w.cup(row, c.col)
	}
	w.b = c.pen.sgr(w.b)
	w.b = append(w.b, "\x1b("...)
	w.b = append(w.b, c.g[0])
	w.b = append(w.b, "\x1b)"...)
	w.b = append(w.b, c.g[1])
	if c.gl == 1 {
		w.b = append(w.b, 0x0e)
	} else {
		w.b = append(w.b, 0x0f)
	}
}

// putModes sets again what drawModes changed, as the model has it. The
// character sets go too, for a terminal whose DECRC leaves them.
func (p *proxy) putModes(w *painter) {
	s := p.scr
	w.b = append(w.b, "\x1b("...)
	w.b = append(w.b, s.cur.g[0])
	if s.cur.gl == 1 {
		w.b = append(w.b, 0x0e)
	} else {
		w.b = append(w.b, 0x0f)
	}
	if s.insert {
		w.b = append(w.b, "\x1b[4h"...)
	}
	if s.visible {
		w.b = append(w.b, "\x1b[?25h"...)
	}
}

func drawView(w *painter, v view) {
	for i, line := range v.lines {
		w.cup(v.top+i, v.left)
		for _, s := range line {
			w.b = append(w.b, s.st.sgr()...)
			w.b = append(w.b, s.text...)
		}
	}
	w.b = append(w.b, "\x1b[0m"...)
	w.set = false
}

// resize gives the child's pty the terminal's new size, and redraws the
// panel in the new top right corner when it is open: over a repaint of
// the whole screen, as the terminal may have moved or cut what was there.
func (p *proxy) resize() {
	ws := winsize(p.out)
	if ws == p.size {
		return
	}
	p.size = ws
	if p.ptm >= 0 {
		unix.IoctlSetWinsize(p.ptm, unix.TIOCSWINSZ, &ws)
	}
	p.scr.Resize(int(ws.Col), int(ws.Row))
	if !p.panel.open {
		return
	}
	w := &painter{}
	w.b = append(w.b, "\x1b[?2026h"...)
	w.b = append(w.b, drawModes...)
	g := p.scr.grid()
	if p.panel.altBuf {
		g = p.scr.main.cells
	}
	w.screen(g)
	p.panel.view = p.layout()
	drawView(w, p.panel.view)
	w.b = append(w.b, "\x1b[?2026l"...)
	p.write(w.b)
}

// stopSelf stops this process for job control, as SIGTSTP's default
// action does, and returns once it is continued (cont), or after a
// second if the stop did not happen. It stops with SIGSTOP: once Go has
// been notified of SIGTSTP its handler stays, even after signal.Reset,
// and drops a SIGTSTP the process sends itself. SIGSTOP stops an
// orphaned process group too, which nothing would continue, so it is
// sent only when there is a shell to continue hop (hasShell), as the
// system does for SIGTSTP. Tests replace it.
var stopSelf = func(cont <-chan os.Signal) {
	for len(cont) > 0 {
		<-cont
	}
	signal.Reset(syscall.SIGTSTP) // one sent meanwhile is dropped
	if !hasShell() {
		return
	}
	syscall.Kill(os.Getpid(), syscall.SIGSTOP)
	select {
	case <-cont:
	case <-time.After(time.Second):
	}
}

// hasShell says whether hop's process group is a job of a shell, which
// can continue it: hop's parent is in another process group of the same
// session. A group with no such process is orphaned.
func hasShell() bool {
	ppid := os.Getppid()
	pg, err := unix.Getpgid(ppid)
	if err != nil || pg == unix.Getpgrp() {
		return false
	}
	sid, err := unix.Getsid(ppid)
	own, err2 := unix.Getsid(0)
	return err == nil && err2 == nil && sid == own
}

// suspend stops hop for job control: the panel's Ctrl-Z, or a SIGTSTP
// sent to it. The terminal goes back to the mode the shell left it in,
// as plainTerminal leaves it, however much of that a terminal that takes
// no output takes within outGrace; resume undoes that. The child stops
// and continues with hop when the caller says so (onSuspend, onResume);
// otherwise it runs on meanwhile, but hop reads nothing from it, so it
// waits once the pty is full.
func (p *proxy) suspend() {
	p.panel.pending, p.panel.queued = false, nil
	p.writeWithin(append(p.closingPanel(), p.plainTerminal()...), outGrace)
	term.Restore(p.inFd, p.orig)
	if p.onSuspend != nil {
		p.onSuspend()
	}
	stopSelf(p.cont)
	if p.onResume != nil {
		p.onResume()
	}
	signal.Notify(p.sig, syscall.SIGTSTP)
	p.needResume = true
	p.resume()
}

// resume makes the terminal the session's again once hop is continued
// and in the foreground: raw mode, the remote side's modes, and the
// screens repainted from the model, as the shell has drawn on them.
func (p *proxy) resume() {
	if p.gone {
		return
	}
	if !p.foreground() {
		p.needResume = true // in the background: hold the output meanwhile
		return
	}
	p.needResume = false
	term.MakeRaw(p.inFd)
	p.resize()
	s := p.scr
	w := &painter{}
	w.b = append(w.b, drawModes...)
	w.screen(s.main.cells)
	w.b = s.kitty[0].redo(w.b)
	if s.altActive {
		// 1049 saves the cursor the normal screen is to get back.
		p.putCursor(w, s.main.saved)
		w.b = append(w.b, "\x1b[?1049h"...)
		w.b = append(w.b, drawModes...)
		w.screen(s.alt.cells)
		w.b = s.kitty[1].redo(w.b)
	}
	if b := s.buf(); b.live {
		p.putCursor(w, b.saved)
		w.b = append(w.b, "\x1b7"...)
	}
	for _, m := range trackedModes {
		if s.modes[m] {
			w.b = append(w.b, "\x1b[?"+strconv.Itoa(m)+"h"...)
		}
	}
	if s.keypad {
		w.b = append(w.b, "\x1b="...)
	}
	if s.otherKeys != 0 {
		w.b = append(w.b, "\x1b[>4;"+strconv.Itoa(s.otherKeys)+"m"...)
	}
	p.putCursor(w, s.cur)
	p.putModes(w)
	p.write(w.b)
}

// plainTerminal is what gives the terminal back to the shell from the
// session: the modes the remote side turned on that change what keys and
// the mouse send off (mouse reports, focus events, bracketed paste,
// application cursor keys and keypad, modifyOtherKeys, and the kitty
// keyboard protocol's flags, popped on each screen), the normal screen,
// plain attributes and the cursor shown. suspend sends it, and restore
// once the session is over.
func (p *proxy) plainTerminal() []byte {
	s := p.scr
	var b []byte
	for _, m := range trackedModes {
		if s.modes[m] {
			b = append(b, "\x1b[?"+strconv.Itoa(m)+"l"...)
		}
	}
	if s.keypad {
		b = append(b, "\x1b>"...)
	}
	if s.otherKeys != 0 {
		b = append(b, "\x1b[>4m"...)
	}
	if s.altActive {
		b = s.kitty[1].undo(b)
		b = append(b, "\x1b[?1049l"...)
	}
	b = s.kitty[0].undo(b)
	return append(b, "\x1b[0m\x1b[?25h"...)
}

// foreground says whether hop's process group has the terminal, or the
// terminal is not hop's controlling terminal, so job control does not
// come into it.
func (p *proxy) foreground() bool {
	pg, err := unix.IoctlGetInt(p.inFd, unix.TIOCGPGRP)
	return err != nil || pg == unix.Getpgrp()
}
