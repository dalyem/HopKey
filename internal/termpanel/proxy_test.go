//go:build linux || darwin

package termpanel

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// vterm is the user's terminal in these tests: a pty whose slave Run gets
// as In and Out, and whose master the test reads into a screen model of
// its own, the terminal's, and writes keys to.
type vterm struct {
	t    *testing.T
	ptm  *os.File
	tty  *os.File
	fd   int // tty's
	mu   sync.Mutex
	scr  *screen
	raw  []byte
	done chan struct{}
}

func newVTerm(t *testing.T, cols, rows int) *vterm {
	t.Helper()
	t.Setenv("LC_ALL", "")
	t.Setenv("LC_CTYPE", "")
	t.Setenv("LANG", "C.UTF-8")
	m, s, err := openPTY()
	if err != nil {
		t.Fatal(err)
	}
	if err := unix.SetNonblock(m, false); err != nil {
		t.Fatal(err)
	}
	ws := unix.Winsize{Col: uint16(cols), Row: uint16(rows)}
	if err := unix.IoctlSetWinsize(m, unix.TIOCSWINSZ, &ws); err != nil {
		t.Fatal(err)
	}
	v := &vterm{t: t, ptm: os.NewFile(uintptr(m), "ptm"), tty: s, fd: int(s.Fd()), scr: newScreen(cols, rows), done: make(chan struct{})}
	go func() {
		defer close(v.done)
		buf := make([]byte, 8192)
		for {
			n, err := v.ptm.Read(buf)
			v.mu.Lock()
			v.scr.Write(buf[:n])
			v.raw = append(v.raw, buf[:n]...)
			v.mu.Unlock()
			if err != nil {
				return
			}
		}
	}()
	t.Cleanup(func() {
		v.tty.Close() // the master's read ends once no slave is open
		<-v.done
		v.ptm.Close()
	})
	return v
}

func (v *vterm) key(s string) {
	v.t.Helper()
	if _, err := v.ptm.Write([]byte(s)); err != nil {
		v.t.Fatal(err)
	}
}

func (v *vterm) dump() string {
	var b strings.Builder
	for r := range v.scr.rows {
		fmt.Fprintf(&b, "%2d|%s|\n", r, v.scr.text(r))
	}
	fmt.Fprintf(&b, "cursor %+v alt %v\n", v.scr.cur, v.scr.altActive)
	return b.String()
}

func (v *vterm) waitFor(what string, ok func(s *screen) bool) {
	v.t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for {
		v.mu.Lock()
		done := ok(v.scr)
		d := ""
		if !done && time.Now().After(deadline) {
			d = v.dump()
		}
		v.mu.Unlock()
		if done {
			return
		}
		if d != "" {
			v.t.Fatalf("timed out waiting for %s; the screen:\n%s", what, d)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func (v *vterm) waitText(s string) {
	v.t.Helper()
	v.waitFor(fmt.Sprintf("%q on the screen", s), func(sc *screen) bool {
		for r := range sc.rows {
			if strings.Contains(sc.text(r), s) {
				return true
			}
		}
		return false
	})
}

// snapshot copies what the terminal shows: the current screen's cells,
// the cursor and the modes.
func (v *vterm) snapshot() *screen {
	v.mu.Lock()
	defer v.mu.Unlock()
	return v.scr.clone()
}

func (s *screen) clone() *screen {
	c := *s
	c.p = parser{}
	cp := func(g [][]cell) [][]cell {
		n := make([][]cell, len(g))
		for i := range g {
			n[i] = append([]cell(nil), g[i]...)
		}
		return n
	}
	c.main.cells, c.alt.cells = cp(s.main.cells), cp(s.alt.cells)
	c.tabs = append([]bool(nil), s.tabs...)
	c.modes = map[int]bool{}
	for k, m := range s.modes {
		c.modes[k] = m
	}
	return &c
}

// diff says how b's current screen differs from a's, cell by cell: ""
// when it shows exactly the same.
func diff(a, b *screen) string {
	var out []string
	if a.cols != b.cols || a.rows != b.rows {
		return fmt.Sprintf("size %dx%d, want %dx%d", b.cols, b.rows, a.cols, a.rows)
	}
	if a.altActive != b.altActive {
		out = append(out, fmt.Sprintf("alternate screen %v, want %v", b.altActive, a.altActive))
	}
	for r := range a.rows {
		for c := range a.cols {
			if x, y := a.grid()[r][c], b.grid()[r][c]; x != y && len(out) < 8 {
				out = append(out, fmt.Sprintf("cell %d,%d: %+v, want %+v", r, c, y, x))
			}
		}
	}
	if a.cur != b.cur {
		out = append(out, fmt.Sprintf("cursor %+v, want %+v", b.cur, a.cur))
	}
	if a.visible != b.visible || a.insert != b.insert || a.autowrap != b.autowrap || a.top != b.top || a.bot != b.bot {
		out = append(out, "modes differ")
	}
	return strings.Join(out, "\n")
}

func (v *vterm) waitSame(want *screen) {
	v.t.Helper()
	last := ""
	deadline := time.Now().Add(10 * time.Second)
	for {
		v.mu.Lock()
		last = diff(want, v.scr)
		d := v.dump()
		v.mu.Unlock()
		if last == "" {
			return
		}
		if time.Now().After(deadline) {
			v.t.Fatalf("the screen is not as it was:\n%s\nscreen now:\n%s", last, d)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func (v *vterm) panelAt(col int) {
	v.t.Helper()
	v.waitFor(fmt.Sprintf("the panel's corner at column %d", col), func(s *screen) bool {
		return strings.Contains(s.text(0), "Shortcuts") && s.grid()[0][col].s == "┌"
	})
}

func (v *vterm) output() []byte {
	v.mu.Lock()
	defer v.mu.Unlock()
	return append([]byte(nil), v.raw...)
}

// proc is the child a test runs under Run.
type proc struct {
	started chan struct{}
	p       *os.Process
	tty     *os.File
	runErr  chan error
}

// run runs sh -c script (with $0 set to arg0) under Run on v.
func run(t *testing.T, v *vterm, opts Options, script, arg0 string) *proc {
	t.Helper()
	opts.In, opts.Out = v.tty, v.tty
	if opts.DoubleTap == 0 {
		opts.DoubleTap = 50 * time.Millisecond
	}
	c := &proc{started: make(chan struct{}), runErr: make(chan error, 1)}
	go func() {
		c.runErr <- Run(context.Background(), opts, func(tty *os.File, sys *syscall.SysProcAttr) (func() error, error) {
			p, err := os.StartProcess("/bin/sh", []string{"sh", "-c", script, arg0}, &os.ProcAttr{Files: []*os.File{tty, tty, tty}, Sys: sys})
			if err != nil {
				return nil, err
			}
			c.p, c.tty = p, tty
			close(c.started)
			return func() error { _, err := p.Wait(); return err }, nil
		})
	}()
	select {
	case <-c.started:
	case err := <-c.runErr:
		t.Fatalf("Run: %v", err)
	}
	t.Cleanup(func() {
		c.p.Kill()
		select {
		case err := <-c.runErr:
			c.runErr <- err
		case <-time.After(10 * time.Second):
			t.Error("Run did not return after its child was killed")
		}
	})
	return c
}

func (c *proc) wait(t *testing.T) error {
	t.Helper()
	select {
	case err := <-c.runErr:
		c.runErr <- err
		return err
	case <-time.After(10 * time.Second):
		t.Fatal("Run did not return")
	}
	return nil
}

func waitFile(t *testing.T, path, want string) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for {
		got, _ := os.ReadFile(path)
		if string(got) == want {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("typed %q, want %q", got, want)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// fill is a script that fills the normal screen with numbered, coloured
// lines as wide as the screen, and leaves the cursor on the last but one
// line with bold red set.
const fill = `stty raw -echo
printf '\033[2J\033[H'
i=1; while [ $i -le 22 ]; do printf '\033[3%dm%02d %s\033[0m\r\n' $((i % 8)) $i "$(printf '%077d' $i)"; i=$((i+1)); done
printf '\033[1;31mREADY'
`

var testShortcuts = []Shortcut{
	{Keys: "u", Name: "Update", Command: "echo hi", Enter: true},
	{Keys: "gs", Name: "Status", Command: "git status", Host: true},
	{Keys: "gl", Name: "Log", Command: "git log", Host: true},
}

func TestPanelOpensAndRestoresNormalScreen(t *testing.T) {
	v := newVTerm(t, 80, 24)
	run(t, v, Options{Shortcuts: testShortcuts}, fill+`exec cat >/dev/null`, "")
	v.waitText("READY")
	before := v.snapshot()
	for _, close := range []string{"\x1b", "\x1d", "\x03"} {
		v.key("\x1d")
		v.panelAt(40)
		// The session shows beside the panel.
		v.mu.Lock()
		left, want := v.scr.text(5)[:40], before.text(5)[:40]
		v.mu.Unlock()
		if left != want {
			t.Fatalf("beside the panel: %q, want %q", left, want)
		}
		time.Sleep(100 * time.Millisecond) // past DoubleTap, so the hotkey closes
		v.key(close)
		v.waitSame(before)
	}
}

func TestShortcutTypesCommand(t *testing.T) {
	v := newVTerm(t, 80, 24)
	typed := filepath.Join(t.TempDir(), "typed")
	run(t, v, Options{Shortcuts: testShortcuts}, fill+`exec cat >"$0"`, typed)
	v.waitText("READY")
	before := v.snapshot()

	v.key("\x1d")
	v.panelAt(40)
	v.key("u")
	waitFile(t, typed, "echo hi\r")
	v.waitSame(before)

	v.key("\x1d")
	v.panelAt(40)
	v.key("g")
	v.waitText("Shortcuts: g")
	v.key("s")
	waitFile(t, typed, "echo hi\rgit status")
	v.waitSame(before)

	// An unknown key beeps and goes nowhere; Backspace leaves a two-key
	// shortcut's first key.
	v.key("\x1d")
	v.panelAt(40)
	n := len(v.output())
	v.key("z")
	v.waitFor("a beep", func(*screen) bool { return bytes.Contains(v.raw[n:], []byte{0x07}) })
	v.key("g")
	v.waitText("Shortcuts: g")
	v.key("\x7f")
	v.waitFor("the full list again", func(s *screen) bool {
		return strings.Contains(s.text(0), "Shortcuts ") && strings.Contains(s.text(5), "Update")
	})
	v.key("\x1b")
	v.waitSame(before)
	time.Sleep(50 * time.Millisecond)
	waitFile(t, typed, "echo hi\rgit status")
}

func TestShortcutTypesBracketedPaste(t *testing.T) {
	v := newVTerm(t, 80, 24)
	typed := filepath.Join(t.TempDir(), "typed")
	run(t, v, Options{Shortcuts: testShortcuts}, `stty raw -echo; printf '\033[?2004hREADY'; exec cat >"$0"`, typed)
	v.waitText("READY")
	v.key("\x1d")
	v.panelAt(40)
	v.key("u")
	waitFile(t, typed, "\x1b[200~echo hi\x1b[201~\r")
}

func TestHotkeyInsidePasteGoesThrough(t *testing.T) {
	v := newVTerm(t, 80, 24)
	typed := filepath.Join(t.TempDir(), "typed")
	run(t, v, Options{Shortcuts: testShortcuts}, `stty raw -echo; printf '\033[?2004hREADY'; exec cat >"$0"`, typed)
	v.waitText("READY")
	paste := "\x1b[200~a\x1db\x1b[201~"
	v.key(paste)
	waitFile(t, typed, paste)
	if bytes.Contains(v.output(), []byte("Shortcuts")) {
		t.Fatal("the hotkey in a paste opened the panel")
	}
	// After the paste, the hotkey is the hotkey again.
	v.key("\x1d")
	v.panelAt(40)
}

func TestDoubleHotkeySendsLiteral(t *testing.T) {
	v := newVTerm(t, 80, 24)
	typed := filepath.Join(t.TempDir(), "typed")
	run(t, v, Options{Shortcuts: testShortcuts, DoubleTap: DefaultDoubleTap}, fill+`exec cat >"$0"`, typed)
	v.waitText("READY")
	before := v.snapshot()
	v.key("\x1d\x1d")
	waitFile(t, typed, "\x1d")
	v.waitSame(before)
	v.key("\x1d")
	v.panelAt(40)
	v.key("\x1d")
	waitFile(t, typed, "\x1d\x1d")
	v.waitSame(before)
}

func TestResizeWhilePanelOpen(t *testing.T) {
	v := newVTerm(t, 80, 24)
	c := run(t, v, Options{Shortcuts: testShortcuts}, fill+`exec cat >/dev/null`, "")
	v.waitText("READY")
	before := v.snapshot()
	v.key("\x1d")
	v.panelAt(40)

	v.mu.Lock()
	ws := unix.Winsize{Col: 100, Row: 30}
	if err := unix.IoctlSetWinsize(v.fd, unix.TIOCSWINSZ, &ws); err != nil {
		t.Fatal(err)
	}
	v.scr.Resize(100, 30) // as the terminal does
	v.mu.Unlock()
	syscall.Kill(os.Getpid(), syscall.SIGWINCH)
	v.panelAt(60)
	inner, err := unix.IoctlGetWinsize(int(c.tty.Fd()), unix.TIOCGWINSZ)
	if err != nil || inner.Col != 100 || inner.Row != 30 {
		t.Fatalf("the child's pty is %+v (%v), want 100x30", inner, err)
	}
	v.key("\x1b")
	before.Resize(100, 30)
	v.waitSame(before)
}

func TestChildExitsWhilePanelOpen(t *testing.T) {
	v := newVTerm(t, 80, 24)
	orig, err := unix.IoctlGetTermios(v.fd, ioctlGetTermios)
	if err != nil {
		t.Fatal(err)
	}
	// Insert mode, which the panel turns off while it is open, shows
	// that it was closed properly, not only taken off the screen.
	c := run(t, v, Options{Shortcuts: testShortcuts}, fill+`printf '\033[4h'; exec cat >/dev/null`, "")
	v.waitText("READY")
	v.waitFor("insert mode", func(s *screen) bool { return s.insert })
	before := v.snapshot()
	v.key("\x1d")
	v.panelAt(40)
	c.p.Kill()
	if err := c.wait(t); err != nil {
		t.Fatalf("Run: %v", err)
	}
	now, err := unix.IoctlGetTermios(v.fd, ioctlGetTermios)
	if err != nil {
		t.Fatal(err)
	}
	if *now != *orig {
		t.Errorf("terminal mode %+v, want %+v", *now, *orig)
	}
	v.waitSame(before)
}

func TestControlCharactersNeutralized(t *testing.T) {
	v := newVTerm(t, 80, 24)
	typed := filepath.Join(t.TempDir(), "typed")
	sc := []Shortcut{{Keys: "x", Name: "\x1b[31mred\x1b[2J", Command: "rm\x1b[2J -rf\x00 /tmp/x\x07"}}
	run(t, v, Options{Shortcuts: sc}, fill+`exec cat >"$0"`, typed)
	v.waitText("READY")
	before := v.snapshot()
	v.key("\x1d")
	v.panelAt(40)
	v.waitText("^[[31mred")
	v.mu.Lock()
	still := v.scr.text(10)[:40] == before.text(10)[:40]
	red := false
	for r := range 5 {
		for _, cl := range v.scr.grid()[r][40:] {
			red = red || (cl.s == "r" && cl.pen.fg == color{colorBasic, 1})
		}
	}
	v.mu.Unlock()
	if !still || red {
		t.Fatalf("the name acted on the terminal: screen kept %v, red %v", still, red)
	}
	v.key("x")
	waitFile(t, typed, "rm[2J -rf /tmp/x")
	v.waitSame(before)
}

// alt draws on the alternate screen: coloured rows, a wide character
// across the panel's left edge, DEC line drawing under the panel, and
// leaves the cursor in the middle with a colour set. extra comes before
// READY.
const alt = `stty raw -echo
printf '\033[?1049h\033[H\033[2J'
i=1; while [ $i -le 20 ]; do printf '\033[%d;1H\033[4%dm%-80s\033[0m' $i $((i % 8)) "row $i"; i=$((i+1)); done
printf '\033[3;40H\033[1m日本語\033[0m\033[5;60H\033(0lqqqk\033(B\033[7;70H\033[4:3mcurly\033[0m'
`

func TestPanelInAlternateScreen(t *testing.T) {
	for _, c := range []struct{ name, extra string }{
		{"slot free", `printf '\033[12;5H\033[32m'`},
		// The remote side saved a cursor: the panel must keep its slot,
		// and put back the cursor and modes from the model.
		{"slot live", `printf '\033[2;3H\033[35m\033(0\033[4h\0337\033[3;18r\033[?6h\033[4;6H\033[33m'`},
	} {
		t.Run(c.name, func(t *testing.T) {
			v := newVTerm(t, 80, 24)
			run(t, v, Options{Shortcuts: testShortcuts}, alt+c.extra+`; printf READY; exec cat >/dev/null`, "")
			v.waitText("READY")
			before := v.snapshot()
			v.key("\x1d")
			v.panelAt(40)
			v.key("\x1b")
			v.waitSame(before)
			v.mu.Lock()
			defer v.mu.Unlock()
			// A free slot is the panel's to use: only a live one must stay.
			if before.alt.live && v.scr.alt.saved != before.alt.saved {
				t.Fatalf("the remote side's saved cursor is %+v, want %+v", v.scr.alt.saved, before.alt.saved)
			}
		})
	}
}

func TestPanelOverNormalScreenWithSavedCursor(t *testing.T) {
	v := newVTerm(t, 80, 24)
	run(t, v, Options{Shortcuts: testShortcuts}, fill+`printf '\033[5;10H\0337\033[23;1H\033[4h'; printf READY; exec cat >/dev/null`, "")
	v.waitText("READY")
	before := v.snapshot()
	v.key("\x1d")
	v.panelAt(40)
	v.key("\x1b")
	v.waitSame(before)
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.scr.main.saved != before.main.saved {
		t.Fatalf("the remote side's saved cursor is %+v, want %+v", v.scr.main.saved, before.main.saved)
	}
}

func TestSmallTerminalBar(t *testing.T) {
	v := newVTerm(t, 25, 8)
	run(t, v, Options{Shortcuts: testShortcuts}, `stty raw -echo; printf 'abcdefghijklmnopqrstuvwxy\r\nREADY'; exec cat >/dev/null`, "")
	v.waitText("READY")
	before := v.snapshot()
	v.key("\x1d")
	v.waitFor("the bar", func(s *screen) bool {
		return strings.HasSuffix(s.text(0), "Esc ") && s.grid()[0][24].pen.attrs&attrReverse != 0
	})
	v.key("\x1b")
	v.waitSame(before)
}

func TestSuspendAndResume(t *testing.T) {
	v := newVTerm(t, 80, 24)
	orig, err := unix.IoctlGetTermios(v.fd, ioctlGetTermios)
	if err != nil {
		t.Fatal(err)
	}
	stops := make(chan *unix.Termios, 4)
	real := stopSelf
	stopSelf = func(<-chan os.Signal) {
		// What the shell gets while hop is stopped: the normal screen,
		// no mouse reports, the mode it had.
		for deadline := time.Now().Add(10 * time.Second); time.Now().Before(deadline); time.Sleep(5 * time.Millisecond) {
			v.mu.Lock()
			left := !v.scr.altActive && !v.scr.modes[1000] && !v.scr.keypad
			v.mu.Unlock()
			if left {
				tio, _ := unix.IoctlGetTermios(v.fd, ioctlGetTermios)
				stops <- tio
				return
			}
		}
		stops <- nil
	}
	t.Cleanup(func() { stopSelf = real })
	run(t, v, Options{Shortcuts: testShortcuts}, alt+`printf '\033[?1000h\033=\033[12;5H'; printf READY; exec cat >/dev/null`, "")
	v.waitText("READY")
	before := v.snapshot()
	check := func(how string) {
		t.Helper()
		select {
		case tio := <-stops:
			if tio == nil {
				t.Fatalf("%s: the terminal was not left to the shell", how)
			}
			if *tio != *orig {
				t.Errorf("%s: stopped with the terminal in mode %+v, want %+v", how, *tio, *orig)
			}
		case <-time.After(10 * time.Second):
			t.Fatalf("%s: hop did not stop", how)
		}
		v.waitSame(before)
		v.waitFor("the modes back", func(s *screen) bool { return s.modes[1000] && s.keypad })
	}
	v.key("\x1d")
	v.panelAt(40)
	v.key("\x1a")
	check("Ctrl-Z in the panel")
	syscall.Kill(os.Getpid(), syscall.SIGTSTP)
	check("SIGTSTP")
}

// The caller stops the child as hop stops, and continues it as hop is
// continued: OnSuspend before the stop, OnResume after it.
func TestSuspendHooks(t *testing.T) {
	v := newVTerm(t, 80, 24)
	var mu sync.Mutex
	var got []string
	note := func(s string) func() {
		return func() {
			mu.Lock()
			got = append(got, s)
			mu.Unlock()
		}
	}
	real := stopSelf
	stopSelf = func(<-chan os.Signal) { note("stop")() }
	t.Cleanup(func() { stopSelf = real })
	run(t, v, Options{Shortcuts: testShortcuts, OnSuspend: note("suspend"), OnResume: note("resume")}, `printf READY; exec cat >/dev/null`, "")
	v.waitText("READY")
	wait := func(how, want string) {
		t.Helper()
		for deadline := time.Now().Add(10 * time.Second); ; time.Sleep(10 * time.Millisecond) {
			mu.Lock()
			s := strings.Join(got, " ")
			mu.Unlock()
			if s == want {
				return
			}
			if time.Now().After(deadline) {
				t.Fatalf("%s: hooks and stops %q, want %q", how, s, want)
			}
		}
	}
	v.key("\x1d")
	v.panelAt(40)
	v.key("\x1a")
	wait("Ctrl-Z in the panel", "suspend stop resume")
	syscall.Kill(os.Getpid(), syscall.SIGTSTP)
	wait("SIGTSTP", "suspend stop resume suspend stop resume")
}

func TestNotATerminal(t *testing.T) {
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	defer w.Close()
	called := false
	err = Run(context.Background(), Options{In: r, Out: w}, func(*os.File, *syscall.SysProcAttr) (func() error, error) {
		called = true
		return func() error { return nil }, nil
	})
	if err != ErrNotTerminal || called {
		t.Fatalf("Run on pipes: %v, started %v", err, called)
	}
}
