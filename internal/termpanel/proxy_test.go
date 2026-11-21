//go:build linux || darwin

package termpanel

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"slices"
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
	return runCtx(t, context.Background(), v, opts, script, arg0)
}

// runCtx is run with ctx for Run's.
func runCtx(t *testing.T, ctx context.Context, v *vterm, opts Options, script, arg0 string) *proc {
	t.Helper()
	opts.In, opts.Out = v.tty, v.tty
	if opts.DoubleTap == 0 {
		opts.DoubleTap = 50 * time.Millisecond
	}
	c := &proc{started: make(chan struct{}), runErr: make(chan error, 1)}
	go func() {
		c.runErr <- Run(ctx, opts, func(tty *os.File, sys *syscall.SysProcAttr) (func() error, error) {
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
	before.cur.pen = pen{} // the session is over: plain attributes
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
			left := !v.scr.altActive && !v.scr.modes[1000] && !v.scr.keypad &&
				!v.scr.kitty[0].active() && !v.scr.kitty[1].active() && v.scr.otherKeys == 0
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
	run(t, v, Options{Shortcuts: testShortcuts}, alt+`printf '\033[?1000h\033=\033[>5u\033[>4;1m\033[12;5H'; printf READY; exec cat >/dev/null`, "")
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
		v.waitFor("the modes back", func(s *screen) bool {
			return s.modes[1000] && s.keypad && slices.Equal(s.kitty[1].pushed, []int{5}) && !s.kitty[0].active() && s.otherKeys == 1
		})
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

// select can't wait on a descriptor from 1024 up. When one of the
// descriptors the proxy would wait on is, Run says so before it starts
// anything, and the caller runs the child directly.
func TestRunRefusesHighDescriptors(t *testing.T) {
	var rl unix.Rlimit
	if err := unix.Getrlimit(unix.RLIMIT_NOFILE, &rl); err != nil {
		t.Fatal(err)
	}
	if rl.Cur < 2*maxFd {
		if rl.Max < 2*maxFd {
			t.Skipf("the descriptor limit is %d", rl.Max)
		}
		old := rl
		rl.Cur = 2 * maxFd
		if err := unix.Setrlimit(unix.RLIMIT_NOFILE, &rl); err != nil {
			t.Skip(err)
		}
		t.Cleanup(func() { unix.Setrlimit(unix.RLIMIT_NOFILE, &old) })
	}
	v := newVTerm(t, 80, 24)
	orig, err := unix.IoctlGetTermios(v.fd, ioctlGetTermios)
	if err != nil {
		t.Fatal(err)
	}
	null, err := unix.Open("/dev/null", unix.O_RDONLY|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	held := []int{null}
	t.Cleanup(func() {
		for _, fd := range held {
			unix.Close(fd)
		}
	})
	// Every descriptor below 1023 in use: the pty's master gets 1023,
	// which select can wait on, and the descriptors after it can't.
	for {
		fd, err := unix.Dup(null)
		if err != nil {
			t.Fatal(err)
		}
		held = append(held, fd)
		if fd >= maxFd-2 {
			break
		}
	}
	err = Run(context.Background(), Options{In: v.tty, Out: v.tty, Shortcuts: testShortcuts}, func(*os.File, *syscall.SysProcAttr) (func() error, error) {
		t.Error("Run started the child")
		return func() error { return nil }, nil
	})
	if !errors.Is(err, ErrUnsupported) {
		t.Errorf("Run: %v, want ErrUnsupported", err)
	}
	now, err := unix.IoctlGetTermios(v.fd, ioctlGetTermios)
	if err != nil {
		t.Fatal(err)
	}
	if *now != *orig {
		t.Errorf("terminal mode %+v, want %+v", *now, *orig)
	}
}

// A panic in the caller's wait unwinds through Run once the proxy's loop
// is stopped and joined: the terminal is put back and the pty closed with
// nothing of the loop left running.
func TestPanicInWaitStopsTheLoop(t *testing.T) {
	v := newVTerm(t, 80, 24)
	orig, err := unix.IoctlGetTermios(v.fd, ioctlGetTermios)
	if err != nil {
		t.Fatal(err)
	}
	var child *os.Process
	func() {
		defer func() {
			if r := recover(); r != "boom" {
				t.Fatalf("Run's panic: %v", r)
			}
		}()
		Run(context.Background(), Options{In: v.tty, Out: v.tty, Shortcuts: testShortcuts}, func(tty *os.File, sys *syscall.SysProcAttr) (func() error, error) {
			p, err := os.StartProcess("/bin/sh", []string{"sh", "-c", "stty raw -echo; exec yes"}, &os.ProcAttr{Files: []*os.File{tty, tty, tty}, Sys: sys})
			if err != nil {
				return nil, err
			}
			child = p
			return func() error {
				v.waitText("y") // the loop is busy with the output
				panic("boom")
			}, nil
		})
	}()
	if child != nil {
		child.Kill()
		child.Wait()
	}
	now, err := unix.IoctlGetTermios(v.fd, ioctlGetTermios)
	if err != nil {
		t.Fatal(err)
	}
	if *now != *orig {
		t.Errorf("terminal mode %+v, want %+v", *now, *orig)
	}
	buf := make([]byte, 1<<20)
	for deadline := time.Now().Add(time.Second); ; time.Sleep(10 * time.Millisecond) {
		n := runtime.Stack(buf, true)
		i := bytes.Index(buf[:n], []byte("(*proxy).loop("))
		if i < 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("the proxy's loop runs on after Run's panic:\n%s", buf[max(i-1000, 0):min(i+500, n)])
		}
	}
}

// resetSetup turns on, on the alternate screen, what the terminal must
// not keep once the session is over: mouse reports, focus events,
// bracketed paste, application cursor keys and keypad, the kitty
// keyboard protocol and modifyOtherKeys, bold red and a hidden cursor.
const resetSetup = `stty raw -echo
printf '\033[?1049h\033[?1000h\033[?1006h\033[?1004h\033[?2004h\033[?1h\033=\033[>1u\033[>4;2m\033[1;31m\033[?25lREADY'
exec cat >/dev/null
`

func waitReset(t *testing.T, v *vterm) {
	t.Helper()
	v.waitFor("the terminal as the shell had it", func(s *screen) bool {
		for _, m := range trackedModes {
			if s.modes[m] {
				return false
			}
		}
		return !s.altActive && !s.keypad && !s.kitty[0].active() && !s.kitty[1].active() && s.otherKeys == 0 &&
			s.visible && s.cur.pen == pen{}
	})
}

// When the session ends, the terminal is left as the shell had it, as on
// a suspend: whether ssh exits on its own or on a signal hop passes on,
// or Run's context ends with the panel open.
func TestSessionEndResetsTerminal(t *testing.T) {
	t.Run("child signalled", func(t *testing.T) {
		v := newVTerm(t, 80, 24)
		c := run(t, v, Options{Shortcuts: testShortcuts}, resetSetup, "")
		v.waitText("READY")
		v.waitFor("the remote side's modes", func(s *screen) bool { return s.altActive && s.modes[1000] && s.keypad })
		c.p.Signal(syscall.SIGTERM)
		c.wait(t)
		waitReset(t, v)
	})
	t.Run("context done, panel open", func(t *testing.T) {
		v := newVTerm(t, 80, 24)
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		c := runCtx(t, ctx, v, Options{Shortcuts: testShortcuts}, resetSetup, "")
		v.waitText("READY")
		v.key("\x1d")
		v.panelAt(40)
		cancel()
		c.wait(t)
		waitReset(t, v)
	})
}

// A child that never reads its input fills the queue of input hop holds
// for it, while it floods its output. When the read that fills the queue
// ends with the hotkey, the panel opens over a session that takes no
// input and whose output waits for the panel: the panel's keys must still
// be read, or Esc could never close it.
func TestPanelUnderInputBackpressure(t *testing.T) {
	v := newVTerm(t, 80, 24)
	run(t, v, Options{Shortcuts: testShortcuts}, `stty raw -echo; exec yes`, "")
	v.waitText("y")
	opened := func(d time.Duration) bool {
		for deadline := time.Now().Add(d); time.Now().Before(deadline); time.Sleep(2 * time.Millisecond) {
			v.mu.Lock()
			up := v.scr.altActive && strings.Contains(v.scr.text(0), "Shortcuts")
			v.mu.Unlock()
			if up {
				return true
			}
		}
		return false
	}
	// One write, which the terminal passes on in one read: the queue
	// fills during a read that ends with the hotkey.
	chunk := strings.Repeat("a", 1000) + "\x1d"
	for sent := len(chunk); ; sent += len(chunk) {
		v.key(chunk)
		if !opened(2 * time.Second) {
			if sent <= writeLimit {
				t.Fatalf("the panel did not open after %d bytes of input", sent)
			}
			// The queue is full and the panel closed: hop reads no
			// more of the terminal until the child takes some input.
			return
		}
		v.key("\x1b")
		v.waitFor(fmt.Sprintf("Esc to close the panel after %d bytes of input", sent), func(s *screen) bool { return !s.altActive })
	}
}

// With the kitty keyboard protocol reporting every key, or xterm's
// modifyOtherKeys, the terminal sends the panel's keys as escape
// sequences: they do what the plain keys do, and a release does nothing.
func TestPanelTakesProtocolKeys(t *testing.T) {
	v := newVTerm(t, 80, 24)
	typed := filepath.Join(t.TempDir(), "typed")
	var mu sync.Mutex
	stops := 0
	real := stopSelf
	stopSelf = func(<-chan os.Signal) {
		mu.Lock()
		stops++
		mu.Unlock()
	}
	t.Cleanup(func() { stopSelf = real })
	run(t, v, Options{Shortcuts: testShortcuts}, fill+`exec cat >"$0"`, typed)
	v.waitText("READY")
	before := v.snapshot()

	v.key("\x1b[93;5u") // Ctrl-]
	v.panelAt(40)
	v.key("\x1b[117;1:3u") // u released
	v.key("\x1b[117u")
	waitFile(t, typed, "echo hi\r")
	v.waitSame(before)

	v.key("\x1b[93;5u")
	v.panelAt(40)
	v.key("\x1b[103;1:1u") // g, pressed
	v.waitText("Shortcuts: g")
	v.key("\x1b[127u") // Backspace
	v.waitFor("the full list again", func(s *screen) bool { return strings.Contains(s.text(0), "Shortcuts ") })
	v.key("\x1b[27;1;103~") // g in modifyOtherKeys
	v.waitText("Shortcuts: g")
	v.key("\x1b[115u")
	waitFile(t, typed, "echo hi\rgit status")
	v.waitSame(before)

	for _, k := range []string{"\x1b[27u", "\x1b[99;5u", "\x1b[27;5;99~", "\x1b[99;69u"} { // Esc, Ctrl-C, Ctrl-C, Ctrl-C with Caps Lock
		v.key("\x1b[27;5;93~") // Ctrl-] in modifyOtherKeys
		v.panelAt(40)
		v.key(k)
		v.waitSame(before)
	}
	v.key("\x1b[93;5u")
	v.panelAt(40)
	v.key("\x1b[122;5u") // Ctrl-Z
	for deadline := time.Now().Add(10 * time.Second); ; time.Sleep(5 * time.Millisecond) {
		mu.Lock()
		n := stops
		mu.Unlock()
		if n == 1 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("Ctrl-Z in the kitty keyboard protocol did not suspend hop")
		}
	}
	v.waitSame(before)
	time.Sleep(50 * time.Millisecond)
	waitFile(t, typed, "echo hi\rgit status")
}

func (w *writer) queued() int {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.n
}

// A child that does not read its input fills the queue of input hop holds
// for it. Then the panel adds nothing to the queue, nor does the input
// after it closes, however the keys come: here one read at a time, each
// submitting and opening the panel again. The panel says why it does
// nothing, and still closes.
func TestPanelKeepsInputQueueBounded(t *testing.T) {
	for _, c := range []struct{ name, keys string }{
		{"shortcut", "u\x1d"},
		{"hotkey twice", "\x1d\x1d"},
		{"typing after Ctrl-C", "\x03" + strings.Repeat("a", 1000) + "\x1d"},
	} {
		t.Run(c.name, func(t *testing.T) {
			v := newVTerm(t, 80, 24)
			sc := []Shortcut{{Keys: "u", Name: "Long", Command: strings.Repeat("x", maxCommand), Enter: true}}
			p, err := newProxy(Options{In: v.tty, Out: v.tty, Shortcuts: sc, DoubleTap: time.Hour})
			if err != nil {
				t.Fatal(err)
			}
			defer p.restore()
			// Nothing reads the other side of the child's pty: once that
			// is full, the queue fills. (In canonical mode the pty would
			// drop what does not fit in a line.)
			tio, err := unix.IoctlGetTermios(int(p.pts.Fd()), ioctlGetTermios)
			if err != nil {
				t.Fatal(err)
			}
			tio.Lflag &^= unix.ICANON | unix.ECHO
			if err := unix.IoctlSetTermios(int(p.pts.Fd()), ioctlSetTermios, tio); err != nil {
				t.Fatal(err)
			}
			for deadline := time.Now().Add(10 * time.Second); ; time.Sleep(20 * time.Millisecond) {
				if p.w.full() {
					time.Sleep(100 * time.Millisecond)
					if p.w.full() {
						break
					}
				}
				if time.Now().After(deadline) {
					t.Fatalf("the queue holds %d bytes", p.w.queued())
				}
				p.w.send(bytes.Repeat([]byte("q"), 4096))
			}
			limit := max(writeLimit, p.w.queued())
			p.openPanel()
			for i := 0; i < 50 && p.readsInput(); i++ {
				p.handle(p.ip.feed([]byte(c.keys)))
				if n := p.w.queued(); n > limit {
					t.Fatalf("after %d reads of %q the queue holds %d bytes, over %d", i+1, c.keys, n, limit)
				}
			}
			if !p.panel.open {
				// The rest waits for room, and the terminal is not read
				// meanwhile.
				if p.readsInput() {
					t.Fatal("the panel is closed, and the terminal is read with the queue full")
				}
				return
			}
			v.waitText(noteNotReading)
			for _, k := range []string{"\x1b", "\x03", "\x1d"} {
				if !p.panel.open {
					p.openPanel()
				}
				p.tap = 0 // the hotkey closes
				p.handle(append(p.ip.feed([]byte(k)), p.ip.flush()...))
				if p.panel.open {
					t.Fatalf("%q does not close the panel", k)
				}
			}
			if n := p.w.queued(); n > limit {
				t.Fatalf("the queue holds %d bytes, over %d", n, limit)
			}
		})
	}
}

// newStalledVTerm is a terminal that takes no output: nothing reads its
// pty's master.
func newStalledVTerm(t *testing.T) *vterm {
	t.Helper()
	m, s, err := openPTY()
	if err != nil {
		t.Fatal(err)
	}
	ws := unix.Winsize{Col: 80, Row: 24}
	if err := unix.IoctlSetWinsize(m, unix.TIOCSWINSZ, &ws); err != nil {
		t.Fatal(err)
	}
	v := &vterm{t: t, ptm: os.NewFile(uintptr(m), "ptm"), tty: s, fd: int(s.Fd()), scr: newScreen(80, 24), done: make(chan struct{})}
	close(v.done)
	t.Cleanup(func() {
		v.ptm.Close() // a write still waiting on the terminal fails
		v.tty.Close()
	})
	return v
}

// stall fills the terminal's buffer, from a descriptor of its own.
func (v *vterm) stall() {
	v.t.Helper()
	fd, err := unix.Open(v.tty.Name(), unix.O_WRONLY|unix.O_NOCTTY|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		v.t.Fatal(err)
	}
	defer unix.Close(fd)
	buf := bytes.Repeat([]byte("x"), 4096)
	for idle := 0; idle < 5; {
		_, err := unix.Write(fd, buf)
		switch {
		case err == unix.EAGAIN:
			idle++
			time.Sleep(20 * time.Millisecond)
		case err != nil:
			v.t.Fatal(err)
		default:
			idle = 0
		}
	}
}

// terminalState is the terminal's mode and its descriptor's flags.
func terminalState(t *testing.T, fd int) (unix.Termios, int) {
	t.Helper()
	tio, err := unix.IoctlGetTermios(fd, ioctlGetTermios)
	if err != nil {
		t.Fatal(err)
	}
	fl, err := unix.FcntlInt(uintptr(fd), unix.F_GETFL, 0)
	if err != nil {
		t.Fatal(err)
	}
	return *tio, fl
}

func checkTerminalState(t *testing.T, fd int, tio unix.Termios, fl int) {
	t.Helper()
	nowTio, nowFl := terminalState(t, fd)
	if nowTio != tio {
		t.Errorf("terminal mode %+v, want %+v", nowTio, tio)
	}
	if nowFl != fl {
		t.Errorf("file status flags %#x, want %#x", nowFl, fl)
	}
}

// A panic in the caller's wait while the loop waits to write to a
// terminal that takes no output still stops the loop, puts the terminal
// back and unwinds through Run.
func TestPanicWhileTerminalStalled(t *testing.T) {
	v := newStalledVTerm(t)
	tio, fl := terminalState(t, v.fd)
	children := make(chan *os.Process, 1)
	res := make(chan any, 1)
	go func() {
		defer func() { res <- recover() }()
		Run(context.Background(), Options{In: v.tty, Out: v.tty, Shortcuts: testShortcuts}, func(tty *os.File, sys *syscall.SysProcAttr) (func() error, error) {
			p, err := os.StartProcess("/bin/sh", []string{"sh", "-c", "stty raw -echo; exec yes"}, &os.ProcAttr{Files: []*os.File{tty, tty, tty}, Sys: sys})
			if err != nil {
				return nil, err
			}
			children <- p
			return func() error {
				time.Sleep(500 * time.Millisecond) // the terminal is full, the loop waits
				panic("boom")
			}, nil
		})
	}()
	select {
	case r := <-res:
		if r != "boom" {
			t.Fatalf("Run's panic: %v", r)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not panic with the terminal taking no output")
	}
	if p := <-children; p != nil {
		p.Kill()
		p.Wait()
	}
	checkTerminalState(t, v.fd, tio, fl)
}

// A terminal that takes no output gets what gives it back to the shell
// as far as it takes it, and its mode back in any case: when the session
// ends, and when hop stops for job control.
func TestStalledTerminal(t *testing.T) {
	t.Run("session end", func(t *testing.T) {
		v := newStalledVTerm(t)
		tio, fl := terminalState(t, v.fd)
		c := run(t, v, Options{Shortcuts: testShortcuts}, `stty raw -echo; printf '\033[?1000h'; exec cat >/dev/null`, "")
		time.Sleep(100 * time.Millisecond)
		v.stall()
		c.p.Kill()
		select {
		case err := <-c.runErr:
			c.runErr <- err
		case <-time.After(5 * time.Second):
			t.Fatal("Run did not return with the terminal taking no output")
		}
		checkTerminalState(t, v.fd, tio, fl)
	})
	t.Run("suspend", func(t *testing.T) {
		v := newStalledVTerm(t)
		tio, _ := terminalState(t, v.fd)
		stops := make(chan unix.Termios, 4)
		real := stopSelf
		stopSelf = func(<-chan os.Signal) {
			now, err := unix.IoctlGetTermios(v.fd, ioctlGetTermios)
			if err == nil {
				stops <- *now
			}
		}
		t.Cleanup(func() { stopSelf = real })
		c := run(t, v, Options{Shortcuts: testShortcuts}, `stty raw -echo; exec cat >/dev/null`, "")
		time.Sleep(100 * time.Millisecond)
		v.stall()
		syscall.Kill(os.Getpid(), syscall.SIGTSTP)
		select {
		case now := <-stops:
			if now != tio {
				t.Errorf("stopped with the terminal in mode %+v, want %+v", now, tio)
			}
		case <-time.After(5 * time.Second):
			t.Fatal("hop did not stop with the terminal taking no output")
		}
		c.p.Kill()
		select {
		case err := <-c.runErr:
			c.runErr <- err
		case <-time.After(5 * time.Second):
			t.Fatal("Run did not return with the terminal taking no output")
		}
	})
}
