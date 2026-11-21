// Package termpanel runs an interactive child, such as ssh, on a pty of
// its own and copies between it and the user's terminal, adding a panel
// of shortcuts: the hotkey (Ctrl-] by default) opens it in the top right
// corner over the live session, a shortcut's keys type its command into
// the session, and Esc or the hotkey closes it, leaving the screen as it
// was. Pressing the hotkey twice quickly sends the hotkey itself.
//
// The proxy keeps a model of the screen (screen) to draw the panel over
// and to put back what was under it. While the panel is open the child's
// output is held: hop stops reading the pty, so the child waits, and the
// output follows once the panel is closed. On the normal screen the panel
// is drawn on the terminal's alternate screen, over a copy of the normal
// one, so closing it is the terminal's own switch back. On the alternate
// screen (vim, htop) closing it repaints the cells it covered.
package termpanel

import (
	"errors"
	"os"
	"time"
)

// DefaultHotkey is Ctrl-].
const DefaultHotkey = 0x1d

// DefaultDoubleTap is how soon a second press of the hotkey must follow
// the first to send the hotkey itself rather than close the panel.
const DefaultDoubleTap = 400 * time.Millisecond

// Options configures Run.
type Options struct {
	// In and Out are the user's terminal; both must be terminals.
	In, Out *os.File
	// Shortcuts are the panel's entries; see entries for the order.
	Shortcuts []Shortcut
	// Hotkey is the control character that opens the panel: 0x01-0x1f
	// but ESC. 0 is DefaultHotkey.
	Hotkey byte
	// DoubleTap is DefaultDoubleTap when 0.
	DoubleTap time.Duration
}

// ErrNotTerminal is Run's error when In or Out is not a terminal. The
// caller runs the child on its streams directly instead.
var ErrNotTerminal = errors.New("termpanel: not a terminal")

// ErrUnsupported is Run's error on a system it does not support: it
// supports Linux and macOS.
var ErrUnsupported = errors.New("termpanel: not supported on this system")

func (o Options) hotkey() (byte, error) {
	switch {
	case o.Hotkey == 0:
		return DefaultHotkey, nil
	case o.Hotkey >= 0x20 || o.Hotkey == 0x1b:
		return 0, errors.New("termpanel: the hotkey must be a control character other than ESC")
	}
	return o.Hotkey, nil
}
