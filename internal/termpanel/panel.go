package termpanel

import (
	"strconv"
	"strings"
)

// entry is a shortcut as the panel shows and runs it.
type entry struct {
	keys    string
	name    string // safe to draw
	command string // safe to draw
	typed   string // what is typed for it
	enter   bool
	host    bool
}

// maxCommand is the longest command a shortcut may type, in bytes, as in
// the shortcut schema.
const maxCommand = 4096

// entries checks and orders the shortcuts: host ones first, then global
// ones, each in the order given. One whose keys are not one or two
// printable ASCII characters is left out, and so is one whose command is
// longer than maxCommand, or whose keys an entry before it has: a host
// shortcut hides a global one with the same keys.
func entries(scs []Shortcut) []entry {
	var host, global []entry
	seen := map[string]bool{}
	for _, pass := range []bool{true, false} {
		for _, sc := range scs {
			if sc.Host != pass || !validKeys(sc.Keys) || len(sc.Command) > maxCommand || seen[sc.Keys] {
				continue
			}
			seen[sc.Keys] = true
			e := entry{
				keys:    sc.Keys,
				name:    displaySafe(sc.Name),
				command: displaySafe(sc.Command),
				typed:   typeable(sc.Command),
				enter:   sc.Enter,
				host:    sc.Host,
			}
			if pass {
				host = append(host, e)
			} else {
				global = append(global, e)
			}
		}
	}
	return append(host, global...)
}

func validKeys(k string) bool {
	if len(k) < 1 || len(k) > 2 {
		return false
	}
	for i := 0; i < len(k); i++ {
		if k[i] < 0x20 || k[i] > 0x7e {
			return false
		}
	}
	return true
}

// caret is how the panel names a control key: ^] for 0x1d.
func caret(b byte) string {
	if b < 0x20 {
		return "^" + string(rune(b+0x40))
	}
	return strconv.Quote(string(rune(b)))
}

type style uint8

const (
	styleNormal style = iota
	styleBold
	styleHost
	styleGlobal
	styleBar // the one-line panel
)

// sgr is the style's SGR: the standard colours and attributes only, so
// that it reads on light and dark backgrounds alike.
func (st style) sgr() string {
	switch st {
	case styleBold:
		return "\x1b[0;1m"
	case styleHost:
		return "\x1b[0;1;32m"
	case styleGlobal:
		return "\x1b[0;1;35m"
	case styleBar:
		return "\x1b[0;7m"
	}
	return "\x1b[0m"
}

type seg struct {
	text string
	st   style
}

// view is the panel laid out: lines of exactly width columns, drawn from
// row top, column left.
type view struct {
	top, left, width int
	lines            [][]seg
}

func (v view) height() int { return len(v.lines) }

// panelLook is what the layout needs besides the shortcuts.
type panelLook struct {
	hotkey     byte
	unicode    bool // box drawing and ellipsis characters; else ASCII
	canSuspend bool
	note       string // shown above the hints, when set
}

const (
	minWidth = 40
	maxWidth = 64
)

// layout lays the panel out for a cols by rows screen, in its top right
// corner: a box about a third of the width, or a one-line bar when the
// screen is too small for the box. prefix is the first key of a two-key
// shortcut, typed already: the box then lists only what it can start.
func layout(cols, rows int, es []entry, prefix string, look panelLook) view {
	hk := caret(look.hotkey)
	h, vbar, tl, tr, bl, br, ell, dot := "─", "│", "┌", "┐", "└", "┘", "…", " · "
	if !look.unicode {
		h, vbar, tl, tr, bl, br, ell, dot = "-", "|", "+", "+", "+", "+", "~", " - "
	}
	width := min(max(cols/3, minWidth), maxWidth, cols)
	text := width - 4

	shown := es
	if prefix != "" {
		shown = nil
		for _, e := range es {
			if strings.HasPrefix(e.keys, prefix) {
				shown = append(shown, e)
			}
		}
	}
	var body [][]seg
	rowsOf := func(host bool) (lines [][]seg) {
		nameW := 0
		for _, e := range shown {
			nameW = max(nameW, strWidth(e.name))
		}
		nameW = min(nameW, max(text/3, 8))
		cmdW := text - 2 - 2 - nameW - 2
		for _, e := range shown {
			if e.host != host {
				continue
			}
			line := []seg{{pad(e.keys, 2), styleBold}, {"  " + pad(truncate(e.name, nameW, ell), nameW) + "  ", styleNormal}}
			if cmdW > 0 {
				c := truncate(e.command, cmdW, ell)
				if e.keys == prefix {
					c = truncate("Enter: "+e.command, cmdW, ell)
				}
				line = append(line, seg{c, styleNormal})
			}
			lines = append(lines, line)
		}
		return lines
	}
	host, global := rowsOf(true), rowsOf(false)
	switch {
	case len(es) == 0:
		body = [][]seg{{{"No shortcuts.", styleNormal}}, {{"Add one with hop shortcut add.", styleNormal}}}
	default:
		if len(host) > 0 {
			body = append(body, []seg{{"Host shortcuts", styleHost}})
			body = append(body, host...)
		}
		if len(global) > 0 {
			body = append(body, []seg{{"Global shortcuts", styleGlobal}})
			body = append(body, global...)
		}
	}
	var hints []string
	if prefix != "" {
		hints = []string{"Backspace back", "Esc close"}
	} else {
		hints = []string{"Esc close", hk + hk + " sends " + hk}
		if look.canSuspend {
			hints = append(hints, "^Z suspends hop")
		}
	}
	footer := wrapHints(hints, dot, text)
	if look.note != "" {
		footer = append([][]seg{{{look.note, styleBold}}}, footer...)
	}

	room := rows - 1 - 2 - len(footer) // a line of the screen stays clear
	if cols < minWidth-10 || room < 1 {
		return bar(cols, es, prefix, hk, look.note)
	}
	if len(body) > room {
		cut := 0
		for _, l := range body[room-1:] {
			if l[0].st == styleBold {
				cut++
			}
		}
		body = append(body[:room-1], []seg{{ell + " " + strconv.Itoa(cut) + " more", styleNormal}})
	}

	title := " Shortcuts "
	if prefix != "" {
		title = " Shortcuts: " + prefix + " "
	}
	right := " " + hk + " close "
	fill := width - 2 - 1 - strWidth(title) - strWidth(right)
	if fill < 1 {
		right, fill = "", width-2-1-strWidth(title)
	}
	v := view{top: 0, left: cols - width, width: width}
	v.lines = append(v.lines, []seg{{tl + h, styleNormal}, {title, styleBold}, {strings.Repeat(h, fill) + right + tr, styleNormal}})
	for _, l := range append(body, footer...) {
		line := []seg{{vbar + " ", styleNormal}}
		n := 0
		for _, s := range l {
			s.text = truncate(s.text, text-n, ell)
			n += strWidth(s.text)
			line = append(line, s)
		}
		line = append(line, seg{strings.Repeat(" ", text-n) + " " + vbar, styleNormal})
		v.lines = append(v.lines, line)
	}
	v.lines = append(v.lines, []seg{{bl + strings.Repeat(h, width-2) + br, styleNormal}})
	return v
}

// wrapHints joins hints with sep into lines of at most w columns.
func wrapHints(hints []string, sep string, w int) [][]seg {
	var lines [][]seg
	cur := ""
	for _, h := range hints {
		switch {
		case cur == "":
			cur = h
		case strWidth(cur+sep+h) <= w:
			cur += sep + h
		default:
			lines = append(lines, []seg{{cur, styleNormal}})
			cur = h
		}
	}
	if cur != "" {
		lines = append(lines, []seg{{cur, styleNormal}})
	}
	return lines
}

// bar is the panel for a screen too small for the box: one reverse-video
// line in the top right corner with the note, if any, and the keys, or a
// notice when there is no shortcut.
func bar(cols int, es []entry, prefix, hk, note string) view {
	t := " " + hk + " "
	if note != "" {
		t += note + ": "
	}
	if len(es) == 0 {
		t += "no shortcuts "
	}
	for _, e := range es {
		if strings.HasPrefix(e.keys, prefix) {
			t += e.keys + " "
		}
	}
	t += "Esc "
	t = truncate(t, cols, "~")
	w := strWidth(t)
	return view{top: 0, left: cols - w, width: w, lines: [][]seg{{{t, styleBar}}}}
}
