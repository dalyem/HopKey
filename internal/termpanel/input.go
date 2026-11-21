package termpanel

import (
	"bytes"
	"slices"
	"strconv"
	"strings"
	"unicode/utf8"
)

// tokKind is what a token of the user's input is.
type tokKind int

const (
	tokText     tokKind = iota // one printable character
	tokControl                 // one C0 control or DEL
	tokSeq                     // an escape sequence: a key, a report, Alt with a key
	tokEsc                     // ESC on its own: the Esc key
	tokHotkey                  // the hotkey, pressed
	tokHotkeyUp                // the hotkey's repeat or release, in the kitty keyboard protocol
	tokPaste                   // part of a bracketed paste, markers included
)

type token struct {
	kind tokKind
	raw  []byte
}

var (
	pasteStart = []byte("\x1b[200~")
	pasteEnd   = []byte("\x1b[201~")
)

// maxSeq bounds an escape sequence; a longer one is passed on as it is.
const maxSeq = 4096

// inputParser splits what the terminal sends into keys, so the hotkey is
// found only as a key of its own: not inside an escape sequence, a
// multi-byte character or a bracketed paste. Ctrl with the hotkey's key
// in the kitty keyboard protocol (CSI 93;5u for Ctrl-]) or in xterm's
// modifyOtherKeys (CSI 27;5;93~) is the hotkey too, for when the remote
// side has turned those on.
type inputParser struct {
	hotkey  byte
	keys    hotkeyCodes // the hotkey's key codes, for the CSI forms
	pending []byte      // an unfinished escape sequence or character
	paste   bool
	match   int // how much of pasteEnd the paste has ended with
}

// hotkeyCodes are the key codes with which Ctrl is a hotkey in the kitty
// keyboard protocol and modifyOtherKeys, and whether Ctrl with Shift is
// too.
type hotkeyCodes struct {
	codes []int
	shift bool
}

// codesOf is the CSI forms of hotkey: none for a byte that is not a
// hotkey Options allows. For a letter, \ and ] it is the key itself.
// Ctrl-^ and Ctrl-_ are Shift with 6 and minus on many layouts (US ones
// among them), and the terminals differ: kitty reports the key without
// Shift, with Shift among the modifiers (CSI 54;6u, with the shifted key
// after a colon when asked: CSI 54:94;6u), xterm's modifyOtherKeys the
// character Shift gives (CSI 27;6;94~), and a layout with a key of its own
// for ^ or _ sends that key with Ctrl alone. So for those two, Ctrl with
// either key, with or without Shift, is the hotkey, as Ctrl-6 and Ctrl-^
// both send 0x1e without these protocols.
func codesOf(hotkey byte) hotkeyCodes {
	switch {
	case hotkey >= 0x01 && hotkey <= 0x1a:
		return hotkeyCodes{codes: []int{int('a' + hotkey - 1)}}
	case hotkey == 0x1c || hotkey == 0x1d:
		return hotkeyCodes{codes: []int{int(hotkey + 0x40)}}
	case hotkey == 0x1e:
		return hotkeyCodes{codes: []int{'^', '6'}, shift: true}
	case hotkey == 0x1f:
		return hotkeyCodes{codes: []int{'_', '-'}, shift: true}
	}
	return hotkeyCodes{}
}

// match says whether key with mods (kitty's encoding: 1 plus the
// modifier bits) is the hotkey. Caps Lock and Num Lock don't count.
func (h hotkeyCodes) match(key, mods int) bool {
	m := (mods - 1) &^ (64 | 128)
	return slices.Contains(h.codes, key) && (m == 4 || (h.shift && m == 5))
}

func newInputParser(hotkey byte) *inputParser {
	return &inputParser{hotkey: hotkey, keys: codesOf(hotkey)}
}

// feed returns the tokens in b. A sequence or character b leaves
// unfinished is held for the next feed, or for flush.
func (p *inputParser) feed(b []byte) []token {
	var out []token
	for i := 0; i < len(b); {
		if p.paste {
			start := i
			for i < len(b) && p.paste {
				c := b[i]
				i++
				switch {
				case c == pasteEnd[p.match]:
					p.match++
				case c == pasteEnd[0]:
					p.match = 1
				default:
					p.match = 0
				}
				if p.match == len(pasteEnd) {
					p.paste, p.match = false, 0
				}
			}
			out = append(out, token{tokPaste, b[start:i]})
			continue
		}
		if len(p.pending) == 0 {
			c := b[i]
			switch {
			case c == p.hotkey:
				out = append(out, token{tokHotkey, b[i : i+1]})
				i++
				continue
			case c == 0x1b, c >= 0xc0 && c < 0xf8:
				p.pending = append(p.pending, c)
				i++
				continue
			case c < 0x20 || c == 0x7f:
				out = append(out, token{tokControl, b[i : i+1]})
			default:
				// ASCII, or a byte that cannot start a character: the
				// remote side gets it as it is.
				out = append(out, token{tokText, b[i : i+1]})
			}
			i++
			continue
		}
		c := b[i]
		if p.pending[0] != 0x1b {
			if c&0xc0 != 0x80 {
				out = append(out, token{tokText, p.take()})
				continue // c starts a token of its own
			}
			p.pending = append(p.pending, c)
			i++
			if utf8.FullRune(p.pending) {
				out = append(out, token{tokText, p.take()})
			}
			continue
		}
		t, done, reuse := p.escape(c)
		if !reuse {
			i++
		}
		if done {
			out = append(out, t)
		}
	}
	return out
}

// escape adds c to the escape sequence in pending. done is that the
// sequence ended, as t; reuse is that c is not part of it and starts the
// next token.
func (p *inputParser) escape(c byte) (t token, done, reuse bool) {
	seq := p.pending
	if len(seq) >= maxSeq {
		return token{tokSeq, p.take()}, true, true
	}
	if len(seq) == 1 {
		switch {
		case c == 0x1b:
			// ESC ESC: the first is the Esc key, the second starts
			// what comes next.
			return token{tokEsc, p.take()}, true, true
		case c >= 0xc0 && c < 0xf8:
			// Alt with a multi-byte character: wait for the rest.
			p.pending = append(p.pending, c)
			return t, false, false
		}
		p.pending = append(p.pending, c)
		switch c {
		case '[', 'O', ']', 'P', 'X', '^', '_':
			return t, false, false
		}
		return token{tokSeq, p.take()}, true, false
	}
	switch seq[1] {
	case '[':
		if c < 0x20 || c > 0x7e {
			return token{tokSeq, p.take()}, true, true
		}
		p.pending = append(p.pending, c)
		if c >= 0x40 {
			return p.csi(), true, false
		}
		return t, false, false
	case 'O':
		if c < 0x20 || c > 0x7e {
			return token{tokSeq, p.take()}, true, true
		}
		p.pending = append(p.pending, c)
		if c >= 0x40 {
			return token{tokSeq, p.take()}, true, false
		}
		return t, false, false
	case ']', 'P', 'X', '^', '_':
		// A string (a reply to a query), ended by BEL or ST.
		p.pending = append(p.pending, c)
		if c == 0x07 || (c == '\\' && seq[len(seq)-1] == 0x1b) {
			return token{tokSeq, p.take()}, true, false
		}
		return t, false, false
	}
	// Alt with a multi-byte character.
	if c&0xc0 != 0x80 {
		return token{tokSeq, p.take()}, true, true
	}
	p.pending = append(p.pending, c)
	if utf8.FullRune(p.pending[1:]) {
		return token{tokSeq, p.take()}, true, false
	}
	return t, false, false
}

// csi classifies the complete CSI sequence in pending.
func (p *inputParser) csi() token {
	seq := p.take()
	switch {
	case bytes.Equal(seq, pasteStart):
		p.paste = true
		return token{tokPaste, seq}
	case len(p.keys.codes) == 0:
		return token{tokSeq, seq}
	}
	body, final := string(seq[2:len(seq)-1]), seq[len(seq)-1]
	nums := func(s string, sep byte) []int {
		var out []int
		for len(s) > 0 {
			j := 0
			for j < len(s) && s[j] != sep {
				j++
			}
			n, err := strconv.Atoi(s[:j])
			if err != nil {
				return nil
			}
			out = append(out, n)
			if j == len(s) {
				break
			}
			s = s[j+1:]
		}
		return out
	}
	switch final {
	case 'u':
		// key[:alternates];mods[:event]
		parts := splitOnce(body, ';')
		key := nums(splitOnce(parts[0], ':')[0], ':')
		if len(parts) < 2 || len(key) != 1 {
			break
		}
		modEv := nums(splitOnce(parts[1], ';')[0], ':')
		if len(modEv) == 0 || !p.keys.match(key[0], modEv[0]) {
			break
		}
		if len(modEv) > 1 && modEv[1] != 1 {
			return token{tokHotkeyUp, seq}
		}
		return token{tokHotkey, seq}
	case '~':
		if n := nums(body, ';'); len(n) == 3 && n[0] == 27 && p.keys.match(n[2], n[1]) {
			return token{tokHotkey, seq}
		}
	}
	return token{tokSeq, seq}
}
func splitOnce(s string, sep byte) []string {
	if i := strings.IndexByte(s, sep); i >= 0 {
		return []string{s[:i], s[i+1:]}
	}
	return []string{s}
}

// take returns pending and empties it.
func (p *inputParser) take() []byte {
	t := p.pending
	p.pending = nil
	return t
}

// held says whether part of a token is waiting for more input.
func (p *inputParser) held() bool { return len(p.pending) > 0 }

// flush returns what is held as a token of its own, when no more of it
// has come: ESC alone is the Esc key.
func (p *inputParser) flush() []token {
	if len(p.pending) == 0 {
		return nil
	}
	t := p.take()
	switch {
	case len(t) == 1 && t[0] == 0x1b:
		return []token{{tokEsc, t}}
	case t[0] == 0x1b:
		return []token{{tokSeq, t}}
	}
	return []token{{tokText, t}}
}
