package termpanel

import (
	"strings"
	"unicode"
	"unicode/utf8"

	"golang.org/x/text/width"
)

// runeWidth is how many columns r takes in a terminal: 0 for a combining
// or other zero-width character, 2 for an East Asian wide or full-width
// one, else 1. Terminals do not all agree, for emoji especially; this is
// the common ground (wcwidth's rules over x/text's Unicode tables).
func runeWidth(r rune) int {
	switch {
	case r < 0x20 || (r >= 0x7f && r < 0xa0):
		return 0
	case r < 0x300:
		return 1
	case unicode.In(r, unicode.Mn, unicode.Me, unicode.Cf),
		r >= 0x1160 && r <= 0x11ff, // Hangul medial vowels and final consonants
		r == 0x200b:
		return 0
	}
	switch width.LookupRune(r).Kind() {
	case width.EastAsianWide, width.EastAsianFullwidth:
		return 2
	}
	return 1
}

// strWidth is the columns s takes, by runeWidth.
func strWidth(s string) int {
	n := 0
	for _, r := range s {
		n += runeWidth(r)
	}
	return n
}

// displaySafe returns s with nothing in it that a terminal would act on
// or that could disguise the text: a C0 control or DEL becomes caret
// notation (^[ for ESC), and a C1 control, a format character (such as
// a bidirectional override), a line or paragraph separator or invalid
// UTF-8 becomes U+FFFD.
func displaySafe(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); {
		r, n := utf8.DecodeRuneInString(s[i:])
		i += n
		switch {
		case r == utf8.RuneError && n == 1:
			b.WriteRune(utf8.RuneError)
		case r < 0x20:
			b.WriteByte('^')
			b.WriteByte(byte(r) + 0x40)
		case r == 0x7f:
			b.WriteString("^?")
		case r < 0xa0 && r >= 0x80, unicode.In(r, unicode.Cf, unicode.Zl, unicode.Zp):
			b.WriteRune(utf8.RuneError)
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}

// typeable returns s without the characters that must never be typed for
// the user: C0 and C1 controls, TAB among them, DEL and invalid UTF-8. A
// control character typed into a shell or an editor is a keystroke (Enter,
// Ctrl-C, Esc, Tab's completion), not text. The shortcut schema already
// refuses them; this is in case a caller passes one on.
func typeable(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); {
		r, n := utf8.DecodeRuneInString(s[i:])
		i += n
		if (r == utf8.RuneError && n == 1) || unicode.IsControl(r) {
			continue
		}
		b.WriteRune(r)
	}
	return b.String()
}

// truncate cuts s to at most w columns, ending it with ell when it is cut.
func truncate(s string, w int, ell string) string {
	if strWidth(s) <= w {
		return s
	}
	ew := strWidth(ell)
	if w < ew {
		return strings.Repeat(" ", max(w, 0))
	}
	var b strings.Builder
	n := 0
	for _, r := range s {
		rw := runeWidth(r)
		if n+rw > w-ew {
			break
		}
		b.WriteRune(r)
		n += rw
	}
	b.WriteString(strings.Repeat(" ", w-ew-n)) // a wide character did not fit
	b.WriteString(ell)
	return b.String()
}

// pad fills s with spaces to w columns; s must be at most w wide.
func pad(s string, w int) string {
	if n := strWidth(s); n < w {
		return s + strings.Repeat(" ", w-n)
	}
	return s
}
