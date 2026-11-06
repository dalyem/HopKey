package redact

import (
	"bytes"
	"encoding/json"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"
)

// Escaped is v as a program that escapes what it prints may show it, in
// each form that differs from v: inside the quotes of Go's %q
// (strconv.Quote) and of a JSON string, with and without encoding/json's
// HTML escapes; and as OpenSSH's client prints a server's text, through
// its log (sshLogVis) and as a banner (sshBannerVis, in a C and in a UTF-8
// locale). Literals looks for each.
func Escaped(v string) []string {
	q := strconv.Quote(v)
	forms := []string{
		q[1 : len(q)-1],
		jsonInner(v, true),
		jsonInner(v, false),
		sshLogVis(v),
		sshBannerVis(v, false),
		sshBannerVis(v, true),
	}
	var out []string
	for _, f := range forms {
		if f != v && f != "" && !slices.Contains(out, f) {
			out = append(out, f)
		}
	}
	return out
}

// jsonInner is v as a JSON string holds it, without the quotes.
func jsonInner(v string, html bool) string {
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(html)
	if err := enc.Encode(v); err != nil {
		return v
	}
	s := strings.TrimSuffix(b.String(), "\n")
	return s[1 : len(s)-1]
}

// sshLogVis is v as OpenSSH's log writes it to stderr: strnvis with
// VIS_SAFE|VIS_OCTAL (log.c), which is how ssh prints a server's
// disconnect message. A backslash is doubled; a printable ASCII byte, a
// space, a tab, a newline, a carriage return, a bell and a backspace
// stand as they are; any other byte, every non-ASCII one included, is
// written in octal, \ooo.
func sshLogVis(v string) string {
	var b strings.Builder
	for i := 0; i < len(v); i++ {
		switch c := v[i]; {
		case c == '\\':
			b.WriteString(`\\`)
		case ' ' <= c && c <= '~', c == '\t', c == '\n', c == '\r', c == '\a', c == '\b':
			b.WriteByte(c)
		default:
			fmt.Fprintf(&b, `\%03o`, c)
		}
	}
	return b.String()
}

// sshBannerVis is v as OpenSSH's client prints a server's banner:
// fmprintf (utf8.c), which writes each byte of a character it cannot
// print in octal, \ooo, and the rest as they are, a backslash included. A
// tab, a newline and a carriage return stand as they are. In a C locale
// nothing outside ASCII prints; in a UTF-8 one a valid character the C
// library calls printable does, which unicode's graphic and format
// characters approximate.
func sshBannerVis(v string, utf8Locale bool) string {
	var b strings.Builder
	for i := 0; i < len(v); {
		c := v[i]
		if ' ' <= c && c <= '~' || c == '\t' || c == '\n' || c == '\r' {
			b.WriteByte(c)
			i++
			continue
		}
		r, n := utf8.DecodeRuneInString(v[i:])
		valid := r != utf8.RuneError || n > 1
		if utf8Locale && c >= utf8.RuneSelf && valid && (unicode.IsGraphic(r) || unicode.Is(unicode.Cf, r)) {
			b.WriteString(v[i : i+n])
			i += n
			continue
		}
		for _, c := range []byte(v[i : i+n]) {
			fmt.Fprintf(&b, `\%03o`, c)
		}
		i += n
	}
	return b.String()
}
