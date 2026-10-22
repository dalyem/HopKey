package cli

// Display safety.
//
// A string that comes from the vault (which later phases fill from other
// devices), from a config or filesystem path, or from the network can carry
// escape sequences, bidi overrides, line breaks and tabs. Encryption does not
// make a string safe to show. The rule is:
//
//	Every vault-, config-, filesystem- or network-derived string that reaches
//	human-readable output passes through oneLine (or printable) at the point
//	where it is inserted into a message, table or prompt.
//
// Sanitizing at the point of insertion matters because the finished message
// has line breaks of its own (layout), and a filter over the finished message
// cannot tell those from injected ones. reportError still runs displaySafe
// over what it prints, as a last line of defence.
//
// JSON output has the same control-character policy through escapeJSONControls.
// Text that is meant to be a live terminal session (the output of ssh from
// `hop <target>` and `hop exec`) is not sanitized; see the comments where
// those streams are wired.

import (
	"fmt"
	"strings"
	"unicode"
)

// unsafeRune reports whether c could redraw, reorder or otherwise rewrite
// what a terminal shows: C0 controls (including line breaks and tabs), DEL, C1
// (which covers the ANSI CSI introducer) and Unicode format characters such as
// bidi overrides.
func unsafeRune(c rune) bool {
	return c < ' ' || c == 0x7f || (c >= 0x80 && c < 0xa0) || unicode.Is(unicode.Cf, c)
}

// oneLine makes s safe to put on a single line of output: every character
// that unsafeRune reports becomes '?'. It does not truncate.
func oneLine(s string) string {
	return strings.Map(func(c rune) rune {
		if unsafeRune(c) {
			return '?'
		}
		return c
	}, s)
}

// oneLines applies oneLine to each element.
func oneLines(ss []string) []string {
	out := make([]string, len(ss))
	for i, s := range ss {
		out[i] = oneLine(s)
	}
	return out
}

// joinOne joins ss with sep after making each element single-line safe.
func joinOne(ss []string, sep string) string {
	return strings.Join(oneLines(ss), sep)
}

// maxShown caps one line of config text echoed back to the user.
const maxShown = 200

// printable is oneLine for a line of config text, which can be long, so it is
// also cut at maxShown characters.
func printable(s string) string {
	r := []rune(s)
	cut := len(r) > maxShown
	if cut {
		r = r[:maxShown]
	}
	out := oneLine(string(r))
	if cut {
		return out + "..."
	}
	return out
}

// safef is fmt.Sprintf for a message that quotes untrusted values: string,
// error and []string arguments are made single-line safe before they are
// formatted. The format itself must be constant text, whose own line breaks
// (if any) are layout.
func safef(format string, args ...any) string {
	clean := make([]any, len(args))
	for i, a := range args {
		switch v := a.(type) {
		case string:
			clean[i] = oneLine(v)
		case error:
			clean[i] = oneLine(v.Error())
		case []string:
			clean[i] = oneLines(v)
		default:
			clean[i] = a
		}
	}
	return fmt.Sprintf(format, clean...)
}

// cleanError is err with a display-safe message. It still unwraps to err, so
// errors.Is and errors.As see through it.
type cleanError struct {
	msg string
	err error
}

func (c *cleanError) Error() string { return c.msg }
func (c *cleanError) Unwrap() error { return c.err }

// cleanErr makes the message of an error that quotes a path or other
// untrusted text single-line safe at the place the error is produced.
func cleanErr(err error) error {
	if err == nil {
		return nil
	}
	msg := err.Error()
	if oneLine(msg) == msg {
		return err
	}
	return &cleanError{msg: oneLine(msg), err: err}
}
