package store

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

// Server text is escaped for a terminal: controls, bidi and other format
// characters, separators and invalid UTF-8 become escapes, a backslash is
// doubled, and long text is cut.
func TestEscapeServerText(t *testing.T) {
	for in, want := range map[string]string{
		"overdue":              "overdue",
		"naïve café":           "naïve café",
		"a\x1b[2Jb":            `a\x1b[2Jb`,
		"tab\tnl\n":            `tab\x09nl\x0a`,
		"del\x7f c1\u009b":     `del\x7f c1\x9b`,
		"bidi\u202egnp":        `bidi\u202egnp`,
		"sep\u2028":            `sep\u2028`,
		"bad\xff":              `bad\xff`,
		`back\slash`:           `back\\slash`,
		strings.Repeat("a", 3): "aaa",
	} {
		if got := EscapeServerText(in); got != want {
			t.Errorf("EscapeServerText(%q) = %q, want %q", in, got, want)
		}
	}
	// A cut text, the mark included, is never longer than the limit,
	// and an escape is never split.
	for _, in := range []string{
		strings.Repeat("x", 1000),
		strings.Repeat("x", maxServerText+1),
		strings.Repeat("x", maxServerText-1) + "\u202e",
		strings.Repeat("x", maxServerText-4) + "\u202e" + "y",
	} {
		got := EscapeServerText(in)
		if len(got) > maxServerText || !strings.HasSuffix(got, "...") || strings.Contains(got, `\u202`) && !strings.Contains(got, `\u202e`) {
			t.Errorf("%d bytes in: %d bytes out, %q", len(in), len(got), got[max(0, len(got)-12):])
		}
	}
	if got := EscapeServerText(strings.Repeat("x", maxServerText)); got != strings.Repeat("x", maxServerText) {
		t.Errorf("text of exactly the limit was cut: %q", got)
	}
}

// An AdminRefusal matches ErrAdminRefused, through wrapping too, and its
// text names what the operator did, with the reason escaped.
func TestAdminRefusal(t *testing.T) {
	err := fmt.Errorf("pull: %w", &AdminRefusal{Code: AdminDeviceBlocked, Reason: "lost\x1b[2J"})
	var ar *AdminRefusal
	if !errors.Is(err, ErrAdminRefused) || !errors.As(err, &ar) || ar.Code != AdminDeviceBlocked {
		t.Fatalf("%v does not match", err)
	}
	if s := err.Error(); !strings.Contains(s, "blocked this device") || !strings.Contains(s, `"lost\x1b[2J"`) || strings.ContainsRune(s, 0x1b) {
		t.Errorf("text %q", s)
	}
	if s := (&AdminRefusal{Code: AdminAccountDisabled}).Error(); s != "the server's operator disabled this account" {
		t.Errorf("without a reason: %q", s)
	}
	if s := (&AdminRefusal{Code: AdminAccountDeleted}).Error(); s != "the server's operator deleted this account" {
		t.Errorf("a deleted account: %q", s)
	}
	if errors.Is(ErrSessionEnded, ErrAdminRefused) {
		t.Error("ErrSessionEnded matches ErrAdminRefused")
	}
}
