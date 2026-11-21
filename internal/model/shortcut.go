package model

import (
	"fmt"
	"slices"
	"strings"
)

// MaxShortcutCommand is the longest command a shortcut may type, in bytes.
const MaxShortcutCommand = 4096

// ShortcutReservedKeys are the printable keys the session panel keeps for
// itself: '?' shows its help. Esc and the panel hotkey are control
// characters, which shortcut keys never are.
const ShortcutReservedKeys = "?"

// CheckShortcutKeys enforces the form of a shortcut's keys (§6.5): one or
// two printable ASCII characters other than space. Keys the panel reserves
// are refused when a shortcut is written (the daemon's put_shortcut), not
// here, so that a later panel can reserve fewer.
func CheckShortcutKeys(keys string) error {
	if len(keys) < 1 || len(keys) > 2 {
		return fmt.Errorf("shortcut keys are one or two characters, not %d", len(keys))
	}
	for i := 0; i < len(keys); i++ {
		if c := keys[i]; c <= ' ' || c > '~' {
			return fmt.Errorf("shortcut keys are printable ASCII characters other than space")
		}
	}
	return nil
}

// ShortcutKeysClash reports whether two key sequences cannot share a
// panel: they are equal, or one is a prefix of the other (a one-key
// shortcut would fire before the second key of the other is pressed).
func ShortcutKeysClash(a, b string) bool {
	return strings.HasPrefix(a, b) || strings.HasPrefix(b, a)
}

// ShortcutInPanel is one shortcut of a host's panel, with the shortcuts it
// hides.
type ShortcutInPanel struct {
	Shortcut Shortcut
	// Hides is every other shortcut that clashes with this one in the
	// panel and so does not appear in it.
	Hides []Shortcut
}

// EffectiveShortcuts is the panel of host: its own shortcuts, then the
// global ones, each group sorted by keys. A zero host is the panel of a
// session to no vault host, with the global shortcuts only. Every
// shortcut whose keys clash (ShortcutKeysClash) with one already in the
// panel is hidden by it, so no two in the panel clash: a host shortcut
// goes in before every global one, and within one scope the shortcut with
// the lower item ID does. Writers refuse a clash within one scope; two
// devices can still each add one, and this picks the same winner on
// every device.
func EffectiveShortcuts(all []Shortcut, host ID) []ShortcutInPanel {
	var own, global []Shortcut
	for _, s := range all {
		switch {
		case s.HostID.IsZero():
			global = append(global, s)
		case s.HostID == host && !host.IsZero():
			own = append(own, s)
		}
	}
	byID := func(a, b Shortcut) int { return strings.Compare(a.ItemID.String(), b.ItemID.String()) }
	slices.SortFunc(own, byID)
	slices.SortFunc(global, byID)
	var panel []ShortcutInPanel
	place := func(group []Shortcut) {
		start := len(panel)
		for _, s := range group {
			if i := slices.IndexFunc(panel, func(p ShortcutInPanel) bool { return ShortcutKeysClash(p.Shortcut.Keys, s.Keys) }); i >= 0 {
				panel[i].Hides = append(panel[i].Hides, s)
				continue
			}
			panel = append(panel, ShortcutInPanel{Shortcut: s})
		}
		slices.SortFunc(panel[start:], func(a, b ShortcutInPanel) int {
			if c := strings.Compare(a.Shortcut.Keys, b.Shortcut.Keys); c != 0 {
				return c
			}
			return byID(a.Shortcut, b.Shortcut)
		})
	}
	place(own)
	place(global)
	return panel
}
