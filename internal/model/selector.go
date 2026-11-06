package model

import (
	"strings"
	"unicode"
)

// Selector keys: two names, aliases or tags are the same selector exactly
// when their keys are equal. Host lookup and the merge (crypto spec rev 17,
// §5.4) both use these, so the merge's idea of "the same alias" or "the
// same tag" can never drift from what a lookup or a tag filter matches.

// NameKey is how host lookup compares a name or an alias: lower case, no
// surrounding white space, no trailing dot.
func NameKey(s string) string { return strings.ToLower(strings.TrimSuffix(strings.TrimSpace(s), ".")) }

// TagKey is the class key of a tag: each rune replaced by the smallest rune
// in its Unicode simple case-folding orbit. TagKey(a) == TagKey(b) exactly
// when strings.EqualFold(a, b), which is how a tag filter matches.
// strings.ToLower is not such a key: EqualFold("ſ", "s") is true, but
// ToLower("ſ") is "ſ".
func TagKey(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		b.WriteRune(foldMin(r))
	}
	return b.String()
}

// foldMin is the smallest rune in r's simple folding orbit.
func foldMin(r rune) rune {
	m := r
	for f := unicode.SimpleFold(r); f != r; f = unicode.SimpleFold(f) {
		m = min(m, f)
	}
	return m
}
