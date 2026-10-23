// Package email holds the phase 2 email address rules (plan R4), shared by
// the server and its clients so both sides normalize an address the same
// way.
package email

import (
	"errors"
	"strings"
)

// ErrInvalid is returned for an address outside the phase 2 email rules.
var ErrInvalid = errors.New("email: invalid email address")

// Normalize applies the phase 2 email rules (R4). It removes leading and
// trailing ASCII SP and HTAB only, keeps the local part byte for byte, and
// lowercases ASCII A-Z in the domain only. It accepts only an ASCII
// dot-atom local part of 1 to 64 bytes and an ASCII DNS domain name
// (A-labels included), at most 254 bytes in all. Quoted local parts,
// domain literals, any remaining whitespace, control characters and
// non-ASCII characters are refused. No Unicode normalization or case
// folding is applied.
//
// The same function serves invite issuance, capability binding, signup
// proofs, uniqueness, prelogin and email-keyed rate limits.
func Normalize(s string) (string, error) {
	s = strings.Trim(s, " \t")
	if len(s) > 254 {
		return "", ErrInvalid
	}
	for i := 0; i < len(s); i++ {
		if c := s[i]; c <= ' ' || c >= 0x7f {
			return "", ErrInvalid
		}
	}
	local, domain, ok := strings.Cut(s, "@")
	if !ok || !dotAtom(local) || len(local) > 64 {
		return "", ErrInvalid
	}
	domain = asciiLower(domain)
	if !dnsName(domain) {
		return "", ErrInvalid
	}
	return local + "@" + domain, nil
}

// dotAtom reports whether s is an RFC 5322 dot-atom: atext runs separated
// by single dots, with no leading or trailing dot. "@" is not atext, so a
// second "@" fails here.
func dotAtom(s string) bool {
	if s == "" {
		return false
	}
	for _, atom := range strings.Split(s, ".") {
		if atom == "" {
			return false
		}
		for i := 0; i < len(atom); i++ {
			if !atext(atom[i]) {
				return false
			}
		}
	}
	return true
}

func atext(c byte) bool {
	switch {
	case 'a' <= c && c <= 'z', 'A' <= c && c <= 'Z', '0' <= c && c <= '9':
		return true
	}
	return strings.IndexByte("!#$%&'*+-/=?^_`{|}~", c) >= 0
}

// dnsName reports whether s (already lowercased) is a DNS name of LDH
// labels: 1 to 63 bytes each, no leading or trailing hyphen, at most 253
// bytes, no trailing dot. A-labels ("xn--...") are LDH labels.
func dnsName(s string) bool {
	if s == "" || len(s) > 253 {
		return false
	}
	for _, label := range strings.Split(s, ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for i := 0; i < len(label); i++ {
			c := label[i]
			if !('a' <= c && c <= 'z' || '0' <= c && c <= '9' || c == '-') {
				return false
			}
		}
	}
	return true
}

func asciiLower(s string) string {
	b := []byte(s)
	for i, c := range b {
		if 'A' <= c && c <= 'Z' {
			b[i] = c + ('a' - 'A')
		}
	}
	return string(b)
}
