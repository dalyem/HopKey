package access

import (
	"encoding/base64"
	"strings"

	"golang.org/x/crypto/ssh"
)

// KeyLine is an authorized_keys line that holds a key, read as sshd reads
// it (crypto spec rev 17, §6.1). hop key rotate and hop access share this
// parse.
type KeyLine struct {
	Pub     ssh.PublicKey
	Options string // the options before the key type, exactly as written; "" for none
	CertCA  bool   // a cert-authority line: it trusts certificates, not the key itself
	Comment string // after the key, without the spaces and tabs around it
	// Marker is the record ID of the hop access marker the comment
	// carries ("" for an ID hop cannot read), and Marked says it carries
	// one at all. Rotate never touches a marked line.
	Marker string
	Marked bool
}

// MarkerPrefix starts a hop access marker token in a comment.
const MarkerPrefix = "hop-access:"

// ReadMarker says whether a comment carries a hop access marker: a token
// (between spaces and tabs) that starts with hop-access:, in any case. id
// is the record ID after it when that is 32 lowercase hex digits.
func ReadMarker(comment string) (id string, marked bool) {
	for _, tok := range strings.FieldsFunc(comment, isBlank) {
		if len(tok) < len(MarkerPrefix) || !asciiEqualFold(tok[:len(MarkerPrefix)], MarkerPrefix) {
			continue
		}
		if id = tok[len(MarkerPrefix):]; !isRecordID(id) {
			id = ""
		}
		return id, true
	}
	return "", false
}

func isBlank(r rune) bool { return r == ' ' || r == '\t' }

func isRecordID(s string) bool { return len(s) == 32 && strings.Trim(s, "0123456789abcdef") == "" }

// asciiEqualFold compares a and b with ASCII letters folded, and no other.
func asciiEqualFold(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := 0; i < len(a); i++ {
		x, y := a[i], b[i]
		if 'A' <= x && x <= 'Z' {
			x += 'a' - 'A'
		}
		if 'A' <= y && y <= 'Z' {
			y += 'a' - 'A'
		}
		if x != y {
			return false
		}
	}
	return true
}

// ParseKeyLine reads one authorized_keys line, without its LF, as sshd
// does: one trailing CR and the leading spaces and tabs are removed; then
// the key type and its base64 at the start, or else an options field
// first, which runs to the first space or tab outside double quotes (a \"
// does not end the quotes), and then the key. ok is false for blank lines,
// comments (hop access tombstones among them) and anything sshd would not
// take as a key, which hop leaves alone.
func ParseKeyLine(line string) (k KeyLine, ok bool) {
	s := strings.TrimLeft(strings.TrimSuffix(line, "\r"), " \t")
	if s == "" || s[0] == '#' {
		return k, false
	}
	if pub, comment, ok := parseKey(s); ok {
		k = KeyLine{Pub: pub, Comment: comment}
		k.Marker, k.Marked = ReadMarker(comment)
		return k, true
	}
	end, ok := optionsEnd(s)
	if !ok {
		return k, false
	}
	pub, comment, ok := parseKey(strings.TrimLeft(s[end:], " \t"))
	if !ok {
		return k, false
	}
	k = KeyLine{Pub: pub, Options: s[:end], Comment: comment}
	k.Marker, k.Marked = ReadMarker(comment)
	for _, o := range splitOptions(k.Options) {
		if strings.EqualFold(o, "cert-authority") {
			k.CertCA = true
		}
	}
	return k, true
}

// optionsEnd is sshd's sshkey_advance_past_options: the index of the
// first space or tab outside quotes. An unterminated quote is not ok.
func optionsEnd(s string) (int, bool) {
	quoted := false
	i := 0
	for ; i < len(s) && (quoted || (s[i] != ' ' && s[i] != '\t')); i++ {
		switch {
		case s[i] == '\\' && i+1 < len(s) && s[i+1] == '"':
			i++ // both
		case s[i] == '"':
			quoted = !quoted
		}
	}
	return i, !(i == len(s) && quoted)
}

// splitOptions splits an options field at the commas outside quotes.
func splitOptions(opts string) []string {
	var out []string
	quoted, start := false, 0
	for i := 0; i < len(opts); i++ {
		switch {
		case opts[i] == '\\' && i+1 < len(opts) && opts[i+1] == '"':
			i++
		case opts[i] == '"':
			quoted = !quoted
		case opts[i] == ',' && !quoted:
			out = append(out, opts[start:i])
			start = i + 1
		}
	}
	return append(out, opts[start:])
}

// parseKey reads "<type> <base64>[ <comment>]": the key, if the type
// names a key and the base64 holds a key of that type, and the comment,
// without the spaces and tabs around it.
func parseKey(s string) (ssh.PublicKey, string, bool) {
	typ, rest, ok := cutSpace(s)
	if !ok {
		return nil, "", false
	}
	b64, comment, _ := cutSpace(strings.TrimLeft(rest, " \t"))
	blob, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return nil, "", false
	}
	pub, err := ssh.ParsePublicKey(blob)
	if err != nil || pub.Type() != typ {
		return nil, "", false
	}
	return pub, strings.Trim(comment, " \t"), true
}

// cutSpace cuts s at its first space or tab.
func cutSpace(s string) (before, after string, found bool) {
	if i := strings.IndexAny(s, " \t"); i >= 0 {
		return s[:i], s[i+1:], true
	}
	return s, "", s != ""
}

func decodeB64(s string) ([]byte, error) { return base64.StdEncoding.DecodeString(s) }

var rawStd = base64.RawStdEncoding.Strict()
