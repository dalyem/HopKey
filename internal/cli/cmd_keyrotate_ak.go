package cli

import (
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/ssh"
)

// The authorized_keys edits of hop key rotate. hop reads the file over ssh,
// works out the new content here, and has a small POSIX sh script on the
// host swap it in: a temp file in ~/.ssh, a copy of the old file's mode and
// owner (cp -p), the new content, then a rename. The script checks the
// file's cksum against what hop read before it renames, so an edit made by
// someone else in between is never overwritten.

// akFile is the file hop edits. A server whose AuthorizedKeysFile points
// elsewhere shows up as a missing file, a missing old key, or a new key
// that does not log in, and the host fails with nothing changed.
const akFile = "~/.ssh/authorized_keys"

// Exit statuses of the remote scripts. ssh itself uses 255.
const (
	akExitSymlink = 81 // authorized_keys is a symbolic link
	akExitMissing = 82 // authorized_keys does not exist
	akExitChanged = 83 // the file changed since hop read it
	akExitWrite   = 84 // the new file could not be written
)

// akMaxSize bounds the authorized_keys file hop will edit.
const akMaxSize = 1 << 20

// akReadScript prints authorized_keys.
const akReadScript = `f="$HOME/.ssh/authorized_keys"; ` +
	`if [ -L "$f" ]; then echo "~/.ssh/authorized_keys is a symbolic link; hop does not edit it" >&2; exit 81; fi; ` +
	`if [ -f "$f" ]; then :; else echo "~/.ssh/authorized_keys does not exist" >&2; exit 82; fi; ` +
	`exec cat -- "$f"`

// akWriteScript replaces authorized_keys with its stdin, if the file's
// cksum is still from and the new content's is to. It has no newline and
// no '!', so any login shell passes it to sh unchanged.
func akWriteScript(from, to string) string {
	check := func(file, want string, code int, msg string) string {
		return fmt.Sprintf(`c=$(cksum < "%s") || exit 84; set -- $c; if [ "$1 $2" = "%s" ]; then :; else echo "%s" >&2; exit %d; fi; `, file, want, msg, code)
	}
	return `f="$HOME/.ssh/authorized_keys"; t="$HOME/.ssh/.authorized_keys.hop-$$"; ` +
		`if [ -L "$f" ]; then echo "~/.ssh/authorized_keys is a symbolic link; hop does not edit it" >&2; exit 81; fi; ` +
		`if [ -f "$f" ]; then :; else echo "~/.ssh/authorized_keys does not exist" >&2; exit 82; fi; ` +
		check("$f", from, akExitChanged, "~/.ssh/authorized_keys changed while hop was editing it") +
		`(set -C; : > "$t") 2>/dev/null || { echo "cannot create a temporary file in ~/.ssh" >&2; exit 84; }; ` +
		`trap 'rm -f "$t"' EXIT; ` +
		`cp -p "$f" "$t" || exit 84; cat >| "$t" || exit 84; ` +
		check("$t", to, akExitWrite, "the new ~/.ssh/authorized_keys was not written completely") +
		check("$f", from, akExitChanged, "~/.ssh/authorized_keys changed while hop was editing it") +
		`mv -f "$t" "$f" || exit 84; ` +
		`if command -v restorecon >/dev/null 2>&1; then restorecon "$f" >/dev/null 2>&1; fi; exit 0`
}

// cksumTable is the CRC table of POSIX cksum: polynomial 0x04C11DB7, most
// significant bit first.
var cksumTable = func() (t [256]uint32) {
	for i := range t {
		c := uint32(i) << 24
		for range 8 {
			if c&0x80000000 != 0 {
				c = c<<1 ^ 0x04C11DB7
			} else {
				c <<= 1
			}
		}
		t[i] = c
	}
	return t
}()

// cksum is what POSIX `cksum < file` prints for data, without the newline:
// the CRC and the length.
func cksum(data []byte) string {
	var crc uint32
	for _, b := range data {
		crc = crc<<8 ^ cksumTable[byte(crc>>24)^b]
	}
	for n := len(data); n > 0; n >>= 8 {
		crc = crc<<8 ^ cksumTable[byte(crc>>24)^byte(n)]
	}
	return fmt.Sprintf("%d %d", ^crc, len(data))
}

// akKey is an authorized_keys line that holds a key.
type akKey struct {
	pub     ssh.PublicKey
	options string // the options before the key type, exactly as written; "" for none
	certCA  bool   // a cert-authority line: it trusts certificates, not the key itself
}

// parseAKLine reads one authorized_keys line. ok is false for blank lines,
// comments and anything that does not parse, which hop leaves alone.
func parseAKLine(line string) (k akKey, ok bool) {
	s := strings.TrimSpace(strings.TrimSuffix(line, "\r"))
	if s == "" || s[0] == '#' {
		return k, false
	}
	pub, _, opts, rest, err := ssh.ParseAuthorizedKey([]byte(s))
	if err != nil || len(bytes.TrimSpace(rest)) > 0 {
		return k, false
	}
	// The options are kept as written, quotes and all: the text before the
	// key type, which is the word before the key's base64.
	blob := base64.StdEncoding.EncodeToString(pub.Marshal())
	i := strings.Index(s, blob)
	if i < 0 {
		return k, false
	}
	head := strings.TrimRight(s[:i], " \t")
	if j := strings.LastIndexAny(head, " \t"); j >= 0 {
		k.options = strings.TrimSpace(head[:j])
	}
	for _, o := range opts {
		if strings.EqualFold(o, "cert-authority") {
			k.certCA = true
		}
	}
	k.pub = pub
	return k, true
}

// akEdit is the plan for one host's authorized_keys.
type akEdit struct {
	orig     []byte
	appended []byte   // orig with the new key's lines added
	final    []byte   // appended without the old key's lines
	added    []string // the lines hop added, without newline
	removed  []string // the old key's lines, as they were
}

var (
	errOldKeyMissing = errors.New("the old key is not in " + akFile + "; the server may read it from somewhere else (AuthorizedKeysFile, authorized_keys2) or force a command for it. Nothing was changed")
	errOldKeyCertCA  = errors.New("the old key is in " + akFile + " only as a cert-authority, which hop does not rotate. Nothing was changed")
)

// splitAK splits authorized_keys content into lines, without the newline
// that ends the last one.
func splitAK(content []byte) []string {
	s := string(content)
	if s == "" {
		return nil
	}
	return strings.Split(strings.TrimSuffix(s, "\n"), "\n")
}

func joinAK(lines []string) []byte {
	if len(lines) == 0 {
		return []byte{}
	}
	return []byte(strings.Join(lines, "\n") + "\n")
}

// planAKEdit works out the edit of authorized_keys content orig that moves
// every line of oldPub to newPub: a new line with the same options and the
// comment comment is added for each, unless the new key is already there
// with those options, and the old lines are then removed. Other lines are
// not touched, and their order is kept.
func planAKEdit(orig []byte, oldPub, newPub ssh.PublicKey, comment string) (*akEdit, error) {
	lines := splitAK(orig)
	oldBlob, newBlob := oldPub.Marshal(), newPub.Marshal()
	var oldIdx []int
	var oldOpts []string
	present := map[string]bool{} // options of the lines that already hold the new key
	certOnly := false
	for i, l := range lines {
		k, ok := parseAKLine(l)
		if !ok {
			continue
		}
		switch {
		case bytes.Equal(k.pub.Marshal(), oldBlob) && k.certCA:
			certOnly = true
		case bytes.Equal(k.pub.Marshal(), oldBlob):
			oldIdx = append(oldIdx, i)
			oldOpts = append(oldOpts, k.options)
		case bytes.Equal(k.pub.Marshal(), newBlob):
			present[k.options] = true
		}
	}
	if len(oldIdx) == 0 {
		if certOnly {
			return nil, errOldKeyCertCA
		}
		return nil, errOldKeyMissing
	}

	ed := &akEdit{orig: orig}
	keyText := newPub.Type() + " " + base64.StdEncoding.EncodeToString(newBlob)
	for _, o := range oldOpts {
		if present[o] {
			continue
		}
		present[o] = true
		line := keyText + " " + comment
		if o != "" {
			line = o + " " + line
		}
		ed.added = append(ed.added, line)
	}
	appended := append(lines[:len(lines):len(lines)], ed.added...)
	ed.appended = joinAK(appended)
	if len(ed.added) == 0 {
		ed.appended = orig
	}
	var final []string
	for i, l := range appended {
		if i < len(lines) && containsInt(oldIdx, i) {
			ed.removed = append(ed.removed, l)
			continue
		}
		final = append(final, l)
	}
	ed.final = joinAK(final)
	return ed, nil
}

func containsInt(s []int, v int) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}

// rollbackAK undoes ed in cur, the file as it is now: the lines hop added
// go, and the old key's lines hop removed come back at the end. Lines
// anyone else changed meanwhile are kept. changed is false when cur needs
// nothing.
func rollbackAK(cur []byte, ed *akEdit) (out []byte, changed bool) {
	lines := splitAK(cur)
	var keep []string
	for _, l := range lines {
		if containsLine(ed.added, l) {
			changed = true
			continue
		}
		keep = append(keep, l)
	}
	for _, r := range ed.removed {
		if !containsLine(keep, r) {
			keep = append(keep, r)
			changed = true
		}
	}
	if !changed {
		return cur, false
	}
	return joinAK(keep), true
}

// containsLine compares lines without a trailing carriage return.
func containsLine(lines []string, l string) bool {
	l = strings.TrimSuffix(l, "\r")
	for _, x := range lines {
		if strings.TrimSuffix(x, "\r") == l {
			return true
		}
	}
	return false
}
