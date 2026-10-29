package cli

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"golang.org/x/crypto/ssh"
)

// The authorized_keys edits of hop key rotate. hop reads the file over ssh,
// works out the new content here, and has one small POSIX sh script on the
// host swap it in. The script takes a lock that other hop runs respect
// (see akLockDir), checks that the file is still byte for byte what hop
// read (cksum and size), writes a temp file in ~/.ssh with the old file's
// mode and owner (cp -p) and the new content, checks the file once more,
// and renames the temp file over it. A mismatch anywhere stops it with
// nothing changed. Other hop runs are kept out by the lock, but a writer
// that does not take it (an editor, configuration management) can still
// change the file between the last check and the rename.

// akFile is the file hop edits. A server whose AuthorizedKeysFile points
// elsewhere shows up as a missing file, a missing old key, or a new key
// that does not log in, and the host fails with nothing changed.
const akFile = "~/.ssh/authorized_keys"

// Exit statuses of the remote scripts. ssh itself uses 255. Every one of
// these is returned before the rename, so the file is unchanged.
const (
	akExitSymlink = 81 // authorized_keys is a symbolic link
	akExitMissing = 82 // authorized_keys does not exist
	akExitChanged = 83 // the file changed since hop read it
	akExitWrite   = 84 // the new file could not be written
	akExitLocked  = 85 // another hop run holds the lock
)

// akMaxSize bounds the authorized_keys file hop will edit.
const akMaxSize = 1 << 20

// The lock of the write script, in ~/.ssh, is the directory akLockDir,
// which mkdir makes or fails to make in one step, and every hop run takes
// it the same way, whatever the host has installed. Inside it, the file
// "owner" says who holds it: a random token of the run, the PID of the
// remote shell, and the time it took the lock. The script removes the
// directory on the way out (exit, or HUP, INT, TERM or PIPE) only if
// "owner" still holds its token, so it never removes another run's lock.
// hop never takes a lock over: a remote script can outlive the ssh that
// started it, so neither an old lock nor a dead PID proves that its run
// has stopped (the PID may be on another machine that shares the home
// directory). A lock that stays for akLockWait seconds stops the edit with
// nothing changed (akExitLocked), and the message names the directory, its
// owner's PID and time, whether that PID is running on the host, and the
// command that removes it.
const akLockDir = ".hop-authorized_keys.lock.d"

// akLockWait is how many seconds the write script waits for the lock.
var akLockWait = 10

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
	tok := make([]byte, 16)
	rand.Read(tok)
	lock := strings.NewReplacer("TOKEN", hex.EncodeToString(tok), "LOCK", "~/.ssh/"+akLockDir, "WAIT", strconv.Itoa(akLockWait)).Replace(
		// hop_unlock removes the lock only while "owner" names this run.
		`hop_unlock() { rm -f "$t"; if { read -r ot op ow < "$d/owner"; } 2>/dev/null && [ "$ot" = "TOKEN" ]; then rm -f "$d/owner"; rmdir "$d"; fi; }; ` +
			`trap hop_unlock EXIT; trap 'hop_unlock; exit 86' HUP INT TERM PIPE; ` +
			`n=0; until mkdir "$d" 2>/dev/null; do n=$((n+1)); if [ $n -gt WAIT ]; then ` +
			`if { read -r ot op ow < "$d/owner"; } 2>/dev/null; then ` +
			`if kill -0 "$op" 2>/dev/null; then st="is still running"; else st="is not running"; fi; ` +
			`echo "LOCK is held by another hop run: process $op on this host took it at $ow, and that process $st; if no hop key rotate is running for this account, remove the lock (rm -r LOCK)" >&2; ` +
			`else echo "LOCK exists, with no owner in it: another hop run is taking it, or one was cut off; if no hop key rotate is running for this account, remove the lock (rm -r LOCK)" >&2; fi; ` +
			`exit 85; fi; sleep 1; done; ` +
			`if { echo "TOKEN $$ $(date -u +%Y-%m-%dT%H:%M:%SZ)" > "$d/owner"; } 2>/dev/null; then :; else rm -f "$d/owner"; rmdir "$d"; echo "cannot write the lock LOCK" >&2; exit 84; fi; `)
	return `umask 077; f="$HOME/.ssh/authorized_keys"; t="$HOME/.ssh/.authorized_keys.hop-$$"; d="$HOME/.ssh/` + akLockDir + `"; ` +
		`if [ -L "$f" ]; then echo "~/.ssh/authorized_keys is a symbolic link; hop does not edit it" >&2; exit 81; fi; ` +
		`if [ -f "$f" ]; then :; else echo "~/.ssh/authorized_keys does not exist" >&2; exit 82; fi; ` +
		// From here the exit status of a signal is not one of the above:
		// the rename may have happened.
		lock +
		check("$f", from, akExitChanged, "~/.ssh/authorized_keys changed while hop was editing it") +
		`(set -C; : > "$t") 2>/dev/null || { echo "cannot create a temporary file in ~/.ssh" >&2; exit 84; }; ` +
		`cp -p "$f" "$t" || exit 84; cat >| "$t" || exit 84; ` +
		check("$t", to, akExitWrite, "the new ~/.ssh/authorized_keys was not written completely") +
		check("$f", from, akExitChanged, "~/.ssh/authorized_keys changed while hop was editing it") +
		`mv -f "$t" "$f" || exit 84; ` +
		`if command -v restorecon >/dev/null 2>&1; then restorecon "$f" >/dev/null 2>&1; fi; exit 0`
}

// akRefused reports whether an exit status of the write script means it
// stopped before the rename.
func akRefused(code int) bool { return code >= akExitSymlink && code <= akExitLocked }

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

// parseAKLine reads one authorized_keys line as sshd does: the key type
// and its base64 at the start of the line, or else an options field first,
// which runs to the first space or tab outside double quotes (a \" does
// not end the quotes), and then the key. ok is false for blank lines,
// comments and anything sshd would not take as a key, which hop leaves
// alone.
func parseAKLine(line string) (k akKey, ok bool) {
	s := strings.TrimLeft(strings.TrimSuffix(line, "\r"), " \t")
	if s == "" || s[0] == '#' {
		return k, false
	}
	if pub, ok := parseAKKey(s); ok {
		return akKey{pub: pub}, true
	}
	end, ok := akOptionsEnd(s)
	if !ok {
		return k, false
	}
	pub, ok := parseAKKey(strings.TrimLeft(s[end:], " \t"))
	if !ok {
		return k, false
	}
	k = akKey{pub: pub, options: s[:end]}
	for _, o := range splitAKOptions(k.options) {
		if strings.EqualFold(o, "cert-authority") {
			k.certCA = true
		}
	}
	return k, true
}

// akOptionsEnd is sshd's sshkey_advance_past_options: the index of the
// first space or tab outside quotes. An unterminated quote is not ok.
func akOptionsEnd(s string) (int, bool) {
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

// splitAKOptions splits an options field at the commas outside quotes.
func splitAKOptions(opts string) []string {
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

// parseAKKey reads "<type> <base64>[ <comment>]": the key, if the type
// names a key and the base64 holds a key of that type.
func parseAKKey(s string) (ssh.PublicKey, bool) {
	typ, rest, ok := cutSpace(s)
	if !ok {
		return nil, false
	}
	b64, _, _ := cutSpace(strings.TrimLeft(rest, " \t"))
	blob, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return nil, false
	}
	pub, err := ssh.ParsePublicKey(blob)
	if err != nil || pub.Type() != typ {
		return nil, false
	}
	return pub, true
}

// cutSpace cuts s at its first space or tab.
func cutSpace(s string) (before, after string, found bool) {
	if i := strings.IndexAny(s, " \t"); i >= 0 {
		return s[:i], s[i+1:], true
	}
	return s, "", s != ""
}

// akEdit is the plan for one host's authorized_keys.
type akEdit struct {
	oldPub   ssh.PublicKey
	newPub   ssh.PublicKey
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

	ed := &akEdit{oldPub: oldPub, newPub: newPub, orig: orig}
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

// withoutKey is content without the lines that log in with pub (a
// cert-authority line does not), and how many lines it dropped.
func withoutKey(content []byte, pub ssh.PublicKey) ([]byte, int) {
	blob := pub.Marshal()
	var keep []string
	n := 0
	for _, l := range splitAK(content) {
		if k, ok := parseAKLine(l); ok && !k.certCA && bytes.Equal(k.pub.Marshal(), blob) {
			n++
			continue
		}
		keep = append(keep, l)
	}
	if n == 0 {
		return content, 0
	}
	return joinAK(keep), n
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

// oldLinesOnly is the part of ed that rollbackAK undoes to bring the old
// key's lines back while keeping the new key's.
func (ed *akEdit) oldLinesOnly() *akEdit {
	return &akEdit{oldPub: ed.oldPub, newPub: ed.newPub, removed: ed.removed}
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

// Where a host stands, as far as its authorized_keys says: hop key rotate
// keeps track of it for every host it changes.
const (
	remUnchanged  = "unchanged"       // the old key, and not the new one
	remAdded      = "new_key_added"   // both keys
	remOldRemoved = "old_key_removed" // the new key, and not the old one
	remUnknown    = "unknown"         // hop could not find out
)

// akState says which of the two keys authorized_keys content holds, on
// lines that log in (not cert-authority ones).
func akState(content []byte, oldPub, newPub ssh.PublicKey) string {
	oldBlob, newBlob := oldPub.Marshal(), newPub.Marshal()
	hasOld, hasNew := false, false
	for _, l := range splitAK(content) {
		k, ok := parseAKLine(l)
		if !ok || k.certCA {
			continue
		}
		hasOld = hasOld || bytes.Equal(k.pub.Marshal(), oldBlob)
		hasNew = hasNew || bytes.Equal(k.pub.Marshal(), newBlob)
	}
	switch {
	case hasOld && !hasNew:
		return remUnchanged
	case hasOld && hasNew:
		return remAdded
	case hasNew:
		return remOldRemoved
	}
	return remUnknown
}
