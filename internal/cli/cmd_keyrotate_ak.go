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

	"github.com/dalyem/hopkey/internal/access"
)

// The authorized_keys edits of hop key rotate. hop reads the file over ssh,
// works out the new content here, and has one small POSIX sh script on the
// host swap it in. The script takes a lock that other hop runs respect
// (see akLockDir), checks that the file is still byte for byte what hop
// read (cksum and size), makes a session directory of its own in ~/.ssh,
// writes a temp file there with the old file's mode and owner (cp -p) and
// the new content, checks the file once more, and renames the temp file
// over it. A mismatch anywhere stops it with nothing changed. Other hop
// runs are kept out by the lock, but a writer that does not take it (an
// editor, configuration management) can still change the file between the
// last check and the rename.

// akFile is the file hop edits. A server whose AuthorizedKeysFile points
// elsewhere shows up as a missing file, a missing old key, or a new key
// that does not log in, and the host fails with nothing changed.
const akFile = "~/.ssh/authorized_keys"

// Exit statuses of the remote scripts. ssh itself uses 255. Every one of
// 81 to 85 is returned before the rename, so the file is unchanged; after
// 86 and 89 the rename may have happened.
const (
	akExitSymlink   = 81 // authorized_keys is a symbolic link
	akExitMissing   = 82 // authorized_keys does not exist
	akExitChanged   = 83 // the file changed since hop read it
	akExitWrite     = 84 // a step before the rename failed: the lock's owner, the session directory, the temp file, the hard-link probe, the new content
	akExitLocked    = 85 // another hop run holds the lock
	akExitUncertain = 86 // mv failed, or a signal ended the script
	akExitCleanup   = 89 // the run could not confirm that it removed its session directory or released its lock
)

// akMaxSize bounds the authorized_keys file hop will edit.
const akMaxSize = 1 << 20

// The lock of the write script, in ~/.ssh, is the directory akLockDir,
// which mkdir makes or fails to make in one step, and every hop run takes
// it the same way, whatever the host has installed. hop access is to take
// the same lock (spec rev 17, §7.7). Inside it, the file "owner" says who
// holds it: a random token of the run, the PID of the remote shell, and
// the time it took the lock. The PID is for the message only: no script
// probes or signals it. On the way out (exit, or HUP, INT, TERM or PIPE)
// the script removes its session directory and then the lock, only if
// "owner" still holds its token, so it never removes another run's lock;
// when it cannot confirm either step it says so, keeps the lock and exits
// akExitCleanup. hop never takes a lock over: a remote script can outlive
// the ssh that started it, so neither an old lock nor a dead PID proves
// that its run has stopped (the PID may be on another machine that shares
// the home directory). A lock that stays for akLockWait seconds stops the
// edit with nothing changed (akExitLocked), and the message names the
// directory, its owner's PID and time, and when it is safe to remove it.
const akLockDir = ".hop-authorized_keys.lock.d"

// akLockWait is how many seconds the write script waits for the lock.
var akLockWait = 10

// akKeepalive are the ssh options of every connection that runs the write
// script: a server that stops answering ends the connection after about
// 45 seconds. They are on the command line, so they win over any config.
var akKeepalive = []string{"-o", "ServerAliveInterval=15", "-o", "ServerAliveCountMax=3"}

// akReadScript prints authorized_keys.
const akReadScript = `f="$HOME/.ssh/authorized_keys"; ` +
	`if [ -L "$f" ]; then echo "~/.ssh/authorized_keys is a symbolic link; hop does not edit it" >&2; exit 81; fi; ` +
	`if [ -f "$f" ]; then :; else echo "~/.ssh/authorized_keys does not exist" >&2; exit 82; fi; ` +
	`exec cat -- "$f"`

// The messages of the write script. LOCK and TOKEN are filled in.
const (
	akHeldAdvice = `hop key rotate and hop access both use this lock, and hop never removes it on its own. ` +
		`Remove it (rm -r LOCK) only when no hop key rotate and no hop access run can still be active for this account: ` +
		`on every device you use, and on every machine that shares this home directory. ` +
		`If you remove it while one is active, run hop access check afterwards.`
	akHeldMsg    = `LOCK is held by another hop run: process $op took it at $ow, on the machine that took it. ` + akHeldAdvice
	akNoOwnerMsg = `LOCK exists, with no owner in it: another hop run is taking it, or one was cut off. ` + akHeldAdvice
	akProbeMsg   = `hop's temporary file can't be hard-linked into ~/.ssh, so hop can't be sure that replacing ~/.ssh/authorized_keys would be a rename; nothing changed`
	akDirKeptMsg = `hop could not confirm that it removed its session directory ~/.ssh/.hop-s.TOKEN, so it left the lock LOCK in place. ` +
		`Check the file with hop access check, remove ~/.ssh/.hop-s.TOKEN if it is still there, and then follow the advice for a held lock before you remove LOCK.`
	akLostLockMsg = `the lock LOCK was removed, replaced or unreadable when this hop run went to release it, ` +
		`so another hop run may have edited ~/.ssh/authorized_keys at the same time. Run hop access check.`
	akUnlockMsg = `hop could not remove its lock LOCK. This hop run has finished; remove the lock (rm -r LOCK) once ` +
		`no hop key rotate and no hop access run is active for this account, on any of your devices or machines that share this home directory.`
)

// akWriteScript replaces authorized_keys with its stdin, if the file's
// cksum is still from and the new content's is to. Each call draws a new
// token, which owns the lock and names the session's paths.
func akWriteScript(from, to string) string {
	tok := make([]byte, 16)
	rand.Read(tok)
	return akTokenScript(hex.EncodeToString(tok), from, to)
}

// akTokenScript is akWriteScript with the token given. No path in it
// holds a PID: two runs whose shells have the same PID (on two machines
// that share the home directory) never touch each other's files. Every
// command runs in the foreground, and the exit trap runs once, after the
// last one has returned, so the rename never lands after the release.
//
// The script is one line, sent through the login shell as one quoted word
// (sh): no newline (tcsh), no '!' (csh history), no '#', and no backslash
// before a backslash or a quote (fish). It is tested on Linux with dash
// and bash as sh, and under those as login shells. Other shells (busybox
// ash, the sh of FreeBSD or macOS, mksh, ksh, and zsh, fish or tcsh as the
// login shell) are run by the tests only where the test machine has them,
// and are not part of what hop claims to support.
func akTokenScript(token, from, to string) string {
	return akFill(token, akScriptHead+akScriptWrite(`"`+from+`"`, `"`+to+`"`))
}

// akFill substitutes the token, the lock and the wait into a script.
func akFill(token, script string) string {
	return strings.NewReplacer("TOKEN", token, "LOCK", "~/.ssh/"+akLockDir, "WAIT", strconv.Itoa(akLockWait)).Replace(script)
}

// akScriptHead is what every hop edit of authorized_keys does first: the
// symlink and missing-file checks, the lock, the owner line and the
// session directory, with the exit trap that undoes them. hop key
// rotate's write script and hop access's locked session both start with
// it (spec rev 17, §7.7).
const akScriptHead = `umask 077; f="$HOME/.ssh/authorized_keys"; d="$HOME/.ssh/` + akLockDir + `"; s="$HOME/.ssh/.hop-s.TOKEN"; p="$HOME/.ssh/.hop-p.TOKEN"; l=; o=; m=; x=; ` +
	`if [ -L "$f" ]; then echo "~/.ssh/authorized_keys is a symbolic link; hop does not edit it" >&2; exit 81; fi; ` +
	`if [ -f "$f" ]; then :; else echo "~/.ssh/authorized_keys does not exist" >&2; exit 82; fi; ` +
	// same FILE "CRC SIZE": the file's cksum is that.
	`same() { y=$(cksum < "$1") || return 1; set -- $y "$2"; [ "$1 $2" = "$3" ]; }; ` +
	`owned() { { read -r ot op ow < "$d/owner"; } 2>/dev/null && [ "$ot" = "TOKEN" ]; }; ` +
	// hop_end removes what this run made, and only that, trusting
	// nothing but the exit statuses of rm and rmdir: $m the session
	// directory, $l the lock, $o its owner line. If it cannot confirm the
	// directory is gone, it keeps the lock.
	`hop_end() { r=$1; trap '' HUP INT TERM PIPE; trap - EXIT; ` +
	`if [ -n "$m" ]; then if rm -f "$s/new" "$p" && rmdir "$s"; then :; else echo "` + akDirKeptMsg + `" >&2; exit 89; fi; fi; ` +
	`if [ -n "$l" ]; then if [ -n "$o" ] && owned; then :; elif [ -n "$o" ]; then echo "` + akLostLockMsg + `" >&2; exit 89; fi; ` +
	`if rm -f "$d/owner" && rmdir "$d"; then :; else echo "` + akUnlockMsg + `" >&2; exit 89; fi; fi; ` +
	`exit "$r"; }; ` +
	// From here the exit status of a signal is not one of 81-85: the
	// rename may have happened. While the script takes the lock and
	// makes its session directory, a signal is only noted ($x): one that
	// ended it between a mkdir and its flag would leave the lock, or the
	// directory, behind. Once the flags are set the signal ends it, at
	// once if one came.
	`trap 'hop_end $?' EXIT; trap 'x=1' HUP INT TERM PIPE; ` +
	`n=0; until mkdir "$d" 2>/dev/null; do [ -z "$x" ] || exit 86; n=$((n+1)); if [ $n -gt WAIT ]; then ` +
	`if { read -r ot op ow < "$d/owner"; } 2>/dev/null; then echo "` + akHeldMsg + `" >&2; ` +
	`else echo "` + akNoOwnerMsg + `" >&2; fi; ` +
	`exit 85; fi; sleep 1; done; l=1; ` +
	`if { echo "TOKEN $$ $(date -u +%Y-%m-%dT%H:%M:%SZ)" > "$d/owner"; } 2>/dev/null; then o=1; else echo "cannot write the lock LOCK" >&2; exit 84; fi; ` +
	`if mkdir "$s" 2>/dev/null; then m=1; else echo "cannot create ~/.ssh/.hop-s.TOKEN" >&2; exit 84; fi; ` +
	`trap 'hop_end 86' HUP INT TERM PIPE; [ -z "$x" ] || hop_end 86; `

// akScriptWrite is the compare-then-rename: the file's cksum must still be
// from, the temp file in the session directory must be hard-linkable into
// ~/.ssh, the new content (stdin) must have cksum to, and the file is
// compared once more before the rename. from and to are shell words.
func akScriptWrite(from, to string) string {
	changed := `{ echo "~/.ssh/authorized_keys changed while hop was editing it" >&2; exit 83; }; `
	return `same "$f" ` + from + ` || ` + changed +
		`(set -C; : > "$s/new") 2>/dev/null || { echo "cannot create a temporary file in ~/.ssh/.hop-s.TOKEN" >&2; exit 84; }; ` +
		// The probe: if the temp file can be hard-linked into ~/.ssh,
		// rename(2) cannot fail with EXDEV, so mv renames or fails; it
		// never falls back to copying into authorized_keys.
		`{ ln "$s/new" "$p" 2>/dev/null && rm -f "$p"; } || { echo "` + akProbeMsg + `" >&2; exit 84; }; ` +
		`cp -p "$f" "$s/new" || exit 84; cat >| "$s/new" || exit 84; ` +
		`same "$s/new" ` + to + ` || { echo "the new ~/.ssh/authorized_keys was not written completely" >&2; exit 84; }; ` +
		`same "$f" ` + from + ` || ` + changed +
		`mv -f "$s/new" "$f" || exit 86; ` +
		`if command -v restorecon >/dev/null 2>&1; then restorecon "$f" >/dev/null 2>&1; fi; exit 0`
}

// The locked session of hop access (spec rev 17, §7.7): rotate's write
// script with the read and the decision inside the lock. Once it holds the
// lock it sends one header line, "hop-session 1 USER CRC SIZE", and then
// the file; then it reads one decision line from stdin: "abort", or
// "write FROM_CRC FROM_SIZE TO_CRC TO_SIZE" followed by the new content to
// the end of input. Anything else, or the end of input before a whole
// line, exits akExitDecision with nothing changed.
const akExitDecision = 87

const akSessionBody = `x=$(cksum < "$f") || exit 84; set -- $x; u=$(id -un) || exit 84; ` +
	`echo "hop-session 1 $u $1 $2"; cat -- "$f" || exit 84; ` +
	`num() { [ -n "$1" ] && [ -z "$(printf %s "$1" | tr -d 0-9)" ]; }; ` +
	`if read -r cmd a b c e; then :; else exit 87; fi; ` +
	`if [ "$cmd" = write ]; then :; else exit 87; fi; ` +
	`for v in "$a" "$b" "$c" "$e"; do num "$v" || exit 87; done; `

// akSessionScript is the access session with token.
func akSessionScript(token string) string {
	return akFill(token, akScriptHead+akSessionBody+akScriptWrite(`"$a $b"`, `"$c $e"`))
}

// akSessionRefused reports whether a session's exit status means it
// stopped before the rename: 81 to 85, and 87.
func akSessionRefused(code int) bool { return akRefused(code) || code == akExitDecision }

// akRefused reports whether an exit status of the write script means it
// stopped before the rename. Every other status, 86 and 89 among them,
// means the rename may have happened.
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

// akKey is an authorized_keys line that holds a key (access.KeyLine).
type akKey struct {
	pub     ssh.PublicKey
	options string // the options before the key type, exactly as written; "" for none
	certCA  bool   // a cert-authority line: it trusts certificates, not the key itself
	comment string // after the key, without the spaces and tabs around it
	// marker is the record ID of the hop access marker the comment
	// carries ("" for an ID hop cannot read), and marked says it carries
	// one at all. Rotate never touches a marked line.
	marker string
	marked bool
}

// readMarker is access.ReadMarker.
func readMarker(comment string) (id string, marked bool) { return access.ReadMarker(comment) }

// parseAKLine reads one authorized_keys line as sshd does
// (access.ParseKeyLine). ok is false for blank lines, comments (hop access
// tombstones among them) and anything sshd would not take as a key, which
// hop leaves alone.
func parseAKLine(line string) (k akKey, ok bool) {
	l, ok := access.ParseKeyLine(line)
	if !ok {
		return k, false
	}
	return akKey{pub: l.Pub, options: l.Options, certCA: l.CertCA, comment: l.Comment, marker: l.Marker, marked: l.Marked}, true
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

// markedOldLines describes the lines of content that carry a hop access
// marker and log in with pub: "record ID", or "an unknown record" for a
// marker hop cannot read. Rotate leaves those lines alone, so while one is
// there the old key is not gone.
func markedOldLines(content []byte, pub ssh.PublicKey) []string {
	blob := pub.Marshal()
	var out []string
	for _, l := range splitAK(content) {
		k, ok := parseAKLine(l)
		if !ok || !k.marked || k.certCA || !bytes.Equal(k.pub.Marshal(), blob) {
			continue
		}
		if k.marker == "" {
			out = append(out, "an unknown record")
		} else {
			out = append(out, "record "+k.marker)
		}
	}
	return out
}

// markedProblem says that hop access lines still let the old key in.
func markedProblem(marked []string) string {
	if len(marked) == 1 {
		return "a hop access line (" + marked[0] + ") still authorizes the old key; rotate left it"
	}
	return "hop access lines (" + strings.Join(marked, ", ") + ") still authorize the old key; rotate left them"
}

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
// not touched, and their order is kept. A line that carries a hop access
// marker is never a source, never counts as the new key's, and is never
// removed: it belongs to hop access.
func planAKEdit(orig []byte, oldPub, newPub ssh.PublicKey, comment string) (*akEdit, error) {
	lines := splitAK(orig)
	oldBlob, newBlob := oldPub.Marshal(), newPub.Marshal()
	var oldIdx []int
	var oldOpts []string
	present := map[string]bool{} // options of the lines that already hold the new key
	certOnly := false
	for i, l := range lines {
		k, ok := parseAKLine(l)
		if !ok || k.marked {
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
		if marked := markedOldLines(orig, oldPub); len(marked) > 0 {
			return nil, errors.New("the old key is in " + akFile + " only on hop access lines (" + strings.Join(marked, ", ") + "), which rotate doesn't touch. Nothing was changed")
		}
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
// cert-authority line does not), and how many lines it dropped. It keeps
// the lines that carry a hop access marker.
func withoutKey(content []byte, pub ssh.PublicKey) ([]byte, int) {
	blob := pub.Marshal()
	var keep []string
	n := 0
	for _, l := range splitAK(content) {
		if k, ok := parseAKLine(l); ok && !k.certCA && !k.marked && bytes.Equal(k.pub.Marshal(), blob) {
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
// the lines rotate edits: lines that log in (not cert-authority ones) and
// carry no hop access marker.
func akState(content []byte, oldPub, newPub ssh.PublicKey) string {
	oldBlob, newBlob := oldPub.Marshal(), newPub.Marshal()
	hasOld, hasNew := false, false
	for _, l := range splitAK(content) {
		k, ok := parseAKLine(l)
		if !ok || k.certCA || k.marked {
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
