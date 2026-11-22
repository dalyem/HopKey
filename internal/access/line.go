package access

import (
	"bytes"
	"fmt"
	"strconv"
	"strings"

	"golang.org/x/crypto/ssh"

	"github.com/dalyem/hopkey/internal/model"
)

// The managed line and the tombstone (crypto spec rev 17, §6.1, §6.1a).

// Render is render(o): the options field of a record's line, "" for none.
func Render(o model.AccessOptions) string {
	var parts []string
	if len(o.From) > 0 {
		parts = append(parts, `from="`+strings.Join(o.From, ",")+`"`)
	}
	if o.Restrict {
		parts = append(parts, "restrict")
	}
	if o.NoForwarding {
		parts = append(parts, "no-agent-forwarding", "no-port-forwarding", "no-X11-forwarding")
	}
	return strings.Join(parts, ",")
}

// Marker is the comment of a's line: hop-access: and its record ID.
func Marker(a *model.Access) string { return MarkerPrefix + a.RecordID.String() }

// LineBody is a's line without its LF: [render SP] public_key SP marker.
// It is checked before it is returned: printable ASCII only, and it parses
// back to a key line that isn't cert-authority, with a's key, options and
// marker (§6.1).
func LineBody(a *model.Access) (string, error) {
	body := a.PublicKey + " " + Marker(a)
	if r := Render(a.Options); r != "" {
		body = r + " " + body
	}
	if !printable(body) {
		return "", fmt.Errorf("access: the line for %s has a byte outside printable ASCII", a.Label)
	}
	k, ok := ParseKeyLine(body)
	pub, err := recordKey(a)
	if !ok || err != nil || k.CertCA || !bytes.Equal(k.Pub.Marshal(), pub.Marshal()) || k.Options != Render(a.Options) || k.Comment != Marker(a) {
		return "", fmt.Errorf("access: the line for %s does not parse back to its key, options and marker", a.Label)
	}
	return body, nil
}

func printable(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < 0x20 || s[i] > 0x7e {
			return false
		}
	}
	return true
}

func recordKey(a *model.Access) (ssh.PublicKey, error) {
	_, rest, _ := strings.Cut(a.PublicKey, " ")
	blob, err := decodeB64(strings.TrimLeft(rest, " "))
	if err != nil {
		return nil, err
	}
	return ssh.ParsePublicKey(blob)
}

// ManagedBy reports whether k is managed by a: not cert-authority, and its
// comment is exactly a's marker.
func ManagedBy(k KeyLine, a *model.Access) bool { return !k.CertCA && k.Comment == Marker(a) }

// Matches reports whether a line managed by a matches it: a's key blob,
// and options byte-equal to render(a.options).
func Matches(k KeyLine, a *model.Access) bool {
	pub, err := recordKey(a)
	return err == nil && bytes.Equal(k.Pub.Marshal(), pub.Marshal()) && k.Options == Render(a.Options)
}

// TombstonePrefix starts every tombstone.
const TombstonePrefix = "hop-access-removed"

// Tombstone is the tombstone line for record rid and gen, without its LF.
func Tombstone(rid model.ID, gen uint64) string {
	return "# " + TombstonePrefix + " " + rid.String() + " " + strconv.FormatUint(gen, 10)
}

// TombstoneLine is one tombstone-like line read from a file.
type TombstoneLine struct {
	Line     int    // 1-based
	Text     string // as in the file, without its LF
	RecordID string // "" when malformed
	Gen      uint64
}

// Malformed reports whether t is tombstone-like but not a tombstone.
func (t TombstoneLine) Malformed() bool { return t.RecordID == "" }

// ParseTombstone reads a raw line, without its LF: like says it is
// tombstone-like (a comment whose first token is hop-access-removed, in
// any case); rid and gen are set when it is a well-formed tombstone.
func ParseTombstone(line string) (like bool, rid string, gen uint64) {
	s := strings.TrimLeft(strings.TrimSuffix(line, "\r"), " \t")
	if !strings.HasPrefix(s, "#") {
		return false, "", 0
	}
	toks := strings.FieldsFunc(s[1:], isBlank)
	if len(toks) == 0 || !asciiEqualFold(toks[0], TombstonePrefix) {
		return false, "", 0
	}
	if len(toks) != 3 || toks[0] != TombstonePrefix || !isRecordID(toks[1]) {
		return true, "", 0
	}
	g := toks[2]
	if g == "" || g[0] == '0' || strings.Trim(g, "0123456789") != "" {
		return true, "", 0
	}
	n, err := strconv.ParseUint(g, 10, 64)
	if err != nil {
		return true, "", 0
	}
	return true, toks[1], n
}

// TombstoneBound is the number of tombstone-like lines at which a removal
// that needs a new tombstone refuses, and TombstoneWarn where hop starts
// to warn (§6.1a).
const (
	TombstoneBound = 128
	TombstoneWarn  = 100
)

// Facts is what an authorized_keys file holds for one record (§7.2):
// Mg, the lines managed by it; Kx, the other lines with its key that
// aren't cert-authority; Tb, its tombstones; and every tombstone-like line,
// Tm among them.
type Facts struct {
	lines []span
	Mg    []int // 0-based line indexes
	Kx    []int
	Tb    []TombstoneLine
	Tm    []TombstoneLine
	// Tombstones is every tombstone-like line in the file.
	Tombstones []TombstoneLine
}

// span is one line of a file: [start, end) without the LF.
type span struct{ start, end int }

func spans(content []byte) []span {
	var out []span
	for start := 0; start < len(content); {
		end := bytes.IndexByte(content[start:], '\n')
		if end < 0 {
			out = append(out, span{start, len(content)})
			break
		}
		out = append(out, span{start, start + end})
		start += end + 1
	}
	return out
}

// Lines splits content into its lines, without their LFs.
func Lines(content []byte) []string {
	var out []string
	for _, s := range spans(content) {
		out = append(out, string(content[s.start:s.end]))
	}
	return out
}

// FactsOf reads content for record a.
func FactsOf(content []byte, a *model.Access) Facts {
	f := Facts{lines: spans(content)}
	pub, _ := recordKey(a)
	rid := a.RecordID.String()
	for i, s := range f.lines {
		line := string(content[s.start:s.end])
		if like, r, g := ParseTombstone(line); like {
			t := TombstoneLine{Line: i + 1, Text: line, RecordID: r, Gen: g}
			f.Tombstones = append(f.Tombstones, t)
			switch {
			case t.Malformed():
				f.Tm = append(f.Tm, t)
			case r == rid:
				f.Tb = append(f.Tb, t)
			}
			continue
		}
		k, ok := ParseKeyLine(line)
		if !ok {
			continue
		}
		switch {
		case ManagedBy(k, a):
			f.Mg = append(f.Mg, i)
		case !k.CertCA && pub != nil && bytes.Equal(k.Pub.Marshal(), pub.Marshal()):
			f.Kx = append(f.Kx, i)
		}
	}
	return f
}

// Outcome of a planner's decision on a file read under the lock.
type Outcome int

const (
	OutWrite     Outcome = iota // write New with the compare-then-rename
	OutInstalled                // add: nothing to write, the line is there
	OutRemoved                  // rm: nothing to write, the line is gone and the tombstone there
	OutRefused                  // nothing to write; add records failed, rm stays removing; Err says why
)

// Decision is a planner's decision on one file.
type Decision struct {
	Outcome Outcome
	New     []byte // for OutWrite: the whole new content
	Err     string // for OutRefused: the stored error (≤256 bytes)
	Show    []string
	// Warn is a warning for the user, not stored: the file left by the
	// run holds TombstoneWarn or more tombstone-like lines.
	Warn string
}

func lineText(content []byte, f Facts, i int) string {
	s := f.lines[i]
	return string(content[s.start:s.end])
}

// clip bounds an error to the 256 bytes the schema allows.
func clip(s string) string {
	if len(s) <= 256 {
		return s
	}
	s = s[:253]
	for len(s) > 0 && s[len(s)-1]&0xc0 == 0x80 {
		s = s[:len(s)-1]
	}
	return s + "..."
}

func refused(err string, show ...string) Decision {
	return Decision{Outcome: OutRefused, Err: clip(err), Show: show}
}

// withLine is content with line appended, one LF first if content doesn't
// end in one.
func withLine(content []byte, line string) []byte {
	out := bytes.Clone(content)
	if len(out) > 0 && out[len(out)-1] != '\n' {
		out = append(out, '\n')
	}
	return append(append(out, line...), '\n')
}

// DecideAdd is §7.2 step 5, in order, for record a on content read under
// the lock. alongside is the committed target's.
func DecideAdd(content []byte, a *model.Access, alongside bool) Decision {
	f := FactsOf(content, a)
	switch {
	case len(f.Tb) > 0:
		return refused(fmt.Sprintf("this machine's authorized_keys says record %s was removed here (gen %d); hop won't install it again. If that is wrong, create a new record", a.Label, f.Tb[0].Gen))
	case len(f.Tm) > 0:
		return refused(fmt.Sprintf("hop can't read a hop access tombstone on line %d; fix or remove it by hand", f.Tm[0].Line), f.Tm[0].Text)
	}
	var mg []string
	for _, i := range f.Mg {
		mg = append(mg, lineText(content, f, i))
	}
	if len(f.Mg) == 1 {
		if k, _ := ParseKeyLine(mg[0]); Matches(k, a) {
			return Decision{Outcome: OutInstalled}
		}
	}
	if len(f.Mg) > 0 {
		return refused(fmt.Sprintf("authorized_keys holds %d lines for record %s that don't match it; hop changed nothing", len(f.Mg), a.Label), mg...)
	}
	if len(f.Kx) > 0 && !alongside {
		var kx []string
		for _, i := range f.Kx {
			kx = append(kx, lineText(content, f, i))
		}
		return refused("already authorized by a line hop doesn't manage; use --alongside to add hop's line anyway", kx...)
	}
	body, err := LineBody(a)
	if err != nil {
		return refused(err.Error())
	}
	return Decision{Outcome: OutWrite, New: withLine(content, body)}
}

// DecideRemove is §7.3 step 5 for record a, removing under gen, on content
// read under the lock. Malformed tombstone-like lines are left alone.
func DecideRemove(content []byte, a *model.Access, gen uint64, host string) Decision {
	f := FactsOf(content, a)
	n := len(f.Tombstones)
	if len(f.Tb) == 0 && n >= TombstoneBound {
		return refused(fmt.Sprintf("~/.ssh/authorized_keys on %s already holds %d hop access tombstones; hop won't remove the line without writing one. See hop access check %s", host, TombstoneBound, host))
	}
	var mg []string
	for _, i := range f.Mg {
		mg = append(mg, lineText(content, f, i))
	}
	if len(f.Mg) > 1 || len(f.Mg) == 1 && !matchesLine(mg[0], a) {
		return refused(fmt.Sprintf("authorized_keys holds %d lines for record %s that don't match it; hop changed nothing", len(f.Mg), a.Label), mg...)
	}
	if len(f.Mg) == 0 && len(f.Tb) > 0 {
		return Decision{Outcome: OutRemoved}
	}
	out := content
	if len(f.Mg) == 1 {
		s := f.lines[f.Mg[0]]
		end := s.end
		if end < len(content) {
			end++ // its LF
		}
		out = append(bytes.Clone(content[:s.start]), content[end:]...)
	}
	added := 0
	if len(f.Tb) == 0 {
		out = withLine(out, Tombstone(a.RecordID, gen))
		added = 1
	}
	d := Decision{Outcome: OutWrite, New: out}
	if n+added >= TombstoneWarn {
		d.Warn = fmt.Sprintf("~/.ssh/authorized_keys on %s holds %d hop access tombstones; at %d, hop access rm can't remove new records there", host, n+added, TombstoneBound)
	}
	return d
}

func matchesLine(line string, a *model.Access) bool {
	k, ok := ParseKeyLine(line)
	return ok && ManagedBy(k, a) && Matches(k, a)
}

// RereadOutcome is the §7.7 re-read table: the file read again after an
// uncertain session. It says whether the file holds the run's intended
// content (to), the content read under the lock (from), or anything else.
type RereadOutcome int

const (
	RereadIntended RereadOutcome = iota
	RereadUnchanged
	RereadOther
)

// Reread classifies a re-read.
func Reread(got, from, to []byte) RereadOutcome {
	switch {
	case bytes.Equal(got, to):
		return RereadIntended
	case bytes.Equal(got, from):
		return RereadUnchanged
	}
	return RereadOther
}
