package cli

import (
	"regexp"
	"slices"
	"strings"
	"testing"
)

// Lines of hop access, in authorized_keys: a line that carries a marker
// and a tombstone line. Rotate keeps both byte for byte, on every path,
// and never takes a marked line as one of its own (spec rev 17, §6.1,
// §6.1a, §7.5).

const testRecord = "0123456789abcdef0123456789abcdef"

func TestReadMarker(t *testing.T) {
	for comment, want := range map[string]struct {
		id     string
		marked bool
	}{
		"hop-access:" + testRecord:                  {testRecord, true},
		"HOP-Access:" + testRecord:                  {testRecord, true},
		"alice hop-access:" + testRecord + " x":     {testRecord, true},
		"x\thop-access:" + testRecord:               {testRecord, true},
		"hop-access:" + strings.ToUpper(testRecord): {"", true},
		"hop-access:abc":                            {"", true},
		"hop-access:":                               {"", true},
		"xhop-access:" + testRecord:                 {"", false},
		"hop-access " + testRecord:                  {"", false},
		"deploy@old":                                {"", false},
		"":                                          {"", false},
	} {
		if id, marked := readMarker(comment); id != want.id || marked != want.marked {
			t.Errorf("%q: %q %v, want %q %v", comment, id, marked, want.id, want.marked)
		}
	}
}

func TestParseAKLineComment(t *testing.T) {
	k := rotTestKey(t)
	for line, want := range map[string]string{
		akText(k):                               "",
		akText(k) + "  a b \t":                  "a b",
		"restrict " + akText(k) + "\tc d\r":     "c d",
		"  " + akText(k) + " hop-access:x\r":    "hop-access:x",
		`from="a b" ` + akText(k) + " the end ": "the end",
	} {
		got, ok := parseAKLine(line)
		if !ok || got.comment != want {
			t.Errorf("%q: comment %q ok %v, want %q", line, got.comment, ok, want)
		}
	}
}

// Every rotate path over a file with hop access lines: the marked lines
// and the tombstones come out byte for byte, a marked line is never a
// source or the new key's, and only rotate's own lines change.
func TestRotateLeavesHopAccessLines(t *testing.T) {
	oldK, newK, other := rotTestKey(t), rotTestKey(t), rotTestKey(t)
	access := []string{
		// Marked lines: the old key (with options rotate must not copy),
		// the new key, another key, a marker inside a longer comment, in
		// another case, and one hop cannot read.
		`from="192.0.2.1",restrict ` + akText(oldK) + " hop-access:" + testRecord,
		akText(newK) + " hop-access:ffffffffffffffffffffffffffffffff",
		akText(other) + " hop-access:" + testRecord,
		"no-pty " + akText(oldK) + " bob HOP-ACCESS:" + testRecord + "\r",
		"\t" + akText(oldK) + " hop-access:not-an-id",
		// Tombstones, well formed and not.
		"# hop-access-removed " + testRecord + " 3",
		"  \t#\thop-access-removed " + testRecord + " 12\r",
		"# HOP-ACCESS-REMOVED x 0 extra",
		"#hop-access-removed",
	}
	mine := []string{"# keys", `command="/bin/x" ` + akText(oldK) + " deploy@old", akText(other) + " alice"}
	orig := joinAK(append(append([]string{}, mine[:2]...), append(access, mine[2])...))

	ed, err := planAKEdit(orig, oldK, newK, "hop-rotated")
	if err != nil {
		t.Fatal(err)
	}
	// One new line, from the unmarked old line, with its options only.
	if want := []string{`command="/bin/x" ` + akText(newK) + " hop-rotated"}; !slices.Equal(ed.added, want) {
		t.Errorf("added %q, want %q", ed.added, want)
	}
	if want := []string{mine[1]}; !slices.Equal(ed.removed, want) {
		t.Errorf("removed %q, want %q", ed.removed, want)
	}
	keeps := func(what string, content []byte) {
		t.Helper()
		lines := splitAK(content)
		for _, l := range access {
			if n := strings.Count("\n"+string(content), "\n"+l+"\n"); n != 1 || !slices.Contains(lines, l) {
				t.Errorf("%s: %q is there %d times, want once, byte for byte", what, l, n)
			}
		}
	}
	keeps("appended", ed.appended)
	keeps("final", ed.final)
	if got := markedOldLines(ed.final, oldK); !slices.Equal(got, []string{"record " + testRecord, "record " + testRecord, "an unknown record"}) {
		t.Errorf("marked old-key lines left: %q", got)
	}

	// Retry and already-rotated: withoutKey drops only rotate's own line.
	next, n := withoutKey(orig, oldK)
	if n != 1 {
		t.Errorf("withoutKey dropped %d lines, want 1", n)
	}
	keeps("withoutKey", next)

	// Rollback restores and deletes only rotate's own lines.
	for name, cur := range map[string][]byte{"appended": ed.appended, "final": ed.final} {
		back, _ := rollbackAK(cur, ed)
		keeps("rollback of "+name, back)
		if strings.Contains(string(back), " hop-rotated") {
			t.Errorf("rollback of %s kept an added line", name)
		}
	}
	back, _ := rollbackAK(ed.final, ed.oldLinesOnly())
	keeps("rollback of the old lines", back)

	// akState counts rotate's lines only: the marked old-key lines do not
	// make the old key "still there".
	if got := akState(ed.final, oldK, newK); got != remOldRemoved {
		t.Errorf("state of the final file: %s, want %s", got, remOldRemoved)
	}
	if got := akState(joinAK(access), oldK, newK); got != remUnknown {
		t.Errorf("state of a file of hop access lines: %s, want %s", got, remUnknown)
	}
}

// A file whose old-key lines all carry a marker has nothing for rotate.
func TestRotateOnlyMarkedOldLines(t *testing.T) {
	oldK, newK := rotTestKey(t), rotTestKey(t)
	orig := joinAK([]string{
		akText(oldK) + " hop-access:" + testRecord,
		"restrict " + akText(oldK) + " x hop-access:zzz",
		"# hop-access-removed " + testRecord + " 1",
	})
	_, err := planAKEdit(orig, oldK, newK, "hop-rotated")
	if err == nil {
		t.Fatal("planned an edit of hop access lines")
	}
	for _, want := range []string{"only on hop access lines (record " + testRecord + ", an unknown record)", "which rotate doesn't touch", "Nothing was changed"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q does not say %q", err, want)
		}
	}
	if next, n := withoutKey(orig, oldK); n != 0 || string(next) != string(orig) {
		t.Errorf("withoutKey removed %d hop access lines", n)
	}
}

func TestMarkedProblem(t *testing.T) {
	if got, want := markedProblem([]string{"record " + testRecord}), "a hop access line (record "+testRecord+") still authorizes the old key; rotate left it"; got != want {
		t.Errorf("%q, want %q", got, want)
	}
	if got := markedProblem([]string{"record a", "an unknown record"}); got != "hop access lines (record a, an unknown record) still authorize the old key; rotate left them" {
		t.Errorf("%q", got)
	}
}

// The messages of the write script go through every login shell inside
// the script: no newline, no '!', no '#', no backslash before a backslash
// or a quote. The held-lock ones name both users of the lock and require
// that no run is active anywhere before the lock is removed; none judges
// a PID.
func TestAKScriptMessages(t *testing.T) {
	msgs := map[string]string{
		"held": akHeldMsg, "no owner": akNoOwnerMsg, "probe": akProbeMsg,
		"session directory": akDirKeptMsg, "lost lock": akLostLockMsg, "unlock": akUnlockMsg,
	}
	for name, m := range msgs {
		for _, bad := range []string{"\n", "!", "#", `\\`, `\'`, `"`, "`"} {
			if strings.Contains(m, bad) {
				t.Errorf("%s message has %q: %s", name, bad, m)
			}
		}
	}
	for _, m := range []string{akHeldMsg, akNoOwnerMsg} {
		for _, want := range []string{
			"hop key rotate and hop access both use this lock",
			"Remove it (rm -r LOCK) only when no hop key rotate and no hop access run can still be active for this account",
			"on every device you use, and on every machine that shares this home directory",
			"check ~/.ssh/authorized_keys by hand afterwards",
		} {
			if !strings.Contains(m, want) {
				t.Errorf("%q does not say %q", m, want)
			}
		}
		if strings.Contains(m, "running") {
			t.Errorf("%q judges whether a process runs", m)
		}
	}
	for name, m := range msgs {
		if strings.Contains(m, "hop access check") {
			t.Errorf("%s message names hop access check, which does not exist yet: %s", name, m)
		}
	}
	s := akWriteScript("1 2", "3 4")
	if strings.Contains(s, "kill") {
		t.Errorf("the script probes or signals a process: %s", s)
	}
	if !strings.Contains(s, akProbeMsg) {
		t.Error("the script does not carry the probe message")
	}
}

// Every script hop builds has a new token, which names its paths and owns
// its lock; no path holds a PID.
func TestAKWriteScriptPathsHaveNoPID(t *testing.T) {
	a, b := akWriteScript("1 2", "3 4"), akWriteScript("1 2", "3 4")
	ta, tb := scriptToken(t, a), scriptToken(t, b)
	if ta == tb {
		t.Errorf("two scripts share the token %s", ta)
	}
	for _, want := range []string{
		`s="$HOME/.ssh/.hop-s.` + ta + `"`,
		`p="$HOME/.ssh/.hop-p.` + ta + `"`,
		`echo "` + ta + ` $$ `,
		`[ "$ot" = "` + ta + `" ]`,
	} {
		if !strings.Contains(a, want) {
			t.Errorf("the script lacks %s", want)
		}
	}
	// $$ appears once, in the owner line, for the message only.
	if n := strings.Count(a, "$$"); n != 1 {
		t.Errorf("$$ appears %d times", n)
	}
	for _, m := range regexp.MustCompile(`\b[a-z]="[^"]*"`).FindAllString(a, -1) {
		if strings.Contains(m, "$$") {
			t.Errorf("a path holds the PID: %s", m)
		}
	}
	// No old temp-file name.
	if strings.Contains(a, "authorized_keys.hop-") {
		t.Error("the script still names a temp file in ~/.ssh")
	}
}
