package cli

import (
	"strings"
	"testing"

	"github.com/dalyem/hopkey/internal/model"
)

// A managed line's comment is exactly hop-access: and a validated record
// ID. A longer comment, a second marker or another case is a marker no
// single record manages, never an untracked line with a suffixed ID
// (review P3).
func TestCheckMarkerComparesTheWholeComment(t *testing.T) {
	live := model.ID{0x11, 0x22}
	unknown := model.ID{0xab, 0xcd}
	key := akText(rotTestKey(t))
	cases := []struct {
		comment string
		kind    string // the finding, "" for none
		rid     string // the untracked finding's record ID
	}{
		{"hop-access:" + live.String(), "", ""},
		{"hop-access:" + unknown.String(), findUntracked, unknown.String()},
		{"hop-access:" + unknown.String() + " extra", findMalformed, ""},
		{"hop-access:" + live.String() + " extra", findMalformed, ""},
		{"note hop-access:" + unknown.String(), findMalformed, ""},
		{"hop-access:" + live.String() + " hop-access:" + unknown.String(), findMalformed, ""},
		{"hop-access:" + unknown.String() + "\thop-access:" + unknown.String(), findMalformed, ""},
		{"HOP-ACCESS:" + unknown.String(), findMalformed, ""},
		{"hop-access:" + strings.ToUpper(unknown.String()), findMalformed, ""},
		{"hop-access:" + unknown.String()[:31], findMalformed, ""},
	}
	for _, c := range cases {
		k := &accessCheck{records: []model.Access{{Label: "alice", RecordID: live}}, read: map[string]bool{}}
		k.fileFindings("web-1", checkRead{user: "u", lock: "not-seen", content: []byte(key + " " + c.comment + "\n")}, "f")
		switch {
		case c.kind == "" && len(k.findings) != 0:
			t.Errorf("%q: findings %+v", c.comment, k.findings)
		case c.kind != "" && (len(k.findings) != 1 || k.findings[0].Kind != c.kind || k.findings[0].RecordID != c.rid):
			t.Errorf("%q: findings %+v, want one %s", c.comment, k.findings, c.kind)
		}
	}
}
