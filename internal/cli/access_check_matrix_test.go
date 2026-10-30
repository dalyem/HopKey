package cli

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"slices"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"

	"github.com/dalyem/hopkey/internal/access"
	"github.com/dalyem/hopkey/internal/model"
)

// The finding table of hop access check (§7.8), row by row: for each, a
// file built for it, the findings with their fix text and line numbers,
// the --json objects (field names and omitted fields), and the exit
// status. The rows that need a connection (can't read, a shared pin
// whose host records read different files) are in
// TestAccessCheckConnectionRowsJSON, end to end.

const (
	mxHost = "web-1"
	mxUser = "deploy"
	mxFP   = "SHA256:bound"
)

var mxHostID = model.ID{0x77, 0x01}

type mxWorld struct {
	a        *model.Access
	line     string // a's managed line
	otherRID model.ID
	other    string // the managed line of a record the vault doesn't have
}

func newMx(t *testing.T) mxWorld {
	t.Helper()
	pub := rotTestKey(t)
	a := &model.Access{Label: "alice", RecordID: model.ID{0x11, 0x22, 0x33}, PublicKey: akText(pub), Fingerprint: ssh.FingerprintSHA256(pub),
		Options: model.AccessOptions{From: []string{}}}
	line, err := access.LineBody(a)
	if err != nil {
		t.Fatal(err)
	}
	o := *a
	o.RecordID = model.ID{0xab, 0xcd}
	other, err := access.LineBody(&o)
	if err != nil {
		t.Fatal(err)
	}
	return mxWorld{a: a, line: line, otherRID: o.RecordID, other: other}
}

func (w mxWorld) target(state string, gen uint64, errText string) model.AccessTarget {
	return model.AccessTarget{HostItemID: mxHostID, User: mxUser, ServerKeyFP: mxFP, Gen: gen, State: state, Error: errText}
}

// run reads content as one target's file (or, with no target, as a host
// with no target, as --all-hosts does), and returns the findings as
// --json prints them, decoded, the raw objects, and the exit status.
func (w mxWorld) run(t *testing.T, content string, r checkRead, tg *model.AccessTarget) ([]AccessFinding, []map[string]any, int) {
	t.Helper()
	r.user, r.content = mxUser, []byte(content)
	if r.lock == "" {
		r.lock = "not-seen"
	}
	k := &accessCheck{records: []model.Access{*w.a}, read: map[string]bool{}}
	k.fileFindings(mxHost, r, "f")
	if tg != nil {
		k.targetFindings(w.a, *tg, mxHost, r)
	}
	var out bytes.Buffer
	err := k.report(&Env{Stdout: &out, Stderr: io.Discard}, true, false)
	code := 0
	var ee *exitError
	if errors.As(err, &ee) {
		code = ee.code
	} else if err != nil {
		t.Fatal(err)
	}
	var got []AccessFinding
	var raw []map[string]any
	if json.Unmarshal(out.Bytes(), &got) != nil || json.Unmarshal(out.Bytes(), &raw) != nil {
		t.Fatalf("--json: %s", out.String())
	}
	return got, raw, code
}

func TestAccessCheckFindingMatrix(t *testing.T) {
	w := newMx(t)
	rid, orid := w.a.RecordID.String(), w.otherRID.String()
	tomb := func(gen uint64) string { return access.Tombstone(w.a.RecordID, gen) }
	// base is a finding about the target, as targetFindings starts it.
	base := func(state string) AccessFinding {
		return AccessFinding{Host: mxHost, HostID: mxHostID.String(), User: mxUser, Binding: mxFP, Label: "alice", RecordID: rid, TargetState: state}
	}
	with := func(f AccessFinding, kind, msg, fix string, line int) AccessFinding {
		f.Kind, f.Message, f.Fix, f.Line = kind, msg, fix, line
		return f
	}
	installed, removed := w.target(model.AccessInstalled, 3, ""), w.target(model.AccessRemoved, 3, "")
	abandoned, failed := w.target(model.AccessAbandoned, 2, ""), w.target(model.AccessFailed, 1, "could not write the file")
	pending, removing := w.target(model.AccessPending, 2, ""), w.target(model.AccessRemoving, 2, "")
	cases := []struct {
		name    string
		content string
		read    checkRead
		target  *model.AccessTarget
		want    []AccessFinding
		code    int
	}{
		{"untracked line", "# keep\n" + w.other + "\n", checkRead{}, nil, []AccessFinding{{
			Kind: findUntracked, Host: mxHost, User: mxUser, Line: 2, Text: w.other, RecordID: orid,
			Message: "a line managed by a record no live record of this vault names",
			Fix:     "if no other vault of yours has record " + orid + ", delete line 2 of ~/.ssh/authorized_keys of deploy on web-1 (it ends in hop-access:" + orid + ")",
		}}, 1},
		{"line present for a removed target, tombstone missing", w.line + "\n", checkRead{}, &removed, []AccessFinding{
			with(base(model.AccessRemoved), findLineRemoved, "line present for a removed target",
				"delete line 1 of ~/.ssh/authorized_keys of deploy on web-1 (it ends in hop-access:"+rid+")", 1),
			with(base(model.AccessRemoved), findTombMissing, "tombstone missing for a removed target",
				"append this line to ~/.ssh/authorized_keys of deploy on web-1: # hop-access-removed "+rid+" 3", 0),
		}, 1},
		{"line present for an abandoned target is informational", w.line + "\n", checkRead{}, &abandoned, []AccessFinding{func() AccessFinding {
			f := with(base(model.AccessAbandoned), findLineAbandoned, "line present for an abandoned target: you confirmed that it may remain",
				"delete line 1 of ~/.ssh/authorized_keys of deploy on web-1 (it ends in hop-access:"+rid+"), if you still reach that machine", 1)
			f.Informational = true
			return f
		}()}, 0},
		{"line missing for an installed target", "# keep\n", checkRead{}, &installed, []AccessFinding{
			with(base(model.AccessInstalled), findLineMissing, "line missing for an installed target", "hop access add alice web-1", 0),
		}, 1},
		{"line changed for an installed target", "restrict " + w.line + "\n", checkRead{}, &installed, []AccessFinding{
			with(base(model.AccessInstalled), findLineChanged, "the line for an installed target changed (or there is more than one)",
				"fix or delete line 1 by hand, then hop access add alice web-1", 1),
		}, 1},
		{"two lines for an installed target", w.line + "\n" + w.line + "\n", checkRead{}, &installed, []AccessFinding{
			with(base(model.AccessInstalled), findLineChanged, "the line for an installed target changed (or there is more than one)",
				"fix or delete line 1 by hand, then hop access add alice web-1", 1),
		}, 1},
		{"tombstone for an installed target: no add over it", tomb(4) + "\n", checkRead{}, &installed, []AccessFinding{
			{Kind: findTombstone, Host: mxHost, User: mxUser, Line: 1, Text: tomb(4), Label: "alice", RecordID: rid, Message: "tombstone for record alice (gen 4)", Informational: true},
			with(base(model.AccessInstalled), findTombNotRemoved, "the host says record alice was removed here (gen 4); your vault shows installed (gen 3)",
				"hop access rm alice web-1 (it records removed without writing)", 1),
		}, 1},
		{"tombstone for an abandoned target", tomb(3) + "\n", checkRead{}, &abandoned, []AccessFinding{
			{Kind: findTombstone, Host: mxHost, User: mxUser, Line: 1, Text: tomb(3), Label: "alice", RecordID: rid, Message: "tombstone for record alice (gen 3)", Informational: true},
			with(base(model.AccessAbandoned), findTombNotRemoved, "the host says record alice was removed here (gen 3); your vault shows abandoned (gen 2)",
				"hop access check can't fix this from here", 1),
		}, 1},
		{"tombstone missing for a removed target alone", "# keep\n", checkRead{}, &removed, []AccessFinding{
			with(base(model.AccessRemoved), findTombMissing, "tombstone missing for a removed target",
				"append this line to ~/.ssh/authorized_keys of deploy on web-1: # hop-access-removed "+rid+" 3", 0),
		}, 1},
		{"pending target holding its line", w.line + "\n", checkRead{}, &pending, []AccessFinding{
			with(base(model.AccessPending), findUnfinished, "pending target (gen 2): the file holds its line (line 1)", "hop access add alice finishes it", 0),
		}, 1},
		{"pending target over a tombstone", tomb(3) + "\n", checkRead{}, &pending, []AccessFinding{
			{Kind: findTombstone, Host: mxHost, User: mxUser, Line: 1, Text: tomb(3), Label: "alice", RecordID: rid, Message: "tombstone for record alice (gen 3)", Informational: true},
			with(base(model.AccessPending), findTombNotRemoved, "the host says record alice was removed here (gen 3); your vault shows pending (gen 2)",
				"hop access rm alice web-1 (it records removed without writing)", 1),
			with(base(model.AccessPending), findUnfinished, "pending target (gen 2): the file holds no line for it, and its tombstone", "hop access rm alice finishes it", 0),
		}, 1},
		{"removing target", "# keep\n", checkRead{}, &removing, []AccessFinding{
			with(base(model.AccessRemoving), findUnfinished, "removing target (gen 2): the file holds no line for it", "hop access rm alice finishes it", 0),
		}, 1},
		{"failed target", "# keep\n", checkRead{}, &failed, []AccessFinding{
			with(base(model.AccessFailed), findFailed, "failed target (could not write the file)", "hop access add alice web-1 retries", 0),
		}, 1},
		{"failed target over a tombstone", tomb(3) + "\n", checkRead{}, &failed, []AccessFinding{
			{Kind: findTombstone, Host: mxHost, User: mxUser, Line: 1, Text: tomb(3), Label: "alice", RecordID: rid, Message: "tombstone for record alice (gen 3)", Informational: true},
			with(base(model.AccessFailed), findTombNotRemoved, "the host says record alice was removed here (gen 3); your vault shows failed (gen 1)",
				"hop access rm alice web-1 (it records removed without writing)", 1),
			with(base(model.AccessFailed), findFailed, "failed target (could not write the file)", "hop access rm alice web-1", 0),
		}, 1},
		{"malformed tombstone-like line", "# HOP-ACCESS-REMOVED junk\n", checkRead{}, nil, []AccessFinding{
			{Kind: findMalformed, Host: mxHost, User: mxUser, Line: 1, Text: "# HOP-ACCESS-REMOVED junk", Message: "a hop access tombstone hop can't read", Fix: "fix or delete line 1 by hand"},
		}, 1},
		{"a marker no single record manages", w.line + " extra\n", checkRead{}, nil, []AccessFinding{
			{Kind: findMalformed, Host: mxHost, User: mxUser, Line: 1, Text: w.line + " extra", Message: "a hop access marker no single record manages", Fix: "fix or delete line 1 by hand"},
		}, 1},
		{"tombstone listing: removed target and an unknown record", tomb(3) + "\n" + access.Tombstone(w.otherRID, 2) + "\n", checkRead{}, &removed, []AccessFinding{
			{Kind: findTombstone, Host: mxHost, User: mxUser, Line: 1, Text: tomb(3), Label: "alice", RecordID: rid, Message: "tombstone for record alice (gen 3)", Informational: true},
			{Kind: findTombstone, Host: mxHost, User: mxUser, Line: 2, Text: access.Tombstone(w.otherRID, 2), RecordID: orid,
				Message: "tombstone for a record this vault doesn't have (gen 2); deleting it removes that record's protection on this file", Informational: true},
		}, 0},
		{"lock or session directory seen", "# keep\n", checkRead{lock: "seen", owner: "ffff 42 2026-10-29T00:00:00Z", dirs: 1}, nil, []AccessFinding{
			{Kind: findLock, Host: mxHost, User: mxUser,
				Message: "the lock ~/.ssh/.hop-authorized_keys.lock.d is present (owner: ffff 42 2026-10-29T00:00:00Z); 1 hop session director(ies) ~/.ssh/.hop-s.* present",
				Fix:     "a hop run is active, was killed, or kept its lock. " + strings.ReplaceAll(akHeldAdvice, "LOCK", "~/.ssh/.hop-authorized_keys.lock.d")},
		}, 1},
		{"a session directory alone", "# keep\n", checkRead{dirs: 2}, nil, []AccessFinding{
			{Kind: findLock, Host: mxHost, User: mxUser, Message: "2 hop session director(ies) ~/.ssh/.hop-s.* present",
				Fix: "a hop run is active, was killed, or kept its lock. " + strings.ReplaceAll(akHeldAdvice, "LOCK", "~/.ssh/.hop-authorized_keys.lock.d")},
		}, 1},
		{"a clean installed target", "# keep\n" + w.line + "\n", checkRead{}, &installed, nil, 0},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, raw, code := w.run(t, c.content, c.read, c.target)
			if !slices.Equal(got, c.want) {
				t.Fatalf("findings:\n%s\nwant:\n%s", mxDump(got), mxDump(c.want))
			}
			if code != c.code {
				t.Errorf("exit status %d, want %d", code, c.code)
			}
			// The JSON object has exactly the fields that are set: kind,
			// host and message always, the rest only when they say
			// something.
			for i, obj := range raw {
				want := mxFields(c.want[i])
				var have []string
				for k := range obj {
					have = append(have, k)
				}
				slices.Sort(have)
				if !slices.Equal(have, want) {
					t.Errorf("finding %d: JSON fields %v, want %v", i, have, want)
				}
			}
		})
	}
	t.Run("tombstone count", func(t *testing.T) {
		var b strings.Builder
		for i := range access.TombstoneWarn {
			id := model.ID{0xee, byte(i)}
			fmt.Fprintf(&b, "%s\n", access.Tombstone(id, 1))
		}
		got, _, code := w.run(t, b.String(), checkRead{}, nil)
		want := AccessFinding{Kind: findTombCount, Host: mxHost, User: mxUser,
			Message: "~/.ssh/authorized_keys holds 100 hop access tombstones; at 128, hop access rm can't remove new records there"}
		n := 0
		for _, f := range got {
			if f.Kind == findTombstone {
				n++
			}
		}
		if n != access.TombstoneWarn || len(got) != n+1 || got[n] != want || code != 1 {
			t.Fatalf("%d tombstones listed, then %+v; exit %d", n, got[len(got)-1], code)
		}
	})
	t.Run("unread wins", func(t *testing.T) {
		k := &accessCheck{read: map[string]bool{}}
		k.add(AccessFinding{Kind: findCantRead, Host: mxHost, Message: "x", Unread: true})
		k.add(AccessFinding{Kind: findLineMissing, Host: mxHost, Message: "y"})
		var ee *exitError
		if err := k.report(&Env{Stdout: io.Discard, Stderr: io.Discard}, true, true); !errors.As(err, &ee) || ee.code != 2 {
			t.Fatalf("report: %v", err)
		}
	})
}

// mxFields are the JSON members f prints.
func mxFields(f AccessFinding) []string {
	out := []string{"host", "kind", "message"}
	add := func(set bool, name string) {
		if set {
			out = append(out, name)
		}
	}
	add(f.HostID != "", "host_id")
	add(f.User != "", "user")
	add(f.Binding != "", "binding")
	add(f.Line != 0, "line")
	add(f.Text != "", "text")
	add(f.Label != "", "label")
	add(f.RecordID != "", "record_id")
	add(f.TargetState != "", "target_state")
	add(f.Fix != "", "fix")
	add(f.Informational, "informational")
	add(f.Unread, "unread")
	slices.Sort(out)
	return out
}

func mxDump(fs []AccessFinding) string {
	var b strings.Builder
	for _, f := range fs {
		fmt.Fprintf(&b, "  %+v\n", f)
	}
	return b.String()
}
