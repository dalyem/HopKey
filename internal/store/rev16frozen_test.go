package store

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/dalyem/hopkey/internal/canonjson"
	"github.com/dalyem/hopkey/internal/crypto"
	"github.com/dalyem/hopkey/internal/merge"
	"github.com/dalyem/hopkey/internal/model"
	"github.com/dalyem/hopkey/internal/vaultlog"
)

// The rev 16 build, frozen: copies of how the build before sync-notes.json
// (157320f^) reads an outbox record, outbox.json and replaced.json, and how
// it drops what an unreadable device record lost. Each has its own copy of
// the file types, so a member a later build adds to any of these files
// fails here, as it would fail that build (canonjson refuses unknown
// members). Do not change them to follow the current code: they stand for
// a build that is already out there (crypto spec rev 17 amendment, §8.3).

type rev16IntentJSON struct {
	V      int            `json:"v"`
	Action merge.Action   `json:"action"`
	ItemID model.ID       `json:"item_id"`
	Type   model.Type     `json:"type"`
	Seen   *canonjson.Raw `json:"seen"`
	Want   *canonjson.Raw `json:"want"`
	Import model.ID       `json:"import"`
}

type rev16Candidate struct {
	Seq    uint64      `json:"seq,string"`
	Prev   crypto.Hash `json:"prev"`
	H      crypto.Hash `json:"h"`
	Status string      `json:"status"`
}

type rev16ReplacedJSON struct {
	H      crypto.Hash `json:"h"`
	Name   string      `json:"name"`
	Fields []string    `json:"fields"`
}

type rev16SealedState struct {
	V          int                 `json:"v"`
	Intent     rev16IntentJSON     `json:"intent"`
	Held       bool                `json:"held"`
	Candidates []rev16Candidate    `json:"candidates"`
	Replaced   []rev16ReplacedJSON `json:"replaced"`
}

type rev16SealedStateV1 struct {
	V          int              `json:"v"`
	Intent     rev16IntentJSON  `json:"intent"`
	Held       bool             `json:"held"`
	Candidates []rev16Candidate `json:"candidates"`
}

type rev16RecordFile struct {
	V       int                 `json:"v"`
	VaultID model.ID            `json:"vault_id"`
	N       uint64              `json:"n,string"`
	Sealed  crypto.AEADEnvelope `json:"sealed"`
	Wires   []canonjson.Raw     `json:"wires"`
}

type rev16OutboxMeta struct {
	V    int    `json:"v"`
	Next uint64 `json:"next,string"`
	Lost uint64 `json:"lost,string"`
}

type rev16ReplacedFileJSON struct {
	V       int                 `json:"v"`
	VaultID model.ID            `json:"vault_id"`
	Sealed  crypto.AEADEnvelope `json:"sealed"`
}

type rev16NoteJSON struct {
	N      uint64     `json:"n,string"`
	ItemID model.ID   `json:"item_id"`
	Type   model.Type `json:"type"`
	Name   string     `json:"name"`
	Fields []string   `json:"fields"`
}

type rev16NotesJSON struct {
	V       int             `json:"v"`
	Next    uint64          `json:"next,string"`
	Evicted uint64          `json:"evicted,string"`
	Notes   []rev16NoteJSON `json:"notes"`
}

// rev16Record is what the frozen reader keeps of a record.
type rev16Record struct {
	N      uint64
	Held   bool
	Intent merge.Intent
	Cands  []rev16Candidate
	Wires  map[crypto.Hash]*vaultlog.Wire
}

func rev16OutboxAAD(vaultID model.ID, n uint64) []byte {
	aad := crypto.LP([]byte("hopkey/v1/outbox"))
	aad = append(aad, crypto.LP(vaultID[:])...)
	return append(aad, crypto.U64(n)...)
}

func rev16ReplacedAAD(vaultID model.ID) []byte {
	return append(crypto.LP([]byte("hopkey/v1/replaced")), crypto.LP(vaultID[:])...)
}

func (j *rev16IntentJSON) intent() (merge.Intent, error) {
	if j.V != 1 {
		return merge.Intent{}, fmt.Errorf("intent v %d", j.V)
	}
	in := merge.Intent{Action: j.Action, ItemID: j.ItemID, Type: j.Type}
	for _, p := range []struct {
		raw *canonjson.Raw
		out **merge.Item
	}{{j.Seen, &in.Seen}, {j.Want, &in.Want}} {
		if p.raw == nil {
			continue
		}
		it, err := merge.ParseItem(*p.raw)
		if err != nil {
			return merge.Intent{}, err
		}
		*p.out = it
	}
	return in, in.Validate()
}

// rev16OpenRecord is the rev 16 openRecord.
func rev16OpenRecord(key *crypto.SymKey, vaultID model.ID, n uint64, b []byte) (*rev16Record, error) {
	bad := func(format string, args ...any) error {
		return fmt.Errorf("%w: outbox record %d: %s", ErrCorrupt, n, fmt.Sprintf(format, args...))
	}
	var f rev16RecordFile
	if err := canonjson.Unmarshal(b, &f); err != nil {
		return nil, bad("%v", err)
	}
	if (f.V != 2 && f.V != 1) || f.N != n || f.VaultID != vaultID {
		return nil, bad("wrong version, number or vault")
	}
	pt, err := crypto.OpenAEAD(key, f.Sealed, rev16OutboxAAD(vaultID, n))
	if err != nil {
		return nil, bad("the sealed state does not open")
	}
	var st rev16SealedState
	if f.V == 1 {
		var v1 rev16SealedStateV1
		err = canonjson.Unmarshal(pt, &v1)
		st = rev16SealedState{V: v1.V, Intent: v1.Intent, Held: v1.Held, Candidates: v1.Candidates}
	} else {
		err = canonjson.Unmarshal(pt, &st)
	}
	clear(pt)
	if err != nil || st.V != f.V {
		return nil, bad("the sealed state does not parse: %v", err)
	}
	in, err := st.Intent.intent()
	if err != nil {
		return nil, bad("intent: %v", err)
	}
	r := &rev16Record{N: n, Held: st.Held, Intent: in, Cands: st.Candidates, Wires: map[crypto.Hash]*vaultlog.Wire{}}
	listed := map[crypto.Hash]bool{}
	live := 0
	for _, c := range r.Cands {
		switch c.Status {
		case "live":
			live++
		case "dead", "committed":
		default:
			return nil, bad("candidate status %q", c.Status)
		}
		if listed[c.H] {
			return nil, bad("a candidate is listed twice")
		}
		listed[c.H] = true
	}
	if live > 1 {
		return nil, bad("more than one live candidate")
	}
	seenRepl := map[crypto.Hash]bool{}
	for _, rj := range st.Replaced {
		if !listed[rj.H] || seenRepl[rj.H] || len(rj.Fields) == 0 {
			return nil, bad("a replacement names no candidate, one twice, or no field")
		}
		seenRepl[rj.H] = true
	}
	for _, raw := range f.Wires {
		w, err := vaultlog.ParseWire(raw)
		if err != nil {
			continue
		}
		h, err := w.Entry.Hash()
		if err != nil || !listed[h] {
			continue
		}
		r.Wires[h] = w
	}
	return r, nil
}

// rev16ReadNotes is the rev 16 readNotes of replaced.json.
func rev16ReadNotes(path string, rec *deviceRecord, vaultID model.ID) (rev16NotesJSON, error) {
	n := rev16NotesJSON{V: 1, Next: 1, Notes: []rev16NoteJSON{}}
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return n, nil
	}
	if err != nil {
		return n, err
	}
	bad := fmt.Errorf("%w: %s does not open", ErrCorrupt, path)
	var f rev16ReplacedFileJSON
	if err := canonjson.Unmarshal(b, &f); err != nil || f.V != 1 || f.VaultID != vaultID {
		return n, bad
	}
	key, err := rec.localKey()
	if err != nil {
		return n, err
	}
	defer key.Zero()
	pt, err := crypto.OpenAEAD(key, f.Sealed, rev16ReplacedAAD(vaultID))
	if err != nil {
		return n, bad
	}
	err = canonjson.Unmarshal(pt, &n)
	clear(pt)
	if err != nil || n.V != 1 || n.Next == 0 {
		return n, bad
	}
	for _, x := range n.Notes {
		if x.N == 0 || x.N >= n.Next || len(x.Fields) == 0 {
			return n, bad
		}
	}
	return n, nil
}

// rev16DropLostRecords is the rev 16 dropLostRecords: it never heard of
// sync-notes.json, so it leaves it. The caller holds the file lock.
func rev16DropLostRecords(s *Store) error {
	ns, err := s.l.outboxNumbers()
	if err != nil {
		return err
	}
	t := &txn{}
	lost, err := s.readLostJournals()
	if err != nil {
		return err
	}
	dropped := false
	for _, f := range []struct {
		rel    string
		exists func() (bool, error)
		flag   *bool
	}{{checkpointRel, s.l.checkpointExists, &lost.Checkpoint}, {approvalRel, s.l.approvalExists, &lost.Approval}} {
		if ok, err := f.exists(); err != nil {
			return err
		} else if ok {
			t.remove(f.rel)
			*f.flag, dropped = true, true
		}
	}
	if dropped {
		if err := putLostJournals(t, lost); err != nil {
			return err
		}
	}
	if len(ns) > 0 {
		m, err := s.readOutboxMeta()
		if err != nil {
			return err
		}
		for _, n := range ns {
			t.remove(outboxRel(n))
			m.Next = max(m.Next, n+1)
		}
		m.Lost += uint64(len(ns))
		if err := putOutboxMeta(t, m); err != nil {
			return err
		}
	}
	if _, err := os.Lstat(s.l.replacedFile()); err == nil {
		t.remove(replacedRel)
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return s.commitTxn(t)
}

// rev16ReadsEverything opens every file the rev 16 build reads that this
// build may have written since: each outbox record, outbox.json and
// replaced.json. It returns the records.
func rev16ReadsEverything(t *testing.T, s *Store, dataDir string) []*rev16Record {
	t.Helper()
	vault := filepath.Join(dataDir, "vault")
	key, err := s.rec.localKey()
	if err != nil {
		t.Fatal(err)
	}
	defer key.Zero()
	ns, err := s.l.outboxNumbers()
	if err != nil {
		t.Fatal(err)
	}
	var out []*rev16Record
	for _, n := range ns {
		b, err := os.ReadFile(filepath.Join(vault, outboxRel(n)))
		if err != nil {
			t.Fatal(err)
		}
		r, err := rev16OpenRecord(key, s.state.VaultID, n, b)
		if err != nil {
			t.Fatalf("the rev 16 build can't read outbox record %d: %v", n, err)
		}
		out = append(out, r)
	}
	if b, err := os.ReadFile(filepath.Join(vault, outboxMetaRel)); err == nil {
		var m rev16OutboxMeta
		if err := canonjson.Unmarshal(b, &m); err != nil || m.V != 1 {
			t.Fatalf("the rev 16 build can't read outbox.json: %v", err)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		t.Fatal(err)
	}
	if _, err := rev16ReadNotes(filepath.Join(vault, replacedRel), s.rec, s.state.VaultID); err != nil {
		t.Fatalf("the rev 16 build can't read replaced.json: %v", err)
	}
	return out
}

// A downgrade and back. This build leaves an acknowledged note of a
// replaced edit, an acknowledged combined note, and a combined write
// journaled but not posted, with its note pending. The frozen rev 16
// readers open every outbox record, outbox.json and replaced.json. The
// rev 16 build then posts the candidate without ever opening
// sync-notes.json, and the re-upgraded build settles the pending note by
// its seq and shows it once.
func TestDowngradeToFrozenRev16AndBack(t *testing.T) {
	p := newPair(t)
	a := p.a.s
	vault := filepath.Join(p.a.cfg.DataDir, "vault")

	// A replaced edit, its note acknowledged.
	editHost(t, p.b.s, p.host.ItemID, func(h *model.Host) { h.Description = "from B" })
	pushAll(t, p.b.s, p.r)
	editHost(t, a, p.host.ItemID, func(h *model.Host) { h.Description = "from A" })
	pushAll(t, a, p.r)
	if rs := takeReplacements(t, a); len(rs) != 1 {
		t.Fatalf("replaced notes %+v", rs)
	}
	// A combined write, its note acknowledged.
	pull(t, p.b.s, p.r)
	p.combine(t)
	pushAll(t, a, p.r)
	checkCombined(t, takeSyncNotes(t, a), p)

	// A second combined write (a respelled name on B, a new port here),
	// journaled, and the process stops before it is posted.
	pull(t, p.b.s, p.r)
	editHost(t, p.b.s, p.host.ItemID, func(h *model.Host) { h.Name = "Web" })
	pushAll(t, p.b.s, p.r)
	editHost(t, a, p.host.ItemID, func(h *model.Host) { h.Port = 2200 })
	a.testHook = func(stage string) error {
		if stage == "outbox:journaled" {
			return errCrash
		}
		return nil
	}
	if _, err := a.PushHead(context.Background(), p.r); !errors.Is(err, errCrash) {
		t.Fatalf("push: %v", err)
	}
	a.testHook = nil
	if f := readNotesFile(t, a); len(f.notes.Pending) != 1 || len(f.notes.Ready) != 0 {
		t.Fatalf("sync notes %+v", f.notes)
	}

	// The rev 16 build reads every file it knows.
	recs := rev16ReadsEverything(t, a, p.a.cfg.DataDir)
	if len(recs) != 1 || recs[0].Intent.ItemID != p.host.ItemID || len(recs[0].Cands) != 1 || recs[0].Cands[0].Status != "live" ||
		len(recs[0].Wires) != 1 {
		t.Fatalf("the rev 16 build reads %+v", recs)
	}

	// It posts the journaled candidate. sync-notes.json is not there for it.
	notes := filepath.Join(vault, syncNotesRel)
	saved, err := os.ReadFile(notes)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(notes); err != nil {
		t.Fatal(err)
	}
	if err := a.Close(); err != nil {
		t.Fatal(err)
	}
	old := open(t, p.a.cfg)
	if res := pushAll(t, old, p.r); res.Outcome != PushEmpty {
		t.Fatalf("push: %+v", res)
	}
	if _, err := os.Lstat(notes); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("the stand-in for the rev 16 build wrote sync-notes.json: %v", err)
	}
	rev16ReadsEverything(t, old, p.a.cfg.DataDir)
	if err := old.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(notes, saved, 0o600); err != nil {
		t.Fatal(err)
	}

	// The re-upgraded build settles the note by its seq, once.
	a = open(t, p.a.cfg)
	ns := takeSyncNotes(t, a)
	if len(ns.Combined) != 1 || ns.Combined[0].ItemID != p.host.ItemID ||
		!slices.Equal(ns.Combined[0].Local, []string{"port"}) || !slices.Equal(ns.Combined[0].Remote, []string{"name"}) {
		t.Fatalf("after the re-upgrade: %+v", ns)
	}
	if again := takeSyncNotes(t, a); !again.Empty() {
		t.Errorf("shown twice: %+v", again)
	}
	h, _ := verifiedHost(t, a, p.host.ItemID)
	if h.Name != "Web" || h.Port != 2200 {
		t.Errorf("host %+v", h)
	}
}

// A frozen rev 16 build that recovers from an unreadable device record
// drops the queued records and replaced.json, and leaves sync-notes.json,
// sealed under the local_key it can no longer read. The re-upgraded build
// discards that file with one notice, never ErrCorrupt.
func TestFrozenRev16RecoveryLeavesSyncNotes(t *testing.T) {
	ctx := context.Background()
	f, r := serverVault(t)
	s := f.s
	_, h := addHost(t, s, "web")
	host := h.ItemID
	vault := filepath.Join(f.cfg.DataDir, "vault")
	n := emptySyncNotes()
	addReady(&n, syncNoteJSON{Kind: NoteCombined, Body: combinedRaw(t, host)})
	writeNotes(t, s, n)
	notes := filepath.Join(vault, syncNotesRel)
	before, err := os.ReadFile(notes)
	if err != nil {
		t.Fatal(err)
	}
	queued := len(outboxFiles(t, f.cfg.DataDir))
	if queued == 0 {
		t.Fatal("nothing queued")
	}
	key := bytes.Clone(s.rec.LocalKey)

	// The rev 16 build's recovery: the records go, the notes file stays.
	s.mu.Lock()
	unlock, err := s.lockFile()
	if err != nil {
		t.Fatal(err)
	}
	err = rev16DropLostRecords(s)
	unlock()
	s.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	if after, err := os.ReadFile(notes); err != nil || !bytes.Equal(after, before) {
		t.Fatalf("the rev 16 recovery changed sync-notes.json: %v", err)
	}
	if len(outboxFiles(t, f.cfg.DataDir)) != 0 {
		t.Fatal("the rev 16 recovery left records")
	}
	// It then signs in with the password and gets a new local_key. (The
	// sign-in is this build's, with the notes file out of its way: the
	// rev 16 build never opens it.)
	if err := os.Remove(notes); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	f.cfg.Keyring.(*memRing).clear()
	s = open(t, f.cfg)
	if err := s.UnlockWithPasswordRemote(ctx, r, []byte(testPassword), f.kit.SecretKey); err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(s.rec.LocalKey, key) {
		t.Fatal("the local_key carried over")
	}
	if lost, err := s.LostIntents(); err != nil || lost != uint64(queued) {
		t.Errorf("lost %d, %v; want %d", lost, err, queued)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(notes, before, 0o600); err != nil {
		t.Fatal(err)
	}

	// The re-upgraded build.
	s = open(t, f.cfg)
	if s.Info().Locked {
		t.Fatal("locked after the re-upgrade")
	}
	d, err := s.SyncNotes()
	if err != nil {
		t.Fatalf("SyncNotes: %v", err)
	}
	if !d.Discarded || len(d.Combined) != 0 {
		t.Fatalf("delivered %+v", d)
	}
	if err := s.AckSyncNotes(d); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(notes); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("the obsolete file is still there: %v", err)
	}
	if d := takeSyncNotes(t, s); d.Discarded {
		t.Error("the notice was shown twice")
	}
}
