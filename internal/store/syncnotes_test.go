package store

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/dalyem/hopkey/internal/canonjson"
	"github.com/dalyem/hopkey/internal/crypto"
	"github.com/dalyem/hopkey/internal/model"
	"github.com/dalyem/hopkey/internal/vaultlog"
)

// Tests of vault/sync-notes.json and the combined note (crypto spec rev 17
// amendment, §3.2, §8.3).

// takeSyncNotes reads s's sync notes and acknowledges them, as the daemon
// does.
func takeSyncNotes(t *testing.T, s *Store) SyncNotes {
	t.Helper()
	ns, err := s.SyncNotes()
	if err != nil {
		t.Fatal(err)
	}
	if err := s.AckSyncNotes(ns); err != nil {
		t.Fatal(err)
	}
	return ns
}

// combine commits on B an address change and queues on A the removal of
// the host's alias: rev 16 holds that, rev 17 combines it (a removed
// selector only narrows what it reaches).
func (p *pair) combine(t *testing.T) {
	t.Helper()
	editHost(t, p.b.s, p.host.ItemID, func(h *model.Host) { h.Addresses = []string{"10.0.0.2"} })
	pushAll(t, p.b.s, p.r)
	editHost(t, p.a.s, p.host.ItemID, func(h *model.Host) { h.Aliases = []string{} })
}

func checkCombined(t *testing.T, ns SyncNotes, p *pair) {
	t.Helper()
	if len(ns.Combined) != 1 {
		t.Fatalf("combined notes %+v", ns.Combined)
	}
	c := ns.Combined[0]
	if c.ItemID != p.host.ItemID || c.Type != model.TypeHost || c.Name != "web" ||
		!slices.Equal(c.Local, []string{"aliases"}) || !slices.Equal(c.Remote, []string{"addresses"}) {
		t.Errorf("combined note %+v", c)
	}
}

// A write rev 16 would have held gets one combined note, shown once
// verified history settles its candidate: after the push, after a lost
// answer and a pull, and after a crash between journaling and posting.
func TestCombinedNoteSettledFromVerifiedHistory(t *testing.T) {
	for _, tc := range []struct {
		name string
		run  func(t *testing.T, p *pair) *Store
	}{
		{"the push", func(t *testing.T, p *pair) *Store {
			if res := pushAll(t, p.a.s, p.r); res.Outcome != PushEmpty {
				t.Fatalf("push: %+v", res)
			}
			return p.a.s
		}},
		{"a lost answer, then a pull", func(t *testing.T, p *pair) *Store {
			p.r.onPost = func(*vaultlog.Wire) (bool, error) { return true, errLostResponse }
			if _, err := p.a.s.PushHead(context.Background(), p.r); !errors.Is(err, errLostResponse) {
				t.Fatalf("push: %v", err)
			}
			p.r.onPost = nil
			if ns, _ := p.a.s.SyncNotes(); len(ns.Combined) != 0 {
				t.Fatalf("shown before verified history settled it: %+v", ns)
			}
			pull(t, p.a.s, p.r)
			return p.a.s
		}},
		{"a crash after journaling", func(t *testing.T, p *pair) *Store {
			p.a.s.testHook = func(stage string) error {
				if stage == "outbox:journaled" {
					return errCrash
				}
				return nil
			}
			if _, err := p.a.s.PushHead(context.Background(), p.r); !errors.Is(err, errCrash) {
				t.Fatalf("push: %v", err)
			}
			a := open(t, p.a.cfg)
			pushAll(t, a, p.r)
			return a
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := newPair(t)
			p.combine(t)
			s := tc.run(t, p)
			h, _ := verifiedHost(t, s, p.host.ItemID)
			if !slices.Equal(h.Addresses, []string{"10.0.0.2"}) || len(h.Aliases) != 0 {
				t.Fatalf("host %+v", h)
			}
			checkCombined(t, takeSyncNotes(t, s), p)
			if again := takeSyncNotes(t, s); !again.Empty() {
				t.Errorf("shown twice: %+v", again)
			}
		})
	}
}

// A write rev 16 would also have made gets no combined note.
func TestNoCombinedNoteWhereRev16Writes(t *testing.T) {
	p := newPair(t)
	editHost(t, p.b.s, p.host.ItemID, func(h *model.Host) { h.Description = "from B" })
	pushAll(t, p.b.s, p.r)
	editHost(t, p.a.s, p.host.ItemID, func(h *model.Host) { h.Tags = []string{"db"} })
	pushAll(t, p.a.s, p.r)
	if ns := takeSyncNotes(t, p.a.s); !ns.Empty() {
		t.Errorf("notes %+v", ns)
	}
	if _, err := os.Lstat(filepath.Join(p.a.cfg.DataDir, "vault", syncNotesRel)); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("sync-notes.json was written: %v", err)
	}
}

// The early-return case: an older build settles the record (it never opens
// sync-notes.json), so the outbox is empty. The next unlock of this build
// still settles the pending note by its seq.
func TestPendingNoteSettledAfterTheOutboxIsEmpty(t *testing.T) {
	p := newPair(t)
	p.combine(t)
	notes := filepath.Join(p.a.cfg.DataDir, "vault", syncNotesRel)
	p.r.onPost = func(*vaultlog.Wire) (bool, error) { return true, errLostResponse }
	if _, err := p.a.s.PushHead(context.Background(), p.r); !errors.Is(err, errLostResponse) {
		t.Fatalf("push: %v", err)
	}
	p.r.onPost = nil
	saved, err := os.ReadFile(notes)
	if err != nil {
		t.Fatal(err)
	}
	// The older build: the file is not there for it, and its pull settles
	// the record.
	if err := os.Remove(notes); err != nil {
		t.Fatal(err)
	}
	pull(t, p.a.s, p.r)
	if len(records(t, p.a.s)) != 0 {
		t.Fatal("the record was not settled")
	}
	if err := p.a.s.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(notes, saved, 0o600); err != nil {
		t.Fatal(err)
	}
	a := open(t, p.a.cfg)
	checkCombined(t, takeSyncNotes(t, a), p)
}

// A pending note whose candidate died (another entry took its seq) is
// dropped, never shown.
func TestPendingNoteOfADeadCandidateIsDropped(t *testing.T) {
	p := newPair(t)
	a := p.a.s
	f := readNotesFile(t, a)
	f.notes.Pending = append(f.notes.Pending, pendingNoteJSON{
		Seq: a.state.Head.Seq + 1, H: crypto.Hash{1}, N: 99, Note: syncNoteJSON{Kind: NoteCombined, Body: combinedRaw(t, p.host.ItemID)},
	})
	writeNotes(t, a, f.notes)
	editHost(t, p.b.s, p.host.ItemID, func(h *model.Host) { h.Description = "B" })
	pushAll(t, p.b.s, p.r)
	pull(t, a, p.r)
	if got := readNotesFile(t, a); len(got.notes.Pending) != 0 || len(got.notes.Ready) != 0 {
		t.Errorf("notes %+v", got.notes)
	}
}

func readNotesFile(t *testing.T, s *Store) syncNotesFile {
	t.Helper()
	s.mu.Lock()
	defer s.mu.Unlock()
	unlock, err := s.lockFile()
	if err != nil {
		t.Fatal(err)
	}
	defer unlock()
	f, err := s.readSyncNotes(s.rec, s.state.VaultID)
	if err != nil {
		t.Fatal(err)
	}
	return f
}

func writeNotes(t *testing.T, s *Store, n syncNotesJSON) {
	t.Helper()
	s.mu.Lock()
	defer s.mu.Unlock()
	unlock, err := s.lockFile()
	if err != nil {
		t.Fatal(err)
	}
	defer unlock()
	tx := &txn{}
	if err := putSyncNotes(tx, s.rec, s.state.VaultID, n); err != nil {
		t.Fatal(err)
	}
	if err := s.commitTxn(tx); err != nil {
		t.Fatal(err)
	}
}

func combinedRaw(t *testing.T, id model.ID) canonjson.Raw {
	t.Helper()
	b, err := canonjson.Marshal(combinedBody{ItemID: id, Type: model.TypeHost, Name: "web", Local: []string{"tags"}, Remote: []string{"addresses"}})
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// futureNote is a note of a kind this build doesn't know.
var futureNote = syncNoteJSON{Kind: "future-kind", Body: canonjson.Raw(`{"x":["a","b"],"y":"z"}`)}

// Acknowledgement removes exactly the delivered IDs; an unknown kind is
// never delivered, removed or evicted, and survives every rewrite byte for
// byte, as does an unknown key in evicted.
func TestSyncNotesAckByExactID(t *testing.T) {
	p := newPair(t)
	a := p.a.s
	n := emptySyncNotes()
	n.Next = 12
	n.Evicted["future-kind"] = 3
	n.Ready = []readyNoteJSON{{ID: 10, Note: futureNote}, {ID: 11, Note: syncNoteJSON{Kind: NoteCombined, Body: combinedRaw(t, p.host.ItemID)}}}
	writeNotes(t, a, n)

	d, err := a.SyncNotes()
	if err != nil {
		t.Fatal(err)
	}
	if len(d.Combined) != 1 || d.Combined[0].ID != 11 || d.Evicted != nil {
		t.Fatalf("delivered %+v", d)
	}
	if err := a.AckSyncNotes(d); err != nil {
		t.Fatal(err)
	}
	got := readNotesFile(t, a).notes
	if len(got.Ready) != 1 || got.Ready[0].ID != 10 || !bytes.Equal(got.Ready[0].Note.Body, futureNote.Body) || got.Evicted["future-kind"] != 3 {
		t.Fatalf("after ack {11}: %+v", got)
	}

	// Deliver {12}; 13 is added meanwhile; acknowledging leaves 13.
	addCombined := func() {
		f := readNotesFile(t, a).notes
		addReady(&f, syncNoteJSON{Kind: NoteCombined, Body: combinedRaw(t, p.host.ItemID)})
		writeNotes(t, a, f)
	}
	addCombined()
	d, err = a.SyncNotes()
	if err != nil || len(d.Combined) != 1 || d.Combined[0].ID != 12 {
		t.Fatalf("delivered %+v %v", d, err)
	}
	addCombined()
	if err := a.AckSyncNotes(d); err != nil {
		t.Fatal(err)
	}
	got = readNotesFile(t, a).notes
	var ids []uint64
	for _, r := range got.Ready {
		ids = append(ids, r.ID)
	}
	if !slices.Equal(ids, []uint64{10, 13}) {
		t.Errorf("ready IDs %v, want [10 13]", ids)
	}
}

// At most 50 ready notes of a known kind: the 51st evicts the oldest of
// that kind, never an unknown kind's, and the count is shown and then
// reduced by what was delivered.
func TestSyncNotesPerKindCapacity(t *testing.T) {
	p := newPair(t)
	a := p.a.s
	n := emptySyncNotes()
	addReady(&n, futureNote)
	for range maxSyncNotesPerKind + 1 {
		addReady(&n, syncNoteJSON{Kind: NoteCombined, Body: combinedRaw(t, p.host.ItemID)})
	}
	if len(n.Ready) != maxSyncNotesPerKind+1 || n.Ready[0].Note.Kind != "future-kind" || n.Ready[1].ID != 3 || n.Evicted[NoteCombined] != 1 {
		t.Fatalf("after 51: %d ready, first %+v, second id %d, evicted %v", len(n.Ready), n.Ready[0].Note.Kind, n.Ready[1].ID, n.Evicted)
	}
	writeNotes(t, a, n)
	d, err := a.SyncNotes()
	if err != nil || len(d.Combined) != maxSyncNotesPerKind || d.Evicted[NoteCombined] != 1 {
		t.Fatalf("delivered %d, evicted %v, %v", len(d.Combined), d.Evicted, err)
	}
	// One more is evicted before the acknowledgement arrives: the count
	// left is what was not delivered.
	f := readNotesFile(t, a).notes
	addReady(&f, syncNoteJSON{Kind: NoteCombined, Body: combinedRaw(t, p.host.ItemID)})
	writeNotes(t, a, f)
	if err := a.AckSyncNotes(d); err != nil {
		t.Fatal(err)
	}
	got := readNotesFile(t, a).notes
	if len(got.Ready) != 2 || got.Ready[0].Note.Kind != "future-kind" || got.Evicted[NoteCombined] != 1 {
		t.Errorf("after ack: %d ready, evicted %v", len(got.Ready), got.Evicted)
	}
}

// A pending note of an unknown kind is settled like any other, and kept.
func TestUnknownKindIsSettledAndKept(t *testing.T) {
	p := newPair(t)
	a := p.a.s
	// Journal a candidate whose answer is lost, and a note of an unknown
	// kind for it, as a newer build would have.
	editHost(t, a, p.host.ItemID, func(h *model.Host) { h.Description = "A" })
	p.r.onPost = func(*vaultlog.Wire) (bool, error) { return true, errLostResponse }
	if _, err := a.PushHead(context.Background(), p.r); !errors.Is(err, errLostResponse) {
		t.Fatalf("push: %v", err)
	}
	p.r.onPost = nil
	c := records(t, a)[0].live()
	n := emptySyncNotes()
	n.Pending = []pendingNoteJSON{{Seq: c.Seq, H: c.H, N: 1, Note: futureNote}}
	writeNotes(t, a, n)
	pull(t, a, p.r)
	got := readNotesFile(t, a).notes
	if len(got.Pending) != 0 || len(got.Ready) != 1 || got.Ready[0].Note.Kind != "future-kind" || !bytes.Equal(got.Ready[0].Note.Body, futureNote.Body) {
		t.Fatalf("notes %+v", got)
	}
	if d := takeSyncNotes(t, a); !d.Empty() {
		t.Errorf("an unknown kind was delivered: %+v", d)
	}
	if got := readNotesFile(t, a).notes; len(got.Ready) != 1 {
		t.Errorf("an unknown kind was acknowledged: %+v", got)
	}
}

// A file of a newer version is not corrupt and is never rewritten, at the
// top level or inside the seal; notes it would have taken are dropped with
// a reason for the daemon log.
func TestNewerSyncNotesAreLeftAlone(t *testing.T) {
	sealedV2 := func(a *Store) []byte {
		pt := []byte(`{"v":2,"whatever":true}`)
		key, err := a.rec.localKey()
		if err != nil {
			t.Fatal(err)
		}
		defer key.Zero()
		lk, _ := crypto.LocalKeyID(key)
		env, err := crypto.SealAEAD(key, pt, syncNotesAAD(a.state.VaultID, lk))
		if err != nil {
			t.Fatal(err)
		}
		b, err := canonjson.Marshal(syncNotesFileJSON{V: 1, VaultID: a.state.VaultID, LK: lk, Sealed: env})
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	for name, body := range map[string]func(*Store) []byte{
		"file v2":   func(*Store) []byte { return []byte(`{"v":2,"vault_id":"x","anything":[1,2,3]}`) },
		"sealed v2": sealedV2,
	} {
		t.Run(name, func(t *testing.T) {
			p := newPair(t)
			a := p.a.s
			path := filepath.Join(p.a.cfg.DataDir, "vault", syncNotesRel)
			body := body(a)
			if err := os.WriteFile(path, body, 0o600); err != nil {
				t.Fatal(err)
			}
			p.combine(t)
			pushAll(t, a, p.r)
			d, err := a.SyncNotes()
			if err != nil {
				t.Fatalf("SyncNotes: %v", err)
			}
			if len(d.Combined) != 0 || len(d.Dropped) != 1 {
				t.Errorf("delivered %+v", d)
			}
			if err := a.AckSyncNotes(d); err != nil {
				t.Fatal(err)
			}
			if got, _ := os.ReadFile(path); !bytes.Equal(got, body) {
				t.Errorf("the newer file was rewritten")
			}
			// It also survives an unlock.
			if err := a.Close(); err != nil {
				t.Fatal(err)
			}
			open(t, p.a.cfg)
			if got, _ := os.ReadFile(path); !bytes.Equal(got, body) {
				t.Errorf("the newer file was rewritten at unlock")
			}
		})
	}
}

// A file sealed under an earlier local_key is obsolete, not corrupt: it is
// discarded with one notice. With the right lk, a flipped ciphertext byte
// or a changed AAD part is corrupt.
func TestSyncNotesKeyGeneration(t *testing.T) {
	p := newPair(t)
	a := p.a.s
	path := filepath.Join(p.a.cfg.DataDir, "vault", syncNotesRel)
	n := emptySyncNotes()
	addReady(&n, syncNoteJSON{Kind: NoteCombined, Body: combinedRaw(t, p.host.ItemID)})

	// An older build replaced local_key and left the file.
	old := *a.rec
	old.LocalKey = make([]byte, localKeySize)
	if _, err := rand.Read(old.LocalKey); err != nil {
		t.Fatal(err)
	}
	stale, err := sealSyncNotes(&old, a.state.VaultID, n)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, stale, 0o600); err != nil {
		t.Fatal(err)
	}
	// It opens, and the unlock settles nothing out of it.
	if err := a.Close(); err != nil {
		t.Fatal(err)
	}
	a = open(t, p.a.cfg)
	p.a.s = a
	d := takeSyncNotes(t, a)
	if !d.Discarded || len(d.Combined) != 0 {
		t.Fatalf("delivered %+v", d)
	}
	if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("the obsolete file is still there: %v", err)
	}
	if d := takeSyncNotes(t, a); d.Discarded {
		t.Error("the notice was shown twice")
	}

	// A write replaces an obsolete file, and the notice is raised once.
	if err := os.WriteFile(path, stale, 0o600); err != nil {
		t.Fatal(err)
	}
	p.combine(t)
	pushAll(t, a, p.r)
	d = takeSyncNotes(t, a)
	if !d.Discarded || len(d.Combined) != 1 {
		t.Errorf("after a write over an obsolete file: %+v", d)
	}

	// The right lk with a flipped byte, or an AAD part changed, is corrupt.
	good, err := sealSyncNotes(a.rec, a.state.VaultID, n)
	if err != nil {
		t.Fatal(err)
	}
	var f syncNotesFileJSON
	if err := canonjson.Unmarshal(good, &f); err != nil {
		t.Fatal(err)
	}
	mut := func(change func(f *syncNotesFileJSON)) []byte {
		g := f
		g.Sealed.CT = slices.Clone(f.Sealed.CT)
		change(&g)
		b, err := canonjson.Marshal(g)
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	for name, body := range map[string][]byte{
		"ciphertext": mut(func(g *syncNotesFileJSON) { g.Sealed.CT[0] ^= 1 }),
		"vault_id":   mut(func(g *syncNotesFileJSON) { g.VaultID = model.ID{9} }),
		"not json":   []byte("{"),
	} {
		t.Run(name, func(t *testing.T) {
			if err := os.WriteFile(path, body, 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := a.SyncNotes(); !errors.Is(err, ErrCorrupt) {
				t.Errorf("SyncNotes: %v, want ErrCorrupt", err)
			}
		})
	}
	// An lk changed outside the seal is a different generation: obsolete.
	if err := os.WriteFile(path, mut(func(g *syncNotesFileJSON) { g.LK = slices.Clone(g.LK); g.LK[0] ^= 1 }), 0o600); err != nil {
		t.Fatal(err)
	}
	if d, err := a.SyncNotes(); err != nil || !d.Discarded {
		t.Errorf("lk changed: %+v %v", d, err)
	}
}

// Whatever drops the outbox for an unreadable device record drops the
// sync notes too, in the same commit.
func TestDropLostRecordsDropsSyncNotes(t *testing.T) {
	p := newPair(t)
	a := p.a.s
	n := emptySyncNotes()
	addReady(&n, syncNoteJSON{Kind: NoteCombined, Body: combinedRaw(t, p.host.ItemID)})
	writeNotes(t, a, n)
	a.mu.Lock()
	unlock, err := a.lockFile()
	if err != nil {
		t.Fatal(err)
	}
	err = a.dropLostRecords()
	unlock()
	a.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(filepath.Join(p.a.cfg.DataDir, "vault", syncNotesRel)); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("sync-notes.json survived: %v", err)
	}
}

// A downgrade: every file other than sync-notes.json keeps its rev 16
// format, so a build that has never heard of the notes parses each one.
func TestOtherFilesKeepTheirFormats(t *testing.T) {
	p := newPair(t)
	p.combine(t)
	// Journal the candidate with its note, and stop before it is posted.
	p.a.s.testHook = func(stage string) error {
		if stage == "outbox:journaled" {
			return errCrash
		}
		return nil
	}
	if _, err := p.a.s.PushHead(context.Background(), p.r); !errors.Is(err, errCrash) {
		t.Fatalf("push: %v", err)
	}
	p.a.s.testHook = nil
	dir := filepath.Join(p.a.cfg.DataDir, "vault")
	ents, err := os.ReadDir(filepath.Join(dir, "outbox"))
	if err != nil || len(ents) != 1 {
		t.Fatalf("outbox %v %v", ents, err)
	}
	raw, err := os.ReadFile(filepath.Join(dir, "outbox", ents[0].Name()))
	if err != nil {
		t.Fatal(err)
	}
	var f recordFile
	if err := canonjson.Unmarshal(raw, &f); err != nil || f.V != recordVersion {
		t.Errorf("the record is not a version %d record: %v", recordVersion, err)
	}
	rec := records(t, p.a.s)[0]
	if c := rec.live(); c == nil || len(rec.Replaced) != 0 {
		t.Errorf("record %+v", rec)
	}
	if _, err := os.Lstat(filepath.Join(dir, syncNotesRel)); err != nil {
		t.Errorf("no sync-notes.json: %v", err)
	}
}
