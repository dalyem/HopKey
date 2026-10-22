package store

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"

	"github.com/dalyem/hopkey/internal/canonjson"
	"github.com/dalyem/hopkey/internal/crypto"
	"github.com/dalyem/hopkey/internal/merge"
	"github.com/dalyem/hopkey/internal/model"
	"github.com/dalyem/hopkey/internal/vaultlog"
)

// The outbox of a server-backed vault (§11.1). Every host, key, credential
// and snippet write is stored first as a record, one file per record:
//
//	vault/outbox/<n>.json   record = JCS({"v":1, "vault_id":id, "n":u64s, "sealed":AEAD(local_key, state, aad), "wires":[wire, ...]})
//	vault/outbox.json       the next n, and the count of records lost with an unreadable device record
//
// with
//
//	intent = JCS({"v":1, "action":"create"|"put"|"delete", "item_id":id, "type":type, "seen":item|null, "want":item|null, "import":id|""})
//	state  = JCS({"v":1, "intent":intent, "held":bool, "candidates":[{"seq":u64s, "prev":h, "h":h, "status":"live"|"committed"|"dead"}]})
//	aad    = lp("hopkey/v1/outbox") || lp(vault_id) || u64(n)
//
// Records are pushed in strict n order. Only the head is ever pushed, and a
// held head blocks every record behind it. A record never changes except
// for its held flag, its candidates and, while held, an in-place
// resolution. The AEAD covers the intent, the hold flag and the candidate
// list: a local attacker who can write the files but can't read local_key
// can delete or roll back records, but can't change them or mark them
// committed.

var (
	// ErrLocalKey means the device record has no usable local_key, so the
	// outbox can't be read or written.
	ErrLocalKey = errors.New("store: the device-local key is unavailable")
	// ErrServerBacked means the operation is not available in a
	// server-backed vault (or needs the server).
	ErrServerBacked = errors.New("store: this vault is server-backed; the operation needs the server")
	// ErrNotServerBacked means the operation needs a server-backed vault.
	ErrNotServerBacked = errors.New("store: this vault is local-only")
)

const (
	labelOutbox = "hopkey/v1/outbox"

	outboxVersion = 1

	statusLive      = "live"
	statusCommitted = "committed"
	statusDead      = "dead"
)

func (l layout) outbox() string     { return filepath.Join(l.vault(), "outbox") }
func (l layout) outboxMeta() string { return filepath.Join(l.vault(), "outbox.json") }
func (l layout) serverFile() string { return filepath.Join(l.vault(), "server.json") }

// Paths of the outbox files in a transaction, relative to vault/.
func outboxRel(n uint64) string { return "outbox/" + strconv.FormatUint(n, 10) + ".json" }

const (
	outboxMetaRel = "outbox.json"
	serverRel     = "server.json"
	stateRel      = "state.json"
)

func entryRel(seq uint64) string { return "entries/" + strconv.FormatUint(seq, 10) + ".json" }

// outboxAAD is lp("hopkey/v1/outbox") || lp(vault_id_bytes) || u64(n).
func outboxAAD(vaultID model.ID, n uint64) []byte {
	aad := crypto.LP([]byte(labelOutbox))
	aad = append(aad, crypto.LP(vaultID[:])...)
	return append(aad, crypto.U64(n)...)
}

// intentJSON is the sealed intent.
type intentJSON struct {
	V      int            `json:"v"`
	Action merge.Action   `json:"action"`
	ItemID model.ID       `json:"item_id"`
	Type   model.Type     `json:"type"`
	Seen   *canonjson.Raw `json:"seen"`
	Want   *canonjson.Raw `json:"want"`
	Import model.ID       `json:"import"`
}

// candidate is one posted candidate of a record: its entry's seq, prev and
// H, and what verified history says about it.
type candidate struct {
	Seq    uint64      `json:"seq,string"`
	Prev   crypto.Hash `json:"prev"`
	H      crypto.Hash `json:"h"`
	Status string      `json:"status"`
}

// sealedState is the plaintext of a record's sealed member.
type sealedState struct {
	V          int         `json:"v"`
	Intent     intentJSON  `json:"intent"`
	Held       bool        `json:"held"`
	Candidates []candidate `json:"candidates"`
}

// recordFile is outbox/<n>.json.
type recordFile struct {
	V       int                 `json:"v"`
	VaultID model.ID            `json:"vault_id"`
	N       uint64              `json:"n,string"`
	Sealed  crypto.AEADEnvelope `json:"sealed"`
	Wires   []canonjson.Raw     `json:"wires"`
}

// outboxMeta is outbox.json: the next record number, so a number is never
// reused, and how many records an unreadable device record lost (§11).
type outboxMeta struct {
	V    int    `json:"v"`
	Next uint64 `json:"next,string"`
	Lost uint64 `json:"lost,string"`
}

// record is an opened outbox record.
type record struct {
	N      uint64
	Held   bool
	Intent merge.Intent
	Import model.ID
	Cands  []candidate
	// Wires holds the candidate wires by H. A wire in the file whose H is
	// not listed in the sealed candidates is ignored.
	Wires map[crypto.Hash]*vaultlog.Wire
}

// live returns the record's live candidate, if it has one.
func (r *record) live() *candidate {
	for i := range r.Cands {
		if r.Cands[i].Status == statusLive {
			return &r.Cands[i]
		}
	}
	return nil
}

func intentToJSON(in merge.Intent, imp model.ID) intentJSON {
	j := intentJSON{V: outboxVersion, Action: in.Action, ItemID: in.ItemID, Type: in.Type, Import: imp}
	if in.Seen != nil {
		raw := canonjson.Raw(in.Seen.Plaintext())
		j.Seen = &raw
	}
	if in.Want != nil {
		raw := canonjson.Raw(in.Want.Plaintext())
		j.Want = &raw
	}
	return j
}

func (j *intentJSON) intent() (merge.Intent, error) {
	if j.V != outboxVersion {
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

// sealRecord encodes r under key for the vault.
func sealRecord(key *crypto.SymKey, vaultID model.ID, r *record) ([]byte, error) {
	st := sealedState{
		V: outboxVersion, Intent: intentToJSON(r.Intent, r.Import), Held: r.Held,
		Candidates: slices.Clone(r.Cands),
	}
	if st.Candidates == nil {
		st.Candidates = []candidate{}
	}
	pt, err := canonjson.Marshal(st)
	if err != nil {
		return nil, err
	}
	env, err := crypto.SealAEAD(key, pt, outboxAAD(vaultID, r.N))
	if err != nil {
		return nil, err
	}
	f := recordFile{V: outboxVersion, VaultID: vaultID, N: r.N, Sealed: env, Wires: []canonjson.Raw{}}
	for _, c := range r.Cands {
		w, ok := r.Wires[c.H]
		if !ok {
			continue
		}
		b, err := w.Marshal()
		if err != nil {
			return nil, err
		}
		f.Wires = append(f.Wires, b)
	}
	return canonjson.Marshal(f)
}

// openRecord decodes outbox/<n>.json. Anything that fails, including the
// AEAD, is ErrCorrupt: only hop writes these files.
func openRecord(key *crypto.SymKey, vaultID model.ID, n uint64, b []byte) (*record, error) {
	bad := func(format string, args ...any) error {
		return fmt.Errorf("%w: outbox record %d: %s", ErrCorrupt, n, fmt.Sprintf(format, args...))
	}
	var f recordFile
	if err := canonjson.Unmarshal(b, &f); err != nil {
		return nil, bad("%v", err)
	}
	if f.V != outboxVersion || f.N != n || f.VaultID != vaultID {
		return nil, bad("wrong version, number or vault")
	}
	pt, err := crypto.OpenAEAD(key, f.Sealed, outboxAAD(vaultID, n))
	if err != nil {
		return nil, bad("the sealed state does not open")
	}
	var st sealedState
	err = canonjson.Unmarshal(pt, &st)
	clear(pt)
	if err != nil || st.V != outboxVersion {
		return nil, bad("the sealed state does not parse")
	}
	in, err := st.Intent.intent()
	if err != nil {
		return nil, bad("intent: %v", err)
	}
	r := &record{N: n, Held: st.Held, Intent: in, Import: st.Intent.Import, Cands: st.Candidates, Wires: map[crypto.Hash]*vaultlog.Wire{}}
	listed := map[crypto.Hash]bool{}
	live := 0
	for _, c := range r.Cands {
		switch c.Status {
		case statusLive:
			live++
		case statusDead, statusCommitted:
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
	for _, raw := range f.Wires {
		w, err := vaultlog.ParseWire(raw)
		if err != nil {
			continue
		}
		h, err := w.Entry.Hash()
		if err != nil || !listed[h] {
			continue // §11.1: a wire whose H isn't in sealed is ignored
		}
		r.Wires[h] = w
	}
	return r, nil
}

// outboxNumbers lists the record numbers on disk, ascending. A missing
// outbox directory is an empty outbox.
func (l layout) outboxNumbers() ([]uint64, error) {
	ents, err := os.ReadDir(l.outbox())
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var out []uint64
	for _, e := range ents {
		name := e.Name()
		if strings.HasPrefix(name, ".tmp") {
			continue
		}
		num, ok := strings.CutSuffix(name, ".json")
		n, err := strconv.ParseUint(num, 10, 64)
		if !ok || err != nil || strconv.FormatUint(n, 10) != num || n == 0 {
			return nil, fmt.Errorf("%w: unexpected file %s in %s", ErrCorrupt, name, l.outbox())
		}
		out = append(out, n)
	}
	slices.Sort(out)
	return out, nil
}

// readOutbox opens every record, in n order. The caller holds the file
// lock.
func (s *Store) readOutbox() ([]*record, error) {
	if s.state == nil || s.rec == nil {
		return nil, s.lockedErr()
	}
	return s.readOutboxAs(s.rec, s.state.VaultID)
}

// readOutboxAs is readOutbox with rec's local_key, for vault vaultID. The
// caller holds the file lock.
func (s *Store) readOutboxAs(rec *deviceRecord, vaultID model.ID) ([]*record, error) {
	ns, err := s.l.outboxNumbers()
	if err != nil || len(ns) == 0 {
		return nil, err
	}
	if rec == nil {
		return nil, s.lockedErr()
	}
	key, err := rec.localKey()
	if err != nil {
		return nil, err
	}
	defer key.Zero()
	out := make([]*record, 0, len(ns))
	for _, n := range ns {
		b, err := os.ReadFile(filepath.Join(s.l.outbox(), strconv.FormatUint(n, 10)+".json"))
		if err != nil {
			return nil, err
		}
		r, err := openRecord(key, vaultID, n, b)
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, nil
}

// outboxKey returns local_key. The record in memory was made durable at
// unlock (upgradeRecord), so it may be used.
func (s *Store) outboxKey() (*crypto.SymKey, error) {
	if s.rec == nil {
		return nil, s.lockedErr()
	}
	return s.rec.localKey()
}

// putRecord adds r's file to t.
func (s *Store) putRecord(t *txn, r *record) error {
	if s.state == nil || s.rec == nil {
		return s.lockedErr()
	}
	return s.putRecordAs(t, r, s.rec, s.state.VaultID)
}

// putRecordAs is putRecord with rec's local_key, for vault vaultID.
func (s *Store) putRecordAs(t *txn, r *record, rec *deviceRecord, vaultID model.ID) error {
	key, err := rec.localKey()
	if err != nil {
		return err
	}
	defer key.Zero()
	b, err := sealRecord(key, vaultID, r)
	if err != nil {
		return err
	}
	t.put(outboxRel(r.N), b)
	return nil
}

func (s *Store) readOutboxMeta() (outboxMeta, error) {
	m := outboxMeta{V: outboxVersion, Next: 1}
	b, err := os.ReadFile(s.l.outboxMeta())
	if errors.Is(err, os.ErrNotExist) {
		return m, nil
	}
	if err != nil {
		return m, err
	}
	if err := canonjson.Unmarshal(b, &m); err != nil || m.V != outboxVersion || m.Next == 0 {
		return m, fmt.Errorf("%w: %s does not parse", ErrCorrupt, s.l.outboxMeta())
	}
	return m, nil
}

func putOutboxMeta(t *txn, m outboxMeta) error {
	b, err := canonjson.Marshal(m)
	if err != nil {
		return err
	}
	t.put(outboxMetaRel, b)
	return nil
}

// appendRecord queues a new record after every existing one, together
// with the counter, in one transaction. The caller holds the file lock.
func (s *Store) appendRecord(in merge.Intent) (uint64, error) {
	m, err := s.readOutboxMeta()
	if err != nil {
		return 0, err
	}
	ns, err := s.l.outboxNumbers()
	if err != nil {
		return 0, err
	}
	n := m.Next
	if len(ns) > 0 && ns[len(ns)-1] >= n {
		n = ns[len(ns)-1] + 1
	}
	t := &txn{}
	if err := s.putRecord(t, &record{N: n, Intent: in, Cands: []candidate{}, Wires: map[crypto.Hash]*vaultlog.Wire{}}); err != nil {
		return 0, err
	}
	m.Next = n + 1
	if err := putOutboxMeta(t, m); err != nil {
		return 0, err
	}
	return n, s.commitTxn(t)
}

// serverBacked reports whether vault/server.json marks the vault as
// server-backed.
func (l layout) serverBacked() (bool, error) {
	b, err := os.ReadFile(l.serverFile())
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	var m struct {
		V int `json:"v"`
	}
	if err := canonjson.Unmarshal(b, &m); err != nil || m.V != 1 {
		return false, fmt.Errorf("%w: %s does not parse", ErrCorrupt, l.serverFile())
	}
	return true, nil
}

// serverModeOps adds the switch to server-backed mode to t. D2's
// publication and E's login commit it together with their own files.
func serverModeOps(t *txn) error {
	b, err := canonjson.Marshal(struct {
		V int `json:"v"`
	}{1})
	if err != nil {
		return err
	}
	t.put(serverRel, b)
	return nil
}

// EnableServerMode makes the vault server-backed (§11.1) in one durable
// commit: from then on every host, key, credential and snippet write goes
// through the outbox, and only verified entries pulled from the server are
// written to the local log. D2's publication and slice E's login call it
// once the vault's log is on the server.
func (s *Store) EnableServerMode() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.state == nil {
		return s.lockedErr()
	}
	if s.server {
		return nil
	}
	if _, err := s.outboxKey(); err != nil {
		return err
	}
	unlock, err := s.lockFile()
	if err != nil {
		return err
	}
	defer unlock()
	t := &txn{}
	if err := serverModeOps(t); err != nil {
		return err
	}
	if err := s.commitTxn(t); err != nil {
		return err
	}
	s.server = true
	return nil
}

// ServerBacked reports whether the vault is server-backed.
func (s *Store) ServerBacked() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.server
}

// OutboxEmpty reports whether the outbox holds no record, pending or held.
// It reads only file names, so it works while the vault is locked. Logout
// refuses unless it is empty or --discard-pending is given (§11.1).
func (s *Store) OutboxEmpty() (bool, error) {
	ns, err := s.l.outboxNumbers()
	return len(ns) == 0, err
}

// HasCheckpointJournal reports whether a checkpoint journal exists (§10.1),
// including one whose kit can no longer be read. Logout always refuses
// while one does (§11.1).
func (s *Store) HasCheckpointJournal() (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	seqs, err := s.journalSeqs()
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	return len(seqs) > 0, err
}

// LostIntents returns how many queued changes were lost because a password
// unlock replaced an unreadable device record (§11). It stays non-zero
// until AckLostIntents.
func (s *Store) LostIntents() (uint64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	m, err := s.readOutboxMeta()
	return m.Lost, err
}

// AckLostIntents records that the user has seen the loss LostIntents
// reports.
func (s *Store) AckLostIntents() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	unlock, err := s.lockFile()
	if err != nil {
		return err
	}
	defer unlock()
	m, err := s.readOutboxMeta()
	if err != nil || m.Lost == 0 {
		return err
	}
	m.Lost = 0
	t := &txn{}
	if err := putOutboxMeta(t, m); err != nil {
		return err
	}
	return s.commitTxn(t)
}
