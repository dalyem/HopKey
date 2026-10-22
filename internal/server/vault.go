package server

import (
	"encoding/hex"
	"errors"
	"net/http"
	"strconv"
	"time"

	"github.com/dalyem/hopkey/internal/canonjson"
	"github.com/dalyem/hopkey/internal/crypto"
	"github.com/dalyem/hopkey/internal/model"
	"github.com/dalyem/hopkey/internal/vaultlog"
)

// entryOverhead is what R13 counts for an entry's durable metadata on top
// of its stored wire.
const entryOverhead = 512

// headSeqReserve is the width R9 reserves for head.seq when it admits a
// wire: 20 decimal digits, the longest u64.
const headSeqReserve = 20

// Fixed parts of the canonical (JCS) log responses. Members are in JCS
// order: entries < head, and h < seq < wire.
const (
	pageOpen   = `{"entries":[`
	pageMid    = `],"head":`
	pageClose  = `}`
	itemOpen   = `{"h":"`
	itemSeq    = `","seq":"`
	itemWire   = `","wire":`
	itemClose  = `}`
	headClose  = `"}`
	hashHexLen = 2 * len(crypto.Hash{})
)

func digits(n uint64) int { return len(strconv.FormatUint(n, 10)) }

// itemLen is the length of {"h":…,"seq":…,"wire":…} for an entry.
func itemLen(seq uint64, wireLen int) int {
	return len(itemOpen) + hashHexLen + len(itemSeq) + digits(seq) + len(itemWire) + wireLen + len(itemClose)
}

// frameLen is the length of a log response without its items, for a head
// seq of headDigits digits.
func frameLen(headDigits int) int {
	return len(pageOpen) + len(pageMid) + len(itemOpen) + hashHexLen + len(itemSeq) + headDigits + len(headClose) + len(pageClose)
}

// singletonLen is R9's admission measure of a wire: the canonical log
// response holding only this entry, with 20 digits reserved for head.seq.
func singletonLen(seq uint64, wireLen int) int {
	return frameLen(headSeqReserve) + itemLen(seq, wireLen)
}

func appendItem(b []byte, e *LogEntry) []byte {
	b = append(b, itemOpen...)
	b = hex.AppendEncode(b, e.H[:])
	b = append(b, itemSeq...)
	b = strconv.AppendUint(b, e.Seq, 10)
	b = append(b, itemWire...)
	b = append(b, e.Wire...)
	return append(b, itemClose...)
}

func appendHead(b []byte, h vaultlog.Head) []byte {
	b = append(b, itemOpen...)
	b = hex.AppendEncode(b, h.H[:])
	b = append(b, itemSeq...)
	b = strconv.AppendUint(b, h.Seq, 10)
	return append(b, headClose...)
}

// page assembles {entries, head} from the entries after after (from
// genesis when fromStart): the largest contiguous prefix of at most
// MaxPageEntries entries whose canonical response fits MaxPageBytes. It
// always holds the next entry when there is one, because every admitted
// wire fits on its own (R9). head is the snapshot head of tx.
func (s *Server) page(tx Tx, v *Vault, after uint64, fromStart bool) ([]byte, int, error) {
	size := frameLen(digits(v.Head.Seq))
	b := append([]byte(nil), pageOpen...)
	n := 0
	err := tx.Entries(v.ID, after, fromStart, s.lim.MaxPageEntries, func(e *LogEntry) bool {
		add := itemLen(e.Seq, len(e.Wire))
		if n > 0 {
			add++ // the comma
		}
		if n > 0 && size+add > s.lim.MaxPageBytes {
			return false
		}
		if n > 0 {
			b = append(b, ',')
		}
		b = appendItem(b, e)
		size += add
		n++
		return true
	})
	if err != nil {
		return nil, 0, err
	}
	b = append(b, pageMid...)
	b = appendHead(b, v.Head)
	b = append(b, pageClose...)
	return b, n, nil
}

// parseU64s parses a u64s (§3): decimal, no sign, no leading zeros.
func parseU64s(s string) (uint64, bool) {
	if s == "" || (len(s) > 1 && s[0] == '0') {
		return 0, false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return 0, false
		}
	}
	n, err := strconv.ParseUint(s, 10, 64)
	return n, err == nil
}

func parseID(s string) (model.ID, bool) {
	var id model.ID
	if len(s) != 2*len(id) || id.UnmarshalText([]byte(s)) != nil || id.IsZero() {
		return model.ID{}, false
	}
	return id, true
}

func parseHash(s string) (crypto.Hash, bool) {
	var h crypto.Hash
	if len(s) != hashHexLen || h.UnmarshalText([]byte(s)) != nil {
		return crypto.Hash{}, false
	}
	return h, true
}

// vaultAuth authenticates a vault request inside tx and checks that the
// path vault is the credential's vault. A path vault that is malformed,
// absent or another tenant's gets the same 404 (R1).
func (s *Server) vaultAuth(tx Tx, tok crypto.Hash, vaultID model.ID, ok bool) (*principal, error) {
	p, err := s.authenticate(tx, tok)
	if err != nil {
		return nil, err
	}
	if !ok || p.vaultID != vaultID {
		return nil, errNotFound
	}
	return p, nil
}

// accountBucket applies the per-account bucket of an authenticated
// endpoint (R14).
func (s *Server) accountBucket(c *call, p *principal) error {
	if !s.limiter.allow(c.route.pattern+"|account|"+p.accountID.String(), s.rates.Account) {
		return errRateLimited
	}
	return nil
}

// getLog: GET /v1/vaults/{id}/log?after=SEQ&wait=SECONDS →
// {entries:[{seq,h,wire}], head:{seq,h}}. With nothing after after, it
// waits up to wait seconds (at most 55) for a commit. Each wake-up
// re-authenticates and reads in one snapshot, so a credential invalidated
// while waiting gets a 401 with no data (R2).
func (s *Server) getLog(w http.ResponseWriter, r *http.Request, c *call) error {
	tok, ok := bearer(r)
	if !ok {
		return errUnauthorized
	}
	vaultID, okV := parseID(r.PathValue("vault"))
	q := r.URL.Query()
	var after uint64
	fromStart := true
	if vs, present := q["after"]; present {
		if len(vs) != 1 {
			return errBadRequest("after")
		}
		if after, ok = parseU64s(vs[0]); !ok {
			return errBadRequest("after")
		}
		fromStart = false
	}
	var wait time.Duration
	if vs, present := q["wait"]; present {
		n, ok := parseU64s(vs[0])
		if len(vs) != 1 || !ok || time.Duration(n)*time.Second > s.lim.MaxPollWait {
			return errBadRequest("wait")
		}
		wait = time.Duration(n) * time.Second
	}
	deadline := time.Now().Add(wait)

	var p *principal
	read := func() (body []byte, n int, beyond bool, err error) {
		err = s.store.View(r.Context(), func(tx Tx) error {
			if p, err = s.vaultAuth(tx, tok, vaultID, okV); err != nil {
				return err
			}
			v, err := tx.Vault(vaultID)
			if err != nil {
				return err
			}
			// A client ahead of the server gets an answer at once.
			beyond = !fromStart && after > v.Head.Seq
			body, n, err = s.page(tx, v, after, fromStart)
			return err
		})
		return
	}
	body, n, beyond, err := read()
	if err != nil {
		return err
	}
	if err := s.accountBucket(c, p); err != nil {
		return err
	}
	if n > 0 || wait == 0 || beyond {
		writeRaw(w, http.StatusOK, body)
		return nil
	}
	release, ok := s.polls.acquire(hex.EncodeToString(p.tokenHash[:]), p.accountID.String(), ipKey(c.ip))
	if !ok {
		return errBusy
	}
	defer release()
	for {
		ch := s.hub.watch(vaultID)
		body, n, beyond, err = read()
		if err != nil {
			return err
		}
		left := time.Until(deadline)
		if n > 0 || beyond || left <= 0 {
			writeRaw(w, http.StatusOK, body)
			return nil
		}
		if exp := p.expiresAt.Sub(s.now()); exp < left {
			left = max(exp, 0)
		}
		t := time.NewTimer(left)
		select {
		case <-ch:
		case <-t.C:
		case <-s.stop:
			t.Stop()
			writeRaw(w, http.StatusOK, body)
			return nil
		case <-r.Context().Done():
			t.Stop()
			return r.Context().Err()
		}
		t.Stop()
	}
}

// getEntry: GET /v1/vaults/{id}/entries/{seq} → {seq, h, wire}, or 404.
func (s *Server) getEntry(w http.ResponseWriter, r *http.Request, c *call) error {
	tok, ok := bearer(r)
	if !ok {
		return errUnauthorized
	}
	vaultID, okV := parseID(r.PathValue("vault"))
	seq, okS := parseU64s(r.PathValue("seq"))
	var body []byte
	err := s.store.View(r.Context(), func(tx Tx) error {
		p, err := s.vaultAuth(tx, tok, vaultID, okV)
		if err != nil {
			return err
		}
		if err := s.accountBucket(c, p); err != nil {
			return err
		}
		if !okS {
			return errNotFound
		}
		e, err := tx.Entry(vaultID, seq)
		if errors.Is(err, ErrNotFound) {
			return errNotFound
		}
		if err != nil {
			return err
		}
		body = appendItem(nil, e)
		return nil
	})
	if err != nil {
		return err
	}
	writeRaw(w, http.StatusOK, body)
	return nil
}

// getObject: GET /v1/vaults/{id}/objects/{sha256} → the canonical envelope
// itself. Only objects named by a committed entry of this vault are stored,
// so only they are served (R1, R11).
func (s *Server) getObject(w http.ResponseWriter, r *http.Request, c *call) error {
	tok, ok := bearer(r)
	if !ok {
		return errUnauthorized
	}
	vaultID, okV := parseID(r.PathValue("vault"))
	h, okH := parseHash(r.PathValue("sha256"))
	var body []byte
	err := s.store.View(r.Context(), func(tx Tx) error {
		p, err := s.vaultAuth(tx, tok, vaultID, okV)
		if err != nil {
			return err
		}
		if err := s.accountBucket(c, p); err != nil {
			return err
		}
		if !okH {
			return errNotFound
		}
		body, err = tx.Object(vaultID, h)
		if errors.Is(err, ErrNotFound) {
			return errNotFound
		}
		return err
	})
	if err != nil {
		return err
	}
	writeRaw(w, http.StatusOK, body)
	return nil
}

// prepared is a parsed wire ready to validate and store: the wire with only
// the supplied objects its entry names, its canonical bytes and its R13
// cost.
type prepared struct {
	w     *vaultlog.Wire
	h     crypto.Hash
	canon []byte
	cost  int64
}

// prepare enforces the collection and size limits that need no state (R9,
// R14) and drops supplied objects the entry does not name (R11).
func (s *Server) prepare(w *vaultlog.Wire) (*prepared, error) {
	if len(w.Entry.Ops) > s.lim.MaxOps || len(w.Objects) > s.lim.MaxObjects {
		return nil, errTooLarge
	}
	h, err := w.Entry.Hash()
	if err != nil {
		return nil, errInvalidEntry(err)
	}
	if _, err := vaultlog.WireObjects(w); err != nil {
		return nil, errInvalidEntry(err)
	}
	named := map[crypto.Hash]bool{}
	for _, d := range w.Entry.ObjectDigests() {
		named[d] = true
	}
	kept := []vaultlog.Object{}
	for _, o := range w.Objects {
		if !named[o.SHA256] {
			continue
		}
		if len(o.Body) > s.lim.MaxObject {
			return nil, errTooLarge
		}
		kept = append(kept, o)
	}
	sw := &vaultlog.Wire{Entry: w.Entry, Sigs: w.Sigs, Objects: kept}
	canon, err := sw.Marshal()
	if err != nil {
		return nil, errInvalidEntry(err)
	}
	if singletonLen(w.Entry.Seq, len(canon)) > s.lim.MaxWireResponse {
		return nil, errTooLarge
	}
	return &prepared{w: sw, h: h, canon: canon, cost: int64(len(canon)) + entryOverhead}, nil
}

// storeObjects fetches the committed objects of one vault.
type storeObjects struct {
	tx    Tx
	vault model.ID
}

func (f storeObjects) FetchObject(h crypto.Hash) ([]byte, error) {
	b, err := f.tx.Object(f.vault, h)
	if errors.Is(err, ErrNotFound) {
		return nil, vaultlog.ErrNoObject
	}
	return b, err
}

// reserve is one maximum-size entry with its metadata: the size of each
// half of the R13 recovery reserve.
func (s *Server) reserve() int64 { return int64(s.lim.MaxWireResponse) + entryOverhead }

// admits applies R13. Ordinary writes leave room for a maximum-size
// bootstrap followed by a maximum-size checkpoint. A bootstrap may spend
// the bootstrap half of that reserve, and a checkpoint that follows a
// bootstrap (completing the recovery sequence) may spend the rest.
// v is nil for a signup.
func (s *Server) admits(a *Account, v *Vault, kind vaultlog.Kind, cost int64) bool {
	quota := a.QuotaBytes
	if quota <= 0 {
		quota = s.lim.QuotaBytes
	}
	need := a.UsedBytes + cost
	switch {
	case v != nil && kind == vaultlog.KindBootstrap:
		need += s.reserve()
	case v != nil && kind == vaultlog.KindCheckpoint && v.LastBootstrap > v.LastCheckpoint:
	default:
		need += 2 * s.reserve()
	}
	return need <= quota
}

// applyEntry writes a validated entry and everything it determines, inside
// the commit transaction (R2): the entry, the objects it names, its
// devices, its departures (sessions ended, permanent receipts), and on a
// checkpoint the end of every session of the account. deps are the
// Departures of the entry's post-state. It updates a and v in memory;
// setState and the caller's writes complete them.
func (s *Server) applyEntry(tx Tx, a *Account, v *Vault, pw *prepared, deps []vaultlog.Departure) error {
	e := &pw.w.Entry
	if err := tx.InsertEntry(v.ID, &LogEntry{Seq: e.Seq, H: pw.h, Kind: e.Kind, Wire: pw.canon}); err != nil {
		return err
	}
	for _, o := range pw.w.Objects {
		if err := tx.InsertObject(v.ID, o.SHA256, o.Body, e.Seq); err != nil {
			return err
		}
	}
	for _, op := range e.Ops {
		if d, ok := op.(*vaultlog.DeviceAddOp); ok {
			if err := tx.PutDevice(&Device{AccountID: a.ID, DeviceID: d.Cert.DeviceID, SigPK: d.SigPK, Active: true, AddedSeq: e.Seq}); err != nil {
				return err
			}
		}
	}
	for _, dep := range deps {
		d, err := tx.Device(a.ID, dep.DeviceID)
		if err != nil {
			return err
		}
		d.Active = false
		if err := tx.PutDevice(d); err != nil {
			return err
		}
		if err := tx.DeleteSessions(a.ID, &dep.DeviceID); err != nil {
			return err
		}
		if err := tx.InsertReceipt(&Receipt{AccountID: a.ID, DeviceID: dep.DeviceID, How: dep.How, Seq: dep.Head.Seq, H: dep.Head.H}); err != nil {
			return err
		}
	}
	switch e.Kind {
	case vaultlog.KindGenesis:
		v.LastCheckpoint = 0
	case vaultlog.KindCheckpoint:
		if err := tx.DeleteSessions(a.ID, nil); err != nil {
			return err
		}
		v.LastCheckpoint = int64(e.Seq)
	case vaultlog.KindBootstrap:
		v.LastBootstrap = int64(e.Seq)
	}
	v.Head = vaultlog.Head{Seq: e.Seq, H: pw.h}
	a.UsedBytes += pw.cost
	return nil
}

// setState records the post-state of the last applied entry: the derived
// creds (auth and rauth hashes, salt, kdf_version, generation) and the
// public state the next commit starts from.
func setState(a *Account, v *Vault, post *vaultlog.PublicState) error {
	creds, ok := post.Creds()
	if !ok || post.Head() != v.Head {
		return errors.New("server: post-state does not match the applied entries")
	}
	a.KDFVersion, a.Salt, a.CredGen = creds.KDFVersion, creds.Salt, creds.Gen
	a.AuthSHA256, a.RAuthSHA256 = creds.AuthSHA256, creds.RAuthSHA256
	ps, err := post.Marshal()
	if err != nil {
		return err
	}
	v.PublicState = ps
	return nil
}

// mayWrite is R1 and R6 for an entry: a session writes only normal and
// checkpoint entries that its own device authors; a login or recovery
// token writes only a bootstrap.
func mayWrite(p *principal, e *vaultlog.Entry) error {
	switch p.kind {
	case credSession:
		if (e.Kind == vaultlog.KindNormal || e.Kind == vaultlog.KindCheckpoint) && e.Author == p.deviceID {
			return nil
		}
	case credLogin, credRecovery:
		if e.Kind == vaultlog.KindBootstrap {
			return nil
		}
	}
	return errUnauthorized
}

type postLogRequest struct {
	Wire canonjson.Raw `json:"wire"`
}

// postLog: POST /v1/vaults/{id}/log {wire} → {seq, h}. The commit is one
// write transaction: authenticate again, return an identical committed H,
// check prev against the head (409 head_conflict otherwise), ApplyPublic,
// check the quota, then write the entry and everything derived from it. A
// login or recovery token's one bootstrap is consumed in the same
// transaction (R6).
func (s *Server) postLog(w http.ResponseWriter, r *http.Request, c *call) error {
	tok, ok := bearer(r)
	if !ok {
		return errUnauthorized
	}
	vaultID, okV := parseID(r.PathValue("vault"))
	var p *principal
	err := s.store.View(r.Context(), func(tx Tx) (err error) {
		p, err = s.vaultAuth(tx, tok, vaultID, okV)
		return err
	})
	if err != nil {
		return err
	}
	if err := s.accountBucket(c, p); err != nil {
		return err
	}
	var req postLogRequest
	if err := s.decode(c.body, &req); err != nil {
		return err
	}
	wire, err := vaultlog.ParseWire(req.Wire)
	if err != nil {
		return errInvalidEntry(err)
	}
	if err := mayWrite(p, &wire.Entry); err != nil {
		return err
	}
	pw, err := s.prepare(wire)
	if err != nil {
		return err
	}
	release, ok := s.validate.acquire(r.Context())
	if !ok {
		return errBusy
	}
	defer release()

	var result vaultlog.Head
	committed := false
	err = s.store.Update(r.Context(), func(tx Tx) error {
		p, err := s.vaultAuth(tx, tok, vaultID, okV)
		if err != nil {
			return err
		}
		if err := mayWrite(p, &pw.w.Entry); err != nil {
			return err
		}
		if p.kind != credSession && p.bootstrap != nil {
			if p.bootstrap.H.Equal(pw.h) {
				result = *p.bootstrap
				return nil
			}
			return errUnauthorized
		}
		if result, committed, err = s.commit(tx, p.accountID, vaultID, pw); err != nil || !committed {
			return err
		}
		if p.kind != credSession {
			return tx.SetLoginTokenBootstrap(p.tokenHash, result)
		}
		return nil
	})
	if err != nil {
		return err
	}
	if committed {
		s.hub.notify(vaultID)
	}
	writeJSON(w, http.StatusOK, result)
	return nil
}

// commit is the commit path every entry write uses, inside the caller's
// write transaction, after the caller authorized the write: an identical
// committed H returns that commit (committed is false); otherwise prev must
// be the head (409 head_conflict), ApplyPublic must accept the wire against
// the stored public state, and R13 must admit it; then the entry and
// everything derived from it are written. The caller notifies long-polls
// after the transaction commits.
func (s *Server) commit(tx Tx, accountID, vaultID model.ID, pw *prepared) (vaultlog.Head, bool, error) {
	old, err := tx.EntryByHash(vaultID, pw.h)
	if err == nil {
		return vaultlog.Head{Seq: old.Seq, H: old.H}, false, nil
	}
	if !errors.Is(err, ErrNotFound) {
		return vaultlog.Head{}, false, err
	}
	v, err := tx.Vault(vaultID)
	if err != nil {
		return vaultlog.Head{}, false, err
	}
	e := &pw.w.Entry
	if e.Seq != v.Head.Seq+1 || !e.Prev.Equal(v.Head.H) {
		return vaultlog.Head{}, false, errHeadConflict(v.Head)
	}
	a, err := tx.Account(accountID)
	if err != nil {
		return vaultlog.Head{}, false, err
	}
	if a.VaultID != vaultID {
		return vaultlog.Head{}, false, errors.New("server: vault does not belong to the account")
	}
	pre, err := vaultlog.ParsePublicState(v.PublicState)
	if err != nil {
		return vaultlog.Head{}, false, err
	}
	post, err := vaultlog.ApplyPublic(pre, pw.w, storeObjects{tx, vaultID})
	if err != nil {
		return vaultlog.Head{}, false, errInvalidEntry(err)
	}
	if !s.admits(a, v, e.Kind, pw.cost) {
		return vaultlog.Head{}, false, errQuota
	}
	if err := s.applyEntry(tx, a, v, pw, post.Departures()); err != nil {
		return vaultlog.Head{}, false, err
	}
	if err := setState(a, v, post); err != nil {
		return vaultlog.Head{}, false, err
	}
	if err := tx.UpdateVault(v); err != nil {
		return vaultlog.Head{}, false, err
	}
	if err := tx.UpdateAccount(a); err != nil {
		return vaultlog.Head{}, false, err
	}
	return v.Head, true, nil
}
