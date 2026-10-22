package server

import (
	"bytes"
	"crypto/rand"
	"crypto/subtle"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"net/http"
	"time"

	"github.com/dalyem/hopkey/internal/canonjson"
	"github.com/dalyem/hopkey/internal/crypto"
	"github.com/dalyem/hopkey/internal/model"
	"github.com/dalyem/hopkey/internal/vaultlog"
)

// The enrollment relay (R7, R12, crypto spec §7). A new device D creates a
// mailbox with its commit and gets a routing code, which its user carries
// to an approving device A. A claims the mailbox with the code, and the two
// exchange chal (A), open (D) and deliver (A) through it. The relay checks
// schemas, roles, ordering and limits; it never decrypts a delivery, and
// both clients keep every §7 check.
//
// Routing codes, mailbox tokens and enroll IDs never reach the log: the
// access log has the route template only.

// Message types and the sequence number each one takes (R12).
const (
	msgChal    = "chal"
	msgOpen    = "open"
	msgDeliver = "deliver"
)

var msgSlot = map[string]uint64{msgChal: 1, msgOpen: 2, msgDeliver: 3}

// routingCodeLen is the length of a routing code: 10 Crockford symbols,
// 50 bits (R7).
const routingCodeLen = 10

const crockford = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"

var (
	errClaimed       = &apiError{http.StatusConflict, "already_claimed", "the mailbox is claimed by another device", nil}
	errEnrollOrder   = &apiError{http.StatusConflict, "conflict", "the message is out of order or its slot holds another message", nil}
	errMailboxFull   = &apiError{http.StatusRequestEntityTooLarge, "too_large", "the mailbox message limit is reached", nil}
	errMailboxesBusy = &apiError{http.StatusTooManyRequests, "busy", "too many live mailboxes", nil}
)

// newRoutingCode returns 50 uniformly random bits as 10 Crockford symbols.
func newRoutingCode() (string, error) {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	v := binary.BigEndian.Uint64(b[:]) >> (64 - 5*routingCodeLen)
	out := make([]byte, routingCodeLen)
	for i := routingCodeLen - 1; i >= 0; i-- {
		out[i] = crockford[v&31]
		v >>= 5
	}
	return string(out), nil
}

// normalizeRoutingCode applies Crockford's decoding rules to a code as a
// user typed it: hyphens are ignored, lowercase is accepted, and I and L
// read as 1, O as 0. It returns the canonical code, or false when the
// input is not 10 symbols.
func normalizeRoutingCode(s string) (string, bool) {
	if len(s) > 2*routingCodeLen {
		return "", false
	}
	out := make([]byte, 0, routingCodeLen)
	for i := 0; i < len(s); i++ {
		c := s[i]
		if 'a' <= c && c <= 'z' {
			c -= 'a' - 'A'
		}
		switch c {
		case '-':
			continue
		case 'I', 'L':
			c = '1'
		case 'O':
			c = '0'
		}
		if bytes.IndexByte([]byte(crockford), c) < 0 {
			return "", false
		}
		out = append(out, c)
	}
	if len(out) != routingCodeLen {
		return "", false
	}
	return string(out), true
}

type enrollRequest struct {
	Commit canonjson.Raw `json:"commit"`
}

type enrollResponse struct {
	EnrollID     model.ID `json:"enroll_id"`
	MailboxToken string   `json:"mailbox_token"`
	RoutingCode  string   `json:"routing_code"`
}

// enrollCreate: POST /v1/enroll {commit} → {enroll_id, routing_code,
// mailbox_token}. No authentication; the route's IP bucket and the live
// mailbox limits per IP and per process apply (R8, R14). The mailbox
// expires MailboxTTL after creation, and nothing extends it.
func (s *Server) enrollCreate(w http.ResponseWriter, r *http.Request, c *call) error {
	var req enrollRequest
	if err := s.decode(c.body, &req); err != nil {
		return err
	}
	var commit crypto.EnrollCommit
	if crypto.ParseEnrollMessage(req.Commit, &commit) != nil {
		return errBadRequest("commit does not match the schema")
	}
	commitJSON, err := canonjson.Marshal(&commit)
	if err != nil {
		return err
	}
	tok, tokHash, err := newSecret()
	if err != nil {
		return err
	}
	ip := ipKey(c.ip)
	var resp enrollResponse
	err = s.store.Update(r.Context(), func(tx Tx) error {
		now := s.now()
		if err := tx.DeleteExpiredMailboxes(now); err != nil {
			return err
		}
		n, err := tx.CountMailboxes(now, &ip)
		if err != nil {
			return err
		}
		if n >= s.lim.MailboxesPerIP {
			return errRateLimited
		}
		if n, err = tx.CountMailboxes(now, nil); err != nil {
			return err
		}
		if n >= s.lim.MailboxesPerProcess {
			return errMailboxesBusy
		}
		// A fresh enroll ID or routing code that collides with a live
		// mailbox is drawn again; with 128 and 50 random bits that is
		// rare, so a few tries suffice.
		for range 8 {
			id, err := vaultlog.NewID()
			if err != nil {
				return err
			}
			code, err := newRoutingCode()
			if err != nil {
				return err
			}
			err = tx.InsertMailbox(&Mailbox{
				ID: id, RoutingCode: code, TokenHash: tokHash, Commit: commitJSON, IP: ip,
				ExpiresAt: now.Add(MailboxTTL),
			})
			if errors.Is(err, ErrDuplicate) {
				continue
			}
			if err != nil {
				return err
			}
			resp = enrollResponse{EnrollID: id, MailboxToken: tok, RoutingCode: code}
			return nil
		}
		return errors.New("server: no free routing code")
	})
	if err != nil {
		return err
	}
	writeJSON(w, http.StatusOK, resp)
	return nil
}

type claimRequest struct {
	RoutingCode string `json:"routing_code"`
}

type claimResponse struct {
	Commit   canonjson.Raw `json:"commit"`
	EnrollID model.ID      `json:"enroll_id"`
}

// sessionPrincipal authenticates a device session inside tx. Login and
// recovery tokens never authorize enrollment (R6).
func (s *Server) sessionPrincipal(tx Tx, tok crypto.Hash) (*principal, error) {
	p, err := s.authenticate(tx, tok)
	if err != nil {
		return nil, err
	}
	if p.kind != credSession {
		return nil, errUnauthorized
	}
	return p, nil
}

// enrollClaim: POST /v1/enroll/claim {routing_code} → {enroll_id, commit}.
// In one write transaction: the session must be valid, the account and
// approving-device buckets must admit the attempt (they count failed
// attempts, R14), and the code must name a live mailbox. An unclaimed
// mailbox is bound to the session's account and device; a repeat by that
// account and device returns the same result; any other claimant gets
// already_claimed and changes nothing (R7).
func (s *Server) enrollClaim(w http.ResponseWriter, r *http.Request, c *call) error {
	tok, ok := bearer(r)
	if !ok {
		return errUnauthorized
	}
	var req claimRequest
	if err := s.decode(c.body, &req); err != nil {
		return err
	}
	var resp claimResponse
	err := s.store.Update(r.Context(), func(tx Tx) error {
		p, err := s.sessionPrincipal(tx, tok)
		if err != nil {
			return err
		}
		if err := s.accountBucket(c, p); err != nil {
			return err
		}
		if !s.limiter.allow(c.route.pattern+"|device", p.accountID.String()+"/"+p.deviceID.String(), s.rates.Claim) {
			return errRateLimited
		}
		code, ok := normalizeRoutingCode(req.RoutingCode)
		if !ok {
			return errBadRequest("routing_code")
		}
		m, err := tx.MailboxByCode(code)
		if errors.Is(err, ErrNotFound) {
			return errNotFound
		}
		if err != nil {
			return err
		}
		if !s.now().Before(m.ExpiresAt) {
			return errNotFound
		}
		switch {
		case m.AccountID == nil:
			if err := tx.ClaimMailbox(m.ID, p.accountID, p.deviceID); err != nil {
				return err
			}
		case *m.AccountID != p.accountID || *m.DeviceID != p.deviceID:
			return errClaimed
		}
		resp = claimResponse{Commit: m.Commit, EnrollID: m.ID}
		return nil
	})
	if err != nil {
		return err
	}
	writeJSON(w, http.StatusOK, resp)
	return nil
}

// enrollRole is the party a mailbox request speaks for.
type enrollRole int

const (
	roleD enrollRole = iota + 1 // the new device, by the mailbox token
	roleA                       // the approving device, by a session
)

// mailboxAuth resolves a mailbox request inside tx (R7). The mailbox token
// of a live mailbox acts as D. Otherwise the credential must be a valid
// session (401 if not), and it acts as A only for the device the mailbox
// is bound to; any other session, and a mailbox that is absent, expired or
// unclaimed, gets 404. p is set for A.
func (s *Server) mailboxAuth(tx Tx, tok crypto.Hash, id model.ID, okID bool) (m *Mailbox, role enrollRole, p *principal, err error) {
	if okID {
		m, err = tx.Mailbox(id)
		switch {
		case errors.Is(err, ErrNotFound):
			m = nil
		case err != nil:
			return nil, 0, nil, err
		case !s.now().Before(m.ExpiresAt):
			m = nil
		}
	}
	if m != nil && subtle.ConstantTimeCompare(tok[:], m.TokenHash[:]) == 1 {
		return m, roleD, nil, nil
	}
	if p, err = s.sessionPrincipal(tx, tok); err != nil {
		return nil, 0, nil, err
	}
	if m == nil || m.AccountID == nil || *m.AccountID != p.accountID || *m.DeviceID != p.deviceID {
		return nil, 0, nil, errNotFound
	}
	return m, roleA, p, nil
}

type enrollMsgRequest struct {
	Body canonjson.Raw `json:"body"`
	Type string        `json:"type"`
}

type enrollMsgResponse struct {
	N uint64 `json:"n,string"`
}

// deliverBody is deliver's body: the HPKE envelope of §7, which only D can
// open.
type deliverBody struct{ crypto.HPKEEnvelope }

func (d *deliverBody) Validate() error { return d.Check() }

// checkMsgBody checks a message body against the closed schema of its
// type (§7) and returns its canonical form. A delivery is checked only as
// an HPKE envelope; the relay cannot open it.
func checkMsgBody(typ string, body []byte) ([]byte, error) {
	if len(body) == 0 || body[0] != '{' {
		return nil, errBadRequest("body must be an object")
	}
	var v interface{ Validate() error }
	switch typ {
	case msgChal:
		v = new(crypto.EnrollChal)
	case msgOpen:
		v = new(crypto.EnrollOpen)
	case msgDeliver:
		v = new(deliverBody)
	default:
		return nil, errBadRequest("type")
	}
	if err := crypto.ParseEnrollMessage(body, v); err != nil {
		return nil, errBadRequest("body does not match the schema of " + typ)
	}
	return canonjson.Marshal(v)
}

// enrollPost: POST /v1/enroll/{id}/msg {type, body} → {n}. A sends chal
// and deliver, D sends open, and they take n = 1, 2 and 3 in that order
// (R12). An identical canonical retransmission returns its original n; a
// different message for a filled slot, or a message out of order, gets 409
// and changes nothing. A chal must name this mailbox and its claim. The
// count and byte limits apply to what is stored (R8).
func (s *Server) enrollPost(w http.ResponseWriter, r *http.Request, c *call) error {
	tok, ok := bearer(r)
	if !ok {
		return errUnauthorized
	}
	id, okID := parseID(r.PathValue("enroll"))
	var req enrollMsgRequest
	if err := s.decode(c.body, &req); err != nil {
		return err
	}
	body, err := checkMsgBody(req.Type, req.Body)
	if err != nil {
		return err
	}
	var n uint64
	added := false
	err = s.store.Update(r.Context(), func(tx Tx) error {
		m, role, p, err := s.mailboxAuth(tx, tok, id, okID)
		if err != nil {
			return err
		}
		if p != nil {
			if err := s.accountBucket(c, p); err != nil {
				return err
			}
		}
		want := roleA
		if req.Type == msgOpen {
			want = roleD
		}
		if role != want {
			return errUnauthorized
		}
		if req.Type == msgChal {
			var ch crypto.EnrollChal
			if err := canonjson.Unmarshal(body, &ch); err != nil {
				return err
			}
			if ch.EnrollID != m.ID || ch.AccountID != *m.AccountID || ch.ApproverDeviceID != *m.DeviceID {
				return errBadRequest("chal does not name this mailbox and its claim")
			}
		}
		msgs, err := tx.MailboxMessages(m.ID, 0)
		if err != nil {
			return err
		}
		n = msgSlot[req.Type]
		if n <= uint64(len(msgs)) {
			old := msgs[n-1]
			if old.Type != req.Type || !bytes.Equal(old.Body, body) {
				return errEnrollOrder
			}
			return nil
		}
		if n != uint64(len(msgs))+1 {
			return errEnrollOrder
		}
		size := len(body)
		for _, old := range msgs {
			size += len(old.Body)
		}
		if len(msgs) >= s.lim.MailboxMessages || size > s.lim.MailboxBytes {
			return errMailboxFull
		}
		added = true
		return tx.InsertMailboxMessage(m.ID, &MailboxMessage{N: n, Type: req.Type, Body: body})
	})
	if err != nil {
		return err
	}
	if added {
		s.mbox.notify(id)
	}
	writeJSON(w, http.StatusOK, enrollMsgResponse{n})
	return nil
}

type enrollMsg struct {
	Body canonjson.Raw `json:"body"`
	N    uint64        `json:"n,string"`
	Type string        `json:"type"`
}

type enrollMsgsResponse struct {
	Messages []enrollMsg `json:"messages"`
}

// enrollGet: GET /v1/enroll/{id}/msg?after=N&wait=S → {messages:[{n, type,
// body}]}, ascending, with n > after (default "0"). With none, it waits up
// to wait seconds (0 to 55, default 0) for one and then answers 200 with
// an empty list (R12). The wait also ends when the mailbox expires or, for
// A, when its session expires; the next read then refuses (A gets 404, and
// D 401, since its token died with the mailbox).
//
// A's response is admitted as a vault log response is: authenticated
// again under the account's admission lock, held until it is written, and
// A's wait wakes on every commit of its vault, so a session ended by a
// retirement, revocation or checkpoint gets a 401 with nothing (R2).
func (s *Server) enrollGet(w http.ResponseWriter, r *http.Request, c *call) error {
	tok, ok := bearer(r)
	if !ok {
		return errUnauthorized
	}
	id, okID := parseID(r.PathValue("enroll"))
	q := r.URL.Query()
	var after uint64
	if vs, present := q["after"]; present {
		if after, ok = parseU64s(vs[0]); len(vs) != 1 || !ok {
			return errBadRequest("after")
		}
	}
	var wait time.Duration
	if vs, present := q["wait"]; present {
		n, ok := parseU64s(vs[0])
		if len(vs) != 1 || !ok || n > uint64(s.lim.MaxPollWait/time.Second) {
			return errBadRequest("wait")
		}
		wait = time.Duration(n) * time.Second
	}
	deadline := time.Now().Add(wait)

	var m *Mailbox
	var p *principal
	read := func() (body []byte, n int, err error) {
		var msgs []MailboxMessage
		err = s.store.View(r.Context(), func(tx Tx) error {
			if m, _, p, err = s.mailboxAuth(tx, tok, id, okID); err != nil {
				return err
			}
			msgs, err = tx.MailboxMessages(m.ID, after)
			return err
		})
		if err != nil {
			return nil, 0, err
		}
		resp := enrollMsgsResponse{Messages: []enrollMsg{}}
		for _, mm := range msgs {
			resp.Messages = append(resp.Messages, enrollMsg{Body: mm.Body, N: mm.N, Type: mm.Type})
		}
		body, err = canonjson.Marshal(resp)
		return body, len(msgs), err
	}
	send := func(body []byte) error {
		if p == nil {
			writeRaw(w, http.StatusOK, body)
			return nil
		}
		unlock, err := s.accounts.rlock(r.Context(), p.accountID)
		if err != nil {
			return err
		}
		defer unlock()
		err = s.store.View(r.Context(), func(tx Tx) error {
			_, _, _, err := s.mailboxAuth(tx, tok, id, okID)
			return err
		})
		if err != nil {
			return err
		}
		rc := http.NewResponseController(w)
		writeBy := time.Now().Add(s.lim.AdmitWrite)
		if c.writeBy.Before(writeBy) {
			writeBy = c.writeBy
		}
		_ = rc.SetWriteDeadline(writeBy)
		writeRaw(w, http.StatusOK, body)
		_ = rc.Flush()
		return nil
	}

	body, n, err := read()
	if err != nil {
		return err
	}
	if p != nil {
		if err := s.accountBucket(c, p); err != nil {
			return err
		}
	}
	if n > 0 || wait == 0 {
		return send(body)
	}
	cred, acct := hex.EncodeToString(tok[:]), "enroll:"+id.String()
	if p != nil {
		acct = p.accountID.String()
	}
	release, ok := s.polls.acquire(cred, acct, ipKey(c.ip))
	if !ok {
		return errBusy
	}
	defer release()
	for {
		ch := s.mbox.watch(id)
		var vch <-chan struct{}
		if p != nil {
			vch = s.hub.watch(p.vaultID)
		}
		if body, n, err = read(); err != nil {
			return err
		}
		left := time.Until(deadline)
		if n > 0 || left <= 0 {
			return send(body)
		}
		// Wake when the mailbox or A's session expires; the next read
		// then refuses.
		ends := m.ExpiresAt
		if p != nil && p.expiresAt.Before(ends) {
			ends = p.expiresAt
		}
		if exp := ends.Sub(s.now()); exp < left {
			left = max(exp, 0)
		}
		t := time.NewTimer(left)
		select {
		case <-ch:
		case <-vch:
		case <-t.C:
		case <-s.stop:
			t.Stop()
			return send(body)
		case <-r.Context().Done():
			t.Stop()
			return r.Context().Err()
		}
		t.Stop()
	}
}
