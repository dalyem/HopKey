package server

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/hpke"
	"crypto/rand"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/dalyem/hopkey/internal/canonjson"
	"github.com/dalyem/hopkey/internal/crypto"
	"github.com/dalyem/hopkey/internal/model"
)

// newD is a new device D with real enrollment keys and its open message.
type newD struct {
	kem    hpke.PrivateKey
	open   crypto.EnrollOpen
	commit crypto.EnrollCommit
	mb     enrollResponse
}

func makeD(t *testing.T, name string) *newD {
	t.Helper()
	kem, err := crypto.GenerateKEMKey()
	if err != nil {
		t.Fatal(err)
	}
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	d := &newD{kem: kem, open: crypto.EnrollOpen{V: 1, KEMPK: kem.PublicKey().Bytes(), SigPK: pub, ND: randBytes(t, 32), Name: name}}
	d.commit = crypto.EnrollCommit{V: 1, C: crypto.Commitment(&d.open)}
	return d
}

func rawJSON(t *testing.T, v any) canonjson.Raw {
	t.Helper()
	b, err := canonjson.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func (e *env) createMailbox(commit any, hdr ...string) resp {
	return e.do("POST", "/v1/enroll", "", enrollRequest{Commit: rawJSON(e.t, commit)}, hdr...)
}

// mailbox creates D's mailbox.
func (e *env) mailbox(d *newD) {
	e.t.Helper()
	e.must(e.createMailbox(d.commit), 200, &d.mb)
}

func (e *env) claim(tok, code string) resp {
	return e.do("POST", "/v1/enroll/claim", tok, claimRequest{code})
}

func msgPath(id model.ID) string { return "/v1/enroll/" + id.String() + "/msg" }

func (e *env) postMsg(id model.ID, tok, typ string, body any) resp {
	e.t.Helper()
	return e.do("POST", msgPath(id), tok, enrollMsgRequest{Body: rawJSON(e.t, body), Type: typ})
}

// mustMsg posts a message and checks the n it was given.
func (e *env) mustMsg(id model.ID, tok, typ string, body any, n uint64) {
	e.t.Helper()
	var r enrollMsgResponse
	e.must(e.postMsg(id, tok, typ, body), 200, &r)
	if r.N != n {
		e.t.Fatalf("%s got n %d, want %d", typ, r.N, n)
	}
}

func (e *env) getMsgs(id model.ID, tok, query string) (resp, enrollMsgsResponse) {
	e.t.Helper()
	r := e.do("GET", msgPath(id)+query, tok, nil)
	var m enrollMsgsResponse
	if r.status == 200 {
		e.must(r, 200, &m)
	}
	return r, m
}

// startGet long-polls path in the background and waits until the server
// holds the poll.
func (e *env) startGet(path, tok string) <-chan resp {
	e.t.Helper()
	before := e.polls()
	ch := make(chan resp, 1)
	go func() { ch <- e.do("GET", path, tok, nil) }()
	deadline := time.Now().Add(10 * time.Second)
	for e.polls() == before {
		if time.Now().After(deadline) {
			e.t.Fatal("the long-poll never started waiting")
		}
		time.Sleep(5 * time.Millisecond)
	}
	return ch
}

func chalFor(t *testing.T, id model.ID, v *tvault, approver model.ID) crypto.EnrollChal {
	var fp crypto.Hash
	copy(fp[:], randBytes(t, 32))
	return crypto.EnrollChal{V: 1, EnrollID: id, NA: randBytes(t, 32), AccountID: v.accountID(), ApproverDeviceID: approver, AcctSigFp: fp, AKV: 1}
}

// deliverFor seals a delivery-shaped envelope to D's KEM key. The relay
// sees only the envelope, so its plaintext need not be a real delivery.
func deliverFor(t *testing.T, d *newD, pt []byte) crypto.HPKEEnvelope {
	t.Helper()
	env, err := crypto.SealHPKE(d.open.KEMPK, []byte("test-deliver"), nil, pt)
	if err != nil {
		t.Fatal(err)
	}
	return env
}

// enrollSetup publishes a vault, opens a session for its first device (A)
// and creates and claims D's mailbox.
func enrollSetup(t *testing.T, e *env) (*tvault, string, *newD) {
	t.Helper()
	v := newVault(t, "a@example.com")
	e.publish(v)
	tokA := e.session(v, v.dev(0))
	d := makeD(t, "laptop")
	e.mailbox(d)
	e.must(e.claim(tokA, d.mb.RoutingCode), 200, nil)
	return v, tokA, d
}

// The whole §7 exchange through the relay: D creates a mailbox with its
// commit, A claims it with the routing code, and chal, open and deliver
// pass between them byte for byte, with long-polls waking on each post.
func TestEnrollFullExchange(t *testing.T) {
	e := newEnv(t)
	v := newVault(t, "a@example.com")
	e.publish(v)
	A := v.dev(0)
	tokA := e.session(v, A)

	d := makeD(t, "laptop")
	e.mailbox(d)
	if len(d.mb.RoutingCode) != 10 || strings.Trim(d.mb.RoutingCode, crockford) != "" {
		t.Fatalf("routing code %q is not 10 Crockford symbols", d.mb.RoutingCode)
	}
	if _, ok := secretHash(d.mb.MailboxToken); !ok {
		t.Fatalf("mailbox token %q is not a 32-byte credential", d.mb.MailboxToken)
	}

	// A claims and receives D's commit.
	var cr claimResponse
	e.must(e.claim(tokA, d.mb.RoutingCode), 200, &cr)
	var commit crypto.EnrollCommit
	if err := crypto.ParseEnrollMessage(cr.Commit, &commit); err != nil || cr.EnrollID != d.mb.EnrollID || commit != d.commit {
		t.Fatalf("claim returned %+v (%v), want enroll ID %v and commit %+v", cr, err, d.mb.EnrollID, d.commit)
	}

	// D waits for chal; A sends it.
	id := d.mb.EnrollID
	poll := e.startGet(msgPath(id)+"?wait=30", d.mb.MailboxToken)
	chal := chalFor(t, id, v, A)
	e.mustMsg(id, tokA, msgChal, chal, 1)
	var got enrollMsgsResponse
	e.must(waitResp(t, poll), 200, &got)
	if len(got.Messages) != 1 || got.Messages[0].N != 1 || got.Messages[0].Type != msgChal {
		t.Fatalf("D's poll returned %+v", got)
	}
	var dChal crypto.EnrollChal
	if err := crypto.ParseEnrollMessage(got.Messages[0].Body, &dChal); err != nil || dChal.EnrollID != id {
		t.Fatalf("D's chal: %+v, %v", dChal, err)
	}

	// A waits for open; D sends it.
	poll = e.startGet(msgPath(id)+"?after=1&wait=30", tokA)
	e.mustMsg(id, d.mb.MailboxToken, msgOpen, d.open, 2)
	e.must(waitResp(t, poll), 200, &got)
	if len(got.Messages) != 1 || got.Messages[0].N != 2 || got.Messages[0].Type != msgOpen {
		t.Fatalf("A's poll returned %+v", got)
	}
	var aOpen crypto.EnrollOpen
	if err := crypto.ParseEnrollMessage(got.Messages[0].Body, &aOpen); err != nil {
		t.Fatal(err)
	}
	if crypto.Commitment(&aOpen) != commit.C {
		t.Fatal("the relayed open does not match the claimed commit")
	}
	sasA, errA := crypto.SAS(crypto.Transcript(commit.C, &chal, &aOpen))
	sasD, errD := crypto.SAS(crypto.Transcript(d.commit.C, &dChal, &d.open))
	if errA != nil || errD != nil || sasA != sasD {
		t.Fatalf("SAS on A %q (%v), on D %q (%v)", sasA, errA, sasD, errD)
	}

	// D waits for the delivery; A seals and sends it.
	secret := []byte(`{"v":1,"secret":"only D reads this"}`)
	deliver := deliverFor(t, d, secret)
	poll = e.startGet(msgPath(id)+"?after=2&wait=30", d.mb.MailboxToken)
	e.mustMsg(id, tokA, msgDeliver, deliver, 3)
	e.must(waitResp(t, poll), 200, &got)
	if len(got.Messages) != 1 || got.Messages[0].N != 3 || got.Messages[0].Type != msgDeliver {
		t.Fatalf("D's delivery poll returned %+v", got)
	}
	var env crypto.HPKEEnvelope
	if err := canonjson.Unmarshal(got.Messages[0].Body, &env); err != nil {
		t.Fatal(err)
	}
	pt, err := crypto.OpenHPKE(d.kem, env, []byte("test-deliver"), nil)
	if err != nil || !bytes.Equal(pt, secret) {
		t.Fatalf("D opened %q, %v", pt, err)
	}

	// Either side reads the whole mailbox, in order, in JCS.
	r, all := e.getMsgs(id, d.mb.MailboxToken, "")
	if len(all.Messages) != 3 || all.Messages[0].N != 1 || all.Messages[1].N != 2 || all.Messages[2].N != 3 {
		t.Fatalf("whole mailbox: %s", r)
	}
	if canon, err := canonjson.Canonicalize(r.body); err != nil || !bytes.Equal(canon, r.body) {
		t.Errorf("the response is not JCS: %s", r.body)
	}
	if !bytes.Contains(r.body, []byte(`"n":"1"`)) {
		t.Errorf("n is not a u64s: %s", r.body)
	}

	// No code, token or mailbox ID reaches the log.
	logs := e.logs.String()
	for _, secret := range []string{d.mb.RoutingCode, strings.ToLower(d.mb.RoutingCode), d.mb.MailboxToken, id.String(), tokA} {
		if strings.Contains(logs, secret) {
			t.Errorf("the log holds %q", secret)
		}
	}
}

// A claim binds the mailbox once, to the account and the approving
// device. The same device repeating it (with any session, in any spelling
// of the code) gets the same answer; anyone else is refused and the
// binding stays (R7).
func TestEnrollClaimRetryAndTheft(t *testing.T) {
	e := newEnv(t)
	v := newVault(t, "a@example.com")
	e.publish(v)
	A := v.dev(0)
	B, wb := v.bootstrap("dev-b")
	e.mustPost(v, e.login(v), wb)
	tokA, tokB := e.session(v, A), e.session(v, B)
	other := newVault(t, "b@example.com")
	e.publish(other)
	tokX := e.session(other, other.dev(0))

	d := makeD(t, "laptop")
	e.mailbox(d)
	code := d.mb.RoutingCode
	var first, again claimResponse
	e.must(e.claim(tokA, code), 200, &first)
	e.must(e.claim(tokA, code), 200, &again)
	if !bytes.Equal(first.Commit, again.Commit) || first.EnrollID != again.EnrollID {
		t.Errorf("repeat claim %+v, first %+v", again, first)
	}
	// Crockford spelling: lowercase, hyphens, O for 0 and I or L for 1.
	spelled := strings.ToLower(code[:5]) + "-" + code[5:]
	spelled = strings.NewReplacer("0", "o", "1", "l").Replace(spelled)
	e.must(e.claim(e.session(v, A), spelled), 200, &again)
	if again.EnrollID != first.EnrollID {
		t.Errorf("a refreshed session's claim got %v", again.EnrollID)
	}

	wantCode(t, e.claim(tokB, code), 409, "already_claimed", "another device of the account")
	wantCode(t, e.claim(tokX, code), 409, "already_claimed", "a device of another account")
	wantCode(t, e.claim(e.login(v), code), 401, "unauthorized", "a login token")
	wantCode(t, e.claim("", code), 401, "unauthorized", "no credential")
	wantCode(t, e.claim(d.mb.MailboxToken, code), 401, "unauthorized", "the mailbox token")
	wantCode(t, e.claim(tokA, "0000000000"), 404, "not_found", "an unknown code")
	wantCode(t, e.claim(tokA, "ABCDEFGHJU"), 400, "bad_request", "a code with U")
	wantCode(t, e.claim(tokA, code[:9]), 400, "bad_request", "a short code")

	// The binding is unchanged: A goes on, the would-be thieves cannot.
	id := d.mb.EnrollID
	e.mustMsg(id, tokA, msgChal, chalFor(t, id, v, A), 1)
	wantCode(t, e.postMsg(id, tokB, msgChal, chalFor(t, id, v, B)), 404, "not_found", "B posts chal")
	r, _ := e.getMsgs(id, tokX, "")
	wantCode(t, r, 404, "not_found", "another account reads")
	e.view(func(tx Tx) error {
		m, err := tx.Mailbox(id)
		if err != nil || m.AccountID == nil || *m.AccountID != v.accountID() || *m.DeviceID != A {
			t.Errorf("binding %+v, %v", m, err)
		}
		return nil
	})
}

// Only the mailbox token acts as D, and only a session of the bound
// device as A; each sends only its own message types (R7).
func TestEnrollRoles(t *testing.T) {
	e := newEnv(t)
	v, tokA, d := enrollSetup(t, e)
	A := v.dev(0)
	B, wb := v.bootstrap("dev-b")
	e.mustPost(v, e.login(v), wb)
	tokB := e.session(v, B)
	id, tokD := d.mb.EnrollID, d.mb.MailboxToken
	chal := chalFor(t, id, v, A)

	// Before any message: D cannot send chal, A cannot send open.
	wantCode(t, e.postMsg(id, tokD, msgChal, chal), 401, "unauthorized", "D sends chal")
	e.mustMsg(id, tokA, msgChal, chal, 1)
	wantCode(t, e.postMsg(id, tokA, msgOpen, d.open), 401, "unauthorized", "A sends open")
	e.mustMsg(id, tokD, msgOpen, d.open, 2)
	wantCode(t, e.postMsg(id, tokD, msgDeliver, deliverFor(t, d, []byte("x"))), 401, "unauthorized", "D sends deliver")
	// Not even a retransmission passes in the wrong role.
	wantCode(t, e.postMsg(id, tokD, msgChal, chal), 401, "unauthorized", "D retransmits A's chal")

	// Other credentials.
	wantCode(t, e.postMsg(id, tokB, msgDeliver, deliverFor(t, d, []byte("x"))), 404, "not_found", "another device's session")
	wantCode(t, e.postMsg(id, e.login(v), msgDeliver, deliverFor(t, d, []byte("x"))), 401, "unauthorized", "a login token")
	wantCode(t, e.postMsg(id, "", msgDeliver, deliverFor(t, d, []byte("x"))), 401, "unauthorized", "no credential")
	d2 := makeD(t, "phone")
	e.mailbox(d2)
	wantCode(t, e.postMsg(id, d2.mb.MailboxToken, msgOpen, d.open), 401, "unauthorized", "another mailbox's token")
	r, _ := e.getMsgs(id, d2.mb.MailboxToken, "")
	wantCode(t, r, 401, "unauthorized", "another mailbox's token reads")
	// An unclaimed mailbox has no A at all.
	r, _ = e.getMsgs(d2.mb.EnrollID, tokA, "")
	wantCode(t, r, 404, "not_found", "a session reads an unclaimed mailbox")
	wantCode(t, e.postMsg(d2.mb.EnrollID, tokA, msgChal, chalFor(t, d2.mb.EnrollID, v, A)), 404, "not_found", "chal to an unclaimed mailbox")
	r, _ = e.getMsgs(model.ID{}, tokD, "")
	wantCode(t, r, 401, "unauthorized", "a malformed mailbox ID with D's token")

	// A chal must name the mailbox and its claim.
	d3 := makeD(t, "tablet")
	e.mailbox(d3)
	e.must(e.claim(tokA, d3.mb.RoutingCode), 200, nil)
	id3 := d3.mb.EnrollID
	otherAccount := chalFor(t, id3, v, A)
	otherAccount.AccountID = randID(t)
	for name, ch := range map[string]crypto.EnrollChal{
		"another enroll ID":  chalFor(t, id, v, A),
		"another approver":   chalFor(t, id3, v, B),
		"another account ID": otherAccount,
	} {
		wantCode(t, e.postMsg(id3, tokA, msgChal, ch), 400, "bad_request", name)
	}
	e.mustMsg(id3, tokA, msgChal, chalFor(t, id3, v, A), 1)
}

// Messages take n = 1, 2, 3 in order. An identical canonical
// retransmission gets its n again and adds nothing; anything else for a
// filled slot, or out of order, gets 409 and changes nothing (R12).
func TestEnrollOrderingAndRetransmission(t *testing.T) {
	e := newEnv(t)
	v, tokA, d := enrollSetup(t, e)
	A := v.dev(0)
	id, tokD := d.mb.EnrollID, d.mb.MailboxToken
	chal := chalFor(t, id, v, A)
	deliver := deliverFor(t, d, []byte("payload"))

	wantCode(t, e.postMsg(id, tokD, msgOpen, d.open), 409, "conflict", "open before chal")
	wantCode(t, e.postMsg(id, tokA, msgDeliver, deliver), 409, "conflict", "deliver before chal")
	e.mustMsg(id, tokA, msgChal, chal, 1)
	// The same chal, not canonically encoded: whitespace and member order
	// differ.
	b := strings.ReplaceAll(string(rawJSON(t, chal)), ",", " ,\n ")
	loose := []byte(`{ "type" : "chal", "body" : ` + b + ` }`)
	var r enrollMsgResponse
	e.must(e.do("POST", msgPath(id), tokA, loose), 200, &r)
	if r.N != 1 {
		t.Errorf("non-canonical retransmission got n %d", r.N)
	}
	wantCode(t, e.postMsg(id, tokA, msgChal, chalFor(t, id, v, A)), 409, "conflict", "a different chal")
	wantCode(t, e.postMsg(id, tokA, msgDeliver, deliver), 409, "conflict", "deliver before open")

	e.mustMsg(id, tokD, msgOpen, d.open, 2)
	e.mustMsg(id, tokD, msgOpen, d.open, 2)
	other := makeD(t, "laptop").open
	wantCode(t, e.postMsg(id, tokD, msgOpen, other), 409, "conflict", "a different open")

	e.mustMsg(id, tokA, msgDeliver, deliver, 3)
	e.mustMsg(id, tokA, msgDeliver, deliver, 3)
	wantCode(t, e.postMsg(id, tokA, msgDeliver, deliverFor(t, d, []byte("other"))), 409, "conflict", "a different deliver")
	e.mustMsg(id, tokA, msgChal, chal, 1)

	_, all := e.getMsgs(id, tokA, "")
	if len(all.Messages) != 3 {
		t.Fatalf("%d messages stored, want 3", len(all.Messages))
	}
	for i, want := range []any{chal, d.open, deliver} {
		if !bytes.Equal(all.Messages[i].Body, rawJSON(t, want)) {
			t.Errorf("message %d is %s", i+1, all.Messages[i].Body)
		}
	}
}

// A mailbox lives MailboxTTL from creation, and messages do not extend
// it. After that it is gone for every party, and the janitor deletes it.
func TestEnrollExpiry(t *testing.T) {
	e := newEnv(t)
	v, tokA, d := enrollSetup(t, e)
	A := v.dev(0)
	id, tokD := d.mb.EnrollID, d.mb.MailboxToken
	e.clock.advance(5 * time.Minute)
	e.mustMsg(id, tokA, msgChal, chalFor(t, id, v, A), 1)
	e.clock.advance(5*time.Minute - time.Second)
	e.mustMsg(id, tokD, msgOpen, d.open, 2)
	wantStatus(t, e.claim(tokA, d.mb.RoutingCode), 200, "claim just before expiry")

	e.clock.advance(time.Second)
	tokA = e.session(v, A) // the first session may be close to its own expiry
	wantCode(t, e.claim(tokA, d.mb.RoutingCode), 404, "not_found", "claim after expiry")
	r, _ := e.getMsgs(id, tokA, "")
	wantCode(t, r, 404, "not_found", "A reads after expiry")
	wantCode(t, e.postMsg(id, tokA, msgDeliver, deliverFor(t, d, []byte("x"))), 404, "not_found", "A posts after expiry")
	r, _ = e.getMsgs(id, tokD, "")
	wantCode(t, r, 401, "unauthorized", "D reads after expiry")

	if err := e.st.Update(context.Background(), func(tx Tx) error { return tx.DeleteExpired(e.clock.now()) }); err != nil {
		t.Fatal(err)
	}
	e.view(func(tx Tx) error {
		if _, err := tx.Mailbox(id); !errors.Is(err, ErrNotFound) {
			t.Errorf("expired mailbox still stored: %v", err)
		}
		if msgs, err := tx.MailboxMessages(id, 0); err != nil || len(msgs) != 0 {
			t.Errorf("expired mailbox's messages still stored: %d, %v", len(msgs), err)
		}
		return nil
	})
}

// Live mailboxes are limited per IP and per process; expired ones stop
// counting (R8).
func TestEnrollMailboxLimits(t *testing.T) {
	e := newEnv(t, withProxies("127.0.0.0/8", "::1/128"), withLimits(func(l *Limits) { l.MailboxesPerProcess = 5 }))
	from := func(ip string) []string { return []string{"X-Forwarded-For", ip} }
	commit := makeD(t, "x").commit
	for range 3 {
		wantStatus(t, e.createMailbox(commit, from("192.0.2.1")...), 200, "mailbox within the IP limit")
	}
	wantCode(t, e.createMailbox(commit, from("192.0.2.1")...), 429, "rate_limited", "a fourth mailbox from one IP")
	wantStatus(t, e.createMailbox(commit, from("192.0.2.2")...), 200, "another IP")
	wantStatus(t, e.createMailbox(commit, from("192.0.2.3")...), 200, "a third IP, the fifth mailbox")
	wantCode(t, e.createMailbox(commit, from("192.0.2.4")...), 429, "busy", "a sixth mailbox in the process")
	e.clock.advance(MailboxTTL)
	wantStatus(t, e.createMailbox(commit, from("192.0.2.1")...), 200, "after the others expired")
	e.view(func(tx Tx) error {
		if n, err := tx.CountMailboxes(time.Time{}, nil); err != nil || n != 1 {
			t.Errorf("%d mailboxes stored after creation cleaned up the expired ones (%v), want 1", n, err)
		}
		return nil
	})
}

// Message count and bytes per mailbox are bounded (R8), and the outer and
// inner schemas are closed.
func TestEnrollMessageLimitsAndSchemas(t *testing.T) {
	t.Run("bytes", func(t *testing.T) {
		e := newEnv(t, withLimits(func(l *Limits) { l.MailboxBytes = 8 << 10 }))
		v, tokA, d := enrollSetup(t, e)
		id := d.mb.EnrollID
		e.mustMsg(id, tokA, msgChal, chalFor(t, id, v, v.dev(0)), 1)
		e.mustMsg(id, d.mb.MailboxToken, msgOpen, d.open, 2) // about 1.7 KiB of X-Wing key
		big := deliverFor(t, d, bytes.Repeat([]byte("x"), 4<<10))
		r := e.postMsg(id, tokA, msgDeliver, big)
		wantCode(t, r, 413, "too_large", "a delivery past the mailbox bytes")
		if !strings.Contains(string(r.body), errMailboxFull.msg) {
			t.Errorf("refused by %s, want the mailbox limit", r.body)
		}
		huge := deliverFor(t, d, bytes.Repeat([]byte("x"), 12<<10))
		r = e.postMsg(id, tokA, msgDeliver, huge)
		wantCode(t, r, 413, "too_large", "a delivery past the mailbox bytes on its own")
		if !strings.Contains(string(r.body), errMailboxFull.msg) {
			t.Errorf("refused by %s, want the mailbox limit", r.body)
		}
		// The request itself meets only the general body limit.
		r = e.do("POST", msgPath(id), tokA, bytes.Repeat([]byte(" "), int(e.srv.lim.MaxBody)+1))
		wantCode(t, r, 413, "too_large", "a request past the route's body limit")
		if !strings.Contains(string(r.body), errTooLarge.msg) {
			t.Errorf("refused by %s, want the body limit", r.body)
		}
		e.mustMsg(id, tokA, msgDeliver, deliverFor(t, d, []byte("small")), 3)
	})
	t.Run("count", func(t *testing.T) {
		e := newEnv(t, withLimits(func(l *Limits) { l.MailboxMessages = 2 }))
		v, tokA, d := enrollSetup(t, e)
		id := d.mb.EnrollID
		e.mustMsg(id, tokA, msgChal, chalFor(t, id, v, v.dev(0)), 1)
		e.mustMsg(id, d.mb.MailboxToken, msgOpen, d.open, 2)
		wantCode(t, e.postMsg(id, tokA, msgDeliver, deliverFor(t, d, []byte("x"))), 413, "too_large", "a third message")
		e.mustMsg(id, d.mb.MailboxToken, msgOpen, d.open, 2) // retransmissions still answer
	})
	t.Run("schemas", func(t *testing.T) {
		e := newEnv(t)
		v, tokA, d := enrollSetup(t, e)
		id := d.mb.EnrollID
		chal := rawJSON(t, chalFor(t, id, v, v.dev(0)))
		for name, body := range map[string]string{
			"unknown outer member": `{"type":"chal","body":` + string(chal) + `,"x":1}`,
			"missing body":         `{"type":"chal"}`,
			"unknown type":         `{"type":"commit","body":` + string(chal) + `}`,
			"body not an object":   `{"type":"chal","body":[1]}`,
			"body a string":        `{"type":"chal","body":"x"}`,
			"chal with extras":     `{"type":"chal","body":` + strings.Replace(string(chal), `{`, `{"extra":1,`, 1) + `}`,
			"chal as open":         `{"type":"open","body":` + string(chal) + `}`,
			"open with a bad key":  `{"type":"open","body":{"v":1,"kem_pk":"AAAA","sig_pk":"AAAA","nD":"AAAA","name":"x"}}`,
			"deliver not HPKE":     `{"type":"deliver","body":{"v":1,"suite":2,"enc":"AAAA","ct":"AAAA"}}`,
			"duplicate member":     `{"type":"chal","type":"chal","body":` + string(chal) + `}`,
		} {
			wantCode(t, e.do("POST", msgPath(id), tokA, []byte(body)), 400, "bad_request", name)
		}
		_, all := e.getMsgs(id, tokA, "")
		if len(all.Messages) != 0 {
			t.Errorf("refused messages were stored: %+v", all)
		}
		for name, commit := range map[string]any{
			"commit v2":          crypto.EnrollCommit{V: 2, C: d.commit.C},
			"commit with extras": map[string]any{"v": 1, "c": d.commit.C, "x": 1},
			"commit not object":  "x",
		} {
			wantCode(t, e.createMailbox(commit), 400, "bad_request", name)
		}
	})
}

// A long-poll that times out answers 200 with an empty list; the query is
// checked (R12).
func TestEnrollLongPollTimeoutShape(t *testing.T) {
	e := newEnv(t)
	v, tokA, d := enrollSetup(t, e)
	id, tokD := d.mb.EnrollID, d.mb.MailboxToken
	for _, tok := range []string{tokD, tokA} {
		start := time.Now()
		r := e.do("GET", msgPath(id)+"?after=0&wait=1", tok, nil)
		if r.status != 200 || string(r.body) != `{"messages":[]}` {
			t.Errorf("timed-out poll: %s", r)
		}
		if time.Since(start) < 900*time.Millisecond {
			t.Errorf("the poll returned after %v, before its wait", time.Since(start))
		}
	}
	e.mustMsg(id, tokA, msgChal, chalFor(t, id, v, v.dev(0)), 1)
	r := e.do("GET", msgPath(id)+"?after=1&wait=0", tokD, nil)
	if r.status != 200 || string(r.body) != `{"messages":[]}` {
		t.Errorf("after the last message: %s", r)
	}
	if r, m := e.getMsgs(id, tokD, "?wait=55"); r.status != 200 || len(m.Messages) != 1 {
		t.Errorf("default after with a message waiting: %s", r)
	}
	for _, q := range []string{"?wait=56", "?wait=-1", "?wait=01", "?after=x", "?after=01", "?after=1&after=2", "?wait=1&wait=1"} {
		r, _ := e.getMsgs(id, tokD, q)
		wantCode(t, r, 400, "bad_request", q)
	}
}

// A's long-poll ends with 401 when a checkpoint ends its session while it
// waits (R2).
func TestEnrollPollEndsWithSession(t *testing.T) {
	e := newEnv(t)
	v, tokA, d := enrollSetup(t, e)
	id := d.mb.EnrollID
	poll := e.startGet(msgPath(id)+"?wait=30", tokA)
	e.mustPost(v, tokA, v.checkpoint(v.dev(0)))
	wantCode(t, waitResp(t, poll), 401, "unauthorized", "A's poll after a checkpoint")
}

// Mailbox creation has its own IP bucket, and claims are limited per IP,
// per account and per approving device, failed attempts included (R14).
func TestEnrollRateLimits(t *testing.T) {
	if r := DefaultRates(); r.EnrollIP != (Rate{10, time.Minute}) || r.Claim != (Rate{60, time.Minute}) {
		t.Errorf("default enroll rates %+v and %+v", r.EnrollIP, r.Claim)
	}
	setup := func(t *testing.T, f func(*Rates)) (*env, *tvault, string, string) {
		rates := *unlimitedRates()
		f(&rates)
		e := newEnv(t, withRates(rates))
		v := newVault(t, "a@example.com")
		e.publish(v)
		B, wb := v.bootstrap("dev-b")
		e.mustPost(v, e.login(v), wb)
		return e, v, e.session(v, v.dev(0)), e.session(v, B)
	}
	t.Run("create per IP", func(t *testing.T) {
		rates := *unlimitedRates()
		rates.EnrollIP = Rate{2, time.Minute}
		e := newEnv(t, withRates(rates))
		commit := makeD(t, "x").commit
		wantStatus(t, e.createMailbox(commit), 200, "first")
		wantStatus(t, e.createMailbox(commit), 200, "second")
		wantCode(t, e.createMailbox(commit), 429, "rate_limited", "third within the minute")
	})
	t.Run("claim per device", func(t *testing.T) {
		e, _, tokA, tokB := setup(t, func(r *Rates) { r.Claim = Rate{3, time.Minute} })
		d := makeD(t, "x")
		e.mailbox(d)
		for range 3 {
			wantCode(t, e.claim(tokA, "0000000000"), 404, "not_found", "a wrong guess")
		}
		wantCode(t, e.claim(tokA, d.mb.RoutingCode), 429, "rate_limited", "the right code after three failures")
		wantStatus(t, e.claim(tokB, d.mb.RoutingCode), 200, "another device of the account")
	})
	t.Run("claim per account", func(t *testing.T) {
		e, _, tokA, tokB := setup(t, func(r *Rates) { r.Account = Rate{2, time.Minute} })
		d := makeD(t, "x")
		e.mailbox(d)
		wantCode(t, e.claim(tokA, "0000000000"), 404, "not_found", "a wrong guess")
		wantCode(t, e.claim(tokA, "ZZZZZZZZZZ"), 404, "not_found", "another wrong guess")
		wantCode(t, e.claim(tokB, d.mb.RoutingCode), 429, "rate_limited", "another device of the same account")
	})
	t.Run("claim per IP", func(t *testing.T) {
		// Buckets are per route, so setup's two requests on each other
		// route fit too.
		e, _, tokA, tokB := setup(t, func(r *Rates) { r.IP = Rate{2, time.Minute} })
		d := makeD(t, "x")
		e.mailbox(d)
		wantCode(t, e.claim(tokA, "0000000000"), 404, "not_found", "a wrong guess")
		wantCode(t, e.claim("", "0000000000"), 401, "unauthorized", "an unauthenticated guess")
		wantCode(t, e.claim(tokB, d.mb.RoutingCode), 429, "rate_limited", "a third claim from the IP")
	})
}

// The mailbox's byte limit counts canonical bodies, not request bytes: a
// valid chal padded with 70 KiB of whitespace, past the whole 64 KiB
// budget, is stored, and an identical retransmission padded differently
// gets its n (R8, R12).
func TestEnrollBudgetCountsCanonicalBodies(t *testing.T) {
	e := newEnv(t)
	v, tokA, d := enrollSetup(t, e)
	id := d.mb.EnrollID
	chal := string(rawJSON(t, chalFor(t, id, v, v.dev(0))))
	padded := func(outer, inner int) []byte {
		ws := func(n int) string { return strings.Repeat(" \n\t\r", n/4) }
		return []byte(`{"type":"chal",` + ws(outer) + `"body":{` + ws(inner) + chal[1:] + ws(outer) + `}`)
	}
	first := padded(20<<10, 30<<10) // 70 KiB of whitespace
	if len(first)-len(chal) < 70<<10 || e.srv.lim.MailboxBytes != 64<<10 {
		t.Fatalf("a %d-byte request for a %d-byte budget", len(first), e.srv.lim.MailboxBytes)
	}
	var r enrollMsgResponse
	e.must(e.do("POST", msgPath(id), tokA, first), 200, &r)
	if r.N != 1 {
		t.Errorf("padded chal got n %d", r.N)
	}
	e.must(e.do("POST", msgPath(id), tokA, padded(40<<10, 10<<10)), 200, &r)
	if r.N != 1 {
		t.Errorf("padded retransmission got n %d", r.N)
	}
	_, all := e.getMsgs(id, tokA, "")
	if len(all.Messages) != 1 || string(all.Messages[0].Body) != chal {
		t.Errorf("stored %+v, want the canonical chal once", all)
	}
	e.mustMsg(id, d.mb.MailboxToken, msgOpen, d.open, 2)
}

// Once a mailbox is claimed, D's requests are charged to the claim's
// account: its long-polls count toward the account's cap together with
// A's, and its requests spend the account's buckets. A poll D started
// before the claim keeps counting under the mailbox (R8, R14).
func TestEnrollClaimedMailboxChargesAccount(t *testing.T) {
	t.Run("long-polls", func(t *testing.T) {
		if n := DefaultLimits().PollsPerAccount; n != 16 {
			t.Fatalf("default polls per account %d", n)
		}
		e := newEnv(t, withLimits(func(l *Limits) { l.PollsPerCredential, l.PollsPerIP = 64, 64 }))
		v := newVault(t, "a@example.com")
		e.publish(v)
		A := v.dev(0)
		tokA := e.session(v, A)
		d := makeD(t, "laptop")
		e.mailbox(d)
		id, tokD := d.mb.EnrollID, d.mb.MailboxToken
		path := msgPath(id) + "?wait=30"
		counts := func() (acct, mailbox int) {
			e.srv.polls.mu.Lock()
			defer e.srv.polls.mu.Unlock()
			return e.srv.polls.acct[v.accountID().String()], e.srv.polls.acct["enroll:"+id.String()]
		}

		polls := []<-chan resp{e.startGet(path, tokD)}
		e.must(e.claim(tokA, d.mb.RoutingCode), 200, nil)
		for range 8 {
			polls = append(polls, e.startGet(path, tokA), e.startGet(path, tokD))
		}
		if acct, mailbox := counts(); acct != 16 || mailbox != 1 {
			t.Errorf("%d polls under the account and %d under the mailbox, want 16 and 1", acct, mailbox)
		}
		wantCode(t, e.do("GET", path, tokD, nil), 429, "busy", "D's poll past the account's cap")
		wantCode(t, e.do("GET", path, tokA, nil), 429, "busy", "A's poll past the account's cap")
		r, _ := e.readLog(v, tokA, "?after="+itoa(v.head().Seq)+"&wait=30")
		wantCode(t, r, 429, "busy", "a log poll past the account's cap")

		// The chal wakes them all.
		e.mustMsg(id, tokA, msgChal, chalFor(t, id, v, A), 1)
		for _, p := range polls {
			wantStatus(t, waitResp(t, p), 200, "a woken poll")
		}
	})
	t.Run("buckets", func(t *testing.T) {
		rates := *unlimitedRates()
		rates.Account = Rate{3, time.Minute}
		e := newEnv(t, withRates(rates))
		v := newVault(t, "a@example.com")
		e.publish(v)
		A := v.dev(0)
		tokA := e.session(v, A)
		d := makeD(t, "laptop")
		e.mailbox(d)
		id, tokD := d.mb.EnrollID, d.mb.MailboxToken
		// Unclaimed, the mailbox has no account to charge.
		for range 5 {
			r, _ := e.getMsgs(id, tokD, "")
			wantStatus(t, r, 200, "D reads its unclaimed mailbox")
		}
		e.must(e.claim(tokA, d.mb.RoutingCode), 200, nil)

		// Each route's account bucket is shared by A and D.
		deliver := deliverFor(t, d, []byte("x"))
		e.mustMsg(id, tokA, msgChal, chalFor(t, id, v, A), 1)
		e.mustMsg(id, tokD, msgOpen, d.open, 2)
		e.mustMsg(id, tokA, msgDeliver, deliver, 3)
		wantCode(t, e.postMsg(id, tokA, msgDeliver, deliver), 429, "rate_limited", "A's post after three on the account")
		wantCode(t, e.postMsg(id, tokD, msgOpen, d.open), 429, "rate_limited", "D's post after three on the account")
		for range 3 {
			r, _ := e.getMsgs(id, tokD, "")
			wantStatus(t, r, 200, "D reads the claimed mailbox")
		}
		r, _ := e.getMsgs(id, tokA, "")
		wantCode(t, r, 429, "rate_limited", "A's read after D's three")
		r, _ = e.getMsgs(id, tokD, "")
		wantCode(t, r, 429, "rate_limited", "D's fourth read")
	})
}

// A's response is admitted by a fresh authentication under the account's
// admission lock: a session that a checkpoint ends after the messages were
// read gets a 401 with nothing (R2).
func TestEnrollGetAdmissionRechecksAuth(t *testing.T) {
	for _, mode := range []string{"read", "long-poll"} {
		t.Run(mode, func(t *testing.T) {
			p := newPauser()
			e := newEnv(t, withHooks(func(s *Server) { s.hooks.enrollSend = p.hook }))
			v, tokA, d := enrollSetup(t, e)
			A := v.dev(0)
			id := d.mb.EnrollID
			e.mustMsg(id, tokA, msgChal, chalFor(t, id, v, A), 1)
			writer := e.session(v, A)
			var got <-chan resp
			if mode == "read" {
				p.armed.Store(true)
				ch := make(chan resp, 1)
				go func() { ch <- e.do("GET", msgPath(id), tokA, nil) }()
				got = ch
			} else {
				got = e.startGet(msgPath(id)+"?after=1&wait=30", tokA)
				p.armed.Store(true)
				// The open wakes the poll, which reads it.
				e.mustMsg(id, d.mb.MailboxToken, msgOpen, d.open, 2)
			}
			p.waitPaused(t)
			e.mustPost(v, writer, v.checkpoint(A))
			close(p.resumed)
			r := waitResp(t, got)
			wantCode(t, r, 401, "unauthorized", "messages read before the checkpoint")
			if strings.Contains(string(r.body), "messages") {
				t.Errorf("the 401 carries data: %s", r.body)
			}
		})
	}
}

// Concurrent claims of one code bind it to exactly one device; every other
// claimant gets already_claimed, and the binding is the winner's (R7).
func TestEnrollCompetingClaims(t *testing.T) {
	e := newEnv(t, withLimits(func(l *Limits) { l.MailboxesPerIP = 100 }))
	v := newVault(t, "a@example.com")
	e.publish(v)
	B, wb := v.bootstrap("dev-b")
	e.mustPost(v, e.login(v), wb)
	other := newVault(t, "b@example.com")
	e.publish(other)
	type claimant struct {
		acct, dev model.ID
		tok       string
	}
	cs := []claimant{
		{v.accountID(), v.dev(0), e.session(v, v.dev(0))},
		{v.accountID(), B, e.session(v, B)},
		{other.accountID(), other.dev(0), e.session(other, other.dev(0))},
	}
	for round := range 8 {
		d := makeD(t, "x")
		e.mailbox(d)
		start := make(chan struct{})
		rs := make([]resp, len(cs))
		var wg sync.WaitGroup
		for i, c := range cs {
			wg.Add(1)
			go func() {
				defer wg.Done()
				<-start
				rs[i] = e.claim(c.tok, d.mb.RoutingCode)
			}()
		}
		close(start)
		wg.Wait()
		winner := -1
		for i, r := range rs {
			if r.status != 200 {
				wantCode(t, r, 409, "already_claimed", "a losing claim")
				continue
			}
			if winner >= 0 {
				t.Errorf("round %d: claimants %d and %d both won", round, winner, i)
			}
			winner = i
		}
		if winner < 0 {
			t.Fatalf("round %d: no claim won: %v", round, rs)
		}
		e.view(func(tx Tx) error {
			m, err := tx.Mailbox(d.mb.EnrollID)
			if err != nil || m.AccountID == nil || *m.AccountID != cs[winner].acct || *m.DeviceID != cs[winner].dev {
				t.Errorf("round %d: binding %+v (%v), want claimant %d", round, m, err, winner)
			}
			return nil
		})
		wantStatus(t, e.claim(cs[winner].tok, d.mb.RoutingCode), 200, "the winner's repeat")
	}
}

// A long-poll ends when its mailbox expires, or for A when its session
// does, instead of waiting out its wait; the read then refuses: D gets
// 401, since its token died with the mailbox, and A 404 for the mailbox or
// 401 for its session (R12).
func TestEnrollPollEndsAtExpiry(t *testing.T) {
	// within checks that a poll of wait=55 ended long before its wait.
	within := func(t *testing.T, poll <-chan resp) resp {
		t.Helper()
		start := time.Now()
		r := waitResp(t, poll)
		if d := time.Since(start); d > 10*time.Second {
			t.Errorf("the poll ended after %v", d)
		}
		return r
	}
	t.Run("mailbox", func(t *testing.T) {
		e := newEnv(t)
		_, tokA, d := enrollSetup(t, e)
		id := d.mb.EnrollID
		e.clock.advance(MailboxTTL - time.Second) // the session outlives the mailbox
		pollD := e.startGet(msgPath(id)+"?wait=55", d.mb.MailboxToken)
		pollA := e.startGet(msgPath(id)+"?wait=55", tokA)
		e.clock.advance(time.Second)
		wantCode(t, within(t, pollD), 401, "unauthorized", "D's poll when the mailbox expires")
		wantCode(t, within(t, pollA), 404, "not_found", "A's poll when the mailbox expires")
	})
	t.Run("session", func(t *testing.T) {
		e := newEnv(t)
		v := newVault(t, "a@example.com")
		e.publish(v)
		tokA := e.session(v, v.dev(0))
		// The mailbox outlives the session by a minute.
		e.clock.advance(SessionTTL - MailboxTTL + time.Minute)
		d := makeD(t, "laptop")
		e.mailbox(d)
		e.must(e.claim(tokA, d.mb.RoutingCode), 200, nil)
		e.clock.advance(MailboxTTL - time.Minute - time.Second)
		id := d.mb.EnrollID
		poll := e.startGet(msgPath(id)+"?wait=55", tokA)
		e.clock.advance(time.Second)
		wantCode(t, within(t, poll), 401, "unauthorized", "A's poll when its session expires")
		r, _ := e.getMsgs(id, d.mb.MailboxToken, "")
		wantStatus(t, r, 200, "D reads the live mailbox")
	})
}
