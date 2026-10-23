package syncclient

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"time"

	"github.com/dalyem/hopkey/internal/canonjson"
	"github.com/dalyem/hopkey/internal/crypto"
	"github.com/dalyem/hopkey/internal/model"
)

// The enrollment relay's transport (R7, R12): mailbox creation, the claim,
// and message exchange. The §7 protocol and every check it needs belong
// to the caller: the relay checks schemas, roles and ordering, never the
// cryptography.

// Relay message types (R12). The server numbers them 1, 2 and 3.
const (
	MsgChal    = "chal"    // A → D
	MsgOpen    = "open"    // D → A
	MsgDeliver = "deliver" // A → D
)

// Mailbox is a new device's mailbox (D's side).
type Mailbox struct {
	EnrollID    model.ID
	RoutingCode string // 10 Crockford symbols, for the user to carry to A
	// Token is D's bearer credential for the mailbox. It is a secret:
	// never log or print it.
	Token string
}

// String describes the mailbox without its token.
func (m Mailbox) String() string {
	return "syncclient.Mailbox{" + m.EnrollID.String() + "}"
}

// GoString describes the mailbox without its token, for %#v.
func (m Mailbox) GoString() string { return m.String() }

type enrollRequest struct {
	Commit crypto.EnrollCommit `json:"commit"`
}

type enrollResponse struct {
	EnrollID     model.ID `json:"enroll_id"`
	MailboxToken string   `json:"mailbox_token"`
	RoutingCode  string   `json:"routing_code"`
}

// CreateMailbox is POST /v1/enroll {commit}: D's mailbox, live for 10
// minutes.
func (c *Client) CreateMailbox(ctx context.Context, commit crypto.EnrollCommit) (*Mailbox, error) {
	var resp enrollResponse
	if err := c.do(ctx, &call{method: http.MethodPost, path: "/v1/enroll", body: enrollRequest{commit}}, &resp); err != nil {
		return nil, err
	}
	if resp.EnrollID.IsZero() || resp.MailboxToken == "" || len(resp.RoutingCode) != 10 {
		return nil, fmt.Errorf("%w: enroll", ErrMalformedResponse)
	}
	return &Mailbox{EnrollID: resp.EnrollID, RoutingCode: resp.RoutingCode, Token: resp.MailboxToken}, nil
}

type claimRequest struct {
	RoutingCode string `json:"routing_code"`
}

type claimResponse struct {
	Commit   canonjson.Raw `json:"commit"`
	EnrollID model.ID      `json:"enroll_id"`
}

// Claim is what claiming a mailbox returns to A: the mailbox and D's
// commit.
type Claim struct {
	EnrollID model.ID
	Commit   crypto.EnrollCommit
}

// Claim is POST /v1/enroll/claim {routing_code} under dev's session: it
// binds the mailbox to dev's account and device (R7). Repeating it from
// the same device returns the same claim; a mailbox another device claimed
// is an *APIError matching ErrAlreadyClaimed.
func (c *Client) Claim(ctx context.Context, dev Device, routingCode string) (Claim, error) {
	var resp claimResponse
	err := c.withSession(ctx, dev, func(tok string) error {
		return c.do(ctx, &call{
			method: http.MethodPost, path: "/v1/enroll/claim", token: tok,
			body: claimRequest{RoutingCode: routingCode},
		}, &resp)
	})
	if err != nil {
		return Claim{}, err
	}
	cl := Claim{EnrollID: resp.EnrollID}
	if err := crypto.ParseEnrollMessage(resp.Commit, &cl.Commit); err != nil {
		return Claim{}, fmt.Errorf("%w: commit: %w", ErrMalformedResponse, err)
	}
	return cl, nil
}

// Message is one relay message.
type Message struct {
	N    uint64
	Type string
	Body canonjson.Raw
}

type msgRequest struct {
	Body canonjson.Raw `json:"body"`
	Type string        `json:"type"`
}

type msgResponse struct {
	N uint64 `json:"n,string"`
}

type msgJSON struct {
	Body canonjson.Raw `json:"body"`
	N    uint64        `json:"n,string"`
	Type string        `json:"type"`
}

type msgsResponse struct {
	Messages []msgJSON `json:"messages"`
}

// Relay is one party's access to a mailbox: D's by the mailbox token, or
// A's by its device session.
type Relay struct {
	c        *Client
	enrollID model.ID
	token    string  // D
	dev      *Device // A
}

// DeviceRelay is D's access to its mailbox.
func (c *Client) DeviceRelay(m *Mailbox) *Relay {
	return &Relay{c: c, enrollID: m.EnrollID, token: m.Token}
}

// ApproverRelay is A's access to a mailbox it claimed, under dev's
// sessions.
func (c *Client) ApproverRelay(enrollID model.ID, dev Device) *Relay {
	return &Relay{c: c, enrollID: enrollID, dev: &dev}
}

// as runs f with the party's credential.
func (r *Relay) as(ctx context.Context, f func(token string) error) error {
	if r.dev != nil {
		return r.c.withSession(ctx, *r.dev, f)
	}
	return f(r.token)
}

func (r *Relay) path() string { return "/v1/enroll/" + url.PathEscape(r.enrollID.String()) + "/msg" }

// Post is POST /v1/enroll/{id}/msg {type, body}: it returns the message's
// number. body is encoded with canonjson and must be a JSON object. An
// identical retransmission returns the same number; a different message
// for a filled slot, or one out of order, is an *APIError matching
// ErrConflict.
func (r *Relay) Post(ctx context.Context, typ string, body any) (uint64, error) {
	b, err := canonjson.Marshal(body)
	if err != nil {
		return 0, err
	}
	if len(b) == 0 || b[0] != '{' {
		return 0, errors.New("syncclient: a relay message body must be an object")
	}
	var resp msgResponse
	err = r.as(ctx, func(tok string) error {
		return r.c.do(ctx, &call{
			method: http.MethodPost, path: r.path(), token: tok,
			body: msgRequest{Body: b, Type: typ},
		}, &resp)
	})
	return resp.N, err
}

// Messages is GET /v1/enroll/{id}/msg?after=after&wait=wait: the messages
// numbered past after, in ascending order. With none, it waits up to wait
// (whole seconds, at most MaxWait) for one, and returns none at the end.
func (r *Relay) Messages(ctx context.Context, after uint64, wait time.Duration) ([]Message, error) {
	wait = min(max(wait, 0), MaxWait).Truncate(time.Second)
	q := url.Values{"after": {strconv.FormatUint(after, 10)}}
	if wait > 0 {
		q.Set("wait", strconv.FormatInt(int64(wait/time.Second), 10))
	}
	var resp msgsResponse
	err := r.as(ctx, func(tok string) error {
		return r.c.do(ctx, &call{
			method: http.MethodGet, path: r.path(), query: q, token: tok,
			maxResp: maxMailboxResponse, wait: wait,
		}, &resp)
	})
	if err != nil {
		return nil, err
	}
	out := make([]Message, 0, len(resp.Messages))
	last := after
	for _, m := range resp.Messages {
		if m.N <= last {
			return nil, fmt.Errorf("%w: message %d after %d is out of order", ErrMalformedResponse, m.N, last)
		}
		if len(m.Body) == 0 || m.Body[0] != '{' {
			return nil, fmt.Errorf("%w: message %d has no object body", ErrMalformedResponse, m.N)
		}
		out = append(out, Message{N: m.N, Type: m.Type, Body: m.Body})
		last = m.N
	}
	return out, nil
}
