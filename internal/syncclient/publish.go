package syncclient

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"sync"

	"github.com/dalyem/hopkey/internal/canonjson"
	"github.com/dalyem/hopkey/internal/crypto"
	"github.com/dalyem/hopkey/internal/model"
	"github.com/dalyem/hopkey/internal/store"
	"github.com/dalyem/hopkey/internal/vaultlog"
)

// Publisher is store.Publisher: the §4.3 publication of a local vault
// (POST /v1/signup, plan R3) and the reads that resolve it.
type Publisher struct {
	c *Client

	mu    sync.Mutex
	vault model.ID
}

var _ store.Publisher = (*Publisher)(nil)

// Publisher returns a Publisher for the vault vaultID, as
// Store.Publication reports it for a publication being resumed. A zero
// vaultID is learnt from the first Signup.
func (c *Client) Publisher(vaultID model.ID) *Publisher {
	return &Publisher{c: c, vault: vaultID}
}

// vaultID returns the vault, setting it from v when it is not known yet.
func (p *Publisher) vaultID(v model.ID) (model.ID, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.vault.IsZero() {
		p.vault = v
	}
	switch {
	case p.vault.IsZero():
		return model.ID{}, errors.New("syncclient: the publication's vault is not known")
	case !v.IsZero() && v != p.vault:
		return model.ID{}, errors.New("syncclient: the publication is for another vault")
	}
	return p.vault, nil
}

type signupChallengeRequest struct {
	Email            string `json:"email"`
	RegistrationCode string `json:"registration_code"`
}

type signupRequest struct {
	Challenge        []byte          `json:"challenge"`
	Email            string          `json:"email"`
	PopSig           []byte          `json:"pop_sig"`
	RegistrationCode string          `json:"registration_code"`
	Wires            []canonjson.Raw `json:"wires"`
}

// Signup is store.Publisher.Signup: POST /v1/signup/challenge, req.Prove
// over this server's origin, then POST /v1/signup with the whole upload.
// The publication must be journaled for this server. A conflict with an
// existing registration is an *APIError matching ErrRegistrationConflict.
func (p *Publisher) Signup(ctx context.Context, req *store.SignupRequest) (vaultlog.Head, error) {
	if o, err := crypto.CanonicalOrigin(req.Server); err != nil || o != p.c.origin {
		return vaultlog.Head{}, fmt.Errorf("syncclient: the publication is for %q, not %s", req.Server, p.c.origin)
	}
	if _, err := p.vaultID(req.VaultID); err != nil {
		return vaultlog.Head{}, err
	}
	wires := make([]canonjson.Raw, len(req.Wires))
	for i, w := range req.Wires {
		b, err := w.Marshal()
		if err != nil {
			return vaultlog.Head{}, err
		}
		wires[i] = b
	}
	var ch challengeResponse
	err := p.c.do(ctx, &call{
		method: http.MethodPost, path: "/v1/signup/challenge",
		body: signupChallengeRequest{Email: req.Email, RegistrationCode: req.RegistrationCode},
	}, &ch)
	if err != nil {
		return vaultlog.Head{}, err
	}
	if len(ch.Challenge) != crypto.ChallengeSize {
		return vaultlog.Head{}, fmt.Errorf("%w: a %d-byte challenge", ErrMalformedResponse, len(ch.Challenge))
	}
	pop, err := req.Prove(p.c.origin, ch.Challenge)
	if err != nil {
		return vaultlog.Head{}, err
	}
	var head vaultlog.Head
	err = p.c.do(ctx, &call{
		method: http.MethodPost, path: "/v1/signup", maxBody: maxSignupBody,
		body: signupRequest{
			Challenge: ch.Challenge, Email: req.Email, PopSig: pop,
			RegistrationCode: req.RegistrationCode, Wires: wires,
		},
	}, &head)
	return head, err
}

// absent maps what a publication that never committed looks like: the
// device has no session to get (its session challenge is refused), or the
// session's vault has no such entry.
func absent(err error) error {
	if errors.Is(err, ErrSessionEnded) || errors.Is(err, ErrNotFound) {
		return fmt.Errorf("%w: %w", store.ErrPublicationAbsent, err)
	}
	return err
}

// EntryAt is store.Publisher.EntryAt, with device authentication. An
// error matches store.ErrPublicationAbsent when the server has no vault
// for the device or no entry at seq.
func (p *Publisher) EntryAt(ctx context.Context, auth store.DeviceAuth, seq uint64) (store.Committed, error) {
	vault, err := p.vaultID(model.ID{})
	if err != nil {
		return store.Committed{}, err
	}
	var c store.Committed
	err = p.c.withSession(ctx, deviceOf(auth), func(tok string) (err error) {
		c, err = p.c.entryAt(ctx, tok, vault, seq)
		return err
	})
	return c, absent(err)
}

// Since is store.Publisher.Since: Remote.Since with device
// authentication.
func (p *Publisher) Since(ctx context.Context, auth store.DeviceAuth, after uint64) (entries []store.Committed, head vaultlog.Head, err error) {
	vault, err := p.vaultID(model.ID{})
	if err != nil {
		return nil, vaultlog.Head{}, err
	}
	err = p.c.withSession(ctx, deviceOf(auth), func(tok string) (err error) {
		entries, head, err = p.c.since(ctx, tok, vault, after, 0)
		return err
	})
	return entries, head, err
}
