package syncclient

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/dalyem/hopkey/internal/crypto"
	"github.com/dalyem/hopkey/internal/model"
	"github.com/dalyem/hopkey/internal/store"
)

// RefreshMargin is how long before its expiry a cached session is
// replaced.
const RefreshMargin = time.Minute

// sessionTTL is the server's session lifetime (§9). A session is never
// cached for longer, whatever expires_at says.
const sessionTTL = 15 * time.Minute

// Signer signs §9 device-auth objects as one device: Sig(dev_sig,
// "hopkey/v1/device-auth", {v, origin, account_id, device_id, operation,
// challenge}). store.DeviceAuth implements it, so the device key stays in
// the store.
type Signer interface {
	Sign(origin, operation string, challenge []byte) ([]byte, error)
}

// Device is a device the client authenticates as. Signer is called once
// for each signature the client needs, and the Signer it returns is
// dropped after that one call: the client never keeps a signer, let alone
// a key, between authentications.
type Device struct {
	AccountID model.ID
	DeviceID  model.ID
	Signer    func() (Signer, error)
}

// StoreDevice is the Device of a store's DeviceAuth method
// (Store.DeviceAuth), for the sync engine's Remote: each authentication
// asks the store for a fresh signer, so a lock (or anything else that ends
// the store's signer) ends the client's ability to authenticate too.
func StoreDevice(auth func() (store.DeviceAuth, error)) (Device, error) {
	a, err := auth()
	if err != nil {
		return Device{}, err
	}
	accountID, deviceID := a.AccountID, a.DeviceID
	return Device{AccountID: accountID, DeviceID: deviceID, Signer: func() (Signer, error) {
		a, err := auth()
		if err != nil {
			return nil, err
		}
		if a.AccountID != accountID || a.DeviceID != deviceID {
			return nil, errors.New("syncclient: the store's device changed")
		}
		return a, nil
	}}, nil
}

// deviceOf is the Device of one store.DeviceAuth, as the store hands one
// to each Publisher and Retirer call.
func deviceOf(a store.DeviceAuth) Device {
	return Device{AccountID: a.AccountID, DeviceID: a.DeviceID, Signer: func() (Signer, error) { return a, nil }}
}

// sign has the device sign one device-auth object for this server.
func (c *Client) sign(dev Device, operation string, challenge []byte) ([]byte, error) {
	if dev.Signer == nil {
		return nil, store.ErrAuthClosed
	}
	s, err := dev.Signer()
	if err != nil {
		return nil, err
	}
	return s.Sign(c.origin, operation, challenge)
}

type sessionKey struct{ account, device model.ID }

// session is one device's cached session. lock is held, as a one-slot
// channel so a waiter can give up with its context, while the token is
// read or replaced.
type session struct {
	lock    chan struct{}
	token   string
	expires time.Time // by the client's clock
}

func (c *Client) session(dev Device) *session {
	c.mu.Lock()
	defer c.mu.Unlock()
	k := sessionKey{dev.AccountID, dev.DeviceID}
	s := c.sessions[k]
	if s == nil {
		s = &session{lock: make(chan struct{}, 1)}
		c.sessions[k] = s
	}
	return s
}

func (s *session) acquire(ctx context.Context) error {
	select {
	case s.lock <- struct{}{}:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (s *session) release() { <-s.lock }

// sessionToken returns the device's cached session token while it has at
// least RefreshMargin left, and is not stale (the token a request was just
// refused with); otherwise it authenticates for a new one. force always
// authenticates.
func (c *Client) sessionToken(ctx context.Context, dev Device, stale string, force bool) (string, error) {
	s := c.session(dev)
	if err := s.acquire(ctx); err != nil {
		return "", err
	}
	defer s.release()
	if !force && s.token != "" && s.token != stale && c.now().Before(s.expires.Add(-RefreshMargin)) {
		return s.token, nil
	}
	s.token = ""
	tok, exp, err := c.authenticate(ctx, dev)
	if err != nil {
		return "", err
	}
	s.token, s.expires = tok, exp
	return tok, nil
}

// dropSession forgets the device's session if it is still tok. When
// another call holds the session it is replacing it already.
func (c *Client) dropSession(dev Device, tok string) {
	s := c.session(dev)
	select {
	case s.lock <- struct{}{}:
	default:
		return
	}
	defer s.release()
	if s.token == tok {
		s.token = ""
	}
}

// withSession runs f with the device's session token. On a 401 it
// authenticates again, once, and runs f again: a session the server ended
// while the device is still active (a checkpoint, an expiry) is replaced
// transparently. A refused session challenge, or a 401 for the session
// just issued, means the server ended this device's sessions: the error
// matches ErrSessionEnded.
func (c *Client) withSession(ctx context.Context, dev Device, f func(token string) error) error {
	tok, err := c.sessionToken(ctx, dev, "", false)
	if err != nil {
		return err
	}
	err = f(tok)
	if !errors.Is(err, ErrUnauthorized) {
		return err
	}
	if tok, err = c.sessionToken(ctx, dev, tok, false); err != nil {
		return err
	}
	err = f(tok)
	if errors.Is(err, ErrUnauthorized) {
		c.dropSession(dev, tok)
		return fmt.Errorf("%w: %w", ErrSessionEnded, err)
	}
	return err
}

type challengeRequest struct {
	AccountID model.ID `json:"account_id"`
	DeviceID  model.ID `json:"device_id"`
	Operation string   `json:"operation"`
}

type challengeResponse struct {
	Challenge []byte `json:"challenge"`
}

// challenge is POST /v1/auth/challenge for the device and operation.
func (c *Client) challenge(ctx context.Context, dev Device, operation string) ([]byte, error) {
	var resp challengeResponse
	err := c.do(ctx, &call{
		method: http.MethodPost, path: "/v1/auth/challenge",
		body: challengeRequest{AccountID: dev.AccountID, DeviceID: dev.DeviceID, Operation: operation},
	}, &resp)
	if err != nil {
		return nil, err
	}
	if len(resp.Challenge) != crypto.ChallengeSize {
		return nil, fmt.Errorf("%w: a %d-byte challenge", ErrMalformedResponse, len(resp.Challenge))
	}
	return resp.Challenge, nil
}

type sessionRequest struct {
	AccountID model.ID `json:"account_id"`
	DeviceID  model.ID `json:"device_id"`
	Challenge []byte   `json:"challenge"`
	Sig       []byte   `json:"sig"`
}

type sessionResponse struct {
	AccessToken string          `json:"access_token"`
	ExpiresAt   model.Timestamp `json:"expires_at"`
}

// authenticate gets a new session (§9): a "session" challenge, the device's
// signature over the device-auth object, and POST /v1/auth/session. A
// refused challenge means the device is not active: ErrSessionEnded. A
// refused session (the device left between the two calls, say) is tried
// once more with a fresh challenge, which then tells. It returns the token
// and its expiry by the client's clock.
func (c *Client) authenticate(ctx context.Context, dev Device) (string, time.Time, error) {
	for attempt := 0; ; attempt++ {
		ch, err := c.challenge(ctx, dev, crypto.OperationSession)
		if errors.Is(err, ErrUnauthorized) {
			return "", time.Time{}, fmt.Errorf("%w: %w", ErrSessionEnded, err)
		}
		if err != nil {
			return "", time.Time{}, err
		}
		sig, err := c.sign(dev, crypto.OperationSession, ch)
		if err != nil {
			return "", time.Time{}, err
		}
		sent := c.now()
		r, err := c.exchange(ctx, &call{
			method: http.MethodPost, path: "/v1/auth/session",
			body: sessionRequest{AccountID: dev.AccountID, DeviceID: dev.DeviceID, Challenge: ch, Sig: sig},
		})
		if err != nil {
			return "", time.Time{}, err
		}
		var resp sessionResponse
		err = r.decode(&resp)
		if errors.Is(err, ErrUnauthorized) && attempt == 0 {
			continue
		}
		if err != nil {
			return "", time.Time{}, err
		}
		if resp.AccessToken == "" {
			return "", time.Time{}, fmt.Errorf("%w: an empty access token", ErrMalformedResponse)
		}
		return resp.AccessToken, sent.Add(lifetime(resp.ExpiresAt.Time(), r.header, sent)), nil
	}
}

// lifetime is how long a session issued at sent (client clock) lives:
// expires_at measured against the response's Date when there is one, so a
// skewed client clock doesn't matter, and never more than the server's
// session lifetime.
func lifetime(expires time.Time, h http.Header, sent time.Time) time.Duration {
	ref := sent
	if d, err := http.ParseTime(h.Get("Date")); err == nil {
		ref = d
	}
	return min(max(expires.Sub(ref), 0), sessionTTL)
}
