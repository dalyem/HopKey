package syncclient

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strconv"
	"time"

	"github.com/dalyem/hopkey/internal/canonjson"
	"github.com/dalyem/hopkey/internal/crypto"
	"github.com/dalyem/hopkey/internal/email"
	"github.com/dalyem/hopkey/internal/model"
	"github.com/dalyem/hopkey/internal/store"
	"github.com/dalyem/hopkey/internal/vaultlog"
)

// The vault endpoints, with any credential that reads them: a session, or
// a login or recovery token.

type wireEntry struct {
	H    crypto.Hash   `json:"h"`
	Seq  uint64        `json:"seq,string"`
	Wire canonjson.Raw `json:"wire"`
}

type logPage struct {
	Entries []wireEntry   `json:"entries"`
	Head    vaultlog.Head `json:"head"`
}

type postRequest struct {
	Wire canonjson.Raw `json:"wire"`
}

func vaultPath(vault model.ID, rest string) string {
	return "/v1/vaults/" + url.PathEscape(vault.String()) + rest
}

func (e wireEntry) committed() (store.Committed, error) {
	w, err := vaultlog.ParseWire(e.Wire)
	if err != nil {
		return store.Committed{}, fmt.Errorf("%w: entry %d: %w", ErrMalformedResponse, e.Seq, err)
	}
	return store.Committed{Seq: e.Seq, H: e.H, Wire: w}, nil
}

// since is GET /v1/vaults/{id}/log?after=after&wait=wait: the committed
// entries past after, in ascending order (a page of them), and the head.
// wait is whole seconds, at most MaxWait.
func (c *Client) since(ctx context.Context, token string, vault model.ID, after uint64, wait time.Duration) ([]store.Committed, vaultlog.Head, error) {
	wait = min(max(wait, 0), MaxWait).Truncate(time.Second)
	q := url.Values{"after": {strconv.FormatUint(after, 10)}}
	if wait > 0 {
		q.Set("wait", strconv.FormatInt(int64(wait/time.Second), 10))
	}
	var p logPage
	err := c.do(ctx, &call{
		method: http.MethodGet, path: vaultPath(vault, "/log"), query: q, token: token,
		maxResp: maxLogResponse, wait: wait,
	}, &p)
	if err != nil {
		return nil, vaultlog.Head{}, err
	}
	out := make([]store.Committed, 0, len(p.Entries))
	next := after + 1
	for _, e := range p.Entries {
		if e.Seq < next {
			return nil, vaultlog.Head{}, fmt.Errorf("%w: entry %d after %d is out of order", ErrMalformedResponse, e.Seq, next-1)
		}
		cm, err := e.committed()
		if err != nil {
			return nil, vaultlog.Head{}, err
		}
		out = append(out, cm)
		next = e.Seq + 1
	}
	return out, p.Head, nil
}

// entryAt is GET /v1/vaults/{id}/entries/{seq}.
func (c *Client) entryAt(ctx context.Context, token string, vault model.ID, seq uint64) (store.Committed, error) {
	var e wireEntry
	err := c.do(ctx, &call{
		method: http.MethodGet, path: vaultPath(vault, "/entries/"+strconv.FormatUint(seq, 10)),
		token: token, maxResp: maxLogResponse,
	}, &e)
	if err != nil {
		return store.Committed{}, err
	}
	return e.committed()
}

// object is GET /v1/vaults/{id}/objects/{sha256}: the envelope itself,
// checked against its digest.
func (c *Client) object(ctx context.Context, token string, vault model.ID, h crypto.Hash) ([]byte, error) {
	var b []byte
	err := c.do(ctx, &call{
		method: http.MethodGet, path: vaultPath(vault, "/objects/"+h.String()),
		token: token, maxResp: maxObjectResponse,
	}, &b)
	if err != nil {
		return nil, err
	}
	if !crypto.SHA256(b).Equal(h) {
		return nil, fmt.Errorf("%w: object %s does not match its digest", ErrMalformedResponse, h)
	}
	return b, nil
}

// post is POST /v1/vaults/{id}/log {wire} → {seq, h}. A head conflict is a
// *store.HeadConflictError.
func (c *Client) post(ctx context.Context, token string, vault model.ID, w *vaultlog.Wire) (vaultlog.Head, error) {
	raw, err := w.Marshal()
	if err != nil {
		return vaultlog.Head{}, err
	}
	var head vaultlog.Head
	err = c.do(ctx, &call{
		method: http.MethodPost, path: vaultPath(vault, "/log"), token: token,
		body: postRequest{Wire: raw},
	}, &head)
	return head, err
}

// Remote is a vault under a device session: store.Remote for the sync
// engine. Each session is authenticated with the device's signer when the
// client has none cached, and again once on a 401.
type Remote struct {
	c     *Client
	vault model.ID
	dev   Device
	wait  time.Duration
}

var _ store.Remote = (*Remote)(nil)

// Remote returns the vault vaultID under dev's sessions. Since does not
// wait for new entries; see WithWait.
func (c *Client) Remote(vaultID model.ID, dev Device) *Remote {
	return &Remote{c: c, vault: vaultID, dev: dev}
}

// WithWait returns a Remote whose Since long-polls up to wait (whole
// seconds, at most MaxWait) when there is nothing past after. It shares
// r's sessions.
func (r *Remote) WithWait(wait time.Duration) *Remote {
	cp := *r
	cp.wait = wait
	return &cp
}

// Since is store.Remote.Since: GET /v1/vaults/{id}/log.
func (r *Remote) Since(ctx context.Context, after uint64) (entries []store.Committed, head vaultlog.Head, err error) {
	err = r.c.withSession(ctx, r.dev, func(tok string) (err error) {
		entries, head, err = r.c.since(ctx, tok, r.vault, after, r.wait)
		return err
	})
	return entries, head, err
}

// Post is store.Remote.Post: POST /v1/vaults/{id}/log.
func (r *Remote) Post(ctx context.Context, w *vaultlog.Wire) (head vaultlog.Head, err error) {
	err = r.c.withSession(ctx, r.dev, func(tok string) (err error) {
		head, err = r.c.post(ctx, tok, r.vault, w)
		return err
	})
	return head, err
}

// EntryAt is GET /v1/vaults/{id}/entries/{seq}.
func (r *Remote) EntryAt(ctx context.Context, seq uint64) (c store.Committed, err error) {
	err = r.c.withSession(ctx, r.dev, func(tok string) (err error) {
		c, err = r.c.entryAt(ctx, tok, r.vault, seq)
		return err
	})
	return c, err
}

// Object is GET /v1/vaults/{id}/objects/{sha256}.
func (r *Remote) Object(ctx context.Context, h crypto.Hash) (b []byte, err error) {
	err = r.c.withSession(ctx, r.dev, func(tok string) (err error) {
		b, err = r.c.object(ctx, tok, r.vault, h)
		return err
	})
	return b, err
}

// DevicesSeen is GET /v1/vaults/{id}/devices/seen: when each of the
// account's devices last made a request with its session, to within a
// minute, as the server saw it. A device that never did is absent.
func (r *Remote) DevicesSeen(ctx context.Context) (map[model.ID]time.Time, error) {
	var resp struct {
		Devices []struct {
			DeviceID model.ID        `json:"device_id"`
			SeenAt   model.Timestamp `json:"seen_at"`
		} `json:"devices"`
	}
	err := r.c.withSession(ctx, r.dev, func(tok string) error {
		return r.c.do(ctx, &call{method: http.MethodGet, path: vaultPath(r.vault, "/devices/seen"), token: tok}, &resp)
	})
	if err != nil {
		return nil, err
	}
	out := make(map[model.ID]time.Time, len(resp.Devices))
	for _, d := range resp.Devices {
		out[d.DeviceID] = d.SeenAt.Time()
	}
	return out, nil
}

// TokenRemote is a vault under a login or recovery token (R6): the three
// vault reads and one bootstrap post. It is store.SignInRemote. The token
// lasts 10 minutes and is never refreshed: a 401 is an *APIError matching
// ErrUnauthorized.
type TokenRemote struct {
	c     *Client
	token string
	// AccountID and VaultID are the account the token was issued for and
	// the vault it reads.
	AccountID model.ID
	VaultID   model.ID
}

var _ store.SignInRemote = (*TokenRemote)(nil)

// String names the remote without its token. A TokenRemote, value or
// pointer, prints as its String with every verb, %#v included, and logs
// as it with slog: no formatting reaches the token.
func (r TokenRemote) String() string {
	return "syncclient.TokenRemote{vault " + r.VaultID.String() + "}"
}

// GoString is String, for %#v.
func (r TokenRemote) GoString() string { return r.String() }

// Format writes String for every verb.
func (r TokenRemote) Format(f fmt.State, _ rune) { io.WriteString(f, r.String()) }

// LogValue is String, for slog.
func (r TokenRemote) LogValue() slog.Value { return slog.StringValue(r.String()) }

// EntryAt is store.SignInRemote.EntryAt.
func (r *TokenRemote) EntryAt(ctx context.Context, seq uint64) (store.Committed, error) {
	return r.c.entryAt(ctx, r.token, r.VaultID, seq)
}

// Since is store.SignInRemote.Since. It never waits.
func (r *TokenRemote) Since(ctx context.Context, after uint64) ([]store.Committed, vaultlog.Head, error) {
	return r.c.since(ctx, r.token, r.VaultID, after, 0)
}

// Post is store.SignInRemote.Post: the one bootstrap entry.
func (r *TokenRemote) Post(ctx context.Context, w *vaultlog.Wire) (vaultlog.Head, error) {
	return r.c.post(ctx, r.token, r.VaultID, w)
}

// Object is GET /v1/vaults/{id}/objects/{sha256}.
func (r *TokenRemote) Object(ctx context.Context, h crypto.Hash) ([]byte, error) {
	return r.c.object(ctx, r.token, r.VaultID, h)
}

type preloginRequest struct {
	Email string `json:"email"`
}

type preloginResponse struct {
	AccountID  model.ID `json:"account_id"`
	KDFVersion uint32   `json:"kdf_version"`
	Salt       []byte   `json:"salt"`
}

// Prelogin is what the server says about an email: the account ID, and the
// kdf_version and salt to derive the login keys with (§4.4). For an
// unknown email these are a deterministic fake (R4), and the login that
// follows fails like a wrong password.
type Prelogin struct {
	AccountID  model.ID
	KDFVersion uint32
	Salt       []byte
}

// Prelogin is POST /v1/prelogin. The address is normalized first (R4).
func (c *Client) Prelogin(ctx context.Context, addr string) (Prelogin, error) {
	norm, err := email.Normalize(addr)
	if err != nil {
		return Prelogin{}, err
	}
	var resp preloginResponse
	if err := c.do(ctx, &call{method: http.MethodPost, path: "/v1/prelogin", body: preloginRequest{norm}}, &resp); err != nil {
		return Prelogin{}, err
	}
	if resp.AccountID.IsZero() || len(resp.Salt) != crypto.SaltSize {
		return Prelogin{}, fmt.Errorf("%w: prelogin", ErrMalformedResponse)
	}
	return Prelogin(resp), nil
}

type loginRequest struct {
	AccountID model.ID `json:"account_id"`
	AuthKey   []byte   `json:"auth_key"`
}

type recoverRequest struct {
	AccountID model.ID `json:"account_id"`
	RAuth     []byte   `json:"r_auth"`
}

type loginResponse struct {
	LoginToken string   `json:"login_token"`
	VaultID    model.ID `json:"vault_id"`
}

// Login is POST /v1/login with the authKey of §4.1: a login token for the
// account's vault. A wrong key and an unknown account are the same
// *APIError matching ErrUnauthorized (R4).
func (c *Client) Login(ctx context.Context, accountID model.ID, authKey []byte) (*TokenRemote, error) {
	return c.login(ctx, "/v1/login", accountID, loginRequest{AccountID: accountID, AuthKey: authKey})
}

// Recover is POST /v1/recover with r_auth from the Recovery Key (§4.5): a
// recovery token for the account's vault.
func (c *Client) Recover(ctx context.Context, accountID model.ID, rAuth []byte) (*TokenRemote, error) {
	return c.login(ctx, "/v1/recover", accountID, recoverRequest{AccountID: accountID, RAuth: rAuth})
}

func (c *Client) login(ctx context.Context, path string, accountID model.ID, body any) (*TokenRemote, error) {
	var resp loginResponse
	if err := c.do(ctx, &call{method: http.MethodPost, path: path, body: body}, &resp); err != nil {
		return nil, err
	}
	if resp.LoginToken == "" || resp.VaultID.IsZero() {
		return nil, errors.New("syncclient: the server issued no login token")
	}
	return &TokenRemote{c: c, token: resp.LoginToken, AccountID: accountID, VaultID: resp.VaultID}, nil
}
