// Package syncclient is the HTTP client for hop-server's API v1 (phase 2
// plan, https://plan.23d.dev/p/agcniv64, rev 4). It implements the store's
// transport interfaces (store.Remote, store.Publisher, store.Retirer,
// store.SignInRemote) and the plain transport of the enrollment relay.
//
// It trusts nothing it receives for integrity: the store verifies every
// entry. What it enforces is the transport contract: HTTPS with
// certificate and hostname verification, credentials that never follow a
// redirect (R10), bounded response sizes (R8, R9), strict decoding and the
// R11 error mapping.
package syncclient

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/dalyem/hopkey/internal/canonjson"
	"github.com/dalyem/hopkey/internal/crypto"
	"github.com/dalyem/hopkey/internal/version"
)

// Request and response limits (plan R8, R9).
const (
	maxRequestBody = 4 << 20  // every request but signup
	maxSignupBody  = 64 << 20 // POST /v1/signup
	// A log page and a singleton entry response are canonical responses
	// of at most 4 MiB (R9).
	maxLogResponse = 4 << 20
	// An object body is one envelope of at most 1 MiB (R8).
	maxObjectResponse = 1 << 20
	// A mailbox holds at most 8 messages of 64 KiB in all (R8); this
	// leaves room for the wrappers.
	maxMailboxResponse = 256 << 10
	// Every other response, error responses included.
	maxSmallResponse = 64 << 10
	maxHeaderBytes   = 64 << 10
	maxRedirects     = 3
)

// MaxWait is the longest long-poll the server accepts (R12, the log
// endpoint).
const MaxWait = 55 * time.Second

// DefaultTimeout is a request's deadline; a long-poll gets its wait on top.
const DefaultTimeout = 30 * time.Second

// DevInsecureEnv is the development opt-in to plaintext HTTP for a
// loopback server (R10).
const DevInsecureEnv = "HOP_DEV_INSECURE"

// DevInsecureFromEnv reports whether getenv sets HOP_DEV_INSECURE=1. The
// caller passes the result in Options; the client never reads the
// environment itself.
func DevInsecureFromEnv(getenv func(string) string) bool { return getenv(DevInsecureEnv) == "1" }

// Options configure a Client.
type Options struct {
	// DevInsecure allows an http:// server URL whose host is a loopback
	// address or localhost, and then only connections to loopback
	// addresses (HOP_DEV_INSECURE=1, R10). It changes nothing for https://
	// and never relaxes certificate checks.
	DevInsecure bool
	// RootCAs replaces the system's trusted roots when set: a private CA,
	// or a test server's certificate.
	RootCAs *x509.CertPool
	// Timeout is each request's deadline; a long-poll gets its wait on
	// top. Zero means DefaultTimeout.
	Timeout time.Duration
	// Now is the clock for session lifetimes. Nil means time.Now.
	Now func() time.Time
}

// Client talks to one hop-server. It is safe for concurrent use. It caches
// device sessions, never device keys: see Device.
type Client struct {
	origin  string // CanonicalOrigin of the server URL
	hc      *http.Client
	timeout time.Duration
	now     func() time.Time

	mu       sync.Mutex
	sessions map[sessionKey]*session
}

// New returns a client for the server at serverURL, which must be an
// origin: https://host[:port], with nothing after it but an optional "/".
func New(serverURL string, opts Options) (*Client, error) {
	origin, err := crypto.CanonicalOrigin(serverURL)
	if err != nil {
		return nil, err
	}
	u, err := url.Parse(origin)
	if err != nil {
		return nil, err
	}
	plain := u.Scheme == "http"
	if plain && !opts.DevInsecure {
		return nil, fmt.Errorf("%w: %s (only loopback servers may use http://, with %s=1)", ErrInsecureURL, origin, DevInsecureEnv)
	}
	if plain && !loopbackHost(u.Hostname()) {
		return nil, fmt.Errorf("%w: %s (%s=1 allows http:// for loopback servers only)", ErrInsecureURL, origin, DevInsecureEnv)
	}
	dialer := &net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}
	tr := &http.Transport{
		Proxy:       http.ProxyFromEnvironment,
		DialContext: dialer.DialContext,
		TLSClientConfig: &tls.Config{
			MinVersion: tls.VersionTLS12,
			RootCAs:    opts.RootCAs,
		},
		ForceAttemptHTTP2:      true,
		DisableCompression:     true,
		MaxResponseHeaderBytes: maxHeaderBytes,
		TLSHandshakeTimeout:    10 * time.Second,
		IdleConnTimeout:        90 * time.Second,
	}
	if plain {
		// Plaintext goes to the loopback server and nowhere else: never
		// through a proxy, and never to an address a name resolved to
		// outside loopback.
		tr.Proxy = nil
		dialer.Control = loopbackOnly
	}
	c := &Client{
		origin:   origin,
		timeout:  opts.Timeout,
		now:      opts.Now,
		sessions: map[sessionKey]*session{},
	}
	if c.timeout <= 0 {
		c.timeout = DefaultTimeout
	}
	if c.now == nil {
		c.now = time.Now
	}
	c.hc = &http.Client{Transport: tr, CheckRedirect: c.checkRedirect}
	return c, nil
}

// Origin is the server's canonical origin: the base of every request, and
// the origin the client signs in device-auth and signup proofs.
func (c *Client) Origin() string { return c.origin }

// CloseIdleConnections closes the transport's idle connections.
func (c *Client) CloseIdleConnections() { c.hc.CloseIdleConnections() }

// loopbackHost reports whether host is localhost or a loopback address.
func loopbackHost(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// loopbackOnly is the dialer's check for plaintext connections: the
// address it is about to connect to must be a loopback address.
func loopbackOnly(network, address string, _ syscall.RawConn) error {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return err
	}
	if ip := net.ParseIP(host); ip == nil || !ip.IsLoopback() {
		return fmt.Errorf("%w: %s is not a loopback address", ErrInsecureURL, host)
	}
	return nil
}

// checkRedirect follows a redirect only within the server's origin, which
// also keeps the scheme, and never with the Authorization header (R10).
func (c *Client) checkRedirect(req *http.Request, via []*http.Request) error {
	req.Header.Del("Authorization")
	if len(via) >= maxRedirects {
		return fmt.Errorf("%w: more than %d redirects", ErrRedirect, maxRedirects)
	}
	if o, err := crypto.CanonicalOrigin(req.URL.Scheme + "://" + req.URL.Host); err != nil || o != c.origin {
		return fmt.Errorf("%w: to another origin (%s://%s)", ErrRedirect, req.URL.Scheme, req.URL.Host)
	}
	return nil
}

// call is one request.
type call struct {
	method  string
	path    string // the escaped path, from "/v1"
	query   url.Values
	body    any    // encoded with canonjson; nil for no body
	maxBody int    // the request body limit; 0 means maxRequestBody
	token   string // a bearer credential, or ""
	maxResp int64  // the response limit; 0 means maxSmallResponse
	wait    time.Duration
}

// reply is a response read in full.
type reply struct {
	status int
	header http.Header
	body   []byte
}

// exchange sends k with a deadline of the client's timeout plus k's wait
// and reads the response, at most k.maxResp bytes for a 200 and
// maxSmallResponse for anything else.
func (c *Client) exchange(ctx context.Context, k *call) (*reply, error) {
	var body io.Reader
	if k.body != nil {
		b, err := canonjson.Marshal(k.body)
		if err != nil {
			return nil, err
		}
		limit := k.maxBody
		if limit == 0 {
			limit = maxRequestBody
		}
		if len(b) > limit {
			return nil, fmt.Errorf("%w: %d bytes, at most %d", ErrRequestTooLarge, len(b), limit)
		}
		body = bytes.NewReader(b)
	}
	ctx, cancel := context.WithTimeout(ctx, c.timeout+k.wait)
	defer cancel()
	target := c.origin + k.path
	if len(k.query) > 0 {
		target += "?" + k.query.Encode()
	}
	req, err := http.NewRequestWithContext(ctx, k.method, target, body)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "hopkey/"+version.Version)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if k.token != "" {
		req.Header.Set("Authorization", "Bearer "+k.token)
	}
	resp, err := c.hc.Do(req)
	if err != nil {
		return nil, transportError(err)
	}
	defer resp.Body.Close()
	limit := k.maxResp
	if limit == 0 || resp.StatusCode != http.StatusOK {
		limit = maxSmallResponse
	}
	if ce := resp.Header.Get("Content-Encoding"); ce != "" && !strings.EqualFold(ce, "identity") {
		return nil, fmt.Errorf("%w: content encoding %q", ErrMalformedResponse, ce)
	}
	if resp.ContentLength > limit && resp.StatusCode == http.StatusOK {
		return nil, fmt.Errorf("%w: %d bytes, at most %d", ErrResponseTooLarge, resp.ContentLength, limit)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if err != nil {
		return nil, transportError(err)
	}
	if int64(len(b)) > limit {
		if resp.StatusCode != http.StatusOK {
			// An oversized error body is no R11 error: keep the status.
			b = nil
		} else {
			return nil, fmt.Errorf("%w: more than %d bytes", ErrResponseTooLarge, limit)
		}
	}
	return &reply{status: resp.StatusCode, header: resp.Header, body: b}, nil
}

// do sends k and decodes a 200 response strictly into out (a *[]byte
// takes the body as it is; nil discards it). Any other status is mapped
// by responseError.
func (c *Client) do(ctx context.Context, k *call, out any) error {
	r, err := c.exchange(ctx, k)
	if err != nil {
		return err
	}
	return r.decode(out)
}

func (r *reply) decode(out any) error {
	if r.status != http.StatusOK {
		return responseError(r.status, r.body)
	}
	switch out := out.(type) {
	case nil:
		return nil
	case *[]byte:
		*out = r.body
		return nil
	}
	if err := canonjson.Unmarshal(r.body, out); err != nil {
		return fmt.Errorf("%w: %w", ErrMalformedResponse, err)
	}
	return nil
}

type healthResponse struct {
	OK      bool   `json:"ok"`
	Version string `json:"version"`
}

// Health is GET /v1/healthz. It returns the server's version.
func (c *Client) Health(ctx context.Context) (string, error) {
	var resp healthResponse
	if err := c.do(ctx, &call{method: http.MethodGet, path: "/v1/healthz"}, &resp); err != nil {
		return "", err
	}
	if !resp.OK {
		return "", errors.New("syncclient: the server reports it is not healthy")
	}
	return resp.Version, nil
}
