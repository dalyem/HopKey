// Package server implements hop-server, the HopKey sync server: the HTTP
// API v1 of the phase 2 plan (https://plan.23d.dev/p/agcniv64, rev 4) over
// a Store.
//
// The server is untrusted for confidentiality and for log integrity:
// clients verify every entry themselves. It enforces tenant isolation,
// sessions, rate limits and account-existence privacy, and it runs only the
// public stage of the log rules (vaultlog.ApplyPublic).
package server

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/dalyem/hopkey/internal/canonjson"
	"github.com/dalyem/hopkey/internal/crypto"
	"github.com/dalyem/hopkey/internal/model"
	"github.com/dalyem/hopkey/internal/vaultlog"
	"github.com/dalyem/hopkey/internal/version"
)

// Lifetimes of the credentials the server issues.
const (
	ChallengeTTL  = 60 * time.Second // R3, R5
	SessionTTL    = 15 * time.Minute // §9
	LoginTokenTTL = 10 * time.Minute // R6
)

// Config configures a Server.
type Config struct {
	// Origin is the external origin clients sign in device-auth and
	// signup-pop objects (R5). It is never taken from a request header.
	// The server uses crypto.CanonicalOrigin of it.
	Origin string
	Store  Store
	// TrustedProxies are the proxies whose X-Forwarded-For is believed
	// (R8).
	TrustedProxies []netip.Prefix
	Logger         *slog.Logger
	Now            func() time.Time // default time.Now
	Limits         *Limits          // default DefaultLimits()
	Rates          *Rates           // default DefaultRates()
}

// Server is the HTTP API v1.
type Server struct {
	origin  string
	store   Store
	proxies []netip.Prefix
	log     *slog.Logger
	now     func() time.Time
	lim     Limits
	rates   Rates

	secret []byte      // prelogin HMAC secret
	dummy  crypto.Hash // verifier for unknown accounts

	limiter  *rateLimiter
	validate *queue
	signups  *queue
	polls    *pollLimiter
	hub      *hub
	mux      *http.ServeMux

	stop     chan struct{}
	stopOnce sync.Once
	wg       sync.WaitGroup
}

// New returns a Server. It creates the prelogin secret on first use.
func New(ctx context.Context, cfg Config) (*Server, error) {
	origin, err := crypto.CanonicalOrigin(cfg.Origin)
	if err != nil {
		return nil, err
	}
	if cfg.Store == nil {
		return nil, errors.New("server: no store")
	}
	s := &Server{
		origin:  origin,
		store:   cfg.Store,
		proxies: cfg.TrustedProxies,
		log:     cfg.Logger,
		now:     cfg.Now,
		lim:     DefaultLimits(),
		rates:   DefaultRates(),
		hub:     newHub(),
		stop:    make(chan struct{}),
	}
	if s.log == nil {
		s.log = slog.Default()
	}
	if s.now == nil {
		s.now = time.Now
	}
	if cfg.Limits != nil {
		s.lim = *cfg.Limits
	}
	if cfg.Rates != nil {
		s.rates = *cfg.Rates
	}
	if _, err := rand.Read(s.dummy[:]); err != nil {
		return nil, err
	}
	if s.secret, err = loadSecret(ctx, s.store); err != nil {
		return nil, err
	}
	s.limiter = newRateLimiter(s.now, 100_000)
	s.validate = newQueue(s.lim.ValidationJobs, s.lim.ValidationQueue)
	s.signups = newQueue(s.lim.SignupJobs, s.lim.SignupQueue)
	s.polls = newPollLimiter(s.lim)
	s.routes()
	s.wg.Add(1)
	go s.janitor()
	return s, nil
}

// Close wakes every long-poll and stops background work. It does not close
// the Store.
func (s *Server) Close() {
	s.stopOnce.Do(func() { close(s.stop) })
	s.wg.Wait()
}

// Handler returns the HTTP handler.
func (s *Server) Handler() http.Handler { return s.mux }

const metaPreloginSecret = "prelogin_secret"

func loadSecret(ctx context.Context, st Store) ([]byte, error) {
	var secret []byte
	err := st.Update(ctx, func(tx Tx) error {
		v, err := tx.Meta(metaPreloginSecret)
		if err == nil {
			secret = v
			return nil
		}
		if !errors.Is(err, ErrNotFound) {
			return err
		}
		secret = make([]byte, 32)
		if _, err := rand.Read(secret); err != nil {
			return err
		}
		return tx.SetMeta(metaPreloginSecret, secret)
	})
	if err == nil && len(secret) != 32 {
		err = errors.New("server: stored prelogin secret has the wrong size")
	}
	return secret, err
}

// janitor deletes expired sessions, tokens and challenges once a minute.
func (s *Server) janitor() {
	defer s.wg.Done()
	t := time.NewTicker(time.Minute)
	defer t.Stop()
	for {
		select {
		case <-s.stop:
			return
		case <-t.C:
			err := s.store.Update(context.Background(), func(tx Tx) error { return tx.DeleteExpired(s.now()) })
			if err != nil {
				s.log.Error("deleting expired credentials", "err", err)
			}
		}
	}
}

// apiError is an error response: {"error":{"code","message"}}, plus the
// head for head_conflict (R11).
type apiError struct {
	status int
	code   string
	msg    string
	head   *vaultlog.Head
}

func (e *apiError) Error() string { return e.code + ": " + e.msg }

func errBadRequest(msg string) *apiError {
	return &apiError{http.StatusBadRequest, "bad_request", msg, nil}
}

// errUnauthorized is the one 401 every authentication failure returns, so
// unknown accounts, wrong secrets, expired and revoked credentials look the
// same (R4).
var errUnauthorized = &apiError{http.StatusUnauthorized, "unauthorized", "authentication failed", nil}

// errNotFound is the one 404 for absent resources and resources of another
// tenant (R1).
var errNotFound = &apiError{http.StatusNotFound, "not_found", "not found", nil}

var (
	errTooLarge    = &apiError{http.StatusRequestEntityTooLarge, "too_large", "request exceeds a size or collection limit", nil}
	errRateLimited = &apiError{http.StatusTooManyRequests, "rate_limited", "too many requests", nil}
	errBusy        = &apiError{http.StatusTooManyRequests, "busy", "too many concurrent requests", nil}
	errQuota       = &apiError{http.StatusInsufficientStorage, "quota_exhausted", "account storage quota exhausted", nil}
	errRegConflict = &apiError{http.StatusConflict, "registration_conflict", "registration conflict", nil}
	errInternal    = &apiError{http.StatusInternalServerError, "internal", "internal error", nil}
)

func errHeadConflict(h vaultlog.Head) *apiError {
	return &apiError{http.StatusConflict, "head_conflict", "prev is not the head", &h}
}

func errInvalidEntry(err error) *apiError {
	msg := "entry rejected"
	if r := vaultlog.RuleOf(err); r != "" {
		msg = "entry rejected: " + string(r)
	}
	return &apiError{http.StatusBadRequest, "invalid_entry", msg, nil}
}

type errorBody struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

type errorResponse struct {
	Error errorBody `json:"error"`
}

type headConflictResponse struct {
	Error errorBody     `json:"error"`
	Head  vaultlog.Head `json:"head"`
}

func writeError(w http.ResponseWriter, e *apiError) {
	var v any = errorResponse{errorBody{e.code, e.msg}}
	if e.head != nil {
		v = headConflictResponse{errorBody{e.code, e.msg}, *e.head}
	}
	writeJSON(w, e.status, v)
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	b, err := canonjson.Marshal(v)
	if err != nil {
		status = http.StatusInternalServerError
		b = []byte(`{"error":{"code":"internal","message":"internal error"}}`)
	}
	writeRaw(w, status, b)
}

func writeRaw(w http.ResponseWriter, status int, b []byte) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	w.Write(b)
}

// route is one endpoint's handling options.
type route struct {
	pattern string // method and template, which is also the bucket name
	ipRate  Rate
	body    int64 // body limit; 0 for none
	poll    bool  // long-poll deadline
	h       func(w http.ResponseWriter, r *http.Request, c *call) error
}

// call is the per-request state the middleware hands a handler.
type call struct {
	route *route
	ip    netip.Addr
	body  []byte
}

func (s *Server) routes() {
	s.mux = http.NewServeMux()
	lim := s.lim
	for _, rt := range []*route{
		{pattern: "GET /v1/healthz", ipRate: s.rates.IP, h: s.healthz},
		{pattern: "POST /v1/prelogin", ipRate: s.rates.PreloginIP, body: lim.MaxBody, h: s.prelogin},
		{pattern: "POST /v1/login", ipRate: s.rates.LoginIP, body: lim.MaxBody, h: s.login},
		{pattern: "POST /v1/recover", ipRate: s.rates.LoginIP, body: lim.MaxBody, h: s.recover},
		{pattern: "POST /v1/auth/challenge", ipRate: s.rates.IP, body: lim.MaxBody, h: s.authChallenge},
		{pattern: "POST /v1/auth/session", ipRate: s.rates.IP, body: lim.MaxBody, h: s.authSession},
		{pattern: "POST /v1/signup/challenge", ipRate: s.rates.IP, body: lim.MaxBody, h: s.signupChallenge},
		// Signup reads its own body, after it has a validation slot.
		{pattern: "POST /v1/signup", ipRate: s.rates.IP, h: s.signup},
		{pattern: "GET /v1/vaults/{vault}/log", ipRate: s.rates.IP, poll: true, h: s.getLog},
		{pattern: "GET /v1/vaults/{vault}/entries/{seq}", ipRate: s.rates.IP, h: s.getEntry},
		{pattern: "GET /v1/vaults/{vault}/objects/{sha256}", ipRate: s.rates.IP, h: s.getObject},
		{pattern: "POST /v1/vaults/{vault}/log", ipRate: s.rates.IP, body: lim.MaxBody, h: s.postLog},
	} {
		s.mux.Handle(rt.pattern, s.wrap(rt))
	}
	s.mux.Handle("/", s.wrap(&route{pattern: "unmatched", ipRate: s.rates.IP,
		h: func(http.ResponseWriter, *http.Request, *call) error { return errNotFound }}))
}

// statusWriter records the status for the access log.
type statusWriter struct {
	http.ResponseWriter
	status int
}

func (w *statusWriter) WriteHeader(code int) {
	if w.status == 0 {
		w.status = code
	}
	w.ResponseWriter.WriteHeader(code)
}

func (w *statusWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }

// wrap applies what every endpoint shares: the request deadline, the IP
// bucket, the content-encoding and body limits, error responses, panics
// and the access log. The log has the method, route template, status and
// duration only: never a body, header, query, token or code (R11).
func (s *Server) wrap(rt *route) http.Handler {
	return http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		start := time.Now()
		w := &statusWriter{ResponseWriter: rw}
		deadline := s.lim.RequestDeadline
		if rt.poll {
			deadline = s.lim.PollDeadline
		}
		rc := http.NewResponseController(w)
		_ = rc.SetReadDeadline(start.Add(deadline))
		_ = rc.SetWriteDeadline(start.Add(deadline + 5*time.Second))
		ctx, cancel := context.WithTimeout(r.Context(), deadline)
		defer cancel()
		r = r.WithContext(ctx)

		defer func() {
			if p := recover(); p != nil {
				s.log.Error("panic", "route", rt.pattern, "panic", fmt.Sprint(p))
				if w.status == 0 {
					writeError(w, errInternal)
				}
			}
			s.log.Info("request", "route", rt.pattern, "status", w.status, "ms", time.Since(start).Milliseconds())
		}()

		c := &call{route: rt, ip: s.clientIP(r)}
		err := s.serve(w, r, c)
		if err == nil {
			return
		}
		var ae *apiError
		if !errors.As(err, &ae) {
			if !errors.Is(err, context.Canceled) && !errors.Is(err, context.DeadlineExceeded) {
				s.log.Error("request failed", "route", rt.pattern, "err", err)
			}
			ae = errInternal
		}
		writeError(w, ae)
	})
}

func (s *Server) serve(w http.ResponseWriter, r *http.Request, c *call) error {
	if !s.limiter.allow(c.route.pattern+"|ip|"+ipKey(c.ip), c.route.ipRate) {
		return errRateLimited
	}
	if ce := r.Header.Get("Content-Encoding"); ce != "" && !strings.EqualFold(ce, "identity") {
		return errBadRequest("unsupported content encoding")
	}
	if c.route.body > 0 {
		b, err := readBody(w, r, c.route.body)
		if err != nil {
			return err
		}
		c.body = b
	}
	return c.route.h(w, r, c)
}

// readBody reads at most limit bytes (R8; R9 measures the bytes actually
// received).
func readBody(w http.ResponseWriter, r *http.Request, limit int64) ([]byte, error) {
	if r.ContentLength > limit {
		return nil, errTooLarge
	}
	b, err := io.ReadAll(http.MaxBytesReader(w, r.Body, limit))
	var mbe *http.MaxBytesError
	switch {
	case errors.As(err, &mbe):
		return nil, errTooLarge
	case err != nil:
		return nil, errBadRequest("reading the request body failed")
	}
	return b, nil
}

// decode checks the nesting depth (R14) and decodes b strictly into v.
func (s *Server) decode(b []byte, v any) error {
	if !depthWithin(b, s.lim.MaxDepth) {
		return errTooLarge
	}
	if err := canonjson.Unmarshal(b, v); err != nil {
		return errBadRequest("request does not match the schema")
	}
	return nil
}

// depthWithin reports whether the JSON nesting depth of b is at most max.
// It only counts brackets outside strings; the strict decoder checks the
// rest.
func depthWithin(b []byte, max int) bool {
	depth := 0
	inStr, esc := false, false
	for _, c := range b {
		if inStr {
			switch {
			case esc:
				esc = false
			case c == '\\':
				esc = true
			case c == '"':
				inStr = false
			}
			continue
		}
		switch c {
		case '"':
			inStr = true
		case '{', '[':
			if depth++; depth > max {
				return false
			}
		case '}', ']':
			depth--
		}
	}
	return true
}

// clientIP is the peer address, or for a trusted proxy the rightmost
// X-Forwarded-For address that is not itself a trusted proxy (R8).
func (s *Server) clientIP(r *http.Request) netip.Addr {
	ap, err := netip.ParseAddrPort(r.RemoteAddr)
	if err != nil {
		return netip.Addr{}
	}
	addr := ap.Addr().Unmap()
	if !s.trusted(addr) {
		return addr
	}
	hops := strings.Split(strings.Join(r.Header.Values("X-Forwarded-For"), ","), ",")
	for i := len(hops) - 1; i >= 0; i-- {
		h := strings.TrimSpace(hops[i])
		if h == "" {
			continue
		}
		a, err := netip.ParseAddr(h)
		if err != nil {
			return addr
		}
		a = a.Unmap()
		if !s.trusted(a) {
			return a
		}
		addr = a
	}
	return addr
}

func (s *Server) trusted(a netip.Addr) bool {
	for _, p := range s.proxies {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

// newSecret returns 32 random bytes as unpadded base64url (an opaque bearer
// credential) and the SHA-256 of the raw bytes, which is what is stored.
func newSecret() (string, crypto.Hash, error) {
	var raw [32]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", crypto.Hash{}, err
	}
	b, err := canonjson.Marshal(raw[:])
	if err != nil {
		return "", crypto.Hash{}, err
	}
	return strings.Trim(string(b), `"`), crypto.SHA256(raw[:]), nil
}

// secretHash decodes an opaque credential and returns the hash it is
// stored under.
func secretHash(s string) (crypto.Hash, bool) {
	var raw []byte
	if len(s) != 43 || canonjson.Unmarshal([]byte(`"`+s+`"`), &raw) != nil || len(raw) != 32 {
		return crypto.Hash{}, false
	}
	return crypto.SHA256(raw), true
}

// bearer returns the hash of the request's bearer credential.
func bearer(r *http.Request) (crypto.Hash, bool) {
	scheme, tok, ok := strings.Cut(r.Header.Get("Authorization"), " ")
	if !ok || !strings.EqualFold(scheme, "Bearer") {
		return crypto.Hash{}, false
	}
	return secretHash(strings.TrimSpace(tok))
}

// healthz: GET /v1/healthz → {ok:true, version}.
func (s *Server) healthz(w http.ResponseWriter, r *http.Request, c *call) error {
	writeJSON(w, http.StatusOK, struct {
		OK      bool   `json:"ok"`
		Version string `json:"version"`
	}{true, version.Version})
	return nil
}

// hub wakes long-polls when a vault commits. Waiters take the vault's
// channel before they read; a commit closes it.
type hub struct {
	mu    sync.Mutex
	chans map[model.ID]chan struct{}
}

func newHub() *hub { return &hub{chans: map[model.ID]chan struct{}{}} }

func (h *hub) watch(v model.ID) <-chan struct{} {
	h.mu.Lock()
	defer h.mu.Unlock()
	ch, ok := h.chans[v]
	if !ok {
		ch = make(chan struct{})
		h.chans[v] = ch
	}
	return ch
}

func (h *hub) notify(v model.ID) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if ch, ok := h.chans[v]; ok {
		close(ch)
		delete(h.chans, v)
	}
}
