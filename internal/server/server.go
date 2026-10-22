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
	"strconv"
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
	accounts *accountLocks
	mux      *http.ServeMux

	stop     chan struct{}
	stopOnce sync.Once
	wg       sync.WaitGroup

	// hooks are nil outside tests, which set them before the first request
	// to pause a request at a fixed point.
	hooks struct {
		beforeSend  func() // getLog: a response is built, before its admission check
		admitted    func() // getLog: a response is admitted, before it is written
		sent        func() // getLog: an admitted response is written and flushed
		invalidated func() // postLog: an invalidating commit is committed and notified
		validating  func() // postLog: a validation slot is held, before any decoding
		prepare     func() // each call of prepare
	}
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
	s.accounts = newAccountLocks(s.lim.LockWaitersPerAccount, s.lim.LockWaiters)
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
	w.Header().Set("Content-Length", strconv.Itoa(len(b)))
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
	route   *route
	ip      netip.Addr
	body    []byte
	writeBy time.Time // the response's write deadline
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
		writeBy := start.Add(deadline + 5*time.Second)
		_ = rc.SetReadDeadline(start.Add(deadline))
		_ = rc.SetWriteDeadline(writeBy)
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

		c := &call{route: rt, ip: s.clientIP(r), writeBy: writeBy}
		err := s.serve(w, r, c)
		if err == nil {
			return
		}
		var ae *apiError
		switch {
		case errors.As(err, &ae):
		case errors.Is(err, context.DeadlineExceeded):
			// The request ran out of time waiting (for an account lock,
			// a validation slot or the database): retryable, as when a
			// queue is full.
			ae = errBusy
		case errors.Is(err, context.Canceled):
			// The client went away; nobody reads a response.
			return
		default:
			s.log.Error("request failed", "route", rt.pattern, "err", err)
			ae = errInternal
		}
		writeError(w, ae)
	})
}

func (s *Server) serve(w http.ResponseWriter, r *http.Request, c *call) error {
	if !s.limiter.allow(c.route.pattern+"|ip", ipKey(c.ip), c.route.ipRate) {
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

// collectionsWithin scans a request body for the R14 collection limits
// and the nesting depth before the strict decoder builds anything: the
// arrays at prefix.entry.ops (MaxOps) and prefix.objects (MaxObjects) and,
// when the member at prefix is itself an array of wires (signup), its
// length (MaxSignupWires). Array elements leave no name in a path, so for
// signup the ops of every wire are at wires.entry.ops.
//
// It only refuses early. It does not validate; the strict decoder and
// prepare enforce the same limits on every request. Member names are
// compared decoded, as the decoder compares them, so a limited name
// spelled with escapes is caught here too.
func (s *Server) collectionsWithin(b []byte, prefix string) bool {
	names := [...]string{prefix, "entry", "ops", "objects"}
	return arrayLens(b, s.lim.MaxDepth, names[:], func(path []string, n int) bool {
		switch {
		case len(path) == 1 && path[0] == prefix:
			return n <= s.lim.MaxSignupWires
		case len(path) == 3 && path[0] == prefix && path[1] == "entry" && path[2] == "ops":
			return n <= s.lim.MaxOps
		case len(path) == 2 && path[0] == prefix && path[1] == "objects":
			return n <= s.lim.MaxObjects
		}
		return true
	})
}

// maxScanName is the longest member name arrayLens can match.
const maxScanName = 32

// arrayLens calls fn with the member-name path (array indexes left out)
// and the element count of each array in b as the array closes, and stops
// with false when fn returns false or the nesting depth exceeds maxDepth.
// A path holds only the names it was given (ASCII, at most maxScanName
// bytes): each member name is decoded, escapes included, and stands for
// the element of names it equals, or "" for any other name. It counts
// brackets and commas outside strings; b need not be valid JSON.
//
// It allocates its stack and path once, at maxDepth entries, so a body of
// nothing but brackets costs no more than a valid one.
func arrayLens(b []byte, maxDepth int, names []string, fn func(path []string, n int) bool) bool {
	type frame struct {
		array    bool
		key      string // object: the current member's name
		wantKey  bool   // object: the next string is a member name
		nonEmpty bool   // array
		commas   int    // array
		pathLen  int    // len(path) outside this container
	}
	stack := make([]frame, 0, maxDepth)
	path := make([]string, 0, maxDepth)
	for i := 0; i < len(b); i++ {
		c := b[i]
		if c == ' ' || c == '\t' || c == '\n' || c == '\r' {
			continue
		}
		var top *frame
		if len(stack) > 0 {
			top = &stack[len(stack)-1]
			if top.array && c != ']' && c != ',' {
				top.nonEmpty = true
			}
		}
		switch c {
		case '"':
			name, j := memberName(b, i, names)
			if top != nil && !top.array && top.wantKey {
				top.key = name
				top.wantKey = false
			}
			i = j
		case '{', '[':
			if len(stack) == maxDepth {
				return false
			}
			n := len(path)
			if top != nil && !top.array {
				path = append(path, top.key)
			}
			stack = append(stack, frame{array: c == '[', wantKey: c == '{', pathLen: n})
		case '}', ']':
			if top == nil {
				return true
			}
			if top.array {
				n := top.commas
				if top.nonEmpty {
					n++
				}
				if !fn(path, n) {
					return false
				}
			}
			path = path[:top.pathLen]
			stack = stack[:len(stack)-1]
		case ',':
			if top != nil {
				if top.array {
					top.commas++
				} else {
					top.wantKey = true
				}
			}
		}
	}
	return true
}

// memberName decodes the JSON string that opens at b[i] and returns the
// element of names it equals ("" for none) and the index of its closing
// quote (len(b) when there is none). A backslash always escapes the byte
// after it, so the string ends where a skip over it would end; \uXXXX is
// decoded, and a code point outside ASCII or an invalid escape matches no
// name. It does not allocate.
func memberName(b []byte, i int, names []string) (string, int) {
	var buf [maxScanName]byte
	n, ok := 0, true
	j := i + 1
	for j < len(b) && b[j] != '"' {
		c := b[j]
		j++
		if c == '\\' {
			if j >= len(b) {
				break
			}
			c = b[j]
			j++
			switch c {
			case '"', '\\', '/':
			case 'b':
				c = '\b'
			case 'f':
				c = '\f'
			case 'n':
				c = '\n'
			case 'r':
				c = '\r'
			case 't':
				c = '\t'
			case 'u':
				r, valid := hex4(b[j:])
				if !valid || r >= 0x80 {
					ok = false
					continue
				}
				c = byte(r)
				j += 4
			default:
				ok = false
				continue
			}
		}
		if n == len(buf) {
			ok = false
			continue
		}
		buf[n] = c
		n++
	}
	if j > len(b) {
		j = len(b)
	}
	if ok {
		for _, name := range names {
			if string(buf[:n]) == name {
				return name, j
			}
		}
	}
	return "", j
}

// hex4 decodes the four hex digits that start b.
func hex4(b []byte) (rune, bool) {
	if len(b) < 4 {
		return 0, false
	}
	var r rune
	for _, c := range b[:4] {
		switch {
		case '0' <= c && c <= '9':
			c -= '0'
		case 'a' <= c && c <= 'f':
			c -= 'a' - 10
		case 'A' <= c && c <= 'F':
			c -= 'A' - 10
		default:
			return 0, false
		}
		r = r<<4 | rune(c)
	}
	return r, true
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

// accountLocks orders log-response admission with the commits that
// invalidate credentials (R2). A commit that ends sessions or changes the
// credential generation holds its account's write lock across the
// transaction and the long-poll notification; a log response holds the
// read lock from its admission check until it has been written, within
// AdmitWrite. So no response leaves after an invalidation of its
// credential commits, and a slow reader can only delay its own account's
// invalidating commits, and only for AdmitWrite.
//
// A waiting writer holds back new readers, so readers cannot starve it.
// Every wait ends with its request's context. Writers wait with a prepared
// wire in memory, so at most perAccount of them wait for one account and
// at most total for all; a writer beyond either is refused with errBusy at
// once. An account's entry exists only while someone holds or waits for
// its lock, so the map is bounded by the requests in flight.
type accountLocks struct {
	mu         sync.Mutex
	m          map[model.ID]*accountLock
	perAccount int
	total      int
	waiting    int // writers waiting, all accounts
}

type accountLock struct {
	readers int  // read holders
	writer  bool // the write holder
	writers int  // writers waiting
	refs    int  // holders and waiters
	// changed is closed, and replaced, whenever the lock is released or a
	// waiting writer gives up.
	changed chan struct{}
}

func newAccountLocks(perAccount, total int) *accountLocks {
	return &accountLocks{m: map[model.ID]*accountLock{}, perAccount: perAccount, total: total}
}

// ref returns the account's lock with a reference taken. l.mu is held.
func (l *accountLocks) ref(id model.ID) *accountLock {
	a := l.m[id]
	if a == nil {
		a = &accountLock{changed: make(chan struct{})}
		l.m[id] = a
	}
	a.refs++
	return a
}

// unref drops a reference, and the entry with the last one. l.mu is held.
func (l *accountLocks) unref(id model.ID, a *accountLock) {
	if a.refs--; a.refs == 0 {
		delete(l.m, id)
	}
}

// wake lets every waiter recheck the lock. l.mu is held.
func (a *accountLock) wake() {
	close(a.changed)
	a.changed = make(chan struct{})
}

// wait blocks until a changes or ctx ends. l.mu is held on entry and on
// return.
func (l *accountLocks) wait(ctx context.Context, a *accountLock) error {
	ch := a.changed
	l.mu.Unlock()
	defer l.mu.Lock()
	select {
	case <-ch:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// lock takes the account's write lock and returns its release. It fails
// with errBusy when too many writers wait already, and with ctx's error
// when ctx ends first.
func (l *accountLocks) lock(ctx context.Context, id model.ID) (func(), error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	a := l.ref(id)
	if a.writer || a.readers > 0 {
		if a.writers >= l.perAccount || l.waiting >= l.total {
			l.unref(id, a)
			return nil, errBusy
		}
		a.writers++
		l.waiting++
		var err error
		for err == nil && (a.writer || a.readers > 0) {
			err = l.wait(ctx, a)
		}
		a.writers--
		l.waiting--
		if err != nil {
			// Readers held back by this writer may go now.
			a.wake()
			l.unref(id, a)
			return nil, err
		}
	}
	a.writer = true
	return func() {
		l.mu.Lock()
		defer l.mu.Unlock()
		a.writer = false
		a.wake()
		l.unref(id, a)
	}, nil
}

// rlock takes the account's read lock and returns its release. It fails
// with ctx's error when ctx ends first.
func (l *accountLocks) rlock(ctx context.Context, id model.ID) (func(), error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	a := l.ref(id)
	var err error
	for err == nil && (a.writer || a.writers > 0) {
		err = l.wait(ctx, a)
	}
	if err != nil {
		l.unref(id, a)
		return nil, err
	}
	a.readers++
	return func() {
		l.mu.Lock()
		defer l.mu.Unlock()
		if a.readers--; a.readers == 0 {
			a.wake()
		}
		l.unref(id, a)
	}, nil
}
