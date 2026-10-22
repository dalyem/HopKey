package server

import (
	"context"
	"net/netip"
	"sync"
	"time"
)

// MiB is 1,048,576 bytes (R9).
const MiB = 1 << 20

// Limits are the R8, R9 and R14 limits. DefaultLimits returns the contract
// values; tests shrink some of them.
type Limits struct {
	MaxBody         int64 // request body, except signup
	MaxSignupBody   int64
	MaxWireResponse int // a wire measured as its canonical singleton log response
	MaxObject       int // len(JCS(envelope)) of one referenced object
	MaxPageEntries  int
	MaxPageBytes    int
	MaxDepth        int // JSON nesting depth of a request body
	MaxSignupWires  int
	MaxOps          int // per wire
	MaxObjects      int // supplied objects per wire

	MaxPollWait        time.Duration
	PollsPerCredential int
	PollsPerAccount    int
	PollsPerIP         int
	PollsPerProcess    int

	ChallengesPerDevice     int
	ChallengesPerCapability int
	ChallengesPerProcess    int

	ValidationJobs  int
	ValidationQueue int
	SignupJobs      int
	SignupQueue     int

	RequestDeadline time.Duration
	PollDeadline    time.Duration
	// AdmitWrite bounds how long an admitted log response may take to be
	// written. The response holds its account's admission lock meanwhile,
	// so this is the longest a slow reader can delay its own account's
	// credential-invalidating commits (R2).
	AdmitWrite time.Duration

	// QuotaBytes is the default account storage quota (R13).
	QuotaBytes int64
}

// DefaultLimits returns the limits of the phase 2 contract (R8, R9, R13,
// R14).
func DefaultLimits() Limits {
	return Limits{
		MaxBody:         4 * MiB,
		MaxSignupBody:   64 * MiB,
		MaxWireResponse: 4 * MiB,
		MaxObject:       1 * MiB,
		MaxPageEntries:  256,
		MaxPageBytes:    4 * MiB,
		MaxDepth:        32,
		MaxSignupWires:  16384,
		MaxOps:          8192,
		MaxObjects:      16384,

		MaxPollWait:        55 * time.Second,
		PollsPerCredential: 4,
		PollsPerAccount:    16,
		PollsPerIP:         64,
		PollsPerProcess:    4096,

		ChallengesPerDevice:     16,
		ChallengesPerCapability: 16,
		ChallengesPerProcess:    10000,

		ValidationJobs:  4,
		ValidationQueue: 16,
		SignupJobs:      2,
		SignupQueue:     8,

		RequestDeadline: 30 * time.Second,
		PollDeadline:    60 * time.Second,
		AdmitWrite:      10 * time.Second,

		QuotaBytes: 256 * MiB,
	}
}

// Rate is n requests per period, as a token bucket of capacity n.
type Rate struct {
	N   int
	Per time.Duration
}

// Rates are the R14 buckets.
type Rates struct {
	PreloginIP    Rate // per IP
	PreloginEmail Rate // per normalized email
	LoginIP       Rate // login and recover, each its own bucket
	LoginAccount  Rate // per submitted account ID
	IP            Rate // every other endpoint, per IP
	Account       Rate // every other endpoint, per authenticated account
	Device        Rate // auth/challenge, per (account ID, device ID)
}

// DefaultRates returns the R14 rates.
func DefaultRates() Rates {
	return Rates{
		PreloginIP:    Rate{10, time.Minute},
		PreloginEmail: Rate{20, time.Hour},
		LoginIP:       Rate{10, time.Minute},
		LoginAccount:  Rate{20, time.Hour},
		IP:            Rate{60, time.Minute},
		Account:       Rate{60, time.Minute},
		Device:        Rate{60, time.Minute},
	}
}

// rateLimiter holds token buckets by scope and key. Its key storage is
// bounded, and it never forgets a bucket that is still refilling, since
// that would hand the key a fresh bucket. When the store is full, buckets
// that have refilled completely (and so carry no information) are dropped.
// If none has, a new key shares its scope's overflow bucket, at the same
// rate. The keys on the overflow bucket are not recorded, so any of them
// may be the next new key: every key without a bucket of its own stays on
// the overflow bucket until it has refilled completely, even when the
// store has room again. The overflow is never more permissive than a
// bucket of its own, and a full store cannot be used to escape a limit or
// to shed debt.
type rateLimiter struct {
	mu       sync.Mutex
	now      func() time.Time
	max      int
	buckets  map[string]*bucket
	overflow map[string]*bucket // by scope; there are few scopes
	// nextFull is the earliest time a stored bucket can have refilled, so
	// a full store is not rescanned on every new key before then.
	nextFull time.Time
}

type bucket struct {
	tokens float64
	last   time.Time
	rate   Rate
}

func newRateLimiter(now func() time.Time, max int) *rateLimiter {
	return &rateLimiter{now: now, max: max, buckets: map[string]*bucket{}, overflow: map[string]*bucket{}}
}

func (b *bucket) refill(now time.Time) {
	if el := now.Sub(b.last); el > 0 {
		b.tokens += float64(b.rate.N) * el.Seconds() / b.rate.Per.Seconds()
		if b.tokens > float64(b.rate.N) {
			b.tokens = float64(b.rate.N)
		}
	}
	b.last = now
}

// fullAt is when b will have refilled completely.
func (b *bucket) fullAt() time.Time {
	missing := float64(b.rate.N) - b.tokens
	return b.last.Add(time.Duration(missing / float64(b.rate.N) * float64(b.rate.Per)))
}

// allow takes one token from the bucket of key in scope, created full at
// rate r. scope names the route and bucket kind, such as
// "POST /v1/login|account".
func (l *rateLimiter) allow(scope, key string, r Rate) bool {
	if r.N <= 0 {
		return true
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	k := scope + "|" + key
	b := l.buckets[k]
	if b == nil {
		if o := l.overflow[scope]; o != nil {
			o.refill(now)
			if o.tokens < float64(o.rate.N) {
				b = o
			} else {
				delete(l.overflow, scope)
			}
		}
	}
	if b == nil {
		if len(l.buckets) >= l.max {
			l.evict(now)
		}
		b = &bucket{tokens: float64(r.N), last: now, rate: r}
		if len(l.buckets) < l.max {
			l.buckets[k] = b
		} else {
			l.overflow[scope] = b
		}
	}
	b.refill(now)
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

// evict drops the buckets that have refilled completely. When it finds
// none, it records when the first one will have.
func (l *rateLimiter) evict(now time.Time) {
	if now.Before(l.nextFull) {
		return
	}
	var next time.Time
	for k, b := range l.buckets {
		b.refill(now)
		if b.tokens >= float64(b.rate.N) {
			delete(l.buckets, k)
			continue
		}
		if t := b.fullAt(); next.IsZero() || t.Before(next) {
			next = t
		}
	}
	if len(l.buckets) >= l.max {
		l.nextFull = next
	}
}

// queue bounds concurrent jobs: jobs run at once, and up to queue more
// wait. A caller that finds the queue full is refused at once (R14).
type queue struct {
	slots   chan struct{}
	mu      sync.Mutex
	waiting int
	max     int
}

func newQueue(jobs, waiting int) *queue {
	return &queue{slots: make(chan struct{}, jobs), max: waiting}
}

// acquire returns a release func, or false when the queue is full or ctx
// ends while waiting.
func (q *queue) acquire(ctx context.Context) (func(), bool) {
	release := func() { <-q.slots }
	select {
	case q.slots <- struct{}{}:
		return release, true
	default:
	}
	q.mu.Lock()
	if q.waiting >= q.max {
		q.mu.Unlock()
		return nil, false
	}
	q.waiting++
	q.mu.Unlock()
	defer func() {
		q.mu.Lock()
		q.waiting--
		q.mu.Unlock()
	}()
	select {
	case q.slots <- struct{}{}:
		return release, true
	case <-ctx.Done():
		return nil, false
	}
}

// pollLimiter counts concurrent long-polls per credential, account, IP and
// process (R8).
type pollLimiter struct {
	mu    sync.Mutex
	lim   Limits
	cred  map[string]int
	acct  map[string]int
	ip    map[string]int
	total int
}

func newPollLimiter(lim Limits) *pollLimiter {
	return &pollLimiter{lim: lim, cred: map[string]int{}, acct: map[string]int{}, ip: map[string]int{}}
}

func (p *pollLimiter) acquire(cred, acct, ip string) (func(), bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.total >= p.lim.PollsPerProcess || p.cred[cred] >= p.lim.PollsPerCredential ||
		p.acct[acct] >= p.lim.PollsPerAccount || p.ip[ip] >= p.lim.PollsPerIP {
		return nil, false
	}
	p.total++
	p.cred[cred]++
	p.acct[acct]++
	p.ip[ip]++
	return func() {
		p.mu.Lock()
		defer p.mu.Unlock()
		p.total--
		dec(p.cred, cred)
		dec(p.acct, acct)
		dec(p.ip, ip)
	}, true
}

func dec(m map[string]int, k string) {
	if m[k]--; m[k] <= 0 {
		delete(m, k)
	}
}

// ipKey is the rate-limit key of a client address: the address itself for
// IPv4 and its /64 for IPv6, since one host usually holds a whole /64.
func ipKey(a netip.Addr) string {
	if a.Is4() || !a.IsValid() {
		return a.String()
	}
	p, err := a.Prefix(64)
	if err != nil {
		return a.String()
	}
	return p.String()
}
