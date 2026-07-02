package api

import (
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

// bucketTTL is how long an idle bucket is retained before the sweeper drops it.
// A bucket that has been idle this long is fully refilled to max anyway (the
// refill-to-full time of every limiter here is far under a minute), so evicting
// it loses no rate-limiting state — a returning client gets an identical fresh
// bucket. The TTL therefore only bounds memory; it never weakens the limit.
const bucketTTL = 10 * time.Minute

// sweepInterval is how often (at most) allow prunes idle buckets. Pruning is
// opportunistic — piggy-backed on request handling under the same lock — so
// there is no background goroutine to manage.
const sweepInterval = time.Minute

// maxBuckets caps the map size so an attacker cycling distinct client keys
// (even real, un-spoofable source IPs from a botnet) can't grow it without
// bound. When full, the least-recently-seen bucket is evicted to admit a new
// one — evicting an idle bucket is safe (see bucketTTL), and evicting the
// least-recently-seen approximates that under a flood.
const maxBuckets = 8192

// ipRateLimiter caps how often a single client IP may call a rate-limited
// endpoint. Different endpoint classes (write mutations, result submission,
// holder reads) get their own instance with their own rate, since their
// legitimate call volumes differ by orders of magnitude. It is a coarse abuse
// brake, not a fairness scheduler.
type ipRateLimiter struct {
	mu           sync.Mutex
	buckets      map[string]*ipBucket
	max          float64
	refillPerSec float64
	// trustProxy gates whether X-Forwarded-For / X-Real-IP are honored when
	// deriving the client key. See clientIP for the security rationale.
	trustProxy bool
	lastSweep  time.Time
	now        func() time.Time
}

type ipBucket struct {
	tokens float64
	last   time.Time
}

// newIPRateLimiter allows up to burst requests, refilling at perMinute/60 per
// second. perMinute <= 0 disables limiting (allow always returns true).
// trustProxy is passed through to clientIP.
func newIPRateLimiter(perMinute, burst int, trustProxy bool) *ipRateLimiter {
	if perMinute <= 0 {
		return nil
	}
	if burst < 1 {
		burst = 1
	}
	return &ipRateLimiter{
		buckets:      map[string]*ipBucket{},
		max:          float64(burst),
		refillPerSec: float64(perMinute) / 60.0,
		trustProxy:   trustProxy,
		now:          time.Now,
	}
}

// allow reports whether a request from ip is permitted, consuming a token. It
// also opportunistically prunes idle buckets and enforces the size cap, all
// under the same lock, so the map cannot grow without bound.
func (l *ipRateLimiter) allow(ip string) bool {
	if l == nil {
		return true
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	if now.Sub(l.lastSweep) >= sweepInterval {
		l.pruneLocked(now)
		l.lastSweep = now
	}
	b, ok := l.buckets[ip]
	if !ok {
		if len(l.buckets) >= maxBuckets {
			l.evictOldestLocked()
		}
		b = &ipBucket{tokens: l.max, last: now}
		l.buckets[ip] = b
	}
	elapsed := now.Sub(b.last).Seconds()
	b.last = now
	b.tokens += elapsed * l.refillPerSec
	if b.tokens > l.max {
		b.tokens = l.max
	}
	if b.tokens >= 1 {
		b.tokens--
		return true
	}
	return false
}

// pruneLocked drops buckets idle longer than bucketTTL. Caller holds l.mu.
func (l *ipRateLimiter) pruneLocked(now time.Time) {
	for ip, b := range l.buckets {
		if now.Sub(b.last) >= bucketTTL {
			delete(l.buckets, ip)
		}
	}
}

// evictOldestLocked removes the least-recently-seen bucket to make room when the
// map is at its cap. Caller holds l.mu.
func (l *ipRateLimiter) evictOldestLocked() {
	var oldestIP string
	var oldest time.Time
	first := true
	for ip, b := range l.buckets {
		if first || b.last.Before(oldest) {
			oldestIP, oldest, first = ip, b.last, false
		}
	}
	if !first {
		delete(l.buckets, oldestIP)
	}
}

// limit wraps h so requests over the rate are answered 429.
func (l *ipRateLimiter) limit(h http.HandlerFunc) http.HandlerFunc {
	if l == nil {
		return h
	}
	return func(w http.ResponseWriter, r *http.Request) {
		if !l.allow(clientIP(r, l.trustProxy)) {
			http.Error(w, "rate limit exceeded", http.StatusTooManyRequests)
			return
		}
		h(w, r)
	}
}

// clientIP extracts the client identity used as the rate-limit key.
//
// Security rationale: X-Forwarded-For / X-Real-IP are client-supplied and
// trivially spoofable. If we honored them unconditionally, a direct
// (non-proxied) attacker could send a random XFF per request, get a fresh
// full-burst bucket every time, and void the limit entirely — while also
// growing the bucket map without bound. So forwarding headers are honored ONLY
// when the operator has asserted (TRUST_PROXY_HEADERS) that a trusted reverse
// proxy sits in front and rewrites them. When it does, we read the LAST hop —
// the entry that proxy appended, i.e. the address that actually connected to
// it — not the spoofable client-supplied first hop. With the trust flag off
// (the default), the un-spoofable connection peer (r.RemoteAddr host) is used.
func clientIP(r *http.Request, trustProxy bool) string {
	if trustProxy {
		if xrip := strings.TrimSpace(r.Header.Get("X-Real-IP")); xrip != "" {
			return xrip
		}
		if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
			parts := strings.Split(xff, ",")
			return strings.TrimSpace(parts[len(parts)-1])
		}
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}
