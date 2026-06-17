package api

import (
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

// ipRateLimiter caps how often a single client IP may call the write endpoints
// (check/subscription/alert creation, probe registration). These endpoints
// accept attacker-controllable, gossiped, or capacity-affecting input, so an
// unbounded caller could flood the catalog, spawn probe-scan work, or churn the
// mesh. It is a coarse abuse brake, not a fairness scheduler.
type ipRateLimiter struct {
	mu           sync.Mutex
	buckets      map[string]*ipBucket
	max          float64
	refillPerSec float64
	now          func() time.Time
}

type ipBucket struct {
	tokens float64
	last   time.Time
}

// newIPRateLimiter allows up to burst requests, refilling at perMinute/60 per
// second. perMinute <= 0 disables limiting (allow always returns true).
func newIPRateLimiter(perMinute, burst int) *ipRateLimiter {
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
		now:          time.Now,
	}
}

// allow reports whether a request from ip is permitted, consuming a token.
func (l *ipRateLimiter) allow(ip string) bool {
	if l == nil {
		return true
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	b, ok := l.buckets[ip]
	if !ok {
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

// limit wraps h so requests over the rate are answered 429.
func (l *ipRateLimiter) limit(h http.HandlerFunc) http.HandlerFunc {
	if l == nil {
		return h
	}
	return func(w http.ResponseWriter, r *http.Request) {
		if !l.allow(clientIP(r)) {
			http.Error(w, "rate limit exceeded", http.StatusTooManyRequests)
			return
		}
		h(w, r)
	}
}

// clientIP extracts a best-effort client identity for rate limiting. It honours
// X-Forwarded-For's first hop (the dashboard nginx proxies the API) and falls
// back to the connection's remote address.
func clientIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		first, _, _ := strings.Cut(xff, ",")
		return strings.TrimSpace(first)
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}
