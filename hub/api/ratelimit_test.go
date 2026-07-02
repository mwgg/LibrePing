package api

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// TestClientIPIgnoresXFFWhenUntrusted proves the spoof fix: with the trust flag
// off (the default) a forged X-Forwarded-For / X-Real-IP is ignored and the
// connection peer is used, so an attacker can't mint a fresh bucket per request.
func TestClientIPIgnoresXFFWhenUntrusted(t *testing.T) {
	r := httptest.NewRequest(http.MethodPost, "/api/v1/results", nil)
	r.RemoteAddr = "203.0.113.7:5555"
	r.Header.Set("X-Forwarded-For", "1.2.3.4")
	r.Header.Set("X-Real-IP", "5.6.7.8")

	if got := clientIP(r, false); got != "203.0.113.7" {
		t.Fatalf("untrusted clientIP = %q, want the connection peer 203.0.113.7", got)
	}
	// When trusted, the LAST forwarded hop is honored, not the spoofable first.
	r.Header.Del("X-Real-IP")
	r.Header.Set("X-Forwarded-For", "1.1.1.1, 9.9.9.9")
	if got := clientIP(r, true); got != "9.9.9.9" {
		t.Fatalf("trusted clientIP = %q, want last hop 9.9.9.9", got)
	}
}

// TestSpoofedXFFDoesNotEscapeLimit proves that under the default (untrusted)
// config a client varying X-Forwarded-For every request is still limited,
// because the bucket is keyed by the un-spoofable RemoteAddr.
func TestSpoofedXFFDoesNotEscapeLimit(t *testing.T) {
	l := newIPRateLimiter(60, 3, false) // burst 3
	allowed := 0
	for i := 0; i < 20; i++ {
		r := httptest.NewRequest(http.MethodGet, "/", nil)
		r.RemoteAddr = "198.51.100.9:4000"
		r.Header.Set("X-Forwarded-For", randIP(i)) // different every request
		if l.allow(clientIP(r, l.trustProxy)) {
			allowed++
		}
	}
	if allowed > 3 {
		t.Fatalf("spoofed XFF let %d requests through; burst is 3 (limit voided)", allowed)
	}
}

func randIP(i int) string {
	return "10.0." + itoa(i/256) + "." + itoa(i%256)
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}

// TestBucketMapEvictsIdle proves the sweeper prunes idle buckets so the map
// can't grow without bound from distinct client keys over time.
func TestBucketMapEvictsIdle(t *testing.T) {
	l := newIPRateLimiter(60, 3, false)
	base := time.Unix(0, 0)
	cur := base
	l.now = func() time.Time { return cur }

	// Seed many distinct keys.
	for i := 0; i < 100; i++ {
		l.allow(randIP(i))
	}
	if got := len(l.buckets); got != 100 {
		t.Fatalf("expected 100 buckets, got %d", got)
	}
	// Advance well past bucketTTL and touch one new key; the sweep must run and
	// drop all the now-idle buckets, keeping only the fresh one.
	cur = base.Add(bucketTTL + sweepInterval + time.Second)
	l.allow("new-key")
	if got := len(l.buckets); got != 1 {
		t.Fatalf("after TTL sweep expected 1 bucket, got %d", got)
	}
}

// TestBucketMapCapBounded proves that even with more distinct keys than the cap
// (all seen at once, so TTL pruning can't help) the map stays bounded via
// oldest-eviction.
func TestBucketMapCapBounded(t *testing.T) {
	l := newIPRateLimiter(60, 3, false)
	base := time.Unix(0, 0)
	// Advance a nanosecond per key so "oldest" is well-defined, but stay within a
	// single sweep window so only the cap (not TTL) bounds the map.
	for i := 0; i < maxBuckets+500; i++ {
		cur := base.Add(time.Duration(i) * time.Nanosecond)
		l.now = func() time.Time { return cur }
		l.allow("k" + itoa(i))
	}
	if got := len(l.buckets); got > maxBuckets {
		t.Fatalf("bucket map grew to %d, exceeds cap %d", got, maxBuckets)
	}
}

// TestResultLimiterGenerousBurst proves POST /results admits a generous burst
// (a busy multi-probe node behind one IP is not throttled at the low write
// rate) yet is not unlimited.
func TestResultLimiterGenerousBurst(t *testing.T) {
	// Default result rate (6000/min) → burst 6000/4+1 = 1501.
	l := newIPRateLimiter(6000, 6000/4+1, false)
	allowed := 0
	for i := 0; i < 2000; i++ {
		if l.allow("192.0.2.50") {
			allowed++
		}
	}
	if allowed < 1000 {
		t.Fatalf("result limiter admitted only %d of a 2000 burst; too tight for a probe fleet", allowed)
	}
	if allowed == 2000 {
		t.Fatal("result limiter admitted the entire 2000 burst; not capping abuse")
	}
}

// TestHolderPushBounded proves the fan-out semaphore is bounded by construction,
// so a submission flood can't explode goroutines.
func TestHolderPushBounded(t *testing.T) {
	srv, _ := newTestServer()
	if got := cap(srv.pushSem); got != maxConcurrentHolderPush {
		t.Fatalf("push semaphore cap = %d, want %d", got, maxConcurrentHolderPush)
	}
}
