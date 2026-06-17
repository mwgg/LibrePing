package reporter

import (
	"math"
	"sync"
	"time"
)

// tokenBucket is a simple rate limiter capping check executions per minute. It
// is the probe operator's hard ceiling: regardless of how much work a hub
// assigns, the probe never runs checks faster than this.
type tokenBucket struct {
	mu           sync.Mutex
	tokens       float64
	max          float64
	refillPerSec float64
	last         time.Time
	now          func() time.Time
}

// newTokenBucket caps to perMinute executions. perMinute <= 0 means unlimited
// (returns nil, and allow() on a nil bucket always permits).
func newTokenBucket(perMinute int) *tokenBucket {
	if perMinute <= 0 {
		return nil
	}
	now := time.Now()
	return &tokenBucket{
		tokens:       float64(perMinute),
		max:          float64(perMinute),
		refillPerSec: float64(perMinute) / 60.0,
		last:         now,
		now:          time.Now,
	}
}

// allow reports whether one execution is permitted right now, consuming a token
// if so.
func (b *tokenBucket) allow() bool {
	if b == nil {
		return true
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	now := b.now()
	elapsed := now.Sub(b.last).Seconds()
	b.last = now
	b.tokens = math.Min(b.max, b.tokens+elapsed*b.refillPerSec)
	if b.tokens >= 1 {
		b.tokens--
		return true
	}
	return false
}
