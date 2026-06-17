// Package outbox retains results a non-holder home hub submitted but does not
// itself store, so a submitted result is never silently lost when no shard
// holder happened to receive the gossip (gossipsub only reaches peers already
// in that shard's topic mesh). It is a bounded in-memory ring: the hub's
// anti-entropy loop re-broadcasts and re-pushes these entries to the shard
// holders until they age out, by which point a holder has either acknowledged
// them (via direct push) or seen them over gossip.
package outbox

import (
	"sync"
	"time"

	"github.com/mwgg/libreping/pkg/protocol"
)

type item struct {
	sr protocol.SignedResult
	at time.Time
}

// Outbox is a bounded, age-limited, concurrency-safe buffer of pending results.
type Outbox struct {
	mu     sync.Mutex
	items  []item
	maxN   int
	maxAge time.Duration
	now    func() time.Time
}

// New returns an outbox bounded to maxN entries and maxAge age.
func New(maxN int, maxAge time.Duration) *Outbox {
	if maxN <= 0 {
		maxN = 2048
	}
	return &Outbox{maxN: maxN, maxAge: maxAge, now: time.Now}
}

// Add records a result, evicting the oldest if the ring is full.
func (o *Outbox) Add(sr protocol.SignedResult) {
	if o == nil {
		return
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	o.items = append(o.items, item{sr: sr, at: o.now()})
	if len(o.items) > o.maxN {
		o.items = o.items[len(o.items)-o.maxN:]
	}
}

// Recent returns the entries still within the age window, pruning expired ones.
func (o *Outbox) Recent() []protocol.SignedResult {
	if o == nil {
		return nil
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	cutoff := o.now().Add(-o.maxAge)
	kept := o.items[:0]
	out := make([]protocol.SignedResult, 0, len(o.items))
	for _, it := range o.items {
		if it.at.Before(cutoff) {
			continue
		}
		kept = append(kept, it)
		out = append(out, it.sr)
	}
	o.items = kept
	return out
}
