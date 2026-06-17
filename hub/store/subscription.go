package store

import (
	"context"
	"sync"
	"time"

	"github.com/mwgg/libreping/pkg/protocol"
)

// SubscriptionStore persists owner→check subscriptions. A subscription is keyed
// by (owner, check_id); a signed tombstone (Deleted) supersedes it.
//
// Records carry a signed UpdatedMS version stamp. Upsert applies an incoming
// record only if it is strictly newer than the stored one, and a delete is kept
// as a tombstone (not erased) until it expires — together these stop a peer from
// replaying an old signed active record to undo a later delete/edit.
type SubscriptionStore interface {
	Upsert(ctx context.Context, ss protocol.SignedSubscription) error
	// ListActive returns non-deleted, non-expired subscriptions.
	ListActive(ctx context.Context) ([]protocol.SignedSubscription, error)
	// ListForGossip returns non-expired records including tombstones, so
	// anti-entropy propagates deletes as well as live subscriptions.
	ListForGossip(ctx context.Context) ([]protocol.SignedSubscription, error)
}

func subKey(s protocol.Subscription) string { return s.Owner + "|" + s.CheckID }

// nowMS is overridable in tests.
var nowMS = func() int64 { return time.Now().UnixMilli() }

// MemSubscriptions is an in-memory SubscriptionStore.
type MemSubscriptions struct {
	mu   sync.Mutex
	subs map[string]protocol.SignedSubscription
}

func NewMemSubscriptions() *MemSubscriptions {
	return &MemSubscriptions{subs: map[string]protocol.SignedSubscription{}}
}

func (m *MemSubscriptions) Upsert(_ context.Context, ss protocol.SignedSubscription) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	key := subKey(ss.Subscription)
	// Reject stale updates: only a strictly newer version supersedes. This is
	// what defeats replay — an old signed active record can't undo a newer
	// tombstone or edit because its UpdatedMS is not greater.
	if cur, ok := m.subs[key]; ok && ss.Subscription.UpdatedMS <= cur.Subscription.UpdatedMS {
		return nil
	}
	m.subs[key] = ss // tombstones are retained, not deleted
	return nil
}

func (m *MemSubscriptions) ListActive(_ context.Context) ([]protocol.SignedSubscription, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	now := nowMS()
	out := []protocol.SignedSubscription{}
	for key, ss := range m.subs {
		if expiredSub(ss, now) {
			delete(m.subs, key) // prune expired (active or tombstone)
			continue
		}
		if ss.Subscription.Deleted {
			continue
		}
		out = append(out, ss)
	}
	return out, nil
}

func (m *MemSubscriptions) ListForGossip(_ context.Context) ([]protocol.SignedSubscription, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	now := nowMS()
	out := []protocol.SignedSubscription{}
	for key, ss := range m.subs {
		if expiredSub(ss, now) {
			delete(m.subs, key)
			continue
		}
		out = append(out, ss)
	}
	return out, nil
}

// expiredSub reports whether a record has passed its expiry. ExpiryMS == 0 means
// no expiry (kept until explicitly tombstoned).
func expiredSub(ss protocol.SignedSubscription, now int64) bool {
	return ss.Subscription.ExpiryMS > 0 && ss.Subscription.ExpiryMS < now
}
