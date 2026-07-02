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

const (
	// maxOwnerRecordTTL bounds the effective lifetime of an owner-signed record
	// (subscription/alert), enforced internally at ingest and NOT by mutating the
	// signed bytes. A record with ExpiryMS == 0 ("forever") or a far-future
	// expiry is still pruned at receivedAt + maxOwnerRecordTTL. The dashboard
	// leases real records for ~7 days and renews them, so this cap (generous
	// relative to that) never lapses a live record, while a Sybil key can't gossip
	// a record every hub then stores and re-broadcasts forever.
	maxOwnerRecordTTL = int64(60) * dayMS
	// maxOwnerClockSkewMS bounds how far in the future an owner record's signed
	// UpdatedMS may be before it's rejected at ingest. UpdatedMS is a
	// last-writer-wins version stamp; a far-future value would lock the record
	// against every future legitimate update (which use the real clock), so a
	// record can't pin itself un-editable. Browsers sign with Date.now(), so a
	// day of allowance more than covers honest clock skew.
	maxOwnerClockSkewMS = int64(24 * 60 * 60 * 1000)
)

// effectiveExpiry is the internal pruning deadline for an owner record: the
// earlier of its signed expiry (0 = no expiry) and receivedAt + maxOwnerRecordTTL.
func effectiveExpiry(expiryMS, receivedMS int64) int64 {
	capped := receivedMS + maxOwnerRecordTTL
	if expiryMS > 0 && expiryMS < capped {
		return expiryMS
	}
	return capped
}

// futureUpdatedMS reports whether a record's signed UpdatedMS is implausibly far
// in the future (clock skew / an attempt to lock the record against updates).
func futureUpdatedMS(updatedMS, now int64) bool {
	return updatedMS > now+maxOwnerClockSkewMS
}

// storedSub pairs a signed subscription with the local time it was accepted, so
// pruning can enforce maxOwnerRecordTTL without mutating the signed record.
type storedSub struct {
	ss         protocol.SignedSubscription
	receivedMS int64
}

// MemSubscriptions is an in-memory SubscriptionStore.
type MemSubscriptions struct {
	mu   sync.Mutex
	subs map[string]storedSub
}

func NewMemSubscriptions() *MemSubscriptions {
	return &MemSubscriptions{subs: map[string]storedSub{}}
}

func (m *MemSubscriptions) Upsert(_ context.Context, ss protocol.SignedSubscription) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	now := nowMS()
	// Reject a record stamped implausibly far in the future so it can't lock
	// itself against later legitimate edits/tombstones (whose UpdatedMS is the
	// real clock).
	if futureUpdatedMS(ss.Subscription.UpdatedMS, now) {
		return nil
	}
	key := subKey(ss.Subscription)
	// Reject stale updates: only a strictly newer version supersedes. This is
	// what defeats replay — an old signed active record can't undo a newer
	// tombstone or edit because its UpdatedMS is not greater.
	if cur, ok := m.subs[key]; ok && ss.Subscription.UpdatedMS <= cur.ss.Subscription.UpdatedMS {
		return nil
	}
	m.subs[key] = storedSub{ss: ss, receivedMS: now} // tombstones are retained, not deleted
	return nil
}

func (m *MemSubscriptions) ListActive(_ context.Context) ([]protocol.SignedSubscription, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	now := nowMS()
	out := []protocol.SignedSubscription{}
	for key, st := range m.subs {
		if expiredSub(st, now) {
			delete(m.subs, key) // prune expired (active or tombstone)
			continue
		}
		if st.ss.Subscription.Deleted {
			continue
		}
		out = append(out, st.ss)
	}
	return out, nil
}

func (m *MemSubscriptions) ListForGossip(_ context.Context) ([]protocol.SignedSubscription, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	now := nowMS()
	out := []protocol.SignedSubscription{}
	for key, st := range m.subs {
		if expiredSub(st, now) {
			delete(m.subs, key)
			continue
		}
		out = append(out, st.ss)
	}
	return out, nil
}

// expiredSub reports whether a record has passed its effective expiry: the
// earlier of its signed ExpiryMS (0 = no signed expiry) and the internal
// receivedAt + maxOwnerRecordTTL cap, so a 0-expiry or far-future record is
// still pruned.
func expiredSub(st storedSub, now int64) bool {
	return effectiveExpiry(st.ss.Subscription.ExpiryMS, st.receivedMS) < now
}
