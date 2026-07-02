package store

import (
	"context"
	"testing"
	"time"

	"github.com/mwgg/libreping/pkg/identity"
	"github.com/mwgg/libreping/pkg/protocol"
)

// TestSubscriptionReplayRejected is the core MEDIUM-7 regression: after a delete
// (tombstone), replaying the earlier signed active subscription must NOT bring
// it back, because the tombstone has a newer UpdatedMS.
func TestSubscriptionReplayRejected(t *testing.T) {
	ctx := context.Background()
	owner, _ := identity.Generate()
	subs := NewMemSubscriptions()

	active := protocol.SignSubscription(owner, protocol.Subscription{
		CheckID: "chk1", IntervalSeconds: 60, ExpiryMS: 0, UpdatedMS: 100,
	})
	if err := subs.Upsert(ctx, active); err != nil {
		t.Fatal(err)
	}
	if got, _ := subs.ListActive(ctx); len(got) != 1 {
		t.Fatalf("expected 1 active subscription, got %d", len(got))
	}

	// User deletes it (newer UpdatedMS tombstone).
	tomb := protocol.SignSubscription(owner, protocol.Subscription{
		CheckID: "chk1", ExpiryMS: 0, UpdatedMS: 200, Deleted: true,
	})
	if err := subs.Upsert(ctx, tomb); err != nil {
		t.Fatal(err)
	}
	if got, _ := subs.ListActive(ctx); len(got) != 0 {
		t.Fatalf("expected 0 active after delete, got %d", len(got))
	}

	// A malicious peer replays the ORIGINAL signed active record.
	if err := subs.Upsert(ctx, active); err != nil {
		t.Fatal(err)
	}
	if got, _ := subs.ListActive(ctx); len(got) != 0 {
		t.Fatalf("replayed stale subscription resurrected a deleted one: %d active", len(got))
	}

	// The tombstone is included in anti-entropy so the delete propagates.
	gossip, _ := subs.ListForGossip(ctx)
	if len(gossip) != 1 || !gossip[0].Subscription.Deleted {
		t.Fatalf("expected tombstone in gossip set, got %v", gossip)
	}
}

// TestSubscriptionMaxTTLClamp proves a record with ExpiryMS == 0 ("forever") is
// still pruned at receivedAt + maxOwnerRecordTTL, so a Sybil can't gossip an
// immortal record every hub stores and re-broadcasts forever.
func TestSubscriptionMaxTTLClamp(t *testing.T) {
	ctx := context.Background()
	owner, _ := identity.Generate()
	subs := NewMemSubscriptions()

	base := int64(1_000_000_000_000)
	nowMS = func() int64 { return base }
	defer func() { nowMS = func() int64 { return time.Now().UnixMilli() } }()

	// Accepted at `base`, with no signed expiry.
	_ = subs.Upsert(ctx, protocol.SignSubscription(owner, protocol.Subscription{
		CheckID: "chk1", IntervalSeconds: 60, ExpiryMS: 0, UpdatedMS: base,
	}))
	if got, _ := subs.ListActive(ctx); len(got) != 1 {
		t.Fatalf("expected the record live within its TTL, got %d", len(got))
	}

	// Advance past receivedAt + maxOwnerRecordTTL: it must be pruned despite
	// ExpiryMS == 0.
	nowMS = func() int64 { return base + maxOwnerRecordTTL + 1 }
	if got, _ := subs.ListActive(ctx); len(got) != 0 {
		t.Fatalf("0-expiry record not pruned at max TTL, got %d", len(got))
	}
}

// TestSubscriptionFutureUpdatedMSRejected proves a record stamped implausibly far
// in the future is refused at ingest, so it can't lock itself against later
// legitimate edits (which use the real clock).
func TestSubscriptionFutureUpdatedMSRejected(t *testing.T) {
	ctx := context.Background()
	owner, _ := identity.Generate()
	subs := NewMemSubscriptions()

	base := int64(1_000_000_000_000)
	nowMS = func() int64 { return base }
	defer func() { nowMS = func() int64 { return time.Now().UnixMilli() } }()

	_ = subs.Upsert(ctx, protocol.SignSubscription(owner, protocol.Subscription{
		CheckID: "chk1", IntervalSeconds: 60, UpdatedMS: base + maxOwnerClockSkewMS + 1,
	}))
	if got, _ := subs.ListForGossip(ctx); len(got) != 0 {
		t.Fatalf("far-future UpdatedMS record was accepted, got %d", len(got))
	}

	// A record within the skew allowance is accepted normally.
	_ = subs.Upsert(ctx, protocol.SignSubscription(owner, protocol.Subscription{
		CheckID: "chk2", IntervalSeconds: 60, UpdatedMS: base + 1000,
	}))
	if got, _ := subs.ListActive(ctx); len(got) != 1 {
		t.Fatalf("in-skew record was rejected, got %d", len(got))
	}
}

// TestSubscriptionNewerUpdateWins confirms a genuinely newer edit is applied.
func TestSubscriptionNewerUpdateWins(t *testing.T) {
	ctx := context.Background()
	owner, _ := identity.Generate()
	subs := NewMemSubscriptions()

	_ = subs.Upsert(ctx, protocol.SignSubscription(owner, protocol.Subscription{CheckID: "chk1", IntervalSeconds: 60, UpdatedMS: 100}))
	_ = subs.Upsert(ctx, protocol.SignSubscription(owner, protocol.Subscription{CheckID: "chk1", IntervalSeconds: 30, UpdatedMS: 150}))

	got, _ := subs.ListActive(ctx)
	if len(got) != 1 || got[0].Subscription.IntervalSeconds != 30 {
		t.Fatalf("newer update did not win: %v", got)
	}
}
