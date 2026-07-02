package store

import (
	"context"
	"testing"
	"time"

	"github.com/mwgg/libreping/pkg/identity"
	"github.com/mwgg/libreping/pkg/protocol"
)

// TestAlertMaxTTLClamp proves an alert rule with ExpiryMS == 0 ("forever") is
// still pruned at receivedAt + maxOwnerRecordTTL, mirroring the subscription cap.
func TestAlertMaxTTLClamp(t *testing.T) {
	ctx := context.Background()
	owner, _ := identity.Generate()
	alerts := NewMemAlerts()

	base := int64(1_000_000_000_000)
	nowMS = func() int64 { return base }
	defer func() { nowMS = func() int64 { return time.Now().UnixMilli() } }()

	_ = alerts.Upsert(ctx, protocol.SignAlertRule(owner, protocol.AlertRule{
		CheckID: "chk1", Channel: protocol.AlertWebhook, DestHash: "d1",
		FailLocations: 1, ForSeconds: 60, ExpiryMS: 0, UpdatedMS: base,
	}))
	if got, _ := alerts.ListActive(ctx); len(got) != 1 {
		t.Fatalf("expected rule live within its TTL, got %d", len(got))
	}

	nowMS = func() int64 { return base + maxOwnerRecordTTL + 1 }
	if got, _ := alerts.ListActive(ctx); len(got) != 0 {
		t.Fatalf("0-expiry rule not pruned at max TTL, got %d", len(got))
	}
}

// TestAlertFutureUpdatedMSRejected proves a rule stamped implausibly far in the
// future is refused at ingest so it can't lock itself against later edits.
func TestAlertFutureUpdatedMSRejected(t *testing.T) {
	ctx := context.Background()
	owner, _ := identity.Generate()
	alerts := NewMemAlerts()

	base := int64(1_000_000_000_000)
	nowMS = func() int64 { return base }
	defer func() { nowMS = func() int64 { return time.Now().UnixMilli() } }()

	_ = alerts.Upsert(ctx, protocol.SignAlertRule(owner, protocol.AlertRule{
		CheckID: "chk1", Channel: protocol.AlertWebhook, DestHash: "d1",
		FailLocations: 1, ForSeconds: 60, UpdatedMS: base + maxOwnerClockSkewMS + 1,
	}))
	if got, _ := alerts.ListForGossip(ctx); len(got) != 0 {
		t.Fatalf("far-future UpdatedMS rule was accepted, got %d", len(got))
	}
}
