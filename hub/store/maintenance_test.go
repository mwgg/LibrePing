package store

import (
	"context"
	"testing"

	"github.com/mwgg/libreping/pkg/identity"
	"github.com/mwgg/libreping/pkg/protocol"
)

// TestMaintenanceReplayRejected mirrors the subscription anti-replay guarantee:
// after a delete (tombstone), replaying the earlier signed active window must
// NOT bring it back, because the tombstone has a newer UpdatedMS.
func TestMaintenanceReplayRejected(t *testing.T) {
	ctx := context.Background()
	owner, _ := identity.Generate()
	m := NewMemMaintenance()

	active := protocol.SignMaintenanceWindow(owner, protocol.MaintenanceWindow{
		CheckID: "chk1", StartMS: 1000, EndMS: 2000, UpdatedMS: 100,
	})
	if err := m.Upsert(ctx, active); err != nil {
		t.Fatal(err)
	}
	if got, _ := m.ListActive(ctx); len(got) != 1 {
		t.Fatalf("expected 1 active window, got %d", len(got))
	}

	// Delete it (newer UpdatedMS tombstone).
	tomb := protocol.SignMaintenanceWindow(owner, protocol.MaintenanceWindow{
		CheckID: "chk1", StartMS: 1000, EndMS: 2000, UpdatedMS: 200, Deleted: true,
	})
	if err := m.Upsert(ctx, tomb); err != nil {
		t.Fatal(err)
	}
	if got, _ := m.ListActive(ctx); len(got) != 0 {
		t.Fatalf("expected 0 active after delete, got %d", len(got))
	}

	// Replay the ORIGINAL signed active record.
	if err := m.Upsert(ctx, active); err != nil {
		t.Fatal(err)
	}
	if got, _ := m.ListActive(ctx); len(got) != 0 {
		t.Fatalf("replayed stale window resurrected a deleted one: %d active", len(got))
	}

	// The tombstone is included in anti-entropy so the delete propagates.
	gossip, _ := m.ListForGossip(ctx)
	if len(gossip) != 1 || !gossip[0].Window.Deleted {
		t.Fatalf("expected tombstone in gossip set, got %v", gossip)
	}
}

// TestMaintenanceNewerUpdateWins confirms a genuinely newer edit is applied and
// keeps the same key (same start), and that IntervalsForCheck reflects it.
func TestMaintenanceNewerUpdateWins(t *testing.T) {
	ctx := context.Background()
	owner, _ := identity.Generate()
	m := NewMemMaintenance()

	_ = m.Upsert(ctx, protocol.SignMaintenanceWindow(owner, protocol.MaintenanceWindow{CheckID: "chk1", StartMS: 1000, EndMS: 2000, UpdatedMS: 100}))
	_ = m.Upsert(ctx, protocol.SignMaintenanceWindow(owner, protocol.MaintenanceWindow{CheckID: "chk1", StartMS: 1000, EndMS: 5000, UpdatedMS: 150}))

	ivs, _ := m.IntervalsForCheck(ctx, "chk1")
	if len(ivs) != 1 || ivs[0].EndMS != 5000 {
		t.Fatalf("newer edit did not win: %v", ivs)
	}
	// A distinct start is a separate window.
	_ = m.Upsert(ctx, protocol.SignMaintenanceWindow(owner, protocol.MaintenanceWindow{CheckID: "chk1", StartMS: 9000, EndMS: 9500, UpdatedMS: 100}))
	if ivs, _ := m.IntervalsForCheck(ctx, "chk1"); len(ivs) != 2 {
		t.Fatalf("expected 2 distinct windows, got %d", len(ivs))
	}
}

// TestMaintenanceExpiryPruned confirms an expired window is dropped from listings.
func TestMaintenanceExpiryPruned(t *testing.T) {
	ctx := context.Background()
	owner, _ := identity.Generate()
	m := NewMemMaintenance()

	old := nowMS
	defer func() { nowMS = old }()
	nowMS = func() int64 { return 10_000 }

	_ = m.Upsert(ctx, protocol.SignMaintenanceWindow(owner, protocol.MaintenanceWindow{CheckID: "chk1", StartMS: 1000, EndMS: 2000, ExpiryMS: 5000, UpdatedMS: 100}))
	if got, _ := m.ListForGossip(ctx); len(got) != 0 {
		t.Fatalf("expired window should be pruned, got %d", len(got))
	}
}
