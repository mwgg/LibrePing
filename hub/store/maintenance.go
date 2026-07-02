package store

import (
	"context"
	"sync"

	"github.com/mwgg/libreping/pkg/protocol"
)

// MaintenanceStore persists owner-signed maintenance windows (planned downtime)
// for checks. Keyed by (owner, check_id, start_ms); a signed tombstone (Deleted)
// supersedes it. Semantics mirror SubscriptionStore exactly:
//
// Records carry a signed UpdatedMS version stamp. Upsert applies an incoming
// record only if it is strictly newer than the stored one, and a delete is kept
// as a tombstone (not erased) until it expires — together these stop a peer from
// replaying an old signed active record to undo a later delete/edit.
type MaintenanceStore interface {
	Upsert(ctx context.Context, sm protocol.SignedMaintenanceWindow) error
	// ListActive returns non-deleted, non-expired windows (of any time range).
	ListActive(ctx context.Context) ([]protocol.SignedMaintenanceWindow, error)
	// ListForGossip returns non-expired records including tombstones, so
	// anti-entropy propagates deletes as well as live windows.
	ListForGossip(ctx context.Context) ([]protocol.SignedMaintenanceWindow, error)
	// IntervalsForCheck returns the [start,end) intervals of all non-deleted,
	// non-expired windows for one check. Used by uptime exclusion, which looks
	// back over a rolling window, so past windows (not only currently-active
	// ones) must be returned.
	IntervalsForCheck(ctx context.Context, checkID string) ([]MaintenanceInterval, error)
}

// MaintenanceInterval is a half-open planned-downtime interval [StartMS, EndMS).
type MaintenanceInterval struct {
	StartMS int64
	EndMS   int64
}

// InMaintenance reports whether t (millis) falls inside any interval.
func InMaintenance(t int64, intervals []MaintenanceInterval) bool {
	for _, iv := range intervals {
		if t >= iv.StartMS && t < iv.EndMS {
			return true
		}
	}
	return false
}

func maintKey(m protocol.MaintenanceWindow) string {
	return m.Owner + "|" + m.CheckID + "|" + itoa(m.StartMS)
}

// MemMaintenance is an in-memory MaintenanceStore.
type MemMaintenance struct {
	mu      sync.Mutex
	windows map[string]protocol.SignedMaintenanceWindow
}

func NewMemMaintenance() *MemMaintenance {
	return &MemMaintenance{windows: map[string]protocol.SignedMaintenanceWindow{}}
}

func (m *MemMaintenance) Upsert(_ context.Context, sm protocol.SignedMaintenanceWindow) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	key := maintKey(sm.Window)
	// Reject stale updates: only a strictly newer version supersedes (defeats replay).
	if cur, ok := m.windows[key]; ok && sm.Window.UpdatedMS <= cur.Window.UpdatedMS {
		return nil
	}
	m.windows[key] = sm // tombstones are retained, not deleted
	return nil
}

func (m *MemMaintenance) ListActive(_ context.Context) ([]protocol.SignedMaintenanceWindow, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	now := nowMS()
	out := []protocol.SignedMaintenanceWindow{}
	for key, sm := range m.windows {
		if expiredMaint(sm, now) {
			delete(m.windows, key) // prune expired (active or tombstone)
			continue
		}
		if sm.Window.Deleted {
			continue
		}
		out = append(out, sm)
	}
	return out, nil
}

func (m *MemMaintenance) ListForGossip(_ context.Context) ([]protocol.SignedMaintenanceWindow, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	now := nowMS()
	out := []protocol.SignedMaintenanceWindow{}
	for key, sm := range m.windows {
		if expiredMaint(sm, now) {
			delete(m.windows, key)
			continue
		}
		out = append(out, sm)
	}
	return out, nil
}

func (m *MemMaintenance) IntervalsForCheck(_ context.Context, checkID string) ([]MaintenanceInterval, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	now := nowMS()
	out := []MaintenanceInterval{}
	for _, sm := range m.windows {
		if sm.Window.Deleted || sm.Window.CheckID != checkID || expiredMaint(sm, now) {
			continue
		}
		out = append(out, MaintenanceInterval{StartMS: sm.Window.StartMS, EndMS: sm.Window.EndMS})
	}
	return out, nil
}

// expiredMaint reports whether a record has passed its expiry. ExpiryMS == 0
// means no expiry (kept until explicitly tombstoned).
func expiredMaint(sm protocol.SignedMaintenanceWindow, now int64) bool {
	return sm.Window.ExpiryMS > 0 && sm.Window.ExpiryMS < now
}
