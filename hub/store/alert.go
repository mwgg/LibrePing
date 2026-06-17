package store

import (
	"context"
	"sync"

	"github.com/mwgg/libreping/pkg/protocol"
)

// Delivery is the last-delivered status for a rule, with the hub and timestamp
// that delivered it. It is merged across hubs last-writer-wins so failover
// doesn't duplicate notifications.
type Delivery struct {
	Status      protocol.Status
	HubID       string
	TimestampMS int64
}

// AlertStore persists alert rules and per-rule delivery state. Delivery state
// lets a hub avoid re-firing on restart, only notify on status transitions, and
// (via gossip + MergeDelivery) hand off cleanly to a failover hub.
//
// Delivery state is keyed by (rule_id, hub_id): each hub's own claim is stored
// separately rather than collapsed last-writer-wins into one row. That keeps a
// hub's own delivery retrievable for anti-entropy and means one hub cannot
// shadow another's state with a future timestamp.
type AlertStore interface {
	Upsert(ctx context.Context, sa protocol.SignedAlertRule) error
	ListActive(ctx context.Context) ([]protocol.SignedAlertRule, error)
	// ListForGossip returns non-expired rules including tombstones, so
	// anti-entropy propagates deletes as well as live rules.
	ListForGossip(ctx context.Context) ([]protocol.SignedAlertRule, error)
	// GetRule returns a single rule by ID (used to validate gossiped delivery
	// state against the rule's recipient set before merging it).
	GetRule(ctx context.Context, ruleID string) (protocol.SignedAlertRule, bool, error)
	// GetDelivery returns the newest delivery state for ruleID across all hubs.
	GetDelivery(ctx context.Context, ruleID string) (Delivery, bool, error)
	// GetDeliveryBy returns the delivery state ruleID was last given by hubID
	// (this hub's own state, for anti-entropy re-broadcast).
	GetDeliveryBy(ctx context.Context, ruleID, hubID string) (Delivery, bool, error)
	// MergeDelivery records d for (ruleID, d.HubID) only if it is newer than the
	// stored state from that same hub (per-hub last-writer-wins). Returns
	// whether it was applied.
	MergeDelivery(ctx context.Context, ruleID string, d Delivery) (bool, error)
}

// MemAlerts is an in-memory AlertStore.
type MemAlerts struct {
	mu    sync.Mutex
	rules map[string]protocol.SignedAlertRule
	state map[string]map[string]Delivery // ruleID -> hubID -> Delivery
}

func NewMemAlerts() *MemAlerts {
	return &MemAlerts{rules: map[string]protocol.SignedAlertRule{}, state: map[string]map[string]Delivery{}}
}

func (m *MemAlerts) Upsert(_ context.Context, sa protocol.SignedAlertRule) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	id := sa.Rule.ID()
	// Reject stale updates (replay defense); retain tombstones rather than
	// erasing so an old signed active rule can't resurrect a deleted alert.
	if cur, ok := m.rules[id]; ok && sa.Rule.UpdatedMS <= cur.Rule.UpdatedMS {
		return nil
	}
	m.rules[id] = sa
	if sa.Rule.Deleted {
		delete(m.state, id) // the alert is gone; drop its delivery state
	}
	return nil
}

func (m *MemAlerts) ListActive(_ context.Context) ([]protocol.SignedAlertRule, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	now := nowMS()
	out := []protocol.SignedAlertRule{}
	for id, sa := range m.rules {
		if expiredRule(sa, now) {
			delete(m.rules, id)
			delete(m.state, id)
			continue
		}
		if sa.Rule.Deleted {
			continue
		}
		out = append(out, sa)
	}
	return out, nil
}

func (m *MemAlerts) ListForGossip(_ context.Context) ([]protocol.SignedAlertRule, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	now := nowMS()
	out := []protocol.SignedAlertRule{}
	for id, sa := range m.rules {
		if expiredRule(sa, now) {
			delete(m.rules, id)
			delete(m.state, id)
			continue
		}
		out = append(out, sa)
	}
	return out, nil
}

// expiredRule reports whether a rule has passed its expiry. ExpiryMS == 0 means
// no expiry.
func expiredRule(sa protocol.SignedAlertRule, now int64) bool {
	return sa.Rule.ExpiryMS > 0 && sa.Rule.ExpiryMS < now
}

func (m *MemAlerts) GetRule(_ context.Context, ruleID string) (protocol.SignedAlertRule, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	sa, ok := m.rules[ruleID]
	return sa, ok, nil
}

func (m *MemAlerts) GetDelivery(_ context.Context, ruleID string) (Delivery, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var newest Delivery
	found := false
	for _, d := range m.state[ruleID] {
		if !found || d.TimestampMS > newest.TimestampMS {
			newest, found = d, true
		}
	}
	return newest, found, nil
}

func (m *MemAlerts) GetDeliveryBy(_ context.Context, ruleID, hubID string) (Delivery, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	d, ok := m.state[ruleID][hubID]
	return d, ok, nil
}

func (m *MemAlerts) MergeDelivery(_ context.Context, ruleID string, d Delivery) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	byHub := m.state[ruleID]
	if byHub == nil {
		byHub = map[string]Delivery{}
		m.state[ruleID] = byHub
	}
	if cur, ok := byHub[d.HubID]; ok && cur.TimestampMS >= d.TimestampMS {
		return false, nil
	}
	byHub[d.HubID] = d
	return true, nil
}
