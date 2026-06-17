package store

import (
	"context"
	"sort"
	"sync"

	"github.com/mwgg/libreping/pkg/protocol"
)

// CatalogStore persists the network's check catalog on a hub. Entries are keyed
// by their content-derived check ID (protocol.CheckSpec.DeriveID), so the same
// monitor created on different hubs converges to a single row.
type CatalogStore interface {
	// UpsertCheck stores or refreshes a signed catalog entry.
	UpsertCheck(ctx context.Context, sc protocol.SignedCatalogEntry) error
	// ListChecks returns all known checks.
	ListChecks(ctx context.Context) ([]protocol.SignedCatalogEntry, error)
	// GetCheck returns the entry for a check ID; ok is false if unknown.
	GetCheck(ctx context.Context, checkID string) (protocol.SignedCatalogEntry, bool, error)
}

// MemCatalog is an in-memory CatalogStore. Safe for concurrent use.
type MemCatalog struct {
	mu      sync.Mutex
	entries map[string]protocol.SignedCatalogEntry
}

// NewMemCatalog returns an empty in-memory catalog.
func NewMemCatalog() *MemCatalog {
	return &MemCatalog{entries: map[string]protocol.SignedCatalogEntry{}}
}

func (m *MemCatalog) UpsertCheck(_ context.Context, sc protocol.SignedCatalogEntry) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.entries[sc.Entry.Spec.ID] = sc
	return nil
}

func (m *MemCatalog) GetCheck(_ context.Context, checkID string) (protocol.SignedCatalogEntry, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	sc, ok := m.entries[checkID]
	return sc, ok, nil
}

func (m *MemCatalog) ListChecks(_ context.Context) ([]protocol.SignedCatalogEntry, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]protocol.SignedCatalogEntry, 0, len(m.entries))
	for _, e := range m.entries {
		out = append(out, e)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Entry.Spec.ID < out[j].Entry.Spec.ID })
	return out, nil
}
