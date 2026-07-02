package store

import (
	"context"
	"errors"
	"sort"
	"sync"

	"github.com/mwgg/libreping/pkg/protocol"
)

// ErrCatalogConflict is returned by UpsertCheck when a *different* check spec
// already occupies the incoming entry's content-derived ID. Because that ID is
// only the first 8 bytes of sha256 (64 bits), a birthday collision — or a
// deliberately-crafted twin — can produce two entries that each validly satisfy
// Spec.ID == DeriveID() yet point at different targets. First-writer-wins: the
// stored entry is kept and the impostor is neither stored nor re-gossiped, so a
// twin can't silently redirect everyone subscribed to a shared check.
var ErrCatalogConflict = errors.New("store: catalog id collides with a different check spec")

// sameCheckContent reports whether two specs describe the same check — i.e. the
// fields that feed CheckSpec.DeriveID (type, target, params). It deliberately
// ignores ID, IntervalSeconds, and signer: two entries can share a
// content-derived ID yet address different targets (an 8-byte sha256 collision),
// which is precisely what the catalog collision guard must catch. Param maps
// are compared by content so nil and empty (both derive identically) match.
func sameCheckContent(a, b protocol.CheckSpec) bool {
	if a.Type != b.Type || a.Target != b.Target || len(a.Params) != len(b.Params) {
		return false
	}
	for k, v := range a.Params {
		if bv, ok := b.Params[k]; !ok || bv != v {
			return false
		}
	}
	return true
}

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

// memCatalogMaxEntries bounds the in-memory catalog. Catalog entries never
// expire, so on the DB-less trial path a Sybil key gossiping distinct checks
// would otherwise grow it without bound. Far above any plausible real catalog;
// once full, further new checks are refused rather than dropping an existing
// (possibly subscribed) shared check. Real deployments use PgCatalog.
const memCatalogMaxEntries = 200_000

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
	id := sc.Entry.Spec.ID
	if existing, ok := m.entries[id]; ok {
		if !sameCheckContent(existing.Entry.Spec, sc.Entry.Spec) {
			return ErrCatalogConflict
		}
		// Identical spec (normal gossip re-delivery or a legitimately re-signed
		// entry) still overwrites, refreshing the stored signature/pubkey.
		m.entries[id] = sc
		return nil
	}
	// New check: refuse once the trial-path cap is reached so a flood of distinct
	// gossiped checks can't grow the in-memory catalog without bound.
	if len(m.entries) >= memCatalogMaxEntries {
		return nil
	}
	m.entries[id] = sc
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
