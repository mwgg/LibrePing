// Package interest decides which results a hub persists. With partial
// replication a hub stores only the results it is responsible for, instead of
// the whole network's stream. A result for check C is kept when any of:
//
//  1. the hub is a full archive, or
//  2. C's shard is one of the hub's rendezvous-assigned shards, or
//  3. C is pinned — run by one of the hub's own probes, or a check the hub is an
//     alert recipient for (it must hold the data to evaluate the alert).
//
// Lookups are O(1): assigned shards and pinned check IDs are precomputed by a
// background refresh (Update) and read on the hot ingest path.
package interest

import (
	"sync"

	"github.com/mwgg/libreping/hub/shard"
)

// Set is a hub's storage interest. The zero value (and a nil *Set) stores
// everything, so a hub with interest not yet wired behaves like an archive.
type Set struct {
	mu       sync.RWMutex
	ready    bool
	archive  bool
	assigned map[uint32]bool
	pinned   map[string]bool
}

// New returns an empty Set that holds everything until the first Update (so a
// hub never silently drops results during startup, before placement is known).
func New() *Set { return &Set{} }

// Update replaces the computed interest. archive forces holding everything;
// assigned is the set of held shards; pinned is the set of explicitly held
// check IDs (own-probe and alert-recipient checks).
func (s *Set) Update(archive bool, assigned map[uint32]bool, pinned map[string]bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.archive = archive
	s.assigned = assigned
	s.pinned = pinned
	s.ready = true
}

// Holds reports whether the hub should persist a result for checkID. A nil Set
// or one not yet populated holds everything (fail-open: never lose data because
// placement hasn't been computed).
func (s *Set) Holds(checkID string) bool {
	if s == nil {
		return true
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	if !s.ready || s.archive {
		return true
	}
	if s.assigned[shard.Of(checkID)] {
		return true
	}
	return s.pinned[checkID]
}
