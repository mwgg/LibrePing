package shard

import (
	"fmt"
	"testing"
)

func hubs(n int, cap int) []Hub {
	out := make([]Hub, n)
	for i := range out {
		out[i] = Hub{ID: fmt.Sprintf("hub-%02d", i), Capacity: cap}
	}
	return out
}

// TestHubFromClampsUntrusted verifies the storage trust boundary: an untrusted
// peer's self-declared capacity is clamped and its archive claim is ignored,
// while a trusted peer passes through unchanged.
func TestHubFromClampsUntrusted(t *testing.T) {
	untrusted := HubFrom("evil", 1_000_000, true, false)
	if untrusted.Capacity != MaxUntrustedCapacity {
		t.Fatalf("untrusted capacity = %d, want clamp to %d", untrusted.Capacity, MaxUntrustedCapacity)
	}
	if untrusted.Archive {
		t.Fatal("untrusted archive claim should be ignored")
	}
	trusted := HubFrom("friend", 1_000_000, true, true)
	if trusted.Capacity != 1_000_000 || !trusted.Archive {
		t.Fatalf("trusted hub should pass through unchanged, got %+v", trusted)
	}
	// A small untrusted capacity is left alone.
	if h := HubFrom("small", 5, false, false); h.Capacity != 5 {
		t.Fatalf("small untrusted capacity altered: %+v", h)
	}
}

// TestSoloAndSmallMeshHoldAll verifies the safety property: with <= Replication
// storage hubs, everyone holds every shard (transparent to small deployments).
func TestSoloAndSmallMeshHoldAll(t *testing.T) {
	for n := 1; n <= Replication; n++ {
		hs := hubs(n, 1)
		for i := 0; i < n; i++ {
			a := AssignedShards(hs[i].ID, hs, Replication)
			if len(a) != Count {
				t.Fatalf("n=%d hub %d should hold all %d shards, holds %d", n, i, Count, len(a))
			}
		}
	}
}

// TestSpreadAndReplication verifies that with many hubs, load spreads and each
// shard has exactly Replication holders.
func TestSpreadAndReplication(t *testing.T) {
	hs := hubs(20, 1)
	counts := map[string]int{}
	for s := uint32(0); s < Count; s++ {
		holders := Holders(s, hs, Replication)
		if len(holders) != Replication {
			t.Fatalf("shard %d has %d holders, want %d", s, len(holders), Replication)
		}
		for _, id := range holders {
			counts[id]++
		}
	}
	// Each hub should hold a meaningful slice, far less than everything.
	for _, h := range hs {
		frac := float64(counts[h.ID]) / float64(Count)
		if frac > 0.5 {
			t.Fatalf("hub %s holds %.0f%% of shards; expected spread", h.ID, frac*100)
		}
	}
	// Total holder-slots = Count * Replication.
	total := 0
	for _, c := range counts {
		total += c
	}
	if total != Count*Replication {
		t.Fatalf("total holder slots %d, want %d", total, Count*Replication)
	}
}

// TestCapacityWeighting verifies a high-capacity hub holds proportionally more.
func TestCapacityWeighting(t *testing.T) {
	hs := hubs(10, 1)
	hs = append(hs, Hub{ID: "big", Capacity: 10}) // 10x weight
	counts := map[string]int{}
	for s := uint32(0); s < Count; s++ {
		for _, id := range Holders(s, hs, Replication) {
			counts[id]++
		}
	}
	avgSmall := 0
	for _, h := range hs[:10] {
		avgSmall += counts[h.ID]
	}
	avgSmall /= 10
	if counts["big"] <= 2*avgSmall {
		t.Fatalf("high-capacity hub holds %d shards vs small-hub avg %d; expected much more", counts["big"], avgSmall)
	}
}

// TestArchiveHoldsAll verifies an archive hub is assigned every shard and is a
// holder of every shard.
func TestArchiveHoldsAll(t *testing.T) {
	hs := hubs(10, 1)
	hs = append(hs, Hub{ID: "arc", Archive: true})
	a := AssignedShards("arc", hs, Replication)
	if len(a) != Count {
		t.Fatalf("archive should hold all %d shards, holds %d", Count, len(a))
	}
	// And it appears in every shard's holder set.
	missing := 0
	for s := uint32(0); s < Count; s++ {
		found := false
		for _, id := range Holders(s, hs, Replication) {
			if id == "arc" {
				found = true
				break
			}
		}
		if !found {
			missing++
		}
	}
	if missing != 0 {
		t.Fatalf("archive missing from %d shard holder sets", missing)
	}
}

// TestDeterministic verifies placement is stable across calls (no map-order or
// RNG dependence) so every hub computes the same holders.
func TestDeterministic(t *testing.T) {
	hs := hubs(15, 1)
	for s := uint32(0); s < 50; s++ {
		a := Holders(s, hs, Replication)
		b := Holders(s, hs, Replication)
		if fmt.Sprint(a) != fmt.Sprint(b) {
			t.Fatalf("shard %d non-deterministic: %v vs %v", s, a, b)
		}
	}
}

// TestZeroCapacityNeverHolds verifies a pure-consumer hub (capacity 0) is never
// selected as a holder.
func TestZeroCapacityNeverHolds(t *testing.T) {
	hs := hubs(5, 1)
	hs = append(hs, Hub{ID: "consumer", Capacity: 0})
	for s := uint32(0); s < Count; s++ {
		for _, id := range Holders(s, hs, Replication) {
			if id == "consumer" {
				t.Fatalf("zero-capacity hub selected for shard %d", s)
			}
		}
	}
}
