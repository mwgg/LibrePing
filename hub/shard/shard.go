// Package shard places result storage across hubs without any coordinator.
//
// Checks are partitioned into a fixed, network-wide number of shards by their
// content ID. Each shard is stored by the top-K hubs ranked by capacity-weighted
// rendezvous hashing of the shard — a function every hub can evaluate locally
// from the gossiped hub directory, so there is no placement service. This is the
// same rendezvous idea the alert engine uses to pick a responsible hub, applied
// to data placement.
//
// Two properties make it safe to roll out:
//   - If the number of storage hubs is <= Replication, every hub is a holder of
//     every shard — a solo hub or tiny mesh stores everything, exactly like
//     before. Spreading only begins once there are more storage hubs than the
//     replication factor.
//   - Capacity-weighting means a big hub holds many shards and a small hub few,
//     so hubs of different sizes coexist.
package shard

import (
	"crypto/sha256"
	"encoding/binary"
	"math"
	"sort"
	"strconv"
)

const (
	// Count is the network-wide shard count. It MUST be identical on every hub
	// (it is part of the placement contract); changing it reshuffles placement.
	// It is also the number of result gossip topics, so it trades placement
	// granularity (finer = a small hub can hold a smaller slice) against per-node
	// topic overhead (a full/archive hub subscribes to all Count topics). 64 is a
	// balance: a full hub runs 64 result topics, a NAS can hold as little as
	// ~1/64th of the data.
	Count = 64
	// Replication is the minimum number of (non-archive) hubs that hold each
	// shard. Also network-wide.
	Replication = 3
)

// MaxUntrustedCapacity caps the placement weight an untrusted peer's
// self-declared capacity can contribute. StorageCapacity/StorageArchive are
// self-declared in signed announcements, so a hostile hub could otherwise claim
// enormous capacity (or the archive role) to pull most shards onto itself and
// let honest hubs drop their own copies — a storage-eclipse / Sybil lever. A
// trusted hub (operator allowlist, or this hub itself) is not clamped.
const MaxUntrustedCapacity = 100

// Hub is a storage candidate: its node ID, its declared relative capacity
// weight, and whether it is a full archive (holds every shard).
type Hub struct {
	ID       string
	Capacity int
	Archive  bool
}

// HubFrom builds a placement candidate from a peer's self-declared capacity and
// archive flag, applying the trust boundary. A trusted peer (or this hub, which
// callers add directly) passes through unchanged. An untrusted peer never gets
// the archive role — that would place it in *every* shard and let honest hubs
// drop their own copies (storage eclipse). Its capacity is clamped to
// MaxUntrustedCapacity; an untrusted archive claim is downgraded to that same
// bounded capacity so the hub still participates as a normal holder (reads from
// it are independently verified, so availability is fine) without being an
// eclipse magnet.
func HubFrom(id string, capacity int, archive bool, trusted bool) Hub {
	if trusted {
		return Hub{ID: id, Capacity: capacity, Archive: archive}
	}
	if archive && capacity < MaxUntrustedCapacity {
		capacity = MaxUntrustedCapacity
	}
	if capacity > MaxUntrustedCapacity {
		capacity = MaxUntrustedCapacity
	}
	return Hub{ID: id, Capacity: capacity, Archive: false}
}

// Of returns the shard a check ID belongs to. Check IDs are hex of a sha256
// prefix, hence already uniformly distributed, so the leading hex digits make a
// good shard key.
func Of(checkID string) uint32 {
	if len(checkID) < 4 {
		// Pad/degrade gracefully for unexpectedly short IDs.
		sum := sha256.Sum256([]byte(checkID))
		return uint32(binary.BigEndian.Uint16(sum[:2])) % Count
	}
	v, err := strconv.ParseUint(checkID[:4], 16, 32)
	if err != nil {
		sum := sha256.Sum256([]byte(checkID))
		return uint32(binary.BigEndian.Uint16(sum[:2])) % Count
	}
	return uint32(v) % Count
}

// unit maps (hubID, shard) to a deterministic value in (0,1) for weighted
// rendezvous.
func unit(hubID string, s uint32) float64 {
	var b [4]byte
	binary.BigEndian.PutUint32(b[:], s)
	h := sha256.New()
	h.Write([]byte(hubID))
	h.Write([]byte{'|'})
	h.Write(b[:])
	sum := h.Sum(nil)
	x := binary.BigEndian.Uint64(sum[:8])
	// (x + 0.5) / 2^64 lies strictly in (0,1).
	return (float64(x) + 0.5) / 18446744073709551616.0
}

// score is the capacity-weighted rendezvous score (Schindelhauer–Schomaker):
// higher capacity and a draw closer to 1 both raise the score. Capacity <= 0
// scores 0 (never selected).
func score(h Hub, s uint32) float64 {
	if h.Capacity <= 0 {
		return 0
	}
	return float64(h.Capacity) * (-1.0 / math.Log(unit(h.ID, s)))
}

// Holders returns the hub IDs that store shard s: every archive hub, plus the
// top-k non-archive hubs by weighted rendezvous (fewer if there aren't k).
func Holders(s uint32, hubs []Hub, k int) []string {
	var out []string
	type scored struct {
		id string
		sc float64
	}
	var cand []scored
	for _, h := range hubs {
		if h.ID == "" {
			continue
		}
		if h.Archive {
			out = append(out, h.ID)
			continue
		}
		if h.Capacity <= 0 {
			continue
		}
		cand = append(cand, scored{h.ID, score(h, s)})
	}
	// Sort by score desc, then ID desc for a deterministic tiebreak.
	sort.Slice(cand, func(i, j int) bool {
		if cand[i].sc != cand[j].sc {
			return cand[i].sc > cand[j].sc
		}
		return cand[i].id > cand[j].id
	})
	if k > len(cand) {
		k = len(cand)
	}
	for i := 0; i < k; i++ {
		out = append(out, cand[i].id)
	}
	return out
}

// AssignedShards returns the set of shards selfID is a holder for. If selfID is
// an archive (present in hubs as Archive), every shard is assigned.
func AssignedShards(selfID string, hubs []Hub, k int) map[uint32]bool {
	for _, h := range hubs {
		if h.ID == selfID && h.Archive {
			all := make(map[uint32]bool, Count)
			for s := uint32(0); s < Count; s++ {
				all[s] = true
			}
			return all
		}
	}
	out := map[uint32]bool{}
	for s := uint32(0); s < Count; s++ {
		for _, id := range Holders(s, hubs, k) {
			if id == selfID {
				out[s] = true
				break
			}
		}
	}
	return out
}
