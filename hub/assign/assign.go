// Package assign distributes the global check catalog across a hub's own
// registered probes. Each hub assigns independently; global redundancy emerges
// from many hubs doing this over a shared catalog. The algorithm is a simple,
// deterministic greedy bin-pack: every check is given to up to `redundancy`
// probes, never exceeding a probe's per-minute capacity, and never assigning a
// check type a probe cannot run.
package assign

import (
	"sort"

	"github.com/mwgg/libreping/pkg/protocol"
)

// Probe is the capacity view of a registered probe used for assignment.
type Probe struct {
	ID             string
	Capacity       int // max checks per minute; <= 0 means unlimited
	SupportedTypes map[protocol.CheckType]bool
}

// supports reports whether the probe can run the given check type. A probe with
// no declared types is treated as supporting all (backward-compatible default).
func (p Probe) supports(t protocol.CheckType) bool {
	if len(p.SupportedTypes) == 0 {
		return true
	}
	return p.SupportedTypes[t]
}

// checkCost is how many checks-per-minute a spec consumes on a probe.
func checkCost(s protocol.CheckSpec) float64 {
	interval := s.IntervalSeconds
	if interval <= 0 {
		interval = 60
	}
	return 60.0 / float64(interval)
}

// Assign returns probeID -> assigned checks. Each check is assigned to at most
// `redundancy` probes that support its type and have remaining capacity, chosen
// least-loaded-first (ties broken by ID) for even spread and determinism.
func Assign(checks []protocol.CheckSpec, probes []Probe, redundancy int) map[string][]protocol.CheckSpec {
	if redundancy < 1 {
		redundancy = 1
	}
	out := make(map[string][]protocol.CheckSpec, len(probes))
	load := make(map[string]float64, len(probes))
	for _, p := range probes {
		out[p.ID] = nil
		load[p.ID] = 0
	}

	// Deterministic check order.
	ordered := append([]protocol.CheckSpec(nil), checks...)
	sort.Slice(ordered, func(i, j int) bool { return ordered[i].ID < ordered[j].ID })

	for _, c := range ordered {
		cost := checkCost(c)
		// Candidate probes that support the type, sorted least-loaded first.
		candidates := make([]Probe, 0, len(probes))
		for _, p := range probes {
			if p.supports(c.Type) {
				candidates = append(candidates, p)
			}
		}
		sort.Slice(candidates, func(i, j int) bool {
			li, lj := load[candidates[i].ID], load[candidates[j].ID]
			if li != lj {
				return li < lj
			}
			return candidates[i].ID < candidates[j].ID
		})

		assigned := 0
		for _, p := range candidates {
			if assigned >= redundancy {
				break
			}
			if p.Capacity > 0 && load[p.ID]+cost > float64(p.Capacity) {
				continue // would exceed this probe's cap
			}
			out[p.ID] = append(out[p.ID], c)
			load[p.ID] += cost
			assigned++
		}
	}
	return out
}
