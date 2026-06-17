package assign

import (
	"testing"

	"github.com/mwgg/libreping/pkg/protocol"
)

func httpCheck(id string, interval int) protocol.CheckSpec {
	return protocol.CheckSpec{ID: id, Type: protocol.CheckHTTP, Target: "https://" + id, IntervalSeconds: interval}
}

func countAssignedTo(m map[string][]protocol.CheckSpec, probeID string) int {
	return len(m[probeID])
}

func TestAssignHonorsRedundancy(t *testing.T) {
	checks := []protocol.CheckSpec{httpCheck("a", 60), httpCheck("b", 60)}
	probes := []Probe{{ID: "p1"}, {ID: "p2"}, {ID: "p3"}, {ID: "p4"}}

	got := Assign(checks, probes, 3)

	for _, c := range checks {
		n := 0
		for _, specs := range got {
			for _, s := range specs {
				if s.ID == c.ID {
					n++
				}
			}
		}
		if n != 3 {
			t.Fatalf("check %s assigned to %d probes, want redundancy 3", c.ID, n)
		}
	}
}

func TestAssignNeverExceedsCapacity(t *testing.T) {
	// Each 60s check costs 1/min. Capacity 2 means at most 2 checks per probe.
	checks := []protocol.CheckSpec{httpCheck("a", 60), httpCheck("b", 60), httpCheck("c", 60)}
	probes := []Probe{{ID: "p1", Capacity: 2}, {ID: "p2", Capacity: 2}}

	got := Assign(checks, probes, 3)
	for _, p := range probes {
		if n := countAssignedTo(got, p.ID); n > p.Capacity {
			t.Fatalf("probe %s assigned %d checks, exceeds capacity %d", p.ID, n, p.Capacity)
		}
	}
}

func TestAssignSkipsUnsupportedTypes(t *testing.T) {
	checks := []protocol.CheckSpec{{ID: "icmp1", Type: protocol.CheckICMP, Target: "1.1.1.1", IntervalSeconds: 60}}
	// p1 supports only HTTP; p2 supports ICMP.
	probes := []Probe{
		{ID: "p1", SupportedTypes: map[protocol.CheckType]bool{protocol.CheckHTTP: true}},
		{ID: "p2", SupportedTypes: map[protocol.CheckType]bool{protocol.CheckICMP: true}},
	}
	got := Assign(checks, probes, 3)
	if countAssignedTo(got, "p1") != 0 {
		t.Fatal("ICMP check assigned to a probe that does not support ICMP")
	}
	if countAssignedTo(got, "p2") != 1 {
		t.Fatal("ICMP check not assigned to the supporting probe")
	}
}

func TestAssignIsDeterministic(t *testing.T) {
	checks := []protocol.CheckSpec{httpCheck("a", 30), httpCheck("b", 120), httpCheck("c", 60)}
	probes := []Probe{{ID: "p1", Capacity: 10}, {ID: "p2", Capacity: 10}}

	first := Assign(checks, probes, 2)
	second := Assign(checks, probes, 2)
	for id, specs := range first {
		if len(specs) != len(second[id]) {
			t.Fatalf("non-deterministic assignment for %s", id)
		}
		for i := range specs {
			if specs[i].ID != second[id][i].ID {
				t.Fatalf("non-deterministic order for %s", id)
			}
		}
	}
}
