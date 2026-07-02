package store

import (
	"context"
	"testing"

	"github.com/mwgg/libreping/pkg/protocol"
)

// TestComputeLatencyPercentiles seeds a known RTT distribution and asserts the
// nearest-rank p50/p95/p99 plus min/max/count, and that down/0-rtt samples are
// excluded from the measured set (mirroring the aggregates and the badge).
func TestComputeLatencyPercentiles(t *testing.T) {
	m := NewMemStore()
	ctx := context.Background()
	now := int64(40_000) * dayMS

	// 100 measured samples with rtt = 1..100 ms, all inside the last 24h. For a
	// nearest-rank percentile over n=100: idx = ceil(p*n)-1, so p50→value 50,
	// p95→95, p99→99, min=1, max=100.
	for i := int64(1); i <= 100; i++ {
		st := protocol.StatusUp
		if i%10 == 0 {
			st = protocol.StatusDegraded // degraded still answered → counted
		}
		_ = m.Insert(ctx, resStatus("c", now-hourMS+i, st, float64(i)))
	}
	// Noise that must NOT affect the percentiles: down rows (even with a high rtt,
	// which is the timeout wait, not latency) and a 0-rtt row.
	_ = m.Insert(ctx, resStatus("c", now-hourMS+200, protocol.StatusDown, 9999))
	_ = m.Insert(ctx, resStatus("c", now-hourMS+201, protocol.StatusDown, 0))
	_ = m.Insert(ctx, resStatus("c", now-hourMS+202, protocol.StatusUp, 0))

	rep, err := ComputeLatencyPercentiles(ctx, m, "c", "24h", now)
	if err != nil {
		t.Fatal(err)
	}
	if !rep.Available || rep.Count != 100 {
		t.Fatalf("expected available with count=100, got %+v", rep)
	}
	if rep.CheckID != "c" || rep.Window != "24h" {
		t.Fatalf("identity: got check=%q window=%q", rep.CheckID, rep.Window)
	}
	assertP := func(name string, got *float64, want float64) {
		t.Helper()
		if got == nil || *got != want {
			t.Fatalf("%s: got %v, want %v", name, got, want)
		}
	}
	assertP("p50", rep.P50, 50)
	assertP("p95", rep.P95, 95)
	assertP("p99", rep.P99, 99)
	assertP("min", rep.Min, 1)
	assertP("max", rep.Max, 100)
}

// TestComputeLatencyPercentilesNoData: a window with no measured samples is
// unavailable with nil percentiles (unknown, not "0 ms") and count 0.
func TestComputeLatencyPercentilesNoData(t *testing.T) {
	m := NewMemStore()
	ctx := context.Background()
	now := int64(40_000) * dayMS
	// Only down/0-rtt rows in the window: nothing measured.
	_ = m.Insert(ctx, resStatus("c", now-hourMS, protocol.StatusDown, 500))
	_ = m.Insert(ctx, resStatus("c", now-hourMS+1, protocol.StatusUp, 0))

	rep, err := ComputeLatencyPercentiles(ctx, m, "c", "7d", now)
	if err != nil {
		t.Fatal(err)
	}
	if rep.Available || rep.P50 != nil || rep.P95 != nil || rep.P99 != nil || rep.Count != 0 {
		t.Fatalf("expected unavailable/nil/zero, got %+v", rep)
	}
	if rep.Window != "7d" {
		t.Fatalf("window: got %q", rep.Window)
	}
}

// TestComputeLatencyPercentilesWindowBound: samples outside the window are
// excluded. A single sample just inside 24h is counted; one just outside is not.
func TestComputeLatencyPercentilesWindowBound(t *testing.T) {
	m := NewMemStore()
	ctx := context.Background()
	now := int64(40_000) * dayMS
	_ = m.Insert(ctx, resStatus("c", now-2*hourMS, protocol.StatusUp, 42)) // inside 24h
	_ = m.Insert(ctx, resStatus("c", now-2*dayMS, protocol.StatusUp, 7))   // outside 24h, inside 7d

	rep, err := ComputeLatencyPercentiles(ctx, m, "c", "24h", now)
	if err != nil {
		t.Fatal(err)
	}
	if !rep.Available || rep.Count != 1 || rep.P50 == nil || *rep.P50 != 42 {
		t.Fatalf("24h should see only the one inside sample, got %+v", rep)
	}
	rep7, _ := ComputeLatencyPercentiles(ctx, m, "c", "7d", now)
	if rep7.Count != 2 {
		t.Fatalf("7d should see both samples, got count=%d", rep7.Count)
	}
}

// TestComputeLatencyPercentilesUnknownWindow rejects an unrecognized window label.
func TestComputeLatencyPercentilesUnknownWindow(t *testing.T) {
	m := NewMemStore()
	if _, err := ComputeLatencyPercentiles(context.Background(), m, "c", "bogus", 1); err == nil {
		t.Fatal("expected an error for an unknown window")
	}
}

// TestNearestRank pins the nearest-rank formula against small hand-checked cases,
// matching web/src/theme.ts (idx = clamp(ceil(p*n)-1, 0, n-1)).
func TestNearestRank(t *testing.T) {
	cases := []struct {
		sorted []float64
		p      float64
		want   float64
	}{
		{[]float64{10}, 0.95, 10},                            // single element
		{[]float64{1, 2, 3, 4, 5}, 0.50, 3},                  // ceil(2.5)-1=2 → 3
		{[]float64{1, 2, 3, 4, 5}, 0.95, 5},                  // ceil(4.75)-1=4 → 5
		{[]float64{1, 2, 3, 4, 5, 6, 7, 8, 9, 10}, 0.95, 10}, // ceil(9.5)-1=9 → 10
	}
	for _, c := range cases {
		if got := nearestRank(c.sorted, c.p); got != c.want {
			t.Fatalf("nearestRank(%v, %v): got %v, want %v", c.sorted, c.p, got, c.want)
		}
	}
}
