package store

import (
	"context"
	"testing"

	"github.com/mwgg/libreping/pkg/protocol"
)

// TestHistogramPercentilesAccuracy seeds the same uniform 1..100ms distribution as
// the raw-percentile test, then compares HistogramPercentiles (interpolated from
// the latency buckets computed by MemStore.HistoryRange) against the exact
// nearest-rank values. The interpolation must land within one bucket width of the
// exact percentile, and min/max come straight from the summaries.
func TestHistogramPercentilesAccuracy(t *testing.T) {
	m := NewMemStore()
	ctx := context.Background()
	now := int64(40_000) * dayMS
	// Spread across a >14d window so HistoryRange rolls up at DAILY resolution — the
	// same tier a 30d latency window uses. 100 measured samples, rtt = 1..100ms.
	span := int64(30) * dayMS
	for i := int64(1); i <= 100; i++ {
		st := protocol.StatusUp
		if i%10 == 0 {
			st = protocol.StatusDegraded // degraded still answered → measured
		}
		ts := now - span + (i * span / 101) // spread over the window
		_ = m.Insert(ctx, resStatus("c", ts, st, float64(i)))
	}
	// Noise excluded from the measured set: a down row with a big rtt and a 0-rtt row.
	_ = m.Insert(ctx, resStatus("c", now-span+10, protocol.StatusDown, 9999))
	_ = m.Insert(ctx, resStatus("c", now-span+11, protocol.StatusUp, 0))

	summaries, err := m.HistoryRange(ctx, "c", now-span, now)
	if err != nil {
		t.Fatal(err)
	}
	rep := HistogramPercentiles("c", "30d", summaries)
	if !rep.Available || rep.Source != "histogram" {
		t.Fatalf("expected available histogram source, got %+v", rep)
	}
	if rep.Count != 100 {
		t.Fatalf("measured count should be 100, got %d", rep.Count)
	}
	// Exact nearest-rank for this distribution: p50=50, p95=95, p99=99. Interpolation
	// must be within one bucket width (the 25→50 or 50→100 bucket) of those.
	within := func(name string, got *float64, exact, tol float64) {
		t.Helper()
		if got == nil {
			t.Fatalf("%s: nil", name)
		}
		d := *got - exact
		if d < 0 {
			d = -d
		}
		if d > tol {
			t.Fatalf("%s: got %g, exact %g, off by %g (> %g)", name, *got, exact, d, tol)
		}
	}
	within("p50", rep.P50, 50, 50) // widest bucket around p50 is [25,50] or [50,100]
	within("p95", rep.P95, 95, 50)
	within("p99", rep.P99, 99, 50)
	// Min/Max are taken exactly from the summaries' rtt_min/rtt_max.
	if rep.Min == nil || *rep.Min != 1 || rep.Max == nil || *rep.Max != 100 {
		t.Fatalf("min/max should be exact 1/100, got min=%v max=%v", rep.Min, rep.Max)
	}
}

// TestHistogramPercentilesZero: no measured samples → unavailable, nil percentiles.
func TestHistogramPercentilesZero(t *testing.T) {
	m := NewMemStore()
	ctx := context.Background()
	now := int64(40_000) * dayMS
	span := int64(30) * dayMS
	_ = m.Insert(ctx, resStatus("c", now-span+1, protocol.StatusDown, 500))
	_ = m.Insert(ctx, resStatus("c", now-span+2, protocol.StatusUp, 0))

	summaries, _ := m.HistoryRange(ctx, "c", now-span, now)
	rep := HistogramPercentiles("c", "30d", summaries)
	if rep.Available || rep.P50 != nil || rep.Count != 0 {
		t.Fatalf("expected unavailable/nil/zero, got %+v", rep)
	}
}

// TestHistogramPercentilesOverflow: every measured sample is slower than the last
// bucket bound (10000ms), so all le_<bound> counts are 0 and the target rank falls
// in the unbounded overflow. Percentiles must clamp to the last bound; max still
// reflects the true slowest sample.
func TestHistogramPercentilesOverflow(t *testing.T) {
	m := NewMemStore()
	ctx := context.Background()
	now := int64(40_000) * dayMS
	span := int64(30) * dayMS
	for i := int64(0); i < 20; i++ {
		ts := now - span + (i * span / 21)
		_ = m.Insert(ctx, resStatus("c", ts, protocol.StatusUp, 15000+float64(i))) // all > 10s
	}
	summaries, _ := m.HistoryRange(ctx, "c", now-span, now)
	rep := HistogramPercentiles("c", "30d", summaries)
	if !rep.Available || rep.Count != 20 {
		t.Fatalf("expected available count=20, got %+v", rep)
	}
	last := float64(RttBucketBoundsMS[numRttBuckets-1])
	if *rep.P50 != last || *rep.P95 != last || *rep.P99 != last {
		t.Fatalf("overflow percentiles should clamp to %g, got p50=%g p95=%g p99=%g",
			last, *rep.P50, *rep.P95, *rep.P99)
	}
	if *rep.Max != 15019 {
		t.Fatalf("max should be the true slowest sample 15019, got %g", *rep.Max)
	}
}

// TestHistogramQuantileInterpolation pins the interpolation on a hand-checked
// cumulative histogram so the Prometheus-style linear step can't silently drift.
func TestHistogramQuantileInterpolation(t *testing.T) {
	// bounds:       5 10 25 50 100 250 500 1000 2500 5000 10000
	// cumulative:   0  0  0 50 100 100 100  100  100  100   100  (total 100)
	var cum [numRttBuckets]int64
	for i, b := range RttBucketBoundsMS {
		switch {
		case b <= 25:
			cum[i] = 0
		case b == 50:
			cum[i] = 50
		default:
			cum[i] = 100
		}
	}
	// p50: rank 50 lands exactly at the top of the [25,50] bucket → 50.
	if got := histogramQuantile(0.50, cum, 100); got != 50 {
		t.Fatalf("p50: got %g want 50", got)
	}
	// p95: rank 95 is in [50,100], frac=(95-50)/50=0.9 → 50+50*0.9 = 95.
	if got := histogramQuantile(0.95, cum, 100); got != 95 {
		t.Fatalf("p95: got %g want 95", got)
	}
}
