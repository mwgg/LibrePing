package store

import (
	"context"
	"testing"

	"github.com/mwgg/libreping/pkg/protocol"
)

// TestComputeUptimeWindows seeds a known mix of up/down/degraded across the last
// 30 days and asserts each window reports (up+degraded)/samples over exactly the
// samples inside it, with the 24h window computed at hourly granularity.
func TestComputeUptimeWindows(t *testing.T) {
	m := NewMemStore()
	ctx := context.Background()
	// A fixed "now" aligned to a day boundary keeps bucket math predictable.
	now := int64(40_000) * dayMS

	// Inside the last 24h: 8 up, 1 down, 1 degraded → available (up+degraded)=9/10.
	// Spread across two different hours so the 24h window must sum hourly buckets.
	hourA := now - 2*hourMS
	hourB := now - 20*hourMS
	for i := int64(0); i < 4; i++ {
		_ = m.Insert(ctx, resStatus("c", hourA+i, protocol.StatusUp, 10))
		_ = m.Insert(ctx, resStatus("c", hourB+i, protocol.StatusUp, 10))
	}
	_ = m.Insert(ctx, resStatus("c", hourA+100, protocol.StatusDown, 0))
	_ = m.Insert(ctx, resStatus("c", hourB+100, protocol.StatusDegraded, 50))

	// Older than 24h but inside 7d: 10 more up. So 7d totals 18 up, 1 down, 1 deg.
	older7d := now - 3*dayMS
	for i := int64(0); i < 10; i++ {
		_ = m.Insert(ctx, resStatus("c", older7d+i, protocol.StatusUp, 10))
	}

	// Older than 7d but inside 30d: 5 up, 5 down. So 30d totals 23 up, 6 down, 1 deg.
	older30d := now - 20*dayMS
	for i := int64(0); i < 5; i++ {
		_ = m.Insert(ctx, resStatus("c", older30d+i, protocol.StatusUp, 10))
		_ = m.Insert(ctx, resStatus("c", older30d+100+i, protocol.StatusDown, 0))
	}

	rep, err := ComputeUptime(ctx, m, "c", now, nil)
	if err != nil {
		t.Fatal(err)
	}

	check := func(label string, wantSamples, wantUp, wantDown, wantDeg int64) {
		t.Helper()
		w, ok := rep.Windows[label]
		if !ok {
			t.Fatalf("%s: window missing", label)
		}
		if w.Samples != wantSamples || w.Up != wantUp || w.Down != wantDown || w.Degraded != wantDeg {
			t.Fatalf("%s totals: got samples=%d up=%d down=%d deg=%d, want %d/%d/%d/%d",
				label, w.Samples, w.Up, w.Down, w.Degraded, wantSamples, wantUp, wantDown, wantDeg)
		}
		if !w.Available || w.Uptime == nil {
			t.Fatalf("%s should be available with non-nil uptime", label)
		}
		want := float64(wantUp+wantDeg) / float64(wantSamples)
		if *w.Uptime != want {
			t.Fatalf("%s uptime: got %v, want %v", label, *w.Uptime, want)
		}
	}
	check("24h", 10, 8, 1, 1)
	check("7d", 20, 18, 1, 1)
	check("30d", 30, 23, 6, 1)
}

// TestComputeUptimeNoData: a check with no samples in any window is unavailable
// with a null uptime, not an error and not a zero uptime (which would read as
// "0% up" rather than "unknown").
func TestComputeUptimeNoData(t *testing.T) {
	m := NewMemStore()
	rep, err := ComputeUptime(context.Background(), m, "unknown", int64(40_000)*dayMS, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, label := range []string{"24h", "7d", "30d"} {
		w, ok := rep.Windows[label]
		if !ok {
			t.Fatalf("%s: window missing", label)
		}
		if w.Available || w.Uptime != nil || w.Samples != 0 {
			t.Fatalf("%s should be unavailable/null/zero, got %+v", label, w)
		}
	}
}

// TestComputeUptimeExcludesMaintenance proves a maintenance window covering a
// down period lifts uptime: the down bucket is excluded entirely, so the 24h
// figure rises from "9/10 down-dented" to a clean 100% over the remaining bucket.
func TestComputeUptimeExcludesMaintenance(t *testing.T) {
	m := NewMemStore()
	ctx := context.Background()
	now := int64(40_000) * dayMS

	// hourA (recent): all UP. hourB (older, within 24h): all DOWN — a planned outage.
	hourA := now - 2*hourMS
	hourB := now - 5*hourMS
	for i := int64(0); i < 5; i++ {
		_ = m.Insert(ctx, resStatus("c", hourA+i, protocol.StatusUp, 10))
		_ = m.Insert(ctx, resStatus("c", hourB+i, protocol.StatusDown, 0))
	}

	// Without maintenance: 5 up / 10 samples = 0.5.
	rep, _ := ComputeUptime(ctx, m, "c", now, nil)
	if u := rep.Windows["24h"].Uptime; u == nil || *u != 0.5 {
		t.Fatalf("baseline 24h uptime: got %v, want 0.5", rep.Windows["24h"].Uptime)
	}

	// A window covering hourB's bucket excludes the down bucket → 5/5 = 1.0.
	bucketB := (hourB / hourMS) * hourMS
	maint := []MaintenanceInterval{{StartMS: bucketB, EndMS: bucketB + hourMS}}
	rep, _ = ComputeUptime(ctx, m, "c", now, maint)
	w := rep.Windows["24h"]
	if w.Samples != 5 || w.Down != 0 {
		t.Fatalf("maintenance should exclude the down bucket: got samples=%d down=%d", w.Samples, w.Down)
	}
	if w.Uptime == nil || *w.Uptime != 1.0 {
		t.Fatalf("24h uptime under maintenance: got %v, want 1.0", w.Uptime)
	}
}
