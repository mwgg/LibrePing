package store

import (
	"context"
	"testing"

	"github.com/mwgg/libreping/pkg/protocol"
)

// TestComputeIncidentsSingleOutage seeds an up→down→up pattern across hourly
// buckets and asserts one incident with the right start/end/duration/worst_status,
// not marked ongoing (an up bucket follows it).
func TestComputeIncidentsSingleOutage(t *testing.T) {
	m := NewMemStore()
	ctx := context.Background()
	now := int64(40_000) * dayMS // aligned to an hour boundary

	seedBucket(ctx, m, "c", now-5*hourMS, protocol.StatusUp, 3)
	seedBucket(ctx, m, "c", now-4*hourMS, protocol.StatusDown, 3) // outage bucket 1
	seedBucket(ctx, m, "c", now-3*hourMS, protocol.StatusDown, 3) // outage bucket 2
	seedBucket(ctx, m, "c", now-2*hourMS, protocol.StatusUp, 3)   // recovery

	rep, err := ComputeIncidents(ctx, m, "c", "7d", now)
	if err != nil {
		t.Fatal(err)
	}
	if rep.Resolution != "hourly" || rep.Window != "7d" {
		t.Fatalf("unexpected report meta: %+v", rep)
	}
	if len(rep.Incidents) != 1 {
		t.Fatalf("expected 1 incident, got %d: %+v", len(rep.Incidents), rep.Incidents)
	}
	inc := rep.Incidents[0]
	wantStart := now - 4*hourMS
	wantEnd := now - 2*hourMS // last non-up bucket's end == recovery bucket's start
	if inc.StartMS != wantStart || inc.EndMS != wantEnd {
		t.Fatalf("edges: got start=%d end=%d, want %d/%d", inc.StartMS, inc.EndMS, wantStart, wantEnd)
	}
	if inc.DurationMS != 2*hourMS || inc.BucketCount != 2 || inc.WorstStatus != "down" || inc.Ongoing {
		t.Fatalf("incident: %+v", inc)
	}
}

// TestComputeIncidentsOngoing: a still-down bucket at the leading edge yields an
// ongoing incident whose end is now.
func TestComputeIncidentsOngoing(t *testing.T) {
	m := NewMemStore()
	ctx := context.Background()
	now := int64(40_000) * dayMS

	seedBucket(ctx, m, "c", now-3*hourMS, protocol.StatusUp, 3)
	seedBucket(ctx, m, "c", now-2*hourMS, protocol.StatusDown, 3)
	seedBucket(ctx, m, "c", now-1*hourMS, protocol.StatusDown, 3) // newest data bucket, still down

	rep, err := ComputeIncidents(ctx, m, "c", "7d", now)
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Incidents) != 1 {
		t.Fatalf("expected 1 incident, got %d", len(rep.Incidents))
	}
	inc := rep.Incidents[0]
	if !inc.Ongoing || inc.EndMS != now {
		t.Fatalf("expected ongoing with end=now, got %+v", inc)
	}
	if inc.StartMS != now-2*hourMS || inc.DurationMS != 2*hourMS {
		t.Fatalf("ongoing edges: %+v", inc)
	}
}

// TestComputeIncidentsDegraded: buckets with up>0 AND down/degraded>0 are degraded,
// not down, so worst_status is "degraded".
func TestComputeIncidentsDegraded(t *testing.T) {
	m := NewMemStore()
	ctx := context.Background()
	now := int64(40_000) * dayMS

	seedBucket(ctx, m, "c", now-4*hourMS, protocol.StatusUp, 3)
	// Mixed bucket: one probe up, another degraded (distinct probes to avoid the
	// (probe, check, ts) dedupe) → degraded verdict.
	seedBucketProbe(ctx, m, "p-up", "c", now-3*hourMS, protocol.StatusUp, 2)
	seedBucketProbe(ctx, m, "p-deg", "c", now-3*hourMS, protocol.StatusDegraded, 2)
	seedBucket(ctx, m, "c", now-2*hourMS, protocol.StatusUp, 3)

	rep, err := ComputeIncidents(ctx, m, "c", "7d", now)
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Incidents) != 1 || rep.Incidents[0].WorstStatus != "degraded" {
		t.Fatalf("expected 1 degraded incident, got %+v", rep.Incidents)
	}
}

// TestComputeIncidentsMultiple: two outages separated by an up bucket yield two
// incidents, newest first.
func TestComputeIncidentsMultiple(t *testing.T) {
	m := NewMemStore()
	ctx := context.Background()
	now := int64(40_000) * dayMS

	seedBucket(ctx, m, "c", now-6*hourMS, protocol.StatusDown, 3) // outage 1
	seedBucket(ctx, m, "c", now-5*hourMS, protocol.StatusUp, 3)   // recovery
	seedBucket(ctx, m, "c", now-4*hourMS, protocol.StatusUp, 3)
	seedBucket(ctx, m, "c", now-3*hourMS, protocol.StatusDown, 3) // outage 2
	seedBucket(ctx, m, "c", now-2*hourMS, protocol.StatusUp, 3)   // recovery

	rep, err := ComputeIncidents(ctx, m, "c", "7d", now)
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Incidents) != 2 {
		t.Fatalf("expected 2 incidents, got %d: %+v", len(rep.Incidents), rep.Incidents)
	}
	// Newest first: outage 2 (now-3h) before outage 1 (now-6h).
	if rep.Incidents[0].StartMS != now-3*hourMS || rep.Incidents[1].StartMS != now-6*hourMS {
		t.Fatalf("order: %+v", rep.Incidents)
	}
}

// TestComputeIncidentsGapBreaksRun: a missing bucket (no data) between two down
// buckets breaks the run — we don't claim an outage without observations.
func TestComputeIncidentsGapBreaksRun(t *testing.T) {
	m := NewMemStore()
	ctx := context.Background()
	now := int64(40_000) * dayMS

	seedBucket(ctx, m, "c", now-5*hourMS, protocol.StatusDown, 3)
	// now-4h has NO data (gap)
	seedBucket(ctx, m, "c", now-3*hourMS, protocol.StatusDown, 3)
	seedBucket(ctx, m, "c", now-2*hourMS, protocol.StatusUp, 3)

	rep, err := ComputeIncidents(ctx, m, "c", "7d", now)
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Incidents) != 2 {
		t.Fatalf("expected 2 incidents across the gap, got %d: %+v", len(rep.Incidents), rep.Incidents)
	}
}

// TestComputeIncidentsAllUp: an all-up window has no incidents (empty, non-nil).
func TestComputeIncidentsAllUp(t *testing.T) {
	m := NewMemStore()
	ctx := context.Background()
	now := int64(40_000) * dayMS
	for i := int64(1); i <= 5; i++ {
		seedBucket(ctx, m, "c", now-i*hourMS, protocol.StatusUp, 3)
	}
	rep, err := ComputeIncidents(ctx, m, "c", "7d", now)
	if err != nil {
		t.Fatal(err)
	}
	if rep.Incidents == nil || len(rep.Incidents) != 0 {
		t.Fatalf("expected empty non-nil incidents, got %+v", rep.Incidents)
	}
}

// TestComputeIncidentsNoData: a check with no history is an empty report, not error.
func TestComputeIncidentsNoData(t *testing.T) {
	m := NewMemStore()
	rep, err := ComputeIncidents(context.Background(), m, "unknown", "30d", int64(40_000)*dayMS)
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Incidents) != 0 || rep.Resolution != "daily" {
		t.Fatalf("expected empty daily report, got %+v", rep)
	}
}

// TestComputeIncidentsBadWindow rejects an unknown window label.
func TestComputeIncidentsBadWindow(t *testing.T) {
	m := NewMemStore()
	if _, err := ComputeIncidents(context.Background(), m, "c", "bogus", 0); err == nil {
		t.Fatal("expected error for unknown window")
	}
}

// seedBucket inserts n results with the given status into the hourly bucket that
// starts at bucketStart (offsets stay inside the hour), all from one probe.
func seedBucket(ctx context.Context, m *MemStore, checkID string, bucketStart int64, st protocol.Status, n int) {
	seedBucketProbe(ctx, m, "c-probe", checkID, bucketStart, st, n)
}

// seedBucketProbe is seedBucket with an explicit probe id, so a bucket can carry
// several probes' observations (each probe's (probe, check, ts) is distinct).
func seedBucketProbe(ctx context.Context, m *MemStore, probeID, checkID string, bucketStart int64, st protocol.Status, n int) {
	for i := 0; i < n; i++ {
		sr := resStatus(checkID, bucketStart+int64(i), st, 10)
		sr.Content.ProbeID = probeID
		_ = m.Insert(ctx, sr)
	}
}
