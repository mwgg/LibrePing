package store

import (
	"context"
	"testing"

	"github.com/mwgg/libreping/hub/shard"
	"github.com/mwgg/libreping/pkg/protocol"
)

func res(checkID string, ts int64) protocol.SignedResult {
	return protocol.SignedResult{Content: protocol.ResultContent{
		ProbeID: "p", CheckID: checkID, Status: protocol.StatusUp, TimestampMS: ts,
	}}
}

// TestRecentSinceCheckFiltersBeforeLimit proves the MEDIUM-5 fix: filtering by
// check happens before the limit, so a flood of other checks' newer rows cannot
// hide an older matching row inside the window.
func TestRecentSinceCheckFiltersBeforeLimit(t *testing.T) {
	m := NewMemStore()
	ctx := context.Background()
	// 1 old row for the wanted check, then many newer rows for other checks.
	_ = m.Insert(ctx, res("wanted", 100))
	for i := int64(0); i < 50; i++ {
		_ = m.Insert(ctx, res("other", 1000+i))
	}
	got, err := m.RecentSinceCheck(ctx, "wanted", 0, 0, 3)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].Content.CheckID != "wanted" {
		t.Fatalf("expected the older wanted row despite newer noise, got %+v", got)
	}
}

func resStatus(checkID string, ts int64, st protocol.Status, rtt float64) protocol.SignedResult {
	return protocol.SignedResult{Content: protocol.ResultContent{
		ProbeID: "p", CheckID: checkID, Status: st, RTTMillis: rtt, TimestampMS: ts,
	}}
}

// TestHistoryRangeBuckets checks the DB-less rollup: results in one hour bucket
// aggregate into a single summary with weighted-friendly counts and RTT stats.
// Latency stats must EXCLUDE down/timed-out samples — a down check's rtt is the
// time it waited (0 on instant refusal, ~the timeout otherwise), not the
// service's latency — so only the up/degraded measurements drive min/avg/max.
func TestHistoryRangeBuckets(t *testing.T) {
	m := NewMemStore()
	ctx := context.Background()
	base := int64(10) * hourMS // aligned to an hour bucket
	_ = m.Insert(ctx, resStatus("c", base+1, protocol.StatusUp, 10))
	_ = m.Insert(ctx, resStatus("c", base+2, protocol.StatusDown, 0)) // instant refusal
	_ = m.Insert(ctx, resStatus("c", base+3, protocol.StatusUp, 30))
	_ = m.Insert(ctx, resStatus("c", base+4, protocol.StatusDown, 10000)) // 10s timeout

	got, err := m.HistoryRange(ctx, "c", base, base+hourMS)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 {
		t.Fatalf("expected 1 bucket, got %d", len(got))
	}
	h := got[0]
	if h.Samples != 4 || h.UpCount != 2 || h.DownCount != 2 {
		t.Fatalf("bad counts: %+v", h)
	}
	// Min/avg/max are over the two up samples (10, 30) only: the 0 and the 10000
	// from the down checks must not leak in.
	if h.RTTMin != 10 || h.RTTMax != 30 || h.RTTAvg != 20 {
		t.Fatalf("rtt stats should exclude timeouts, got min=%g avg=%g max=%g", h.RTTMin, h.RTTAvg, h.RTTMax)
	}
	if h.LastStatus != "down" || h.Resolution != "hourly" {
		t.Fatalf("bad stats: %+v", h)
	}
	// Measured count and latency buckets exclude the down rows: the two up samples
	// (10, 30) are both <= 50, so every le_<bound> from 50ms up counts 2; le_25
	// counts only the 10ms sample; le_5 counts none. le_10000 must equal rtt_samples
	// (no overflow), so overflow = rtt_samples - le_10000 = 0.
	if h.RTTSamples != 2 {
		t.Fatalf("rtt_samples should be 2 measured, got %d", h.RTTSamples)
	}
	wantBuckets := map[int64]int64{5: 0, 10: 1, 25: 1, 50: 2, 100: 2, 10000: 2}
	for i, bound := range RttBucketBoundsMS {
		if want, ok := wantBuckets[bound]; ok && h.RttBuckets[i] != want {
			t.Fatalf("le_%d: got %d, want %d", bound, h.RttBuckets[i], want)
		}
	}
	if h.RttBuckets[numRttBuckets-1] != h.RTTSamples {
		t.Fatalf("le_10000 (%d) must equal rtt_samples (%d): no overflow expected",
			h.RttBuckets[numRttBuckets-1], h.RTTSamples)
	}
}

func TestRecentSinceShardAndBefore(t *testing.T) {
	m := NewMemStore()
	ctx := context.Background()
	id := "abcd1234abcd1234"
	for _, ts := range []int64{100, 200, 300} {
		_ = m.Insert(ctx, res(id, ts))
	}
	sh := shard.Of(id)
	// before_ms excludes the newest row.
	got, _ := m.RecentSinceShard(ctx, sh, 0, 300, 10)
	if len(got) != 2 || got[0].Content.TimestampMS != 200 {
		t.Fatalf("expected ts<300 newest-first, got %+v", got)
	}
}
