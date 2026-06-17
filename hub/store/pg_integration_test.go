package store

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/mwgg/libreping/hub/shard"
	"github.com/mwgg/libreping/pkg/identity"
	"github.com/mwgg/libreping/pkg/protocol"
)

// TestPgIntegration exercises the Postgres-only paths that unit tests can't
// reach: migrations (incl. 0007's result_shard function + indexes), tier setup
// (continuous aggregates, weighted daily rollup, historical refresh), and the
// filter-before-limit / history queries. Skipped unless TEST_DATABASE_URL points
// at a TimescaleDB instance.
func TestPgIntegration(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("set TEST_DATABASE_URL to run the Postgres integration test")
	}
	ctx := context.Background()
	pg, err := NewPgStore(ctx, dsn)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer pg.Close()

	if err := pg.RunMigrations(ctx, "../../migrations"); err != nil {
		t.Fatalf("migrations: %v", err)
	}
	// Isolate from prior runs: drop the aggregates and clear raw so counts are
	// deterministic. ConfigureResultTiers recreates the aggregates.
	_, _ = pg.pool.Exec(ctx, "DROP MATERIALIZED VIEW IF EXISTS results_daily")
	_, _ = pg.pool.Exec(ctx, "DROP MATERIALIZED VIEW IF EXISTS results_hourly")
	if _, err := pg.pool.Exec(ctx, "TRUNCATE results"); err != nil {
		t.Fatalf("truncate: %v", err)
	}
	if err := pg.ConfigureResultTiers(ctx, DefaultTierConfig()); err != nil {
		t.Fatalf("configure tiers: %v", err)
	}
	// Re-run to prove idempotency (the refresh + policies must be safe twice).
	if err := pg.ConfigureResultTiers(ctx, DefaultTierConfig()); err != nil {
		t.Fatalf("configure tiers (2nd): %v", err)
	}

	probe, _ := identity.Generate()
	check := "abcd1234abcd1234"
	now := time.Now().UnixMilli()
	for i := int64(0); i < 5; i++ {
		sr, _ := protocol.SignResult(probe, protocol.ResultContent{
			CheckID: check, CheckType: protocol.CheckHTTP, Target: "https://svc",
			Status: protocol.StatusUp, RTTMillis: float64(10 + i), TimestampMS: now - i*1000,
		})
		if err := pg.Insert(ctx, sr); err != nil {
			t.Fatalf("insert: %v", err)
		}
	}

	// Filter-before-limit: per-check and per-shard.
	if got, err := pg.RecentSinceCheck(ctx, check, 0, 0, 100); err != nil || len(got) != 5 {
		t.Fatalf("RecentSinceCheck: %v len=%d", err, len(got))
	}
	if got, err := pg.RecentSinceShard(ctx, shard.Of(check), 0, 0, 100); err != nil || len(got) != 5 {
		t.Fatalf("RecentSinceShard: %v len=%d", err, len(got))
	}
	// before_ms excludes the newest row.
	if got, _ := pg.RecentSinceShard(ctx, shard.Of(check), 0, now, 100); len(got) != 4 {
		t.Fatalf("RecentSinceShard before_ms: len=%d want 4", len(got))
	}
	// Add two down/timed-out results (rtt ~10s and an instant 0): their RTT must
	// NOT pollute the aggregates — a down check is infinite latency, not 10s.
	for i, rtt := range []float64{10000, 0} {
		sr, _ := protocol.SignResult(probe, protocol.ResultContent{
			CheckID: check, CheckType: protocol.CheckHTTP, Target: "https://svc",
			Status: protocol.StatusDown, RTTMillis: rtt, TimestampMS: now - int64(5+i)*1000,
		})
		if err := pg.Insert(ctx, sr); err != nil {
			t.Fatalf("insert down: %v", err)
		}
	}

	// History range over the last day (hourly resolution) — at least the bucket
	// holding our rows should appear with the right counts.
	hist, err := pg.HistoryRange(ctx, check, now-2*hourMS, now+hourMS)
	if err != nil {
		t.Fatalf("HistoryRange: %v", err)
	}
	var samples, down int64
	var rttMin, rttMax float64
	for _, h := range hist {
		samples += h.Samples
		down += h.DownCount
		if h.RTTMax > rttMax {
			rttMax = h.RTTMax
		}
		if h.RTTMin > 0 && (rttMin == 0 || h.RTTMin < rttMin) {
			rttMin = h.RTTMin
		}
	}
	if samples != 7 || down != 2 {
		t.Fatalf("history counts = %d samples / %d down, want 7/2 (rows=%+v)", samples, down, hist)
	}
	// rtt stats span only the up rows (10..14); the 10000 timeout and the 0 must
	// be excluded.
	if rttMin != 10 || rttMax != 14 {
		t.Fatalf("rtt stats should exclude timeouts: min=%g max=%g, want 10/14 (rows=%+v)", rttMin, rttMax, hist)
	}
}
