package store

import (
	"context"
	"fmt"
	"strings"
)

// TierConfig controls the result storage tiers. The principle: the further back
// a measurement is, the less detail is kept. Recent data is per-result (and
// transparently compressed); older data is rolled up into hourly then daily
// summaries; the oldest is dropped. This keeps a hub's disk modest enough for a
// hobbyist VPS even though every hub stores the whole network's stream.
//
// A value of 0 disables that tier's retention (keep forever). Days are converted
// to the hypertable's integer time unit (milliseconds since epoch).
type TierConfig struct {
	CompressAfterDays   int // compress raw results older than this (0 = no compression)
	RawRetentionDays    int // drop raw results older than this (0 = keep)
	HourlyRetentionDays int // drop hourly rollups older than this (0 = keep)
	DailyRetentionDays  int // drop daily rollups older than this (0 = keep)
}

// DefaultTierConfig is tuned for a small VPS: a week of full-detail raw results,
// three months of hourly summaries, two years of daily summaries.
func DefaultTierConfig() TierConfig {
	return TierConfig{CompressAfterDays: 2, RawRetentionDays: 7, HourlyRetentionDays: 90, DailyRetentionDays: 730}
}

// hourlyCompressAfterDays compresses hourly-rollup chunks older than this. Fixed
// (not env-tunable) to keep configuration small; hourly rows are already tiny.
const hourlyCompressAfterDays = 7

// maxTierRefreshDays bounds the one-time historical aggregate refresh when a
// tier's retention is "keep forever" (0), so the catch-up can't scan unbounded
// history on a long-lived hub.
const maxTierRefreshDays = 30

// refreshLookbackDays is how far back to manually refresh an aggregate so no raw
// row is dropped by retention before it is summarized: one day past the lower
// tier's retention, or a bounded default when that tier keeps data forever.
func refreshLookbackDays(retentionDays int) int {
	if retentionDays <= 0 {
		return maxTierRefreshDays
	}
	return retentionDays + 1
}

const dayMS = int64(86_400_000)

// ConfigureResultTiers sets up compression + downsampling on the results
// hypertable: native columnar compression, two hierarchical continuous
// aggregates (hourly→daily), and retention policies per tier. It is idempotent
// and safe to run on every startup; changing a TierConfig value re-applies the
// affected retention/compression policy.
//
// Statements are executed one at a time (not as a batch) because TimescaleDB
// forbids creating a continuous aggregate inside a transaction, and pgx would
// wrap a multi-statement Exec in one. Requires the TimescaleDB extension, which
// the hub's Postgres mode always has.
func (s *PgStore) ConfigureResultTiers(ctx context.Context, cfg TierConfig) error {
	if err := s.migrateResultAggregates(ctx); err != nil {
		return err
	}
	for _, stmt := range tierStatements(cfg) {
		if _, err := s.pool.Exec(ctx, stmt); err != nil {
			// The one-time historical aggregate refresh is best-effort: on a later
			// restart the refresh window can clip an already-compressed rollup
			// chunk, which some TimescaleDB versions refuse — that must not abort
			// the rest of tier setup (compression + retention policies), and the
			// continuous-aggregate policy keeps materializing going forward anyway.
			if strings.HasPrefix(strings.TrimSpace(stmt), "CALL refresh_continuous_aggregate") {
				continue
			}
			return fmt.Errorf("configure result tiers: %w\nstatement: %s", err, stmt)
		}
	}
	return nil
}

// migrateResultAggregates drops the result rollups when they exist in an older
// shape, so tierStatements' CREATE ... IF NOT EXISTS recreates them with the
// current definition. The continuous aggregates are created IF NOT EXISTS, so a
// changed SELECT — here, excluding timed-out samples from the RTT stats — would
// otherwise never take effect on a hub that already ran an earlier version.
//
// Detection: the current definition adds an rtt_samples column; its absence on an
// existing results_hourly marks the old shape. Dropping hourly CASCADE also drops
// the dependent daily aggregate (and their policies); both are rebuilt and
// re-materialized from raw by the CREATE + refresh steps that follow. This runs
// at most once — after the rebuild the column is present, so later restarts skip
// it (no per-restart data loss).
func (s *PgStore) migrateResultAggregates(ctx context.Context) error {
	var exists, current bool
	if err := s.pool.QueryRow(ctx, `
		SELECT
		  to_regclass('results_hourly') IS NOT NULL,
		  EXISTS (SELECT 1 FROM information_schema.columns
		          WHERE table_name = 'results_hourly' AND column_name = 'rtt_samples')`,
	).Scan(&exists, &current); err != nil {
		return fmt.Errorf("inspect result aggregates: %w", err)
	}
	if exists && !current {
		if _, err := s.pool.Exec(ctx, `DROP MATERIALIZED VIEW IF EXISTS results_hourly CASCADE`); err != nil {
			return fmt.Errorf("drop outdated result aggregates: %w", err)
		}
	}
	return nil
}

// tierStatements builds the ordered, idempotent statement list. Retention and
// compression policies are removed then (conditionally) re-added so a changed
// config takes effect and a 0 disables the tier.
func tierStatements(cfg TierConfig) []string {
	stmts := []string{
		// An integer hypertable needs a "now" function before time-based
		// compression/retention policies can be attached.
		`CREATE OR REPLACE FUNCTION results_now_ms() RETURNS BIGINT
		   LANGUAGE SQL STABLE AS $$ SELECT (extract(epoch from now())*1000)::BIGINT $$`,
		`SELECT set_integer_now_func('results', 'results_now_ms', replace_if_exists => true)`,

		// Enable columnar compression on raw results, grouped so a probe's run of
		// a check compresses together (the repetitive columns shrink enormously;
		// the signature does not, which is the storage floor).
		`ALTER TABLE results SET (
		   timescaledb.compress,
		   timescaledb.compress_segmentby = 'check_id, probe_id',
		   timescaledb.compress_orderby = 'timestamp_ms DESC')`,

		// Tier 1: hourly rollup per (check, probe) — counts by status and RTT
		// stats, plus the last status/target/location. No signatures, no detail
		// JSONB, no per-result rows: this is the "less detail" tier.
		`CREATE MATERIALIZED VIEW IF NOT EXISTS results_hourly
		 WITH (timescaledb.continuous) AS
		 SELECT
		   time_bucket(3600000::BIGINT, timestamp_ms) AS bucket,
		   check_id, probe_id,
		   count(*)                                    AS samples,
		   count(*) FILTER (WHERE status = 'up')       AS up_count,
		   count(*) FILTER (WHERE status = 'down')     AS down_count,
		   count(*) FILTER (WHERE status = 'degraded') AS degraded_count,
		   -- Latency stats over MEASURED samples only: a down/timed-out check
		   -- reports the time it waited before giving up (~the timeout), not the
		   -- service's latency, so exclude down and any 0-rtt rows. rtt_samples
		   -- carries the measured count so the daily rollup can sample-weight it.
		   count(*) FILTER (WHERE status <> 'down' AND rtt_ms > 0)   AS rtt_samples,
		   avg(rtt_ms) FILTER (WHERE status <> 'down' AND rtt_ms > 0) AS rtt_avg,
		   min(rtt_ms) FILTER (WHERE status <> 'down' AND rtt_ms > 0) AS rtt_min,
		   max(rtt_ms) FILTER (WHERE status <> 'down' AND rtt_ms > 0) AS rtt_max,
		   last(status, timestamp_ms)     AS last_status,
		   last(check_type, timestamp_ms) AS check_type,
		   last(target, timestamp_ms)     AS target,
		   last(country, timestamp_ms)    AS country,
		   last(city, timestamp_ms)       AS city,
		   last(lat, timestamp_ms)        AS lat,
		   last(lon, timestamp_ms)        AS lon
		 FROM results
		 GROUP BY bucket, check_id, probe_id
		 WITH NO DATA`,

		// Tier 2: daily rollup, built hierarchically from the hourly aggregate so
		// it survives raw AND hourly retention (the data has already been folded
		// up before the lower tier is dropped).
		`CREATE MATERIALIZED VIEW IF NOT EXISTS results_daily
		 WITH (timescaledb.continuous) AS
		 SELECT
		   time_bucket(86400000::BIGINT, bucket) AS bucket,
		   check_id, probe_id,
		   sum(samples) AS samples, sum(up_count) AS up_count,
		   sum(down_count) AS down_count, sum(degraded_count) AS degraded_count,
		   -- Sample-weight the hourly averages by the MEASURED count (rtt_samples),
		   -- not total samples: an hour with one measurement must not count the same
		   -- as an hour with thousands, and a down-heavy hour must not dilute the
		   -- day's latency. Consistent with the hourly tier, timed-out/down rows are
		   -- excluded (min/max already filtered there, so their NULLs drop out here).
		   sum(rtt_samples) AS rtt_samples,
		   sum(rtt_avg * rtt_samples) / nullif(sum(rtt_samples), 0) AS rtt_avg,
		   min(rtt_min) AS rtt_min, max(rtt_max) AS rtt_max,
		   last(last_status, bucket) AS last_status,
		   last(check_type, bucket)  AS check_type,
		   last(target, bucket)      AS target,
		   last(country, bucket)     AS country,
		   last(city, bucket)        AS city,
		   last(lat, bucket)         AS lat,
		   last(lon, bucket)         AS lon
		 FROM results_hourly
		 GROUP BY time_bucket(86400000::BIGINT, bucket), check_id, probe_id
		 WITH NO DATA`,

		`ALTER MATERIALIZED VIEW results_hourly SET (timescaledb.compress = true)`,

		// Enable real-time aggregation (recent TimescaleDB defaults materialized_only
		// to true): a query against the aggregate unions the materialized rollups
		// with a live aggregate over the not-yet-materialized recent window, so the
		// leading edge (newer than the refresh policy's end_offset) is still visible
		// in history reads instead of lagging by up to an hour/day.
		`ALTER MATERIALIZED VIEW results_hourly SET (timescaledb.materialized_only = false)`,
		`ALTER MATERIALIZED VIEW results_daily SET (timescaledb.materialized_only = false)`,

		// Keep the rollups materialized. start_offset must comfortably exceed the
		// next tier's retention so nothing is lost in the fold-up.
		`SELECT add_continuous_aggregate_policy('results_hourly',
		   start_offset => ` + ms(3) + `, end_offset => 3600000::BIGINT,
		   schedule_interval => INTERVAL '30 minutes', if_not_exists => true)`,
		`SELECT add_continuous_aggregate_policy('results_daily',
		   start_offset => ` + ms(10) + `, end_offset => 86400000::BIGINT,
		   schedule_interval => INTERVAL '6 hours', if_not_exists => true)`,
	}

	// Materialize existing history BEFORE retention is (re)applied. The aggregates
	// are created WITH NO DATA and their refresh policies only cover a recent
	// rolling window, so on an upgrade/rollout raw rows older than that window
	// would be dropped by retention before they were ever folded into the hourly
	// (then daily) summaries — silent history loss. A one-time manual refresh over
	// the raw/hourly retention windows closes that gap. Refresh is idempotent, so
	// re-running on every startup is safe; hourly is refreshed first so the
	// hierarchical daily refresh sees materialized hourly rows.
	// Cap the hourly catch-up so the window never reaches into hourly chunks that
	// the hourly compression policy may already have compressed (>
	// hourlyCompressAfterDays). The continuous-aggregate policy materializes the
	// recent window continuously, so this only needs to bridge the gap between the
	// policy's reach and raw retention. Daily is never compressed, but cap it too
	// so a long hourly retention can't trigger a huge scan each restart.
	hourlyLookback := refreshLookbackDays(cfg.RawRetentionDays)
	if hourlyLookback > hourlyCompressAfterDays {
		hourlyLookback = hourlyCompressAfterDays
	}
	dailyLookback := refreshLookbackDays(cfg.HourlyRetentionDays)
	if dailyLookback > maxTierRefreshDays {
		dailyLookback = maxTierRefreshDays
	}
	stmts = append(stmts,
		`CALL refresh_continuous_aggregate('results_hourly', results_now_ms() - `+ms(hourlyLookback)+`, NULL)`,
		`CALL refresh_continuous_aggregate('results_daily', results_now_ms() - `+ms(dailyLookback)+`, NULL)`,
	)

	// Tunable policies: remove then (if enabled) re-add, so a config change or a
	// 0 ("keep forever") takes effect on restart.
	stmts = append(stmts,
		`SELECT remove_compression_policy('results', if_exists => true)`)
	if cfg.CompressAfterDays > 0 {
		stmts = append(stmts, `SELECT add_compression_policy('results', compress_after => `+ms(cfg.CompressAfterDays)+`, if_not_exists => true)`)
	}
	stmts = append(stmts, `SELECT remove_retention_policy('results', if_exists => true)`)
	if cfg.RawRetentionDays > 0 {
		stmts = append(stmts, `SELECT add_retention_policy('results', drop_after => `+ms(cfg.RawRetentionDays)+`, if_not_exists => true)`)
	}
	stmts = append(stmts, `SELECT remove_retention_policy('results_hourly', if_exists => true)`)
	if cfg.HourlyRetentionDays > 0 {
		stmts = append(stmts, `SELECT add_retention_policy('results_hourly', drop_after => `+ms(cfg.HourlyRetentionDays)+`, if_not_exists => true)`)
	}
	stmts = append(stmts, `SELECT remove_retention_policy('results_daily', if_exists => true)`)
	if cfg.DailyRetentionDays > 0 {
		stmts = append(stmts, `SELECT add_retention_policy('results_daily', drop_after => `+ms(cfg.DailyRetentionDays)+`, if_not_exists => true)`)
	}
	stmts = append(stmts,
		`SELECT remove_compression_policy('results_hourly', if_exists => true)`,
		`SELECT add_compression_policy('results_hourly', compress_after => `+ms(hourlyCompressAfterDays)+`, if_not_exists => true)`,
	)
	return stmts
}

// ms renders a day count as a BIGINT-typed millisecond literal. The value is
// computed in Go (int64) so it can't overflow int4 during SQL evaluation.
func ms(days int) string {
	return fmt.Sprintf("%d::BIGINT", int64(days)*dayMS)
}
