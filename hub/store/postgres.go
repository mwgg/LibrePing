package store

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/mwgg/libreping/pkg/protocol"
)

// PgStore is a Postgres/TimescaleDB-backed ResultStore.
type PgStore struct {
	pool *pgxpool.Pool
}

// NewPgStore connects to the database at dsn.
func NewPgStore(ctx context.Context, dsn string) (*PgStore, error) {
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		return nil, err
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("ping database: %w", err)
	}
	return &PgStore{pool: pool}, nil
}

// RunMigrations applies every *.sql file in dir, in lexical order. Files are
// expected to be idempotent (CREATE ... IF NOT EXISTS), so re-running on
// startup is safe.
func (s *PgStore) RunMigrations(ctx context.Context, dir string) error {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return fmt.Errorf("read migrations dir %s: %w", dir, err)
	}
	var files []string
	for _, e := range entries {
		if !e.IsDir() && strings.HasSuffix(e.Name(), ".sql") {
			files = append(files, e.Name())
		}
	}
	sort.Strings(files)
	for _, f := range files {
		sqlBytes, err := os.ReadFile(filepath.Join(dir, f))
		if err != nil {
			return err
		}
		if _, err := s.pool.Exec(ctx, string(sqlBytes)); err != nil {
			return fmt.Errorf("apply migration %s: %w", f, err)
		}
	}
	return nil
}

func (s *PgStore) Insert(ctx context.Context, sr protocol.SignedResult) error {
	detail, err := json.Marshal(sr.Content.Detail)
	if err != nil {
		return err
	}
	const q = `
INSERT INTO results
  (probe_id, check_id, check_type, target, country, city, lat, lon,
   timestamp_ms, status, rtt_ms, detail, pubkey, signature)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)
ON CONFLICT (probe_id, check_id, timestamp_ms) DO NOTHING`
	c := sr.Content
	_, err = s.pool.Exec(ctx, q,
		c.ProbeID, c.CheckID, string(c.CheckType), c.Target,
		c.Location.Country, c.Location.City, c.Location.Lat, c.Location.Lon,
		c.TimestampMS, string(c.Status), c.RTTMillis, detail,
		[]byte(sr.PubKey), sr.Signature,
	)
	return err
}

const resultColumnsSelect = `
SELECT probe_id, check_id, check_type, target, country, city, lat, lon,
       timestamp_ms, status, rtt_ms, detail, pubkey, signature
FROM results`

func (s *PgStore) Recent(ctx context.Context, limit int) ([]protocol.SignedResult, error) {
	if limit <= 0 {
		limit = 100
	}
	rows, err := s.pool.Query(ctx, resultColumnsSelect+` ORDER BY timestamp_ms DESC LIMIT $1`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanResults(rows)
}

func (s *PgStore) RecentSince(ctx context.Context, sinceMS int64, limit int) ([]protocol.SignedResult, error) {
	if limit <= 0 {
		limit = 1000
	}
	rows, err := s.pool.Query(ctx, resultColumnsSelect+` WHERE timestamp_ms >= $1 ORDER BY timestamp_ms DESC LIMIT $2`, sinceMS, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanResults(rows)
}

// beforeClause returns " AND timestamp_ms < $N" (and the arg) when beforeMS > 0,
// for backward pagination; otherwise an empty clause and no extra arg.
func beforeClause(beforeMS int64, n int) (string, []any) {
	if beforeMS <= 0 {
		return "", nil
	}
	return fmt.Sprintf(" AND timestamp_ms < $%d", n), []any{beforeMS}
}

func (s *PgStore) RecentSinceCheck(ctx context.Context, checkID string, sinceMS, beforeMS int64, limit int) ([]protocol.SignedResult, error) {
	if limit <= 0 {
		limit = 1000
	}
	clause, extra := beforeClause(beforeMS, 4)
	args := append([]any{checkID, sinceMS, limit}, extra...)
	rows, err := s.pool.Query(ctx, resultColumnsSelect+
		` WHERE check_id = $1 AND timestamp_ms >= $2`+clause+` ORDER BY timestamp_ms DESC LIMIT $3`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanResults(rows)
}

func (s *PgStore) RecentSinceShard(ctx context.Context, shardID uint32, sinceMS, beforeMS int64, limit int) ([]protocol.SignedResult, error) {
	if limit <= 0 {
		limit = 1000
	}
	// Filters on result_shard(check_id) (migration 0007), which mirrors shard.Of
	// and is expression-indexed, so the LIMIT applies only to this shard's rows.
	clause, extra := beforeClause(beforeMS, 4)
	args := append([]any{int32(shardID), sinceMS, limit}, extra...)
	rows, err := s.pool.Query(ctx, resultColumnsSelect+
		` WHERE result_shard(check_id) = $1 AND timestamp_ms >= $2`+clause+` ORDER BY timestamp_ms DESC LIMIT $3`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanResults(rows)
}

// HistoryRange serves rolled-up history for one check from the continuous
// aggregates (results_hourly / results_daily). Real-time aggregation means the
// most recent, not-yet-materialized window is filled from raw on the fly, so the
// leading edge is covered. Returns aggregate DTOs, not signed results.
func (s *PgStore) HistoryRange(ctx context.Context, checkID string, fromMS, toMS int64) ([]HistorySummary, error) {
	if toMS <= fromMS {
		return nil, nil
	}
	label, _ := historyResolution(toMS - fromMS)
	view := "results_hourly"
	if label == "daily" {
		view = "results_daily"
	}
	q := `SELECT bucket, probe_id, samples, up_count, down_count, degraded_count,
	             rtt_avg, rtt_min, rtt_max, last_status, check_type, target,
	             country, city, lat, lon
	      FROM ` + view + `
	      WHERE check_id = $1 AND bucket >= $2 AND bucket < $3
	      ORDER BY bucket, probe_id`
	rows, err := s.pool.Query(ctx, q, checkID, fromMS, toMS)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []HistorySummary
	for rows.Next() {
		h := HistorySummary{Resolution: label, CheckID: checkID}
		var rttAvg, rttMin, rttMax *float64
		if err := rows.Scan(
			&h.BucketMS, &h.ProbeID, &h.Samples, &h.UpCount, &h.DownCount, &h.DegradedCount,
			&rttAvg, &rttMin, &rttMax, &h.LastStatus, &h.CheckType, &h.Target,
			&h.Location.Country, &h.Location.City, &h.Location.Lat, &h.Location.Lon,
		); err != nil {
			return nil, err
		}
		if rttAvg != nil {
			h.RTTAvg = *rttAvg
		}
		if rttMin != nil {
			h.RTTMin = *rttMin
		}
		if rttMax != nil {
			h.RTTMax = *rttMax
		}
		out = append(out, h)
	}
	return out, rows.Err()
}

// scanResults reads SignedResult rows in the column order of resultColumnsSelect.
func scanResults(rows pgx.Rows) ([]protocol.SignedResult, error) {
	var out []protocol.SignedResult
	for rows.Next() {
		var (
			sr        protocol.SignedResult
			c         protocol.ResultContent
			checkType string
			status    string
			detail    []byte
			pubkey    []byte
		)
		if err := rows.Scan(
			&c.ProbeID, &c.CheckID, &checkType, &c.Target,
			&c.Location.Country, &c.Location.City, &c.Location.Lat, &c.Location.Lon,
			&c.TimestampMS, &status, &c.RTTMillis, &detail,
			&pubkey, &sr.Signature,
		); err != nil {
			return nil, err
		}
		c.CheckType = protocol.CheckType(checkType)
		c.Status = protocol.Status(status)
		_ = json.Unmarshal(detail, &c.Detail)
		sr.Content = c
		sr.PubKey = pubkey
		out = append(out, sr)
	}
	return out, rows.Err()
}

func (s *PgStore) Close() error {
	s.pool.Close()
	return nil
}
