// Package store persists verified results on a hub.
//
// Two implementations share one interface so the rest of the hub never cares
// which is in use:
//   - MemStore keeps results in memory (used for tests and DB-less probe-style
//     runs),
//   - PgStore writes to Postgres/TimescaleDB for real hub deployments.
package store

import (
	"context"
	"sort"
	"sync"

	"github.com/mwgg/libreping/hub/shard"
	"github.com/mwgg/libreping/pkg/protocol"
)

// ResultStore is the persistence contract for the hub.
type ResultStore interface {
	// Insert stores a verified result. It must be idempotent on
	// (probe_id, check_id, timestamp_ms): re-delivering the same gossiped
	// result is normal and must not duplicate rows.
	Insert(ctx context.Context, sr protocol.SignedResult) error
	// Recent returns the most recent results, newest first.
	Recent(ctx context.Context, limit int) ([]protocol.SignedResult, error)
	// RecentSince returns results with timestamp_ms >= sinceMS, newest first,
	// capped at limit. Used for result anti-entropy and peer catch-up sync.
	RecentSince(ctx context.Context, sinceMS int64, limit int) ([]protocol.SignedResult, error)
	// RecentSinceCheck returns results for one check with timestamp_ms >= sinceMS
	// (and < beforeMS when beforeMS > 0), newest first, capped at limit. The
	// filter is applied BEFORE the limit, so a busy network's other checks can't
	// push a requested check's rows out of the window (the bug a global
	// RecentSince + in-memory filter has). beforeMS is an exclusive upper bound
	// for backward pagination (0 = no upper bound).
	RecentSinceCheck(ctx context.Context, checkID string, sinceMS, beforeMS int64, limit int) ([]protocol.SignedResult, error)
	// RecentSinceShard is RecentSinceCheck for a whole shard (backfill/repair).
	RecentSinceShard(ctx context.Context, shardID uint32, sinceMS, beforeMS int64, limit int) ([]protocol.SignedResult, error)
	// HistoryRange returns per-(probe) rolled-up summaries for one check over
	// [fromMS, toMS), at a resolution chosen from the span (hourly for short
	// ranges, daily for long ones). Summaries are locally-derived, NOT per-result
	// signed records — they are aggregates, so they are returned as DTOs rather
	// than SignedResult.
	HistoryRange(ctx context.Context, checkID string, fromMS, toMS int64) ([]HistorySummary, error)
	// Close releases resources.
	Close() error
}

// HistorySummary is one rolled-up bucket for a (check, probe): status counts and
// RTT stats over the bucket. Resolution is "hourly" or "daily". These are
// aggregates the hub computed locally; unlike a Result they are not individually
// probe-signed.
type HistorySummary struct {
	BucketMS      int64             `json:"bucket_ms"`
	Resolution    string            `json:"resolution"`
	CheckID       string            `json:"check_id"`
	ProbeID       string            `json:"probe_id"`
	Samples       int64             `json:"samples"`
	UpCount       int64             `json:"up_count"`
	DownCount     int64             `json:"down_count"`
	DegradedCount int64             `json:"degraded_count"`
	RTTAvg        float64           `json:"rtt_avg"`
	RTTMin        float64           `json:"rtt_min"`
	RTTMax        float64           `json:"rtt_max"`
	LastStatus    string            `json:"last_status"`
	CheckType     string            `json:"check_type"`
	Target        string            `json:"target"`
	Location      protocol.Location `json:"location"`
}

const (
	hourMS = int64(3_600_000)
	// historyHourlyMaxSpan is the longest range served at hourly resolution;
	// longer ranges use daily buckets to keep the response bounded.
	historyHourlyMaxSpan = int64(14) * dayMS
)

// historyResolution picks the bucket size for a span: hourly for short ranges,
// daily for long ones.
func historyResolution(spanMS int64) (label string, bucketMS int64) {
	if spanMS <= historyHourlyMaxSpan {
		return "hourly", hourMS
	}
	return "daily", dayMS
}

// MemStore is an in-memory ResultStore. Safe for concurrent use.
type MemStore struct {
	mu   sync.Mutex
	seen map[string]struct{}
	all  []protocol.SignedResult
}

// NewMemStore returns an empty in-memory store.
func NewMemStore() *MemStore {
	return &MemStore{seen: map[string]struct{}{}}
}

func dedupeKey(c protocol.ResultContent) string {
	return c.ProbeID + "|" + c.CheckID + "|" + itoa(c.TimestampMS)
}

func (m *MemStore) Insert(_ context.Context, sr protocol.SignedResult) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	key := dedupeKey(sr.Content)
	if _, ok := m.seen[key]; ok {
		return nil
	}
	m.seen[key] = struct{}{}
	m.all = append(m.all, sr)
	return nil
}

func (m *MemStore) Recent(_ context.Context, limit int) ([]protocol.SignedResult, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]protocol.SignedResult, len(m.all))
	copy(out, m.all)
	sort.Slice(out, func(i, j int) bool {
		return out[i].Content.TimestampMS > out[j].Content.TimestampMS
	})
	if limit > 0 && len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}

func (m *MemStore) RecentSince(_ context.Context, sinceMS int64, limit int) ([]protocol.SignedResult, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]protocol.SignedResult, 0, len(m.all))
	for _, sr := range m.all {
		if sr.Content.TimestampMS >= sinceMS {
			out = append(out, sr)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].Content.TimestampMS > out[j].Content.TimestampMS
	})
	if limit > 0 && len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}

func (m *MemStore) RecentSinceCheck(_ context.Context, checkID string, sinceMS, beforeMS int64, limit int) ([]protocol.SignedResult, error) {
	return m.filterSince(func(c protocol.ResultContent) bool { return c.CheckID == checkID }, sinceMS, beforeMS, limit), nil
}

func (m *MemStore) RecentSinceShard(_ context.Context, shardID uint32, sinceMS, beforeMS int64, limit int) ([]protocol.SignedResult, error) {
	return m.filterSince(func(c protocol.ResultContent) bool { return shard.Of(c.CheckID) == shardID }, sinceMS, beforeMS, limit), nil
}

// filterSince returns matching results with timestamp_ms >= sinceMS (and <
// beforeMS when beforeMS > 0), newest first, capped at limit (the filter is
// applied before the cap).
func (m *MemStore) filterSince(match func(protocol.ResultContent) bool, sinceMS, beforeMS int64, limit int) []protocol.SignedResult {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]protocol.SignedResult, 0, len(m.all))
	for _, sr := range m.all {
		if sr.Content.TimestampMS < sinceMS {
			continue
		}
		if beforeMS > 0 && sr.Content.TimestampMS >= beforeMS {
			continue
		}
		if match(sr.Content) {
			out = append(out, sr)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].Content.TimestampMS > out[j].Content.TimestampMS
	})
	if limit > 0 && len(out) > limit {
		out = out[:limit]
	}
	return out
}

func (m *MemStore) HistoryRange(_ context.Context, checkID string, fromMS, toMS int64) ([]HistorySummary, error) {
	if toMS <= fromMS {
		return nil, nil
	}
	label, bucketMS := historyResolution(toMS - fromMS)

	m.mu.Lock()
	defer m.mu.Unlock()
	// Aggregate raw results into (probe, bucket) summaries, mirroring the SQL
	// continuous aggregates so a DB-less hub serves the same shape.
	type acc struct {
		s      HistorySummary
		rttSum float64
		rttN   int64 // measured samples (down/0-rtt excluded), for the average
		lastTS int64
	}
	buckets := map[string]*acc{}
	for _, sr := range m.all {
		c := sr.Content
		if c.CheckID != checkID || c.TimestampMS < fromMS || c.TimestampMS >= toMS {
			continue
		}
		b := (c.TimestampMS / bucketMS) * bucketMS
		key := c.ProbeID + "|" + itoa(b)
		a := buckets[key]
		if a == nil {
			a = &acc{s: HistorySummary{
				BucketMS: b, Resolution: label, CheckID: checkID, ProbeID: c.ProbeID,
			}}
			buckets[key] = a
		}
		a.s.Samples++
		switch c.Status {
		case protocol.StatusUp:
			a.s.UpCount++
		case protocol.StatusDown:
			a.s.DownCount++
		case protocol.StatusDegraded:
			a.s.DegradedCount++
		}
		// Latency stats exclude down/timed-out samples: a down check's rtt is the
		// time it waited before giving up (~the timeout), not the service's
		// latency. Mirrors the SQL aggregates and the dashboard's latencyStats.
		if c.Status != protocol.StatusDown && c.RTTMillis > 0 {
			if a.rttN == 0 {
				a.s.RTTMin = c.RTTMillis
				a.s.RTTMax = c.RTTMillis
			} else {
				if c.RTTMillis < a.s.RTTMin {
					a.s.RTTMin = c.RTTMillis
				}
				if c.RTTMillis > a.s.RTTMax {
					a.s.RTTMax = c.RTTMillis
				}
			}
			a.rttSum += c.RTTMillis
			a.rttN++
		}
		if c.TimestampMS >= a.lastTS {
			a.lastTS = c.TimestampMS
			a.s.LastStatus = string(c.Status)
			a.s.CheckType = string(c.CheckType)
			a.s.Target = c.Target
			a.s.Location = c.Location
		}
	}
	out := make([]HistorySummary, 0, len(buckets))
	for _, a := range buckets {
		if a.rttN > 0 {
			a.s.RTTAvg = a.rttSum / float64(a.rttN)
		}
		out = append(out, a.s)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].BucketMS != out[j].BucketMS {
			return out[i].BucketMS < out[j].BucketMS
		}
		return out[i].ProbeID < out[j].ProbeID
	})
	return out, nil
}

func (m *MemStore) Close() error { return nil }

func itoa(n int64) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}
