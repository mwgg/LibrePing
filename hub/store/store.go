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
	// RecentProbes returns the distinct probes that produced a result with
	// timestamp_ms >= sinceMS, each with its latest self-declared location and
	// newest result timestamp. It surfaces probes that contribute results even
	// when their home hub is not in the directory — the topology map's
	// "gossip-only" probes. It reflects only what this hub holds locally (under
	// partial replication a hub holds only its shards' results).
	RecentProbes(ctx context.Context, sinceMS int64) ([]ProbeSeen, error)
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
	BucketMS      int64   `json:"bucket_ms"`
	Resolution    string  `json:"resolution"`
	CheckID       string  `json:"check_id"`
	ProbeID       string  `json:"probe_id"`
	Samples       int64   `json:"samples"`
	UpCount       int64   `json:"up_count"`
	DownCount     int64   `json:"down_count"`
	DegradedCount int64   `json:"degraded_count"`
	RTTAvg        float64 `json:"rtt_avg"`
	RTTMin        float64 `json:"rtt_min"`
	RTTMax        float64 `json:"rtt_max"`
	// RTTSamples is the MEASURED sample count (down/0-rtt excluded) backing the RTT
	// stats and the histogram denominator. RttBuckets holds cumulative latency-bucket
	// counts (le_<bound>: measured samples with rtt_ms <= RttBucketBoundsMS[i]); the
	// overflow (rtt > last bound) is RTTSamples - RttBuckets[last]. Together they let
	// HistogramPercentiles interpolate percentiles over aggregate-retention windows.
	RTTSamples int64                `json:"rtt_samples"`
	RttBuckets [numRttBuckets]int64 `json:"rtt_buckets"`
	LastStatus string               `json:"last_status"`
	CheckType  string               `json:"check_type"`
	Target     string               `json:"target"`
	Location   protocol.Location    `json:"location"`
}

// ProbeSeen is a probe observed in the result stream: its most recent
// self-declared location and the newest result timestamp. Used to place probes
// on the topology map even when their home hub is not in the directory.
type ProbeSeen struct {
	ProbeID    string
	Location   protocol.Location
	LastSeenMS int64
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

const (
	// memStoreMaxResults bounds the in-memory result ring. MemStore is the
	// trial/no-DB path (DATABASE_URL unset) and its results are already
	// documented as not persisted, so keeping a finite, generous window rather
	// than every result ever seen is acceptable and honest: a DB-less hub that
	// runs indefinitely stays bounded instead of growing until OOM. Real
	// deployments use PgStore, which has retention/tiering and is untouched here.
	memStoreMaxResults = 200_000
	// memStoreEvictBatch is how many oldest entries are dropped once the ring is
	// full, so the O(n) compaction runs once per batch of inserts (amortized
	// O(1)) instead of on every insert past the cap.
	memStoreEvictBatch = memStoreMaxResults / 8
)

// MemStore is an in-memory ResultStore. Safe for concurrent use.
//
// It is a finite ring: at most memStoreMaxResults results are retained, oldest
// (by insertion order) evicted first. Eviction also drops the corresponding
// dedupe key so memory is actually reclaimed — an evicted result that later
// re-arrives over gossip is simply re-inserted, which is fine on this
// non-persistent trial path.
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
	m.evictOverCapLocked()
	return nil
}

// evictOverCapLocked drops the oldest entries in a batch once the ring exceeds
// its cap, reclaiming both the slice element and its dedupe key. Compaction
// copies the surviving tail to the front and clears the freed slots so the
// evicted SignedResults are collected rather than pinned by the backing array.
func (m *MemStore) evictOverCapLocked() {
	if len(m.all) <= memStoreMaxResults {
		return
	}
	drop := len(m.all) - (memStoreMaxResults - memStoreEvictBatch)
	if drop > len(m.all) {
		drop = len(m.all)
	}
	for i := 0; i < drop; i++ {
		delete(m.seen, dedupeKey(m.all[i].Content))
	}
	n := copy(m.all, m.all[drop:])
	for i := n; i < len(m.all); i++ {
		m.all[i] = protocol.SignedResult{} // release references in the freed tail
	}
	m.all = m.all[:n]
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

func (m *MemStore) RecentProbes(_ context.Context, sinceMS int64) ([]ProbeSeen, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	latest := map[string]ProbeSeen{}
	for _, sr := range m.all {
		c := sr.Content
		if c.TimestampMS < sinceMS {
			continue
		}
		if cur, ok := latest[c.ProbeID]; !ok || c.TimestampMS > cur.LastSeenMS {
			latest[c.ProbeID] = ProbeSeen{ProbeID: c.ProbeID, Location: c.Location, LastSeenMS: c.TimestampMS}
		}
	}
	out := make([]ProbeSeen, 0, len(latest))
	for _, p := range latest {
		out = append(out, p)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].LastSeenMS > out[j].LastSeenMS })
	return out, nil
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
			// Tally the cumulative latency buckets (le_<bound>), mirroring the SQL
			// count(*) FILTER (rtt_ms <= bound): a sample lands in every bucket whose
			// bound it is <= to. Same measured set as rttN.
			for i, bound := range RttBucketBoundsMS {
				if c.RTTMillis <= float64(bound) {
					a.s.RttBuckets[i]++
				}
			}
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
		a.s.RTTSamples = a.rttN
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
