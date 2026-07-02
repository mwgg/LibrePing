package store

import (
	"context"
	"errors"
	"sort"

	"github.com/mwgg/libreping/pkg/protocol"
)

// ErrUnknownWindow is returned when a caller asks for a window label that is not
// one of LatencyWindows. The endpoint validates the label first, so this is a
// defensive guard for direct callers.
var errUnknownWindow = errors.New("unknown latency window")

// LatencyPercentiles is a check's RTT distribution over one rolling window,
// computed from RAW results (not the rolled-up aggregates, which carry only
// avg/min/max). p50/p95/p99 are NEAREST-RANK percentiles in milliseconds, matching
// the frontend's latencyStats (web/src/theme.ts) so the badge and this endpoint
// agree. Min/Max/Count describe the same measured sample set.
//
// Percentiles are nil and Available is false when the window has no measured
// samples: either the check has no local raw data yet, or the hub does not hold
// the check's shard (this is computed from local raw results only).
//
// Because it reads RAW results, the effective coverage is capped by raw
// retention (RESULT_RETENTION_DAYS, ~7d on Postgres). A 30d window therefore only
// reflects the raw window that survives on a Postgres hub; MemStore keeps
// everything it holds. Count reports how many measured samples actually backed the
// numbers, so a caller can see the real coverage. Longer-window percentiles from
// the aggregates await a TimescaleDB toolkit tdigest column (deferred — see
// tiering.go), which the pinned plain TimescaleDB image does not ship.
type LatencyPercentiles struct {
	CheckID   string   `json:"check_id"`
	Window    string   `json:"window"`
	P50       *float64 `json:"p50"`
	P95       *float64 `json:"p95"`
	P99       *float64 `json:"p99"`
	Min       *float64 `json:"min"`
	Max       *float64 `json:"max"`
	Count     int64    `json:"count"`
	Available bool     `json:"available"`
}

// LatencyWindows are the rolling windows the latency endpoint accepts, keyed by a
// stable label. Kept as a package var (mirroring uptimeWindows) so the endpoint,
// its validation, and tests reference the same set.
var LatencyWindows = map[string]int64{
	"24h": int64(24) * hourMS,
	"7d":  int64(7) * dayMS,
	"30d": int64(30) * dayMS,
}

// maxLatencySamples bounds how many raw rows a single percentile computation
// scans, so a busy check over a long window can't pull an unbounded result set
// into memory. Newest-first, so the cap keeps the most recent samples — the ones
// a latency reading cares about. On the rare check that exceeds it the percentiles
// are computed over the newest maxLatencySamples measurements.
const maxLatencySamples = 200_000

// ComputeLatencyPercentiles gathers a check's RAW rtt_ms over [nowMS-window, nowMS)
// and returns nearest-rank p50/p95/p99 plus min/max/count in milliseconds.
//
// It reads through the ResultStore interface (RecentSinceCheck), so it works
// identically for MemStore and PgStore and only sees what the hub holds locally.
// Measured samples mirror the aggregates and uptime latency: down/timed-out rows
// and 0-rtt rows are excluded, because a down check's rtt is the time it waited
// before giving up, not the service's latency. An empty measured set yields
// Available=false with nil percentiles (unknown, not "0 ms").
func ComputeLatencyPercentiles(ctx context.Context, st ResultStore, checkID, window string, nowMS int64) (LatencyPercentiles, error) {
	span, ok := LatencyWindows[window]
	if !ok {
		return LatencyPercentiles{}, errUnknownWindow
	}
	out := LatencyPercentiles{CheckID: checkID, Window: window}
	results, err := st.RecentSinceCheck(ctx, checkID, nowMS-span, nowMS, maxLatencySamples)
	if err != nil {
		return LatencyPercentiles{}, err
	}
	rtts := make([]float64, 0, len(results))
	for _, sr := range results {
		c := sr.Content
		// Exclude down/timed-out and 0-rtt rows: same measured-sample rule as the
		// SQL aggregates, MemStore.HistoryRange, and the dashboard's latencyStats.
		if c.Status != protocol.StatusDown && c.RTTMillis > 0 {
			rtts = append(rtts, c.RTTMillis)
		}
	}
	if len(rtts) == 0 {
		return out, nil
	}
	sort.Float64s(rtts)
	out.Count = int64(len(rtts))
	p50 := nearestRank(rtts, 0.50)
	p95 := nearestRank(rtts, 0.95)
	p99 := nearestRank(rtts, 0.99)
	minV := rtts[0]
	maxV := rtts[len(rtts)-1]
	out.P50, out.P95, out.P99 = &p50, &p95, &p99
	out.Min, out.Max = &minV, &maxV
	out.Available = true
	return out, nil
}

// EmptyLatencyPercentiles returns an unavailable report for one window. A hub
// short-circuiting because it does not hold the check's shard emits this, so the
// response shape matches a computed one — just no data.
func EmptyLatencyPercentiles(checkID, window string) LatencyPercentiles {
	return LatencyPercentiles{CheckID: checkID, Window: window}
}

// nearestRank returns the nearest-rank percentile of an ascending-sorted slice
// (len > 0), matching web/src/theme.ts: idx = clamp(ceil(p*n)-1, 0, n-1).
func nearestRank(sorted []float64, p float64) float64 {
	n := len(sorted)
	idx := int(ceilPos(p*float64(n))) - 1
	if idx < 0 {
		idx = 0
	}
	if idx > n-1 {
		idx = n - 1
	}
	return sorted[idx]
}

// ceilPos is math.Ceil for the non-negative values used here, avoiding a math
// import for one call. p*n is always >= 0.
func ceilPos(x float64) float64 {
	i := float64(int64(x))
	if i < x {
		return i + 1
	}
	return i
}
