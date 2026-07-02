package store

import (
	"context"
	"errors"
	"sort"
	"strings"

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
	CheckID string   `json:"check_id"`
	Window  string   `json:"window"`
	P50     *float64 `json:"p50"`
	P95     *float64 `json:"p95"`
	P99     *float64 `json:"p99"`
	Min     *float64 `json:"min"`
	Max     *float64 `json:"max"`
	Count   int64    `json:"count"`
	// Source is how the percentiles were derived: "raw" (exact nearest-rank over
	// raw results, within raw retention) or "histogram" (interpolated from the
	// aggregates' latency buckets, for windows longer than raw retention). Empty on
	// an unavailable report.
	Source    string `json:"source,omitempty"`
	Available bool   `json:"available"`
}

// LatencyWindows are the rolling windows the latency endpoint accepts, keyed by a
// stable label. Kept as a package var (mirroring uptimeWindows) so the endpoint,
// its validation, and tests reference the same set.
var LatencyWindows = map[string]int64{
	"24h": int64(24) * hourMS,
	"7d":  int64(7) * dayMS,
	"30d": int64(30) * dayMS,
}

// RttBucketBoundsMS are the fixed upper edges (milliseconds) of the latency
// histogram carried on the continuous aggregates as cumulative le_<bound> counts.
// They are chosen ~logarithmically to cover fast local checks through slow/timeout
// territory. Changing this set is a wire/schema change: the aggregate columns are
// named le_<bound>, so bump the aggregate marker in tiering.go (rebuild) and keep
// numRttBuckets in step. Ascending order is required (interpolation walks it).
var RttBucketBoundsMS = []int64{5, 10, 25, 50, 100, 250, 500, 1000, 2500, 5000, 10000}

// numRttBuckets is the fixed length of the per-summary bucket array. It must equal
// len(RttBucketBoundsMS); a package init guards that.
const numRttBuckets = 11

// histBucketSelect is the comma-separated le_<bound> column list, in
// RttBucketBoundsMS order, for the PgStore.HistoryRange SELECT.
var histBucketSelect = buildHistBucketSelect()

func buildHistBucketSelect() string {
	parts := make([]string, len(RttBucketBoundsMS))
	for i, b := range RttBucketBoundsMS {
		parts[i] = "le_" + itoa(b)
	}
	return strings.Join(parts, ", ")
}

func init() {
	if len(RttBucketBoundsMS) != numRttBuckets {
		panic("store: numRttBuckets must equal len(RttBucketBoundsMS)")
	}
}

// HistogramPercentiles interpolates p50/p95/p99 (plus min/max/count) from the
// summed latency-bucket histogram across a window's HistorySummary rows. It is the
// longer-than-raw-retention path: the le_<bound> counts survive the full aggregate
// retention (90d hourly / 730d daily), so a 30d window stays accurate even after
// raw results are dropped.
//
// Method mirrors Prometheus histogram_quantile: sum the cumulative bucket counts
// and the measured-sample total across all summaries, then for each quantile take
// rank = p*total, find the first bucket whose cumulative count reaches it, and
// LINEARLY interpolate within that bucket ([prevBound, bound]) by the fraction of
// the rank inside it. The first bucket's lower edge is 0.
//
// Caveats (documented honestly): this is bucket-interpolation, exact only when a
// bucket's samples are uniformly spread; it is softest in a sparse tail. The
// overflow bucket (rtt > the last bound, 10000ms) has an UNBOUNDED upper edge that
// cannot be interpolated, so a target rank landing there is CLAMPED to the last
// bound and reported as that value (i.e. ">= 10000ms"); Max still reflects the
// true summed rtt_max. Min/Max are taken exactly from the summaries' rtt_min/rtt_max
// (not interpolated). Zero measured samples → Available=false with nil percentiles.
func HistogramPercentiles(checkID, window string, summaries []HistorySummary) LatencyPercentiles {
	out := LatencyPercentiles{CheckID: checkID, Window: window, Source: "histogram"}
	var total int64
	var cum [numRttBuckets]int64
	var minV, maxV float64
	haveMinMax := false
	for _, s := range summaries {
		if s.RTTSamples <= 0 {
			continue // no measured samples in this bucket
		}
		total += s.RTTSamples
		for i := 0; i < numRttBuckets; i++ {
			cum[i] += s.RttBuckets[i]
		}
		if !haveMinMax {
			minV, maxV, haveMinMax = s.RTTMin, s.RTTMax, true
			continue
		}
		if s.RTTMin < minV {
			minV = s.RTTMin
		}
		if s.RTTMax > maxV {
			maxV = s.RTTMax
		}
	}
	if total == 0 {
		return out // unavailable: nothing measured over the window
	}
	out.Count = total
	p50 := histogramQuantile(0.50, cum, total)
	p95 := histogramQuantile(0.95, cum, total)
	p99 := histogramQuantile(0.99, cum, total)
	out.P50, out.P95, out.P99 = &p50, &p95, &p99
	out.Min, out.Max = &minV, &maxV
	out.Available = true
	return out
}

// histogramQuantile interpolates the p-quantile from a cumulative bucket histogram
// (cum[i] = measured samples with rtt <= RttBucketBoundsMS[i]) and the measured
// total. Prometheus-style: rank = p*total, find the first bucket reaching it, then
// linear-interpolate within [prevBound, bound]. A rank above the last bucket's
// count falls in the unbounded overflow and is clamped to the last bound.
func histogramQuantile(p float64, cum [numRttBuckets]int64, total int64) float64 {
	rank := p * float64(total)
	var prevCum int64
	var prevBound float64
	for i := 0; i < numRttBuckets; i++ {
		bound := float64(RttBucketBoundsMS[i])
		if float64(cum[i]) >= rank {
			inBucket := cum[i] - prevCum
			if inBucket <= 0 {
				return bound // empty bucket straddling the rank: report its edge
			}
			frac := (rank - float64(prevCum)) / float64(inBucket)
			if frac < 0 {
				frac = 0
			}
			if frac > 1 {
				frac = 1
			}
			return prevBound + (bound-prevBound)*frac
		}
		prevCum = cum[i]
		prevBound = bound
	}
	// Overflow: the target rank lies above the last bucket (rtt > last bound). The
	// upper edge is unbounded and cannot be interpolated, so clamp to the last bound.
	return float64(RttBucketBoundsMS[numRttBuckets-1])
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
	out.Source = "raw"
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
