package store

import "context"

// UptimeWindow is a check's availability over one rolling window, sample-weighted:
//
//	uptime = (up + degraded) / samples
//
// A degraded sample counts as available — the service still answered, just
// slowly or partially — which is a deliberate product decision, not an accident
// of the math. Uptime is nil and Available is false when the window has no
// samples: either the check has no local data yet, or the hub does not hold the
// check's shard (uptime is computed from local rolled-up history only).
//
// Because uptime is sample-weighted across probes and buckets, a probe (or hour)
// that produced more samples pulls the number more than a sparse one. That is the
// intended, honest reading of "percent of observations that saw the service up".
type UptimeWindow struct {
	Uptime    *float64 `json:"uptime"`
	Samples   int64    `json:"samples"`
	Up        int64    `json:"up"`
	Down      int64    `json:"down"`
	Degraded  int64    `json:"degraded"`
	Available bool     `json:"available"`
}

// UptimeReport is a check's per-window uptime. Windows are keyed by a stable
// label ("24h", "7d", "30d"), so more windows can be added without breaking
// clients — this DTO is the shared foundation for the uptime badge, an SVG badge
// endpoint, and SLO budgets.
type UptimeReport struct {
	CheckID string                  `json:"check_id"`
	Windows map[string]UptimeWindow `json:"windows"`
}

// uptimeWindows are the rolling windows ComputeUptime reports. 24h and 7d fall
// within historyHourlyMaxSpan, so HistoryRange serves them at hourly resolution
// (an accurate short-window number); 30d exceeds it and is served daily. Kept as
// a package var rather than inline literals so the endpoint and tests reference
// the same set.
var uptimeWindows = []struct {
	Label    string
	Duration int64
}{
	{"24h", int64(24) * hourMS},
	{"7d", int64(7) * dayMS},
	{"30d", int64(30) * dayMS},
}

// ComputeUptime aggregates a check's rolled-up history into per-window uptime.
//
// It makes one HistoryRange call per window (three total: 24h and 7d at hourly
// resolution, 30d at daily) and sums every (probe, bucket) summary the range
// returns. Three separate calls — rather than one 30d daily call reused for the
// short windows — keep the 24h and 7d numbers hourly-accurate; a daily bucket is
// too coarse to give an honest 24h figure.
//
// maint carries the check's planned-downtime intervals; buckets that fall inside
// one are EXCLUDED from the figure entirely (they count toward neither samples
// nor up/down), so scheduled downtime doesn't dent uptime.
//
// It goes through the ResultStore interface, so it works identically for MemStore
// and PgStore, and it reads only what the store holds locally: a hub that does
// not hold the check's shard simply sees zero samples (Available=false) rather
// than reaching across the mesh.
func ComputeUptime(ctx context.Context, st ResultStore, checkID string, nowMS int64, maint []MaintenanceInterval) (UptimeReport, error) {
	rep := UptimeReport{CheckID: checkID, Windows: make(map[string]UptimeWindow, len(uptimeWindows))}
	for _, w := range uptimeWindows {
		summaries, err := st.HistoryRange(ctx, checkID, nowMS-w.Duration, nowMS)
		if err != nil {
			return UptimeReport{}, err
		}
		rep.Windows[w.Label] = summarizeUptime(excludeMaintenance(summaries, maint))
	}
	return rep, nil
}

// excludeMaintenance drops summaries whose bucket falls inside a maintenance
// window, so planned downtime is not counted against uptime.
//
// Approximation: exclusion is BUCKET-GRANULAR. A summary is dropped when its
// bucket START (BucketMS) is inside a [start,end) interval — the same
// coarseness ComputeUptime already reports at (hourly ≤14d, daily beyond). A
// window that covers only part of a bucket therefore drops the whole bucket (an
// hour/day), and a window shorter than one bucket that doesn't contain a bucket
// boundary excludes nothing. This is deliberately simple and slightly generous
// to the operator; sub-bucket precision would require re-aggregating raw results.
func excludeMaintenance(summaries []HistorySummary, maint []MaintenanceInterval) []HistorySummary {
	if len(maint) == 0 {
		return summaries
	}
	out := summaries[:0]
	for _, s := range summaries {
		if InMaintenance(s.BucketMS, maint) {
			continue
		}
		out = append(out, s)
	}
	return out
}

// EmptyUptimeReport returns a report with every window present but unavailable.
// A hub short-circuiting because it does not hold the check's shard emits this,
// so the response has the same window keys as a computed one — just no data.
func EmptyUptimeReport(checkID string) UptimeReport {
	rep := UptimeReport{CheckID: checkID, Windows: make(map[string]UptimeWindow, len(uptimeWindows))}
	for _, w := range uptimeWindows {
		rep.Windows[w.Label] = UptimeWindow{}
	}
	return rep
}

// summarizeUptime folds a window's (probe, bucket) summaries into one uptime
// figure: totals across all of them, with availability = (up+degraded)/samples.
func summarizeUptime(summaries []HistorySummary) UptimeWindow {
	var uw UptimeWindow
	for _, s := range summaries {
		uw.Samples += s.Samples
		uw.Up += s.UpCount
		uw.Down += s.DownCount
		uw.Degraded += s.DegradedCount
	}
	if uw.Samples > 0 {
		u := float64(uw.Up+uw.Degraded) / float64(uw.Samples)
		uw.Uptime = &u
		uw.Available = true
	}
	return uw
}
