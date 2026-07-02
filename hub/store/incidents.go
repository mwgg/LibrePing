package store

import "context"

// Incident is one past (or ongoing) outage for a check, DERIVED ON READ from the
// hub's rolled-up history — there is no stored/gossiped incident record. It is a
// maximal contiguous run of non-up time buckets (see ComputeIncidents for the
// per-bucket status rule).
//
// Because it is derived from rolled-up buckets, its edges are BUCKET-ALIGNED, not
// precise transition timestamps: hourly for windows ≤14d, daily beyond (see
// historyResolution). Resolution is carried so the UI can caption the granularity
// honestly ("hourly, times are bucket-aligned"). Storing precise transition
// timestamps as first-class gossiped incidents is a future enhancement.
type Incident struct {
	StartMS     int64  `json:"start_ms"`
	EndMS       int64  `json:"end_ms"`
	DurationMS  int64  `json:"duration_ms"`
	WorstStatus string `json:"worst_status"` // "down" or "degraded"
	BucketCount int    `json:"bucket_count"`
	Resolution  string `json:"resolution"` // "hourly" or "daily"
	Ongoing     bool   `json:"ongoing"`    // true if it reaches the window's leading edge (end = now)
}

// IncidentReport is a check's outage timeline over one rolling window, newest
// incident first. An all-up (or no-data) window yields an empty (non-nil)
// Incidents slice, so the DTO shape is identical whether or not there were
// outages — a hub that does not hold the check's shard emits the same empty
// report rather than reaching across the mesh.
type IncidentReport struct {
	CheckID    string     `json:"check_id"`
	Window     string     `json:"window"`
	Resolution string     `json:"resolution"`
	Incidents  []Incident `json:"incidents"`
}

// IncidentWindows are the rolling windows the incidents endpoint accepts, keyed
// by a stable label (mirroring LatencyWindows). 24h/7d resolve to hourly buckets,
// 30d to daily. Kept as a package var so the endpoint, its validation, and tests
// reference the same set.
var IncidentWindows = map[string]int64{
	"24h": int64(24) * hourMS,
	"7d":  int64(7) * dayMS,
	"30d": int64(30) * dayMS,
}

// bucketAgg is one time bucket's status counts summed across every probe.
type bucketAgg struct {
	start    int64
	up       int64
	down     int64
	degraded int64
}

// status collapses a bucket's per-probe counts into a single network-level
// availability verdict. This is a deliberate heuristic over AGGREGATED buckets,
// not a per-probe truth:
//
//   - "down"     — nothing was reachable in the bucket: up==0 and (down+degraded)>0.
//   - "degraded" — something answered but not cleanly: up>0 and (down+degraded)>0.
//   - "up"       — everything observed was up (or the bucket had no negative signal).
//
// A bucket with only "up" observations (or, defensively, no observations) is "up".
func (b bucketAgg) status() protocolStatus {
	bad := b.down + b.degraded
	switch {
	case bad == 0:
		return statusUp
	case b.up == 0:
		return statusDown
	default:
		return statusDegraded
	}
}

// protocolStatus is a tiny local enum for the collapsed per-bucket verdict, kept
// separate from protocol.Status (which describes a single result) so the bucket
// heuristic reads clearly.
type protocolStatus int

const (
	statusUp protocolStatus = iota
	statusDown
	statusDegraded
)

// ComputeIncidents derives a check's outage timeline over [nowMS-window, nowMS)
// from the hub's rolled-up history.
//
// It makes ONE HistoryRange call for the window, collapses the per-(probe, bucket)
// summaries into a per-bucket network status (bucketAgg.status), then walks the
// buckets oldest-first and emits a maximal contiguous run of non-up buckets as one
// Incident. A run is broken by an up bucket OR by a gap in the bucket series (a
// missing bucket means no observations, and we don't claim an outage without data),
// so start/end are bucket-aligned and honest.
//
// end_ms is the last non-up bucket's end (== the next up bucket's start when
// contiguous). An incident whose last bucket sits at the window's leading edge (the
// current bucket, allowing for one bucket of ingest lag) is still in progress:
// Ongoing=true and EndMS=nowMS.
//
// It reads through the ResultStore interface, so it behaves identically for
// MemStore and PgStore and only sees what the hub holds locally: a hub that does
// not hold the check's shard sees no summaries and returns an empty report.
func ComputeIncidents(ctx context.Context, st ResultStore, checkID, window string, nowMS int64) (IncidentReport, error) {
	span, ok := IncidentWindows[window]
	if !ok {
		return IncidentReport{}, errUnknownWindow
	}
	label, bucketMS := historyResolution(span)
	rep := IncidentReport{CheckID: checkID, Window: window, Resolution: label, Incidents: []Incident{}}

	summaries, err := st.HistoryRange(ctx, checkID, nowMS-span, nowMS)
	if err != nil {
		return IncidentReport{}, err
	}
	if len(summaries) == 0 {
		return rep, nil
	}

	// Sum every probe's counts into one aggregate per bucket start.
	byBucket := map[int64]*bucketAgg{}
	for _, s := range summaries {
		b := byBucket[s.BucketMS]
		if b == nil {
			b = &bucketAgg{start: s.BucketMS}
			byBucket[s.BucketMS] = b
		}
		b.up += s.UpCount
		b.down += s.DownCount
		b.degraded += s.DegradedCount
	}
	buckets := make([]*bucketAgg, 0, len(byBucket))
	for _, b := range byBucket {
		buckets = append(buckets, b)
	}
	sortBucketsAsc(buckets)

	// currentBucket is the bucket that contains nowMS; an incident reaching it (or
	// the immediately preceding bucket, tolerating one bucket of ingest lag) is
	// still in progress.
	currentBucket := (nowMS / bucketMS) * bucketMS

	var incidents []Incident
	var run *Incident      // the incident being accumulated, nil when in an up stretch
	var runHasDown bool    // any "down" bucket seen in the current run → worst=down
	var prevStart int64    // start of the previous bucket, to detect gaps
	var runLastStart int64 // start of the run's last non-up bucket

	flush := func() {
		if run == nil {
			return
		}
		run.EndMS = runLastStart + bucketMS
		if runHasDown {
			run.WorstStatus = "down"
		} else {
			run.WorstStatus = "degraded"
		}
		// Ongoing if the run reaches the leading edge (current bucket, or the prior
		// one to allow for a not-yet-filled current bucket).
		if runLastStart >= currentBucket-bucketMS {
			run.Ongoing = true
			run.EndMS = nowMS
		}
		run.DurationMS = run.EndMS - run.StartMS
		incidents = append(incidents, *run)
		run = nil
		runHasDown = false
	}

	for i, b := range buckets {
		gap := i > 0 && b.start != prevStart+bucketMS
		prevStart = b.start
		st := b.status()
		if st == statusUp {
			flush()
			continue
		}
		// A gap ends the previous run: no data means we can't call it an outage.
		if gap {
			flush()
		}
		if run == nil {
			run = &Incident{StartMS: b.start, Resolution: label}
		}
		run.BucketCount++
		runLastStart = b.start
		if st == statusDown {
			runHasDown = true
		}
	}
	flush()

	// Newest incident first.
	for i, j := 0, len(incidents)-1; i < j; i, j = i+1, j-1 {
		incidents[i], incidents[j] = incidents[j], incidents[i]
	}
	if len(incidents) > 0 {
		rep.Incidents = incidents
	}
	return rep, nil
}

// EmptyIncidentReport returns a report with no incidents for one window. A hub
// short-circuiting because it does not hold the check's shard emits this, so the
// response shape matches a computed one — just no data.
func EmptyIncidentReport(checkID, window string) IncidentReport {
	label, _ := historyResolution(IncidentWindows[window])
	return IncidentReport{CheckID: checkID, Window: window, Resolution: label, Incidents: []Incident{}}
}

// sortBucketsAsc orders bucket aggregates by start time ascending (insertion sort
// is fine — the bucket count is bounded by the window's resolution, ≤ ~720).
func sortBucketsAsc(b []*bucketAgg) {
	for i := 1; i < len(b); i++ {
		for j := i; j > 0 && b[j-1].start > b[j].start; j-- {
			b[j-1], b[j] = b[j], b[j-1]
		}
	}
}
