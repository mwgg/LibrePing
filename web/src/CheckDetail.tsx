import { useEffect, useState } from "react";
import { Identity } from "./identity";
import { HistorySummary, IncidentReport, IncidentWindowKey, LatencyPercentiles, MaintenanceWindow, Service, SignedResult, UptimeReport, UptimeWindowKey, deleteMaintenance, getSLOTarget, history, incidents, latency, listMaintenance, queryResults, scheduleMaintenance, setSLOTarget, uptime } from "./api";
import { budgetColor, errorBudget, fmtDuration, fmtRtt, fmtUptime, latencyStats, pct, relativeTime, statusColor, uptimeColor, UPTIME_WINDOWS, WINDOW_MINUTES } from "./theme";
import History from "./History";
import AlertForm from "./AlertForm";
import Alerts from "./Alerts";
import StatusBadge from "./Badge";

// CheckDetail is the per-monitor deep view: uptime/latency timeline, a
// per-location breakdown, a recent-checks event log, and (for the owner) alert
// management scoped to this check.
export default function CheckDetail({
  svc,
  id,
  owner,
  services,
  onBack,
  onChange,
}: {
  svc: Service;
  id: Identity | null;
  owner: string;
  services: Service[];
  onBack: () => void;
  onChange: () => void;
}) {
  const [showAddAlert, setShowAddAlert] = useState(false);
  const [events, setEvents] = useState<SignedResult[] | null>(null);
  const [alertsKey, setAlertsKey] = useState(0); // bump to force Alerts reload
  // Fetch the rolled-up history once here and share it with both the timeline
  // chart (<History>) and the per-region breakdown below, so opening a monitor
  // makes a single /results/history request rather than one per consumer.
  const historyRows = useHistoryRows(svc.check_id);
  // Fetch the availability windows once and share them with both the uptime
  // summary and the SLO panel, so opening a monitor makes a single /uptime
  // request rather than one per consumer.
  const uptimeReport = useUptime(svc.check_id);
  // Owner's maintenance windows for this check, shared between the header badge
  // (active indicator) and the scheduling panel below.
  const maintenance = useMaintenance(svc.check_id, owner);

  useEffect(() => {
    let live = true;
    queryResults(svc.check_id, undefined, 40).then((r) => live && setEvents(r));
    return () => {
      live = false;
    };
  }, [svc.check_id]);

  const locations = [...svc.locations].sort((a, b) => a.status.localeCompare(b.status));
  const lat = latencyStats(svc.locations);

  return (
    <div className="rise">
      <div className="detail-head">
        <button className="btn btn-sm" onClick={onBack}>
          ← Back
        </button>
        <div style={{ minWidth: 0 }}>
          <h2 className="detail-title">{svc.target || svc.check_id}</h2>
          <div className="service-metrics" style={{ marginTop: 8 }}>
            <StatusBadge status={svc.overall} />
            {maintenance.active && (
              <span className="badge badge-degraded" title="A maintenance window is currently active for this monitor">
                In maintenance
              </span>
            )}
            <span className="service-type">{svc.type}</span>
            <div className="metric">
              <span className="metric-label">Lowest</span>
              <span className="metric-value">{lat.lowest === null ? "—" : fmtRtt(lat.lowest)}</span>
            </div>
            <div className="metric">
              <span className="metric-label">p95</span>
              <span className="metric-value">{lat.p95 === null ? "—" : fmtRtt(lat.p95)}</span>
            </div>
            <span className="muted note">checks every {svc.interval_seconds}s</span>
          </div>
        </div>
      </div>

      <div className="detail-grid">
        <div className="panel">
          <h3>Uptime &amp; latency</h3>
          <UptimeSummary report={uptimeReport} />
          <LatencySummary checkId={svc.check_id} />
          <History checkId={svc.check_id} rows={historyRows} />
        </div>

        <div className="panel">
          <h3>SLO &amp; error budget</h3>
          <SLOPanel checkId={svc.check_id} report={uptimeReport} />
        </div>

        <div className="panel">
          <h3>Uptime by region</h3>
          <RegionUptime rows={historyRows} />
        </div>

        <div className="panel">
          <h3>By location ({locations.length})</h3>
          {locations.length === 0 ? (
            <p className="muted note">No probe results held by this hub yet.</p>
          ) : (
            <table className="loctable">
              <thead>
                <tr>
                  <th>Location</th>
                  <th>Status</th>
                  <th>Latency</th>
                  <th>Last seen</th>
                </tr>
              </thead>
              <tbody>
                {locations.map((l) => (
                  <tr key={l.probe_id}>
                    <td>
                      {l.location.city || "?"}
                      {l.location.country ? `, ${l.location.country}` : ""}
                    </td>
                    <td>
                      <StatusBadge status={l.status} />
                    </td>
                    <td className="num">{fmtRtt(l.rtt_ms)}</td>
                    <td className="num muted">{relativeTime(l.timestamp_ms)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>

        <div className="panel">
          <h3>Recent checks</h3>
          {events === null ? (
            <div className="loading-line">
              <span className="spinner" /> Loading…
            </div>
          ) : events.length === 0 ? (
            <p className="muted note">No raw results on this hub (it may not store this check).</p>
          ) : (
            <div className="events">
              {events.slice(0, 25).map((e, i) => {
                const c = e.content;
                return (
                  <div className="event" key={`${c.probe_id}-${c.timestamp_ms}-${i}`}>
                    <span className="dot" style={{ background: statusColor(c.status) }} />
                    <span>
                      {c.status} from {c.location.city || c.location.country || c.probe_id.slice(0, 8)}
                    </span>
                    <span className="num muted">{fmtRtt(c.rtt_ms)}</span>
                    <span className="event-time">{relativeTime(c.timestamp_ms)}</span>
                  </div>
                );
              })}
            </div>
          )}
        </div>

        <div className="panel">
          <h3>Incident history</h3>
          <IncidentHistory checkId={svc.check_id} />
        </div>

        <div className="panel">
          <h3>Maintenance</h3>
          <MaintenancePanel id={id} checkId={svc.check_id} maintenance={maintenance} />
        </div>

        {id && (
          <div className="panel">
            <div className="row-between" style={{ marginBottom: 12 }}>
              <h3 style={{ margin: 0 }}>Alerts</h3>
              <button className="btn btn-sm" onClick={() => setShowAddAlert((v) => !v)}>
                {showAddAlert ? "Cancel" : "+ Add alert"}
              </button>
            </div>
            <Alerts key={alertsKey} id={id} owner={owner} services={services} checkId={svc.check_id} onChange={onChange} />
            {showAddAlert && (
              <AlertForm
                id={id}
                checkIds={[svc.check_id]}
                onDone={() => {
                  setShowAddAlert(false);
                  setAlertsKey((k) => k + 1);
                }}
              />
            )}
          </div>
        )}
      </div>
    </div>
  );
}

// useHistoryRows loads a check's rolled-up history summaries once (and again
// when the check changes). Best-effort: on error `history()` resolves to an
// empty list, so callers render "no history" rather than spinning forever.
function useHistoryRows(checkId: string): HistorySummary[] | null {
  const [rows, setRows] = useState<HistorySummary[] | null>(null);
  useEffect(() => {
    let live = true;
    setRows(null);
    history(checkId).then((r) => live && setRows(r));
    return () => {
      live = false;
    };
  }, [checkId]);
  return rows;
}

// RegionStat is one region's availability aggregated over the whole loaded
// history window (distinct from the "By location" panel, which is a current
// snapshot of each probe's latest status). `uptime` is (up+degraded)/samples in
// [0,1], or null when the region has zero samples.
interface RegionStat {
  region: string;
  samples: number;
  uptime: number | null;
  rtt: number | null;
}

// aggregateByRegion groups the per-(bucket, probe) history rows by probe country
// — the same granularity as the country pills on the service cards — and folds
// each region's availability across the window. Rows with a blank country fall
// into an "Unknown" region rather than being dropped, since location is
// self-declared and may be empty. Latency is weighted by responsive samples
// (up + degraded) so timed-out probes' ~timeout rtt doesn't inflate it, mirroring
// latencyStats. Sorted worst-uptime first so problem regions stay at the top.
function aggregateByRegion(rows: HistorySummary[]): RegionStat[] {
  const by = new Map<string, { samples: number; ok: number; rttSum: number; rttN: number }>();
  for (const r of rows) {
    const region = r.location?.country || "Unknown";
    const e = by.get(region) ?? { samples: 0, ok: 0, rttSum: 0, rttN: 0 };
    e.samples += r.samples;
    e.ok += r.up_count + r.degraded_count;
    // rtt_avg is an average over the bucket; weight it by responsive samples.
    const responsive = r.up_count + r.degraded_count;
    if (responsive > 0 && r.rtt_avg > 0) {
      e.rttSum += r.rtt_avg * responsive;
      e.rttN += responsive;
    }
    by.set(region, e);
  }
  return [...by.entries()]
    .map(([region, e]) => ({
      region,
      samples: e.samples,
      uptime: e.samples > 0 ? e.ok / e.samples : null,
      rtt: e.rttN > 0 ? e.rttSum / e.rttN : null,
    }))
    .sort((a, b) => (a.uptime ?? 1) - (b.uptime ?? 1) || b.samples - a.samples || a.region.localeCompare(b.region));
}

// RegionUptime renders the time-aggregated per-region availability table. It
// complements the current-snapshot "By location" panel: this one answers
// "reachable from EU 100%, from US 97% over the window", not "up right now".
function RegionUptime({ rows }: { rows: HistorySummary[] | null }) {
  if (rows === null)
    return (
      <div className="loading-line">
        <span className="spinner" /> Loading…
      </div>
    );
  const regions = aggregateByRegion(rows);
  if (regions.length === 0)
    return <div className="muted note">No history yet (this hub may not store this check).</div>;
  return (
    <>
      <table className="loctable">
        <thead>
          <tr>
            <th>Region</th>
            <th>Uptime</th>
            <th>Latency</th>
            <th>Samples</th>
          </tr>
        </thead>
        <tbody>
          {regions.map((r) => (
            <tr key={r.region}>
              <td>{r.region}</td>
              <td className="num" style={r.uptime !== null ? { color: uptimeColor(r.uptime) } : undefined}>
                {r.uptime === null ? "n/a" : pct(r.uptime)}
              </td>
              <td className="num">{r.rtt === null ? "—" : fmtRtt(r.rtt)}</td>
              <td className="num muted">{r.samples}</td>
            </tr>
          ))}
        </tbody>
      </table>
      <span className="muted note">Share of checks up (up + degraded) over the loaded history window, grouped by probe country.</span>
    </>
  );
}

// useUptime loads a check's sample-weighted availability report once (and again
// when the check changes). Best-effort: on error it settles to an empty report
// so callers show "n/a" rather than a spinner forever. Shared by the detail view
// and the service cards.
export function useUptime(checkId: string): UptimeReport | null {
  const [report, setReport] = useState<UptimeReport | null>(null);
  useEffect(() => {
    let live = true;
    setReport(null);
    uptime(checkId).then((r) => live && setReport(r));
    return () => {
      live = false;
    };
  }, [checkId]);
  return report;
}

// UptimeSummary renders the three availability windows (24h / 7d / 30d) as
// coloured percentages, with a caption clarifying it is a sample-weighted
// estimate rather than wall-clock uptime. The report is fetched once by the
// parent (see CheckDetail) and shared with the SLO panel.
function UptimeSummary({ report }: { report: UptimeReport | null }) {
  return (
    <div style={{ marginBottom: 12 }}>
      <div className="service-metrics" style={{ marginTop: 0 }}>
        {UPTIME_WINDOWS.map(({ key, label }) => {
          const w = report?.windows[key];
          const value = report === null ? "…" : fmtUptime(w);
          const color = w && w.available && w.uptime !== null ? uptimeColor(w.uptime) : undefined;
          const title =
            w && w.available && w.uptime !== null
              ? `${w.up + w.degraded} of ${w.samples} observations up over ${label}`
              : "No local data on this hub for this window";
          return (
            <div className="metric" key={key} title={title}>
              <span className="metric-label">{label}</span>
              <span className="metric-value" style={color ? { color } : undefined}>
                {value}
              </span>
            </div>
          );
        })}
      </div>
      <span className="muted note">Sample-weighted availability estimate (share of observations up, not wall-clock).</span>
    </div>
  );
}

// Common SLO targets offered in the picker, as availability fractions. The
// user can also type any custom fraction (see SLOPanel).
const SLO_PRESETS: { value: number; label: string }[] = [
  { value: 0.99, label: "99%" },
  { value: 0.999, label: "99.9%" },
  { value: 0.9995, label: "99.95%" },
  { value: 0.9999, label: "99.99%" },
];

// The SLO windows we surface a budget for: the 30d window is the headline SLO
// period, with 7d shown alongside for a shorter-term read.
const SLO_WINDOWS: { key: UptimeWindowKey; label: string }[] = [
  { key: "30d", label: "30d" },
  { key: "7d", label: "7d" },
];

// SLOPanel lets the owner (or anyone) pin an availability target for this check
// and shows the resulting error budget per window. The target is stored only in
// this browser (see api.getSLOTarget/setSLOTarget) — it is never signed or
// gossiped, so it is a per-device preference, not shared network state. The
// budget is derived from the same /uptime report the summary already fetched.
function SLOPanel({ checkId, report }: { checkId: string; report: UptimeReport | null }) {
  const [target, setTarget] = useState<number | null>(() => getSLOTarget(checkId));
  const [customPct, setCustomPct] = useState("");
  const [custom, setCustom] = useState(false);

  // Reset when switching between monitors (checkId change) so a stale target
  // from the previous check never leaks in.
  useEffect(() => {
    const t = getSLOTarget(checkId);
    setTarget(t);
    setCustom(t !== null && !SLO_PRESETS.some((p) => p.value === t));
    setCustomPct(t !== null ? String(+(t * 100).toFixed(4)) : "");
  }, [checkId]);

  const save = (t: number | null) => {
    setTarget(t);
    setSLOTarget(checkId, t);
  };

  const onSelect = (v: string) => {
    if (v === "custom") {
      setCustom(true);
      return;
    }
    if (v === "") {
      setCustom(false);
      save(null);
      return;
    }
    setCustom(false);
    save(Number(v));
  };

  // Parse a percentage like "99.95" into a (0,1) fraction; reject anything out
  // of range (0 leaves no service, 100 leaves no budget).
  const applyCustom = () => {
    const p = parseFloat(customPct);
    if (!isFinite(p) || p <= 0 || p >= 100) {
      save(null);
      return;
    }
    save(p / 100);
  };

  const selectValue = custom ? "custom" : target === null ? "" : String(target);

  return (
    <div>
      <div className="row-between" style={{ marginBottom: 8, gap: 8 }}>
        <span className="muted note" style={{ margin: 0 }}>
          Availability target
        </span>
        <div className="service-metrics" style={{ marginTop: 0, gap: 6 }}>
          <select className="btn btn-sm" value={selectValue} onChange={(e) => onSelect(e.target.value)} aria-label="SLO target">
            <option value="">No target</option>
            {SLO_PRESETS.map((p) => (
              <option key={p.value} value={p.value}>
                {p.label}
              </option>
            ))}
            <option value="custom">Custom…</option>
          </select>
          {custom && (
            <>
              <input
                className="btn btn-sm"
                style={{ width: 80 }}
                type="number"
                step="0.001"
                min="0"
                max="100"
                placeholder="99.9"
                value={customPct}
                onChange={(e) => setCustomPct(e.target.value)}
                onBlur={applyCustom}
                onKeyDown={(e) => e.key === "Enter" && applyCustom()}
                aria-label="Custom SLO target percent"
              />
              <span className="muted note" style={{ margin: 0 }}>
                %
              </span>
            </>
          )}
        </div>
      </div>

      {target === null ? (
        <p className="muted note">Set a target to track this monitor's error budget.</p>
      ) : (
        <>
          <table className="loctable">
            <thead>
              <tr>
                <th>Window</th>
                <th>Uptime</th>
                <th>Budget used</th>
                <th>Downtime allowance</th>
              </tr>
            </thead>
            <tbody>
              {SLO_WINDOWS.map(({ key, label }) => {
                const w = report?.windows[key];
                const budget = errorBudget(target, w, WINDOW_MINUTES[key]);
                const uptimeVal = report === null ? "…" : fmtUptime(w);
                return (
                  <tr key={key}>
                    <td>{label}</td>
                    <td className="num" style={w && w.available && w.uptime !== null ? { color: uptimeColor(w.uptime) } : undefined}>
                      {uptimeVal}
                    </td>
                    <td className="num" style={budget.available ? { color: budgetColor(budget.consumed) } : undefined}>
                      {report === null ? "…" : !budget.available ? "n/a" : budget.consumed! > 1 ? `${pct(budget.consumed!)} (blown)` : pct(budget.consumed!)}
                    </td>
                    <td className="num muted">
                      {!budget.available
                        ? "n/a"
                        : `${fmtDuration(Math.max(0, budget.allowedMinutes! - budget.consumedMinutes!) * 60_000)} of ${fmtDuration(budget.allowedMinutes! * 60_000)} left`}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
          <span className="muted note">
            Target {pct(target)}. Budget is downtime observed ÷ downtime allowed, from the sample-weighted uptime above (approximate, not
            wall-clock). Stored in this browser only.
          </span>
        </>
      )}
    </div>
  );
}

// useLatency loads a check's latency percentiles for all three windows at once
// (one call per window — the endpoint is per-window — issued together via
// Promise.all so the panel doesn't wait serially). Best-effort: `latency()`
// resolves to an unavailable shape on error, so a failed window shows "n/a"
// without failing the others. Keyed by window so a toggle reads without refetch.
function useLatency(checkId: string): Partial<Record<UptimeWindowKey, LatencyPercentiles>> | null {
  const [byWindow, setByWindow] = useState<Partial<Record<UptimeWindowKey, LatencyPercentiles>> | null>(null);
  useEffect(() => {
    let live = true;
    setByWindow(null);
    Promise.all(UPTIME_WINDOWS.map(({ key }) => latency(checkId, key))).then((rows) => {
      if (!live) return;
      const map: Partial<Record<UptimeWindowKey, LatencyPercentiles>> = {};
      rows.forEach((r) => (map[r.window] = r));
      setByWindow(map);
    });
    return () => {
      live = false;
    };
  }, [checkId]);
  return byWindow;
}

// LatencySummary shows the p50 / p95 / p99 latency percentiles for one window,
// with a small 24h/7d/30d toggle. All three windows are fetched up front (see
// useLatency), so switching is instant. Values render in ms via fmtRtt to match
// the latency figures elsewhere; a subtle caption reports the sample count and
// how the selected window's percentiles were derived (exact nearest-rank over the
// raw window, or histogram-interpolated from latency buckets for windows longer
// than raw retention — 30d) so a raw-limited long window is honest.
function LatencySummary({ checkId }: { checkId: string }) {
  const byWindow = useLatency(checkId);
  const [win, setWin] = useState<UptimeWindowKey>("24h");
  const cur = byWindow?.[win];
  const avail = !!cur && cur.available;
  const cells: { label: string; value: number | null }[] = [
    { label: "p50", value: cur?.p50 ?? null },
    { label: "p95", value: cur?.p95 ?? null },
    { label: "p99", value: cur?.p99 ?? null },
  ];
  return (
    <div style={{ marginBottom: 12 }}>
      <div className="row-between" style={{ marginBottom: 8 }}>
        <span className="muted note" style={{ margin: 0 }}>
          Latency percentiles
        </span>
        <div className="service-metrics" style={{ marginTop: 0, gap: 6 }}>
          {UPTIME_WINDOWS.map(({ key, label }) => (
            <button
              key={key}
              className={`btn btn-sm${win === key ? " btn-primary" : ""}`}
              aria-pressed={win === key}
              onClick={() => setWin(key)}
            >
              {label}
            </button>
          ))}
        </div>
      </div>
      <div className="service-metrics" style={{ marginTop: 0 }}>
        {cells.map((c) => (
          <div className="metric" key={c.label}>
            <span className="metric-label">{c.label}</span>
            <span className="metric-value">
              {byWindow === null ? "…" : !avail || c.value === null ? "n/a" : fmtRtt(c.value)}
            </span>
          </div>
        ))}
      </div>
      {byWindow !== null && avail && cur && (
        <span className="muted note">
          {cur.source === "histogram" ? "Histogram-interpolated from latency buckets over" : "Nearest-rank over"} {cur.count} sample
          {cur.count === 1 ? "" : "s"} in the {win} window.
        </span>
      )}
    </div>
  );
}

// useIncidents loads a check's outage timeline for one window (and again when
// the check or window changes). Best-effort: on error `incidents()` resolves to
// an empty report, so callers render the empty state rather than spinning.
function useIncidents(checkId: string, window: IncidentWindowKey): IncidentReport | null {
  const [report, setReport] = useState<IncidentReport | null>(null);
  useEffect(() => {
    let live = true;
    setReport(null);
    incidents(checkId, window).then((r) => live && setReport(r));
    return () => {
      live = false;
    };
  }, [checkId, window]);
  return report;
}

// INCIDENT_WINDOWS is the lookback toggle for the incident timeline, matching the
// windows the endpoint accepts. Default is the widest (30d).
const INCIDENT_WINDOWS: { key: IncidentWindowKey; label: string }[] = [
  { key: "24h", label: "24h" },
  { key: "7d", label: "7d" },
  { key: "30d", label: "30d" },
];

// IncidentHistory lists past outages newest-first, each with a status dot
// coloured by its worst status, the start time, the duration, and an "ongoing"
// tag for outages still open. Times are bucket-aligned to the report's
// resolution, so a caption calls that out honestly. Renders independently of the
// other panels via its own hook.
function IncidentHistory({ checkId }: { checkId: string }) {
  const [win, setWin] = useState<IncidentWindowKey>("30d");
  const report = useIncidents(checkId, win);
  const winLabel = INCIDENT_WINDOWS.find((w) => w.key === win)?.label ?? win;
  return (
    <div>
      <div className="row-between" style={{ marginBottom: 8 }}>
        <span className="muted note" style={{ margin: 0 }}>
          Outages
        </span>
        <div className="service-metrics" style={{ marginTop: 0, gap: 6 }}>
          {INCIDENT_WINDOWS.map(({ key, label }) => (
            <button
              key={key}
              className={`btn btn-sm${win === key ? " btn-primary" : ""}`}
              aria-pressed={win === key}
              onClick={() => setWin(key)}
            >
              {label}
            </button>
          ))}
        </div>
      </div>
      {report === null ? (
        <div className="loading-line">
          <span className="spinner" /> Loading…
        </div>
      ) : report.incidents.length === 0 ? (
        <p className="muted note">No incidents in the last {winLabel}.</p>
      ) : (
        <>
          <div className="events">
            {report.incidents.map((inc) => (
              <div className="event" key={inc.start_ms}>
                <span className="dot" style={{ background: statusColor(inc.worst_status) }} />
                <span>
                  {new Date(inc.start_ms).toLocaleString()}
                  {inc.ongoing && <span className="badge badge-down" style={{ marginLeft: 8 }}>ongoing</span>}
                </span>
                <span className="event-time">{fmtDuration(inc.duration_ms)}</span>
              </div>
            ))}
          </div>
          {report.resolution && (
            <span className="muted note">Times are {report.resolution}-bucket aligned.</span>
          )}
        </>
      )}
    </div>
  );
}

// MaintenanceState is the shared owner-window state: the list, whether one is
// active right now, and a reload to refresh after scheduling/deleting.
interface MaintenanceState {
  windows: MaintenanceWindow[] | null;
  active: boolean;
  reload: () => void;
}

// isMaintenanceActive reports whether a window covers "now" (start <= now < end
// and not tombstoned), mirroring Go MaintenanceWindow.Active.
function isMaintenanceActive(w: MaintenanceWindow, now: number): boolean {
  return !w.deleted && w.start_ms <= now && now < w.end_ms;
}

// useMaintenance loads the owner's maintenance windows for a check (and again
// when the check or owner changes). Best-effort: on error listMaintenance
// resolves to an empty list. `active` is recomputed against the current clock so
// the header badge reflects a window that has just started.
function useMaintenance(checkId: string, owner: string): MaintenanceState {
  const [windows, setWindows] = useState<MaintenanceWindow[] | null>(null);
  const [nonce, setNonce] = useState(0);
  useEffect(() => {
    let live = true;
    setWindows(null);
    listMaintenance({ checkId, owner }).then((w) => live && setWindows(w));
    return () => {
      live = false;
    };
  }, [checkId, owner, nonce]);
  const now = Date.now();
  const active = (windows ?? []).some((w) => isMaintenanceActive(w, now));
  return { windows, active, reload: () => setNonce((n) => n + 1) };
}

// toLocalInput renders an epoch-ms as a value for a datetime-local input in the
// browser's local timezone ("YYYY-MM-DDTHH:mm").
function toLocalInput(ms: number): string {
  const d = new Date(ms - new Date(ms).getTimezoneOffset() * 60_000);
  return d.toISOString().slice(0, 16);
}

// MaintenancePanel lists this owner's planned-downtime windows for a check and,
// when the view is editable (an owner identity is present), lets them schedule a
// new window or delete an existing one. Scheduling is gated exactly like the
// alerts panel — read-only without a browser key. Windows are owner-signed and
// gossiped, so one scheduled here shows up on every hub.
function MaintenancePanel({ id, checkId, maintenance }: { id: Identity | null; checkId: string; maintenance: MaintenanceState }) {
  const { windows, reload } = maintenance;
  const [start, setStart] = useState(() => toLocalInput(Date.now()));
  const [end, setEnd] = useState(() => toLocalInput(Date.now() + 60 * 60 * 1000));
  const [reason, setReason] = useState("");
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState("");
  const [delKey, setDelKey] = useState<string | null>(null);
  const now = Date.now();

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    if (!id || busy) return;
    const startMs = new Date(start).getTime();
    const endMs = new Date(end).getTime();
    if (!isFinite(startMs) || !isFinite(endMs)) {
      setErr("Enter a valid start and end time.");
      return;
    }
    if (endMs <= startMs) {
      setErr("End must be after start.");
      return;
    }
    setErr("");
    setBusy(true);
    try {
      await scheduleMaintenance(id, { checkId, startMs, endMs, reason: reason.trim() || undefined });
      setReason("");
      reload();
    } catch (e) {
      setErr(String(e));
    } finally {
      setBusy(false);
    }
  }

  async function remove(w: MaintenanceWindow) {
    if (!id) return;
    const key = `${w.check_id}|${w.start_ms}`;
    setDelKey(key);
    try {
      await deleteMaintenance(id, w);
      reload();
    } finally {
      setDelKey(null);
    }
  }

  const sorted = [...(windows ?? [])].sort((a, b) => a.start_ms - b.start_ms);

  return (
    <div>
      {windows === null ? (
        <div className="loading-line">
          <span className="spinner" /> Loading…
        </div>
      ) : sorted.length === 0 ? (
        <p className="muted note">No maintenance scheduled for this monitor.</p>
      ) : (
        <div className="alert-list">
          {sorted.map((w) => {
            const key = `${w.check_id}|${w.start_ms}`;
            const active = isMaintenanceActive(w, now);
            const past = w.end_ms <= now;
            return (
              <div className="alert-item" key={key}>
                <span className={`badge ${active ? "badge-degraded" : "badge-unknown"}`}>
                  {active ? "Active" : past ? "Ended" : "Scheduled"}
                </span>
                <div className="alert-main">
                  <span className="alert-dest">
                    {new Date(w.start_ms).toLocaleString()} → {new Date(w.end_ms).toLocaleString()}
                  </span>
                  <span className="alert-meta">{w.reason || "Planned maintenance"}</span>
                </div>
                {id && (
                  <button className="btn btn-sm btn-danger" disabled={delKey === key} onClick={() => remove(w)}>
                    {delKey === key ? "Removing…" : "Delete"}
                  </button>
                )}
              </div>
            );
          })}
        </div>
      )}

      {id && (
        <form className="alert-form" onSubmit={submit}>
          <label className="alert-num">
            from{" "}
            <input type="datetime-local" style={{ width: "auto" }} value={start} onChange={(e) => setStart(e.target.value)} />
          </label>
          <label className="alert-num">
            to{" "}
            <input type="datetime-local" style={{ width: "auto" }} value={end} onChange={(e) => setEnd(e.target.value)} />
          </label>
          <input
            value={reason}
            placeholder="Reason (optional) — e.g. planned db upgrade"
            maxLength={280}
            onChange={(e) => setReason(e.target.value)}
          />
          <button className="btn btn-primary" type="submit" disabled={busy}>
            {busy ? "Scheduling…" : "Schedule window"}
          </button>
          {err && (
            <div className="err" style={{ flexBasis: "100%" }}>
              {err}
            </div>
          )}
          <span className="muted note" style={{ flexBasis: "100%" }}>
            Maintenance windows are owner-signed and shared across the network. During an active window this monitor is
            flagged "In maintenance" so its downtime is expected, not alarming.
          </span>
        </form>
      )}
    </div>
  );
}
