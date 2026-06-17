import { useCallback, useEffect, useState } from "react";
import { Identity } from "./identity";
import { Service, LocationStatus, listServices, unsubscribe, renewLeases, forgetStoredAlerts } from "./api";
import { fmtRtt, latencyStats, relativeTime, statusColor } from "./theme";
import AddMonitor from "./AddMonitor";
import { Sparkline } from "./History";
import StatusBadge from "./Badge";
import Alerts from "./Alerts";
import AlertForm from "./AlertForm";
import CheckDetail from "./CheckDetail";
import ServiceMap from "./ServiceMap";

// Services is the "my services" dashboard for a given owner. When `editable`
// (the viewer holds the private key) it shows add/remove/alert controls;
// otherwise it's a read-only shared view (?owner=… bookmark).
export default function Services({ id, owner, editable }: { id: Identity | null; owner: string; editable: boolean }) {
  const [services, setServices] = useState<Service[]>([]);
  const [loaded, setLoaded] = useState(false);
  const [openId, setOpenId] = useState<string | null>(null);
  const [showAlerts, setShowAlerts] = useState(false);
  const [bulkAdd, setBulkAdd] = useState(false);

  const refresh = useCallback(async () => {
    const svcs = await listServices(owner);
    // The API returns services in map-iteration (i.e. random) order, so sort them
    // into a stable alphabetical order by target — otherwise the list reshuffles
    // on every 15s refresh.
    svcs.sort((a, b) => (a.target || a.check_id).localeCompare(b.target || b.check_id));
    setServices(svcs);
    setLoaded(true);
    // Keep this owner's subscriptions and alerts alive: re-sign them before the
    // bounded expiry lapses (throttled inside renewLeases). Only the key holder
    // can renew, so this runs only on the editable dashboard.
    if (editable && id && svcs.length > 0) {
      const intervals: Record<string, number> = {};
      for (const s of svcs) intervals[s.check_id] = s.interval_seconds;
      renewLeases(id, svcs.map((s) => s.check_id), intervals).catch(() => {});
    }
  }, [owner, editable, id]);

  useEffect(() => {
    refresh();
    const t = setInterval(refresh, 15_000);
    return () => clearInterval(t);
  }, [refresh]);

  const open = services.find((s) => s.check_id === openId);
  if (open) {
    return (
      <div className="container">
        <CheckDetail
          svc={open}
          id={editable ? id : null}
          owner={owner}
          services={services}
          onBack={() => setOpenId(null)}
          onChange={refresh}
        />
      </div>
    );
  }

  return (
    <div className="container">
      <h1 className="page-title">{editable ? "My services" : "Shared services"}</h1>
      <p className="page-sub">
        {editable
          ? "Targets you’re watching from probes around the network."
          : "A read-only view of someone’s monitors. Open your own dashboard to make changes."}
      </p>

      {editable && id && <AddMonitor id={id} onAdded={refresh} />}

      {editable && id && services.length > 0 && (
        <div className="toolbar">
          <span className="count">
            {services.length} monitor{services.length === 1 ? "" : "s"}
          </span>
          <button className="btn btn-sm" style={{ marginLeft: "auto" }} onClick={() => setShowAlerts((v) => !v)}>
            {showAlerts ? "Hide alerts" : "Manage alerts"}
          </button>
        </div>
      )}

      {showAlerts && editable && id && (
        <div className="panel rise" style={{ marginBottom: 18 }}>
          <div className="row-between" style={{ marginBottom: 12 }}>
            <h3 style={{ margin: 0 }}>Alert rules</h3>
            <button className="btn btn-sm" onClick={() => setBulkAdd((v) => !v)}>
              {bulkAdd ? "Cancel" : "+ Add to all monitors"}
            </button>
          </div>
          {bulkAdd && (
            <AlertForm
              id={id}
              checkIds={services.map((s) => s.check_id)}
              onDone={() => {
                setBulkAdd(false);
                refresh();
              }}
            />
          )}
          <Alerts id={id} owner={owner} services={services} onChange={refresh} />
        </div>
      )}

      {!loaded && (
        <div className="loading-line">
          <span className="spinner" /> Loading services…
        </div>
      )}

      {loaded && services.length === 0 && (
        <div className="empty">
          <div className="empty-title">Nothing monitored yet</div>
          {editable ? "Add a website, host, or port above and it’ll be checked from probes worldwide." : "This dashboard has no monitors."}
        </div>
      )}

      {services.map((s, i) => (
        <ServiceCard
          key={s.check_id}
          svc={s}
          id={editable ? id : null}
          index={i}
          onOpen={() => setOpenId(s.check_id)}
          onChange={refresh}
        />
      ))}
    </div>
  );
}

// summarize derives card metrics from a service's per-location statuses.
// Latency is computed separately (latencyStats) so down/timed-out probes don't
// pollute it.
function summarize(locations: LocationStatus[]) {
  let up = 0;
  let last = 0;
  for (const l of locations) {
    if (l.status === "up") up++;
    if (l.timestamp_ms > last) last = l.timestamp_ms;
  }
  return { up, total: locations.length, last };
}

// maxCountryTags caps how many country pills a card shows before collapsing the
// rest into a "+N more" affordance (the full per-probe list lives on the service
// page). Keeps a card compact no matter how many probes report.
const maxCountryTags = 8;

type CountryStat = { country: string; count: number; up: number; status: string };

// aggregateByCountry collapses per-probe statuses into one pill per country, so
// many probes in the same country (e.g. several Russian cities) read as a single
// "Russia" tag rather than a wall of duplicates. The country is up if any probe
// there sees it up, else degraded if any degraded, else down. Sorted worst-first
// (so problems stay visible when the list is capped), then alphabetically.
function aggregateByCountry(locations: LocationStatus[]): CountryStat[] {
  const by = new Map<string, { count: number; up: number; degraded: number; down: number }>();
  for (const l of locations) {
    const key = l.location.country || "?";
    const e = by.get(key) ?? { count: 0, up: 0, degraded: 0, down: 0 };
    e.count++;
    if (l.status === "up") e.up++;
    else if (l.status === "degraded") e.degraded++;
    else if (l.status === "down") e.down++;
    by.set(key, e);
  }
  const rank: Record<string, number> = { down: 0, degraded: 1, up: 2, unknown: 3 };
  return [...by.entries()]
    .map(([country, e]) => ({
      country,
      count: e.count,
      up: e.up,
      status: e.up > 0 ? "up" : e.degraded > 0 ? "degraded" : "down",
    }))
    .sort((a, b) => rank[a.status] - rank[b.status] || a.country.localeCompare(b.country));
}

function ServiceCard({
  svc,
  id,
  index,
  onOpen,
  onChange,
}: {
  svc: Service;
  id: Identity | null;
  index: number;
  onOpen: () => void;
  onChange: () => void;
}) {
  const [removing, setRemoving] = useState(false);
  const [mapOpen, setMapOpen] = useState(false);
  const m = summarize(svc.locations);
  const lat = latencyStats(svc.locations);
  const countries = aggregateByCountry(svc.locations);
  const shownCountries = countries.slice(0, maxCountryTags);
  const extraCountries = countries.length - shownCountries.length;

  async function remove(e: React.MouseEvent) {
    e.stopPropagation();
    if (!id) return;
    setRemoving(true);
    try {
      await unsubscribe(id, svc.check_id);
      forgetStoredAlerts(svc.check_id);
      onChange();
    } finally {
      setRemoving(false);
    }
  }

  return (
    <div
      className="service clickable rise"
      style={{ animationDelay: `${Math.min(index * 40, 320)}ms` }}
      onClick={onOpen}
      role="button"
      tabIndex={0}
      onKeyDown={(e) => (e.key === "Enter" ? onOpen() : undefined)}
    >
      <div className="service-head">
        <StatusBadge status={svc.overall} />
        <span className="service-target">{svc.target || svc.check_id}</span>
        <span className="service-type">{svc.type}</span>
        <span className="service-actions" onClick={(e) => e.stopPropagation()}>
          <button className="btn btn-ghost btn-sm" onClick={() => setMapOpen((v) => !v)} aria-expanded={mapOpen}>
            {mapOpen ? "Hide map" : "Map"}
          </button>
          {id && (
            <button className="btn btn-ghost btn-sm btn-danger" onClick={remove} disabled={removing}>
              {removing ? "Removing…" : "Remove"}
            </button>
          )}
        </span>
      </div>

      <div className="service-metrics">
        <div className="metric">
          <span className="metric-label">Locations</span>
          <span className="metric-value">
            {m.up}/{m.total} up
          </span>
        </div>
        <div className="metric">
          <span className="metric-label">Lowest</span>
          <span className="metric-value">{lat.lowest === null ? "—" : fmtRtt(lat.lowest)}</span>
        </div>
        <div className="metric">
          <span className="metric-label">p95</span>
          <span className="metric-value">{lat.p95 === null ? "—" : fmtRtt(lat.p95)}</span>
        </div>
        <div className="metric">
          <span className="metric-label">Last check</span>
          <span className="metric-value">{relativeTime(m.last)}</span>
        </div>
        <div className="service-spark">
          <Sparkline checkId={svc.check_id} />
        </div>
      </div>

      {countries.length > 0 && (
        <div className="locations">
          {shownCountries.map((c) => (
            <span
              key={c.country}
              className="loc"
              title={`${c.country}: ${c.up}/${c.count} probe${c.count === 1 ? "" : "s"} up`}
            >
              <span className="dot" style={{ background: statusColor(c.status) }} />
              {c.country}
              {c.count > 1 && <span className="loc-count">{c.count}</span>}
            </span>
          ))}
          {extraCountries > 0 && (
            <span className="loc loc-more" title="Open the service page for the full per-probe breakdown">
              +{extraCountries} more
            </span>
          )}
        </div>
      )}

      {mapOpen && (
        <div className="service-map-panel" onClick={(e) => e.stopPropagation()}>
          <ServiceMap locations={svc.locations} />
        </div>
      )}
    </div>
  );
}
