import { useEffect, useState } from "react";
import { Identity } from "./identity";
import { Service, SignedResult, queryResults } from "./api";
import { fmtRtt, latencyStats, relativeTime, statusColor } from "./theme";
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
          <History checkId={svc.check_id} />
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
