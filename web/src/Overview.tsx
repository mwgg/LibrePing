import { useEffect, useState } from "react";
import { Service, LocationStatus, listServices } from "./api";
import { pct } from "./theme";
import StatusBadge from "./Badge";

interface ShardCoverage {
  total: number;
  replication: number;
  storage_hubs: number;
  uncovered: number;
  under_replicated: number;
}

interface PeerHub {
  hub_id: string;
}

// Overview is the network-at-a-glance landing view: monitor health, how many
// probes and locations are reporting, peer-hub count, and result-shard coverage.
// Everything is derived from existing public endpoints.
export default function Overview({ owner }: { owner: string }) {
  const [services, setServices] = useState<Service[]>([]);
  const [locations, setLocations] = useState<LocationStatus[]>([]);
  const [hubs, setHubs] = useState<PeerHub[]>([]);
  const [shards, setShards] = useState<ShardCoverage | null>(null);
  const [loaded, setLoaded] = useState(false);

  useEffect(() => {
    let live = true;
    async function load() {
      const [svcs, loc, hubList, p2p] = await Promise.all([
        listServices(owner),
        fetch("/api/v1/locations").then((r) => (r.ok ? r.json() : [])).catch(() => []),
        fetch("/api/v1/hubs").then((r) => (r.ok ? r.json() : [])).catch(() => []),
        fetch("/api/v1/p2p").then((r) => (r.ok ? r.json() : null)).catch(() => null),
      ]);
      if (!live) return;
      setServices(svcs);
      setLocations(loc);
      setHubs(hubList);
      setShards(p2p?.shards ?? null);
      setLoaded(true);
    }
    load();
    const t = setInterval(load, 30_000);
    return () => {
      live = false;
      clearInterval(t);
    };
  }, [owner]);

  const up = services.filter((s) => s.overall === "up").length;
  const down = services.filter((s) => s.overall === "down").length;
  const degraded = services.filter((s) => s.overall === "degraded").length;
  const operational = services.length > 0 ? up / services.length : 1;

  const probes = new Set(locations.map((l) => l.probe_id)).size;
  const places = new Set(
    locations.filter((l) => l.location.lat || l.location.lon).map((l) => `${l.location.city}|${l.location.country}`),
  ).size;

  const attention = services.filter((s) => s.overall === "down" || s.overall === "degraded");

  return (
    <div className="container">
      <h1 className="page-title">Network overview</h1>
      <p className="page-sub">Live health across your monitors and the probes and hubs reporting them.</p>

      {!loaded ? (
        <div className="loading-line">
          <span className="spinner" /> Gathering signals…
        </div>
      ) : (
        <>
          <div className="stats">
            <div className={`stat ${down > 0 ? "stat-down" : degraded > 0 ? "stat-degraded" : "stat-up"} rise`}>
              <div className="stat-label">Monitors</div>
              <div className="stat-value">{services.length}</div>
              <div className="stat-foot">
                {up} up · {down} down · {degraded} degraded
              </div>
            </div>
            <div className="stat stat-up rise" style={{ animationDelay: "60ms" }}>
              <div className="stat-label">Operational</div>
              <div className="stat-value">{pct(operational)}</div>
              <div className="stat-foot">of your monitors are up</div>
            </div>
            <div className="stat rise" style={{ animationDelay: "120ms" }}>
              <div className="stat-label">Probes reporting</div>
              <div className="stat-value">{probes}</div>
              <div className="stat-foot">{places} distinct location{places === 1 ? "" : "s"}</div>
            </div>
            <div className="stat rise" style={{ animationDelay: "180ms" }}>
              <div className="stat-label">Peer hubs</div>
              <div className="stat-value">{hubs.length}</div>
              <div className="stat-foot">federating over libp2p</div>
            </div>
          </div>

          {attention.length > 0 && (
            <>
              <h2 className="section-head">Needs attention</h2>
              <div className="alert-list">
                {attention.map((s) => (
                  <div className="alert-item" key={s.check_id}>
                    <StatusBadge status={s.overall} />
                    <div className="alert-main">
                      <span className="alert-dest">{s.target || s.check_id}</span>
                      <span className="alert-meta">{s.type.toUpperCase()} · checked from {s.locations.length} location(s)</span>
                    </div>
                  </div>
                ))}
              </div>
            </>
          )}

          <h2 className="section-head">Result-shard coverage</h2>
          <div className="panel">
            {shards ? (
              <>
                <div className="health" style={{ marginBottom: 8 }}>
                  <span
                    className="pip"
                    style={{
                      background:
                        shards.uncovered > 0 ? "var(--down)" : shards.under_replicated > 0 ? "var(--degraded)" : "var(--up)",
                    }}
                  />
                  {shards.uncovered > 0
                    ? `${shards.uncovered} of ${shards.total} shards have no holder`
                    : shards.under_replicated > 0
                      ? `${shards.under_replicated} of ${shards.total} shards are under-replicated`
                      : `All ${shards.total} shards are sufficiently replicated`}
                </div>
                <p className="muted note" style={{ margin: 0 }}>
                  Results are sharded across {shards.storage_hubs} storage hub{shards.storage_hubs === 1 ? "" : "s"}, each shard
                  targeting {shards.replication} replicas. The control plane (catalog, subscriptions, alerts) is fully replicated
                  everywhere.
                </p>
              </>
            ) : (
              <p className="muted note" style={{ margin: 0 }}>
                Coverage data unavailable from this hub.
              </p>
            )}
          </div>
        </>
      )}
    </div>
  );
}
