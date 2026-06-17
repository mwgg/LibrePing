import { useEffect, useRef, useState } from "react";
import maplibregl, { Map as MapLibreMap, Marker } from "maplibre-gl";
import "maplibre-gl/dist/maplibre-gl.css";
import { STATUS_COLOR } from "./theme";

// Map view of the results THIS hub holds, plus the peer-hub directory. Under
// partial replication a hub stores only a slice of the network's results, so
// /api/v1/locations is a local/partial view, not the whole network — the banner
// surfaces how many shards this hub holds so the picture isn't mistaken for global.
interface LocationStatus {
  probe_id: string;
  location: { country: string; city: string; lat: number; lon: number };
  target: string;
  check_type: string;
  status: "up" | "down" | "degraded";
  rtt_ms: number;
  timestamp_ms: number;
}

interface PeerHub {
  hub_id: string;
  public_url: string;
  name?: string;
}

// Default to OpenFreeMap's "positron" — a key-less, free light vector style that
// suits the editorial theme far better than the low-detail demo tiles.
// Override with VITE_MAP_STYLE to use a different/keyed provider.
const MAP_STYLE = import.meta.env.VITE_MAP_STYLE ?? "https://tiles.openfreemap.org/styles/positron";

interface Coverage {
  subscribed_shards: number;
  total_shards: number;
}

export default function GlobalMap() {
  const markersRef = useRef<Marker[]>([]);
  const [hubs, setHubs] = useState<PeerHub[]>([]);
  const [coverage, setCoverage] = useState<Coverage | null>(null);

  useEffect(() => {
    async function loadHubs() {
      try {
        const res = await fetch("/api/v1/hubs");
        if (res.ok) setHubs(await res.json());
      } catch {
        /* best-effort */
      }
    }
    async function loadCoverage() {
      try {
        const res = await fetch("/api/v1/p2p");
        if (res.ok) {
          const j = await res.json();
          if (j.mesh) setCoverage({ subscribed_shards: j.mesh.subscribed_shards, total_shards: j.mesh.total_shards });
        }
      } catch {
        /* best-effort */
      }
    }
    loadHubs();
    loadCoverage();
    const timer = setInterval(() => {
      loadHubs();
      loadCoverage();
    }, 30_000);
    return () => clearInterval(timer);
  }, []);

  useEffect(() => {
    const map = new maplibregl.Map({ container: "map", style: MAP_STYLE, center: [10, 25], zoom: 1.4 });
    async function refresh() {
      try {
        const res = await fetch("/api/v1/locations");
        if (!res.ok) return;
        drawMarkers(map, markersRef, await res.json());
      } catch {
        /* keep last state */
      }
    }
    map.on("load", refresh);
    const timer = setInterval(refresh, 15_000);
    return () => {
      clearInterval(timer);
      map.remove();
    };
  }, []);

  const partial = coverage !== null && coverage.subscribed_shards < coverage.total_shards;

  return (
    <>
      <div id="map" />
      {partial && coverage && (
        <div className="map-overlay map-scope">
          Local view — this hub holds {coverage.subscribed_shards}/{coverage.total_shards} result shards. Other hubs see more.
        </div>
      )}
      {hubs.length > 0 && (
        <div className="map-overlay peers">
          <div className="peers-title">Peer hubs ({hubs.length})</div>
          {hubs.map((h) => (
            <a key={h.hub_id} className="peer" href={h.public_url} target="_blank" rel="noreferrer">
              {h.name || h.public_url.replace(/^https?:\/\//, "")}
            </a>
          ))}
        </div>
      )}
      <div className="map-overlay legend">
        <div className="row"><span className="dot" style={{ background: STATUS_COLOR.up }} /> up</div>
        <div className="row"><span className="dot" style={{ background: STATUS_COLOR.degraded }} /> degraded</div>
        <div className="row"><span className="dot" style={{ background: STATUS_COLOR.down }} /> down</div>
      </div>
    </>
  );
}

function drawMarkers(map: MapLibreMap, markersRef: React.MutableRefObject<Marker[]>, points: LocationStatus[]) {
  for (const m of markersRef.current) m.remove();
  markersRef.current = [];
  for (const p of points) {
    if (p.location.lat === 0 && p.location.lon === 0) continue;
    const el = document.createElement("div");
    el.className = p.status === "down" ? "map-marker is-down" : "map-marker";
    el.style.background = STATUS_COLOR[p.status] ?? STATUS_COLOR.unknown;
    // Build the popup as DOM nodes and assign untrusted fields via textContent.
    // The result target/location come from any validly-signed result, so they
    // are attacker-controlled — never interpolate them into HTML (stored XSS
    // would run in the dashboard origin and could exfiltrate the account seed).
    const popup = new maplibregl.Popup({ offset: 12 }).setDOMContent(popupContent(p));
    markersRef.current.push(
      new maplibregl.Marker({ element: el }).setLngLat([p.location.lon, p.location.lat]).setPopup(popup).addTo(map),
    );
  }
}

// popupContent builds the marker popup as a DOM subtree. Every dynamic value is
// set via textContent so attacker-controlled fields (target, city, country)
// cannot inject markup or script.
function popupContent(p: LocationStatus): HTMLElement {
  const root = document.createElement("div");

  const place = document.createElement("strong");
  place.textContent = `${p.location.city || "?"}, ${p.location.country || "?"}`;
  root.appendChild(place);
  root.appendChild(document.createElement("br"));

  const line = document.createElement("span");
  line.textContent = `${p.check_type} → ${p.target}`;
  root.appendChild(line);
  root.appendChild(document.createElement("br"));

  root.appendChild(document.createTextNode("status: "));
  const status = document.createElement("b");
  status.textContent = p.status;
  root.appendChild(status);
  root.appendChild(document.createTextNode(` · ${p.rtt_ms.toFixed(1)} ms`));

  return root;
}
