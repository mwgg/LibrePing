import { useEffect, useRef, useState } from "react";
import maplibregl, { Map as MapLibreMap, Marker } from "maplibre-gl";
import "maplibre-gl/dist/maplibre-gl.css";
import { NetworkView, HubNode, ProbeNode, fetchNetwork } from "./api";

// The network map showcases who is participating: every hub, every probe, and
// which hub each probe is talking to (the edges). It is NOT a monitoring view —
// monitoring lives on the per-service pages.

const MAP_STYLE = import.meta.env.VITE_MAP_STYLE ?? "https://tiles.openfreemap.org/styles/positron";
const HUB_COLOR = "#173a5e";
const PROBE_COLOR = "#15803d";

export default function GlobalMap() {
  const mapRef = useRef<MapLibreMap | null>(null);
  const markersRef = useRef<Marker[]>([]);
  const loadedRef = useRef(false);
  const [view, setView] = useState<NetworkView>({ hubs: [], probes: [] });

  useEffect(() => {
    const map = new maplibregl.Map({ container: "map", style: MAP_STYLE, center: [10, 25], zoom: 1.4 });
    mapRef.current = map;
    map.on("load", () => {
      map.addSource("edges", { type: "geojson", data: { type: "FeatureCollection", features: [] } });
      map.addLayer({
        id: "edges",
        type: "line",
        source: "edges",
        paint: { "line-color": HUB_COLOR, "line-width": 1, "line-opacity": 0.28 },
      });
      loadedRef.current = true;
      draw(map, markersRef, view);
    });
    const refresh = () => fetchNetwork().then(setView);
    refresh();
    const timer = setInterval(refresh, 30_000);
    return () => {
      clearInterval(timer);
      for (const m of markersRef.current) m.remove();
      map.remove();
      mapRef.current = null;
      loadedRef.current = false;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  // Redraw whenever data changes (once the map style is ready).
  useEffect(() => {
    const map = mapRef.current;
    if (map && loadedRef.current) draw(map, markersRef, view);
  }, [view]);

  const countries = new Set<string>();
  for (const p of view.probes) if (p.location.country) countries.add(p.location.country);
  for (const h of view.hubs) if (h.location.country) countries.add(h.location.country);

  return (
    <>
      <div id="map" />
      <div className="map-overlay map-scope">
        <div className="net-stats">
          <b>{view.hubs.length}</b> hubs · <b>{view.probes.length}</b> probes · <b>{countries.size}</b> countries
        </div>
        <span className="muted note">Live network — who's participating and which hub each probe talks to.</span>
      </div>
      <div className="map-overlay legend">
        <div className="row">
          <span className="net-diamond" style={{ background: HUB_COLOR }} /> hub
        </div>
        <div className="row">
          <span className="dot" style={{ background: PROBE_COLOR }} /> probe
        </div>
      </div>
    </>
  );
}

function placed(loc: { lat: number; lon: number }): boolean {
  return !(loc.lat === 0 && loc.lon === 0);
}

function draw(map: MapLibreMap, markersRef: React.MutableRefObject<Marker[]>, view: NetworkView) {
  for (const m of markersRef.current) m.remove();
  markersRef.current = [];

  const hubAt = new Map<string, HubNode>();
  for (const h of view.hubs) hubAt.set(h.hub_id, h);

  // Edges: probe → its hub.
  const features: GeoJSON.Feature[] = [];
  for (const p of view.probes) {
    const hub = hubAt.get(p.hub_id);
    if (!hub || !placed(p.location) || !placed(hub.location)) continue;
    features.push({
      type: "Feature",
      properties: {},
      geometry: {
        type: "LineString",
        coordinates: [
          [p.location.lon, p.location.lat],
          [hub.location.lon, hub.location.lat],
        ],
      },
    });
  }
  const src = map.getSource("edges") as maplibregl.GeoJSONSource | undefined;
  src?.setData({ type: "FeatureCollection", features });

  // Probe dots (drawn first, so hubs sit on top).
  for (const p of view.probes) {
    if (!placed(p.location)) continue;
    const el = document.createElement("div");
    el.className = "map-marker net-probe";
    el.style.background = PROBE_COLOR;
    markersRef.current.push(
      new maplibregl.Marker({ element: el })
        .setLngLat([p.location.lon, p.location.lat])
        .setPopup(new maplibregl.Popup({ offset: 10 }).setDOMContent(probePopup(p, hubAt.get(p.hub_id))))
        .addTo(map),
    );
  }
  // Hub diamonds.
  for (const h of view.hubs) {
    if (!placed(h.location)) continue;
    const n = view.probes.filter((p) => p.hub_id === h.hub_id).length;
    const el = document.createElement("div");
    el.className = "net-diamond net-hub-marker";
    el.style.background = HUB_COLOR;
    markersRef.current.push(
      new maplibregl.Marker({ element: el })
        .setLngLat([h.location.lon, h.location.lat])
        .setPopup(new maplibregl.Popup({ offset: 12 }).setDOMContent(hubPopup(h, n)))
        .addTo(map),
    );
  }
}

// Popups are built as DOM nodes with textContent — hub names and locations are
// self-declared (attacker-controllable), so they must never be interpolated as HTML.
function hubPopup(h: HubNode, probeCount: number): HTMLElement {
  const root = document.createElement("div");
  const title = document.createElement("strong");
  title.textContent = (h.name || h.public_url?.replace(/^https?:\/\//, "") || h.hub_id.slice(0, 10)) + (h.self ? " (this hub)" : "");
  root.appendChild(title);
  root.appendChild(document.createElement("br"));
  const where = document.createElement("span");
  where.textContent = `Hub · ${h.location.city || "?"}, ${h.location.country || "?"}`;
  root.appendChild(where);
  root.appendChild(document.createElement("br"));
  root.appendChild(document.createTextNode(`${probeCount} probe${probeCount === 1 ? "" : "s"} connected`));
  return root;
}

function probePopup(p: ProbeNode, hub?: HubNode): HTMLElement {
  const root = document.createElement("div");
  const title = document.createElement("strong");
  title.textContent = `${p.location.city || "?"}, ${p.location.country || "?"}`;
  root.appendChild(title);
  root.appendChild(document.createElement("br"));
  const line = document.createElement("span");
  line.textContent = "Probe → " + (hub ? hub.name || hub.public_url?.replace(/^https?:\/\//, "") || hub.hub_id.slice(0, 10) : "?");
  root.appendChild(line);
  return root;
}
