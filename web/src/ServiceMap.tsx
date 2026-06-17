import { useEffect, useRef } from "react";
import maplibregl, { Map as MapLibreMap, Marker } from "maplibre-gl";
import "maplibre-gl/dist/maplibre-gl.css";
import { LocationStatus } from "./api";
import { fmtRtt, relativeTime, STATUS_COLOR } from "./theme";

// Per-service map: one marker per probe that reported on this check, coloured by
// status, with a popup showing that probe's result. Unlike the global map this
// is scoped to a single monitor, so it stays readable.
//
// Same key-less OpenFreeMap style as the global map; override with VITE_MAP_STYLE.
const MAP_STYLE = import.meta.env.VITE_MAP_STYLE ?? "https://tiles.openfreemap.org/styles/positron";

export default function ServiceMap({ locations }: { locations: LocationStatus[] }) {
  const containerRef = useRef<HTMLDivElement | null>(null);
  const mapRef = useRef<MapLibreMap | null>(null);
  const markersRef = useRef<Marker[]>([]);
  const fittedRef = useRef(false);
  // Keep the latest data in a ref so the map's load handler and the data effect
  // both draw from current state without recreating the map on every refresh.
  const dataRef = useRef(locations);
  dataRef.current = locations;

  // Probes without a known location (lat/lon 0,0) can't be placed.
  const located = locations.filter((l) => !(l.location.lat === 0 && l.location.lon === 0));

  // Create the map once; redraw markers when data changes.
  useEffect(() => {
    if (!containerRef.current) return;
    const map = new maplibregl.Map({
      container: containerRef.current,
      style: MAP_STYLE,
      center: [10, 25],
      zoom: 1.1,
    });
    mapRef.current = map;
    map.addControl(new maplibregl.NavigationControl({ showCompass: false }), "top-right");
    map.on("load", () => draw(map, markersRef, fittedRef, dataRef.current));
    return () => {
      for (const m of markersRef.current) m.remove();
      markersRef.current = [];
      map.remove();
      mapRef.current = null;
      fittedRef.current = false;
    };
  }, []);

  useEffect(() => {
    const map = mapRef.current;
    if (map && map.loaded()) draw(map, markersRef, fittedRef, locations);
  }, [locations]);

  return (
    <div className="service-map-wrap">
      <div ref={containerRef} className="service-map" />
      {located.length === 0 && (
        <div className="service-map-empty">No probe locations to plot yet.</div>
      )}
      <div className="service-map-legend">
        <span><span className="dot" style={{ background: STATUS_COLOR.up }} /> up</span>
        <span><span className="dot" style={{ background: STATUS_COLOR.degraded }} /> degraded</span>
        <span><span className="dot" style={{ background: STATUS_COLOR.down }} /> down</span>
        {located.length < locations.length && (
          <span className="muted">· {locations.length - located.length} without location</span>
        )}
      </div>
    </div>
  );
}

function draw(
  map: MapLibreMap,
  markersRef: React.MutableRefObject<Marker[]>,
  fittedRef: React.MutableRefObject<boolean>,
  locations: LocationStatus[],
) {
  for (const m of markersRef.current) m.remove();
  markersRef.current = [];
  const bounds = new maplibregl.LngLatBounds();
  for (const p of locations) {
    if (p.location.lat === 0 && p.location.lon === 0) continue;
    const el = document.createElement("div");
    el.className = p.status === "down" ? "map-marker is-down" : "map-marker";
    el.style.background = STATUS_COLOR[p.status] ?? STATUS_COLOR.unknown;
    const popup = new maplibregl.Popup({ offset: 12 }).setDOMContent(popupContent(p));
    markersRef.current.push(
      new maplibregl.Marker({ element: el }).setLngLat([p.location.lon, p.location.lat]).setPopup(popup).addTo(map),
    );
    bounds.extend([p.location.lon, p.location.lat]);
  }
  // Fit to the probes once, so periodic refreshes don't fight the user's pan/zoom.
  if (!fittedRef.current && !bounds.isEmpty()) {
    map.fitBounds(bounds, { padding: 48, maxZoom: 6, duration: 0 });
    fittedRef.current = true;
  }
}

// popupContent builds the marker popup as DOM nodes. Result fields (city,
// country, target) come from any validly-signed probe result and are therefore
// attacker-controlled, so each is set via textContent — never interpolated into
// HTML — to keep a malicious result from injecting script into the dashboard.
function popupContent(p: LocationStatus): HTMLElement {
  const root = document.createElement("div");

  const place = document.createElement("strong");
  place.textContent = `${p.location.city || "?"}, ${p.location.country || "?"}`;
  root.appendChild(place);
  root.appendChild(document.createElement("br"));

  root.appendChild(document.createTextNode("status: "));
  const status = document.createElement("b");
  status.textContent = p.status;
  root.appendChild(status);
  root.appendChild(document.createTextNode(` · ${fmtRtt(p.rtt_ms)}`));
  root.appendChild(document.createElement("br"));

  const seen = document.createElement("span");
  seen.className = "muted";
  seen.textContent = relativeTime(p.timestamp_ms);
  root.appendChild(seen);

  return root;
}
