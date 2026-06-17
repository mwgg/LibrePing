// Shared visual + formatting helpers. Status colours live here (single source of
// truth) instead of being copied into every component, and a few small
// formatters keep number/time rendering consistent across views.

export type StatusKey = "up" | "down" | "degraded" | "unknown";

// Status hues, tuned for legibility on the light paper theme. These mirror the
// CSS custom properties in index.css so DOM-built nodes (map markers, popups)
// and React components agree.
export const STATUS_COLOR: Record<string, string> = {
  up: "#15803d",
  down: "#b91c1c",
  degraded: "#b45309",
  unknown: "#9a9d92",
};

export const STATUS_LABEL: Record<string, string> = {
  up: "Operational",
  down: "Down",
  degraded: "Degraded",
  unknown: "Unknown",
};

export function statusColor(status: string): string {
  return STATUS_COLOR[status] ?? STATUS_COLOR.unknown;
}

// relativeTime renders a compact "3m ago" style string from an epoch-ms value.
export function relativeTime(ms: number): string {
  if (!ms) return "—";
  const diff = Date.now() - ms;
  if (diff < 0) return "just now";
  const s = Math.floor(diff / 1000);
  if (s < 45) return "just now";
  const m = Math.floor(s / 60);
  if (m < 60) return `${m}m ago`;
  const h = Math.floor(m / 60);
  if (h < 24) return `${h}h ago`;
  const d = Math.floor(h / 24);
  if (d < 30) return `${d}d ago`;
  return new Date(ms).toLocaleDateString();
}

// fmtRtt renders a round-trip time with sensible precision.
export function fmtRtt(ms: number): string {
  if (!isFinite(ms) || ms <= 0) return "—";
  if (ms < 1) return `${ms.toFixed(2)} ms`;
  if (ms < 100) return `${ms.toFixed(1)} ms`;
  return `${Math.round(ms)} ms`;
}

// pct renders a 0..1 fraction as a percentage with one decimal under 100%.
export function pct(fraction: number): string {
  const p = fraction * 100;
  if (p >= 100) return "100%";
  return `${p.toFixed(1)}%`;
}

// latencyStats summarises round-trip times across samples, EXCLUDING ones that
// didn't actually measure a response. A down/timed-out check reports the time it
// waited before giving up (~the 10s timeout), which is not the service's
// latency — counting it would conflate "unreachable" with "slow". A down result
// is infinite latency, not 10s, so it is dropped here. Degraded/up samples keep
// their real rtt. Returns the lowest and the 95th-percentile (nearest-rank) over
// the measured samples; `n` is how many counted (0 => values are null).
export function latencyStats(samples: { status: string; rtt_ms: number }[]): {
  lowest: number | null;
  p95: number | null;
  n: number;
} {
  const rtts = samples
    .filter((s) => s.status !== "down" && s.rtt_ms > 0)
    .map((s) => s.rtt_ms)
    .sort((a, b) => a - b);
  if (rtts.length === 0) return { lowest: null, p95: null, n: 0 };
  const idx = Math.min(rtts.length - 1, Math.max(0, Math.ceil(0.95 * rtts.length) - 1));
  return { lowest: rtts[0], p95: rtts[idx], n: rtts.length };
}
