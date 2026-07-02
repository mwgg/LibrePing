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

// fmtDuration renders a millisecond span as a compact "2h 15m" style string. It
// shows at most the two largest non-zero units (e.g. "1d 3h", "5m 20s") so an
// outage length reads at a glance. Sub-minute spans fall back to seconds, and a
// zero/negative span reads as "0s" rather than an empty string.
export function fmtDuration(ms: number): string {
  if (!isFinite(ms) || ms <= 0) return "0s";
  const s = Math.floor(ms / 1000);
  const d = Math.floor(s / 86400);
  const h = Math.floor((s % 86400) / 3600);
  const m = Math.floor((s % 3600) / 60);
  const sec = s % 60;
  const parts: string[] = [];
  if (d > 0) parts.push(`${d}d`);
  if (h > 0) parts.push(`${h}h`);
  if (m > 0) parts.push(`${m}m`);
  if (sec > 0) parts.push(`${sec}s`);
  return parts.slice(0, 2).join(" ") || "0s";
}

// pct renders a 0..1 fraction as a percentage with one decimal under 100%.
export function pct(fraction: number): string {
  const p = fraction * 100;
  if (p >= 100) return "100%";
  return `${p.toFixed(1)}%`;
}

// Availability thresholds (as 0..1 fractions) — the single source of truth for
// colouring SLA uptime figures: green at/above 99.9%, amber at/above 99%, red
// below. Reuses the shared status palette so the hues match the rest of the UI.
export const UPTIME_GREEN = 0.999;
export const UPTIME_AMBER = 0.99;

// uptimeColor maps a 0..1 availability fraction to a status hue. Null (no data)
// reads as unknown/grey.
export function uptimeColor(fraction: number | null): string {
  if (fraction === null) return STATUS_COLOR.unknown;
  if (fraction >= UPTIME_GREEN) return STATUS_COLOR.up;
  if (fraction >= UPTIME_AMBER) return STATUS_COLOR.degraded;
  return STATUS_COLOR.down;
}

// fmtUptime renders an uptime window as a percentage, or "n/a" when the hub has
// no data for it (unavailable / null).
export function fmtUptime(w: { uptime: number | null; available: boolean } | undefined): string {
  if (!w || !w.available || w.uptime === null) return "n/a";
  return pct(w.uptime);
}

// The uptime windows shown across the dashboard, in display order. Kept here so
// CheckDetail and the service cards agree on labels/order.
export const UPTIME_WINDOWS: { key: "24h" | "7d" | "30d"; label: string }[] = [
  { key: "24h", label: "24h" },
  { key: "7d", label: "7d" },
  { key: "30d", label: "30d" },
];

// Wall-clock minutes per window, used to translate the error budget into an
// approximate downtime allowance ("13m of 43m used"). It is approximate because
// the uptime figure is sample-weighted (share of observations up), not measured
// wall-clock, so we map the fractions onto the nominal window length.
export const WINDOW_MINUTES: Record<"24h" | "7d" | "30d", number> = {
  "24h": 24 * 60,
  "7d": 7 * 24 * 60,
  "30d": 30 * 24 * 60,
};

// ErrorBudget is the SLO error-budget view for one window against a target
// availability fraction. When the window has no data (`available` is false) all
// numeric fields are null and `available` is false, so the UI renders "n/a".
// `consumed` is observedDowntime/allowedDowntime clamped at ≥0 (it can exceed 1,
// meaning the budget is blown); `remaining` is 1-consumed (can go negative).
// `allowedMinutes`/`consumedMinutes` express the same fractions as approximate
// wall-clock downtime over the window (sample-weighted, so approximate).
export interface ErrorBudget {
  available: boolean;
  consumed: number | null;
  remaining: number | null;
  allowedMinutes: number | null;
  consumedMinutes: number | null;
}

// errorBudget computes the SLO error budget for one uptime window against a
// target fraction. A window with no data, a null uptime, or zero samples yields
// an unavailable budget. A target of 100% (allowed downtime of 0) is treated as
// unavailable too, since dividing by a zero budget is meaningless.
export function errorBudget(
  target: number,
  window: { uptime: number | null; samples: number; available: boolean } | undefined,
  windowMinutes: number,
): ErrorBudget {
  const na: ErrorBudget = { available: false, consumed: null, remaining: null, allowedMinutes: null, consumedMinutes: null };
  if (!window || !window.available || window.uptime === null || window.samples <= 0) return na;
  const allowedDowntime = 1 - target;
  if (allowedDowntime <= 0) return na;
  const observedDowntime = Math.max(0, 1 - window.uptime);
  const consumed = observedDowntime / allowedDowntime;
  return {
    available: true,
    consumed,
    remaining: 1 - consumed,
    allowedMinutes: allowedDowntime * windowMinutes,
    consumedMinutes: observedDowntime * windowMinutes,
  };
}

// budgetColor maps error-budget consumption to a status hue: green with plenty
// of budget left, amber when most of it is spent, red once it is blown (>100%
// consumed). Mirrors the up/degraded/down palette used for uptime figures.
export function budgetColor(consumed: number | null): string {
  if (consumed === null) return STATUS_COLOR.unknown;
  if (consumed >= 1) return STATUS_COLOR.down;
  if (consumed >= 0.75) return STATUS_COLOR.degraded;
  return STATUS_COLOR.up;
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
