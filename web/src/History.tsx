import { useEffect, useState } from "react";
import { HistorySummary, history } from "./api";
import { STATUS_COLOR } from "./theme";

// History shows a per-check uptime/latency strip from the hub's rolled-up
// summaries (hourly for short ranges, daily for long). Buckets are merged across
// probes into a single point per time bucket. Read-only; aggregates are
// locally-derived, not signed per-result records.

interface Bucket {
  ts: number;
  uptime: number;
  rtt: number;
  total: number;
  up: number;
  down: number;
  degraded: number;
}

// mergeBuckets folds per-probe summaries into one point per bucket.
function mergeBuckets(rows: HistorySummary[]): Bucket[] {
  const by = new Map<number, { up: number; down: number; degraded: number; total: number; rtt: number; rttN: number }>();
  for (const r of rows) {
    const b = by.get(r.bucket_ms) ?? { up: 0, down: 0, degraded: 0, total: 0, rtt: 0, rttN: 0 };
    b.up += r.up_count;
    b.down += r.down_count;
    b.degraded += r.degraded_count;
    b.total += r.samples;
    b.rtt += r.rtt_avg * r.samples;
    b.rttN += r.samples;
    by.set(r.bucket_ms, b);
  }
  return [...by.entries()]
    .sort((a, b) => a[0] - b[0])
    .map(([ts, b]) => ({
      ts,
      uptime: b.total > 0 ? b.up / b.total : 0,
      rtt: b.rttN > 0 ? b.rtt / b.rttN : 0,
      total: b.total,
      up: b.up,
      down: b.down,
      degraded: b.degraded,
    }));
}

// bucketFill paints a bucket as a stacked gradient of its up / degraded / down
// shares instead of one solid colour, so a service down from one of several
// locations reads as a mostly-green bar with a small red band — proportional to
// the actual failure rate — rather than full red or a misleading full green.
function bucketFill(b: Bucket): string {
  const t = b.total || 1;
  const up = (b.up / t) * 100;
  const deg = (b.degraded / t) * 100;
  const down = (b.down / t) * 100;
  // Stack bottom → top: up (green), degraded (amber), down (red), then any
  // remaining unknown samples (grey). Hard stops give crisp bands.
  const s1 = up;
  const s2 = up + deg;
  const s3 = up + deg + down;
  return (
    `linear-gradient(to top,` +
    ` ${STATUS_COLOR.up} 0% ${s1}%,` +
    ` ${STATUS_COLOR.degraded} ${s1}% ${s2}%,` +
    ` ${STATUS_COLOR.down} ${s2}% ${s3}%,` +
    ` ${STATUS_COLOR.unknown} ${s3}% 100%)`
  );
}

// useHistory loads + merges a check's history once.
function useHistory(checkId: string): { buckets: Bucket[] | null; resolution: string } {
  const [rows, setRows] = useState<HistorySummary[] | null>(null);
  useEffect(() => {
    let live = true;
    setRows(null);
    history(checkId).then((r) => live && setRows(r));
    return () => {
      live = false;
    };
  }, [checkId]);
  if (rows === null) return { buckets: null, resolution: "" };
  return { buckets: mergeBuckets(rows), resolution: rows[0]?.resolution ?? "" };
}

export default function History({ checkId }: { checkId: string }) {
  const { buckets, resolution } = useHistory(checkId);

  if (buckets === null)
    return (
      <div className="loading-line">
        <span className="spinner" /> Loading history…
      </div>
    );
  if (buckets.length === 0) return <div className="muted note">No history yet (this hub may not store this check).</div>;

  return (
    <div className="history">
      <div className="history-bars">
        {buckets.map((b) => {
          const when = new Date(b.ts).toLocaleString();
          return (
            <span
              key={b.ts}
              className="history-bar"
              title={`${when} — ${(b.uptime * 100).toFixed(1)}% up (${b.up} up / ${b.degraded} degraded / ${b.down} down of ${b.total}), ${b.rtt.toFixed(0)}ms avg`}
              style={{ background: bucketFill(b), height: "100%" }}
            />
          );
        })}
      </div>
      <span className="note">
        {buckets.length} {resolution} buckets · each bar is the share of checks up (green) / degraded (amber) / down (red)
      </span>
    </div>
  );
}

// Sparkline is a compact, label-free uptime strip for service cards.
export function Sparkline({ checkId }: { checkId: string }) {
  const { buckets } = useHistory(checkId);
  if (!buckets || buckets.length === 0) return null;
  const recent = buckets.slice(-32);
  return (
    <div className="sparkline" title="recent uptime">
      {recent.map((b) => (
        <span key={b.ts} className="spark-bar" style={{ background: bucketFill(b), height: "100%" }} />
      ))}
    </div>
  );
}
