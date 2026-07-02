// Thin client for the hub JSON API. Reads are public; writes carry an
// owner-signed payload built in identity.ts.
import { Identity, signSubscription, signAlertRule, signMaintenanceWindow, AlertInput, AlertChannel, HubKey } from "./identity";

const DEFAULT_EXPIRY_DAYS = 7;

function expiryMs(): number {
  return Date.now() + DEFAULT_EXPIRY_DAYS * 24 * 60 * 60 * 1000;
}

export interface CreatedCheck {
  id: string;
  type: string;
  target: string;
  interval_seconds: number;
}

export interface LocationStatus {
  probe_id: string;
  location: { country: string; city: string; lat: number; lon: number };
  target: string;
  check_type: string;
  status: string;
  rtt_ms: number;
  timestamp_ms: number;
}

export interface Service {
  check_id: string;
  type: string;
  target: string;
  interval_seconds: number;
  overall: string;
  locations: LocationStatus[];
}

export interface HistorySummary {
  bucket_ms: number;
  resolution: string;
  check_id: string;
  probe_id: string;
  samples: number;
  up_count: number;
  down_count: number;
  degraded_count: number;
  rtt_avg: number;
  rtt_min: number;
  rtt_max: number;
  last_status: string;
  check_type: string;
  target: string;
  // The probe's self-declared location for the bucket. May be partially empty
  // (country/city blank) since location is not proven — group the blanks into an
  // "Unknown" region rather than dropping them.
  location: { country: string; city: string; lat: number; lon: number };
}

// UptimeWindow is one time-window's availability estimate (GET /api/v1/uptime).
// `uptime` is (up+degraded)/samples in [0,1], or null when `available` is false —
// which happens when this hub has no local data for the check or doesn't hold it.
export interface UptimeWindow {
  uptime: number | null;
  samples: number;
  up: number;
  down: number;
  degraded: number;
  available: boolean;
}

// The windows the uptime endpoint reports, in display order.
export type UptimeWindowKey = "24h" | "7d" | "30d";

// UptimeReport is the per-check availability across the standard windows. It is a
// sample-weighted estimate (a share of observations up, not wall-clock uptime).
export interface UptimeReport {
  check_id: string;
  windows: Partial<Record<UptimeWindowKey, UptimeWindow>>;
}

// AlertRule is the hub-side view of a rule (GET /api/v1/alerts). The destination
// is never returned in the clear — only the sealed-per-hub `recipients` map and
// a stable `dest_hash` fingerprint.
export interface AlertRule {
  owner: string;
  check_id: string;
  channel: AlertChannel;
  dest_hash: string;
  recipients: Record<string, string>;
  fail_locations: number;
  for_seconds: number;
  expiry_ms: number;
  updated_ms: number;
  deleted?: boolean;
}

// MaintenanceWindow is the hub-side view of an owner's planned-downtime window
// (GET /api/v1/maintenance). It is owner-signed and gossiped, not sealed. A
// window is ACTIVE at time T when !deleted && start_ms <= T < end_ms.
export interface MaintenanceWindow {
  owner: string;
  check_id: string;
  start_ms: number;
  end_ms: number;
  reason?: string;
  expiry_ms: number;
  updated_ms: number;
  deleted?: boolean;
}

// SignedResult mirrors protocol.SignedResult; only the fields the dashboard
// reads are typed here.
export interface SignedResult {
  content: {
    check_id: string;
    check_type: string;
    target: string;
    probe_id: string;
    location: { country: string; city: string; lat: number; lon: number };
    timestamp_ms: number;
    status: string;
    rtt_ms: number;
    detail?: Record<string, string>;
  };
}

// history fetches rolled-up (hourly/daily) summaries for one check. These are
// locally-derived aggregates, not signed per-result records.
export async function history(checkId: string, fromMs?: number, toMs?: number): Promise<HistorySummary[]> {
  const p = new URLSearchParams({ check_id: checkId });
  if (fromMs) p.set("from_ms", String(fromMs));
  if (toMs) p.set("to_ms", String(toMs));
  const res = await fetch(`/api/v1/results/history?${p.toString()}`);
  if (!res.ok) return [];
  return res.json();
}

// queryResults fetches raw signed results for one check (newest-first). Returns
// empty if this hub doesn't store the check (partial replication) — unlike
// /services, this path does not remote-fetch from shard holders.
export async function queryResults(checkId: string, sinceMs?: number, limit = 50): Promise<SignedResult[]> {
  const p = new URLSearchParams({ check_id: checkId, limit: String(limit) });
  if (sinceMs) p.set("since_ms", String(sinceMs));
  const res = await fetch(`/api/v1/results/query?${p.toString()}`);
  if (!res.ok) return [];
  return res.json();
}

// uptime fetches sample-weighted availability estimates (24h/7d/30d) for one
// check. Like the other read paths it never throws: on error (or a hub that
// doesn't hold the check) it returns an empty-windows report so callers render
// "n/a" rather than blowing up the card.
export async function uptime(checkId: string): Promise<UptimeReport> {
  try {
    const res = await fetch(`/api/v1/uptime?check_id=${encodeURIComponent(checkId)}`);
    if (!res.ok) return { check_id: checkId, windows: {} };
    return res.json();
  } catch {
    return { check_id: checkId, windows: {} };
  }
}

// LatencyPercentiles is one time-window's latency distribution (GET
// /api/v1/latency). p50/p95/p99/min/max are milliseconds or null; `available`
// is false when this hub doesn't hold the check or has no measured samples (then
// render "n/a"). `count` is the number of samples that fed the percentiles —
// note long windows are raw-limited (on Postgres the raw window is ~7d), so a
// 30d request's `count` reflects actual coverage, not a full 30 days.
export interface LatencyPercentiles {
  check_id: string;
  window: UptimeWindowKey;
  p50: number | null;
  p95: number | null;
  p99: number | null;
  min: number | null;
  max: number | null;
  count: number;
  available: boolean;
}

// latency fetches the latency percentile distribution for one check over one
// window. Like the other read paths it never throws: on error (or a hub that
// doesn't hold the check) it returns an unavailable shape so callers render
// "n/a" rather than blowing up the panel.
export async function latency(checkId: string, window: UptimeWindowKey = "24h"): Promise<LatencyPercentiles> {
  const unavailable = (): LatencyPercentiles => ({
    check_id: checkId,
    window,
    p50: null,
    p95: null,
    p99: null,
    min: null,
    max: null,
    count: 0,
    available: false,
  });
  try {
    const p = new URLSearchParams({ check_id: checkId, window });
    const res = await fetch(`/api/v1/latency?${p.toString()}`);
    if (!res.ok) return unavailable();
    return res.json();
  } catch {
    return unavailable();
  }
}

// IncidentWindowKey is the lookback the incident endpoint accepts.
export type IncidentWindowKey = "24h" | "7d" | "30d";

// Incident is one past outage window (GET /api/v1/incidents). Times are
// bucket-aligned to the report's `resolution` (hourly ≤14d, daily beyond), so
// `duration_ms` reflects covered buckets, not wall-clock to the second.
// `worst_status` is the most severe status seen across the incident's buckets.
// `ongoing` means the outage is still open (end_ms is "now").
export interface Incident {
  start_ms: number;
  end_ms: number;
  duration_ms: number;
  worst_status: string;
  bucket_count: number;
  resolution: string;
  ongoing: boolean;
}

// IncidentReport is the list of past outages for one check over a window,
// newest-first. `incidents` is empty when the check was all-up, had no data, or
// isn't held by this hub. `resolution` captions the bucket granularity.
export interface IncidentReport {
  check_id: string;
  window: IncidentWindowKey;
  resolution: string;
  incidents: Incident[];
}

// incidents fetches the outage timeline for one check. Like the other read
// paths it never throws: on error (or a hub that doesn't hold the check) it
// returns an empty-incidents report so callers render the empty state rather
// than blowing up the panel.
export async function incidents(checkId: string, window: IncidentWindowKey = "30d"): Promise<IncidentReport> {
  const empty = (): IncidentReport => ({ check_id: checkId, window, resolution: "", incidents: [] });
  try {
    const p = new URLSearchParams({ check_id: checkId, window });
    const res = await fetch(`/api/v1/incidents?${p.toString()}`);
    if (!res.ok) return empty();
    const v = await res.json();
    return { ...v, incidents: Array.isArray(v.incidents) ? v.incidents : [] };
  } catch {
    return empty();
  }
}

// listAlerts returns the owner's alert rules as the hub sees them (no plaintext
// destinations). Used to show propagation/recipient info and rules created on
// another device.
export async function listAlerts(owner: string): Promise<AlertRule[]> {
  const res = await fetch(`/api/v1/alerts?owner=${encodeURIComponent(owner)}`);
  if (!res.ok) return [];
  return res.json();
}

// createCheck registers (or dedups to) a shared check and returns its spec.
export async function createCheck(input: {
  type: string;
  target: string;
  interval_seconds: number;
  params?: Record<string, string>;
}): Promise<CreatedCheck> {
  const res = await fetch("/api/v1/checks", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(input),
  });
  if (!res.ok) throw new Error(`create check failed: ${res.status}`);
  return res.json();
}

// subscribe links the owner to a check so it appears on their dashboard.
export async function subscribe(id: Identity, checkId: string, intervalSeconds: number): Promise<void> {
  const payload = signSubscription(id, { checkId, intervalSeconds, expiryMs: expiryMs(), updatedMs: Date.now() });
  await postSigned("/api/v1/subscriptions", payload);
}

// unsubscribe sends a signed tombstone. It carries a fresh updatedMs (so it
// wins over the earlier create) and a bounded expiry (so hubs retain the
// tombstone long enough to reject replays of the old record, then prune it).
export async function unsubscribe(id: Identity, checkId: string): Promise<void> {
  const payload = signSubscription(id, {
    checkId,
    intervalSeconds: 0,
    expiryMs: expiryMs(),
    updatedMs: Date.now(),
    deleted: true,
  });
  await postSigned("/api/v1/subscriptions", payload);
}

export async function addAlert(id: Identity, input: Omit<AlertInput, "expiryMs" | "updatedMs">): Promise<void> {
  const hubs = await alertRecipientHubs();
  if (hubs.length === 0) throw new Error("no hub encryption keys available to secure the alert");
  const payload = signAlertRule(id, { ...input, expiryMs: expiryMs(), updatedMs: Date.now() }, hubs);
  await postSigned("/api/v1/alerts", payload);
  // Persist the alert inputs so the browser can renew the lease before expiry.
  // The destination is sealed on the wire and not retrievable from the hub, so
  // renewal needs the plaintext locally. This sits alongside the account seed in
  // localStorage (same XSS exposure already documented for the seed).
  saveStoredAlert({ ...input });
}

// --- Owner lease renewal (subscriptions + alerts) ---
//
// Subscriptions and alert rules carry a bounded expiry so abandoned ones fall
// out of the network. An active owner's browser must therefore re-sign them
// before they lapse. Without this, even live monitors silently expire (and, for
// records signed under an older canonical version before an upgrade, re-signing
// is what re-propagates them to peers running current code).

const RENEW_KEY = "libreping_last_renew";
const RENEW_EVERY_MS = 12 * 60 * 60 * 1000; // re-sign at most twice a day
const ALERTS_KEY = "libreping_alerts";

// StoredAlert is the locally-retained plaintext of an alert the owner created on
// this device. The destination is sealed on the wire and not retrievable from
// the hub, so the browser keeps it here to renew the lease and to re-sign a
// tombstone when deleting.
export type StoredAlert = Omit<AlertInput, "expiryMs" | "updatedMs">;

const alertKey = (x: StoredAlert) => `${x.checkId}|${x.channel}|${x.destination}`;

export function loadStoredAlerts(): StoredAlert[] {
  try {
    return JSON.parse(localStorage.getItem(ALERTS_KEY) || "[]");
  } catch {
    return [];
  }
}

function saveStoredAlert(a: StoredAlert) {
  const all = loadStoredAlerts().filter((x) => alertKey(x) !== alertKey(a));
  all.push(a);
  localStorage.setItem(ALERTS_KEY, JSON.stringify(all));
}

// forgetStoredAlerts drops every stored alert for a check (used when the whole
// monitor is removed).
export function forgetStoredAlerts(checkId: string) {
  const all = loadStoredAlerts().filter((x) => x.checkId !== checkId);
  localStorage.setItem(ALERTS_KEY, JSON.stringify(all));
}

// --- Local SLO targets (browser-only) ---
//
// A per-check SLO target is a user preference, not network state: it is never
// signed, gossiped, or sent to a hub. It lives only in this browser's
// localStorage (same model as the account seed and the stored alerts), so
// targets are per-device, not shared across a user's browsers. The error budget
// is derived at render time from the public /api/v1/uptime numbers, so there is
// nothing to persist beyond the target fraction itself.
const SLO_KEY = "libreping_slo";

// Targets are availability fractions strictly inside (0,1), e.g. 0.999 for
// three-nines. Stored as a { [checkId]: targetFraction } map.
type SLOMap = Record<string, number>;

function loadSLOMap(): SLOMap {
  try {
    const raw = JSON.parse(localStorage.getItem(SLO_KEY) || "{}");
    if (!raw || typeof raw !== "object") return {};
    const out: SLOMap = {};
    for (const [k, v] of Object.entries(raw)) {
      if (typeof v === "number" && v > 0 && v < 1) out[k] = v;
    }
    return out;
  } catch {
    return {};
  }
}

// getSLOTarget returns the saved target fraction for a check, or null if none is
// set (or the stored value is out of the (0,1) range).
export function getSLOTarget(checkId: string): number | null {
  const v = loadSLOMap()[checkId];
  return typeof v === "number" ? v : null;
}

// setSLOTarget saves (or, when passed null, clears) a check's target. A target
// outside (0,1) is treated as clearing it — 100% leaves no budget and 0% is
// meaningless.
export function setSLOTarget(checkId: string, target: number | null): void {
  const map = loadSLOMap();
  if (target === null || !(target > 0 && target < 1)) {
    delete map[checkId];
  } else {
    map[checkId] = target;
  }
  localStorage.setItem(SLO_KEY, JSON.stringify(map));
}

// deleteAlert removes one alert: it gossips a signed tombstone (deleted rule,
// recipients omitted — see identity.signAlertRule) so the network forgets it,
// then drops the local copy. Mirrors the unsubscribe tombstone pattern.
export async function deleteAlert(id: Identity, a: StoredAlert): Promise<void> {
  const hubs = await alertRecipientHubs();
  const payload = signAlertRule(id, { ...a, deleted: true, expiryMs: expiryMs(), updatedMs: Date.now() }, hubs);
  await postSigned("/api/v1/alerts", payload);
  const all = loadStoredAlerts().filter((x) => alertKey(x) !== alertKey(a));
  localStorage.setItem(ALERTS_KEY, JSON.stringify(all));
}

// --- Maintenance windows (owner-signed, gossiped) ---

// The bound placed on a window's ExpiryMS past its end, so hubs retain the
// record (and its tombstone) through the window and a grace period, then prune.
const MAINTENANCE_SLACK_MS = 7 * 24 * 60 * 60 * 1000;

// listMaintenance returns the owner's (and/or a check's) active maintenance
// windows as the hub sees them. Deleted/expired windows are not returned. Never
// throws: on error it resolves to an empty list.
export async function listMaintenance(filter: { checkId?: string; owner?: string }): Promise<MaintenanceWindow[]> {
  const p = new URLSearchParams();
  if (filter.checkId) p.set("check_id", filter.checkId);
  if (filter.owner) p.set("owner", filter.owner);
  try {
    const res = await fetch(`/api/v1/maintenance?${p.toString()}`);
    if (!res.ok) return [];
    const data = await res.json();
    return Array.isArray(data) ? data : [];
  } catch {
    return [];
  }
}

// scheduleMaintenance signs and posts a planned-downtime window for a check. The
// expiry is bounded to the window's end plus a grace slack so abandoned windows
// fall out of the network. Mirrors the subscribe pattern.
export async function scheduleMaintenance(id: Identity, input: { checkId: string; startMs: number; endMs: number; reason?: string }): Promise<void> {
  const payload = signMaintenanceWindow(id, {
    checkId: input.checkId,
    startMs: input.startMs,
    endMs: input.endMs,
    reason: input.reason,
    expiryMs: input.endMs + MAINTENANCE_SLACK_MS,
    updatedMs: Date.now(),
  });
  await postSigned("/api/v1/maintenance", payload);
}

// deleteMaintenance sends a signed tombstone (deleted window) with a fresh
// updatedMs so it wins over the earlier record, and a bounded expiry so hubs
// retain the tombstone to reject replays, then prune it. Mirrors unsubscribe.
export async function deleteMaintenance(id: Identity, w: MaintenanceWindow): Promise<void> {
  const payload = signMaintenanceWindow(id, {
    checkId: w.check_id,
    startMs: w.start_ms,
    endMs: w.end_ms,
    reason: w.reason,
    expiryMs: expiryMs(),
    updatedMs: Date.now(),
    deleted: true,
  });
  await postSigned("/api/v1/maintenance", payload);
}

// renewLeases re-signs the owner's current subscriptions and stored alerts with
// a fresh expiry, throttled so it runs at most twice a day. Best-effort: a
// failure (e.g. a hub briefly down) just retries on the next call.
export async function renewLeases(id: Identity, checkIds: string[], intervalByCheck: Record<string, number>): Promise<void> {
  const last = Number(localStorage.getItem(RENEW_KEY) || 0);
  if (Date.now() - last < RENEW_EVERY_MS) return;
  localStorage.setItem(RENEW_KEY, String(Date.now()));
  for (const checkId of checkIds) {
    try {
      await subscribe(id, checkId, intervalByCheck[checkId] || 60);
    } catch {
      /* retry next cycle */
    }
  }
  for (const a of loadStoredAlerts()) {
    try {
      await addAlert(id, a);
    } catch {
      /* retry next cycle */
    }
  }
}

// alertRecipientHubs gathers candidate hubs (the local hub + the peer directory)
// with their X25519 keys, so the destination can be sealed to the responsible ones.
async function alertRecipientHubs(): Promise<HubKey[]> {
  const out: HubKey[] = [];
  const seen = new Set<string>();
  try {
    const self = await (await fetch("/api/v1/identity")).json();
    if (self.hub_id && self.enc_pubkey) {
      out.push({ hubId: self.hub_id, encPubKey: self.enc_pubkey });
      seen.add(self.hub_id);
    }
  } catch {
    /* ignore */
  }
  try {
    const peers = await (await fetch("/api/v1/hubs")).json();
    for (const h of peers as Array<{ hub_id: string; enc_pubkey?: string }>) {
      if (h.enc_pubkey && !seen.has(h.hub_id)) {
        out.push({ hubId: h.hub_id, encPubKey: h.enc_pubkey });
        seen.add(h.hub_id);
      }
    }
  } catch {
    /* ignore */
  }
  return out;
}

// --- Network topology (the "network" showcase map) ---

interface GeoLoc {
  country: string;
  city: string;
  lat: number;
  lon: number;
}
export interface HubNode {
  hub_id: string;
  name?: string;
  public_url?: string;
  location: GeoLoc;
  self?: boolean;
}
export interface ProbeNode {
  probe_id: string;
  location: GeoLoc;
  hub_id: string; // the hub this probe is talking to ("" for gossip-only probes)
  last_seen_ms: number;
  via_gossip?: boolean; // known only from the result stream; its hub isn't in the directory
}
export interface NetworkView {
  hubs: HubNode[];
  probes: ProbeNode[];
}

export async function fetchNetwork(): Promise<NetworkView> {
  try {
    const res = await fetch("/api/v1/network");
    if (!res.ok) return { hubs: [], probes: [] };
    const v = await res.json();
    return { hubs: Array.isArray(v.hubs) ? v.hubs : [], probes: Array.isArray(v.probes) ? v.probes : [] };
  } catch {
    return { hubs: [], probes: [] };
  }
}

export async function listServices(owner: string): Promise<Service[]> {
  const res = await fetch(`/api/v1/services?owner=${encodeURIComponent(owner)}`);
  if (!res.ok) return [];
  const data = await res.json();
  if (!Array.isArray(data)) return [];
  // A freshly-added monitor has no results yet; never let a null `locations`
  // (or list) reach the components, which iterate it unconditionally.
  return data.map((s: Service) => ({ ...s, locations: Array.isArray(s.locations) ? s.locations : [] }));
}

async function postSigned(path: string, payload: unknown): Promise<void> {
  const res = await fetch(path, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(payload),
  });
  if (!res.ok) throw new Error(`${path} failed: ${res.status} ${await res.text()}`);
}
