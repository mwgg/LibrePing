// Thin client for the hub JSON API. Reads are public; writes carry an
// owner-signed payload built in identity.ts.
import { Identity, signSubscription, signAlertRule, AlertInput, AlertChannel, HubKey } from "./identity";

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
