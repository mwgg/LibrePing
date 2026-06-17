import { useCallback, useEffect, useState } from "react";
import { Identity, alertDestHash } from "./identity";
import { AlertRule, Service, StoredAlert, deleteAlert, listAlerts, loadStoredAlerts } from "./api";

// Alerts lists the owner's alert rules and lets them be deleted.
//
// Two sources are reconciled: the locally-stored plaintext alerts (which carry
// the destination, so they can be re-signed into a tombstone and deleted here)
// and the hub's view (GET /api/v1/alerts), whose destinations are sealed. A rule
// the hub knows but this browser doesn't (created on another device) is shown
// read-only — without the plaintext destination it can't be re-signed here.
export default function Alerts({
  id,
  owner,
  services,
  checkId,
  onChange,
}: {
  id: Identity;
  owner: string;
  services: Service[];
  checkId?: string;
  onChange?: () => void;
}) {
  const [stored, setStored] = useState<StoredAlert[]>([]);
  const [server, setServer] = useState<AlertRule[]>([]);
  const [loading, setLoading] = useState(true);
  const [busyKey, setBusyKey] = useState<string | null>(null);

  const refresh = useCallback(async () => {
    let local = loadStoredAlerts();
    if (checkId) local = local.filter((a) => a.checkId === checkId);
    setStored(local);
    const rules = (await listAlerts(owner)).filter((r) => !r.deleted && (!checkId || r.check_id === checkId));
    setServer(rules);
    setLoading(false);
  }, [owner, checkId]);

  useEffect(() => {
    refresh();
  }, [refresh]);

  const targetFor = (cid: string) => services.find((s) => s.check_id === cid)?.target || cid;

  async function remove(a: StoredAlert) {
    const key = `${a.checkId}|${a.channel}|${a.destination}`;
    setBusyKey(key);
    try {
      await deleteAlert(id, a);
      await refresh();
      onChange?.();
    } finally {
      setBusyKey(null);
    }
  }

  // Server rules that have no local plaintext counterpart (by owner+dest_hash).
  const localHashes = new Set(stored.map((a) => alertDestHash(owner, a.destination) + "|" + a.checkId + "|" + a.channel));
  const foreign = server.filter((r) => !localHashes.has(r.dest_hash + "|" + r.check_id + "|" + r.channel));

  if (loading) {
    return (
      <div className="loading-line">
        <span className="spinner" /> Loading alerts…
      </div>
    );
  }

  if (stored.length === 0 && foreign.length === 0) {
    return (
      <p className="muted note">
        No alert rules{checkId ? " for this monitor" : ""} yet. Add one from a monitor to be notified when it goes down.
      </p>
    );
  }

  return (
    <div className="alert-list">
      {stored.map((a) => {
        const key = `${a.checkId}|${a.channel}|${a.destination}`;
        const rule = server.find(
          (r) => r.dest_hash === alertDestHash(owner, a.destination) && r.check_id === a.checkId && r.channel === a.channel,
        );
        const recipients = rule ? Object.keys(rule.recipients).length : 0;
        return (
          <div className="alert-item" key={key}>
            <span className="chan-tag">{a.channel}</span>
            <div className="alert-main">
              <span className="alert-dest">{a.destination}</span>
              <span className="alert-meta">
                {!checkId && <>{targetFor(a.checkId)} · </>}
                triggers after {a.failLocations} probes down for {a.forSeconds}s
                {rule ? ` · sealed to ${recipients} hub${recipients === 1 ? "" : "s"}` : " · not yet propagated"}
              </span>
            </div>
            <button className="btn btn-sm btn-danger" disabled={busyKey === key} onClick={() => remove(a)}>
              {busyKey === key ? "Removing…" : "Delete"}
            </button>
          </div>
        );
      })}

      {foreign.map((r) => (
        <div className="alert-item" key={r.dest_hash + r.check_id + r.channel}>
          <span className="chan-tag">{r.channel}</span>
          <div className="alert-main">
            <span className="alert-dest mono muted">sealed · {r.dest_hash.slice(0, 12)}…</span>
            <span className="alert-meta">
              {!checkId && <>{targetFor(r.check_id)} · </>}
              managed on another device · sealed to {Object.keys(r.recipients).length} hubs
            </span>
          </div>
          <button className="btn btn-sm" disabled title="Delete from the device that created it">
            Delete
          </button>
        </div>
      ))}
    </div>
  );
}
