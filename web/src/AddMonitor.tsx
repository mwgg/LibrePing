import { useState } from "react";
import { Identity } from "./identity";
import { createCheck, subscribe } from "./api";

const TYPES = [
  { v: "http", label: "Website / HTTP", placeholder: "https://example.com" },
  { v: "tcp", label: "TCP port", placeholder: "example.com:443" },
  { v: "dns", label: "DNS", placeholder: "example.com" },
  { v: "tls", label: "TLS certificate", placeholder: "example.com:443" },
  { v: "icmp", label: "Ping (ICMP)", placeholder: "example.com" },
  { v: "traceroute", label: "Traceroute", placeholder: "example.com" },
];

// AddMonitor: the no-jargon "watch something" form. Creates (or dedups to) a
// shared check and subscribes this browser's owner key to it.
export default function AddMonitor({ id, onAdded }: { id: Identity; onAdded: () => void }) {
  const [type, setType] = useState("http");
  const [target, setTarget] = useState("");
  const [interval, setInterval] = useState(60);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState("");

  const placeholder = TYPES.find((t) => t.v === type)?.placeholder ?? "";

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    if (!target.trim()) return;
    setBusy(true);
    setErr("");
    try {
      const check = await createCheck({ type, target: target.trim(), interval_seconds: interval });
      await subscribe(id, check.id, interval);
      setTarget("");
      onAdded();
    } catch (e) {
      setErr(String(e));
    } finally {
      setBusy(false);
    }
  }

  return (
    <form className="add-monitor" onSubmit={submit}>
      <select value={type} onChange={(e) => setType(e.target.value)}>
        {TYPES.map((t) => (
          <option key={t.v} value={t.v}>
            {t.label}
          </option>
        ))}
      </select>
      <input
        value={target}
        placeholder={placeholder}
        onChange={(e) => setTarget(e.target.value)}
        aria-label="target"
      />
      <select value={interval} onChange={(e) => setInterval(Number(e.target.value))} aria-label="interval">
        <option value={30}>every 30s</option>
        <option value={60}>every 1m</option>
        <option value={300}>every 5m</option>
      </select>
      <button className="btn btn-primary" type="submit" disabled={busy}>
        {busy ? "Adding…" : "Monitor it"}
      </button>
      {err && <div className="err">{err}</div>}
    </form>
  );
}
