import { useState } from "react";
import { Identity, AlertChannel } from "./identity";
import { addAlert } from "./api";

// CHANNELS are all plain HTTPS pushes to an owner-supplied destination — no hub
// operator config needed (the old SMTP email channel is gone).
const CHANNELS: { value: AlertChannel; label: string; placeholder: string; hint: string }[] = [
  {
    value: "ntfy",
    label: "ntfy",
    placeholder: "https://ntfy.sh/your-topic",
    hint: "Free push to phone/desktop — pick any topic on ntfy.sh (or your own server).",
  },
  {
    value: "discord",
    label: "Discord",
    placeholder: "https://discord.com/api/webhooks/…",
    hint: "A Discord channel webhook URL (Channel → Integrations → Webhooks).",
  },
  {
    value: "slack",
    label: "Slack",
    placeholder: "https://hooks.slack.com/services/…",
    hint: "A Slack incoming-webhook URL.",
  },
  {
    value: "webhook",
    label: "Webhook (raw JSON)",
    placeholder: "https://your-endpoint.example/hook",
    hint: "Receives the full LibrePing JSON payload (check_id, target, status, locations, at_ms).",
  },
];

// AlertForm creates owner-signed alert rules. The destination is sealed
// client-side (identity.signAlertRule) so only the responsible hubs can read it.
// It applies to every check in `checkIds`, so the same form serves a single
// monitor (CheckDetail) and a bulk "add to all monitors" action (Services).
export default function AlertForm({ id, checkIds, onDone }: { id: Identity; checkIds: string[]; onDone: () => void }) {
  const [channel, setChannel] = useState<AlertChannel>("ntfy");
  const [destination, setDestination] = useState("");
  const [failLocations, setFailLocations] = useState(2);
  const [forSeconds, setForSeconds] = useState(120);
  const [progress, setProgress] = useState<string | null>(null);
  const [err, setErr] = useState("");
  const spec = CHANNELS.find((c) => c.value === channel)!;
  const bulk = checkIds.length > 1;

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    if (!destination.trim() || progress) return;
    setErr("");
    try {
      let done = 0;
      for (const checkId of checkIds) {
        setProgress(bulk ? `Adding… ${done + 1}/${checkIds.length}` : "Saving…");
        await addAlert(id, { checkId, channel, destination: destination.trim(), failLocations, forSeconds });
        done++;
      }
      setDestination("");
      onDone();
    } catch (e) {
      setErr(String(e));
    } finally {
      setProgress(null);
    }
  }

  return (
    <form className="alert-form" onSubmit={submit}>
      <select value={channel} onChange={(e) => setChannel(e.target.value as AlertChannel)}>
        {CHANNELS.map((c) => (
          <option key={c.value} value={c.value}>
            {c.label}
          </option>
        ))}
      </select>
      <input value={destination} placeholder={spec.placeholder} onChange={(e) => setDestination(e.target.value)} />
      <label className="alert-num">
        after{" "}
        <input
          type="number"
          min={1}
          value={failLocations}
          onChange={(e) => setFailLocations(Math.max(1, Number(e.target.value) || 1))}
        />{" "}
        locations down for{" "}
        <input
          type="number"
          min={0}
          step={30}
          value={forSeconds}
          onChange={(e) => setForSeconds(Math.max(0, Number(e.target.value) || 0))}
        />
        s
      </label>
      <button className="btn btn-primary" type="submit" disabled={!!progress}>
        {progress ?? (bulk ? `Add to ${checkIds.length} monitors` : "Save alert")}
      </button>
      {err && (
        <div className="err" style={{ flexBasis: "100%" }}>
          {err}
        </div>
      )}
      <span className="muted note" style={{ flexBasis: "100%" }}>
        {spec.hint} Your destination is encrypted and readable only by the few hubs that notify you — not by the rest of
        the network.
      </span>
    </form>
  );
}
