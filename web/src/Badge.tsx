import { STATUS_LABEL, statusColor } from "./theme";

// StatusBadge renders a pill with a status dot and human label, using the shared
// status palette.
export default function StatusBadge({ status }: { status: string }) {
  const cls =
    status === "up"
      ? "badge-up"
      : status === "down"
        ? "badge-down"
        : status === "degraded"
          ? "badge-degraded"
          : "badge-unknown";
  return (
    <span className={`badge ${cls}`}>
      <span className="dot" style={{ background: statusColor(status) }} />
      {STATUS_LABEL[status] ?? status}
    </span>
  );
}
