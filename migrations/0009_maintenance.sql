-- Maintenance windows (gossiped, owner-signed): planned downtime for a check.
-- While a window is active, alerts for the check are suppressed and the window
-- is excluded from the check's uptime percentage. Because any hub may be the one
-- responsible for a check's alerts and every hub computes uptime, windows must be
-- known network-wide, so they gossip and tombstone exactly like subscriptions.
-- Keyed by (owner, check_id, start_ms): one window per owner+check+start, so a
-- user can schedule several distinct windows for the same check.
CREATE TABLE IF NOT EXISTS maintenance (
    owner      TEXT   NOT NULL,
    check_id   TEXT   NOT NULL,
    start_ms   BIGINT NOT NULL,
    end_ms     BIGINT NOT NULL,
    reason     TEXT   NOT NULL DEFAULT '',
    expiry_ms  BIGINT NOT NULL DEFAULT 0,  -- 0 = no expiry
    updated_ms BIGINT NOT NULL DEFAULT 0,  -- signed, monotonic version stamp (anti-replay)
    deleted    BOOLEAN NOT NULL DEFAULT false,  -- retained signed tombstone
    pubkey     BYTEA  NOT NULL,
    signature  BYTEA  NOT NULL,
    PRIMARY KEY (owner, check_id, start_ms)
);

CREATE INDEX IF NOT EXISTS maintenance_check_idx ON maintenance (check_id);
