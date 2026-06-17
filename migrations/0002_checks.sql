-- The check catalog: monitor definitions that propagate across the whole
-- network via gossip. Keyed by the content-derived check_id so the same monitor
-- created on different hubs converges to one row.
CREATE TABLE IF NOT EXISTS checks (
    check_id         TEXT   NOT NULL PRIMARY KEY,
    check_type       TEXT   NOT NULL,
    target           TEXT   NOT NULL,
    interval_seconds INT    NOT NULL DEFAULT 60,
    params           JSONB,
    hub_id           TEXT   NOT NULL,   -- hub that signed this entry
    pubkey           BYTEA  NOT NULL,
    signature        BYTEA  NOT NULL
);
