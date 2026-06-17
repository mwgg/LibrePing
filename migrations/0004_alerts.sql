-- Alert rules (gossiped, owner-signed) and per-rule firing state. A hub stores
-- every rule it learns, but only fires for rules it is the rendezvous-hash
-- responsible hub for. alert_state lets a hub fire only on status transitions
-- and survive restarts without re-alerting.
CREATE TABLE IF NOT EXISTS alerts (
    rule_id        TEXT   NOT NULL PRIMARY KEY,
    owner          TEXT   NOT NULL,
    check_id       TEXT   NOT NULL,
    channel        TEXT   NOT NULL,
    dest_hash      TEXT   NOT NULL,   -- stable fingerprint; destination itself is sealed
    recipients     JSONB  NOT NULL,   -- hubID -> base64 sealed destination
    fail_locations INT    NOT NULL DEFAULT 2,
    for_seconds    INT    NOT NULL DEFAULT 120,
    expiry_ms      BIGINT NOT NULL DEFAULT 0,
    pubkey         BYTEA  NOT NULL,
    signature      BYTEA  NOT NULL
);

CREATE INDEX IF NOT EXISTS alerts_check_idx ON alerts (check_id);

-- Delivery state per rule: the last status actually delivered, by which hub,
-- and when. Merged last-writer-wins across hubs (via gossip) so failover hands
-- off without duplicate notifications.
CREATE TABLE IF NOT EXISTS alert_state (
    rule_id     TEXT   NOT NULL PRIMARY KEY,
    last_status TEXT   NOT NULL,
    by_hub      TEXT   NOT NULL DEFAULT '',
    ts_ms       BIGINT NOT NULL DEFAULT 0
);
