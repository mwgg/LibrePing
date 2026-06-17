-- Subscriptions: which owner (a browser-held key) wants to watch which check.
-- Many owners may subscribe to the same content-addressed check; the check is
-- still monitored once. Keyed by (owner, check_id).
CREATE TABLE IF NOT EXISTS subscriptions (
    owner            TEXT   NOT NULL,
    check_id         TEXT   NOT NULL,
    interval_seconds INT    NOT NULL DEFAULT 60,
    expiry_ms        BIGINT NOT NULL DEFAULT 0,  -- 0 = no expiry
    pubkey           BYTEA  NOT NULL,
    signature        BYTEA  NOT NULL,
    PRIMARY KEY (owner, check_id)
);

CREATE INDEX IF NOT EXISTS subscriptions_check_idx ON subscriptions (check_id);
