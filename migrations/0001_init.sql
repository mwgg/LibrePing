-- LibrePing hub schema. Migrations are applied in lexical order on startup and
-- must be idempotent (IF NOT EXISTS), so re-running is always safe.

-- TimescaleDB powers time-series storage. The extension ships in the
-- timescale/timescaledb image; CREATE EXTENSION is a no-op if already present.
CREATE EXTENSION IF NOT EXISTS timescaledb;

CREATE TABLE IF NOT EXISTS results (
    probe_id      TEXT             NOT NULL,
    check_id      TEXT             NOT NULL,
    check_type    TEXT             NOT NULL,
    target        TEXT             NOT NULL,
    country       TEXT             NOT NULL DEFAULT '',
    city          TEXT             NOT NULL DEFAULT '',
    lat           DOUBLE PRECISION NOT NULL DEFAULT 0,
    lon           DOUBLE PRECISION NOT NULL DEFAULT 0,
    timestamp_ms  BIGINT           NOT NULL,
    status        TEXT             NOT NULL,
    rtt_ms        DOUBLE PRECISION NOT NULL DEFAULT 0,
    detail        JSONB,
    pubkey        BYTEA            NOT NULL,
    signature     BYTEA            NOT NULL,
    -- A signed measurement is uniquely identified by who produced it, which
    -- check it answers, and when. This makes gossip re-delivery idempotent.
    PRIMARY KEY (probe_id, check_id, timestamp_ms)
);

-- Convert to a hypertable partitioned on time. Guarded so re-running is safe.
SELECT create_hypertable(
    'results',
    by_range('timestamp_ms', 86400000::BIGINT),  -- 1-day chunks (ms)
    if_not_exists => TRUE
);

CREATE INDEX IF NOT EXISTS results_target_idx ON results (target, timestamp_ms DESC);
CREATE INDEX IF NOT EXISTS results_probe_idx ON results (probe_id, timestamp_ms DESC);
