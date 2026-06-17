-- Indexes so holder queries filter by check or shard BEFORE applying a row
-- limit. Without these, /api/v1/results/query selected the newest N rows
-- globally and filtered in memory, so a busy network could push a requested
-- check's older rows out of the window — silently incomplete reads and backfill.

-- result_shard mirrors hub/shard.Of exactly: the first 4 hex chars of check_id
-- as a 16-bit integer, mod the network-wide shard count (64; see
-- hub/shard.Count). Check IDs are 16 hex chars (CheckSpec.DeriveID), so this
-- matches Go for every real id. A short/non-hex id (never a real catalog id, and
-- never queried by shard) falls back to 0 so the function is total and indexing
-- can never fail. IMMUTABLE + PARALLEL SAFE so it can back an expression index.
CREATE OR REPLACE FUNCTION result_shard(cid TEXT) RETURNS INT
    LANGUAGE sql IMMUTABLE PARALLEL SAFE AS $$
    SELECT CASE
        WHEN cid ~ '^[0-9a-fA-F]{4}'
        THEN (('x' || substr(cid, 1, 4))::bit(16)::int) % 64
        ELSE 0
    END
$$;

-- Per-check reads (dashboard on-demand): RecentSinceCheck.
CREATE INDEX IF NOT EXISTS results_check_idx ON results (check_id, timestamp_ms DESC);

-- Per-shard reads (backfill/repair): RecentSinceShard. Expression index on the
-- same function the query filters by, so the shard predicate is index-backed.
CREATE INDEX IF NOT EXISTS results_shard_idx ON results (result_shard(check_id), timestamp_ms DESC);
