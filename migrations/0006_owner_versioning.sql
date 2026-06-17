-- Owner-signed subscriptions and alert rules gained a signed, monotonic
-- updated_ms version stamp and a retained `deleted` tombstone flag. Previously a
-- delete erased the row, so any peer could replay the old signed active record
-- and resurrect it. Now Upsert accepts a record only if updated_ms is strictly
-- newer, and a delete is stored as a tombstone (deleted = true) until it
-- expires, so the stale replay is rejected. Anti-entropy gossips tombstones too,
-- so deletes propagate network-wide.
--
-- Upgrade note: rows that existed before this migration get updated_ms = 0 and
-- keep signatures made over the OLDER canonical format, so peers running current
-- code (which verify the v2/v3 canonical strings) will not accept them over
-- gossip. They still work locally, and the dashboard re-signs an owner's
-- subscriptions/alerts under the current format on a throttled lease-renewal
-- pass (web: renewLeases) — which is what re-propagates them network-wide and
-- keeps still-wanted records from expiring. Records whose owner never returns
-- simply lapse, as intended.
ALTER TABLE subscriptions ADD COLUMN IF NOT EXISTS updated_ms BIGINT NOT NULL DEFAULT 0;
ALTER TABLE subscriptions ADD COLUMN IF NOT EXISTS deleted    BOOLEAN NOT NULL DEFAULT false;

ALTER TABLE alerts ADD COLUMN IF NOT EXISTS updated_ms BIGINT NOT NULL DEFAULT 0;
ALTER TABLE alerts ADD COLUMN IF NOT EXISTS deleted    BOOLEAN NOT NULL DEFAULT false;
