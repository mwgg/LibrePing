-- Bound the effective lifetime of owner-signed subscriptions and alert rules.
--
-- A record with expiry_ms = 0 ("forever") or a far-future expiry was stored and
-- re-gossiped by every hub forever, so a Sybil key could pin unbounded rows on
-- the fully-replicated control plane. We now track received_ms (this hub's clock
-- when the record was last accepted) and prune at
-- received_ms + maxOwnerRecordTTL, without touching the signed bytes.
--
-- Legacy rows keep received_ms = 0, which the store treats as "no internal cap"
-- (only the signed expiry applies) so an in-place upgrade doesn't suddenly drop
-- existing records; they gain a real received_ms the next time the owner's
-- dashboard re-signs and re-upserts them.
ALTER TABLE subscriptions ADD COLUMN IF NOT EXISTS received_ms BIGINT NOT NULL DEFAULT 0;
ALTER TABLE alerts        ADD COLUMN IF NOT EXISTS received_ms BIGINT NOT NULL DEFAULT 0;
