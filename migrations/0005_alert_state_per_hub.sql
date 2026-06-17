-- Delivery state was keyed by rule_id alone (last-writer-wins across all hubs),
-- which let any hub's claim overwrite another's — including a non-recipient
-- writing a far-future timestamp that the real responsible hub could then never
-- correct, causing repeated alerts. Re-key it by (rule_id, by_hub) so each
-- hub's own claim is stored separately. Ingest now also rejects delivery state
-- from hubs that are not recipients of the rule, so only legitimate claims land
-- here. The newest claim per rule is read back with ORDER BY ts_ms DESC.
ALTER TABLE alert_state DROP CONSTRAINT IF EXISTS alert_state_pkey;
ALTER TABLE alert_state ALTER COLUMN by_hub DROP DEFAULT;

-- Collapse any pre-existing rows that share a rule_id so the new composite key
-- can be added (keep the newest per (rule_id, by_hub)).
DELETE FROM alert_state a USING alert_state b
  WHERE a.rule_id = b.rule_id AND a.by_hub = b.by_hub AND a.ts_ms < b.ts_ms;

ALTER TABLE alert_state ADD PRIMARY KEY (rule_id, by_hub);
