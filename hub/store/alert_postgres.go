package store

import (
	"context"
	"encoding/json"
	"errors"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/mwgg/libreping/pkg/protocol"
)

// PgAlerts is a Postgres-backed AlertStore.
type PgAlerts struct {
	pool *pgxpool.Pool
}

func NewPgAlerts(s *PgStore) *PgAlerts { return &PgAlerts{pool: s.pool} }

// Upsert applies sa only if its UpdatedMS is strictly newer than the stored
// rule's, keeping tombstones rather than deleting so a replayed old rule can't
// resurrect a deleted alert.
func (p *PgAlerts) Upsert(ctx context.Context, sa protocol.SignedAlertRule) error {
	r := sa.Rule
	id := r.ID()
	recipients, err := json.Marshal(r.Recipients)
	if err != nil {
		return err
	}
	const q = `
INSERT INTO alerts (rule_id, owner, check_id, channel, dest_hash, recipients, fail_locations, for_seconds, expiry_ms, updated_ms, deleted, pubkey, signature)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)
ON CONFLICT (rule_id) DO UPDATE SET
  dest_hash = EXCLUDED.dest_hash,
  recipients = EXCLUDED.recipients,
  fail_locations = EXCLUDED.fail_locations,
  for_seconds = EXCLUDED.for_seconds,
  expiry_ms = EXCLUDED.expiry_ms,
  updated_ms = EXCLUDED.updated_ms,
  deleted = EXCLUDED.deleted,
  pubkey = EXCLUDED.pubkey,
  signature = EXCLUDED.signature
  WHERE EXCLUDED.updated_ms > alerts.updated_ms`
	if _, err = p.pool.Exec(ctx, q, id, r.Owner, r.CheckID, string(r.Channel), r.DestHash, recipients,
		r.FailLocations, r.ForSeconds, r.ExpiryMS, r.UpdatedMS, r.Deleted, []byte(sa.PubKey), sa.Signature); err != nil {
		return err
	}
	if r.Deleted {
		_, _ = p.pool.Exec(ctx, `DELETE FROM alert_state WHERE rule_id=$1`, id)
	}
	return nil
}

func (p *PgAlerts) ListActive(ctx context.Context) ([]protocol.SignedAlertRule, error) {
	return p.listRules(ctx, false)
}

func (p *PgAlerts) ListForGossip(ctx context.Context) ([]protocol.SignedAlertRule, error) {
	return p.listRules(ctx, true)
}

func (p *PgAlerts) listRules(ctx context.Context, includeTombstones bool) ([]protocol.SignedAlertRule, error) {
	q := `
SELECT owner, check_id, channel, dest_hash, recipients, fail_locations, for_seconds, expiry_ms, updated_ms, deleted, pubkey, signature
FROM alerts WHERE (expiry_ms = 0 OR expiry_ms > $1)`
	if !includeTombstones {
		q += ` AND deleted = false`
	}
	rows, err := p.pool.Query(ctx, q, nowMS())
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []protocol.SignedAlertRule
	for rows.Next() {
		var sa protocol.SignedAlertRule
		var channel string
		var recipients []byte
		var pubkey []byte
		if err := rows.Scan(&sa.Rule.Owner, &sa.Rule.CheckID, &channel, &sa.Rule.DestHash, &recipients,
			&sa.Rule.FailLocations, &sa.Rule.ForSeconds, &sa.Rule.ExpiryMS, &sa.Rule.UpdatedMS, &sa.Rule.Deleted,
			&pubkey, &sa.Signature); err != nil {
			return nil, err
		}
		sa.Rule.Channel = protocol.AlertChannel(channel)
		_ = json.Unmarshal(recipients, &sa.Rule.Recipients)
		sa.PubKey = pubkey
		out = append(out, sa)
	}
	return out, rows.Err()
}

// GetRule returns a single rule by ID.
func (p *PgAlerts) GetRule(ctx context.Context, ruleID string) (protocol.SignedAlertRule, bool, error) {
	const q = `
SELECT owner, check_id, channel, dest_hash, recipients, fail_locations, for_seconds, expiry_ms, pubkey, signature
FROM alerts WHERE rule_id=$1`
	var sa protocol.SignedAlertRule
	var channel string
	var recipients, pubkey []byte
	err := p.pool.QueryRow(ctx, q, ruleID).Scan(&sa.Rule.Owner, &sa.Rule.CheckID, &channel, &sa.Rule.DestHash,
		&recipients, &sa.Rule.FailLocations, &sa.Rule.ForSeconds, &sa.Rule.ExpiryMS, &pubkey, &sa.Signature)
	if errors.Is(err, pgx.ErrNoRows) {
		return protocol.SignedAlertRule{}, false, nil
	}
	if err != nil {
		return protocol.SignedAlertRule{}, false, err
	}
	sa.Rule.Channel = protocol.AlertChannel(channel)
	_ = json.Unmarshal(recipients, &sa.Rule.Recipients)
	sa.PubKey = pubkey
	return sa, true, nil
}

// GetDelivery returns the newest delivery state for ruleID across all hubs.
func (p *PgAlerts) GetDelivery(ctx context.Context, ruleID string) (Delivery, bool, error) {
	var d Delivery
	var status string
	err := p.pool.QueryRow(ctx,
		`SELECT last_status, by_hub, ts_ms FROM alert_state WHERE rule_id=$1 ORDER BY ts_ms DESC LIMIT 1`, ruleID,
	).Scan(&status, &d.HubID, &d.TimestampMS)
	if errors.Is(err, pgx.ErrNoRows) {
		return Delivery{}, false, nil
	}
	if err != nil {
		return Delivery{}, false, err
	}
	d.Status = protocol.Status(status)
	return d, true, nil
}

// GetDeliveryBy returns the state ruleID was last given by hubID.
func (p *PgAlerts) GetDeliveryBy(ctx context.Context, ruleID, hubID string) (Delivery, bool, error) {
	var d Delivery
	var status string
	d.HubID = hubID
	err := p.pool.QueryRow(ctx,
		`SELECT last_status, ts_ms FROM alert_state WHERE rule_id=$1 AND by_hub=$2`, ruleID, hubID,
	).Scan(&status, &d.TimestampMS)
	if errors.Is(err, pgx.ErrNoRows) {
		return Delivery{}, false, nil
	}
	if err != nil {
		return Delivery{}, false, err
	}
	d.Status = protocol.Status(status)
	return d, true, nil
}

// MergeDelivery applies d only if newer than this hub's prior state for the
// rule (per-(rule_id, by_hub) last-writer-wins), atomically.
func (p *PgAlerts) MergeDelivery(ctx context.Context, ruleID string, d Delivery) (bool, error) {
	const q = `
INSERT INTO alert_state (rule_id, by_hub, last_status, ts_ms) VALUES ($1,$2,$3,$4)
ON CONFLICT (rule_id, by_hub) DO UPDATE SET
  last_status = EXCLUDED.last_status, ts_ms = EXCLUDED.ts_ms
  WHERE EXCLUDED.ts_ms > alert_state.ts_ms`
	tag, err := p.pool.Exec(ctx, q, ruleID, d.HubID, string(d.Status), d.TimestampMS)
	if err != nil {
		return false, err
	}
	return tag.RowsAffected() > 0, nil
}
