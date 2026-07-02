package store

import (
	"context"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/mwgg/libreping/pkg/protocol"
)

// PgMaintenance is a Postgres-backed MaintenanceStore.
type PgMaintenance struct {
	pool *pgxpool.Pool
}

func NewPgMaintenance(s *PgStore) *PgMaintenance { return &PgMaintenance{pool: s.pool} }

// Upsert applies sm only if its UpdatedMS is strictly newer than the stored
// record's (WHERE clause), keeping tombstones rather than deleting so a replayed
// old record can't resurrect a deleted window.
func (p *PgMaintenance) Upsert(ctx context.Context, sm protocol.SignedMaintenanceWindow) error {
	m := sm.Window
	const q = `
INSERT INTO maintenance (owner, check_id, start_ms, end_ms, reason, expiry_ms, updated_ms, deleted, pubkey, signature)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)
ON CONFLICT (owner, check_id, start_ms) DO UPDATE SET
  end_ms = EXCLUDED.end_ms,
  reason = EXCLUDED.reason,
  expiry_ms = EXCLUDED.expiry_ms,
  updated_ms = EXCLUDED.updated_ms,
  deleted = EXCLUDED.deleted,
  pubkey = EXCLUDED.pubkey,
  signature = EXCLUDED.signature
  WHERE EXCLUDED.updated_ms > maintenance.updated_ms`
	_, err := p.pool.Exec(ctx, q, m.Owner, m.CheckID, m.StartMS, m.EndMS, m.Reason, m.ExpiryMS, m.UpdatedMS, m.Deleted, []byte(sm.PubKey), sm.Signature)
	return err
}

func (p *PgMaintenance) ListActive(ctx context.Context) ([]protocol.SignedMaintenanceWindow, error) {
	return p.list(ctx, false)
}

func (p *PgMaintenance) ListForGossip(ctx context.Context) ([]protocol.SignedMaintenanceWindow, error) {
	return p.list(ctx, true)
}

func (p *PgMaintenance) list(ctx context.Context, includeTombstones bool) ([]protocol.SignedMaintenanceWindow, error) {
	q := `
SELECT owner, check_id, start_ms, end_ms, reason, expiry_ms, updated_ms, deleted, pubkey, signature
FROM maintenance WHERE (expiry_ms = 0 OR expiry_ms > $1)`
	if !includeTombstones {
		q += ` AND deleted = false`
	}
	rows, err := p.pool.Query(ctx, q, nowMS())
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []protocol.SignedMaintenanceWindow
	for rows.Next() {
		var sm protocol.SignedMaintenanceWindow
		var pubkey []byte
		if err := rows.Scan(&sm.Window.Owner, &sm.Window.CheckID, &sm.Window.StartMS,
			&sm.Window.EndMS, &sm.Window.Reason, &sm.Window.ExpiryMS, &sm.Window.UpdatedMS,
			&sm.Window.Deleted, &pubkey, &sm.Signature); err != nil {
			return nil, err
		}
		sm.PubKey = pubkey
		out = append(out, sm)
	}
	return out, rows.Err()
}

func (p *PgMaintenance) IntervalsForCheck(ctx context.Context, checkID string) ([]MaintenanceInterval, error) {
	const q = `
SELECT start_ms, end_ms FROM maintenance
WHERE check_id = $1 AND deleted = false AND (expiry_ms = 0 OR expiry_ms > $2)`
	rows, err := p.pool.Query(ctx, q, checkID, nowMS())
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []MaintenanceInterval
	for rows.Next() {
		var iv MaintenanceInterval
		if err := rows.Scan(&iv.StartMS, &iv.EndMS); err != nil {
			return nil, err
		}
		out = append(out, iv)
	}
	return out, rows.Err()
}
