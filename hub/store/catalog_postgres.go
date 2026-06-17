package store

import (
	"context"
	"encoding/json"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/mwgg/libreping/pkg/protocol"
)

// PgCatalog is a Postgres-backed CatalogStore. It reuses the PgStore pool.
type PgCatalog struct {
	pool *pgxpool.Pool
}

// NewPgCatalog returns a catalog store sharing an existing PgStore's pool.
func NewPgCatalog(s *PgStore) *PgCatalog { return &PgCatalog{pool: s.pool} }

func (c *PgCatalog) UpsertCheck(ctx context.Context, sc protocol.SignedCatalogEntry) error {
	params, err := json.Marshal(sc.Entry.Spec.Params)
	if err != nil {
		return err
	}
	const q = `
INSERT INTO checks (check_id, check_type, target, interval_seconds, params, hub_id, pubkey, signature)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8)
ON CONFLICT (check_id) DO UPDATE SET
  check_type = EXCLUDED.check_type,
  target = EXCLUDED.target,
  interval_seconds = EXCLUDED.interval_seconds,
  params = EXCLUDED.params,
  hub_id = EXCLUDED.hub_id,
  pubkey = EXCLUDED.pubkey,
  signature = EXCLUDED.signature`
	s := sc.Entry.Spec
	_, err = c.pool.Exec(ctx, q,
		s.ID, string(s.Type), s.Target, s.IntervalSeconds, params,
		sc.Entry.HubID, []byte(sc.PubKey), sc.Signature,
	)
	return err
}

func (c *PgCatalog) GetCheck(ctx context.Context, checkID string) (protocol.SignedCatalogEntry, bool, error) {
	const q = `
SELECT check_id, check_type, target, interval_seconds, params, hub_id, pubkey, signature
FROM checks WHERE check_id = $1`
	var (
		sc        protocol.SignedCatalogEntry
		checkType string
		params    []byte
		pubkey    []byte
	)
	err := c.pool.QueryRow(ctx, q, checkID).Scan(
		&sc.Entry.Spec.ID, &checkType, &sc.Entry.Spec.Target, &sc.Entry.Spec.IntervalSeconds,
		&params, &sc.Entry.HubID, &pubkey, &sc.Signature,
	)
	if err != nil {
		if err == pgx.ErrNoRows {
			return protocol.SignedCatalogEntry{}, false, nil
		}
		return protocol.SignedCatalogEntry{}, false, err
	}
	sc.Entry.Spec.Type = protocol.CheckType(checkType)
	_ = json.Unmarshal(params, &sc.Entry.Spec.Params)
	sc.PubKey = pubkey
	return sc, true, nil
}

func (c *PgCatalog) ListChecks(ctx context.Context) ([]protocol.SignedCatalogEntry, error) {
	const q = `
SELECT check_id, check_type, target, interval_seconds, params, hub_id, pubkey, signature
FROM checks ORDER BY check_id`
	rows, err := c.pool.Query(ctx, q)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []protocol.SignedCatalogEntry
	for rows.Next() {
		var (
			sc        protocol.SignedCatalogEntry
			checkType string
			params    []byte
			pubkey    []byte
		)
		if err := rows.Scan(
			&sc.Entry.Spec.ID, &checkType, &sc.Entry.Spec.Target, &sc.Entry.Spec.IntervalSeconds,
			&params, &sc.Entry.HubID, &pubkey, &sc.Signature,
		); err != nil {
			return nil, err
		}
		sc.Entry.Spec.Type = protocol.CheckType(checkType)
		_ = json.Unmarshal(params, &sc.Entry.Spec.Params)
		sc.PubKey = pubkey
		out = append(out, sc)
	}
	return out, rows.Err()
}
