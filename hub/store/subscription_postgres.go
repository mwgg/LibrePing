package store

import (
	"context"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/mwgg/libreping/pkg/protocol"
)

// PgSubscriptions is a Postgres-backed SubscriptionStore.
type PgSubscriptions struct {
	pool *pgxpool.Pool
}

func NewPgSubscriptions(s *PgStore) *PgSubscriptions { return &PgSubscriptions{pool: s.pool} }

// Upsert applies ss only if its UpdatedMS is strictly newer than the stored
// record's (WHERE clause), keeping tombstones rather than deleting so a replayed
// old record can't resurrect a deleted subscription.
func (p *PgSubscriptions) Upsert(ctx context.Context, ss protocol.SignedSubscription) error {
	s := ss.Subscription
	const q = `
INSERT INTO subscriptions (owner, check_id, interval_seconds, expiry_ms, updated_ms, deleted, pubkey, signature)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8)
ON CONFLICT (owner, check_id) DO UPDATE SET
  interval_seconds = EXCLUDED.interval_seconds,
  expiry_ms = EXCLUDED.expiry_ms,
  updated_ms = EXCLUDED.updated_ms,
  deleted = EXCLUDED.deleted,
  pubkey = EXCLUDED.pubkey,
  signature = EXCLUDED.signature
  WHERE EXCLUDED.updated_ms > subscriptions.updated_ms`
	_, err := p.pool.Exec(ctx, q, s.Owner, s.CheckID, s.IntervalSeconds, s.ExpiryMS, s.UpdatedMS, s.Deleted, []byte(ss.PubKey), ss.Signature)
	return err
}

func (p *PgSubscriptions) ListActive(ctx context.Context) ([]protocol.SignedSubscription, error) {
	return p.list(ctx, false)
}

func (p *PgSubscriptions) ListForGossip(ctx context.Context) ([]protocol.SignedSubscription, error) {
	return p.list(ctx, true)
}

func (p *PgSubscriptions) list(ctx context.Context, includeTombstones bool) ([]protocol.SignedSubscription, error) {
	q := `
SELECT owner, check_id, interval_seconds, expiry_ms, updated_ms, deleted, pubkey, signature
FROM subscriptions WHERE (expiry_ms = 0 OR expiry_ms > $1)`
	if !includeTombstones {
		q += ` AND deleted = false`
	}
	rows, err := p.pool.Query(ctx, q, nowMS())
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []protocol.SignedSubscription
	for rows.Next() {
		var ss protocol.SignedSubscription
		var pubkey []byte
		if err := rows.Scan(&ss.Subscription.Owner, &ss.Subscription.CheckID,
			&ss.Subscription.IntervalSeconds, &ss.Subscription.ExpiryMS, &ss.Subscription.UpdatedMS,
			&ss.Subscription.Deleted, &pubkey, &ss.Signature); err != nil {
			return nil, err
		}
		ss.PubKey = pubkey
		out = append(out, ss)
	}
	return out, rows.Err()
}
