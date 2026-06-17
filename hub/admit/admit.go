// Package admit holds the semantic admission checks a hub applies to a result
// after it has passed cryptographic verification and the trust policy.
//
// SignedResult.Verify proves who produced a result; it says nothing about
// whether the result is meaningful. Without these checks a validly-signed
// result (trivial under the default open policy, where anyone can mint a probe
// key) could claim a target/type that disagrees with the catalog, carry a
// wild-future timestamp, or stuff oversized fields — poisoning the map, the
// alert engine, and storage. admit.Result is the second gate, applied on both
// the HTTP submit path and the mesh ingest path so they stay identical.
package admit

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/mwgg/libreping/pkg/protocol"
)

const (
	// MaxClockSkew bounds how far into the future a result's timestamp may be.
	MaxClockSkew = 2 * time.Minute
	// MaxResultAge bounds how stale a submitted result may be. Gossip
	// re-delivery is deduped by the store, so genuinely fresh data is always
	// well inside this window.
	MaxResultAge = 24 * time.Hour
	// maxTargetLen / maxFieldLen / maxDetailEntries bound free-form fields so a
	// result can't carry an oversized payload into storage or the dashboard.
	maxTargetLen     = 2048
	maxFieldLen      = 256
	maxDetailEntries = 32
	maxDetailValLen  = 1024
)

// ErrUnknownStatus, ErrTimestamp, etc. let callers distinguish reject reasons.
var (
	ErrTimestamp       = errors.New("admit: result timestamp out of acceptable window")
	ErrBadStatus       = errors.New("admit: unknown status value")
	ErrCatalogMismatch = errors.New("admit: result target/type disagree with catalog entry")
	ErrOversized       = errors.New("admit: result field exceeds size bound")
)

// CatalogLookup fetches a catalog entry by check ID. *store.CatalogStore's
// GetCheck satisfies it; tests can supply a stub.
type CatalogLookup interface {
	GetCheck(ctx context.Context, checkID string) (protocol.SignedCatalogEntry, bool, error)
}

// Result validates a cryptographically-verified result for semantic sanity. It
// must be called AFTER SignedResult.Verify and the trust policy. now is passed
// in so tests are deterministic.
//
// Catalog policy: if the check is known, the result's target and type must
// match the immutable catalog spec — a result cannot redefine what a shared
// check measures. If the check is unknown, the result is allowed through
// (results legitimately race ahead of catalog gossip), but its fields are still
// bounded.
func Result(ctx context.Context, catalog CatalogLookup, sr protocol.SignedResult, now time.Time) error {
	c := sr.Content

	switch c.Status {
	case protocol.StatusUp, protocol.StatusDown, protocol.StatusDegraded:
	default:
		return ErrBadStatus
	}

	nowMS := now.UnixMilli()
	if c.TimestampMS > nowMS+MaxClockSkew.Milliseconds() ||
		c.TimestampMS < nowMS-MaxResultAge.Milliseconds() {
		return ErrTimestamp
	}

	if len(c.Target) > maxTargetLen {
		return fmt.Errorf("%w: target", ErrOversized)
	}
	if len(c.Location.City) > maxFieldLen || len(c.Location.Country) > maxFieldLen {
		return fmt.Errorf("%w: location", ErrOversized)
	}
	if len(c.Detail) > maxDetailEntries {
		return fmt.Errorf("%w: detail entries", ErrOversized)
	}
	for k, v := range c.Detail {
		if len(k) > maxFieldLen || len(v) > maxDetailValLen {
			return fmt.Errorf("%w: detail field", ErrOversized)
		}
	}

	if catalog == nil {
		return nil
	}
	entry, ok, err := catalog.GetCheck(ctx, c.CheckID)
	if err != nil {
		// A storage error shouldn't admit unvalidated data, but also shouldn't
		// be silently swallowed — surface it so the caller can log/refuse.
		return fmt.Errorf("admit: catalog lookup: %w", err)
	}
	if !ok {
		return nil // unknown check: allow (may precede catalog gossip)
	}
	if c.Target != entry.Entry.Spec.Target || c.CheckType != entry.Entry.Spec.Type {
		return ErrCatalogMismatch
	}
	return nil
}
