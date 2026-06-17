// Package trust holds a hub's policy for which probes/hubs it will accept
// results from. Verification (is the signature valid?) is separate and always
// enforced in pkg/protocol; trust is the *additional* question of whether a
// validly-signed result from a given identity should be admitted at all.
package trust

import "strings"

// Policy decides whether a result from a given self-certifying node ID is
// admitted to this hub's store and re-gossip.
type Policy interface {
	Allow(nodeID string) bool
	Name() string
}

// Open admits any validly-signed result, tagged with its origin. This is the
// default: it maximizes coverage and relies on cross-probe corroboration
// (multiple independent probes agreeing) rather than gatekeeping for trust.
//
// Tradeoff: an open mesh is Sybil-prone. Operators who need stronger guarantees
// should run AllowList instead.
type Open struct{}

func (Open) Allow(string) bool { return true }
func (Open) Name() string      { return "open" }

// AllowList admits results only from an explicit set of node IDs.
type AllowList struct{ ids map[string]struct{} }

// NewAllowList builds an allowlist from node IDs.
func NewAllowList(ids []string) *AllowList {
	m := make(map[string]struct{}, len(ids))
	for _, id := range ids {
		if id = strings.TrimSpace(id); id != "" {
			m[id] = struct{}{}
		}
	}
	return &AllowList{ids: m}
}

func (a *AllowList) Allow(id string) bool { _, ok := a.ids[id]; return ok }
func (a *AllowList) Name() string         { return "allowlist" }

// TrustedStorage reports whether a peer hub may be granted unclamped storage
// placement weight (large capacity / the archive role). Only an allowlist
// policy conveys that trust: under the open policy every peer is admitted for
// results (corroboration is the mitigation there), but none is trusted to hold
// an outsized share of storage, which would be a Sybil/eclipse lever. This
// hub's own identity is always trusted and is handled by the caller.
func TrustedStorage(p Policy, hubID string) bool {
	return p != nil && p.Name() == "allowlist" && p.Allow(hubID)
}

// FromConfig returns a policy for the given mode. mode "allowlist" uses ids;
// anything else (including "open" or empty) returns Open.
func FromConfig(mode string, ids []string) Policy {
	if strings.EqualFold(strings.TrimSpace(mode), "allowlist") {
		return NewAllowList(ids)
	}
	return Open{}
}
