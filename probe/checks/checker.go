// Package checks implements the monitoring checks a probe can run.
//
// Each check type implements Checker and registers itself (typically from an
// init function or from RegisterDefaults). Adding a new check is three steps:
//  1. add a CheckType constant in pkg/protocol,
//  2. implement Checker here and register it,
//  3. if it needs raw sockets (ICMP/traceroute), document the NET_RAW
//     requirement and reflect it in the probe Dockerfile / compose file.
package checks

import (
	"context"
	"errors"
	"sort"

	"github.com/mwgg/libreping/pkg/protocol"
)

// ErrNotImplemented is returned by checks that are registered but not yet built.
var ErrNotImplemented = errors.New("checker not yet implemented")

// Outcome is the measurement a Checker produces.
type Outcome struct {
	Status    protocol.Status
	RTTMillis float64
	Detail    map[string]string
}

// Checker runs one kind of check against a target.
type Checker interface {
	Type() protocol.CheckType
	Run(ctx context.Context, spec protocol.CheckSpec) (Outcome, error)
}

// Registry maps check types to their implementations.
type Registry struct {
	checkers map[protocol.CheckType]Checker
}

// NewRegistry returns a registry preloaded with all built-in checks.
func NewRegistry() *Registry {
	r := &Registry{checkers: map[protocol.CheckType]Checker{}}
	r.Register(HTTPChecker{})
	r.Register(TCPChecker{})
	r.Register(DNSChecker{})
	r.Register(TLSChecker{})
	r.Register(ICMPChecker{})
	r.Register(TracerouteChecker{})
	return r
}

// Register adds or replaces a checker.
func (r *Registry) Register(c Checker) { r.checkers[c.Type()] = c }

// Get returns the checker for a type.
func (r *Registry) Get(t protocol.CheckType) (Checker, bool) {
	c, ok := r.checkers[t]
	return c, ok
}

// Types lists the registered check types in stable order.
func (r *Registry) Types() []protocol.CheckType {
	out := make([]protocol.CheckType, 0, len(r.checkers))
	for t := range r.checkers {
		out = append(out, t)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}
