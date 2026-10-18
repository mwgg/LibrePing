package reporter

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/mwgg/libreping/pkg/identity"
	"github.com/mwgg/libreping/pkg/protocol"
	"github.com/mwgg/libreping/probe/checks"
)

// fakeHub records submissions and serves a fixed catalog.
type fakeHub struct {
	mu         sync.Mutex
	specs      []protocol.CheckSpec
	results    []protocol.SignedResult
	registered bool
}

func (f *fakeHub) Register(_ context.Context, reg protocol.SignedProbeRegistration) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	// The reporter must send a registration that verifies against the probe key.
	if err := reg.Verify(); err != nil {
		return err
	}
	f.registered = true
	return nil
}

func (f *fakeHub) FetchChecks(context.Context, string) ([]protocol.CheckSpec, error) {
	return f.specs, nil
}

func (f *fakeHub) SubmitResult(_ context.Context, sr protocol.SignedResult) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.results = append(f.results, sr)
	return nil
}

func TestReporterRunsSignsAndSubmits(t *testing.T) {
	id, _ := identity.Generate()
	hub := &fakeHub{specs: []protocol.CheckSpec{
		// A stub check type still produces a (degraded) signed result.
		{ID: "tcp-1", Type: protocol.CheckTCP, Target: "example.com:443"},
	}}
	loc := protocol.Location{Country: "DE", City: "Frankfurt"}

	r := New(Config{Identity: id, Location: loc, Hub: hub, PollInterval: time.Hour})
	r.refresh(context.Background())
	r.runDue(context.Background())

	hub.mu.Lock()
	defer hub.mu.Unlock()
	if len(hub.results) != 1 {
		t.Fatalf("expected 1 submitted result, got %d", len(hub.results))
	}
	got := hub.results[0]
	if err := got.Verify(); err != nil {
		t.Fatalf("submitted result does not verify: %v", err)
	}
	if got.Content.ProbeID != id.NodeID() {
		t.Fatal("result not attributed to this probe")
	}
	if got.Content.Location.City != "Frankfurt" {
		t.Fatal("declared location not carried into result")
	}
	if !hub.registered {
		t.Fatal("probe did not register with the hub")
	}
}

func TestRateLimiterCapsBurst(t *testing.T) {
	b := newTokenBucket(3)
	allowed := 0
	for i := 0; i < 20; i++ {
		if b.allow() {
			allowed++
		}
	}
	// The bucket starts full (burst == cap) and barely refills over microseconds.
	if allowed != 3 {
		t.Fatalf("expected 3 executions permitted in a burst, got %d", allowed)
	}
}

func TestRateLimiterUnlimitedWhenZero(t *testing.T) {
	b := newTokenBucket(0) // nil bucket = unlimited
	for i := 0; i < 100; i++ {
		if !b.allow() {
			t.Fatal("unlimited limiter denied an execution")
		}
	}
}

func TestUnsupportedHTTPConnectEmitsNoResult(t *testing.T) {
	id, _ := identity.Generate()
	hub := &fakeHub{}
	r := New(Config{Identity: id, Hub: hub})
	r.registry = new(checks.Registry) // Simulate a legacy binary without the checker.
	r.execute(context.Background(), protocol.CheckSpec{ID: "pinned", Type: protocol.CheckHTTPConnect, Target: "https://example.com", Params: map[string]string{"connect_address": "192.0.2.1"}})
	if len(hub.results) != 0 {
		t.Fatal("unsupported type emitted a result")
	}
}

func TestHTTPConnectReporterPreservesWireIdentity(t *testing.T) {
	id, _ := identity.Generate()
	hub := &fakeHub{}
	r := New(Config{Identity: id, Hub: hub})
	found := false
	for _, kind := range r.supported {
		if kind == protocol.CheckHTTPConnect {
			found = true
		}
	}
	if !found {
		t.Fatal("new checker not advertised")
	}
	spec := protocol.CheckSpec{Type: protocol.CheckHTTPConnect, Target: "https://example.com", Params: map[string]string{"connect_address": "invalid"}}
	spec.ID = spec.DeriveID()
	r.execute(context.Background(), spec)
	if len(hub.results) != 1 {
		t.Fatal("missing result")
	}
	got := hub.results[0]
	if got.Verify() != nil || got.Content.CheckID != spec.ID || got.Content.CheckType != spec.Type || got.Content.Target != spec.Target {
		t.Fatalf("wrong result: %+v", got)
	}
}
