// Package reporter ties a probe together: it registers with a home hub
// (declaring its capacity and supported check types), pulls the subset of
// checks the hub assigns to it, runs each on its own schedule subject to a hard
// per-minute rate cap, signs every result, and submits them. Signing happens
// here so that the hub — and every hub the result is later gossiped to — can
// verify the measurement came from this probe.
package reporter

import (
	"context"
	"log/slog"
	"sync"
	"time"

	"github.com/mwgg/libreping/pkg/identity"
	"github.com/mwgg/libreping/pkg/protocol"
	"github.com/mwgg/libreping/probe/checks"
)

// schedulerTick is how often the probe checks for due work.
const schedulerTick = time.Second

// nowMS is the current time in unix milliseconds. It is a package var so tests
// can substitute a deterministic clock.
var nowMS = func() int64 { return time.Now().UnixMilli() }

// Submitter is the subset of HubClient the reporter needs; an interface keeps
// the run loop testable without a live hub.
type Submitter interface {
	Register(ctx context.Context, reg protocol.SignedProbeRegistration) error
	FetchChecks(ctx context.Context, probeID string) ([]protocol.CheckSpec, error)
	SubmitResult(ctx context.Context, sr protocol.SignedResult) error
}

// Config builds a Reporter.
type Config struct {
	Identity           *identity.Identity
	Location           protocol.Location
	Hub                Submitter
	PollInterval       time.Duration        // how often to re-register + refresh assignment
	MaxChecksPerMinute int                  // hard cap; <= 0 means unlimited
	SupportedTypes     []protocol.CheckType // declared to the hub; empty => all built-in types
	Logger             *slog.Logger
}

type scheduledCheck struct {
	spec protocol.CheckSpec
	due  time.Time
}

// Reporter runs the probe's measurement loop.
type Reporter struct {
	id           *identity.Identity
	location     protocol.Location
	registry     *checks.Registry
	hub          Submitter
	pollInterval time.Duration
	maxPerMinute int
	supported    []protocol.CheckType
	limiter      *tokenBucket
	log          *slog.Logger

	mu       sync.Mutex
	schedule map[string]scheduledCheck
	now      func() time.Time
}

// New builds a Reporter from cfg.
func New(cfg Config) *Reporter {
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	reg := checks.NewRegistry()
	supported := cfg.SupportedTypes
	if len(supported) == 0 {
		supported = reg.Types()
	}
	return &Reporter{
		id:           cfg.Identity,
		location:     cfg.Location,
		registry:     reg,
		hub:          cfg.Hub,
		pollInterval: cfg.PollInterval,
		maxPerMinute: cfg.MaxChecksPerMinute,
		supported:    supported,
		limiter:      newTokenBucket(cfg.MaxChecksPerMinute),
		log:          cfg.Logger,
		schedule:     map[string]scheduledCheck{},
		now:          time.Now,
	}
}

// Run registers the probe and then runs assigned checks on schedule until the
// context is cancelled. Two cadences: a slow poll re-registers (heartbeat) and
// refreshes the assignment; a fast tick runs due checks under the rate cap.
func (r *Reporter) Run(ctx context.Context) error {
	r.refresh(ctx)

	poll := time.NewTicker(r.pollInterval)
	tick := time.NewTicker(schedulerTick)
	defer poll.Stop()
	defer tick.Stop()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-poll.C:
			r.refresh(ctx)
		case <-tick.C:
			r.runDue(ctx)
		}
	}
}

// refresh re-registers with the hub (heartbeat + current capacity) and pulls
// the assigned check subset, merging it into the schedule.
func (r *Reporter) refresh(ctx context.Context) {
	reg, err := protocol.SignProbeRegistration(r.id, protocol.ProbeRegistration{
		Location:           r.location,
		MaxChecksPerMinute: r.maxPerMinute,
		SupportedTypes:     r.supported,
		TimestampMS:        r.now().UnixMilli(),
	})
	if err != nil {
		r.log.Warn("sign registration failed, continuing", "err", err)
	} else if err := r.hub.Register(ctx, reg); err != nil {
		r.log.Warn("register/heartbeat failed, continuing", "err", err)
	}

	specs, err := r.hub.FetchChecks(ctx, r.id.NodeID())
	if err != nil {
		r.log.Warn("fetch assignment failed", "err", err)
		return
	}

	r.mu.Lock()
	defer r.mu.Unlock()
	next := make(map[string]scheduledCheck, len(specs))
	for _, s := range specs {
		if existing, ok := r.schedule[s.ID]; ok {
			existing.spec = s // keep its next-due time
			next[s.ID] = existing
		} else {
			next[s.ID] = scheduledCheck{spec: s, due: r.now()} // new check runs soon
		}
	}
	r.schedule = next
}

// runDue runs every check whose interval has elapsed, subject to the rate cap.
// Checks run concurrently; runDue waits for the batch so scheduling stays
// coherent (and tests are deterministic).
func (r *Reporter) runDue(ctx context.Context) {
	now := r.now()

	r.mu.Lock()
	var toRun []protocol.CheckSpec
	for id, sc := range r.schedule {
		if sc.due.After(now) {
			continue
		}
		if !r.limiter.allow() {
			continue // over the cap; retried on the next tick
		}
		interval := sc.spec.IntervalSeconds
		if interval <= 0 {
			interval = 60
		}
		sc.due = now.Add(time.Duration(interval) * time.Second)
		r.schedule[id] = sc
		toRun = append(toRun, sc.spec)
	}
	r.mu.Unlock()

	var wg sync.WaitGroup
	for _, spec := range toRun {
		wg.Add(1)
		go func(spec protocol.CheckSpec) {
			defer wg.Done()
			r.execute(ctx, spec)
		}(spec)
	}
	wg.Wait()
}

func (r *Reporter) execute(ctx context.Context, spec protocol.CheckSpec) {
	checker, ok := r.registry.Get(spec.Type)
	if !ok {
		r.log.Warn("no checker for type", "type", spec.Type)
		return
	}
	outcome, err := checker.Run(ctx, spec)
	if err != nil && outcome.Status == "" {
		r.log.Warn("check errored", "id", spec.ID, "type", spec.Type, "err", err)
		return
	}

	content := protocol.ResultContent{
		CheckID:     spec.ID,
		CheckType:   spec.Type,
		Target:      spec.Target,
		Location:    r.location,
		TimestampMS: nowMS(),
		Status:      outcome.Status,
		RTTMillis:   outcome.RTTMillis,
		Detail:      outcome.Detail,
	}
	signed, err := protocol.SignResult(r.id, content)
	if err != nil {
		r.log.Error("sign result", "err", err)
		return
	}
	if err := r.hub.SubmitResult(ctx, signed); err != nil {
		r.log.Warn("submit result failed", "id", spec.ID, "err", err)
	}
}
