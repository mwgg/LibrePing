package reporter

import (
	"context"
	"errors"
	"log/slog"
	"sync"
	"time"

	"github.com/mwgg/libreping/pkg/protocol"
)

// errNoHubs is returned when the pool has no candidate hubs at all.
var errNoHubs = errors.New("no hubs configured")

// hubConn is the per-hub capability the failover pool depends on. *HubClient
// satisfies it; tests inject fakes.
type hubConn interface {
	Submitter
	FetchHubs(ctx context.Context) ([]protocol.HubAnnouncement, error)
	URL() string
}

// failoverCooldown is how long a hub is skipped after a failed call before the
// pool will try it again.
const failoverCooldown = 30 * time.Second

// maxCandidates bounds how large the discovered pool can grow so a noisy or
// hostile directory can't make the probe track unbounded hubs.
const maxCandidates = 32

type candidate struct {
	conn          hubConn
	cooldownUntil time.Time
}

// FailoverClient is a Submitter over an ordered pool of hubs. The configured
// seed hubs come first (in order); peers learned from the gossiped directory of
// whichever hub the probe is talking to are appended. Calls try the preferred
// order, skipping hubs in cooldown, so a probe survives its home hub going down
// and re-homes to it once it recovers.
//
// Results submitted to any hub are verified and gossiped network-wide, so it
// does not matter which hub a probe lands on — the home hub gets them back via
// gossip once it is up again.
type FailoverClient struct {
	newConn         func(url string) hubConn
	log             *slog.Logger
	discoverEnabled bool

	mu         sync.Mutex
	candidates []*candidate
	cur        int             // index of the sticky current hub (hot path)
	seen       map[string]bool // known base URLs, for dedupe
	now        func() time.Time
}

// NewFailoverClient builds a pool from the seed hub URLs (config order
// preserved). discover enables learning additional hubs from the directory.
func NewFailoverClient(seedURLs []string, discover bool, log *slog.Logger) *FailoverClient {
	if log == nil {
		log = slog.Default()
	}
	f := &FailoverClient{
		newConn:         func(url string) hubConn { return NewHubClient(url) },
		log:             log,
		discoverEnabled: discover,
		seen:            map[string]bool{},
		now:             time.Now,
	}
	for _, u := range seedURLs {
		f.add(u)
	}
	return f
}

// add appends a hub by URL if not already known and the cap allows it. Caller
// holds no lock on first construction; addLocked is the locked variant.
func (f *FailoverClient) add(url string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.addLocked(url)
}

func (f *FailoverClient) addLocked(url string) {
	if url == "" || f.seen[url] || len(f.candidates) >= maxCandidates {
		return
	}
	f.seen[url] = true
	f.candidates = append(f.candidates, &candidate{conn: f.newConn(url)})
}

// Register heartbeats and re-homes: it grows the pool from the directory, then
// runs the call preferring the configured order (index 0 first), so the probe
// gravitates back to its home hub as soon as that hub is healthy again.
func (f *FailoverClient) Register(ctx context.Context, reg protocol.SignedProbeRegistration) error {
	f.discover(ctx)
	return f.do(ctx, "register", true, func(c hubConn) error {
		return c.Register(ctx, reg)
	})
}

// FetchChecks pulls the assignment from the current hub (the one that just
// answered register), failing over only if it is unreachable.
func (f *FailoverClient) FetchChecks(ctx context.Context, probeID string) ([]protocol.CheckSpec, error) {
	var specs []protocol.CheckSpec
	err := f.do(ctx, "fetch", false, func(c hubConn) error {
		s, err := c.FetchChecks(ctx, probeID)
		if err != nil {
			return err
		}
		specs = s
		return nil
	})
	return specs, err
}

// SubmitResult sends a result to the current hub; on failure it rotates to the
// next healthy hub and re-submits, so an in-flight result survives a hub going
// down mid-cycle (the result gossips network-wide from wherever it lands).
func (f *FailoverClient) SubmitResult(ctx context.Context, sr protocol.SignedResult) error {
	return f.do(ctx, "submit", false, func(c hubConn) error {
		return c.SubmitResult(ctx, sr)
	})
}

// do runs fn against pool hubs until one succeeds. When preferHome is true it
// starts at index 0 (re-home to the configured seed order); otherwise it starts
// at the sticky current hub (cheap hot path, only rotates on failure). Hubs in
// cooldown are tried last rather than skipped, so if every hub is cooled down
// the probe still attempts delivery and never goes fully dark. On success cur is
// updated to the answering hub and a transition is logged only when cur changed.
func (f *FailoverClient) do(ctx context.Context, op string, preferHome bool, fn func(hubConn) error) error {
	f.mu.Lock()
	n := len(f.candidates)
	if n == 0 {
		f.mu.Unlock()
		return errNoHubs
	}
	start := f.cur
	if preferHome {
		start = 0
	}
	// Attempt order: healthy hubs first (preference order from start), cooled-down
	// hubs after, as a last resort.
	now := f.now()
	var healthy, cooled []int
	for i := 0; i < n; i++ {
		idx := (start + i) % n
		if f.candidates[idx].cooldownUntil.After(now) {
			cooled = append(cooled, idx)
		} else {
			healthy = append(healthy, idx)
		}
	}
	order := append(healthy, cooled...)
	f.mu.Unlock()

	var lastErr error
	for _, idx := range order {
		f.mu.Lock()
		c := f.candidates[idx]
		conn := c.conn
		f.mu.Unlock()

		if err := fn(conn); err != nil {
			f.mu.Lock()
			c.cooldownUntil = f.now().Add(failoverCooldown)
			f.mu.Unlock()
			f.log.Debug("hub call failed, trying next", "op", op, "hub", conn.URL(), "err", err)
			lastErr = err
			continue
		}

		f.mu.Lock()
		c.cooldownUntil = time.Time{}
		changed := f.cur != idx
		f.cur = idx
		f.mu.Unlock()
		if changed {
			f.log.Info("failed over to hub", "op", op, "hub", conn.URL())
		}
		return nil
	}
	return lastErr
}

// discover grows the pool with peers from the current hub's directory. It is
// best-effort: failure is non-fatal because the seed list already works.
func (f *FailoverClient) discover(ctx context.Context) {
	if !f.discoverEnabled {
		return
	}
	f.mu.Lock()
	if len(f.candidates) == 0 {
		f.mu.Unlock()
		return
	}
	conn := f.candidates[f.cur].conn
	f.mu.Unlock()

	hubs, err := conn.FetchHubs(ctx)
	if err != nil {
		f.log.Debug("hub discovery failed", "hub", conn.URL(), "err", err)
		return
	}
	for _, h := range hubs {
		f.addLockedSafe(h.PublicURL)
	}
}

// addLockedSafe is add() that also logs newly-learned hubs at debug.
func (f *FailoverClient) addLockedSafe(url string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	before := len(f.candidates)
	f.addLocked(url)
	if len(f.candidates) > before {
		f.log.Debug("discovered hub", "hub", url)
	}
}
