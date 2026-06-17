package reporter

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"sync"
	"testing"
	"time"

	"github.com/mwgg/libreping/pkg/protocol"
)

// fakeConn is a scriptable hubConn for failover tests.
type fakeConn struct {
	url   string
	peers []protocol.HubAnnouncement

	mu        sync.Mutex
	down      bool // every call fails while true
	registers int
	fetches   int
	submits   int
}

func (f *fakeConn) URL() string { return f.url }

func (f *fakeConn) setDown(down bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.down = down
}

func (f *fakeConn) Register(context.Context, protocol.SignedProbeRegistration) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.down {
		return errors.New("down")
	}
	f.registers++
	return nil
}

func (f *fakeConn) FetchChecks(context.Context, string) ([]protocol.CheckSpec, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.down {
		return nil, errors.New("down")
	}
	f.fetches++
	return nil, nil
}

func (f *fakeConn) SubmitResult(context.Context, protocol.SignedResult) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.down {
		return errors.New("down")
	}
	f.submits++
	return nil
}

func (f *fakeConn) FetchHubs(context.Context) ([]protocol.HubAnnouncement, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.down {
		return nil, errors.New("down")
	}
	return f.peers, nil
}

func (f *fakeConn) count() (int, int, int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.registers, f.fetches, f.submits
}

// newTestPool builds a FailoverClient over the given fakes, wiring newConn so
// discovery can construct further fakes keyed by URL.
func newTestPool(t *testing.T, conns ...*fakeConn) (*FailoverClient, map[string]*fakeConn) {
	t.Helper()
	byURL := map[string]*fakeConn{}
	var seeds []string
	for _, c := range conns {
		byURL[c.url] = c
		seeds = append(seeds, c.url)
	}
	f := NewFailoverClient(nil, true, slog.New(slog.NewTextHandler(io.Discard, nil)))
	f.newConn = func(url string) hubConn {
		if c, ok := byURL[url]; ok {
			return c
		}
		c := &fakeConn{url: url}
		byURL[url] = c
		return c
	}
	for _, s := range seeds {
		f.add(s)
	}
	return f, byURL
}

func TestFailoverPrimaryHealthy(t *testing.T) {
	a := &fakeConn{url: "a"}
	b := &fakeConn{url: "b"}
	f, _ := newTestPool(t, a, b)
	f.discoverEnabled = false

	ctx := context.Background()
	for i := 0; i < 3; i++ {
		if err := f.Register(ctx, protocol.SignedProbeRegistration{}); err != nil {
			t.Fatalf("register: %v", err)
		}
		if _, err := f.FetchChecks(ctx, "p"); err != nil {
			t.Fatalf("fetch: %v", err)
		}
		if err := f.SubmitResult(ctx, protocol.SignedResult{}); err != nil {
			t.Fatalf("submit: %v", err)
		}
	}
	if r, fc, s := a.count(); r != 3 || fc != 3 || s != 3 {
		t.Fatalf("primary should have served everything, got reg=%d fetch=%d submit=%d", r, fc, s)
	}
	if r, fc, s := b.count(); r != 0 || fc != 0 || s != 0 {
		t.Fatalf("secondary should be untouched, got reg=%d fetch=%d submit=%d", r, fc, s)
	}
}

func TestFailoverWhenPrimaryDown(t *testing.T) {
	a := &fakeConn{url: "a"}
	b := &fakeConn{url: "b"}
	f, _ := newTestPool(t, a, b)
	f.discoverEnabled = false
	a.setDown(true)

	ctx := context.Background()
	if err := f.Register(ctx, protocol.SignedProbeRegistration{}); err != nil {
		t.Fatalf("register should have failed over to b: %v", err)
	}
	if _, err := f.FetchChecks(ctx, "p"); err != nil {
		t.Fatalf("fetch should hit b: %v", err)
	}
	if err := f.SubmitResult(ctx, protocol.SignedResult{}); err != nil {
		t.Fatalf("submit should hit b: %v", err)
	}
	if r, fc, s := b.count(); r != 1 || fc != 1 || s != 1 {
		t.Fatalf("secondary should have served everything, got reg=%d fetch=%d submit=%d", r, fc, s)
	}
}

func TestFailoverReHomesOnRecovery(t *testing.T) {
	a := &fakeConn{url: "a"}
	b := &fakeConn{url: "b"}
	f, _ := newTestPool(t, a, b)
	f.discoverEnabled = false

	// Pin a synthetic clock so cooldowns are deterministic.
	now := time.Unix(0, 0)
	f.now = func() time.Time { return now }

	ctx := context.Background()
	a.setDown(true)
	if err := f.Register(ctx, protocol.SignedProbeRegistration{}); err != nil {
		t.Fatalf("register failover: %v", err)
	}
	// cur is now b. Bring a back and advance past its cooldown.
	a.setDown(false)
	now = now.Add(failoverCooldown + time.Second)

	if err := f.Register(ctx, protocol.SignedProbeRegistration{}); err != nil {
		t.Fatalf("register re-home: %v", err)
	}
	// preferHome starts at index 0 (a); a is healthy now so it should win.
	f.mu.Lock()
	cur := f.cur
	f.mu.Unlock()
	if cur != 0 {
		t.Fatalf("expected re-home to index 0 (a), cur=%d", cur)
	}
}

func TestFailoverSubmitRetriesOnNextHub(t *testing.T) {
	a := &fakeConn{url: "a"}
	b := &fakeConn{url: "b"}
	f, _ := newTestPool(t, a, b)
	f.discoverEnabled = false

	ctx := context.Background()
	// Establish a as current via a healthy register.
	if err := f.Register(ctx, protocol.SignedProbeRegistration{}); err != nil {
		t.Fatalf("register: %v", err)
	}
	// a dies mid-cycle; the in-flight submit must survive on b.
	a.setDown(true)
	if err := f.SubmitResult(ctx, protocol.SignedResult{}); err != nil {
		t.Fatalf("submit should have failed over: %v", err)
	}
	if _, _, s := b.count(); s != 1 {
		t.Fatalf("result should have landed on b, submits=%d", s)
	}
}

func TestFailoverDiscoveryMergesPeers(t *testing.T) {
	a := &fakeConn{url: "a", peers: []protocol.HubAnnouncement{
		{PublicURL: "b"},
		{PublicURL: "a"}, // self: deduped
		{PublicURL: ""},  // empty: skipped
	}}
	f, byURL := newTestPool(t, a)

	ctx := context.Background()
	if err := f.Register(ctx, protocol.SignedProbeRegistration{}); err != nil {
		t.Fatalf("register: %v", err)
	}
	f.mu.Lock()
	n := len(f.candidates)
	f.mu.Unlock()
	if n != 2 {
		t.Fatalf("expected pool to grow to 2 (a + discovered b), got %d", n)
	}
	if _, ok := byURL["b"]; !ok {
		t.Fatalf("discovered hub b was not constructed")
	}

	// With a down, a subsequent op fails over onto the discovered b.
	a.setDown(true)
	if err := f.SubmitResult(ctx, protocol.SignedResult{}); err != nil {
		t.Fatalf("submit should fail over to discovered b: %v", err)
	}
	if _, _, s := byURL["b"].count(); s != 1 {
		t.Fatalf("result should have landed on discovered b, submits=%d", s)
	}
}

func TestFailoverAllDown(t *testing.T) {
	a := &fakeConn{url: "a"}
	b := &fakeConn{url: "b"}
	f, _ := newTestPool(t, a, b)
	f.discoverEnabled = false
	a.setDown(true)
	b.setDown(true)

	ctx := context.Background()
	if err := f.SubmitResult(ctx, protocol.SignedResult{}); err == nil {
		t.Fatal("expected error when every hub is down")
	}
	// Cooldowns are now set on both; a later call must still attempt delivery
	// (cooled-down hubs tried as a last resort), and succeed once a recovers.
	a.setDown(false)
	if err := f.SubmitResult(ctx, protocol.SignedResult{}); err != nil {
		t.Fatalf("recovered hub should be tried despite cooldown: %v", err)
	}
}

func TestFailoverNoHubs(t *testing.T) {
	f := NewFailoverClient(nil, false, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err := f.SubmitResult(context.Background(), protocol.SignedResult{}); !errors.Is(err, errNoHubs) {
		t.Fatalf("expected errNoHubs, got %v", err)
	}
}
