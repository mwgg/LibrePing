package directory

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/mwgg/libreping/pkg/identity"
	"github.com/mwgg/libreping/pkg/protocol"
)

func signedAnn(t *testing.T, url string) (protocol.SignedHubAnnouncement, string) {
	t.Helper()
	id, _ := identity.Generate()
	sa, err := protocol.SignHubAnnouncement(id, protocol.HubAnnouncement{PublicURL: url, TimestampMS: 1})
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	return sa, id.NodeID()
}

// waitList polls until the directory lists at least one hub or times out.
func waitList(d *Directory) []protocol.HubAnnouncement {
	for i := 0; i < 50; i++ {
		if l := d.List(); len(l) > 0 {
			return l
		}
		time.Sleep(10 * time.Millisecond)
	}
	return d.List()
}

func TestDirectoryListsOnlyReachabilityVerified(t *testing.T) {
	d := New("self-id", time.Minute, false, nil)

	good, goodID := signedAnn(t, "https://good.example")
	bad, _ := signedAnn(t, "https://bad.example")

	// Only the "good" URL passes the reachability/identity check.
	d.verify = func(_ context.Context, url, expectID string) bool {
		return url == "https://good.example" && expectID == goodID
	}

	d.Add(context.Background(), good)
	d.Add(context.Background(), bad)

	list := waitList(d)
	if len(list) != 1 {
		t.Fatalf("expected 1 verified hub, got %d", len(list))
	}
	if list[0].HubID != goodID {
		t.Fatal("listed the wrong hub")
	}
}

func TestDirectorySkipsSelf(t *testing.T) {
	id, _ := identity.Generate()
	d := New(id.NodeID(), time.Minute, false, nil)
	d.verify = func(context.Context, string, string) bool { return true }

	sa, _ := protocol.SignHubAnnouncement(id, protocol.HubAnnouncement{PublicURL: "https://me.example", TimestampMS: 1})
	d.Add(context.Background(), sa)

	time.Sleep(50 * time.Millisecond)
	if len(d.List()) != 0 {
		t.Fatal("directory listed the hub's own announcement")
	}
}

// TestDirectoryDoesNotServeUnverifiedURLChange covers the verified-state-reuse
// bug: a hub that is verified at one URL re-announces a new URL. Until the new
// URL passes its own check, the directory must keep serving the OLD verified URL
// and never expose the new (unverified) one.
func TestDirectoryDoesNotServeUnverifiedURLChange(t *testing.T) {
	d := New("self-id", time.Minute, false, nil)

	id, _ := identity.Generate()
	hubID := id.NodeID()
	annA, _ := protocol.SignHubAnnouncement(id, protocol.HubAnnouncement{PublicURL: "https://a.example", TimestampMS: 1})
	annB, _ := protocol.SignHubAnnouncement(id, protocol.HubAnnouncement{PublicURL: "https://b.example", TimestampMS: 2})

	// Only URL A ever verifies; B (the "swapped" URL) always fails.
	var mu sync.Mutex
	allow := map[string]bool{"https://a.example": true}
	d.verify = func(_ context.Context, url, expectID string) bool {
		mu.Lock()
		defer mu.Unlock()
		return allow[url] && expectID == hubID
	}

	d.Add(context.Background(), annA)
	if l := waitList(d); len(l) != 1 || l[0].PublicURL != "https://a.example" {
		t.Fatalf("expected A verified, got %+v", l)
	}

	// Re-announce a new, unverifiable URL. The directory must keep serving A.
	d.Add(context.Background(), annB)
	time.Sleep(60 * time.Millisecond)
	l := d.List()
	if len(l) != 1 || l[0].PublicURL != "https://a.example" {
		t.Fatalf("expected directory to keep serving verified A, got %+v", l)
	}

	// Once B becomes reachable and re-announced, it should be promoted.
	mu.Lock()
	allow["https://b.example"] = true
	mu.Unlock()
	d.Add(context.Background(), annB)
	for i := 0; i < 50; i++ {
		if l := d.List(); len(l) == 1 && l[0].PublicURL == "https://b.example" {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("expected B to be promoted after it verified, got %+v", d.List())
}

func TestDirectoryTTLEviction(t *testing.T) {
	d := New("self", time.Minute, false, nil)
	d.verify = func(context.Context, string, string) bool { return true }

	var mu sync.Mutex
	fake := time.Unix(1_000_000, 0)
	mu.Lock()
	d.now = func() time.Time { mu.Lock(); defer mu.Unlock(); return fake }
	mu.Unlock()

	sa, _ := signedAnn(t, "https://peer.example")
	d.Add(context.Background(), sa)
	if l := waitList(d); len(l) != 1 {
		t.Fatalf("expected hub listed before TTL, got %d", len(l))
	}

	// Advance past TTL.
	mu.Lock()
	fake = fake.Add(2 * time.Minute)
	mu.Unlock()
	if l := d.List(); len(l) != 0 {
		t.Fatalf("expected eviction after TTL, got %d", len(l))
	}
}
