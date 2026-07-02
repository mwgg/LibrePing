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

// signedAnnFor signs an announcement for a FIXED identity so a test can model a
// single hub re-announcing over time (LWW is keyed on hub ID + TimestampMS).
func signedAnnFor(t *testing.T, id *identity.Identity, ann protocol.HubAnnouncement) protocol.SignedHubAnnouncement {
	t.Helper()
	sa, err := protocol.SignHubAnnouncement(id, ann)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	return sa
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
	waitIdle(d)
	l := d.List()
	if len(l) != 1 || l[0].PublicURL != "https://a.example" {
		t.Fatalf("expected directory to keep serving verified A, got %+v", l)
	}

	// Once B becomes reachable, a fresh re-announcement (newer TimestampMS, as a
	// real hub stamps each advertise tick) is promoted through full verification.
	mu.Lock()
	allow["https://b.example"] = true
	mu.Unlock()
	annB2, _ := protocol.SignHubAnnouncement(id, protocol.HubAnnouncement{PublicURL: "https://b.example", TimestampMS: 3})
	d.Add(context.Background(), annB2)
	for i := 0; i < 50; i++ {
		if l := d.List(); len(l) == 1 && l[0].PublicURL == "https://b.example" {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("expected B to be promoted after it verified, got %+v", d.List())
}

// idle waits until no verifier goroutine is in flight for the directory.
func (d *Directory) idle() bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	return len(d.verifying) == 0
}

func waitIdle(d *Directory) {
	for i := 0; i < 200; i++ {
		if d.idle() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// TestDirectoryVerifyBackoff proves a hub whose URL keeps failing is not
// re-verified on every announcement: within the cooldown, repeated announcements
// do not trigger a new outbound reachability check.
func TestDirectoryVerifyBackoff(t *testing.T) {
	d := New("self", time.Minute, false, nil)

	var mu sync.Mutex
	calls := 0
	d.verify = func(context.Context, string, string) bool {
		mu.Lock()
		calls++
		mu.Unlock()
		return false // never verifies
	}
	fake := time.Unix(1_000_000, 0)
	d.now = func() time.Time { mu.Lock(); defer mu.Unlock(); return fake }

	// One hub re-announcing the same failing URL over time. Each honest
	// re-announcement carries a strictly newer TimestampMS (the LWW version key),
	// so the backoff — not the LWW replay guard — is what suppresses re-verifying.
	id, _ := identity.Generate()
	ann := func(ts int64) protocol.SignedHubAnnouncement {
		return signedAnnFor(t, id, protocol.HubAnnouncement{PublicURL: "https://bad.example", TimestampMS: ts})
	}

	d.Add(context.Background(), ann(1))
	waitIdle(d)
	mu.Lock()
	first := calls
	mu.Unlock()
	if first != 1 {
		t.Fatalf("expected 1 verify attempt, got %d", first)
	}

	// Re-announce (newer ts) within the cooldown: must NOT re-verify.
	d.Add(context.Background(), ann(2))
	waitIdle(d)
	mu.Lock()
	second := calls
	mu.Unlock()
	if second != 1 {
		t.Fatalf("backoff failed: re-verified within cooldown, calls=%d", second)
	}

	// Advance past the cooldown: a fresh announcement re-verifies.
	mu.Lock()
	fake = fake.Add(verifyCooldown + time.Second)
	mu.Unlock()
	d.Add(context.Background(), ann(3))
	waitIdle(d)
	mu.Lock()
	third := calls
	mu.Unlock()
	if third != 2 {
		t.Fatalf("expected re-verify after cooldown, calls=%d", third)
	}
}

// TestDirectoryEntryCap proves the directory never tracks more than maxEntries
// hubs, so a Sybil minting fresh HubIDs can't grow it without bound.
func TestDirectoryEntryCap(t *testing.T) {
	d := New("self", time.Minute, false, nil)
	d.verify = func(context.Context, string, string) bool { return false }

	for i := 0; i < maxEntries+200; i++ {
		sa, _ := signedAnn(t, "https://peer.example")
		d.Add(context.Background(), sa)
	}
	waitIdle(d)
	d.mu.Lock()
	n := len(d.entries)
	d.mu.Unlock()
	if n > maxEntries {
		t.Fatalf("entry cap breached: %d > %d", n, maxEntries)
	}
}

// TestDirectoryActiveWithinPrunesIdle proves ActiveWithin (not just List) reclaims
// entries idle past the display TTL, so an alert-only hot path doesn't leak.
func TestDirectoryActiveWithinPrunesIdle(t *testing.T) {
	d := New("self", time.Minute, false, nil)
	d.verify = func(context.Context, string, string) bool { return true }

	var mu sync.Mutex
	fake := time.Unix(2_000_000, 0)
	d.now = func() time.Time { mu.Lock(); defer mu.Unlock(); return fake }

	sa, _ := signedAnn(t, "https://peer.example")
	d.Add(context.Background(), sa)
	waitIdle(d)
	if l := d.ActiveWithin(time.Minute); len(l) != 1 {
		t.Fatalf("expected 1 active hub, got %d", len(l))
	}

	// Advance past the display TTL and query only via ActiveWithin.
	mu.Lock()
	fake = fake.Add(2 * time.Minute)
	mu.Unlock()
	if l := d.ActiveWithin(time.Minute); len(l) != 0 {
		t.Fatalf("expected 0 active after TTL, got %d", len(l))
	}
	d.mu.Lock()
	n := len(d.entries)
	d.mu.Unlock()
	if n != 0 {
		t.Fatalf("ActiveWithin did not prune idle entry: %d remain", n)
	}
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

// TestDirectoryLWWRejectsReplay proves an OLDER (by TimestampMS) announcement
// cannot overwrite a newer stored one — so a peer can't replay a hub's stale
// signed announcement to regress its capacity or (the sharp edge) its EncPubKey.
func TestDirectoryLWWRejectsReplay(t *testing.T) {
	d := New("self", time.Minute, false, nil)
	d.verify = func(context.Context, string, string) bool { return true }

	id, _ := identity.Generate()
	url := "https://peer.example"
	newKey := []byte("new-enc-key")
	oldKey := []byte("old-enc-key")

	// Newer announcement first: capacity 50, new key, ts 200.
	newer := signedAnnFor(t, id, protocol.HubAnnouncement{
		PublicURL: url, TimestampMS: 200, StorageCapacity: 50, EncPubKey: newKey,
	})
	d.Add(context.Background(), newer)
	waitIdle(d)
	if l := d.List(); len(l) != 1 || l[0].StorageCapacity != 50 {
		t.Fatalf("expected newer announcement listed, got %+v", l)
	}

	// Replay an OLDER announcement (ts 100, capacity 10, old key). Must be dropped.
	older := signedAnnFor(t, id, protocol.HubAnnouncement{
		PublicURL: url, TimestampMS: 100, StorageCapacity: 10, EncPubKey: oldKey,
	})
	d.Add(context.Background(), older)
	waitIdle(d)
	l := d.List()
	if len(l) != 1 {
		t.Fatalf("expected 1 hub after replay, got %d", len(l))
	}
	if l[0].StorageCapacity != 50 {
		t.Fatalf("replay regressed capacity to %d", l[0].StorageCapacity)
	}
	if string(l[0].EncPubKey) != string(newKey) {
		t.Fatalf("replay regressed EncPubKey to %q", l[0].EncPubKey)
	}

	// An announcement with the SAME timestamp is also rejected (reject <=).
	sameTS := signedAnnFor(t, id, protocol.HubAnnouncement{
		PublicURL: url, TimestampMS: 200, StorageCapacity: 7, EncPubKey: oldKey,
	})
	d.Add(context.Background(), sameTS)
	waitIdle(d)
	if l := d.List(); len(l) != 1 || l[0].StorageCapacity != 50 || string(l[0].EncPubKey) != string(newKey) {
		t.Fatalf("same-timestamp announcement regressed the entry: %+v", l)
	}
}

// TestDirectorySameURLRefreshNoReverify proves a NEWER same-URL announcement
// refreshes the verified entry's fields (capacity/archive/EncPubKey/P2PAddrs)
// in place WITHOUT triggering a second reachability verification — the
// hubID↔URL binding is unchanged, so re-fetching /identity is unnecessary.
func TestDirectorySameURLRefreshNoReverify(t *testing.T) {
	d := New("self", time.Minute, false, nil)
	var mu sync.Mutex
	calls := 0
	d.verify = func(context.Context, string, string) bool {
		mu.Lock()
		calls++
		mu.Unlock()
		return true
	}

	id, _ := identity.Generate()
	url := "https://peer.example"
	a1 := signedAnnFor(t, id, protocol.HubAnnouncement{
		PublicURL: url, TimestampMS: 1, StorageCapacity: 10,
		EncPubKey: []byte("k1"), P2PAddrs: []string{"/ip4/1.2.3.4/tcp/4001/p2p/x"},
	})
	d.Add(context.Background(), a1)
	waitIdle(d)
	mu.Lock()
	first := calls
	mu.Unlock()
	if first != 1 {
		t.Fatalf("expected 1 verify for first announcement, got %d", first)
	}

	// Newer announcement, SAME URL, rotated key + changed capacity/archive/addrs.
	a2 := signedAnnFor(t, id, protocol.HubAnnouncement{
		PublicURL: url, TimestampMS: 2, StorageCapacity: 99, StorageArchive: true,
		EncPubKey: []byte("k2-rotated"), P2PAddrs: []string{"/ip4/5.6.7.8/tcp/4001/p2p/y"},
	})
	d.Add(context.Background(), a2)
	waitIdle(d)
	mu.Lock()
	second := calls
	mu.Unlock()
	if second != 1 {
		t.Fatalf("same-URL refresh must not re-verify, calls=%d", second)
	}

	l := d.List()
	if len(l) != 1 {
		t.Fatalf("expected 1 hub, got %d", len(l))
	}
	got := l[0]
	if got.StorageCapacity != 99 || !got.StorageArchive {
		t.Fatalf("capacity/archive not refreshed: %+v", got)
	}
	if string(got.EncPubKey) != "k2-rotated" {
		t.Fatalf("EncPubKey rotation not applied: %q", got.EncPubKey)
	}
	if len(got.P2PAddrs) != 1 || got.P2PAddrs[0] != "/ip4/5.6.7.8/tcp/4001/p2p/y" {
		t.Fatalf("P2PAddrs not refreshed: %+v", got.P2PAddrs)
	}
}

// TestDirectoryRejectsFarFuture proves an announcement stamped implausibly far
// in the future is dropped, so a hub (or forger) can't pin its entry against
// every later honest re-announcement with a bogus max TimestampMS.
func TestDirectoryRejectsFarFuture(t *testing.T) {
	d := New("self", time.Minute, false, nil)
	d.verify = func(context.Context, string, string) bool { return true }

	var mu sync.Mutex
	fake := time.Unix(1_000_000, 0)
	d.now = func() time.Time { mu.Lock(); defer mu.Unlock(); return fake }

	id, _ := identity.Generate()
	future := fake.UnixMilli() + maxAnnFutureSkewMS + 60_000
	sa := signedAnnFor(t, id, protocol.HubAnnouncement{PublicURL: "https://peer.example", TimestampMS: future})
	d.Add(context.Background(), sa)
	waitIdle(d)
	if l := d.List(); len(l) != 0 {
		t.Fatalf("far-future announcement must be dropped, got %+v", l)
	}
	d.mu.Lock()
	n := len(d.entries)
	d.mu.Unlock()
	if n != 0 {
		t.Fatalf("far-future announcement created an entry: %d", n)
	}
}
