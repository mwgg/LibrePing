package p2p

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/mwgg/libreping/hub/trust"
	"github.com/mwgg/libreping/pkg/identity"
	"github.com/mwgg/libreping/pkg/protocol"
)

// TestGossipVerify brings up two in-process hubs, connects them, and asserts
// that a signed result published by one is verified and ingested by the other —
// while a tampered copy is rejected at the trust gate. This is the end-to-end
// proof of the decentralized + verifiable design.
func TestGossipVerify(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	idA, _ := identity.Generate()   // hub A identity
	idB, _ := identity.Generate()   // hub B identity
	probe, _ := identity.Generate() // the probe that signs the result

	var mu sync.Mutex
	var got []protocol.SignedResult
	ingestB := func(_ context.Context, sr protocol.SignedResult) {
		mu.Lock()
		got = append(got, sr)
		mu.Unlock()
	}

	a, err := New(ctx, Config{PrivateKey: idA.PrivateKey(), ListenAddrs: []string{"/ip4/127.0.0.1/tcp/0"}, Policy: trust.Open{}})
	if err != nil {
		t.Fatalf("new node A: %v", err)
	}
	defer a.Close()

	b, err := New(ctx, Config{PrivateKey: idB.PrivateKey(), ListenAddrs: []string{"/ip4/127.0.0.1/tcp/0"}, Policy: trust.Open{}, Ingest: ingestB})
	if err != nil {
		t.Fatalf("new node B: %v", err)
	}
	defer b.Close()

	// Connect A -> B directly (no DHT needed for the test).
	addrs := b.Addrs()
	if len(addrs) == 0 {
		t.Fatal("node B has no addresses")
	}
	if err := a.Connect(ctx, addrs[0]); err != nil {
		t.Fatalf("connect: %v", err)
	}

	// Wait for the gossipsub mesh to form (B appears among A's topic peers).
	waitForTopicPeer(t, a, b.ID())

	valid, err := protocol.SignResult(probe, protocol.ResultContent{
		CheckID: "c1", CheckType: protocol.CheckHTTP, Target: "https://example.com",
		Status: protocol.StatusUp, RTTMillis: 12.3,
		Location:    protocol.Location{Country: "DE", City: "Frankfurt"},
		TimestampMS: 1,
	})
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	// Publish the valid result; retry because mesh delivery is eventually
	// consistent.
	waitFor(t, 15*time.Second, func() bool {
		_ = a.PublishResult(ctx, valid)
		mu.Lock()
		defer mu.Unlock()
		return len(got) >= 1
	}, "node B never ingested the valid result")

	// Now publish a tampered copy: flip the status after signing so the
	// signature no longer matches. B must drop it.
	tampered := valid
	tampered.Content.Status = protocol.StatusDown
	for i := 0; i < 5; i++ {
		_ = a.PublishResult(ctx, tampered)
		time.Sleep(200 * time.Millisecond)
	}

	mu.Lock()
	defer mu.Unlock()
	for _, r := range got {
		if r.Content.Status == protocol.StatusDown {
			t.Fatal("tampered result was ingested; trust gate failed")
		}
	}
}

// TestCatalogGossipVerify mirrors TestGossipVerify for catalog entries: a check
// definition created on hub A propagates to hub B (proving global-catalog
// convergence), and a tampered entry is rejected.
func TestCatalogGossipVerify(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	idA, _ := identity.Generate()
	idB, _ := identity.Generate()

	var mu sync.Mutex
	var got []protocol.SignedCatalogEntry
	ingestCatalogB := func(_ context.Context, sc protocol.SignedCatalogEntry) {
		mu.Lock()
		got = append(got, sc)
		mu.Unlock()
	}

	a, err := New(ctx, Config{PrivateKey: idA.PrivateKey(), ListenAddrs: []string{"/ip4/127.0.0.1/tcp/0"}})
	if err != nil {
		t.Fatalf("new node A: %v", err)
	}
	defer a.Close()
	b, err := New(ctx, Config{PrivateKey: idB.PrivateKey(), ListenAddrs: []string{"/ip4/127.0.0.1/tcp/0"}, IngestCatalog: ingestCatalogB})
	if err != nil {
		t.Fatalf("new node B: %v", err)
	}
	defer b.Close()

	addrs := b.Addrs()
	if len(addrs) == 0 {
		t.Fatal("node B has no addresses")
	}
	if err := a.Connect(ctx, addrs[0]); err != nil {
		t.Fatalf("connect: %v", err)
	}
	waitForTopicPeer(t, a, b.ID())

	spec := protocol.CheckSpec{Type: protocol.CheckHTTP, Target: "https://example.com", IntervalSeconds: 60}
	spec.ID = spec.DeriveID()
	valid, err := protocol.SignCatalogEntry(idA, protocol.CatalogEntry{Spec: spec})
	if err != nil {
		t.Fatalf("sign catalog: %v", err)
	}

	waitFor(t, 15*time.Second, func() bool {
		_ = a.PublishCatalog(ctx, valid)
		mu.Lock()
		defer mu.Unlock()
		return len(got) >= 1
	}, "node B never ingested the valid catalog entry")

	tampered := valid
	tampered.Entry.Spec.Target = "https://evil.example.com"
	for i := 0; i < 5; i++ {
		_ = a.PublishCatalog(ctx, tampered)
		time.Sleep(200 * time.Millisecond)
	}
	mu.Lock()
	defer mu.Unlock()
	for _, e := range got {
		if e.Entry.Spec.Target == "https://evil.example.com" {
			t.Fatal("tampered catalog entry was ingested")
		}
	}
}

// TestSubscriptionGossipVerify confirms owner-signed subscriptions propagate
// and verify across hubs (and tampered ones are dropped).
func TestSubscriptionGossipVerify(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	idA, _ := identity.Generate()
	idB, _ := identity.Generate()
	owner, _ := identity.Generate()

	var mu sync.Mutex
	var got []protocol.SignedSubscription
	ingestB := func(_ context.Context, ss protocol.SignedSubscription) {
		mu.Lock()
		got = append(got, ss)
		mu.Unlock()
	}

	a, err := New(ctx, Config{PrivateKey: idA.PrivateKey(), ListenAddrs: []string{"/ip4/127.0.0.1/tcp/0"}})
	if err != nil {
		t.Fatalf("new A: %v", err)
	}
	defer a.Close()
	b, err := New(ctx, Config{PrivateKey: idB.PrivateKey(), ListenAddrs: []string{"/ip4/127.0.0.1/tcp/0"}, IngestSubscription: ingestB})
	if err != nil {
		t.Fatalf("new B: %v", err)
	}
	defer b.Close()

	if err := a.Connect(ctx, b.Addrs()[0]); err != nil {
		t.Fatalf("connect: %v", err)
	}
	waitForTopicPeer(t, a, b.ID())

	valid := protocol.SignSubscription(owner, protocol.Subscription{CheckID: "abc", IntervalSeconds: 60, ExpiryMS: 999})
	waitFor(t, 15*time.Second, func() bool {
		_ = a.PublishSubscription(ctx, valid)
		mu.Lock()
		defer mu.Unlock()
		return len(got) >= 1
	}, "node B never ingested the subscription")

	tampered := valid
	tampered.Subscription.CheckID = "hijacked"
	for i := 0; i < 5; i++ {
		_ = a.PublishSubscription(ctx, tampered)
		time.Sleep(200 * time.Millisecond)
	}
	mu.Lock()
	defer mu.Unlock()
	for _, s := range got {
		if s.Subscription.CheckID == "hijacked" {
			t.Fatal("tampered subscription was ingested")
		}
	}
}

// TestResultSyncOnConnect proves the catch-up sync: hub A already holds a
// result that hub B never received via gossip (B was not connected when it was
// published). When B connects, it pulls A's recent results over the sync stream
// and ingests them — so a late-joining hub converges on history, not just future
// gossip. The pulled result is re-verified, so the relaying peer isn't trusted.
func TestResultSyncOnConnect(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	idA, _ := identity.Generate()
	idB, _ := identity.Generate()
	probe, _ := identity.Generate()

	missed, err := protocol.SignResult(probe, protocol.ResultContent{
		CheckID: "c1", CheckType: protocol.CheckHTTP, Target: "https://example.com",
		Status: protocol.StatusUp, TimestampMS: time.Now().UnixMilli(),
	})
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	// A serves its stored results to sync requests.
	resultsSince := func(_ context.Context, sinceMS int64, _ int) ([]protocol.SignedResult, error) {
		return []protocol.SignedResult{missed}, nil
	}
	a, err := New(ctx, Config{PrivateKey: idA.PrivateKey(), ListenAddrs: []string{"/ip4/127.0.0.1/tcp/0"}, ResultsSince: resultsSince})
	if err != nil {
		t.Fatalf("new A: %v", err)
	}
	defer a.Close()

	var mu sync.Mutex
	var got []protocol.SignedResult
	b, err := New(ctx, Config{
		PrivateKey: idB.PrivateKey(), ListenAddrs: []string{"/ip4/127.0.0.1/tcp/0"},
		Ingest: func(_ context.Context, sr protocol.SignedResult) {
			mu.Lock()
			got = append(got, sr)
			mu.Unlock()
		},
	})
	if err != nil {
		t.Fatalf("new B: %v", err)
	}
	defer b.Close()

	// B connects to A; B's connect notifiee triggers the catch-up sync.
	if err := b.Connect(ctx, a.Addrs()[0]); err != nil {
		t.Fatalf("connect: %v", err)
	}

	waitFor(t, 15*time.Second, func() bool {
		mu.Lock()
		defer mu.Unlock()
		return len(got) >= 1
	}, "node B never synced the missed result from A")

	mu.Lock()
	defer mu.Unlock()
	if got[0].Content.CheckID != "c1" {
		t.Fatalf("unexpected synced result: %+v", got[0].Content)
	}
}

// TestControlSyncOnConnect proves the control-plane catch-up: hub A already
// holds a catalog entry and a subscription that hub B never received via gossip.
// When B connects, it pulls A's control plane over the control-sync stream and
// ingests both (re-verified), so a freshly-joined hub has the monitors to assign
// to its probes immediately instead of waiting for the next periodic re-broadcast.
func TestControlSyncOnConnect(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	idA, _ := identity.Generate()
	idB, _ := identity.Generate()
	owner, _ := identity.Generate()

	spec := protocol.CheckSpec{Type: protocol.CheckHTTP, Target: "https://example.com", IntervalSeconds: 60}
	spec.ID = spec.DeriveID()
	entry, err := protocol.SignCatalogEntry(idA, protocol.CatalogEntry{Spec: spec})
	if err != nil {
		t.Fatalf("sign catalog: %v", err)
	}
	sub := protocol.SignSubscription(owner, protocol.Subscription{CheckID: spec.ID, IntervalSeconds: 60, ExpiryMS: 999})

	// A serves its control plane to a connecting peer's control-sync.
	a, err := New(ctx, Config{
		PrivateKey: idA.PrivateKey(), ListenAddrs: []string{"/ip4/127.0.0.1/tcp/0"},
		CatalogSnapshot: func(context.Context) ([]protocol.SignedCatalogEntry, error) {
			return []protocol.SignedCatalogEntry{entry}, nil
		},
		SubscriptionSnapshot: func(context.Context) ([]protocol.SignedSubscription, error) {
			return []protocol.SignedSubscription{sub}, nil
		},
	})
	if err != nil {
		t.Fatalf("new A: %v", err)
	}
	defer a.Close()

	var mu sync.Mutex
	var gotCatalog, gotSubs int
	b, err := New(ctx, Config{
		PrivateKey: idB.PrivateKey(), ListenAddrs: []string{"/ip4/127.0.0.1/tcp/0"},
		IngestCatalog: func(_ context.Context, _ protocol.SignedCatalogEntry) {
			mu.Lock()
			gotCatalog++
			mu.Unlock()
		},
		IngestSubscription: func(_ context.Context, _ protocol.SignedSubscription) {
			mu.Lock()
			gotSubs++
			mu.Unlock()
		},
	})
	if err != nil {
		t.Fatalf("new B: %v", err)
	}
	defer b.Close()

	// B connects to A; B's connect notifiee triggers the control-plane catch-up.
	if err := b.Connect(ctx, a.Addrs()[0]); err != nil {
		t.Fatalf("connect: %v", err)
	}

	waitFor(t, 15*time.Second, func() bool {
		mu.Lock()
		defer mu.Unlock()
		return gotCatalog >= 1 && gotSubs >= 1
	}, "node B never control-synced the catalog + subscription from A")
}

func TestFilterDialable(t *testing.T) {
	// A real, parseable peer ID is required (a /p2p component must be a valid id).
	id, _ := identity.Generate()
	priv, _ := crypto.UnmarshalEd25519PrivateKey(id.PrivateKey())
	pid, _ := peer.IDFromPrivateKey(priv)
	p := "/p2p/" + pid.String()

	pub := "/ip4/8.8.8.8/tcp/4001" + p
	addrs := []string{
		pub,
		"/ip4/127.0.0.1/tcp/4001" + p,   // loopback
		"/ip4/10.0.0.5/tcp/4001" + p,    // private
		"/ip4/192.168.1.9/tcp/4001" + p, // private
		"/ip4/8.8.4.4/tcp/4001",         // public but no /p2p id
		"not-a-multiaddr",               // malformed
	}

	// Default policy: only the public address survives.
	got := FilterDialable(addrs, false)
	if len(got) != 1 || got[0] != pub {
		t.Fatalf("expected only the public addr, got %v", got)
	}

	// allowPrivate keeps the private/loopback ones too, still dropping malformed.
	got = FilterDialable(addrs, true)
	if len(got) != 4 {
		t.Fatalf("expected 4 valid addrs with allowPrivate, got %v", got)
	}
}

// TestShardScopedDelivery proves the Phase 2 property: a hub that holds only a
// subset of shards receives results for those shards and NOT for others.
func TestShardScopedDelivery(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	idA, _ := identity.Generate()
	idB, _ := identity.Generate()
	probe, _ := identity.Generate()

	// Two checks in different shards.
	heldCheck := "00000000000000aa"  // shard 0
	otherCheck := "00010000000000bb" // shard 1
	if shardOf(heldCheck) == shardOf(otherCheck) {
		t.Fatal("test setup: checks must be in different shards")
	}

	var mu sync.Mutex
	got := map[string]bool{}
	a, err := New(ctx, Config{PrivateKey: idA.PrivateKey(), ListenAddrs: []string{"/ip4/127.0.0.1/tcp/0"}})
	if err != nil {
		t.Fatalf("new A: %v", err)
	}
	defer a.Close()
	b, err := New(ctx, Config{
		PrivateKey: idB.PrivateKey(), ListenAddrs: []string{"/ip4/127.0.0.1/tcp/0"},
		Ingest: func(_ context.Context, sr protocol.SignedResult) {
			mu.Lock()
			got[sr.Content.CheckID] = true
			mu.Unlock()
		},
	})
	if err != nil {
		t.Fatalf("new B: %v", err)
	}
	defer b.Close()

	// Narrow B to hold only shard 0.
	b.UpdateShards(ctx, map[uint32]bool{shardOf(heldCheck): true})

	if err := a.Connect(ctx, b.Addrs()[0]); err != nil {
		t.Fatalf("connect: %v", err)
	}
	waitForTopicPeer(t, a, b.ID())

	held := signResult(t, probe, heldCheck)
	other := signResult(t, probe, otherCheck)

	// B must receive the held-shard result (retry for mesh formation).
	waitFor(t, 15*time.Second, func() bool {
		_ = a.PublishResult(ctx, held)
		_ = a.PublishResult(ctx, other)
		mu.Lock()
		defer mu.Unlock()
		return got[heldCheck]
	}, "B never received the result for its held shard")

	// Give the other-shard result ample chance to (wrongly) arrive, then assert
	// it did not.
	for i := 0; i < 5; i++ {
		_ = a.PublishResult(ctx, other)
		time.Sleep(150 * time.Millisecond)
	}
	mu.Lock()
	defer mu.Unlock()
	if got[otherCheck] {
		t.Fatal("B received a result for a shard it does not hold")
	}
}

func shardOf(checkID string) uint32 {
	// Local mirror to avoid importing the shard package into the test for one call.
	v := uint32(0)
	for _, c := range checkID[:4] {
		v = v*16 + uint32(hexVal(c))
	}
	return v % 64
}

func hexVal(c rune) int {
	switch {
	case c >= '0' && c <= '9':
		return int(c - '0')
	case c >= 'a' && c <= 'f':
		return int(c-'a') + 10
	}
	return 0
}

func signResult(t *testing.T, probe *identity.Identity, checkID string) protocol.SignedResult {
	t.Helper()
	sr, err := protocol.SignResult(probe, protocol.ResultContent{
		CheckID: checkID, CheckType: protocol.CheckHTTP, Target: "https://example.com",
		Status: protocol.StatusUp, TimestampMS: time.Now().UnixMilli(),
	})
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	return sr
}

func waitForTopicPeer(t *testing.T, n *Node, want peer.ID) {
	t.Helper()
	waitFor(t, 15*time.Second, func() bool {
		for _, p := range n.TopicPeers() {
			if p == want {
				return true
			}
		}
		return false
	}, "peer never joined the topic mesh")
}

func waitFor(t *testing.T, d time.Duration, cond func() bool, msg string) {
	t.Helper()
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(150 * time.Millisecond)
	}
	t.Fatal(msg)
}
