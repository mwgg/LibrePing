package alert

import (
	"context"
	"encoding/base64"
	"errors"
	"sync"
	"testing"

	"github.com/mwgg/libreping/hub/encbox"
	"github.com/mwgg/libreping/hub/store"
	"github.com/mwgg/libreping/pkg/identity"
	"github.com/mwgg/libreping/pkg/protocol"
)

func TestResponsibleAmongExactlyOneWinner(t *testing.T) {
	candidates := []string{"hubA", "hubB", "hubC"}
	key := "rule-key-1"

	wins := 0
	for _, self := range candidates {
		if ResponsibleAmong(self, candidates, key) {
			wins++
		}
	}
	if wins != 1 {
		t.Fatalf("expected exactly one responsible hub, got %d", wins)
	}

	// A hub not in the candidate set is never responsible (it can't decrypt).
	if ResponsibleAmong("outsider", candidates, key) {
		t.Fatal("a non-candidate hub claimed responsibility")
	}
	// Failover: drop the current winner; exactly one of the rest takes over.
	winner := ""
	for _, self := range candidates {
		if ResponsibleAmong(self, candidates, key) {
			winner = self
		}
	}
	var rest []string
	for _, h := range candidates {
		if h != winner {
			rest = append(rest, h)
		}
	}
	wins = 0
	for _, self := range rest {
		if ResponsibleAmong(self, rest, key) {
			wins++
		}
	}
	if wins != 1 {
		t.Fatalf("after failover expected exactly one responsible hub, got %d", wins)
	}
}

// flakyNotifier fails while fail is true; records notifications otherwise.
type flakyNotifier struct {
	mu   sync.Mutex
	fail bool
	n    []Notification
}

func (f *flakyNotifier) Notify(_ context.Context, n Notification) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.fail {
		return errors.New("delivery boom")
	}
	f.n = append(f.n, n)
	return nil
}
func (f *flakyNotifier) count() int     { f.mu.Lock(); defer f.mu.Unlock(); return len(f.n) }
func (f *flakyNotifier) setFail(v bool) { f.mu.Lock(); f.fail = v; f.mu.Unlock() }

func downResult(check, probe string, ts int64) protocol.SignedResult {
	return protocol.SignedResult{Content: protocol.ResultContent{CheckID: check, ProbeID: probe, Target: "https://x", Status: protocol.StatusDown, TimestampMS: ts}}
}
func upResult(check, probe string, ts int64) protocol.SignedResult {
	return protocol.SignedResult{Content: protocol.ResultContent{CheckID: check, ProbeID: probe, Target: "https://x", Status: protocol.StatusUp, TimestampMS: ts}}
}

// engineFixture wires an engine whose single recipient is itself.
func engineFixture(t *testing.T, notifier Notifier) (*Engine, *store.MemAlerts, *store.MemStore, protocol.AlertRule) {
	t.Helper()
	hubID, _ := identity.Generate()
	enc := encbox.FromSeed(hubID.Seed())
	sealed, _ := encbox.Seal([]byte("https://hook"), enc.PublicKey())

	rule := protocol.AlertRule{
		Owner: "owner1", CheckID: "chk", Channel: protocol.AlertWebhook,
		DestHash:      "deadbeef",
		Recipients:    map[string]string{hubID.NodeID(): base64.StdEncoding.EncodeToString(sealed)},
		FailLocations: 2, ForSeconds: 0,
	}
	alerts := store.NewMemAlerts()
	results := store.NewMemStore()
	_ = alerts.Upsert(context.Background(), protocol.SignedAlertRule{Rule: rule})

	eng := NewEngine(hubID, alerts, results, func() []string { return nil }, enc.Open,
		func(context.Context, protocol.SignedDeliveryState) {},
		map[protocol.AlertChannel]Notifier{protocol.AlertWebhook: notifier}, nil)
	return eng, alerts, results, rule
}

func TestEngineRetriesThenDeliversOnceThenRecovers(t *testing.T) {
	ctx := context.Background()
	nf := &flakyNotifier{fail: true}
	eng, _, results, _ := engineFixture(t, nf)

	_ = results.Insert(ctx, downResult("chk", "pa", 100))
	_ = results.Insert(ctx, downResult("chk", "pb", 100))

	// Delivery fails → nothing recorded, so it must be retried (not lost).
	eng.Evaluate(ctx)
	if nf.count() != 0 {
		t.Fatalf("failed delivery should record nothing, got %d", nf.count())
	}

	// Now delivery succeeds → fires once.
	nf.setFail(false)
	eng.Evaluate(ctx)
	if nf.count() != 1 {
		t.Fatalf("expected 1 delivery after recovery of the webhook, got %d", nf.count())
	}
	if nf.n[0].Destination != "https://hook" {
		t.Fatalf("destination not decrypted: %q", nf.n[0].Destination)
	}

	// Stable down state → no duplicate.
	eng.Evaluate(ctx)
	if nf.count() != 1 {
		t.Fatalf("stable state must not re-deliver, got %d", nf.count())
	}

	// Service recovers → one more delivery (the "up" transition).
	_ = results.Insert(ctx, upResult("chk", "pa", 200))
	_ = results.Insert(ctx, upResult("chk", "pb", 200))
	eng.Evaluate(ctx)
	if nf.count() != 2 || nf.n[1].Status != protocol.StatusUp {
		t.Fatalf("expected recovery delivery, got %d", nf.count())
	}
}

func TestInheritedDeliveryStateSuppressesDuplicate(t *testing.T) {
	ctx := context.Background()
	nf := &flakyNotifier{}
	eng, alerts, results, rule := engineFixture(t, nf)

	_ = results.Insert(ctx, downResult("chk", "pa", 100))
	_ = results.Insert(ctx, downResult("chk", "pb", 100))

	// Simulate a delivery already done by a recipient hub (this hub's own ID, as
	// if learned via gossip / restart): the engine must not re-deliver.
	_, _ = alerts.MergeDelivery(ctx, rule.ID(), store.Delivery{Status: protocol.StatusDown, HubID: eng.self, TimestampMS: 50})
	eng.Evaluate(ctx)
	if nf.count() != 0 {
		t.Fatalf("inherited down state must suppress duplicate, got %d", nf.count())
	}
}

func TestDeliveryStateFromNonRecipientIgnored(t *testing.T) {
	ctx := context.Background()
	nf := &flakyNotifier{}
	eng, alerts, results, rule := engineFixture(t, nf)

	_ = results.Insert(ctx, downResult("chk", "pa", 100))
	_ = results.Insert(ctx, downResult("chk", "pb", 100))

	// A delivery-state authored by a hub NOT in the rule's recipients must be
	// ignored, so it cannot suppress a real alert.
	_, _ = alerts.MergeDelivery(ctx, rule.ID(), store.Delivery{Status: protocol.StatusDown, HubID: "stranger-hub", TimestampMS: 50})
	eng.Evaluate(ctx)
	if nf.count() != 1 {
		t.Fatalf("non-recipient state must not suppress; expected 1 delivery, got %d", nf.count())
	}
}

// TestFutureStrangerStateCannotShadow proves the per-(rule,hub) storage closes
// the poisoning gap: a recipient's real delivery still suppresses duplicates
// even when a non-recipient has written a higher-timestamp "down" state.
func TestFutureStrangerStateCannotShadow(t *testing.T) {
	ctx := context.Background()
	nf := &flakyNotifier{}
	eng, alerts, results, rule := engineFixture(t, nf)

	_ = results.Insert(ctx, downResult("chk", "pa", 100))
	_ = results.Insert(ctx, downResult("chk", "pb", 100))

	// The legitimate recipient (this hub) has already delivered "down".
	_, _ = alerts.MergeDelivery(ctx, rule.ID(), store.Delivery{Status: protocol.StatusDown, HubID: eng.self, TimestampMS: 50})
	// A stranger writes a far-future "down" that, under the old single-key
	// last-writer-wins, would shadow the recipient's state and force re-delivery.
	_, _ = alerts.MergeDelivery(ctx, rule.ID(), store.Delivery{Status: protocol.StatusDown, HubID: "stranger-hub", TimestampMS: 1 << 40})

	eng.Evaluate(ctx)
	if nf.count() != 0 {
		t.Fatalf("stranger future state must not shadow recipient's; expected 0 deliveries, got %d", nf.count())
	}
}
