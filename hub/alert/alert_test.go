package alert

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/mwgg/libreping/hub/encbox"
	"github.com/mwgg/libreping/hub/store"
	"github.com/mwgg/libreping/pkg/identity"
	"github.com/mwgg/libreping/pkg/protocol"
)

// testNowMS is the fixed "now" the engine sees in tests. Result timestamps are
// expressed relative to it so they land inside the freshness window regardless
// of wall-clock time when the test runs.
const testNowMS = int64(1_700_000_000_000)

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
	eng, alerts, results, _, rule := engineFixtureMaint(t, notifier)
	return eng, alerts, results, rule
}

// engineFixtureMaint is engineFixture plus the maintenance store, for tests that
// need to schedule planned-downtime windows.
func engineFixtureMaint(t *testing.T, notifier Notifier) (*Engine, *store.MemAlerts, *store.MemStore, *store.MemMaintenance, protocol.AlertRule) {
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
	maint := store.NewMemMaintenance()
	_ = alerts.Upsert(context.Background(), protocol.SignedAlertRule{Rule: rule})

	eng := NewEngine(hubID, alerts, results, maint, func() []string { return nil }, enc.Open,
		func(context.Context, protocol.SignedDeliveryState) {},
		map[protocol.AlertChannel]Notifier{protocol.AlertWebhook: notifier}, nil)
	eng.now = func() time.Time { return time.UnixMilli(testNowMS) }
	return eng, alerts, results, maint, rule
}

// losingPeer returns a hub ID that loses the rendezvous for key to self, so that
// among {self, peer} this hub is the responsible one. That lets a test cast the
// peer as a NON-responsible recipient (the delivery-state poisoning attacker).
func losingPeer(t *testing.T, self, key string) string {
	t.Helper()
	for i := 0; i < 100000; i++ {
		cand := fmt.Sprintf("peer-hub-%d", i)
		if ResponsibleAmong(self, []string{self, cand}, key) {
			return cand
		}
	}
	t.Fatal("could not find a peer that loses rendezvous to self")
	return ""
}

// twoRecipientFixture wires an engine that is one of TWO live recipients and is
// the responsible one; peer is the other (non-responsible) recipient.
func twoRecipientFixture(t *testing.T, notifier Notifier) (*Engine, *store.MemAlerts, *store.MemStore, protocol.AlertRule, string) {
	t.Helper()
	hubID, _ := identity.Generate()
	enc := encbox.FromSeed(hubID.Seed())
	sealed, _ := encbox.Seal([]byte("https://hook"), enc.PublicKey())

	rule := protocol.AlertRule{
		Owner: "owner1", CheckID: "chk", Channel: protocol.AlertWebhook,
		DestHash:      "deadbeef",
		FailLocations: 2, ForSeconds: 0,
	}
	peer := losingPeer(t, hubID.NodeID(), rule.ID())
	rule.Recipients = map[string]string{
		hubID.NodeID(): base64.StdEncoding.EncodeToString(sealed),
		peer:           base64.StdEncoding.EncodeToString([]byte("sealed-to-peer")),
	}

	alerts := store.NewMemAlerts()
	results := store.NewMemStore()
	maint := store.NewMemMaintenance()
	_ = alerts.Upsert(context.Background(), protocol.SignedAlertRule{Rule: rule})

	eng := NewEngine(hubID, alerts, results, maint, func() []string { return []string{peer} }, enc.Open,
		func(context.Context, protocol.SignedDeliveryState) {},
		map[protocol.AlertChannel]Notifier{protocol.AlertWebhook: notifier}, nil)
	eng.now = func() time.Time { return time.UnixMilli(testNowMS) }
	return eng, alerts, results, rule, peer
}

// A delivery-state pre-seeded by a NON-responsible recipient must not suppress a
// genuine down alert on the responsible hub (the "suppress" poisoning vector).
func TestPoisonedStateDoesNotSuppressRealDown(t *testing.T) {
	ctx := context.Background()
	nf := &flakyNotifier{}
	eng, alerts, results, rule, peer := twoRecipientFixture(t, nf)

	// The attacker (a recipient, but NOT the responsible hub) gossips a "down"
	// delivery-state BEFORE any real outage, hoping the responsible hub sees
	// delivered==down==observed and skips the genuine alert.
	_, _ = alerts.MergeDelivery(ctx, rule.ID(), store.Delivery{Status: protocol.StatusDown, HubID: peer, TimestampMS: testNowMS})

	// Now a real outage happens.
	_ = results.Insert(ctx, downResult("chk", "pa", testNowMS-2000))
	_ = results.Insert(ctx, downResult("chk", "pb", testNowMS-2000))

	eng.Evaluate(ctx)
	if nf.count() != 1 {
		t.Fatalf("non-responsible recipient's down state must not suppress a real alert; got %d deliveries", nf.count())
	}
}

// A flood of fresh "up" states from a NON-responsible recipient during a genuine
// outage must not make the responsible hub re-fire each tick (the "flood" vector).
func TestPoisonedUpFloodDoesNotRefire(t *testing.T) {
	ctx := context.Background()
	nf := &flakyNotifier{}
	eng, alerts, results, rule, peer := twoRecipientFixture(t, nf)

	// Genuine, sustained outage.
	_ = results.Insert(ctx, downResult("chk", "pa", testNowMS-2000))
	_ = results.Insert(ctx, downResult("chk", "pb", testNowMS-2000))

	// First tick fires once and records this hub's own delivered==down.
	eng.Evaluate(ctx)
	if nf.count() != 1 {
		t.Fatalf("expected the genuine down to fire once, got %d", nf.count())
	}

	// The attacker floods fresh "up" states each tick, trying to reset the
	// baseline so the down re-fires. The responsible hub reads only its OWN row.
	for i := 0; i < 5; i++ {
		_, _ = alerts.MergeDelivery(ctx, rule.ID(), store.Delivery{Status: protocol.StatusUp, HubID: peer, TimestampMS: testNowMS + int64(i)})
		eng.Evaluate(ctx)
	}
	if nf.count() != 1 {
		t.Fatalf("non-responsible recipient's up flood must not cause re-fire; got %d deliveries", nf.count())
	}
}

// A check with zero rows in a global newest-N slice (because other checks are
// busier) must still evaluate: the per-check query gives it its own window.
func TestQuietCheckOutsideGlobalWindowStillEvaluates(t *testing.T) {
	ctx := context.Background()
	nf := &flakyNotifier{}
	eng, _, results, _ := engineFixture(t, nf)

	// Flood the store with newest results for OTHER checks: a global Recent(1000)
	// would return only these and never see "chk".
	for i := 0; i < 1500; i++ {
		_ = results.Insert(ctx, upResult(fmt.Sprintf("busy-%d", i), "px", testNowMS-int64(i)))
	}
	// The monitored check is down, but its rows are older than the busy noise.
	_ = results.Insert(ctx, downResult("chk", "pa", testNowMS-5000))
	_ = results.Insert(ctx, downResult("chk", "pb", testNowMS-5000))

	eng.Evaluate(ctx)
	if nf.count() != 1 {
		t.Fatalf("a quiet check pushed out of a global window must still fire; got %d", nf.count())
	}
}

// Stale-only down observations (older than the recency window) must not assert an
// outage — so a silent fleet's last "down" can't fire, including on rule creation.
func TestStaleDownDoesNotFire(t *testing.T) {
	ctx := context.Background()
	nf := &flakyNotifier{}
	eng, _, results, _ := engineFixture(t, nf)

	stale := testNowMS - (downRecencyMS + 60*1000) // comfortably beyond the window
	_ = results.Insert(ctx, downResult("chk", "pa", stale))
	_ = results.Insert(ctx, downResult("chk", "pb", stale))

	eng.Evaluate(ctx)
	if nf.count() != 0 {
		t.Fatalf("stale-only down must not assert an outage; got %d deliveries", nf.count())
	}
}

func TestCorroboratedStatus(t *testing.T) {
	freshDown := protocol.ResultContent{Status: protocol.StatusDown, TimestampMS: testNowMS}
	freshUp := protocol.ResultContent{Status: protocol.StatusUp, TimestampMS: testNowMS}
	staleUp := protocol.ResultContent{Status: protocol.StatusUp, TimestampMS: testNowMS - downRecencyMS - 1}
	staleDown := protocol.ResultContent{Status: protocol.StatusDown, TimestampMS: testNowMS - downRecencyMS - 1}
	degraded := protocol.ResultContent{Status: protocol.StatusDegraded, TimestampMS: testNowMS}
	graceUp := protocol.ResultContent{Status: protocol.StatusUp, TimestampMS: testNowMS - 120_000}
	tests := []struct {
		name          string
		observations  []protocol.ResultContent
		failLocations int
		forSeconds    int
		want          protocol.Status
		wantOK        bool
	}{
		{name: "no observations", failLocations: 2},
		{name: "one remaining down", observations: []protocol.ResultContent{freshDown, staleDown}, failLocations: 2},
		{name: "degraded only", observations: []protocol.ResultContent{degraded}, failLocations: 2},
		{name: "stale up and fresh down", observations: []protocol.ResultContent{staleUp, freshDown}, failLocations: 2},
		{name: "all stale", observations: []protocol.ResultContent{staleUp, staleDown}, failLocations: 2},
		{name: "fresh up", observations: []protocol.ResultContent{freshUp}, failLocations: 2, want: protocol.StatusUp, wantOK: true},
		{name: "fresh up below quorum", observations: []protocol.ResultContent{freshUp, freshDown}, failLocations: 2, want: protocol.StatusUp, wantOK: true},
		{name: "down quorum", observations: []protocol.ResultContent{freshDown, freshDown}, failLocations: 2, want: protocol.StatusDown, wantOK: true},
		{name: "default quorum", observations: []protocol.ResultContent{freshDown}, want: protocol.StatusDown, wantOK: true},
		{name: "up within grace", observations: []protocol.ResultContent{freshDown, freshDown, freshUp}, failLocations: 2, forSeconds: 120, want: protocol.StatusUp, wantOK: true},
		{name: "up at grace boundary", observations: []protocol.ResultContent{freshDown, freshDown, graceUp}, failLocations: 2, forSeconds: 120, want: protocol.StatusDown, wantOK: true},
		{name: "zero grace", observations: []protocol.ResultContent{freshDown, freshDown, freshUp}, failLocations: 2, want: protocol.StatusDown, wantOK: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			latest := make(map[string]protocol.ResultContent, len(tt.observations))
			for i, c := range tt.observations {
				latest[fmt.Sprint(i)] = c
			}
			got, ok := corroboratedStatus(latest, tt.failLocations, tt.forSeconds, testNowMS)
			if got != tt.want || ok != tt.wantOK {
				t.Fatalf("corroboratedStatus = (%q, %v), want (%q, %v)", got, ok, tt.want, tt.wantOK)
			}
		})
	}
}

func TestEngineRetainsDownUntilFreshUp(t *testing.T) {
	ctx := context.Background()
	nf := &flakyNotifier{}
	eng, alerts, results, rule := engineFixture(t, nf)
	now := testNowMS
	eng.now = func() time.Time { return time.UnixMilli(now) }
	steps := []struct {
		name    string
		now     int64
		results []protocol.SignedResult
		count   int
		status  protocol.Status
	}{
		{"down", testNowMS, []protocol.SignedResult{downResult("chk", "pa", testNowMS-1000), downResult("chk", "pb", testNowMS)}, 1, protocol.StatusDown},
		{"partial stale", testNowMS + downRecencyMS, nil, 1, protocol.StatusDown},
		{"all stale", testNowMS + downRecencyMS + 1, nil, 1, protocol.StatusDown},
		{"fresh down", testNowMS + 3_600_000, []protocol.SignedResult{downResult("chk", "pa", testNowMS+3_600_000), downResult("chk", "pb", testNowMS+3_600_000)}, 1, protocol.StatusDown},
		{"actual up", testNowMS + 3_601_000, []protocol.SignedResult{upResult("chk", "pa", testNowMS+3_601_000)}, 2, protocol.StatusUp},
	}
	for _, step := range steps {
		t.Run(step.name, func(t *testing.T) {
			now = step.now
			for _, sr := range step.results {
				if err := results.Insert(ctx, sr); err != nil {
					t.Fatal(err)
				}
			}
			eng.Evaluate(ctx)
			if nf.count() != step.count {
				t.Errorf("got %d notifications, want %d", nf.count(), step.count)
			}
			delivery, ok, err := alerts.GetDeliveryBy(ctx, rule.ID(), eng.self)
			if err != nil || !ok || delivery.Status != step.status {
				t.Fatalf("delivery = %+v, %v, %v; want status %q", delivery, ok, err, step.status)
			}
			if step.status == protocol.StatusDown && delivery.TimestampMS != testNowMS {
				t.Errorf("down delivery timestamp changed: got %d, want %d", delivery.TimestampMS, testNowMS)
			}
		})
	}
}

func TestEngineRetriesThenDeliversOnceThenRecovers(t *testing.T) {
	ctx := context.Background()
	nf := &flakyNotifier{fail: true}
	eng, _, results, _ := engineFixture(t, nf)

	_ = results.Insert(ctx, downResult("chk", "pa", testNowMS-2000))
	_ = results.Insert(ctx, downResult("chk", "pb", testNowMS-2000))

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
	_ = results.Insert(ctx, upResult("chk", "pa", testNowMS-1000))
	_ = results.Insert(ctx, upResult("chk", "pb", testNowMS-1000))
	eng.Evaluate(ctx)
	if nf.count() != 2 || nf.n[1].Status != protocol.StatusUp {
		t.Fatalf("expected recovery delivery, got %d", nf.count())
	}
}

func TestInheritedDeliveryStateSuppressesDuplicate(t *testing.T) {
	ctx := context.Background()
	nf := &flakyNotifier{}
	eng, alerts, results, rule := engineFixture(t, nf)

	_ = results.Insert(ctx, downResult("chk", "pa", testNowMS-2000))
	_ = results.Insert(ctx, downResult("chk", "pb", testNowMS-2000))

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

	_ = results.Insert(ctx, downResult("chk", "pa", testNowMS-2000))
	_ = results.Insert(ctx, downResult("chk", "pb", testNowMS-2000))

	// A delivery-state authored by a hub NOT in the rule's recipients must be
	// ignored, so it cannot suppress a real alert.
	_, _ = alerts.MergeDelivery(ctx, rule.ID(), store.Delivery{Status: protocol.StatusDown, HubID: "stranger-hub", TimestampMS: 50})
	eng.Evaluate(ctx)
	if nf.count() != 1 {
		t.Fatalf("non-recipient state must not suppress; expected 1 delivery, got %d", nf.count())
	}
}

// TestMaintenanceSuppressesDownThenAlertsAfter proves a planned-downtime window
// suppresses the DOWN alert while active (without advancing delivered state), and
// that once the window ends a still-down service alerts normally.
func TestMaintenanceSuppressesDownThenAlertsAfter(t *testing.T) {
	ctx := context.Background()
	nf := &flakyNotifier{}
	eng, _, results, maint, rule := engineFixtureMaint(t, nf)

	// Pin the engine clock so the window can bracket "now".
	fixedNow := int64(1_000_000)
	eng.now = func() time.Time { return time.UnixMilli(fixedNow) }

	_ = results.Insert(ctx, downResult("chk", "pa", fixedNow-100))
	_ = results.Insert(ctx, downResult("chk", "pb", fixedNow-100))

	// Schedule a window covering "now".
	owner, _ := identity.Generate()
	_ = maint.Upsert(ctx, protocol.SignMaintenanceWindow(owner, protocol.MaintenanceWindow{
		CheckID: rule.CheckID, StartMS: fixedNow - 500, EndMS: fixedNow + 500, UpdatedMS: 1,
	}))

	// Inside the window: the down must be suppressed and delivered state untouched.
	eng.Evaluate(ctx)
	if nf.count() != 0 {
		t.Fatalf("maintenance must suppress the down alert, got %d deliveries", nf.count())
	}
	if s := eng.deliveredStatus(ctx, rule); s != protocol.StatusUp {
		t.Fatalf("suppressed down must not advance delivered state, got %q", s)
	}

	// After the window ends, the still-down service must alert.
	eng.now = func() time.Time { return time.UnixMilli(fixedNow + 1000) }
	_ = results.Insert(ctx, downResult("chk", "pa", fixedNow+900))
	_ = results.Insert(ctx, downResult("chk", "pb", fixedNow+900))
	eng.Evaluate(ctx)
	if nf.count() != 1 || nf.n[0].Status != protocol.StatusDown {
		t.Fatalf("after the window a still-down service must alert, got %d", nf.count())
	}
}

// TestFutureStrangerStateCannotShadow proves the per-(rule,hub) storage closes
// the poisoning gap: a recipient's real delivery still suppresses duplicates
// even when a non-recipient has written a higher-timestamp "down" state.
func TestFutureStrangerStateCannotShadow(t *testing.T) {
	ctx := context.Background()
	nf := &flakyNotifier{}
	eng, alerts, results, rule := engineFixture(t, nf)

	_ = results.Insert(ctx, downResult("chk", "pa", testNowMS-2000))
	_ = results.Insert(ctx, downResult("chk", "pb", testNowMS-2000))

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
