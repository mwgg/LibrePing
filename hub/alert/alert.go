// Package alert evaluates gossiped alert rules against the (also gossiped)
// result stream and delivers notifications.
//
// Decentralization: every hub stores every rule, but for each rule exactly one
// hub — chosen by rendezvous hashing over the live verified-hub set — actually
// evaluates and fires it (see Responsible). That prevents duplicate alerts with
// no central coordinator, and fails over automatically when a hub drops out.
//
// Downtime is corroborated across locations: a check is "down" only when at
// least FailLocations distinct probes report down and nothing has reported up
// within ForSeconds. Alerts fire only on transitions (up→down, down→up), and
// the last status is persisted so restarts don't re-alert.
package alert

import (
	"context"
	"encoding/base64"
	"log/slog"
	"time"

	"github.com/mwgg/libreping/hub/store"
	"github.com/mwgg/libreping/pkg/identity"
	"github.com/mwgg/libreping/pkg/protocol"
)

// Opener decrypts a sealed destination addressed to this hub (encbox.KeyPair.Open).
type Opener func(sealed []byte) ([]byte, bool)

// Engine evaluates alert rules this hub is responsible for.
type Engine struct {
	id              *identity.Identity
	self            string
	alerts          store.AlertStore
	results         store.ResultStore
	peerHubs        func() []string // live verified peer hub IDs (short liveness window)
	open            Opener
	publishDelivery func(ctx context.Context, sd protocol.SignedDeliveryState)
	notifiers       map[protocol.AlertChannel]Notifier
	log             *slog.Logger
	now             func() time.Time
}

// NewEngine builds an alert engine. open decrypts destinations sealed to this
// hub; publishDelivery gossips a delivery-state after a successful send.
func NewEngine(id *identity.Identity, alerts store.AlertStore, results store.ResultStore, peerHubs func() []string, open Opener, publishDelivery func(ctx context.Context, sd protocol.SignedDeliveryState), notifiers map[protocol.AlertChannel]Notifier, log *slog.Logger) *Engine {
	if log == nil {
		log = slog.Default()
	}
	return &Engine{
		id: id, self: id.NodeID(), alerts: alerts, results: results, peerHubs: peerHubs,
		open: open, publishDelivery: publishDelivery, notifiers: notifiers, log: log, now: time.Now,
	}
}

// Run evaluates rules every interval until ctx is cancelled.
func (e *Engine) Run(ctx context.Context, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			e.Evaluate(ctx)
		}
	}
}

// Evaluate runs one pass over all rules this hub is responsible for.
func (e *Engine) Evaluate(ctx context.Context) {
	rules, err := e.alerts.ListActive(ctx)
	if err != nil {
		e.log.Warn("alert: list rules", "err", err)
		return
	}
	if len(rules) == 0 {
		return
	}
	peers := e.peerHubs()
	live := map[string]bool{e.self: true}
	for _, p := range peers {
		live[p] = true
	}
	results, err := e.results.Recent(ctx, 1000)
	if err != nil {
		e.log.Warn("alert: recent results", "err", err)
		return
	}
	latestByCheck := latestPerProbeByCheck(results)
	now := e.now().UnixMilli()

	for _, sa := range rules {
		rule := sa.Rule
		// Responsibility is limited to recipients that can actually decrypt the
		// destination and are currently live (short liveness window → failover).
		var candidates []string
		for hubID := range rule.Recipients {
			if live[hubID] {
				candidates = append(candidates, hubID)
			}
		}
		if !ResponsibleAmong(e.self, candidates, rule.ID()) {
			continue
		}
		observed, ok := corroboratedStatus(latestByCheck[rule.CheckID], rule.FailLocations, rule.ForSeconds, now)
		if !ok {
			continue // no data yet
		}
		// Compare against what has actually been DELIVERED (locally or by a peer
		// we learned from via gossip). Anything not yet delivered is (re)tried;
		// the delivered state only advances on a successful send below.
		if observed == e.deliveredStatus(ctx, rule) {
			continue
		}
		e.deliver(ctx, rule, observed, latestByCheck[rule.CheckID])
	}
}

// deliveredStatus is the last status known to have been delivered for the rule.
// Missing state is treated as "up" (the baseline, so we don't alert on a service
// that's been fine since the rule was created).
//
// Only states authored by the rule's recipients are considered — and the newest
// among them wins. Because delivery state is keyed per (rule, hub), a state from
// a non-recipient (or any other hub) cannot shadow a recipient's, even if it
// carries a higher timestamp. This is what keeps failover deduplication honest
// against a delivery-state poisoning attempt.
func (e *Engine) deliveredStatus(ctx context.Context, rule protocol.AlertRule) protocol.Status {
	var newest store.Delivery
	found := false
	for hubID := range rule.Recipients {
		d, ok, _ := e.alerts.GetDeliveryBy(ctx, rule.ID(), hubID)
		if ok && (!found || d.TimestampMS > newest.TimestampMS) {
			newest, found = d, true
		}
	}
	if !found {
		return protocol.StatusUp
	}
	return newest.Status
}

// deliver decrypts the destination, notifies, and — only on success — records
// and gossips the new delivered status. On failure it records nothing, so the
// next tick retries (at-least-once, no loss).
func (e *Engine) deliver(ctx context.Context, rule protocol.AlertRule, status protocol.Status, latest map[string]protocol.ResultContent) {
	notifier, ok := e.notifiers[rule.Channel]
	if !ok {
		e.log.Warn("alert: no notifier for channel", "channel", rule.Channel)
		return
	}
	dest, ok := e.decrypt(rule)
	if !ok {
		e.log.Warn("alert: cannot decrypt destination for this hub", "check", rule.CheckID)
		return
	}
	locs := make([]protocol.ResultContent, 0, len(latest))
	target := ""
	for _, c := range latest {
		locs = append(locs, c)
		target = c.Target
	}
	n := Notification{
		Destination: dest, Channel: rule.Channel, CheckID: rule.CheckID,
		Target: target, Status: status, Locations: locs, AtMS: e.now().UnixMilli(),
	}
	if err := notifier.Notify(ctx, n); err != nil {
		// No state change → retried next tick.
		e.log.Warn("alert: notify failed, will retry", "channel", rule.Channel, "err", err)
		return
	}

	ts := e.now().UnixMilli()
	if _, err := e.alerts.MergeDelivery(ctx, rule.ID(), store.Delivery{Status: status, HubID: e.self, TimestampMS: ts}); err != nil {
		e.log.Warn("alert: record delivery", "err", err)
	}
	if e.publishDelivery != nil {
		e.publishDelivery(ctx, protocol.SignDeliveryState(e.id, protocol.DeliveryState{
			RuleID: rule.ID(), Status: status, TimestampMS: ts,
		}))
	}
	e.log.Info("alert delivered", "check", rule.CheckID, "status", status, "channel", rule.Channel)
}

// decrypt opens the destination sealed to this hub in the rule's recipients.
func (e *Engine) decrypt(rule protocol.AlertRule) (string, bool) {
	if e.open == nil {
		return "", false
	}
	b64, ok := rule.Recipients[e.self]
	if !ok {
		return "", false
	}
	sealed, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return "", false
	}
	plain, ok := e.open(sealed)
	if !ok {
		return "", false
	}
	return string(plain), true
}

// latestPerProbeByCheck reduces a result list to the newest result per
// (check_id, probe_id), grouped by check_id.
func latestPerProbeByCheck(results []protocol.SignedResult) map[string]map[string]protocol.ResultContent {
	out := map[string]map[string]protocol.ResultContent{}
	for _, sr := range results {
		c := sr.Content
		m := out[c.CheckID]
		if m == nil {
			m = map[string]protocol.ResultContent{}
			out[c.CheckID] = m
		}
		if cur, ok := m[c.ProbeID]; !ok || c.TimestampMS > cur.TimestampMS {
			m[c.ProbeID] = c
		}
	}
	return out
}

// corroboratedStatus decides a check's status from the latest result per probe.
func corroboratedStatus(latest map[string]protocol.ResultContent, failLocations, forSeconds int, nowMS int64) (protocol.Status, bool) {
	if len(latest) == 0 {
		return "", false
	}
	if failLocations < 1 {
		failLocations = 1
	}
	down := 0
	var newestUp int64
	for _, c := range latest {
		switch c.Status {
		case protocol.StatusDown:
			down++
		case protocol.StatusUp:
			if c.TimestampMS > newestUp {
				newestUp = c.TimestampMS
			}
		}
	}
	downCorroborated := down >= failLocations && (newestUp == 0 || nowMS-newestUp >= int64(forSeconds)*1000)
	if downCorroborated {
		return protocol.StatusDown, true
	}
	return protocol.StatusUp, true
}
