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

const (
	// downRecencyMS is the floor of the recency window: a probe's latest
	// observation must be no older than this to count toward corroboration.
	// Without a recency bound a silent fleet's last "down" would assert an
	// outage forever (and fire on rule creation), because admission accepts
	// results up to 24h old. The effective window for a rule is the larger of
	// this floor and its own ForSeconds grace period, so the down side gets the
	// same freshness treatment the up side already has.
	downRecencyMS = int64(15 * 60 * 1000)
	// evalResultLimit caps how many recent rows are pulled per evaluated check.
	// The query is already scoped to one check and a recency window, so this is
	// only a safety ceiling.
	evalResultLimit = 1000
)

// Engine evaluates alert rules this hub is responsible for.
type Engine struct {
	id              *identity.Identity
	self            string
	alerts          store.AlertStore
	results         store.ResultStore
	maint           store.MaintenanceStore
	peerHubs        func() []string // live verified peer hub IDs (short liveness window)
	open            Opener
	publishDelivery func(ctx context.Context, sd protocol.SignedDeliveryState)
	notifiers       map[protocol.AlertChannel]Notifier
	log             *slog.Logger
	now             func() time.Time
}

// NewEngine builds an alert engine. open decrypts destinations sealed to this
// hub; publishDelivery gossips a delivery-state after a successful send. maint
// supplies planned-downtime windows that suppress "down" alerts; it may be nil
// (no suppression).
func NewEngine(id *identity.Identity, alerts store.AlertStore, results store.ResultStore, maint store.MaintenanceStore, peerHubs func() []string, open Opener, publishDelivery func(ctx context.Context, sd protocol.SignedDeliveryState), notifiers map[protocol.AlertChannel]Notifier, log *slog.Logger) *Engine {
	if log == nil {
		log = slog.Default()
	}
	return &Engine{
		id: id, self: id.NodeID(), alerts: alerts, results: results, maint: maint, peerHubs: peerHubs,
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
	now := e.now().UnixMilli()

	// Per-check recency window: the widest lookback any active rule on that check
	// needs (its ForSeconds grace period, floored at downRecencyMS). One query per
	// check is shared by every rule on it, so a busy hub doesn't re-scan.
	windowByCheck := map[string]int64{}
	for _, sa := range rules {
		w := recencyMS(sa.Rule.ForSeconds)
		if w > windowByCheck[sa.Rule.CheckID] {
			windowByCheck[sa.Rule.CheckID] = w
		}
	}
	latestCache := map[string]map[string]protocol.ResultContent{}
	latestFor := func(checkID string) map[string]protocol.ResultContent {
		if m, ok := latestCache[checkID]; ok {
			return m
		}
		// Query this check's own recent results, not a global newest-N slice: on a
		// busy hub a global cap can hold zero rows for a quiet check and silently
		// stop its outage evaluation. The store filters by check_id BEFORE the
		// limit, so the window is always this check's.
		res, err := e.results.RecentSinceCheck(ctx, checkID, now-windowByCheck[checkID], 0, evalResultLimit)
		if err != nil {
			e.log.Warn("alert: recent results", "check", checkID, "err", err)
			res = nil
		}
		m := latestPerProbe(res)
		latestCache[checkID] = m
		return m
	}

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
		// This hub is the sole responsible hub for the rule right now, so its own
		// corroborated view and its own delivered-state are authoritative below.
		latest := latestFor(rule.CheckID)
		observed, ok := corroboratedStatus(latest, rule.FailLocations, rule.ForSeconds, now)
		if !ok {
			continue // neither corroborated down nor a fresh up
		}
		// Own-observation guard: skip only when our OWN corroborated observation
		// matches what THIS responsible hub last successfully delivered. `observed`
		// is derived solely from results this hub holds and corroborates, and the
		// baseline is our own delivery row (see deliveredStatus), so a peer's
		// gossiped delivery-state can never by itself make us skip a real down
		// transition (suppress) nor make us re-fire on a false transition (flood).
		//
		// Planned downtime: while the check is inside an active maintenance window,
		// suppress a "down" alert and do NOT advance the delivered state (skip the
		// rule entirely). A recovery ("up") is still delivered so a service that
		// comes back mid-window clears any earlier down. Once the window ends,
		// normal evaluation resumes — so a still-down service alerts then.
		if observed == protocol.StatusDown && e.underMaintenance(ctx, rule.CheckID, now) {
			continue
		}
		if observed == e.deliveredStatus(ctx, rule) {
			continue
		}
		e.deliver(ctx, rule, observed, latest)
	}
}

// deliveredStatus is the authoritative last-delivered status for the rule.
// Missing state is treated as "up" (the baseline, so we don't alert on a service
// that's been fine since the rule was created).
//
// The currently-responsible hub is authoritative for a rule's delivered-status,
// and this method is only reached from the responsible hub (Evaluate gates on
// ResponsibleAmong first), so the authoritative row is THIS hub's own row =
// exactly what it last successfully sent. States authored by any other recipient
// are ignored: a non-responsible recipient must not be able to move the baseline,
// which is the suppress (pre-seed a "down") and flood (flip to "up" each tick)
// vector. All recipients' states are still stored per (rule, hub) for
// anti-entropy — only this decision reads the responsible hub's own row.
//
// Failover cost: when responsibility moves to a hub with no state yet, its own
// row is missing → baseline "up" → it may re-notify once. That single duplicate
// is accepted (the design prioritizes at-least-once/no-loss over no-duplicate in
// the brief failover window) rather than reopening the suppression hole by
// trusting a no-longer-responsible hub's state.
func (e *Engine) deliveredStatus(ctx context.Context, rule protocol.AlertRule) protocol.Status {
	d, ok, _ := e.alerts.GetDeliveryBy(ctx, rule.ID(), e.self)
	if !ok {
		return protocol.StatusUp
	}
	return d.Status
}

// underMaintenance reports whether the check is inside an active planned-downtime
// window at time nowMS. A nil store or a lookup error means "not in maintenance"
// (fail open: never silently swallow a real alert on a maintenance-store hiccup).
func (e *Engine) underMaintenance(ctx context.Context, checkID string, nowMS int64) bool {
	if e.maint == nil {
		return false
	}
	intervals, err := e.maint.IntervalsForCheck(ctx, checkID)
	if err != nil {
		e.log.Warn("alert: maintenance lookup", "check", checkID, "err", err)
		return false
	}
	return store.InMaintenance(nowMS, intervals)
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

// latestPerProbe reduces one check's result list to the newest result per probe.
func latestPerProbe(results []protocol.SignedResult) map[string]protocol.ResultContent {
	m := map[string]protocol.ResultContent{}
	for _, sr := range results {
		c := sr.Content
		if cur, ok := m[c.ProbeID]; !ok || c.TimestampMS > cur.TimestampMS {
			m[c.ProbeID] = c
		}
	}
	return m
}

// recencyMS is the freshness window a rule with the given ForSeconds uses: its
// grace period, floored at downRecencyMS. An observation older than this is
// ignored, so neither a stale "down" nor a stale "up" can drive a decision.
func recencyMS(forSeconds int) int64 {
	w := int64(forSeconds) * 1000
	if w < downRecencyMS {
		w = downRecencyMS
	}
	return w
}

// corroboratedStatus decides a check's status from the latest result per probe.
// Only observations within the recency window (recencyMS(forSeconds)) count, so
// recovery requires an actual fresh up, not merely loss of the down quorum.
// Without either decision the rule is skipped, leaving delivery state untouched.
func corroboratedStatus(latest map[string]protocol.ResultContent, failLocations, forSeconds int, nowMS int64) (protocol.Status, bool) {
	if failLocations < 1 {
		failLocations = 1
	}
	recency := recencyMS(forSeconds)
	down := 0
	var newestUp int64
	for _, c := range latest {
		if nowMS-c.TimestampMS > recency {
			continue // stale: cannot assert up or down
		}
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
	if newestUp != 0 {
		return protocol.StatusUp, true
	}
	return "", false
}
