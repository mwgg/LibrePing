// Command hub is a LibrePing hub: a publicly-reachable peer in the hub mesh. It
// accepts results from local probes, verifies and stores them, gossips results
// and the check catalog to peer hubs, advertises itself, and serves the
// dashboard API. Hubs have no central coordinator — each is autonomous and
// federates with the rest over libp2p, so the whole network shares all data.
//
// Configuration (environment variables):
//
//	HTTP_ADDR          dashboard/probe API listen address       (default :8080)
//	HUB_KEY_PATH       hub identity key file                    (default ./data/hub.key)
//	P2P_LISTEN         libp2p listen multiaddr                  (default /ip4/0.0.0.0/tcp/4001)
//	P2P_ANNOUNCE_ADDRS comma-separated public multiaddrs to advertise (NAT/containers)
//	P2P_RELAYS         comma-separated /p2p relay multiaddrs for AutoRelay
//	ENABLE_MDNS        local-network (mDNS) peer discovery       (default false)
//	BOOTSTRAP_PEERS    comma-separated peer multiaddrs to join  (default empty)
//	DEFAULT_BOOTSTRAP  fallback bootstrap peers, merged with BOOTSTRAP_PEERS
//	BOOTSTRAP_SEEDS    comma-separated hub URLs whose /api/v1/hubs supplies a
//	                   live, self-maintaining list of dialable peers to join
//	HUB_ALLOW_PRIVATE_PEERS  allow directory checks to reach private IPs (default false)
//	WRITE_RATE_PER_MIN per-IP rate limit on write endpoints     (0 = default)
//	ALERT_WEBHOOK_ALLOW_HTTP allow plain-http webhook destinations (default false)
//	DATABASE_URL       Postgres/TimescaleDB DSN; empty = in-memory store
//	MIGRATIONS_DIR     directory of *.sql migrations            (default ./migrations)
//	TRUST_POLICY       "open" (default) or "allowlist"
//	TRUST_ALLOWLIST    comma-separated node IDs for allowlist mode
//	TARGET_REDUNDANCY  probes to assign per check               (default 3)
//	HUB_STORAGE        storage role: shards (default) | archive | none
//	HUB_STORAGE_CAPACITY  relative weight for shard placement   (default 1)
//	RESULT_COMPRESS_AFTER_DAYS / RESULT_RETENTION_DAYS / RESULT_HOURLY_RETENTION_DAYS /
//	RESULT_DAILY_RETENTION_DAYS  result storage tiers (compress/raw/hourly/daily; 0=keep)
//	ADVERTISE          advertise this hub to the network        (default true)
//	PUBLIC_URL         this hub's public base URL (required to advertise)
//	HUB_NAME           friendly name shown in directories
//	HUB_LOCATION       "Country,City,lat,lon" (overrides auto-detect)
//	HUB_GEOIP          auto-detect hub location from public IP   (default true)
//	SEED_CHECK_TARGET  optional URL to seed one HTTP check on first boot
//	ALERT_INTERVAL     how often the alert engine evaluates rules (default 30s)
//	ALERT_HUB_TTL      silence before a peer takes over a hub's alerts (default 3m)
//	ALERT_WEBHOOK_ALLOW_HTTP  allow plain-http alert destinations (default false)
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/mwgg/libreping/hub/admit"
	"github.com/mwgg/libreping/hub/alert"
	"github.com/mwgg/libreping/hub/api"
	"github.com/mwgg/libreping/hub/directory"
	"github.com/mwgg/libreping/hub/encbox"
	"github.com/mwgg/libreping/hub/interest"
	"github.com/mwgg/libreping/hub/outbox"
	"github.com/mwgg/libreping/hub/p2p"
	"github.com/mwgg/libreping/hub/remote"
	"github.com/mwgg/libreping/hub/shard"
	"github.com/mwgg/libreping/hub/store"
	"github.com/mwgg/libreping/hub/trust"
	"github.com/mwgg/libreping/pkg/geoip"
	"github.com/mwgg/libreping/pkg/identity"
	"github.com/mwgg/libreping/pkg/netguard"
	"github.com/mwgg/libreping/pkg/protocol"
)

const directoryTTL = 15 * time.Minute

// deliveryClockSkewMS bounds how far in the future a gossiped delivery state's
// timestamp may be before it's rejected as implausible (clock skew / forgery).
const deliveryClockSkewMS = int64(2 * 60 * 1000)

// resultGossipWindow is how far back the anti-entropy loop re-broadcasts recent
// results, so peers converge without re-streaming the entire history each tick.
const resultGossipWindow = 10 * time.Minute

func main() {
	log := slog.New(slog.NewTextHandler(os.Stdout, nil))

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	id, err := identity.LoadOrCreate(env("HUB_KEY_PATH", "./data/hub.key"))
	if err != nil {
		log.Error("load identity", "err", err)
		os.Exit(1)
	}
	log.Info("hub identity ready", "hub_id", id.NodeID())

	// X25519 keypair (derived from the same seed) for decrypting alert
	// destinations sealed to this hub.
	enc := encbox.FromSeed(id.Seed())

	resultStore, catalogStore, subStore, alertStore := openStores(ctx, log)
	defer resultStore.Close()

	policy := trust.FromConfig(os.Getenv("TRUST_POLICY"), splitCSV(os.Getenv("TRUST_ALLOWLIST")))
	log.Info("trust policy", "policy", policy.Name())

	allowPrivatePeers := boolDefault(os.Getenv("HUB_ALLOW_PRIVATE_PEERS"), false)
	dir := directory.New(id.NodeID(), directoryTTL, allowPrivatePeers, log)

	// Storage role for partial replication. "shards" (default) holds a
	// rendezvous-assigned, capacity-weighted slice of the result shards;
	// "archive" holds everything; "none" stores only its own pins. A solo or
	// small mesh (<= shard.Replication storage hubs) holds everything regardless,
	// so this is transparent until the network is large enough to spread.
	storeMode := env("HUB_STORAGE", "shards")
	selfHub := shard.Hub{ID: id.NodeID(), Capacity: atoiDefault(os.Getenv("HUB_STORAGE_CAPACITY"), 1), Archive: storeMode == "archive"}
	if storeMode == "none" {
		selfHub.Capacity = 0
	}
	interestSet := interest.New()
	log.Info("storage role", "mode", storeMode, "capacity", selfHub.Capacity)

	// The mesh ingest paths and the HTTP submit path share the same stores, so a
	// gossiped item and a locally-submitted one are treated identically.
	mesh, err := p2p.New(ctx, p2p.Config{
		PrivateKey:    id.PrivateKey(),
		ListenAddrs:   []string{env("P2P_LISTEN", "/ip4/0.0.0.0/tcp/4001")},
		AnnounceAddrs: splitCSV(os.Getenv("P2P_ANNOUNCE_ADDRS")),
		StaticRelays:  splitCSV(os.Getenv("P2P_RELAYS")),
		EnableMDNS:    boolDefault(os.Getenv("ENABLE_MDNS"), false),
		ResultsSince:  resultStore.RecentSince,
		// Serve this hub's control plane to peers on connect, so a freshly-joined
		// hub starts monitoring (assigning checks to its probes) immediately
		// instead of waiting for the next periodic gossip re-broadcast to reach it.
		CatalogSnapshot:      catalogStore.ListChecks,
		SubscriptionSnapshot: subStore.ListForGossip,
		AlertSnapshot:        alertStore.ListForGossip,
		Policy:               policy,
		Logger:               log,
		Ingest: func(ctx context.Context, sr protocol.SignedResult) {
			// Same semantic admission the HTTP submit path applies (the p2p
			// layer already did signature + trust). Keeps gossiped and locally
			// submitted results held to one standard.
			if err := admit.Result(ctx, catalogStore, sr, time.Now()); err != nil {
				log.Debug("dropping gossiped result", "err", err)
				return
			}
			// Partial replication: persist only results this hub is responsible
			// for (its shards + pins). Others are seen but not stored.
			if !interestSet.Holds(sr.Content.CheckID) {
				return
			}
			if err := resultStore.Insert(ctx, sr); err != nil {
				log.Warn("store gossiped result", "err", err)
			}
		},
		IngestCatalog: func(ctx context.Context, sc protocol.SignedCatalogEntry) {
			if err := catalogStore.UpsertCheck(ctx, sc); err != nil {
				log.Warn("store gossiped catalog entry", "err", err)
			}
		},
		IngestHub: func(ctx context.Context, sa protocol.SignedHubAnnouncement) {
			dir.Add(ctx, sa)
		},
		IngestSubscription: func(ctx context.Context, ss protocol.SignedSubscription) {
			if err := subStore.Upsert(ctx, ss); err != nil {
				log.Warn("store gossiped subscription", "err", err)
			}
		},
		IngestAlert: func(ctx context.Context, sa protocol.SignedAlertRule) {
			if err := alertStore.Upsert(ctx, sa); err != nil {
				log.Warn("store gossiped alert", "err", err)
			}
		},
		IngestDelivery: func(ctx context.Context, sd protocol.SignedDeliveryState) {
			// A valid hub signature is not enough: only a hub that is a
			// *recipient* of the rule may legitimately deliver it. Without this
			// gate any hub could write a far-future delivery state that shadows
			// the real one and forces repeated alerts. Also reject states dated
			// implausibly far in the future (clock-skew bound).
			rule, ok, err := alertStore.GetRule(ctx, sd.State.RuleID)
			if err != nil || !ok {
				return // unknown rule: nothing to corroborate against
			}
			if _, isRecipient := rule.Rule.Recipients[sd.State.HubID]; !isRecipient {
				log.Debug("dropping delivery-state from non-recipient hub", "hub", sd.State.HubID, "rule", sd.State.RuleID)
				return
			}
			if sd.State.TimestampMS > time.Now().UnixMilli()+deliveryClockSkewMS {
				log.Debug("dropping delivery-state with implausible future timestamp", "rule", sd.State.RuleID)
				return
			}
			_, _ = alertStore.MergeDelivery(ctx, sd.State.RuleID, store.Delivery{
				Status: sd.State.Status, HubID: sd.State.HubID, TimestampMS: sd.State.TimestampMS,
			})
		},
	})
	if err != nil {
		log.Error("start p2p mesh", "err", err)
		os.Exit(1)
	}
	defer mesh.Close()
	log.Info("p2p mesh listening", "addrs", mesh.Addrs())

	// Bootstrap from operator-configured peers plus any built-in defaults, so a
	// fresh hub can join the DHT without manual peering. With neither set, the
	// hub still works but forms an isolated DHT view until a peer connects.
	bootstrap := append(splitCSV(os.Getenv("DEFAULT_BOOTSTRAP")), splitCSV(os.Getenv("BOOTSTRAP_PEERS"))...)
	// Seed directories: fetch a live, self-maintaining list of dialable peers from
	// one or more well-known hubs' /api/v1/hubs, so a new hub joins with zero hand-
	// configured peers and the list stays fresh on its own (dead hubs age out).
	seeds := splitCSV(os.Getenv("BOOTSTRAP_SEEDS"))
	bootstrap = append(bootstrap, fetchSeedPeers(ctx, log, seeds, allowPrivatePeers)...)
	if err := mesh.Bootstrap(ctx, bootstrap); err != nil {
		log.Warn("mesh bootstrap", "err", err)
	}
	// Self-heal: if the seeds were down at startup or every peer later drops, keep
	// retrying the seed directory while isolated. Once any peer connects, the DHT
	// takes over discovery and this stays idle.
	if len(seeds) > 0 {
		go seedHealLoop(ctx, log, mesh, seeds, allowPrivatePeers)
	}

	seedCheck(ctx, log, id, catalogStore, subStore, mesh)

	// Outbox retains non-held submitted results for direct holder push + gossip
	// anti-entropy, bounded to the gossip window so it stays small.
	ob := outbox.New(2048, resultGossipWindow)

	srv := api.New(api.Config{
		Store:             resultStore,
		Catalog:           catalogStore,
		Subscriptions:     subStore,
		Alerts:            alertStore,
		Mesh:              mesh,
		Identity:          id,
		EncPubKey:         enc.PublicKey(),
		Directory:         dir,
		Policy:            policy,
		Redundancy:        atoiDefault(os.Getenv("TARGET_REDUNDANCY"), 3),
		WriteRatePerMin:   atoiDefault(os.Getenv("WRITE_RATE_PER_MIN"), 0),
		MeshDiagnostics:   func() any { return mesh.Diagnostics() },
		SelfAddrs:         mesh.PublicAddrs,
		Interest:          interestSet,
		SelfHub:           selfHub,
		AllowPrivatePeers: allowPrivatePeers,
		Outbox:            ob,
		Logger:            log,
	})

	// backfill pulls a newly-assigned shard's recent results from its current
	// holders and ingests them (verify → policy → admit → store), so a hub that
	// takes over a shard on churn catches up on history instead of starting blank.
	remoteClient := remote.NewClient(allowPrivatePeers)
	// Repair horizon is tied to raw retention (how far back this hub keeps full
	// detail), not hub liveness — so a hub taking over a shard rebuilds the whole
	// raw window it is supposed to hold, not just the last few minutes. Bounded so
	// a "keep forever" retention can't request unbounded history.
	retentionDays := atoiDefault(os.Getenv("RESULT_RETENTION_DAYS"), store.DefaultTierConfig().RawRetentionDays)
	backfillHorizon := time.Duration(retentionDays) * 24 * time.Hour
	if retentionDays <= 0 || backfillHorizon > maxBackfillHorizon {
		backfillHorizon = maxBackfillHorizon
	}
	backfill := func(s uint32) {
		since := time.Now().Add(-backfillHorizon).UnixMilli()
		hubs := []shard.Hub{selfHub}
		urlByID := map[string]string{}
		for _, ann := range dir.ActiveWithin(storageWindow) {
			hubs = append(hubs, shard.HubFrom(ann.HubID, ann.StorageCapacity, ann.StorageArchive, trust.TrustedStorage(policy, ann.HubID)))
			urlByID[ann.HubID] = ann.PublicURL
		}
		// Query every holder (not just the first to answer): a single holder may
		// itself hold an incomplete slice, so merging across holders — deduped by
		// the store's ON CONFLICT — gives the best repair. Each holder is paged
		// backward by timestamp cursor so a large window isn't truncated by a limit.
		total := 0
		for _, id := range shard.Holders(s, hubs, shard.Replication) {
			if id == selfHub.ID || urlByID[id] == "" {
				continue
			}
			stored := 0
			before := int64(0) // 0 = newest page first
			for total < backfillMaxPerShard {
				res, err := remoteClient.Fetch(ctx, urlByID[id], remote.ShardQuery(s, since, before, backfillPage))
				if err != nil || len(res) == 0 {
					break
				}
				oldest := res[0].Content.TimestampMS
				for _, sr := range res { // Fetch already verified signatures
					if sr.Content.TimestampMS < oldest {
						oldest = sr.Content.TimestampMS
					}
					if !policy.Allow(sr.Content.ProbeID) || admit.Result(ctx, catalogStore, sr, time.Now()) != nil {
						continue
					}
					if interestSet.Holds(sr.Content.CheckID) && resultStore.Insert(ctx, sr) == nil {
						stored++
						total++
					}
				}
				if len(res) < backfillPage {
					break // exhausted this holder's window
				}
				before = oldest // page backward (exclusive); ties at one ms self-heal via gossip
			}
			if stored > 0 {
				log.Info("backfilled newly-assigned shard", "shard", s, "from", id, "stored", stored)
			}
		}
		if total >= backfillMaxPerShard {
			log.Warn("backfill hit per-shard cap; older history may rely on anti-entropy", "shard", s, "cap", backfillMaxPerShard)
		}
	}

	// Recompute storage interest periodically (and on startup) from the hub
	// directory: which shards this hub is rendezvous-assigned, plus pinned checks
	// (its own probes' assignments and checks it is an alert recipient for).
	trustedStorage := func(hubID string) bool { return trust.TrustedStorage(policy, hubID) }
	go interestLoop(ctx, selfHub, dir, srv, alertStore, mesh, interestSet, backfill, trustedStorage, durDefault(os.Getenv("INTEREST_INTERVAL"), 30*time.Second))

	// Background gossip: re-announce known checks (anti-entropy so new hubs
	// converge) and advertise this hub if enabled. Intervals govern how fast a
	// newly-joined hub converges on the catalog/directory.
	go gossipLoop(ctx, log, id, resultStore, catalogStore, subStore, alertStore, mesh, ob, srv.PushToHolders, durDefault(os.Getenv("CATALOG_GOSSIP_INTERVAL"), time.Minute))
	go advertiseLoop(ctx, log, id, enc.PublicKey(), selfHub, mesh, durDefault(os.Getenv("ADVERTISE_INTERVAL"), time.Minute))

	// Alert engine: this hub fires only the rules rendezvous-hashing assigns to
	// it among the recipient hubs that are currently live. A short liveness
	// window means a dead responsible hub ages out quickly and a peer takes over.
	hubTTL := durDefault(os.Getenv("ALERT_HUB_TTL"), 3*time.Minute)
	engine := alert.NewEngine(id, alertStore, resultStore,
		func() []string {
			hubs := dir.ActiveWithin(hubTTL)
			ids := make([]string, 0, len(hubs))
			for _, h := range hubs {
				ids = append(ids, h.HubID)
			}
			return ids
		},
		enc.Open,
		func(ctx context.Context, sd protocol.SignedDeliveryState) { _ = mesh.PublishDelivery(ctx, sd) },
		alertNotifiers(boolDefault(os.Getenv("ALERT_WEBHOOK_ALLOW_HTTP"), false)), log)
	go engine.Run(ctx, durDefault(os.Getenv("ALERT_INTERVAL"), 30*time.Second))

	httpSrv := &http.Server{
		Addr:              env("HTTP_ADDR", ":8080"),
		Handler:           srv.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
	}
	go func() {
		log.Info("hub API listening", "addr", httpSrv.Addr)
		if err := httpSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Error("http server", "err", err)
			stop()
		}
	}()

	<-ctx.Done()
	log.Info("shutting down")
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_ = httpSrv.Shutdown(shutdownCtx)
}

// dbConnectTimeout bounds how long the hub waits for the database to accept
// connections on startup (covers a fresh-volume TimescaleDB init + restart).
const dbConnectTimeout = 90 * time.Second

// connectWithRetry dials the database, retrying transient failures (DB still
// starting up, container not yet resolvable) with a fixed backoff until it
// succeeds or the timeout elapses.
func connectWithRetry(ctx context.Context, log *slog.Logger, dsn string, timeout time.Duration) (*store.PgStore, error) {
	deadline := time.Now().Add(timeout)
	for attempt := 1; ; attempt++ {
		pg, err := store.NewPgStore(ctx, dsn)
		if err == nil {
			return pg, nil
		}
		if ctx.Err() != nil || time.Now().After(deadline) {
			return nil, err
		}
		log.Warn("database not ready, retrying", "attempt", attempt, "err", err)
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(2 * time.Second):
		}
	}
}

// openStores returns result + catalog stores. With DATABASE_URL set both are
// Postgres-backed (migrations run first); otherwise both are in-memory so the
// hub can run with zero dependencies for local trials.
func openStores(ctx context.Context, log *slog.Logger) (store.ResultStore, store.CatalogStore, store.SubscriptionStore, store.AlertStore) {
	dsn := os.Getenv("DATABASE_URL")
	if dsn == "" {
		log.Warn("DATABASE_URL not set; using in-memory stores (data is not persisted)")
		return store.NewMemStore(), store.NewMemCatalog(), store.NewMemSubscriptions(), store.NewMemAlerts()
	}
	// Wait for the database instead of exiting on the first failure: on a fresh
	// volume TimescaleDB runs its init then restarts, so a hub started by
	// docker-compose (even with a healthcheck) can briefly hit "the database
	// system is starting up". Retry with backoff for a bounded window so the hub
	// rides out that startup/restart rather than crash-looping the whole stack.
	pg, err := connectWithRetry(ctx, log, dsn, dbConnectTimeout)
	if err != nil {
		log.Error("connect database", "err", err)
		os.Exit(1)
	}
	if err := pg.RunMigrations(ctx, env("MIGRATIONS_DIR", "./migrations")); err != nil {
		log.Error("run migrations", "err", err)
		os.Exit(1)
	}
	log.Info("connected to database, migrations applied")

	// Configure tiered result storage (compression + hourly/daily downsampling +
	// retention) so a hub's disk stays modest despite storing the whole network's
	// result stream. Failure here is logged but non-fatal — the hub still serves.
	def := store.DefaultTierConfig()
	tier := store.TierConfig{
		CompressAfterDays:   atoiDefault(os.Getenv("RESULT_COMPRESS_AFTER_DAYS"), def.CompressAfterDays),
		RawRetentionDays:    atoiDefault(os.Getenv("RESULT_RETENTION_DAYS"), def.RawRetentionDays),
		HourlyRetentionDays: atoiDefault(os.Getenv("RESULT_HOURLY_RETENTION_DAYS"), def.HourlyRetentionDays),
		DailyRetentionDays:  atoiDefault(os.Getenv("RESULT_DAILY_RETENTION_DAYS"), def.DailyRetentionDays),
	}
	if err := pg.ConfigureResultTiers(ctx, tier); err != nil {
		log.Error("configure result storage tiers (continuing without full tiering)", "err", err)
	} else {
		log.Info("result storage tiers configured", "raw_days", tier.RawRetentionDays,
			"hourly_days", tier.HourlyRetentionDays, "daily_days", tier.DailyRetentionDays)
	}
	return pg, store.NewPgCatalog(pg), store.NewPgSubscriptions(pg), store.NewPgAlerts(pg)
}

// seedCheck optionally creates one HTTP check on boot, signed by this hub and
// gossiped — a convenience so a fresh network isn't empty. It also creates a
// hub-owned subscription so the seeded check is actually monitored (only
// subscribed checks are assigned to probes).
func seedCheck(ctx context.Context, log *slog.Logger, id *identity.Identity, catalog store.CatalogStore, subs store.SubscriptionStore, mesh *p2p.Node) {
	target := os.Getenv("SEED_CHECK_TARGET")
	if target == "" {
		return
	}
	spec := protocol.CheckSpec{Type: protocol.CheckHTTP, Target: target, IntervalSeconds: 60}
	spec.ID = spec.DeriveID()
	sc, err := protocol.SignCatalogEntry(id, protocol.CatalogEntry{Spec: spec})
	if err != nil {
		log.Warn("seed check sign", "err", err)
		return
	}
	if err := catalog.UpsertCheck(ctx, sc); err != nil {
		log.Warn("seed check store", "err", err)
		return
	}
	_ = mesh.PublishCatalog(ctx, sc)

	// Hub subscribes to its own seed check so it gets monitored.
	ss := protocol.SignSubscription(id, protocol.Subscription{CheckID: spec.ID, IntervalSeconds: 60, UpdatedMS: time.Now().UnixMilli()})
	if err := subs.Upsert(ctx, ss); err == nil {
		_ = mesh.PublishSubscription(ctx, ss)
	}
	log.Info("seeded check", "target", target, "check_id", spec.ID)
}

// gossipLoop periodically re-broadcasts this hub's catalog, subscriptions,
// alert rules, and its own alert delivery states (anti-entropy) so newly-joined
// or previously-disconnected hubs converge on the full picture. Re-broadcasting
// delivery state is what makes failover deduplication reliable: a peer that
// missed the one-shot publish at delivery time still learns what was already
// notified before it might become responsible.
func gossipLoop(ctx context.Context, log *slog.Logger, id *identity.Identity, results store.ResultStore, catalog store.CatalogStore, subs store.SubscriptionStore, alerts store.AlertStore, mesh *p2p.Node, ob *outbox.Outbox, pushToHolders func(protocol.SignedResult), every time.Duration) {
	self := id.NodeID()
	ticker := time.NewTicker(every)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			// Re-broadcast recent results so a peer that missed the one-shot
			// publish (offline, joining late, partition) still converges. Stores
			// dedupe on (probe,check,ts), so re-delivery is free of duplicates.
			if recent, err := results.RecentSince(ctx, time.Now().Add(-resultGossipWindow).UnixMilli(), 1000); err == nil {
				for _, sr := range recent {
					_ = mesh.PublishResult(ctx, sr)
				}
			}
			// Re-broadcast and re-push outbox entries: results this hub submitted
			// but does not itself store. Anti-entropy repairs any that no holder
			// received at submit time; the direct push covers holders not in this
			// hub's result-topic mesh. Entries age out of the outbox after the
			// window, by which point a holder has converged on them.
			for _, sr := range ob.Recent() {
				_ = mesh.PublishResult(ctx, sr)
				if pushToHolders != nil {
					pushToHolders(sr)
				}
			}
			if entries, err := catalog.ListChecks(ctx); err == nil {
				for _, sc := range entries {
					_ = mesh.PublishCatalog(ctx, sc)
				}
			}
			if subList, err := subs.ListForGossip(ctx); err == nil {
				for _, ss := range subList {
					_ = mesh.PublishSubscription(ctx, ss)
				}
			}
			if ruleList, err := alerts.ListForGossip(ctx); err == nil {
				for _, sa := range ruleList {
					_ = mesh.PublishAlert(ctx, sa)
					// Re-broadcast only this hub's own delivery state for the
					// rule. Re-signing is deterministic (same content → same
					// bytes), and we never re-sign a peer's state under our key.
					if d, ok, derr := alerts.GetDeliveryBy(ctx, sa.Rule.ID(), self); derr == nil && ok {
						sd := protocol.SignDeliveryState(id, protocol.DeliveryState{
							RuleID: sa.Rule.ID(), Status: d.Status, TimestampMS: d.TimestampMS,
						})
						_ = mesh.PublishDelivery(ctx, sd)
					}
				}
			}
		}
	}
}

// storageWindow is how recently a hub must have been seen to count as a live
// storage holder for placement. Shorter than the directory display TTL so a
// departed hub's shards are reassigned promptly.
const storageWindow = 10 * time.Minute

const (
	// maxBackfillHorizon caps how far back a shard backfill reaches when raw
	// retention is unbounded ("keep forever"), so repair can't request unbounded
	// history from a holder.
	maxBackfillHorizon = 30 * 24 * time.Hour
	// backfillPage is how many rows one holder query pulls per page.
	backfillPage = 2000
	// backfillMaxPerShard caps a single shard's backfill so a runaway / spammed
	// shard can't pull unbounded data; the remainder is left to anti-entropy.
	backfillMaxPerShard = 200_000
	// backfillConcurrency bounds simultaneous shard backfills so the first
	// interest pass (which may cover many shards) doesn't fetch them all at once.
	backfillConcurrency = 4
)

// interestLoop recomputes this hub's storage interest from the live hub
// directory: the shards capacity-weighted rendezvous assigns it, plus pinned
// checks (its own probes' assignments and checks it is an alert recipient for).
// Recomputing on a timer picks up directory changes (hubs joining/leaving), so
// placement self-heals without coordination.
func interestLoop(ctx context.Context, self shard.Hub, dir *directory.Directory, srv *api.Server, alerts store.AlertStore, mesh *p2p.Node, set *interest.Set, backfill func(uint32), trusted func(string) bool, every time.Duration) {
	var prev map[uint32]bool
	// Throttle concurrent shard backfills (the first pass may cover many shards).
	sem := make(chan struct{}, backfillConcurrency)
	launch := func(s uint32) {
		go func() {
			sem <- struct{}{}
			defer func() { <-sem }()
			backfill(s)
		}()
	}
	recompute := func() {
		hubs := []shard.Hub{self}
		for _, ann := range dir.ActiveWithin(storageWindow) {
			hubs = append(hubs, shard.HubFrom(ann.HubID, ann.StorageCapacity, ann.StorageArchive, trusted(ann.HubID)))
		}
		assigned := shard.AssignedShards(self.ID, hubs, shard.Replication)

		pinned := srv.LocalProbeCheckIDs(ctx)
		if pinned == nil {
			pinned = map[string]bool{}
		}
		if rules, err := alerts.ListActive(ctx); err == nil {
			for _, sa := range rules {
				if _, ok := sa.Rule.Recipients[self.ID]; ok {
					pinned[sa.Rule.CheckID] = true
				}
			}
		}
		set.Update(self.Archive, assigned, pinned)

		// Subscribe to the shards we store, plus the shards of any pinned checks
		// (so a pinned check's results reach us live from other probes), so gossip
		// membership tracks storage responsibility.
		subscribed := map[uint32]bool{}
		if self.Archive {
			for s := uint32(0); s < shard.Count; s++ {
				subscribed[s] = true
			}
		} else {
			for s := range assigned {
				subscribed[s] = true
			}
			for checkID := range pinned {
				subscribed[shard.Of(checkID)] = true
			}
		}
		mesh.UpdateShards(ctx, subscribed)

		// Repair: backfill assigned shards. The first pass (prev == nil) backfills
		// every assigned shard — sync-on-connect alone only covers a bounded recent
		// window, so a hub restarting as a holder would otherwise hold a thin slice
		// of its shards' raw history. Later passes backfill only shards newly
		// assigned by churn. Throttled via the launch semaphore so a wide first
		// pass doesn't fetch all shards at once.
		if !self.Archive && backfill != nil {
			for s := range assigned {
				if prev == nil || !prev[s] {
					launch(s)
				}
			}
		}
		prev = assigned
	}

	recompute()
	ticker := time.NewTicker(every)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			recompute()
		}
	}
}

// seedHealInterval is how often, while isolated, the hub re-queries the seed
// directories to find a peer to dial.
const seedHealInterval = 5 * time.Minute

// fetchSeedPeers queries each seed hub's /api/v1/hubs and returns the deduped,
// vetted set of dialable libp2p multiaddrs advertised there. The fetch is
// SSRF-safe and each address is filtered against the private-peer policy, so a
// hostile seed can neither probe the operator's network nor steer dials into it.
func fetchSeedPeers(ctx context.Context, log *slog.Logger, seeds []string, allowPrivate bool) []string {
	if len(seeds) == 0 {
		return nil
	}
	client := netguard.SafeClient(netguard.Options{Timeout: 10 * time.Second, AllowPrivate: allowPrivate})
	seen := map[string]bool{}
	var out []string
	add := func(addrs []string) {
		for _, addr := range p2p.FilterDialable(addrs, allowPrivate) {
			if !seen[addr] {
				seen[addr] = true
				out = append(out, addr)
			}
		}
	}
	for _, base := range seeds {
		base = strings.TrimRight(base, "/")
		// The seed's own addresses (so we can dial it directly — the directory
		// lists peers, never self), plus the live peers it knows about.
		if self, err := fetchSeedSelf(ctx, client, base); err == nil {
			add(self)
		}
		anns, err := fetchSeedHubs(ctx, client, base)
		if err != nil {
			log.Warn("bootstrap seed fetch failed", "seed", base, "err", err)
			continue
		}
		for _, a := range anns {
			add(a.P2PAddrs)
		}
	}
	if len(out) > 0 {
		log.Info("discovered bootstrap peers from seed directory", "seeds", len(seeds), "peers", len(out))
	}
	return out
}

// fetchSeedSelf GETs {base}/api/v1/identity and returns the seed's own dialable
// addresses, so a new hub can bootstrap by dialing the seed directly.
func fetchSeedSelf(ctx context.Context, client *http.Client, base string) ([]string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, base+"/api/v1/identity", nil)
	if err != nil {
		return nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("seed returned %s", resp.Status)
	}
	var body struct {
		P2PAddrs []string `json:"p2p_addrs"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&body); err != nil {
		return nil, err
	}
	return body.P2PAddrs, nil
}

// fetchSeedHubs GETs {base}/api/v1/hubs and decodes the directory.
func fetchSeedHubs(ctx context.Context, client *http.Client, base string) ([]protocol.HubAnnouncement, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, base+"/api/v1/hubs", nil)
	if err != nil {
		return nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("seed returned %s", resp.Status)
	}
	var anns []protocol.HubAnnouncement
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&anns); err != nil {
		return nil, err
	}
	return anns, nil
}

// seedHealLoop re-bootstraps from the seed directories whenever the hub has no
// peers, recovering from a seed that was down at startup or a total partition.
// While connected it does nothing — the DHT handles ongoing discovery.
func seedHealLoop(ctx context.Context, log *slog.Logger, mesh *p2p.Node, seeds []string, allowPrivate bool) {
	ticker := time.NewTicker(seedHealInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if mesh.PeerCount() > 0 {
				continue
			}
			for _, p := range fetchSeedPeers(ctx, log, seeds, allowPrivate) {
				if err := mesh.Connect(ctx, p); err != nil {
					log.Debug("seed reconnect failed", "peer", p, "err", err)
				}
			}
		}
	}
}

// advertiseLoop periodically gossips this hub's signed announcement, if
// advertising is enabled and a PUBLIC_URL is configured.
func advertiseLoop(ctx context.Context, log *slog.Logger, id *identity.Identity, encPub []byte, self shard.Hub, mesh *p2p.Node, every time.Duration) {
	if !boolDefault(os.Getenv("ADVERTISE"), true) {
		log.Info("hub advertisement disabled")
		return
	}
	publicURL := strings.TrimRight(os.Getenv("PUBLIC_URL"), "/")
	if publicURL == "" {
		log.Warn("ADVERTISE is on but PUBLIC_URL is empty; not advertising")
		return
	}
	name := os.Getenv("HUB_NAME")
	loc := resolveLocation(ctx, os.Getenv("HUB_LOCATION"), boolDefault(os.Getenv("HUB_GEOIP"), true), log)
	log.Info("advertising hub", "public_url", publicURL)

	announce := func() {
		sa, err := protocol.SignHubAnnouncement(id, protocol.HubAnnouncement{
			PublicURL:       publicURL,
			Name:            name,
			Location:        loc,
			TimestampMS:     time.Now().UnixMilli(),
			EncPubKey:       encPub,
			StorageCapacity: self.Capacity,
			StorageArchive:  self.Archive,
			// Publicly-dialable libp2p addresses so peers can bootstrap straight
			// from the directory (re-evaluated each tick as reachability settles).
			P2PAddrs: mesh.PublicAddrs(),
		})
		if err != nil {
			log.Warn("sign announcement", "err", err)
			return
		}
		_ = mesh.PublishHub(ctx, sa)
	}

	ticker := time.NewTicker(every)
	defer ticker.Stop()
	announce()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			announce()
		}
	}
}

// resolveLocation determines this hub's self-declared location: HUB_LOCATION
// overrides, otherwise it is looked up from the public IP when geoip is enabled.
// A lookup failure is non-fatal — the hub advertises without a location.
func resolveLocation(ctx context.Context, declared string, geoEnabled bool, log *slog.Logger) protocol.Location {
	lctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	loc, auto, err := geoip.Resolve(lctx, declared, geoEnabled)
	switch {
	case err != nil:
		log.Warn("could not auto-detect hub location from IP; advertising without one", "err", err)
	case auto:
		log.Info("hub location auto-detected from public IP", "city", loc.City, "country", loc.Country,
			"lat", loc.Lat, "lon", loc.Lon)
	case loc != (protocol.Location{}):
		log.Info("hub location set from HUB_LOCATION", "city", loc.City, "country", loc.Country)
	}
	return loc
}

// alertNotifiers builds the delivery channels. All are plain outbound HTTPS to
// an owner-supplied destination, so none needs hub-operator configuration;
// allowHTTP (ALERT_WEBHOOK_ALLOW_HTTP) relaxes the https-only rule for trusted
// internal endpoints across every channel.
func alertNotifiers(allowHTTP bool) map[protocol.AlertChannel]alert.Notifier {
	return map[protocol.AlertChannel]alert.Notifier{
		protocol.AlertWebhook: alert.WebhookNotifier{AllowHTTP: allowHTTP},
		protocol.AlertNtfy:    alert.NtfyNotifier{AllowHTTP: allowHTTP},
		protocol.AlertDiscord: alert.DiscordNotifier{AllowHTTP: allowHTTP},
		protocol.AlertSlack:   alert.SlackNotifier{AllowHTTP: allowHTTP},
	}
}

func splitCSV(s string) []string {
	if strings.TrimSpace(s) == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func durDefault(s string, def time.Duration) time.Duration {
	if d, err := time.ParseDuration(strings.TrimSpace(s)); err == nil && d > 0 {
		return d
	}
	return def
}

func atoiDefault(s string, def int) int {
	if n, err := strconv.Atoi(strings.TrimSpace(s)); err == nil {
		return n
	}
	return def
}

func boolDefault(s string, def bool) bool {
	if s == "" {
		return def
	}
	b, err := strconv.ParseBool(strings.TrimSpace(s))
	if err != nil {
		return def
	}
	return b
}

func env(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}
