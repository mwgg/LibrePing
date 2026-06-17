// Package api serves the hub's HTTP/JSON endpoints: the probe-facing API
// (registration, per-probe check assignment, result submission), the
// catalog/creation API, and the dashboard-facing API (recent results, map
// data, peer-hub directory).
//
// The result-submission path is the local mirror of the P2P trust gate: a
// result POSTed by a probe is verified and policy-checked exactly like one
// arriving over gossip, then stored and re-published to the mesh.
package api

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/mwgg/libreping/hub/admit"
	"github.com/mwgg/libreping/hub/assign"
	"github.com/mwgg/libreping/hub/directory"
	"github.com/mwgg/libreping/hub/interest"
	"github.com/mwgg/libreping/hub/outbox"
	"github.com/mwgg/libreping/hub/remote"
	"github.com/mwgg/libreping/hub/shard"
	"github.com/mwgg/libreping/hub/store"
	"github.com/mwgg/libreping/hub/trust"
	"github.com/mwgg/libreping/pkg/identity"
	"github.com/mwgg/libreping/pkg/protocol"
)

// remoteCacheTTL bounds how long a fetched-from-holder result set is reused, so
// dashboard reads for non-held checks don't hammer holder hubs.
const remoteCacheTTL = 15 * time.Second

// storageWindow is how recently a peer hub must have been seen to count as a
// live storage holder (matches the hub's interest loop).
const storageWindow = 10 * time.Minute

func atoi64(s string) int64 {
	n, _ := strconv.ParseInt(strings.TrimSpace(s), 10, 64)
	return n
}

func atoiDefaultStr(s string, def int) int {
	if n, err := strconv.Atoi(strings.TrimSpace(s)); err == nil {
		return n
	}
	return def
}

// probeTTL bounds how long a registered probe is considered live for
// assignment. Probes re-register (heartbeat) well within this window.
const probeTTL = 3 * time.Minute

// Publisher gossips signed payloads to the mesh. *p2p.Node satisfies this.
type Publisher interface {
	PublishResult(ctx context.Context, sr protocol.SignedResult) error
	PublishCatalog(ctx context.Context, sc protocol.SignedCatalogEntry) error
	PublishSubscription(ctx context.Context, ss protocol.SignedSubscription) error
	PublishAlert(ctx context.Context, sa protocol.SignedAlertRule) error
}

// noopPublisher is used when the hub runs without a mesh (e.g. tests).
type noopPublisher struct{}

func (noopPublisher) PublishResult(context.Context, protocol.SignedResult) error        { return nil }
func (noopPublisher) PublishCatalog(context.Context, protocol.SignedCatalogEntry) error { return nil }
func (noopPublisher) PublishSubscription(context.Context, protocol.SignedSubscription) error {
	return nil
}
func (noopPublisher) PublishAlert(context.Context, protocol.SignedAlertRule) error { return nil }

// minSubIntervalFloor caps how frequently subscribers can drive a check.
const minSubIntervalFloor = 30

// registeredProbe is the hub's record of a probe that has registered with it,
// including the capacity it declared for assignment.
type registeredProbe struct {
	location  protocol.Location
	capacity  int
	supported map[protocol.CheckType]bool
	lastSeen  time.Time
}

// Server holds hub API state.
type Server struct {
	store       store.ResultStore
	catalog     store.CatalogStore
	subs        store.SubscriptionStore
	alerts      store.AlertStore
	mesh        Publisher
	identity    *identity.Identity
	encPubKey   []byte
	dir         *directory.Directory
	policy      trust.Policy
	redundancy  int
	log         *slog.Logger
	writeLimit  *ipRateLimiter
	meshDiagFn  func() any
	selfAddrsFn func() []string
	interest    *interest.Set
	self        shard.Hub
	remote      *remote.Client
	outbox      *outbox.Outbox

	mu     sync.Mutex
	probes map[string]registeredProbe
	now    func() time.Time

	rcMu        sync.Mutex
	remoteCache map[string]cachedResults
}

type cachedResults struct {
	at      time.Time
	results []protocol.SignedResult
}

// Config configures the API server.
type Config struct {
	Store         store.ResultStore
	Catalog       store.CatalogStore
	Subscriptions store.SubscriptionStore
	Alerts        store.AlertStore
	Mesh          Publisher
	Identity      *identity.Identity
	EncPubKey     []byte
	Directory     *directory.Directory
	Policy        trust.Policy
	Redundancy    int
	Logger        *slog.Logger
	// WriteRatePerMin caps per-IP requests to the write endpoints (create
	// check/subscription/alert, probe register). 0 uses a sane default; set
	// negative to disable.
	WriteRatePerMin int
	// MeshDiagnostics returns a JSON-serializable snapshot of P2P health for
	// GET /api/v1/p2p. Optional (nil → endpoint reports unavailable).
	MeshDiagnostics func() any
	// SelfAddrs returns this hub's own publicly-dialable libp2p multiaddrs, served
	// at GET /api/v1/identity so a new hub can bootstrap by dialing this one
	// directly (the hub directory lists peers, never self). Optional.
	SelfAddrs func() []string
	// Interest decides which submitted results this hub persists (partial
	// replication). Nil stores everything.
	Interest *interest.Set
	// SelfHub is this hub's storage identity (ID + capacity), used to compute
	// shard holders for on-demand reads of checks this hub doesn't store.
	SelfHub shard.Hub
	// AllowPrivatePeers lets holder fetches/pushes reach private/LAN addresses
	// (mirrors HUB_ALLOW_PRIVATE_PEERS). Default false blocks SSRF.
	AllowPrivatePeers bool
	// Outbox retains non-held submitted results for direct holder push + gossip
	// anti-entropy, so a non-holder home hub never silently drops a submission.
	// Nil disables retention (a hub that holds everything never needs it).
	Outbox *outbox.Outbox
}

// New builds a Server.
func New(cfg Config) *Server {
	if cfg.Mesh == nil {
		cfg.Mesh = noopPublisher{}
	}
	if cfg.Catalog == nil {
		cfg.Catalog = store.NewMemCatalog()
	}
	if cfg.Subscriptions == nil {
		cfg.Subscriptions = store.NewMemSubscriptions()
	}
	if cfg.Alerts == nil {
		cfg.Alerts = store.NewMemAlerts()
	}
	if cfg.Policy == nil {
		cfg.Policy = trust.Open{}
	}
	if cfg.Redundancy < 1 {
		cfg.Redundancy = 3
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	// Default the write rate to 120/min per IP (burst 30). 0 means "use
	// default"; a negative value disables the limiter.
	rate := cfg.WriteRatePerMin
	if rate == 0 {
		rate = 120
	}
	return &Server{
		store:       cfg.Store,
		catalog:     cfg.Catalog,
		subs:        cfg.Subscriptions,
		alerts:      cfg.Alerts,
		mesh:        cfg.Mesh,
		identity:    cfg.Identity,
		encPubKey:   cfg.EncPubKey,
		dir:         cfg.Directory,
		policy:      cfg.Policy,
		redundancy:  cfg.Redundancy,
		log:         cfg.Logger,
		writeLimit:  newIPRateLimiter(rate, rate/4+1),
		meshDiagFn:  cfg.MeshDiagnostics,
		selfAddrsFn: cfg.SelfAddrs,
		interest:    cfg.Interest,
		self:        cfg.SelfHub,
		remote:      remote.NewClient(cfg.AllowPrivatePeers),
		outbox:      cfg.Outbox,
		probes:      map[string]registeredProbe{},
		now:         time.Now,
		remoteCache: map[string]cachedResults{},
	}
}

// Handler returns the configured HTTP routes.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", s.handleHealth)
	mux.HandleFunc("GET /api/v1/identity", s.handleIdentity)
	mux.HandleFunc("GET /api/v1/p2p", s.handleP2P)
	mux.HandleFunc("POST /api/v1/probes/register", s.writeLimit.limit(s.handleRegister))
	mux.HandleFunc("GET /api/v1/checks", s.handleChecks)                           // assigned subset for ?probe_id=
	mux.HandleFunc("POST /api/v1/checks", s.writeLimit.limit(s.handleCreateCheck)) // create a monitor
	mux.HandleFunc("GET /api/v1/catalog", s.handleCatalog)                         // full global catalog
	mux.HandleFunc("POST /api/v1/results", s.handleSubmit)
	mux.HandleFunc("GET /api/v1/results/recent", s.handleRecent)
	mux.HandleFunc("GET /api/v1/results/query", s.handleQuery)     // holder query (by check_id or shard)
	mux.HandleFunc("GET /api/v1/results/history", s.handleHistory) // rolled-up history for one check
	mux.HandleFunc("GET /api/v1/locations", s.handleLocations)
	mux.HandleFunc("GET /api/v1/hubs", s.handleHubs)
	mux.HandleFunc("POST /api/v1/subscriptions", s.writeLimit.limit(s.handleSubscribe)) // create or tombstone (signed)
	mux.HandleFunc("GET /api/v1/services", s.handleServices)                            // my services for ?owner=
	mux.HandleFunc("POST /api/v1/alerts", s.writeLimit.limit(s.handleAlertRule))        // create or tombstone (signed)
	mux.HandleFunc("GET /api/v1/alerts", s.handleListAlerts)                            // my alerts for ?owner=
	return mux
}

func (s *Server) handleHealth(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// handleP2P reports mesh connectivity and storage coverage so operators can see
// whether the hub is federating and whether every result shard has enough
// holders (the durability invariant of partial replication).
func (s *Server) handleP2P(w http.ResponseWriter, _ *http.Request) {
	hubs := s.storageHubs()
	uncovered, under := coverage(hubs)
	// Trusted coverage ignores untrusted peers entirely, so a Sybil peer claiming
	// a big capacity / archive role can't make durability look healthier than the
	// operator's own + allowlisted hubs actually provide.
	trustedHubs := s.trustedStorageHubs()
	trustedUncovered, trustedUnder := coverage(trustedHubs)
	resp := map[string]any{
		"shards": map[string]any{
			"total":                    shard.Count,
			"replication":              shard.Replication,
			"storage_hubs":             len(hubs),
			"uncovered":                uncovered,
			"under_replicated":         under,
			"trusted_storage_hubs":     len(trustedHubs),
			"trusted_uncovered":        trustedUncovered,
			"trusted_under_replicated": trustedUnder,
		},
	}
	if s.meshDiagFn != nil {
		resp["mesh"] = s.meshDiagFn()
	}
	writeJSON(w, http.StatusOK, resp)
}

// coverage counts shards with no holder (results would be lost) and shards held
// by fewer than the replication target, over the given storage-hub set.
func coverage(hubs []shard.Hub) (uncovered, under int) {
	for sh := uint32(0); sh < shard.Count; sh++ {
		n := len(shard.Holders(sh, hubs, shard.Replication))
		if n == 0 {
			uncovered++
		}
		if n < shard.Replication {
			under++
		}
	}
	return uncovered, under
}

// handleIdentity reports this hub's self-certifying ID. Peer hubs call it to
// confirm an advertised URL really serves the hub that signed the announcement.
func (s *Server) handleIdentity(w http.ResponseWriter, _ *http.Request) {
	id := ""
	if s.identity != nil {
		id = s.identity.NodeID()
	}
	// enc_pubkey lets a browser seal alert destinations directly to this hub,
	// even when it isn't yet listed in any peer directory. p2p_addrs lets a new
	// hub bootstrap by dialing this one directly.
	var addrs []string
	if s.selfAddrsFn != nil {
		addrs = s.selfAddrsFn()
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"hub_id":     id,
		"enc_pubkey": s.encPubKey,
		"p2p_addrs":  addrs,
	})
}

// maxDeclaredCapacity caps the per-minute capacity a probe may declare, so a
// spoofed or greedy registration can't claim implausible capacity and soak up
// assignments. The probe also enforces its own hard token-bucket cap.
const maxDeclaredCapacity = 600

func (s *Server) handleRegister(w http.ResponseWriter, r *http.Request) {
	var reg protocol.SignedProbeRegistration
	if err := json.NewDecoder(r.Body).Decode(&reg); err != nil || reg.Registration.ProbeID == "" {
		http.Error(w, "invalid registration", http.StatusBadRequest)
		return
	}
	// A probe must prove possession of its key: the signature must verify and
	// ProbeID must derive from it. This stops registering ghost probes under
	// arbitrary IDs or overwriting a known probe's registration.
	if err := reg.Verify(); err != nil {
		http.Error(w, "registration failed verification: "+err.Error(), http.StatusBadRequest)
		return
	}
	req := reg.Registration
	capacity := req.MaxChecksPerMinute
	if capacity < 0 {
		capacity = 0
	}
	if capacity > maxDeclaredCapacity {
		capacity = maxDeclaredCapacity
	}
	supported := make(map[protocol.CheckType]bool, len(req.SupportedTypes))
	for _, t := range req.SupportedTypes {
		supported[t] = true
	}
	s.mu.Lock()
	s.probes[req.ProbeID] = registeredProbe{
		location:  req.Location,
		capacity:  capacity,
		supported: supported,
		lastSeen:  s.now(),
	}
	s.mu.Unlock()
	writeJSON(w, http.StatusOK, map[string]string{"status": "registered"})
}

// handleChecks returns the subset of the global catalog assigned to the
// requesting probe (?probe_id=…), computed fresh from the live probe set. Only
// checks with at least one live subscription are monitored.
func (s *Server) handleChecks(w http.ResponseWriter, r *http.Request) {
	probeID := r.URL.Query().Get("probe_id")
	specs, err := s.monitoredSpecs(r.Context())
	if err != nil {
		http.Error(w, "catalog error", http.StatusInternalServerError)
		return
	}
	assignment := assign.Assign(specs, s.liveProbes(), s.redundancy)

	out := assignment[probeID]
	if out == nil {
		out = []protocol.CheckSpec{}
	}
	writeJSON(w, http.StatusOK, out)
}

// monitoredSpecs returns the checks that should actually be monitored: those
// with ≥1 live subscription, each at the most-frequent subscriber's interval
// (floored). This ties probe capacity to real demand and dedups by check ID.
func (s *Server) monitoredSpecs(ctx context.Context) ([]protocol.CheckSpec, error) {
	entries, err := s.catalog.ListChecks(ctx)
	if err != nil {
		return nil, err
	}
	byID := make(map[string]protocol.CheckSpec, len(entries))
	for _, e := range entries {
		byID[e.Entry.Spec.ID] = e.Entry.Spec
	}

	subs, err := s.subs.ListActive(ctx)
	if err != nil {
		return nil, err
	}
	minInterval := map[string]int{} // check_id -> min subscriber interval
	for _, ss := range subs {
		iv := ss.Subscription.IntervalSeconds
		if iv < minSubIntervalFloor {
			iv = minSubIntervalFloor
		}
		if cur, ok := minInterval[ss.Subscription.CheckID]; !ok || iv < cur {
			minInterval[ss.Subscription.CheckID] = iv
		}
	}

	out := make([]protocol.CheckSpec, 0, len(minInterval))
	for checkID, iv := range minInterval {
		spec, ok := byID[checkID]
		if !ok {
			continue // subscribed to a check this hub hasn't learned yet
		}
		spec.IntervalSeconds = iv
		out = append(out, spec)
	}
	return out, nil
}

// handleCreateCheck adds a monitor to the network: derive its ID, sign it, store
// it, and gossip it so every hub converges on it.
func (s *Server) handleCreateCheck(w http.ResponseWriter, r *http.Request) {
	if s.identity == nil {
		http.Error(w, "hub has no signing identity", http.StatusServiceUnavailable)
		return
	}
	var req struct {
		Type            protocol.CheckType `json:"type"`
		Target          string             `json:"target"`
		IntervalSeconds int                `json:"interval_seconds"`
		Params          map[string]string  `json:"params,omitempty"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Target == "" || req.Type == "" {
		http.Error(w, "invalid check: type and target are required", http.StatusBadRequest)
		return
	}
	if req.IntervalSeconds <= 0 {
		req.IntervalSeconds = 60
	}
	spec := protocol.CheckSpec{Type: req.Type, Target: req.Target, IntervalSeconds: req.IntervalSeconds, Params: req.Params}
	spec.ID = spec.DeriveID()

	sc, err := protocol.SignCatalogEntry(s.identity, protocol.CatalogEntry{Spec: spec})
	if err != nil {
		http.Error(w, "sign error", http.StatusInternalServerError)
		return
	}
	if err := s.catalog.UpsertCheck(r.Context(), sc); err != nil {
		http.Error(w, "catalog error", http.StatusInternalServerError)
		return
	}
	if err := s.mesh.PublishCatalog(r.Context(), sc); err != nil {
		s.log.Warn("gossip catalog failed", "err", err)
	}
	writeJSON(w, http.StatusCreated, spec)
}

func (s *Server) handleCatalog(w http.ResponseWriter, r *http.Request) {
	specs, err := s.catalogSpecs(r.Context())
	if err != nil {
		http.Error(w, "catalog error", http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, specs)
}

// handleSubmit verifies and admits a probe-submitted result, then gossips it.
func (s *Server) handleSubmit(w http.ResponseWriter, r *http.Request) {
	var sr protocol.SignedResult
	if err := json.NewDecoder(r.Body).Decode(&sr); err != nil {
		http.Error(w, "invalid result", http.StatusBadRequest)
		return
	}
	if err := sr.Verify(); err != nil {
		// A failed signature is a hard reject — never store unverifiable data.
		http.Error(w, "result failed verification: "+err.Error(), http.StatusBadRequest)
		return
	}
	if !s.policy.Allow(sr.Content.ProbeID) {
		http.Error(w, "probe not permitted by trust policy", http.StatusForbidden)
		return
	}
	// Semantic admission after the crypto/trust gate: a valid signature doesn't
	// make a result meaningful (catalog target/type must match, timestamp sane,
	// fields bounded). Mirrors the mesh ingest path in hub/main.go.
	if err := admit.Result(r.Context(), s.catalog, sr, s.now()); err != nil {
		http.Error(w, "result rejected: "+err.Error(), http.StatusBadRequest)
		return
	}
	// Always gossip so the check's shard holders receive it; persist locally only
	// if this hub is responsible for the check (partial replication). A probe's
	// home hub holds its own probes' checks, so it keeps what it submits.
	if s.interest.Holds(sr.Content.CheckID) {
		if err := s.store.Insert(r.Context(), sr); err != nil {
			s.log.Error("store insert", "err", err)
			http.Error(w, "storage error", http.StatusInternalServerError)
			return
		}
	} else {
		// Non-holder home hub: gossip alone is best-effort and reaches nobody if no
		// shard holder is currently in this hub's result-topic mesh. Retain the
		// result for anti-entropy and push it directly to the shard holders over
		// HTTP, so it is durably delivered rather than silently dropped.
		s.outbox.Add(sr)
		go s.PushToHolders(sr)
	}
	if err := s.mesh.PublishResult(r.Context(), sr); err != nil {
		s.log.Warn("gossip publish failed", "err", err)
	}
	writeJSON(w, http.StatusAccepted, map[string]string{"status": "accepted"})
}

// PushToHolders best-effort delivers a result directly to its shard holders over
// HTTP (the holder re-runs verify→policy→admit on ingest). This is the durable
// path for a non-holder home hub: it does not depend on gossipsub mesh
// membership, so a holder that was never connected to the publisher still gets
// the result. Used on submit and re-tried from the anti-entropy loop.
func (s *Server) PushToHolders(sr protocol.SignedResult) {
	urls := s.holderURLs(sr.Content.CheckID)
	if len(urls) == 0 {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	for _, u := range urls {
		if err := s.remote.Submit(ctx, u, sr); err != nil {
			s.log.Debug("holder push failed", "url", u, "err", err)
		}
	}
}

func (s *Server) handleRecent(w http.ResponseWriter, r *http.Request) {
	results, err := s.store.Recent(r.Context(), 200)
	if err != nil {
		http.Error(w, "storage error", http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, results)
}

// handleQuery serves this hub's locally-held results, filtered by check_id or
// shard and a since_ms window. Peer hubs call it to read checks they don't hold
// (on-demand reads) and to backfill shards they've just been assigned (repair).
func (s *Server) handleQuery(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	sinceMS := atoi64(q.Get("since_ms"))
	beforeMS := atoi64(q.Get("before_ms")) // exclusive upper bound for backward pagination (0 = none)
	limit := atoiDefaultStr(q.Get("limit"), 1000)
	if limit <= 0 || limit > 5000 {
		limit = 5000
	}
	checkID := q.Get("check_id")
	shardStr := q.Get("shard")

	// Filter in the store BEFORE the limit so a busy network's other checks/shards
	// can't push the requested rows out of the window.
	var (
		out []protocol.SignedResult
		err error
	)
	switch {
	case checkID != "":
		out, err = s.store.RecentSinceCheck(r.Context(), checkID, sinceMS, beforeMS, limit)
	case shardStr != "":
		sh, perr := strconv.ParseUint(shardStr, 10, 32)
		if perr != nil {
			http.Error(w, "invalid shard", http.StatusBadRequest)
			return
		}
		out, err = s.store.RecentSinceShard(r.Context(), uint32(sh), sinceMS, beforeMS, limit)
	default:
		out, err = s.store.RecentSince(r.Context(), sinceMS, limit)
	}
	if err != nil {
		http.Error(w, "storage error", http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, out)
}

// defaultHistorySpan is the window served when from_ms/to_ms are omitted.
const defaultHistorySpan = 30 * 24 * time.Hour

// handleHistory serves rolled-up history (hourly/daily summaries) for one check
// from this hub's local store. The summaries are aggregates the hub derived
// locally — NOT per-result signed records — so they are returned as DTOs. This
// reads the local store only; a hub that does not hold the check serves an empty
// history (the live status on "my services" still cross-fetches from holders).
func (s *Server) handleHistory(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	checkID := q.Get("check_id")
	if checkID == "" {
		http.Error(w, "check_id is required", http.StatusBadRequest)
		return
	}
	toMS := atoi64(q.Get("to_ms"))
	if toMS <= 0 {
		toMS = s.now().UnixMilli()
	}
	fromMS := atoi64(q.Get("from_ms"))
	if fromMS <= 0 {
		fromMS = toMS - defaultHistorySpan.Milliseconds()
	}
	summaries, err := s.store.HistoryRange(r.Context(), checkID, fromMS, toMS)
	if err != nil {
		http.Error(w, "storage error", http.StatusInternalServerError)
		return
	}
	if summaries == nil {
		summaries = []store.HistorySummary{}
	}
	writeJSON(w, http.StatusOK, summaries)
}

// storageHubs is the set of hubs that participate in result placement: this hub
// plus the live, verified peer hubs from the directory. Peer capacity/archive
// claims are self-declared, so they pass through shard.HubFrom's trust boundary
// (untrusted peers are capacity-clamped and never treated as archives).
func (s *Server) storageHubs() []shard.Hub {
	hubs := []shard.Hub{s.self}
	if s.dir != nil {
		for _, ann := range s.dir.ActiveWithin(storageWindow) {
			hubs = append(hubs, shard.HubFrom(ann.HubID, ann.StorageCapacity, ann.StorageArchive, trust.TrustedStorage(s.policy, ann.HubID)))
		}
	}
	return hubs
}

// trustedStorageHubs is storageHubs restricted to hubs this operator actually
// trusts to hold data (self + allowlisted peers). Coverage over this set is the
// honest durability floor: a Sybil "archive" can inflate storageHubs coverage
// but cannot appear here.
func (s *Server) trustedStorageHubs() []shard.Hub {
	hubs := []shard.Hub{s.self}
	if s.dir != nil {
		for _, ann := range s.dir.ActiveWithin(storageWindow) {
			if trust.TrustedStorage(s.policy, ann.HubID) {
				hubs = append(hubs, shard.HubFrom(ann.HubID, ann.StorageCapacity, ann.StorageArchive, true))
			}
		}
	}
	return hubs
}

// holderURLs returns the public URLs of the hubs (other than this one) that hold
// the given check's shard, so this hub can fetch results it doesn't store.
func (s *Server) holderURLs(checkID string) []string {
	if s.dir == nil {
		return nil
	}
	holders := shard.Holders(shard.Of(checkID), s.storageHubs(), shard.Replication)
	urlByID := map[string]string{}
	for _, ann := range s.dir.ActiveWithin(storageWindow) {
		urlByID[ann.HubID] = ann.PublicURL
	}
	var urls []string
	for _, id := range holders {
		if id == s.self.ID {
			continue
		}
		if u := urlByID[id]; u != "" {
			urls = append(urls, u)
		}
	}
	return urls
}

// fetchRemote pulls a check's recent results from its holders, applying the SAME
// gate as local ingest before caching or returning anything: signature (done in
// remote.Fetch), the requested check_id/since_ms, the trust policy, and semantic
// admission against the local catalog. A holder is just a relay — without this a
// malicious holder could return validly-signed results from a non-allowlisted
// probe, or with a target/type that disagrees with the catalog, and poison the
// dashboard. Returns nil if this hub has no directory / no reachable holder.
func (s *Server) fetchRemote(ctx context.Context, checkID string, sinceMS int64) []protocol.SignedResult {
	s.rcMu.Lock()
	if c, ok := s.remoteCache[checkID]; ok && s.now().Sub(c.at) < remoteCacheTTL {
		s.rcMu.Unlock()
		return c.results
	}
	s.rcMu.Unlock()

	for _, u := range s.holderURLs(checkID) {
		res, err := s.remote.Fetch(ctx, u, remote.CheckQuery(checkID, sinceMS, 500))
		if err != nil {
			continue
		}
		admitted := s.admitRemote(ctx, checkID, sinceMS, res)
		s.rcMu.Lock()
		s.remoteCache[checkID] = cachedResults{at: s.now(), results: admitted}
		s.rcMu.Unlock()
		return admitted
	}
	return nil
}

// admitRemote filters holder-returned results through the local trust policy and
// semantic admission, the same gate stored results pass. Results for the wrong
// check, outside the window, from a disallowed probe, or disagreeing with the
// catalog are dropped rather than displayed.
func (s *Server) admitRemote(ctx context.Context, checkID string, sinceMS int64, res []protocol.SignedResult) []protocol.SignedResult {
	out := make([]protocol.SignedResult, 0, len(res))
	for _, sr := range res {
		if sr.Content.CheckID != checkID || sr.Content.TimestampMS < sinceMS {
			continue
		}
		if !s.policy.Allow(sr.Content.ProbeID) {
			continue
		}
		if admit.Result(ctx, s.catalog, sr, s.now()) != nil {
			continue
		}
		out = append(out, sr)
	}
	return out
}

func (s *Server) handleHubs(w http.ResponseWriter, _ *http.Request) {
	out := []protocol.HubAnnouncement{}
	if s.dir != nil {
		out = s.dir.List()
	}
	writeJSON(w, http.StatusOK, out)
}

// handleSubscribe accepts an owner-signed subscription (or tombstone), stores
// it, and gossips it. One endpoint handles both create and delete: a signed
// subscription with Deleted=true removes it.
func (s *Server) handleSubscribe(w http.ResponseWriter, r *http.Request) {
	var ss protocol.SignedSubscription
	if err := json.NewDecoder(r.Body).Decode(&ss); err != nil {
		http.Error(w, "invalid subscription", http.StatusBadRequest)
		return
	}
	if err := ss.Verify(); err != nil {
		http.Error(w, "subscription failed verification: "+err.Error(), http.StatusBadRequest)
		return
	}
	if err := s.subs.Upsert(r.Context(), ss); err != nil {
		http.Error(w, "storage error", http.StatusInternalServerError)
		return
	}
	if err := s.mesh.PublishSubscription(r.Context(), ss); err != nil {
		s.log.Warn("gossip subscription failed", "err", err)
	}
	writeJSON(w, http.StatusAccepted, map[string]string{"status": "accepted"})
}

// Service is the per-monitor view on the "my services" dashboard.
type Service struct {
	CheckID         string             `json:"check_id"`
	Type            protocol.CheckType `json:"type"`
	Target          string             `json:"target"`
	IntervalSeconds int                `json:"interval_seconds"`
	Overall         string             `json:"overall"`
	Locations       []LocationStatus   `json:"locations"`
}

// handleServices returns the services a given owner subscribes to, each joined
// with its latest per-location status from the (globally gossiped) results.
func (s *Server) handleServices(w http.ResponseWriter, r *http.Request) {
	owner := r.URL.Query().Get("owner")
	out := []Service{}
	if owner == "" {
		writeJSON(w, http.StatusOK, out)
		return
	}

	subs, err := s.subs.ListActive(r.Context())
	if err != nil {
		http.Error(w, "storage error", http.StatusInternalServerError)
		return
	}
	mine := map[string]struct{}{}
	for _, ss := range subs {
		if ss.Subscription.Owner == owner {
			mine[ss.Subscription.CheckID] = struct{}{}
		}
	}
	if len(mine) == 0 {
		writeJSON(w, http.StatusOK, out)
		return
	}

	entries, err := s.catalog.ListChecks(r.Context())
	if err != nil {
		http.Error(w, "catalog error", http.StatusInternalServerError)
		return
	}
	specByID := map[string]protocol.CheckSpec{}
	for _, e := range entries {
		if _, ok := mine[e.Entry.Spec.ID]; ok {
			specByID[e.Entry.Spec.ID] = e.Entry.Spec
		}
	}

	results, err := s.store.Recent(r.Context(), 1000)
	if err != nil {
		http.Error(w, "storage error", http.StatusInternalServerError)
		return
	}
	// latest result per (check_id, probe_id) from this hub's local store.
	seen := map[string]struct{}{}
	byCheck := map[string][]LocationStatus{}
	add := func(c protocol.ResultContent) {
		key := c.CheckID + "|" + c.ProbeID
		if _, ok := seen[key]; ok {
			return
		}
		seen[key] = struct{}{}
		byCheck[c.CheckID] = append(byCheck[c.CheckID], LocationStatus{
			ProbeID: c.ProbeID, Location: c.Location, Target: c.Target,
			CheckType: c.CheckType, Status: c.Status, RTTMillis: c.RTTMillis, TimestampMS: c.TimestampMS,
		})
	}
	for _, sr := range results {
		if _, ok := mine[sr.Content.CheckID]; ok {
			add(sr.Content)
		}
	}
	// Partial replication: for subscribed checks this hub does NOT store, fetch
	// the latest from the shard's holders on demand so "my services" still shows
	// a global view from any hub.
	since := s.now().Add(-24 * time.Hour).UnixMilli()
	for checkID := range mine {
		if s.interest.Holds(checkID) {
			continue
		}
		for _, sr := range s.fetchRemote(r.Context(), checkID, since) {
			add(sr.Content)
		}
	}

	for checkID := range mine {
		spec, ok := specByID[checkID]
		locs := byCheck[checkID]
		if locs == nil {
			// A freshly-added check has no results yet; emit an empty array, not
			// JSON null, so clients can iterate locations unconditionally.
			locs = []LocationStatus{}
		}
		svc := Service{CheckID: checkID, Locations: locs, Overall: overallStatus(locs)}
		if ok {
			svc.Type = spec.Type
			svc.Target = spec.Target
			svc.IntervalSeconds = spec.IntervalSeconds
		}
		out = append(out, svc)
	}
	writeJSON(w, http.StatusOK, out)
}

// overallStatus reduces per-location statuses to one: up if any location sees
// it up, else degraded if any degraded, else down; "unknown" with no data.
func overallStatus(locs []LocationStatus) string {
	if len(locs) == 0 {
		return "unknown"
	}
	anyDegraded := false
	for _, l := range locs {
		if l.Status == protocol.StatusUp {
			return string(protocol.StatusUp)
		}
		if l.Status == protocol.StatusDegraded {
			anyDegraded = true
		}
	}
	if anyDegraded {
		return string(protocol.StatusDegraded)
	}
	return string(protocol.StatusDown)
}

// handleAlertRule accepts an owner-signed alert rule (or tombstone), stores it,
// and gossips it.
func (s *Server) handleAlertRule(w http.ResponseWriter, r *http.Request) {
	var sa protocol.SignedAlertRule
	if err := json.NewDecoder(r.Body).Decode(&sa); err != nil {
		http.Error(w, "invalid alert rule", http.StatusBadRequest)
		return
	}
	if err := sa.Verify(); err != nil {
		http.Error(w, "alert rule failed verification: "+err.Error(), http.StatusBadRequest)
		return
	}
	if err := s.alerts.Upsert(r.Context(), sa); err != nil {
		http.Error(w, "storage error", http.StatusInternalServerError)
		return
	}
	if err := s.mesh.PublishAlert(r.Context(), sa); err != nil {
		s.log.Warn("gossip alert failed", "err", err)
	}
	writeJSON(w, http.StatusAccepted, map[string]string{"status": "accepted"})
}

// handleListAlerts returns the alert rules owned by ?owner=.
func (s *Server) handleListAlerts(w http.ResponseWriter, r *http.Request) {
	owner := r.URL.Query().Get("owner")
	rules, err := s.alerts.ListActive(r.Context())
	if err != nil {
		http.Error(w, "storage error", http.StatusInternalServerError)
		return
	}
	out := []protocol.AlertRule{}
	for _, sa := range rules {
		if owner == "" || sa.Rule.Owner == owner {
			out = append(out, sa.Rule)
		}
	}
	writeJSON(w, http.StatusOK, out)
}

// LocationStatus is a flattened, map-friendly view of the latest result per
// probe.
type LocationStatus struct {
	ProbeID     string             `json:"probe_id"`
	Location    protocol.Location  `json:"location"`
	Target      string             `json:"target"`
	CheckType   protocol.CheckType `json:"check_type"`
	Status      protocol.Status    `json:"status"`
	RTTMillis   float64            `json:"rtt_ms"`
	TimestampMS int64              `json:"timestamp_ms"`
}

func (s *Server) handleLocations(w http.ResponseWriter, r *http.Request) {
	results, err := s.store.Recent(r.Context(), 500)
	if err != nil {
		http.Error(w, "storage error", http.StatusInternalServerError)
		return
	}
	// Keep the newest result per (probe, target). Recent() is newest-first, so
	// the first occurrence wins.
	seen := map[string]struct{}{}
	out := []LocationStatus{}
	for _, sr := range results {
		key := sr.Content.ProbeID + "|" + sr.Content.Target
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, LocationStatus{
			ProbeID:     sr.Content.ProbeID,
			Location:    sr.Content.Location,
			Target:      sr.Content.Target,
			CheckType:   sr.Content.CheckType,
			Status:      sr.Content.Status,
			RTTMillis:   sr.Content.RTTMillis,
			TimestampMS: sr.Content.TimestampMS,
		})
	}
	writeJSON(w, http.StatusOK, out)
}

// catalogSpecs returns the bare specs from the stored catalog entries.
func (s *Server) catalogSpecs(ctx context.Context) ([]protocol.CheckSpec, error) {
	entries, err := s.catalog.ListChecks(ctx)
	if err != nil {
		return nil, err
	}
	specs := make([]protocol.CheckSpec, 0, len(entries))
	for _, e := range entries {
		specs = append(specs, e.Entry.Spec)
	}
	return specs, nil
}

// LocalProbeCheckIDs returns the set of check IDs currently assigned to this
// hub's own registered probes. These are "pinned" for storage: the hub produces
// this data, so it keeps it regardless of shard placement.
func (s *Server) LocalProbeCheckIDs(ctx context.Context) map[string]bool {
	specs, err := s.monitoredSpecs(ctx)
	if err != nil {
		return nil
	}
	assignment := assign.Assign(specs, s.liveProbes(), s.redundancy)
	out := map[string]bool{}
	for _, forProbe := range assignment {
		for _, sp := range forProbe {
			out[sp.ID] = true
		}
	}
	return out
}

// liveProbes snapshots probes seen within the TTL as assignment inputs.
func (s *Server) liveProbes() []assign.Probe {
	s.mu.Lock()
	defer s.mu.Unlock()
	cutoff := s.now().Add(-probeTTL)
	out := make([]assign.Probe, 0, len(s.probes))
	for id, p := range s.probes {
		if p.lastSeen.Before(cutoff) {
			delete(s.probes, id)
			continue
		}
		out = append(out, assign.Probe{ID: id, Capacity: p.capacity, SupportedTypes: p.supported})
	}
	return out
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}
