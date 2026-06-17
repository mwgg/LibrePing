// Package p2p implements LibrePing's decentralized hub mesh.
//
// Every hub is a first-class libp2p peer. Hubs discover each other (bootstrap
// peers + Kademlia DHT) and exchange results over a gossipsub topic — there is
// no central server. The hub's libp2p identity is derived from the same
// Ed25519 key as its LibrePing identity, so a hub's PeerID and its trust
// identity are one and the same.
//
// Trust is enforced on ingest, not on relay: every result arriving from the
// mesh is cryptographically verified (pkg/protocol.SignedResult.Verify) and run
// through the hub's trust policy before it is stored or re-gossiped. Because
// results carry the producing probe's public key inline, a hub can validate a
// result no matter how many peers relayed it — relaying hubs are never trusted,
// only the original signer is.
package p2p

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"log/slog"
	"strconv"
	"sync"
	"time"

	"github.com/libp2p/go-libp2p"
	dht "github.com/libp2p/go-libp2p-kad-dht"
	pubsub "github.com/libp2p/go-libp2p-pubsub"
	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	mdns "github.com/libp2p/go-libp2p/p2p/discovery/mdns"
	drouting "github.com/libp2p/go-libp2p/p2p/discovery/routing"
	dutil "github.com/libp2p/go-libp2p/p2p/discovery/util"
	ma "github.com/multiformats/go-multiaddr"
	manet "github.com/multiformats/go-multiaddr/net"

	"github.com/mwgg/libreping/hub/shard"
	"github.com/mwgg/libreping/hub/trust"
	"github.com/mwgg/libreping/pkg/protocol"
)

// mdnsServiceTag scopes local-network mDNS discovery to LibrePing hubs.
const mdnsServiceTag = "libreping-hub"

const (
	// controlTopic carries the global control plane — catalog, hub
	// announcements, subscriptions, alert rules, delivery state. Every hub
	// subscribes to it; it's small and bounded by entities, not time.
	controlTopic = "libreping/control/v1"
	// resultTopicPrefix + shard id names a per-shard result topic. Results are
	// partitioned across these so a hub only carries the shards it holds, rather
	// than the whole network's result stream.
	resultTopicPrefix = "libreping/results/v1/"
	// rendezvous is the DHT advertisement string hubs use to find each other.
	// One global rendezvous keeps hubs connected; per-shard gossipsub meshes then
	// form among the connected peers that subscribe to each shard.
	rendezvous = "libreping/v1"
	// syncProtocol is a request/response stream a freshly-connected hub uses to
	// pull recent results it missed while disconnected. Gossip is best-effort
	// (a peer offline at publish time never receives that result), so this
	// catch-up sync is what makes result convergence reliable rather than
	// hope-based.
	syncProtocol = "/libreping/sync/1.0.0"
	// syncWindow is how far back a catch-up sync requests, and syncMaxResults
	// bounds the response so one sync can't stream unbounded history.
	syncWindow     = 30 * time.Minute
	syncMaxResults = 5000

	// controlSyncProtocol is the control-plane analogue of syncProtocol: on
	// connect a hub pulls the peer's full catalog, subscriptions, and alert rules.
	// The result sync only carries results, so without this a freshly-joined hub
	// would have no monitors to assign to its probes until the next periodic
	// re-broadcast happened to reach it — leaving a new vantage point idle. Pulling
	// the control plane on connect makes a new hub start monitoring promptly.
	controlSyncProtocol = "/libreping/controlsync/1.0.0"
	// controlSyncMax bounds each list in a control-sync response.
	controlSyncMax = 20000
)

// syncRequest asks a peer for results at or after SinceMS (capped to Limit).
type syncRequest struct {
	SinceMS int64 `json:"since_ms"`
	Limit   int   `json:"limit"`
}

// controlSyncResponse is a peer's snapshot of the control plane, served on
// connect. Each item is independently signature-verified on ingest, so the
// relaying peer is never trusted — only the original signer.
type controlSyncResponse struct {
	Catalog       []protocol.SignedCatalogEntry `json:"catalog,omitempty"`
	Subscriptions []protocol.SignedSubscription `json:"subscriptions,omitempty"`
	Alerts        []protocol.SignedAlertRule    `json:"alerts,omitempty"`
}

// resultShardName is the gossipsub topic for a result shard.
func resultShardName(s uint32) string {
	return resultTopicPrefix + strconv.FormatUint(uint64(s), 10)
}

// IngestFunc handles a verified, trusted result that arrived from the mesh.
type IngestFunc func(ctx context.Context, sr protocol.SignedResult)

// IngestCatalogFunc handles a verified catalog entry from the mesh.
type IngestCatalogFunc func(ctx context.Context, sc protocol.SignedCatalogEntry)

// IngestHubFunc handles a verified hub announcement from the mesh.
type IngestHubFunc func(ctx context.Context, sa protocol.SignedHubAnnouncement)

// IngestSubscriptionFunc handles a verified subscription from the mesh.
type IngestSubscriptionFunc func(ctx context.Context, ss protocol.SignedSubscription)

// IngestAlertFunc handles a verified alert rule from the mesh.
type IngestAlertFunc func(ctx context.Context, sa protocol.SignedAlertRule)

// IngestDeliveryFunc handles a verified delivery-state from the mesh.
type IngestDeliveryFunc func(ctx context.Context, sd protocol.SignedDeliveryState)

// Config configures a Node.
type Config struct {
	// PrivateKey is the hub's Ed25519 key — its libp2p and trust identity.
	PrivateKey ed25519.PrivateKey
	// ListenAddrs are libp2p multiaddrs to listen on; defaults to a random TCP
	// port on all interfaces.
	ListenAddrs []string
	// AnnounceAddrs are publicly-reachable multiaddrs to advertise to peers in
	// addition to (or instead of) the auto-detected ones. Set this on a NAT'd or
	// containerized hub whose locally-observed addresses are not dialable from
	// outside (e.g. /ip4/203.0.113.10/tcp/4001).
	AnnounceAddrs []string
	// StaticRelays are full /p2p relay multiaddrs to use for AutoRelay, so a
	// hub behind NAT stays reachable via a relay when direct dialing fails.
	StaticRelays []string
	// EnableMDNS turns on local-network (mDNS) peer discovery, handy for
	// development or a LAN of hubs.
	EnableMDNS bool
	// ResultsSince supplies recent results to serve a peer's catch-up sync
	// request. Typically resultStore.RecentSince. If nil, this hub answers sync
	// requests with nothing (it still pulls from peers).
	ResultsSince func(ctx context.Context, sinceMS int64, limit int) ([]protocol.SignedResult, error)
	// CatalogSnapshot/SubscriptionSnapshot/AlertSnapshot supply this hub's full
	// control plane to serve a peer's on-connect control-sync. Typically
	// catalog.ListChecks / subs.ListForGossip / alerts.ListForGossip. Nil ones are
	// served as empty.
	CatalogSnapshot      func(ctx context.Context) ([]protocol.SignedCatalogEntry, error)
	SubscriptionSnapshot func(ctx context.Context) ([]protocol.SignedSubscription, error)
	AlertSnapshot        func(ctx context.Context) ([]protocol.SignedAlertRule, error)
	// Ingest is called for each verified+trusted result from peers.
	Ingest IngestFunc
	// IngestCatalog is called for each verified catalog entry from peers.
	IngestCatalog IngestCatalogFunc
	// IngestHub is called for each verified hub announcement from peers.
	IngestHub IngestHubFunc
	// IngestSubscription is called for each verified subscription from peers.
	IngestSubscription IngestSubscriptionFunc
	// IngestAlert is called for each verified alert rule from peers.
	IngestAlert IngestAlertFunc
	// IngestDelivery is called for each verified delivery-state from peers.
	IngestDelivery IngestDeliveryFunc
	// Policy decides which result signers are admitted; defaults to trust.Open.
	Policy trust.Policy
	Logger *slog.Logger
}

// Node is a hub's presence on the P2P mesh.
type Node struct {
	host               host.Host
	dht                *dht.IpfsDHT
	ps                 *pubsub.PubSub
	control            *pubsub.Topic
	controlSub         *pubsub.Subscription
	ingest             IngestFunc
	ingestCatalog      IngestCatalogFunc
	ingestHub          IngestHubFunc
	ingestSubscription IngestSubscriptionFunc
	ingestAlert        IngestAlertFunc
	ingestDelivery     IngestDeliveryFunc
	resultsSince       func(ctx context.Context, sinceMS int64, limit int) ([]protocol.SignedResult, error)
	catalogSnapshot    func(ctx context.Context) ([]protocol.SignedCatalogEntry, error)
	subSnapshot        func(ctx context.Context) ([]protocol.SignedSubscription, error)
	alertSnapshot      func(ctx context.Context) ([]protocol.SignedAlertRule, error)
	policy             trust.Policy
	log                *slog.Logger
	mdnsSvc            mdns.Service

	// smu guards the per-shard result topics. joined caches every shard topic we
	// have Join()ed (for publish and/or subscribe); shardSubs are the shards we
	// are actively subscribed to (and thus store results for).
	smu       sync.Mutex
	joined    map[uint32]*pubsub.Topic
	shardSubs map[uint32]*shardReader
}

// shardReader is an active subscription to one result shard topic.
type shardReader struct {
	sub    *pubsub.Subscription
	cancel context.CancelFunc
}

// New creates a libp2p host, joins the results topic, and starts the ingest
// loop. Call Bootstrap afterwards to connect to peers and enable discovery.
func New(ctx context.Context, cfg Config) (*Node, error) {
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	if cfg.Policy == nil {
		cfg.Policy = trust.Open{}
	}

	priv, err := crypto.UnmarshalEd25519PrivateKey(cfg.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("p2p: load identity key: %w", err)
	}

	listen := cfg.ListenAddrs
	if len(listen) == 0 {
		listen = []string{"/ip4/0.0.0.0/tcp/0"}
	}

	opts := []libp2p.Option{
		libp2p.Identity(priv),
		libp2p.ListenAddrStrings(listen...),
		// Reachability: ask the gateway to map the port, run the AutoNAT service
		// so peers can learn their own reachability, and hole-punch through NATs
		// when a relayed connection exists. These make a NAS-behind-NAT hub far
		// more likely to be dialable without manual port-forwarding.
		libp2p.NATPortMap(),
		libp2p.EnableNATService(),
		libp2p.EnableHolePunching(),
	}

	// Advertise operator-declared public addresses. Auto-detected addresses can
	// be container-internal/private and undialable; AddrsFactory lets the
	// operator append the real ones (and we drop obviously-unroutable announces).
	if announce := parseMultiaddrs(cfg.Logger, cfg.AnnounceAddrs); len(announce) > 0 {
		opts = append(opts, libp2p.AddrsFactory(func(addrs []ma.Multiaddr) []ma.Multiaddr {
			return append(addrs, announce...)
		}))
	}

	// AutoRelay via operator-supplied static relays keeps a NAT'd hub reachable
	// through a relay when direct dialing fails.
	if relays := parseAddrInfos(cfg.Logger, cfg.StaticRelays); len(relays) > 0 {
		opts = append(opts, libp2p.EnableAutoRelayWithStaticRelays(relays))
	}

	h, err := libp2p.New(opts...)
	if err != nil {
		return nil, err
	}

	ps, err := pubsub.NewGossipSub(ctx, h)
	if err != nil {
		_ = h.Close()
		return nil, err
	}
	control, err := ps.Join(controlTopic)
	if err != nil {
		_ = h.Close()
		return nil, err
	}
	controlSub, err := control.Subscribe()
	if err != nil {
		_ = h.Close()
		return nil, err
	}
	kad, err := dht.New(ctx, h)
	if err != nil {
		_ = h.Close()
		return nil, err
	}

	n := &Node{
		host: h, dht: kad, ps: ps, control: control, controlSub: controlSub,
		ingest: cfg.Ingest, ingestCatalog: cfg.IngestCatalog, ingestHub: cfg.IngestHub,
		ingestSubscription: cfg.IngestSubscription, ingestAlert: cfg.IngestAlert,
		ingestDelivery: cfg.IngestDelivery, resultsSince: cfg.ResultsSince,
		catalogSnapshot: cfg.CatalogSnapshot, subSnapshot: cfg.SubscriptionSnapshot,
		alertSnapshot: cfg.AlertSnapshot,
		policy:        cfg.Policy, log: cfg.Logger,
		joined: map[uint32]*pubsub.Topic{}, shardSubs: map[uint32]*shardReader{},
	}

	// Serve catch-up sync requests, and pull from each peer as it connects so a
	// freshly-joined or reconnected hub converges on recent results AND the control
	// plane (catalog, subscriptions, alerts) instead of only receiving whatever is
	// gossiped after it joins.
	h.SetStreamHandler(syncProtocol, n.handleSyncStream)
	h.SetStreamHandler(controlSyncProtocol, n.handleControlSyncStream)
	h.Network().Notify(&syncNotifee{node: n, ctx: ctx})

	// Default to full replication — subscribe to every result shard until the hub
	// narrows its interest via UpdateShards. A Node that is never told its
	// interest therefore behaves exactly like the old store-everything hub.
	all := make(map[uint32]bool, shard.Count)
	for s := uint32(0); s < shard.Count; s++ {
		all[s] = true
	}
	n.UpdateShards(ctx, all)

	// Local-network discovery: useful for a LAN of hubs or development where the
	// DHT has no public bootstrap to reach.
	if cfg.EnableMDNS {
		svc := mdns.NewMdnsService(h, mdnsServiceTag, &mdnsNotifee{host: h, log: cfg.Logger})
		if err := svc.Start(); err != nil {
			cfg.Logger.Warn("mdns start failed", "err", err)
		} else {
			n.mdnsSvc = svc
		}
	}

	go n.controlReadLoop(ctx)
	return n, nil
}

// UpdateShards sets the result shards this hub subscribes to (and therefore
// stores). It joins+subscribes newly-wanted shards, starting a reader for each,
// and unsubscribes shards no longer wanted. Called from the hub's interest loop
// as placement changes, so gossip membership tracks storage responsibility.
func (n *Node) UpdateShards(ctx context.Context, want map[uint32]bool) {
	n.smu.Lock()
	defer n.smu.Unlock()
	for s := range want {
		if _, ok := n.shardSubs[s]; ok {
			continue
		}
		t, err := n.topicForShardLocked(s)
		if err != nil {
			n.log.Warn("join shard topic", "shard", s, "err", err)
			continue
		}
		sub, err := t.Subscribe()
		if err != nil {
			n.log.Warn("subscribe shard topic", "shard", s, "err", err)
			continue
		}
		rctx, cancel := context.WithCancel(ctx)
		n.shardSubs[s] = &shardReader{sub: sub, cancel: cancel}
		go n.shardReadLoop(rctx, sub)
	}
	for s, r := range n.shardSubs {
		if want[s] {
			continue
		}
		r.cancel()
		r.sub.Cancel()
		delete(n.shardSubs, s)
	}
}

// topicForShardLocked returns the (cached) gossipsub topic for a shard, joining
// it on first use. Caller must hold smu.
func (n *Node) topicForShardLocked(s uint32) (*pubsub.Topic, error) {
	if t, ok := n.joined[s]; ok {
		return t, nil
	}
	t, err := n.ps.Join(resultShardName(s))
	if err != nil {
		return nil, err
	}
	n.joined[s] = t
	return t, nil
}

// mdnsNotifee connects to peers discovered on the local network.
type mdnsNotifee struct {
	host host.Host
	log  *slog.Logger
}

func (m *mdnsNotifee) HandlePeerFound(pi peer.AddrInfo) {
	if pi.ID == m.host.ID() {
		return
	}
	if err := m.host.Connect(context.Background(), pi); err != nil {
		m.log.Debug("mdns connect failed", "peer", pi.ID, "err", err)
	}
}

// parseMultiaddrs parses a list of multiaddr strings, logging and skipping bad
// ones rather than failing hub startup.
func parseMultiaddrs(log *slog.Logger, addrs []string) []ma.Multiaddr {
	out := make([]ma.Multiaddr, 0, len(addrs))
	for _, a := range addrs {
		if a == "" {
			continue
		}
		m, err := ma.NewMultiaddr(a)
		if err != nil {
			log.Warn("ignoring invalid announce multiaddr", "addr", a, "err", err)
			continue
		}
		out = append(out, m)
	}
	return out
}

// parseAddrInfos parses full /p2p relay multiaddrs into peer.AddrInfo.
func parseAddrInfos(log *slog.Logger, addrs []string) []peer.AddrInfo {
	out := make([]peer.AddrInfo, 0, len(addrs))
	for _, a := range addrs {
		if a == "" {
			continue
		}
		ai, err := peer.AddrInfoFromString(a)
		if err != nil {
			log.Warn("ignoring invalid relay multiaddr", "addr", a, "err", err)
			continue
		}
		out = append(out, *ai)
	}
	return out
}

// syncNotifee triggers a catch-up sync from each peer as it connects.
type syncNotifee struct {
	node *Node
	ctx  context.Context
}

func (s *syncNotifee) Connected(_ network.Network, c network.Conn) {
	go s.node.syncFrom(s.ctx, c.RemotePeer())
	go s.node.controlSyncFrom(s.ctx, c.RemotePeer())
}
func (s *syncNotifee) Disconnected(network.Network, network.Conn) {}
func (s *syncNotifee) Listen(network.Network, ma.Multiaddr)       {}
func (s *syncNotifee) ListenClose(network.Network, ma.Multiaddr)  {}

// handleSyncStream answers a peer's catch-up request with this hub's recent
// results. The response is bounded in time window and count.
func (n *Node) handleSyncStream(s network.Stream) {
	defer s.Close()
	_ = s.SetDeadline(time.Now().Add(30 * time.Second))

	var req syncRequest
	if err := json.NewDecoder(s).Decode(&req); err != nil {
		return
	}
	if n.resultsSince == nil {
		_ = json.NewEncoder(s).Encode([]protocol.SignedResult{})
		return
	}
	limit := req.Limit
	if limit <= 0 || limit > syncMaxResults {
		limit = syncMaxResults
	}
	results, err := n.resultsSince(context.Background(), req.SinceMS, limit)
	if err != nil {
		n.log.Debug("sync: fetch results", "err", err)
		return
	}
	_ = json.NewEncoder(s).Encode(results)
}

// syncFrom pulls recent results from a peer and ingests them through the same
// verify→policy→ingest gate as gossiped results, so a relaying peer is never
// trusted — only the original signer is.
func (n *Node) syncFrom(ctx context.Context, p peer.ID) {
	if p == n.host.ID() {
		return
	}
	streamCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	s, err := n.host.NewStream(streamCtx, p, syncProtocol)
	if err != nil {
		return // peer may not speak the sync protocol; that's fine
	}
	defer s.Close()
	_ = s.SetDeadline(time.Now().Add(30 * time.Second))

	since := time.Now().Add(-syncWindow).UnixMilli()
	if err := json.NewEncoder(s).Encode(syncRequest{SinceMS: since, Limit: syncMaxResults}); err != nil {
		return
	}
	var results []protocol.SignedResult
	if err := json.NewDecoder(s).Decode(&results); err != nil {
		n.log.Debug("sync: decode response", "peer", p, "err", err)
		return
	}
	for _, sr := range results {
		n.handleResult(ctx, sr) // re-verifies signature + applies trust policy
	}
	if len(results) > 0 {
		n.log.Debug("sync: ingested results from peer", "peer", p, "count", len(results))
	}
}

// handleControlSyncStream answers a peer's on-connect control-plane catch-up
// with this hub's full catalog, subscriptions, and alert rules (each bounded).
func (n *Node) handleControlSyncStream(s network.Stream) {
	defer s.Close()
	_ = s.SetDeadline(time.Now().Add(30 * time.Second))

	ctx := context.Background()
	var resp controlSyncResponse
	if n.catalogSnapshot != nil {
		if c, err := n.catalogSnapshot(ctx); err == nil {
			resp.Catalog = capSlice(c, controlSyncMax)
		}
	}
	if n.subSnapshot != nil {
		if subs, err := n.subSnapshot(ctx); err == nil {
			resp.Subscriptions = capSlice(subs, controlSyncMax)
		}
	}
	if n.alertSnapshot != nil {
		if a, err := n.alertSnapshot(ctx); err == nil {
			resp.Alerts = capSlice(a, controlSyncMax)
		}
	}
	_ = json.NewEncoder(s).Encode(resp)
}

// controlSyncFrom pulls a peer's control plane on connect and ingests each item
// through the same verify gate as gossip, so a freshly-joined hub has the
// monitors to assign to its probes immediately rather than waiting for the next
// periodic re-broadcast to reach it.
func (n *Node) controlSyncFrom(ctx context.Context, p peer.ID) {
	if p == n.host.ID() {
		return
	}
	streamCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	s, err := n.host.NewStream(streamCtx, p, controlSyncProtocol)
	if err != nil {
		return // peer may not speak the control-sync protocol; that's fine
	}
	defer s.Close()
	_ = s.SetDeadline(time.Now().Add(30 * time.Second))

	var resp controlSyncResponse
	if err := json.NewDecoder(s).Decode(&resp); err != nil {
		n.log.Debug("control-sync: decode response", "peer", p, "err", err)
		return
	}
	for _, sc := range resp.Catalog {
		n.handleCatalog(ctx, sc)
	}
	for _, ss := range resp.Subscriptions {
		n.handleSubscription(ctx, ss)
	}
	for _, sa := range resp.Alerts {
		n.handleAlert(ctx, sa)
	}
	if len(resp.Catalog)+len(resp.Subscriptions)+len(resp.Alerts) > 0 {
		n.log.Debug("control-sync: ingested from peer", "peer", p,
			"catalog", len(resp.Catalog), "subs", len(resp.Subscriptions), "alerts", len(resp.Alerts))
	}
}

// capSlice returns s truncated to at most n elements.
func capSlice[T any](s []T, n int) []T {
	if len(s) > n {
		return s[:n]
	}
	return s
}

// Bootstrap connects to the given peer multiaddrs and starts DHT-based peer
// discovery so the hub keeps finding new peers over time.
func (n *Node) Bootstrap(ctx context.Context, peers []string) error {
	for _, p := range peers {
		if p == "" {
			continue
		}
		if err := n.Connect(ctx, p); err != nil {
			n.log.Warn("bootstrap connect failed", "peer", p, "err", err)
		}
	}
	if err := n.dht.Bootstrap(ctx); err != nil {
		return fmt.Errorf("p2p: dht bootstrap: %w", err)
	}
	rd := drouting.NewRoutingDiscovery(n.dht)
	dutil.Advertise(ctx, rd, rendezvous)
	go n.discoverLoop(ctx, rd)
	return nil
}

// Connect dials a peer given a full multiaddr including its /p2p/<id> suffix.
func (n *Node) Connect(ctx context.Context, addr string) error {
	ai, err := peer.AddrInfoFromString(addr)
	if err != nil {
		return err
	}
	return n.host.Connect(ctx, *ai)
}

// PublishResult gossips a signed result to its shard's topic. The publisher need
// not be subscribed to (i.e. store) that shard — a probe's home hub routes the
// result to the shard's holders even when it doesn't hold the shard itself.
func (n *Node) PublishResult(ctx context.Context, sr protocol.SignedResult) error {
	data, err := json.Marshal(protocol.GossipEnvelope{Kind: protocol.GossipResult, Result: &sr})
	if err != nil {
		return err
	}
	n.smu.Lock()
	t, err := n.topicForShardLocked(shard.Of(sr.Content.CheckID))
	n.smu.Unlock()
	if err != nil {
		return err
	}
	return t.Publish(ctx, data)
}

// PublishCatalog gossips a signed catalog entry on the control topic.
func (n *Node) PublishCatalog(ctx context.Context, sc protocol.SignedCatalogEntry) error {
	return n.publishControl(ctx, protocol.GossipEnvelope{Kind: protocol.GossipCatalog, Catalog: &sc})
}

// PublishHub gossips this hub's signed announcement on the control topic.
func (n *Node) PublishHub(ctx context.Context, sa protocol.SignedHubAnnouncement) error {
	return n.publishControl(ctx, protocol.GossipEnvelope{Kind: protocol.GossipHub, Hub: &sa})
}

// PublishSubscription gossips a signed subscription on the control topic.
func (n *Node) PublishSubscription(ctx context.Context, ss protocol.SignedSubscription) error {
	return n.publishControl(ctx, protocol.GossipEnvelope{Kind: protocol.GossipSubscription, Subscription: &ss})
}

// PublishAlert gossips a signed alert rule on the control topic.
func (n *Node) PublishAlert(ctx context.Context, sa protocol.SignedAlertRule) error {
	return n.publishControl(ctx, protocol.GossipEnvelope{Kind: protocol.GossipAlert, Alert: &sa})
}

// PublishDelivery gossips a signed delivery-state on the control topic.
func (n *Node) PublishDelivery(ctx context.Context, sd protocol.SignedDeliveryState) error {
	return n.publishControl(ctx, protocol.GossipEnvelope{Kind: protocol.GossipDelivery, Delivery: &sd})
}

func (n *Node) publishControl(ctx context.Context, env protocol.GossipEnvelope) error {
	data, err := json.Marshal(env)
	if err != nil {
		return err
	}
	return n.control.Publish(ctx, data)
}

// Addrs returns this hub's dialable multiaddrs (with /p2p/<id>), suitable for
// sharing as bootstrap peers.
func (n *Node) Addrs() []string {
	ai := peer.AddrInfo{ID: n.host.ID(), Addrs: n.host.Addrs()}
	p2pAddrs, err := peer.AddrInfoToP2pAddrs(&ai)
	if err != nil {
		return nil
	}
	out := make([]string, 0, len(p2pAddrs))
	for _, a := range p2pAddrs {
		out = append(out, a.String())
	}
	return out
}

// PublicAddrs returns this hub's publicly-dialable multiaddrs (with /p2p/<id>),
// filtering out loopback/private/container-internal addresses. These are what a
// hub advertises so other hubs can dial it straight from the directory; an empty
// result means the hub has no public address (e.g. behind NAT without
// P2P_ANNOUNCE_ADDRS) and so cannot serve as a bootstrap target.
func (n *Node) PublicAddrs() []string {
	// Filter the transport addresses (no /p2p suffix) for public reachability,
	// then attach the peer ID — IsPublicAddr inspects the IP component, so it must
	// see the bare transport addr.
	var pub []ma.Multiaddr
	for _, a := range n.host.Addrs() {
		if manet.IsPublicAddr(a) {
			pub = append(pub, a)
		}
	}
	if len(pub) == 0 {
		return nil
	}
	p2pAddrs, err := peer.AddrInfoToP2pAddrs(&peer.AddrInfo{ID: n.host.ID(), Addrs: pub})
	if err != nil {
		return nil
	}
	out := make([]string, 0, len(p2pAddrs))
	for _, a := range p2pAddrs {
		out = append(out, a.String())
	}
	return out
}

// PeerCount is the number of peers this hub currently has a connection to.
func (n *Node) PeerCount() int { return len(n.host.Network().Peers()) }

// FilterDialable keeps the well-formed multiaddr strings, dropping malformed ones
// and (unless allowPrivate) private/loopback/container-internal addresses. Used
// to vet bootstrap peers discovered from a seed directory before dialing them, so
// a hostile seed can't steer a hub into dialing its operator's internal network.
func FilterDialable(addrs []string, allowPrivate bool) []string {
	out := make([]string, 0, len(addrs))
	for _, s := range addrs {
		m, err := ma.NewMultiaddr(s)
		if err != nil {
			continue
		}
		// Must carry a /p2p/<id> so we dial a specific identity, not an open IP.
		transport, id := peer.SplitAddr(m)
		if transport == nil || id == "" {
			continue
		}
		if !allowPrivate && !manet.IsPublicAddr(transport) {
			continue
		}
		out = append(out, s)
	}
	return out
}

// ID returns the hub's libp2p peer ID.
func (n *Node) ID() peer.ID { return n.host.ID() }

// TopicPeers lists peers currently in the control topic — i.e. every other hub,
// since all hubs subscribe to it. Used by tests and diagnostics as a measure of
// mesh connectivity.
func (n *Node) TopicPeers() []peer.ID { return n.control.ListPeers() }

// SubscribedShards returns how many result shards this hub currently holds.
func (n *Node) SubscribedShards() int {
	n.smu.Lock()
	defer n.smu.Unlock()
	return len(n.shardSubs)
}

// Diagnostics is an observable snapshot of the node's mesh health, surfaced at
// GET /api/v1/p2p so operators can tell whether a hub is actually federating
// (peers connected, topic peers present, DHT populated) or silently isolated.
type Diagnostics struct {
	PeerID           string   `json:"peer_id"`
	Addrs            []string `json:"addrs"`
	ConnectedPeers   int      `json:"connected_peers"`
	TopicPeers       int      `json:"topic_peers"`
	SubscribedShards int      `json:"subscribed_shards"`
	TotalShards      int      `json:"total_shards"`
	DHTRoutingTable  int      `json:"dht_routing_table"`
}

// Diagnostics returns a snapshot of mesh connectivity and storage coverage.
func (n *Node) Diagnostics() Diagnostics {
	return Diagnostics{
		PeerID:           n.host.ID().String(),
		Addrs:            n.Addrs(),
		ConnectedPeers:   len(n.host.Network().Peers()),
		TopicPeers:       len(n.control.ListPeers()),
		SubscribedShards: n.SubscribedShards(),
		TotalShards:      shard.Count,
		DHTRoutingTable:  n.dht.RoutingTable().Size(),
	}
}

// Close shuts the node down.
func (n *Node) Close() error {
	if n.mdnsSvc != nil {
		_ = n.mdnsSvc.Close()
	}
	n.smu.Lock()
	for s, r := range n.shardSubs {
		r.cancel()
		r.sub.Cancel()
		delete(n.shardSubs, s)
	}
	for s, t := range n.joined {
		_ = t.Close()
		delete(n.joined, s)
	}
	n.smu.Unlock()
	n.controlSub.Cancel()
	_ = n.control.Close()
	_ = n.dht.Close()
	return n.host.Close()
}

// controlReadLoop dispatches control-plane gossip (everything except results).
func (n *Node) controlReadLoop(ctx context.Context) {
	self := n.host.ID()
	for {
		msg, err := n.controlSub.Next(ctx)
		if err != nil {
			return // context cancelled or subscription closed
		}
		if msg.GetFrom() == self {
			continue
		}
		var env protocol.GossipEnvelope
		if err := json.Unmarshal(msg.Data, &env); err != nil {
			continue
		}
		switch env.Kind {
		case protocol.GossipCatalog:
			if env.Catalog != nil {
				n.handleCatalog(ctx, *env.Catalog)
			}
		case protocol.GossipHub:
			if env.Hub != nil {
				n.handleHub(ctx, *env.Hub)
			}
		case protocol.GossipSubscription:
			if env.Subscription != nil {
				n.handleSubscription(ctx, *env.Subscription)
			}
		case protocol.GossipAlert:
			if env.Alert != nil {
				n.handleAlert(ctx, *env.Alert)
			}
		case protocol.GossipDelivery:
			if env.Delivery != nil {
				n.handleDelivery(ctx, *env.Delivery)
			}
		}
	}
}

// shardReadLoop dispatches results from one subscribed shard topic.
func (n *Node) shardReadLoop(ctx context.Context, sub *pubsub.Subscription) {
	self := n.host.ID()
	for {
		msg, err := sub.Next(ctx)
		if err != nil {
			return // unsubscribed or context cancelled
		}
		if msg.GetFrom() == self {
			continue
		}
		var env protocol.GossipEnvelope
		if err := json.Unmarshal(msg.Data, &env); err != nil {
			continue
		}
		if env.Kind == protocol.GossipResult && env.Result != nil {
			n.handleResult(ctx, *env.Result)
		}
	}
}

// handleResult is the trust gate: verify the signature, then apply policy,
// before anything is ingested or re-gossiped.
func (n *Node) handleResult(ctx context.Context, sr protocol.SignedResult) {
	if err := sr.Verify(); err != nil {
		n.log.Debug("dropping unverifiable gossiped result", "err", err)
		return
	}
	if !n.policy.Allow(sr.Content.ProbeID) {
		n.log.Debug("dropping untrusted result", "probe", sr.Content.ProbeID, "policy", n.policy.Name())
		return
	}
	if n.ingest != nil {
		n.ingest(ctx, sr)
	}
}

// handleCatalog verifies a gossiped catalog entry before ingesting it. Catalog
// entries are admitted on a valid signature: the catalog is meant to be global,
// so the trust policy (which gates result authorship) does not restrict it.
func (n *Node) handleCatalog(ctx context.Context, sc protocol.SignedCatalogEntry) {
	if err := sc.Verify(); err != nil {
		n.log.Debug("dropping unverifiable catalog entry", "err", err)
		return
	}
	if n.ingestCatalog != nil {
		n.ingestCatalog(ctx, sc)
	}
}

// handleHub verifies a gossiped hub announcement's signature before handing it
// to the directory, which performs the separate reachability check.
func (n *Node) handleHub(ctx context.Context, sa protocol.SignedHubAnnouncement) {
	if err := sa.Verify(); err != nil {
		n.log.Debug("dropping unverifiable hub announcement", "err", err)
		return
	}
	if n.ingestHub != nil {
		n.ingestHub(ctx, sa)
	}
}

// handleSubscription verifies an owner-signed subscription before ingesting it.
func (n *Node) handleSubscription(ctx context.Context, ss protocol.SignedSubscription) {
	if err := ss.Verify(); err != nil {
		n.log.Debug("dropping unverifiable subscription", "err", err)
		return
	}
	if n.ingestSubscription != nil {
		n.ingestSubscription(ctx, ss)
	}
}

// handleAlert verifies an owner-signed alert rule before ingesting it.
func (n *Node) handleAlert(ctx context.Context, sa protocol.SignedAlertRule) {
	if err := sa.Verify(); err != nil {
		n.log.Debug("dropping unverifiable alert rule", "err", err)
		return
	}
	if n.ingestAlert != nil {
		n.ingestAlert(ctx, sa)
	}
}

// handleDelivery verifies a hub-signed delivery-state before ingesting it.
func (n *Node) handleDelivery(ctx context.Context, sd protocol.SignedDeliveryState) {
	if err := sd.Verify(); err != nil {
		n.log.Debug("dropping unverifiable delivery-state", "err", err)
		return
	}
	if n.ingestDelivery != nil {
		n.ingestDelivery(ctx, sd)
	}
}

func (n *Node) discoverLoop(ctx context.Context, rd *drouting.RoutingDiscovery) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			peers, err := dutil.FindPeers(ctx, rd, rendezvous)
			if err != nil {
				continue
			}
			for _, p := range peers {
				if p.ID == n.host.ID() || len(p.Addrs) == 0 {
					continue
				}
				_ = n.host.Connect(ctx, p)
			}
		}
	}
}
