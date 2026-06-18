package api

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"sync"
	"time"

	"github.com/mwgg/libreping/pkg/netguard"
	"github.com/mwgg/libreping/pkg/protocol"
)

// The network topology view powers the dashboard's "network" map — a showcase of
// who is participating, not a monitoring view. It joins the gossiped hub
// directory with the probes registered at each hub, so the map can draw every
// probe and the hub it is talking to.

const (
	networkCacheTTL = 30 * time.Second // peers are fanned out to at most this often
	networkMaxPeers = 64               // bound the fan-out
	networkFetchPar = 8                // concurrent peer fetches
)

// ProbeInfo is one probe as a hub knows it (served at GET /api/v1/probes).
type ProbeInfo struct {
	ProbeID    string            `json:"probe_id"`
	Location   protocol.Location `json:"location"`
	LastSeenMS int64             `json:"last_seen_ms"`
}

// HubNode is a hub on the topology map.
type HubNode struct {
	HubID     string            `json:"hub_id"`
	Name      string            `json:"name,omitempty"`
	PublicURL string            `json:"public_url,omitempty"`
	Location  protocol.Location `json:"location"`
	Self      bool              `json:"self,omitempty"`
}

// ProbeNode is a probe on the topology map, tagged with the hub it talks to.
type ProbeNode struct {
	ProbeID    string            `json:"probe_id"`
	Location   protocol.Location `json:"location"`
	HubID      string            `json:"hub_id"`
	LastSeenMS int64             `json:"last_seen_ms"`
}

// NetworkView is the whole topology: hubs, probes, and (implicitly) the
// probe→hub edges via ProbeNode.HubID.
type NetworkView struct {
	Hubs   []HubNode   `json:"hubs"`
	Probes []ProbeNode `json:"probes"`
}

type networkCache struct {
	at   time.Time
	view NetworkView
}

// handleProbes lists the probes currently registered with THIS hub (live within
// the heartbeat TTL). Other hubs aggregate this into the network view.
func (s *Server) handleProbes(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, s.liveProbeInfo())
}

func (s *Server) liveProbeInfo() []ProbeInfo {
	s.mu.Lock()
	defer s.mu.Unlock()
	cutoff := s.now().Add(-probeTTL)
	out := []ProbeInfo{}
	for id, p := range s.probes {
		if p.lastSeen.Before(cutoff) {
			continue
		}
		out = append(out, ProbeInfo{ProbeID: id, Location: p.location, LastSeenMS: p.lastSeen.UnixMilli()})
	}
	return out
}

// handleNetwork serves the topology JSON (cached).
func (s *Server) handleNetwork(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, s.networkView(r.Context()))
}

// networkView returns the topology, fanning out to peers at most once per
// networkCacheTTL so a load (JSON or SVG) doesn't hammer every peer each time.
func (s *Server) networkView(ctx context.Context) NetworkView {
	s.netMu.Lock()
	if s.netCache != nil && s.now().Sub(s.netCache.at) < networkCacheTTL {
		view := s.netCache.view
		s.netMu.Unlock()
		return view
	}
	s.netMu.Unlock()

	view := s.buildNetworkView(ctx)

	s.netMu.Lock()
	s.netCache = &networkCache{at: s.now(), view: view}
	s.netMu.Unlock()
	return view
}

// Countries counts the distinct countries across hubs and probes — the "from N
// places" headline number for the banner/map.
func (v NetworkView) Countries() int {
	set := map[string]bool{}
	for _, p := range v.Probes {
		if p.Location.Country != "" {
			set[p.Location.Country] = true
		}
	}
	for _, h := range v.Hubs {
		if h.Location.Country != "" {
			set[h.Location.Country] = true
		}
	}
	return len(set)
}

// buildNetworkView joins the hub directory (self + verified peers) with each
// hub's registered probes. Peers' probe lists are fetched over HTTP through the
// SSRF-safe client; a probe seen at several hubs (failover) is shown once, at the
// hub it talked to most recently.
func (s *Server) buildNetworkView(ctx context.Context) NetworkView {
	selfID := ""
	if s.identity != nil {
		selfID = s.identity.NodeID()
	}

	hubs := []HubNode{{HubID: selfID, Name: s.selfName, PublicURL: s.selfURL, Location: s.selfLoc, Self: true}}
	peers := []protocol.HubAnnouncement{}
	if s.dir != nil {
		peers = s.dir.List()
	}
	for _, h := range peers {
		hubs = append(hubs, HubNode{HubID: h.HubID, Name: h.Name, PublicURL: h.PublicURL, Location: h.Location})
	}

	// latest (probeID -> node) keeps one edge per probe, the most recent.
	latest := map[string]ProbeNode{}
	add := func(hubID string, ps []ProbeInfo) {
		for _, p := range ps {
			cur, ok := latest[p.ProbeID]
			if !ok || p.LastSeenMS > cur.LastSeenMS {
				latest[p.ProbeID] = ProbeNode{ProbeID: p.ProbeID, Location: p.Location, HubID: hubID, LastSeenMS: p.LastSeenMS}
			}
		}
	}
	add(selfID, s.liveProbeInfo())

	// Fan out to peers that advertise a URL, bounded and concurrent.
	type peerProbes struct {
		hubID string
		ps    []ProbeInfo
	}
	var targets []protocol.HubAnnouncement
	for _, h := range peers {
		if h.PublicURL != "" && h.HubID != selfID {
			targets = append(targets, h)
			if len(targets) >= networkMaxPeers {
				break
			}
		}
	}
	results := make([]peerProbes, len(targets))
	client := netguard.SafeClient(netguard.Options{Timeout: 4 * time.Second, AllowPrivate: s.allowPriv})
	sem := make(chan struct{}, networkFetchPar)
	var wg sync.WaitGroup
	for i, h := range targets {
		wg.Add(1)
		sem <- struct{}{}
		go func(i int, h protocol.HubAnnouncement) {
			defer wg.Done()
			defer func() { <-sem }()
			results[i] = peerProbes{hubID: h.HubID, ps: fetchPeerProbes(ctx, client, h.PublicURL)}
		}(i, h)
	}
	wg.Wait()
	for _, r := range results {
		add(r.hubID, r.ps)
	}

	probes := make([]ProbeNode, 0, len(latest))
	for _, p := range latest {
		probes = append(probes, p)
	}
	return NetworkView{Hubs: hubs, Probes: probes}
}

// fetchPeerProbes GETs {base}/api/v1/probes. Best-effort: any error yields none.
func fetchPeerProbes(ctx context.Context, client *http.Client, base string) []ProbeInfo {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, base+"/api/v1/probes", nil)
	if err != nil {
		return nil
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil
	}
	var out []ProbeInfo
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&out); err != nil {
		return nil
	}
	return out
}
