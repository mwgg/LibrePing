package api

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/mwgg/libreping/hub/store"
	"github.com/mwgg/libreping/pkg/identity"
	"github.com/mwgg/libreping/pkg/protocol"
)

func TestNetworkViewAndSVGs(t *testing.T) {
	hubID, _ := identity.Generate()
	mem := store.NewMemStore()
	srv := New(Config{
		Store: mem, Identity: hubID,
		SelfName: "nl", SelfPublicURL: "https://nl.example",
		SelfLocation: protocol.Location{Country: "Netherlands", City: "Amsterdam", Lat: 52.37, Lon: 4.90},
	})

	// Register a probe with a location.
	probe, _ := identity.Generate()
	reg, _ := protocol.SignProbeRegistration(probe, protocol.ProbeRegistration{
		Location:           protocol.Location{Country: "Germany", City: "Berlin", Lat: 52.52, Lon: 13.40},
		MaxChecksPerMinute: 60,
		SupportedTypes:     []protocol.CheckType{protocol.CheckHTTP},
		TimestampMS:        1,
	})
	if rec := do(srv, http.MethodPost, "/api/v1/probes/register", reg); rec.Code != http.StatusOK {
		t.Fatalf("register: %d", rec.Code)
	}

	// /api/v1/probes lists this hub's probe.
	var probes []ProbeInfo
	_ = json.Unmarshal(do(srv, http.MethodGet, "/api/v1/probes", nil).Body.Bytes(), &probes)
	if len(probes) != 1 || probes[0].ProbeID != probe.NodeID() || probes[0].Location.Country != "Germany" {
		t.Fatalf("probes wrong: %+v", probes)
	}

	// A probe known only from the gossiped result stream — its home hub is not in
	// the directory, so it never registered here, but its signed result is stored.
	gossipProbe, _ := identity.Generate()
	sr, _ := protocol.SignResult(gossipProbe, protocol.ResultContent{
		CheckID: "abc", CheckType: protocol.CheckHTTP, Target: "https://x.example",
		Location:    protocol.Location{Country: "China", City: "Wuhan", Lat: 30.59, Lon: 114.30},
		TimestampMS: time.Now().UnixMilli(), Status: protocol.StatusUp,
	})
	if err := mem.Insert(context.Background(), sr); err != nil {
		t.Fatalf("insert gossip result: %v", err)
	}

	// /api/v1/network places the hub (self), the registered probe (with edge), and
	// the gossip-only probe (no edge, ViaGossip).
	var net NetworkView
	_ = json.Unmarshal(do(srv, http.MethodGet, "/api/v1/network", nil).Body.Bytes(), &net)
	if len(net.Hubs) != 1 || !net.Hubs[0].Self || net.Hubs[0].HubID != hubID.NodeID() {
		t.Fatalf("hubs wrong: %+v", net.Hubs)
	}
	if len(net.Probes) != 2 {
		t.Fatalf("want 2 probes (registered + gossip), got %+v", net.Probes)
	}
	var registered, gossip *ProbeNode
	for i := range net.Probes {
		p := &net.Probes[i]
		if p.ViaGossip {
			gossip = p
		} else {
			registered = p
		}
	}
	if registered == nil || registered.HubID != hubID.NodeID() || registered.ProbeID != probe.NodeID() {
		t.Fatalf("registered probe/edge wrong: %+v", net.Probes)
	}
	if gossip == nil || gossip.HubID != "" || gossip.ProbeID != gossipProbe.NodeID() || gossip.Location.Country != "China" {
		t.Fatalf("gossip-only probe wrong: %+v", net.Probes)
	}
	if net.Countries() != 3 { // Netherlands (hub) + Germany (probe) + China (gossip)
		t.Fatalf("countries = %d, want 3", net.Countries())
	}

	// The embeddable banner renders as image/svg+xml.
	rec := do(srv, http.MethodGet, "/api/v1/network/banner.svg", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("banner: %d", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "image/svg+xml") {
		t.Fatalf("banner content-type = %q", ct)
	}
	if !strings.HasPrefix(strings.TrimSpace(rec.Body.String()), "<svg") {
		t.Fatalf("banner not an svg: %.40s", rec.Body.String())
	}
}
