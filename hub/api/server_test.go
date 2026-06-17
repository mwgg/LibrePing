package api

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/mwgg/libreping/hub/directory"
	"github.com/mwgg/libreping/hub/interest"
	"github.com/mwgg/libreping/hub/shard"
	"github.com/mwgg/libreping/hub/store"
	"github.com/mwgg/libreping/pkg/identity"
	"github.com/mwgg/libreping/pkg/protocol"
)

func newTestServer() (*Server, *store.MemStore) {
	st := store.NewMemStore()
	return New(Config{Store: st}), st
}

func TestSubmitAcceptsValidResult(t *testing.T) {
	srv, st := newTestServer()
	probe, _ := identity.Generate()
	sr, _ := protocol.SignResult(probe, protocol.ResultContent{
		CheckID: "c1", CheckType: protocol.CheckHTTP, Target: "https://example.com",
		Status: protocol.StatusUp, TimestampMS: time.Now().UnixMilli(),
	})

	rec := submit(srv, sr)
	if rec.Code != http.StatusAccepted {
		t.Fatalf("expected 202, got %d: %s", rec.Code, rec.Body.String())
	}
	stored, _ := st.Recent(context.Background(), 10)
	if len(stored) != 1 {
		t.Fatalf("expected 1 stored result, got %d", len(stored))
	}
}

func TestSubmitRejectsTamperedResult(t *testing.T) {
	srv, st := newTestServer()
	probe, _ := identity.Generate()
	sr, _ := protocol.SignResult(probe, protocol.ResultContent{
		CheckID: "c1", CheckType: protocol.CheckHTTP, Target: "https://example.com",
		Status: protocol.StatusUp, TimestampMS: 1,
	})
	sr.Content.Status = protocol.StatusDown // invalidate signature

	rec := submit(srv, sr)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for tampered result, got %d", rec.Code)
	}
	stored, _ := st.Recent(context.Background(), 10)
	if len(stored) != 0 {
		t.Fatal("tampered result was stored")
	}
}

func submit(srv *Server, sr protocol.SignedResult) *httptest.ResponseRecorder {
	body, _ := json.Marshal(sr)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/results", bytes.NewReader(body))
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)
	return rec
}

func do(srv *Server, method, path string, body any) *httptest.ResponseRecorder {
	var r *http.Request
	if body != nil {
		b, _ := json.Marshal(body)
		r = httptest.NewRequest(method, path, bytes.NewReader(b))
	} else {
		r = httptest.NewRequest(method, path, nil)
	}
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, r)
	return rec
}

func TestCreateCheckGossipsAndAppearsInCatalog(t *testing.T) {
	hubID, _ := identity.Generate()
	srv := New(Config{Store: store.NewMemStore(), Identity: hubID})

	rec := do(srv, http.MethodPost, "/api/v1/checks", map[string]any{
		"type": "http", "target": "https://example.com", "interval_seconds": 60,
	})
	if rec.Code != http.StatusCreated {
		t.Fatalf("create check: expected 201, got %d: %s", rec.Code, rec.Body.String())
	}
	var created protocol.CheckSpec
	_ = json.Unmarshal(rec.Body.Bytes(), &created)
	if created.ID != created.DeriveID() {
		t.Fatal("created check ID is not content-derived")
	}

	cat := do(srv, http.MethodGet, "/api/v1/catalog", nil)
	var specs []protocol.CheckSpec
	_ = json.Unmarshal(cat.Body.Bytes(), &specs)
	if len(specs) != 1 || specs[0].Target != "https://example.com" {
		t.Fatalf("catalog did not contain the created check: %v", specs)
	}
}

func TestChecksEndpointReturnsAssignment(t *testing.T) {
	hubID, _ := identity.Generate()
	srv := New(Config{Store: store.NewMemStore(), Identity: hubID, Redundancy: 1})

	// Register a probe that supports HTTP (signed by the probe key).
	probe, _ := identity.Generate()
	signedReg, _ := protocol.SignProbeRegistration(probe, protocol.ProbeRegistration{
		MaxChecksPerMinute: 60,
		SupportedTypes:     []protocol.CheckType{protocol.CheckHTTP},
		TimestampMS:        time.Now().UnixMilli(),
	})
	reg := do(srv, http.MethodPost, "/api/v1/probes/register", signedReg)
	if reg.Code != http.StatusOK {
		t.Fatalf("register: %d %s", reg.Code, reg.Body.String())
	}

	// Create a check.
	created := do(srv, http.MethodPost, "/api/v1/checks", map[string]any{
		"type": "http", "target": "https://example.com", "interval_seconds": 60,
	})
	if created.Code != http.StatusCreated {
		t.Fatalf("create check: %d", created.Code)
	}
	var spec protocol.CheckSpec
	_ = json.Unmarshal(created.Body.Bytes(), &spec)

	// With no subscription, the check is not monitored → no assignment.
	if got := assignedTo(srv, probe.NodeID()); len(got) != 0 {
		t.Fatalf("unsubscribed check should not be assigned, got %v", got)
	}

	// Subscribe an owner to the check; now it should be assigned.
	user, _ := identity.Generate()
	subscribe(t, srv, user, spec.ID, 60)

	if got := assignedTo(srv, probe.NodeID()); len(got) != 1 || got[0].Target != "https://example.com" {
		t.Fatalf("probe was not assigned the subscribed check: %v", got)
	}
	if got := assignedTo(srv, "nobody"); len(got) != 0 {
		t.Fatalf("unknown probe should get no checks, got %v", got)
	}
}

func TestDedupSameTargetAcrossOwners(t *testing.T) {
	hubID, _ := identity.Generate()
	srv := New(Config{Store: store.NewMemStore(), Identity: hubID, Redundancy: 1})

	// Two different owners add the same target.
	c1 := do(srv, http.MethodPost, "/api/v1/checks", map[string]any{"type": "http", "target": "https://google.com"})
	c2 := do(srv, http.MethodPost, "/api/v1/checks", map[string]any{"type": "http", "target": "https://google.com"})
	var s1, s2 protocol.CheckSpec
	_ = json.Unmarshal(c1.Body.Bytes(), &s1)
	_ = json.Unmarshal(c2.Body.Bytes(), &s2)
	if s1.ID != s2.ID {
		t.Fatal("same target produced different check IDs (no dedup)")
	}

	// Catalog holds exactly one check.
	cat := do(srv, http.MethodGet, "/api/v1/catalog", nil)
	var specs []protocol.CheckSpec
	_ = json.Unmarshal(cat.Body.Bytes(), &specs)
	if len(specs) != 1 {
		t.Fatalf("expected 1 deduped check, got %d", len(specs))
	}

	// Both owners subscribe; both see it in their own services list.
	alice, _ := identity.Generate()
	bob, _ := identity.Generate()
	subscribe(t, srv, alice, s1.ID, 60)
	subscribe(t, srv, bob, s1.ID, 60)
	for _, u := range []string{alice.NodeID(), bob.NodeID()} {
		svc := do(srv, http.MethodGet, "/api/v1/services?owner="+u, nil)
		var services []Service
		_ = json.Unmarshal(svc.Body.Bytes(), &services)
		if len(services) != 1 || services[0].Target != "https://google.com" {
			t.Fatalf("owner %s services wrong: %v", u, services)
		}
	}
}

// TestServicesEmptyLocationsNotNull guards the freshly-added-monitor case: a
// subscribed check with no results yet must serialize locations as [], not null,
// so dashboard clients can iterate it unconditionally (a null blanked the page).
func TestServicesEmptyLocationsNotNull(t *testing.T) {
	hubID, _ := identity.Generate()
	srv := New(Config{Store: store.NewMemStore(), Identity: hubID, Redundancy: 1})

	c := do(srv, http.MethodPost, "/api/v1/checks", map[string]any{"type": "http", "target": "https://example.com"})
	var spec protocol.CheckSpec
	_ = json.Unmarshal(c.Body.Bytes(), &spec)

	owner, _ := identity.Generate()
	subscribe(t, srv, owner, spec.ID, 60)

	rec := do(srv, http.MethodGet, "/api/v1/services?owner="+owner.NodeID(), nil)
	if bytes.Contains(rec.Body.Bytes(), []byte(`"locations":null`)) {
		t.Fatalf("services emitted null locations for a result-less check: %s", rec.Body.String())
	}
	var services []Service
	_ = json.Unmarshal(rec.Body.Bytes(), &services)
	if len(services) != 1 {
		t.Fatalf("expected 1 service, got %d", len(services))
	}
	if services[0].Locations == nil {
		t.Fatal("Locations is nil; want empty slice")
	}
	if services[0].Overall != "unknown" {
		t.Fatalf("overall for a result-less check = %q, want unknown", services[0].Overall)
	}
}

func TestQueryEndpointFiltersByCheck(t *testing.T) {
	st := store.NewMemStore()
	srv := New(Config{Store: st})
	probe, _ := identity.Generate()
	now := time.Now().UnixMilli()
	for _, cid := range []string{"aaaa1111", "bbbb2222"} {
		sr, _ := protocol.SignResult(probe, protocol.ResultContent{
			CheckID: cid, CheckType: protocol.CheckHTTP, Target: "https://x", Status: protocol.StatusUp, TimestampMS: now,
		})
		_ = st.Insert(context.Background(), sr)
	}
	rec := do(srv, http.MethodGet, "/api/v1/results/query?check_id=aaaa1111&since_ms=0", nil)
	var out []protocol.SignedResult
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	if len(out) != 1 || out[0].Content.CheckID != "aaaa1111" {
		t.Fatalf("query by check_id returned %d results: %v", len(out), out)
	}
}

// TestOnDemandReadFromHolder proves a hub that does NOT store a check still
// serves it on the dashboard by fetching from a holder hub over HTTP.
func TestOnDemandReadFromHolder(t *testing.T) {
	// Holder hub A: stores a result for the check and serves /query.
	holderStore := store.NewMemStore()
	holder := New(Config{Store: holderStore})
	probe, _ := identity.Generate()
	check := "abcd1234abcd1234"
	sr, _ := protocol.SignResult(probe, protocol.ResultContent{
		CheckID: check, CheckType: protocol.CheckHTTP, Target: "https://svc", Status: protocol.StatusUp,
		Location: protocol.Location{Country: "DE"}, TimestampMS: time.Now().UnixMilli(),
	})
	_ = holderStore.Insert(context.Background(), sr)
	holderHTTP := httptest.NewServer(holder.Handler())
	defer holderHTTP.Close()

	// Lite hub B: holds nothing (interest with empty assigned/pins), but its
	// directory lists A as an archive holder reachable at holderHTTP.URL.
	hubA, _ := identity.Generate()
	owner, _ := identity.Generate()
	hubID, _ := identity.Generate()

	dir := directory.New(hubID.NodeID(), time.Minute, true, nil)
	dir.AddVerified(protocol.HubAnnouncement{HubID: hubA.NodeID(), PublicURL: holderHTTP.URL, StorageArchive: true})

	noInterest := interest.New()
	noInterest.Update(false, map[uint32]bool{}, map[string]bool{}) // holds nothing

	b := New(Config{
		Store: store.NewMemStore(), Identity: hubID, Directory: dir,
		Interest: noInterest, SelfHub: shard.Hub{ID: hubID.NodeID(), Capacity: 0},
		AllowPrivatePeers: true, // the holder runs on loopback in this test
	})
	// B knows the check (catalog) and the owner's subscription, but stores no results.
	spec := protocol.CheckSpec{Type: protocol.CheckHTTP, Target: "https://svc"}
	spec.ID = check
	sc, _ := protocol.SignCatalogEntry(hubID, protocol.CatalogEntry{Spec: spec})
	_ = b.catalog.UpsertCheck(context.Background(), sc)
	_ = b.subs.Upsert(context.Background(), protocol.SignSubscription(owner, protocol.Subscription{CheckID: check, IntervalSeconds: 60, UpdatedMS: 1}))

	rec := do(b, http.MethodGet, "/api/v1/services?owner="+owner.NodeID(), nil)
	var services []Service
	_ = json.Unmarshal(rec.Body.Bytes(), &services)
	if len(services) != 1 || len(services[0].Locations) != 1 || services[0].Locations[0].Location.Country != "DE" {
		t.Fatalf("expected the held-elsewhere check to be fetched on demand, got %v", services)
	}
}

// TestNonHolderSubmitPushesToHolder proves HIGH-2's fix: a hub that does NOT
// hold a check's shard, on accepting a submitted result, delivers it directly to
// the shard holder over HTTP — so the result is not lost even though the home
// hub stores nothing and no holder is in its gossip mesh.
func TestNonHolderSubmitPushesToHolder(t *testing.T) {
	// Holder hub A: holds everything (nil interest) and serves /api/v1/results.
	holderStore := store.NewMemStore()
	holderID, _ := identity.Generate()
	holder := New(Config{Store: holderStore, Identity: holderID})
	holderHTTP := httptest.NewServer(holder.Handler())
	defer holderHTTP.Close()

	// Home hub B: holds nothing, lists A as a holder, retains + pushes on submit.
	hubID, _ := identity.Generate()
	dir := directory.New(hubID.NodeID(), time.Minute, true, nil)
	dir.AddVerified(protocol.HubAnnouncement{HubID: holderID.NodeID(), PublicURL: holderHTTP.URL, StorageArchive: true})
	noInterest := interest.New()
	noInterest.Update(false, map[uint32]bool{}, map[string]bool{})
	b := New(Config{
		Store: store.NewMemStore(), Identity: hubID, Directory: dir,
		Interest: noInterest, SelfHub: shard.Hub{ID: hubID.NodeID(), Capacity: 0},
		AllowPrivatePeers: true,
	})

	probe, _ := identity.Generate()
	sr, _ := protocol.SignResult(probe, protocol.ResultContent{
		CheckID: "abcd1234abcd1234", CheckType: protocol.CheckHTTP, Target: "https://svc",
		Status: protocol.StatusUp, TimestampMS: time.Now().UnixMilli(),
	})
	if rec := submit(b, sr); rec.Code != http.StatusAccepted {
		t.Fatalf("submit to non-holder: %d %s", rec.Code, rec.Body.String())
	}
	// B stores nothing; the holder must receive it via the async direct push.
	if local, _ := b.store.Recent(context.Background(), 10); len(local) != 0 {
		t.Fatalf("non-holder should store nothing, got %d", len(local))
	}
	for i := 0; i < 100; i++ {
		if got, _ := holderStore.Recent(context.Background(), 10); len(got) == 1 {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("holder never received the directly-pushed result")
}

func assignedTo(srv *Server, probeID string) []protocol.CheckSpec {
	rec := do(srv, http.MethodGet, "/api/v1/checks?probe_id="+probeID, nil)
	var specs []protocol.CheckSpec
	_ = json.Unmarshal(rec.Body.Bytes(), &specs)
	return specs
}

func subscribe(t *testing.T, srv *Server, owner *identity.Identity, checkID string, interval int) {
	t.Helper()
	ss := protocol.SignSubscription(owner, protocol.Subscription{CheckID: checkID, IntervalSeconds: interval})
	if rec := do(srv, http.MethodPost, "/api/v1/subscriptions", ss); rec.Code != http.StatusAccepted {
		t.Fatalf("subscribe: %d %s", rec.Code, rec.Body.String())
	}
}
