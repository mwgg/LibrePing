package api

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
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

// TestUptimeEndpoint seeds a check with a known up/down/degraded mix and asserts
// the /uptime endpoint returns sample-weighted (up+degraded)/samples per window,
// with the 24h number computed at hourly granularity.
func TestUptimeEndpoint(t *testing.T) {
	srv, st := newTestServer()
	ctx := context.Background()
	now := int64(40_000) * 86_400_000 // day-aligned "now"
	srv.now = func() time.Time { return time.UnixMilli(now) }

	hourMS := int64(3_600_000)
	// Two distinct hours inside the last 24h: 8 up, 1 down, 1 degraded.
	for i := int64(0); i < 4; i++ {
		_ = st.Insert(ctx, seedRes("c", now-2*hourMS+i, protocol.StatusUp))
		_ = st.Insert(ctx, seedRes("c", now-20*hourMS+i, protocol.StatusUp))
	}
	_ = st.Insert(ctx, seedRes("c", now-2*hourMS+100, protocol.StatusDown))
	_ = st.Insert(ctx, seedRes("c", now-20*hourMS+100, protocol.StatusDegraded))

	rec := do(srv, http.MethodGet, "/api/v1/uptime?check_id=c", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	var rep store.UptimeReport
	if err := json.Unmarshal(rec.Body.Bytes(), &rep); err != nil {
		t.Fatal(err)
	}
	if rep.CheckID != "c" {
		t.Fatalf("check_id: got %q", rep.CheckID)
	}
	w := rep.Windows["24h"]
	if !w.Available || w.Samples != 10 || w.Up != 8 || w.Down != 1 || w.Degraded != 1 {
		t.Fatalf("24h totals: got %+v", w)
	}
	if w.Uptime == nil || *w.Uptime != 0.9 { // (8 up + 1 degraded) / 10
		t.Fatalf("24h uptime: got %v, want 0.9", w.Uptime)
	}
	// A window with no samples in it is present but unavailable, not an error.
	if empty, ok := rep.Windows["7d"]; !ok || !empty.Available {
		// 7d also contains the same samples, so it is available; sanity only.
		t.Logf("7d window: %+v", empty)
	}
}

// TestUptimeBadgeSVG seeds a held check, requests its badge, and asserts a
// well-formed SVG carrying the formatted percentage and the correct content type.
func TestUptimeBadgeSVG(t *testing.T) {
	srv, st := newTestServer()
	ctx := context.Background()
	now := int64(40_000) * 86_400_000
	srv.now = func() time.Time { return time.UnixMilli(now) }
	dayMS := int64(86_400_000)
	// Within 30d: 9 up, 1 down → 90.0% uptime (red band).
	for i := int64(0); i < 9; i++ {
		_ = st.Insert(ctx, seedRes("c", now-2*dayMS+i, protocol.StatusUp))
	}
	_ = st.Insert(ctx, seedRes("c", now-2*dayMS+100, protocol.StatusDown))

	rec := do(srv, http.MethodGet, "/api/v1/uptime/badge.svg?check_id=c", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	if ct := rec.Header().Get("Content-Type"); ct != "image/svg+xml; charset=utf-8" {
		t.Fatalf("content-type: got %q", ct)
	}
	body := rec.Body.String()
	if !strings.HasPrefix(body, "<svg") || !strings.HasSuffix(body, "</svg>") {
		t.Fatalf("not a well-formed svg: %q", body)
	}
	for _, want := range []string{"90.0%", "uptime 30d"} {
		if !strings.Contains(body, want) {
			t.Fatalf("badge missing %q: %s", want, body)
		}
	}
	if strings.Contains(body, "n/a") {
		t.Fatalf("held check should not render n/a: %s", body)
	}
}

// TestUptimeBadgeWindow honors an explicit valid window and rejects an unknown one.
func TestUptimeBadgeWindow(t *testing.T) {
	srv, _ := newTestServer()
	if rec := do(srv, http.MethodGet, "/api/v1/uptime/badge.svg?check_id=c&window=7d", nil); rec.Code != http.StatusOK {
		t.Fatalf("valid window: expected 200, got %d", rec.Code)
	} else if !strings.Contains(rec.Body.String(), "uptime 7d") {
		t.Fatalf("expected 7d label: %s", rec.Body.String())
	}
	if rec := do(srv, http.MethodGet, "/api/v1/uptime/badge.svg?check_id=c&window=bogus", nil); rec.Code != http.StatusBadRequest {
		t.Fatalf("bad window: expected 400, got %d", rec.Code)
	}
}

// TestUptimeBadgeUnknownCheck renders a valid grey "n/a" badge (not an error) for a
// check with no local data.
func TestUptimeBadgeUnknownCheck(t *testing.T) {
	srv, _ := newTestServer()
	rec := do(srv, http.MethodGet, "/api/v1/uptime/badge.svg?check_id=nope", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	body := rec.Body.String()
	if !strings.HasPrefix(body, "<svg") || !strings.HasSuffix(body, "</svg>") || !strings.Contains(body, "n/a") {
		t.Fatalf("expected a well-formed n/a badge: %s", body)
	}
}

// TestUptimeBadgeMissingCheckID rejects a badge request without check_id.
func TestUptimeBadgeMissingCheckID(t *testing.T) {
	srv, _ := newTestServer()
	if rec := do(srv, http.MethodGet, "/api/v1/uptime/badge.svg", nil); rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", rec.Code)
	}
}

// TestUptimeMissingCheckID rejects a request without check_id.
func TestUptimeMissingCheckID(t *testing.T) {
	srv, _ := newTestServer()
	rec := do(srv, http.MethodGet, "/api/v1/uptime", nil)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", rec.Code)
	}
}

// TestUptimeUnknownCheck: a check the hub has no data for reports every window
// unavailable (null uptime), not an error.
func TestUptimeUnknownCheck(t *testing.T) {
	srv, _ := newTestServer()
	rec := do(srv, http.MethodGet, "/api/v1/uptime?check_id=nope", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	var rep store.UptimeReport
	_ = json.Unmarshal(rec.Body.Bytes(), &rep)
	for _, label := range []string{"24h", "7d", "30d"} {
		if w := rep.Windows[label]; w.Available || w.Uptime != nil {
			t.Fatalf("%s should be unavailable/null, got %+v", label, w)
		}
	}
}

// TestUptimeNonHeldShard: a hub that does not hold the check's shard reports
// every window unavailable without reaching across the mesh (local-only).
func TestUptimeNonHeldShard(t *testing.T) {
	noInterest := interest.New()
	noInterest.Update(false, map[uint32]bool{}, map[string]bool{}) // holds nothing
	srv := New(Config{Store: store.NewMemStore(), Interest: noInterest})

	rec := do(srv, http.MethodGet, "/api/v1/uptime?check_id=abcd1234abcd1234", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	var rep store.UptimeReport
	_ = json.Unmarshal(rec.Body.Bytes(), &rep)
	if len(rep.Windows) != 3 {
		t.Fatalf("expected 3 windows, got %d", len(rep.Windows))
	}
	for label, w := range rep.Windows {
		if w.Available || w.Uptime != nil {
			t.Fatalf("%s should be unavailable on a non-holder, got %+v", label, w)
		}
	}
}

func seedRes(checkID string, ts int64, st protocol.Status) protocol.SignedResult {
	return protocol.SignedResult{Content: protocol.ResultContent{
		ProbeID: "p", CheckID: checkID, Status: st, TimestampMS: ts,
	}}
}

func seedResRTT(checkID string, ts int64, st protocol.Status, rtt float64) protocol.SignedResult {
	return protocol.SignedResult{Content: protocol.ResultContent{
		ProbeID: "p", CheckID: checkID, Status: st, TimestampMS: ts, RTTMillis: rtt,
	}}
}

// TestLatencyEndpoint seeds a known RTT distribution and asserts the /latency
// endpoint returns nearest-rank p50/p95/p99 plus min/max/count over the window.
func TestLatencyEndpoint(t *testing.T) {
	srv, st := newTestServer()
	ctx := context.Background()
	now := int64(40_000) * 86_400_000
	srv.now = func() time.Time { return time.UnixMilli(now) }
	hourMS := int64(3_600_000)
	// rtt = 1..100 ms inside the last 24h → p50=50, p95=95, p99=99, min=1, max=100.
	for i := int64(1); i <= 100; i++ {
		_ = st.Insert(ctx, seedResRTT("c", now-hourMS+i, protocol.StatusUp, float64(i)))
	}
	// A down row with a big rtt must not skew the percentiles.
	_ = st.Insert(ctx, seedResRTT("c", now-hourMS+200, protocol.StatusDown, 9999))

	rec := do(srv, http.MethodGet, "/api/v1/latency?check_id=c&window=24h", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	var rep store.LatencyPercentiles
	if err := json.Unmarshal(rec.Body.Bytes(), &rep); err != nil {
		t.Fatal(err)
	}
	if !rep.Available || rep.Count != 100 || rep.CheckID != "c" || rep.Window != "24h" {
		t.Fatalf("unexpected report: %+v", rep)
	}
	if rep.P50 == nil || *rep.P50 != 50 || rep.P95 == nil || *rep.P95 != 95 ||
		rep.P99 == nil || *rep.P99 != 99 || rep.Min == nil || *rep.Min != 1 || rep.Max == nil || *rep.Max != 100 {
		t.Fatalf("percentiles: got %+v", rep)
	}
}

// TestLatencySourceSelection: a window within raw retention (24h) is answered from
// raw (source "raw"); a window longer than raw retention (30d, > the default 7d) is
// answered from the aggregate latency histogram (source "histogram"). The default
// test server uses the default raw retention.
func TestLatencySourceSelection(t *testing.T) {
	srv, st := newTestServer()
	ctx := context.Background()
	now := int64(40_000) * 86_400_000
	srv.now = func() time.Time { return time.UnixMilli(now) }
	dayMS := int64(86_400_000)
	// Seed measured samples across a 30d span so both windows have data.
	for i := int64(1); i <= 100; i++ {
		ts := now - int64(30)*dayMS + i*(int64(30)*dayMS)/101
		_ = st.Insert(ctx, seedResRTT("c", ts, protocol.StatusUp, float64(i)))
	}
	// A few recent samples inside 24h for the raw path.
	for i := int64(1); i <= 10; i++ {
		_ = st.Insert(ctx, seedResRTT("c", now-int64(3_600_000)+i, protocol.StatusUp, float64(i)))
	}

	get := func(window string) store.LatencyPercentiles {
		rec := do(srv, http.MethodGet, "/api/v1/latency?check_id=c&window="+window, nil)
		if rec.Code != http.StatusOK {
			t.Fatalf("%s: expected 200, got %d", window, rec.Code)
		}
		var rep store.LatencyPercentiles
		if err := json.Unmarshal(rec.Body.Bytes(), &rep); err != nil {
			t.Fatal(err)
		}
		return rep
	}
	if raw := get("24h"); raw.Source != "raw" || !raw.Available {
		t.Fatalf("24h should be raw+available, got %+v", raw)
	}
	hist := get("30d")
	if hist.Source != "histogram" || !hist.Available || hist.P50 == nil {
		t.Fatalf("30d should be histogram+available with percentiles, got %+v", hist)
	}
}

// TestLatencyDefaultWindow: omitting window defaults to 24h.
func TestLatencyDefaultWindow(t *testing.T) {
	srv, st := newTestServer()
	ctx := context.Background()
	now := int64(40_000) * 86_400_000
	srv.now = func() time.Time { return time.UnixMilli(now) }
	_ = st.Insert(ctx, seedResRTT("c", now-1000, protocol.StatusUp, 12))

	rec := do(srv, http.MethodGet, "/api/v1/latency?check_id=c", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	var rep store.LatencyPercentiles
	_ = json.Unmarshal(rec.Body.Bytes(), &rep)
	if rep.Window != "24h" || !rep.Available || rep.Count != 1 {
		t.Fatalf("expected 24h/available/count=1, got %+v", rep)
	}
}

// TestLatencyBadWindow rejects an unknown window label.
func TestLatencyBadWindow(t *testing.T) {
	srv, _ := newTestServer()
	if rec := do(srv, http.MethodGet, "/api/v1/latency?check_id=c&window=bogus", nil); rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", rec.Code)
	}
}

// TestLatencyMissingCheckID rejects a request without check_id.
func TestLatencyMissingCheckID(t *testing.T) {
	srv, _ := newTestServer()
	if rec := do(srv, http.MethodGet, "/api/v1/latency", nil); rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", rec.Code)
	}
}

// TestLatencyUnknownCheck: a check with no local data is available:false, not error.
func TestLatencyUnknownCheck(t *testing.T) {
	srv, _ := newTestServer()
	rec := do(srv, http.MethodGet, "/api/v1/latency?check_id=nope", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	var rep store.LatencyPercentiles
	_ = json.Unmarshal(rec.Body.Bytes(), &rep)
	if rep.Available || rep.P50 != nil || rep.Count != 0 {
		t.Fatalf("expected unavailable/nil/zero, got %+v", rep)
	}
}

// TestLatencyNonHeldShard: a hub that does not hold the check's shard reports the
// window unavailable without reaching across the mesh (local-only).
func TestLatencyNonHeldShard(t *testing.T) {
	noInterest := interest.New()
	noInterest.Update(false, map[uint32]bool{}, map[string]bool{}) // holds nothing
	srv := New(Config{Store: store.NewMemStore(), Interest: noInterest})

	rec := do(srv, http.MethodGet, "/api/v1/latency?check_id=abcd1234abcd1234&window=7d", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	var rep store.LatencyPercentiles
	_ = json.Unmarshal(rec.Body.Bytes(), &rep)
	if rep.Available || rep.P50 != nil || rep.Window != "7d" {
		t.Fatalf("expected unavailable on a non-holder, got %+v", rep)
	}
}

// TestIncidentsEndpoint seeds an up→down→up pattern and asserts the /incidents
// endpoint returns one bucket-aligned incident with the right worst status.
func TestIncidentsEndpoint(t *testing.T) {
	srv, st := newTestServer()
	ctx := context.Background()
	now := int64(40_000) * 86_400_000
	srv.now = func() time.Time { return time.UnixMilli(now) }
	hourMS := int64(3_600_000)
	_ = st.Insert(ctx, seedRes("c", now-4*hourMS, protocol.StatusUp))
	for i := int64(0); i < 3; i++ {
		_ = st.Insert(ctx, seedRes("c", now-3*hourMS+i, protocol.StatusDown))
	}
	_ = st.Insert(ctx, seedRes("c", now-2*hourMS, protocol.StatusUp))

	rec := do(srv, http.MethodGet, "/api/v1/incidents?check_id=c&window=7d", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	var rep store.IncidentReport
	if err := json.Unmarshal(rec.Body.Bytes(), &rep); err != nil {
		t.Fatal(err)
	}
	if rep.Window != "7d" || rep.Resolution != "hourly" || len(rep.Incidents) != 1 {
		t.Fatalf("unexpected report: %+v", rep)
	}
	inc := rep.Incidents[0]
	if inc.WorstStatus != "down" || inc.BucketCount != 1 || inc.Ongoing {
		t.Fatalf("incident: %+v", inc)
	}
}

// TestIncidentsDefaultWindow: omitting window defaults to 30d (daily resolution).
func TestIncidentsDefaultWindow(t *testing.T) {
	srv, _ := newTestServer()
	rec := do(srv, http.MethodGet, "/api/v1/incidents?check_id=c", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	var rep store.IncidentReport
	_ = json.Unmarshal(rec.Body.Bytes(), &rep)
	if rep.Window != "30d" || rep.Resolution != "daily" || len(rep.Incidents) != 0 {
		t.Fatalf("expected empty 30d/daily report, got %+v", rep)
	}
}

// TestIncidentsBadWindow rejects an unknown window label.
func TestIncidentsBadWindow(t *testing.T) {
	srv, _ := newTestServer()
	if rec := do(srv, http.MethodGet, "/api/v1/incidents?check_id=c&window=bogus", nil); rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", rec.Code)
	}
}

// TestIncidentsMissingCheckID rejects a request without check_id.
func TestIncidentsMissingCheckID(t *testing.T) {
	srv, _ := newTestServer()
	if rec := do(srv, http.MethodGet, "/api/v1/incidents", nil); rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", rec.Code)
	}
}

// TestIncidentsNonHeldShard: a hub that does not hold the check's shard reports an
// empty timeline without reaching across the mesh (local-only).
func TestIncidentsNonHeldShard(t *testing.T) {
	noInterest := interest.New()
	noInterest.Update(false, map[uint32]bool{}, map[string]bool{}) // holds nothing
	srv := New(Config{Store: store.NewMemStore(), Interest: noInterest})

	rec := do(srv, http.MethodGet, "/api/v1/incidents?check_id=abcd1234abcd1234&window=7d", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	var rep store.IncidentReport
	_ = json.Unmarshal(rec.Body.Bytes(), &rep)
	if rep.Window != "7d" || len(rep.Incidents) != 0 {
		t.Fatalf("expected empty on a non-holder, got %+v", rep)
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

func TestRegisterFloorsZeroCapacity(t *testing.T) {
	// A probe declaring MaxChecksPerMinute: 0 must not end up with the assigner's
	// "unlimited" semantic (Capacity <= 0). handleRegister floors it to a finite
	// positive value so a signed registration can't soak up every assignment slot.
	hubID, _ := identity.Generate()
	srv := New(Config{Store: store.NewMemStore(), Identity: hubID, Redundancy: 1})

	probe, _ := identity.Generate()
	for _, declared := range []int{0, -5} {
		signedReg, _ := protocol.SignProbeRegistration(probe, protocol.ProbeRegistration{
			MaxChecksPerMinute: declared,
			SupportedTypes:     []protocol.CheckType{protocol.CheckHTTP},
			TimestampMS:        time.Now().UnixMilli(),
		})
		reg := do(srv, http.MethodPost, "/api/v1/probes/register", signedReg)
		if reg.Code != http.StatusOK {
			t.Fatalf("register (declared=%d): %d %s", declared, reg.Code, reg.Body.String())
		}
		probes := srv.liveProbes()
		if len(probes) != 1 {
			t.Fatalf("expected 1 live probe, got %d", len(probes))
		}
		if probes[0].Capacity < minDeclaredCapacity {
			t.Fatalf("declared=%d yielded capacity %d, want >= %d (finite, not unlimited)",
				declared, probes[0].Capacity, minDeclaredCapacity)
		}
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

// TestSubmitRejectsOversizedBody proves the body cap: a POST larger than the
// per-request limit returns 413 (not a 500) and nothing is stored — the body is
// refused before it is fully buffered and decoded.
func TestSubmitRejectsOversizedBody(t *testing.T) {
	srv, st := newTestServer()
	// A syntactically-plausible but enormous JSON body: a Target padded well past
	// the maxBodyBytes cap. It must be rejected before allocation/decode.
	huge := strings.Repeat("a", maxBodyBytes+1024)
	body := []byte(`{"content":{"target":"` + huge + `"}}`)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/results", bytes.NewReader(body))
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("oversized body: expected 413, got %d: %s", rec.Code, rec.Body.String())
	}
	if stored, _ := st.Recent(context.Background(), 10); len(stored) != 0 {
		t.Fatalf("oversized submission was stored (%d results)", len(stored))
	}
}

// TestCreateCheckRejectsOversizedBody proves the cap applies to the catalog
// create path too, so an oversized spec never reaches signing/gossip.
func TestCreateCheckRejectsOversizedBody(t *testing.T) {
	hubID, _ := identity.Generate()
	srv := New(Config{Store: store.NewMemStore(), Identity: hubID})
	huge := strings.Repeat("a", maxBodyBytes+1024)
	body := []byte(`{"type":"http","target":"https://` + huge + `"}`)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/checks", bytes.NewReader(body))
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("oversized check body: expected 413, got %d: %s", rec.Code, rec.Body.String())
	}
}

// TestCreateCheckRejectsOversizedTarget proves the spec field bound: a Target
// within the body cap but over the per-field limit is rejected with 400 before
// it is signed and gossiped network-wide.
func TestCreateCheckRejectsOversizedTarget(t *testing.T) {
	hubID, _ := identity.Generate()
	srv := New(Config{Store: store.NewMemStore(), Identity: hubID})
	// Under the 64 KiB body cap, but over admit's Target bound.
	target := "https://" + strings.Repeat("a", 4096)
	rec := do(srv, http.MethodPost, "/api/v1/checks", map[string]any{"type": "http", "target": target})
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("oversized target: expected 400, got %d: %s", rec.Code, rec.Body.String())
	}
	cat := do(srv, http.MethodGet, "/api/v1/catalog", nil)
	var specs []protocol.CheckSpec
	_ = json.Unmarshal(cat.Body.Bytes(), &specs)
	if len(specs) != 0 {
		t.Fatalf("oversized-target check was stored: %v", specs)
	}
}

// TestSubmitStillAcceptsNormalBody guards against the cap breaking legitimate
// use: an ordinary signed result still succeeds.
func TestSubmitStillAcceptsNormalBody(t *testing.T) {
	srv, st := newTestServer()
	probe, _ := identity.Generate()
	sr, _ := protocol.SignResult(probe, protocol.ResultContent{
		CheckID: "c1", CheckType: protocol.CheckHTTP, Target: "https://example.com",
		Status: protocol.StatusUp, TimestampMS: time.Now().UnixMilli(),
	})
	if rec := submit(srv, sr); rec.Code != http.StatusAccepted {
		t.Fatalf("normal submit: expected 202, got %d: %s", rec.Code, rec.Body.String())
	}
	if stored, _ := st.Recent(context.Background(), 10); len(stored) != 1 {
		t.Fatalf("normal result not stored, got %d", len(stored))
	}
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

func TestHTTPConnectCreationAndMixedRegistration(t *testing.T) {
	hubID, _ := identity.Generate()
	srv := New(Config{Store: store.NewMemStore(), Identity: hubID, Redundancy: 3})
	bad := do(srv, http.MethodPost, "/api/v1/checks", map[string]any{"type": "http_connect", "target": "https://example.com"})
	if bad.Code != http.StatusBadRequest {
		t.Fatalf("missing address accepted: %d", bad.Code)
	}
	created := do(srv, http.MethodPost, "/api/v1/checks", map[string]any{"type": "http_connect", "target": "https://example.com", "params": map[string]string{"connect_address": "192.0.2.1"}})
	if created.Code != http.StatusCreated {
		t.Fatalf("create: %d %s", created.Code, created.Body.String())
	}
	var spec protocol.CheckSpec
	json.Unmarshal(created.Body.Bytes(), &spec)
	owner, _ := identity.Generate()
	subscribe(t, srv, owner, spec.ID, 60)
	for _, types := range [][]protocol.CheckType{nil, {protocol.CheckHTTP}, {protocol.CheckHTTPConnect, protocol.CheckType("future_check")}} {
		probe, _ := identity.Generate()
		reg, _ := protocol.SignProbeRegistration(probe, protocol.ProbeRegistration{SupportedTypes: types, MaxChecksPerMinute: 60, TimestampMS: time.Now().UnixMilli()})
		resp := do(srv, http.MethodPost, "/api/v1/probes/register", reg)
		if resp.Code != http.StatusOK {
			t.Fatalf("registration: %d %s", resp.Code, resp.Body.String())
		}
		want := 0
		if len(types) == 2 {
			want = 1
		}
		if got := assignedTo(srv, probe.NodeID()); len(got) != want {
			t.Fatalf("%v assigned %v", types, got)
		}
	}
	legacy := do(srv, http.MethodPost, "/api/v1/checks", map[string]any{"type": "http", "target": "https://example.com", "params": map[string]string{"connect_address": "ignored"}})
	if legacy.Code != http.StatusCreated {
		t.Fatalf("legacy spec rejected: %d", legacy.Code)
	}
}
