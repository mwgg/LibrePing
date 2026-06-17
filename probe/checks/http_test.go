package checks

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/mwgg/libreping/pkg/protocol"
)

func TestHTTPCheckerUp(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("hello libreping"))
	}))
	defer srv.Close()

	spec := protocol.CheckSpec{
		ID:     "c1",
		Type:   protocol.CheckHTTP,
		Target: srv.URL,
		Params: map[string]string{"keyword": "libreping"},
	}
	out, err := HTTPChecker{}.Run(context.Background(), spec)
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if out.Status != protocol.StatusUp {
		t.Fatalf("expected up, got %s (%v)", out.Status, out.Detail)
	}
	if out.RTTMillis <= 0 {
		t.Fatal("expected a positive RTT measurement")
	}
}

func TestHTTPCheckerKeywordMissingIsDegraded(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("nothing relevant here"))
	}))
	defer srv.Close()

	spec := protocol.CheckSpec{
		Type:   protocol.CheckHTTP,
		Target: srv.URL,
		Params: map[string]string{"keyword": "libreping"},
	}
	out, _ := HTTPChecker{}.Run(context.Background(), spec)
	if out.Status != protocol.StatusDegraded {
		t.Fatalf("expected degraded for missing keyword, got %s", out.Status)
	}
}

func TestHTTPCheckerDownOnBadStatus(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	spec := protocol.CheckSpec{Type: protocol.CheckHTTP, Target: srv.URL}
	out, _ := HTTPChecker{}.Run(context.Background(), spec)
	if out.Status != protocol.StatusDown {
		t.Fatalf("expected down for 500, got %s", out.Status)
	}
}

func TestHTTPCheckerDownOnUnreachable(t *testing.T) {
	spec := protocol.CheckSpec{
		Type:   protocol.CheckHTTP,
		Target: "http://127.0.0.1:1", // nothing listening
		Params: map[string]string{"timeout_seconds": "1"},
	}
	out, _ := HTTPChecker{}.Run(context.Background(), spec)
	if out.Status != protocol.StatusDown {
		t.Fatalf("expected down for unreachable target, got %s", out.Status)
	}
}
