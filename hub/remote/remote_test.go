package remote

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/mwgg/libreping/pkg/identity"
	"github.com/mwgg/libreping/pkg/protocol"
)

// TestFetchVerifiesSignatures ensures a holder cannot inject forged results: a
// tampered result in the response is dropped, a valid one is kept.
func TestFetchVerifiesSignatures(t *testing.T) {
	probe, _ := identity.Generate()
	valid, _ := protocol.SignResult(probe, protocol.ResultContent{
		CheckID: "c1", CheckType: protocol.CheckHTTP, Target: "https://x", Status: protocol.StatusUp,
		TimestampMS: time.Now().UnixMilli(),
	})
	tampered := valid
	tampered.Content.Status = protocol.StatusDown // breaks the signature

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode([]protocol.SignedResult{valid, tampered})
	}))
	defer srv.Close()

	// httptest binds to loopback, so allow private ranges in the test client.
	got, err := NewClient(true).Fetch(context.Background(), srv.URL, CheckQuery("c1", 0, 100))
	if err != nil {
		t.Fatalf("fetch: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("expected 1 verified result, got %d", len(got))
	}
	if got[0].Content.Status != protocol.StatusUp {
		t.Fatal("kept the wrong (tampered) result")
	}
}

func TestFetchHandlesErrorStatus(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()
	if _, err := NewClient(true).Fetch(context.Background(), srv.URL, CheckQuery("c1", 0, 100)); err == nil {
		t.Fatal("expected error on 500")
	}
}
