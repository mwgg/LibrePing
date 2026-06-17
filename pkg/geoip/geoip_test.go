package geoip

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/mwgg/libreping/pkg/protocol"
)

// serve spins up a test server that returns the given status and body.
func serve(t *testing.T, status int, body string) string {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)
	return srv.URL
}

func TestProviderParsers(t *testing.T) {
	cases := []struct {
		name     string
		provider provider
		body     string
		want     protocol.Location
		wantErr  bool
	}{
		{
			name:     "ipwho.is",
			provider: providers[0],
			body:     `{"success":true,"country":"Germany","city":"Berlin","latitude":52.52,"longitude":13.405}`,
			want:     protocol.Location{Country: "Germany", City: "Berlin", Lat: 52.52, Lon: 13.405},
		},
		{
			name:     "ipwho.is failure flag",
			provider: providers[0],
			body:     `{"success":false}`,
			wantErr:  true,
		},
		{
			name:     "ipapi.co",
			provider: providers[1],
			body:     `{"country_name":"France","city":"Paris","latitude":48.85,"longitude":2.35}`,
			want:     protocol.Location{Country: "France", City: "Paris", Lat: 48.85, Lon: 2.35},
		},
		{
			name:     "ipapi.co error flag",
			provider: providers[1],
			body:     `{"error":true,"reason":"RateLimited"}`,
			wantErr:  true,
		},
		{
			name:     "geojs.io string coords",
			provider: providers[2],
			body:     `{"country":"United States","city":"New York","latitude":"40.71","longitude":"-74.01"}`,
			want:     protocol.Location{Country: "United States", City: "New York", Lat: 40.71, Lon: -74.01},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := c.provider.parse([]byte(c.body))
			if c.wantErr {
				if err == nil {
					t.Fatalf("expected error, got %+v", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("parse: %v", err)
			}
			if got != c.want {
				t.Fatalf("got %+v, want %+v", got, c.want)
			}
		})
	}
}

func TestValid(t *testing.T) {
	cases := []struct {
		loc protocol.Location
		ok  bool
	}{
		{protocol.Location{Lat: 52.5, Lon: 13.4}, true},
		{protocol.Location{Lat: 0, Lon: 0}, false},      // Null Island => unusable
		{protocol.Location{Lat: 91, Lon: 0}, false},     // out of range
		{protocol.Location{Lat: 0, Lon: -200}, false},   // out of range
		{protocol.Location{Lat: -33.8, Lon: 151}, true}, // Sydney
	}
	for _, c := range cases {
		if got := valid(c.loc); got != c.ok {
			t.Errorf("valid(%+v) = %v, want %v", c.loc, got, c.ok)
		}
	}
}

// TestLookupFallback verifies Lookup skips a failing/invalid provider and uses
// the next one that returns a usable location.
func TestLookupFallback(t *testing.T) {
	saved := providers
	t.Cleanup(func() { providers = saved })

	down := serve(t, http.StatusInternalServerError, "")
	nullIsland := serve(t, http.StatusOK, `{"success":true,"country":"","city":"","latitude":0,"longitude":0}`)
	good := serve(t, http.StatusOK, `{"success":true,"country":"Japan","city":"Tokyo","latitude":35.68,"longitude":139.69}`)

	providers = []provider{
		{name: "down", url: down, parse: saved[0].parse},
		{name: "null", url: nullIsland, parse: saved[0].parse},
		{name: "good", url: good, parse: saved[0].parse},
	}

	loc, err := Lookup(context.Background())
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	want := protocol.Location{Country: "Japan", City: "Tokyo", Lat: 35.68, Lon: 139.69}
	if loc != want {
		t.Fatalf("got %+v, want %+v", loc, want)
	}
}

// TestLookupAllFail verifies Lookup returns an error when no provider yields a
// usable location.
func TestLookupAllFail(t *testing.T) {
	saved := providers
	t.Cleanup(func() { providers = saved })

	down := serve(t, http.StatusBadGateway, "")
	providers = []provider{{name: "down", url: down, parse: saved[0].parse}}

	if _, err := Lookup(context.Background()); err == nil {
		t.Fatal("expected error when all providers fail")
	}
}
