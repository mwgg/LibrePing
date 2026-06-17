// Package geoip auto-detects a node's own geographic location from its public
// IP address using free, key-less geolocation services.
//
// Why: a probe's (or hub's) location is otherwise hand-entered by the operator
// as "Country,City,lat,lon", which is tedious and usually left blank or wrong.
// Looking it up from the public IP fills the global map accurately with no
// configuration.
//
// Honest limitation: this is still SELF-declared. A node reports its own
// location, and nothing here proves it — a probe operator can override or spoof
// it. The mesh relies on cross-probe corroboration, not proof-of-location. (The
// resulting Location flows into the probe-signed ResultContent exactly as the
// env-derived value did, so no wire format changes.)
package geoip

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/mwgg/libreping/pkg/protocol"
)

// providerTimeout bounds each individual provider request so a slow service
// can't stall startup; Lookup moves on to the next provider.
const providerTimeout = 4 * time.Second

// provider is one geolocation service: a URL to GET and a parser for its JSON.
type provider struct {
	name  string
	url   string
	parse func([]byte) (protocol.Location, error)
}

// providers are tried in order; the first to return a valid Location wins.
// All are key-less and served over HTTPS. Listing several gives redundancy if
// one is down or rate-limits us. The URLs are fixed, trusted hostnames (not
// user input), so the SSRF-hardened netguard client is unnecessary here.
var providers = []provider{
	{
		name: "ipwho.is",
		url:  "https://ipwho.is/",
		parse: func(b []byte) (protocol.Location, error) {
			var r struct {
				Success   bool    `json:"success"`
				Country   string  `json:"country"`
				City      string  `json:"city"`
				Latitude  float64 `json:"latitude"`
				Longitude float64 `json:"longitude"`
			}
			if err := json.Unmarshal(b, &r); err != nil {
				return protocol.Location{}, err
			}
			if !r.Success {
				return protocol.Location{}, fmt.Errorf("ipwho.is reported failure")
			}
			return protocol.Location{Country: r.Country, City: r.City, Lat: r.Latitude, Lon: r.Longitude}, nil
		},
	},
	{
		name: "ipapi.co",
		url:  "https://ipapi.co/json/",
		parse: func(b []byte) (protocol.Location, error) {
			var r struct {
				CountryName string  `json:"country_name"`
				City        string  `json:"city"`
				Latitude    float64 `json:"latitude"`
				Longitude   float64 `json:"longitude"`
				Error       bool    `json:"error"`
			}
			if err := json.Unmarshal(b, &r); err != nil {
				return protocol.Location{}, err
			}
			if r.Error {
				return protocol.Location{}, fmt.Errorf("ipapi.co reported error")
			}
			return protocol.Location{Country: r.CountryName, City: r.City, Lat: r.Latitude, Lon: r.Longitude}, nil
		},
	},
	{
		name: "geojs.io",
		url:  "https://get.geojs.io/v1/ip/geo.json",
		parse: func(b []byte) (protocol.Location, error) {
			// geojs returns latitude/longitude as strings.
			var r struct {
				Country   string `json:"country"`
				City      string `json:"city"`
				Latitude  string `json:"latitude"`
				Longitude string `json:"longitude"`
			}
			if err := json.Unmarshal(b, &r); err != nil {
				return protocol.Location{}, err
			}
			loc := protocol.Location{Country: r.Country, City: r.City}
			fmt.Sscanf(r.Latitude, "%g", &loc.Lat)
			fmt.Sscanf(r.Longitude, "%g", &loc.Lon)
			return loc, nil
		},
	},
}

// valid reports whether a looked-up Location is usable: real (non-zero)
// coordinates within range. Many services return 0/0 ("Null Island") when they
// cannot place an IP, which would put a bogus marker in the Gulf of Guinea.
func valid(l protocol.Location) bool {
	if l.Lat == 0 && l.Lon == 0 {
		return false
	}
	return l.Lat >= -90 && l.Lat <= 90 && l.Lon >= -180 && l.Lon <= 180
}

// Lookup queries the configured providers in order and returns the first valid
// Location. It returns an error only if every provider fails (or ctx is done).
func Lookup(ctx context.Context) (protocol.Location, error) {
	client := &http.Client{}
	var lastErr error
	for _, p := range providers {
		loc, err := lookupOne(ctx, client, p)
		if err != nil {
			lastErr = err
			continue
		}
		if !valid(loc) {
			lastErr = fmt.Errorf("%s returned no usable coordinates", p.name)
			continue
		}
		return loc, nil
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("no geolocation providers configured")
	}
	return protocol.Location{}, fmt.Errorf("geoip lookup failed: %w", lastErr)
}

func lookupOne(ctx context.Context, client *http.Client, p provider) (protocol.Location, error) {
	ctx, cancel := context.WithTimeout(ctx, providerTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, p.url, nil)
	if err != nil {
		return protocol.Location{}, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return protocol.Location{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return protocol.Location{}, fmt.Errorf("%s: status %d", p.name, resp.StatusCode)
	}
	// Cap the body; these responses are small JSON objects.
	b, err := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	if err != nil {
		return protocol.Location{}, err
	}
	return p.parse(b)
}
