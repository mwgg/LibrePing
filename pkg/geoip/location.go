package geoip

import (
	"context"
	"strconv"
	"strings"

	"github.com/mwgg/libreping/pkg/protocol"
)

// ParseLocation reads an operator-declared "Country,City,lat,lon" string.
// Missing or malformed parts are left zero rather than failing — location is
// self-declared metadata, not validated.
func ParseLocation(s string) protocol.Location {
	if strings.TrimSpace(s) == "" {
		return protocol.Location{}
	}
	parts := strings.Split(s, ",")
	loc := protocol.Location{}
	if len(parts) > 0 {
		loc.Country = strings.TrimSpace(parts[0])
	}
	if len(parts) > 1 {
		loc.City = strings.TrimSpace(parts[1])
	}
	if len(parts) > 2 {
		loc.Lat, _ = strconv.ParseFloat(strings.TrimSpace(parts[2]), 64)
	}
	if len(parts) > 3 {
		loc.Lon, _ = strconv.ParseFloat(strings.TrimSpace(parts[3]), 64)
	}
	return loc
}

// Resolve decides a node's own location. An operator-declared string always
// wins (so anyone can override or pin a location). Otherwise, when autoDetect
// is enabled, it looks the location up from the public IP. The returned auto
// flag reports whether IP geolocation was used (handy for logging); err is
// non-nil only when auto-detection was attempted and every provider failed.
func Resolve(ctx context.Context, declared string, autoDetect bool) (loc protocol.Location, auto bool, err error) {
	if strings.TrimSpace(declared) != "" {
		return ParseLocation(declared), false, nil
	}
	if !autoDetect {
		return protocol.Location{}, false, nil
	}
	loc, err = Lookup(ctx)
	if err != nil {
		return protocol.Location{}, true, err
	}
	return loc, true, nil
}
