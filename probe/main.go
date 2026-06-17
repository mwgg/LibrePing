// Command probe is the LibrePing probe agent. Run it on a VPS or NAS to
// contribute a monitoring vantage point: it attaches to a home hub, runs the
// hub's checks from your location, signs each result, and submits them.
//
// Configuration (environment variables):
//
//	HUB_URL                home hub base URL(s), comma-separated    (default http://localhost:8080)
//	HUB_DISCOVERY          learn more hubs from the gossiped directory (default true)
//	PROBE_KEY_PATH         probe identity key file                 (default ./data/probe.key)
//	PROBE_LOCATION         "Country,City,lat,lon" (overrides auto)  (default unset -> auto-detect)
//	PROBE_GEOIP            auto-detect location from public IP      (default true)
//	POLL_INTERVAL          how often to re-register + refresh      (default 60s)
//	MAX_CHECKS_PER_MINUTE  hard cap on checks this probe runs      (default 300; 0 = unlimited)
//	DISABLE_CHECKS         comma-separated check types to refuse   (e.g. icmp,traceroute)
//
// A probe is not tied to one hub. HUB_URL is a comma-separated list of seed
// hubs, and unless HUB_DISCOVERY is false the probe also learns peer hubs from
// the gossiped directory of whichever hub it is talking to. If its current hub
// goes down it fails over to another and re-homes to the configured hub once it
// recovers; results gossip network-wide regardless of which hub they land on.
//
// Location is self-declared: PROBE_LOCATION wins if set, otherwise the probe
// looks its location up from its public IP (PROBE_GEOIP). There is no
// proof-of-location — the mesh corroborates through cross-probe agreement.
package main

import (
	"context"
	"log/slog"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/mwgg/libreping/pkg/geoip"
	"github.com/mwgg/libreping/pkg/identity"
	"github.com/mwgg/libreping/pkg/protocol"
	"github.com/mwgg/libreping/probe/checks"
	"github.com/mwgg/libreping/probe/reporter"
)

func main() {
	log := slog.New(slog.NewTextHandler(os.Stdout, nil))

	id, err := identity.LoadOrCreate(env("PROBE_KEY_PATH", "./data/probe.key"))
	if err != nil {
		log.Error("load identity", "err", err)
		os.Exit(1)
	}
	log.Info("probe identity ready", "probe_id", id.NodeID())

	interval, err := time.ParseDuration(env("POLL_INTERVAL", "60s"))
	if err != nil {
		log.Error("invalid POLL_INTERVAL", "err", err)
		os.Exit(1)
	}

	maxPerMinute, err := strconv.Atoi(env("MAX_CHECKS_PER_MINUTE", "300"))
	if err != nil {
		log.Error("invalid MAX_CHECKS_PER_MINUTE", "err", err)
		os.Exit(1)
	}

	hubURLs := splitCSV(env("HUB_URL", "http://localhost:8080"))
	if len(hubURLs) == 0 {
		log.Error("no hub URL configured (set HUB_URL)")
		os.Exit(1)
	}
	client := reporter.NewFailoverClient(hubURLs, envBool("HUB_DISCOVERY", true), log)
	supported := supportedTypes(os.Getenv("DISABLE_CHECKS"), log)
	location := resolveLocation(os.Getenv("PROBE_LOCATION"), envBool("PROBE_GEOIP", true), log)
	rep := reporter.New(reporter.Config{
		Identity:           id,
		Location:           location,
		Hub:                client,
		PollInterval:       interval,
		MaxChecksPerMinute: maxPerMinute,
		SupportedTypes:     supported,
		Logger:             log,
	})

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	log.Info("probe started", "hubs", hubURLs,
		"interval", interval, "max_per_minute", maxPerMinute, "supports", supported)
	if err := rep.Run(ctx); err != nil && ctx.Err() == nil {
		log.Error("reporter stopped", "err", err)
		os.Exit(1)
	}
}

// supportedTypes returns the check types this probe will run: every type its
// registry implements, minus any listed in DISABLE_CHECKS and minus the
// raw-socket checks (icmp, traceroute) when this host can't open ICMP sockets.
func supportedTypes(disableCSV string, log *slog.Logger) []protocol.CheckType {
	disabled := map[protocol.CheckType]bool{}
	for _, t := range strings.Split(disableCSV, ",") {
		if t = strings.TrimSpace(t); t != "" {
			disabled[protocol.CheckType(t)] = true
		}
	}
	if !checks.RawSocketsAvailable() {
		disabled[protocol.CheckICMP] = true
		disabled[protocol.CheckTraceroute] = true
		log.Info("raw sockets unavailable; not offering icmp/traceroute (grant NET_RAW to enable)")
	}
	out := []protocol.CheckType{}
	for _, t := range checks.NewRegistry().Types() {
		if !disabled[t] {
			out = append(out, t)
		}
	}
	return out
}

// resolveLocation determines this probe's self-declared location: PROBE_LOCATION
// overrides, otherwise it is looked up from the public IP when geoip is enabled.
// A lookup failure is non-fatal — the probe runs with an empty location.
func resolveLocation(declared string, geoEnabled bool, log *slog.Logger) protocol.Location {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	loc, auto, err := geoip.Resolve(ctx, declared, geoEnabled)
	switch {
	case err != nil:
		log.Warn("could not auto-detect location from IP; running without one", "err", err)
	case auto:
		log.Info("location auto-detected from public IP", "city", loc.City, "country", loc.Country,
			"lat", loc.Lat, "lon", loc.Lon)
	case loc != (protocol.Location{}):
		log.Info("location set from PROBE_LOCATION", "city", loc.City, "country", loc.Country)
	}
	return loc
}

// splitCSV parses a comma-separated list, trimming whitespace and dropping
// empty entries. Order is preserved so the configured hubs keep their failover
// preference.
func splitCSV(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func env(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

// envBool reads a boolean env var; anything other than an explicit false/0/no
// (case-insensitive) keeps the default.
func envBool(key string, def bool) bool {
	v := strings.ToLower(strings.TrimSpace(os.Getenv(key)))
	if v == "" {
		return def
	}
	switch v {
	case "0", "false", "no", "off":
		return false
	case "1", "true", "yes", "on":
		return true
	}
	return def
}
