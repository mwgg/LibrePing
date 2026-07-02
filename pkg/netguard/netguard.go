// Package netguard provides SSRF defenses shared by the hub and probe: an IP
// classifier that flags addresses no outbound request should reach, and an
// http.Client whose dialer re-checks the *resolved* IP at connect time so a
// hostname that passes a pre-check cannot be rebound to a private IP between
// the check and the dial (DNS rebinding).
//
// The hub uses it for owner-supplied webhook destinations and for directory
// reachability probes; the probe uses the IP classifier to enforce an operator
// target policy. It is deliberately conservative: when in doubt, block.
package netguard

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"time"
)

// ErrBlockedAddress is returned when a destination resolves to a blocked range.
var ErrBlockedAddress = errors.New("netguard: destination resolves to a blocked address")

// metadataV4 is the cloud instance-metadata address (AWS/GCP/Azure/OpenStack
// all share 169.254.169.254); metadataV6 is the AWS IMDSv6 form.
var (
	metadataV4 = net.IPv4(169, 254, 169, 254)
	metadataV6 = net.ParseIP("fd00:ec2::254")
)

// blockedCIDRs are non-public ranges Go's IsPrivate()/IsLinkLocal*/etc. do not
// cover but that an outbound request still must never reach. Parsed once at
// startup. IPNet.Contains normalizes IPv4-mapped-IPv6 forms via To4(), so a
// mapped ::ffff:100.64.0.1 is caught by the IPv4 CIDRs here.
var blockedCIDRs = mustParseCIDRs(
	// 100.64.0.0/10 — RFC 6598 shared address space (CGNAT, and the range
	// Tailscale hands out): a hub on a tailnet must not be SSRF'd into the
	// operator's private tailnet via an owner-supplied webhook destination.
	"100.64.0.0/10",
	"192.0.0.0/24",       // RFC 6890 IETF protocol assignments
	"198.18.0.0/15",      // RFC 2544 benchmarking
	"255.255.255.255/32", // limited broadcast
	"0.0.0.0/8",          // RFC 1122 "this network" (0.0.0.0 unspecified is handled separately)
	// 64:ff9b::/96 — RFC 6052 NAT64 well-known prefix: these embed an IPv4
	// address (e.g. 64:ff9b::7f00:1 → 127.0.0.1), so a resolver behind a NAT64
	// gateway would translate them back to blocked v4 targets.
	"64:ff9b::/96",
	"fec0::/10", // deprecated IPv6 site-local
)

func mustParseCIDRs(cidrs ...string) []*net.IPNet {
	out := make([]*net.IPNet, 0, len(cidrs))
	for _, c := range cidrs {
		_, n, err := net.ParseCIDR(c)
		if err != nil {
			panic("netguard: bad blocked CIDR " + c + ": " + err.Error())
		}
		out = append(out, n)
	}
	return out
}

// IsBlockedIP reports whether ip is one an outbound request must not reach:
// loopback, private (RFC1918 / unique-local), link-local, multicast,
// unspecified, a cloud metadata endpoint, or one of the additional non-public
// ranges in blockedCIDRs (CGNAT/tailnet, NAT64, benchmarking, etc.). nil is
// treated as blocked.
func IsBlockedIP(ip net.IP) bool {
	if ip == nil {
		return true
	}
	if ip.IsLoopback() || ip.IsPrivate() || ip.IsUnspecified() ||
		ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsMulticast() {
		return true
	}
	if ip.Equal(metadataV4) || (metadataV6 != nil && ip.Equal(metadataV6)) {
		return true
	}
	for _, n := range blockedCIDRs {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

// ValidateURL parses raw, requires an http/https scheme (https only when
// requireHTTPS), and rejects it if the host is an IP literal in a blocked
// range. Hostname targets are fully checked at dial time by SafeClient; this is
// a cheap upfront reject for obviously-bad URLs.
func ValidateURL(raw string, requireHTTPS bool) error {
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("netguard: parse url: %w", err)
	}
	switch u.Scheme {
	case "https":
	case "http":
		if requireHTTPS {
			return errors.New("netguard: https is required")
		}
	default:
		return fmt.Errorf("netguard: scheme %q not allowed", u.Scheme)
	}
	host := u.Hostname()
	if host == "" {
		return errors.New("netguard: url has no host")
	}
	if ip := net.ParseIP(host); ip != nil && IsBlockedIP(ip) {
		return ErrBlockedAddress
	}
	return nil
}

// Options tunes a SafeClient.
type Options struct {
	// Timeout bounds the whole request (default 10s).
	Timeout time.Duration
	// AllowRedirects permits following redirects (each re-checked); default
	// false — redirects are a classic SSRF bypass.
	AllowRedirects bool
	// AllowPrivate disables the blocked-IP-range check at dial time. It exists
	// for operators who deliberately federate over a trusted LAN or container
	// network (where peers resolve to private IPs). Default false: private,
	// loopback, link-local, and metadata ranges are all refused.
	AllowPrivate bool
}

// SafeClient returns an *http.Client that refuses to connect to blocked IP
// ranges. The check happens inside DialContext on the IP the host actually
// resolved to, so it is robust against DNS rebinding. Proxies from the
// environment are ignored, and (unless AllowRedirects) redirects are blocked.
func SafeClient(opts Options) *http.Client {
	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	dialer := &net.Dialer{Timeout: timeout}
	transport := &http.Transport{
		Proxy:                 nil,
		DialContext:           guardedDial(dialer, opts.AllowPrivate),
		TLSHandshakeTimeout:   timeout,
		ResponseHeaderTimeout: timeout,
		ForceAttemptHTTP2:     true,
	}
	checkRedirect := func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}
	if opts.AllowRedirects {
		checkRedirect = nil
	}
	return &http.Client{Timeout: timeout, Transport: transport, CheckRedirect: checkRedirect}
}

// guardedDial resolves the host, rejects the dial if any candidate address is
// blocked, and otherwise dials the first allowed address. Resolving here (not
// before) closes the rebinding window.
func guardedDial(dialer *net.Dialer, allowPrivate bool) func(ctx context.Context, network, addr string) (net.Conn, error) {
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		host, port, err := net.SplitHostPort(addr)
		if err != nil {
			return nil, err
		}
		resolver := dialer.Resolver
		if resolver == nil {
			resolver = net.DefaultResolver
		}
		ips, err := resolver.LookupIPAddr(ctx, host)
		if err != nil {
			return nil, err
		}
		if !allowPrivate {
			for _, ipa := range ips {
				if IsBlockedIP(ipa.IP) {
					return nil, ErrBlockedAddress
				}
			}
		}
		// All resolved addresses are allowed; dial the first that connects,
		// pinning to the validated IP so no second lookup can slip in.
		var lastErr error
		for _, ipa := range ips {
			conn, err := dialer.DialContext(ctx, network, net.JoinHostPort(ipa.IP.String(), port))
			if err == nil {
				return conn, nil
			}
			lastErr = err
		}
		if lastErr == nil {
			lastErr = ErrBlockedAddress
		}
		return nil, lastErr
	}
}
