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

// IsBlockedIP reports whether ip is one an outbound request must not reach:
// loopback, private (RFC1918 / unique-local), link-local, multicast,
// unspecified, or a cloud metadata endpoint. nil is treated as blocked.
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
