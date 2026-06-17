package checks

import (
	"context"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/mwgg/libreping/pkg/netguard"
)

// TargetPolicy decides whether a probe may run a check against a resolved
// address. Checks are network-wide and anyone can create one, so without a
// policy a public probe could be subscribed to checks that make it scan its
// operator's LAN or hit cloud metadata — turning the probe into an SSRF/scan
// relay. By default the probe blocks private, loopback, link-local, and
// metadata ranges; an operator can allowlist specific CIDRs to monitor their
// own internal services on purpose.
type TargetPolicy struct {
	blockPrivate bool
	allow        []*net.IPNet // CIDRs permitted even when blockPrivate is on
}

var (
	policyMu     sync.Mutex
	loadedPolicy *TargetPolicy
)

// targetPolicy returns the process-wide policy, loaded once from the
// environment on first use: PROBE_BLOCK_PRIVATE (default true) and
// PROBE_ALLOW_TARGETS (comma-separated CIDRs allowed even when blocking is on).
func targetPolicy() TargetPolicy {
	policyMu.Lock()
	defer policyMu.Unlock()
	if loadedPolicy == nil {
		p := loadPolicy()
		loadedPolicy = &p
	}
	return *loadedPolicy
}

// loadPolicy reads the policy from the environment.
func loadPolicy() TargetPolicy {
	p := TargetPolicy{blockPrivate: envBool("PROBE_BLOCK_PRIVATE", true)}
	for _, c := range strings.Split(os.Getenv("PROBE_ALLOW_TARGETS"), ",") {
		c = strings.TrimSpace(c)
		if c == "" {
			continue
		}
		if _, n, err := net.ParseCIDR(c); err == nil {
			p.allow = append(p.allow, n)
		}
	}
	return p
}

// reloadPolicy clears the cached policy so the next use re-reads the
// environment. Used by tests that toggle PROBE_BLOCK_PRIVATE.
func reloadPolicy() {
	policyMu.Lock()
	loadedPolicy = nil
	policyMu.Unlock()
}

func envBool(key string, def bool) bool {
	v := strings.TrimSpace(os.Getenv(key))
	if v == "" {
		return def
	}
	b, err := strconv.ParseBool(v)
	if err != nil {
		return def
	}
	return b
}

// permitted reports whether the policy allows reaching ip.
func (p TargetPolicy) permitted(ip net.IP) bool {
	if !p.blockPrivate {
		return true
	}
	for _, n := range p.allow {
		if n.Contains(ip) {
			return true
		}
	}
	return !netguard.IsBlockedIP(ip)
}

// guardIP returns an error if the policy forbids reaching ip (used by the
// raw-socket checks, which resolve the target IP themselves).
func guardIP(ip net.IP) error {
	if !targetPolicy().permitted(ip) {
		return fmt.Errorf("target %s is blocked by probe policy (set PROBE_BLOCK_PRIVATE=false or PROBE_ALLOW_TARGETS to permit)", ip)
	}
	return nil
}

// guardResolve resolves host to the subset of addresses the policy permits,
// erroring if none are allowed. Resolving here lets callers pin the dial to a
// validated IP, closing the DNS-rebinding window.
func guardResolve(ctx context.Context, host string) ([]net.IP, error) {
	ips, err := net.DefaultResolver.LookupIPAddr(ctx, host)
	if err != nil {
		return nil, err
	}
	p := targetPolicy()
	out := make([]net.IP, 0, len(ips))
	for _, ipa := range ips {
		if p.permitted(ipa.IP) {
			out = append(out, ipa.IP)
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("target %s is blocked by probe policy (set PROBE_BLOCK_PRIVATE=false or PROBE_ALLOW_TARGETS to permit)", host)
	}
	return out, nil
}

// guardDial resolves and policy-checks addr ("host:port"), then dials only a
// permitted, pinned IP. Used by the HTTP and TLS checks so that even a redirect
// or DNS rebind cannot steer the connection to a blocked address.
func guardDial(ctx context.Context, network, addr string, timeout time.Duration) (net.Conn, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	ips, err := guardResolve(ctx, host)
	if err != nil {
		return nil, err
	}
	d := net.Dialer{Timeout: timeout}
	var lastErr error
	for _, ip := range ips {
		conn, err := d.DialContext(ctx, network, net.JoinHostPort(ip.String(), port))
		if err == nil {
			return conn, nil
		}
		lastErr = err
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("could not dial %s", host)
	}
	return nil, lastErr
}
