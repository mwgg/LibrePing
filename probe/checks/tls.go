package checks

import (
	"context"
	"crypto/tls"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/mwgg/libreping/pkg/protocol"
)

// TLSChecker connects and inspects the served certificate.
// `target` is "host" or "host:port" (default port 443). Params:
//   - warn_days: report degraded when the cert expires within this many days (default 14)
//
// Reports down on handshake/validation failure or an expired cert. No privilege.
type TLSChecker struct{}

func (TLSChecker) Type() protocol.CheckType { return protocol.CheckTLS }

func (TLSChecker) Run(ctx context.Context, spec protocol.CheckSpec) (Outcome, error) {
	warnDays := paramInt(spec, "warn_days", 14)
	timeout := paramDuration(spec, "timeout_seconds", 10*time.Second)

	addr := spec.Target
	host := addr
	if _, _, err := net.SplitHostPort(addr); err != nil {
		addr = net.JoinHostPort(addr, "443")
	} else {
		host, _, _ = net.SplitHostPort(addr)
	}

	dctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	start := time.Now()
	// Dial through the target guard (pins to a policy-permitted IP), then run
	// the TLS handshake over that connection so the cert check still happens.
	raw, err := guardDial(dctx, "tcp", addr, timeout)
	if err != nil {
		return Outcome{Status: protocol.StatusDown, RTTMillis: msSince(start), Detail: map[string]string{"error": err.Error()}}, nil
	}
	conn := tls.Client(raw, &tls.Config{ServerName: host})
	if err := conn.HandshakeContext(dctx); err != nil {
		rtt := msSince(start)
		_ = conn.Close()
		// Includes expired/invalid-chain errors (verification is on by default).
		return Outcome{Status: protocol.StatusDown, RTTMillis: rtt, Detail: map[string]string{"error": err.Error()}}, nil
	}
	rtt := msSince(start)
	defer conn.Close()

	state := conn.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		return Outcome{Status: protocol.StatusDown, RTTMillis: rtt, Detail: map[string]string{"error": "no peer certificate"}}, nil
	}
	leaf := state.PeerCertificates[0]
	daysLeft := int(time.Until(leaf.NotAfter).Hours() / 24)
	detail := map[string]string{
		"expires":   leaf.NotAfter.UTC().Format(time.RFC3339),
		"days_left": strconv.Itoa(daysLeft),
		"dns_names": strings.Join(leaf.DNSNames, ","),
		"issuer":    leaf.Issuer.CommonName,
	}

	switch {
	case time.Now().After(leaf.NotAfter):
		return Outcome{Status: protocol.StatusDown, RTTMillis: rtt, Detail: detail}, nil
	case daysLeft < warnDays:
		return Outcome{Status: protocol.StatusDegraded, RTTMillis: rtt, Detail: detail}, nil
	default:
		return Outcome{Status: protocol.StatusUp, RTTMillis: rtt, Detail: detail}, nil
	}
}
