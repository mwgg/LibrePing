package checks

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"

	"golang.org/x/net/ipv4"

	"github.com/mwgg/libreping/pkg/protocol"
)

// TracerouteChecker maps the network path to the target by sending ICMP echoes
// with increasing TTL and recording which hop replies with time-exceeded.
// `target` is a host or IP. Params:
//   - max_hops: TTL ceiling (default 20)
//
// Requires raw sockets (CAP_NET_RAW or net.ipv4.ping_group_range).
type TracerouteChecker struct{}

func (TracerouteChecker) Type() protocol.CheckType { return protocol.CheckTraceroute }

func (TracerouteChecker) Run(ctx context.Context, spec protocol.CheckSpec) (Outcome, error) {
	maxHops := paramInt(spec, "max_hops", 20)
	if maxHops < 1 || maxHops > 40 {
		maxHops = 20
	}
	perHop := paramDuration(spec, "timeout_seconds", 2*time.Second)

	ipAddr, err := net.ResolveIPAddr("ip4", spec.Target)
	if err != nil {
		return Outcome{Status: protocol.StatusDown, Detail: map[string]string{"error": err.Error()}}, nil
	}
	if err := guardIP(ipAddr.IP); err != nil {
		return Outcome{Status: protocol.StatusDown, Detail: map[string]string{"error": err.Error()}}, nil
	}

	conn, privileged, err := icmpListen()
	if err != nil {
		return Outcome{Status: protocol.StatusDegraded, Detail: map[string]string{"error": "raw sockets unavailable: " + err.Error()}}, ErrNotImplemented
	}
	defer conn.Close()

	var hops []string
	reached := false
	for ttl := 1; ttl <= maxHops; ttl++ {
		if ctx.Err() != nil {
			break
		}
		hop, rtt, typ, err := pingOnce(conn, privileged, ipAddr.IP, ttl, ttl, perHop)
		switch {
		case err != nil:
			hops = append(hops, fmt.Sprintf("%d:*", ttl))
		default:
			hops = append(hops, fmt.Sprintf("%d:%s:%.1fms", ttl, hop, float64(rtt.Microseconds())/1000.0))
			if typ == ipv4.ICMPTypeEchoReply {
				reached = true
			}
		}
		if reached {
			break
		}
	}

	detail := map[string]string{"hops": strings.Join(hops, " "), "reached": fmt.Sprintf("%t", reached)}
	if reached {
		return Outcome{Status: protocol.StatusUp, RTTMillis: 0, Detail: detail}, nil
	}
	return Outcome{Status: protocol.StatusDegraded, Detail: detail}, nil
}
