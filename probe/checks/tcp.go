package checks

import (
	"context"
	"time"

	"github.com/mwgg/libreping/pkg/protocol"
)

// TCPChecker opens a TCP connection to host:port and measures connect latency.
// `target` must be "host:port". No special privileges.
type TCPChecker struct{}

func (TCPChecker) Type() protocol.CheckType { return protocol.CheckTCP }

func (TCPChecker) Run(ctx context.Context, spec protocol.CheckSpec) (Outcome, error) {
	timeout := paramDuration(spec, "timeout_seconds", 10*time.Second)

	start := time.Now()
	// guardDial resolves + policy-checks the target before connecting.
	conn, err := guardDial(ctx, "tcp", spec.Target, timeout)
	rtt := msSince(start)
	if err != nil {
		return Outcome{Status: protocol.StatusDown, RTTMillis: rtt, Detail: map[string]string{"error": err.Error()}}, nil
	}
	_ = conn.Close()
	return Outcome{Status: protocol.StatusUp, RTTMillis: rtt}, nil
}
