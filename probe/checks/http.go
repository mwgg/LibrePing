package checks

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/mwgg/libreping/pkg/protocol"
)

// HTTPChecker performs an HTTP(S) GET and measures availability and latency.
//
// Spec.Params (all optional):
//   - method:          HTTP method (default GET)
//   - expect_status:   comma-separated acceptable status codes (default: any 2xx/3xx)
//   - keyword:         substring that must appear in the body for an "up" result
//   - timeout_seconds: per-request timeout (default 10)
//
// Requires no special privileges.
type HTTPChecker struct{}

func (HTTPChecker) Type() protocol.CheckType { return protocol.CheckHTTP }

func (HTTPChecker) Run(ctx context.Context, spec protocol.CheckSpec) (Outcome, error) {
	timeout := 10 * time.Second
	if v := spec.Params["timeout_seconds"]; v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			timeout = time.Duration(n) * time.Second
		}
	}
	reqCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	method := strings.ToUpper(spec.Params["method"])
	if method == "" {
		method = http.MethodGet
	}

	req, err := http.NewRequestWithContext(reqCtx, method, spec.Target, nil)
	if err != nil {
		return Outcome{Status: protocol.StatusDown, Detail: map[string]string{"error": err.Error()}}, nil
	}
	req.Header.Set("User-Agent", "LibrePing-Probe/0.1")

	// A fresh client per run avoids connection reuse skewing latency between
	// independent checks. The dialer enforces the target policy (and re-checks
	// every redirect hop), so a check cannot be used to reach internal hosts.
	client := &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			Proxy: nil,
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				return guardDial(ctx, network, addr, timeout)
			},
		},
	}

	start := time.Now()
	resp, err := client.Do(req)
	rtt := float64(time.Since(start).Microseconds()) / 1000.0
	if err != nil {
		return Outcome{
			Status:    protocol.StatusDown,
			RTTMillis: rtt,
			Detail:    map[string]string{"error": err.Error()},
		}, nil
	}
	defer resp.Body.Close()

	detail := map[string]string{"status_code": strconv.Itoa(resp.StatusCode)}

	keyword := spec.Params["keyword"]
	if keyword != "" {
		// Cap the read so a huge body cannot exhaust memory.
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		if !strings.Contains(string(body), keyword) {
			detail["keyword"] = "missing"
			return Outcome{Status: protocol.StatusDegraded, RTTMillis: rtt, Detail: detail}, nil
		}
		detail["keyword"] = "found"
	}

	if !statusAcceptable(resp.StatusCode, spec.Params["expect_status"]) {
		return Outcome{Status: protocol.StatusDown, RTTMillis: rtt, Detail: detail}, nil
	}
	return Outcome{Status: protocol.StatusUp, RTTMillis: rtt, Detail: detail}, nil
}

// statusAcceptable reports whether code satisfies the expectation. When expect
// is empty, any 2xx/3xx is accepted.
func statusAcceptable(code int, expect string) bool {
	if expect == "" {
		return code >= 200 && code < 400
	}
	for _, part := range strings.Split(expect, ",") {
		if strings.TrimSpace(part) == fmt.Sprintf("%d", code) {
			return true
		}
	}
	return false
}
