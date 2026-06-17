package checks

import (
	"context"
	"net"
	"strings"
	"time"

	"github.com/mwgg/libreping/pkg/protocol"
)

// DNSChecker resolves a name and (optionally) checks the answer.
// `target` is the hostname. Params:
//   - record:  A|AAAA|MX|TXT (default A)
//   - expect:  substring that must appear in the joined answers (optional)
//
// No special privileges.
type DNSChecker struct{}

func (DNSChecker) Type() protocol.CheckType { return protocol.CheckDNS }

func (DNSChecker) Run(ctx context.Context, spec protocol.CheckSpec) (Outcome, error) {
	timeout := paramDuration(spec, "timeout_seconds", 10*time.Second)
	rctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	record := strings.ToUpper(paramString(spec, "record", "A"))
	var r net.Resolver

	start := time.Now()
	answers, err := resolve(rctx, &r, record, spec.Target)
	rtt := msSince(start)
	if err != nil {
		return Outcome{Status: protocol.StatusDown, RTTMillis: rtt, Detail: map[string]string{"error": err.Error()}}, nil
	}

	detail := map[string]string{"record": record, "answers": strings.Join(answers, ",")}
	if len(answers) == 0 {
		return Outcome{Status: protocol.StatusDown, RTTMillis: rtt, Detail: detail}, nil
	}
	if expect := spec.Params["expect"]; expect != "" {
		if !strings.Contains(strings.Join(answers, ","), expect) {
			detail["expect"] = "missing"
			return Outcome{Status: protocol.StatusDegraded, RTTMillis: rtt, Detail: detail}, nil
		}
		detail["expect"] = "found"
	}
	return Outcome{Status: protocol.StatusUp, RTTMillis: rtt, Detail: detail}, nil
}

func resolve(ctx context.Context, r *net.Resolver, record, host string) ([]string, error) {
	switch record {
	case "AAAA", "A":
		ips, err := r.LookupIP(ctx, ipNetwork(record), host)
		if err != nil {
			return nil, err
		}
		out := make([]string, 0, len(ips))
		for _, ip := range ips {
			out = append(out, ip.String())
		}
		return out, nil
	case "MX":
		mxs, err := r.LookupMX(ctx, host)
		if err != nil {
			return nil, err
		}
		out := make([]string, 0, len(mxs))
		for _, mx := range mxs {
			out = append(out, mx.Host)
		}
		return out, nil
	case "TXT":
		return r.LookupTXT(ctx, host)
	default:
		return r.LookupHost(ctx, host)
	}
}

func ipNetwork(record string) string {
	if record == "AAAA" {
		return "ip6"
	}
	return "ip4"
}
