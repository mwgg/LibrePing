package checks

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/mwgg/libreping/pkg/protocol"
)

// TestMain disables the private-target guard for the checker tests, which
// deliberately exercise the checkers against loopback test servers. The guard
// itself is covered separately in guard_test.go. Setting the env before any
// test runs ensures the lazily-loaded policy picks it up.
func TestMain(m *testing.M) {
	os.Setenv("PROBE_BLOCK_PRIVATE", "false")
	os.Exit(m.Run())
}

func TestTCPChecker(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			_ = c.Close()
		}
	}()

	up, _ := TCPChecker{}.Run(context.Background(), protocol.CheckSpec{Type: protocol.CheckTCP, Target: ln.Addr().String()})
	if up.Status != protocol.StatusUp {
		t.Fatalf("expected up to open port, got %s", up.Status)
	}

	down, _ := TCPChecker{}.Run(context.Background(), protocol.CheckSpec{
		Type: protocol.CheckTCP, Target: "127.0.0.1:1", Params: map[string]string{"timeout_seconds": "1"},
	})
	if down.Status != protocol.StatusDown {
		t.Fatalf("expected down to closed port, got %s", down.Status)
	}
}

func TestDNSChecker(t *testing.T) {
	up, _ := DNSChecker{}.Run(context.Background(), protocol.CheckSpec{
		Type: protocol.CheckDNS, Target: "localhost", Params: map[string]string{"record": "A"},
	})
	if up.Status != protocol.StatusUp {
		t.Fatalf("expected localhost to resolve, got %s (%v)", up.Status, up.Detail)
	}

	down, _ := DNSChecker{}.Run(context.Background(), protocol.CheckSpec{
		Type: protocol.CheckDNS, Target: "this-name-should-not-exist.invalid",
		Params: map[string]string{"timeout_seconds": "3"},
	})
	if down.Status != protocol.StatusDown {
		t.Fatalf("expected unresolvable name to be down, got %s", down.Status)
	}
}

func TestTLSCheckerUntrustedIsDown(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {}))
	defer srv.Close()
	addr := srv.Listener.Addr().String()

	// Default verification is on, so the self-signed test cert fails → down.
	out, _ := TLSChecker{}.Run(context.Background(), protocol.CheckSpec{Type: protocol.CheckTLS, Target: addr})
	if out.Status != protocol.StatusDown {
		t.Fatalf("expected down for untrusted cert, got %s (%v)", out.Status, out.Detail)
	}

	unreach, _ := TLSChecker{}.Run(context.Background(), protocol.CheckSpec{
		Type: protocol.CheckTLS, Target: "127.0.0.1:1", Params: map[string]string{"timeout_seconds": "1"},
	})
	if unreach.Status != protocol.StatusDown {
		t.Fatalf("expected down for unreachable TLS, got %s", unreach.Status)
	}
}

func TestICMPCheckerLoopback(t *testing.T) {
	if !RawSocketsAvailable() {
		t.Skip("raw/unprivileged ICMP sockets unavailable in this environment")
	}
	out, _ := ICMPChecker{}.Run(context.Background(), protocol.CheckSpec{
		Type: protocol.CheckICMP, Target: "127.0.0.1", Params: map[string]string{"count": "2"},
	})
	if out.Status != protocol.StatusUp {
		t.Fatalf("expected loopback ping up, got %s (%v)", out.Status, out.Detail)
	}
}
