package checks

import (
	"context"
	"testing"

	"github.com/mwgg/libreping/pkg/protocol"
)

// TestTargetPolicyBlocksPrivate verifies the default policy refuses private
// targets, and that PROBE_ALLOW_TARGETS re-permits a specific range. It toggles
// the env and reloads the cached policy (TestMain disables blocking globally).
func TestTargetPolicyBlocksPrivate(t *testing.T) {
	t.Setenv("PROBE_BLOCK_PRIVATE", "true")
	t.Setenv("PROBE_ALLOW_TARGETS", "")
	reloadPolicy()
	t.Cleanup(reloadPolicy)

	// A TCP check to loopback must now be refused (reported down) rather than
	// connecting — even if something is listening.
	out, _ := TCPChecker{}.Run(context.Background(), protocol.CheckSpec{
		Type: protocol.CheckTCP, Target: "127.0.0.1:22", Params: map[string]string{"timeout_seconds": "1"},
	})
	if out.Status != protocol.StatusDown {
		t.Fatalf("expected blocked loopback target to be down, got %s", out.Status)
	}
	if got := out.Detail["error"]; got == "" {
		t.Fatal("expected a policy error detail")
	}

	// Allowlisting loopback re-permits it.
	t.Setenv("PROBE_ALLOW_TARGETS", "127.0.0.0/8")
	reloadPolicy()
	if _, err := guardResolve(context.Background(), "127.0.0.1"); err != nil {
		t.Fatalf("allowlisted loopback should resolve, got %v", err)
	}
}
