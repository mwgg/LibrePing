package protocol

import (
	"testing"

	"github.com/mwgg/libreping/pkg/identity"
)

func TestProbeRegistrationSignVerify(t *testing.T) {
	probe, _ := identity.Generate()
	reg, err := SignProbeRegistration(probe, ProbeRegistration{
		MaxChecksPerMinute: 60, SupportedTypes: []CheckType{CheckHTTP, CheckTCP}, TimestampMS: 1,
	})
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	if reg.Registration.ProbeID != probe.NodeID() {
		t.Fatal("probe ID not stamped")
	}
	if err := reg.Verify(); err != nil {
		t.Fatalf("valid registration failed to verify: %v", err)
	}

	// Forging a different probe ID (claiming someone else's capacity slot) must
	// fail: ProbeID no longer derives from the embedded key.
	reg.Registration.ProbeID = "deadbeefdeadbeef"
	if err := reg.Verify(); err == nil {
		t.Fatal("registration with mismatched probe ID verified")
	}
}
