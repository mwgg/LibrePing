package protocol

import (
	"encoding/hex"
	"testing"

	"github.com/mwgg/libreping/pkg/identity"
)

func TestSubscriptionSignVerifyTamper(t *testing.T) {
	owner, _ := identity.Generate()
	ss := SignSubscription(owner, Subscription{CheckID: "abc123", IntervalSeconds: 60, ExpiryMS: 1000})
	if ss.Subscription.Owner != owner.NodeID() {
		t.Fatal("owner not stamped")
	}
	if err := ss.Verify(); err != nil {
		t.Fatalf("valid subscription failed to verify: %v", err)
	}
	ss.Subscription.CheckID = "different"
	if err := ss.Verify(); err == nil {
		t.Fatal("tampered subscription verified")
	}
}

func TestAlertRuleSignVerifyTamper(t *testing.T) {
	owner, _ := identity.Generate()
	sa := SignAlertRule(owner, AlertRule{
		CheckID: "abc123", Channel: AlertWebhook,
		DestHash:      AlertDestHash(owner.NodeID(), "https://hook.example"),
		Recipients:    map[string]string{"hub1": "c2VhbGVk", "hub2": "b3RoZXI="},
		FailLocations: 2, ForSeconds: 120, ExpiryMS: 1000,
	})
	if err := sa.Verify(); err != nil {
		t.Fatalf("valid alert rule failed to verify: %v", err)
	}
	// Tampering with a sealed recipient (e.g. redirecting to an attacker's hub)
	// breaks the signature.
	sa.Rule.Recipients["hub1"] = "dGFtcGVyZWQ="
	if err := sa.Verify(); err == nil {
		t.Fatal("tampered alert rule verified")
	}
}

// fixedSeed is a deterministic key used only for the cross-language vectors.
var fixedSeed = []byte{
	1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16,
	17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32,
}

// TestCrossLanguageVectors pins the signatures that the browser client
// (web/src/identity.ts) must reproduce byte-for-byte from the same seed and
// inputs. Ed25519 is deterministic, so any divergence in the canonical encoding
// shows up as a mismatch here. If you change a canonical() encoding, regenerate
// these AND the JS test vector together.
func TestCrossLanguageVectors(t *testing.T) {
	id, err := identity.FromSeed(fixedSeed)
	if err != nil {
		t.Fatalf("seed: %v", err)
	}

	sub := Subscription{Owner: id.NodeID(), CheckID: "7a0e21c6e134a0c0", IntervalSeconds: 60, ExpiryMS: 1700000000000, UpdatedMS: 1699999999000}
	subSig := hex.EncodeToString(id.Sign(sub.canonical()))

	rule := AlertRule{
		Owner: id.NodeID(), CheckID: "7a0e21c6e134a0c0", Channel: AlertWebhook,
		DestHash:      "11112222333344445555666677778888",
		Recipients:    map[string]string{"hubB": "Y2lwaGVyQg==", "hubA": "Y2lwaGVyQQ=="},
		FailLocations: 2, ForSeconds: 120, ExpiryMS: 1700000000000, UpdatedMS: 1699999999000,
	}
	ruleSig := hex.EncodeToString(id.Sign(rule.canonical()))

	t.Logf("node_id=%s", id.NodeID())
	t.Logf("subscription canonical=%q", string(sub.canonical()))
	t.Logf("subscription sig=%s", subSig)
	t.Logf("alert canonical=%q", string(rule.canonical()))
	t.Logf("alert sig=%s", ruleSig)

	// Pinned vectors. web/src/identity.ts has the same seed + expected hex in
	// its own test; both must match. Regenerate together if canonical() changes.
	const wantNodeID = "65b60673d6ed884bf01c2c222d82ada0"
	const wantSubSig = "dc079b7fbb2a61ca1ab313ff294fc769242d118665dd189626aa7bbbde0ae444b8f97baf7bcf54170359a4d6d5a2b5982745a231072e48a5dce7d2bc2024440d"
	const wantRuleSig = "40d2789a8d22310d763453a2c02c134b4ff2e3a9d45478644a80ac623949a201195e636dcded214f03601c210bffd0839077131a978e77efc4154f29fbbe6c0a"
	if id.NodeID() != wantNodeID {
		t.Fatalf("node id drifted: got %s want %s", id.NodeID(), wantNodeID)
	}
	if subSig != wantSubSig {
		t.Fatalf("subscription signature drifted: got %s want %s", subSig, wantSubSig)
	}
	if ruleSig != wantRuleSig {
		t.Fatalf("alert signature drifted: got %s want %s", ruleSig, wantRuleSig)
	}
}
