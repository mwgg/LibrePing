package protocol

import (
	"bytes"
	"testing"

	"github.com/mwgg/libreping/pkg/identity"
)

func sampleContent() ResultContent {
	return ResultContent{
		CheckID:     "check-1",
		CheckType:   CheckHTTP,
		Target:      "https://example.com",
		Location:    Location{Country: "DE", City: "Frankfurt", Lat: 50.11, Lon: 8.68},
		TimestampMS: 1_700_000_000_000,
		Status:      StatusUp,
		RTTMillis:   42.5,
	}
}

func TestSignAndVerifyResult(t *testing.T) {
	id, _ := identity.Generate()
	sr, err := SignResult(id, sampleContent())
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	if sr.Content.ProbeID != id.NodeID() {
		t.Fatal("SignResult did not stamp probe ID")
	}
	if err := sr.Verify(); err != nil {
		t.Fatalf("freshly signed result failed to verify: %v", err)
	}
}

func TestVerifyRejectsTamperedContent(t *testing.T) {
	id, _ := identity.Generate()
	sr, _ := SignResult(id, sampleContent())

	// Flip a measured value after signing — verification must fail.
	sr.Content.Status = StatusDown
	if err := sr.Verify(); err == nil {
		t.Fatal("tampered result verified; forged data would be accepted")
	}
}

func TestVerifyRejectsSpoofedProbeID(t *testing.T) {
	id, _ := identity.Generate()
	sr, _ := SignResult(id, sampleContent())

	// Attacker swaps in a different identity's pubkey but keeps the signature.
	// The signature no longer matches the key, so it must be rejected.
	other, _ := identity.Generate()
	sr.PubKey = other.Public()
	if err := sr.Verify(); err == nil {
		t.Fatal("result with mismatched pubkey verified")
	}
}

func TestDeriveIDIsDeterministicAndContentBased(t *testing.T) {
	a := CheckSpec{Type: CheckHTTP, Target: "https://example.com", IntervalSeconds: 60, Params: map[string]string{"keyword": "ok", "method": "GET"}}
	// Same content, different param insertion order and a different interval.
	b := CheckSpec{Type: CheckHTTP, Target: "https://example.com", IntervalSeconds: 30, Params: map[string]string{"method": "GET", "keyword": "ok"}}
	if a.DeriveID() != b.DeriveID() {
		t.Fatal("DeriveID should ignore param order and interval")
	}
	c := CheckSpec{Type: CheckHTTP, Target: "https://other.example.com"}
	if a.DeriveID() == c.DeriveID() {
		t.Fatal("different targets must derive different IDs")
	}
}

// TestDeriveIDNoSeparatorCollision guards the content-addressing boundary: two
// specs that differ only in where a field boundary falls must not collide, even
// if a value contains the characters a naive encoding would use as separators.
func TestDeriveIDNoSeparatorCollision(t *testing.T) {
	// With a "type|target" join these would both render "http|a|b"; with
	// length-prefixing they cannot collide.
	x := CheckSpec{Type: CheckHTTP, Target: "a|b"}
	y := CheckSpec{Type: CheckType("http|a"), Target: "b"}
	if x.DeriveID() == y.DeriveID() {
		t.Fatal("separator-ambiguous specs collided")
	}
	// Same for params: a "k=v" join would let key/value boundaries shift.
	p := CheckSpec{Type: CheckHTTP, Target: "t", Params: map[string]string{"a": "b=c"}}
	q := CheckSpec{Type: CheckHTTP, Target: "t", Params: map[string]string{"a=b": "c"}}
	if p.DeriveID() == q.DeriveID() {
		t.Fatal("separator-ambiguous params collided")
	}
}

// TestCatalogVerifyRejectsForgedID ensures a signed entry whose Spec.ID does not
// match its content is rejected — otherwise a valid signature could redirect a
// popular check's ID to an attacker-controlled target.
func TestCatalogVerifyRejectsForgedID(t *testing.T) {
	hub, _ := identity.Generate()
	spec := CheckSpec{Type: CheckHTTP, Target: "https://evil.example.com", IntervalSeconds: 60}
	spec.ID = "deadbeefdeadbeef" // a different (e.g. popular) check's ID
	sc, err := SignCatalogEntry(hub, CatalogEntry{Spec: spec})
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	if err := sc.Verify(); err != ErrSpecIDMismatch {
		t.Fatalf("expected ErrSpecIDMismatch, got %v", err)
	}
}

func TestSignAndVerifyCatalogEntry(t *testing.T) {
	hub, _ := identity.Generate()
	spec := CheckSpec{Type: CheckHTTP, Target: "https://example.com", IntervalSeconds: 60}
	spec.ID = spec.DeriveID()
	sc, err := SignCatalogEntry(hub, CatalogEntry{Spec: spec})
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	if sc.Entry.HubID != hub.NodeID() {
		t.Fatal("SignCatalogEntry did not stamp hub ID")
	}
	if err := sc.Verify(); err != nil {
		t.Fatalf("freshly signed catalog entry failed to verify: %v", err)
	}
	// Tamper with the target after signing.
	sc.Entry.Spec.Target = "https://evil.example.com"
	if err := sc.Verify(); err == nil {
		t.Fatal("tampered catalog entry verified")
	}
}

func TestSignAndVerifyHubAnnouncement(t *testing.T) {
	hub, _ := identity.Generate()
	sa, err := SignHubAnnouncement(hub, HubAnnouncement{PublicURL: "https://nl.libreping.mw.gg", Name: "nl", TimestampMS: 1})
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	if sa.Announcement.HubID != hub.NodeID() {
		t.Fatal("SignHubAnnouncement did not stamp hub ID")
	}
	if err := sa.Verify(); err != nil {
		t.Fatalf("freshly signed announcement failed to verify: %v", err)
	}
	// Tamper with the advertised URL after signing.
	sa.Announcement.PublicURL = "https://attacker.example.com"
	if err := sa.Verify(); err == nil {
		t.Fatal("tampered announcement verified")
	}
}

func TestHubAnnouncementP2PAddrs(t *testing.T) {
	hub, _ := identity.Generate()
	addr := "/ip4/203.0.113.10/tcp/4001/p2p/12D3KooWtest"
	sa, err := SignHubAnnouncement(hub, HubAnnouncement{
		PublicURL: "https://hub.example.org", TimestampMS: 1, P2PAddrs: []string{addr},
	})
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	if err := sa.Verify(); err != nil {
		t.Fatalf("announcement with P2PAddrs failed to verify: %v", err)
	}
	if len(sa.Announcement.P2PAddrs) != 1 || sa.Announcement.P2PAddrs[0] != addr {
		t.Fatalf("P2PAddrs not preserved: %v", sa.Announcement.P2PAddrs)
	}
	// The advertised dial addresses are signed, so they can't be swapped in transit.
	sa.Announcement.P2PAddrs = []string{"/ip4/10.0.0.1/tcp/4001/p2p/12D3KooWevil"}
	if err := sa.Verify(); err == nil {
		t.Fatal("tampered P2PAddrs verified")
	}
}

// TestHubAnnouncementAdditiveCompat proves the new field is additive: an
// announcement that sets no P2PAddrs signs to the exact bytes an older hub
// produced (omitempty drops it), so existing signatures still verify.
func TestHubAnnouncementAdditiveCompat(t *testing.T) {
	a := HubAnnouncement{HubID: "abc", PublicURL: "https://h", TimestampMS: 1}
	b, err := a.CanonicalBytes()
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(b, []byte("p2p_addrs")) {
		t.Fatalf("empty P2PAddrs must be omitted from the signing payload, got %s", b)
	}
}
