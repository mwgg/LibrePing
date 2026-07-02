package store

import (
	"context"
	"errors"
	"testing"

	"github.com/mwgg/libreping/pkg/identity"
	"github.com/mwgg/libreping/pkg/protocol"
)

// signSpec builds a valid SignedCatalogEntry for spec, forcing the spec's ID to
// the given collidingID so a test can simulate two different specs that share a
// content-derived ID (a sha256[:8] collision) — both still verify because
// Verify only requires Spec.ID == Spec.DeriveID(), which we satisfy by setting
// the ID to DeriveID for the honest case and asserting the forged case.
func mustSign(t *testing.T, id *identity.Identity, spec protocol.CheckSpec) protocol.SignedCatalogEntry {
	t.Helper()
	sc, err := protocol.SignCatalogEntry(id, protocol.CatalogEntry{Spec: spec})
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	return sc
}

func TestMemCatalogCollisionReject(t *testing.T) {
	id, err := identity.Generate()
	if err != nil {
		t.Fatalf("gen: %v", err)
	}
	ctx := context.Background()
	cat := NewMemCatalog()

	// Spec A: legitimate first writer.
	specA := protocol.CheckSpec{Type: protocol.CheckHTTP, Target: "https://good.example", IntervalSeconds: 60}
	specA.ID = specA.DeriveID()
	scA := mustSign(t, id, specA)
	if err := cat.UpsertCheck(ctx, scA); err != nil {
		t.Fatalf("upsert A: %v", err)
	}

	// Spec B: DIFFERENT target, but forced onto A's ID to simulate a collision.
	specB := protocol.CheckSpec{Type: protocol.CheckHTTP, Target: "https://evil.example", IntervalSeconds: 60}
	specB.ID = specA.ID // the collision: same 16-hex ID, different content
	scB := mustSign(t, id, specB)

	if err := cat.UpsertCheck(ctx, scB); !errors.Is(err, ErrCatalogConflict) {
		t.Fatalf("expected ErrCatalogConflict upserting twin, got %v", err)
	}

	// The stored entry must still be A, unmodified.
	got, ok, err := cat.GetCheck(ctx, specA.ID)
	if err != nil || !ok {
		t.Fatalf("get: ok=%v err=%v", ok, err)
	}
	if got.Entry.Spec.Target != "https://good.example" {
		t.Fatalf("stored entry was overwritten: target=%q", got.Entry.Spec.Target)
	}

	// Idempotent re-upsert of the identical spec A must still succeed.
	if err := cat.UpsertCheck(ctx, scA); err != nil {
		t.Fatalf("re-upsert identical A: %v", err)
	}

	// A newer signature over the SAME spec (different signer) must be accepted.
	id2, err := identity.Generate()
	if err != nil {
		t.Fatalf("gen2: %v", err)
	}
	scA2 := mustSign(t, id2, specA)
	if err := cat.UpsertCheck(ctx, scA2); err != nil {
		t.Fatalf("re-sign identical A by another hub: %v", err)
	}
	got, _, _ = cat.GetCheck(ctx, specA.ID)
	if got.Entry.HubID != id2.NodeID() {
		t.Fatalf("re-signed identical spec did not refresh signer")
	}
}

func TestSameCheckContent(t *testing.T) {
	base := protocol.CheckSpec{Type: protocol.CheckHTTP, Target: "https://x", Params: map[string]string{"k": "v"}}
	// Same content, differing ID/interval must still be equal.
	other := protocol.CheckSpec{Type: protocol.CheckHTTP, Target: "https://x", IntervalSeconds: 999, ID: "deadbeef", Params: map[string]string{"k": "v"}}
	if !sameCheckContent(base, other) {
		t.Fatal("expected equal content")
	}
	// nil vs empty params derive identically -> equal.
	if !sameCheckContent(
		protocol.CheckSpec{Type: protocol.CheckTCP, Target: "h:1"},
		protocol.CheckSpec{Type: protocol.CheckTCP, Target: "h:1", Params: map[string]string{}},
	) {
		t.Fatal("nil vs empty params should be equal")
	}
	// Different target.
	if sameCheckContent(base, protocol.CheckSpec{Type: protocol.CheckHTTP, Target: "https://y", Params: map[string]string{"k": "v"}}) {
		t.Fatal("different target should differ")
	}
	// Different param value.
	if sameCheckContent(base, protocol.CheckSpec{Type: protocol.CheckHTTP, Target: "https://x", Params: map[string]string{"k": "w"}}) {
		t.Fatal("different param value should differ")
	}
}
