package admit

import (
	"context"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/mwgg/libreping/pkg/identity"
	"github.com/mwgg/libreping/pkg/protocol"
)

// stubCatalog is a minimal CatalogLookup for tests.
type stubCatalog map[string]protocol.SignedCatalogEntry

func (s stubCatalog) GetCheck(_ context.Context, id string) (protocol.SignedCatalogEntry, bool, error) {
	e, ok := s[id]
	return e, ok, nil
}

func sign(t *testing.T, c protocol.ResultContent) protocol.SignedResult {
	t.Helper()
	probe, _ := identity.Generate()
	sr, err := protocol.SignResult(probe, c)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	return sr
}

func TestResultAdmission(t *testing.T) {
	now := time.UnixMilli(1_700_000_000_000)
	base := protocol.ResultContent{
		CheckID: "c1", CheckType: protocol.CheckHTTP, Target: "https://example.com",
		Status: protocol.StatusUp, TimestampMS: now.UnixMilli(),
	}

	// Unknown check, sane fields → admitted.
	if err := Result(context.Background(), stubCatalog{}, sign(t, base), now); err != nil {
		t.Fatalf("valid result rejected: %v", err)
	}

	// Future timestamp beyond skew → rejected.
	future := base
	future.TimestampMS = now.Add(10 * time.Minute).UnixMilli()
	if err := Result(context.Background(), stubCatalog{}, sign(t, future), now); err != ErrTimestamp {
		t.Fatalf("expected ErrTimestamp, got %v", err)
	}

	// Ancient timestamp → rejected.
	old := base
	old.TimestampMS = now.Add(-48 * time.Hour).UnixMilli()
	if err := Result(context.Background(), stubCatalog{}, sign(t, old), now); err != ErrTimestamp {
		t.Fatalf("expected ErrTimestamp for old result, got %v", err)
	}

	// Bad status → rejected.
	bad := base
	bad.Status = "weird"
	if err := Result(context.Background(), stubCatalog{}, sign(t, bad), now); err != ErrBadStatus {
		t.Fatalf("expected ErrBadStatus, got %v", err)
	}

	// Oversized target → rejected.
	big := base
	big.Target = strings.Repeat("a", maxTargetLen+1)
	if err := Result(context.Background(), stubCatalog{}, sign(t, big), now); err == nil {
		t.Fatal("expected oversized target rejection")
	}
}

func TestResultOversizedIdentifiers(t *testing.T) {
	now := time.UnixMilli(1_700_000_000_000)
	base := protocol.ResultContent{
		CheckID: "c1", CheckType: protocol.CheckHTTP, Target: "https://example.com",
		Status: protocol.StatusUp, TimestampMS: now.UnixMilli(),
	}

	// Over-long CheckID → rejected (attacker-chosen free-form field).
	longCheck := base
	longCheck.CheckID = strings.Repeat("a", maxIDLen+1)
	if err := Result(context.Background(), stubCatalog{}, sign(t, longCheck), now); err == nil {
		t.Fatal("expected oversized CheckID rejection")
	}

	// A normal 16-char check ID is fine.
	base.CheckID = "abcd1234abcd1234"
	if err := Result(context.Background(), stubCatalog{}, sign(t, base), now); err != nil {
		t.Fatalf("normal CheckID rejected: %v", err)
	}
}

func TestSpecBounds(t *testing.T) {
	// A normal spec passes.
	ok := protocol.CheckSpec{Type: protocol.CheckHTTP, Target: "https://example.com", Params: map[string]string{"method": "GET"}}
	if err := Spec(ok); err != nil {
		t.Fatalf("normal spec rejected: %v", err)
	}

	// Oversized target rejected.
	bigTarget := protocol.CheckSpec{Type: protocol.CheckHTTP, Target: strings.Repeat("a", maxTargetLen+1)}
	if err := Spec(bigTarget); err == nil {
		t.Fatal("expected oversized target rejection")
	}

	// Too many params rejected.
	manyParams := protocol.CheckSpec{Type: protocol.CheckHTTP, Target: "https://x", Params: map[string]string{}}
	for i := 0; i < maxParamEntries+1; i++ {
		manyParams.Params[strconv.Itoa(i)] = "v"
	}
	if err := Spec(manyParams); err == nil {
		t.Fatal("expected too-many-params rejection")
	}

	// Oversized param value rejected.
	bigParam := protocol.CheckSpec{Type: protocol.CheckHTTP, Target: "https://x", Params: map[string]string{"k": strings.Repeat("b", maxParamValLen+1)}}
	if err := Spec(bigParam); err == nil {
		t.Fatal("expected oversized param value rejection")
	}
}

func TestResultCatalogMismatch(t *testing.T) {
	now := time.UnixMilli(1_700_000_000_000)
	hub, _ := identity.Generate()
	spec := protocol.CheckSpec{Type: protocol.CheckHTTP, Target: "https://real.example.com"}
	spec.ID = spec.DeriveID()
	entry, _ := protocol.SignCatalogEntry(hub, protocol.CatalogEntry{Spec: spec})
	cat := stubCatalog{spec.ID: entry}

	// A result claiming the known check ID but a different target is rejected.
	r := protocol.ResultContent{
		CheckID: spec.ID, CheckType: protocol.CheckHTTP, Target: "https://evil.example.com",
		Status: protocol.StatusDown, TimestampMS: now.UnixMilli(),
	}
	if err := Result(context.Background(), cat, sign(t, r), now); err != ErrCatalogMismatch {
		t.Fatalf("expected ErrCatalogMismatch, got %v", err)
	}

	// The matching target is admitted.
	r.Target = "https://real.example.com"
	if err := Result(context.Background(), cat, sign(t, r), now); err != nil {
		t.Fatalf("matching result rejected: %v", err)
	}
}
