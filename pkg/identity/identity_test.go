package identity

import (
	"path/filepath"
	"testing"
)

func TestSignVerify(t *testing.T) {
	id, err := Generate()
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	msg := []byte("a libreping result payload")
	sig := id.Sign(msg)

	if !Verify(id.Public(), msg, sig) {
		t.Fatal("valid signature failed to verify")
	}
	// Tampered message must not verify.
	if Verify(id.Public(), []byte("a libreping result payloaX"), sig) {
		t.Fatal("tampered message verified")
	}
	// Wrong key must not verify.
	other, _ := Generate()
	if Verify(other.Public(), msg, sig) {
		t.Fatal("signature verified under wrong key")
	}
}

func TestNodeIDIsSelfCertifying(t *testing.T) {
	id, _ := Generate()
	if id.NodeID() != NodeIDFromPub(id.Public()) {
		t.Fatal("NodeID does not match derivation from public key")
	}
	other, _ := Generate()
	if id.NodeID() == other.NodeID() {
		t.Fatal("distinct identities produced identical node IDs")
	}
}

func TestLoadOrCreatePersists(t *testing.T) {
	path := filepath.Join(t.TempDir(), "keys", "node.key")

	first, err := LoadOrCreate(path)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	second, err := LoadOrCreate(path)
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	if first.NodeID() != second.NodeID() {
		t.Fatal("identity changed across reload; key not persisted")
	}
}
