package encbox

import (
	"encoding/base64"
	"encoding/hex"
	"testing"
)

func TestSealOpenRoundTrip(t *testing.T) {
	kp := FromSeed([]byte("seed-one"))
	msg := []byte("you@example.com")
	sealed, err := Seal(msg, kp.PublicKey())
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	got, ok := kp.Open(sealed)
	if !ok || string(got) != string(msg) {
		t.Fatalf("round-trip failed: ok=%v got=%q", ok, got)
	}

	// A different hub cannot open it.
	other := FromSeed([]byte("seed-two"))
	if _, ok := other.Open(sealed); ok {
		t.Fatal("a non-recipient hub opened the sealed box")
	}
}

// fixedSeed reproduces a hub keypair the JS cross-check seals to.
var fixedSeed = mustHex("0101010101010101010101010101010101010101010101010101010101010101")

// TestPublicKeyVector pins the X25519 public key derived from fixedSeed, so the
// JS sealing side and this Go side agree on the recipient key.
func TestPublicKeyVector(t *testing.T) {
	kp := FromSeed(fixedSeed)
	const wantPub = "wGbvmGQIyQA52uf0ZjL9MAYPYUKIofb9AO6d3uHstTE="
	got := base64.StdEncoding.EncodeToString(kp.PublicKey())
	if got != wantPub {
		t.Fatalf("enc pubkey drifted: got %s want %s", got, wantPub)
	}
}

// TestOpenJSVector opens a sealed box produced by the browser code
// (tweetnacl-sealedbox-js) to confirm cross-language compatibility.
func TestOpenJSVector(t *testing.T) {
	// Produced by tweetnacl-sealedbox-js sealing "you@example.com" to the
	// fixedSeed hub's X25519 public key (see web seal vector). Sealing is
	// randomized, so this is one captured instance; opening is deterministic.
	const jsSealedB64 = "SSUuilYzgyymPaEsQRvGmpI9kmIqsUAGLNzPn2nfyXh73MrmFLQuGgI30grkLUlriMGBDK5LbPXUmpRqsdGy"
	kp := FromSeed(fixedSeed)
	sealed, err := base64.StdEncoding.DecodeString(jsSealedB64)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	got, ok := kp.Open(sealed)
	if !ok {
		t.Fatal("failed to open JS-sealed box")
	}
	if string(got) != "you@example.com" {
		t.Fatalf("unexpected plaintext: %q", got)
	}
}

func mustHex(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}
