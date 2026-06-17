// Package encbox seals alert destinations so only the chosen recipient hubs can
// read them. It uses libsodium-compatible anonymous sealed boxes
// (golang.org/x/crypto/nacl/box, which matches tweetnacl-sealedbox-js used in
// the browser), over X25519 keys derived from each hub's Ed25519 identity seed.
package encbox

import (
	"crypto/rand"
	"crypto/sha256"
	"errors"

	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/nacl/box"
)

// x25519Domain separates the encryption key from the signing key derivation.
const x25519Domain = "libreping-x25519-v1"

// KeyPair is a hub's X25519 keypair for sealing/opening alert destinations.
type KeyPair struct {
	pub  [32]byte
	priv [32]byte
}

// FromSeed deterministically derives an X25519 keypair from an Ed25519 seed, so
// a hub's encryption key is bound to its identity with no extra storage.
func FromSeed(seed []byte) KeyPair {
	priv := sha256.Sum256(append([]byte(x25519Domain), seed...))
	var kp KeyPair
	kp.priv = priv
	// curve25519.X25519 clamps the scalar per RFC 7748; box.OpenAnonymous
	// derives the same way, so pub and priv stay consistent.
	pub, _ := curve25519.X25519(kp.priv[:], curve25519.Basepoint)
	copy(kp.pub[:], pub)
	return kp
}

// PublicKey returns the X25519 public key to advertise.
func (k KeyPair) PublicKey() []byte {
	out := make([]byte, 32)
	copy(out, k.pub[:])
	return out
}

// Seal anonymously seals msg to recipientPub (crypto_box_seal compatible).
func Seal(msg, recipientPub []byte) ([]byte, error) {
	if len(recipientPub) != 32 {
		return nil, errors.New("encbox: recipient key must be 32 bytes")
	}
	var pk [32]byte
	copy(pk[:], recipientPub)
	return box.SealAnonymous(nil, msg, &pk, rand.Reader)
}

// Open decrypts a sealed box addressed to this keypair.
func (k KeyPair) Open(sealed []byte) ([]byte, bool) {
	return box.OpenAnonymous(nil, sealed, &k.pub, &k.priv)
}
