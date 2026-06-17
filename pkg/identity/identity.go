// Package identity provides self-certifying cryptographic identities for
// LibrePing nodes (probes and hubs).
//
// Every node owns an Ed25519 keypair. A node's ID is derived deterministically
// from its public key, so anyone can verify that a signature came from the node
// claiming a given ID without consulting a central authority or certificate
// chain. This is the root of LibrePing's trust model: results are signed by the
// probe that produced them, and any hub can verify any result end-to-end using
// only the public key carried alongside it.
package identity

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// nodeIDBytes is how many bytes of the public-key hash form the textual node ID.
// 16 bytes (128 bits) is collision-resistant for any realistic mesh size while
// staying short enough to display.
const nodeIDBytes = 16

var (
	// ErrInvalidKey is returned when key material has the wrong size.
	ErrInvalidKey = errors.New("identity: invalid key material")
)

// Identity is a node's Ed25519 keypair plus its derived ID.
type Identity struct {
	priv ed25519.PrivateKey
	pub  ed25519.PublicKey
}

// Generate creates a brand-new random identity.
func Generate() (*Identity, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	return &Identity{priv: priv, pub: pub}, nil
}

// FromSeed reconstructs an identity from a 32-byte Ed25519 seed.
func FromSeed(seed []byte) (*Identity, error) {
	if len(seed) != ed25519.SeedSize {
		return nil, ErrInvalidKey
	}
	priv := ed25519.NewKeyFromSeed(seed)
	return &Identity{priv: priv, pub: priv.Public().(ed25519.PublicKey)}, nil
}

// Public returns the node's Ed25519 public key.
func (i *Identity) Public() ed25519.PublicKey { return i.pub }

// PrivateKey returns the raw 64-byte Ed25519 private key. Used to derive a
// matching libp2p host identity on hubs — keep it secret.
func (i *Identity) PrivateKey() ed25519.PrivateKey { return i.priv }

// Seed returns the 32-byte seed, suitable for persistence.
func (i *Identity) Seed() []byte { return i.priv.Seed() }

// NodeID returns this identity's self-certifying textual ID.
func (i *Identity) NodeID() string { return NodeIDFromPub(i.pub) }

// Sign signs msg with the node's private key.
func (i *Identity) Sign(msg []byte) []byte { return ed25519.Sign(i.priv, msg) }

// NodeIDFromPub derives the textual node ID from any public key. This is what
// makes IDs self-certifying: the ID is a hash of the key, so a forged ID cannot
// match a key the forger does not control.
func NodeIDFromPub(pub ed25519.PublicKey) string {
	sum := sha256.Sum256(pub)
	return hex.EncodeToString(sum[:nodeIDBytes])
}

// Verify reports whether sig is a valid signature of msg by pub.
func Verify(pub ed25519.PublicKey, msg, sig []byte) bool {
	if len(pub) != ed25519.PublicKeySize {
		return false
	}
	return ed25519.Verify(pub, msg, sig)
}

// LoadOrCreate loads an identity from path, creating and persisting a new one
// if the file does not exist. The key file holds the base64-encoded seed and is
// written with 0600 permissions.
func LoadOrCreate(path string) (*Identity, error) {
	data, err := os.ReadFile(path)
	switch {
	case err == nil:
		seed, derr := base64.StdEncoding.DecodeString(string(data))
		if derr != nil {
			return nil, fmt.Errorf("identity: decode key file %s: %w", path, derr)
		}
		return FromSeed(seed)
	case errors.Is(err, os.ErrNotExist):
		id, gerr := Generate()
		if gerr != nil {
			return nil, gerr
		}
		if serr := id.Save(path); serr != nil {
			return nil, serr
		}
		return id, nil
	default:
		return nil, err
	}
}

// Save writes the identity's seed to path with 0600 permissions.
func (i *Identity) Save(path string) error {
	if dir := filepath.Dir(path); dir != "" {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return err
		}
	}
	enc := base64.StdEncoding.EncodeToString(i.Seed())
	return os.WriteFile(path, []byte(enc), 0o600)
}
