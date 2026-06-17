package protocol

import (
	"crypto/ed25519"
	"encoding/json"

	"github.com/mwgg/libreping/pkg/identity"
)

// ProbeRegistration is a probe's signed self-announcement to a hub: the
// location, capacity, and check types it offers for assignment.
//
// It is JSON-signed exactly like ResultContent (additive wire format: keep
// field order stable). Signing matters because the hub uses a probe's declared
// capacity as an assignment input — an unauthenticated registration lets anyone
// flood the hub with high-capacity ghost probes that are assigned real checks
// they never run, or overwrite a known probe's registration. Verify proves the
// registration came from the holder of the probe key and that ProbeID derives
// from it.
type ProbeRegistration struct {
	ProbeID            string      `json:"probe_id"`
	Location           Location    `json:"location"`
	MaxChecksPerMinute int         `json:"max_checks_per_minute"`
	SupportedTypes     []CheckType `json:"supported_types"`
	TimestampMS        int64       `json:"timestamp_ms"`
}

// CanonicalBytes returns the deterministic signing payload.
func (p ProbeRegistration) CanonicalBytes() ([]byte, error) { return json.Marshal(p) }

// SignedProbeRegistration is a ProbeRegistration plus the probe's key/signature.
type SignedProbeRegistration struct {
	Registration ProbeRegistration `json:"registration"`
	PubKey       ed25519.PublicKey `json:"pubkey"`
	Signature    []byte            `json:"signature"`
}

// SignProbeRegistration stamps the probe ID onto the registration and signs it.
func SignProbeRegistration(id *identity.Identity, reg ProbeRegistration) (SignedProbeRegistration, error) {
	reg.ProbeID = id.NodeID()
	payload, err := reg.CanonicalBytes()
	if err != nil {
		return SignedProbeRegistration{}, err
	}
	return SignedProbeRegistration{Registration: reg, PubKey: id.Public(), Signature: id.Sign(payload)}, nil
}

// Verify checks the signature and that ProbeID derives from the embedded key.
func (sp SignedProbeRegistration) Verify() error {
	if len(sp.PubKey) != ed25519.PublicKeySize {
		return ErrBadKey
	}
	payload, err := sp.Registration.CanonicalBytes()
	if err != nil {
		return err
	}
	if !identity.Verify(sp.PubKey, payload, sp.Signature) {
		return ErrBadSignature
	}
	if sp.Registration.ProbeID != identity.NodeIDFromPub(sp.PubKey) {
		return ErrIDMismatch
	}
	return nil
}
