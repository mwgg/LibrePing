// Package protocol is the single source of truth for the data contract shared
// between probes, hubs, and the peer-to-peer gossip mesh.
//
// IMPORTANT: ResultContent is signed by serializing it to JSON. Go's
// encoding/json emits struct fields in declaration order, so the byte output is
// deterministic — but that also means changing field order, names, tags, or
// types silently invalidates every existing signature. Treat ResultContent's
// layout as a wire format: additive changes only, and bump a version if you
// must break it.
package protocol

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"sort"
	"strconv"
	"strings"

	"github.com/mwgg/libreping/pkg/identity"
)

// CheckType identifies a kind of monitoring check. Adding a value here is step
// one of adding a check: the probe must also register a Checker for it.
type CheckType string

const (
	CheckHTTP       CheckType = "http"       // HTTP(S) status, latency, keyword match — no privilege
	CheckTCP        CheckType = "tcp"        // TCP connect reachability + latency — no privilege
	CheckDNS        CheckType = "dns"        // DNS resolution + expected answer — no privilege
	CheckTLS        CheckType = "tls"        // TLS certificate expiry/chain — no privilege
	CheckICMP       CheckType = "icmp"       // ICMP ping — REQUIRES raw sockets (NET_RAW / ping_group_range)
	CheckTraceroute CheckType = "traceroute" // path + per-hop latency — REQUIRES raw sockets (NET_RAW)
)

// Status is the outcome of a check.
type Status string

const (
	StatusUp       Status = "up"
	StatusDown     Status = "down"
	StatusDegraded Status = "degraded"
)

// Location is a self-declared geographic position for a probe or hub. It is
// auto-detected from the node's public IP by default (pkg/geoip) and can be
// overridden by the operator (PROBE_LOCATION / HUB_LOCATION).
//
// Honest limitation: there is no cryptographic proof-of-location. IP
// geolocation is a convenience, not proof — a node still self-reports where it
// is, and an operator can override or spoof it. The mesh corroborates
// plausibility through cross-probe agreement, not proof.
type Location struct {
	Country string  `json:"country"`
	City    string  `json:"city"`
	Lat     float64 `json:"lat"`
	Lon     float64 `json:"lon"`
}

// CheckSpec is a monitor definition: what to check and how often.
type CheckSpec struct {
	ID              string            `json:"id"`
	Type            CheckType         `json:"type"`
	Target          string            `json:"target"`
	IntervalSeconds int               `json:"interval_seconds"`
	Params          map[string]string `json:"params,omitempty"`
}

// DeriveID returns a deterministic, content-derived ID for the check
// (independent of who created it). Two hubs that create the same monitor
// produce the same ID, so the global catalog deduplicates by identity rather
// than by origin. The ID excludes IntervalSeconds: the same target+type is one
// logical monitor regardless of how often a given hub schedules it.
//
// The fields are length-prefixed (each as "<len>:<bytes>") rather than joined
// by separator characters, so a target or param value containing the separator
// cannot be crafted to collide with a different spec — content addressing must
// be injective to be a security boundary (it gates which target a shared check
// points at). Params are sorted by key for determinism.
func (s CheckSpec) DeriveID() string {
	keys := make([]string, 0, len(s.Params))
	for k := range s.Params {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var b strings.Builder
	writeField := func(v string) {
		b.WriteString(strconv.Itoa(len(v)))
		b.WriteByte(':')
		b.WriteString(v)
	}
	writeField(string(s.Type))
	writeField(s.Target)
	for _, k := range keys {
		writeField(k)
		writeField(s.Params[k])
	}
	sum := sha256.Sum256([]byte(b.String()))
	return hex.EncodeToString(sum[:8])
}

// ResultContent is the signed core of a measurement. See the package doc: its
// JSON serialization is the exact byte string that gets signed.
type ResultContent struct {
	CheckID     string            `json:"check_id"`
	CheckType   CheckType         `json:"check_type"`
	Target      string            `json:"target"`
	ProbeID     string            `json:"probe_id"`
	Location    Location          `json:"location"`
	TimestampMS int64             `json:"timestamp_ms"`
	Status      Status            `json:"status"`
	RTTMillis   float64           `json:"rtt_ms"`
	Detail      map[string]string `json:"detail,omitempty"`
}

// CanonicalBytes returns the deterministic signing payload for the content.
func (c ResultContent) CanonicalBytes() ([]byte, error) { return json.Marshal(c) }

// SignedResult is a ResultContent plus the producing probe's public key and
// signature. It is self-verifying: the pubkey is carried inline, so any node
// can validate it without a key directory.
type SignedResult struct {
	Content   ResultContent     `json:"content"`
	PubKey    ed25519.PublicKey `json:"pubkey"`
	Signature []byte            `json:"signature"`
}

var (
	ErrBadKey         = errors.New("protocol: invalid public key")
	ErrBadSignature   = errors.New("protocol: signature does not verify")
	ErrIDMismatch     = errors.New("protocol: probe_id does not match public key")
	ErrSpecIDMismatch = errors.New("protocol: check spec ID is not its content-derived ID")
)

// SignResult stamps the producing probe's ID onto content and signs it.
func SignResult(id *identity.Identity, content ResultContent) (SignedResult, error) {
	content.ProbeID = id.NodeID()
	payload, err := content.CanonicalBytes()
	if err != nil {
		return SignedResult{}, err
	}
	return SignedResult{
		Content:   content,
		PubKey:    id.Public(),
		Signature: id.Sign(payload),
	}, nil
}

// Verify checks that the result is well-formed, that the signature is valid for
// the embedded public key, and that the claimed ProbeID is genuinely derived
// from that key. A hub MUST call this before storing or re-gossiping a result.
func (sr SignedResult) Verify() error {
	if len(sr.PubKey) != ed25519.PublicKeySize {
		return ErrBadKey
	}
	payload, err := sr.Content.CanonicalBytes()
	if err != nil {
		return err
	}
	if !identity.Verify(sr.PubKey, payload, sr.Signature) {
		return ErrBadSignature
	}
	if sr.Content.ProbeID != identity.NodeIDFromPub(sr.PubKey) {
		return ErrIDMismatch
	}
	return nil
}

// GossipKind tags a gossip envelope payload.
type GossipKind string

const (
	GossipResult       GossipKind = "result"
	GossipCatalog      GossipKind = "catalog"
	GossipHub          GossipKind = "hub"
	GossipSubscription GossipKind = "subscription"
	GossipAlert        GossipKind = "alert"
	GossipDelivery     GossipKind = "delivery"
)

// CatalogEntry announces a check that exists on the network. It is signed by
// the hub that first published it, but identifies the check by its content
// (Spec.ID == Spec.DeriveID()), so the network converges on one entry per
// logical monitor regardless of how many hubs announce it.
type CatalogEntry struct {
	Spec  CheckSpec `json:"spec"`
	HubID string    `json:"hub_id"`
}

// CanonicalBytes returns the deterministic signing payload for the entry.
func (c CatalogEntry) CanonicalBytes() ([]byte, error) { return json.Marshal(c) }

// SignedCatalogEntry is a CatalogEntry plus the announcing hub's key/signature,
// verifiable by any node exactly like a SignedResult.
type SignedCatalogEntry struct {
	Entry     CatalogEntry      `json:"entry"`
	PubKey    ed25519.PublicKey `json:"pubkey"`
	Signature []byte            `json:"signature"`
}

// SignCatalogEntry stamps the announcing hub's ID onto the entry and signs it.
func SignCatalogEntry(id *identity.Identity, entry CatalogEntry) (SignedCatalogEntry, error) {
	entry.HubID = id.NodeID()
	payload, err := entry.CanonicalBytes()
	if err != nil {
		return SignedCatalogEntry{}, err
	}
	return SignedCatalogEntry{Entry: entry, PubKey: id.Public(), Signature: id.Sign(payload)}, nil
}

// Verify checks the signature, that HubID derives from the embedded key, and
// that the check's ID is genuinely its content-derived ID. The last check is
// what makes the catalog content-addressed rather than name-addressed: without
// it, a signed entry could reuse a popular check's ID while pointing Target at
// an attacker-controlled host, silently redirecting everyone subscribed to that
// shared check. A valid signature proves authorship, not that ID matches body.
func (sc SignedCatalogEntry) Verify() error {
	if len(sc.PubKey) != ed25519.PublicKeySize {
		return ErrBadKey
	}
	payload, err := sc.Entry.CanonicalBytes()
	if err != nil {
		return err
	}
	if !identity.Verify(sc.PubKey, payload, sc.Signature) {
		return ErrBadSignature
	}
	if sc.Entry.HubID != identity.NodeIDFromPub(sc.PubKey) {
		return ErrIDMismatch
	}
	if sc.Entry.Spec.ID != sc.Entry.Spec.DeriveID() {
		return ErrSpecIDMismatch
	}
	return nil
}

// HubAnnouncement advertises a publicly-reachable hub so other hubs can list it
// in their directory and humans can browse the network.
type HubAnnouncement struct {
	HubID       string   `json:"hub_id"`
	PublicURL   string   `json:"public_url"`
	Name        string   `json:"name,omitempty"`
	Location    Location `json:"location"`
	TimestampMS int64    `json:"timestamp_ms"`
	// EncPubKey is the hub's X25519 public key (base64 in JSON) used to seal
	// alert destinations to it. Empty on hubs that predate encryption.
	EncPubKey []byte `json:"enc_pubkey,omitempty"`
	// StorageCapacity is this hub's relative weight for result-shard placement
	// (capacity-weighted rendezvous). 0/absent = pure consumer (stores no shards
	// for others). Additive + omitempty so older announcements still verify.
	StorageCapacity int `json:"storage_capacity,omitempty"`
	// StorageArchive marks a hub that holds every shard (a full mirror).
	StorageArchive bool `json:"storage_archive,omitempty"`
	// P2PAddrs are this hub's publicly-dialable libp2p multiaddrs, each including
	// its /p2p/<peerID> suffix, so a new hub that fetches the directory can dial
	// straight into the mesh without a hand-configured bootstrap peer. Empty when
	// the hub has no public address to advertise. Additive + omitempty so older
	// announcements still verify.
	P2PAddrs []string `json:"p2p_addrs,omitempty"`
}

// CanonicalBytes returns the deterministic signing payload for the announcement.
func (a HubAnnouncement) CanonicalBytes() ([]byte, error) { return json.Marshal(a) }

// SignedHubAnnouncement is a HubAnnouncement plus the hub's key/signature.
type SignedHubAnnouncement struct {
	Announcement HubAnnouncement   `json:"announcement"`
	PubKey       ed25519.PublicKey `json:"pubkey"`
	Signature    []byte            `json:"signature"`
}

// SignHubAnnouncement stamps the hub's ID onto the announcement and signs it.
func SignHubAnnouncement(id *identity.Identity, a HubAnnouncement) (SignedHubAnnouncement, error) {
	a.HubID = id.NodeID()
	payload, err := a.CanonicalBytes()
	if err != nil {
		return SignedHubAnnouncement{}, err
	}
	return SignedHubAnnouncement{Announcement: a, PubKey: id.Public(), Signature: id.Sign(payload)}, nil
}

// Verify checks the signature and that HubID derives from the embedded key.
// Note: this proves the announcement came from the holder of the hub identity.
// Confirming the advertised URL actually serves that hub is a separate,
// reachability check the directory performs before listing it.
func (sa SignedHubAnnouncement) Verify() error {
	if len(sa.PubKey) != ed25519.PublicKeySize {
		return ErrBadKey
	}
	payload, err := sa.Announcement.CanonicalBytes()
	if err != nil {
		return err
	}
	if !identity.Verify(sa.PubKey, payload, sa.Signature) {
		return ErrBadSignature
	}
	if sa.Announcement.HubID != identity.NodeIDFromPub(sa.PubKey) {
		return ErrIDMismatch
	}
	return nil
}

// DeliveryState records that a hub delivered a given status for an alert rule.
// Hubs gossip it (last-writer-wins by timestamp) so that whichever hub becomes
// responsible knows what has already been notified and won't re-send unless the
// status actually changed — making failover de-duplicated rather than noisy.
type DeliveryState struct {
	RuleID      string `json:"rule_id"`
	Status      Status `json:"status"`
	HubID       string `json:"hub_id"`
	TimestampMS int64  `json:"timestamp_ms"`
}

// CanonicalBytes returns the deterministic signing payload.
func (d DeliveryState) CanonicalBytes() ([]byte, error) { return json.Marshal(d) }

// SignedDeliveryState is a DeliveryState signed by the delivering hub.
type SignedDeliveryState struct {
	State     DeliveryState     `json:"state"`
	PubKey    ed25519.PublicKey `json:"pubkey"`
	Signature []byte            `json:"signature"`
}

// SignDeliveryState stamps the hub ID and signs.
func SignDeliveryState(id *identity.Identity, d DeliveryState) SignedDeliveryState {
	d.HubID = id.NodeID()
	payload, _ := d.CanonicalBytes()
	return SignedDeliveryState{State: d, PubKey: id.Public(), Signature: id.Sign(payload)}
}

// Verify checks the signature and that HubID derives from the embedded key.
func (sd SignedDeliveryState) Verify() error {
	if len(sd.PubKey) != ed25519.PublicKeySize {
		return ErrBadKey
	}
	payload, err := sd.State.CanonicalBytes()
	if err != nil {
		return err
	}
	if !identity.Verify(sd.PubKey, payload, sd.Signature) {
		return ErrBadSignature
	}
	if sd.State.HubID != identity.NodeIDFromPub(sd.PubKey) {
		return ErrIDMismatch
	}
	return nil
}

// GossipEnvelope is the message format published on the mesh. Exactly one of
// the payload pointers is set, matching Kind.
type GossipEnvelope struct {
	Kind         GossipKind             `json:"kind"`
	Result       *SignedResult          `json:"result,omitempty"`
	Catalog      *SignedCatalogEntry    `json:"catalog,omitempty"`
	Hub          *SignedHubAnnouncement `json:"hub,omitempty"`
	Subscription *SignedSubscription    `json:"subscription,omitempty"`
	Alert        *SignedAlertRule       `json:"alert,omitempty"`
	Delivery     *SignedDeliveryState   `json:"delivery,omitempty"`
}
