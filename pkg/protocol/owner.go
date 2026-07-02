package protocol

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"sort"
	"strconv"
	"strings"

	"github.com/mwgg/libreping/pkg/identity"
)

// Owner-signed types (Subscription, AlertRule) are created in the browser and
// verified on hubs, so they MUST sign over a byte string both languages can
// reproduce exactly. JSON is too fragile across languages (key order, escaping,
// number formatting), so these use an explicit canonical string:
//
//	"libreping-<type>-v1" + "\n" + field + "\n" + field + ...
//
// fields are plain strings; ints via base-10; bools as "1"/"0". The JS client
// in web/src/identity.ts mirrors this exactly, and a Go test pins a
// JS-generated signature so the two encoders cannot drift.

func boolField(b bool) string {
	if b {
		return "1"
	}
	return "0"
}

// verifyOwner is the shared check for owner-signed payloads: valid signature for
// the embedded key, and the claimed owner ID derived from that key.
func verifyOwner(pub ed25519.PublicKey, owner string, payload, sig []byte) error {
	if len(pub) != ed25519.PublicKeySize {
		return ErrBadKey
	}
	if !identity.Verify(pub, payload, sig) {
		return ErrBadSignature
	}
	if owner != identity.NodeIDFromPub(pub) {
		return ErrIDMismatch
	}
	return nil
}

// Subscription links an owner (a browser-held key) to a shared, content-
// addressed check. "My services" is the set of a given owner's subscriptions;
// many owners can subscribe to the same check, which is still monitored once.
type Subscription struct {
	Owner           string `json:"owner"`
	CheckID         string `json:"check_id"`
	IntervalSeconds int    `json:"interval_seconds"`
	ExpiryMS        int64  `json:"expiry_ms"`
	// UpdatedMS is a signed, monotonic version stamp (the creator's clock at
	// signing). A hub accepts an incoming record only if its UpdatedMS is newer
	// than the one it already holds, so a peer cannot replay an old signed
	// subscription to undo a later delete or edit. The signature covers it.
	UpdatedMS int64 `json:"updated_ms"`
	Deleted   bool  `json:"deleted,omitempty"` // signed tombstone
}

func (s Subscription) canonical() []byte {
	return []byte(strings.Join([]string{
		"libreping-subscription-v2",
		s.Owner,
		s.CheckID,
		strconv.Itoa(s.IntervalSeconds),
		strconv.FormatInt(s.ExpiryMS, 10),
		strconv.FormatInt(s.UpdatedMS, 10),
		boolField(s.Deleted),
	}, "\n"))
}

// SignedSubscription is a Subscription plus the owner's key and signature.
type SignedSubscription struct {
	Subscription Subscription      `json:"subscription"`
	PubKey       ed25519.PublicKey `json:"pubkey"`
	Signature    []byte            `json:"signature"`
}

// SignSubscription stamps the owner ID and signs (used by Go callers/tests; the
// browser signs with the identical canonical form).
func SignSubscription(id *identity.Identity, s Subscription) SignedSubscription {
	s.Owner = id.NodeID()
	return SignedSubscription{Subscription: s, PubKey: id.Public(), Signature: id.Sign(s.canonical())}
}

func (ss SignedSubscription) Verify() error {
	return verifyOwner(ss.PubKey, ss.Subscription.Owner, ss.Subscription.canonical(), ss.Signature)
}

// MaintenanceWindow is an owner-signed, planned-downtime window for a check.
// While a window is active, alerts for the check are suppressed and the window
// is excluded from the check's uptime percentage. Because any hub may be the one
// responsible for a rule and every hub computes uptime, a window must be known
// network-wide — so it is gossiped and tombstoned exactly like a Subscription
// (owner-signed, versioned by UpdatedMS, expiring), NOT sealed to any hub.
//
// A window is ACTIVE at time T when !Deleted && StartMS <= T < EndMS.
//
// Unlike Subscription/AlertRule (which newline-join their canonical fields),
// MaintenanceWindow uses a LENGTH-PREFIXED canonical encoding (each field as
// "<byteLen>:<bytes>", the same hardening CheckSpec.DeriveID uses): a field
// value that contains the "\n" separator cannot be crafted to shift the field
// boundaries and forge a different-but-identically-signing window. This is the
// project's convention for new owner-signed types. Version: libreping-maintenance-v1.
type MaintenanceWindow struct {
	Owner    string `json:"owner"`
	CheckID  string `json:"check_id"`
	StartMS  int64  `json:"start_ms"`
	EndMS    int64  `json:"end_ms"`
	Reason   string `json:"reason,omitempty"`
	ExpiryMS int64  `json:"expiry_ms"`
	// UpdatedMS is a signed, monotonic version stamp; a store rejects an incoming
	// window older than the one it holds, so an old signed record cannot be
	// replayed to undo a later delete or edit. See Subscription.UpdatedMS.
	UpdatedMS int64 `json:"updated_ms"`
	Deleted   bool  `json:"deleted,omitempty"` // signed tombstone
}

// MaxMaintenanceReasonLen bounds the free-text reason so a signed window can't
// carry an unbounded blob through gossip.
const MaxMaintenanceReasonLen = 280

// ID is the storage/dedup key for a window: one per owner+check+start. Editing
// End/Reason keeps the same ID; a different start is a distinct window.
func (m MaintenanceWindow) ID() string {
	sum := sha256.Sum256([]byte(m.Owner + "|" + m.CheckID + "|" + strconv.FormatInt(m.StartMS, 10)))
	return hex.EncodeToString(sum[:8])
}

// Active reports whether the window is in effect at time t (millis).
func (m MaintenanceWindow) Active(t int64) bool {
	return !m.Deleted && m.StartMS <= t && t < m.EndMS
}

// canonical renders the length-prefixed signing payload (see the type doc). The
// domain tag is length-prefixed too, so nothing — not even the version — can be
// shifted across a field boundary. The JS client mirrors this byte-for-byte.
func (m MaintenanceWindow) canonical() []byte {
	var b strings.Builder
	writeField := func(v string) {
		b.WriteString(strconv.Itoa(len(v)))
		b.WriteByte(':')
		b.WriteString(v)
	}
	writeField("libreping-maintenance-v1")
	writeField(m.Owner)
	writeField(m.CheckID)
	writeField(strconv.FormatInt(m.StartMS, 10))
	writeField(strconv.FormatInt(m.EndMS, 10))
	writeField(m.Reason)
	writeField(strconv.FormatInt(m.ExpiryMS, 10))
	writeField(strconv.FormatInt(m.UpdatedMS, 10))
	writeField(boolField(m.Deleted))
	return []byte(b.String())
}

// SignedMaintenanceWindow is a MaintenanceWindow plus the owner's key/signature.
type SignedMaintenanceWindow struct {
	Window    MaintenanceWindow `json:"window"`
	PubKey    ed25519.PublicKey `json:"pubkey"`
	Signature []byte            `json:"signature"`
}

// SignMaintenanceWindow stamps the owner ID and signs (the browser signs with
// the identical canonical form).
func SignMaintenanceWindow(id *identity.Identity, m MaintenanceWindow) SignedMaintenanceWindow {
	m.Owner = id.NodeID()
	return SignedMaintenanceWindow{Window: m, PubKey: id.Public(), Signature: id.Sign(m.canonical())}
}

func (sm SignedMaintenanceWindow) Verify() error {
	return verifyOwner(sm.PubKey, sm.Window.Owner, sm.Window.canonical(), sm.Signature)
}

// AlertChannel is how an alert is delivered. Every channel is a plain outbound
// HTTPS request to an owner-supplied destination, so none needs any hub-operator
// configuration (unlike the old SMTP email channel, which is gone).
type AlertChannel string

const (
	AlertWebhook AlertChannel = "webhook" // POST the raw LibrePing JSON payload
	AlertNtfy    AlertChannel = "ntfy"    // POST a text message to an ntfy topic URL
	AlertDiscord AlertChannel = "discord" // POST {content} to a Discord webhook URL
	AlertSlack   AlertChannel = "slack"   // POST {text} to a Slack incoming webhook URL
)

// Known reports whether c is a supported delivery channel.
func (c AlertChannel) Known() bool {
	switch c {
	case AlertWebhook, AlertNtfy, AlertDiscord, AlertSlack:
		return true
	}
	return false
}

// AlertRule asks for a notification when a check is corroborated down.
//
// Privacy: the destination (webhook URL / email) is NOT carried in the clear.
// It is sealed (X25519 anonymous box) once per recipient hub into Recipients,
// keyed by hub ID, so only the small set of hubs the owner chose — the top-K
// rendezvous-responsible hubs — can decrypt and notify. DestHash is a stable,
// non-reversible fingerprint of the destination so the rule has a constant ID
// across re-encryptions (each refresh uses fresh ephemeral keys).
type AlertRule struct {
	Owner         string            `json:"owner"`
	CheckID       string            `json:"check_id"`
	Channel       AlertChannel      `json:"channel"`
	DestHash      string            `json:"dest_hash"`      // sha256(owner|destination)[:16]
	Recipients    map[string]string `json:"recipients"`     // hubID -> base64 sealed destination
	FailLocations int               `json:"fail_locations"` // distinct probes that must agree "down"
	ForSeconds    int               `json:"for_seconds"`    // sustained for at least this long
	ExpiryMS      int64             `json:"expiry_ms"`
	// UpdatedMS is a signed, monotonic version stamp; a hub rejects an incoming
	// rule older than the one it holds, so an old signed rule cannot be replayed
	// to resurrect a deleted alert or revert an edit. See Subscription.UpdatedMS.
	UpdatedMS int64 `json:"updated_ms"`
	Deleted   bool  `json:"deleted,omitempty"` // signed tombstone
}

// AlertDestHash is the stable fingerprint of a destination for a given owner.
func AlertDestHash(owner, destination string) string {
	sum := sha256.Sum256([]byte(owner + "|" + destination))
	return hex.EncodeToString(sum[:16])
}

// ID is the storage/dedup key for a rule: one rule per owner+check+channel+dest
// (via DestHash, which is stable across re-encryptions).
func (a AlertRule) ID() string {
	sum := sha256.Sum256([]byte(a.Owner + "|" + a.CheckID + "|" + string(a.Channel) + "|" + a.DestHash))
	return hex.EncodeToString(sum[:8])
}

// canonical builds the byte string an owner signs for an AlertRule.
//
// Every variable-length field is length-prefixed as "<byteLen>:<bytes>" and the
// fields are concatenated with no separator (the same injective encoding as
// CheckSpec.DeriveID). Newline-joining free-form fields — as the earlier v3
// encoding did — was ambiguous: because CheckID, Channel, DestHash and the
// recipient entries are all attacker-influenced (hub-supplied IDs and checkIds
// flow into what the browser signs), a value containing "\n", ":" or "," could
// shift a delimiter so two distinct rules produced identical signed bytes, and
// one signature verified both. Length-prefixing removes that: a separator inside
// a value can no longer be confused for a field boundary. The recipient count is
// written before the entries so the map's extent is unambiguous too. Hub IDs are
// sorted so the encoding is reproducible in any language.
func (a AlertRule) canonical() []byte {
	ids := make([]string, 0, len(a.Recipients))
	for id := range a.Recipients {
		ids = append(ids, id)
	}
	sort.Strings(ids)

	var b strings.Builder
	b.WriteString("libreping-alert-v4\n")
	writeField := func(v string) {
		b.WriteString(strconv.Itoa(len(v)))
		b.WriteByte(':')
		b.WriteString(v)
	}
	writeField(a.Owner)
	writeField(a.CheckID)
	writeField(string(a.Channel))
	writeField(a.DestHash)
	writeField(strconv.Itoa(len(ids)))
	for _, id := range ids {
		writeField(id)
		writeField(a.Recipients[id])
	}
	writeField(strconv.Itoa(a.FailLocations))
	writeField(strconv.Itoa(a.ForSeconds))
	writeField(strconv.FormatInt(a.ExpiryMS, 10))
	writeField(strconv.FormatInt(a.UpdatedMS, 10))
	writeField(boolField(a.Deleted))
	return []byte(b.String())
}

// SignedAlertRule is an AlertRule plus the owner's key and signature.
type SignedAlertRule struct {
	Rule      AlertRule         `json:"rule"`
	PubKey    ed25519.PublicKey `json:"pubkey"`
	Signature []byte            `json:"signature"`
}

// SignAlertRule stamps the owner ID and signs.
func SignAlertRule(id *identity.Identity, a AlertRule) SignedAlertRule {
	a.Owner = id.NodeID()
	return SignedAlertRule{Rule: a, PubKey: id.Public(), Signature: id.Sign(a.canonical())}
}

func (sa SignedAlertRule) Verify() error {
	return verifyOwner(sa.PubKey, sa.Rule.Owner, sa.Rule.canonical(), sa.Signature)
}
