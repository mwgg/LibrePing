// Package directory maintains a hub's view of other publicly-reachable hubs.
//
// A signed hub announcement arriving over gossip proves only that the holder of
// a hub identity *claims* a public URL. Before listing that hub, the directory
// performs a separate reachability check: it fetches the advertised URL's
// identity endpoint and confirms the hub_id served there matches the
// announcement's signer. This stops a hub from advertising someone else's URL
// or a bogus one.
package directory

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"sort"
	"sync"
	"time"

	"github.com/mwgg/libreping/pkg/netguard"
	"github.com/mwgg/libreping/pkg/protocol"
)

// maxIdentityBody bounds how much of an advertised hub's /identity response the
// directory will read, so a hostile or buggy peer can't exhaust memory.
const maxIdentityBody = 64 << 10

// VerifyFunc confirms that the hub served at url reports the expected hub ID.
// Injectable so tests don't need real HTTP.
type VerifyFunc func(ctx context.Context, url, expectID string) bool

// entry separates the announcement that last *passed* verification from the
// latest one received. Only verifiedAnn is ever exposed (List/ActiveWithin), so
// a hub that re-announces a new URL, capacity, or archive flag cannot have those
// new values trusted until that exact announcement passes its own reachability
// check. Without this split, a verified hub could swap its URL to an internal
// address and be served as "verified" before the new URL was ever checked.
type entry struct {
	verifiedAnn protocol.HubAnnouncement // last announcement that passed verification
	verified    bool
	pendingAnn  protocol.HubAnnouncement // latest received (may be unverified)
	lastSeen    time.Time
}

// Directory is a TTL-bounded set of known peer hubs.
type Directory struct {
	mu        sync.Mutex
	entries   map[string]*entry
	verifying map[string]bool // hub IDs with an in-flight reachability check
	ttl       time.Duration
	selfID    string
	verify    VerifyFunc
	now       func() time.Time
	log       *slog.Logger
}

// New builds a directory. ttl is how long an un-refreshed entry survives.
// allowPrivatePeers lets reachability checks reach private/LAN addresses, for
// operators who deliberately federate over a trusted network; it defaults off
// so a public hub can't be steered into probing internal hosts (SSRF).
func New(selfID string, ttl time.Duration, allowPrivatePeers bool, log *slog.Logger) *Directory {
	if log == nil {
		log = slog.Default()
	}
	d := &Directory{
		entries:   map[string]*entry{},
		verifying: map[string]bool{},
		ttl:       ttl,
		selfID:    selfID,
		now:       time.Now,
		log:       log,
	}
	d.verify = newHTTPVerifier(allowPrivatePeers)
	return d
}

// Add records a signature-verified announcement and (re)confirms reachability
// asynchronously. The caller is responsible for having checked the signature
// (the p2p layer does this before calling Add).
func (d *Directory) Add(ctx context.Context, sa protocol.SignedHubAnnouncement) {
	ann := sa.Announcement
	if ann.HubID == d.selfID || ann.PublicURL == "" {
		return // don't list ourselves or URL-less announcements
	}
	d.mu.Lock()
	e, ok := d.entries[ann.HubID]
	if !ok {
		e = &entry{}
		d.entries[ann.HubID] = e
	}
	e.pendingAnn = ann
	e.lastSeen = d.now()
	// Nothing to re-check if the pending URL is already the verified one — just
	// refreshing lastSeen (above) keeps the verified entry live.
	if e.verified && e.verifiedAnn.PublicURL == ann.PublicURL {
		d.mu.Unlock()
		return
	}
	// Coalesce reachability checks: a hub re-announces every minute and several
	// peers may relay the same announcement, so run at most one verifier
	// goroutine per hub. Without this, repeated announcements spawn unbounded
	// goroutines all dialing the advertised URL — an amplification/DoS lever for
	// a hostile URL. The verifier loops if the URL changes mid-check, so a
	// genuinely new URL is still (re)verified.
	if d.verifying[ann.HubID] {
		d.mu.Unlock()
		return
	}
	d.verifying[ann.HubID] = true
	d.mu.Unlock()

	go d.verifyLoop(ctx, ann.HubID)
}

// verifyLoop reachability-checks a hub's pending URL off the gossip path. It is
// the only writer of verified state. It promotes pendingAnn to verifiedAnn only
// when that exact URL passes, and demotes the entry if the currently-verified
// URL stops verifying. If the pending URL changes while a check is in flight it
// loops, so a new URL is always (re)verified rather than inheriting the old
// URL's verified flag.
func (d *Directory) verifyLoop(ctx context.Context, hubID string) {
	for {
		d.mu.Lock()
		e, exists := d.entries[hubID]
		if !exists {
			delete(d.verifying, hubID)
			d.mu.Unlock()
			return
		}
		if e.verified && e.verifiedAnn.PublicURL == e.pendingAnn.PublicURL {
			delete(d.verifying, hubID)
			d.mu.Unlock()
			return
		}
		url := e.pendingAnn.PublicURL
		d.mu.Unlock()

		ok := d.verify(ctx, url, hubID)

		d.mu.Lock()
		e, exists = d.entries[hubID]
		if !exists {
			delete(d.verifying, hubID)
			d.mu.Unlock()
			return
		}
		if e.pendingAnn.PublicURL != url {
			// URL changed during the check; verify the newer one before settling.
			d.mu.Unlock()
			continue
		}
		if ok {
			e.verifiedAnn = e.pendingAnn // promote: URL, capacity, archive all from one verified announcement
			e.verified = true
		} else if e.verifiedAnn.PublicURL == url {
			e.verified = false // the previously-verified URL stopped verifying
		}
		delete(d.verifying, hubID)
		d.mu.Unlock()
		if !ok {
			d.log.Debug("hub failed reachability/identity check", "hub", hubID, "url", url)
		}
		return
	}
}

// AddVerified inserts an announcement as already-verified, skipping the async
// reachability probe. Intended for tests and statically-configured peer sets.
func (d *Directory) AddVerified(ann protocol.HubAnnouncement) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.entries[ann.HubID] = &entry{verifiedAnn: ann, pendingAnn: ann, verified: true, lastSeen: d.now()}
}

// List returns verified, non-expired peer hubs, newest announcement first.
func (d *Directory) List() []protocol.HubAnnouncement {
	d.mu.Lock()
	defer d.mu.Unlock()
	cutoff := d.now().Add(-d.ttl)
	out := []protocol.HubAnnouncement{}
	for id, e := range d.entries {
		if e.lastSeen.Before(cutoff) {
			delete(d.entries, id)
			continue
		}
		if e.verified {
			out = append(out, e.verifiedAnn)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].TimestampMS > out[j].TimestampMS })
	return out
}

// ActiveWithin returns verified hubs whose announcement was seen within d. It
// uses a shorter window than List's display TTL so alert responsibility fails
// over promptly when a hub goes silent.
func (d *Directory) ActiveWithin(window time.Duration) []protocol.HubAnnouncement {
	d.mu.Lock()
	defer d.mu.Unlock()
	cutoff := d.now().Add(-window)
	out := []protocol.HubAnnouncement{}
	for _, e := range d.entries {
		if e.verified && e.lastSeen.After(cutoff) {
			out = append(out, e.verifiedAnn)
		}
	}
	return out
}

// newHTTPVerifier returns a VerifyFunc that fetches {url}/api/v1/identity and
// checks the reported hub_id. It uses an SSRF-safe client (no redirects, no
// proxy, blocked-range refusal at dial time unless allowPrivate) and caps the
// response body — the advertised URL is attacker-controlled, so a verified
// signature is not licence to fire an unconstrained request from the hub.
func newHTTPVerifier(allowPrivate bool) VerifyFunc {
	client := netguard.SafeClient(netguard.Options{Timeout: 10 * time.Second, AllowPrivate: allowPrivate})
	return func(ctx context.Context, rawURL, expectID string) bool {
		if !allowPrivate {
			if err := netguard.ValidateURL(rawURL, false); err != nil {
				return false
			}
		}
		reqCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
		defer cancel()
		req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, rawURL+"/api/v1/identity", nil)
		if err != nil {
			return false
		}
		resp, err := client.Do(req)
		if err != nil {
			return false
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			return false
		}
		var body struct {
			HubID string `json:"hub_id"`
		}
		if err := json.NewDecoder(io.LimitReader(resp.Body, maxIdentityBody)).Decode(&body); err != nil {
			return false
		}
		return body.HubID == expectID
	}
}
