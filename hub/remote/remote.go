// Package remote fetches results from the hubs that hold a shard, for the two
// cases partial replication creates: a hub serving a dashboard read for a check
// it doesn't store (on-demand query), and a hub backfilling a shard it has just
// been assigned (repair). Either way the holder is just a relay — every fetched
// result is signature-verified here, so a malicious holder cannot inject data.
package remote

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/mwgg/libreping/pkg/netguard"
	"github.com/mwgg/libreping/pkg/protocol"
)

// QueryPath is the holder endpoint that serves a hub's locally-held results.
const QueryPath = "/api/v1/results/query"

// SubmitPath is the holder endpoint that ingests a directly-pushed result.
const SubmitPath = "/api/v1/results"

// maxBody caps a holder's response so one query can't exhaust memory.
const maxBody = 8 << 20

// Client fetches from (and pushes to) holder hubs. The zero value is unusable;
// use NewClient.
type Client struct {
	http         *http.Client
	allowPrivate bool
}

// NewClient returns a holder client with a bounded timeout. It uses the
// SSRF-safe HTTP client so a holder URL — which can momentarily be an
// unverified directory entry — cannot steer the hub into private ranges or
// follow redirects. allowPrivate mirrors HUB_ALLOW_PRIVATE_PEERS for operators
// who deliberately federate over a trusted private network.
func NewClient(allowPrivate bool) *Client {
	return &Client{
		http:         netguard.SafeClient(netguard.Options{Timeout: 15 * time.Second, AllowPrivate: allowPrivate}),
		allowPrivate: allowPrivate,
	}
}

// Fetch GETs {baseURL}/api/v1/results/query with the given query values and
// returns only the results whose signatures verify.
func (c *Client) Fetch(ctx context.Context, baseURL string, q url.Values) ([]protocol.SignedResult, error) {
	if !c.allowPrivate {
		if err := netguard.ValidateURL(baseURL, false); err != nil {
			return nil, err
		}
	}
	u := strings.TrimRight(baseURL, "/") + QueryPath + "?" + q.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("holder query %s: %s", baseURL, resp.Status)
	}
	var raw []protocol.SignedResult
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxBody)).Decode(&raw); err != nil {
		return nil, err
	}
	out := raw[:0]
	for _, sr := range raw {
		if sr.Verify() == nil { // never trust the relaying hub, only the signer
			out = append(out, sr)
		}
	}
	return out, nil
}

// Submit POSTs one signed result to a holder's submit endpoint. Used to route a
// result directly to its shard holders when the submitting (home) hub does not
// hold the shard itself, so gossip delivery is not the only path. The holder
// re-runs verify→policy→admit on ingest, so this is no more trusted than gossip.
func (c *Client) Submit(ctx context.Context, baseURL string, sr protocol.SignedResult) error {
	if !c.allowPrivate {
		if err := netguard.ValidateURL(baseURL, false); err != nil {
			return err
		}
	}
	body, err := json.Marshal(sr)
	if err != nil {
		return err
	}
	u := strings.TrimRight(baseURL, "/") + SubmitPath
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4<<10))
	if resp.StatusCode != http.StatusAccepted && resp.StatusCode != http.StatusOK {
		return fmt.Errorf("holder submit %s: %s", baseURL, resp.Status)
	}
	return nil
}

// CheckQuery builds query values for one check's recent results.
func CheckQuery(checkID string, sinceMS int64, limit int) url.Values {
	q := url.Values{}
	q.Set("check_id", checkID)
	q.Set("since_ms", fmt.Sprintf("%d", sinceMS))
	q.Set("limit", fmt.Sprintf("%d", limit))
	return q
}

// ShardQuery builds query values for a whole shard's results (backfill) in the
// window [sinceMS, beforeMS), newest first. beforeMS == 0 means no upper bound;
// pass the oldest timestamp of the previous page to walk backward through a
// large window without a global limit dropping older rows.
func ShardQuery(s uint32, sinceMS, beforeMS int64, limit int) url.Values {
	q := url.Values{}
	q.Set("shard", fmt.Sprintf("%d", s))
	q.Set("since_ms", fmt.Sprintf("%d", sinceMS))
	if beforeMS > 0 {
		q.Set("before_ms", fmt.Sprintf("%d", beforeMS))
	}
	q.Set("limit", fmt.Sprintf("%d", limit))
	return q
}
