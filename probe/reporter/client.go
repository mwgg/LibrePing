package reporter

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"time"

	"github.com/mwgg/libreping/pkg/protocol"
)

// HubClient talks to a hub's probe-facing JSON API.
type HubClient struct {
	baseURL string
	http    *http.Client
}

// NewHubClient returns a client for the hub at baseURL (e.g. http://hub:8080).
func NewHubClient(baseURL string) *HubClient {
	return &HubClient{
		baseURL: baseURL,
		http:    &http.Client{Timeout: 15 * time.Second},
	}
}

// URL returns the hub base URL this client targets. Used by the failover pool
// to dedupe and label hubs.
func (c *HubClient) URL() string { return c.baseURL }

// Register makes the hub aware of this probe and its declared location. The
// registration is signed by the probe key so the hub can reject spoofed or
// ghost-probe registrations.
func (c *HubClient) Register(ctx context.Context, reg protocol.SignedProbeRegistration) error {
	return c.postJSON(ctx, "/api/v1/probes/register", reg, nil)
}

// FetchChecks pulls the subset of checks the hub has assigned to this probe.
func (c *HubClient) FetchChecks(ctx context.Context, probeID string) ([]protocol.CheckSpec, error) {
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+"/api/v1/checks?probe_id="+url.QueryEscape(probeID), nil)
	if err != nil {
		return nil, err
	}
	resp, err := c.http.Do(httpReq)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("fetch checks: hub returned %s", resp.Status)
	}
	var specs []protocol.CheckSpec
	if err := json.NewDecoder(resp.Body).Decode(&specs); err != nil {
		return nil, err
	}
	return specs, nil
}

// SubmitResult sends a signed measurement to the hub.
func (c *HubClient) SubmitResult(ctx context.Context, sr protocol.SignedResult) error {
	return c.postJSON(ctx, "/api/v1/results", sr, nil)
}

// FetchHubs pulls this hub's reachability-verified directory of peer hubs. The
// failover pool uses it to discover additional hubs it can fall back to, so a
// probe configured with a single seed hub still learns the whole mesh.
func (c *HubClient) FetchHubs(ctx context.Context) ([]protocol.HubAnnouncement, error) {
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+"/api/v1/hubs", nil)
	if err != nil {
		return nil, err
	}
	resp, err := c.http.Do(httpReq)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("fetch hubs: hub returned %s", resp.Status)
	}
	var hubs []protocol.HubAnnouncement
	if err := json.NewDecoder(resp.Body).Decode(&hubs); err != nil {
		return nil, err
	}
	return hubs, nil
}

func (c *HubClient) postJSON(ctx context.Context, path string, body, out any) error {
	buf, err := json.Marshal(body)
	if err != nil {
		return err
	}
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+path, bytes.NewReader(buf))
	if err != nil {
		return err
	}
	httpReq.Header.Set("Content-Type", "application/json")
	resp, err := c.http.Do(httpReq)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("POST %s: hub returned %s", path, resp.Status)
	}
	if out != nil {
		return json.NewDecoder(resp.Body).Decode(out)
	}
	return nil
}
