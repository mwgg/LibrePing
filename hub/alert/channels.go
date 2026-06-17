package alert

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/mwgg/libreping/pkg/netguard"
	"github.com/mwgg/libreping/pkg/protocol"
)

// Notification is what a Notifier delivers on a status transition. Destination
// is the decrypted recipient (never gossiped in the clear) and is excluded from
// the webhook JSON payload.
type Notification struct {
	Destination string                   `json:"-"`
	Channel     protocol.AlertChannel    `json:"-"`
	CheckID     string                   `json:"check_id"`
	Target      string                   `json:"target"`
	Status      protocol.Status          `json:"status"`
	Locations   []protocol.ResultContent `json:"locations"`
	AtMS        int64                    `json:"at_ms"`
}

// Notifier delivers a notification over one channel.
type Notifier interface {
	Notify(ctx context.Context, n Notification) error
}

// WebhookNotifier POSTs the notification as JSON to the rule's destination URL.
//
// The destination is owner-supplied, so without guardrails the hub is an open
// SSRF relay: it would POST to loopback/private/metadata URLs from its own
// network position. Client therefore defaults to an SSRF-safe client
// (netguard.SafeClient) that refuses blocked IP ranges at dial time and does
// not follow redirects, and the URL is validated (https-only unless AllowHTTP)
// before the request is built.
type WebhookNotifier struct {
	Client *http.Client
	// AllowHTTP permits plain-http destinations (operator opt-in for trusted
	// internal endpoints). Default false: https is required.
	AllowHTTP bool
}

func (wn WebhookNotifier) Notify(ctx context.Context, n Notification) error {
	body, err := json.Marshal(n)
	if err != nil {
		return err
	}
	return postAlert(ctx, wn.Client, wn.AllowHTTP, n.Destination, "application/json", body, nil)
}

// postAlert is the shared delivery primitive for every (HTTP-based) channel: it
// validates the owner-supplied destination (https-only unless allowHTTP), then
// POSTs the body through an SSRF-safe client that refuses blocked IP ranges at
// dial time and follows no redirects, so the hub can't be turned into an SSRF
// relay regardless of channel.
func postAlert(ctx context.Context, client *http.Client, allowHTTP bool, url, contentType string, body []byte, headers map[string]string) error {
	if err := netguard.ValidateURL(url, !allowHTTP); err != nil {
		return fmt.Errorf("alert destination rejected: %w", err)
	}
	if client == nil {
		client = netguard.SafeClient(netguard.Options{Timeout: 10 * time.Second})
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", contentType)
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("alert endpoint returned %s", resp.Status)
	}
	return nil
}

// title and text render a human-readable summary for the message-oriented
// channels (ntfy/Discord/Slack). The raw webhook channel sends the structured
// JSON instead; these are for humans.
func (n Notification) title() string {
	return fmt.Sprintf("LibrePing: %s is %s", n.Target, n.Status)
}

func (n Notification) text() string {
	up := 0
	var down []string
	for _, c := range n.Locations {
		if c.Status == protocol.StatusUp {
			up++
			continue
		}
		where := strings.TrimSpace(c.Location.City + " " + c.Location.Country)
		if where == "" {
			where = c.ProbeID[:min(8, len(c.ProbeID))]
		}
		down = append(down, where)
	}
	when := time.UnixMilli(n.AtMS).UTC().Format("2006-01-02 15:04 UTC")
	s := fmt.Sprintf("%s is %s — %d/%d locations up (as of %s)", n.Target, n.Status, up, len(n.Locations), when)
	if len(down) > 0 {
		s += "\nDown from: " + strings.Join(down, ", ")
	}
	return s
}

// NtfyNotifier POSTs a text message to an ntfy topic URL (ntfy.sh or self-hosted),
// with title/priority/tags so it renders as a proper push notification.
type NtfyNotifier struct {
	Client    *http.Client
	AllowHTTP bool
}

func (nn NtfyNotifier) Notify(ctx context.Context, n Notification) error {
	priority, tags := "default", "white_check_mark"
	if n.Status != protocol.StatusUp {
		priority, tags = "high", "warning"
	}
	headers := map[string]string{"Title": n.title(), "Priority": priority, "Tags": tags}
	return postAlert(ctx, nn.Client, nn.AllowHTTP, n.Destination, "text/plain", []byte(n.text()), headers)
}

// DiscordNotifier POSTs to a Discord channel webhook URL.
type DiscordNotifier struct {
	Client    *http.Client
	AllowHTTP bool
}

func (dn DiscordNotifier) Notify(ctx context.Context, n Notification) error {
	body, _ := json.Marshal(map[string]string{"content": n.title() + "\n" + n.text()})
	return postAlert(ctx, dn.Client, dn.AllowHTTP, n.Destination, "application/json", body, nil)
}

// SlackNotifier POSTs to a Slack incoming-webhook URL.
type SlackNotifier struct {
	Client    *http.Client
	AllowHTTP bool
}

func (sn SlackNotifier) Notify(ctx context.Context, n Notification) error {
	body, _ := json.Marshal(map[string]string{"text": n.title() + "\n" + n.text()})
	return postAlert(ctx, sn.Client, sn.AllowHTTP, n.Destination, "application/json", body, nil)
}
