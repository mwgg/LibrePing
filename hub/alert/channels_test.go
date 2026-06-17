package alert

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/mwgg/libreping/pkg/protocol"
)

func testNotification() Notification {
	return Notification{
		CheckID: "chk1", Target: "http://svc.example", Status: protocol.StatusDown, AtMS: 1700000000000,
		Locations: []protocol.ResultContent{
			{ProbeID: "p1", Status: protocol.StatusDown, Location: protocol.Location{City: "Moscow", Country: "Russia"}},
			{ProbeID: "p2", Status: protocol.StatusUp, Location: protocol.Location{City: "Helsinki", Country: "Finland"}},
		},
	}
}

// captured records the last request a test server received.
type captured struct {
	contentType string
	headers     http.Header
	body        []byte
}

// serveCapture starts a server that records one request, and returns a
// destination URL using a hostname (not an IP literal) so netguard.ValidateURL
// accepts it; the injected client still actually reaches loopback.
func serveCapture(t *testing.T, cap *captured) (string, *http.Client, func()) {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cap.contentType = r.Header.Get("Content-Type")
		cap.headers = r.Header.Clone()
		cap.body, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusOK)
	}))
	url := strings.Replace(srv.URL, "127.0.0.1", "localhost", 1)
	return url, srv.Client(), srv.Close
}

func TestWebhookNotifierPayload(t *testing.T) {
	var cap captured
	url, client, done := serveCapture(t, &cap)
	defer done()

	n := testNotification()
	n.Destination = url
	if err := (WebhookNotifier{Client: client, AllowHTTP: true}).Notify(context.Background(), n); err != nil {
		t.Fatalf("notify: %v", err)
	}
	if cap.contentType != "application/json" {
		t.Fatalf("content-type = %q", cap.contentType)
	}
	var got map[string]any
	if err := json.Unmarshal(cap.body, &got); err != nil {
		t.Fatalf("body not json: %v (%s)", err, cap.body)
	}
	// The documented payload shape — fields integrators depend on.
	for _, k := range []string{"check_id", "target", "status", "locations", "at_ms"} {
		if _, ok := got[k]; !ok {
			t.Fatalf("payload missing %q: %s", k, cap.body)
		}
	}
	if got["status"] != "down" || got["target"] != "http://svc.example" {
		t.Fatalf("unexpected payload: %s", cap.body)
	}
	// The decrypted destination must never appear in the body.
	if strings.Contains(string(cap.body), url) {
		t.Fatal("destination leaked into webhook body")
	}
}

func TestNtfyNotifierHeadersAndText(t *testing.T) {
	var cap captured
	url, client, done := serveCapture(t, &cap)
	defer done()

	n := testNotification()
	n.Destination = url
	if err := (NtfyNotifier{Client: client, AllowHTTP: true}).Notify(context.Background(), n); err != nil {
		t.Fatalf("notify: %v", err)
	}
	if cap.contentType != "text/plain" {
		t.Fatalf("content-type = %q", cap.contentType)
	}
	if cap.headers.Get("Title") == "" || cap.headers.Get("Priority") != "high" || cap.headers.Get("Tags") == "" {
		t.Fatalf("ntfy headers wrong: Title=%q Priority=%q Tags=%q",
			cap.headers.Get("Title"), cap.headers.Get("Priority"), cap.headers.Get("Tags"))
	}
	if !strings.Contains(string(cap.body), "Moscow") {
		t.Fatalf("ntfy text should name the down location: %s", cap.body)
	}
}

func TestDiscordAndSlackPayload(t *testing.T) {
	for _, tc := range []struct {
		name  string
		send  func(url string, c *http.Client, n Notification) error
		field string
	}{
		{"discord", func(u string, c *http.Client, n Notification) error {
			n.Destination = u
			return DiscordNotifier{Client: c, AllowHTTP: true}.Notify(context.Background(), n)
		}, "content"},
		{"slack", func(u string, c *http.Client, n Notification) error {
			n.Destination = u
			return SlackNotifier{Client: c, AllowHTTP: true}.Notify(context.Background(), n)
		}, "text"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var cap captured
			url, client, done := serveCapture(t, &cap)
			defer done()
			if err := tc.send(url, client, testNotification()); err != nil {
				t.Fatalf("notify: %v", err)
			}
			var got map[string]string
			if err := json.Unmarshal(cap.body, &got); err != nil {
				t.Fatalf("body not json: %v (%s)", err, cap.body)
			}
			if got[tc.field] == "" {
				t.Fatalf("%s payload missing %q: %s", tc.name, tc.field, cap.body)
			}
		})
	}
}

func TestChannelKnown(t *testing.T) {
	for _, c := range []protocol.AlertChannel{protocol.AlertWebhook, protocol.AlertNtfy, protocol.AlertDiscord, protocol.AlertSlack} {
		if !c.Known() {
			t.Fatalf("%q should be known", c)
		}
	}
	if protocol.AlertChannel("email").Known() {
		t.Fatal("email should no longer be a known channel")
	}
}
