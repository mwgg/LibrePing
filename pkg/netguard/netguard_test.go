package netguard

import (
	"net"
	"testing"
)

func TestIsBlockedIP(t *testing.T) {
	blocked := []string{
		"127.0.0.1", "::1", // loopback
		"10.0.0.5", "192.168.1.1", "172.16.0.1", // private v4
		"fc00::1", "fd12::1", // unique-local v6
		"169.254.1.1", "fe80::1", // link-local
		"169.254.169.254", "fd00:ec2::254", // cloud metadata
		"0.0.0.0", "::", // unspecified
		"224.0.0.1", // multicast
	}
	for _, s := range blocked {
		if !IsBlockedIP(net.ParseIP(s)) {
			t.Errorf("expected %s to be blocked", s)
		}
	}
	allowed := []string{"8.8.8.8", "1.1.1.1", "93.184.216.34", "2606:4700:4700::1111"}
	for _, s := range allowed {
		if IsBlockedIP(net.ParseIP(s)) {
			t.Errorf("expected %s to be allowed", s)
		}
	}
	if !IsBlockedIP(nil) {
		t.Error("nil IP should be blocked")
	}
}

func TestValidateURL(t *testing.T) {
	bad := []struct {
		url          string
		requireHTTPS bool
	}{
		{"http://127.0.0.1/x", false},
		{"http://169.254.169.254/latest/meta-data", false},
		{"http://10.0.0.1/", false},
		{"gopher://example.com/", false},
		{"file:///etc/passwd", false},
		{"http://example.com/", true}, // https required
		{"https://[::1]/", false},
		{"not a url at all ::::", false},
	}
	for _, c := range bad {
		if err := ValidateURL(c.url, c.requireHTTPS); err == nil {
			t.Errorf("expected %q (requireHTTPS=%v) to be rejected", c.url, c.requireHTTPS)
		}
	}
	good := []struct {
		url          string
		requireHTTPS bool
	}{
		{"https://example.com/hook", true},
		{"http://example.com/hook", false},
		{"https://hub.example.org:8443/api", true},
	}
	for _, c := range good {
		if err := ValidateURL(c.url, c.requireHTTPS); err != nil {
			t.Errorf("expected %q to be allowed, got %v", c.url, err)
		}
	}
}
