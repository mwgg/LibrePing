package protocol

import "testing"

func TestHTTPConnectContract(t *testing.T) {
	for _, address := range []string{"192.0.2.1", "2001:db8::1"} {
		s := CheckSpec{Type: CheckHTTPConnect, Target: "https://example.com/health", Params: map[string]string{"connect_address": address}}
		if err := s.ValidateHTTPConnect(); err != nil {
			t.Fatal(err)
		}
		before := s.DeriveID()
		s.Params["connect_address"] = "192.0.2.2"
		if before == s.DeriveID() {
			t.Fatal("backend missing from identity")
		}
	}
	for _, address := range []string{"", "example.com", "192.0.2.1:443", "192.0.2.0/24", "[2001:db8::1]", "2001:0DB8::1", "fe80::1%eth0", "::ffff:192.0.2.1"} {
		s := CheckSpec{Type: CheckHTTPConnect, Target: "https://example.com", Params: map[string]string{"connect_address": address}}
		if s.ValidateHTTPConnect() == nil {
			t.Fatalf("accepted %q", address)
		}
	}
}
