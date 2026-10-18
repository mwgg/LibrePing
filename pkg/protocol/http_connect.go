package protocol

import (
	"fmt"
	"net/netip"
	"net/url"
)

// ValidateHTTPConnect validates only the additive pinned HTTP contract. Other
// types retain their historical parameter semantics.
func (s CheckSpec) ValidateHTTPConnect() error {
	if s.Type != CheckHTTPConnect {
		return nil
	}
	raw := s.Params["connect_address"]
	ip, err := netip.ParseAddr(raw)
	if err != nil || ip.Zone() != "" || ip.Is4In6() || ip.String() != raw {
		return fmt.Errorf("http_connect requires connect_address as a canonical literal IP without brackets, zone or port")
	}
	u, err := url.Parse(s.Target)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Hostname() == "" {
		return fmt.Errorf("http_connect requires an absolute HTTP(S) URL")
	}
	return nil
}
