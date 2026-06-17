package checks

import (
	"context"
	"net"
	"os"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"

	"github.com/mwgg/libreping/pkg/protocol"
)

// icmpProtocol is the IANA protocol number for ICMPv4, used by icmp.ParseMessage.
const icmpProtocol = 1

// icmpListen opens an ICMP socket, preferring unprivileged datagram ICMP (works
// when net.ipv4.ping_group_range allows it) and falling back to a raw socket
// (needs CAP_NET_RAW). Returns whether the socket is the privileged raw kind.
func icmpListen() (*icmp.PacketConn, bool, error) {
	if c, err := icmp.ListenPacket("udp4", "0.0.0.0"); err == nil {
		return c, false, nil
	}
	c, err := icmp.ListenPacket("ip4:icmp", "0.0.0.0")
	if err != nil {
		return nil, false, err
	}
	return c, true, nil
}

// RawSocketsAvailable reports whether ICMP sockets can be opened, so the probe
// can decide at startup whether to offer ICMP/traceroute checks.
func RawSocketsAvailable() bool {
	c, _, err := icmpListen()
	if err != nil {
		return false
	}
	_ = c.Close()
	return true
}

// pingOnce sends a single ICMP echo with the given TTL and waits for a reply or
// a time-exceeded (used by traceroute). Returns the responding hop, the RTT,
// and the ICMP reply type.
func pingOnce(conn *icmp.PacketConn, privileged bool, dst net.IP, ttl, seq int, timeout time.Duration) (net.IP, time.Duration, ipv4.ICMPType, error) {
	if err := conn.IPv4PacketConn().SetTTL(ttl); err != nil {
		return nil, 0, 0, err
	}
	msg := icmp.Message{
		Type: ipv4.ICMPTypeEcho, Code: 0,
		Body: &icmp.Echo{ID: os.Getpid() & 0xffff, Seq: seq, Data: []byte("libreping")},
	}
	wb, err := msg.Marshal(nil)
	if err != nil {
		return nil, 0, 0, err
	}

	var addr net.Addr = &net.IPAddr{IP: dst}
	if !privileged {
		addr = &net.UDPAddr{IP: dst}
	}

	start := time.Now()
	if _, err := conn.WriteTo(wb, addr); err != nil {
		return nil, 0, 0, err
	}
	_ = conn.SetReadDeadline(time.Now().Add(timeout))

	rb := make([]byte, 1500)
	for {
		n, peer, err := conn.ReadFrom(rb)
		if err != nil {
			return nil, 0, 0, err // typically a read timeout
		}
		rm, err := icmp.ParseMessage(icmpProtocol, rb[:n])
		if err != nil {
			continue
		}
		switch rm.Type {
		case ipv4.ICMPTypeEchoReply:
			return peerIP(peer), time.Since(start), ipv4.ICMPTypeEchoReply, nil
		case ipv4.ICMPTypeTimeExceeded:
			return peerIP(peer), time.Since(start), ipv4.ICMPTypeTimeExceeded, nil
		}
	}
}

func peerIP(addr net.Addr) net.IP {
	switch a := addr.(type) {
	case *net.IPAddr:
		return a.IP
	case *net.UDPAddr:
		return a.IP
	}
	return nil
}

// ICMPChecker pings the target. `target` is a host or IP. Params:
//   - count: echo requests to send (default 3)
//
// Requires raw sockets (CAP_NET_RAW or net.ipv4.ping_group_range).
type ICMPChecker struct{}

func (ICMPChecker) Type() protocol.CheckType { return protocol.CheckICMP }

func (ICMPChecker) Run(ctx context.Context, spec protocol.CheckSpec) (Outcome, error) {
	count := paramInt(spec, "count", 3)
	if count < 1 {
		count = 1
	}
	timeout := paramDuration(spec, "timeout_seconds", 3*time.Second)

	ipAddr, err := net.ResolveIPAddr("ip4", spec.Target)
	if err != nil {
		return Outcome{Status: protocol.StatusDown, Detail: map[string]string{"error": err.Error()}}, nil
	}
	if err := guardIP(ipAddr.IP); err != nil {
		return Outcome{Status: protocol.StatusDown, Detail: map[string]string{"error": err.Error()}}, nil
	}

	conn, privileged, err := icmpListen()
	if err != nil {
		return Outcome{Status: protocol.StatusDegraded, Detail: map[string]string{"error": "raw sockets unavailable: " + err.Error()}}, ErrNotImplemented
	}
	defer conn.Close()

	var received int
	var total time.Duration
	for seq := 0; seq < count; seq++ {
		_, rtt, typ, err := pingOnce(conn, privileged, ipAddr.IP, 64, seq, timeout)
		if err == nil && typ == ipv4.ICMPTypeEchoReply {
			received++
			total += rtt
		}
	}

	detail := map[string]string{
		"sent":     itoa(count),
		"received": itoa(received),
		"loss_pct": itoa((count - received) * 100 / count),
	}
	switch {
	case received == 0:
		return Outcome{Status: protocol.StatusDown, Detail: detail}, nil
	case received < count:
		return Outcome{Status: protocol.StatusDegraded, RTTMillis: float64(total.Microseconds()) / 1000.0 / float64(received), Detail: detail}, nil
	default:
		return Outcome{Status: protocol.StatusUp, RTTMillis: float64(total.Microseconds()) / 1000.0 / float64(received), Detail: detail}, nil
	}
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var b [12]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		b[i] = '-'
	}
	return string(b[i:])
}
