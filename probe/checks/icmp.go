package checks

import (
	"bytes"
	"context"
	"crypto/rand"
	"net"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"

	"github.com/mwgg/libreping/pkg/protocol"
)

// icmpProtocol is the IANA protocol number for ICMPv4, used by icmp.ParseMessage.
const icmpProtocol = 1

// icmpProbe is the per-run identity used to recognise our own echo replies
// among all ICMP traffic. On the raw-socket path the kernel delivers every
// host's ICMP packets to every raw ICMP socket, so a check must not count a
// reply unless it carries this run's identifier, sequence, and echo token —
// otherwise concurrent checks (or any other pinging process) inject false
// replies. A random per-run id and token also prevents two concurrent checks,
// which would otherwise share a PID-derived id, from counting each other.
type icmpProbe struct {
	id    int    // ICMP identifier we set on outgoing echoes (16-bit)
	token []byte // echo body we send and must see echoed back
}

// newICMPProbe derives a fresh 16-bit identifier and a "libreping"-prefixed
// nonce token, so a foreign echo whose body happens to be "libreping" can't be
// mistaken for ours.
func newICMPProbe() icmpProbe {
	var b [6]byte
	_, _ = rand.Read(b[:])
	return icmpProbe{
		id:    int(b[0])<<8 | int(b[1]),
		token: append([]byte("libreping"), b[2:]...),
	}
}

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
// a time-exceeded (used by traceroute) that matches this run's probe identity.
// Returns the responding hop, the RTT, and the ICMP reply type. Packets that do
// not belong to this probe are skipped (the read continues on the same absolute
// deadline) so a foreign packet can't steal the read or be counted as a reply.
func pingOnce(conn *icmp.PacketConn, privileged bool, p icmpProbe, dst net.IP, ttl, seq int, timeout time.Duration) (net.IP, time.Duration, ipv4.ICMPType, error) {
	if err := conn.IPv4PacketConn().SetTTL(ttl); err != nil {
		return nil, 0, 0, err
	}
	msg := icmp.Message{
		Type: ipv4.ICMPTypeEcho, Code: 0,
		Body: &icmp.Echo{ID: p.id, Seq: seq, Data: p.token},
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
		reply, ok := parseReply(rm, peer)
		if !ok || !matchReply(reply, privileged, p, seq, dst) {
			continue
		}
		return reply.src, time.Since(start), reply.typ, nil
	}
}

// icmpReply is the matcher-relevant view of a received ICMP message. For a
// TimeExceeded, innerID/innerSeq come from the quoted original echo header;
// they are -1 when the quotation is too short to parse.
type icmpReply struct {
	typ      ipv4.ICMPType
	src      net.IP
	id       int    // EchoReply identifier
	seq      int    // EchoReply sequence
	body     []byte // EchoReply payload
	innerID  int    // quoted original echo identifier (TimeExceeded)
	innerSeq int    // quoted original echo sequence (TimeExceeded)
}

// parseReply projects a parsed ICMP message into the fields the matcher needs.
// It returns false for message types we never match on.
func parseReply(rm *icmp.Message, peer net.Addr) (icmpReply, bool) {
	typ, ok := rm.Type.(ipv4.ICMPType)
	if !ok {
		return icmpReply{}, false
	}
	r := icmpReply{typ: typ, src: peerIP(peer), innerID: -1, innerSeq: -1}
	switch b := rm.Body.(type) {
	case *icmp.Echo:
		r.id, r.seq, r.body = b.ID, b.Seq, b.Data
	case *icmp.TimeExceeded:
		if id, seq, ok := quotedEcho(b.Data); ok {
			r.innerID, r.innerSeq = id, seq
		}
	default:
		return r, false
	}
	return r, true
}

// quotedEcho extracts the ICMP identifier and sequence of the original echo
// quoted inside a TimeExceeded body. The quotation is the original IPv4 header
// (variable length via IHL) followed by at least the 8-byte ICMP header
// (type, code, checksum, id, seq).
func quotedEcho(data []byte) (id, seq int, ok bool) {
	if len(data) < 20 {
		return 0, 0, false
	}
	ihl := int(data[0]&0x0f) * 4
	if ihl < 20 || len(data) < ihl+8 {
		return 0, 0, false
	}
	h := data[ihl:]
	return int(h[4])<<8 | int(h[5]), int(h[6])<<8 | int(h[7]), true
}

// matchReply reports whether an ICMP message is a reply to the echo this run
// sent with the given sequence to dst. On the unprivileged datagram path the
// kernel rewrites the identifier to the socket's port, so the id is trusted
// only when privileged (a raw socket, where we control it); on that path the
// socket is already per-flow demuxed, and seq/token/source still hold.
func matchReply(r icmpReply, privileged bool, p icmpProbe, seq int, dst net.IP) bool {
	switch r.typ {
	case ipv4.ICMPTypeEchoReply:
		if privileged && r.id != p.id {
			return false
		}
		if r.seq != seq {
			return false
		}
		if !bytes.Equal(r.body, p.token) {
			return false
		}
		// An echo reply must originate from the host we pinged.
		if dst != nil && r.src != nil && !r.src.Equal(dst) {
			return false
		}
		return true
	case ipv4.ICMPTypeTimeExceeded:
		// Match the quoted original echo so a foreign time-exceeded (or a
		// stray echo reply) can't be attributed to our traceroute hop. The
		// hop's source address is an intermediate router, not dst, so it is
		// not constrained here.
		if r.innerSeq != seq {
			return false
		}
		if privileged && r.innerID >= 0 && r.innerID != p.id {
			return false
		}
		return true
	}
	return false
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

	probe := newICMPProbe()
	var received int
	var total time.Duration
	for seq := 0; seq < count; seq++ {
		_, rtt, typ, err := pingOnce(conn, privileged, probe, ipAddr.IP, 64, seq, timeout)
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
