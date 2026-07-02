package checks

import (
	"net"
	"testing"

	"golang.org/x/net/ipv4"
)

// buildProbe returns a fixed probe identity for deterministic matcher tests.
func buildProbe() icmpProbe {
	return icmpProbe{id: 0x1234, token: []byte("libreping\x01\x02\x03\x04")}
}

// TestMatchReplyEcho covers the raw-socket path where every field must line up:
// a foreign packet differing in id, seq, token, or source must be rejected so
// it can't be counted as an "up" reply for a check it doesn't belong to.
func TestMatchReplyEcho(t *testing.T) {
	p := buildProbe()
	dst := net.ParseIP("192.0.2.10")
	good := icmpReply{typ: ipv4.ICMPTypeEchoReply, src: dst, id: p.id, seq: 5, body: p.token, innerID: -1, innerSeq: -1}

	if !matchReply(good, true, p, 5, dst) {
		t.Fatal("expected a fully-matching echo reply to be accepted")
	}

	cases := []struct {
		name string
		mut  func(r *icmpReply)
		seq  int
	}{
		{"wrong id", func(r *icmpReply) { r.id = 0x9999 }, 5},
		{"wrong seq", func(r *icmpReply) { r.seq = 6 }, 5},
		{"wrong token", func(r *icmpReply) { r.body = []byte("libreping\x00\x00\x00\x00") }, 5},
		{"foreign source", func(r *icmpReply) { r.src = net.ParseIP("198.51.100.7") }, 5},
	}
	for _, c := range cases {
		r := good
		c.mut(&r)
		if matchReply(r, true, p, c.seq, dst) {
			t.Errorf("%s: expected reply to be rejected", c.name)
		}
	}
}

// TestMatchReplyEchoUnprivileged: on the datagram path the kernel rewrites the
// identifier, so a mismatched id must NOT reject an otherwise-valid reply,
// while seq/token/source still gate it.
func TestMatchReplyEchoUnprivileged(t *testing.T) {
	p := buildProbe()
	dst := net.ParseIP("192.0.2.10")
	r := icmpReply{typ: ipv4.ICMPTypeEchoReply, src: dst, id: 0x9999, seq: 3, body: p.token, innerID: -1, innerSeq: -1}
	if !matchReply(r, false, p, 3, dst) {
		t.Fatal("unprivileged path must ignore the id mismatch and accept")
	}
	r.body = []byte("nope")
	if matchReply(r, false, p, 3, dst) {
		t.Fatal("unprivileged path must still reject a token mismatch")
	}
}

// TestMatchReplyTimeExceeded checks that a traceroute hop is attributed only
// when the quoted original echo header matches, and a foreign echo reply from
// some other host can't set the hop as reached.
func TestMatchReplyTimeExceeded(t *testing.T) {
	p := buildProbe()
	dst := net.ParseIP("192.0.2.10")
	hop := net.ParseIP("192.0.2.1")

	match := icmpReply{typ: ipv4.ICMPTypeTimeExceeded, src: hop, innerID: p.id, innerSeq: 2}
	if !matchReply(match, true, p, 2, dst) {
		t.Fatal("expected time-exceeded with matching quoted echo to be accepted")
	}

	badSeq := icmpReply{typ: ipv4.ICMPTypeTimeExceeded, src: hop, innerID: p.id, innerSeq: 9}
	if matchReply(badSeq, true, p, 2, dst) {
		t.Fatal("time-exceeded quoting a different seq must be rejected")
	}
	badID := icmpReply{typ: ipv4.ICMPTypeTimeExceeded, src: hop, innerID: 0x9999, innerSeq: 2}
	if matchReply(badID, true, p, 2, dst) {
		t.Fatal("time-exceeded quoting a different id must be rejected on the raw path")
	}

	// A foreign echo reply from a non-target host must never mark reached.
	foreign := icmpReply{typ: ipv4.ICMPTypeEchoReply, src: net.ParseIP("198.51.100.7"), id: p.id, seq: 2, body: p.token, innerID: -1, innerSeq: -1}
	if matchReply(foreign, true, p, 2, dst) {
		t.Fatal("an echo reply from a foreign source must not match")
	}
}

// TestQuotedEcho verifies the inner-header parser tolerates short quotations
// and reads id/seq from a well-formed one.
func TestQuotedEcho(t *testing.T) {
	if _, _, ok := quotedEcho([]byte{0x45, 0x00, 0x00}); ok {
		t.Fatal("expected a too-short quotation to fail")
	}
	// Minimal 20-byte IPv4 header (IHL=5) + 8-byte ICMP echo header.
	data := make([]byte, 28)
	data[0] = 0x45
	data[24] = 8                        // type = echo request
	data[28-4], data[28-3] = 0x12, 0x34 // id
	data[28-2], data[28-1] = 0x00, 0x07 // seq
	id, seq, ok := quotedEcho(data)
	if !ok || id != 0x1234 || seq != 7 {
		t.Fatalf("quotedEcho = (%#x, %d, %v), want (0x1234, 7, true)", id, seq, ok)
	}
}
