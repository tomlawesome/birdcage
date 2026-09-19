package portscan

import (
	"errors"
	"testing"
)

// parse_test feeds bare IPv4 packets -- no Ethernet header -- because
// that is what a SOCK_DGRAM packet socket hands userspace, and the
// mismatch with filter_test's Ethernet-framed packets is the real
// kernel behaviour rather than an inconsistency between the two tests.
// See filter.go.

func TestParseIPv4ReadsConnectionAttempts(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name      string
		packet    []byte
		wantProto string
		wantSrc   string
		wantDst   string
		wantSPort uint16
		wantDPort uint16
	}{
		{
			name:      "TCP SYN",
			packet:    ipv4Packet(ipv4Header{protocol: protoTCP}, tcpSegment(44123, 9999, tcpFlagSYN)),
			wantProto: ProtoTCP,
			wantSrc:   "198.51.100.5",
			wantDst:   "203.0.113.9",
			wantSPort: 44123,
			wantDPort: 9999,
		},
		{
			name:      "TCP SYN behind IPv4 options",
			packet:    ipv4Packet(ipv4Header{protocol: protoTCP, optWords: 2}, tcpSegment(1234, 3389, tcpFlagSYN)),
			wantProto: ProtoTCP,
			wantSrc:   "198.51.100.5",
			wantDst:   "203.0.113.9",
			wantSPort: 1234,
			wantDPort: 3389,
		},
		{
			name:      "UDP",
			packet:    ipv4Packet(ipv4Header{protocol: protoUDP}, udpDatagram(5353, 161)),
			wantProto: ProtoUDP,
			wantSrc:   "198.51.100.5",
			wantDst:   "203.0.113.9",
			wantSPort: 5353,
			wantDPort: 161,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			p, err := parseIPv4(tc.packet)
			if err != nil {
				t.Fatalf("parseIPv4: %v", err)
			}
			if p.Protocol != tc.wantProto {
				t.Errorf("protocol = %q, want %q", p.Protocol, tc.wantProto)
			}
			if p.Src.String() != tc.wantSrc {
				t.Errorf("src = %s, want %s", p.Src, tc.wantSrc)
			}
			if p.Dst.String() != tc.wantDst {
				t.Errorf("dst = %s, want %s", p.Dst, tc.wantDst)
			}
			if p.SrcPort != tc.wantSPort {
				t.Errorf("src port = %d, want %d", p.SrcPort, tc.wantSPort)
			}
			if p.DstPort != tc.wantDPort {
				t.Errorf("dst port = %d, want %d", p.DstPort, tc.wantDPort)
			}
		})
	}
}

// TestParseIPv4RejectsWhatTheFilterAlsoRejects is the belt to the
// filter's braces: parse.go re-checks version, fragment offset, protocol
// and the SYN-without-ACK test rather than trusting that the filter ran,
// and this is the test of that second check. If it ever starts passing
// these, a filter that failed to attach stops being survivable and
// starts producing wrong alerts.
func TestParseIPv4RejectsWhatTheFilterAlsoRejects(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name   string
		packet []byte
		want   error
	}{
		{"SYN+ACK", ipv4Packet(ipv4Header{protocol: protoTCP}, tcpSegment(22, 44123, tcpFlagSYN|tcpFlagACK)), errNotOfInterest},
		{"bare ACK", ipv4Packet(ipv4Header{protocol: protoTCP}, tcpSegment(44123, 22, tcpFlagACK)), errNotOfInterest},
		{"RST", ipv4Packet(ipv4Header{protocol: protoTCP}, tcpSegment(44123, 22, 0x04)), errNotOfInterest},
		{"ICMP", ipv4Packet(ipv4Header{protocol: 1}, make([]byte, 8)), errNotOfInterest},
		{"continuation fragment", ipv4Packet(ipv4Header{protocol: protoTCP, fragOffset: 0x0185}, tcpSegment(44123, 9999, tcpFlagSYN)), errNotOfInterest},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if _, err := parseIPv4(tc.packet); !errors.Is(err, tc.want) {
				t.Fatalf("parseIPv4 error = %v, want %v", err, tc.want)
			}
		})
	}
}

// TestParseIPv4RejectsMalformedWithoutPanicking covers the packets an
// attacker writes on purpose. Every one of these is a length or header
// field that, unchecked, would index past the end of the read buffer --
// the parser runs on wholly attacker-controlled bytes in the hot path
// (internal/agent/event's threat-model note applies here word for word),
// so a panic is a remote denial of service against the agent.
func TestParseIPv4RejectsMalformedWithoutPanicking(t *testing.T) {
	t.Parallel()

	full := ipv4Packet(ipv4Header{protocol: protoTCP}, tcpSegment(44123, 9999, tcpFlagSYN))

	truncatedTCP := ipv4Packet(ipv4Header{protocol: protoTCP}, tcpSegment(44123, 9999, tcpFlagSYN))
	truncatedTCP = truncatedTCP[:ipMinHeaderLen+4]

	truncatedUDP := ipv4Packet(ipv4Header{protocol: protoUDP}, udpDatagram(44123, 9999))
	truncatedUDP = truncatedUDP[:ipMinHeaderLen+2]

	// IHL claiming 15 words (60 bytes) of header on a 40-byte packet.
	lyingIHL := append([]byte(nil), full...)
	lyingIHL[0] = 4<<4 | 15

	// IHL claiming a header shorter than the minimum.
	tinyIHL := append([]byte(nil), full...)
	tinyIHL[0] = 4<<4 | 3

	cases := []struct {
		name   string
		packet []byte
		want   error
	}{
		{"empty", nil, errMalformed},
		{"shorter than an IPv4 header", full[:12], errMalformed},
		{"IHL past the end of the packet", lyingIHL, errMalformed},
		{"IHL below the minimum", tinyIHL, errMalformed},
		{"TCP header cut short", truncatedTCP, errMalformed},
		{"UDP header cut short", truncatedUDP, errMalformed},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if _, err := parseIPv4(tc.packet); !errors.Is(err, tc.want) {
				t.Fatalf("parseIPv4 error = %v, want %v", err, tc.want)
			}
		})
	}
}

// TestParseIPv4IgnoresIPv6 proves the seam is closed rather than
// half-open: an IPv6 packet reaching the parser is declined, not read as
// if its fields were IPv4's.
func TestParseIPv4IgnoresIPv6(t *testing.T) {
	t.Parallel()

	pkt := make([]byte, 60)
	pkt[0] = 6 << 4
	if _, err := parseIPv4(pkt); !errors.Is(err, errNotOfInterest) {
		t.Fatalf("parseIPv4 on an IPv6 packet: %v, want errNotOfInterest", err)
	}
}
