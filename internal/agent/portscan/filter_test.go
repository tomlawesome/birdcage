package portscan

import (
	"encoding/binary"
	"testing"

	"golang.org/x/net/bpf"
)

// These tests run the exact instructions openCapture attaches through
// golang.org/x/net/bpf's own virtual machine. That matters more than it
// might look: a classic BPF program is a flat list of forward-only
// relative jumps, a wrong skip count silently reroutes a branch rather
// than failing to load, and the failure mode in production -- an
// accepting filter that drops everything -- looks exactly like a quiet
// network. Running it in a VM against hand-built packets is the only way
// to see that without a NIC.
//
// Every packet here is a bare IPv4 packet with no link-layer header,
// because that is what the kernel shows a filter attached to a
// SOCK_DGRAM packet socket -- the same bytes parse.go gets, which is why
// parse_test.go builds its packets with the same helpers. See filter.go
// for why this is not what packet-socket filters usually see.
//
// A wrongly link-layer-relative filter passes this file's tests as
// happily as a correct one, provided the tests frame their packets the
// same wrong way. That is how the first draft of filter.go shipped a
// program that dropped everything, and why the image proof in issue #65
// is part of the work rather than a nicety.

// ipv4Header describes the IPv4 header to build. optWords is how many
// 4-byte option words to include, so a test can prove the filter follows
// IHL rather than assuming a 20-byte header.
type ipv4Header struct {
	protocol   uint8
	fragOffset uint16
	optWords   int
}

func ipv4Packet(h ipv4Header, payload []byte) []byte {
	headerLen := ipMinHeaderLen + h.optWords*4
	pkt := make([]byte, headerLen)
	pkt[0] = 4<<4 | uint8(headerLen/4)
	binary.BigEndian.PutUint16(pkt[2:4], uint16(headerLen+len(payload)))
	binary.BigEndian.PutUint16(pkt[6:8], h.fragOffset)
	pkt[8] = 64 // TTL
	pkt[9] = h.protocol
	copy(pkt[12:16], []byte{198, 51, 100, 5}) // TEST-NET-2 source
	copy(pkt[16:20], []byte{203, 0, 113, 9})  // TEST-NET-3 destination
	return append(pkt, payload...)
}

// ipv6Packet is a minimal IPv6 header: enough for the filter's version
// check to see a 6 where it wants a 4.
func ipv6Packet() []byte {
	pkt := make([]byte, 40)
	pkt[0] = 6 << 4
	pkt[6] = protoTCP // next header
	return pkt
}

func tcpSegment(srcPort, dstPort uint16, flags uint8) []byte {
	seg := make([]byte, tcpMinHeadLen)
	binary.BigEndian.PutUint16(seg[0:2], srcPort)
	binary.BigEndian.PutUint16(seg[2:4], dstPort)
	seg[12] = 5 << 4 // data offset: 5 words, no options
	seg[13] = flags
	binary.BigEndian.PutUint16(seg[14:16], 65535) // window
	return seg
}

func udpDatagram(srcPort, dstPort uint16) []byte {
	dg := make([]byte, udpHeaderLen)
	binary.BigEndian.PutUint16(dg[0:2], srcPort)
	binary.BigEndian.PutUint16(dg[2:4], dstPort)
	binary.BigEndian.PutUint16(dg[4:6], udpHeaderLen)
	return dg
}

// runFilter returns what the assembled program returns for frame: 0 for
// a dropped packet, snapLen for an accepted one.
func runFilter(t *testing.T, frame []byte) int {
	t.Helper()
	vm, err := bpf.NewVM(filterInstructions())
	if err != nil {
		t.Fatalf("assemble filter into a VM: %v", err)
	}
	out, err := vm.Run(frame)
	if err != nil {
		t.Fatalf("run filter: %v", err)
	}
	return out
}

func TestFilterPassesBareSYNAndUDP(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name  string
		frame []byte
	}{
		{
			name:  "TCP SYN, no options",
			frame: ipv4Packet(ipv4Header{protocol: protoTCP}, tcpSegment(44123, 9999, tcpFlagSYN)),
		},
		{
			// The whole reason the filter uses LoadMemShift rather than
			// a constant offset: a SYN with IPv4 options has its TCP
			// header further in, and nmap can be asked to send one.
			name:  "TCP SYN behind three IPv4 option words",
			frame: ipv4Packet(ipv4Header{protocol: protoTCP, optWords: 3}, tcpSegment(44123, 9999, tcpFlagSYN)),
		},
		{
			name:  "UDP datagram",
			frame: ipv4Packet(ipv4Header{protocol: protoUDP}, udpDatagram(44123, 9999)),
		},
		{
			// The Don't Fragment bit sits in the same field as the
			// fragment offset and is set on most ordinary traffic. It
			// must not be mistaken for a fragment.
			name:  "TCP SYN with the Don't Fragment bit set",
			frame: ipv4Packet(ipv4Header{protocol: protoTCP, fragOffset: 0x4000}, tcpSegment(44123, 9999, tcpFlagSYN)),
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := runFilter(t, tc.frame); got != snapLen {
				t.Fatalf("filter returned %d, want %d (packet should have passed)", got, snapLen)
			}
		})
	}
}

func TestFilterDropsEverythingElse(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name  string
		frame []byte
	}{
		{
			name:  "SYN+ACK is a reply to something we sent",
			frame: ipv4Packet(ipv4Header{protocol: protoTCP}, tcpSegment(22, 44123, tcpFlagSYN|tcpFlagACK)),
		},
		{
			name:  "bare ACK belongs to an established connection",
			frame: ipv4Packet(ipv4Header{protocol: protoTCP}, tcpSegment(44123, 22, tcpFlagACK)),
		},
		{
			name:  "RST",
			frame: ipv4Packet(ipv4Header{protocol: protoTCP}, tcpSegment(44123, 22, 0x04)),
		},
		{
			name:  "FIN+ACK",
			frame: ipv4Packet(ipv4Header{protocol: protoTCP}, tcpSegment(44123, 22, 0x01|tcpFlagACK)),
		},
		{
			name:  "no flags at all (an nmap NULL scan, which this slice does not claim)",
			frame: ipv4Packet(ipv4Header{protocol: protoTCP}, tcpSegment(44123, 22, 0)),
		},
		{
			name:  "ICMP",
			frame: ipv4Packet(ipv4Header{protocol: 1}, make([]byte, 8)),
		},
		{
			// The socket is bound to ETH_P_IP so this should not arrive,
			// but the filter checks the version nibble rather than
			// trusting that -- the seam for IPv6 is a branch here, not a
			// removed assumption.
			name:  "IPv6 (the seam, not yet wired)",
			frame: ipv6Packet(),
		},
		{
			name:  "continuation fragment carries no transport header",
			frame: ipv4Packet(ipv4Header{protocol: protoTCP, fragOffset: 0x0185}, tcpSegment(44123, 9999, tcpFlagSYN)),
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := runFilter(t, tc.frame); got != 0 {
				t.Fatalf("filter returned %d, want 0 (packet should have been dropped)", got)
			}
		})
	}
}

// TestFilterAssembles is the check that the program is well-formed in
// the kernel's terms -- every jump in range, a return on every path --
// which is what openCapture would otherwise discover as an
// SO_ATTACH_FILTER failure at startup on a canary rather than here.
func TestFilterAssembles(t *testing.T) {
	t.Parallel()

	assembled, err := assembleFilter()
	if err != nil {
		t.Fatalf("assembleFilter: %v", err)
	}
	if len(assembled) != len(filterInstructions()) {
		t.Fatalf("assembled %d instructions from %d", len(assembled), len(filterInstructions()))
	}
}
