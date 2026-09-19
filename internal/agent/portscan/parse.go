package portscan

import (
	"encoding/binary"
	"errors"
	"net/netip"
)

// Protocol names as they appear in an emitted event's logdata.PROTO.
const (
	ProtoTCP = "TCP"
	ProtoUDP = "UDP"
)

// packet is everything this package needs from one captured frame. Four
// small values and no retained reference to the read buffer, so the
// capture loop can reuse one buffer for the life of the process.
type packet struct {
	Src      netip.Addr
	Dst      netip.Addr
	SrcPort  uint16
	DstPort  uint16
	Protocol string
}

// errNotOfInterest is returned by parseIPv4 for a packet this package
// has nothing to say about: not IPv4, a continuation fragment, a
// protocol other than TCP or UDP, or a TCP packet that is not a bare
// SYN. It is not a failure -- the kernel filter is supposed to have
// dropped these already -- so the capture loop counts it and moves on
// rather than logging.
var errNotOfInterest = errors.New("portscan: packet is not a connection attempt")

// errMalformed is returned for a packet too short or too self-
// inconsistent to read ports out of. Distinguished from
// errNotOfInterest because it is the one a hostile sender can provoke
// deliberately, and is counted separately so a flood of them is visible
// in the agent's own numbers rather than silently indistinguishable
// from ordinary uninteresting traffic.
var errMalformed = errors.New("portscan: malformed packet")

// Offsets inside an IPv4 header, and inside the TCP/UDP header that
// follows it. The four the filter also uses live in filter.go and are
// shared, not restated: a SOCK_DGRAM packet socket shows the filter and
// userspace the same bytes, so there is one set of offsets and no chance
// of the two drifting apart. See filter.go for why that is not the usual
// arrangement for a packet-socket filter.
const (
	ipMinHeaderLen = 20
	ipSrcOff       = 12
	ipDstOff       = 16

	// Both TCP and UDP put source port first and destination port
	// second, so one pair of offsets covers both.
	portSrcOff = 0
	portDstOff = 2
	portsLen   = 4

	tcpMinHeadLen = 20
	udpHeaderLen  = 8
)

// parseIPv4 reads one captured IPv4 packet, as handed to a SOCK_DGRAM
// AF_PACKET reader, and returns the connection attempt it represents.
//
// It deliberately re-checks everything the kernel filter already checked
// -- version, fragment offset, protocol, the SYN-without-ACK test --
// rather than assuming the filter ran. Two reasons: a kernel that
// refuses SO_ATTACH_FILTER leaves an unfiltered socket rather than no
// socket, and a future edit to filter.go should not be able to turn a
// filter bug into a wrong alert. The first draft of that filter read the
// wrong offsets entirely and dropped everything, which is the failure
// this second check cannot help with -- but the opposite mistake, a
// filter that passes too much, is exactly what it catches. Re-checking
// costs a handful of byte comparisons on a packet that already survived
// the kernel's own test, next to the syscall that delivered it.
func parseIPv4(b []byte) (packet, error) {
	if len(b) < ipMinHeaderLen {
		return packet{}, errMalformed
	}
	if b[ipVersionIHLOffset]>>4 != 4 {
		return packet{}, errNotOfInterest
	}
	headerLen := int(b[ipVersionIHLOffset]&0x0f) * 4
	if headerLen < ipMinHeaderLen || headerLen > len(b) {
		return packet{}, errMalformed
	}
	if binary.BigEndian.Uint16(b[ipFlagsFragOffset:ipFlagsFragOffset+2])&fragmentOffsetMask != 0 {
		return packet{}, errNotOfInterest
	}

	payload := b[headerLen:]

	var proto string
	switch b[ipProtocolOffset] {
	case protoTCP:
		if len(payload) < tcpMinHeadLen {
			return packet{}, errMalformed
		}
		if payload[tcpFlagsOffset]&synMask != synValue {
			return packet{}, errNotOfInterest
		}
		proto = ProtoTCP
	case protoUDP:
		if len(payload) < udpHeaderLen {
			return packet{}, errMalformed
		}
		proto = ProtoUDP
	default:
		return packet{}, errNotOfInterest
	}

	if len(payload) < portsLen {
		return packet{}, errMalformed
	}
	src, _ := netip.AddrFromSlice(b[ipSrcOff : ipSrcOff+4])
	dst, _ := netip.AddrFromSlice(b[ipDstOff : ipDstOff+4])

	return packet{
		Src:      src,
		Dst:      dst,
		SrcPort:  binary.BigEndian.Uint16(payload[portSrcOff : portSrcOff+2]),
		DstPort:  binary.BigEndian.Uint16(payload[portDstOff : portDstOff+2]),
		Protocol: proto,
	}, nil
}
