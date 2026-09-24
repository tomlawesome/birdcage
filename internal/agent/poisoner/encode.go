package poisoner

import (
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
)

// Protocol names one of the three ways a client asks the local segment
// for a name. It is the value that reaches the alert's PROTOCOL field, so
// the strings are the ones an operator reads on the dashboard.
type Protocol string

// The three protocols. Lower case, because they are wire-protocol names
// on a dashboard, not acronyms to shout.
const (
	ProtocolLLMNR Protocol = "llmnr"
	ProtocolNBNS  Protocol = "nbt-ns"
	ProtocolMDNS  Protocol = "mdns"
)

// Query record types, from the DNS type registry (RFC 1035 section 3.2.2
// for A, RFC 3596 section 2.1 for AAAA). LLMNR and mDNS both carry DNS
// question sections verbatim, so both use these.
const (
	typeA    uint16 = 1
	typeAAAA uint16 = 28
)

// classIN is the DNS IN class (RFC 1035 section 3.2.4). NBT-NS reuses the
// same value for its QUESTION_CLASS (RFC 1002 section 4.2.12, "IN").
const classIN uint16 = 0x0001

// mdnsUnicastResponseBit is the QU bit: RFC 6762 section 5.4 puts "the
// currently unused top bit of the qclass field" to work asking for a
// unicast reply, which a one-shot query (as opposed to a continuous
// browse) SHOULD set. Windows' own name resolution does not set it; a
// systemd-resolved one-shot lookup does, which is why it is a per-profile
// knob rather than a constant.
const mdnsUnicastResponseBit uint16 = 0x8000

// llmnrQueryFlags is the LLMNR header's second 16-bit word for a query.
// RFC 4795 section 2.1.1 lays the header out as DNS does but renames the
// bits: QR, OPCODE(4), C, TC, T, Z(4), RCODE(4). A query has every one of
// them clear -- QR=0 because it is a query, OPCODE=0 for a standard
// query, and no C (conflict), TC (truncation) or T (tentative).
//
// Zero is also what separates an LLMNR query on the wire from a DNS one:
// a DNS resolver sets RD, giving 0x0100, and LLMNR has no RD bit at all.
// Sending 0x0100 here would be the "not quite Windows" shape the research
// note warns about.
const llmnrQueryFlags uint16 = 0x0000

// mdnsQueryFlags is the mDNS header's flags word for a query: zero.
// RFC 6762 section 18.2 requires OPCODE 0 in a multicast DNS query,
// section 18.3 requires RD to be ignored, and 18.4 to 18.11 leave the
// rest clear for a query. The same "no RD" reasoning as LLMNR applies.
const mdnsQueryFlags uint16 = 0x0000

// mdnsQueryID is the transaction id in a multicast mDNS query. RFC 6762
// section 18.1: "In multicast query messages, the Query Identifier
// SHOULD be set to zero on transmission." A random id here would be the
// giveaway, not the disguise.
//
// It also means an mDNS reply cannot be matched to one outstanding query
// by id the way LLMNR's can -- see matchOutstanding in poisoner.go for
// what is matched instead.
const mdnsQueryID uint16 = 0x0000

// nbnsBroadcastQueryFlags is the NBT-NS header's second word for a
// broadcast NAME QUERY REQUEST. RFC 1002 section 4.2.1.1 lays the 16 bits
// out most-significant first as R(1), OPCODE(4), NM_FLAGS(7), RCODE(4),
// and section 4.2.12 says a name query request sets R=0, OPCODE=0
// (query), RD=1 and, when broadcast, B=1.
//
// NM_FLAGS occupies bits 5 to 11, in the order AA, TC, RD, RA, 0, 0, B --
// so RD is bit 7, worth 1<<(15-7) = 0x0100, and B is bit 11, worth
// 1<<(15-11) = 0x0010. Together 0x0110, which is what a capture of a
// Windows NBNS broadcast query shows.
const nbnsBroadcastQueryFlags uint16 = 0x0110

// nbnsTypeNB is NBT-NS QUESTION_TYPE "NB", a general name service
// resource record (RFC 1002 section 4.2.12: NB is 0x0020). Not NBSTAT
// (0x0021), which asks for a node's whole name table -- that is a
// scanner's question, not a client resolving a name.
const nbnsTypeNB uint16 = 0x0020

// NetBIOS name geometry, RFC 1001 section 4.1 and RFC 1002 section 4.2.1.2.
const (
	// nbnsNameLen is the fixed width of a NetBIOS name: 16 bytes, the
	// last of which is the service suffix.
	nbnsNameLen = 16

	// nbnsNamePadLen is how many of those 16 bytes carry the name
	// itself, space-padded on the right.
	nbnsNamePadLen = 15

	// nbnsSuffixWorkstation is the suffix byte for the workstation /
	// redirector service -- what a client resolving a machine name asks
	// for. 0x00 in Microsoft's NetBIOS suffix table.
	nbnsSuffixWorkstation = 0x00

	// nbnsEncodedLen is the first-level-encoded length: each of the 16
	// bytes becomes two characters, so 32.
	nbnsEncodedLen = nbnsNameLen * 2

	// nbnsEncodeBase is the character the two half-octets are added to.
	// RFC 1001 section 4.1: "each half-octet of the NetBIOS name is
	// encoded into one byte of the 32-byte field ... by adding the ASCII
	// value of 'A'".
	nbnsEncodeBase = 'A'
)

// mdnsTopLevelDomain is the label mDNS names live under: RFC 6762
// section 3 reserves ".local." for link-local multicast name resolution.
const mdnsTopLevelDomain = "local"

// dnsHeaderLen is the fixed DNS message header, shared by LLMNR, mDNS and
// NBT-NS: six 16-bit words (RFC 1035 section 4.1.1, RFC 1002 section
// 4.2.1.1).
const dnsHeaderLen = 12

// maxLabelLen is the DNS limit on one label (RFC 1035 section 2.3.4,
// "labels 63 octets or less"). A bait name is a single label, so this is
// also the longest one can be before encoding refuses it -- though
// validName in name.go already holds bait names to NetBIOS' much shorter
// 15.
const maxLabelLen = 63

// errEmptyName is returned rather than encoding a zero-length label,
// which would terminate the name and produce a query for the root.
var errEmptyName = errors.New("poisoner: empty query name")

// encodeLLMNRQuery builds one LLMNR query for name (a single label, no
// domain) and record type qtype.
//
// RFC 4795 section 2.1: an LLMNR query is a DNS message with QDCOUNT 1
// and every other count zero. The name is sent as the single label it is
// -- LLMNR exists precisely for the names DNS has no suffix for -- so no
// search domain is appended.
func encodeLLMNRQuery(id uint16, name string, qtype uint16) ([]byte, error) {
	qname, err := encodeLabels(name)
	if err != nil {
		return nil, err
	}
	return dnsQuery(id, llmnrQueryFlags, qname, qtype, classIN), nil
}

// encodeMDNSQuery builds one mDNS query for name, which it puts under
// ".local" (RFC 6762 section 3). unicastResponse sets the QU bit
// described at mdnsUnicastResponseBit.
//
// The transaction id is not a parameter: RFC 6762 section 18.1 pins it to
// zero for a multicast query, and mdnsQueryID is that zero.
func encodeMDNSQuery(name string, qtype uint16, unicastResponse bool) ([]byte, error) {
	qname, err := encodeLabels(name, mdnsTopLevelDomain)
	if err != nil {
		return nil, err
	}
	qclass := classIN
	if unicastResponse {
		qclass |= mdnsUnicastResponseBit
	}
	return dnsQuery(mdnsQueryID, mdnsQueryFlags, qname, qtype, qclass), nil
}

// encodeNBNSQuery builds one NBT-NS broadcast NAME QUERY REQUEST for
// name.
//
// RFC 1002 section 4.2.12 gives the shape: the standard 12-byte header
// with QDCOUNT 1, then a QUESTION_NAME in the first-level encoding of
// RFC 1001 section 4.1, QUESTION_TYPE NB and QUESTION_CLASS IN.
func encodeNBNSQuery(id uint16, name string) ([]byte, error) {
	qname, err := encodeNBNSName(name, nbnsSuffixWorkstation)
	if err != nil {
		return nil, err
	}
	return dnsQuery(id, nbnsBroadcastQueryFlags, qname, nbnsTypeNB, classIN), nil
}

// dnsQuery assembles a header plus a one-question section. Shared by all
// three protocols because all three carry the same header and the same
// question layout; only the flags word, the name encoding and the type
// differ, and those are the caller's.
func dnsQuery(id, flags uint16, qname []byte, qtype, qclass uint16) []byte {
	msg := make([]byte, 0, dnsHeaderLen+len(qname)+4)
	msg = binary.BigEndian.AppendUint16(msg, id)
	msg = binary.BigEndian.AppendUint16(msg, flags)
	msg = binary.BigEndian.AppendUint16(msg, 1) // QDCOUNT: one question
	msg = binary.BigEndian.AppendUint16(msg, 0) // ANCOUNT
	msg = binary.BigEndian.AppendUint16(msg, 0) // NSCOUNT
	msg = binary.BigEndian.AppendUint16(msg, 0) // ARCOUNT
	msg = append(msg, qname...)
	msg = binary.BigEndian.AppendUint16(msg, qtype)
	msg = binary.BigEndian.AppendUint16(msg, qclass)
	return msg
}

// encodeLabels renders labels as a DNS QNAME: each label prefixed by its
// own length, the whole terminated by a zero byte (RFC 1035 section
// 4.1.2). No compression pointer is ever emitted -- there is nothing in a
// one-question message to point at, and Windows emits none here either.
func encodeLabels(labels ...string) ([]byte, error) {
	out := make([]byte, 0, 32)
	for _, label := range labels {
		if label == "" {
			return nil, errEmptyName
		}
		if len(label) > maxLabelLen {
			return nil, fmt.Errorf("poisoner: query label is %d bytes, over the %d-byte limit", len(label), maxLabelLen)
		}
		out = append(out, byte(len(label)))
		out = append(out, label...)
	}
	if len(out) == 0 {
		return nil, errEmptyName
	}
	return append(out, 0), nil
}

// encodeNBNSName renders name in NetBIOS first-level encoding with the
// given service suffix, in the form a question section carries it: a
// length byte of 32, the 32 encoded characters, then the root scope
// (RFC 1002 section 4.2.1.2 -- "the NetBIOS scope identifier is a
// standard domain name"; the root scope every Windows client on a
// default configuration uses is the empty one, a single zero byte).
//
// The name is upper-cased first. RFC 1001 section 4.1 calls NetBIOS names
// case-sensitive, but Windows upper-cases them before encoding and a
// lower-case NBNS query would stand out on a capture for exactly that
// reason.
func encodeNBNSName(name string, suffix byte) ([]byte, error) {
	if name == "" {
		return nil, errEmptyName
	}
	upper := strings.ToUpper(name)
	if len(upper) > nbnsNamePadLen {
		return nil, fmt.Errorf("poisoner: %d-character name does not fit a %d-character NetBIOS name", len(upper), nbnsNamePadLen)
	}

	// The 16 raw bytes: the name, right-padded with spaces to 15, then
	// the suffix (RFC 1002 section 4.2.1.2's "NetBIOS name ... padded
	// with space characters").
	raw := make([]byte, nbnsNameLen)
	copy(raw, upper)
	for i := len(upper); i < nbnsNamePadLen; i++ {
		raw[i] = ' '
	}
	raw[nbnsNamePadLen] = suffix

	// First-level encoding: high half-octet first, each half plus 'A'.
	out := make([]byte, 0, 1+nbnsEncodedLen+1)
	out = append(out, nbnsEncodedLen)
	for _, b := range raw {
		out = append(out, nbnsEncodeBase+(b>>4), nbnsEncodeBase+(b&0x0f))
	}
	return append(out, 0), nil
}

// decodeNBNSName reverses encodeNBNSName's 32-character field, returning
// the trimmed name and its suffix byte. Used only to read a reply's
// question section back, so it is strict about the alphabet: anything
// outside 'A' to 'P' is not first-level encoding and the datagram is not
// a NBT-NS message this agent sent.
func decodeNBNSName(encoded []byte) (string, byte, error) {
	if len(encoded) != nbnsEncodedLen {
		return "", 0, fmt.Errorf("poisoner: netbios name field is %d bytes, want %d", len(encoded), nbnsEncodedLen)
	}
	raw := make([]byte, nbnsNameLen)
	for i := range raw {
		hi := encoded[2*i] - nbnsEncodeBase
		lo := encoded[2*i+1] - nbnsEncodeBase
		if hi > 0x0f || lo > 0x0f {
			return "", 0, errors.New("poisoner: netbios name field is not first-level encoded")
		}
		raw[i] = hi<<4 | lo
	}
	return strings.TrimRight(string(raw[:nbnsNamePadLen]), " "), raw[nbnsNamePadLen], nil
}
