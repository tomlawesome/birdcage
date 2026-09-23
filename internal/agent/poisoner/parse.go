package poisoner

import (
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
)

// MaxDatagramLen caps one read from any of this package's sockets, and so
// the largest reply the parser below will look at. Issue #86 design point
// 6 sets it: 512 bytes is the classic DNS-over-UDP message limit (RFC
// 1035 section 4.2.1) and more than any LLMNR, mDNS or NBT-NS answer to a
// one-question query needs. A larger datagram is truncated by the read,
// so the length fields inside it stop agreeing with the data in hand and
// the parse fails -- the malformed case, dropped.
const MaxDatagramLen = 512

// Bounds on name decoding. Every one of these exists because the bytes
// being decoded arrived unsolicited from a host this agent has just
// invited to lie to it.
const (
	// maxNameLen is the DNS limit on a whole domain name (RFC 1035
	// section 2.3.4, "names 255 octets or less"), counting the length
	// bytes. A decoded name longer than this is not a name.
	maxNameLen = 255

	// maxNameJumps bounds how many compression pointers one name may
	// follow. A pointer must already point strictly backwards (see
	// readName), which makes an infinite loop impossible on its own;
	// this is the second bound, so that a chain of thousands of
	// one-byte-back pointers cannot cost more than a fixed amount of
	// work either.
	maxNameJumps = 16

	// compressionMask and compressionOffsetMask split a name's leading
	// byte. RFC 1035 section 4.1.4: the two high bits set (0xc0) mark a
	// pointer, and the remaining 14 bits are the offset.
	compressionMask       = 0xc0
	compressionOffsetMask = 0x3fff
)

// headerFlagResponse is the QR bit (RFC 1035 section 4.1.1), set in a
// response. NBT-NS calls the same bit R (RFC 1002 section 4.2.1.1) and
// uses it the same way.
const headerFlagResponse uint16 = 0x8000

// reply is what the parser extracts from one datagram. Deliberately
// small: the transaction id and the question name are all that is used,
// and both only to decide whether the datagram is an answer to something
// this agent asked. The answer records -- the addresses the poisoner is
// offering -- are never decoded, because nothing here may act on them
// (issue #86 design point 6) and a record this code does not read is a
// record it cannot be tricked by.
type reply struct {
	// ID is the transaction id the datagram carries.
	ID uint16

	// Name is the question section's name, lower-cased, with any
	// trailing ".local" from an mDNS reply already stripped. Used only
	// to check the datagram answers a name this agent asked for; the
	// name that reaches the alert comes from the agent's own record.
	Name string

	// Answers is the datagram's ANCOUNT. A response with no answer at
	// all is not a poisoning, so the caller requires at least one.
	Answers uint16
}

// parseDNSReply reads an LLMNR or mDNS reply. Both carry plain DNS
// messages (RFC 4795 section 2.1, RFC 6762 section 18), so one parser
// serves both.
func parseDNSReply(b []byte) (reply, error) {
	hdr, off, err := parseHeader(b)
	if err != nil {
		return reply{}, err
	}
	// QDCOUNT 0 and 1 are both ordinary, and which one appears is the
	// difference between the two protocols that share this parser:
	//
	//   - LLMNR echoes the question back (RFC 4795 section 2.1), so a
	//     reply has QDCOUNT 1.
	//   - mDNS does not: RFC 6762 section 6 is explicit that "Multicast
	//     DNS responses MUST NOT contain any questions", so a reply has
	//     QDCOUNT 0 and the name is in the first answer record.
	//
	// Requiring exactly one question here made this parser silently drop
	// every real mDNS answer. It was caught by running Responder against
	// the real encoders rather than by reading the RFC (the journey in
	// scripts/e2e/poisoner.sh is what keeps it caught).
	//
	// Either way the name this function wants is the first one after the
	// header, because a question's QNAME and a resource record's NAME are
	// the same encoding in the same place.
	if hdr.questions > 1 {
		return reply{}, fmt.Errorf("poisoner: reply carries %d questions, want 0 or 1", hdr.questions)
	}
	if hdr.questions == 0 && hdr.answers == 0 {
		// Nothing to read a name from, and nothing being claimed either.
		return reply{}, errors.New("poisoner: reply carries neither a question nor an answer")
	}
	name, end, err := readName(b, off)
	if err != nil {
		return reply{}, err
	}
	// Whatever follows the name -- a question's QTYPE/QCLASS, or a
	// record's TYPE/CLASS -- is not read: a reply is free to answer
	// either the A or the AAAA twin, and issue #86 design point 6 says to
	// act only on a reply's source, never its content. But four bytes of
	// it must be present, because a section short of them means a
	// truncated datagram, which is the malformed case.
	if end+4 > len(b) {
		return reply{}, errors.New("poisoner: the section after the name is truncated")
	}
	return reply{ID: hdr.id, Name: trimLocal(name), Answers: hdr.answers}, nil
}

// parseNBNSReply reads a NBT-NS NAME QUERY RESPONSE (RFC 1002 section
// 4.2.13). The header is the same twelve bytes; the question name is the
// first-level encoding of RFC 1001 section 4.1 rather than plain labels.
//
// A positive name query response echoes the name in its ANSWER section
// rather than a question section, so a compliant one has QDCOUNT 0 --
// which is why, unlike parseDNSReply, this accepts either and reads the
// name from whichever section is present. Responder sends QDCOUNT 0 with
// one answer record.
func parseNBNSReply(b []byte) (reply, error) {
	hdr, off, err := parseHeader(b)
	if err != nil {
		return reply{}, err
	}
	if hdr.questions > 1 {
		return reply{}, fmt.Errorf("poisoner: nbt-ns reply carries %d questions, want 0 or 1", hdr.questions)
	}
	// Whether the name sits in a question section or an answer record,
	// it is the first field after the header in both shapes (RFC 1002
	// sections 4.2.12 and 4.2.13: QUESTION_NAME and RR_NAME are the
	// same encoded form in the same place).
	encoded, _, err := readNBNSNameField(b, off)
	if err != nil {
		return reply{}, err
	}
	name, _, err := decodeNBNSName(encoded)
	if err != nil {
		return reply{}, err
	}
	return reply{ID: hdr.id, Name: strings.ToLower(name), Answers: hdr.answers}, nil
}

// header is the twelve-byte message header, as much of it as this package
// reads.
type header struct {
	id        uint16
	flags     uint16
	questions uint16
	answers   uint16
}

// parseHeader checks the datagram's size and reads its header, refusing
// anything that is not a response. It returns the offset just past the
// header as well, so a caller does not repeat the constant.
func parseHeader(b []byte) (header, int, error) {
	if len(b) > MaxDatagramLen {
		return header{}, 0, fmt.Errorf("poisoner: datagram is %d bytes, over the %d-byte cap", len(b), MaxDatagramLen)
	}
	if len(b) < dnsHeaderLen {
		return header{}, 0, errors.New("poisoner: datagram is shorter than a message header")
	}
	hdr := header{
		id:        binary.BigEndian.Uint16(b[0:2]),
		flags:     binary.BigEndian.Uint16(b[2:4]),
		questions: binary.BigEndian.Uint16(b[4:6]),
		answers:   binary.BigEndian.Uint16(b[6:8]),
	}
	if hdr.flags&headerFlagResponse == 0 {
		// Another host's query, not an answer to ours. On the query
		// sockets this should not happen at all (see this package's
		// comment on which socket sees what); dropped rather than
		// reasoned about.
		return header{}, 0, errors.New("poisoner: datagram is a query, not a response")
	}
	return hdr, dnsHeaderLen, nil
}

// readName decodes a DNS name starting at off, returning the name in
// dotted form (lower-cased, no trailing dot) and the offset of the first
// byte after the name *as encoded at off* -- which, when the name ends in
// a compression pointer, is the byte after that pointer, not after
// whatever it pointed at.
//
// The compression rule issue #86 design point 6 asks for is enforced
// here: a pointer must point strictly backwards, to an offset lower than
// the position of the pointer itself. That refuses a forward pointer
// (which no encoder can legitimately emit, and which is how a
// crafted message walks a parser off the end) and a self-referential one
// in the same test, so no loop is representable. maxNameJumps bounds the
// work a legal backwards chain can cost.
func readName(b []byte, off int) (string, int, error) {
	var sb strings.Builder
	var end int
	jumps := 0
	total := 0

	for {
		if off < 0 || off >= len(b) {
			return "", 0, errors.New("poisoner: name runs past the end of the datagram")
		}
		n := int(b[off])

		if n&compressionMask == compressionMask {
			if off+1 >= len(b) {
				return "", 0, errors.New("poisoner: compression pointer is truncated")
			}
			target := int(binary.BigEndian.Uint16(b[off:off+2]) & compressionOffsetMask)
			if target >= off {
				return "", 0, fmt.Errorf("poisoner: compression pointer at %d points to %d, which is not strictly backwards", off, target)
			}
			if jumps++; jumps > maxNameJumps {
				return "", 0, errors.New("poisoner: too many compression pointers in one name")
			}
			if end == 0 {
				// The first pointer is where the name ends on the wire;
				// later ones are inside what it pointed at.
				end = off + 2
			}
			off = target
			continue
		}
		if n&compressionMask != 0 {
			// 0x40 and 0x80 are reserved label types (RFC 1035 section
			// 4.1.4 defines only 00 and 11).
			return "", 0, fmt.Errorf("poisoner: reserved label type 0x%02x in a name", n&compressionMask)
		}
		if n == 0 {
			if end == 0 {
				end = off + 1
			}
			return sb.String(), end, nil
		}
		if off+1+n > len(b) {
			return "", 0, errors.New("poisoner: label runs past the end of the datagram")
		}
		total += n + 1
		if total > maxNameLen {
			return "", 0, fmt.Errorf("poisoner: name is over the %d-byte limit", maxNameLen)
		}
		if sb.Len() > 0 {
			sb.WriteByte('.')
		}
		sb.Write(lowerASCII(b[off+1 : off+1+n]))
		off += 1 + n
	}
}

// readNBNSNameField reads a NetBIOS name field at off -- a length byte of
// 32, the 32 encoded characters, and the scope, which this only has to
// skip. It returns the 32 encoded characters and the offset past the
// whole field.
//
// A NBT-NS name may itself be a compression pointer (RFC 1002 section
// 4.2.1.2 allows the scope to be compressed, and implementations compress
// the name too), so a pointer is followed once, under the same
// strictly-backwards rule readName applies.
func readNBNSNameField(b []byte, off int) ([]byte, int, error) {
	if off >= len(b) {
		return nil, 0, errors.New("poisoner: netbios name runs past the end of the datagram")
	}
	end := 0
	if b[off]&compressionMask == compressionMask {
		if off+1 >= len(b) {
			return nil, 0, errors.New("poisoner: netbios name pointer is truncated")
		}
		target := int(binary.BigEndian.Uint16(b[off:off+2]) & compressionOffsetMask)
		if target >= off {
			return nil, 0, fmt.Errorf("poisoner: netbios name pointer at %d points to %d, which is not strictly backwards", off, target)
		}
		end = off + 2
		off = target
		if off >= len(b) {
			return nil, 0, errors.New("poisoner: netbios name pointer target is past the end of the datagram")
		}
		if b[off]&compressionMask == compressionMask {
			// One hop only. A chain here buys a sender nothing a single
			// pointer does not, and refusing it keeps this function's
			// bound obvious.
			return nil, 0, errors.New("poisoner: netbios name pointer chains to another pointer")
		}
	}
	if int(b[off]) != nbnsEncodedLen {
		return nil, 0, fmt.Errorf("poisoner: netbios name length is %d, want %d", b[off], nbnsEncodedLen)
	}
	start := off + 1
	if start+nbnsEncodedLen > len(b) {
		return nil, 0, errors.New("poisoner: netbios name runs past the end of the datagram")
	}
	encoded := b[start : start+nbnsEncodedLen]
	if end == 0 {
		// Past the encoded name and its scope terminator. The scope is a
		// domain name; only the root scope (a single zero byte) is
		// accepted, because that is the only one a default Windows
		// configuration -- or this package's own encoder -- sends.
		scope := start + nbnsEncodedLen
		if scope >= len(b) || b[scope] != 0 {
			return nil, 0, errors.New("poisoner: netbios name is not in the root scope")
		}
		end = scope + 1
	}
	return encoded, end, nil
}

// trimLocal strips the ".local" mDNS names carry (RFC 6762 section 3) so
// a reply's name can be compared with the bare bait name that was asked
// for. An LLMNR name has no suffix to strip.
func trimLocal(name string) string {
	return strings.TrimSuffix(name, "."+mdnsTopLevelDomain)
}

// lowerASCII lower-cases a label in place in a fresh slice. Names are
// compared case-insensitively (RFC 4343 for DNS; RFC 6762 section 16
// repeats it for mDNS), and a reply is free to change the case of what it
// echoes -- Responder does not, but matching must not depend on that.
// Only ASCII is folded: a byte outside A-Z is copied unchanged, so this
// cannot mangle a non-ASCII label into a different one.
func lowerASCII(b []byte) []byte {
	out := make([]byte, len(b))
	for i, c := range b {
		if c >= 'A' && c <= 'Z' {
			c += 'a' - 'A'
		}
		out[i] = c
	}
	return out
}
