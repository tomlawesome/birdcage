package snmp

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// BER (Basic Encoding Rules) tags this parser recognizes. SNMP v1/v2c
// uses only these: the message and PDU envelopes are SEQUENCEs, the
// version and PDU header fields are INTEGERs, the community string is
// an OCTET STRING, and each varbind names an OBJECT IDENTIFIER.
const (
	tagInteger     = 0x02
	tagOctetString = 0x04
	tagOID         = 0x06
	tagSequence    = 0x30
)

// pduTagMin and pduTagMax bound the context-specific, constructed tags
// RFC 3416 assigns SNMP's PDU types: GetRequest (0xA0) through Report
// (0xA8). This parser does not distinguish which one arrived --
// "log who asked and what they asked for" holds regardless of whether
// the request was a Get, a GetNext or a GetBulk, and all of them share
// the same request-id / [error-status|non-repeaters] /
// [error-index|max-repetitions] / varbind-list shape parseMessage reads.
const (
	pduTagMin = 0xA0
	pduTagMax = 0xA8
)

// Bounds on hostile input. Every one of these exists because this
// parser reads bytes from a port the whole point of this service is to
// invite strangers to attack (see this package's doc comment): a length
// field in the packet is a claim, never a fact, and everything below is
// sized against the buffer actually in hand rather than against what a
// header says should be there.
const (
	// maxCommunityLen bounds the community string. Real ones are a
	// handful of characters; SNMPv1's spec puts no hard cap on the
	// OCTET STRING, so this is a sanity bound rather than a protocol
	// rule -- long enough for any real community or self-test marker
	// (selftest.MarkerBytes hex-encodes to 32 characters), short enough
	// that a hostile "community" cannot itself be the payload of an
	// attack.
	maxCommunityLen = 255

	// maxOIDs caps how many varbinds one message's requests are read
	// from -- the same defence portscan's maxPortsListed is: a message
	// listing thousands of OIDs must cost this parser and the eventual
	// event a bounded amount of work, not one proportional to whatever
	// the attacker sent.
	maxOIDs = 32

	// maxOIDValueLen bounds one OID's own BER encoding. RFC 2578 caps
	// an object identifier at 128 sub-identifiers; even at the
	// generous maxSubIDBytes below, 128 of them fits well inside this.
	maxOIDValueLen = 128

	// maxOIDComponents is RFC 2578's own cap (clause 3.5) on the number
	// of sub-identifiers an object identifier may have.
	maxOIDComponents = 128

	// maxSubIDBytes bounds how many continuation-flagged bytes one
	// base-128 sub-identifier may spend. 5 bytes covers a full 32-bit
	// value (5*7=35 bits) with margin; anything longer is not a real
	// sub-identifier.
	maxSubIDBytes = 5
)

// readTLV reads one BER tag-length-value from the front of b and
// returns its tag, its value (a sub-slice of b, never a copy) and
// whatever of b follows it.
//
// The length is read from the packet but never trusted to size
// anything: it is checked against the bytes actually remaining in b
// before value is sliced out, so a header claiming a length far beyond
// what is really there is refused here rather than turned into an
// out-of-range slice or, were this written differently, an allocation
// sized off attacker input. Indefinite-length BER (a length byte of
// exactly 0x80) is refused too -- real SNMP clients never send it, and
// supporting it would mean scanning forward for an end-of-contents
// marker through content this parser does not otherwise need to look
// inside.
func readTLV(b []byte) (tag byte, value []byte, rest []byte, err error) {
	if len(b) < 2 {
		return 0, nil, nil, errors.New("snmp: truncated TLV header")
	}
	tag = b[0]
	lenByte := b[1]
	headerLen := 2
	var length int
	if lenByte&0x80 == 0 {
		length = int(lenByte)
	} else {
		numLenBytes := int(lenByte & 0x7f)
		if numLenBytes == 0 {
			return 0, nil, nil, errors.New("snmp: indefinite-length BER is not supported")
		}
		if numLenBytes > 4 {
			return 0, nil, nil, errors.New("snmp: length-of-length too large")
		}
		if len(b) < headerLen+numLenBytes {
			return 0, nil, nil, errors.New("snmp: truncated length")
		}
		for _, lb := range b[headerLen : headerLen+numLenBytes] {
			length = length<<8 | int(lb)
		}
		headerLen += numLenBytes
	}
	if length < 0 || headerLen+length > len(b) {
		return 0, nil, nil, errors.New("snmp: declared length exceeds the datagram")
	}
	return tag, b[headerLen : headerLen+length], b[headerLen+length:], nil
}

// decodeInt decodes a BER INTEGER as a signed value, two's-complement,
// most significant byte first. Capped at 8 bytes -- every INTEGER this
// parser reads (version, request-id, error-status, error-index) is a
// small value; a longer encoding is not a real one.
func decodeInt(v []byte) (int64, error) {
	if len(v) == 0 {
		return 0, errors.New("snmp: empty INTEGER")
	}
	if len(v) > 8 {
		return 0, errors.New("snmp: INTEGER too large")
	}
	var n int64
	if v[0]&0x80 != 0 {
		n = -1 // sign-extend with all-ones before folding in the bytes
	}
	for _, b := range v {
		n = n<<8 | int64(b)
	}
	return n, nil
}

// decodeOID renders a BER OBJECT IDENTIFIER as a dotted string. The
// first byte encodes the first two arcs as X*40+Y (X capped at 2 per
// the ASN.1 rule); every byte after that is a base-128, continuation-
// flagged sub-identifier, high bit set on every byte but the last of
// each one.
func decodeOID(v []byte) (string, error) {
	if len(v) == 0 {
		return "", errors.New("snmp: empty OID")
	}
	if len(v) > maxOIDValueLen {
		return "", errors.New("snmp: OID too long")
	}

	comps := make([]uint64, 0, 8)
	first := v[0]
	if first >= 80 {
		comps = append(comps, 2, uint64(first)-80)
	} else {
		comps = append(comps, uint64(first)/40, uint64(first)%40)
	}

	var cur uint64
	bytesInCur := 0
	for _, b := range v[1:] {
		bytesInCur++
		if bytesInCur > maxSubIDBytes {
			return "", errors.New("snmp: OID sub-identifier too long")
		}
		cur = cur<<7 | uint64(b&0x7f)
		if b&0x80 == 0 {
			if len(comps) >= maxOIDComponents {
				return "", errors.New("snmp: OID has too many sub-identifiers")
			}
			comps = append(comps, cur)
			cur = 0
			bytesInCur = 0
		}
	}
	if bytesInCur != 0 {
		return "", errors.New("snmp: OID ends mid sub-identifier")
	}

	var b strings.Builder
	for i, c := range comps {
		if i > 0 {
			b.WriteByte('.')
		}
		b.WriteString(strconv.FormatUint(c, 10))
	}
	return b.String(), nil
}

// extractOIDs reads a VarBindList SEQUENCE OF VarBind and returns the
// name (OID) of every well-formed entry, up to maxOIDs.
//
// Framing and content are deliberately kept separate: advancing to the
// next varbind always uses readTLV's own rest slice, which only depends
// on the tag/length header having parsed, not on the varbind's content
// making sense. A varbind whose OID fails to decode is skipped without
// losing track of where the next one starts; only a header that itself
// fails to parse ends the scan, since at that point there is no longer
// a reliable boundary to resume from.
func extractOIDs(varbindList []byte) []string {
	var oids []string
	data := varbindList
	for len(data) > 0 && len(oids) < maxOIDs {
		tag, vbValue, rest, err := readTLV(data)
		if err != nil {
			break
		}
		data = rest
		if tag != tagSequence {
			continue
		}
		oidTag, oidValue, _, err := readTLV(vbValue)
		if err != nil || oidTag != tagOID {
			continue
		}
		oid, err := decodeOID(oidValue)
		if err != nil {
			continue
		}
		oids = append(oids, oid)
	}
	return oids
}

// parseMessage extracts the community string and requested OIDs from
// one SNMP v1/v2c datagram. Any error means data was not a well-formed
// SNMP v1/v2c request -- malformed, truncated, wrongly typed, an
// unsupported version (SNMPv3 has no plaintext community string to
// read), or simply not SNMP -- and the caller drops it without logging,
// the same as portscan's handle drops an uninteresting packet.
//
// This function never recurses into arbitrary structure: the SNMP
// message shape it reads is fixed and shallow (message, PDU, varbind
// list, varbind, OID -- five levels, all hard-coded here), so there is
// no depth for "absurdly nested" input to exploit. A packet that does
// not match this shape at some level simply fails the tag or length
// check for that level and the whole message is dropped.
func parseMessage(data []byte) (community string, oids []string, err error) {
	tag, msgValue, _, err := readTLV(data)
	if err != nil {
		return "", nil, err
	}
	if tag != tagSequence {
		return "", nil, errors.New("snmp: not a SEQUENCE")
	}

	tag, verValue, rest, err := readTLV(msgValue)
	if err != nil || tag != tagInteger {
		return "", nil, errors.New("snmp: missing version")
	}
	version, err := decodeInt(verValue)
	if err != nil {
		return "", nil, err
	}
	if version != 0 && version != 1 {
		return "", nil, fmt.Errorf("snmp: unsupported version %d", version)
	}

	tag, commValue, rest, err := readTLV(rest)
	if err != nil || tag != tagOctetString {
		return "", nil, errors.New("snmp: missing community string")
	}
	if len(commValue) > maxCommunityLen {
		return "", nil, errors.New("snmp: community string too long")
	}
	community = string(commValue)

	pduTag, pduValue, _, err := readTLV(rest)
	if err != nil || pduTag < pduTagMin || pduTag > pduTagMax {
		return "", nil, errors.New("snmp: missing or unrecognized PDU")
	}

	// request-id, [error-status|non-repeaters], [error-index|
	// max-repetitions]: three INTEGERs regardless of PDU type (RFC
	// 3416 s4.2 vs s4.2.3 -- GetBulkRequest's fields differ in meaning,
	// never in shape), their content unused here.
	cur := pduValue
	for i := 0; i < 3; i++ {
		var t byte
		var r []byte
		t, _, r, err = readTLV(cur)
		if err != nil || t != tagInteger {
			return "", nil, errors.New("snmp: malformed PDU header")
		}
		cur = r
	}

	vbTag, vbValue, _, err := readTLV(cur)
	if err != nil || vbTag != tagSequence {
		return "", nil, errors.New("snmp: missing varbind list")
	}

	return community, extractOIDs(vbValue), nil
}
