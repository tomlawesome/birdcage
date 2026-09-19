package probe

import (
	"context"
	"fmt"
)

// probeSNMP plants marker as the community string in a GetRequest PDU
// (#46 carrier table). SNMP has no session to establish -- the
// community string rides on the very first packet -- so this hand-rolls
// the minimal ASN.1 BER encoding for one SNMPv1 GetRequest of
// sysDescr.0 (1.3.6.1.2.1.1.1.0), a fixed, well-known OID chosen only
// because a GetRequest needs some varbind and OpenCanary's snmp module
// logs the community regardless of which OID is asked for.
func probeSNMP(ctx context.Context, address string, port int, marker string) error {
	conn, err := dialUDP(ctx, address, port)
	if err != nil {
		return err
	}
	// Deferred cleanup after this probe's single write; a failed close
	// here can't change whether the probe itself succeeded.
	defer func() { _ = conn.Close() }()

	// sysDescr.0: 1.3.6.1.2.1.1.1.0, BER-encoded (first two arcs
	// combined as 1*40+3=43=0x2B, remaining arcs each fit one byte).
	sysDescr0 := []byte{0x2B, 0x06, 0x01, 0x02, 0x01, 0x01, 0x01, 0x00}

	varbind := berSeq(concat(berTLV(0x06, sysDescr0), berTLV(0x05, nil)))
	varbindList := berSeq(varbind)

	pdu := berTLV(0xA0, concat(
		berInt(1), // request-id
		berInt(0), // error-status
		berInt(0), // error-index
		varbindList,
	))

	packet := berSeq(concat(
		berInt(0), // version: SNMPv1
		berTLV(0x04, []byte(marker)),
		pdu,
	))

	_, err = conn.Write(packet)
	return err
}

// probeTFTP plants marker as the filename in a TFTP read request (#46
// carrier table). TFTP has no session either: the filename is the
// first thing on the wire, in the RRQ packet -- opcode 1, filename,
// NUL, transfer mode, NUL.
func probeTFTP(ctx context.Context, address string, port int, marker string) error {
	conn, err := dialUDP(ctx, address, port)
	if err != nil {
		return err
	}
	// Deferred cleanup after this probe's single write; a failed close
	// here can't change whether the probe itself succeeded.
	defer func() { _ = conn.Close() }()

	packet := concat(
		[]byte{0x00, 0x01}, // opcode 1: RRQ
		[]byte(marker),
		[]byte{0x00},
		[]byte("octet"),
		[]byte{0x00},
	)
	_, err = conn.Write(packet)
	return err
}

// probeSIP plants marker in the From header's URI user part of a SIP
// OPTIONS request (#46 carrier table: "a header value"). OPTIONS is
// used because it needs no prior registration or session, and its own
// reply (if any) is irrelevant -- OpenCanary's sip module logs the
// request as received.
func probeSIP(ctx context.Context, address string, port int, marker string) error {
	conn, err := dialUDP(ctx, address, port)
	if err != nil {
		return err
	}
	// Deferred cleanup after this probe's single write; a failed close
	// here can't change whether the probe itself succeeded.
	defer func() { _ = conn.Close() }()

	target := fmt.Sprintf("%s:%d", address, port)
	req := "OPTIONS sip:" + target + " SIP/2.0\r\n" +
		"Via: SIP/2.0/UDP " + target + ";branch=z9hG4bK-" + marker + "\r\n" +
		"Max-Forwards: 70\r\n" +
		"To: <sip:probe@" + target + ">\r\n" +
		"From: <sip:" + marker + "@" + target + ">;tag=" + marker + "\r\n" +
		"Call-ID: " + marker + "@" + target + "\r\n" +
		"CSeq: 1 OPTIONS\r\n" +
		"Contact: <sip:probe@" + target + ">\r\n" +
		"Content-Length: 0\r\n\r\n"

	_, err = conn.Write([]byte(req))
	return err
}

// berTLV encodes one ASN.1 BER tag-length-value.
func berTLV(tag byte, content []byte) []byte {
	return concat([]byte{tag}, berLength(len(content)), content)
}

// berSeq wraps content in a SEQUENCE tag (0x30).
func berSeq(content []byte) []byte {
	return berTLV(0x30, content)
}

// berInt encodes a non-negative small integer as an ASN.1 INTEGER.
// Every value this package sends fits one byte, so no two's-complement
// padding is needed.
func berInt(v byte) []byte {
	return berTLV(0x02, []byte{v})
}

// berLength encodes an ASN.1 BER length in the appropriate form: short
// form for the vast majority of fields this package builds, long form
// only if a marker long enough to need it ever comes through --
// selftest.MarkerBytes-derived markers never do, but a hostile or
// future one might, and fail-closed is easier to reason about with a
// correct encoder than a documented assumption never checked.
func berLength(n int) []byte {
	if n < 0x80 {
		return []byte{byte(n)}
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte(n & 0xFF)}, b...)
		n >>= 8
	}
	return append([]byte{byte(0x80 | len(b))}, b...)
}

// concat joins byte slices without the caller needing to pre-size a
// buffer; every packet built in this file is small and built once.
func concat(parts ...[]byte) []byte {
	var out []byte
	for _, p := range parts {
		out = append(out, p...)
	}
	return out
}
