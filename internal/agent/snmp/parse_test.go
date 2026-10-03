package snmp

import (
	"encoding/hex"
	"strings"
	"testing"
)

// mustHex decodes a hex literal or fails the test. Every packet below
// carrying a comment naming the real client that produced it was
// captured with tcpdump against that client's own output -- see this
// file's package-level comment for how.
func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("bad hex literal in test: %v", err)
	}
	return b
}

// realV1GetTwoOIDs is a genuine SNMPv1 GetRequest captured from
// net-snmp's own snmpget (Debian package "snmp", version 5.9.4), run
// as:
//
//	snmpget -v1 -c e2e-snmp-marker-0123456789abcdef -r 0 -t 2 \
//	  <target> 1.3.6.1.2.1.1.1.0 1.3.6.1.2.1.1.5.0
//
// captured on the wire with a raw UDP listener printing the datagram's
// hex, exactly what testing-and-ci's "test against the real producer"
// rule asks for: this is not a packet this package's own logic
// produced, so it cannot agree with the parser by construction.
const realV1GetTwoOIDs = "305102010004206532652d736e6d702d6d61726b65722d3031323334353637" +
	"3839616263646566a02a02044bf00523020100020100301c300c06082b0601" +
	"02010101000500300c06082b060102010105000500"

// realV2cGetOneOID is a genuine SNMPv2c GetRequest from the same
// net-snmp client:
//
//	snmpget -v2c -c e2e-v2c-marker -r 0 -t 2 <target> 1.3.6.1.2.1.1.1.0
const realV2cGetOneOID = "3031020101040e6532652d7632632d6d61726b6572a01c0204716917c802" +
	"0100020100300e300c06082b060102010101000500"

func TestParseMessageRealV1Get(t *testing.T) {
	t.Parallel()

	community, oids, err := parseMessage(mustHex(t, realV1GetTwoOIDs))
	if err != nil {
		t.Fatalf("parseMessage: %v", err)
	}
	if community != "e2e-snmp-marker-0123456789abcdef" {
		t.Errorf("community = %q, want the marker net-snmp sent", community)
	}
	want := []string{"1.3.6.1.2.1.1.1.0", "1.3.6.1.2.1.1.5.0"}
	if len(oids) != len(want) {
		t.Fatalf("oids = %v, want %v", oids, want)
	}
	for i := range want {
		if oids[i] != want[i] {
			t.Errorf("oids[%d] = %q, want %q", i, oids[i], want[i])
		}
	}
}

func TestParseMessageRealV2cGet(t *testing.T) {
	t.Parallel()

	community, oids, err := parseMessage(mustHex(t, realV2cGetOneOID))
	if err != nil {
		t.Fatalf("parseMessage: %v", err)
	}
	if community != "e2e-v2c-marker" {
		t.Errorf("community = %q, want e2e-v2c-marker", community)
	}
	if len(oids) != 1 || oids[0] != "1.3.6.1.2.1.1.1.0" {
		t.Errorf("oids = %v, want [1.3.6.1.2.1.1.1.0]", oids)
	}
}

// TestParseMessageHostileInputsAreDroppedNeverPanic is the security
// property this whole package exists for: nothing arriving on the port
// this service invites attacks against may crash or hang the agent.
// Every case here must return an error and must not panic; go test -race
// running these alongside everything else is the hang/crash detector.
func TestParseMessageHostileInputsAreDroppedNeverPanic(t *testing.T) {
	t.Parallel()

	real := mustHex(t, realV1GetTwoOIDs)

	cases := map[string][]byte{
		"empty datagram":                                             {},
		"single byte":                                                {0x30},
		"just a tag and no data":                                     {0x30, 0x00},
		"truncated real packet, half the header":                     real[:5],
		"truncated real packet, mid PDU":                             real[:len(real)-10],
		"truncated real packet, one byte short":                      real[:len(real)-1],
		"wrong outer tag (not a SEQUENCE)":                           append([]byte{0x02}, real[1:]...),
		"huge declared length, short form absent, indefinite marker": {0x30, 0x80, 0x02, 0x01, 0x00},
		"length-of-length claims 4 bytes it does not have":           {0x30, 0x84, 0xFF, 0xFF, 0xFF},
		"length-of-length itself absurd (127 length bytes claimed)":  {0x30, 0xFF, 0x00},
		"declared length far exceeds the datagram":                   {0x30, 0x7F, 0x02, 0x01, 0x00},
		"version field is not an INTEGER":                            {0x30, 0x05, 0x04, 0x03, 'a', 'b', 'c'},
		"unsupported version (v3 = 2)": func() []byte {
			b := append([]byte(nil), real...)
			// The version INTEGER is the third and fourth bytes of the
			// message (tag 0x02, length 0x01) with its value at index 4.
			b[4] = 0x02
			return b
		}(),
		"community string tag is wrong": func() []byte {
			b := append([]byte(nil), real...)
			// Byte 5 is the community OCTET STRING's tag (0x04);
			// corrupt it to an INTEGER tag instead.
			b[5] = 0x02
			return b
		}(),
		"PDU tag out of range (a SEQUENCE where a PDU belongs)": func() []byte {
			b := append([]byte(nil), real...)
			for i, tag := range b {
				if tag == 0xA0 {
					b[i] = 0x30
					break
				}
			}
			return b
		}(),
		"nested rubbish: SEQUENCE of SEQUENCEs of SEQUENCEs, all empty": {
			0x30, 0x08,
			0x30, 0x06,
			0x30, 0x04,
			0x30, 0x02,
			0x30, 0x00,
		},
		"deeply nested SEQUENCE headers with no content, many levels": func() []byte {
			// 64 levels of "SEQUENCE containing one more byte of
			// header, then nothing" -- if this parser recursed
			// generically into nested structure, this is the shape that
			// would blow a stack. It hard-codes a fixed traversal
			// instead, so this must simply fail the first mismatched
			// tag/length check it hits, immediately.
			b := []byte{0x30, 0x02}
			for i := 0; i < 64; i++ {
				b = append([]byte{0x30, byte(len(b))}, b...)
			}
			return b
		}(),
		"all zero bytes": make([]byte, 64),
		"all 0xff bytes": bytesRepeat(0xff, 64),
	}

	for name, packet := range cases {
		name, packet := name, packet
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("parseMessage panicked on %q: %v", name, r)
				}
			}()
			community, oids, err := parseMessage(packet)
			if err == nil {
				t.Fatalf("parseMessage(%q) = (%q, %v, nil), want an error", name, community, oids)
			}
		})
	}
}

func bytesRepeat(b byte, n int) []byte {
	out := make([]byte, n)
	for i := range out {
		out[i] = b
	}
	return out
}

// TestParseMessageOversizeOIDCount proves the OID cap actually bounds
// work and output: a varbind list naming far more OIDs than maxOIDs is
// still accepted (the message itself is well-formed), but only the
// first maxOIDs are returned.
func TestParseMessageOversizeOIDCount(t *testing.T) {
	t.Parallel()

	const n = maxOIDs * 4
	varbinds := make([][]byte, n)
	for i := range varbinds {
		// sysDescr.<i>: reuses 1.3.6.1.2.1.1.1 and varies the final
		// arc, so every varbind is a distinct, validly encoded OID.
		oid := append([]byte{0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x01}, byte(i))
		varbinds[i] = berSeqForTest(concatForTest(berTLVForTest(tagOID, oid), berTLVForTest(0x05, nil)))
	}
	varbindList := berSeqForTest(concatForTest(varbinds...))
	pdu := berTLVForTest(0xA0, concatForTest(
		berIntForTest(1), berIntForTest(0), berIntForTest(0), varbindList,
	))
	packet := berSeqForTest(concatForTest(
		berIntForTest(0),
		berTLVForTest(tagOctetString, []byte("public")),
		pdu,
	))

	_, oids, err := parseMessage(packet)
	if err != nil {
		t.Fatalf("parseMessage: %v", err)
	}
	if len(oids) != maxOIDs {
		t.Fatalf("got %d OIDs from a %d-OID request, want the cap %d", len(oids), n, maxOIDs)
	}
}

// TestParseMessageDropsWhenOIDValueLooksLikeAnAllocationBomb proves the
// "never trust a length field to size an allocation" property directly:
// an OID TLV that declares a length larger than the whole rest of the
// datagram must be refused by readTLV before decodeOID ever sees it,
// not truncated into something decodeOID quietly accepts.
func TestParseMessageDropsWhenOIDValueLooksLikeAnAllocationBomb(t *testing.T) {
	t.Parallel()

	// An OID TLV claiming a 4-byte length of 0x7FFFFFFF, with only two
	// trailing bytes actually present.
	oidTLV := []byte{tagOID, 0x84, 0x7F, 0xFF, 0xFF, 0xFF, 0x2b, 0x06}
	varbind := berSeqForTest(oidTLV)
	varbindList := berSeqForTest(varbind)
	pdu := berTLVForTest(0xA0, concatForTest(
		berIntForTest(1), berIntForTest(0), berIntForTest(0), varbindList,
	))
	packet := berSeqForTest(concatForTest(
		berIntForTest(0),
		berTLVForTest(tagOctetString, []byte("public")),
		pdu,
	))

	// This must not panic and must not somehow report a decoded OID out
	// of two bytes of an allegedly-huge value; extractOIDs (called via
	// parseMessage) should simply find no usable varbind here.
	_, oids, err := parseMessage(packet)
	if err != nil {
		// A message-level failure is also an acceptable outcome, as
		// long as it is a clean error and not a panic or a bogus OID.
		return
	}
	if len(oids) != 0 {
		t.Fatalf("oids = %v, want none from a fabricated over-length OID TLV", oids)
	}
}

// --- tiny BER builders, test-only -------------------------------------
//
// Deliberately separate from probe.go's own berTLV/berSeq/berInt (used
// by the self-test's SNMP carrier): that file builds one fixed,
// well-known request and has no reason to depend on this package, and
// this package's tests have no reason to depend on it back. A few lines
// of duplication here beats a test-only cross-package dependency.

func berTLVForTest(tag byte, content []byte) []byte {
	return concatForTest([]byte{tag}, berLengthForTest(len(content)), content)
}

func berSeqForTest(content []byte) []byte { return berTLVForTest(tagSequence, content) }

func berIntForTest(v byte) []byte { return berTLVForTest(tagInteger, []byte{v}) }

func berLengthForTest(n int) []byte {
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

func concatForTest(parts ...[]byte) []byte {
	var out []byte
	for _, p := range parts {
		out = append(out, p...)
	}
	return out
}

func TestDecodeOIDRoundTripsRealArcs(t *testing.T) {
	t.Parallel()
	// 1.3.6.1.2.1.1.1.0 BER-encoded, taken from the real capture above.
	oid, err := decodeOID([]byte{0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x01, 0x00})
	if err != nil {
		t.Fatalf("decodeOID: %v", err)
	}
	if oid != "1.3.6.1.2.1.1.1.0" {
		t.Fatalf("decodeOID = %q, want 1.3.6.1.2.1.1.1.0", oid)
	}
}

func TestDecodeOIDRejectsUnterminatedSubIdentifier(t *testing.T) {
	t.Parallel()
	// Continuation bit set on the last byte -- there is no terminating
	// byte, which must be an error, never a value that silently drops
	// the unfinished arc.
	_, err := decodeOID([]byte{0x2b, 0x86})
	if err == nil {
		t.Fatal("decodeOID accepted an OID that ends mid sub-identifier")
	}
	if !strings.Contains(err.Error(), "mid sub-identifier") {
		t.Fatalf("decodeOID error = %v, want it to name the real defect", err)
	}
}
