package poisoner

import (
	"bytes"
	"strings"
	"testing"
)

// Every want below is written out byte by byte from the protocol
// specification, not captured from this package's own output: the value of
// the shape is that it matches what a real client sends, so a test that
// only agreed with the encoder would prove nothing.

// TestEncodeLLMNRQueryBytes builds the exact datagram RFC 4795 section
// 2.1 describes for a single-label A query, and again for its AAAA twin.
func TestEncodeLLMNRQueryBytes(t *testing.T) {
	tests := []struct {
		name  string
		id    uint16
		qname string
		qtype uint16
		want  []byte
	}{
		{
			name:  "A record",
			id:    0x1234,
			qname: "fs-lon-02",
			qtype: typeA,
			want: []byte{
				0x12, 0x34, // ID, as given
				0x00, 0x00, // flags: QR=0, OPCODE=0, C=0, TC=0, T=0, RCODE=0 (RFC 4795 2.1.1) -- no RD bit exists, so a DNS query's 0x0100 would be wrong here
				0x00, 0x01, // QDCOUNT 1
				0x00, 0x00, // ANCOUNT 0
				0x00, 0x00, // NSCOUNT 0
				0x00, 0x00, // ARCOUNT 0
				0x09, 'f', 's', '-', 'l', 'o', 'n', '-', '0', '2', // one 9-byte label (RFC 1035 4.1.2)
				0x00,       // root: end of QNAME
				0x00, 0x01, // QTYPE A (RFC 1035 3.2.2)
				0x00, 0x01, // QCLASS IN (RFC 1035 3.2.4)
			},
		},
		{
			name:  "AAAA twin",
			id:    0xabcd,
			qname: "wpad",
			qtype: typeAAAA,
			want: []byte{
				0xab, 0xcd,
				0x00, 0x00,
				0x00, 0x01,
				0x00, 0x00,
				0x00, 0x00,
				0x00, 0x00,
				0x04, 'w', 'p', 'a', 'd',
				0x00,
				0x00, 0x1c, // QTYPE AAAA = 28 (RFC 3596 2.1)
				0x00, 0x01,
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := encodeLLMNRQuery(tc.id, tc.qname, tc.qtype)
			if err != nil {
				t.Fatalf("encodeLLMNRQuery: %v", err)
			}
			if !bytes.Equal(got, tc.want) {
				t.Errorf("bytes differ\n got %x\nwant %x", got, tc.want)
			}
		})
	}
}

// TestEncodeMDNSQueryBytes checks the ".local" suffix, the zero
// transaction id RFC 6762 section 18.1 requires of a multicast query, and
// the QU bit of section 5.4.
func TestEncodeMDNSQueryBytes(t *testing.T) {
	tests := []struct {
		name            string
		qname           string
		qtype           uint16
		unicastResponse bool
		want            []byte
	}{
		{
			name:  "multicast response requested",
			qname: "fs-lon-07",
			qtype: typeA,
			want: []byte{
				0x00, 0x00, // ID zero (RFC 6762 18.1: SHOULD be zero in a multicast query)
				0x00, 0x00, // flags zero: QR=0, OPCODE=0 (RFC 6762 18.2)
				0x00, 0x01, // QDCOUNT 1
				0x00, 0x00,
				0x00, 0x00,
				0x00, 0x00,
				0x09, 'f', 's', '-', 'l', 'o', 'n', '-', '0', '7',
				0x05, 'l', 'o', 'c', 'a', 'l', // the .local domain (RFC 6762 3)
				0x00,
				0x00, 0x01, // QTYPE A
				0x00, 0x01, // QCLASS IN, QU bit clear
			},
		},
		{
			name:            "unicast response requested",
			qname:           "wpad",
			qtype:           typeAAAA,
			unicastResponse: true,
			want: []byte{
				0x00, 0x00,
				0x00, 0x00,
				0x00, 0x01,
				0x00, 0x00,
				0x00, 0x00,
				0x00, 0x00,
				0x04, 'w', 'p', 'a', 'd',
				0x05, 'l', 'o', 'c', 'a', 'l',
				0x00,
				0x00, 0x1c, // QTYPE AAAA
				0x80, 0x01, // QCLASS IN with the QU bit set (RFC 6762 5.4)
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := encodeMDNSQuery(tc.qname, tc.qtype, tc.unicastResponse)
			if err != nil {
				t.Fatalf("encodeMDNSQuery: %v", err)
			}
			if !bytes.Equal(got, tc.want) {
				t.Errorf("bytes differ\n got %x\nwant %x", got, tc.want)
			}
		})
	}
}

// TestEncodeNBNSQueryBytes is the one worth spelling out in full: the
// first-level encoding of RFC 1001 section 4.1 is the step an
// implementation gets wrong, and the 0x0110 flags word is the one a
// scanner gets wrong.
//
// "FS-LON-02" padded to fifteen characters with spaces plus a 0x00
// workstation suffix is
//
//	46 53 2d 4c 4f 4e 2d 30 32 20 20 20 20 20 20 00
//
// and each half-octet plus 'A' (0x41) gives, high nibble first:
//
//	4->'E' 6->'G'  5->'F' 3->'D'  2->'C' d->'N'  4->'E' c->'M'
//	4->'E' f->'P'  4->'E' e->'O'  2->'C' d->'N'  3->'D' 0->'A'
//	3->'D' 2->'C'  2->'C' 0->'A'  (x6 for the six spaces)  0->'A' 0->'A'
func TestEncodeNBNSQueryBytes(t *testing.T) {
	want := []byte{
		0x00, 0x2a, // NAME_TRN_ID, as given
		0x01, 0x10, // R=0, OPCODE=0 (query), RD=1 (bit 7), B=1 (bit 11) -- RFC 1002 4.2.1.1 and 4.2.12
		0x00, 0x01, // QDCOUNT 1
		0x00, 0x00, // ANCOUNT 0
		0x00, 0x00, // NSCOUNT 0
		0x00, 0x00, // ARCOUNT 0
		0x20, // QUESTION_NAME length: 32 encoded characters
	}
	// 18 characters for "FS-LON-02", 12 for the six pad spaces, 2 for the
	// 0x00 suffix: 32 in all.
	encoded := "EGFDCNEMEPEOCNDADC" + "CACACACACACA" + "AA"
	if len(encoded) != nbnsEncodedLen {
		t.Fatalf("the hand-written expectation is %d characters, not %d", len(encoded), nbnsEncodedLen)
	}
	want = append(want, encoded...)
	want = append(want,
		0x00,       // root scope
		0x00, 0x20, // QUESTION_TYPE NB (RFC 1002 4.2.12)
		0x00, 0x01, // QUESTION_CLASS IN
	)

	got, err := encodeNBNSQuery(0x002a, "fs-lon-02")
	if err != nil {
		t.Fatalf("encodeNBNSQuery: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("bytes differ\n got %x\nwant %x", got, want)
	}
	// The name is upper-cased on the way in: a lower-case NBNS query
	// would stand out on a capture.
	upper, err := encodeNBNSQuery(0x002a, "FS-LON-02")
	if err != nil {
		t.Fatalf("encodeNBNSQuery upper: %v", err)
	}
	if !bytes.Equal(upper, got) {
		t.Error("case of the bait name changed the encoded query")
	}
}

// TestEncodeNBNSNameRoundTrip proves decodeNBNSName reverses the encoder
// for every length a bait name may have, suffix included.
func TestEncodeNBNSNameRoundTrip(t *testing.T) {
	for _, name := range []string{"A", "WPAD", "FS-LON-02", "ABCDEFGHIJKLMNO"} {
		encoded, err := encodeNBNSName(name, nbnsSuffixWorkstation)
		if err != nil {
			t.Fatalf("encodeNBNSName(%q): %v", name, err)
		}
		// One length byte, 32 characters, one scope byte.
		if len(encoded) != 1+nbnsEncodedLen+1 {
			t.Fatalf("encodeNBNSName(%q) produced %d bytes, want %d", name, len(encoded), 1+nbnsEncodedLen+1)
		}
		if encoded[0] != nbnsEncodedLen {
			t.Errorf("encodeNBNSName(%q) length byte = %d, want %d", name, encoded[0], nbnsEncodedLen)
		}
		if encoded[len(encoded)-1] != 0 {
			t.Errorf("encodeNBNSName(%q) does not end in the root scope", name)
		}
		for i, c := range encoded[1 : 1+nbnsEncodedLen] {
			if c < 'A' || c > 'P' {
				t.Fatalf("encodeNBNSName(%q) character %d is %q, outside A-P", name, i, c)
			}
		}
		got, suffix, err := decodeNBNSName(encoded[1 : 1+nbnsEncodedLen])
		if err != nil {
			t.Fatalf("decodeNBNSName(%q): %v", name, err)
		}
		if got != name {
			t.Errorf("round trip of %q gave %q", name, got)
		}
		if suffix != nbnsSuffixWorkstation {
			t.Errorf("round trip of %q gave suffix 0x%02x, want 0x%02x", name, suffix, nbnsSuffixWorkstation)
		}
	}
}

// TestEncodeNBNSNameRefusesOverlongName holds the encoder to the
// sixteen-byte NetBIOS name RFC 1002 section 4.2.1.2 defines: fifteen
// characters and a suffix, with no room to spill.
func TestEncodeNBNSNameRefusesOverlongName(t *testing.T) {
	if _, err := encodeNBNSName(strings.Repeat("A", nbnsNamePadLen+1), nbnsSuffixWorkstation); err == nil {
		t.Fatal("a 16-character NetBIOS name was accepted")
	}
	if _, err := encodeNBNSName("", nbnsSuffixWorkstation); err == nil {
		t.Fatal("an empty NetBIOS name was accepted")
	}
}

// TestDecodeNBNSNameRefusesBadAlphabet proves the decoder refuses a field
// that is not first-level encoded rather than producing nonsense from it.
func TestDecodeNBNSNameRefusesBadAlphabet(t *testing.T) {
	tests := map[string][]byte{
		"too short":          []byte("EGFDCNEM"),
		"character above P":  []byte("EGFDCNEMEPEOCNDADCCACACACACACACZ"),
		"character below A":  []byte("EGFDCNEMEPEOCNDADCCACACACACACAC0"),
		"all the wrong size": make([]byte, nbnsEncodedLen+1),
	}
	for name, field := range tests {
		t.Run(name, func(t *testing.T) {
			if _, _, err := decodeNBNSName(field); err == nil {
				t.Fatalf("decodeNBNSName accepted %q", field)
			}
		})
	}
}

// TestEncodeLabelsRefusesEmptyAndOverlong keeps a bad bait name from
// becoming a query for the DNS root, or a label over RFC 1035's 63-byte
// limit.
func TestEncodeLabelsRefusesEmptyAndOverlong(t *testing.T) {
	if _, err := encodeLabels(); err == nil {
		t.Error("encodeLabels with no labels was accepted")
	}
	if _, err := encodeLabels(""); err == nil {
		t.Error("an empty label was accepted")
	}
	if _, err := encodeLabels(strings.Repeat("a", maxLabelLen+1)); err == nil {
		t.Error("a 64-byte label was accepted")
	}
	if _, err := encodeLLMNRQuery(1, "", typeA); err == nil {
		t.Error("encodeLLMNRQuery accepted an empty name")
	}
	if _, err := encodeMDNSQuery("", typeA, false); err == nil {
		t.Error("encodeMDNSQuery accepted an empty name")
	}
	if _, err := encodeNBNSQuery(1, ""); err == nil {
		t.Error("encodeNBNSQuery accepted an empty name")
	}
}

// TestEveryEncoderFitsTheDatagramCap proves the longest bait name this
// package will send still produces a query well inside MaxDatagramLen, so
// the cap the parser applies can never be the reason a query is refused.
func TestEveryEncoderFitsTheDatagramCap(t *testing.T) {
	long := strings.Repeat("a", maxBaitNameLen)
	llmnr, err := encodeLLMNRQuery(1, long, typeAAAA)
	if err != nil {
		t.Fatalf("llmnr: %v", err)
	}
	mdns, err := encodeMDNSQuery(long, typeAAAA, true)
	if err != nil {
		t.Fatalf("mdns: %v", err)
	}
	nbns, err := encodeNBNSQuery(1, long)
	if err != nil {
		t.Fatalf("nbns: %v", err)
	}
	for name, msg := range map[string][]byte{"llmnr": llmnr, "mdns": mdns, "nbns": nbns} {
		if len(msg) > MaxDatagramLen {
			t.Errorf("%s query is %d bytes, over the %d-byte cap", name, len(msg), MaxDatagramLen)
		}
	}
}
