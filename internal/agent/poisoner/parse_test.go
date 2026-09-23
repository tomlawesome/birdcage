package poisoner

import (
	"bytes"
	"strings"
	"testing"
)

// dnsResponse builds a minimal LLMNR/mDNS response around a raw question
// section, for the parser tests below. answers goes straight into ANCOUNT,
// so a test can claim more answers than it carries -- which is exactly
// what a hostile sender would do.
func dnsResponse(id uint16, question []byte, answers uint16) []byte {
	msg := []byte{
		byte(id >> 8), byte(id),
		0x80, 0x00, // QR set: a response
		0x00, 0x01, // QDCOUNT 1
		byte(answers >> 8), byte(answers),
		0x00, 0x00,
		0x00, 0x00,
	}
	return append(msg, question...)
}

// TestParseDNSReplyReadsWhatMatters checks the three fields the caller
// uses, on a response shaped the way Responder sends one: the question
// echoed back, one answer record claimed.
func TestParseDNSReplyReadsWhatMatters(t *testing.T) {
	tests := []struct {
		name     string
		question []byte
		wantName string
	}{
		{
			name: "llmnr single label",
			question: []byte{
				0x09, 'f', 's', '-', 'l', 'o', 'n', '-', '0', '2', 0x00,
				0x00, 0x01, 0x00, 0x01,
			},
			wantName: "fs-lon-02",
		},
		{
			name: "mdns name under .local, suffix stripped",
			question: []byte{
				0x04, 'w', 'p', 'a', 'd', 0x05, 'l', 'o', 'c', 'a', 'l', 0x00,
				0x00, 0x01, 0x00, 0x01,
			},
			wantName: "wpad",
		},
		{
			name: "case folded, because a reply may change it",
			question: []byte{
				0x04, 'W', 'P', 'A', 'D', 0x00,
				0x00, 0x1c, 0x00, 0x01,
			},
			wantName: "wpad",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := parseDNSReply(dnsResponse(0x4d2, tc.question, 1))
			if err != nil {
				t.Fatalf("parseDNSReply: %v", err)
			}
			if got.ID != 0x4d2 {
				t.Errorf("ID = %#x, want 0x4d2", got.ID)
			}
			if got.Name != tc.wantName {
				t.Errorf("Name = %q, want %q", got.Name, tc.wantName)
			}
			if got.Answers != 1 {
				t.Errorf("Answers = %d, want 1", got.Answers)
			}
		})
	}
}

// TestParseDNSReplyRefusesMalformed is the hostile-input table. Each entry
// is a datagram a poisoner, or something pretending to be one, could
// actually put on the wire.
func TestParseDNSReplyRefusesMalformed(t *testing.T) {
	question := []byte{0x04, 'w', 'p', 'a', 'd', 0x00, 0x00, 0x01, 0x00, 0x01}

	// A name whose only label is a pointer to offset 12 -- itself. Legal
	// DNS syntax, an infinite loop for a parser that follows it.
	selfPointer := dnsResponse(1, []byte{0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01}, 1)

	// A pointer into the answer section, which has not been read yet:
	// forwards, and the classic way a crafted message steers a parser.
	forwardPointer := dnsResponse(1, []byte{0xc0, 0x20, 0x00, 0x01, 0x00, 0x01}, 1)

	tests := map[string][]byte{
		"over the 512-byte cap":     dnsResponse(1, append(question, make([]byte, MaxDatagramLen)...), 1),
		"shorter than a header":     {0x00, 0x01, 0x80, 0x00},
		"a query, not a response":   {0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
		"two questions":             {0x00, 0x01, 0x80, 0x00, 0x00, 0x02, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00},
		"self-referential pointer":  selfPointer,
		"forward pointer":           forwardPointer,
		"reserved label type":       dnsResponse(1, []byte{0x40, 'w', 'p'}, 1),
		"label runs off the end":    dnsResponse(1, []byte{0x09, 'w', 'p'}, 1),
		"truncated pointer":         dnsResponse(1, []byte{0xc0}, 1),
		"unterminated name":         dnsResponse(1, []byte{0x04, 'w', 'p', 'a', 'd'}, 1),
		"question missing its tail": dnsResponse(1, []byte{0x04, 'w', 'p', 'a', 'd', 0x00, 0x00}, 1),
	}

	for name, datagram := range tests {
		t.Run(name, func(t *testing.T) {
			if got, err := parseDNSReply(datagram); err == nil {
				t.Fatalf("parseDNSReply accepted it, returning %+v", got)
			}
		})
	}
}

// TestReadNameFollowsALegalBackwardPointer proves the pointer rule refuses
// only what it should: a reply that compresses its question name against
// an earlier copy still decodes.
func TestReadNameFollowsALegalBackwardPointer(t *testing.T) {
	// Lay "wpad" down at offset 12, then a name at offset 18 that is
	// nothing but a pointer back to it.
	msg := []byte{
		0x00, 0x01,
		0x80, 0x00,
		0x00, 0x01,
		0x00, 0x01,
		0x00, 0x00,
		0x00, 0x00,
		0x04, 'w', 'p', 'a', 'd', 0x00,
	}
	target := dnsHeaderLen
	name, end, err := readName(msg, target)
	if err != nil {
		t.Fatalf("readName on the literal name: %v", err)
	}
	if name != "wpad" || end != 18 {
		t.Fatalf("literal name gave (%q, %d), want (\"wpad\", 18)", name, end)
	}

	msg = append(msg, byte(0xc0|(target>>8)), byte(target))
	name, end, err = readName(msg, 18)
	if err != nil {
		t.Fatalf("readName on the pointer: %v", err)
	}
	if name != "wpad" {
		t.Errorf("pointer decoded to %q, want \"wpad\"", name)
	}
	// The name ends after the two pointer bytes, not after what they
	// point at: a caller reading QTYPE next depends on this.
	if end != 20 {
		t.Errorf("end = %d, want 20 (just past the pointer)", end)
	}
}

// TestReadNameRefusesALongPointerChain exercises maxNameJumps. It cannot
// be reached through parseDNSReply: a question name starts at offset 12,
// every pointer must go strictly backwards, and two-byte pointers fit at
// most six hops into the twelve bytes ahead of it -- so this calls readName
// directly on a buffer where the name starts far enough in to build a
// chain that is legal at every hop and still too long.
func TestReadNameRefusesALongPointerChain(t *testing.T) {
	msg := []byte{0x00} // a root label at offset 0 for the chain to land on
	for i := 0; i <= maxNameJumps+1; i++ {
		target := len(msg) - 2
		if target < 0 {
			target = 0
		}
		msg = append(msg, byte(0xc0|(target>>8)), byte(target))
	}
	// Every hop is strictly backwards, so the pointer rule allows all of
	// them and only the jump budget refuses the name.
	if _, _, err := readName(msg, len(msg)-2); err == nil {
		t.Fatalf("a %d-hop pointer chain was accepted", maxNameJumps+2)
	}
	// A chain inside the budget still decodes, so the budget is not simply
	// refusing every pointer.
	short := []byte{0x04, 'w', 'p', 'a', 'd', 0x00, 0xc0, 0x00, 0xc0, 0x06}
	if name, _, err := readName(short, 8); err != nil || name != "wpad" {
		t.Errorf("a two-hop chain gave (%q, %v), want (\"wpad\", nil)", name, err)
	}
}

// TestReadNameRefusesAnOverlongName keeps a chain of maximal labels from
// decoding into a name past RFC 1035's 255-byte limit.
func TestReadNameRefusesAnOverlongName(t *testing.T) {
	var msg []byte
	for len(msg) < maxNameLen+8 {
		msg = append(msg, byte(maxLabelLen))
		msg = append(msg, bytes.Repeat([]byte{'a'}, maxLabelLen)...)
	}
	msg = append(msg, 0x00)
	if _, _, err := readName(msg, 0); err == nil {
		t.Fatal("a name over 255 bytes was accepted")
	}
}

// TestParseNBNSReply covers the shape Responder actually sends -- QDCOUNT
// 0, one answer record whose RR_NAME is the encoded bait name -- and the
// compliant-query echo shape alongside it.
func TestParseNBNSReply(t *testing.T) {
	encoded, err := encodeNBNSName("FS-LON-02", nbnsSuffixWorkstation)
	if err != nil {
		t.Fatalf("encodeNBNSName: %v", err)
	}

	tests := []struct {
		name      string
		questions uint16
		answers   uint16
	}{
		{name: "responder shape: no question, one answer", questions: 0, answers: 1},
		{name: "question echoed back", questions: 1, answers: 1},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			msg := []byte{
				0x2a, 0x00,
				0x85, 0x00, // R=1, AA=1, RD=1: a positive name query response
				byte(tc.questions >> 8), byte(tc.questions),
				byte(tc.answers >> 8), byte(tc.answers),
				0x00, 0x00,
				0x00, 0x00,
			}
			msg = append(msg, encoded...)
			got, err := parseNBNSReply(msg)
			if err != nil {
				t.Fatalf("parseNBNSReply: %v", err)
			}
			if got.ID != 0x2a00 {
				t.Errorf("ID = %#x, want 0x2a00", got.ID)
			}
			if got.Name != "fs-lon-02" {
				t.Errorf("Name = %q, want \"fs-lon-02\"", got.Name)
			}
			if got.Answers != tc.answers {
				t.Errorf("Answers = %d, want %d", got.Answers, tc.answers)
			}
		})
	}
}

// TestParseNBNSReplyRefusesMalformed is the NBT-NS half of the
// hostile-input table.
func TestParseNBNSReplyRefusesMalformed(t *testing.T) {
	header := []byte{0x00, 0x01, 0x85, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00}
	with := func(tail ...byte) []byte {
		return append(append([]byte{}, header...), tail...)
	}
	encoded, err := encodeNBNSName("WPAD", nbnsSuffixWorkstation)
	if err != nil {
		t.Fatalf("encodeNBNSName: %v", err)
	}

	tests := map[string][]byte{
		"a query, not a response":  {0x00, 0x01, 0x01, 0x10, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
		"two questions":            {0x00, 0x01, 0x85, 0x00, 0x00, 0x02, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00},
		"nothing after the header": header,
		"wrong name length":        with(0x10),
		"name runs off the end":    with(0x20, 'E', 'G'),
		"not in the root scope":    with(append(append([]byte{0x20}, encoded[1:1+nbnsEncodedLen]...), 0x04, 'h', 'o', 'm', 'e')...),
		"forward name pointer":     with(0xc0, 0x40),
		"self-referential pointer": with(0xc0, 0x0c),
		"truncated name pointer":   with(0xc0),
		// ARCOUNT's own bytes (offsets 10 and 11) are made to look like a
		// pointer, so the pointer at offset 12 lands on another pointer.
		// Nothing reads ARCOUNT, so the header stays otherwise valid.
		"pointer to a pointer": {0x00, 0x01, 0x85, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0xc0, 0x02, 0xc0, 0x0a},
	}

	for name, datagram := range tests {
		t.Run(name, func(t *testing.T) {
			if got, err := parseNBNSReply(datagram); err == nil {
				t.Fatalf("parseNBNSReply accepted it, returning %+v", got)
			}
		})
	}
}

// TestParseNBNSReplyFollowsALegalNamePointer proves a compressed RR_NAME
// still decodes, so the strictly-backwards rule is not simply refusing
// every pointer.
func TestParseNBNSReplyFollowsALegalNamePointer(t *testing.T) {
	encoded, err := encodeNBNSName("WPAD", nbnsSuffixWorkstation)
	if err != nil {
		t.Fatalf("encodeNBNSName: %v", err)
	}
	// The literal name at offset 12, then a second name just past it that
	// points back at it. Reading from that second name must decode to the
	// same thing the literal copy does.
	header := []byte{0x00, 0x01, 0x85, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00}
	long := append(append([]byte{}, header...), encoded...)
	target := dnsHeaderLen
	long = append(long, byte(0xc0|(target>>8)), byte(target))
	field, end, err := readNBNSNameField(long, len(long)-2)
	if err != nil {
		t.Fatalf("readNBNSNameField on the pointer: %v", err)
	}
	if end != len(long) {
		t.Errorf("end = %d, want %d (just past the pointer)", end, len(long))
	}
	name, _, err := decodeNBNSName(field)
	if err != nil {
		t.Fatalf("decodeNBNSName: %v", err)
	}
	if !strings.EqualFold(name, "WPAD") {
		t.Errorf("decoded %q, want \"WPAD\"", name)
	}
}
