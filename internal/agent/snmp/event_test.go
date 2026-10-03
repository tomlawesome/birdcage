package snmp

import (
	"encoding/json"
	"regexp"
	"testing"
	"time"

	"github.com/tomlawesome/birdcage/internal/agent/event"
	"github.com/tomlawesome/birdcage/internal/opencanary"
)

func sampleDetection(oids []string) detection {
	return detection{
		Src:       "198.51.100.5",
		SrcPort:   45090,
		Dst:       "0.0.0.0",
		DstPort:   161,
		Community: "public",
		OIDs:      oids,
	}
}

var sampleTime = time.Date(2026, 9, 20, 10, 0, 0, 123456000, time.UTC)

// TestEncodeMatchesOpenCanaryShape is the compatibility test the whole
// design rests on -- see portscan/event_test.go's test of the same
// name: what comes out of here has to be an OpenCanary event, not
// merely look like one, since nothing downstream is changed for this
// feature.
func TestEncodeMatchesOpenCanaryShape(t *testing.T) {
	t.Parallel()

	body, err := encode(sampleDetection([]string{"1.3.6.1.2.1.1.1.0", "1.3.6.1.2.1.1.5.0"}), "mockingbird", sampleTime)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}

	want := `{"dst_host":"0.0.0.0","dst_port":161,"local_time":"2026-09-20 10:00:00.123456",` +
		`"logdata":{"COMMUNITY_STRING":"public","REQUESTS":["1.3.6.1.2.1.1.1.0","1.3.6.1.2.1.1.5.0"]},` +
		`"logtype":13001,"node_id":"mockingbird","src_host":"198.51.100.5","src_port":45090,` +
		`"utc_time":"2026-09-20 10:00:00.123456"}`
	if string(body) != want {
		t.Fatalf("encoded event\n got: %s\nwant: %s", body, want)
	}
}

// TestEncodeSortsItsKeys states the sorted-key requirement as a
// property, the same way portscan's equivalent test does: OpenCanary
// emits json.dumps(logdata, sort_keys=True), and a Go struct only
// reproduces that for as long as its fields stay declared in sorted
// order.
func TestEncodeSortsItsKeys(t *testing.T) {
	t.Parallel()

	body, err := encode(sampleDetection([]string{"1.3.6.1.2.1.1.1.0"}), "mockingbird", sampleTime)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}

	matches := regexp.MustCompile(`"([A-Za-z_]+)":`).FindAllStringSubmatch(string(body), -1)
	var top []string
	for _, m := range matches {
		// The nested logdata keys are upper-case by OpenCanary's own
		// convention; skip them so this only checks the nine top-level
		// keys, the same trick portscan's test uses.
		if m[1] != "COMMUNITY_STRING" && m[1] != "REQUESTS" {
			top = append(top, m[1])
		}
	}
	if len(top) != 9 {
		t.Fatalf("found %d top-level keys (%v), want 9", len(top), top)
	}
	for i := 1; i < len(top); i++ {
		if top[i-1] >= top[i] {
			t.Fatalf("keys out of order: %q comes before %q in %s", top[i-1], top[i], body)
		}
	}
}

// TestEncodedEventParsesAsAnIngestibleEvent runs the emitted bytes
// through the same two functions the other roads' events go through on
// their way to birdcage -- see portscan/event_test.go's equivalent.
func TestEncodedEventParsesAsAnIngestibleEvent(t *testing.T) {
	t.Parallel()

	body, err := encode(sampleDetection([]string{"1.3.6.1.2.1.1.1.0"}), "canary-7", sampleTime)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}

	id, err := event.IDFromEmittedMessage(body)
	if err != nil {
		t.Fatalf("IDFromEmittedMessage: %v", err)
	}
	if len(id) != 64 {
		t.Fatalf("event id %q is %d characters, want 64", id, len(id))
	}

	logID, message, err := event.IDFromLogLine(body)
	if err != nil {
		t.Fatalf("IDFromLogLine: %v", err)
	}
	if logID != id {
		t.Fatalf("log-road id %s != emitted id %s", logID, id)
	}
	if string(message) != string(body) {
		t.Fatalf("log road recovered different bytes:\n got: %s\nwant: %s", message, body)
	}

	fields, err := event.ExtractFields(body)
	if err != nil {
		t.Fatalf("ExtractFields: %v", err)
	}
	if fields.SourceIP != "198.51.100.5" {
		t.Errorf("SourceIP = %q, want 198.51.100.5", fields.SourceIP)
	}
	if fields.DestPort != 161 {
		t.Errorf("DestPort = %d, want 161", fields.DestPort)
	}
	if fields.Service != "snmp" {
		t.Errorf("Service = %q, want snmp -- logtype %d must map through internal/opencanary", fields.Service, LogTypeSNMPCmd)
	}
	if got := opencanary.ServiceForLogType(ptr(LogTypeSNMPCmd)); got != "snmp" {
		t.Errorf("ServiceForLogType(%d) = %q, want snmp", LogTypeSNMPCmd, got)
	}
}

func ptr(v int) *int { return &v }

// TestEncodeHandlesZeroOIDs: a degenerate but valid GetRequest with no
// varbinds must still produce an event -- the community string alone is
// what tells an operator or #46's self-test whether this was a
// monitoring poll or a guess, so it belongs on the wire even with an
// empty REQUESTS list, and that list must be [] rather than null.
func TestEncodeHandlesZeroOIDs(t *testing.T) {
	t.Parallel()

	body, err := encode(sampleDetection(nil), "mockingbird", sampleTime)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	var decoded struct {
		LogData struct {
			Requests json.RawMessage `json:"REQUESTS"`
		} `json:"logdata"`
	}
	if err := json.Unmarshal(body, &decoded); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if string(decoded.LogData.Requests) != "[]" {
		t.Fatalf("REQUESTS = %s, want the empty array [] rather than null", decoded.LogData.Requests)
	}
}

// TestEncodeStaysUnderTheLogLineCap proves the parser's own bounds
// (maxOIDs, maxOIDValueLen) are enough on their own to keep one event
// well inside event.MaxLogLineBytes, without this package needing a
// second truncation step the way portscan's encode does for its ports
// list -- unlike a port number, an OID string's own length is already
// capped where it is decoded (parse.go), not where it is encoded.
func TestEncodeStaysUnderTheLogLineCap(t *testing.T) {
	t.Parallel()

	oids := make([]string, maxOIDs)
	for i := range oids {
		// The longest plausible OID this parser will ever hand to
		// encode: maxOIDComponents dotted components, each set to a
		// large multi-digit value.
		oid := ""
		for c := 0; c < maxOIDComponents; c++ {
			if c > 0 {
				oid += "."
			}
			oid += "4294967295"
		}
		oids[i] = oid
	}

	body, err := encode(sampleDetection(oids), "mockingbird", sampleTime)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	if len(body) > event.MaxLogLineBytes {
		t.Fatalf("encoded event is %d bytes, over the %d-byte cap", len(body), event.MaxLogLineBytes)
	}
}
