package portscan

import (
	"encoding/json"
	"net/netip"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/tomlawesome/birdcage/internal/agent/event"
	"github.com/tomlawesome/birdcage/internal/opencanary"
)

func sampleDetection(ports []uint16) detection {
	return detection{
		Src:       netip.MustParseAddr("198.51.100.5"),
		SrcPort:   44123,
		Dst:       netip.MustParseAddr("203.0.113.9"),
		FirstPort: ports[0],
		Ports:     ports,
		Protocol:  ProtoTCP,
	}
}

var sampleTime = time.Date(2026, 9, 19, 10, 0, 0, 123456000, time.UTC)

// TestEncodeMatchesOpenCanaryShape is the compatibility test the whole
// design rests on: nothing downstream of the agent -- ingest parsing,
// the service mapping, the dashboard -- is changed for this feature, so
// what comes out of here has to be an OpenCanary event and not merely
// look like one.
func TestEncodeMatchesOpenCanaryShape(t *testing.T) {
	t.Parallel()

	body, err := encode(sampleDetection([]uint16{21, 23, 25, 3389, 5900}), "mockingbird", sampleTime)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}

	want := `{"dst_host":"203.0.113.9","dst_port":21,"local_time":"2026-09-19 10:00:00.123456",` +
		`"logdata":{"COUNT":"5","PORTS":"21,23,25,3389,5900","PROTO":"TCP"},"logtype":5001,` +
		`"node_id":"mockingbird","src_host":"198.51.100.5","src_port":44123,` +
		`"utc_time":"2026-09-19 10:00:00.123456"}`
	if string(body) != want {
		t.Fatalf("encoded event\n got: %s\nwant: %s", body, want)
	}
}

// TestEncodeSortsItsKeys states the sorted-key requirement as a property
// rather than trusting the literal above: OpenCanary emits
// json.dumps(logdata, sort_keys=True), and a Go struct only reproduces
// that for as long as its fields stay declared in sorted order -- which
// nothing but this test enforces.
func TestEncodeSortsItsKeys(t *testing.T) {
	t.Parallel()

	body, err := encode(sampleDetection([]uint16{21, 23, 25, 3389, 5900}), "mockingbird", sampleTime)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}

	// The nested logdata keys are upper-case by OpenCanary's own
	// convention, so matching lower-case keys picks out exactly the
	// top-level set without needing to track brace depth.
	matches := regexp.MustCompile(`"([a-z_]+)":`).FindAllStringSubmatch(string(body), -1)
	var top []string
	for _, m := range matches {
		top = append(top, m[1])
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
// through the same two functions the other two roads' events go through
// on their way to birdcage.
func TestEncodedEventParsesAsAnIngestibleEvent(t *testing.T) {
	t.Parallel()

	body, err := encode(sampleDetection([]uint16{21, 23, 25, 3389, 5900}), "canary-7", sampleTime)
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

	// The log road locates the first '{' and hashes from there. The
	// emitted bytes start with it, so both roads agree on this event's
	// id -- which is what makes the third road a road into the same
	// queue rather than a parallel one.
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
	if fields.DestPort != 21 {
		t.Errorf("DestPort = %d, want 21", fields.DestPort)
	}
	if fields.Service != "portscan" {
		t.Errorf("Service = %q, want portscan -- logtype %d must map through internal/opencanary", fields.Service, LogTypePortSYN)
	}
	if got := opencanary.ServiceForLogType(ptr(LogTypePortSYN)); got != "portscan" {
		t.Errorf("ServiceForLogType(%d) = %q, want portscan", LogTypePortSYN, got)
	}
}

func ptr(v int) *int { return &v }

// TestEncodeCapsThePortsList: a sweep of the whole port range must not
// turn one event into a 380 KiB payload that blows through
// event.MaxLogLineBytes and evicts every real alert from the queue
// behind it. COUNT still tells the truth about how big the scan was.
func TestEncodeCapsThePortsList(t *testing.T) {
	t.Parallel()

	ports := make([]uint16, 0, 65535)
	for p := 1; p <= 65535; p++ {
		ports = append(ports, uint16(p))
	}

	body, err := encode(sampleDetection(ports), "mockingbird", sampleTime)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	if len(body) > event.MaxLogLineBytes {
		t.Fatalf("encoded event is %d bytes, over the %d-byte cap", len(body), event.MaxLogLineBytes)
	}

	var decoded struct {
		LogData struct {
			Count string `json:"COUNT"`
			Ports string `json:"PORTS"`
		} `json:"logdata"`
	}
	if err := json.Unmarshal(body, &decoded); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if decoded.LogData.Count != strconv.Itoa(len(ports)) {
		t.Errorf("COUNT = %q, want the true total %d even though PORTS is truncated", decoded.LogData.Count, len(ports))
	}
	if !strings.HasSuffix(decoded.LogData.Ports, ",...") {
		t.Errorf("PORTS = %q, want a truncation marker", decoded.LogData.Ports)
	}
	if got := strings.Count(decoded.LogData.Ports, ",") - 1; got != maxPortsListed-1 {
		t.Errorf("PORTS lists %d ports, want %d", got+1, maxPortsListed)
	}
}
