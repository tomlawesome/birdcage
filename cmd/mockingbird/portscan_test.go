package main

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/tomlawesome/birdcage/internal/agent/event"
	"github.com/tomlawesome/birdcage/internal/agent/queue"
)

func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// TestSubmitPortscanEventQueuesWithTheSameIDTheOtherRoadsWouldMint is
// what makes the port-scan road a third road into the same queue rather
// than a parallel pipeline: the id has to be the same kind of value, in
// the same format, that the webhook and log roads produce, or
// deduplication and birdcage's own event-id validation both stop
// applying to it.
func TestSubmitPortscanEventQueuesWithTheSameIDTheOtherRoadsWouldMint(t *testing.T) {
	in, _ := newTestIntake(t, queue.Config{MaxEvents: 16, MaxBytes: 1 << 20})

	message := []byte(`{"dst_host":"203.0.113.9","dst_port":25,"logdata":{"COUNT":"5"},"logtype":5001}`)
	if err := in.SubmitPortscanEvent(message); err != nil {
		t.Fatalf("SubmitPortscanEvent: %v", err)
	}

	if got := in.Queue.Depth(); got != 1 {
		t.Fatalf("queue depth = %d, want 1", got)
	}
	peeked := in.Queue.Peek(1)
	if len(peeked) != 1 {
		t.Fatal("nothing queued")
	}
	queued := peeked[0]

	// The log road locates the first '{' and hashes from there. These
	// bytes start with it, so both roads agree.
	wantID, _, err := event.IDFromLogLine(message)
	if err != nil {
		t.Fatalf("IDFromLogLine: %v", err)
	}
	if queued.ID != wantID {
		t.Errorf("queued id %s, want %s -- the third road must mint ids the same way", queued.ID, wantID)
	}
	if len(queued.ID) != 64 {
		t.Errorf("id %q is %d characters, want the 64 birdcage validates", queued.ID, len(queued.ID))
	}
	if string(queued.Payload) != string(message) {
		t.Errorf("queued payload was altered:\n got: %s\nwant: %s", queued.Payload, message)
	}
}

// TestSubmitPortscanEventAppendsNoLedgerEntry is #48 decision 3 applied
// to this road: the ledger maps event ids to positions in OpenCanary's
// log file, and a port scan the agent detected itself was never in that
// file. Giving it an entry would stall the acknowledged frontier on
// something that can never resolve, and the log road would then re-read
// from a position that never advances.
func TestSubmitPortscanEventAppendsNoLedgerEntry(t *testing.T) {
	in, _ := newTestIntake(t, queue.Config{MaxEvents: 16, MaxBytes: 1 << 20})

	before := in.Ledger().Len()
	for i := 0; i < 5; i++ {
		message := []byte(`{"logtype":5001,"n":` + string(rune('0'+i)) + `}`)
		if err := in.SubmitPortscanEvent(message); err != nil {
			t.Fatalf("SubmitPortscanEvent: %v", err)
		}
	}
	if after := in.Ledger().Len(); after != before {
		t.Fatalf("ledger grew from %d to %d entries; the port-scan road must not touch it", before, after)
	}
	if _, ok := in.Ledger().Advance(); ok {
		t.Fatal("the ledger produced an acknowledged position; the port-scan road left an entry behind")
	}
}

// TestSubmitPortscanEventRefusesUnusableBytes: the queue holds what the
// sender ships verbatim, so a caller handing over nothing (or something
// absurdly large) must be refused here rather than quietly pushed.
func TestSubmitPortscanEventRefusesUnusableBytes(t *testing.T) {
	in, _ := newTestIntake(t, queue.Config{MaxEvents: 16, MaxBytes: 1 << 20})

	if err := in.SubmitPortscanEvent(nil); err == nil {
		t.Error("expected an error for empty bytes")
	}
	if err := in.SubmitPortscanEvent(make([]byte, event.MaxLogLineBytes+1)); err == nil {
		t.Error("expected an error for bytes over the cap")
	}
	if got := in.Queue.Depth(); got != 0 {
		t.Errorf("queue depth = %d after two refusals, want 0", got)
	}
}

// TestSubmitPortscanEventDeduplicates: the same detection submitted
// twice is one queued event, because Push keys on the id and the id is a
// hash of the bytes. Worth stating because the whole reason the other
// two roads can both carry the same hit is this property.
func TestSubmitPortscanEventDeduplicates(t *testing.T) {
	in, _ := newTestIntake(t, queue.Config{MaxEvents: 16, MaxBytes: 1 << 20})

	message := []byte(`{"logtype":5001,"dst_port":25}`)
	for i := 0; i < 3; i++ {
		if err := in.SubmitPortscanEvent(message); err != nil {
			t.Fatalf("SubmitPortscanEvent: %v", err)
		}
	}
	if got := in.Queue.Depth(); got != 1 {
		t.Fatalf("queue depth = %d, want 1", got)
	}
}

func TestParseIgnorePorts(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want []uint16
	}{
		{"empty", "", nil},
		{"one", "9999", []uint16{9999}},
		{"several with spaces", " 21, 8080 ,443 ", []uint16{21, 8080, 443}},
		{"trailing and doubled commas are not entries", "22,,23,", []uint16{22, 23}},
		// A typo in an optional tuning variable must not take the
		// honeypot down, and must not silently become a real port.
		{"out of range and nonsense are skipped", "0,70000,-1,http,22", []uint16{22}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := parseIgnorePorts(tc.in, discardLogger())
			if len(got) != len(tc.want) {
				t.Fatalf("got %v, want %v", got, tc.want)
			}
			for i := range got {
				if got[i] != tc.want[i] {
					t.Fatalf("got %v, want %v", got, tc.want)
				}
			}
		})
	}
}

// TestListenPort: the agent's own loopback receiver must be treated as
// one of ours, or OpenCanary posting every webhook to it would read as
// somebody probing a closed port.
func TestListenPort(t *testing.T) {
	cases := []struct {
		in       string
		want     uint16
		wantOK   bool
		whatItIs string
	}{
		{"127.0.0.1:9919", 9919, true, "the shipped default"},
		{"[::1]:9919", 9919, true, "IPv6 loopback"},
		{"", 0, false, "unset"},
		{"127.0.0.1", 0, false, "no port at all"},
		{"127.0.0.1:0", 0, false, "port zero is not a port to ignore"},
		{"127.0.0.1:notaport", 0, false, "nonsense"},
	}
	for _, tc := range cases {
		got, ok := listenPort(tc.in)
		if ok != tc.wantOK || got != tc.want {
			t.Errorf("listenPort(%q) = %d, %v; want %d, %v (%s)", tc.in, got, ok, tc.want, tc.wantOK, tc.whatItIs)
		}
	}
}

func TestPortscanEnabled(t *testing.T) {
	for _, tc := range []struct {
		value string
		set   bool
		want  bool
	}{
		{set: false, want: true},
		{value: "", set: true, want: true},
		{value: "1", set: true, want: true},
		{value: "0", set: true, want: false},
	} {
		if tc.set {
			t.Setenv(envPortscan, tc.value)
		}
		if got := portscanEnabled(); got != tc.want {
			t.Errorf("%s=%q (set=%v): portscanEnabled() = %v, want %v", envPortscan, tc.value, tc.set, got, tc.want)
		}
	}
}

// TestInventoryLineNamesNothingSensitive is the logging rule this
// binary's package doc states, applied to the one startup line #65 adds:
// a count, never the list of ports, and nothing about the state
// directory, the log path or the listen address.
func TestInventoryLineNamesNothingSensitive(t *testing.T) {
	for _, inv := range []agentInventory{
		{PortscanActive: true, ListeningPorts: 11},
		{PortscanActive: false},
	} {
		line := inv.line()
		for _, forbidden := range []string{"/var/lib", "/var/log", "127.0.0.1", "9919", ":"} {
			if strings.Contains(line, forbidden) {
				t.Errorf("inventory line %q contains %q", line, forbidden)
			}
		}
	}
	if got := (agentInventory{PortscanActive: true, ListeningPorts: 11}).line(); !strings.Contains(got, "11") {
		t.Errorf("active line %q does not report the listening-port count", got)
	}
	if got := (agentInventory{}).line(); !strings.Contains(got, "off") {
		t.Errorf("inactive line %q does not say detection is off", got)
	}
}

// TestPortscanEventEncodingRoundTrips proves the bytes this road queues
// are still a decodable OpenCanary event after passing through the
// queue, which is what the sender will hand to birdcage.
func TestPortscanEventEncodingRoundTrips(t *testing.T) {
	in, _ := newTestIntake(t, queue.Config{MaxEvents: 16, MaxBytes: 1 << 20})

	message := []byte(`{"dst_host":"203.0.113.9","dst_port":25,"local_time":"2026-09-19 10:00:00.000000",` +
		`"logdata":{"COUNT":"5","PORTS":"25,110,143,445,5900","PROTO":"TCP"},"logtype":5001,` +
		`"node_id":"mockingbird","src_host":"198.51.100.5","src_port":44123,"utc_time":"2026-09-19 10:00:00.000000"}`)
	if err := in.SubmitPortscanEvent(message); err != nil {
		t.Fatalf("SubmitPortscanEvent: %v", err)
	}
	queued := in.Queue.Peek(1)[0]

	var decoded map[string]any
	if err := json.Unmarshal(queued.Payload, &decoded); err != nil {
		t.Fatalf("queued payload is not decodable JSON: %v", err)
	}
	fields := fieldsOrFallback(queued.Payload)
	if fields.Service != "portscan" {
		t.Errorf("service = %q, want portscan", fields.Service)
	}
	if fields.DestPort != 25 {
		t.Errorf("dest port = %d, want 25", fields.DestPort)
	}
	if fields.SourceIP != "198.51.100.5" {
		t.Errorf("source ip = %q, want 198.51.100.5", fields.SourceIP)
	}
}

// TestNewPortscanRoadDisabled proves the off switch actually turns
// newPortscanRoad into a no-op: no detector, and an inventory that says
// so -- the same contract TestNewSNMPRoadDisabled proves for the SNMP
// road.
func TestNewPortscanRoadDisabled(t *testing.T) {
	t.Setenv(envPortscan, "0")
	in, _ := newTestIntake(t, queue.Config{})

	detector, inv := newPortscanRoad(Config{}, in, discardLogger())
	if detector != nil {
		t.Error("expected a nil detector when MOCKINGBIRD_PORTSCAN=0")
	}
	if inv.PortscanActive {
		t.Error("expected PortscanActive=false when disabled")
	}
}

// TestNewPortscanRoadOpenFailureIsHandled proves newPortscanRoad's
// documented contract that a failure to open the capture socket is
// never fatal: it returns a nil detector and an inactive inventory
// rather than an error, so main keeps running with port-scan detection
// off. Opening the AF_PACKET capture socket needs CAP_NET_RAW, which
// this test process does not have.
func TestNewPortscanRoadOpenFailureIsHandled(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("running as root: CAP_NET_RAW is likely present, so the capture socket would open")
	}
	in, _ := newTestIntake(t, queue.Config{})

	detector, inv := newPortscanRoad(Config{}, in, discardLogger())
	if detector != nil {
		t.Error("expected a nil detector when opening the capture socket fails")
	}
	if inv.PortscanActive {
		t.Error("expected PortscanActive=false when opening the capture socket fails")
	}
	if inv.ListeningPorts != 0 {
		t.Errorf("ListeningPorts = %d, want 0 when detection is off", inv.ListeningPorts)
	}
}

// TestRunPortscanRoadNilDetectorIsANoOp proves the "disabled, or the
// open failed" case main relies on: runPortscanRoad must return
// immediately rather than block, so main can start this goroutine
// unconditionally regardless of whether detection is actually running.
func TestRunPortscanRoadNilDetectorIsANoOp(t *testing.T) {
	done := make(chan struct{})
	go func() {
		runPortscanRoad(context.Background(), nil, discardLogger())
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("runPortscanRoad(nil, ...) did not return")
	}
}
