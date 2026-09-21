package main

import (
	"context"
	"testing"
	"time"

	"github.com/tomlawesome/birdcage/internal/agent/event"
	"github.com/tomlawesome/birdcage/internal/agent/queue"
)

// TestSubmitSNMPEventQueuesWithTheSameIDTheOtherRoadsWouldMint is the
// SNMP road's version of portscan_test.go's equivalent test: the id has
// to be the same kind of value, in the same format, that the webhook,
// log and port-scan roads produce, or deduplication and birdcage's own
// event-id validation both stop applying to it.
func TestSubmitSNMPEventQueuesWithTheSameIDTheOtherRoadsWouldMint(t *testing.T) {
	in, _ := newTestIntake(t, queue.Config{MaxEvents: 16, MaxBytes: 1 << 20})

	message := []byte(`{"dst_host":"0.0.0.0","dst_port":161,"local_time":"2026-09-20 10:00:00.123456",` +
		`"logdata":{"COMMUNITY_STRING":"public","REQUESTS":["1.3.6.1.2.1.1.1.0"]},"logtype":13001,` +
		`"node_id":"mockingbird","src_host":"198.51.100.5","src_port":45090,` +
		`"utc_time":"2026-09-20 10:00:00.123456"}`)
	if err := in.SubmitSNMPEvent(message); err != nil {
		t.Fatalf("SubmitSNMPEvent: %v", err)
	}

	if got := in.Queue.Depth(); got != 1 {
		t.Fatalf("queue depth = %d, want 1", got)
	}
	queued := in.Queue.Peek(1)[0]

	wantID, err := event.IDFromEmittedMessage(message)
	if err != nil {
		t.Fatalf("IDFromEmittedMessage: %v", err)
	}
	if queued.ID != wantID {
		t.Errorf("queued id %s, want %s -- the SNMP road must mint ids the same way", queued.ID, wantID)
	}
	if len(queued.ID) != 64 {
		t.Errorf("id %q is %d characters, want the 64 birdcage validates", queued.ID, len(queued.ID))
	}
	if string(queued.Payload) != string(message) {
		t.Errorf("queued payload was altered:\n got: %s\nwant: %s", queued.Payload, message)
	}
}

// TestSubmitSNMPEventAppendsNoLedgerEntry is #48 decision 3 applied to
// the SNMP road, the same as portscan_test.go's equivalent test: this
// event was never a line in OpenCanary's log file, so it has no log
// position to record, and giving it one would stall the acknowledged
// frontier on an entry that can never resolve.
func TestSubmitSNMPEventAppendsNoLedgerEntry(t *testing.T) {
	in, _ := newTestIntake(t, queue.Config{MaxEvents: 16, MaxBytes: 1 << 20})

	before := in.Ledger().Len()
	for i := 0; i < 5; i++ {
		message := []byte(`{"logtype":13001,"n":` + string(rune('0'+i)) + `}`)
		if err := in.SubmitSNMPEvent(message); err != nil {
			t.Fatalf("SubmitSNMPEvent: %v", err)
		}
	}
	if after := in.Ledger().Len(); after != before {
		t.Fatalf("ledger grew from %d to %d entries; the SNMP road must not touch it", before, after)
	}
	if _, ok := in.Ledger().Advance(); ok {
		t.Fatal("the ledger produced an acknowledged position; the SNMP road left an entry behind")
	}
}

// TestSubmitSNMPEventRefusesUnusableBytes: the queue holds what the
// sender ships verbatim, so a caller handing over nothing (or something
// absurdly large) must be refused here rather than quietly pushed.
func TestSubmitSNMPEventRefusesUnusableBytes(t *testing.T) {
	in, _ := newTestIntake(t, queue.Config{MaxEvents: 16, MaxBytes: 1 << 20})

	if err := in.SubmitSNMPEvent(nil); err == nil {
		t.Error("expected an error for empty bytes")
	}
	if err := in.SubmitSNMPEvent(make([]byte, event.MaxLogLineBytes+1)); err == nil {
		t.Error("expected an error for bytes over the cap")
	}
	if got := in.Queue.Depth(); got != 0 {
		t.Errorf("queue depth = %d after two refusals, want 0", got)
	}
}

// TestSubmitSNMPEventDeduplicates mirrors portscan_test.go's dedup test:
// the same detection submitted twice is one queued event, because Push
// keys on the id and the id is a hash of the bytes.
func TestSubmitSNMPEventDeduplicates(t *testing.T) {
	in, _ := newTestIntake(t, queue.Config{MaxEvents: 16, MaxBytes: 1 << 20})

	message := []byte(`{"logtype":13001,"dst_port":161}`)
	for i := 0; i < 3; i++ {
		if err := in.SubmitSNMPEvent(message); err != nil {
			t.Fatalf("SubmitSNMPEvent: %v", err)
		}
	}
	if got := in.Queue.Depth(); got != 1 {
		t.Fatalf("queue depth = %d, want 1", got)
	}
}

// TestSNMPEnabled mirrors portscan_test.go's TestPortscanEnabled: one
// switch, no levels -- anything but "0" leaves SNMP detection on.
func TestSNMPEnabled(t *testing.T) {
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
			t.Setenv(envSNMP, tc.value)
		}
		if got := snmpEnabled(); got != tc.want {
			t.Errorf("%s=%q (set=%v): snmpEnabled() = %v, want %v", envSNMP, tc.value, tc.set, got, tc.want)
		}
	}
}

// TestSNMPInventoryLine is the SNMP road's version of
// TestInventoryLineNamesNothingSensitive: the one startup line main
// prints must say active or off, and (being just a bool, unlike the
// port-scan inventory) has no count or address to leak in the first
// place.
func TestSNMPInventoryLine(t *testing.T) {
	if got := (snmpInventory{SNMPActive: true}).line(); got != "snmp detection active" {
		t.Errorf("active line = %q, want %q", got, "snmp detection active")
	}
	if got := (snmpInventory{}).line(); got != "snmp detection off" {
		t.Errorf("inactive line = %q, want %q", got, "snmp detection off")
	}
}

// TestNewSNMPRoadDisabled proves the off switch actually turns
// newSNMPRoad into a no-op: no detector, and an inventory that says so.
func TestNewSNMPRoadDisabled(t *testing.T) {
	t.Setenv(envSNMP, "0")
	in, _ := newTestIntake(t, queue.Config{})

	detector, inv := newSNMPRoad(in, discardLogger())
	if detector != nil {
		t.Error("expected a nil detector when MOCKINGBIRD_SNMP=0")
	}
	if inv.SNMPActive {
		t.Error("expected SNMPActive=false when disabled")
	}
}

// TestNewSNMPRoadBindFailureIsHandled proves newSNMPRoad's documented
// contract that a bind failure is never fatal: it returns a nil
// detector and an inactive inventory rather than an error, so main keeps
// running with SNMP detection off.
//
// The address is unparseable rather than privileged, which matters. This
// test first tried the real-world failure -- binding the standard SNMP
// port (161) as a non-root user -- and it passed on a workstation and
// failed in CI (pipeline 1409), because the runner's containers have
// net.ipv4.ip_unprivileged_port_start=0, so uid 1001 binds 161 there
// quite happily. That is the same sysctl the enrolment command passes to
// the mockingbird container, and on this runner it is already the
// default.
//
// So a test that needs a bind to fail cannot get there by asking for a
// privileged port: whether that fails is the host's decision, not the
// code's. An unparseable port always fails, in Detector.Open's
// ResolveUDPAddr, before any privilege question arises.
func TestNewSNMPRoadBindFailureIsHandled(t *testing.T) {
	t.Setenv(envSNMPListen, "127.0.0.1:not-a-port")
	in, _ := newTestIntake(t, queue.Config{})

	detector, inv := newSNMPRoad(in, discardLogger())
	if detector != nil {
		t.Error("expected a nil detector when the bind fails")
	}
	if inv.SNMPActive {
		t.Error("expected SNMPActive=false when the bind fails")
	}
}

// TestNewSNMPRoadBindsAndRunSNMPRoadStopsOnCancel proves the success
// path end to end: an unprivileged listen address binds, and the
// goroutine main starts around the returned detector actually returns
// once its context is cancelled -- so a canary that opened this socket
// does not leak it, or a blocked goroutine, past shutdown.
func TestNewSNMPRoadBindsAndRunSNMPRoadStopsOnCancel(t *testing.T) {
	t.Setenv(envSNMPListen, "127.0.0.1:0")
	in, _ := newTestIntake(t, queue.Config{})

	detector, inv := newSNMPRoad(in, discardLogger())
	if detector == nil {
		t.Fatal("expected a non-nil detector when the bind succeeds")
	}
	if !inv.SNMPActive {
		t.Error("expected SNMPActive=true when the bind succeeds")
	}

	runCtx, cancel := context.WithCancel(context.Background())
	cancel() // cancelled before Run starts: it must still return promptly, not block on a read.

	done := make(chan struct{})
	go func() {
		runSNMPRoad(runCtx, detector, discardLogger())
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("runSNMPRoad did not return after its context was cancelled")
	}
}

// TestRunSNMPRoadNilDetectorIsANoOp proves the "disabled, or the bind
// failed" case main relies on: runSNMPRoad must return immediately
// rather than block, so main can start this goroutine unconditionally.
func TestRunSNMPRoadNilDetectorIsANoOp(t *testing.T) {
	done := make(chan struct{})
	go func() {
		runSNMPRoad(context.Background(), nil, discardLogger())
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("runSNMPRoad(nil, ...) did not return")
	}
}
