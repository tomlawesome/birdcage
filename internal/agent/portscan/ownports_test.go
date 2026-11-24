package portscan

import (
	"bytes"
	"log/slog"
	"testing"
	"time"
)

// Issue #240: the poisoner sends its LLMNR and mDNS questions from
// ephemeral UDP ports and closes the socket when the lookup is done, so an
// answer arriving late is a datagram to a closed port. The poisoner tells
// the detector each local port it sent from (OwnPorts.Add), and the
// detector skips UDP datagrams to such a port for ownPortWindow (30 s)
// after the query. These tests name the seam: NewOwnPorts, OwnPorts.Add,
// OwnPorts.Recent and Config.OwnPorts.

// newOwnPortsDetector builds a detector whose /proc tables show no socket on
// any of the ephemeral ports the tests use, sharing own with the caller.
func newOwnPortsDetector(t *testing.T, clock *fakeClock, own *OwnPorts) (*Detector, *[][]byte) {
	t.Helper()
	var got [][]byte
	var logs bytes.Buffer
	log := slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelWarn}))
	d, _ := New(Config{
		ConfPath: t.TempDir() + "/absent.conf",
		Now:      clock.Now,
		ReadFile: newFakeProc().read,
		OwnPorts: own,
	}, func(message []byte) error {
		got = append(got, append([]byte(nil), message...))
		return nil
	}, log)
	return d, &got
}

// fromOtherHost rewrites the IPv4 source of a test packet, so a second
// sender can be told apart from the one ipv4Packet always uses.
func fromOtherHost(pkt []byte) []byte {
	out := append([]byte(nil), pkt...)
	copy(out[12:16], []byte{198, 51, 100, 77})
	return out
}

var queryPorts = []uint16{49152, 49153, 49154, 49155, 49156}

func recordQueries(own *OwnPorts, at time.Time) {
	for _, p := range queryPorts {
		own.Add(p, at)
	}
}

func TestAnswersToTheOwnQueryPortsDoNotCountAsAScan(t *testing.T) {
	t.Parallel()

	clock := newFakeClock()
	own := NewOwnPorts()
	d, got := newOwnPortsDetector(t, clock, own)
	recordQueries(own, clock.Now())

	clock.Advance(500 * time.Millisecond)
	for _, p := range queryPorts {
		d.handle(udpPacket(p))
		clock.Advance(200 * time.Millisecond)
	}
	if len(*got) != 0 {
		t.Fatalf("answers to the poisoner's own queries alerted: %s", (*got)[0])
	}
}

func TestAnswerAfterTheScanWindowCountsAgain(t *testing.T) {
	t.Parallel()

	clock := newFakeClock()
	own := NewOwnPorts()
	d, got := newOwnPortsDetector(t, clock, own)
	recordQueries(own, clock.Now())

	clock.Advance(31 * time.Second)
	for _, p := range queryPorts {
		d.handle(udpPacket(p))
		clock.Advance(200 * time.Millisecond)
	}
	if len(*got) != 1 {
		t.Fatalf("five datagrams to recorded ports 31 s after the query gave %d events, want 1", len(*got))
	}
}

func TestTCPSYNToAQueryPortNumberStillCounts(t *testing.T) {
	t.Parallel()

	clock := newFakeClock()
	own := NewOwnPorts()
	d, got := newOwnPortsDetector(t, clock, own)
	recordQueries(own, clock.Now())

	for _, p := range queryPorts {
		d.handle(scanPacket(p))
		clock.Advance(200 * time.Millisecond)
	}
	if len(*got) != 1 {
		t.Fatalf("five TCP SYNs to recorded UDP port numbers gave %d events, want 1 (the exemption is UDP only)", len(*got))
	}
}

func TestClosedPortsFromAnotherHostStillAlertBesideOwnPorts(t *testing.T) {
	t.Parallel()

	clock := newFakeClock()
	own := NewOwnPorts()
	d, got := newOwnPortsDetector(t, clock, own)
	recordQueries(own, clock.Now())

	// The answerer's replies are skipped; a different host sweeping five
	// other closed UDP ports is not.
	for i, p := range queryPorts {
		d.handle(udpPacket(p))
		d.handle(fromOtherHost(udpPacket(30000 + uint16(i))))
		clock.Advance(200 * time.Millisecond)
	}
	if len(*got) != 1 {
		t.Fatalf("a sweep from another host gave %d events, want 1", len(*got))
	}
}

func TestOwnPortsOnlyKnowsPortsItWasToldAbout(t *testing.T) {
	t.Parallel()

	clock := newFakeClock()
	own := NewOwnPorts()
	own.Add(49152, clock.Now())

	if !own.Recent(49152, clock.Now().Add(10*time.Second)) {
		t.Error("a port added 10 s ago is not recent")
	}
	if own.Recent(49153, clock.Now()) {
		t.Error("a port nobody added is recent")
	}
	if own.Recent(49152, clock.Now().Add(31*time.Second)) {
		t.Error("a port added 31 s ago is still recent")
	}
}
