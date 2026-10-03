package portscan

import (
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"testing"
	"time"
)

func quietLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// newTestDetector builds a detector over a temporary config naming the
// given listening ports, and returns it with the slice every submitted
// event lands in.
func newTestDetector(t *testing.T, clock *fakeClock, listening []uint16) (*Detector, *[][]byte) {
	t.Helper()

	var got [][]byte
	d, warning := New(Config{
		// No config file: New must fall back rather than refuse, and
		// ExtraIgnorePorts is then the whole listening set.
		ConfPath:         t.TempDir() + "/absent.conf",
		ExtraIgnorePorts: listening,
		Now:              clock.Now,
	}, func(message []byte) error {
		got = append(got, append([]byte(nil), message...))
		return nil
	}, quietLogger())
	if warning == "" {
		t.Fatal("expected a warning for an unreadable config file")
	}
	return d, &got
}

// scanPacket is one captured frame as the kernel hands it to a
// SOCK_DGRAM reader: a bare IPv4 packet, no Ethernet header.
func scanPacket(dstPort uint16) []byte {
	return ipv4Packet(ipv4Header{protocol: protoTCP}, tcpSegment(44123, dstPort, tcpFlagSYN))
}

// TestDetectorIgnoresOurOwnListeningPorts is the false-positive test.
// OpenCanary's emulated services answer on these ports and birdcage
// already gets an event for each hit; counting them again as scan
// evidence would make every ordinary visit to the honeypot look like a
// sweep.
func TestDetectorIgnoresOurOwnListeningPorts(t *testing.T) {
	t.Parallel()

	clock := newFakeClock()
	listening := []uint16{21, 22, 23, 80, 3389, 9919}
	d, got := newTestDetector(t, clock, listening)

	for _, port := range listening {
		d.handle(scanPacket(port))
		clock.Advance(time.Second)
	}
	// Repeatedly, well past the threshold.
	for i := 0; i < 5; i++ {
		for _, port := range listening {
			d.handle(scanPacket(port))
			clock.Advance(100 * time.Millisecond)
		}
	}

	if len(*got) != 0 {
		t.Fatalf("emitted %d events for traffic to our own listening ports: %s", len(*got), (*got)[0])
	}
	if d.Detected() != 0 {
		t.Fatalf("Detected() = %d, want 0", d.Detected())
	}
	if d.ListeningPorts() != len(listening) {
		t.Fatalf("ListeningPorts() = %d, want %d", d.ListeningPorts(), len(listening))
	}
}

// TestDetectorEmitsOneEventForAScan is the end-to-end of everything this
// package does, minus the socket: packets in, one OpenCanary event out.
func TestDetectorEmitsOneEventForAScan(t *testing.T) {
	t.Parallel()

	clock := newFakeClock()
	d, got := newTestDetector(t, clock, []uint16{21, 22, 23, 80, 3389, 9919})

	// A sweep of closed ports, with two hits on a listening one mixed in
	// -- those must not count towards the threshold, so five closed
	// ports are still needed.
	for _, port := range []uint16{25, 22, 110, 143, 22, 445} {
		d.handle(scanPacket(port))
		clock.Advance(200 * time.Millisecond)
	}
	if len(*got) != 0 {
		t.Fatalf("fired after four closed ports: %s", (*got)[0])
	}

	d.handle(scanPacket(5900))
	if len(*got) != 1 {
		t.Fatalf("emitted %d events, want exactly 1", len(*got))
	}

	var ev struct {
		DstHost string `json:"dst_host"`
		DstPort int    `json:"dst_port"`
		LogType int    `json:"logtype"`
		NodeID  string `json:"node_id"`
		SrcHost string `json:"src_host"`
		SrcPort int    `json:"src_port"`
		LogData struct {
			Count string `json:"COUNT"`
			Ports string `json:"PORTS"`
			Proto string `json:"PROTO"`
		} `json:"logdata"`
	}
	if err := json.Unmarshal((*got)[0], &ev); err != nil {
		t.Fatalf("decode emitted event: %v", err)
	}
	if ev.LogType != LogTypePortSYN {
		t.Errorf("logtype = %d, want %d", ev.LogType, LogTypePortSYN)
	}
	if ev.NodeID != DefaultNodeID {
		t.Errorf("node_id = %q, want the fallback %q", ev.NodeID, DefaultNodeID)
	}
	if ev.SrcHost != "198.51.100.5" || ev.SrcPort != 44123 {
		t.Errorf("src = %s:%d, want 198.51.100.5:44123", ev.SrcHost, ev.SrcPort)
	}
	if ev.DstHost != "203.0.113.9" {
		t.Errorf("dst_host = %q, want 203.0.113.9", ev.DstHost)
	}
	if ev.DstPort != 25 {
		t.Errorf("dst_port = %d, want 25 (the first non-listening port)", ev.DstPort)
	}
	if ev.LogData.Count != "5" {
		t.Errorf("COUNT = %q, want 5 -- the two hits on a listening port must not be counted", ev.LogData.Count)
	}
	if ev.LogData.Ports != "25,110,143,445,5900" {
		t.Errorf("PORTS = %q, want the five closed ports in first-seen order", ev.LogData.Ports)
	}
	if ev.LogData.Proto != ProtoTCP {
		t.Errorf("PROTO = %q, want %q", ev.LogData.Proto, ProtoTCP)
	}
	if d.Detected() != 1 {
		t.Errorf("Detected() = %d, want 1", d.Detected())
	}
}

// TestDetectorDropsUninterestingPacketsSilently: the capture socket's
// filter is the flood defence, but a packet that reaches userspace and
// is not a connection attempt must still cost nothing and produce
// nothing -- no event, and (the reason it is worth a test) no log line
// per packet, which on a box built to be flooded would be the denial of
// service itself.
func TestDetectorDropsUninterestingPacketsSilently(t *testing.T) {
	t.Parallel()

	clock := newFakeClock()
	d, got := newTestDetector(t, clock, nil)

	for i := 0; i < 100; i++ {
		d.handle(ipv4Packet(ipv4Header{protocol: protoTCP}, tcpSegment(22, uint16(40000+i), tcpFlagSYN|tcpFlagACK)))
		d.handle(ipv4Packet(ipv4Header{protocol: 1}, make([]byte, 8)))
		d.handle(nil)
		d.handle([]byte{0xff, 0xff})
		clock.Advance(time.Millisecond)
	}
	if len(*got) != 0 {
		t.Fatalf("emitted %d events for packets that are not connection attempts", len(*got))
	}
}

// TestDetectorSurvivesASubmitFailure: a rejected event must not stop the
// loop that is watching for the next one, and must not be counted as
// delivered.
func TestDetectorSurvivesASubmitFailure(t *testing.T) {
	t.Parallel()

	clock := newFakeClock()
	d, _ := New(Config{
		ConfPath: t.TempDir() + "/absent.conf",
		Now:      clock.Now,
	}, func([]byte) error {
		return errors.New("queue said no")
	}, quietLogger())

	for _, port := range []uint16{21, 23, 25, 3389, 5900, 8080, 9999} {
		d.handle(scanPacket(port))
		clock.Advance(time.Second)
	}
	if d.Detected() != 0 {
		t.Fatalf("Detected() = %d, want 0 -- a refused event was counted as emitted", d.Detected())
	}
}
