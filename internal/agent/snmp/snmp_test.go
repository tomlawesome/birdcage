package snmp

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net"
	"sync"
	"testing"
	"time"
)

func quietLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// collector is a concurrency-safe Submit sink: Run's own goroutine
// calls it while a test goroutine reads it, so plain slice access here
// would be exactly the data race `go test -race` exists to catch.
type collector struct {
	mu  sync.Mutex
	got [][]byte
}

func (c *collector) submit(message []byte) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.got = append(c.got, append([]byte(nil), message...))
	return nil
}

func (c *collector) count() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.got)
}

func (c *collector) at(i int) []byte {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.got[i]
}

func waitForCount(t *testing.T, c *collector, n int, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if c.count() >= n {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("timed out after %s waiting for %d event(s); got %d", timeout, n, c.count())
}

// newTestDetector builds a Detector over a nonexistent config file, so
// New's fallback path is exercised the same way portscan's tests do,
// and never opens a socket -- for tests that call d.handle directly.
func newTestDetector(t *testing.T, submit Submit) *Detector {
	t.Helper()
	d, warning := New(Config{
		ConfPath: t.TempDir() + "/absent.conf",
	}, submit, quietLogger())
	if warning == "" {
		t.Fatal("expected a warning for an unreadable config file")
	}
	return d
}

func udpAddr(t *testing.T, ip string, port int) *net.UDPAddr {
	t.Helper()
	addr := &net.UDPAddr{IP: net.ParseIP(ip), Port: port}
	if addr.IP == nil {
		t.Fatalf("bad test IP %q", ip)
	}
	return addr
}

// TestHandleEmitsOneEventForARealGet is the glue test between the
// parser and the wire encoding: a real captured GetRequest in, one
// OpenCanary-shaped event out, with the fields a dashboard reader (or
// #46's self-test matcher) actually needs.
func TestHandleEmitsOneEventForARealGet(t *testing.T) {
	t.Parallel()

	c := &collector{}
	d := newTestDetector(t, c.submit)
	d.handle(mustHex(t, realV1GetTwoOIDs), udpAddr(t, "198.51.100.5", 45090))

	if c.count() != 1 {
		t.Fatalf("emitted %d events, want exactly 1", c.count())
	}
	var ev struct {
		SrcHost string `json:"src_host"`
		SrcPort int    `json:"src_port"`
		LogType int    `json:"logtype"`
		NodeID  string `json:"node_id"`
		LogData struct {
			CommunityString string   `json:"COMMUNITY_STRING"`
			Requests        []string `json:"REQUESTS"`
		} `json:"logdata"`
	}
	if err := json.Unmarshal(c.at(0), &ev); err != nil {
		t.Fatalf("decode emitted event: %v", err)
	}
	if ev.SrcHost != "198.51.100.5" || ev.SrcPort != 45090 {
		t.Errorf("src = %s:%d, want 198.51.100.5:45090", ev.SrcHost, ev.SrcPort)
	}
	if ev.LogType != LogTypeSNMPCmd {
		t.Errorf("logtype = %d, want %d", ev.LogType, LogTypeSNMPCmd)
	}
	if ev.NodeID != DefaultNodeID {
		t.Errorf("node_id = %q, want the fallback %q", ev.NodeID, DefaultNodeID)
	}
	if ev.LogData.CommunityString != "e2e-snmp-marker-0123456789abcdef" {
		t.Errorf("COMMUNITY_STRING = %q, want the marker net-snmp sent", ev.LogData.CommunityString)
	}
	want := []string{"1.3.6.1.2.1.1.1.0", "1.3.6.1.2.1.1.5.0"}
	if len(ev.LogData.Requests) != len(want) || ev.LogData.Requests[0] != want[0] || ev.LogData.Requests[1] != want[1] {
		t.Errorf("REQUESTS = %v, want %v", ev.LogData.Requests, want)
	}
	if d.Logged() != 1 {
		t.Errorf("Logged() = %d, want 1", d.Logged())
	}
}

// TestHandleDropsHostileDatagramsSilently is this package's version of
// portscan's TestDetectorDropsUninterestingPacketsSilently: a datagram
// this parser cannot make sense of must cost nothing observable -- no
// event, and no log line per datagram, which on a port this service
// exists to be attacked on would be the denial of service itself. The
// individual malformed shapes and the "never panics" property are
// parse_test.go's job; this proves the same inputs produce no side
// effect at the detector layer, and that the detector keeps working
// afterwards.
func TestHandleDropsHostileDatagramsSilently(t *testing.T) {
	t.Parallel()

	c := &collector{}
	d := newTestDetector(t, c.submit)
	src := udpAddr(t, "203.0.113.9", 12345)

	hostile := [][]byte{
		{},
		{0x30},
		{0x30, 0x80, 0x02, 0x01, 0x00},
		{0x30, 0xFF, 0x00},
		make([]byte, 256),
		mustHex(t, realV1GetTwoOIDs)[:10],
	}
	for _, packet := range hostile {
		d.handle(packet, src)
	}
	if c.count() != 0 {
		t.Fatalf("emitted %d events for hostile datagrams, want 0: %s", c.count(), c.at(0))
	}

	// The detector must still work afterwards: a real request right
	// behind a stream of garbage must not be lost because of anything
	// the garbage left behind.
	d.handle(mustHex(t, realV2cGetOneOID), src)
	if c.count() != 1 {
		t.Fatalf("emitted %d events after a real request following garbage, want 1", c.count())
	}
}

// TestHandleSurvivesASubmitFailure mirrors portscan's
// TestDetectorSurvivesASubmitFailure: a rejected event must not stop
// the detector, and must not be counted as logged.
func TestHandleSurvivesASubmitFailure(t *testing.T) {
	t.Parallel()

	d := newTestDetector(t, func([]byte) error { return errors.New("queue said no") })
	d.handle(mustHex(t, realV1GetTwoOIDs), udpAddr(t, "198.51.100.5", 1))

	if d.Logged() != 0 {
		t.Fatalf("Logged() = %d, want 0 -- a refused event was counted as emitted", d.Logged())
	}
}

// TestDetectorEndToEndNeverReplies opens a real UDP socket -- the one
// part of this package parse_test.go and the direct-handle tests above
// cannot exercise -- and proves the two things that matter at that
// layer: a real datagram in produces a real queued event out, and
// nothing is ever written back to the sender. "Never reply" is this
// package's central safety property (issue #88): a canary that answers
// is not a silent listener any more.
func TestDetectorEndToEndNeverReplies(t *testing.T) {
	t.Parallel()

	c := &collector{}
	d, warning := New(Config{
		ListenAddr: "127.0.0.1:0",
		ConfPath:   t.TempDir() + "/absent.conf",
	}, c.submit, quietLogger())
	if warning == "" {
		t.Fatal("expected a warning for an unreadable config file")
	}
	if err := d.Open(); err != nil {
		t.Fatalf("Open: %v", err)
	}
	serverAddr := d.conn.LocalAddr().String()

	ctx, cancel := context.WithCancel(context.Background())
	runDone := make(chan error, 1)
	go func() { runDone <- d.Run(ctx) }()
	t.Cleanup(func() {
		cancel()
		select {
		case err := <-runDone:
			if err != nil {
				t.Errorf("Run returned an error after cancellation: %v", err)
			}
		case <-time.After(5 * time.Second):
			t.Fatal("detector.Run did not stop after its context was cancelled")
		}
	})

	client, err := net.Dial("udp", serverAddr)
	if err != nil {
		t.Fatalf("dial %s: %v", serverAddr, err)
	}
	defer func() { _ = client.Close() }()

	if _, err := client.Write(mustHex(t, realV1GetTwoOIDs)); err != nil {
		t.Fatalf("write real SNMP request: %v", err)
	}

	waitForCount(t, c, 1, 2*time.Second)

	// Now prove the negative: nothing comes back. A short read deadline
	// on the client socket turns "no reply" into a fast, deterministic
	// timeout rather than a test that only passes by accident of
	// scheduling.
	if err := client.SetReadDeadline(time.Now().Add(300 * time.Millisecond)); err != nil {
		t.Fatalf("SetReadDeadline: %v", err)
	}
	buf := make([]byte, 64)
	n, err := client.Read(buf)
	if err == nil {
		t.Fatalf("the listener replied with %d bytes; it must never answer", n)
	}
	var netErr net.Error
	if !errors.As(err, &netErr) || !netErr.Timeout() {
		t.Fatalf("expected a read timeout proving silence, got: %v", err)
	}
}
