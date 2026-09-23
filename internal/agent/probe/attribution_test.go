package probe

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"testing"
	"time"
)

// TestProbeNTP_SendsTheMonlistRequest checks probeNTP's payload against
// ntp.py's own trigger condition -- `len(data) >= 4 and d[3] == '*'`
// (byte 3 is 0x2A, the historic "ntpdc monlist" request code, which
// happens to equal ASCII '*') -- since that module logs a fixed string
// regardless of anything else in the packet, this is the whole probe.
func TestProbeNTP_SendsTheMonlistRequest(t *testing.T) {
	ln, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer func() { _ = ln.Close() }() // test teardown; nothing left to act on a close error

	port := ln.LocalAddr().(*net.UDPAddr).Port

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := probeNTP(ctx, "127.0.0.1", port, "unused-marker"); err != nil {
		t.Fatalf("probeNTP: %v", err)
	}

	buf := make([]byte, 64)
	if err := ln.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatalf("set read deadline: %v", err)
	}
	n, _, err := ln.ReadFromUDP(buf)
	if err != nil {
		t.Fatalf("read datagram: %v", err)
	}
	got := buf[:n]
	want := []byte{0x17, 0x00, 0x03, 0x2A}
	if len(got) < 4 || string(got[:4]) != string(want) {
		t.Fatalf("datagram = %x, want it to start with %x (mode 7, monlist)", got, want)
	}
	if got[3] != '*' {
		t.Fatalf("byte 3 = %#x, want '*' (0x2A) -- ntp.py's own trigger check", got[3])
	}
}

// reserveConsecutiveFreePorts finds portscanTouchCount consecutive ports
// on 127.0.0.1 that are all free at the moment this returns, retrying a
// fresh base a bounded number of times if the first candidate collides.
// No sleeps: each attempt is a direct bind/close, and the bound is on
// attempt count, not wall-clock time.
func reserveConsecutiveFreePorts(t *testing.T, n int) int {
	t.Helper()
	for attempt := 0; attempt < 20; attempt++ {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("listen: %v", err)
		}
		_, portStr, _ := net.SplitHostPort(ln.Addr().String())
		base, _ := strconv.Atoi(portStr)
		_ = ln.Close()

		ok := true
		for i := 1; i < n; i++ {
			l2, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", base+i))
			if err != nil {
				ok = false
				break
			}
			_ = l2.Close()
		}
		if ok {
			return base
		}
	}
	t.Fatal("could not reserve consecutive free ports")
	return 0
}

// TestProbePortscan_TreatsRefusalAsSuccessAcrossTheWholeRange is #46
// slice 2's inversion, stated as a test: five closed ports, no error --
// a refusal is the scan signature working, not a probe failure.
func TestProbePortscan_TreatsRefusalAsSuccessAcrossTheWholeRange(t *testing.T) {
	base := reserveConsecutiveFreePorts(t, portscanTouchCount)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := probePortscan(ctx, "127.0.0.1", base, "unused-marker"); err != nil {
		t.Fatalf("probePortscan against %d unlistened ports: want nil, got %v", portscanTouchCount, err)
	}
}

// TestProbePortscan_ReachesEveryPortInTheRange proves the loop does not
// stop at the first refusal: only the middle port of the range has a
// listener, and it must still be dialed.
func TestProbePortscan_ReachesEveryPortInTheRange(t *testing.T) {
	base := reserveConsecutiveFreePorts(t, portscanTouchCount)
	mid := base + portscanTouchCount/2

	ln, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", mid))
	if err != nil {
		t.Fatalf("listen on %d: %v", mid, err)
	}
	defer func() { _ = ln.Close() }() // test teardown; nothing left to act on a close error

	accepted := make(chan struct{}, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer func() { _ = c.Close() }() // test teardown; nothing left to act on a close error
		accepted <- struct{}{}
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := probePortscan(ctx, "127.0.0.1", base, "unused-marker"); err != nil {
		t.Fatalf("probePortscan: %v", err)
	}

	select {
	case <-accepted:
	case <-time.After(2 * time.Second):
		t.Fatal("probePortscan never reached the listening port in the middle of its range")
	}
}

func TestProbePortscan_CancelledContextIsAnError(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := probePortscan(ctx, "127.0.0.1", 50000, "unused-marker"); err == nil {
		t.Fatal("probePortscan with an already-cancelled context: want an error, got nil")
	}
}

// TestProbePortscan_WrapsPortNumberNearTheCeiling exercises the one
// arithmetic edge probePortscan's own doc comment names: a base port
// within portscanTouchCount-1 of 65535 must still dial every touch as a
// valid port number, wrapping rather than producing an invalid one.
func TestProbePortscan_WrapsPortNumberNearTheCeiling(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	base := 65535 - portscanTouchCount + 2 // touches base..65535 then wraps to 1
	if err := probePortscan(ctx, "127.0.0.1", base, "unused-marker"); err != nil {
		t.Fatalf("probePortscan near the port ceiling: want nil, got %v", err)
	}
}

// TestProbeNTP_UnresolvableAddressIsAnError covers probeNTP's dial
// failure path: a UDP dial to something that can never resolve, the one
// way this connectionless probe's dial can fail before it ever writes.
func TestProbeNTP_UnresolvableAddressIsAnError(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := probeNTP(ctx, "not a valid host or address", 123, "unused-marker"); err == nil {
		t.Fatal("probeNTP against an unresolvable address: want an error, got nil")
	}
}
