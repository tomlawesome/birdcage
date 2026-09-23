//go:build linux

package poisoner

import (
	"context"
	"errors"
	"net"
	"syscall"
	"testing"
	"time"
)

// reuseListen binds an unprivileged UDP port with SO_REUSEADDR, the way the
// real listener does, so these tests never need port 137, 5353 or 5355 --
// binding those needs the container's privileged-port floor lowered, which a
// test host has no business assuming.
func reuseListen(t *testing.T, addr string) *net.UDPConn {
	t.Helper()
	lc := net.ListenConfig{Control: controlSetReuseAddr}
	pc, err := lc.ListenPacket(context.Background(), "udp4", addr)
	if err != nil {
		t.Fatalf("bind %s: %v", addr, err)
	}
	conn, ok := pc.(*net.UDPConn)
	if !ok {
		_ = pc.Close()
		t.Fatalf("bind %s did not give a UDP connection", addr)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return conn
}

// TestListenerRefusesSend is issue #86 design point 5, proved rather than
// asserted: the counting socket is shut for writing when it opens, and after
// that the kernel refuses any send from it.
//
// This is the guarantee that does not depend on the code being correct. A
// process listening on 5355, 5353 or 137 is one sendto away from being a
// poisoner itself; this test is what says that sendto cannot succeed.
func TestListenerRefusesSend(t *testing.T) {
	conn := reuseListen(t, "127.0.0.1:0")
	if err := shutdownWrite(conn); err != nil {
		t.Fatalf("shutdownWrite: %v", err)
	}

	peer := reuseListen(t, "127.0.0.1:0")
	target := peer.LocalAddr().(*net.UDPAddr)

	n, err := conn.WriteToUDP([]byte("an answer nobody asked for"), target)
	if err == nil {
		t.Fatalf("the shut socket sent %d bytes: nothing in this agent may be able to answer another machine's query", n)
	}
	// Linux's answer to a send on a shut-for-writing socket. Named
	// explicitly so a kernel that ever answered something else would be
	// noticed here rather than silently accepted as "an error, good
	// enough".
	if !errors.Is(err, syscall.EPIPE) {
		t.Errorf("send failed with %v, want EPIPE", err)
	}

	// And nothing arrived, which is the claim that actually matters.
	_ = peer.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
	buf := make([]byte, 64)
	if got, _, err := peer.ReadFromUDP(buf); err == nil {
		t.Errorf("the peer received %d bytes from the shut socket: %q", got, buf[:got])
	}
}

// TestShutdownWriteKeepsReading proves the shutdown closes the send side
// only. If it closed reading too, the pace-matcher would count nothing and
// the multicast-answer path in Detector.observe would never fire.
func TestShutdownWriteKeepsReading(t *testing.T) {
	conn := reuseListen(t, "127.0.0.1:0")
	if err := shutdownWrite(conn); err != nil {
		t.Fatalf("shutdownWrite: %v", err)
	}
	local := conn.LocalAddr().(*net.UDPAddr)

	sender := reuseListen(t, "127.0.0.1:0")
	if _, err := sender.WriteToUDP([]byte("a query"), local); err != nil {
		t.Fatalf("send to the shut socket: %v", err)
	}

	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 64)
	n, _, err := conn.ReadFromUDP(buf)
	if err != nil {
		t.Fatalf("the shut socket could not read: %v", err)
	}
	if string(buf[:n]) != "a query" {
		t.Errorf("read %q, want \"a query\"", buf[:n])
	}
}

// TestShutdownWriteToleratesENOTCONN pins the kernel quirk the package
// comment describes. Linux returns ENOTCONN from shutdown() on an
// unconnected UDP socket -- there is no connection to shut -- but records
// the shutdown before returning it, which is why shutdownWrite treats that
// one error as success. A change that started returning it as a failure
// would turn every counting socket off.
func TestShutdownWriteToleratesENOTCONN(t *testing.T) {
	conn := reuseListen(t, "127.0.0.1:0")
	raw, err := conn.SyscallConn()
	if err != nil {
		t.Fatalf("SyscallConn: %v", err)
	}
	var direct error
	if err := raw.Control(func(fd uintptr) {
		direct = syscall.Shutdown(int(fd), syscall.SHUT_WR)
	}); err != nil {
		t.Fatalf("Control: %v", err)
	}
	if !errors.Is(direct, syscall.ENOTCONN) {
		t.Skipf("this kernel answers shutdown(SHUT_WR) on an unconnected UDP socket with %v, not ENOTCONN; the tolerance in shutdownWrite is then unnecessary rather than wrong", direct)
	}
	// Same call through shutdownWrite: the error is swallowed, and the send
	// side is shut all the same.
	if err := shutdownWrite(conn); err != nil {
		t.Fatalf("shutdownWrite turned ENOTCONN into a failure: %v", err)
	}
	if _, err := conn.WriteToUDP([]byte("x"), &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 9}); err == nil {
		t.Error("the socket can still send")
	}
}

// TestWildcardAndSpecificShareOnePort is what makes the NBT-NS design work:
// the counting listener binds the wildcard address on the shared port and
// the query socket binds the interface's own address on the same port, so a
// broadcast query reaches only the listener and the unicast reply to our own
// query reaches only the query socket.
//
// Loopback stands in for the segment here -- 127.255.255.255 is loopback's
// own broadcast address -- so the test needs no real interface and no
// privileged port.
func TestWildcardAndSpecificShareOnePort(t *testing.T) {
	// Bind the wildcard first, then a specific address on whatever port it
	// got: that is the order Detector.Open and openNBNSSocket use.
	wildcard := reuseListen(t, "0.0.0.0:0")
	port := wildcard.LocalAddr().(*net.UDPAddr).Port
	specific := reuseListen(t, net.JoinHostPort("127.0.0.1", itoa(port)))

	sender := reuseListen(t, "127.0.0.1:0")

	// A unicast datagram -- our own reply -- goes to the specific socket.
	if _, err := sender.WriteToUDP([]byte("reply"), &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: port}); err != nil {
		t.Fatalf("unicast send: %v", err)
	}
	if got := readOne(t, specific); got != "reply" {
		t.Errorf("the specific socket read %q, want \"reply\"", got)
	}
	if got := readOne(t, wildcard); got != "" {
		t.Errorf("the wildcard socket also saw the unicast reply: %q", got)
	}

	// A broadcast datagram -- the segment's own query -- goes to the
	// wildcard socket, which is the one counting.
	if _, err := sender.WriteToUDP([]byte("query"), &net.UDPAddr{IP: net.IPv4(127, 255, 255, 255), Port: port}); err != nil {
		t.Skipf("this host will not send to loopback's broadcast address (%v); the split is then untested here rather than broken", err)
	}
	if got := readOne(t, wildcard); got != "query" {
		t.Errorf("the wildcard socket read %q, want \"query\"", got)
	}
	if got := readOne(t, specific); got != "" {
		t.Errorf("the specific socket also saw the broadcast query: %q", got)
	}
}

// readOne reads one datagram with a short deadline, returning the empty
// string when nothing arrives.
func readOne(t *testing.T, conn *net.UDPConn) string {
	t.Helper()
	_ = conn.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
	buf := make([]byte, 64)
	n, _, err := conn.ReadFromUDP(buf)
	if err != nil {
		return ""
	}
	return string(buf[:n])
}

// itoa keeps the port formatting out of the test bodies without pulling in
// strconv for one call.
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var digits []byte
	for n > 0 {
		digits = append([]byte{byte('0' + n%10)}, digits...)
		n /= 10
	}
	return string(digits)
}

// TestListenReceiveOnlyIsShutForWriting opens a real listener the way
// Detector.Open does, on an unprivileged port, and proves the socket it
// hands back cannot write.
//
// listenReceiveOnly binds the wildcard on a fixed port, so this picks one
// well above the range a test host is likely to be using and skips rather
// than fails if something already has it.
func TestListenReceiveOnlyIsShutForWriting(t *testing.T) {
	const port = 45355
	conn, err := listenReceiveOnly(port, nil)
	if err != nil {
		t.Skipf("could not bind %d for the test: %v", port, err)
	}
	defer func() { _ = conn.Close() }()

	if _, err := conn.WriteToUDP([]byte("x"), &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 9}); err == nil {
		t.Fatal("a socket from listenReceiveOnly can send")
	}
}

// TestListenReceiveOnlyJoinsAMulticastGroup proves the group join really
// happens, so the pace-matcher sees the segment's LLMNR and mDNS queries
// rather than only its broadcasts -- and that a join failure is reported
// rather than leaving a half-open socket behind.
func TestListenReceiveOnlyJoinsAMulticastGroup(t *testing.T) {
	const port = 45353
	conn, err := listenReceiveOnly(port, []net.IP{mdnsGroupV4})
	if err != nil {
		t.Skipf("could not bind %d and join %s for the test: %v", port, mdnsGroupV4, err)
	}
	_ = conn.Close()

	// A group that is not multicast at all must be refused, and must not
	// leave a listener open on the port.
	if conn, err := listenReceiveOnly(port, []net.IP{net.ParseIP("::1")}); err == nil {
		_ = conn.Close()
		t.Error("listenReceiveOnly joined an address that is not an IPv4 group")
	}
	// The port is free again, which is what proves the failed call closed
	// what it had opened.
	again, err := listenReceiveOnly(port, nil)
	if err != nil {
		t.Errorf("the port was left bound after a failed join: %v", err)
		return
	}
	_ = again.Close()
}
