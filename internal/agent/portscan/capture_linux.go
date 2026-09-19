//go:build linux

package portscan

import (
	"errors"
	"fmt"
	"time"

	"golang.org/x/net/bpf"
	"golang.org/x/sys/unix"
)

// readTimeout is how long a blocked read waits before returning so the
// capture loop can check whether the agent is shutting down. A raw
// socket's file descriptor is not registered with Go's network poller,
// so a blocking recvfrom would otherwise sit there until the next packet
// arrived -- on a quiet segment, indefinitely, holding up shutdown. One
// wakeup a second on an idle canary is the whole cost.
const readTimeout = time.Second

// captureSocket is an AF_PACKET socket with the classic BPF filter from
// filter.go attached.
type captureSocket struct {
	fd int
}

// openCapture opens the capture socket, attaches the filter, and only
// then starts receiving.
//
// The order matters and is the reason this does not simply call
// socket(AF_PACKET, SOCK_DGRAM, htons(ETH_P_IP)) in one step: a socket
// created with a live protocol receives packets from the instant it
// exists, and every packet that arrives before SO_ATTACH_FILTER lands is
// queued unfiltered. On the one box built to attract floods, that window
// is exactly where a flood would be aimed. Creating the socket with
// protocol 0 -- which receives nothing -- attaching the filter, and then
// binding with ETH_P_IP closes it: there is no instant at which this
// socket is both receiving and unfiltered.
//
// SOCK_DGRAM, not SOCK_RAW: the kernel strips the link-layer header
// before handing the packet over, so parse.go reads an IPv4 header at
// offset zero. The filter still sees that header (see filter.go), which
// is why its offsets differ.
//
// Failure here is expected and survivable. Without CAP_NET_RAW the
// socket call returns EPERM, and the caller's contract is to log that
// once and keep running with detection off (issue #65) -- a canary that
// refused to start because it could not watch for scans would trade a
// missing detection for a missing honeypot.
func openCapture() (*captureSocket, error) {
	filter, err := assembleFilter()
	if err != nil {
		return nil, fmt.Errorf("assemble packet filter: %w", err)
	}

	fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("open AF_PACKET socket (needs CAP_NET_RAW): %w", err)
	}

	c := &captureSocket{fd: fd}
	if err := c.configure(filter); err != nil {
		_ = c.Close()
		return nil, err
	}
	return c, nil
}

// configure attaches the filter, sets the read timeout, and binds the
// socket to IPv4 on every interface. Split out from openCapture only so
// the single "close the fd and give up" path there covers all of it.
//
// The instructions are copied field by field into unix.SockFilter rather
// than reinterpreted through unsafe: the two structs happen to share a
// layout today, and a package whose whole job is reading hostile packets
// is the wrong place to depend on that continuing to be true. Thirteen
// instructions are copied once, at startup.
func (c *captureSocket) configure(assembled []bpf.RawInstruction) error {
	filter := make([]unix.SockFilter, len(assembled))
	for i, ins := range assembled {
		filter[i] = unix.SockFilter{Code: ins.Op, Jt: ins.Jt, Jf: ins.Jf, K: ins.K}
	}
	prog := &unix.SockFprog{
		Len:    uint16(len(filter)),
		Filter: &filter[0],
	}
	if err := unix.SetsockoptSockFprog(c.fd, unix.SOL_SOCKET, unix.SO_ATTACH_FILTER, prog); err != nil {
		return fmt.Errorf("attach packet filter: %w", err)
	}

	tv := unix.NsecToTimeval(int64(readTimeout))
	if err := unix.SetsockoptTimeval(c.fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &tv); err != nil {
		return fmt.Errorf("set capture read timeout: %w", err)
	}

	// Ifindex 0 is every interface: the Mockingbird container's macvlan
	// interface has no fixed name, and there is nothing else in its
	// network namespace to confuse the capture with.
	addr := &unix.SockaddrLinklayer{
		Protocol: htons(unix.ETH_P_IP),
		Ifindex:  0,
	}
	if err := unix.Bind(c.fd, addr); err != nil {
		return fmt.Errorf("bind capture socket: %w", err)
	}
	return nil
}

// Read waits for one packet and returns the bytes of it written into
// buf, together with whether the packet was inbound.
//
// The inbound test is the reason this returns the sockaddr's packet type
// rather than just bytes. A packet socket sees the agent's own outbound
// traffic as well as what arrives -- every SYN it sends birdcage would
// otherwise be a connection attempt to a port nothing local is listening
// on, which is precisely the tracker's definition of a scan hit. The
// classic filter cannot test this without SKF_AD_PKTTYPE, an extension
// bpf.NewVM does not implement, so testing it here keeps filter.go
// verifiable in a VM at the cost of one comparison per packet.
//
// A read that times out returns (0, false, errReadTimeout).
func (c *captureSocket) Read(buf []byte) (n int, inbound bool, err error) {
	n, from, err := unix.Recvfrom(c.fd, buf, 0)
	if err != nil {
		if errors.Is(err, unix.EAGAIN) || errors.Is(err, unix.EWOULDBLOCK) || errors.Is(err, unix.EINTR) {
			return 0, false, errReadTimeout
		}
		return 0, false, err
	}
	ll, ok := from.(*unix.SockaddrLinklayer)
	if !ok {
		return n, false, nil
	}
	return n, ll.Pkttype == unix.PACKET_HOST || ll.Pkttype == unix.PACKET_BROADCAST || ll.Pkttype == unix.PACKET_MULTICAST, nil
}

// Close releases the socket. Safe to call more than once; the second
// call's EBADF is discarded.
func (c *captureSocket) Close() error {
	if c.fd < 0 {
		return nil
	}
	fd := c.fd
	c.fd = -1
	return unix.Close(fd)
}

// htons converts a port/protocol number to network byte order, which is
// what sll_protocol wants. Go has no htons, and the alternative --
// letting the caller write 0x0008 -- is the kind of constant nobody can
// check by reading.
func htons(v uint16) uint16 { return v<<8 | v>>8 }
