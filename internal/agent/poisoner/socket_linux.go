//go:build linux

package poisoner

import (
	"context"
	"errors"
	"fmt"
	"net"
	"syscall"

	"golang.org/x/sys/unix"
)

// listenReceiveOnly opens one of the pace-matcher's counting sockets: it
// binds the wildcard address on port, joins groups so the segment's own
// multicast queries arrive, and then shuts the socket for writing so
// nothing this process does afterwards can put a byte on the wire from it.
//
// That last step is issue #86 design point 5, and it is the only guarantee
// in this package that does not depend on the code being correct: a
// process listening on 5355, 5353 or 137 is one sendto away from being a
// poisoner itself, and after this call the kernel refuses that sendto.
//
// SO_REUSEADDR is set because the NBT-NS query socket has to share port
// 137 with this one -- see openQuerySocket and this package's comment on
// how the two are kept apart.
func listenReceiveOnly(port int, groups []net.IP) (*net.UDPConn, error) {
	lc := net.ListenConfig{Control: controlSetReuseAddr}
	pc, err := lc.ListenPacket(context.Background(), "udp4", fmt.Sprintf("0.0.0.0:%d", port))
	if err != nil {
		return nil, fmt.Errorf("poisoner: listen udp4 on %d: %w", port, err)
	}
	conn, ok := pc.(*net.UDPConn)
	if !ok {
		_ = pc.Close()
		return nil, errors.New("poisoner: listener is not a UDP connection")
	}

	for _, group := range groups {
		if err := joinGroupV4(conn, group); err != nil {
			// Not fatal: a container whose interface cannot join a group
			// still counts the broadcast and unicast queries that reach
			// it, and pace-matching on a partial count is better than no
			// pace-matching. The caller reports it once at startup.
			_ = pc.Close()
			return nil, err
		}
	}

	if err := shutdownWrite(conn); err != nil {
		_ = conn.Close()
		return nil, err
	}
	return conn, nil
}

// shutdownWrite closes the send side of an already-bound UDP socket.
//
// Linux answers ENOTCONN here, because an unconnected datagram socket has
// no connection to shut down -- but inet_shutdown records the shutdown
// before returning that error, so the send side really is closed and a
// later sendto fails with EPIPE. Treating ENOTCONN as success is therefore
// correct rather than a shrug, and TestListenerRefusesSend proves the send
// actually fails rather than trusting this comment.
func shutdownWrite(conn *net.UDPConn) error {
	raw, err := conn.SyscallConn()
	if err != nil {
		return fmt.Errorf("poisoner: reach the listener's file descriptor: %w", err)
	}
	var shutErr error
	if err := raw.Control(func(fd uintptr) {
		shutErr = unix.Shutdown(int(fd), unix.SHUT_WR)
	}); err != nil {
		return fmt.Errorf("poisoner: shut the listener for writing: %w", err)
	}
	if shutErr != nil && !errors.Is(shutErr, unix.ENOTCONN) {
		return fmt.Errorf("poisoner: shut the listener for writing: %w", shutErr)
	}
	return nil
}

// controlSetReuseAddr is a net.ListenConfig control function that sets
// SO_REUSEADDR before the bind.
//
// On Linux this is what lets two UDP sockets share a port when their local
// addresses differ: the pace-matcher's wildcard 0.0.0.0:137 listener and
// the NBT-NS query socket bound to the interface's own address on the same
// port. Broadcast queries, whose destination is the subnet broadcast
// address, then reach only the wildcard socket, and the unicast reply to
// our own query reaches only the more specific one -- so neither socket
// sees the other's traffic and only one of them can write.
func controlSetReuseAddr(_, _ string, c syscall.RawConn) error {
	var serr error
	if err := c.Control(func(fd uintptr) {
		serr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_REUSEADDR, 1)
	}); err != nil {
		return err
	}
	return serr
}

// joinGroupV4 adds conn to an IPv4 multicast group on the interface the
// kernel's own routing table picks (interface index zero). On a canary
// that is the segment-facing interface, which is the one whose queries
// need counting; naming an interface explicitly would mean guessing which
// of a multi-homed container's interfaces the operator meant.
func joinGroupV4(conn *net.UDPConn, group net.IP) error {
	v4 := group.To4()
	if v4 == nil {
		return fmt.Errorf("poisoner: %s is not an IPv4 multicast group", group)
	}
	mreq := &unix.IPMreq{}
	copy(mreq.Multiaddr[:], v4)
	return controlErr(conn, func(fd int) error {
		return unix.SetsockoptIPMreq(fd, unix.IPPROTO_IP, unix.IP_ADD_MEMBERSHIP, mreq)
	}, fmt.Sprintf("join %s", group))
}

// setTTLv4 sets the unicast/broadcast IP TTL on an IPv4 socket.
func setTTLv4(conn *net.UDPConn, ttl int) error {
	return controlErr(conn, func(fd int) error {
		return unix.SetsockoptInt(fd, unix.IPPROTO_IP, unix.IP_TTL, ttl)
	}, "set the IP TTL")
}

// setMulticastTTLv4 sets the IPv4 multicast TTL and turns multicast
// loopback off.
//
// Loopback off matters for more than tidiness: with it on, the kernel
// delivers a copy of every query this agent sends to any socket in this
// container that has joined the group -- which is exactly what the
// pace-matcher's listener is. The canary would then count itself as one of
// the segment's talking hosts and pace against its own traffic.
func setMulticastTTLv4(conn *net.UDPConn, ttl int) error {
	if err := controlErr(conn, func(fd int) error {
		return unix.SetsockoptInt(fd, unix.IPPROTO_IP, unix.IP_MULTICAST_TTL, ttl)
	}, "set the IPv4 multicast TTL"); err != nil {
		return err
	}
	return controlErr(conn, func(fd int) error {
		return unix.SetsockoptInt(fd, unix.IPPROTO_IP, unix.IP_MULTICAST_LOOP, 0)
	}, "turn IPv4 multicast loopback off")
}

// setMulticastHopsV6 is setMulticastTTLv4's IPv6 twin: RFC 6762 and RFC
// 4795 both specify their hop limit the same way for IPv6 as their TTL for
// IPv4.
func setMulticastHopsV6(conn *net.UDPConn, hops int) error {
	if err := controlErr(conn, func(fd int) error {
		return unix.SetsockoptInt(fd, unix.IPPROTO_IPV6, unix.IPV6_MULTICAST_HOPS, hops)
	}, "set the IPv6 multicast hop limit"); err != nil {
		return err
	}
	return controlErr(conn, func(fd int) error {
		return unix.SetsockoptInt(fd, unix.IPPROTO_IPV6, unix.IPV6_MULTICAST_LOOP, 0)
	}, "turn IPv6 multicast loopback off")
}

// controlErr runs fn on conn's file descriptor, wrapping either failure
// -- reaching the descriptor, or the setsockopt itself -- in the same
// message.
func controlErr(conn *net.UDPConn, fn func(fd int) error, what string) error {
	raw, err := conn.SyscallConn()
	if err != nil {
		return fmt.Errorf("poisoner: %s: reach the file descriptor: %w", what, err)
	}
	var inner error
	if err := raw.Control(func(fd uintptr) { inner = fn(int(fd)) }); err != nil {
		return fmt.Errorf("poisoner: %s: %w", what, err)
	}
	if inner != nil {
		return fmt.Errorf("poisoner: %s: %w", what, inner)
	}
	return nil
}
