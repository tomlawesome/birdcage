package poisoner

import (
	"errors"
	"fmt"
	"net"
)

// segment is what this package needs to know about the network the canary
// is on: which address to send from, and where a NBT-NS broadcast goes.
type segment struct {
	// Name is the interface's name, kept for the startup warning when
	// something about it does not work. Never logged beside a bait name.
	Name string

	// IP is the interface's IPv4 unicast address. The NBT-NS query socket
	// binds this specific address on port 137, which is what keeps it
	// apart from the pace-matcher's wildcard listener on the same port.
	IP net.IP

	// Broadcast is the subnet broadcast address NBT-NS queries go to
	// (RFC 1002 section 4.2.12's "broadcast" name query). Derived from
	// the interface's own address and mask rather than using
	// 255.255.255.255: a limited broadcast is not what a Windows client
	// sends, and on a multi-homed host it would go out of whichever
	// interface the routing table picked.
	Broadcast net.IP

	// HasIPv6 is whether the interface has a usable IPv6 address, so the
	// LLMNR and mDNS senders know whether their IPv6 twins have anywhere
	// to go. A container with IPv6 disabled is the ordinary case, not a
	// failure.
	HasIPv6 bool
}

// errNoSegment is returned when no interface looks like a segment to ask
// on. A canary with only loopback is the usual cause -- a container run
// with `--network none`, or a unit test's own namespace.
var errNoSegment = errors.New("poisoner: no broadcast-capable interface with an IPv4 address")

// findSegment picks the interface to ask on.
//
// The rule is the narrowest one that works: up, not loopback, capable of
// broadcast and multicast, and holding a routable IPv4 address. A canary
// normally has exactly one such interface -- ADR-0008's run shape puts it
// on a macvlan on the segment it is watching -- and on a host with more
// than one, the first in the kernel's own ordering is the same one the
// routing table would pick for an unbound socket, so the bait goes where
// the rest of the canary's traffic goes.
func findSegment() (segment, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return segment{}, fmt.Errorf("poisoner: list interfaces: %w", err)
	}
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 ||
			iface.Flags&net.FlagLoopback != 0 ||
			iface.Flags&net.FlagBroadcast == 0 ||
			iface.Flags&net.FlagMulticast == 0 {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		seg := segment{Name: iface.Name}
		for _, addr := range addrs {
			ipNet, ok := addr.(*net.IPNet)
			if !ok {
				continue
			}
			if v4 := ipNet.IP.To4(); v4 != nil {
				if v4.IsLinkLocalUnicast() || seg.IP != nil {
					// 169.254.0.0/16 means DHCP failed; a second address
					// on the same interface is not a second segment.
					continue
				}
				bcast, err := broadcastFor(ipNet)
				if err != nil {
					continue
				}
				seg.IP, seg.Broadcast = v4, bcast
				continue
			}
			if ipNet.IP.To16() != nil && ipNet.IP.IsGlobalUnicast() {
				seg.HasIPv6 = true
			}
		}
		if seg.IP != nil {
			return seg, nil
		}
	}
	return segment{}, errNoSegment
}

// broadcastFor computes a network's subnet broadcast address: every host
// bit set. A /31 or /32 has no broadcast address to speak of, so it is
// refused rather than producing the interface's own address back.
func broadcastFor(ipNet *net.IPNet) (net.IP, error) {
	// To4 is the test for "this is IPv4", and it has to come first: an IPv6
	// network can carry a 16-byte mask whose last four bytes happen to look
	// like a usable IPv4 one, and reaching the loop below without an IPv4
	// address to index is a crash rather than a wrong answer.
	ip := ipNet.IP.To4()
	if ip == nil {
		return nil, fmt.Errorf("poisoner: %s is not an IPv4 network", ipNet)
	}
	mask := ipNet.Mask
	switch len(mask) {
	case net.IPv4len:
	case net.IPv6len:
		// An IPv4 address carrying a 16-byte mask: the last four bytes are
		// the IPv4 mask. net.Interface.Addrs really does produce this.
		mask = mask[net.IPv6len-net.IPv4len:]
	default:
		return nil, fmt.Errorf("poisoner: %s has a mask this package cannot read", ipNet)
	}
	ones, bits := net.IPMask(mask).Size()
	if bits != 32 || ones > 30 {
		return nil, fmt.Errorf("poisoner: %s is too small to have a broadcast address", ipNet)
	}
	out := make(net.IP, net.IPv4len)
	for i := range out {
		out[i] = ip[i] | ^mask[i]
	}
	return out, nil
}
