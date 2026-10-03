package poisoner

import (
	"net"
	"testing"
)

// TestBroadcastFor is where a NBT-NS query is actually aimed. Getting it
// wrong sends the broadcast to the wrong segment, or to 255.255.255.255,
// which is not what a Windows client sends.
func TestBroadcastFor(t *testing.T) {
	tests := []struct {
		cidr    string
		want    string
		wantErr bool
	}{
		{cidr: "192.168.1.5/24", want: "192.168.1.255"},
		{cidr: "10.0.0.5/8", want: "10.255.255.255"},
		{cidr: "172.16.4.10/20", want: "172.16.15.255"},
		{cidr: "10.1.2.3/30", want: "10.1.2.3"},
		// A /31 is a point-to-point link and a /32 a single host: neither
		// has a broadcast address, so neither is a segment to ask on.
		{cidr: "10.1.2.2/31", wantErr: true},
		{cidr: "10.1.2.2/32", wantErr: true},
	}

	for _, tc := range tests {
		t.Run(tc.cidr, func(t *testing.T) {
			ip, ipNet, err := net.ParseCIDR(tc.cidr)
			if err != nil {
				t.Fatalf("ParseCIDR: %v", err)
			}
			// net.Interface.Addrs gives the interface's own address with the
			// network's mask, not the masked network address, so that is
			// what this is handed.
			got, err := broadcastFor(&net.IPNet{IP: ip, Mask: ipNet.Mask})
			if (err != nil) != tc.wantErr {
				t.Fatalf("error = %v, want an error: %v", err, tc.wantErr)
			}
			if tc.wantErr {
				return
			}
			if got.String() != tc.want {
				t.Errorf("broadcast = %s, want %s", got, tc.want)
			}
		})
	}
}

// TestBroadcastForAcceptsA16ByteMask covers the shape the standard library
// hands back for an IPv4 address carrying an IPv6-length mask, which is a
// real thing net.Interface.Addrs can produce.
func TestBroadcastForAcceptsA16ByteMask(t *testing.T) {
	mask := make(net.IPMask, net.IPv6len)
	// The last four bytes carry the IPv4 /24.
	copy(mask[net.IPv6len-net.IPv4len:], net.IPv4Mask(255, 255, 255, 0))
	got, err := broadcastFor(&net.IPNet{IP: net.ParseIP("192.168.1.5"), Mask: mask})
	if err != nil {
		t.Fatalf("broadcastFor: %v", err)
	}
	if got.String() != "192.168.1.255" {
		t.Errorf("broadcast = %s, want 192.168.1.255", got)
	}
}

// TestBroadcastForRefusesWhatIsNotIPv4 keeps an IPv6 network from producing
// a nonsense broadcast address: IPv6 has no broadcast, and NBT-NS is IPv4
// only.
func TestBroadcastForRefusesWhatIsNotIPv4(t *testing.T) {
	_, ipNet, err := net.ParseCIDR("2001:db8::/64")
	if err != nil {
		t.Fatalf("ParseCIDR: %v", err)
	}
	if got, err := broadcastFor(ipNet); err == nil {
		t.Errorf("broadcastFor on an IPv6 network gave %s", got)
	}
}

// TestFindSegment runs against whatever interfaces this host actually has.
// It asserts the shape of the answer rather than a particular address, so it
// is meaningful on a developer's machine, in CI, and in the container --
// none of which have the same network.
func TestFindSegment(t *testing.T) {
	seg, err := findSegment()
	if err != nil {
		// A host with only loopback is a real case (a container run with
		// --network none, or a sandboxed test runner), and the right answer
		// there is the error findSegment returned.
		t.Skipf("no broadcast-capable interface on this host: %v", err)
	}
	if seg.Name == "" {
		t.Error("the segment has no interface name")
	}
	if seg.IP == nil || seg.IP.To4() == nil {
		t.Fatalf("segment IP = %v, want an IPv4 address", seg.IP)
	}
	if seg.IP.IsLoopback() {
		t.Error("findSegment picked loopback, which has no segment to ask")
	}
	if seg.IP.IsLinkLocalUnicast() {
		t.Error("findSegment picked a link-local address, which means DHCP failed")
	}
	if seg.Broadcast == nil || seg.Broadcast.To4() == nil {
		t.Fatalf("segment broadcast = %v, want an IPv4 address", seg.Broadcast)
	}
	if seg.Broadcast.Equal(seg.IP) {
		t.Error("the broadcast address is the interface's own address")
	}
	// The interface really is up and capable of what the segment needs.
	iface, err := net.InterfaceByName(seg.Name)
	if err != nil {
		t.Fatalf("InterfaceByName(%q): %v", seg.Name, err)
	}
	if iface.Flags&net.FlagUp == 0 {
		t.Errorf("%s is not up", seg.Name)
	}
	if iface.Flags&net.FlagBroadcast == 0 {
		t.Errorf("%s cannot broadcast, so NBT-NS has nowhere to go", seg.Name)
	}
	if iface.Flags&net.FlagMulticast == 0 {
		t.Errorf("%s cannot multicast, so LLMNR and mDNS have nowhere to go", seg.Name)
	}
}
