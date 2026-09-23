package poisoner

import (
	"bufio"
	"net"
	"os"
	"strings"
)

// DefaultARPPath is the kernel's own neighbour table for IPv4, readable
// without any privilege inside the container's own network namespace.
//
// Reading it is the whole of issue #86 decision 34's MAC: passive, no
// probe, no privilege. The entry is there because the reply has just
// arrived from that address, so the kernel resolved it a moment ago.
const DefaultARPPath = "/proc/net/arp"

// arpFields are the columns /proc/net/arp has, in order: IP address, HW
// type, Flags, HW address, Mask, Device. The header line has the same
// count, which is why lookupMAC identifies it by content rather than by
// position.
const arpFields = 6

// zeroMAC is what the kernel puts in an incomplete entry -- the neighbour
// has been asked for and has not answered. Reporting it as the attacker's
// MAC would be worse than reporting none.
const zeroMAC = "00:00:00:00:00:00"

// lookupMAC reads path and returns the MAC recorded against ip, or the
// empty string if there is none.
//
// The empty string is an ordinary answer, not a failure. Two cases produce
// it and neither is worth a log line: the answering host is more than one
// hop away, so the neighbour table holds the router's MAC and not its --
// which cannot happen for a link-local protocol, but can if something
// unicasts a reply from off-segment -- and the answer arrived over IPv6,
// which Linux does not expose in /proc/net/arp at all.
//
// The path is a parameter only so a test can point it at a fixture;
// nothing configures it.
func lookupMAC(path, ip string) string {
	f, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer func() { _ = f.Close() }()

	want := net.ParseIP(ip)
	if want == nil {
		return ""
	}

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) != arpFields {
			continue
		}
		// The header line's first column is "IP" -- not an address, so
		// ParseIP rejects it and no special case is needed.
		have := net.ParseIP(fields[0])
		if have == nil || !have.Equal(want) {
			continue
		}
		mac := strings.ToLower(fields[3])
		if _, err := net.ParseMAC(mac); err != nil || mac == zeroMAC {
			continue
		}
		return mac
	}
	return ""
}
