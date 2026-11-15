package main

import (
	"fmt"
	"net/netip"
	"strings"
)

// Reverse-proxy settings (issue #8 items 13-14, ADR-0016 decision 4).
const (
	// envTrustedProxies lists the peers a forwarding header is believed
	// from: comma-separated bare IPs, CIDRs, private, or unix. Empty by default,
	// and empty means forwarding headers are ignored. Optional.
	envTrustedProxies = "BIRDCAGE_TRUSTED_PROXIES"
	// envClientIPHeader names the header read for a trusted peer. Defaults
	// to X-Forwarded-For. Optional.
	envClientIPHeader = "BIRDCAGE_CLIENT_IP_HEADER"

	defaultClientIPHeader = "X-Forwarded-For"
)

// privateProxyRanges back the private shorthand: loopback, RFC 1918, CGNAT,
// link-local and IPv6 ULA, which is where a proxy sharing a LAN or a
// container network lands.
var privateProxyRanges = []string{
	"127.0.0.0/8", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",
	"100.64.0.0/10", "169.254.0.0/16",
	"::1/128", "fc00::/7", "fe80::/10",
}

// parseTrustedProxies turns the comma-separated setting into prefixes:
// peers, whose forwarding header is believed, and hops, the chain entries
// skipped when walking it (SEC-A1). The shorthand private adds peers only,
// never hops; a bare address (a single-host prefix) or a CIDR adds both.
// Blank entries are skipped; the entry unix (item 15) trusts a proxy on the
// unix socket and adds no prefix; any other entry that is not an address, a
// CIDR or private is an error, never skipped.
func parseTrustedProxies(value string) (peers, hops []netip.Prefix, trustUnix bool, err error) {
	for _, raw := range strings.Split(value, ",") {
		entry := strings.TrimSpace(raw)
		if entry == "" {
			continue
		}
		if strings.EqualFold(entry, "unix") {
			trustUnix = true
			continue
		}
		if strings.EqualFold(entry, "private") {
			for _, r := range privateProxyRanges {
				peers = append(peers, netip.MustParsePrefix(r))
			}
			continue
		}
		if p, err := netip.ParsePrefix(entry); err == nil {
			peers = append(peers, p.Masked())
			hops = append(hops, p.Masked())
			continue
		}
		addr, err := netip.ParseAddr(entry)
		if err != nil {
			return nil, nil, false, fmt.Errorf("%q is neither an IP address, a CIDR, private nor unix", entry)
		}
		addr = addr.Unmap()
		p := netip.PrefixFrom(addr, addr.BitLen())
		peers = append(peers, p)
		hops = append(hops, p)
	}
	return peers, hops, trustUnix, nil
}
