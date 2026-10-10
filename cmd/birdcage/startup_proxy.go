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

// parseTrustedProxies turns the comma-separated setting into prefixes. A
// bare address is a single-host prefix; blank entries are skipped; the entry
// unix (item 15) trusts a proxy on the unix socket and adds no prefix; any
// other entry that is not an address, a CIDR or private is an error, never
// skipped.
func parseTrustedProxies(value string) (prefixes []netip.Prefix, trustUnix bool, err error) {
	var out []netip.Prefix
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
				out = append(out, netip.MustParsePrefix(r))
			}
			continue
		}
		if p, err := netip.ParsePrefix(entry); err == nil {
			out = append(out, p.Masked())
			continue
		}
		addr, err := netip.ParseAddr(entry)
		if err != nil {
			return nil, false, fmt.Errorf("%q is neither an IP address, a CIDR, private nor unix", entry)
		}
		addr = addr.Unmap()
		out = append(out, netip.PrefixFrom(addr, addr.BitLen()))
	}
	return out, trustUnix, nil
}
