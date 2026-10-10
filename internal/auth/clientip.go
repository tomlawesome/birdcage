package auth

import (
	"net"
	"net/http"
	"net/netip"
	"strings"
)

// defaultClientIPHeader is the header nginx, Caddy, Traefik, HAProxy and
// the cloud load balancers set without being asked.
const defaultClientIPHeader = "X-Forwarded-For"

// ClientIP is the address the login limiter and audit records use (ADR-0016
// decision 4; the same rule as mikroview's).
//
// With no trusted proxies, or a connecting peer outside them, it is the
// peer's own address and every forwarding header is ignored: a header is
// only text the client sent, so believing one unconditionally would give
// every request a fresh limiter bucket.
//
// For a trusted peer the named header (all its lines, read as one comma
// separated list) is walked right to left, skipping entries that are
// themselves trusted proxies; the first untrusted entry is the client. Each
// proxy appends the address it saw, so the right-most entries were written
// by proxies we trust and anything further left may be forged. If every
// entry is trusted the left-most is returned; an entry that is not an
// address, or no header at all, falls back to the peer, never to something
// the client chose.
func ClientIP(r *http.Request, trusted []netip.Prefix, header string) string {
	return ClientIPWith(r, trusted, false, header)
}

// unixPeer is the RemoteAddr net/http gives a request that arrived on a
// unix-domain socket: it has no IP address to match against a prefix.
const unixPeer = "@"

// ClientIPWith is ClientIP with one more way for a peer to be trusted: when
// trustUnix is true a unix-socket peer counts as a trusted proxy, even with
// no address prefixes listed (BIRDCAGE_TRUSTED_PROXIES entry "unix"; only
// processes allowed to open the socket file can connect). trustUnix never
// makes a TCP peer trusted. Otherwise the walk is that of ClientIP.
func ClientIPWith(r *http.Request, trusted []netip.Prefix, trustUnix bool, header string) string {
	peer := peerHost(r)
	if r.RemoteAddr == unixPeer {
		if !trustUnix {
			return peer
		}
	} else {
		if len(trusted) == 0 {
			return peer
		}
		peerAddr, err := netip.ParseAddr(peer)
		if err != nil || !isTrusted(trusted, peerAddr) {
			return peer
		}
	}
	if header == "" {
		header = defaultClientIPHeader
	}
	if ip, ok := forwardedClient(trusted, r.Header.Values(header)); ok {
		return ip
	}
	return peer
}

func forwardedClient(trusted []netip.Prefix, values []string) (string, bool) {
	var chain []string
	for _, v := range values {
		for _, part := range strings.Split(v, ",") {
			if part = strings.TrimSpace(part); part != "" {
				chain = append(chain, part)
			}
		}
	}
	var last netip.Addr
	for i := len(chain) - 1; i >= 0; i-- {
		addr, ok := parseForwardedAddr(chain[i])
		if !ok {
			return "", false // malformed from here leftwards: believe none of it
		}
		if !isTrusted(trusted, addr) {
			return addr.String(), true
		}
		last = addr
	}
	if last.IsValid() {
		return last.String(), true // every entry trusted: the left-most
	}
	return "", false
}

// parseForwardedAddr accepts a bare address, or one with a port (IPv6
// bracketed), as proxies write them.
func parseForwardedAddr(s string) (netip.Addr, bool) {
	if addr, err := netip.ParseAddr(s); err == nil {
		return addr.Unmap(), true
	}
	if ap, err := netip.ParseAddrPort(s); err == nil {
		return ap.Addr().Unmap(), true
	}
	return netip.Addr{}, false
}

func isTrusted(trusted []netip.Prefix, addr netip.Addr) bool {
	addr = addr.Unmap()
	for _, p := range trusted {
		if p.Contains(addr) {
			return true
		}
	}
	return false
}

// peerHost is the connection's own address with any port stripped: the one
// address in a request that cannot be forged. An IPv4-mapped IPv6 peer is
// reported as plain IPv4.
func peerHost(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr // a unix socket has no port to strip
	}
	if addr, err := netip.ParseAddr(host); err == nil {
		return addr.Unmap().String()
	}
	return host
}
