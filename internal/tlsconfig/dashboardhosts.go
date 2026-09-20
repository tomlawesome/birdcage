package tlsconfig

import (
	"fmt"
	"net"
	"os"
	"strings"
)

// DashboardHosts returns the hostnames and/or IP addresses ModeMintedCert's
// leaf certificate (issue #63) should cover, given BIRDCAGE_DASHBOARD_HOST's
// value (envValue; pass os.Getenv("BIRDCAGE_DASHBOARD_HOST")).
//
// A certificate for the wrong name still warns in a browser even after
// the operator has installed birdcage's CA, which would defeat the
// whole point of minting one -- so this is deliberately exact rather
// than a best guess:
//
//   - envValue set: exactly the comma-separated names it lists, nothing
//     added and nothing guessed. Blank entries (extra commas, spaces)
//     are dropped; if nothing is left, that is a configuration mistake
//     and this returns an error rather than silently falling back to
//     the defaults below.
//   - envValue unset: the machine's hostname (if it can be determined),
//     every non-loopback IP address found on any interface, and
//     localhost/127.0.0.1/::1 -- since an operator commonly browses to
//     the dashboard by LAN IP from another machine, IP SANs are not
//     optional here. A failure to enumerate hostname or interfaces is
//     not fatal -- the certificate still covers loopback -- but is
//     reported via ok so the caller can log it; the boot log is the
//     only way an operator finds out why a name they expect is
//     missing.
func DashboardHosts(envValue string) (hosts []string, err error) {
	if envValue != "" {
		for _, h := range strings.Split(envValue, ",") {
			h = strings.TrimSpace(h)
			if h == "" {
				continue
			}
			hosts = append(hosts, h)
		}
		if len(hosts) == 0 {
			return nil, fmt.Errorf("tlsconfig: BIRDCAGE_DASHBOARD_HOST=%q names no hosts", envValue)
		}
		return hosts, nil
	}

	hosts = []string{"localhost", "127.0.0.1", "::1"}

	if hostname, hostErr := os.Hostname(); hostErr == nil && hostname != "" {
		hosts = append(hosts, hostname)
	}

	addrs, addrErr := net.InterfaceAddrs()
	if addrErr != nil {
		// Best-effort: the certificate still covers loopback, so this is
		// not a startup failure -- but the caller should log addrErr so
		// an operator who gets a browser warning can see why.
		return hosts, addrErr
	}
	for _, a := range addrs {
		ipnet, ok := a.(*net.IPNet)
		if !ok || ipnet.IP.IsLoopback() {
			continue
		}
		hosts = append(hosts, ipnet.IP.String())
	}
	return hosts, nil
}
