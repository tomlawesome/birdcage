package auth

import (
	"fmt"
	"net"
	"net/url"
	"strings"

	"github.com/tomlawesome/gauntlet/gate"
)

// AdminPasskeyRule decides whether every admin must hold a passkey
// (ADR-0016 decision 5, which settles #180).
//
// Without an override, the rule is required exactly when passkeys are
// wired and publicURL is an https address on a domain name: that is the
// only place a browser can make a passkey that works, so the block it
// causes can always be lifted. Everywhere else it is optional: an IP
// address, plain http, or no public URL at all (passkeys not wired).
//
// override is BIRDCAGE_AUTH_ADMIN_PASSKEY: "required", "optional", or
// empty for the default above. "required" while passkeys are not wired
// is an error, because no admin could ever satisfy it. Any other value
// is an error.
func AdminPasskeyRule(publicURL string, passkeysWired bool, override string) (gate.AdminPasskeyRule, error) {
	switch strings.ToLower(strings.TrimSpace(override)) {
	case "":
		if passkeysWired && httpsOnDomainName(publicURL) {
			return gate.AdminPasskeyRequired, nil
		}
		return gate.AdminPasskeyOptional, nil
	case "optional":
		return gate.AdminPasskeyOptional, nil
	case "required":
		if !passkeysWired {
			return "", fmt.Errorf("BIRDCAGE_AUTH_ADMIN_PASSKEY=required needs passkeys, which are wired only when BIRDCAGE_PUBLIC_URL is set; set it, or use optional")
		}
		return gate.AdminPasskeyRequired, nil
	default:
		return "", fmt.Errorf("BIRDCAGE_AUTH_ADMIN_PASSKEY=%q is not recognised; use required or optional, or leave it unset", override)
	}
}

// httpsOnDomainName reports whether publicURL is an https URL whose host
// is a domain name rather than an IP address.
func httpsOnDomainName(publicURL string) bool {
	u, err := url.Parse(publicURL)
	if err != nil || u.Scheme != "https" {
		return false
	}
	host := u.Hostname()
	return host != "" && net.ParseIP(host) == nil
}
