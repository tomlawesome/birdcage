package neverblock

import (
	"fmt"
	"net/netip"
	"strings"
)

// EnvAllow is the operator's never-block allowlist: a comma-separated
// list of bare addresses and/or CIDR ranges, IPv4 and IPv6, that Check
// must never let a mitigation action touch, in addition to the compiled-in
// floor. Named and documented next to the rule that validates it,
// matching internal/mail's EnvHost and friends -- see that package's own
// comment on why.
const EnvAllow = "BIRDCAGE_NEVER_BLOCK_ALLOW"

// Config is a validated never-block configuration. The only field is
// Allow: there is deliberately no key, value or syntax anywhere in this
// package that removes or narrows a floor entry -- an operator can only
// ever add to what Check refuses. See the package doc comment and
// TestConfigCannotShrinkTheFloor.
type Config struct {
	Allow []netip.Prefix
}

// Load reads and validates EnvAllow from getenv (os.Getenv in production;
// a map lookup in tests, matching internal/mail.Load's own signature).
//
// Unset or blank is a valid, empty Config -- an operator who never sets
// this gets exactly the compiled-in floor. Once set, every comma-separated
// entry must parse as a bare IP address or a CIDR range, or Load rejects
// the WHOLE value and returns an error naming the bad entry: fail-closed,
// all-or-nothing, the same shape as mail.Load and for the same reason
// fail2ban/fail2ban#2706 exists (see the package doc comment) -- a
// configuration this package can't fully parse must never be treated as
// "no allowlist entry there", since that reads as safe while actually
// being a partially-lost operator's protection.
//
// Because a config entry can only ever be a plain address or CIDR, there
// is no syntax for "remove" or "exclude" to begin with: something written
// to try to negate or narrow a floor entry (e.g. "!10.0.0.0/8") simply
// fails to parse as an address or range and rejects the whole
// configuration, the same as any other typo.
func Load(getenv func(string) string) (Config, error) {
	raw := strings.TrimSpace(getenv(EnvAllow))
	if raw == "" {
		return Config{}, nil
	}

	var allow []netip.Prefix
	for _, part := range strings.Split(raw, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		p, err := parseTarget(part)
		if err != nil {
			return Config{}, fmt.Errorf("neverblock: %s: entry %q does not parse as an IP address or CIDR range: %w", EnvAllow, part, err)
		}
		allow = append(allow, p)
	}
	return Config{Allow: allow}, nil
}
