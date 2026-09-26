package neverblock

import (
	"net/netip"
	"testing"
)

func getenvMap(m map[string]string) func(string) string {
	return func(key string) string { return m[key] }
}

// TestLoadEmptyIsNoAllowlist proves an unset (or blank) environment
// variable is a valid, empty configuration -- an operator who never opts
// into the allowlist gets exactly the compiled-in floor, nothing more.
func TestLoadEmptyIsNoAllowlist(t *testing.T) {
	for _, raw := range []string{"", "   "} {
		cfg, err := Load(getenvMap(map[string]string{EnvAllow: raw}))
		if err != nil {
			t.Fatalf("Load(%q) error = %v, want nil", raw, err)
		}
		if len(cfg.Allow) != 0 {
			t.Fatalf("Load(%q).Allow = %v, want empty", raw, cfg.Allow)
		}
	}
}

// TestLoadParsesAddressesAndRanges proves the allowlist accepts both bare
// addresses and CIDR ranges, IPv4 and IPv6, comma-separated.
func TestLoadParsesAddressesAndRanges(t *testing.T) {
	raw := "198.51.100.5, 203.0.113.0/24 ,2001:db8::1,2001:db8:1::/48"
	cfg, err := Load(getenvMap(map[string]string{EnvAllow: raw}))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	want := []netip.Prefix{
		netip.MustParsePrefix("198.51.100.5/32"),
		netip.MustParsePrefix("203.0.113.0/24"),
		netip.MustParsePrefix("2001:db8::1/128"),
		netip.MustParsePrefix("2001:db8:1::/48"),
	}
	if len(cfg.Allow) != len(want) {
		t.Fatalf("Load(%q).Allow = %v, want %v", raw, cfg.Allow, want)
	}
	for i, p := range want {
		if cfg.Allow[i] != p {
			t.Errorf("Allow[%d] = %v, want %v", i, cfg.Allow[i], p)
		}
	}
}

// TestLoadSkipsEmptySegments proves a stray comma (trailing, or doubled
// between two real entries) is tolerated rather than treated as an empty
// address to reject -- convenient for a hand-edited environment variable,
// and distinct from an actually-invalid entry like "not-an-address".
func TestLoadSkipsEmptySegments(t *testing.T) {
	cfg, err := Load(getenvMap(map[string]string{EnvAllow: "198.51.100.5,,203.0.113.0/24,"}))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	want := []netip.Prefix{
		netip.MustParsePrefix("198.51.100.5/32"),
		netip.MustParsePrefix("203.0.113.0/24"),
	}
	if len(cfg.Allow) != len(want) {
		t.Fatalf("Load.Allow = %v, want %v", cfg.Allow, want)
	}
	for i, p := range want {
		if cfg.Allow[i] != p {
			t.Errorf("Allow[%d] = %v, want %v", i, cfg.Allow[i], p)
		}
	}
}

// TestLoadRejectsUnparseableEntry is the fail-closed, all-or-nothing case
// mirrored on mail.Load: one bad entry rejects the whole configuration
// rather than silently dropping it (the fail2ban ignoreip trap the
// package doc comment cites -- a CIDR that fails to parse must not be
// treated as "not on the allowlist" quietly).
func TestLoadRejectsUnparseableEntry(t *testing.T) {
	cases := []string{
		"198.51.100.5, not-an-address",
		"10.0.0.0/99",
		"garbage",
	}
	for _, raw := range cases {
		t.Run(raw, func(t *testing.T) {
			if _, err := Load(getenvMap(map[string]string{EnvAllow: raw})); err == nil {
				t.Fatalf("Load(%q) = nil error, want a refusal", raw)
			}
		})
	}
}

// TestLoadRejectsAttemptsToNegateOrRemove proves the config format has no
// way to express "remove" or "narrow" a floor entry: syntax that might be
// mistaken for a negation/exclusion marker in some allowlist tools simply
// fails to parse as an address or CIDR, so it is rejected outright rather
// than being interpreted as an instruction to shrink the floor.
func TestLoadRejectsAttemptsToNegateOrRemove(t *testing.T) {
	cases := []string{
		"!10.0.0.0/8",
		"-192.168.0.0/16",
		"not 10.0.0.0/8",
	}
	for _, raw := range cases {
		t.Run(raw, func(t *testing.T) {
			if _, err := Load(getenvMap(map[string]string{EnvAllow: raw})); err == nil {
				t.Fatalf("Load(%q) = nil error, want a refusal (no way to remove/narrow the floor)", raw)
			}
		})
	}
}
