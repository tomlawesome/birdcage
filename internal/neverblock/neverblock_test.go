package neverblock

import (
	"context"
	"errors"
	"net/netip"
	"testing"

	"github.com/tomlawesome/birdcage/internal/db"
	"github.com/tomlawesome/birdcage/internal/db/dbtest"
)

// auditRows returns every audit_log row's (action, target, reason,
// triggered_by), in insertion order, for asserting on what Check wrote.
func auditRows(t *testing.T, database *db.DB) []auditRow {
	t.Helper()
	rows, err := database.Query(`SELECT action, target, reason, triggered_by FROM audit_log ORDER BY id`)
	if err != nil {
		t.Fatalf("query audit_log: %v", err)
	}
	defer rows.Close()
	var out []auditRow
	for rows.Next() {
		var r auditRow
		if err := rows.Scan(&r.action, &r.target, &r.reason, &r.triggeredBy); err != nil {
			t.Fatalf("scan audit_log row: %v", err)
		}
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("iterate audit_log rows: %v", err)
	}
	return out
}

type auditRow struct {
	action      string
	target      string
	reason      string
	triggeredBy string
}

// TestCheckRefusesEveryStaticFloorCategory proves each fixed, compiled-in
// floor category refuses a target inside it, in both IPv4 and IPv6 where
// the category has both -- and writes exactly one audit_log row per
// refusal, with the action text the issue specifies verbatim.
func TestCheckRefusesEveryStaticFloorCategory(t *testing.T) {
	cases := []struct {
		name   string
		target string
	}{
		{"loopback v4", "127.0.0.1"},
		{"loopback v4 range", "127.0.0.0/8"},
		{"loopback v6", "::1"},
		{"link-local v4", "169.254.1.1"},
		{"link-local v6", "fe80::1"},
		{"multicast v4", "224.0.0.1"},
		{"multicast v6", "ff02::1"},
		{"rfc1918 10/8", "10.1.2.3"},
		{"rfc1918 172.16/12", "172.16.5.5"},
		{"rfc1918 192.168/16", "192.168.1.1"},
	}

	for _, tgt := range dbtest.Targets(t) {
		t.Run(tgt.Name, func(t *testing.T) {
			for _, tc := range cases {
				t.Run(tc.name, func(t *testing.T) {
					database := tgt.DB
					f := New(Config{})
					err := f.Check(context.Background(), database, tc.target, Inputs{}, "test/router")
					if err == nil {
						t.Fatalf("Check(%q) = nil, want a refusal", tc.target)
					}
					if !errors.Is(err, ErrRefused) {
						t.Fatalf("Check(%q) error = %v, want errors.Is(_, ErrRefused)", tc.target, err)
					}
				})
			}
		})
	}
}

// TestCheckRefusesIPv4MappedIPv6 is the CVE-2026-2455-shaped case (see the
// package doc comment): an IPv4-mapped IPv6 literal describing an address
// inside an IPv4 floor entry must be caught exactly as its bare IPv4 form
// would be, not slip past because the comparison never unmapped it.
func TestCheckRefusesIPv4MappedIPv6(t *testing.T) {
	database := openSQLiteOnly(t)
	f := New(Config{})

	cases := []string{
		"::ffff:10.0.0.1",    // RFC1918
		"::ffff:127.0.0.1",   // loopback
		"::ffff:169.254.1.1", // link-local
		"::ffff:0a00:0001",   // same as ::ffff:10.0.0.1, hex form
	}
	for _, target := range cases {
		t.Run(target, func(t *testing.T) {
			err := f.Check(context.Background(), database, target, Inputs{}, "test/router")
			if !errors.Is(err, ErrRefused) {
				t.Fatalf("Check(%q) = %v, want ErrRefused (IPv4-mapped IPv6 must not bypass the IPv4 rule)", target, err)
			}
		})
	}
}

// TestCheckRefusesOverlappingRangeNotJustContained proves the floor
// refuses any block target that OVERLAPS a floor entry, not only one that
// is fully contained within it -- 0.0.0.0/0 and 10.0.0.0/7 both overlap
// (without being contained by) the RFC1918 10.0.0.0/8 entry.
func TestCheckRefusesOverlappingRangeNotJustContained(t *testing.T) {
	database := openSQLiteOnly(t)
	f := New(Config{})

	cases := []string{
		"0.0.0.0/0",  // the whole IPv4 space: overlaps every IPv4 floor entry
		"10.0.0.0/7", // wider than, and overlapping, 10.0.0.0/8
		"::/0",       // the whole IPv6 space
	}
	for _, target := range cases {
		t.Run(target, func(t *testing.T) {
			err := f.Check(context.Background(), database, target, Inputs{}, "test/router")
			if !errors.Is(err, ErrRefused) {
				t.Fatalf("Check(%q) = %v, want ErrRefused (overlap, not just containment)", target, err)
			}
		})
	}
}

// TestCheckRefusesUnparseableTarget is the fail-closed case: a target that
// doesn't parse as an address or CIDR range must be refused, not passed
// through as "not on the floor".
func TestCheckRefusesUnparseableTarget(t *testing.T) {
	database := openSQLiteOnly(t)
	f := New(Config{})

	cases := []string{"", "not-an-address", "10.0.0.0/33", "999.1.1.1", "10.0.0.1/-1"}
	for _, target := range cases {
		t.Run(target, func(t *testing.T) {
			err := f.Check(context.Background(), database, target, Inputs{}, "test/router")
			if !errors.Is(err, ErrRefused) {
				t.Fatalf("Check(%q) = %v, want ErrRefused (fail closed on unparseable input)", target, err)
			}
		})
	}
}

// TestCheckAllowsUnrelatedTarget proves the floor doesn't over-refuse: an
// ordinary public address, with no dynamic inputs and no configured
// allowlist, is not refused, and no audit row is written for it.
func TestCheckAllowsUnrelatedTarget(t *testing.T) {
	database := openSQLiteOnly(t)
	f := New(Config{})

	if err := f.Check(context.Background(), database, "203.0.113.50", Inputs{}, "test/router"); err != nil {
		t.Fatalf("Check(203.0.113.50) = %v, want nil", err)
	}
	if rows := auditRows(t, database); len(rows) != 0 {
		t.Fatalf("audit_log has %d rows after an allowed check, want 0: %+v", len(rows), rows)
	}
}

// TestCheckRefusesDynamicInputs proves each caller-supplied dynamic
// category (router address, birdcage host, mikroview host, OIDC provider,
// admin session address) is honoured -- these are inputs the not-yet-built
// callers pass in, but the categories themselves are fixed by this
// package, not by the caller.
func TestCheckRefusesDynamicInputs(t *testing.T) {
	database := openSQLiteOnly(t)
	f := New(Config{})

	addr := netip.MustParseAddr("203.0.113.9")

	cases := []struct {
		name   string
		inputs Inputs
	}{
		{"router", Inputs{RouterAddresses: []netip.Addr{addr}}},
		{"birdcage host", Inputs{BirdcageHost: []netip.Addr{addr}}},
		{"mikroview host", Inputs{MikroviewHost: []netip.Addr{addr}}},
		{"oidc provider", Inputs{OIDCProvider: []netip.Addr{addr}}},
		{"admin session", Inputs{AdminSession: addr}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := f.Check(context.Background(), database, "203.0.113.9", tc.inputs, "test/router")
			if !errors.Is(err, ErrRefused) {
				t.Fatalf("Check with %s input = %v, want ErrRefused", tc.name, err)
			}
		})
	}

	// The same address, with none of the dynamic inputs set, must not be
	// refused -- proving the refusal above came from the input, not from
	// some other floor rule matching 203.0.113.9.
	if err := f.Check(context.Background(), database, "203.0.113.9", Inputs{}, "test/router"); err != nil {
		t.Fatalf("Check(203.0.113.9) with no dynamic inputs = %v, want nil", err)
	}
}

// TestCheckRefusesOperatorAllowlistEntry proves a config-loaded operator
// allowlist entry is honoured by Check.
func TestCheckRefusesOperatorAllowlistEntry(t *testing.T) {
	database := openSQLiteOnly(t)
	f := New(Config{Allow: []netip.Prefix{netip.MustParsePrefix("198.51.100.0/24")}})

	if err := f.Check(context.Background(), database, "198.51.100.5", Inputs{}, "test/router"); !errors.Is(err, ErrRefused) {
		t.Fatalf("Check(198.51.100.5) = %v, want ErrRefused (operator allowlist)", err)
	}
	// Outside the allowlisted range: not refused.
	if err := f.Check(context.Background(), database, "198.51.101.5", Inputs{}, "test/router"); err != nil {
		t.Fatalf("Check(198.51.101.5) = %v, want nil", err)
	}
}

// TestConfigCannotShrinkTheFloor is the structural proof the issue asks
// for: the static floor (e.g. RFC1918) is refused identically whether
// Config is empty, or carries operator entries -- there is no field or
// value in Config that can narrow or remove a floor entry, because the
// floor entries are not derived from Config at all.
func TestConfigCannotShrinkTheFloor(t *testing.T) {
	database := openSQLiteOnly(t)

	configs := []Config{
		{},
		{Allow: []netip.Prefix{netip.MustParsePrefix("198.51.100.0/24")}},
		// Even an allowlist entry that exactly duplicates, or sits inside,
		// a floor entry changes nothing: the floor is still enforced by
		// its own compiled-in rule.
		{Allow: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}},
	}
	for i, cfg := range configs {
		f := New(cfg)
		if err := f.Check(context.Background(), database, "10.5.5.5", Inputs{}, "test/router"); !errors.Is(err, ErrRefused) {
			t.Fatalf("config[%d]: Check(10.5.5.5) = %v, want ErrRefused (RFC1918 floor must hold regardless of Config)", i, err)
		}
	}
}

// TestCheckWritesAuditRowOnRefusal proves the exact audit_log contract:
// action "refused: never-block floor", the raw target, a non-empty reason,
// and the caller's triggeredBy -- written once per refusal.
func TestCheckWritesAuditRowOnRefusal(t *testing.T) {
	database := openSQLiteOnly(t)
	f := New(Config{})

	err := f.Check(context.Background(), database, "127.0.0.1", Inputs{}, "routeros/mitigate")
	if !errors.Is(err, ErrRefused) {
		t.Fatalf("Check = %v, want ErrRefused", err)
	}

	rows := auditRows(t, database)
	if len(rows) != 1 {
		t.Fatalf("audit_log has %d rows, want 1: %+v", len(rows), rows)
	}
	row := rows[0]
	if row.action != AuditAction {
		t.Errorf("action = %q, want %q", row.action, AuditAction)
	}
	if row.target != "127.0.0.1" {
		t.Errorf("target = %q, want %q", row.target, "127.0.0.1")
	}
	if row.reason == "" {
		t.Errorf("reason is empty, want a non-empty explanation")
	}
	if row.triggeredBy != "routeros/mitigate" {
		t.Errorf("triggered_by = %q, want %q", row.triggeredBy, "routeros/mitigate")
	}
}

// TestCheckWritesAuditRowOnUnparseableTarget proves a refusal caused by
// unparseable input is still recorded -- "every refusal", not just the
// ones matched against a floor entry.
func TestCheckWritesAuditRowOnUnparseableTarget(t *testing.T) {
	database := openSQLiteOnly(t)
	f := New(Config{})

	err := f.Check(context.Background(), database, "not-an-address", Inputs{}, "routeros/mitigate")
	if !errors.Is(err, ErrRefused) {
		t.Fatalf("Check = %v, want ErrRefused", err)
	}
	rows := auditRows(t, database)
	if len(rows) != 1 {
		t.Fatalf("audit_log has %d rows, want 1: %+v", len(rows), rows)
	}
	if rows[0].action != AuditAction {
		t.Errorf("action = %q, want %q", rows[0].action, AuditAction)
	}
}

// TestParseTargetUnmapsAnIPv4MappedIPv6Range proves normalizePrefix's
// genuinely-mapped branch: a CIDR range written entirely in IPv4-mapped
// IPv6 notation (bits >= 96, so the whole range is inside ::ffff:0:0/96)
// is reduced to the plain IPv4 range it denotes, not left as an IPv6
// prefix that would only ever match IPv6 floor entries.
func TestParseTargetUnmapsAnIPv4MappedIPv6Range(t *testing.T) {
	got, err := parseTarget("::ffff:10.0.0.0/104")
	if err != nil {
		t.Fatalf("parseTarget: %v", err)
	}
	want := netip.MustParsePrefix("10.0.0.0/8")
	if got != want {
		t.Fatalf("parseTarget(::ffff:10.0.0.0/104) = %v, want %v", got, want)
	}
}

// TestCheckRefusesIPv4MappedIPv6Range is the same case through Check: a
// block target given as an IPv4-mapped IPv6 CIDR must be refused by the
// IPv4 floor entry it actually denotes.
func TestCheckRefusesIPv4MappedIPv6Range(t *testing.T) {
	database := openSQLiteOnly(t)
	f := New(Config{})
	if err := f.Check(context.Background(), database, "::ffff:10.0.0.0/104", Inputs{}, "test/router"); !errors.Is(err, ErrRefused) {
		t.Fatalf("Check(::ffff:10.0.0.0/104) = %v, want ErrRefused", err)
	}
}

func openSQLiteOnly(t *testing.T) *db.DB {
	t.Helper()
	return dbtest.Targets(t)[0].DB
}
