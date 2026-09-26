// Package neverblock is issue #33's never-block floor: the fixed set of
// hosts and ranges no automated mitigation action is ever allowed to
// touch, however it decided to act. It exists to be called from exactly
// one place in each mitigation caller -- #5 (RouterOS) and #4 (CrowdSec),
// neither built yet -- immediately before that caller issues a real block,
// so a bug in a detector can never turn into birdcage fencing off its own
// router, itself, Mikroview, its OIDC provider, or the operator currently
// looking at it.
//
// # What is on the floor
//
// Two kinds of entry, both refused identically by Check:
//
//   - Fixed categories, compiled into the binary and never configurable:
//     loopback, link-local and multicast (v4 and v6), RFC1918 private
//     IPv4 space, IPv6 unique local space, the unspecified ranges, and
//     RFC 6598 shared address space. See staticFloor.
//   - Dynamic categories, whose *membership* is fixed in code but whose
//     *value* a caller supplies per call, because this package cannot know
//     the router's address, the OIDC provider, or which address an admin
//     session is currently using: router, birdcage host, Mikroview host,
//     OIDC provider, admin session. See Inputs.
//
// An operator can only ever ADD to this, via Config.Allow (see config.go,
// Load) -- there is no field, value or syntax anywhere in this package
// that removes or narrows a floor entry. Manually confirmed internal
// blocking of RFC1918 ranges is a later, human-in-the-loop feature; this
// floor still applies to it, because it applies to every automated caller
// regardless of what asked.
//
// # Traps this package specifically guards against
//
// Researched per docs/security-by-design.md before writing this, against
// real prior bugs in allowlist/never-block implementations, not general
// caution:
//
//   - Comparing a raw address against an IPv4 range without normalizing an
//     IPv4-mapped IPv6 literal first. Mattermost's outbound-request guard
//     had exactly this bug (CVE-2026-2455: IsReservedIP compared net.IP
//     directly against IPv4-only reserved ranges, so ::ffff:127.0.0.1 and
//     similar literals never matched and sailed through). Guarded against
//     here by normalizePrefix, which masks first and then unmaps an
//     IPv4-in-IPv6 network before any comparison -- see its comment for
//     why masking has to happen first.
//   - Silently treating an allowlist entry that fails to parse as "not
//     matched" rather than refusing the whole configuration.
//     fail2ban/fail2ban#2706 is exactly this: an IPv6 CIDR in `ignoreip`
//     that fail2ban couldn't parse was logged as a warning and then simply
//     not applied, leaving the operator's own address unprotected while
//     looking, from the config file, like it was. Guarded against here by
//     Load (config.go) rejecting the entire configuration on the first
//     unparseable entry, fail-closed, never a partial allowlist.
//   - A whitelist that exists in configuration but isn't actually wired
//     into the path that takes action. A CrowdSec support thread
//     (discourse.crowdsec.net/t/help-with-allowlist-whitelist-cidr-still-
//     creating-alert-and-decision/2704) traced a "whitelisted IP still got
//     a decision against it" report to the whitelist parser sitting in the
//     wrong pipeline stage, before enrichment ran, so it was never
//     consulted. Guarded against here structurally: Check is the one
//     function a mitigation caller runs immediately before acting, and it
//     writes the audit_log refusal itself -- there is no way to "check"
//     without the refusal being both enforced and recorded in the same
//     call, so a future caller cannot wire the check in loosely enough to
//     repeat that bug.
//
// Everything here is net/netip: no string-prefix or regex matching on
// addresses, which is how several of the CVEs above (and the IPv4-mapped
// IPv6 class generally) happen in other languages' ad hoc parsers.
package neverblock

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"time"

	"github.com/tomlawesome/birdcage/internal/audit"
	"github.com/tomlawesome/birdcage/internal/db"
)

// Category names one class of floor entry, recorded in the audit reason
// so an operator can see why a target was refused without decoding a bare
// CIDR.
type Category string

const (
	CategoryLoopback       Category = "loopback"
	CategoryLinkLocal      Category = "link_local"
	CategoryMulticast      Category = "multicast"
	CategoryPrivateRFC1918 Category = "rfc1918_private"
	CategoryUniqueLocal    Category = "ipv6_unique_local"
	CategoryUnspecified    Category = "unspecified"
	CategorySharedAddress  Category = "shared_address_space"
	CategoryRouter         Category = "router"
	CategoryBirdcageHost   Category = "birdcage_host"
	CategoryMikroviewHost  Category = "mikroview_host"
	CategoryOIDCProvider   Category = "oidc_provider"
	CategoryAdminSession   Category = "admin_session"
	CategoryOperatorAllow  Category = "operator_allowlist"
)

// entry is one floor prefix and why it's there.
type entry struct {
	Prefix   netip.Prefix
	Category Category
	Why      string
}

// staticFloor is the fixed part of the floor: compiled into the binary,
// never touched by config, never touched by a caller. Order is
// declaration order and does not matter for correctness (every entry is
// checked), only for which reason a target that matches more than one
// gets reported against -- the first match, which is fine since the
// refusal itself is what matters, not which of several true reasons is
// quoted.
var staticFloor = []entry{
	{netip.MustParsePrefix("127.0.0.0/8"), CategoryLoopback, "IPv4 loopback"},
	{netip.MustParsePrefix("::1/128"), CategoryLoopback, "IPv6 loopback"},
	{netip.MustParsePrefix("169.254.0.0/16"), CategoryLinkLocal, "IPv4 link-local"},
	{netip.MustParsePrefix("fe80::/10"), CategoryLinkLocal, "IPv6 link-local"},
	{netip.MustParsePrefix("224.0.0.0/4"), CategoryMulticast, "IPv4 multicast"},
	{netip.MustParsePrefix("ff00::/8"), CategoryMulticast, "IPv6 multicast"},
	{netip.MustParsePrefix("10.0.0.0/8"), CategoryPrivateRFC1918, "RFC1918 private range"},
	{netip.MustParsePrefix("172.16.0.0/12"), CategoryPrivateRFC1918, "RFC1918 private range"},
	{netip.MustParsePrefix("192.168.0.0/16"), CategoryPrivateRFC1918, "RFC1918 private range"},
	// Added by the owner beyond #33's list (2026-09-26): IPv6's private
	// range, the "no address" ranges, and the shared address space that
	// Tailscale and carrier-grade NAT use -- which may be the admin's own
	// way in.
	{netip.MustParsePrefix("fc00::/7"), CategoryUniqueLocal, "IPv6 unique local (private) range"},
	{netip.MustParsePrefix("0.0.0.0/8"), CategoryUnspecified, "IPv4 \"this network\" / unspecified"},
	{netip.MustParsePrefix("::/128"), CategoryUnspecified, "IPv6 unspecified address"},
	{netip.MustParsePrefix("100.64.0.0/10"), CategorySharedAddress, "shared address space (RFC 6598: carrier-grade NAT, Tailscale)"},
}

// Inputs carries the dynamic floor categories for one Check call. Each
// field is a category this package has decided must never be a mitigation
// target; the *value* is supplied by whichever caller knows it, since
// this package has no way to learn a router's address, an OIDC provider's
// address, or which address the admin currently looking at the dashboard
// is using. A zero value (nil slice, or the zero netip.Addr for
// AdminSession) means "not known/not applicable to this call" and is
// simply skipped -- it never widens or narrows anything else on the
// floor.
type Inputs struct {
	// RouterAddresses are the router's own addresses (RouterOS, #5).
	RouterAddresses []netip.Addr
	// BirdcageHost are birdcage's own addresses on the box it runs on.
	BirdcageHost []netip.Addr
	// MikroviewHost are the Mikroview host's addresses.
	MikroviewHost []netip.Addr
	// OIDCProvider are the configured OIDC provider's addresses.
	OIDCProvider []netip.Addr
	// AdminSession is the address the currently authenticated admin
	// session came from. The zero netip.Addr means no session context
	// applies to this call.
	AdminSession netip.Addr
}

// entries returns every floor entry (static plus this Floor's config
// allowlist plus in's dynamic addresses) for one Check call. Each dynamic
// address becomes a single-host prefix (its full bit length) after the
// same normalization Check applies to the target, so an IPv4-mapped IPv6
// admin-session address is caught exactly as its plain IPv4 form would be.
func (f *Floor) entries(in Inputs) []entry {
	out := make([]entry, 0, len(staticFloor)+len(f.allow)+
		len(in.RouterAddresses)+len(in.BirdcageHost)+len(in.MikroviewHost)+len(in.OIDCProvider)+1)
	out = append(out, staticFloor...)

	for _, p := range f.allow {
		out = append(out, entry{Prefix: p, Category: CategoryOperatorAllow, Why: "operator allowlist entry"})
	}

	addCategory := func(addrs []netip.Addr, cat Category, why string) {
		for _, a := range addrs {
			out = append(out, entry{Prefix: hostPrefix(a), Category: cat, Why: why})
		}
	}
	addCategory(in.RouterAddresses, CategoryRouter, "the router's own address")
	addCategory(in.BirdcageHost, CategoryBirdcageHost, "birdcage's own host address")
	addCategory(in.MikroviewHost, CategoryMikroviewHost, "the Mikroview host's address")
	addCategory(in.OIDCProvider, CategoryOIDCProvider, "the OIDC provider's address")
	if in.AdminSession.IsValid() {
		out = append(out, entry{Prefix: hostPrefix(in.AdminSession), Category: CategoryAdminSession, Why: "the current admin session's address"})
	}
	return out
}

// Floor is a never-block floor, static entries plus a caller-loaded,
// additive-only operator allowlist. The zero value is not usable; build
// one with New.
type Floor struct {
	allow []netip.Prefix
}

// New builds a Floor from cfg. cfg.Allow only ever adds entries to what
// Check refuses -- see the package doc comment and
// TestConfigCannotShrinkTheFloor.
func New(cfg Config) *Floor {
	allow := make([]netip.Prefix, len(cfg.Allow))
	copy(allow, cfg.Allow)
	return &Floor{allow: allow}
}

// AuditAction is the exact audit_log action string issue #33 specifies
// for a never-block refusal.
const AuditAction = "refused: never-block floor"

// ErrRefused is wrapped into every error Check returns. Callers that only
// need to know "was this refused" can use errors.Is(err, ErrRefused);
// err's message carries the reason a human needs.
var ErrRefused = errors.New("neverblock: refused by the never-block floor")

// Check is the one function every mitigation caller (#4, #5) must call
// immediately before acting, and the only door into this package's
// refusal: it decides whether target may be acted on, and if not, writes
// the audit_log row itself (action AuditAction, reason naming what
// matched) before returning a non-nil error wrapping ErrRefused. A nil
// return means target is not on the floor; it says nothing about whether
// the action is otherwise a good idea.
//
// target is whatever the caller was about to block: a bare address
// ("203.0.113.7") or a CIDR range ("203.0.113.0/24"), IPv4 or IPv6. It is
// refused if it fails to parse at all (fail closed -- see
// TestCheckRefusesUnparseableTarget), or if, once parsed and normalized,
// it OVERLAPS any floor entry -- not only if it is contained by one, so
// blocking 0.0.0.0/0 or a range like 10.0.0.0/7 that merely straddles a
// floor entry is refused exactly as blocking that entry directly would
// be.
//
// in supplies this call's dynamic floor addresses (see Inputs); triggeredBy
// identifies the caller for the audit row, the same field every other
// audit.Entry in this codebase carries (e.g. "routeros/mitigate").
func (f *Floor) Check(ctx context.Context, database db.Conn, target string, in Inputs, triggeredBy string) error {
	tp, perr := parseTarget(target)
	if perr != nil {
		reason := fmt.Sprintf("%q does not parse as an IP address or CIDR range: %v", target, perr)
		return f.refuse(ctx, database, target, reason, triggeredBy)
	}

	for _, e := range f.entries(in) {
		if tp.Overlaps(e.Prefix) {
			reason := fmt.Sprintf("overlaps the never-block floor entry %s (%s: %s)", e.Prefix, e.Category, e.Why)
			return f.refuse(ctx, database, target, reason, triggeredBy)
		}
	}
	return nil
}

// refuse writes the audit_log row and returns the wrapped error. The
// refusal is returned even if the audit write itself fails -- an audit
// outage must never be a way to make mitigation proceed; it can only ever
// make the action less recorded, never more permitted.
func (f *Floor) refuse(ctx context.Context, database db.Conn, target, reason, triggeredBy string) error {
	refusalErr := fmt.Errorf("%w: %s: %s", ErrRefused, target, reason)
	_, auditErr := audit.Append(ctx, database, audit.Entry{
		Action:      AuditAction,
		Target:      target,
		Reason:      reason,
		TriggeredBy: triggeredBy,
		CreatedAt:   time.Now().UTC(),
	})
	if auditErr != nil {
		return fmt.Errorf("%w (additionally, writing the audit_log row failed: %v)", refusalErr, auditErr)
	}
	return refusalErr
}

// hostPrefix returns a's full-bit-length prefix (/32 for IPv4, /128 for
// IPv6) after the same normalization parseTarget applies, so a dynamic
// input given in IPv4-mapped IPv6 form is compared in its true, unmapped
// family.
func hostPrefix(a netip.Addr) netip.Prefix {
	a = a.Unmap()
	return netip.PrefixFrom(a, a.BitLen())
}

// parseTarget parses raw as a bare IP address or a CIDR range and returns
// its normalized form (see normalizePrefix). A bare address becomes a
// full-bit-length prefix. Any parse failure is returned as-is; Check
// treats that as a refusal, never as "not on the floor".
func parseTarget(raw string) (netip.Prefix, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return netip.Prefix{}, fmt.Errorf("empty target")
	}
	if strings.Contains(raw, "/") {
		p, err := netip.ParsePrefix(raw)
		if err != nil {
			return netip.Prefix{}, err
		}
		return normalizePrefix(p), nil
	}
	a, err := netip.ParseAddr(raw)
	if err != nil {
		return netip.Prefix{}, err
	}
	return hostPrefix(a), nil
}

// normalizePrefix returns p in canonical, unmapped form: masked to its
// network address first, and only then unmapped from IPv4-in-IPv6 to
// plain IPv4 if the network address (after masking) is still one.
//
// Masking has to happen before the IPv4-in-6 check, not after: an address
// like "::ffff:10.0.0.1/64" carries the IPv4-mapped bit pattern only in
// bits 80-95, which a /64 mask zeroes out as host bits (the pattern needs
// Bits>=96 to survive masking). Checking Is4In6 on the raw, unmasked
// address would misidentify that /64 -- whose real network address is
// "::/64", ordinary IPv6 space, nothing to do with 10.0.0.1 -- as an IPv4
// range. Checking it on the masked address gets both cases right for
// free: a genuinely IPv4-mapped range (Bits>=96) unmaps and adjusts its
// bit count by the fixed 96-bit "::ffff:0:0/96" prefix; anything coarser
// is left as the IPv6 range it actually is.
func normalizePrefix(p netip.Prefix) netip.Prefix {
	m := p.Masked()
	addr := m.Addr()
	if addr.Is4In6() {
		return netip.PrefixFrom(addr.Unmap(), m.Bits()-96)
	}
	return m
}
