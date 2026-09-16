// Visitors (issue #35): GET /api/visitors groups alerts in a range by
// source_ip into one Visitor per source, classified into a VisitorKind
// and summarized with what it tried against which canaries. Kind
// classification and "tried" extraction are both pure Go functions (see
// classifyKind and triedFor) with their own table tests -- SQL's only job
// here is fetching rows (alertsInRange, store.go), per AGENTS.md's
// "reuse the mechanism, don't invent a second one" and the issue's own
// "kind classification is in Go, not SQL" rule.
package store

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"sort"
	"strings"
	"time"

	"github.com/tomlawesome/birdcage/internal/db"
)

// VisitorKind is which of the four ADR-0004 rise colours a visitor gets.
type VisitorKind string

const (
	KindInside VisitorKind = "inside"
	KindSweep  VisitorKind = "sweep"
	KindRepeat VisitorKind = "repeat"
	KindTouch  VisitorKind = "touch"
)

// VisitorCanaryHits is one canary a Visitor touched, and how many times.
type VisitorCanaryHits struct {
	ID   string `json:"id"`
	Hits int64  `json:"hits"`
}

// Visitor is one source_ip's whole history within the requested range,
// GET /api/visitors' per-entry shape. Field names and JSON shape match
// frontend/src/lib/types.ts's Visitor exactly.
type Visitor struct {
	SourceIP      string              `json:"source_ip"`
	Kind          VisitorKind         `json:"kind"`
	FirstAt       time.Time           `json:"first_at"`
	LastAt        time.Time           `json:"last_at"`
	Hits          int64               `json:"hits"`
	Canaries      []VisitorCanaryHits `json:"canaries"`
	Services      []string            `json:"services"`
	Tried         []string            `json:"tried"`
	StillArriving bool                `json:"still_arriving"`
}

// stillArrivingWindow is how recent a visitor's newest hit must be for
// still_arriving to be true (issue #35: "a hit in the last 5 min").
const stillArrivingWindow = 5 * time.Minute

// sweepWindow and repeatDays are the sliding-window and distinct-day
// thresholds the "sweep" and "repeat" kind rules use (issue #35 §Kind
// rules).
const (
	sweepWindow = 15 * time.Minute
	repeatDays  = 3
)

// hitPoint is the minimal shape classifyKind needs: when a hit landed and
// which canary it landed on. Built from Alert rows so classification
// never has to re-touch the database.
type hitPoint struct {
	At       time.Time
	CanaryID string
}

// ParseInternalRanges parses BIRDCAGE_INTERNAL_RANGES (issue #35): a
// comma-separated list of CIDR blocks, additional to the always-internal
// set classifyKind's "inside" rule already recognizes on its own (RFC
// 1918, IPv6 ULA, link-local -- see isInside), for an operator whose LAN
// uses address space outside those defaults. An empty or all-whitespace s
// is valid and yields no additional ranges (nil, nil) -- the variable
// being unset is the common case, not an error.
func ParseInternalRanges(s string) ([]*net.IPNet, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, nil
	}
	parts := strings.Split(s, ",")
	ranges := make([]*net.IPNet, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		_, ipNet, err := net.ParseCIDR(p)
		if err != nil {
			return nil, fmt.Errorf("store: BIRDCAGE_INTERNAL_RANGES: invalid CIDR %q: %w", p, err)
		}
		ranges = append(ranges, ipNet)
	}
	return ranges, nil
}

// isInside reports whether sourceIP counts as "from inside" (issue #35
// rule 1): RFC 1918, IPv6 ULA, link-local, or one of internalRanges.
// net.IP.IsPrivate covers RFC 1918 (10/8, 172.16/12, 192.168/16) and IPv6
// ULA (fc00::/7) in one call (documented Go stdlib behavior since 1.17);
// IsLinkLocalUnicast covers 169.254/16 and fe80::/10. An unparseable
// sourceIP (should never happen -- alerts.source_ip always comes from
// net.ListenPacket's own peer address -- but this function must still
// answer something for a malformed or empty value) is never "inside".
func isInside(sourceIP string, internalRanges []*net.IPNet) bool {
	ip := net.ParseIP(sourceIP)
	if ip == nil {
		return false
	}
	if ip.IsPrivate() || ip.IsLinkLocalUnicast() {
		return true
	}
	for _, r := range internalRanges {
		if r.Contains(ip) {
			return true
		}
	}
	return false
}

// isSweep reports whether hits touch >= 2 distinct canaries within any
// 15-minute window (issue #35 rule 2). O(n^2) worst case; fine for a
// single source's hit volume within one range query.
func isSweep(hits []hitPoint) bool {
	sorted := append([]hitPoint(nil), hits...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].At.Before(sorted[j].At) })

	for i := range sorted {
		canaries := map[string]bool{sorted[i].CanaryID: true}
		for j := i + 1; j < len(sorted) && sorted[j].At.Sub(sorted[i].At) <= sweepWindow; j++ {
			canaries[sorted[j].CanaryID] = true
			if len(canaries) >= 2 {
				return true
			}
		}
	}
	return false
}

// isRepeat reports whether some single canary has hits on >= 3 distinct
// UTC calendar days (issue #35 rule 3).
func isRepeat(hits []hitPoint) bool {
	daysByCanary := map[string]map[string]bool{}
	for _, h := range hits {
		day := h.At.UTC().Format("2006-01-02")
		days, ok := daysByCanary[h.CanaryID]
		if !ok {
			days = map[string]bool{}
			daysByCanary[h.CanaryID] = days
		}
		days[day] = true
	}
	for _, days := range daysByCanary {
		if len(days) >= repeatDays {
			return true
		}
	}
	return false
}

// classifyKind applies issue #35's four kind rules in the stated order,
// first match wins: inside, then sweep, then repeat, then touch as the
// default. hits is every hit sourceIP made anywhere in the queried range
// -- GET /api/visitors and GET /api/trace both build it the same way
// (alertsInRange, grouped by source_ip) so the two endpoints never
// disagree about a source's kind.
func classifyKind(sourceIP string, hits []hitPoint, internalRanges []*net.IPNet) VisitorKind {
	if isInside(sourceIP, internalRanges) {
		return KindInside
	}
	if isSweep(hits) {
		return KindSweep
	}
	if isRepeat(hits) {
		return KindRepeat
	}
	return KindTouch
}

// emptyMark is what triedFor shows for an explicitly empty credential
// value (issue #35: "empty password shown as (empty)").
const emptyMark = "(empty)"

// extractLogData decodes raw (an alerts.raw value -- OpenCanary's whole
// log payload exactly as the ingest path stored it, syslog envelope and
// all where one is present) and returns its "logdata" object. raw is
// parsed the same way internal/ingest.ParseOpenCanaryMessage does --
// skip to the first '{' byte, since OpenCanary lets operators change the
// syslog formatter prefix -- but reimplemented here rather than
// imported: internal/ingest
// never captures logdata at all (its Alert type has no field for it), so
// there is nothing exported to reuse, and store deliberately stays a
// read-only, ingest-independent consumer of the alerts table (see
// store.go's package doc). Returns nil, not an error, for anything that
// doesn't parse -- a hand-inserted test fixture's placeholder raw string,
// or a future malformed row -- since triedFor's callers must always get a
// usable fallback rather than propagating a per-hit error through an
// aggregate response.
func extractLogData(raw string) map[string]json.RawMessage {
	start := strings.IndexByte(raw, '{')
	if start < 0 {
		return nil
	}
	var payload struct {
		LogData map[string]json.RawMessage `json:"logdata"`
	}
	if err := json.NewDecoder(strings.NewReader(raw[start:])).Decode(&payload); err != nil {
		return nil
	}
	return payload.LogData
}

// logString reads key from logdata as a string. false covers both "key
// absent" and "key present but not a JSON string" -- either way there is
// nothing triedFor can safely use.
func logString(logdata map[string]json.RawMessage, key string) (string, bool) {
	raw, ok := logdata[key]
	if !ok {
		return "", false
	}
	var s string
	if err := json.Unmarshal(raw, &s); err != nil {
		return "", false
	}
	return s, true
}

// displayCred formats a USERNAME/PASSWORD value for triedFor's "USERNAME
// / PASSWORD" summaries, showing an empty credential as emptyMark rather
// than a blank that would otherwise vanish into "root / ".
func displayCred(s string) string {
	if s == "" {
		return emptyMark
	}
	return s
}

// triedFor extracts issue #35's one-line "what was tried" summary for a
// single hit, from service (alerts.service, already resolved by
// internal/ingest) and raw (alerts.raw). Field names (USERNAME, PASSWORD,
// PATH, SHARENAME) match upstream OpenCanary's own logdata keys, verified
// against the modules' source (thinkst/opencanary: ssh.py, ftp.py,
// mysql.py, telnet.py, http.py, samba.py all use these exact uppercase
// keys) rather than assumed.
func triedFor(service, raw string) string {
	logdata := extractLogData(raw)
	switch service {
	case "ssh", "telnet", "ftp", "mysql":
		if username, ok := logString(logdata, "USERNAME"); ok {
			password, _ := logString(logdata, "PASSWORD")
			return username + " / " + displayCred(password)
		}
		return service
	case "http":
		path, ok := logString(logdata, "PATH")
		if !ok {
			return service
		}
		if username, ok := logString(logdata, "USERNAME"); ok {
			password, _ := logString(logdata, "PASSWORD")
			return path + " " + username + " / " + displayCred(password)
		}
		return path
	case "smb":
		if share, ok := logString(logdata, "SHARENAME"); ok && share != "" {
			return share
		}
		return "smb"
	default:
		return service
	}
}

// triedSummaries builds Visitor.Tried from hits (newest first, as
// alertsInRange returns them): every hit's triedFor result, deduplicated,
// keeping the first four in time order -- ascending, i.e. the order the
// visitor actually tried them in, not arrival-into-this-slice order
// (issue #35: "Deduplicate, keep the first 4 in time order").
func triedSummaries(hits []Alert) []string {
	seen := make(map[string]bool, 4)
	out := make([]string, 0, 4)
	for i := len(hits) - 1; i >= 0 && len(out) < 4; i-- {
		a := hits[i]
		t := triedFor(a.Service, a.Raw)
		if seen[t] {
			continue
		}
		seen[t] = true
		out = append(out, t)
	}
	return out
}

// buildVisitor turns one source_ip's hits (newest first, as
// alertsInRange/ListVisitors group them) into its Visitor summary.
func buildVisitor(sourceIP string, hits []Alert, now time.Time, internalRanges []*net.IPNet) Visitor {
	newest := hits[0].ReceivedAt
	oldest := hits[len(hits)-1].ReceivedAt

	canaryHits := map[string]int64{}
	serviceSet := map[string]bool{}
	classifyHits := make([]hitPoint, 0, len(hits))
	for _, a := range hits {
		canaryHits[a.InstanceID]++
		serviceSet[a.Service] = true
		classifyHits = append(classifyHits, hitPoint{At: a.ReceivedAt, CanaryID: a.InstanceID})
	}

	canaryIDs := make([]string, 0, len(canaryHits))
	for id := range canaryHits {
		canaryIDs = append(canaryIDs, id)
	}
	sort.Strings(canaryIDs)
	canaries := make([]VisitorCanaryHits, 0, len(canaryIDs))
	for _, id := range canaryIDs {
		canaries = append(canaries, VisitorCanaryHits{ID: id, Hits: canaryHits[id]})
	}

	services := make([]string, 0, len(serviceSet))
	for s := range serviceSet {
		services = append(services, s)
	}
	sort.Strings(services)

	return Visitor{
		SourceIP:      sourceIP,
		Kind:          classifyKind(sourceIP, classifyHits, internalRanges),
		FirstAt:       oldest,
		LastAt:        newest,
		Hits:          int64(len(hits)),
		Canaries:      canaries,
		Services:      services,
		Tried:         triedSummaries(hits),
		StillArriving: !newest.Before(now.Add(-stillArrivingWindow)),
	}
}

// VisitorFilter narrows ListVisitors. Since/Until bound the range being
// summarized (the caller resolves these from a Range via ParseRange, same
// as ListCanaries' rangeWindow). Before is a paging cursor: only visitors
// whose LastAt is strictly before it are returned -- the grouped-visitor
// analogue of AlertFilter.Before, which cuts on id instead since alerts
// aren't grouped. A zero Before means "no cursor, start from the newest
// visitor".
type VisitorFilter struct {
	Since  time.Time
	Until  time.Time
	Before time.Time
	Limit  int
}

const (
	defaultVisitorLimit = 100
	maxVisitorLimit     = 1000
)

// NormalizeVisitorLimit applies VisitorFilter.Limit's defaulting/capping
// rule, mirroring NormalizeLimit -- exported for the same reason: the API
// handler needs the exact effective page size to decide whether
// next_before should be null.
func NormalizeVisitorLimit(limit int) int {
	if limit <= 0 {
		return defaultVisitorLimit
	}
	if limit > maxVisitorLimit {
		return maxVisitorLimit
	}
	return limit
}

// ListVisitors groups every alert in [filter.Since, filter.Until] by
// source_ip into a Visitor, newest last_at first, paged by filter.Before
// and filter.Limit.
//
// alertsInRange already returns rows newest id (== newest received_at)
// first; bucketing them by source_ip while walking that order in a single
// pass, and recording each source's *first* appearance in a separate
// order slice, gets the buckets sorted by last_at descending for free --
// the first alert seen for a given source, in a newest-first scan, is
// necessarily that source's own newest hit.
func ListVisitors(ctx context.Context, database *db.DB, now time.Time, filter VisitorFilter, internalRanges []*net.IPNet) ([]Visitor, error) {
	now = now.UTC()

	alerts, err := alertsInRange(ctx, database, filter.Since, filter.Until)
	if err != nil {
		return nil, err
	}

	bySource := map[string][]Alert{}
	var order []string
	for _, a := range alerts {
		if _, ok := bySource[a.SourceIP]; !ok {
			order = append(order, a.SourceIP)
		}
		bySource[a.SourceIP] = append(bySource[a.SourceIP], a)
	}

	limit := NormalizeVisitorLimit(filter.Limit)
	visitors := make([]Visitor, 0, limit)
	for _, ip := range order {
		v := buildVisitor(ip, bySource[ip], now, internalRanges)
		if !filter.Before.IsZero() && !v.LastAt.Before(filter.Before) {
			continue
		}
		visitors = append(visitors, v)
		if len(visitors) == limit {
			break
		}
	}
	return visitors, nil
}
