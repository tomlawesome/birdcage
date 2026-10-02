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
	"unicode/utf8"

	"github.com/tomlawesome/birdcage/internal/db"
	"github.com/tomlawesome/birdcage/internal/term"
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

// VisitorPoisoner is what a poisoner hit adds to a Visitor (#86 slice D):
// the facts the dashboard's sentence and band label need, which no other
// service has an equivalent of.
//
// Carried as its own field rather than squeezed into Tried, which is a list
// of credentials-and-paths a visitor tried against a service. A poisoner did
// not try anything -- it answered -- so putting a bait name in that list
// would make every reader of Tried handle a value that is not what the field
// means.
type VisitorPoisoner struct {
	// Name is the bait name the poisoner claimed to be.
	Name string `json:"name"`

	// Protocol is which of the three bait protocols carried the answer:
	// "llmnr", "nbt-ns" or "mdns".
	Protocol string `json:"protocol"`

	// MAC is the answering host's hardware address, or empty -- the
	// detector reads it passively from the kernel's neighbour table, and an
	// answer from off-segment or over IPv6 has no entry to read
	// (internal/agent/poisoner/arp.go).
	MAC string `json:"mac"`
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
	Clients       []string            `json:"clients"`
	StillArriving bool                `json:"still_arriving"`

	// Poisoner is present only for a visitor with a poisoner hit (#86
	// slice D) -- absent, not zeroed, for every other visitor, so the
	// dashboard tests presence rather than comparing empty strings.
	Poisoner *VisitorPoisoner `json:"poisoner,omitempty"`
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

	// Service is the alert's service name, for classifyKind's poisoner
	// rule (#86 slice D) -- the only rule that looks at what a hit was
	// rather than when or where it landed.
	Service string
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

// isPoisoner reports whether any of these hits is a poisoner hit -- #86's
// detector catching something that answered a name nobody should answer.
func isPoisoner(hits []hitPoint) bool {
	for _, h := range hits {
		if h.Service == poisonerService {
			return true
		}
	}
	return false
}

// poisonerService is the service name #86's detector's alerts carry, as
// internal/opencanary derives it from logtype 30001. Written out rather than
// imported to keep this file's only dependency on that package the one
// extractLogData already avoids (see its own comment on why store stays an
// ingest-independent reader); TestPoisonerServiceMatchesTheMapping pins the
// two together.
const poisonerService = "poisoner"

// classifyKind applies the kind rules in the stated order, first match wins:
// poisoner, then issue #35's own four -- inside, sweep, repeat, and touch as
// the default. hits is every hit sourceIP made anywhere in the queried range
// -- GET /api/visitors and GET /api/trace both build it the same way
// (alertsInRange, grouped by source_ip) so the two endpoints never disagree
// about a source's kind.
func classifyKind(sourceIP string, hits []hitPoint, internalRanges []*net.IPNet) VisitorKind {
	// A poisoner is inside, by definition and not by address: LLMNR, NBT-NS
	// and mDNS are link-local, so something that answered one of this
	// canary's bait queries received a link-local multicast or a subnet
	// broadcast, which only a host on the segment can do. That makes it the
	// "inside" kind whatever its source address says, and deliberately
	// without consulting internalRanges -- an operator who has not
	// configured BIRDCAGE_INTERNAL_RANGES, or whose LAN uses public address
	// space, must not see the one near-certain hit on the dashboard demoted
	// to "one touch".
	//
	// First, so it wins over sweep and repeat: #86 decision 34 makes this
	// confidence near-certain, so it outranks other hits in the band. No new
	// colour comes with it -- ADR-0004's palette is the four validated in
	// round 1, and this rise is drawn in the one it already belongs to.
	if isPoisoner(hits) {
		return KindInside
	}
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

// logHeader reads key (already lowercase -- twisted.protocols.sip.Message
// .addHeader lowercases every header name before storing it) from
// logdata's HEADERS object, returning its first value. Unlike every other
// field triedFor reads, HEADERS is not a JSON string but an object mapping
// header name to a list of values (sip.py:17's request.headers, one list
// per header to allow repeats), so it needs its own decode rather than
// logString's.
func logHeader(logdata map[string]json.RawMessage, key string) (string, bool) {
	raw, ok := logdata["HEADERS"]
	if !ok {
		return "", false
	}
	var headers map[string][]string
	if err := json.Unmarshal(raw, &headers); err != nil {
		return "", false
	}
	values, ok := headers[key]
	if !ok || len(values) == 0 {
		return "", false
	}
	return values[0], true
}

// triedFor extracts issue #35's one-line "what was tried" summary for a
// single hit, from service (alerts.service, already resolved by
// internal/ingest) and raw (alerts.raw). Field names match upstream
// OpenCanary 0.9.10's own logdata keys, verified against the modules'
// source rather than assumed: ssh.py, ftp.py, mysql.py, telnet.py,
// http.py, samba.py (USERNAME, PASSWORD, PATH, SHARENAME, all uppercase);
// rdp.py:27 (USERNAME), tftp.py:33 (FILENAME, OPCODE, MODE), sip.py:17
// (HEADERS), redis.py:698 (CMD, ARGS); and mssql.py:194's loginData dict
// (UserName, Password, AppName -- mixed case, the one service here whose
// keys an ssh-shaped case would silently never match). Credentials are
// shown exactly as ssh/ftp show theirs -- in the clear, via displayCred --
// never redacted further and never less: this is a honeypot summarizing
// what an attacker themselves sent, not a secret birdcage is holding.
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
	case "rdp":
		// rdp.py:27 logs only a USERNAME, pulled from the X.224 Connection
		// Request's routing token by regex -- no password field exists to
		// show alongside it. displayCred rather than a bare return: a
		// client that sent the mstshash= cookie with nothing after the '='
		// (regex matches, captures "") must still show as "(empty)", not
		// a blank Tried entry.
		if username, ok := logString(logdata, "USERNAME"); ok {
			return displayCred(username)
		}
		return service
	case "tftp":
		// tftp.py:33 logs FILENAME, OPCODE ("READ"/"WRITE") and MODE
		// ("octet"/"netascii"); FILENAME is the one field every request
		// carries (a read or write with no filename never reaches this
		// line -- Tftp.datagramReceived's own split would already have
		// bailed), so it plays PATH's role here.
		filename, ok := logString(logdata, "FILENAME")
		if !ok {
			return service
		}
		tried := filename
		if opcode, _ := logString(logdata, "OPCODE"); opcode != "" {
			tried = opcode + " " + tried
		}
		if mode, _ := logString(logdata, "MODE"); mode != "" {
			tried += " (" + mode + ")"
		}
		return tried
	case "sip":
		// sip.py:17 logs the whole parsed header set; the From header is
		// the one field that answers "who tried this" -- a caller identity
		// the request itself supplies, the SIP analogue of a username.
		if from, ok := logHeader(logdata, "from"); ok && from != "" {
			return from
		}
		return service
	case "redis":
		// redis.py:698's _logAlert logs the rejected command and its
		// arguments verbatim (already truncated and UTF-8-sanitized by
		// that function) -- CMD/ARGS plays USERNAME/PASSWORD's exact role
		// for a protocol whose one authentication command is AUTH
		// <password>, so it gets the same "cmd / (empty)" treatment as a
		// blank credential rather than a new display rule.
		if cmd, ok := logString(logdata, "CMD"); ok {
			args, _ := logString(logdata, "ARGS")
			return cmd + " " + displayCred(args)
		}
		return service
	case "mssql":
		// mssql.py:194's loginData dict is logdata verbatim, mixed case
		// throughout (UserName, Password, AppName) -- see this function's
		// own doc comment on why a copy of the ssh branch above would
		// silently match nothing. AppName (the client's own declared
		// program name, e.g. "Microsoft SQL Server Management Studio")
		// prefixes the credential pair the way http's PATH prefixes
		// USERNAME/PASSWORD, since it is the same kind of context field.
		username, ok := logString(logdata, "UserName")
		if !ok {
			return service
		}
		password, _ := logString(logdata, "Password")
		cred := username + " / " + displayCred(password)
		if appName, _ := logString(logdata, "AppName"); appName != "" {
			return appName + " " + cred
		}
		return cred
	case poisonerService:
		// The protocol, which is what a poisoner rise is labelled with on
		// the band -- in the place a credential label goes, since that is
		// the one fact about the answer worth reading at a glance. The bait
		// name and the MAC go on Visitor.Poisoner instead, for the sentence
		// in the events list; see VisitorPoisoner's own comment on why they
		// are not in this list.
		if protocol, ok := logString(logdata, "PROTOCOL"); ok && protocol != "" {
			return protocol
		}
		return poisonerService
	default:
		return service
	}
}

// clientSentinel is OpenCanary's own placeholder for a client field it has
// nothing to report (http.py:144, :169) -- its words, not the visitor's, so
// it is treated the same as absent rather than shown.
const clientSentinel = "<not supplied>"

// maxClientRunes caps how long a stored client string can be: a user agent
// or an SSH version banner is attacker-controlled and otherwise unbounded.
const maxClientRunes = 160

// clientFor extracts issue #143's client field for a single hit -- the
// string that says what kind of client knocked, which triedFor's
// credentials-and-paths summary has no room for. Only http (USERAGENT) and
// ssh (REMOTEVERSION, present on OpenCanary logtypes 4001 and 4002) have
// one; every other service returns "" rather than falling back to the
// service name the way triedFor does, since an empty client means "say
// nothing" here, not "say http".
func clientFor(service, raw string) string {
	logdata := extractLogData(raw)
	switch service {
	case "http":
		s, _ := logString(logdata, "USERAGENT")
		return normalizeClient(s)
	case "ssh":
		s, _ := logString(logdata, "REMOTEVERSION")
		return normalizeClient(s)
	default:
		return ""
	}
}

// normalizeClient applies clientFor's display pipeline to one raw field
// value, in order: invalid UTF-8 (mail/templates.go:136's displayName
// pattern) withholds the whole value rather than showing a mangled one;
// strings.TrimSpace; OpenCanary's own clientSentinel withholds too, since
// it is OpenCanary's words rather than the visitor's; term.Escape so
// control bytes and bidi overrides show as literal escapes instead of
// doing something to the operator's terminal; then a 160-rune cap, with
// "…" appended when that cuts the string, so one long value can't push a
// row's layout around the way triedFor's credentials never have to.
func normalizeClient(s string) string {
	if !utf8.ValidString(s) {
		return ""
	}
	s = strings.TrimSpace(s)
	if s == clientSentinel {
		return ""
	}
	s = term.Escape(s)
	if utf8.RuneCountInString(s) > maxClientRunes {
		runes := []rune(s)
		s = string(runes[:maxClientRunes]) + "…"
	}
	return s
}

// poisonerFor builds Visitor.Poisoner from hits (newest first, as
// alertsInRange returns them): the newest poisoner hit's own facts, or nil
// when this visitor has none.
//
// The newest, not the first: if the same host answered twice, what it most
// recently claimed is what an operator is looking at.
func poisonerFor(hits []Alert) *VisitorPoisoner {
	for _, a := range hits {
		if a.Service != poisonerService {
			continue
		}
		logdata := extractLogData(a.Raw)
		name, _ := logString(logdata, "NAME")
		protocol, _ := logString(logdata, "PROTOCOL")
		mac, _ := logString(logdata, "MAC")
		if name == "" && protocol == "" {
			// Neither fact present: not an event this can describe, so keep
			// looking rather than returning a row of empty strings the
			// dashboard would then have to render.
			continue
		}
		return &VisitorPoisoner{Name: name, Protocol: protocol, MAC: mac}
	}
	return nil
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

// clientSummaries builds Visitor.Clients from hits (newest first, as
// alertsInRange returns them): every hit's clientFor result, skipping the
// empties (absent, odd, or a non-client service), deduplicated, keeping the
// first four in time order -- the same shape as triedSummaries, for the
// same reason: ascending is the order the visitor's own clients actually
// appeared in, not arrival-into-this-slice order.
func clientSummaries(hits []Alert) []string {
	seen := make(map[string]bool, 4)
	out := make([]string, 0, 4)
	for i := len(hits) - 1; i >= 0 && len(out) < 4; i-- {
		a := hits[i]
		c := clientFor(a.Service, a.Raw)
		if c == "" || seen[c] {
			continue
		}
		seen[c] = true
		out = append(out, c)
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
		classifyHits = append(classifyHits, hitPoint{At: a.ReceivedAt, CanaryID: a.InstanceID, Service: a.Service})
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
		Clients:       clientSummaries(hits),
		StillArriving: !newest.Before(now.Add(-stillArrivingWindow)),
		Poisoner:      poisonerFor(hits),
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
