package store

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/tomlawesome/birdcage/internal/db"
	"github.com/tomlawesome/birdcage/internal/opencanary"
)

// mustCIDR parses a CIDR block for the classifyKind fixtures.
func mustCIDR(t *testing.T, cidr string) *net.IPNet {
	t.Helper()
	_, n, err := net.ParseCIDR(cidr)
	if err != nil {
		t.Fatalf("ParseCIDR(%q): %v", cidr, err)
	}
	return n
}

// --- classifyKind: pure Go, no database -- one fixture per rule that
// only that rule matches, per issue #35, plus the rule-ordering cases.

func hp(t *testing.T, at, canaryID string) hitPoint {
	return hitPoint{At: mustParse(t, at), CanaryID: canaryID}
}

func TestClassifyKindInsideBeatsEverythingElse(t *testing.T) {
	// 10.0.40.23 is RFC 1918 -- inside wins even though its own hits also
	// satisfy the sweep rule (2 distinct canaries within 15 minutes), which
	// is evaluated after inside and must never be reached.
	hits := []hitPoint{
		hp(t, "2026-09-12T19:11:04Z", "canary-lan"),
		hp(t, "2026-09-12T19:11:22Z", "canary-srv"),
	}
	if got := classifyKind("10.0.40.23", hits, nil); got != KindInside {
		t.Errorf("classifyKind = %q, want inside", got)
	}
}

func TestClassifyKindInsideFromOperatorRange(t *testing.T) {
	_, cidr, err := net.ParseCIDR("100.64.0.0/10")
	if err != nil {
		t.Fatal(err)
	}
	hits := []hitPoint{hp(t, "2026-09-12T19:11:04Z", "canary-lan")}
	if got := classifyKind("100.64.5.9", hits, []*net.IPNet{cidr}); got != KindInside {
		t.Errorf("classifyKind = %q, want inside (BIRDCAGE_INTERNAL_RANGES)", got)
	}
	if got := classifyKind("8.8.8.8", hits, []*net.IPNet{cidr}); got == KindInside {
		t.Errorf("classifyKind(8.8.8.8) = inside, want not inside (outside every configured range)")
	}
}

func TestClassifyKindSweepTwoCanariesWithin15Minutes(t *testing.T) {
	// 203.0.113.42 walks four canaries in nine minutes (the data story).
	hits := []hitPoint{
		hp(t, "2026-09-12T22:04:31Z", "canary-guest"),
		hp(t, "2026-09-12T22:04:02Z", "canary-guest"),
		hp(t, "2026-09-12T22:01:47Z", "canary-iot"),
		hp(t, "2026-09-12T21:57:22Z", "canary-srv"),
		hp(t, "2026-09-12T21:56:58Z", "canary-srv"),
		hp(t, "2026-09-12T21:55:40Z", "canary-lan"),
		hp(t, "2026-09-12T21:55:39Z", "canary-lan"),
	}
	if got := classifyKind("203.0.113.42", hits, nil); got != KindSweep {
		t.Errorf("classifyKind = %q, want sweep", got)
	}
}

func TestClassifyKindSweepJustOutside15MinutesIsNotSweep(t *testing.T) {
	// Same two canaries, but 15 minutes and 1 second apart: no 15-minute
	// window contains both, so this must not classify as sweep -- and
	// with only one canary per window, it also can't be repeat (one day),
	// so it falls through to touch.
	hits := []hitPoint{
		hp(t, "2026-09-12T22:00:00Z", "canary-lan"),
		hp(t, "2026-09-12T22:15:01Z", "canary-srv"),
	}
	if got := classifyKind("203.0.113.99", hits, nil); got != KindTouch {
		t.Errorf("classifyKind = %q, want touch (window just missed)", got)
	}
}

func TestClassifyKindRepeatThreeDistinctDaysSameCanary(t *testing.T) {
	// 198.51.100.7 knocks canary-iot every ~20 minutes across six nights
	// (the data story); three representative days are enough to trigger
	// the rule on their own.
	hits := []hitPoint{
		hp(t, "2026-09-07T10:19:10Z", "canary-iot"),
		hp(t, "2026-09-08T21:59:10Z", "canary-iot"),
		hp(t, "2026-09-12T21:59:10Z", "canary-iot"),
	}
	if got := classifyKind("198.51.100.7", hits, nil); got != KindRepeat {
		t.Errorf("classifyKind = %q, want repeat", got)
	}
}

func TestClassifyKindRepeatOnlyTwoDistinctDaysIsNotRepeat(t *testing.T) {
	hits := []hitPoint{
		hp(t, "2026-09-07T10:19:10Z", "canary-iot"),
		hp(t, "2026-09-08T21:59:10Z", "canary-iot"),
	}
	if got := classifyKind("198.51.100.7", hits, nil); got != KindTouch {
		t.Errorf("classifyKind = %q, want touch (only 2 distinct days)", got)
	}
}

func TestClassifyKindRepeatDaysMustBeSameCanary(t *testing.T) {
	// Three distinct days, but split across two different canaries --
	// no single canary reaches 3 distinct days, so this is not repeat.
	// It is also not sweep: the hits are days apart, never within 15
	// minutes of each other.
	hits := []hitPoint{
		hp(t, "2026-09-07T10:19:10Z", "canary-iot"),
		hp(t, "2026-09-08T21:59:10Z", "canary-lan"),
	}
	if got := classifyKind("198.51.100.7", hits, nil); got != KindTouch {
		t.Errorf("classifyKind = %q, want touch (days split across canaries)", got)
	}
}

func TestClassifyKindTouchIsTheDefault(t *testing.T) {
	// 192.0.2.88, a single anonymous FTP login and nothing else.
	hits := []hitPoint{hp(t, "2026-09-11T03:18:40Z", "canary-srv")}
	if got := classifyKind("192.0.2.88", hits, nil); got != KindTouch {
		t.Errorf("classifyKind = %q, want touch", got)
	}
}

func TestClassifyKindUnparseableSourceIsNeverInside(t *testing.T) {
	hits := []hitPoint{hp(t, "2026-09-11T03:18:40Z", "canary-srv")}
	if got := classifyKind("not-an-ip", hits, nil); got != KindTouch {
		t.Errorf("classifyKind(%q) = %q, want touch (falls through, not inside)", "not-an-ip", got)
	}
}

// --- ParseInternalRanges

func TestParseInternalRangesEmptyIsNilNoError(t *testing.T) {
	ranges, err := ParseInternalRanges("")
	if err != nil || ranges != nil {
		t.Errorf("ParseInternalRanges(\"\") = %v, %v, want nil, nil", ranges, err)
	}
	ranges, err = ParseInternalRanges("   ")
	if err != nil || ranges != nil {
		t.Errorf("ParseInternalRanges(whitespace) = %v, %v, want nil, nil", ranges, err)
	}
}

func TestParseInternalRangesValidList(t *testing.T) {
	ranges, err := ParseInternalRanges("100.64.0.0/10, 203.0.113.0/24")
	if err != nil {
		t.Fatalf("ParseInternalRanges: %v", err)
	}
	if len(ranges) != 2 {
		t.Fatalf("got %d ranges, want 2: %v", len(ranges), ranges)
	}
	if !ranges[0].Contains(net.ParseIP("100.64.1.1")) {
		t.Errorf("ranges[0] does not contain 100.64.1.1")
	}
	if !ranges[1].Contains(net.ParseIP("203.0.113.42")) {
		t.Errorf("ranges[1] does not contain 203.0.113.42")
	}
}

func TestParseInternalRangesInvalidCIDR(t *testing.T) {
	if _, err := ParseInternalRanges("not-a-cidr"); err == nil {
		t.Error("ParseInternalRanges(\"not-a-cidr\") = nil error, want an error")
	}
}

// --- triedFor / extractLogData: pure Go, no database.

// datagram wraps jsonBody in a syslog-envelope-like prefix, matching how
// internal/ingest.ParseOpenCanaryMessage's own test builds one and how
// alerts.raw is actually stored (the whole datagram, not just the JSON).
func datagram(jsonBody string) string {
	return "<14>opencanaryd[12345:987654]: canary-1 WARNING " + jsonBody + "\x00"
}

func TestTriedForCredentialServices(t *testing.T) {
	tests := []struct {
		name    string
		service string
		raw     string
		want    string
	}{
		{
			name:    "ssh username and password",
			service: "ssh",
			raw:     datagram(`{"logdata": {"USERNAME": "root", "PASSWORD": "toor"}, "logtype": 4002}`),
			want:    "root / toor",
		},
		{
			name:    "ftp empty password shown as (empty)",
			service: "ftp",
			raw:     datagram(`{"logdata": {"USERNAME": "anonymous", "PASSWORD": ""}, "logtype": 2001}`),
			want:    "anonymous / (empty)",
		},
		{
			name:    "mysql password absent entirely also shown as (empty)",
			service: "mysql",
			raw:     datagram(`{"logdata": {"USERNAME": "root"}, "logtype": 8001}`),
			want:    "root / (empty)",
		},
		{
			name:    "telnet",
			service: "telnet",
			raw:     datagram(`{"logdata": {"USERNAME": "admin", "PASSWORD": "admin"}, "logtype": 6001}`),
			want:    "admin / admin",
		},
		{
			name:    "ssh with no USERNAME at all falls back to the service name",
			service: "ssh",
			raw:     datagram(`{"logdata": {}, "logtype": 4000}`),
			want:    "ssh",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := triedFor(tt.service, tt.raw); got != tt.want {
				t.Errorf("triedFor(%q, ...) = %q, want %q", tt.service, got, tt.want)
			}
		})
	}
}

func TestTriedForHTTP(t *testing.T) {
	tests := []struct {
		name string
		raw  string
		want string
	}{
		{
			name: "path only, no credentials",
			raw:  datagram(`{"logdata": {"PATH": "/admin"}, "logtype": 3000}`),
			want: "/admin",
		},
		{
			name: "path with credentials appended",
			raw:  datagram(`{"logdata": {"PATH": "/login", "USERNAME": "admin", "PASSWORD": "letmein"}, "logtype": 3001}`),
			want: "/login admin / letmein",
		},
		{
			name: "no PATH at all falls back to the service name",
			raw:  datagram(`{"logdata": {}, "logtype": 3000}`),
			want: "http",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := triedFor("http", tt.raw); got != tt.want {
				t.Errorf("triedFor(http, ...) = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestTriedForSMB(t *testing.T) {
	tests := []struct {
		name string
		raw  string
		want string
	}{
		{
			name: "sharename present",
			raw:  datagram(`{"logdata": {"SHARENAME": "backups"}, "logtype": 5000}`),
			want: "backups",
		},
		{
			name: "sharename absent falls back to smb",
			raw:  datagram(`{"logdata": {}, "logtype": 5000}`),
			want: "smb",
		},
		{
			name: "sharename empty string also falls back to smb",
			raw:  datagram(`{"logdata": {"SHARENAME": ""}, "logtype": 5000}`),
			want: "smb",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := triedFor("smb", tt.raw); got != tt.want {
				t.Errorf("triedFor(smb, ...) = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestTriedForUnenumeratedServiceIsJustTheServiceName(t *testing.T) {
	for _, service := range []string{"portscan", "tcpbanner", "unknown", "base"} {
		raw := datagram(`{"logdata": {"whatever": "value"}, "logtype": 1004}`)
		if got := triedFor(service, raw); got != service {
			t.Errorf("triedFor(%q, ...) = %q, want %q", service, got, service)
		}
	}
}

func TestTriedForUnparseableRawFallsBackToServiceName(t *testing.T) {
	tests := []struct {
		name string
		raw  string
	}{
		{"no JSON object at all", "this is not json"},
		{"the store_test.go fixture placeholder", "raw-1"},
		{"truncated JSON", `{"logdata": {"USERNAME": "root"`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := triedFor("ssh", tt.raw); got != "ssh" {
				t.Errorf("triedFor(ssh, %q) = %q, want the service name %q", tt.raw, got, "ssh")
			}
		})
	}
}

// --- ListVisitors: exercises the database.

// insertAlertRaw is store_test.go's insertFixtures loop, generalized so
// individual tests can control alerts.raw (needed here to exercise
// triedFor's JSON extraction end to end) and received_at per row.
func insertAlertRaw(t *testing.T, database *db.DB, instanceID, sourceIP string, destPort int, service, raw, receivedAt string) {
	t.Helper()
	_, err := database.Exec(
		`INSERT INTO alerts (instance_id, source_ip, dest_port, service, raw, received_at)
		 VALUES (?, ?, ?, ?, ?, ?)`,
		instanceID, sourceIP, destPort, service, raw, receivedAt,
	)
	if err != nil {
		t.Fatalf("insert alert: %v", err)
	}
}

// TestListVisitorsDataStoryClassification is issue #35's required
// end-to-end fixture: the round-6 data story's four named visitors, each
// built so only the rule its own kind depends on fires.
func TestListVisitorsDataStoryClassification(t *testing.T) {
	forEachEngine(t, func(t *testing.T, database *db.DB) {
		// Inserted in chronological order, oldest first: alertsInRange
		// orders by id DESC, and (per ListAlerts' own doc comment) id
		// order agrees with receipt order only when rows are inserted in
		// that order to begin with -- true of real ingestion, and true
		// here because the fixture is built that way on purpose.

		// repeat: 198.51.100.7 knocks canary-iot on 3 distinct UTC days.
		insertAlertRaw(t, database, "canary-iot", "198.51.100.7", 445, "smb", `{}`, "2026-09-07T10:19:10Z")
		insertAlertRaw(t, database, "canary-iot", "198.51.100.7", 445, "smb", `{}`, "2026-09-08T21:59:10Z")

		// touch: 192.0.2.88, one anonymous FTP login and nothing else.
		insertAlertRaw(t, database, "canary-srv", "192.0.2.88", 21, "ftp",
			`{"logdata": {"USERNAME": "anonymous", "PASSWORD": ""}}`, "2026-09-11T03:18:40Z")

		// inside: 10.0.40.23 (RFC 1918) browses canary-lan :80 -- its own
		// two hits, 18 seconds apart on the same canary, would otherwise
		// classify as neither sweep nor repeat, proving rule 1 alone puts
		// it in "inside" rather than falling through to "touch".
		insertAlertRaw(t, database, "canary-lan", "10.0.40.23", 80, "http",
			`{"logdata": {"PATH": "/"}}`, "2026-09-12T19:11:04Z")
		insertAlertRaw(t, database, "canary-lan", "10.0.40.23", 80, "http",
			`{"logdata": {"PATH": "/admin"}}`, "2026-09-12T19:11:22Z")

		// sweep: 203.0.113.42 touches two canaries within 15 minutes.
		insertAlertRaw(t, database, "canary-lan", "203.0.113.42", 22, "ssh",
			`{"logdata": {"USERNAME": "root", "PASSWORD": "root"}}`, "2026-09-12T21:55:40Z")
		insertAlertRaw(t, database, "canary-srv", "203.0.113.42", 3306, "mysql",
			`{"logdata": {"USERNAME": "root"}}`, "2026-09-12T21:57:22Z")

		// repeat's third distinct day, after the sweep visitor's hits.
		insertAlertRaw(t, database, "canary-iot", "198.51.100.7", 445, "smb", `{}`, "2026-09-12T21:59:10Z")

		now := mustParse(t, "2026-09-12T22:04:31Z")
		visitors, err := ListVisitors(context.Background(), database, now, VisitorFilter{
			Since: now.Add(-14 * 24 * time.Hour), Until: now,
		}, nil)
		if err != nil {
			t.Fatalf("ListVisitors: %v", err)
		}
		if len(visitors) != 4 {
			t.Fatalf("got %d visitors, want 4: %+v", len(visitors), visitors)
		}

		want := map[string]VisitorKind{
			"203.0.113.42": KindSweep,
			"198.51.100.7": KindRepeat,
			"10.0.40.23":   KindInside,
			"192.0.2.88":   KindTouch,
		}
		got := make(map[string]VisitorKind, len(visitors))
		for _, v := range visitors {
			got[v.SourceIP] = v.Kind
		}
		for ip, wantKind := range want {
			if got[ip] != wantKind {
				t.Errorf("visitor %s kind = %q, want %q", ip, got[ip], wantKind)
			}
		}

		// Newest last_at first: 198.51.100.7's third repeat day (21:59:10)
		// lands after the sweep visitor's own last hit (21:57:22).
		if visitors[0].SourceIP != "198.51.100.7" {
			t.Errorf("visitors[0] = %s, want 198.51.100.7 (newest last_at)", visitors[0].SourceIP)
		}
	})
}

func TestListVisitorsFields(t *testing.T) {
	forEachEngine(t, func(t *testing.T, database *db.DB) {
		insertAlertRaw(t, database, "canary-lan", "203.0.113.42", 22, "ssh",
			`{"logdata": {"USERNAME": "root", "PASSWORD": "toor"}}`, "2026-09-12T21:55:39Z")
		insertAlertRaw(t, database, "canary-lan", "203.0.113.42", 22, "ssh",
			`{"logdata": {"USERNAME": "root", "PASSWORD": "root"}}`, "2026-09-12T21:55:40Z")
		insertAlertRaw(t, database, "canary-srv", "203.0.113.42", 3306, "mysql",
			`{"logdata": {"USERNAME": "root", "PASSWORD": ""}}`, "2026-09-12T21:57:22Z")

		now := mustParse(t, "2026-09-12T22:00:00Z")
		visitors, err := ListVisitors(context.Background(), database, now, VisitorFilter{
			Since: now.Add(-time.Hour), Until: now,
		}, nil)
		if err != nil {
			t.Fatalf("ListVisitors: %v", err)
		}
		if len(visitors) != 1 {
			t.Fatalf("got %d visitors, want 1: %+v", len(visitors), visitors)
		}
		v := visitors[0]

		if v.Hits != 3 {
			t.Errorf("Hits = %d, want 3", v.Hits)
		}
		if !v.FirstAt.Equal(mustParse(t, "2026-09-12T21:55:39Z")) {
			t.Errorf("FirstAt = %v, want the oldest hit", v.FirstAt)
		}
		if !v.LastAt.Equal(mustParse(t, "2026-09-12T21:57:22Z")) {
			t.Errorf("LastAt = %v, want the newest hit", v.LastAt)
		}
		wantCanaries := []VisitorCanaryHits{{ID: "canary-lan", Hits: 2}, {ID: "canary-srv", Hits: 1}}
		if len(v.Canaries) != len(wantCanaries) || v.Canaries[0] != wantCanaries[0] || v.Canaries[1] != wantCanaries[1] {
			t.Errorf("Canaries = %+v, want %+v", v.Canaries, wantCanaries)
		}
		wantServices := []string{"mysql", "ssh"}
		if len(v.Services) != 2 || v.Services[0] != wantServices[0] || v.Services[1] != wantServices[1] {
			t.Errorf("Services = %v, want %v (sorted)", v.Services, wantServices)
		}
		// triedSummaries dedups in ascending time order: root/toor
		// (21:55:39) then root/root (21:55:40) then "root / (empty)"
		// (21:57:22, the empty mysql password).
		wantTried := []string{"root / toor", "root / root", "root / (empty)"}
		if len(v.Tried) != len(wantTried) {
			t.Fatalf("Tried = %v, want %v", v.Tried, wantTried)
		}
		for i := range wantTried {
			if v.Tried[i] != wantTried[i] {
				t.Errorf("Tried[%d] = %q, want %q (full: %v)", i, v.Tried[i], wantTried[i], v.Tried)
			}
		}
	})
}

func TestListVisitorsStillArrivingBoundary(t *testing.T) {
	forEachEngine(t, func(t *testing.T, database *db.DB) {
		insertAlertRaw(t, database, "canary-lan", "203.0.113.42", 22, "ssh", `{}`, "2026-09-12T22:00:00Z")

		// Exactly 5 minutes later: still arriving (inclusive threshold,
		// matching canary.go's own "ok" threshold convention).
		now := mustParse(t, "2026-09-12T22:05:00Z")
		visitors, err := ListVisitors(context.Background(), database, now, VisitorFilter{
			Since: now.Add(-time.Hour), Until: now,
		}, nil)
		if err != nil {
			t.Fatalf("ListVisitors: %v", err)
		}
		if !visitors[0].StillArriving {
			t.Error("StillArriving = false at exactly 5 minutes, want true")
		}

		// One second later: not still arriving.
		now2 := now.Add(time.Second)
		visitors2, err := ListVisitors(context.Background(), database, now2, VisitorFilter{
			Since: now2.Add(-time.Hour), Until: now2,
		}, nil)
		if err != nil {
			t.Fatalf("ListVisitors: %v", err)
		}
		if visitors2[0].StillArriving {
			t.Error("StillArriving = true past 5 minutes, want false")
		}
	})
}

func TestListVisitorsPagingBeforeAndLimit(t *testing.T) {
	forEachEngine(t, func(t *testing.T, database *db.DB) {
		ips := []string{"203.0.113.1", "203.0.113.2", "203.0.113.3", "203.0.113.4"}
		times := []string{"2026-09-12T10:00:00Z", "2026-09-12T11:00:00Z", "2026-09-12T12:00:00Z", "2026-09-12T13:00:00Z"}
		for i, ip := range ips {
			insertAlertRaw(t, database, "canary-lan", ip, 22, "ssh", `{}`, times[i])
		}

		now := mustParse(t, "2026-09-12T14:00:00Z")
		filter := VisitorFilter{Since: now.Add(-24 * time.Hour), Until: now, Limit: 2}
		page1, err := ListVisitors(context.Background(), database, now, filter, nil)
		if err != nil {
			t.Fatalf("ListVisitors page1: %v", err)
		}
		if len(page1) != 2 || page1[0].SourceIP != "203.0.113.4" || page1[1].SourceIP != "203.0.113.3" {
			t.Fatalf("page1 = %+v, want [203.0.113.4, 203.0.113.3] (newest last_at first)", page1)
		}

		filter.Before = page1[1].LastAt
		page2, err := ListVisitors(context.Background(), database, now, filter, nil)
		if err != nil {
			t.Fatalf("ListVisitors page2: %v", err)
		}
		if len(page2) != 2 || page2[0].SourceIP != "203.0.113.2" || page2[1].SourceIP != "203.0.113.1" {
			t.Fatalf("page2 = %+v, want [203.0.113.2, 203.0.113.1]", page2)
		}
	})
}

func TestNormalizeVisitorLimitDefaultAndCap(t *testing.T) {
	if got := NormalizeVisitorLimit(0); got != defaultVisitorLimit {
		t.Errorf("NormalizeVisitorLimit(0) = %d, want %d", got, defaultVisitorLimit)
	}
	if got := NormalizeVisitorLimit(-5); got != defaultVisitorLimit {
		t.Errorf("NormalizeVisitorLimit(-5) = %d, want %d", got, defaultVisitorLimit)
	}
	if got := NormalizeVisitorLimit(5000); got != maxVisitorLimit {
		t.Errorf("NormalizeVisitorLimit(5000) = %d, want %d", got, maxVisitorLimit)
	}
	if got := NormalizeVisitorLimit(50); got != 50 {
		t.Errorf("NormalizeVisitorLimit(50) = %d, want 50", got)
	}
}

// TestClassifyKindPoisonerIsAlwaysInside is #86 decision 34's ranking, and
// the reason it needs no fifth rise colour: LLMNR, NBT-NS and mDNS are
// link-local, so something that answered one of this canary's bait queries
// received a link-local multicast or a subnet broadcast -- which only a host
// on the segment can do. It is inside by definition, not by address.
func TestClassifyKindPoisonerIsAlwaysInside(t *testing.T) {
	at := time.Date(2026, 9, 24, 10, 0, 0, 0, time.UTC)

	tests := []struct {
		name     string
		sourceIP string
		hits     []hitPoint
		ranges   []*net.IPNet
	}{
		{
			name:     "a public source address, with no ranges configured",
			sourceIP: "203.0.113.9",
			hits:     []hitPoint{{At: at, CanaryID: "c1", Service: "poisoner"}},
		},
		{
			// The case that makes the rule matter: an operator whose LAN
			// uses public address space and who has not set
			// BIRDCAGE_INTERNAL_RANGES must not see the one near-certain
			// hit demoted to "one touch".
			name:     "a public source address, with unrelated ranges configured",
			sourceIP: "198.51.100.4",
			hits:     []hitPoint{{At: at, CanaryID: "c1", Service: "poisoner"}},
			ranges:   []*net.IPNet{mustCIDR(t, "203.0.113.0/24")},
		},
		{
			// Outranks sweep: five canaries inside the sweep window would
			// otherwise classify as a sweep.
			name:     "alongside enough hits to be a sweep",
			sourceIP: "203.0.113.9",
			hits: []hitPoint{
				{At: at, CanaryID: "c1", Service: "poisoner"},
				{At: at.Add(time.Minute), CanaryID: "c2", Service: "ssh"},
				{At: at.Add(2 * time.Minute), CanaryID: "c3", Service: "ssh"},
				{At: at.Add(3 * time.Minute), CanaryID: "c4", Service: "ssh"},
				{At: at.Add(4 * time.Minute), CanaryID: "c5", Service: "ssh"},
				{At: at.Add(5 * time.Minute), CanaryID: "c6", Service: "ssh"},
			},
		},
		{
			name:     "the poisoner hit is not the first one",
			sourceIP: "203.0.113.9",
			hits: []hitPoint{
				{At: at, CanaryID: "c1", Service: "ssh"},
				{At: at.Add(time.Minute), CanaryID: "c1", Service: "poisoner"},
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := classifyKind(tc.sourceIP, tc.hits, tc.ranges); got != KindInside {
				t.Errorf("classifyKind = %q, want %q", got, KindInside)
			}
		})
	}
}

// TestClassifyKindWithoutAPoisonerHitIsUnchanged proves the new rule only
// fires on a poisoner hit -- every other classification behaves exactly as
// issue #35 set it.
func TestClassifyKindWithoutAPoisonerHitIsUnchanged(t *testing.T) {
	at := time.Date(2026, 9, 24, 10, 0, 0, 0, time.UTC)

	// One hit from a public address, nothing else: still "one touch".
	if got := classifyKind("203.0.113.9", []hitPoint{{At: at, CanaryID: "c1", Service: "ssh"}}, nil); got != KindTouch {
		t.Errorf("a single public hit classified as %q, want %q", got, KindTouch)
	}
	// A hit with no service at all must not be mistaken for one.
	if got := classifyKind("203.0.113.9", []hitPoint{{At: at, CanaryID: "c1"}}, nil); got != KindTouch {
		t.Errorf("a hit with no service classified as %q, want %q", got, KindTouch)
	}
	// And a private source is inside as before, poisoner or not.
	if got := classifyKind("10.0.0.9", []hitPoint{{At: at, CanaryID: "c1", Service: "ssh"}}, nil); got != KindInside {
		t.Errorf("a private-address hit classified as %q, want %q", got, KindInside)
	}
}

// TestPoisonerServiceMatchesTheMapping pins this file's written-out service
// name to the one internal/opencanary actually derives from #86's logtype,
// so the two cannot drift apart silently.
func TestPoisonerServiceMatchesTheMapping(t *testing.T) {
	logType := 30001
	if got := opencanary.ServiceForLogType(&logType); got != poisonerService {
		t.Errorf("ServiceForLogType(30001) = %q, but this package classifies on %q", got, poisonerService)
	}
}
