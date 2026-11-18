package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/tomlawesome/birdcage/internal/db"
	"github.com/tomlawesome/birdcage/internal/store"
)

// Issue #213: GET /api/findings defaults to open+accepted, takes
// ?state=fixed|all, and caps the result with ?limit= (default 1000,
// clamped to 5000), saying so in "truncated" when it cut.

func getFindingsAt(t *testing.T, h http.Handler, query string) (int, findingsResponse) {
	t.Helper()
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/findings"+query, nil))
	var resp findingsResponse
	if rec.Code == http.StatusOK {
		if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
			t.Fatalf("decode response: %v; body=%.200s", err, rec.Body.String())
		}
	}
	return rec.Code, resp
}

func applyN(t *testing.T, database *db.DB, n int, at time.Time) {
	t.Helper()
	observed := make([]store.ObservedFinding, n)
	for i := range observed {
		observed[i] = store.ObservedFinding{Target: "deb:pkg", VulnerabilityID: fmt.Sprintf("CVE-%06d", i), Severity: "high"}
	}
	if err := store.ApplyFindingSnapshot(context.Background(), database, "scanner-a", observed, at); err != nil {
		t.Fatalf("ApplyFindingSnapshot: %v", err)
	}
}

func TestHandleFindingsStateFilter(t *testing.T) {
	database := openTempDB(t)
	ctx := context.Background()
	t1 := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	mk := func(id string) store.ObservedFinding {
		return store.ObservedFinding{Target: "deb:pkg", VulnerabilityID: id, Severity: "high"}
	}
	apply := func(at time.Time, ids ...string) {
		var o []store.ObservedFinding
		for _, id := range ids {
			o = append(o, mk(id))
		}
		if err := store.ApplyFindingSnapshot(ctx, database, "scanner-a", o, at); err != nil {
			t.Fatalf("ApplyFindingSnapshot: %v", err)
		}
	}
	apply(t1, "OPEN", "ACC", "GONE")
	if err := store.AcceptFinding(ctx, database, "scanner-a", "deb:pkg", "ACC", "tester", t1); err != nil {
		t.Fatalf("AcceptFinding: %v", err)
	}
	apply(t1.Add(time.Hour), "OPEN", "ACC") // GONE is fixed

	h := newHandler(database, time.Now, nil)
	ids := func(query string) map[string]store.FindingState {
		code, resp := getFindingsAt(t, h, query)
		if code != http.StatusOK {
			t.Fatalf("GET %s: status %d, want 200", query, code)
		}
		m := map[string]store.FindingState{}
		for _, f := range resp.Findings {
			m[f.VulnerabilityID] = f.State
		}
		return m
	}

	if got := ids(""); len(got) != 2 || got["OPEN"] != store.FindingOpen || got["ACC"] != store.FindingAccepted {
		t.Errorf("default = %v, want open and accepted only", got)
	}
	if got := ids("?state=fixed"); len(got) != 1 || got["GONE"] != store.FindingFixed {
		t.Errorf("?state=fixed = %v, want only GONE", got)
	}
	if got := ids("?state=all"); len(got) != 3 {
		t.Errorf("?state=all = %v, want all 3", got)
	}
}

func TestHandleFindingsLimitDefaultsAndClamps(t *testing.T) {
	database := openTempDB(t)
	applyN(t, database, 5100, time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC))
	h := newHandler(database, time.Now, nil)

	cases := []struct {
		query     string
		wantLen   int
		truncated bool
	}{
		{"", 1000, true},             // default limit
		{"?limit=10", 10, true},      // explicit
		{"?limit=5000", 5000, true},  // the maximum
		{"?limit=99999", 5000, true}, // clamped, not refused
		{"?limit=5100", 5000, true},  // still above the maximum
	}
	for _, c := range cases {
		code, resp := getFindingsAt(t, h, c.query)
		if code != http.StatusOK {
			t.Errorf("GET %q: status %d, want 200", c.query, code)
			continue
		}
		if len(resp.Findings) != c.wantLen {
			t.Errorf("GET %q: %d findings, want %d", c.query, len(resp.Findings), c.wantLen)
		}
		if resp.Truncated != c.truncated {
			t.Errorf("GET %q: truncated = %v, want %v", c.query, resp.Truncated, c.truncated)
		}
	}
}

func TestHandleFindingsNotTruncatedWhenEverythingFits(t *testing.T) {
	database := openTempDB(t)
	applyN(t, database, 50, time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC))
	h := newHandler(database, time.Now, nil)

	for _, q := range []string{"", "?limit=50", "?limit=100"} {
		code, resp := getFindingsAt(t, h, q)
		if code != http.StatusOK || len(resp.Findings) != 50 || resp.Truncated {
			t.Errorf("GET %q: status %d, %d findings, truncated=%v; want 200, 50, false", q, code, len(resp.Findings), resp.Truncated)
		}
	}
}
