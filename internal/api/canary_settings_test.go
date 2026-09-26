package api

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/tomlawesome/birdcage/internal/agentkind"
	"github.com/tomlawesome/birdcage/internal/audit"
	"github.com/tomlawesome/birdcage/internal/store"
)

func postSettings(t *testing.T, h http.Handler, id, body string) *httptest.ResponseRecorder {
	t.Helper()
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/canary/settings?id="+id, bytes.NewBufferString(body))
	h.ServeHTTP(rec, req)
	return rec
}

// TestHandleSetCanarySettingsWritesAndAudits proves issue #124's one
// write path: a valid body is stored, readable straight back through
// store.ListCanarySettings, and logged in audit_log with the key name
// but never the value.
func TestHandleSetCanarySettingsWritesAndAudits(t *testing.T) {
	database := openTempDB(t)
	insertCanary(t, database, store.Canary{ID: "canary-a", Name: "canary-a", Lane: "lan", HeartbeatIntervalS: 60, EnrolledAt: time.Now().UTC()})
	writeAt := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
	h := newHandler(database, fixedNow(writeAt), nil)

	rec := postSettings(t, h, "canary-a", `{"segment_profile":"linux"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}

	settings, err := store.ListCanarySettings(context.Background(), database, "canary-a")
	if err != nil {
		t.Fatalf("ListCanarySettings: %v", err)
	}
	if len(settings) != 1 || settings[0].Key != store.CanarySettingSegmentProfile || settings[0].Value != "linux" {
		t.Fatalf("ListCanarySettings = %+v, want one row (segment_profile=linux)", settings)
	}

	var entries []audit.Entry
	rows, err := database.Query(`SELECT action, target, reason, triggered_by FROM audit_log ORDER BY id DESC LIMIT 1`)
	if err != nil {
		t.Fatalf("query audit_log: %v", err)
	}
	defer rows.Close()
	for rows.Next() {
		var e audit.Entry
		if err := rows.Scan(&e.Action, &e.Target, &e.Reason, &e.TriggeredBy); err != nil {
			t.Fatalf("scan audit row: %v", err)
		}
		entries = append(entries, e)
	}
	if len(entries) != 1 {
		t.Fatalf("audit_log has %d matching rows, want 1", len(entries))
	}
	e := entries[0]
	if e.Action != "canary_settings.updated" || e.Target != "canary-a" || e.TriggeredBy != "dashboard" {
		t.Errorf("audit entry = %+v, unexpected", e)
	}
	if !contains(e.Reason, "segment_profile") {
		t.Errorf("audit reason %q does not name the changed key", e.Reason)
	}
}

func contains(haystack, needle string) bool {
	return len(haystack) >= len(needle) && (haystack == needle || len(needle) == 0 ||
		func() bool {
			for i := 0; i+len(needle) <= len(haystack); i++ {
				if haystack[i:i+len(needle)] == needle {
					return true
				}
			}
			return false
		}())
}

// TestHandleSetCanarySettingsAuditNeverCarriesABaitName proves the
// specific case the code comment calls out: writing bait_names must
// never put the value in the audit log, only the key name.
func TestHandleSetCanarySettingsAuditNeverCarriesABaitName(t *testing.T) {
	database := openTempDB(t)
	insertCanary(t, database, store.Canary{ID: "canary-a", Name: "canary-a", Lane: "lan", HeartbeatIntervalS: 60, EnrolledAt: time.Now().UTC()})
	h := newHandler(database, fixedNow(time.Now().UTC()), nil)

	secretName := "secret-fs-01"
	rec := postSettings(t, h, "canary-a", `{"bait_names":"`+secretName+`"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}

	var reason string
	row := database.QueryRow(`SELECT reason FROM audit_log ORDER BY id DESC LIMIT 1`)
	if err := row.Scan(&reason); err != nil {
		t.Fatalf("scan audit reason: %v", err)
	}
	if contains(reason, secretName) {
		t.Fatalf("audit reason %q leaks the bait name", reason)
	}
	if !contains(reason, "bait_names") {
		t.Errorf("audit reason %q does not name the changed key", reason)
	}
}

func TestHandleSetCanarySettingsUnknownCanary(t *testing.T) {
	database := openTempDB(t)
	h := newHandler(database, fixedNow(time.Now().UTC()), nil)

	rec := postSettings(t, h, "does-not-exist", `{"segment_profile":"off"}`)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404; body=%s", rec.Code, rec.Body.String())
	}
}

func TestHandleSetCanarySettingsRejectsUnknownKeyAndWritesNothing(t *testing.T) {
	database := openTempDB(t)
	insertCanary(t, database, store.Canary{ID: "canary-a", Name: "canary-a", Lane: "lan", HeartbeatIntervalS: 60, EnrolledAt: time.Now().UTC()})
	h := newHandler(database, fixedNow(time.Now().UTC()), nil)

	rec := postSettings(t, h, "canary-a", `{"not_a_real_setting":"x"}`)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", rec.Code, rec.Body.String())
	}
	settings, err := store.ListCanarySettings(context.Background(), database, "canary-a")
	if err != nil {
		t.Fatalf("ListCanarySettings: %v", err)
	}
	if len(settings) != 0 {
		t.Fatalf("ListCanarySettings after a rejected write = %v, want empty", settings)
	}
}

func TestHandleSetCanarySettingsRejectsInvalidValue(t *testing.T) {
	database := openTempDB(t)
	insertCanary(t, database, store.Canary{ID: "canary-a", Name: "canary-a", Lane: "lan", HeartbeatIntervalS: 60, EnrolledAt: time.Now().UTC()})
	h := newHandler(database, fixedNow(time.Now().UTC()), nil)

	rec := postSettings(t, h, "canary-a", `{"segment_profile":"not-a-profile"}`)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", rec.Code, rec.Body.String())
	}
}

// TestHandleSetCanarySettingsRejectsWrongKind proves segment_profile
// (honeypot-only) is refused for a scanner, the same "only the honeypot
// has lures" rule cmd/birdcage's own enrol command applies to --lure.
func TestHandleSetCanarySettingsRejectsWrongKind(t *testing.T) {
	database := openTempDB(t)
	insertCanary(t, database, store.Canary{ID: "scanner-a", Name: "scanner-a", Lane: "lan", Kind: agentkind.Scanner, HeartbeatIntervalS: 60, EnrolledAt: time.Now().UTC()})
	h := newHandler(database, fixedNow(time.Now().UTC()), nil)

	rec := postSettings(t, h, "scanner-a", `{"segment_profile":"windows"}`)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", rec.Code, rec.Body.String())
	}
}

func TestHandleSetCanarySettingsRejectsEmptyBody(t *testing.T) {
	database := openTempDB(t)
	insertCanary(t, database, store.Canary{ID: "canary-a", Name: "canary-a", Lane: "lan", HeartbeatIntervalS: 60, EnrolledAt: time.Now().UTC()})
	h := newHandler(database, fixedNow(time.Now().UTC()), nil)

	rec := postSettings(t, h, "canary-a", `{}`)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", rec.Code, rec.Body.String())
	}
}

func TestHandleSetCanarySettingsMissingID(t *testing.T) {
	database := openTempDB(t)
	h := newHandler(database, fixedNow(time.Now().UTC()), nil)

	rec := postSettings(t, h, "", `{"segment_profile":"off"}`)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", rec.Code, rec.Body.String())
	}
}
