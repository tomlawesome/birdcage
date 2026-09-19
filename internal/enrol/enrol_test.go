package enrol

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/tomlawesome/birdcage/internal/ca"
	"github.com/tomlawesome/birdcage/internal/db"
	"github.com/tomlawesome/birdcage/internal/db/dbtest"
	"github.com/tomlawesome/birdcage/internal/store"
)

// forEachEngine mirrors internal/store's and internal/ingest's own
// helper of the same name: every test that touches the database runs
// once per engine dbtest.Targets returns.
func forEachEngine(t *testing.T, fn func(t *testing.T, database *db.DB)) {
	t.Helper()
	for _, tgt := range dbtest.Targets(t) {
		tgt := tgt
		t.Run(tgt.Name, func(t *testing.T) {
			fn(t, tgt.DB)
		})
	}
}

// newTestCA mirrors internal/ingest/tlsserver_test.go's own helper: a
// fresh internal/ca.CA in a throwaway 0700 directory.
func newTestCA(t *testing.T) *ca.CA {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "ca")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatalf("mkdir CA dir: %v", err)
	}
	c, _, err := ca.Load(dir, nil)
	if err != nil {
		t.Fatalf("ca.Load: %v", err)
	}
	return c
}

func setAddresses(t *testing.T, database *db.DB) {
	t.Helper()
	ctx := context.Background()
	if err := store.SetSetting(ctx, database, store.SettingAdminApprovalAddress, "ops@example.com", time.Now().UTC()); err != nil {
		t.Fatalf("SetSetting(admin_approval_address): %v", err)
	}
	if err := store.SetSetting(ctx, database, store.SettingReleaseAddress, "#releases", time.Now().UTC()); err != nil {
		t.Fatalf("SetSetting(release_address): %v", err)
	}
}

func helloRequestBody(token string) *bytes.Buffer {
	body, _ := json.Marshal(helloRequest{Token: token})
	return bytes.NewBuffer(body)
}

// TestHandleHelloContactedReturnsSecretAndCAAndAddresses is the success
// path: a freshly minted, never-contacted session presented before its
// deadline gets 200 with everything "The flow" step 3 promises.
func TestHandleHelloContactedReturnsSecretAndCAAndAddresses(t *testing.T) {
	forEachEngine(t, func(t *testing.T, database *db.DB) {
		setAddresses(t, database)
		testCA := newTestCA(t)

		mintedAt := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
		raw, _, err := store.MintEnrolmentSession(context.Background(), database, mintedAt)
		if err != nil {
			t.Fatalf("MintEnrolmentSession: %v", err)
		}

		now := mintedAt.Add(1 * time.Minute)
		h := NewHandler(database, testCA, func() time.Time { return now }, nil)

		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/enrol/hello", helloRequestBody(raw))
		h.ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200; body: %s", rec.Code, rec.Body.String())
		}
		var resp helloResponse
		if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
			t.Fatalf("unmarshal response: %v; body: %s", err, rec.Body.String())
		}
		if resp.EnrolmentSecret == "" {
			t.Error("EnrolmentSecret is empty")
		}
		if resp.CAPEM != string(testCA.CertPEM()) {
			t.Error("CAPEM does not match the handler's CA certificate")
		}
		wantWindow := now.Add(30 * time.Minute).Format(time.RFC3339)
		if resp.WindowDeadline != wantWindow {
			t.Errorf("WindowDeadline = %q, want %q", resp.WindowDeadline, wantWindow)
		}
		if resp.AdminApprovalAddress != "ops@example.com" {
			t.Errorf("AdminApprovalAddress = %q, want %q", resp.AdminApprovalAddress, "ops@example.com")
		}
		if resp.ReleaseAddress != "#releases" {
			t.Errorf("ReleaseAddress = %q, want %q", resp.ReleaseAddress, "#releases")
		}

		// The presented token cannot be reused for a second secret.
		rec2 := httptest.NewRecorder()
		req2 := httptest.NewRequest(http.MethodPost, "/enrol/hello", helloRequestBody(raw))
		h.ServeHTTP(rec2, req2)
		if rec2.Code != http.StatusUnauthorized {
			t.Errorf("second call status = %d, want 401", rec2.Code)
		}
	})
}

// TestHandleHelloRefusalsAreByteIdentical is design note decision 1's
// "nothing distinguishes them to the caller": an unknown token, an
// expired token and a reused (burned) token must all produce the exact
// same status and body.
func TestHandleHelloRefusalsAreByteIdentical(t *testing.T) {
	forEachEngine(t, func(t *testing.T, database *db.DB) {
		setAddresses(t, database)
		testCA := newTestCA(t)

		mintedAt := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

		// Unknown: a token never minted at all.
		hUnknown := NewHandler(database, testCA, func() time.Time { return mintedAt }, nil)
		recUnknown := httptest.NewRecorder()
		hUnknown.ServeHTTP(recUnknown, httptest.NewRequest(http.MethodPost, "/enrol/hello", helloRequestBody("never-minted")))

		// Expired: minted, never contacted, presented after its deadline.
		expiredRaw, _, err := store.MintEnrolmentSession(context.Background(), database, mintedAt)
		if err != nil {
			t.Fatalf("MintEnrolmentSession (expired fixture): %v", err)
		}
		afterDeadline := mintedAt.Add(10 * time.Minute)
		hExpired := NewHandler(database, testCA, func() time.Time { return afterDeadline }, nil)
		recExpired := httptest.NewRecorder()
		hExpired.ServeHTTP(recExpired, httptest.NewRequest(http.MethodPost, "/enrol/hello", helloRequestBody(expiredRaw)))

		// Reused: minted, contacted once, presented a second time.
		reusedRaw, _, err := store.MintEnrolmentSession(context.Background(), database, mintedAt)
		if err != nil {
			t.Fatalf("MintEnrolmentSession (reused fixture): %v", err)
		}
		contactAt := mintedAt.Add(1 * time.Minute)
		hFirst := NewHandler(database, testCA, func() time.Time { return contactAt }, nil)
		hFirst.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodPost, "/enrol/hello", helloRequestBody(reusedRaw)))
		recReused := httptest.NewRecorder()
		hFirst.ServeHTTP(recReused, httptest.NewRequest(http.MethodPost, "/enrol/hello", helloRequestBody(reusedRaw)))

		for name, rec := range map[string]*httptest.ResponseRecorder{
			"unknown": recUnknown, "expired": recExpired, "reused": recReused,
		} {
			if rec.Code != http.StatusUnauthorized {
				t.Errorf("%s status = %d, want 401", name, rec.Code)
			}
		}
		if recUnknown.Code != recExpired.Code || recExpired.Code != recReused.Code {
			t.Fatal("refusal status codes are not identical")
		}
		if !bytes.Equal(recUnknown.Body.Bytes(), recExpired.Body.Bytes()) || !bytes.Equal(recExpired.Body.Bytes(), recReused.Body.Bytes()) {
			t.Fatalf("refusal bodies are not byte-identical: unknown=%q expired=%q reused=%q",
				recUnknown.Body.String(), recExpired.Body.String(), recReused.Body.String())
		}
		wantBody := `{"error":"refused"}` + "\n"
		if recUnknown.Body.String() != wantBody {
			t.Errorf("refusal body = %q, want %q", recUnknown.Body.String(), wantBody)
		}
	})
}

// TestHandleHelloReusedWritesAuditEntryNamingSessionNeverToken is design
// note decision 1's "a second /enrol/hello with a burned token: uniform
// refusal plus an audit entry enrolment.deploy_token_reuse" -- proving
// the entry exists, names the session id, and never contains the raw
// token anywhere in its fields.
func TestHandleHelloReusedWritesAuditEntryNamingSessionNeverToken(t *testing.T) {
	forEachEngine(t, func(t *testing.T, database *db.DB) {
		setAddresses(t, database)
		testCA := newTestCA(t)

		mintedAt := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
		raw, minted, err := store.MintEnrolmentSession(context.Background(), database, mintedAt)
		if err != nil {
			t.Fatalf("MintEnrolmentSession: %v", err)
		}

		contactAt := mintedAt.Add(1 * time.Minute)
		h := NewHandler(database, testCA, func() time.Time { return contactAt }, nil)
		h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodPost, "/enrol/hello", helloRequestBody(raw)))
		h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodPost, "/enrol/hello", helloRequestBody(raw)))

		rows, err := database.Query(`SELECT action, target, reason, triggered_by FROM audit_log WHERE action = 'enrolment.deploy_token_reuse'`)
		if err != nil {
			t.Fatalf("query audit_log: %v", err)
		}
		defer func() { _ = rows.Close() }()

		var found int
		for rows.Next() {
			var action, target, reason, triggeredBy string
			if err := rows.Scan(&action, &target, &reason, &triggeredBy); err != nil {
				t.Fatalf("scan audit_log row: %v", err)
			}
			found++
			if target != minted.ID {
				t.Errorf("target = %q, want session id %q", target, minted.ID)
			}
			for _, field := range []string{action, target, reason, triggeredBy} {
				if strings.Contains(field, raw) {
					t.Errorf("audit row field %q contains the raw deploy token", field)
				}
			}
		}
		if found != 1 {
			t.Fatalf("found %d enrolment.deploy_token_reuse audit rows, want 1", found)
		}
	})
}

// TestHandleHelloMalformedBody covers the two ways a request body can be
// rejected before it ever reaches store.FirstContact: not JSON, and over
// the 1 KiB cap. Both are 400s, distinct from the token-outcome 401s
// above.
func TestHandleHelloMalformedBody(t *testing.T) {
	forEachEngine(t, func(t *testing.T, database *db.DB) {
		testCA := newTestCA(t)
		h := NewHandler(database, testCA, nil, nil)

		t.Run("not JSON", func(t *testing.T) {
			rec := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodPost, "/enrol/hello", strings.NewReader("not json at all"))
			h.ServeHTTP(rec, req)
			if rec.Code != http.StatusBadRequest {
				t.Errorf("status = %d, want 400; body: %s", rec.Code, rec.Body.String())
			}
		})

		t.Run("oversized", func(t *testing.T) {
			big := `{"token":"` + strings.Repeat("a", maxHelloBodyBytes*2) + `"}`
			rec := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodPost, "/enrol/hello", strings.NewReader(big))
			h.ServeHTTP(rec, req)
			if rec.Code != http.StatusBadRequest {
				t.Errorf("status = %d, want 400; body: %s", rec.Code, rec.Body.String())
			}
		})

		t.Run("unknown field", func(t *testing.T) {
			rec := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodPost, "/enrol/hello", strings.NewReader(`{"token":"x","extra":"y"}`))
			h.ServeHTTP(rec, req)
			if rec.Code != http.StatusBadRequest {
				t.Errorf("status = %d, want 400; body: %s", rec.Code, rec.Body.String())
			}
		})
	})
}

// TestHandleHelloServesOnlyPostEnrolHello proves the mux's isolation:
// every other method and path gets a 404/405, never a dashboard or
// ingest route (there are none registered here to reach).
func TestHandleHelloServesOnlyPostEnrolHello(t *testing.T) {
	forEachEngine(t, func(t *testing.T, database *db.DB) {
		testCA := newTestCA(t)
		h := NewHandler(database, testCA, nil, nil)

		// A GET to the same path falls through to the "/" catch-all
		// (notFoundJSON) rather than a 405, matching internal/ingest's
		// own mux -- there is no other registered pattern for
		// /enrol/hello to disambiguate a method mismatch against.
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/enrol/hello", nil))
		if rec.Code != http.StatusNotFound {
			t.Errorf("GET /enrol/hello status = %d, want 404", rec.Code)
		}

		rec2 := httptest.NewRecorder()
		h.ServeHTTP(rec2, httptest.NewRequest(http.MethodGet, "/api/alerts", nil))
		if rec2.Code != http.StatusNotFound {
			t.Errorf("GET /api/alerts status = %d, want 404", rec2.Code)
		}
	})
}
