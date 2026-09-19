package enrol

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/tomlawesome/birdcage/internal/db"
	"github.com/tomlawesome/birdcage/internal/store"
)

func provisionRequestBody(secret string) *bytes.Buffer {
	body, _ := json.Marshal(provisionRequest{EnrolmentSecret: secret})
	return bytes.NewBuffer(body)
}

// contactedSecret mints a session, first-contacts it, and returns the
// raw enrolment secret POST /enrol/provision consumes.
func contactedSecret(t *testing.T, database *db.DB, mintedAt, contactAt time.Time) string {
	t.Helper()
	raw, _, err := store.MintEnrolmentSession(context.Background(), database, "canary-a", "lane-a", mintedAt)
	if err != nil {
		t.Fatalf("MintEnrolmentSession: %v", err)
	}
	secret, _, outcome, err := store.FirstContact(context.Background(), database, store.HashToken(raw), contactAt)
	if err != nil {
		t.Fatalf("FirstContact: %v", err)
	}
	if outcome != store.Contacted {
		t.Fatalf("FirstContact outcome = %v, want Contacted", outcome)
	}
	return secret
}

// TestHandleProvisionSuccess is the happy path: a contacted session,
// presented within its window, gets 200 with a bearer token, a client
// certificate/key pair issued by the handler's own CA, and the default
// heartbeat interval -- and the canary row it created uses
// MockingbirdPorts, proving that constant and store's own private mirror
// haven't drifted apart.
func TestHandleProvisionSuccess(t *testing.T) {
	forEachEngine(t, func(t *testing.T, database *db.DB) {
		testCA := newTestCA(t)
		mintedAt := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
		contactAt := mintedAt.Add(time.Minute)
		secret := contactedSecret(t, database, mintedAt, contactAt)

		provisionAt := contactAt.Add(time.Minute)
		h := NewHandler(database, testCA, "", func() time.Time { return provisionAt }, nil)

		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/enrol/provision", provisionRequestBody(secret))
		h.ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200; body: %s", rec.Code, rec.Body.String())
		}
		var resp provisionResponse
		if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
			t.Fatalf("unmarshal response: %v; body: %s", err, rec.Body.String())
		}
		if resp.CanaryID == "" {
			t.Error("CanaryID is empty")
		}
		if resp.CanaryToken == "" {
			t.Error("CanaryToken is empty")
		}
		if resp.HeartbeatIntervalS != store.DefaultHeartbeatIntervalS {
			t.Errorf("HeartbeatIntervalS = %d, want %d", resp.HeartbeatIntervalS, store.DefaultHeartbeatIntervalS)
		}
		if !strings.Contains(resp.ClientCertPEM, "BEGIN CERTIFICATE") {
			t.Errorf("ClientCertPEM does not look like a PEM certificate: %q", resp.ClientCertPEM)
		}
		if !strings.Contains(resp.ClientKeyPEM, "PRIVATE KEY") {
			t.Errorf("ClientKeyPEM does not look like a PEM private key: %q", resp.ClientKeyPEM)
		}

		// The token birdcage's own ingest listener would authenticate is
		// live and resolves to the returned canary id.
		tok, err := store.LookupCanaryTokenByHash(context.Background(), database, store.HashToken(resp.CanaryToken))
		if err != nil {
			t.Fatalf("LookupCanaryTokenByHash: %v", err)
		}
		if tok.CanaryID != resp.CanaryID {
			t.Errorf("token CanaryID = %q, want %q", tok.CanaryID, resp.CanaryID)
		}

		var ports string
		row := database.QueryRow(`SELECT ports FROM canaries WHERE id = ?`, resp.CanaryID)
		if err := row.Scan(&ports); err != nil {
			t.Fatalf("scan canaries.ports: %v", err)
		}
		if ports != MockingbirdPorts {
			t.Errorf("canaries.ports = %q, want MockingbirdPorts = %q", ports, MockingbirdPorts)
		}

		// The secret cannot be provisioned a second time.
		rec2 := httptest.NewRecorder()
		h.ServeHTTP(rec2, httptest.NewRequest(http.MethodPost, "/enrol/provision", provisionRequestBody(secret)))
		if rec2.Code != http.StatusUnauthorized {
			t.Errorf("replay status = %d, want 401", rec2.Code)
		}
	})
}

// TestHandleProvisionRefusalsAreByteIdentical covers both refusal
// outcomes (unknown secret, window expired) and proves they produce the
// exact same response as each other and as POST /enrol/hello's own
// refusal -- design note decision 1's uniform-refusal rule extended to
// provisioning.
func TestHandleProvisionRefusalsAreByteIdentical(t *testing.T) {
	forEachEngine(t, func(t *testing.T, database *db.DB) {
		testCA := newTestCA(t)
		mintedAt := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

		// Unknown: a secret never minted at all.
		hUnknown := NewHandler(database, testCA, "", func() time.Time { return mintedAt }, nil)
		recUnknown := httptest.NewRecorder()
		hUnknown.ServeHTTP(recUnknown, httptest.NewRequest(http.MethodPost, "/enrol/provision", provisionRequestBody("never-minted")))

		// Window expired: contacted, then presented at its window_deadline.
		contactAt := mintedAt.Add(time.Minute)
		expiredSecret := contactedSecret(t, database, mintedAt, contactAt)
		windowDeadline := contactAt.Add(30 * time.Minute)
		hExpired := NewHandler(database, testCA, "", func() time.Time { return windowDeadline }, nil)
		recExpired := httptest.NewRecorder()
		hExpired.ServeHTTP(recExpired, httptest.NewRequest(http.MethodPost, "/enrol/provision", provisionRequestBody(expiredSecret)))

		for name, rec := range map[string]*httptest.ResponseRecorder{"unknown": recUnknown, "window expired": recExpired} {
			if rec.Code != http.StatusUnauthorized {
				t.Errorf("%s status = %d, want 401", name, rec.Code)
			}
		}
		wantBody := `{"error":"refused"}` + "\n"
		if recUnknown.Body.String() != wantBody {
			t.Errorf("unknown refusal body = %q, want %q", recUnknown.Body.String(), wantBody)
		}
		if recExpired.Body.String() != wantBody {
			t.Errorf("window-expired refusal body = %q, want %q", recExpired.Body.String(), wantBody)
		}
	})
}

// TestHandleProvisionMalformedBody mirrors TestHandleHelloMalformedBody:
// not JSON, oversized, and an unknown field are all 400s before
// store.Provision is ever called.
func TestHandleProvisionMalformedBody(t *testing.T) {
	forEachEngine(t, func(t *testing.T, database *db.DB) {
		testCA := newTestCA(t)
		h := NewHandler(database, testCA, "", nil, nil)

		t.Run("not JSON", func(t *testing.T) {
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/enrol/provision", strings.NewReader("not json at all")))
			if rec.Code != http.StatusBadRequest {
				t.Errorf("status = %d, want 400; body: %s", rec.Code, rec.Body.String())
			}
		})

		t.Run("oversized", func(t *testing.T) {
			big := `{"enrolment_secret":"` + strings.Repeat("a", maxProvisionBodyBytes*2) + `"}`
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/enrol/provision", strings.NewReader(big)))
			if rec.Code != http.StatusBadRequest {
				t.Errorf("status = %d, want 400; body: %s", rec.Code, rec.Body.String())
			}
		})

		t.Run("unknown field", func(t *testing.T) {
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/enrol/provision", strings.NewReader(`{"enrolment_secret":"x","extra":"y"}`)))
			if rec.Code != http.StatusBadRequest {
				t.Errorf("status = %d, want 400; body: %s", rec.Code, rec.Body.String())
			}
		})
	})
}
