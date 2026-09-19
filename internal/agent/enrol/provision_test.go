package enrol

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

// certPEMOf PEM-encodes ts's own leaf certificate, for a stock-verification
// caller (Provision) to trust exactly it -- the same shape
// internal/agent/client's own tests use.
func certPEMOf(t *testing.T, ts *httptest.Server) []byte {
	t.Helper()
	cert := ts.Certificate()
	if cert == nil {
		t.Fatal("test server has no certificate")
	}
	return pemCert(cert.Raw)
}

// TestProvisionHappyPath proves the success path decodes every field.
func TestProvisionHappyPath(t *testing.T) {
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/enrol/provision" {
			t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
		}
		var req wireProvisionRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Errorf("decode request: %v", err)
		}
		if req.EnrolmentSecret != "secret-abc" {
			t.Errorf("EnrolmentSecret = %q, want %q", req.EnrolmentSecret, "secret-abc")
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(wireProvisionResponse{
			CanaryID:           "canary-1",
			CanaryToken:        "raw-token",
			ClientCertPEM:      "PLACEHOLDER-CLIENT-CERT-PEM-CONTENT",
			ClientKeyPEM:       "PLACEHOLDER-CLIENT-KEY-PEM-CONTENT",
			HeartbeatIntervalS: 30,
		})
	}))
	defer ts.Close()

	creds, err := Provision(ctx(), ts.URL, certPEMOf(t, ts), "secret-abc")
	if err != nil {
		t.Fatalf("Provision: %v", err)
	}
	if creds.CanaryID != "canary-1" {
		t.Errorf("CanaryID = %q", creds.CanaryID)
	}
	if creds.CanaryToken != "raw-token" {
		t.Errorf("CanaryToken = %q", creds.CanaryToken)
	}
	if creds.HeartbeatIntervalS != 30 {
		t.Errorf("HeartbeatIntervalS = %d", creds.HeartbeatIntervalS)
	}
}

// TestProvisionRefused401IsTypedErrRefused mirrors hello's own case (e)
// for the provisioning route.
func TestProvisionRefused401IsTypedErrRefused(t *testing.T) {
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"error":"refused"}`))
	}))
	defer ts.Close()

	_, err := Provision(ctx(), ts.URL, certPEMOf(t, ts), "secret-abc")
	if !errors.Is(err, ErrRefused) {
		t.Fatalf("err = %v, want ErrRefused", err)
	}
}

// TestProvisionRejectsUntrustedServer proves stock verification is real:
// a server whose certificate does not chain to caPEM must be refused.
func TestProvisionRejectsUntrustedServer(t *testing.T) {
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("handler reached; Provision should have refused the connection before sending a request")
	}))
	defer ts.Close()

	unrelatedDER, _, _ := genCA(t, "unrelated-ca")

	_, err := Provision(ctx(), ts.URL, pemCert(unrelatedDER), "secret-abc")
	if err == nil {
		t.Fatal("Provision succeeded against a server whose certificate does not chain to caPEM")
	}
}
