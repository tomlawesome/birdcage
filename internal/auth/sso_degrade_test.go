package auth_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/tomlawesome/birdcage/internal/auth"
)

const ssoTestPublicURL = "https://birdcage.example.net"

// ssoSessionAvailable serves svc the way startSystem does and reports the
// ssoAvailable flag of GET /api/auth/session.
func ssoSessionAvailable(t *testing.T, svc *auth.Service) bool {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	})
	server := httptest.NewServer(svc.Wrap(mux))
	t.Cleanup(server.Close)
	status, body := call(t, newClient(t), http.MethodGet, server.URL+"/api/auth/session", nil, nil)
	if status != http.StatusOK {
		t.Fatalf("GET /api/auth/session = %d %s, want 200", status, body)
	}
	var s struct {
		SSOAvailable bool `json:"ssoAvailable"`
	}
	if err := json.Unmarshal(body, &s); err != nil {
		t.Fatalf("decode session %q: %v", body, err)
	}
	return s.SSOAvailable
}

// TestOpenStartsWithoutSSOWhenIssuerUnreachable reproduces audit finding
// A-R1: with SSO configured and the identity provider not answering, Open
// must degrade (start without SSO, log it) rather than refuse to start.
func TestOpenStartsWithoutSSOWhenIssuerUnreachable(t *testing.T) {
	database := openDatabase(t)
	issuer := closedIssuerURL(t)
	logger, capture := newLogCapture()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	svc, err := auth.Open(ctx, database, auth.Config{
		Key:              testKey('b'),
		PublicURL:        ssoTestPublicURL,
		OIDCIssuer:       issuer,
		OIDCClientID:     "birdcage-test-client",
		OIDCClientSecret: "fake-client-secret-for-tests",
	}, logger)
	if err != nil {
		t.Fatalf("auth.Open with an unreachable SSO issuer = %v, want nil (start without SSO)", err)
	}
	svc.ReleaseCodes()
	t.Cleanup(svc.Close)

	if ssoSessionAvailable(t, svc) {
		t.Error("ssoAvailable = true with an unreachable issuer, want false")
	}
	found := false
	for _, line := range capture.all() {
		if strings.Contains(line, "SSO") && strings.Contains(line, issuer) {
			found = true
		}
	}
	if !found {
		t.Errorf("no log line naming SSO and %s; log = %q", issuer, capture.all())
	}
	if codes := capture.setupCodes(); len(codes) != 1 {
		t.Errorf("setup codes logged = %v, want exactly one", codes)
	}
}

// TestOpenWiresSSOWhenIssuerAnswers is the legitimate path: a reachable
// provider gives SSO. It guards the degrade path from being over-applied.
func TestOpenWiresSSOWhenIssuerAnswers(t *testing.T) {
	var issuer string
	provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/.well-known/openid-configuration" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"issuer":                                issuer,
			"authorization_endpoint":                issuer + "/auth",
			"token_endpoint":                        issuer + "/token",
			"jwks_uri":                              issuer + "/keys",
			"response_types_supported":              []string{"code"},
			"subject_types_supported":               []string{"public"},
			"id_token_signing_alg_values_supported": []string{"RS256"},
		})
	}))
	t.Cleanup(provider.Close)
	issuer = provider.URL

	database := openDatabase(t)
	logger, _ := newLogCapture()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	svc, err := auth.Open(ctx, database, auth.Config{
		Key:              testKey('c'),
		PublicURL:        ssoTestPublicURL,
		OIDCIssuer:       issuer,
		OIDCClientID:     "birdcage-test-client",
		OIDCClientSecret: "fake-client-secret-for-tests",
	}, logger)
	if err != nil {
		t.Fatalf("auth.Open with a reachable SSO issuer: %v", err)
	}
	t.Cleanup(svc.Close)
	if !ssoSessionAvailable(t, svc) {
		t.Error("ssoAvailable = false with a reachable issuer, want true")
	}
}

// TestOpenRefusesSharedIssuer pins the split between configuration and
// reachability: a shared issuer without a tenant pin still refuses to start.
func TestOpenRefusesSharedIssuer(t *testing.T) {
	database := openDatabase(t)
	logger, _ := newLogCapture()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	svc, err := auth.Open(ctx, database, auth.Config{
		Key:              testKey('d'),
		PublicURL:        ssoTestPublicURL,
		OIDCIssuer:       "https://accounts.google.com",
		OIDCClientID:     "birdcage-test-client",
		OIDCClientSecret: "fake-client-secret-for-tests",
	}, logger)
	if err == nil {
		svc.Close()
		t.Fatal("auth.Open with a shared issuer = nil error, want a refusal")
	}
	if !strings.Contains(err.Error(), "SSO") {
		t.Errorf("error %q does not mention SSO", err)
	}
}
