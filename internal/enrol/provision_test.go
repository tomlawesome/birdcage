package enrol

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/tomlawesome/birdcage/internal/agentkind"
	"github.com/tomlawesome/birdcage/internal/db"
	"github.com/tomlawesome/birdcage/internal/store"
)

// newCSRPEM builds what an agent sends (ADR-0012 B1): a CSR over a
// fresh ECDSA P-256 key it keeps. Returns the key too, for tests that
// check the certificate pairs with it.
func newCSRPEM(t *testing.T, subject pkix.Name) (string, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: subject}, key)
	if err != nil {
		t.Fatalf("CreateCertificateRequest: %v", err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der})), key
}

// validCSR is one well-formed CSR, shared by the tests that only need
// the request to get past the CSR check.
var (
	validCSROnce sync.Once
	validCSRPEM  string
)

func provisionRequestBody(secret string) *bytes.Buffer {
	validCSROnce.Do(func() {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			panic(err)
		}
		der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, key)
		if err != nil {
			panic(err)
		}
		validCSRPEM = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}))
	})
	return provisionRequestBodyWithCSR(secret, validCSRPEM)
}

func provisionRequestBodyWithCSR(secret, csrPEM string) *bytes.Buffer {
	body, _ := json.Marshal(provisionRequest{EnrolmentSecret: secret, CSRPEM: csrPEM})
	return bytes.NewBuffer(body)
}

// contactedSecret mints a session, first-contacts it, and returns the
// raw enrolment secret POST /enrol/provision consumes.
func contactedSecret(t *testing.T, database *db.DB, mintedAt, contactAt time.Time) string {
	t.Helper()
	raw, _, err := store.MintEnrolmentSession(context.Background(), database, "canary-a", "lane-a", agentkind.Honeypot, mintedAt)
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
// heartbeat interval -- and the canary row it created uses the honeypot
// kind's agentkind.Profile.Ports, the one place that port list now lives
// (issue #105 deleted the two constants this test used to compare
// against each other).
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

		// The token birdcage's own ingest listener would authenticate is
		// live and resolves to the returned canary id.
		tok, err := store.LookupCanaryTokenByHash(context.Background(), database, store.HashToken(resp.CanaryToken))
		if err != nil {
			t.Fatalf("LookupCanaryTokenByHash: %v", err)
		}
		if tok.CanaryID != resp.CanaryID {
			t.Errorf("token CanaryID = %q, want %q", tok.CanaryID, resp.CanaryID)
		}

		honeypotProfile, ok := agentkind.Lookup(agentkind.Honeypot)
		if !ok {
			t.Fatal("agentkind.Lookup(Honeypot) ok = false")
		}
		var kind, ports string
		row := database.QueryRow(`SELECT kind, ports FROM canaries WHERE id = ?`, resp.CanaryID)
		if err := row.Scan(&kind, &ports); err != nil {
			t.Fatalf("scan canaries.kind/ports: %v", err)
		}
		if kind != string(agentkind.Honeypot) {
			t.Errorf("canaries.kind = %q, want %q", kind, agentkind.Honeypot)
		}
		if ports != honeypotProfile.Ports {
			t.Errorf("canaries.ports = %q, want the honeypot profile's %q", ports, honeypotProfile.Ports)
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

// TestHandleProvisionSignsTheAgentsKeyAndReturnsNoKey is ADR-0012 B1 at
// the wire: the response has no private key in it at all, the
// certificate is over the CSR's key (so it pairs with the key the agent
// kept), and the subject is the registry's -- the server-minted id and
// the session's kind -- whatever the CSR asked for.
func TestHandleProvisionSignsTheAgentsKeyAndReturnsNoKey(t *testing.T) {
	forEachEngine(t, func(t *testing.T, database *db.DB) {
		testCA := newTestCA(t)
		mintedAt := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
		secret := contactedSecret(t, database, mintedAt, mintedAt.Add(time.Minute))
		h := NewHandler(database, testCA, "", func() time.Time { return mintedAt.Add(2 * time.Minute) }, nil)

		csrPEM, key := newCSRPEM(t, pkix.Name{CommonName: "someone-elses-id", OrganizationalUnit: []string{string(agentkind.Scanner)}})
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/enrol/provision", provisionRequestBodyWithCSR(secret, csrPEM)))
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200; body: %s", rec.Code, rec.Body.String())
		}

		var raw map[string]any
		if err := json.Unmarshal(rec.Body.Bytes(), &raw); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		if _, ok := raw["client_key_pem"]; ok {
			t.Error("response still carries client_key_pem")
		}
		if strings.Contains(rec.Body.String(), "PRIVATE KEY") {
			t.Error("response body contains a private key")
		}
		want := map[string]bool{"canary_id": true, "canary_token": true, "client_cert_pem": true, "heartbeat_interval_s": true}
		for k := range raw {
			if !want[k] {
				t.Errorf("unexpected response field %q", k)
			}
		}

		var resp provisionResponse
		if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		keyDER, err := x509.MarshalECPrivateKey(key)
		if err != nil {
			t.Fatalf("marshal key: %v", err)
		}
		pair, err := tls.X509KeyPair([]byte(resp.ClientCertPEM), pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}))
		if err != nil {
			t.Fatalf("certificate does not pair with the agent's own key: %v", err)
		}
		leaf, err := x509.ParseCertificate(pair.Certificate[0])
		if err != nil {
			t.Fatalf("parse leaf: %v", err)
		}
		if leaf.Subject.CommonName != resp.CanaryID {
			t.Errorf("CN = %q, want the server-minted id %q", leaf.Subject.CommonName, resp.CanaryID)
		}
		if ou := leaf.Subject.OrganizationalUnit; len(ou) != 1 || ou[0] != string(agentkind.Honeypot) {
			t.Errorf("OU = %v, want exactly the session's kind [honeypot]", ou)
		}
		if got := leaf.NotAfter.Sub(leaf.NotBefore); got < ClientCertTTL || got > ClientCertTTL+10*time.Minute {
			t.Errorf("validity = %s, want about %s", got, ClientCertTTL)
		}

		// Recorded, and the token is bound to it.
		fp := store.CertFingerprint(leaf.Raw)
		if _, err := store.LookupClientCertByFingerprint(context.Background(), database, fp); err != nil {
			t.Errorf("issued certificate not recorded: %v", err)
		}
		tok, err := store.LookupCanaryTokenByHash(context.Background(), database, store.HashToken(resp.CanaryToken))
		if err != nil {
			t.Fatalf("LookupCanaryTokenByHash: %v", err)
		}
		if tok.CertFingerprint != fp {
			t.Errorf("token bound to %q, want the issued certificate %q", tok.CertFingerprint, fp)
		}
	})
}

// TestHandleProvisionBadCSRIsRetryable: every refused CSR is a 400 that
// spends nothing -- the same secret with a good CSR afterwards still
// provisions. Fails if the CSR check moves after the secret is spent.
func TestHandleProvisionBadCSRIsRetryable(t *testing.T) {
	forEachEngine(t, func(t *testing.T, database *db.DB) {
		testCA := newTestCA(t)
		mintedAt := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
		secret := contactedSecret(t, database, mintedAt, mintedAt.Add(time.Minute))
		h := NewHandler(database, testCA, "", func() time.Time { return mintedAt.Add(2 * time.Minute) }, nil)

		p384, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
		if err != nil {
			t.Fatalf("generate P-384 key: %v", err)
		}
		der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, p384)
		if err != nil {
			t.Fatalf("CreateCertificateRequest: %v", err)
		}
		wrongCurve := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}))

		bad := map[string]string{
			"missing":     "",
			"not PEM":     "hello",
			"wrong curve": wrongCurve,
			"certificate": string(testCA.CertPEM()),
		}
		for name, csr := range bad {
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/enrol/provision", provisionRequestBodyWithCSR(secret, csr)))
			if rec.Code != http.StatusBadRequest {
				t.Errorf("%s: status = %d, want 400; body: %s", name, rec.Code, rec.Body.String())
			}
			if strings.Contains(rec.Body.String(), secret) {
				t.Errorf("%s: error body echoes the secret", name)
			}
		}

		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/enrol/provision", provisionRequestBody(secret)))
		if rec.Code != http.StatusOK {
			t.Fatalf("good CSR after bad ones: status = %d, want 200; body: %s", rec.Code, rec.Body.String())
		}
	})
}
