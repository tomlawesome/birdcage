package ingest

import (
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/tomlawesome/birdcage/internal/ca"
	"github.com/tomlawesome/birdcage/internal/db"
)

// clientCertificate mints a client cert/key pair for canaryID via
// testCA.IssueClient and parses it into a tls.Certificate an
// http.Client's TLSClientConfig can present.
func clientCertificate(t *testing.T, testCA *ca.CA, canaryID string) tls.Certificate {
	t.Helper()
	certPEM, keyPEM, err := testCA.IssueClient(canaryID, time.Hour)
	if err != nil {
		t.Fatalf("IssueClient(%s): %v", canaryID, err)
	}
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatalf("X509KeyPair(%s): %v", canaryID, err)
	}
	return cert
}

// TestRequireBearerTokenEnforcesClientCertificateCN is issue #47 slice
// 3's required mTLS test: real TLS, a real ClientAuth:
// RequireAndVerifyClientCert listener (mirroring what
// cmd/birdcage/main.go wires for the ingest listener), and internal/ca
// for every certificate involved.
//
// (a) A client certificate whose CommonName matches the bearer token's
// canary is accepted. (b) One naming a different canary is refused with
// a 401 and an ingest.client_cert_mismatch audit entry -- the request
// still passes the TLS handshake (the certificate is valid, just for the
// wrong identity) so this is requireBearerToken's own check, not the
// listener's. (c) No client certificate at all never reaches
// requireBearerToken -- the handshake itself fails, since the server
// requires one.
func TestRequireBearerTokenEnforcesClientCertificateCN(t *testing.T) {
	forEachEngine(t, func(t *testing.T, database *db.DB) {
		testCA := newTestCA(t)
		raw := mintToken(t, database, "right-canary")

		rightCert := clientCertificate(t, testCA, "right-canary")
		wrongCert := clientCertificate(t, testCA, "wrong-canary")

		limiters := newLimiterRegistry(defaultLimiterLimits)
		coalescer := newAuditCoalescer()
		mux := http.NewServeMux()
		mux.Handle("POST /probe", requireBearerToken(database, time.Now, limiters, coalescer, func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		}))

		srv := httptest.NewUnstartedServer(mux)
		getCert := testCA.ServerCertificateSource([]string{"127.0.0.1"}, time.Hour, 10*time.Minute, nil)
		// httptest.Server.StartTLS injects its own self-signed
		// certificate into TLS.Certificates whenever that slice is
		// empty, which would win over GetCertificate for a client that
		// dials by IP (no SNI) -- minting the leaf directly here and
		// setting Certificates avoids that, so the client actually
		// verifies against testCA.
		leaf, err := getCert(&tls.ClientHelloInfo{ServerName: "127.0.0.1"})
		if err != nil {
			t.Fatalf("mint server leaf: %v", err)
		}
		srv.TLS = &tls.Config{
			MinVersion:   tls.VersionTLS13,
			Certificates: []tls.Certificate{*leaf},
			ClientAuth:   tls.RequireAndVerifyClientCert,
			ClientCAs:    testCA.Pool(),
		}
		srv.StartTLS()
		defer srv.Close()

		doRequest := func(certs ...tls.Certificate) (*http.Response, error) {
			client := &http.Client{
				Transport: &http.Transport{
					TLSClientConfig: &tls.Config{RootCAs: testCA.Pool(), Certificates: certs},
				},
				Timeout: 5 * time.Second,
			}
			req, err := http.NewRequest(http.MethodPost, srv.URL+"/probe", nil)
			if err != nil {
				t.Fatalf("build request: %v", err)
			}
			req.Header.Set("Authorization", "Bearer "+raw)
			return client.Do(req)
		}

		t.Run("matching CN accepted", func(t *testing.T) {
			resp, err := doRequest(rightCert)
			if err != nil {
				t.Fatalf("request with matching client cert: %v", err)
			}
			defer resp.Body.Close()
			if resp.StatusCode != http.StatusOK {
				t.Errorf("status = %d, want 200", resp.StatusCode)
			}
		})

		t.Run("mismatched CN refused with audit entry", func(t *testing.T) {
			resp, err := doRequest(wrongCert)
			if err != nil {
				t.Fatalf("request with mismatched client cert: %v", err)
			}
			defer resp.Body.Close()
			if resp.StatusCode != http.StatusUnauthorized {
				t.Errorf("status = %d, want 401", resp.StatusCode)
			}

			rows, err := database.Query(`SELECT target, reason FROM audit_log WHERE action = 'ingest.client_cert_mismatch'`)
			if err != nil {
				t.Fatalf("query audit_log: %v", err)
			}
			defer func() { _ = rows.Close() }()
			var found int
			for rows.Next() {
				var target, reason string
				if err := rows.Scan(&target, &reason); err != nil {
					t.Fatalf("scan audit_log row: %v", err)
				}
				found++
				if target != "right-canary" {
					t.Errorf("target = %q, want %q (the token's canary, not the presented cert's)", target, "right-canary")
				}
				if !strings.Contains(reason, "wrong-canary") {
					t.Errorf("reason = %q, want it to name the presented CN %q", reason, "wrong-canary")
				}
			}
			if found != 1 {
				t.Fatalf("found %d ingest.client_cert_mismatch audit rows, want 1", found)
			}
		})

		t.Run("no client certificate refused at the handshake", func(t *testing.T) {
			resp, err := doRequest()
			if err == nil {
				resp.Body.Close()
				t.Fatal("request without a client certificate succeeded, want a TLS handshake failure")
			}
		})
	})
}
