package ingest

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/tomlawesome/birdcage/internal/agentkind"
	"github.com/tomlawesome/birdcage/internal/ca"
	"github.com/tomlawesome/birdcage/internal/db"
	"github.com/tomlawesome/birdcage/internal/store"
)

// clientCertificate does what an agent does since issue #130 (ADR-0012
// B1): generates its own ECDSA P-256 key, sends a CSR, and gets back a
// certificate testCA.SignClient signed over that key. Returned as a
// tls.Certificate an http.Client can present. Not recorded:
// registerCert does that, as provisioning or renewal would.
func clientCertificate(t *testing.T, testCA *ca.CA, canaryID string, kind agentkind.Kind) tls.Certificate {
	t.Helper()
	return clientCertificateTTL(t, testCA, canaryID, kind, time.Hour)
}

func clientCertificateTTL(t *testing.T, testCA *ca.CA, canaryID string, kind agentkind.Kind, ttl time.Duration) tls.Certificate {
	t.Helper()
	key, csr := newAgentCSR(t)
	certPEM, _, err := testCA.SignClient(csr, canaryID, kind, ttl)
	if err != nil {
		t.Fatalf("SignClient(%s): %v", canaryID, err)
	}
	return keyPair(t, certPEM, key)
}

// newAgentCSR is the agent's half of B1: a fresh key and a CSR over it.
func newAgentCSR(t *testing.T) (*ecdsa.PrivateKey, *x509.CertificateRequest) {
	t.Helper()
	key, csrPEM := newAgentCSRPEM(t)
	csr, err := ca.ParseClientCSR(csrPEM)
	if err != nil {
		t.Fatalf("ParseClientCSR: %v", err)
	}
	return key, csr
}

func newAgentCSRPEM(t *testing.T) (*ecdsa.PrivateKey, []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate agent key: %v", err)
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, key)
	if err != nil {
		t.Fatalf("CreateCertificateRequest: %v", err)
	}
	return key, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der})
}

func keyPair(t *testing.T, certPEM []byte, key *ecdsa.PrivateKey) tls.Certificate {
	t.Helper()
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}
	pair, err := tls.X509KeyPair(certPEM, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}))
	if err != nil {
		t.Fatalf("X509KeyPair: %v", err)
	}
	return pair
}

// registerCert records cert in client_certs for canaryID and binds every
// live token of canaryID to it -- what provisioning (or a renewal) does
// in production. Returns the recorded row.
func registerCert(t *testing.T, database *db.DB, canaryID string, cert tls.Certificate) store.ClientCert {
	t.Helper()
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		t.Fatalf("parse leaf: %v", err)
	}
	rec, err := store.RecordClientCert(context.Background(), database, canaryID, leaf)
	if err != nil {
		t.Fatalf("RecordClientCert(%s): %v", canaryID, err)
	}
	if _, err := store.BindCanaryTokensToCert(context.Background(), database, canaryID, rec.Fingerprint); err != nil {
		t.Fatalf("BindCanaryTokensToCert(%s): %v", canaryID, err)
	}
	return rec
}

// newMTLSServer starts a real httptest.Server, TLS 1.3, ClientAuth:
// RequireAndVerifyClientCert against clientCAs -- mirroring what
// cmd/birdcage/main.go wires for the real ingest listener
// (internal/ingest/tlsserver.go's own NewTLSServer). serverCA mints the
// serving leaf; clientCAs is a separate parameter from serverCA so a
// test can trust more than one issuer at once (the real testCA plus a
// throwaway test-local one, for the malformed-certificate cases below).
func newMTLSServer(t *testing.T, serverCA *ca.CA, clientCAs *x509.CertPool, mux http.Handler) *httptest.Server {
	t.Helper()
	srv := httptest.NewUnstartedServer(mux)
	getCert := serverCA.ServerCertificateSource([]string{"127.0.0.1"}, time.Hour, 10*time.Minute, nil)
	// httptest.Server.StartTLS injects its own self-signed certificate
	// into TLS.Certificates whenever that slice is empty, which would
	// win over GetCertificate for a client that dials by IP (no SNI) --
	// minting the leaf directly here and setting Certificates avoids
	// that, so the client actually verifies against serverCA.
	leaf, err := getCert(&tls.ClientHelloInfo{ServerName: "127.0.0.1"})
	if err != nil {
		t.Fatalf("mint server leaf: %v", err)
	}
	srv.TLS = &tls.Config{
		MinVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{*leaf},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    clientCAs,
	}
	srv.StartTLS()
	return srv
}

// mtlsRequest POSTs to srv.URL+path with token as the bearer credential
// and certs (zero or one) as the presented client certificate.
func mtlsRequest(t *testing.T, srv *httptest.Server, rootCAs *x509.CertPool, path, token string, certs ...tls.Certificate) (*http.Response, error) {
	t.Helper()
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{RootCAs: rootCAs, Certificates: certs},
		},
		Timeout: 5 * time.Second,
	}
	req, err := http.NewRequest(http.MethodPost, srv.URL+path, nil)
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	return client.Do(req)
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
		enrollCanary(t, database, "right-canary")
		raw := mintToken(t, database, "right-canary")

		rightCert := clientCertificate(t, testCA, "right-canary", agentkind.Honeypot)
		wrongCert := clientCertificate(t, testCA, "wrong-canary", agentkind.Honeypot)
		registerCert(t, database, "right-canary", rightCert)

		limiters := newLimiterRegistry(defaultLimiterLimits)
		coalescer := newAuditCoalescer()
		route := ingestRoute{pattern: "POST /probe", kinds: []agentkind.Kind{agentkind.Honeypot}, handler: func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		}}
		mux := http.NewServeMux()
		mux.Handle(route.pattern, requireBearerToken(database, time.Now, limiters, coalescer, newDualUseTracker(), nil, route))

		srv := newMTLSServer(t, testCA, testCA.Pool(), mux)
		defer srv.Close()

		t.Run("matching CN accepted", func(t *testing.T) {
			resp, err := mtlsRequest(t, srv, testCA.Pool(), "/probe", raw, rightCert)
			if err != nil {
				t.Fatalf("request with matching client cert: %v", err)
			}
			defer func() { _ = resp.Body.Close() }() // test teardown; nothing left to act on a close error
			if resp.StatusCode != http.StatusOK {
				t.Errorf("status = %d, want 200", resp.StatusCode)
			}
		})

		t.Run("mismatched CN refused with audit entry", func(t *testing.T) {
			resp, err := mtlsRequest(t, srv, testCA.Pool(), "/probe", raw, wrongCert)
			if err != nil {
				t.Fatalf("request with mismatched client cert: %v", err)
			}
			defer func() { _ = resp.Body.Close() }() // test teardown; nothing left to act on a close error
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
			resp, err := mtlsRequest(t, srv, testCA.Pool(), "/probe", raw)
			if err == nil {
				_ = resp.Body.Close() // test teardown; nothing left to act on a close error
				t.Fatal("request without a client certificate succeeded, want a TLS handshake failure")
			}
		})
	})
}

// throwawayCA is a second, independent CA -- not internal/ca.CA -- built
// directly with crypto/x509, used only to mint the certificate shapes
// internal/ca.SignClient can no longer produce (issue #106, design note
// section 5: "do not add a kindless option to IssueClient", now SignClient -- a legacy
// pre-#106 certificate carries no OU at all, and a malformed one carries
// more than one). Its own certificate is added to the listener's
// ClientCAs pool alongside the real testCA's, so a leaf it signs still
// passes the TLS handshake -- what's under test is requireBearerToken's
// application-level kind check, not certificate trust.
type throwawayCA struct {
	key  *ecdsa.PrivateKey
	cert *x509.Certificate
}

func newThrowawayCA(t *testing.T) *throwawayCA {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate throwaway CA key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "throwaway-test-ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create throwaway CA cert: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse throwaway CA cert: %v", err)
	}
	return &throwawayCA{key: key, cert: cert}
}

// issueLeaf mints a client-auth leaf for canaryID with ou set verbatim
// (including nil, for a legacy pre-#106 shape) -- the point of this type
// existing at all, since internal/ca.SignClient's signature no longer
// allows either shape.
func (c *throwawayCA) issueLeaf(t *testing.T, canaryID string, ou []string) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate leaf key: %v", err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		t.Fatalf("generate serial: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: canaryID, OrganizationalUnit: ou},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, c.cert, &key.PublicKey, c.key)
	if err != nil {
		t.Fatalf("create leaf: %v", err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatalf("marshal leaf key: %v", err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	pair, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatalf("X509KeyPair: %v", err)
	}
	return pair
}

// TestRequireBearerTokenEnforcesCertificateKind is issue #106's own
// required real-TLS suite (design note section 5): every certificate is
// either issued by internal/ca (the seagull and matching-kind cases,
// real production certificates carrying a real if unregistered OU) or by
// a throwaway CA the listener is also told to trust (the legacy and
// two-OU cases, shapes internal/ca.SignClient's own signature no longer
// allows) -- never a mocked authoriser.
func TestRequireBearerTokenEnforcesCertificateKind(t *testing.T) {
	forEachEngine(t, func(t *testing.T, database *db.DB) {
		testCA := newTestCA(t)
		other := newThrowawayCA(t)

		clientCAs := x509.NewCertPool()
		if !clientCAs.AppendCertsFromPEM(testCA.CertPEM()) {
			t.Fatal("failed to add testCA's certificate to the client CA pool")
		}
		clientCAs.AddCert(other.cert)

		// newProbeServer builds a fresh mux -- and therefore a fresh
		// auditCoalescer -- per call, so each subtest's audit assertion
		// below sees exactly its own row rather than a later subtest's
		// occurrence being folded into an earlier one's (the coalescer's
		// own window is 1 minute, comfortably longer than this test
		// runs). kinds is the single "POST /probe" route's own allowed
		// set; nil (the empty-kinds subtest) exercises ingestRoute's own
		// "refuses everything by construction" zero value.
		newProbeServer := func(kinds []agentkind.Kind) *httptest.Server {
			t.Helper()
			limiters := newLimiterRegistry(defaultLimiterLimits)
			coalescer := newAuditCoalescer()
			route := ingestRoute{pattern: "POST /probe", kinds: kinds, handler: func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
			}}
			mux := http.NewServeMux()
			mux.Handle(route.pattern, requireBearerToken(database, time.Now, limiters, coalescer, newDualUseTracker(), nil, route))
			return newMTLSServer(t, testCA, clientCAs, mux)
		}

		assertAuditRow := func(t *testing.T, action, canaryID string) {
			t.Helper()
			row := database.QueryRow(`SELECT reason FROM audit_log WHERE action = ? AND target = ? ORDER BY id DESC LIMIT 1`, action, canaryID)
			var reason string
			if err := row.Scan(&reason); err != nil {
				t.Fatalf("no %s audit row for %s: %v", action, canaryID, err)
			}
			if reason == "" {
				t.Errorf("%s audit row for %s has an empty reason", action, canaryID)
			}
		}

		t.Run("legacy kindless certificate refused with kind_mismatch", func(t *testing.T) {
			enrollCanary(t, database, "legacy-canary")
			raw := mintToken(t, database, "legacy-canary")
			srv := newProbeServer([]agentkind.Kind{agentkind.Honeypot})
			defer srv.Close()

			cert := other.issueLeaf(t, "legacy-canary", nil)
			registerCert(t, database, "legacy-canary", cert)
			resp, err := mtlsRequest(t, srv, testCA.Pool(), "/probe", raw, cert)
			if err != nil {
				t.Fatalf("request with a legacy (kindless) certificate: %v", err)
			}
			defer func() { _ = resp.Body.Close() }() // test teardown; nothing left to act on a close error
			if resp.StatusCode != http.StatusForbidden {
				t.Errorf("status = %d, want 403", resp.StatusCode)
			}
			assertAuditRow(t, "ingest.kind_mismatch", "legacy-canary")
		})

		t.Run("two-OU certificate refused", func(t *testing.T) {
			enrollCanary(t, database, "two-ou-canary")
			raw := mintToken(t, database, "two-ou-canary")
			srv := newProbeServer([]agentkind.Kind{agentkind.Honeypot})
			defer srv.Close()

			cert := other.issueLeaf(t, "two-ou-canary", []string{string(agentkind.Honeypot), string(agentkind.Scanner)})
			registerCert(t, database, "two-ou-canary", cert)
			resp, err := mtlsRequest(t, srv, testCA.Pool(), "/probe", raw, cert)
			if err != nil {
				t.Fatalf("request with a two-OU certificate: %v", err)
			}
			defer func() { _ = resp.Body.Close() }() // test teardown; nothing left to act on a close error
			if resp.StatusCode != http.StatusForbidden {
				t.Errorf("status = %d, want 403", resp.StatusCode)
			}
			assertAuditRow(t, "ingest.kind_mismatch", "two-ou-canary")
		})

		t.Run("unregistered kind seagull refused", func(t *testing.T) {
			enrollCanary(t, database, "seagull-canary")
			raw := mintToken(t, database, "seagull-canary")
			srv := newProbeServer([]agentkind.Kind{agentkind.Honeypot})
			defer srv.Close()

			cert := clientCertificate(t, testCA, "seagull-canary", agentkind.Kind("seagull"))
			registerCert(t, database, "seagull-canary", cert)
			resp, err := mtlsRequest(t, srv, testCA.Pool(), "/probe", raw, cert)
			if err != nil {
				t.Fatalf("request with an unregistered-kind certificate: %v", err)
			}
			defer func() { _ = resp.Body.Close() }() // test teardown; nothing left to act on a close error
			if resp.StatusCode != http.StatusForbidden {
				t.Errorf("status = %d, want 403", resp.StatusCode)
			}
			assertAuditRow(t, "ingest.kind_mismatch", "seagull-canary")
		})

		t.Run("matching kind accepted", func(t *testing.T) {
			enrollCanary(t, database, "matching-canary")
			raw := mintToken(t, database, "matching-canary")
			srv := newProbeServer([]agentkind.Kind{agentkind.Honeypot})
			defer srv.Close()

			cert := clientCertificate(t, testCA, "matching-canary", agentkind.Honeypot)
			registerCert(t, database, "matching-canary", cert)
			resp, err := mtlsRequest(t, srv, testCA.Pool(), "/probe", raw, cert)
			if err != nil {
				t.Fatalf("request with a matching-kind certificate: %v", err)
			}
			defer func() { _ = resp.Body.Close() }() // test teardown; nothing left to act on a close error
			if resp.StatusCode != http.StatusOK {
				t.Errorf("status = %d, want 200", resp.StatusCode)
			}
		})

		t.Run("empty-kinds route refuses even a valid honeypot", func(t *testing.T) {
			enrollCanary(t, database, "empty-route-canary")
			raw := mintToken(t, database, "empty-route-canary")
			srv := newProbeServer(nil) // ingestRoute's own zero value: refuses every request
			defer srv.Close()

			cert := clientCertificate(t, testCA, "empty-route-canary", agentkind.Honeypot)
			registerCert(t, database, "empty-route-canary", cert)
			resp, err := mtlsRequest(t, srv, testCA.Pool(), "/probe", raw, cert)
			if err != nil {
				t.Fatalf("request against an empty-kinds route: %v", err)
			}
			defer func() { _ = resp.Body.Close() }() // test teardown; nothing left to act on a close error
			if resp.StatusCode != http.StatusForbidden {
				t.Errorf("status = %d, want 403", resp.StatusCode)
			}
			// This is the registry check refusing (empty allowed set),
			// never reaching the certificate check -- ingest.kind_refused,
			// not ingest.kind_mismatch, even though the certificate here
			// is perfectly valid.
			assertAuditRow(t, "ingest.kind_refused", "empty-route-canary")
		})
	})
}
