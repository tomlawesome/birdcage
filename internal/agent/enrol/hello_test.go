package enrol

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"testing"
	"time"
)

func ctx() context.Context { return context.Background() }

// TestFirstContactRefusesUnmatchedPin is required case (a): the pin does
// not match any certificate the server presents -- refused, and the
// handler must never be reached, since a TLS handshake that fails in
// VerifyConnection never lets the HTTP request past it.
func TestFirstContactRefusesUnmatchedPin(t *testing.T) {
	_, caCert, caKey := genCA(t, "enrol-test-ca")
	leafDER, leafKey := genLeaf(t, caCert, caKey)
	caDER := caCert.Raw

	var handlerReached bool
	ts := newChainServer(t, [][]byte{leafDER, caDER}, leafKey, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handlerReached = true
		w.WriteHeader(http.StatusInternalServerError)
	}))

	unrelatedDER, _, _ := genCA(t, "unrelated-ca")
	pin := pinFor(unrelatedDER)

	_, err := FirstContact(ctx(), ts.URL, pin, "tok")
	if err == nil {
		t.Fatal("FirstContact succeeded with a pin matching nothing in the presented chain")
	}
	if handlerReached {
		t.Fatal("FirstContact's HTTP request reached the server handler; the TLS handshake should have failed first")
	}
	if IsRetryable(err) {
		t.Fatalf("err = %v, want a permanent (non-retryable) failure: a wrong pin will never match on retry", err)
	}
}

// TestFirstContactRefusesUnchainedLeaf is required case (b): the pin
// matches a certificate the server presents, but the leaf the server is
// actually serving was not signed by it -- refused.
func TestFirstContactRefusesUnchainedLeaf(t *testing.T) {
	_, caCert, caKey := genCA(t, "enrol-test-ca")
	leafDER, leafKey := genLeaf(t, caCert, caKey)
	unrelatedCADER, _, _ := genCA(t, "unrelated-ca")

	var handlerReached bool
	// The server presents its real leaf (signed by caCert) alongside an
	// unrelated CA certificate that has nothing to do with it.
	ts := newChainServer(t, [][]byte{leafDER, unrelatedCADER}, leafKey, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handlerReached = true
		w.WriteHeader(http.StatusInternalServerError)
	}))

	pin := pinFor(unrelatedCADER) // matches the presented-but-unrelated CA

	_, err := FirstContact(ctx(), ts.URL, pin, "tok")
	if err == nil {
		t.Fatal("FirstContact succeeded even though the leaf does not chain to the pinned certificate")
	}
	if handlerReached {
		t.Fatal("FirstContact's HTTP request reached the server handler; the TLS handshake should have failed first")
	}
	if IsRetryable(err) {
		t.Fatalf("err = %v, want a permanent (non-retryable) failure: an unchained leaf will never chain on retry", err)
	}
}

// TestFirstContactHappyPath is required case (c): a correctly pinned,
// correctly chained server answering 200 with a well-formed body succeeds.
func TestFirstContactHappyPath(t *testing.T) {
	caDER, caCert, caKey := genCA(t, "enrol-test-ca")
	leafDER, leafKey := genLeaf(t, caCert, caKey)

	deadline := time.Now().Add(5 * time.Minute).UTC().Truncate(time.Second)
	ts := newChainServer(t, [][]byte{leafDER, caDER}, leafKey, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/enrol/hello" {
			t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
		}
		var req wireHelloRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Errorf("decode request: %v", err)
		}
		if req.Token != "deploy-token" {
			t.Errorf("Token = %q, want %q", req.Token, "deploy-token")
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(wireHelloResponse{
			EnrolmentSecret:      "secret-abc",
			CAPEM:                string(pemCert(caDER)),
			IngestURL:            "https://ingest.example:8443",
			WindowDeadline:       deadline.Format(time.RFC3339),
			AdminApprovalAddress: "admin@example.com",
			ReleaseAddress:       "release@example.com",
		})
	}))

	hello, err := FirstContact(ctx(), ts.URL, pinFor(caDER), "deploy-token")
	if err != nil {
		t.Fatalf("FirstContact: %v", err)
	}
	if hello.EnrolmentSecret != "secret-abc" {
		t.Errorf("EnrolmentSecret = %q", hello.EnrolmentSecret)
	}
	if hello.IngestURL != "https://ingest.example:8443" {
		t.Errorf("IngestURL = %q", hello.IngestURL)
	}
	if !hello.WindowDeadline.Equal(deadline) {
		t.Errorf("WindowDeadline = %v, want %v", hello.WindowDeadline, deadline)
	}
	if hello.AdminApprovalAddress != "admin@example.com" {
		t.Errorf("AdminApprovalAddress = %q", hello.AdminApprovalAddress)
	}
	if hello.ReleaseAddress != "release@example.com" {
		t.Errorf("ReleaseAddress = %q", hello.ReleaseAddress)
	}
	if string(hello.CAPEM) != string(pemCert(caDER)) {
		t.Errorf("CAPEM does not match the server's own CA certificate")
	}
}

// TestFirstContactRefusesMismatchedResponseCAPEM is required case (d): the
// TLS handshake itself is pinned correctly, but the ca_pem the response
// body carries hashes to something else -- refused.
func TestFirstContactRefusesMismatchedResponseCAPEM(t *testing.T) {
	caDER, caCert, caKey := genCA(t, "enrol-test-ca")
	leafDER, leafKey := genLeaf(t, caCert, caKey)
	otherCADER, _, _ := genCA(t, "other-ca")

	ts := newChainServer(t, [][]byte{leafDER, caDER}, leafKey, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(wireHelloResponse{
			EnrolmentSecret:      "secret-abc",
			CAPEM:                string(pemCert(otherCADER)), // does not match the pin
			IngestURL:            "https://ingest.example:8443",
			WindowDeadline:       time.Now().Add(5 * time.Minute).UTC().Format(time.RFC3339),
			AdminApprovalAddress: "admin@example.com",
			ReleaseAddress:       "release@example.com",
		})
	}))

	_, err := FirstContact(ctx(), ts.URL, pinFor(caDER), "deploy-token")
	if err == nil {
		t.Fatal("FirstContact succeeded with a response ca_pem that does not match the pin")
	}
	if IsRetryable(err) {
		t.Fatalf("err = %v, want a permanent (non-retryable) failure: a mismatched ca_pem will never fix itself on retry", err)
	}
}

// TestFirstContactRefused401IsTypedErrRefused is required case (e): 401
// from the pinned server must be reported as ErrRefused specifically, not
// a generic or retryable error.
func TestFirstContactRefused401IsTypedErrRefused(t *testing.T) {
	caDER, caCert, caKey := genCA(t, "enrol-test-ca")
	leafDER, leafKey := genLeaf(t, caCert, caKey)

	ts := newChainServer(t, [][]byte{leafDER, caDER}, leafKey, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"error":"refused"}`))
	}))

	_, err := FirstContact(ctx(), ts.URL, pinFor(caDER), "deploy-token")
	if !errors.Is(err, ErrRefused) {
		t.Fatalf("err = %v, want ErrRefused", err)
	}
	if IsRetryable(err) {
		t.Fatal("a 401 must never be reported as retryable")
	}
}
