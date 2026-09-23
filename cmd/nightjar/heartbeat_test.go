package main

import (
	"context"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/tomlawesome/birdcage/internal/agent/client"
)

// newTestClient builds a client.Client trusting ts's own certificate --
// no mTLS material, since this file exercises only the heartbeat loop's
// own wire behavior, not certificate presentation (internal/agent/client
// and cmd/mockingbird each carry their own, fuller version of this same
// helper for tests that do need one).
func newTestClient(t *testing.T, ts *httptest.Server) *client.Client {
	t.Helper()
	cert := ts.Certificate()
	if cert == nil {
		t.Fatal("test server has no certificate")
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
	c, err := client.New(client.Config{BaseURL: ts.URL, CACert: certPEM})
	if err != nil {
		t.Fatalf("client.New: %v", err)
	}
	return c
}

// TestSendHeartbeatPostsCommonShapeOnly is issue #106's own required
// proof that Nightjar sends the common heartbeat, not a hand-inspected
// assumption: the request lands on POST /ingest/heartbeat carrying
// agent_version and nothing a log tailer would send -- a queue_depth or
// log_read_ok field here would be refused by internal/ingest's own
// DisallowUnknownFields decode for a Scanner-kind token (heartbeat_test.go
// in internal/ingest proves that refusal; this proves Nightjar never
// tries to send one in the first place).
func TestSendHeartbeatPostsCommonShapeOnly(t *testing.T) {
	var gotPath string
	var gotBody map[string]any
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		if err := json.NewDecoder(r.Body).Decode(&gotBody); err != nil {
			t.Errorf("decode request body: %v", err)
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer ts.Close()
	c := newTestClient(t, ts)

	sendHeartbeat(context.Background(), c, "tok", "1.2.3")

	if gotPath != "/ingest/heartbeat" {
		t.Errorf("path = %q, want /ingest/heartbeat", gotPath)
	}
	if gotBody["agent_version"] != "1.2.3" {
		t.Errorf("agent_version = %v, want 1.2.3", gotBody["agent_version"])
	}
	for _, logTailerField := range []string{"queue_depth", "log_read_ok", "last_event_id", "dropped", "rejected", "event_id_collisions", "position_found"} {
		if _, present := gotBody[logTailerField]; present {
			t.Errorf("body carries %q -- the common shape must never claim a log-tailer field", logTailerField)
		}
	}
}

// TestSendHeartbeatUnauthorizedDoesNotPanic proves sendHeartbeat's
// uniform handling of a dead token (issue #106, matching every other
// agent's stance -- recovery is re-enrolment, #47): it must return
// without panicking or blocking, leaving the next tick to try again.
func TestSendHeartbeatUnauthorizedDoesNotPanic(t *testing.T) {
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"error":"unauthorized"}`))
	}))
	defer ts.Close()
	c := newTestClient(t, ts)

	sendHeartbeat(context.Background(), c, "not-a-real-token", "1.0.0")
}
