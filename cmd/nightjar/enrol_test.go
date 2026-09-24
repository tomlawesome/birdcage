package main

import (
	"testing"
	"time"

	"github.com/tomlawesome/birdcage/internal/agent/enrol"
)

// TestWriteEnrolmentStateWritesOnlyWhatNightjarReadsBack proves Nightjar's
// own writeEnrolmentState -- unlike cmd/mockingbird's -- writes exactly
// the CA cert, its mTLS identity, its bearer token and the ingest URL,
// and nothing else: no admin-approval or release address, since a
// scanner has no log tailer or dashboard to show either on (enrol.go's
// own doc comment). A field that leaked into this list would be a
// scanner boot writing state it can never use, silently.
func TestWriteEnrolmentStateWritesOnlyWhatNightjarReadsBack(t *testing.T) {
	hello := enrol.Hello{
		EnrolmentSecret:      "secret",
		CAPEM:                []byte("ca-pem-bytes"),
		IngestURL:            "https://birdcage.example:8443",
		WindowDeadline:       time.Now().Add(time.Hour),
		AdminApprovalAddress: "admin@example.com",
		ReleaseAddress:       "release@example.com",
	}
	creds := enrol.Credentials{
		CanaryID:      "canary-1",
		CanaryToken:   "tok-abc",
		ClientCertPEM: []byte("client-cert-pem"),
	}
	keyPEM := []byte("client-key-pem")

	files := writeEnrolmentState(hello, creds, keyPEM)

	want := map[string]string{
		caFileName:         "ca-pem-bytes",
		clientCertFileName: "client-cert-pem",
		clientKeyFileName:  "client-key-pem",
		tokenFileName:      "tok-abc",
		ingestURLFileName:  "https://birdcage.example:8443",
	}
	if len(files) != len(want) {
		t.Fatalf("len(files) = %d, want %d (no admin-approval or release address)", len(files), len(want))
	}
	got := make(map[string]string, len(files))
	for _, f := range files {
		got[f.Name] = string(f.Data)
	}
	for name, wantData := range want {
		gotData, ok := got[name]
		if !ok {
			t.Errorf("missing state file %q", name)
			continue
		}
		if gotData != wantData {
			t.Errorf("file %q = %q, want %q", name, gotData, wantData)
		}
	}
}
