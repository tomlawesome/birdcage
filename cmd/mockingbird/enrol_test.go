package main

import (
	"testing"
	"time"

	"github.com/tomlawesome/birdcage/internal/agent/enrol"
)

// TestWriteEnrolmentStateWritesNonRequiredFilesBeforeRequiredFiles proves
// writeState's own restart-safety promise -- "a crash or failure partway
// through leaves whichever files landed durably on disk and the rest
// simply absent, which the next boot's EnsureEnrolled reports as
// incomplete enrolment state" -- actually holds for this agent kind.
// EnsureEnrolled only checks enrolStateFiles (ca.pem, client.pem,
// client-key.pem, token, ingest-url), a strict subset of what
// writeEnrolmentState writes; the promise only holds if every file
// outside that subset (admin-approval-address, release-address) is
// written before every file inside it, since writeState writes
// sequentially and a crash lands a prefix of the list. If a required
// file were ever written before a non-required one, a crash between
// them would leave EnsureEnrolled reporting "already enrolled" while
// that non-required file stays absent forever.
func TestWriteEnrolmentStateWritesNonRequiredFilesBeforeRequiredFiles(t *testing.T) {
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

	required := make(map[string]bool, len(enrolStateFiles))
	for _, name := range enrolStateFiles {
		required[name] = true
	}

	seenRequired := false
	for _, f := range files {
		if required[f.Name] {
			seenRequired = true
			continue
		}
		if seenRequired {
			t.Fatalf("%s (not in enrolStateFiles) is written after a required file; a crash between them leaves EnsureEnrolled reporting \"already enrolled\" with %s still absent", f.Name, f.Name)
		}
	}
}
