package auth_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/tomlawesome/birdcage/internal/auth"
)

// closedIssuerURL returns the address of an HTTPS server that has been
// shut down: nothing answers there, so SSO discovery against it fails.
func closedIssuerURL(t *testing.T) string {
	t.Helper()
	dead := httptest.NewTLSServer(http.NotFoundHandler())
	url := dead.URL
	dead.Close()
	return url
}

// TestNoSetupCodeUntilOpenHasSucceeded is review fix 10. If Open fails after
// the accounts store has opened (here: SSO is configured with a shared issuer
// and no tenant pin: a configuration refusal), no setup code appears in the log, because the operator
// would copy a code from a process that never started. Opening again over the
// same database without the bad setting succeeds and announces exactly one.
func TestNoSetupCodeUntilOpenHasSucceeded(t *testing.T) {
	database := openDatabase(t)
	key := testKey('a')

	failedLog, failed := newLogCapture()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	svc, err := auth.Open(ctx, database, auth.Config{
		Key:              key,
		PublicURL:        "https://birdcage.example.net",
		OIDCIssuer:       "https://accounts.google.com",
		OIDCClientID:     "birdcage-test-client",
		OIDCClientSecret: "fake-client-secret-for-tests",
	}, failedLog)
	if err == nil {
		svc.Close()
		t.Fatal("auth.Open with a shared SSO issuer = nil error, want a failure")
	}
	if codes := failed.setupCodes(); len(codes) != 0 {
		t.Errorf("setup codes logged by an Open that failed = %v, want none", codes)
	}
	for _, line := range failed.all() {
		if strings.Contains(strings.ToLower(line), "setup code") {
			t.Errorf("log line from an Open that failed mentions a setup code: %q", line)
		}
	}

	_, ok, err := openService(t, database, key)
	if err != nil {
		t.Fatalf("auth.Open again, over the same database, without SSO: %v", err)
	}
	if codes := ok.setupCodes(); len(codes) != 1 {
		t.Errorf("setup codes logged by the Open that succeeded = %v, want exactly one", codes)
	}
}
